use crate::snapshots::{
    SnapshotBatchRequest, SnapshotSource, SnapshotSourceManifest, SNAPSHOT_ENTITY_ACK_CONTRACT,
};
use anyhow::{anyhow, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use ottto_core::{
    compiled_release_version, redact_inline, ControlTokenStore, FileDeviceStore,
    FilePendingDeviceCredentialStore, KeychainSecretStore, LocalDeviceBinding,
    OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
};
use ottto_protocol::{AgentStatusSnapshot, LocalMachineHealthV1, MachineRuntimeHeartbeatV1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Whether snapshot batch bodies are gzip-encoded.
///
/// Default OFF, deliberately. Response compression is universal, but nothing
/// decompresses a *request* body unless a route opts in, and the batch route does
/// not yet — the OTLP route is the only one in the estate with a request
/// decompression path. Shipping this enabled would 4xx every upload from an
/// upgraded daemon against today's server.
///
/// So the encoder ships now (the release train is the long pole) behind
/// `OTTTO_SNAPSHOT_UPLOAD_GZIP=1`, and the default flips in the release AFTER the
/// batch route decompresses. The refusal fallback below means a premature flip
/// degrades to identity encoding instead of stopping sync.
static SNAPSHOT_UPLOAD_GZIP: AtomicBool = AtomicBool::new(false);
static SNAPSHOT_UPLOAD_GZIP_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(crate) fn snapshot_upload_gzip_enabled() -> bool {
    if !SNAPSHOT_UPLOAD_GZIP_INITIALIZED.swap(true, Ordering::Relaxed) {
        let enabled = std::env::var("OTTTO_SNAPSHOT_UPLOAD_GZIP")
            .map(|value| matches!(value.trim(), "1" | "true" | "yes"))
            .unwrap_or(false);
        SNAPSHOT_UPLOAD_GZIP.store(enabled, Ordering::Relaxed);
    }
    SNAPSHOT_UPLOAD_GZIP.load(Ordering::Relaxed)
}

fn disable_snapshot_upload_gzip() {
    SNAPSHOT_UPLOAD_GZIP_INITIALIZED.store(true, Ordering::Relaxed);
    if SNAPSHOT_UPLOAD_GZIP.swap(false, Ordering::Relaxed) {
        eprintln!(
            "ottto-service: snapshot upload gzip disabled for this process — the backend refused \
             the encoded body; falling back to identity encoding."
        );
    }
}

/// gzip `body`, or `None` if the encoder failed (in which case the caller sends
/// identity encoding rather than nothing).
fn gzip(body: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).ok()?;
    encoder.finish().ok()
}

/// A rejection that means "I could not read your encoding", as opposed to "your
/// payload is wrong". A server without request decompression cannot parse the
/// body at all, so it answers 400 (unreadable JSON) or 415 (unsupported media
/// type) — never 422, which requires having parsed the body first.
fn encoding_was_refused(outcome: &Result<ureq::Response, ureq::Error>) -> bool {
    matches!(outcome, Err(ureq::Error::Status(400 | 415, _)))
}

/// The backend shed this request instead of failing it: 429 or 503, with the
/// server's `Retry-After` when it sent one.
///
/// This is a distinct class from every other upload error on purpose. A shed
/// request is not a validation failure (the payload is fine), not an auth
/// failure, and not a network failure (the server answered). Treating it as any
/// of those produces an identical re-upload on the next tick, forever, which is
/// exactly what the deployed daemon does today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadShed {
    pub status: u16,
    pub retry_after: Option<Duration>,
}

impl std::fmt::Display for UploadShed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.retry_after {
            Some(retry_after) => write!(
                f,
                "backend shed the snapshot upload: HTTP {} retry_after={}s",
                self.status,
                retry_after.as_secs()
            ),
            None => write!(f, "backend shed the snapshot upload: HTTP {}", self.status),
        }
    }
}

impl std::error::Error for UploadShed {}

/// Ceiling on an honoured `Retry-After`. A server that asks for a day off is
/// still asking for freshness the product promises in minutes, so the daemon
/// caps the wait and keeps reporting instead of going silent.
pub const MAX_HONOURED_RETRY_AFTER: Duration = Duration::from_secs(30 * 60);

/// Parse a `Retry-After` header value: delta-seconds or an HTTP-date.
///
/// Both forms are in the spec and real load balancers send both. An unparsable
/// or absent value returns `None`, which the caller turns into its own jittered
/// backoff rather than retrying immediately.
pub(crate) fn parse_retry_after(value: &str, now: OffsetDateTime) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds).min(MAX_HONOURED_RETRY_AFTER));
    }
    // IMF-fixdate, the only date form HTTP requires a client to produce and the
    // one every proxy in this path emits. RFC 2822 parsing covers it; the
    // `GMT` zone name is the one difference, so normalise it to the numeric
    // offset RFC 2822 expects rather than hand-rolling a second date parser.
    let normalized = value.strip_suffix("GMT").map(|head| format!("{head}+0000"));
    let deadline = OffsetDateTime::parse(
        normalized.as_deref().unwrap_or(value),
        &time::format_description::well_known::Rfc2822,
    )
    .ok()?;
    let delta = deadline - now;
    if delta.is_negative() {
        return Some(Duration::ZERO);
    }
    Some(Duration::from_secs(delta.whole_seconds().unsigned_abs()).min(MAX_HONOURED_RETRY_AFTER))
}

fn shed_from_response(status: u16, response: &ureq::Response) -> UploadShed {
    UploadShed {
        status,
        retry_after: response
            .header("Retry-After")
            .and_then(|value| parse_retry_after(value, OffsetDateTime::now_utc())),
    }
}

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

/// The provider-daily-reference ingest route refused the principal or the
/// build. Kept typed and distinct from a contract rejection because
/// "this collector version is not admitted yet" is the expected steady state
/// until a reviewed server change admits a shipped build - it must not read as
/// a provider fault or count against any circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderDailyReferenceUploadRejected {
    pub status: u16,
}

impl std::fmt::Display for ProviderDailyReferenceUploadRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend refused provider daily reference upload: HTTP {}",
            self.status
        )
    }
}

impl std::error::Error for ProviderDailyReferenceUploadRejected {}

/// Closed reason vocabulary for provider-daily-reference contract refusals.
/// Only the bounded `detail.code` is retained; the response body is discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderDailyReferenceContractRejection {
    AccountExcluded,
    GrantEpochConflict,
    Other,
}

/// The provider-daily-reference ingest route rejected the batch as shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderDailyReferenceContractRejected {
    pub status: u16,
    pub reason: ProviderDailyReferenceContractRejection,
}

impl std::fmt::Display for ProviderDailyReferenceContractRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend rejected provider daily reference contract: HTTP {}",
            self.status
        )
    }
}

impl std::error::Error for ProviderDailyReferenceContractRejected {}

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
    /// Additive server capability for bounded private labels on opaque
    /// attribution facts. Defaults false so a new daemon never sends nested
    /// fields to an older backend. The backend derives this from the existing
    /// `session_titles_enabled` privacy choice; it is not a second consent.
    #[serde(default)]
    pub session_attribution_labels_enabled: bool,
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
    #[serde(default)]
    pub entity_ack_contract: Option<String>,
    #[serde(default)]
    pub accepted_entities: Vec<SnapshotEntityRef>,
    #[serde(default)]
    pub unchanged_entities: Vec<SnapshotEntityRef>,
    #[serde(default)]
    pub rejected_entities: Vec<SnapshotEntityRejection>,
    #[serde(default)]
    pub conflict_entities: Vec<SnapshotEntityRef>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotEntityRef {
    pub source_session_id: String,
    pub snapshot_fingerprint: String,
    #[serde(default = "default_occurrence_count")]
    pub occurrence_count: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SnapshotEntityRejection {
    pub source_session_id: String,
    pub snapshot_fingerprint: String,
    pub reason: String,
    pub detail: String,
    #[serde(default = "default_true")]
    pub permanent: bool,
    #[serde(default = "default_occurrence_count")]
    pub occurrence_count: u64,
}

fn default_occurrence_count() -> u64 {
    1
}

impl SnapshotBatchResponse {
    /// Reject malformed, short, duplicated, foreign, overlapping, or partial
    /// ACKs before any local checkpoint can advance.
    pub fn validate_entity_ack(&self, request: &SnapshotBatchRequest) -> Result<()> {
        if self.disabled {
            if self.accepted != 0
                || !self.accepted_entities.is_empty()
                || !self.unchanged_entities.is_empty()
                || !self.rejected_entities.is_empty()
                || !self.conflict_entities.is_empty()
            {
                return Err(anyhow!(
                    "disabled snapshot response contains entity outcomes"
                ));
            }
            return Ok(());
        }
        match self.entity_ack_contract.as_deref() {
            None => {
                if self.accepted != request.snapshots.len() as u64 {
                    return Err(anyhow!("legacy snapshot response accepted count mismatch"));
                }
                return Ok(());
            }
            Some(SNAPSHOT_ENTITY_ACK_CONTRACT) => {}
            Some(_) => {
                return Err(anyhow!(
                    "snapshot response uses an unsupported entity ACK contract"
                ));
            }
        }
        self.validate_entity_ack_identities(request.snapshots.iter().map(|item| {
            (
                item.source_session_id.as_str(),
                item.snapshot_fingerprint.as_str(),
            )
        }))
    }

    fn validate_entity_ack_identities<'a>(
        &self,
        identities: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<()> {
        let mut requested = std::collections::BTreeMap::new();
        for (source_session_id, snapshot_fingerprint) in identities {
            *requested
                .entry((
                    source_session_id.to_string(),
                    snapshot_fingerprint.to_string(),
                ))
                .or_insert(0_u64) += 1;
        }
        let mut covered = std::collections::BTreeMap::new();
        let mut classifications = std::collections::BTreeMap::new();
        let mut accepted_or_unchanged = 0_u64;
        for (classification, references) in [
            ("accepted", self.accepted_entities.as_slice()),
            ("unchanged", self.unchanged_entities.as_slice()),
        ] {
            for reference in references {
                validate_snapshot_entity_ref(reference)?;
                record_snapshot_ack_occurrences(
                    &requested,
                    &mut covered,
                    &mut classifications,
                    reference.source_session_id.as_str(),
                    reference.snapshot_fingerprint.as_str(),
                    reference.occurrence_count,
                    classification,
                )?;
                accepted_or_unchanged = accepted_or_unchanged
                    .checked_add(reference.occurrence_count)
                    .ok_or_else(|| anyhow!("snapshot ACK accepted count overflow"))?;
            }
        }
        for rejection in &self.rejected_entities {
            let reference = SnapshotEntityRef {
                source_session_id: rejection.source_session_id.clone(),
                snapshot_fingerprint: rejection.snapshot_fingerprint.clone(),
                occurrence_count: rejection.occurrence_count,
            };
            validate_snapshot_entity_ref(&reference)?;
            if !rejection.permanent {
                return Err(anyhow!("snapshot ACK contains invalid rejection"));
            }
            record_snapshot_ack_occurrences(
                &requested,
                &mut covered,
                &mut classifications,
                rejection.source_session_id.as_str(),
                rejection.snapshot_fingerprint.as_str(),
                rejection.occurrence_count,
                "rejected",
            )?;
        }
        for reference in &self.conflict_entities {
            validate_snapshot_entity_ref(reference)?;
            record_snapshot_ack_occurrences(
                &requested,
                &mut covered,
                &mut classifications,
                reference.source_session_id.as_str(),
                reference.snapshot_fingerprint.as_str(),
                reference.occurrence_count,
                "conflict",
            )?;
        }
        if covered != requested {
            return Err(anyhow!("snapshot ACK does not cover the request exactly"));
        }
        if self.accepted != accepted_or_unchanged {
            return Err(anyhow!("snapshot ACK accepted count mismatch"));
        }
        Ok(())
    }
}

fn record_snapshot_ack_occurrences(
    requested: &std::collections::BTreeMap<(String, String), u64>,
    covered: &mut std::collections::BTreeMap<(String, String), u64>,
    classifications: &mut std::collections::BTreeMap<(String, String), &'static str>,
    source_session_id: &str,
    snapshot_fingerprint: &str,
    occurrence_count: u64,
    classification: &'static str,
) -> Result<()> {
    let key = (
        source_session_id.to_string(),
        snapshot_fingerprint.to_string(),
    );
    let Some(expected) = requested.get(&key) else {
        return Err(anyhow!("snapshot ACK contains a foreign entity"));
    };
    if occurrence_count == 0 {
        return Err(anyhow!("snapshot ACK occurrence_count must be positive"));
    }
    if classifications
        .insert(key.clone(), classification)
        .is_some()
    {
        return Err(anyhow!(
            "snapshot ACK contains a duplicate outcome identity"
        ));
    }
    let observed = covered.entry(key).or_insert(0);
    *observed = observed
        .checked_add(occurrence_count)
        .ok_or_else(|| anyhow!("snapshot ACK occurrence_count overflow"))?;
    if *observed > *expected {
        return Err(anyhow!("snapshot ACK over-counts an entity"));
    }
    Ok(())
}

fn validate_snapshot_entity_ref(reference: &SnapshotEntityRef) -> Result<()> {
    if reference.source_session_id.trim().is_empty()
        || reference.occurrence_count == 0
        || reference.snapshot_fingerprint.len() != 64
        || !reference
            .snapshot_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(anyhow!("snapshot ACK entity identity is malformed"));
    }
    Ok(())
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
    pub last_zero_snapshot_confirmed_count: u64,
    pub last_zero_snapshot_usage_evidence_count: u64,
    pub last_dropped_usage_record_count: u64,
    pub last_backfill_window_days: u64,
    pub last_backfill_file_limit: u64,
    pub last_discovered_file_count: u64,
    pub last_skipped_file_count_due_to_limit: u64,
    pub last_scan_cap_hit: bool,
    /// Sessions the local semantic fuse classified as no-ops and therefore did
    /// not upload. Without it, "the collector suppressed 718 unchanged
    /// sessions" and "the collector did nothing" are the same receipt.
    pub last_semantic_noop_count: u64,
    pub last_census_complete: bool,
    pub last_symlink_rejected_count: u64,
    pub last_unreadable_path_count: u64,
    pub last_oversized_file_count: u64,
    pub last_disappeared_file_count: u64,
    pub last_malformed_json_line_count: u64,
    pub last_invalid_utf8_line_count: u64,
    pub last_over_line_cap_count: u64,
    pub last_recognized_usage_drop_count: u64,
    pub consecutive_failures: u64,
    pub next_retry_at: Option<String>,
    pub collector_version: Option<String>,
    pub parser_version: Option<String>,
    /// `{source, entity_count, rolling_hash}` over this source's scan index, as
    /// of the most recent completed scan on this machine. On a terminal status,
    /// absence explicitly withdraws prior agreement; on a nonterminal check-in,
    /// absence is liveness-only/unknown. Never fabricated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<SnapshotSourceManifest>,
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

fn require_cloud_session_success(
    response: ureq::Response,
    operation: &'static str,
    endpoint: &'static str,
) -> Result<ureq::Response> {
    let status = response.status();
    if (200..300).contains(&status) {
        Ok(response)
    } else {
        Err(anyhow::Error::new(UploadFailureDiagnostics::http(
            operation, endpoint, status, &response,
        )))
    }
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
        let response = agent
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
            })?;
        let response: RelayTokenResponse =
            require_cloud_session_success(response, "relay token request", "relay_token")?
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
        let body = serde_json::to_vec(request)
            .map_err(|error| anyhow!("serialize snapshot batch failed: {error}"))?;
        let compressed = snapshot_upload_gzip_enabled()
            .then(|| gzip(&body))
            .flatten();
        let request_builder = || {
            self.batch_agent
                .post(&self.api_url("/api/v1/agent-session-snapshots/batches"))
                .set("Accept", "application/json")
                .set("Content-Type", "application/json")
                .set("Authorization", &format!("Bearer {relay_token}"))
        };
        // Sent inline rather than through a closure: a closure returning
        // `ureq::Error` trips `clippy::result_large_err` on newer toolchains, and
        // the duplication here is two lines.
        let mut outcome = match compressed.as_ref() {
            Some(encoded) => request_builder()
                .set("Content-Encoding", "gzip")
                .send_bytes(encoded),
            None => request_builder().send_bytes(&body),
        };
        // A server that does not decompress request bodies cannot tell us so in
        // advance; it just fails to parse. Fall back to identity encoding once,
        // remember it for the process, and let the batch through instead of
        // stalling every upload behind a capability mismatch.
        if compressed.is_some() && encoding_was_refused(&outcome) {
            disable_snapshot_upload_gzip();
            outcome = request_builder().send_bytes(&body);
        }
        match outcome {
            Ok(response) => response
                .into_json()
                .map_err(|error| anyhow!("parse snapshot batch response failed: {error}")),
            // A shed request is not a failed request. Keep it typed and carry the
            // server's own backoff so the caller can honour it instead of
            // re-uploading identical bytes on the next tick.
            Err(ureq::Error::Status(code @ (429 | 503), response)) => {
                Err(anyhow::Error::new(shed_from_response(code, &response)))
            }
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
                let receipt = require_cloud_session_success(
                    response,
                    "cloud-session upload",
                    "cloud_session_batch",
                )?
                .into_json()
                .map_err(|error| anyhow!("parse cloud-session batch response failed: {error}"))?;
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

    /// Read one exact, relay-device-bound cloud grant epoch. This endpoint is
    /// deliberately not a list and never accepts browser authentication.
    pub fn get_cloud_session_grant_authority_with_timeout(
        &self,
        relay_token: &str,
        grant_id: &str,
        grant_version: u64,
        timeout: Duration,
    ) -> Result<Value> {
        if !valid_cloud_grant_id(grant_id) || grant_version == 0 {
            return Err(anyhow!("cloud-session authority identity is invalid"));
        }
        let (agent, request_timeout) = cloud_session_deadline_agent(timeout)?;
        let path = format!(
            "/api/v1/cloud-session-observations/grants/{grant_id}/authority?grant_version={grant_version}"
        );
        match agent
            .get(&self.api_url(&path))
            .timeout(request_timeout)
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .call()
        {
            Ok(response) => require_cloud_session_success(
                response,
                "cloud-session authority read",
                "cloud_session_authority",
            )?
            .into_json()
            .map_err(|error| anyhow!("parse cloud-session authority response failed: {error}")),
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
                    "cloud-session authority read",
                    "cloud_session_authority",
                    code,
                    &response,
                )))
            }
            Err(error) => Err(anyhow::Error::new(UploadFailureDiagnostics::transport(
                "cloud-session authority read",
                "cloud_session_authority",
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
                let receipt = require_cloud_session_success(
                    response,
                    "cloud-session scan upload",
                    operation,
                )?
                .into_json()
                .map_err(|error| anyhow!("parse cloud-session scan response failed: {error}"))?;
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

    /// Upload one bounded batch of provider-reported day aggregates.
    ///
    /// Relay-device authentication only: the route refuses an ordinary ingest
    /// API key, and the declared `installation_id` must be this device. The
    /// same one-shot deadline agent as the other credential-bearing calls is
    /// used so a blocked resolver cannot outlive the caller's budget and so a
    /// redirect can never replay the bearer token.
    pub fn upload_provider_daily_reference_batch_with_timeout(
        &self,
        relay_token: &str,
        request: &Value,
        timeout: Duration,
    ) -> Result<Value> {
        let (agent, request_timeout) = cloud_session_deadline_agent(timeout)?;
        let url = self.api_url("/api/v1/provider-daily-reference/batches");
        match agent
            .post(&url)
            .timeout(request_timeout)
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => require_cloud_session_success(
                response,
                "provider daily reference upload",
                "provider_daily_reference_batch",
            )?
            .into_json()
            .map_err(|error| anyhow!("parse provider daily reference response failed: {error}")),
            Err(ureq::Error::Status(code @ (401 | 403), _response)) => {
                Err(anyhow::Error::new(ProviderDailyReferenceUploadRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code @ (400 | 404 | 409 | 422), response)) => {
                let reason = if code == 409 {
                    let body = response.into_json::<serde_json::Value>().ok();
                    match body
                        .as_ref()
                        .and_then(|value| value.pointer("/detail/code"))
                        .and_then(serde_json::Value::as_str)
                    {
                        Some("provider_daily_reference_account_excluded") => {
                            ProviderDailyReferenceContractRejection::AccountExcluded
                        }
                        Some("provider_daily_reference_grant_epoch_mismatch") => {
                            ProviderDailyReferenceContractRejection::GrantEpochConflict
                        }
                        _ => ProviderDailyReferenceContractRejection::Other,
                    }
                } else {
                    ProviderDailyReferenceContractRejection::Other
                };
                Err(anyhow::Error::new(ProviderDailyReferenceContractRejected {
                    status: code,
                    reason,
                }))
            }
            Err(ureq::Error::Status(code, response)) => {
                Err(anyhow::Error::new(UploadFailureDiagnostics::http(
                    "provider daily reference upload",
                    "provider_daily_reference_batch",
                    code,
                    &response,
                )))
            }
            Err(error) => Err(anyhow::Error::new(UploadFailureDiagnostics::transport(
                "provider daily reference upload",
                "provider_daily_reference_batch",
                &error,
            ))),
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

fn valid_cloud_grant_id(value: &str) -> bool {
    valid_cloud_scan_id(value)
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
        // Cloud-session requests carry either the long-lived device secret or
        // a relay bearer token. Never let ureq replay either credential to a
        // redirect target; a 3xx is handled as an ordinary non-success status.
        .redirects(0)
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

/// Fence relay admission once confirmation may have reached the server and
/// until the candidate is fully promoted into local active state. Persisted
/// pre-confirm guards are the crash boundary immediately before the request:
/// a transport failure after that cut cannot prove the old authority survived.
pub fn ensure_no_incomplete_device_credential_promotion() -> Result<()> {
    let pending = FilePendingDeviceCredentialStore::default().load()?;
    if pending.as_ref().is_some_and(|pending| {
        pending.confirmed_at.is_some()
            || (pending.confirmation_authorized && pending.preconfirm_guards_passed)
    }) {
        return Err(anyhow!("relay identity commit is incomplete"));
    }
    Ok(())
}

pub fn load_snapshot_device_credentials() -> Result<(LocalDeviceBinding, String)> {
    ensure_no_incomplete_device_credential_promotion()?;
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
    use std::io::Read;

    fn activity_hint_json(extra: &str) -> String {
        format!(
            r#"{{
                "source":"codex",
                "server_time":"2026-07-21T10:00:00Z",
                "last_data_at":null,
                "record_count_15m":0,
                "record_count_24h":0,
                "local_usage_reconciliation_enabled":true,
                "backfill_window_days":183,
                "session_titles_enabled":true,
                "workspace_labels_enabled":true,
                "session_attribution_enabled":true,
                "recommended_scan_after":"2026-07-21T10:05:00Z"
                {extra}
            }}"#
        )
    }

    #[test]
    fn attribution_private_label_capability_defaults_off_for_older_backends() {
        let old_backend: ActivityHintResponse =
            serde_json::from_str(&activity_hint_json("")).expect("old activity hint");
        assert!(!old_backend.session_attribution_labels_enabled);

        let new_backend: ActivityHintResponse = serde_json::from_str(&activity_hint_json(
            r#", "session_attribution_labels_enabled":true"#,
        ))
        .expect("new activity hint");
        assert!(new_backend.session_attribution_labels_enabled);
    }

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
    fn retry_after_accepts_delta_seconds_and_http_dates() {
        let now = OffsetDateTime::parse("2026-07-26T10:00:00Z", &Rfc3339).expect("now");
        assert_eq!(
            parse_retry_after("120", now),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after("  30 ", now),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            parse_retry_after("Sun, 26 Jul 2026 10:02:00 GMT", now),
            Some(Duration::from_secs(120))
        );
        // A date already in the past means "now", not a negative wait.
        assert_eq!(
            parse_retry_after("Sun, 26 Jul 2026 09:00:00 GMT", now),
            Some(Duration::ZERO)
        );
        // An absurd wait is capped rather than obeyed: the product promises
        // freshness in minutes, so going silent for a day is not an option.
        assert_eq!(
            parse_retry_after("86400", now),
            Some(MAX_HONOURED_RETRY_AFTER)
        );
        assert_eq!(parse_retry_after("", now), None);
        assert_eq!(parse_retry_after("later", now), None);
    }

    #[test]
    fn gzip_round_trips_and_shrinks_a_repetitive_body() {
        // Snapshot batches repeat identical selector maps per hour bucket, which
        // is exactly the shape a deflate window exploits.
        let body = r#"{"selector_context":{"auth_mode":"subscription"}}"#.repeat(64);
        let compressed = gzip(body.as_bytes()).expect("gzip");
        assert!(compressed.len() * 4 < body.len());
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(compressed.as_slice())
            .read_to_end(&mut decoded)
            .expect("gunzip");
        assert_eq!(decoded, body.as_bytes());
    }

    #[test]
    fn only_unreadable_encodings_trigger_the_identity_fallback() {
        // 422 means the server parsed the body and disliked its contents, so the
        // encoding worked; falling back would hide a real validation failure.
        // 400/415 are the answers a server without request decompression gives.
        assert!(encoding_was_refused(&Err(ureq::Error::Status(
            400,
            ureq::Response::new(400, "Bad Request", "{}").expect("response")
        ))));
        assert!(encoding_was_refused(&Err(ureq::Error::Status(
            415,
            ureq::Response::new(415, "Unsupported Media Type", "{}").expect("response")
        ))));
        assert!(!encoding_was_refused(&Err(ureq::Error::Status(
            422,
            ureq::Response::new(422, "Unprocessable", "{}").expect("response")
        ))));
        assert!(!encoding_was_refused(&Ok(ureq::Response::new(
            200, "OK", "{}"
        )
        .expect("response"))));
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
            last_zero_snapshot_confirmed_count: 12,
            last_zero_snapshot_usage_evidence_count: 0,
            last_dropped_usage_record_count: 0,
            last_semantic_noop_count: 7,
            last_census_complete: false,
            last_symlink_rejected_count: 1,
            last_unreadable_path_count: 2,
            last_oversized_file_count: 3,
            last_disappeared_file_count: 4,
            last_malformed_json_line_count: 5,
            last_invalid_utf8_line_count: 6,
            last_over_line_cap_count: 7,
            last_recognized_usage_drop_count: 8,
            consecutive_failures: 1,
            next_retry_at: None,
            collector_version: Some("0.1.0".to_string()),
            parser_version: Some(CODEX_SNAPSHOT_PARSER_VERSION.to_string()),
            manifest: Some(SnapshotSourceManifest {
                contract_version: crate::snapshots::SNAPSHOT_MANIFEST_CONTRACT_VERSION,
                scope: crate::snapshots::SNAPSHOT_MANIFEST_SCOPE,
                source: "codex".to_string(),
                window_start: "2026-01-01T00:00:00Z".to_string(),
                window_end: "2026-07-03T00:00:00Z".to_string(),
                entity_count: 3,
                rolling_hash: "b".repeat(64),
            }),
        };
        let serialized = serde_json::to_string(&status).expect("serialize");
        assert!(!serialized.contains(".codex"));
        assert!(!serialized.contains("/Users/"));
    }

    fn entity_ref(session: &str, fingerprint: &str, occurrence_count: u64) -> SnapshotEntityRef {
        SnapshotEntityRef {
            source_session_id: session.to_string(),
            snapshot_fingerprint: fingerprint.to_string(),
            occurrence_count,
        }
    }

    fn entity_ack(
        accepted: u64,
        accepted_entities: Vec<SnapshotEntityRef>,
    ) -> SnapshotBatchResponse {
        SnapshotBatchResponse {
            accepted,
            sessions_reconciled: 0,
            session_ids: Vec::new(),
            disabled: false,
            disabled_reason: None,
            entity_ack_contract: Some(SNAPSHOT_ENTITY_ACK_CONTRACT.to_string()),
            accepted_entities,
            unchanged_entities: Vec::new(),
            rejected_entities: Vec::new(),
            conflict_entities: Vec::new(),
        }
    }

    #[test]
    fn disabled_batch_response_is_not_mistaken_for_a_partial_ack() {
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "codex".to_string(),
            machine_id: "machine".to_string(),
            collector_version: None,
            snapshots: Vec::new(),
            upload_policy: crate::snapshots::SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let mut response = entity_ack(0, Vec::new());
        response.disabled = true;
        response.disabled_reason = Some("disabled_by_admin".to_string());
        response
            .validate_entity_ack(&request)
            .expect("disabled response intentionally has no entity partition");

        response.accepted = 1;
        response
            .validate_entity_ack(&request)
            .expect_err("disabled response cannot settle an entity");
    }

    #[test]
    fn unknown_entity_ack_contract_never_falls_back_to_legacy_count_only_ack() {
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "codex".to_string(),
            machine_id: "machine".to_string(),
            collector_version: None,
            snapshots: Vec::new(),
            upload_policy: crate::snapshots::SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let mut response = entity_ack(0, Vec::new());
        response.entity_ack_contract = Some("snapshot_entity_ack:v999".to_string());
        response
            .validate_entity_ack(&request)
            .expect_err("future ACK shapes require explicit client support");
    }

    #[test]
    fn entity_ack_validates_reordered_duplicate_occurrences_as_a_multiset() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let response = entity_ack(
            3,
            vec![
                entity_ref("session-b", &second, 1),
                entity_ref("session-a", &first, 2),
            ],
        );
        response
            .validate_entity_ack_identities([
                ("session-a", first.as_str()),
                ("session-b", second.as_str()),
                ("session-a", first.as_str()),
            ])
            .expect("reordered duplicate occurrences are exact");
    }

    #[test]
    fn entity_ack_requires_one_compressed_outcome_per_identity() {
        let fingerprint = "a".repeat(64);
        let requested = [
            ("session", fingerprint.as_str()),
            ("session", fingerprint.as_str()),
        ];

        entity_ack(
            2,
            vec![
                entity_ref("session", &fingerprint, 1),
                entity_ref("session", &fingerprint, 1),
            ],
        )
        .validate_entity_ack_identities(requested)
        .expect_err("duplicate response entries are not a compressed outcome");

        entity_ack(2, vec![entity_ref("session", &fingerprint, 2)])
            .validate_entity_ack_identities(requested)
            .expect("one response entry may cover both requested occurrences");
    }

    #[test]
    fn entity_ack_allows_divergent_bodies_for_one_session_when_each_is_exact() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        entity_ack(
            2,
            vec![
                entity_ref("same-session", &first, 1),
                entity_ref("same-session", &second, 1),
            ],
        )
        .validate_entity_ack_identities([
            ("same-session", first.as_str()),
            ("same-session", second.as_str()),
        ])
        .expect("fingerprint keeps divergent revisions distinct");
    }

    #[test]
    fn entity_ack_rejects_partial_foreign_and_inconsistent_duplicate_counts() {
        let fingerprint = "a".repeat(64);
        let foreign = "b".repeat(64);
        assert!(entity_ack(1, vec![entity_ref("session", &fingerprint, 1)])
            .validate_entity_ack_identities([
                ("session", fingerprint.as_str()),
                ("session", fingerprint.as_str()),
            ])
            .is_err());
        assert!(entity_ack(2, vec![entity_ref("foreign", &foreign, 2)])
            .validate_entity_ack_identities([
                ("session", fingerprint.as_str()),
                ("session", fingerprint.as_str()),
            ])
            .is_err());

        let mut inconsistent = entity_ack(1, vec![entity_ref("session", &fingerprint, 1)]);
        inconsistent.unchanged_entities = vec![entity_ref("session", &fingerprint, 1)];
        inconsistent.accepted = 2;
        assert!(inconsistent
            .validate_entity_ack_identities([
                ("session", fingerprint.as_str()),
                ("session", fingerprint.as_str()),
            ])
            .is_err());
    }

    #[test]
    fn entity_ack_decodes_compressed_outcomes_across_all_classes() {
        let accepted = "a".repeat(64);
        let unchanged = "b".repeat(64);
        let rejected = "c".repeat(64);
        let conflict = "d".repeat(64);
        let response: SnapshotBatchResponse = serde_json::from_value(serde_json::json!({
            "accepted": 5,
            "sessions_reconciled": 0,
            "session_ids": [],
            "disabled": false,
            "disabled_reason": null,
            "entity_ack_contract": SNAPSHOT_ENTITY_ACK_CONTRACT,
            "accepted_entities": [{
                "source_session_id": "accepted-session",
                "snapshot_fingerprint": accepted,
                "occurrence_count": 2
            }],
            "unchanged_entities": [{
                "source_session_id": "unchanged-session",
                "snapshot_fingerprint": unchanged,
                "occurrence_count": 3
            }],
            "rejected_entities": [{
                "source_session_id": "rejected-session",
                "snapshot_fingerprint": rejected,
                "reason": "schema",
                "detail": "bounded",
                "permanent": true,
                "occurrence_count": 2
            }],
            "conflict_entities": [{
                "source_session_id": "conflict-session",
                "snapshot_fingerprint": conflict,
                "occurrence_count": 2
            }]
        }))
        .expect("decode compressed ACK");
        response
            .validate_entity_ack_identities(
                std::iter::repeat_n(("accepted-session", accepted.as_str()), 2)
                    .chain(std::iter::repeat_n(
                        ("unchanged-session", unchanged.as_str()),
                        3,
                    ))
                    .chain(std::iter::repeat_n(
                        ("rejected-session", rejected.as_str()),
                        2,
                    ))
                    .chain(std::iter::repeat_n(
                        ("conflict-session", conflict.as_str()),
                        2,
                    )),
            )
            .expect("identity-unique compressed outcomes cover the request exactly");
    }

    #[test]
    fn entity_ack_rejects_zero_and_overflow_occurrence_counts() {
        let fingerprint = "a".repeat(64);
        entity_ack(0, vec![entity_ref("session", &fingerprint, 0)])
            .validate_entity_ack_identities([("session", fingerprint.as_str())])
            .expect_err("zero occurrence count is invalid");

        let key = ("session".to_string(), fingerprint.clone());
        let requested = std::collections::BTreeMap::from([(key, u64::MAX)]);
        let mut covered = std::collections::BTreeMap::new();
        let mut classifications = std::collections::BTreeMap::new();
        record_snapshot_ack_occurrences(
            &requested,
            &mut covered,
            &mut classifications,
            "session",
            &fingerprint,
            u64::MAX,
            "accepted",
        )
        .expect("first count fits");
        record_snapshot_ack_occurrences(
            &requested,
            &mut covered,
            &mut classifications,
            "session",
            &fingerprint,
            1,
            "accepted",
        )
        .expect_err("occurrence sum overflow is rejected");
    }
}
