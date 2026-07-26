//! Codex daily aggregates, normalized to the `provider_daily_reference.v1`
//! upload contract.
//!
//! The capability is "verify Ottto against your provider's own numbers": an
//! accuracy and self-audit surface, not cloud sessions and not community-led.
//! With an explicit, versioned, revocable disclosure grant the collector reads
//! the customer's own Codex daily aggregate endpoint with the customer's own
//! already-issued credential, normalizes it locally to a closed struct of
//! scalars, and uploads only that struct over the existing relay-device
//! channel.
//!
//! Boundaries this module enforces, not merely documents:
//!
//! * **Scalars only.** Every string that crosses the upload boundary is a
//!   fixed literal, an opaque `hmac-sha256:` fingerprint, a UUID, an ISO date
//!   or timestamp, a closed surface enum, or a bounded lowercase model slug.
//!   `wire_payload_is_content_free` proves it, and a test drives poisoned
//!   provider text through the whole path.
//! * **Content endpoints are never contacted.** Only
//!   `wham/analytics/daily-workspace-usage-counts` is read. `wham/tasks/*`,
//!   `teleport-events`, and `/v1/sessions` are permanently out of scope.
//! * **The credential and the raw response body never leave the machine.**
//! * **Dark by default.** No grant, no sentinel-free support directory, no
//!   approved server policy, or an unadmitted collector version each stop the
//!   cycle before a socket is opened.

use anyhow::{anyhow, Context, Result};
use getrandom::fill as random_fill;
use hmac::{Hmac, Mac};
use ottto_core::{
    compiled_release_version, default_support_dir, FileAccountStore, FileConnectionStore,
    FileDeviceStore, LocalDeviceBinding,
};
use ottto_protocol::{AgentDiagnosticSeverity, AgentStatusDiagnostic, LocalAccountState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::thread;
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

// ---------------------------------------------------------------------------
// Contract identity - every value here is fixed by the backend contract
// ---------------------------------------------------------------------------

/// Wire schema of the upload contract.
pub const SCHEMA_VERSION: &str = "provider_daily_reference.v1";
/// Wire source. This collector reads Codex only.
pub const SOURCE: &str = "codex";
/// Wire collector id.
pub const COLLECTOR_ID: &str = "provider_daily_reference";
/// Versioned disclosure the grant is bound to.
pub const DISCLOSURE_VERSION: &str = "provider_daily_reference_disclosure.v1";
/// Release lane the server admits.
pub const RELEASE_LANE: &str = "supported";
/// Ack schema the backend answers a batch with.
const ACK_SCHEMA_VERSION: &str = "provider_daily_reference_ack.v1";
/// Provider days are UTC days. The contract pins this literal.
const PROVIDER_DAY_TIMEZONE: &str = "UTC";
/// Sentinel row model meaning "the surface total, not one model".
const ALL_MODELS: &str = "__all__";
/// Hard bound on one batch's declared coverage window.
const MAX_COVERAGE_DAYS: i64 = 200;
/// Hard bound on rows in one batch.
const MAX_ROWS_PER_BATCH: usize = 1_000;
/// How far back a full collection reaches. The provider window is ~120 days.
const LOOKBACK_DAYS: i64 = 120;

/// Local grant-file schema. Independent of the wire schema on purpose: the
/// on-disk shape may change without the contract changing.
const GRANT_FILE_SCHEMA_VERSION: &str = "codex_daily_aggregates_grant.v1";
const STATE_FILE_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Local operator surface - names an operator sees on disk
// ---------------------------------------------------------------------------

const GRANT_DIR: &str = "codex-daily-aggregates";
const GRANT_FILE: &str = "grant.json";
const STATE_FILE: &str = "state.json";
/// Presence disables the capability outright. Fixed contract with the macOS
/// Companion toggle, exactly like the Claude OAuth usage sentinel.
const SENTINEL_FILE: &str = "codex-daily-aggregates-disabled";

// ---------------------------------------------------------------------------
// Posture: honest identity, sparse polling, circuit break instead of adapt
// ---------------------------------------------------------------------------

const PROVIDER_ENDPOINT: &str =
    "https://chatgpt.com/backend-api/wham/analytics/daily-workspace-usage-counts";
/// Day-grain data does not reward frequent polling. Six hours with a modest
/// deterministic spread across our own installs.
const FETCH_INTERVAL_SECONDS: u64 = 6 * 60 * 60;
const FETCH_INTERVAL_JITTER_SECONDS: u64 = 15 * 60;
/// Supervisor tick. The cadence gate above does the real limiting; the short
/// tick only means a grant created after boot activates without a restart.
const POLL_INTERVAL: Duration = Duration::from_secs(30 * 60);
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(20);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(20);

const BREAKER_COOLDOWN_SECONDS: u64 = 24 * 60 * 60;
const BREAKER_AUTH_THRESHOLD: u32 = 3;
const BREAKER_SHAPE_THRESHOLD: u32 = 3;
const BREAKER_RATE_LIMIT_THRESHOLD: u32 = 5;

const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const LEGACY_API_BASE_URL: &str = "https://ottto.net/backend";

static COLLECTOR_SUPERVISOR_STARTED: AtomicBool = AtomicBool::new(false);

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Closed surface vocabulary
// ---------------------------------------------------------------------------

/// The closed surface enum of the upload contract.
///
/// The daemon never invents a surface value. A provider `client_id` it does
/// not recognize maps to [`Surface::Other`]; `CODEX_UNKNOWN_DEFAULT` is the
/// provider's *own* unknown bucket and keeps its own slot so "the provider
/// could not attribute this" stays distinguishable from "Ottto has never seen
/// this client id".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    CodexWeb,
    CodexDesktopApp,
    CodexServiceExec,
    CodexWorkDesktop,
    CodexUnknownDefault,
    Other,
}

impl Surface {
    pub fn wire(self) -> &'static str {
        match self {
            Surface::CodexWeb => "codex_web",
            Surface::CodexDesktopApp => "codex_desktop_app",
            Surface::CodexServiceExec => "codex_service_exec",
            Surface::CodexWorkDesktop => "codex_work_desktop",
            Surface::CodexUnknownDefault => "codex_unknown_default",
            Surface::Other => "other",
        }
    }
}

/// Map a provider `client_id` onto the closed surface enum, locally.
///
/// Matching is case-insensitive and ignores surrounding whitespace because the
/// provider's own casing is not a contract. Anything unrecognized is `other`.
pub fn surface_for_client_id(client_id: &str) -> Surface {
    match client_id.trim().to_ascii_uppercase().as_str() {
        "CODEX_WEB" => Surface::CodexWeb,
        "CODEX_DESKTOP_APP" => Surface::CodexDesktopApp,
        "CODEX_SERVICE_EXEC" => Surface::CodexServiceExec,
        "CODEX_WORK_DESKTOP" => Surface::CodexWorkDesktop,
        "CODEX_UNKNOWN_DEFAULT" => Surface::CodexUnknownDefault,
        _ => Surface::Other,
    }
}

/// Normalize a provider model identifier to the contract's bounded slug, or
/// refuse it.
///
/// The contract pattern is `^(__all__|[a-z0-9][a-z0-9._-]{0,63})$`. Characters
/// outside the alphabet become `-` so an ordinary vendor id survives, but a
/// value that cannot begin with an alphanumeric, or that is empty, is refused
/// rather than coerced: the surface total row already carries the numbers, so
/// dropping an unrepresentable model loses nothing comparable and inventing a
/// slug would be a fabricated identifier.
pub fn normalized_model_slug(raw: &str) -> Option<String> {
    let lowered = raw.trim().to_ascii_lowercase();
    if lowered.is_empty() || lowered == ALL_MODELS {
        return None;
    }
    let mut slug = String::with_capacity(lowered.len().min(64));
    for character in lowered.chars() {
        if slug.len() == 64 {
            break;
        }
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            slug.push(character);
        } else {
            slug.push('-');
        }
    }
    let first = slug.chars().next()?;
    if !first.is_ascii_alphanumeric() {
        return None;
    }
    Some(slug)
}

// ---------------------------------------------------------------------------
// Wire structs - the only shapes that may be serialized toward the backend
// ---------------------------------------------------------------------------

/// One provider-reported day at `(surface, model)` grain.
///
/// Every counter is `Option` because "the provider did not report this
/// counter" and "the provider reported zero" are different facts. Collapsing
/// them would manufacture a reconciliation delta, so an absent counter is
/// omitted from the payload rather than sent as `0`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DailyReferenceRow {
    pub provider_day: String,
    pub surface: &'static str,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credits_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_count: Option<u64>,
}

/// One bounded upload of provider-reported day aggregates.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DailyReferenceBatch {
    pub schema_version: &'static str,
    pub source: &'static str,
    pub collector_id: &'static str,
    pub collector_version: String,
    pub installation_id: String,
    pub grant_scope_fingerprint: String,
    pub account_fingerprint: String,
    pub grant_version: u64,
    pub provider_day_timezone: &'static str,
    pub coverage_start: String,
    pub coverage_end: String,
    pub collected_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_data_refreshed_at: Option<String>,
    pub rows: Vec<DailyReferenceRow>,
}

/// The exact key set the batch envelope may carry. Pinned so a future field
/// cannot be added without failing `wire_key_sets_match_the_contract`.
const BATCH_KEYS: &[&str] = &[
    "schema_version",
    "source",
    "collector_id",
    "collector_version",
    "installation_id",
    "grant_scope_fingerprint",
    "account_fingerprint",
    "grant_version",
    "provider_day_timezone",
    "coverage_start",
    "coverage_end",
    "collected_at",
    "provider_data_refreshed_at",
    "rows",
];

/// The exact key set one row may carry.
const ROW_KEYS: &[&str] = &[
    "provider_day",
    "surface",
    "model",
    "credits_used",
    "uncached_input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "total_tokens",
    "thread_count",
    "turn_count",
];

// ---------------------------------------------------------------------------
// Grant: versioned, revocable, credential-free consent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Off,
    ConsentRequired,
    Enabled,
    Revoked,
}

/// Server policy for this grant. Defaults closed so a binding written before
/// the field existed can never be read as approval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerPolicyState {
    Approved,
    #[default]
    Disabled,
    RolloutDisabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendGrantBinding {
    pub grant_id: String,
    pub grant_version: u64,
    #[serde(default)]
    pub backend_revoked: bool,
    #[serde(default)]
    pub server_policy_state: ServerPolicyState,
}

/// Local consent record. It holds fingerprints only: the raw installation id,
/// the tenant scopes, and the provider account id are never written to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DailyReferenceGrant {
    pub schema_version: String,
    pub source: String,
    pub collector_id: String,
    /// Server-owned. Only [`GrantStore::bind_backend_grant`] writes it, and a
    /// binary whose release version differs is refused at runtime.
    pub collector_version: String,
    pub release_lane: String,
    pub disclosure_version: String,
    pub status: GrantStatus,
    pub installation_fingerprint: String,
    pub grant_scope_fingerprint: String,
    pub account_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_binding: Option<BackendGrantBinding>,
    #[serde(default)]
    pub backend_create_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_category: Option<String>,
}

/// The raw scopes consent is taken over. Held in memory only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSetup {
    /// Relay device id. Equals the wire `installation_id`.
    pub installation_id: String,
    pub organization_scope: String,
    pub effective_user_scope: String,
    /// The provider account the consent covers. Two Codex accounts on one
    /// machine are two grants, and the backend judges freshness per grant.
    pub provider_account_scope: String,
}

/// What the Companion posts to `POST /api/v1/provider-daily-reference/grants`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantCreateRequest {
    pub installation_id: String,
    pub source: &'static str,
    pub collector_id: &'static str,
    pub schema_version: &'static str,
    pub collector_version: String,
    pub disclosure_version: &'static str,
    pub grant_scope_fingerprint: String,
    pub account_fingerprint: String,
    pub consent: bool,
}

/// The subset of the backend grant response the daemon binds against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantResponse {
    pub id: String,
    pub installation_id: String,
    pub source: String,
    pub collector_id: String,
    pub schema_version: String,
    pub collector_version: String,
    pub release_lane: String,
    pub disclosure_version: String,
    pub grant_scope_fingerprint: String,
    pub account_fingerprint: String,
    pub status: String,
    pub grant_version: u64,
    #[serde(default)]
    pub server_policy_state: ServerPolicyState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedGrant {
    schema_version: String,
    hmac_key_hex: String,
    grant: DailyReferenceGrant,
}

/// Consent store. One grant per installation, held under the support dir.
#[derive(Debug, Clone)]
pub struct GrantStore {
    path: PathBuf,
}

impl Default for GrantStore {
    fn default() -> Self {
        Self::new(default_support_dir().join(GRANT_DIR).join(GRANT_FILE))
    }
}

impl GrantStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<Option<PersistedGrant>> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("read codex daily aggregates grant"),
        };
        let state: PersistedGrant = match serde_json::from_str(&raw) {
            Ok(state) => state,
            // An unreadable or superseded grant file is not consent. Refuse it
            // rather than repairing it into something that looks live.
            Err(_) => return Ok(None),
        };
        if state.schema_version != GRANT_FILE_SCHEMA_VERSION {
            return Ok(None);
        }
        if !matches!(decode_hex(&state.hmac_key_hex), Some(key) if key.len() == 32) {
            return Ok(None);
        }
        Ok(Some(state))
    }

    pub fn load(&self) -> Result<Option<DailyReferenceGrant>> {
        Ok(self.read()?.map(|state| state.grant))
    }

    /// Derive the account fingerprint for a raw provider account id under this
    /// installation's key, so the caller can prove the live credential is the
    /// one consent was taken over.
    pub fn account_fingerprint_for(&self, provider_account_scope: &str) -> Result<Option<String>> {
        let Some(state) = self.read()? else {
            return Ok(None);
        };
        let key = decode_hex(&state.hmac_key_hex).ok_or_else(|| anyhow!("grant key is invalid"))?;
        Ok(Some(opaque_key(&key, provider_account_scope)))
    }

    /// Derive the installation fingerprint for a raw relay device id.
    pub fn installation_fingerprint_for(&self, installation_id: &str) -> Result<Option<String>> {
        let Some(state) = self.read()? else {
            return Ok(None);
        };
        let key = decode_hex(&state.hmac_key_hex).ok_or_else(|| anyhow!("grant key is invalid"))?;
        Ok(Some(opaque_key(&key, installation_id)))
    }

    /// Record local consent. The grant is not live until the backend binds it:
    /// `collector_version` stays empty and `backend_create_pending` is set, so
    /// [`grant_runtime_ready`] refuses it.
    pub fn enable(&self, setup: &GrantSetup, now: OffsetDateTime) -> Result<DailyReferenceGrant> {
        if !is_uuid(&setup.installation_id) {
            return Err(anyhow!("installation id is not a device uuid"));
        }
        if setup.organization_scope.trim().is_empty()
            || setup.effective_user_scope.trim().is_empty()
            || setup.provider_account_scope.trim().is_empty()
        {
            return Err(anyhow!("grant scopes are incomplete"));
        }
        // Reuse an existing key so re-consent under the same installation keeps
        // stable fingerprints; mint one on first consent.
        let key = match self.read()? {
            Some(state) => decode_hex(&state.hmac_key_hex)
                .ok_or_else(|| anyhow!("stored grant key is invalid"))?,
            None => random_key()?,
        };
        let grant = DailyReferenceGrant {
            schema_version: SCHEMA_VERSION.to_string(),
            source: SOURCE.to_string(),
            collector_id: COLLECTOR_ID.to_string(),
            collector_version: String::new(),
            release_lane: RELEASE_LANE.to_string(),
            disclosure_version: DISCLOSURE_VERSION.to_string(),
            status: GrantStatus::ConsentRequired,
            installation_fingerprint: opaque_key(&key, &setup.installation_id),
            grant_scope_fingerprint: grant_scope_fingerprint(&key, setup),
            account_fingerprint: opaque_key(&key, &setup.provider_account_scope),
            backend_binding: None,
            backend_create_pending: true,
            granted_at: Some(timestamp(now)),
            revoked_at: None,
            last_success_at: None,
            last_error_category: None,
        };
        let state = PersistedGrant {
            schema_version: GRANT_FILE_SCHEMA_VERSION.to_string(),
            hmac_key_hex: hex(&key),
            grant: grant.clone(),
        };
        atomic_json_write(&self.path, &state)?;
        Ok(grant)
    }

    /// Build the create request the Companion posts. The raw installation id is
    /// supplied by the caller and is never read back from disk.
    pub fn grant_create_request(&self, installation_id: &str) -> Result<GrantCreateRequest> {
        let state = self
            .read()?
            .ok_or_else(|| anyhow!("codex daily aggregates consent is absent"))?;
        let key = decode_hex(&state.hmac_key_hex)
            .ok_or_else(|| anyhow!("stored grant key is invalid"))?;
        if opaque_key(&key, installation_id) != state.grant.installation_fingerprint {
            return Err(anyhow!(
                "installation id does not match the recorded consent"
            ));
        }
        Ok(GrantCreateRequest {
            installation_id: installation_id.to_string(),
            source: SOURCE,
            collector_id: COLLECTOR_ID,
            schema_version: SCHEMA_VERSION,
            collector_version: compiled_release_version(),
            disclosure_version: DISCLOSURE_VERSION,
            grant_scope_fingerprint: state.grant.grant_scope_fingerprint.clone(),
            account_fingerprint: state.grant.account_fingerprint.clone(),
            consent: true,
        })
    }

    /// Bind the server's answer. This is the only writer of `collector_version`
    /// and of the backend binding: the server owns admission, the client only
    /// compares the answer to its own release.
    pub fn bind_backend_grant(
        &self,
        response: &GrantResponse,
        expected_installation_id: &str,
    ) -> Result<DailyReferenceGrant> {
        let mut state = self
            .read()?
            .ok_or_else(|| anyhow!("codex daily aggregates consent is absent"))?;
        let key = decode_hex(&state.hmac_key_hex)
            .ok_or_else(|| anyhow!("stored grant key is invalid"))?;
        if opaque_key(&key, expected_installation_id) != state.grant.installation_fingerprint {
            return Err(anyhow!(
                "installation id does not match the recorded consent"
            ));
        }
        validate_grant_response(&state.grant, response, expected_installation_id)?;
        let previous_version = state
            .grant
            .backend_binding
            .as_ref()
            .map(|binding| binding.grant_version)
            .unwrap_or(0);
        if response.grant_version <= previous_version {
            return Err(anyhow!(
                "backend grant epoch did not advance past the recorded epoch"
            ));
        }
        let revoked = response.status == "revoked";
        state.grant.collector_version = response.collector_version.clone();
        state.grant.backend_binding = Some(BackendGrantBinding {
            grant_id: response.id.clone(),
            grant_version: response.grant_version,
            backend_revoked: revoked,
            server_policy_state: response.server_policy_state,
        });
        state.grant.backend_create_pending = false;
        state.grant.status = if revoked {
            GrantStatus::Revoked
        } else {
            GrantStatus::Enabled
        };
        state.grant.granted_at = Some(timestamp(OffsetDateTime::now_utc()));
        // A new epoch never inherits the previous epoch's evidence.
        state.grant.last_success_at = None;
        state.grant.last_error_category = None;
        atomic_json_write(&self.path, &state)?;
        Ok(state.grant)
    }

    pub fn revoke(&self, now: OffsetDateTime) -> Result<()> {
        let Some(mut state) = self.read()? else {
            return Ok(());
        };
        state.grant.status = GrantStatus::Revoked;
        state.grant.revoked_at = Some(timestamp(now));
        if let Some(binding) = state.grant.backend_binding.as_mut() {
            binding.backend_revoked = true;
        }
        atomic_json_write(&self.path, &state)
    }

    /// Record collector health. Never resurrects a non-enabled grant.
    fn record_health(&self, success_at: Option<&str>, error_category: Option<&str>) -> Result<()> {
        let Some(mut state) = self.read()? else {
            return Ok(());
        };
        if state.grant.status != GrantStatus::Enabled {
            return Ok(());
        }
        if let Some(success_at) = success_at {
            state.grant.last_success_at = Some(success_at.to_string());
        }
        state.grant.last_error_category = error_category.map(|value| value.to_string());
        atomic_json_write(&self.path, &state)
    }
}

fn validate_grant_response(
    grant: &DailyReferenceGrant,
    response: &GrantResponse,
    expected_installation_id: &str,
) -> Result<()> {
    if response.installation_id != expected_installation_id
        || response.source != SOURCE
        || response.collector_id != COLLECTOR_ID
        || response.schema_version != SCHEMA_VERSION
        || response.release_lane != RELEASE_LANE
        || response.disclosure_version != DISCLOSURE_VERSION
        || response.grant_scope_fingerprint != grant.grant_scope_fingerprint
        || response.account_fingerprint != grant.account_fingerprint
        || !is_uuid(&response.id)
        || response.grant_version == 0
        || !matches!(response.status.as_str(), "enabled" | "revoked")
    {
        return Err(anyhow!(
            "backend grant response does not match the recorded consent"
        ));
    }
    Ok(())
}

/// The single answer to "may this build collect right now".
///
/// Note the `collector_version` check: the server states which build it
/// admitted, and a daemon upgrade therefore makes the stored grant ineligible
/// until the customer re-consents on the new build. Consent is per build.
pub fn grant_runtime_ready(grant: &DailyReferenceGrant) -> bool {
    grant.status == GrantStatus::Enabled
        && grant.schema_version == SCHEMA_VERSION
        && grant.source == SOURCE
        && grant.collector_id == COLLECTOR_ID
        && grant.disclosure_version == DISCLOSURE_VERSION
        && grant.collector_version == compiled_release_version()
        && !grant.backend_create_pending
        && grant.backend_binding.as_ref().is_some_and(|binding| {
            !binding.backend_revoked
                && binding.server_policy_state == ServerPolicyState::Approved
                && binding.grant_version >= 1
        })
}

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

fn sentinel_path() -> PathBuf {
    default_support_dir().join(SENTINEL_FILE)
}

/// Presence of the sentinel disables the capability. Absent is the default and
/// is not by itself permission: the grant still has to be live.
pub fn network_disabled() -> bool {
    sentinel_path().is_file()
}

// ---------------------------------------------------------------------------
// Collector state: cadence, circuit breaker, covered window
// ---------------------------------------------------------------------------

/// Failure classes that open the breaker. Transport errors and 5xx are absent
/// on purpose: they say the network or the vendor had a bad moment, not that
/// we should stop asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailure {
    AuthRejected,
    ResponseShape,
    RateLimited,
}

impl ProviderFailure {
    pub fn code(self) -> &'static str {
        match self {
            ProviderFailure::AuthRejected => "auth_rejected",
            ProviderFailure::ResponseShape => "response_shape_changed",
            ProviderFailure::RateLimited => "rate_limited",
        }
    }

    fn threshold(self) -> u32 {
        match self {
            ProviderFailure::AuthRejected => BREAKER_AUTH_THRESHOLD,
            ProviderFailure::ResponseShape => BREAKER_SHAPE_THRESHOLD,
            ProviderFailure::RateLimited => BREAKER_RATE_LIMIT_THRESHOLD,
        }
    }
}

/// Why a provider read did not produce a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderReadError {
    /// 401/403 - the credential no longer authorizes this read.
    AuthRejected(u16),
    /// The answer is not the shape we normalize: unreadable body, no day rows,
    /// or a status that says the route moved (400/404/410).
    ResponseShape(String),
    /// 429 beyond ordinary politeness.
    RateLimited,
    /// 5xx and transport failures. Never counted against the breaker.
    Transient(String),
}

impl ProviderReadError {
    fn failure_class(&self) -> Option<ProviderFailure> {
        match self {
            ProviderReadError::AuthRejected(_) => Some(ProviderFailure::AuthRejected),
            ProviderReadError::ResponseShape(_) => Some(ProviderFailure::ResponseShape),
            ProviderReadError::RateLimited => Some(ProviderFailure::RateLimited),
            ProviderReadError::Transient(_) => None,
        }
    }

    fn category(&self) -> &'static str {
        match self {
            ProviderReadError::AuthRejected(_) => "provider_auth_rejected",
            ProviderReadError::ResponseShape(_) => "provider_response_shape",
            ProviderReadError::RateLimited => "provider_rate_limited",
            ProviderReadError::Transient(_) => "provider_unavailable",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct CollectorState {
    schema_version: u16,
    #[serde(default)]
    identity: String,
    #[serde(default)]
    last_fetch_epoch_seconds: u64,
    #[serde(default)]
    last_success_epoch_seconds: u64,
    #[serde(default)]
    auth_failures: u32,
    #[serde(default)]
    shape_failures: u32,
    #[serde(default)]
    rate_limit_failures: u32,
    #[serde(default)]
    reopen_after_epoch_seconds: u64,
    #[serde(default)]
    opened_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error_category: Option<String>,
}

/// Cadence and breaker state, keyed to one grant epoch.
#[derive(Debug, Clone)]
pub struct StateStore {
    path: PathBuf,
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new(default_support_dir().join(GRANT_DIR).join(STATE_FILE))
    }
}

impl StateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load state for this grant epoch. Any change to the account, the endpoint
    /// configuration, or the consent epoch reads as a clean slate, so a prior
    /// verdict never carries across a change the customer made.
    fn load(&self, identity: &str) -> CollectorState {
        let Ok(raw) = fs::read_to_string(&self.path) else {
            return CollectorState::default();
        };
        let Ok(state) = serde_json::from_str::<CollectorState>(&raw) else {
            return CollectorState::default();
        };
        if state.schema_version != STATE_FILE_SCHEMA_VERSION || state.identity != identity {
            return CollectorState::default();
        }
        state
    }

    fn save(&self, state: &CollectorState) -> Result<()> {
        atomic_json_write(&self.path, state)
    }

    fn clear(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Identity the breaker and cadence are keyed by: the grant epoch plus the
/// call's own configuration.
fn state_identity(grant: &DailyReferenceGrant, sentinel_disabled: bool) -> String {
    let binding = grant
        .backend_binding
        .as_ref()
        .map(|binding| (binding.grant_id.as_str(), binding.grant_version))
        .unwrap_or(("", 0));
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:codex-daily-aggregates-identity:");
    for part in [
        grant.account_fingerprint.as_str(),
        grant.grant_scope_fingerprint.as_str(),
        binding.0,
        &binding.1.to_string(),
        PROVIDER_ENDPOINT,
        &crate::agent_status::ottto_user_agent(),
        if sentinel_disabled { "off" } else { "on" },
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0_u8]);
    }
    hex(&hasher.finalize())[..32].to_string()
}

fn breaker_is_open(state: &CollectorState, now: u64) -> bool {
    now < state.reopen_after_epoch_seconds
}

/// Fold one failure into the breaker. Pure so the thresholds are testable
/// without a network or a clock.
fn state_after_failure(
    mut state: CollectorState,
    identity: &str,
    failure: ProviderFailure,
    category: &str,
    now: u64,
) -> CollectorState {
    state.schema_version = STATE_FILE_SCHEMA_VERSION;
    state.identity = identity.to_string();
    state.last_error_category = Some(category.to_string());
    let counter = match failure {
        ProviderFailure::AuthRejected => &mut state.auth_failures,
        ProviderFailure::ResponseShape => &mut state.shape_failures,
        ProviderFailure::RateLimited => &mut state.rate_limit_failures,
    };
    *counter = counter.saturating_add(1);
    if *counter >= failure.threshold() && !breaker_is_open(&state, now) {
        state.reopen_after_epoch_seconds = now.saturating_add(BREAKER_COOLDOWN_SECONDS);
        state.opened_by = failure.code().to_string();
    }
    state
}

/// Clear the failure counters after one clean answer. The thresholds are about
/// *consecutive* failures.
fn state_after_success(mut state: CollectorState, identity: &str, now: u64) -> CollectorState {
    state.schema_version = STATE_FILE_SCHEMA_VERSION;
    state.identity = identity.to_string();
    state.auth_failures = 0;
    state.shape_failures = 0;
    state.rate_limit_failures = 0;
    state.reopen_after_epoch_seconds = 0;
    state.opened_by = String::new();
    state.last_error_category = None;
    state.last_success_epoch_seconds = now;
    state
}

/// Deterministic 5h45m-6h15m gate.
///
/// The spread is load-spreading across our own installs so every Ottto machine
/// does not wake on the same wall-clock minute. It is derived from the grant
/// identity rather than redrawn per tick, so a machine holds one steady phase,
/// and it hides nothing: the request identifies itself honestly and a
/// timer-driven daemon is recognizable from its behaviour regardless of phase.
fn fetch_interval_seconds(identity: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:codex-daily-aggregates-cadence:");
    hasher.update(identity.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let span = FETCH_INTERVAL_JITTER_SECONDS * 2 + 1;
    let offset = u64::from_be_bytes(bytes) % span;
    FETCH_INTERVAL_SECONDS + offset - FETCH_INTERVAL_JITTER_SECONDS
}

fn fetch_due(state: &CollectorState, identity: &str, now: u64) -> bool {
    now.saturating_sub(state.last_fetch_epoch_seconds) >= fetch_interval_seconds(identity)
}

// ---------------------------------------------------------------------------
// Provider read
// ---------------------------------------------------------------------------

/// Read one bounded day window from the provider.
pub trait ProviderDailyUsageReader {
    fn fetch_window(&self, start_date: &str, end_date: &str) -> Result<Value, ProviderReadError>;
}

/// The Codex credential this read uses. The daemon reads the customer's own
/// already-issued token from their own `~/.codex/auth.json`; it never mints,
/// refreshes, or stores one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexCredential {
    pub access_token: String,
    pub account_id: Option<String>,
    /// Stable scope the grant's account fingerprint is derived from.
    pub account_scope: String,
}

/// The one provider route this capability may contact.
pub struct ChatGptDailyUsageReader {
    credential: CodexCredential,
}

impl ChatGptDailyUsageReader {
    pub fn new(credential: CodexCredential) -> Self {
        Self { credential }
    }
}

impl ProviderDailyUsageReader for ChatGptDailyUsageReader {
    fn fetch_window(&self, start_date: &str, end_date: &str) -> Result<Value, ProviderReadError> {
        // `workspace_user=true` scopes the answer to the signed-in user's own
        // usage. Without it a workspace member could be handed workspace-wide
        // numbers, which would be compared against one user's Ottto totals.
        let url = format!(
            "{PROVIDER_ENDPOINT}?start_date={start_date}&end_date={end_date}&group_by=day&workspace_user=true"
        );
        let mut request = ureq::get(&url)
            .timeout(PROVIDER_TIMEOUT)
            .set("Accept", "application/json")
            // Be trivially identifiable and trivially benign. Never a
            // provider-client User-Agent.
            .set("User-Agent", &crate::agent_status::ottto_user_agent())
            .set(
                "Authorization",
                &format!("Bearer {}", self.credential.access_token),
            );
        if let Some(account_id) = self.credential.account_id.as_deref() {
            request = request.set("ChatGPT-Account-Id", account_id);
        }
        match request.call() {
            Ok(response) => response
                .into_json::<Value>()
                .map_err(|error| ProviderReadError::ResponseShape(format!("unreadable: {error}"))),
            Err(ureq::Error::Status(status @ (401 | 403), _response)) => {
                Err(ProviderReadError::AuthRejected(status))
            }
            Err(ureq::Error::Status(429, _response)) => Err(ProviderReadError::RateLimited),
            Err(ureq::Error::Status(status @ (400 | 404 | 410), _response)) => Err(
                ProviderReadError::ResponseShape(format!("unexpected status {status}")),
            ),
            Err(ureq::Error::Status(status, _response)) => Err(ProviderReadError::Transient(
                format!("provider status {status}"),
            )),
            Err(_) => Err(ProviderReadError::Transient("transport error".to_string())),
        }
    }
}

/// Read the customer's own Codex credential.
///
/// This mirrors the credential mechanics of the existing `wham/usage` read: the
/// already-issued access token and account id from `~/.codex/auth.json`. The
/// token is used for exactly one request and is never persisted or logged.
pub fn read_codex_credential() -> Option<CodexCredential> {
    let path = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join(".codex")
        .join("auth.json");
    let raw = fs::read_to_string(path).ok()?;
    let json: Value = serde_json::from_str(&raw).ok()?;
    codex_credential_from_auth(&json)
}

fn codex_credential_from_auth(json: &Value) -> Option<CodexCredential> {
    let access_token = json
        .pointer("/tokens/access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let account_id = ["account_id", "chatgpt_account_id"]
        .iter()
        .find_map(|key| {
            json.get(*key).and_then(Value::as_str).or_else(|| {
                json.pointer(&format!("/tokens/{key}"))
                    .and_then(Value::as_str)
            })
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    // The account scope must identify the provider account, not the token: a
    // token rotation must not read as a different account and invalidate the
    // customer's consent.
    let account_scope = account_id.clone().or_else(|| {
        json.pointer("/tokens/id_token")
            .and_then(Value::as_str)
            .and_then(id_token_account_scope)
    })?;
    Some(CodexCredential {
        access_token: access_token.to_string(),
        account_id,
        account_scope,
    })
}

/// Pull the ChatGPT account claim out of an id token, without verifying it: it
/// is used only as a local, stable account scope that is immediately hashed.
fn id_token_account_scope(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let decoded = base64_url_decode(payload)?;
    let json: Value = serde_json::from_slice(&decoded).ok()?;
    let auth = json.get("https://api.openai.com/auth")?;
    ["chatgpt_account_id", "chatgpt_user_id"]
        .iter()
        .find_map(|key| auth.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn base64_url_decode(value: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut accumulator: u32 = 0;
    let mut bits = 0_u32;
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    for byte in value.bytes() {
        if byte == b'=' {
            break;
        }
        let index = ALPHABET.iter().position(|candidate| *candidate == byte)? as u32;
        accumulator = (accumulator << 6) | index;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// A counter merge that preserves "not reported".
///
/// Two provider client ids can collapse onto the same local surface (every
/// unrecognized id becomes `other`), so their rows have to combine. `None`
/// means the provider did not report the counter, so it contributes nothing
/// and never turns a reported value back into "not reported".
fn merge_counter(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => Some(left.saturating_add(right)),
    }
}

fn merge_credits(left: Option<f64>, right: Option<f64>) -> Option<f64> {
    match (left, right) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => Some(left + right),
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Counters {
    credits_used: Option<f64>,
    uncached_input_tokens: Option<u64>,
    cached_input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    thread_count: Option<u64>,
    turn_count: Option<u64>,
}

impl Counters {
    fn merge(&mut self, other: &Counters) {
        self.credits_used = merge_credits(self.credits_used, other.credits_used);
        self.uncached_input_tokens =
            merge_counter(self.uncached_input_tokens, other.uncached_input_tokens);
        self.cached_input_tokens =
            merge_counter(self.cached_input_tokens, other.cached_input_tokens);
        self.output_tokens = merge_counter(self.output_tokens, other.output_tokens);
        self.total_tokens = merge_counter(self.total_tokens, other.total_tokens);
        self.thread_count = merge_counter(self.thread_count, other.thread_count);
        self.turn_count = merge_counter(self.turn_count, other.turn_count);
    }

    fn is_empty(&self) -> bool {
        *self == Counters::default()
    }
}

/// Read a non-negative integer counter, only when the provider actually
/// reported it. A present-but-unreadable value stays `None` rather than
/// becoming `0`.
fn counter_at(value: &Value, keys: &[&str]) -> Option<u64> {
    let raw = keys.iter().find_map(|key| value.get(*key))?;
    match raw {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_f64().filter(|v| *v >= 0.0).map(|v| v as u64)),
        _ => None,
    }
}

fn credits_at(value: &Value, keys: &[&str]) -> Option<f64> {
    let raw = keys.iter().find_map(|key| value.get(*key))?;
    raw.as_f64().filter(|value| *value >= 0.0)
}

fn counters_at(value: &Value, include_credits: bool) -> Counters {
    Counters {
        credits_used: include_credits
            .then(|| credits_at(value, &["credits"]))
            .flatten(),
        uncached_input_tokens: counter_at(
            value,
            &["uncached_text_input_tokens", "uncached_input_tokens"],
        ),
        cached_input_tokens: counter_at(
            value,
            &["cached_text_input_tokens", "cached_input_tokens"],
        ),
        output_tokens: counter_at(value, &["text_output_tokens", "output_tokens"]),
        total_tokens: counter_at(value, &["text_total_tokens", "total_tokens"]),
        thread_count: counter_at(value, &["threads", "thread_count"]),
        turn_count: counter_at(value, &["turns", "turn_count"]),
    }
}

fn first_array<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Vec<Value>> {
    if let Value::Array(items) = value {
        return Some(items);
    }
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_array))
}

fn first_string<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Accept only a plain `YYYY-MM-DD` UTC day, or the date part of a timestamp.
fn provider_day(raw: &str) -> Option<String> {
    let candidate = raw.trim();
    let day = candidate.split(['T', ' ']).next()?;
    let bytes = day.as_bytes();
    if bytes.len() != 10 {
        return None;
    }
    let shaped = bytes.iter().enumerate().all(|(index, byte)| match index {
        4 | 7 => *byte == b'-',
        _ => byte.is_ascii_digit(),
    });
    if !shaped {
        return None;
    }
    // Reject an impossible day rather than uploading it as a provider fact.
    parse_day(day)?;
    Some(day.to_string())
}

/// What one provider window normalized to.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NormalizedWindow {
    pub rows: Vec<DailyReferenceRow>,
    pub provider_data_refreshed_at: Option<String>,
    /// Model identifiers the contract's slug cannot represent. Counted, never
    /// coerced, and never uploaded.
    pub dropped_model_rows: usize,
}

/// Normalize a provider payload into contract rows.
///
/// Only counters, a closed surface value, a bounded model slug and a UTC day
/// survive. Everything else in the payload - ids, labels, names, links, free
/// text of any kind - is dropped here and never reaches a struct that can be
/// serialized toward the backend.
pub fn normalize_provider_window(
    payload: &Value,
    coverage_start: &str,
    coverage_end: &str,
) -> Result<NormalizedWindow, ProviderReadError> {
    let days = first_array(
        payload,
        &[
            "results", "data", "days", "daily", "buckets", "items", "usage",
        ],
    )
    .ok_or_else(|| ProviderReadError::ResponseShape("no day rows in payload".to_string()))?;

    let refreshed_at = first_string(
        payload,
        &[
            "data_refreshed_at",
            "refreshed_at",
            "last_refreshed_at",
            "updated_at",
        ],
    )
    .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
    .map(timestamp);

    let mut grouped: BTreeMap<(String, Surface, String), Counters> = BTreeMap::new();
    let mut dropped_model_rows = 0_usize;
    let mut recognized_days = 0_usize;

    for day in days {
        let Some(day_key) = first_string(
            day,
            &["date", "day", "usage_date", "bucket_start", "start_date"],
        )
        .and_then(provider_day) else {
            continue;
        };
        recognized_days += 1;
        // A provider day outside the window we asked for is not evidence for
        // this batch; the contract rejects it and so do we.
        if day_key.as_str() < coverage_start || day_key.as_str() > coverage_end {
            continue;
        }
        let Some(clients) = first_array(
            day,
            &[
                "clients",
                "client_breakdown",
                "by_client",
                "per_client",
                "client_counts",
                "breakdown",
            ],
        ) else {
            continue;
        };
        for client in clients {
            let Some(client_id) = first_string(client, &["client_id", "client", "id", "name"])
            else {
                continue;
            };
            let surface = surface_for_client_id(client_id);
            let surface_counters = counters_at(client, true);
            if !surface_counters.is_empty() {
                grouped
                    .entry((day_key.clone(), surface, ALL_MODELS.to_string()))
                    .or_default()
                    .merge(&surface_counters);
            }
            let Some(models) = first_array(
                client,
                &["models", "model_breakdown", "by_model", "per_model"],
            ) else {
                continue;
            };
            for model in models {
                let Some(raw_model) =
                    first_string(model, &["model", "model_id", "model_slug", "name"])
                else {
                    continue;
                };
                let Some(slug) = normalized_model_slug(raw_model) else {
                    dropped_model_rows += 1;
                    continue;
                };
                // The provider reports 0.0 for per-model credits, which is not
                // a real attribution. Per-model rows carry tokens, threads and
                // turns only; the surface row carries the metered credits.
                let model_counters = counters_at(model, false);
                if model_counters.is_empty() {
                    continue;
                }
                grouped
                    .entry((day_key.clone(), surface, slug))
                    .or_default()
                    .merge(&model_counters);
            }
        }
    }

    if recognized_days == 0 {
        return Err(ProviderReadError::ResponseShape(
            "no recognizable provider day in payload".to_string(),
        ));
    }

    let rows = grouped
        .into_iter()
        .map(|((day, surface, model), counters)| DailyReferenceRow {
            provider_day: day,
            surface: surface.wire(),
            model,
            credits_used: counters.credits_used.map(format_credits),
            uncached_input_tokens: counters.uncached_input_tokens,
            cached_input_tokens: counters.cached_input_tokens,
            output_tokens: counters.output_tokens,
            total_tokens: counters.total_tokens,
            thread_count: counters.thread_count,
            turn_count: counters.turn_count,
        })
        .collect();

    Ok(NormalizedWindow {
        rows,
        provider_data_refreshed_at: refreshed_at,
        dropped_model_rows,
    })
}

/// Render credits at the contract's six decimal places, as a string, so no
/// float formatting surprise reaches the wire.
fn format_credits(value: f64) -> String {
    format!("{value:.6}")
}

// ---------------------------------------------------------------------------
// Windows and batching
// ---------------------------------------------------------------------------

fn date_string(value: OffsetDateTime) -> String {
    let date = value.date();
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// The window a cycle asks the provider for.
///
/// `coverage_end` is the last *complete* UTC day: today is still accumulating,
/// so uploading it would publish a number that is knowably short.
pub fn collection_window(now: OffsetDateTime) -> (String, String) {
    let end = now.to_offset(time::UtcOffset::UTC) - TimeDuration::days(1);
    let start = end - TimeDuration::days(LOOKBACK_DAYS - 1);
    (date_string(start), date_string(end))
}

/// Split normalized rows into contract-legal batches.
///
/// Three properties matter for the backend's coverage envelope, which is one
/// contiguous span: batches go oldest first, consecutive windows **abut
/// exactly** (a closed window ends the day before the next one starts, so a
/// stretch of idle days between two observed days is still declared covered
/// rather than left as a hole), and no day is split across batches. A window
/// that neither overlaps nor abuts the stored envelope would *replace* it, so a
/// hole here would silently discard already-uploaded coverage.
///
/// A single day that alone exceeds the row bound is refused rather than
/// truncated: a silently partial day is a manufactured delta.
fn pack_batches(
    rows: Vec<DailyReferenceRow>,
    window_start: &str,
    window_end: &str,
) -> Result<Vec<(String, String, Vec<DailyReferenceRow>)>> {
    if rows.is_empty() {
        // A genuinely idle account still declares the window it observed.
        return Ok(vec![(
            window_start.to_string(),
            window_end.to_string(),
            Vec::new(),
        )]);
    }
    let mut by_day: BTreeMap<String, Vec<DailyReferenceRow>> = BTreeMap::new();
    for row in rows {
        by_day
            .entry(row.provider_day.clone())
            .or_default()
            .push(row);
    }
    if let Some((day, group)) = by_day
        .iter()
        .find(|(_, group)| group.len() > MAX_ROWS_PER_BATCH)
    {
        return Err(anyhow!(
            "provider day {day} normalized to {} rows, beyond the {MAX_ROWS_PER_BATCH} row bound",
            group.len()
        ));
    }

    let mut batches = Vec::new();
    let mut current: Vec<DailyReferenceRow> = Vec::new();
    // The first batch owns the declared window start, so no day Ottto asked
    // about sits outside the envelope it claims to have covered.
    let mut start = window_start.to_string();

    for (day, group) in by_day {
        let overflow_rows = !current.is_empty() && current.len() + group.len() > MAX_ROWS_PER_BATCH;
        // Measured from the declared start, not the first observed day, because
        // the declared window is what the bound applies to.
        let overflow_days = !current.is_empty()
            && !matches!(day_span(&start, &day), Some(span) if span <= MAX_COVERAGE_DAYS);
        if overflow_rows || overflow_days {
            let end = day_before(&day).ok_or_else(|| {
                anyhow!("could not close a coverage window immediately before {day}")
            })?;
            batches.push((start, end, std::mem::take(&mut current)));
            start = day.clone();
        }
        current.extend(group);
    }
    batches.push((start, window_end.to_string(), current));
    Ok(batches)
}

fn parse_day(value: &str) -> Option<time::Date> {
    let year: i32 = value.get(0..4)?.parse().ok()?;
    let month: u8 = value.get(5..7)?.parse().ok()?;
    let day: u8 = value.get(8..10)?.parse().ok()?;
    time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()
}

/// Inclusive day span between two `YYYY-MM-DD` days, or `None` when either is
/// not a real calendar day.
fn day_span(start: &str, end: &str) -> Option<i64> {
    Some((parse_day(end)? - parse_day(start)?).whole_days() + 1)
}

fn day_before(value: &str) -> Option<String> {
    parse_day(value)?.previous_day().map(|date| {
        format!(
            "{:04}-{:02}-{:02}",
            date.year(),
            u8::from(date.month()),
            date.day()
        )
    })
}

// ---------------------------------------------------------------------------
// Upload transport
// ---------------------------------------------------------------------------

/// Why an upload did not land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    /// The backend refused this build or this principal. Expected until a
    /// reviewed server change admits the shipped collector version, so it is
    /// never counted against the provider circuit breaker.
    NotAdmitted(u16),
    /// The declared consent epoch is behind the server's. Only re-consent can
    /// fix it, so the collector stops rather than retrying.
    GrantEpochConflict,
    /// Contract rejection: the batch is not acceptable as shaped.
    ContractRejected(u16),
    /// Everything else. Retried on the next cycle.
    Unavailable(String),
}

impl UploadError {
    fn category(&self) -> &'static str {
        match self {
            UploadError::NotAdmitted(_) => "collector_not_admitted",
            UploadError::GrantEpochConflict => "grant_epoch_conflict",
            UploadError::ContractRejected(_) => "contract_rejected",
            UploadError::Unavailable(_) => "upload_unavailable",
        }
    }
}

/// Send one batch to the backend. Defaults fail closed.
pub trait DailyReferenceTransport {
    fn is_configured(&self) -> bool {
        false
    }

    fn send_batch(&self, _batch: &Value) -> Result<Value, UploadError> {
        Err(UploadError::Unavailable(
            "codex daily aggregates transport is not configured".to_string(),
        ))
    }
}

/// Transport that exists only so a cycle can run inert before the relay
/// credentials are available.
pub struct DeferredTransport;

impl DailyReferenceTransport for DeferredTransport {}

/// Relay-device transport over the existing snapshot upload channel.
pub struct RelayTransport {
    client: crate::snapshot_client::SnapshotApiClient,
    device: LocalDeviceBinding,
    device_secret: String,
    relay_token: std::sync::Mutex<Option<String>>,
}

impl RelayTransport {
    pub fn new(
        api_base_url: impl Into<String>,
        device: LocalDeviceBinding,
        device_secret: String,
    ) -> Self {
        Self {
            client: crate::snapshot_client::SnapshotApiClient::new(api_base_url),
            device,
            device_secret,
            relay_token: std::sync::Mutex::new(None),
        }
    }

    fn token(&self, force_refresh: bool) -> Result<String, UploadError> {
        if !force_refresh {
            if let Ok(cached) = self.relay_token.lock() {
                if let Some(token) = cached.as_ref() {
                    return Ok(token.clone());
                }
            }
        }
        let token = self
            .client
            .issue_relay_token_with_timeout(
                &self.device,
                &self.device_secret,
                crate::snapshots::SnapshotSource::Codex,
                UPLOAD_TIMEOUT,
            )
            .map_err(|error| {
                UploadError::Unavailable(format!("relay token unavailable: {error}"))
            })?;
        if let Ok(mut cached) = self.relay_token.lock() {
            *cached = Some(token.clone());
        }
        Ok(token)
    }
}

impl DailyReferenceTransport for RelayTransport {
    fn is_configured(&self) -> bool {
        !self.device_secret.is_empty()
            && is_uuid(&self.device.device_id)
            && self.device.sources.iter().any(|source| source == SOURCE)
    }

    fn send_batch(&self, batch: &Value) -> Result<Value, UploadError> {
        let token = self.token(false)?;
        match self
            .client
            .upload_provider_daily_reference_batch_with_timeout(&token, batch, UPLOAD_TIMEOUT)
        {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                let mapped = map_upload_error(&error);
                // A relay token can simply have expired. Refresh once and
                // replay the identical body before concluding the build is not
                // admitted.
                if matches!(mapped, UploadError::NotAdmitted(401)) {
                    let token = self.token(true)?;
                    return self
                        .client
                        .upload_provider_daily_reference_batch_with_timeout(
                            &token,
                            batch,
                            UPLOAD_TIMEOUT,
                        )
                        .map_err(|error| map_upload_error(&error));
                }
                Err(mapped)
            }
        }
    }
}

fn map_upload_error(error: &anyhow::Error) -> UploadError {
    if let Some(rejected) =
        error.downcast_ref::<crate::snapshot_client::ProviderDailyReferenceUploadRejected>()
    {
        return UploadError::NotAdmitted(rejected.status);
    }
    if let Some(rejected) =
        error.downcast_ref::<crate::snapshot_client::ProviderDailyReferenceContractRejected>()
    {
        return if rejected.status == 409 {
            UploadError::GrantEpochConflict
        } else {
            UploadError::ContractRejected(rejected.status)
        };
    }
    UploadError::Unavailable(error.to_string())
}

// ---------------------------------------------------------------------------
// Cycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// Sentinel, absent consent, unapproved policy, or an unadmitted build.
    Disabled,
    /// The breaker is open; no provider request was made.
    CircuitOpen,
    /// Nothing to do this tick - the cadence gate has not elapsed.
    Noop,
    /// The transport or the credential is not available yet.
    Deferred,
    /// Batches landed.
    Uploaded,
    /// The backend has not admitted this collector version. Expected.
    NotAdmitted,
    /// A provider or upload failure this cycle.
    Failed,
}

#[derive(Debug, Clone)]
pub struct Cycle {
    pub outcome: CycleOutcome,
    pub diagnostics: Vec<AgentStatusDiagnostic>,
}

impl Cycle {
    fn new(outcome: CycleOutcome) -> Self {
        Self {
            outcome,
            diagnostics: Vec::new(),
        }
    }

    fn with(outcome: CycleOutcome, diagnostic: AgentStatusDiagnostic) -> Self {
        Self {
            outcome,
            diagnostics: vec![diagnostic],
        }
    }
}

/// Raw runtime identity the cycle proves against the grant's fingerprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runtime {
    /// Relay device id. Equals the wire `installation_id`.
    pub installation_id: String,
    /// The provider account the live credential belongs to.
    pub provider_account_scope: String,
}

fn info(code: &str, message: &str) -> AgentStatusDiagnostic {
    AgentStatusDiagnostic::source(code, AgentDiagnosticSeverity::Info, message)
}

fn warning(code: &str, message: &str) -> AgentStatusDiagnostic {
    AgentStatusDiagnostic::source(code, AgentDiagnosticSeverity::Warning, message)
}

/// Consent, cadence state, and the off-switch for one installation.
#[derive(Debug, Clone)]
pub struct Collector {
    grants: GrantStore,
    state: StateStore,
    sentinel: PathBuf,
}

impl Default for Collector {
    fn default() -> Self {
        Self {
            grants: GrantStore::default(),
            state: StateStore::default(),
            sentinel: sentinel_path(),
        }
    }
}

impl Collector {
    pub fn new(grants: GrantStore, state: StateStore, sentinel: impl Into<PathBuf>) -> Self {
        Self {
            grants,
            state,
            sentinel: sentinel.into(),
        }
    }

    pub fn grants(&self) -> &GrantStore {
        &self.grants
    }

    pub fn state_path(&self) -> &Path {
        self.state.path()
    }

    /// Presence of the sentinel disables the capability. Absent is the default
    /// and is not by itself permission: the grant still has to be live.
    pub fn network_disabled(&self) -> bool {
        self.sentinel.is_file()
    }

    /// Run one collection cycle.
    ///
    /// Every gate below runs before a socket is opened, in this order: the
    /// sentinel, live consent at the current epoch on this exact build, the
    /// live credential proving it is the installation and account consent was
    /// taken over, the circuit breaker, and finally the cadence gate.
    pub fn collect_once(
        &self,
        runtime: &Runtime,
        reader: &dyn ProviderDailyUsageReader,
        transport: &dyn DailyReferenceTransport,
        now: OffsetDateTime,
    ) -> Cycle {
        collect_once(
            &self.grants,
            &self.state,
            self.network_disabled(),
            runtime,
            reader,
            transport,
            now,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_once(
    grants: &GrantStore,
    state_store: &StateStore,
    sentinel_disabled: bool,
    runtime: &Runtime,
    reader: &dyn ProviderDailyUsageReader,
    transport: &dyn DailyReferenceTransport,
    now: OffsetDateTime,
) -> Cycle {
    if sentinel_disabled {
        state_store.clear();
        return Cycle::with(
            CycleOutcome::Disabled,
            info(
                "codex_daily_aggregates_network_disabled",
                "Codex daily aggregates are disabled by the local off-switch; the provider endpoint is never contacted.",
            ),
        );
    }

    // No consent is the silent case: nothing to report, nothing to warn about.
    let Ok(Some(grant)) = grants.load() else {
        return Cycle::new(CycleOutcome::Disabled);
    };
    if !grant_runtime_ready(&grant) {
        return Cycle::new(CycleOutcome::Disabled);
    }

    // Consent is bound to one installation and one provider account. Prove both
    // before the credential is used, so account B's numbers can never be
    // uploaded under account A's fingerprint.
    let installation_matches = grants
        .installation_fingerprint_for(&runtime.installation_id)
        .ok()
        .flatten()
        .is_some_and(|fingerprint| fingerprint == grant.installation_fingerprint);
    if !installation_matches {
        return Cycle::with(
            CycleOutcome::Disabled,
            warning(
                "codex_daily_aggregates_installation_mismatch",
                "Codex daily aggregates consent was recorded for a different installation; collection is stopped.",
            ),
        );
    }
    let account_matches = grants
        .account_fingerprint_for(&runtime.provider_account_scope)
        .ok()
        .flatten()
        .is_some_and(|fingerprint| fingerprint == grant.account_fingerprint);
    if !account_matches {
        return Cycle::with(
            CycleOutcome::Disabled,
            warning(
                "codex_daily_aggregates_account_mismatch",
                "The live Codex account is not the account this consent covers; collection is stopped.",
            ),
        );
    }

    if !transport.is_configured() {
        return Cycle::new(CycleOutcome::Deferred);
    }

    let identity = state_identity(&grant, sentinel_disabled);
    let mut state = state_store.load(&identity);
    let now_seconds = unix_seconds(now);
    if breaker_is_open(&state, now_seconds) {
        return Cycle::with(
            CycleOutcome::CircuitOpen,
            warning(
                "codex_daily_aggregates_circuit_open",
                &format!(
                    "The Codex daily aggregate read is paused after repeated {} answers; it will retry after the cool-down.",
                    state.opened_by
                ),
            ),
        );
    }
    if !fetch_due(&state, &identity, now_seconds) {
        return Cycle::new(CycleOutcome::Noop);
    }

    let (window_start, window_end) = collection_window(now);
    state.last_fetch_epoch_seconds = now_seconds;
    state.schema_version = STATE_FILE_SCHEMA_VERSION;
    state.identity = identity.clone();

    let payload = match reader.fetch_window(&window_start, &window_end) {
        Ok(payload) => payload,
        Err(error) => {
            return record_provider_failure(
                grants,
                state_store,
                state,
                &identity,
                error,
                now_seconds,
            )
        }
    };
    let normalized = match normalize_provider_window(&payload, &window_start, &window_end) {
        Ok(normalized) => normalized,
        Err(error) => {
            return record_provider_failure(
                grants,
                state_store,
                state,
                &identity,
                error,
                now_seconds,
            )
        }
    };
    // The payload has served its purpose; nothing derived from it beyond the
    // normalized scalars may outlive this point.
    drop(payload);

    let mut diagnostics = Vec::new();
    if normalized.dropped_model_rows > 0 {
        diagnostics.push(info(
            "codex_daily_aggregates_model_slug_dropped",
            &format!(
                "{} provider model rows could not be expressed as a bounded model slug and were not uploaded.",
                normalized.dropped_model_rows
            ),
        ));
    }

    let batches = match pack_batches(normalized.rows, &window_start, &window_end) {
        Ok(batches) => batches,
        Err(error) => {
            state.last_error_category = Some("row_budget_exceeded".to_string());
            let _ = state_store.save(&state);
            let _ = grants.record_health(None, Some("row_budget_exceeded"));
            diagnostics.push(warning(
                "codex_daily_aggregates_row_budget_exceeded",
                &format!("The provider window did not fit the upload contract: {error}"),
            ));
            return Cycle {
                outcome: CycleOutcome::Failed,
                diagnostics,
            };
        }
    };

    let collected_at = timestamp(now);
    let grant_version = grant
        .backend_binding
        .as_ref()
        .map(|binding| binding.grant_version)
        .unwrap_or_default();

    for (coverage_start, coverage_end, rows) in batches {
        let batch = DailyReferenceBatch {
            schema_version: SCHEMA_VERSION,
            source: SOURCE,
            collector_id: COLLECTOR_ID,
            collector_version: compiled_release_version(),
            installation_id: runtime.installation_id.clone(),
            grant_scope_fingerprint: grant.grant_scope_fingerprint.clone(),
            account_fingerprint: grant.account_fingerprint.clone(),
            grant_version,
            provider_day_timezone: PROVIDER_DAY_TIMEZONE,
            coverage_start: coverage_start.clone(),
            coverage_end: coverage_end.clone(),
            collected_at: collected_at.clone(),
            provider_data_refreshed_at: normalized.provider_data_refreshed_at.clone(),
            rows,
        };
        let payload = match serde_json::to_value(&batch) {
            Ok(payload) => payload,
            Err(error) => {
                diagnostics.push(warning(
                    "codex_daily_aggregates_batch_invalid",
                    &format!("The normalized batch could not be encoded: {error}"),
                ));
                return Cycle {
                    outcome: CycleOutcome::Failed,
                    diagnostics,
                };
            }
        };
        // Last line of defence: refuse to send anything the contract's closed
        // vocabulary cannot describe, whatever the provider returned.
        if !wire_payload_is_content_free(&payload) {
            diagnostics.push(warning(
                "codex_daily_aggregates_batch_invalid",
                "The normalized batch failed the content-free check and was not uploaded.",
            ));
            state.last_error_category = Some("batch_not_content_free".to_string());
            let _ = state_store.save(&state);
            return Cycle {
                outcome: CycleOutcome::Failed,
                diagnostics,
            };
        }

        match transport.send_batch(&payload) {
            Ok(receipt) => {
                if let Err(error) = validate_ack(&receipt, &coverage_start, &coverage_end) {
                    diagnostics.push(warning(
                        "codex_daily_aggregates_ack_invalid",
                        &format!("The backend acknowledgement did not match the batch: {error}"),
                    ));
                    state.last_error_category = Some("ack_invalid".to_string());
                    let _ = state_store.save(&state);
                    return Cycle {
                        outcome: CycleOutcome::Failed,
                        diagnostics,
                    };
                }
            }
            Err(UploadError::NotAdmitted(status)) => {
                // Expected until a reviewed backend change admits this build.
                // Not a provider failure, so the circuit breaker is untouched.
                state.last_error_category = Some("collector_not_admitted".to_string());
                let _ = state_store.save(&state);
                let _ = grants.record_health(None, Some("collector_not_admitted"));
                diagnostics.push(info(
                    "codex_daily_aggregates_collector_not_admitted",
                    &format!(
                        "The backend has not admitted this collector build yet (HTTP {status}); nothing was stored."
                    ),
                ));
                return Cycle {
                    outcome: CycleOutcome::NotAdmitted,
                    diagnostics,
                };
            }
            Err(error) => {
                state.last_error_category = Some(error.category().to_string());
                let _ = state_store.save(&state);
                let _ = grants.record_health(None, Some(error.category()));
                diagnostics.push(warning(
                    "codex_daily_aggregates_upload_unavailable",
                    &format!(
                        "A Codex daily aggregate batch was not stored: {}",
                        error.category()
                    ),
                ));
                return Cycle {
                    outcome: CycleOutcome::Failed,
                    diagnostics,
                };
            }
        }
    }

    let state = state_after_success(state, &identity, now_seconds);
    let _ = state_store.save(&state);
    let _ = grants.record_health(Some(&collected_at), None);
    Cycle {
        outcome: CycleOutcome::Uploaded,
        diagnostics,
    }
}

fn record_provider_failure(
    grants: &GrantStore,
    state_store: &StateStore,
    state: CollectorState,
    identity: &str,
    error: ProviderReadError,
    now: u64,
) -> Cycle {
    let category = error.category();
    let Some(failure) = error.failure_class() else {
        // Transport and 5xx: record the reason, count nothing.
        let mut state = state;
        state.last_error_category = Some(category.to_string());
        let _ = state_store.save(&state);
        let _ = grants.record_health(None, Some(category));
        return Cycle::new(CycleOutcome::Failed);
    };
    let was_open = breaker_is_open(&state, now);
    let state = state_after_failure(state, identity, failure, category, now);
    let _ = state_store.save(&state);
    let _ = grants.record_health(None, Some(category));
    if breaker_is_open(&state, now) && !was_open {
        return Cycle::with(
            CycleOutcome::CircuitOpen,
            warning(
                "codex_daily_aggregates_circuit_open",
                &format!(
                    "The Codex daily aggregate read stopped after repeated {} answers; it will retry after the cool-down.",
                    failure.code()
                ),
            ),
        );
    }
    Cycle::new(CycleOutcome::Failed)
}

fn validate_ack(receipt: &Value, coverage_start: &str, coverage_end: &str) -> Result<()> {
    let schema_version = receipt
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if schema_version != ACK_SCHEMA_VERSION {
        return Err(anyhow!("unexpected ack schema {schema_version}"));
    }
    if receipt.get("coverage_start").and_then(Value::as_str) != Some(coverage_start)
        || receipt.get("coverage_end").and_then(Value::as_str) != Some(coverage_end)
    {
        return Err(anyhow!("ack does not echo the declared coverage window"));
    }
    if receipt
        .get("accepted_row_count")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(anyhow!("ack is missing accepted_row_count"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Content-free proof
// ---------------------------------------------------------------------------

fn is_fingerprint(value: &str) -> bool {
    value.len() == 76
        && value.starts_with("hmac-sha256:")
        && value[12..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_semver(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return false;
    }
    let parts: Vec<&str> = value.split(['.', '-']).collect();
    parts.len() >= 3
        && parts[..3]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_iso_day(value: &str) -> bool {
    provider_day(value).as_deref() == Some(value)
}

fn is_model_slug(value: &str) -> bool {
    if value == ALL_MODELS {
        return true;
    }
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

/// Prove that every string in an outgoing batch is a fixed literal, an opaque
/// fingerprint, a UUID, a date, a timestamp, a closed surface value, a bounded
/// model slug, or a decimal.
///
/// This is the daemon-side counterpart to the backend's must-not-persist key
/// pinning: the backend proves no unexpected *key* can reach storage, and this
/// proves no unexpected *value* can leave the machine.
pub fn wire_payload_is_content_free(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    if object.keys().any(|key| !BATCH_KEYS.contains(&key.as_str())) {
        return false;
    }
    let string_at = |key: &str| object.get(key).and_then(Value::as_str);
    if string_at("schema_version") != Some(SCHEMA_VERSION)
        || string_at("source") != Some(SOURCE)
        || string_at("collector_id") != Some(COLLECTOR_ID)
        || string_at("provider_day_timezone") != Some(PROVIDER_DAY_TIMEZONE)
    {
        return false;
    }
    if !string_at("collector_version").is_some_and(is_semver)
        || !string_at("installation_id").is_some_and(is_uuid)
        || !string_at("grant_scope_fingerprint").is_some_and(is_fingerprint)
        || !string_at("account_fingerprint").is_some_and(is_fingerprint)
        || !string_at("coverage_start").is_some_and(is_iso_day)
        || !string_at("coverage_end").is_some_and(is_iso_day)
        || !string_at("collected_at").is_some_and(is_rfc3339)
    {
        return false;
    }
    if let Some(refreshed_at) = object.get("provider_data_refreshed_at") {
        if !refreshed_at.as_str().is_some_and(is_rfc3339) {
            return false;
        }
    }
    if object
        .get("grant_version")
        .and_then(Value::as_u64)
        .is_none()
    {
        return false;
    }
    let Some(rows) = object.get("rows").and_then(Value::as_array) else {
        return false;
    };
    if rows.len() > MAX_ROWS_PER_BATCH {
        return false;
    }
    rows.iter().all(|row| {
        let Some(row) = row.as_object() else {
            return false;
        };
        if row.keys().any(|key| !ROW_KEYS.contains(&key.as_str())) {
            return false;
        }
        if !row
            .get("provider_day")
            .and_then(Value::as_str)
            .is_some_and(is_iso_day)
        {
            return false;
        }
        if !row
            .get("surface")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                [
                    Surface::CodexWeb,
                    Surface::CodexDesktopApp,
                    Surface::CodexServiceExec,
                    Surface::CodexWorkDesktop,
                    Surface::CodexUnknownDefault,
                    Surface::Other,
                ]
                .iter()
                .any(|surface| surface.wire() == value)
            })
        {
            return false;
        }
        if !row
            .get("model")
            .and_then(Value::as_str)
            .is_some_and(is_model_slug)
        {
            return false;
        }
        if let Some(credits) = row.get("credits_used") {
            if !credits.as_str().is_some_and(is_decimal) {
                return false;
            }
        }
        [
            "uncached_input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "total_tokens",
            "thread_count",
            "turn_count",
        ]
        .iter()
        .all(|key| match row.get(*key) {
            None => true,
            Some(value) => value.as_u64().is_some(),
        })
    })
}

fn is_rfc3339(value: &str) -> bool {
    OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

// ---------------------------------------------------------------------------
// Composition and supervisor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorStartup {
    Started,
}

/// Compose the real runtime and run one cycle.
///
/// Ordering matters: consent is read first, so a machine without a grant does
/// no local work beyond one file read and never touches the account, device,
/// connection, credential, or keychain state.
pub fn collect_composed_once(now: OffsetDateTime) -> Cycle {
    let collector = Collector::default();
    if collector.network_disabled() {
        collector.state.clear();
        return Cycle::with(
            CycleOutcome::Disabled,
            info(
                "codex_daily_aggregates_network_disabled",
                "Codex daily aggregates are disabled by the local off-switch; the provider endpoint is never contacted.",
            ),
        );
    }
    // The default/off path is one local grant read. Nothing below - account,
    // device, connection, destination, credential, or keychain - is touched
    // until consent is capable of becoming runtime-ready.
    let Ok(Some(grant)) = collector.grants.load() else {
        return Cycle::new(CycleOutcome::Disabled);
    };
    if !grant_runtime_ready(&grant) {
        return Cycle::new(CycleOutcome::Disabled);
    }

    let Ok(Some((runtime, credential, api_base_url))) = load_runtime_binding() else {
        return Cycle::new(CycleOutcome::Deferred);
    };
    let Ok((device, device_secret)) = crate::snapshot_client::load_snapshot_device_credentials()
    else {
        return Cycle::new(CycleOutcome::Deferred);
    };
    let transport = RelayTransport::new(api_base_url, device, device_secret);
    let reader = ChatGptDailyUsageReader::new(credential);
    collector.collect_once(&runtime, &reader, &transport, now)
}

type RuntimeBinding = Option<(Runtime, CodexCredential, String)>;

fn load_runtime_binding() -> Result<RuntimeBinding> {
    let account = FileAccountStore::default().load()?;
    if account.state != LocalAccountState::Connected {
        return Ok(None);
    }
    let Some(device) = FileDeviceStore::default().load()? else {
        return Ok(None);
    };
    if !is_uuid(&device.device_id) || !device.sources.iter().any(|source| source == SOURCE) {
        return Ok(None);
    }
    let Some(connection) = FileConnectionStore::default().load()? else {
        return Ok(None);
    };
    if connection.setup_run_id.trim().is_empty() || connection.machine_id != device.machine_id {
        return Ok(None);
    }
    // Validate the destination before any credential is read, so an on-disk URL
    // can never receive one.
    let api_base_url = validated_api_base_url(&connection.api_base_url)?;
    let Some(credential) = read_codex_credential() else {
        return Ok(None);
    };
    Ok(Some((
        Runtime {
            installation_id: device.device_id,
            provider_account_scope: credential.account_scope.clone(),
        },
        credential,
        api_base_url,
    )))
}

fn validated_api_base_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.contains('@') || trimmed.contains('?') || trimmed.contains('#') {
        return Err(anyhow!("api base url is not an accepted destination"));
    }
    let accepted = trimmed == DEFAULT_API_BASE_URL
        || trimmed == LEGACY_API_BASE_URL
        || std::env::var("OTTTO_API_BASE_URL")
            .is_ok_and(|override_url| override_url.trim().trim_end_matches('/') == trimmed);
    if !accepted {
        return Err(anyhow!("api base url is not an accepted destination"));
    }
    Ok(trimmed.to_string())
}

/// Start the collector supervisor.
///
/// The supervisor starts unconditionally and every tick is inert until consent,
/// server policy, and admission all allow, so a grant created after boot
/// activates without a daemon restart.
pub fn spawn_codex_daily_aggregate_collector() -> Result<CollectorStartup> {
    if COLLECTOR_SUPERVISOR_STARTED
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .is_err()
    {
        return Ok(CollectorStartup::Started);
    }
    let spawned = thread::Builder::new()
        .name("ottto-codex-daily-aggregates".to_string())
        .spawn(|| loop {
            let cycle = collect_composed_once(OffsetDateTime::now_utc());
            if !matches!(cycle.outcome, CycleOutcome::Disabled | CycleOutcome::Noop) {
                eprintln!(
                    "codex_daily_aggregates_collector outcome={:?} diagnostics={}",
                    cycle.outcome,
                    cycle.diagnostics.len()
                );
            }
            thread::sleep(POLL_INTERVAL + cycle_jitter());
        });
    if let Err(error) = spawned {
        COLLECTOR_SUPERVISOR_STARTED.store(false, AtomicOrdering::Release);
        return Err(anyhow!("spawn Codex daily aggregates collector: {error}"));
    }
    Ok(CollectorStartup::Started)
}

fn cycle_jitter() -> Duration {
    Duration::from_secs(u64::from(OffsetDateTime::now_utc().second()) % 61)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn opaque_key(key: &[u8], raw: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(raw.as_bytes());
    format!("hmac-sha256:{}", hex(&mac.finalize().into_bytes()))
}

fn grant_scope_fingerprint(key: &[u8], setup: &GrantSetup) -> String {
    opaque_key(
        key,
        &format!(
            "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
            setup.installation_id,
            setup.organization_scope,
            setup.effective_user_scope,
            setup.provider_account_scope,
            COLLECTOR_ID
        ),
    )
}

fn random_key() -> Result<Vec<u8>> {
    let mut key = vec![0_u8; 32];
    random_fill(&mut key).map_err(|_| anyhow!("generate codex daily aggregates HMAC key"))?;
    Ok(key)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(raw: &str) -> Option<Vec<u8>> {
    (raw.len() % 2 == 0).then_some(())?;
    (0..raw.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&raw[index..index + 2], 16).ok())
        .collect()
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn timestamp(value: OffsetDateTime) -> String {
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn unix_seconds(value: OffsetDateTime) -> u64 {
    u64::try_from(value.unix_timestamp()).unwrap_or_default()
}

fn atomic_json_write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("codex daily aggregates state path has no parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let payload = serde_json::to_vec(value)?;
    let mut nonce = [0_u8; 16];
    random_fill(&mut nonce).map_err(|_| anyhow!("generate codex daily aggregates nonce"))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("codex daily aggregates state filename is invalid"))?;
    let temporary = parent.join(format!(".{filename}.{}.tmp", hex(&nonce)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .context("create codex daily aggregates temporary state")?;
        file.write_all(&payload)
            .context("write codex daily aggregates temporary state")?;
        file.sync_all()
            .context("sync codex daily aggregates temporary state")?;
        drop(file);
        fs::rename(&temporary, path).context("replace codex daily aggregates state")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("sync codex daily aggregates state directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicU64;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    const INSTALLATION_ID: &str = "00000000-0000-4000-8000-000000000001";
    const GRANT_ID: &str = "00000000-0000-4000-8000-000000000002";
    const ORG_SCOPE: &str = "org-fixture-private";
    const USER_SCOPE: &str = "user-fixture-private";
    const ACCOUNT_SCOPE: &str = "acct-fixture-private";

    fn temp_dir(name: &str) -> PathBuf {
        let unique = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
        std::env::temp_dir().join(format!(
            "ottto-codex-daily-aggregates-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    /// Every store gets an explicit path, so no test reads or mutates process
    /// environment and the suite runs in parallel.
    fn collector(name: &str) -> Collector {
        let root = temp_dir(name);
        Collector::new(
            GrantStore::new(root.join("grant.json")),
            StateStore::new(root.join("state.json")),
            root.join(SENTINEL_FILE),
        )
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-07-27T09:00:00Z", &Rfc3339).expect("fixture timestamp")
    }

    fn setup() -> GrantSetup {
        GrantSetup {
            installation_id: INSTALLATION_ID.to_string(),
            organization_scope: ORG_SCOPE.to_string(),
            effective_user_scope: USER_SCOPE.to_string(),
            provider_account_scope: ACCOUNT_SCOPE.to_string(),
        }
    }

    fn runtime() -> Runtime {
        Runtime {
            installation_id: INSTALLATION_ID.to_string(),
            provider_account_scope: ACCOUNT_SCOPE.to_string(),
        }
    }

    fn grant_response(local: &DailyReferenceGrant, status: &str, version: u64) -> GrantResponse {
        GrantResponse {
            id: GRANT_ID.to_string(),
            installation_id: INSTALLATION_ID.to_string(),
            source: SOURCE.to_string(),
            collector_id: COLLECTOR_ID.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            collector_version: compiled_release_version(),
            release_lane: RELEASE_LANE.to_string(),
            disclosure_version: DISCLOSURE_VERSION.to_string(),
            grant_scope_fingerprint: local.grant_scope_fingerprint.clone(),
            account_fingerprint: local.account_fingerprint.clone(),
            status: status.to_string(),
            grant_version: version,
            server_policy_state: ServerPolicyState::Approved,
        }
    }

    fn enabled(collector: &Collector) -> DailyReferenceGrant {
        let local = collector
            .grants()
            .enable(&setup(), now())
            .expect("record consent");
        collector
            .grants()
            .bind_backend_grant(&grant_response(&local, "enabled", 1), INSTALLATION_ID)
            .expect("bind backend grant")
    }

    // -- fakes ------------------------------------------------------------

    struct StaticReader {
        payload: Value,
        calls: Cell<usize>,
    }

    impl StaticReader {
        fn new(payload: Value) -> Self {
            Self {
                payload,
                calls: Cell::new(0),
            }
        }
    }

    impl ProviderDailyUsageReader for StaticReader {
        fn fetch_window(&self, _start: &str, _end: &str) -> Result<Value, ProviderReadError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.payload.clone())
        }
    }

    struct FailingReader {
        errors: RefCell<VecDeque<ProviderReadError>>,
        calls: Cell<usize>,
    }

    impl FailingReader {
        fn new(errors: Vec<ProviderReadError>) -> Self {
            Self {
                errors: RefCell::new(errors.into()),
                calls: Cell::new(0),
            }
        }
    }

    impl ProviderDailyUsageReader for FailingReader {
        fn fetch_window(&self, _start: &str, _end: &str) -> Result<Value, ProviderReadError> {
            self.calls.set(self.calls.get() + 1);
            Err(self
                .errors
                .borrow_mut()
                .pop_front()
                .unwrap_or(ProviderReadError::RateLimited))
        }
    }

    /// A reader that must never be called. Proves a gate ran before the network.
    struct ForbiddenReader;

    impl ProviderDailyUsageReader for ForbiddenReader {
        fn fetch_window(&self, _start: &str, _end: &str) -> Result<Value, ProviderReadError> {
            panic!("the provider endpoint was contacted while collection was not permitted");
        }
    }

    fn ack_for(batch: &Value) -> Value {
        let rows = batch["rows"].as_array().map(Vec::len).unwrap_or_default();
        json!({
            "schema_version": ACK_SCHEMA_VERSION,
            "grant_id": GRANT_ID,
            "accepted_row_count": rows,
            "stored_row_count": rows,
            "superseded_row_count": 0,
            "coverage_start": batch["coverage_start"],
            "coverage_end": batch["coverage_end"],
            "fresh_at": batch["collected_at"],
        })
    }

    #[derive(Default)]
    struct RecordingTransport {
        batches: RefCell<Vec<Value>>,
    }

    impl DailyReferenceTransport for RecordingTransport {
        fn is_configured(&self) -> bool {
            true
        }

        fn send_batch(&self, batch: &Value) -> Result<Value, UploadError> {
            self.batches.borrow_mut().push(batch.clone());
            Ok(ack_for(batch))
        }
    }

    struct RejectingTransport {
        error: UploadError,
        calls: Cell<usize>,
    }

    impl RejectingTransport {
        fn new(error: UploadError) -> Self {
            Self {
                error,
                calls: Cell::new(0),
            }
        }
    }

    impl DailyReferenceTransport for RejectingTransport {
        fn is_configured(&self) -> bool {
            true
        }

        fn send_batch(&self, _batch: &Value) -> Result<Value, UploadError> {
            self.calls.set(self.calls.get() + 1);
            Err(self.error.clone())
        }
    }

    struct ForbiddenTransport;

    impl DailyReferenceTransport for ForbiddenTransport {
        fn is_configured(&self) -> bool {
            true
        }

        fn send_batch(&self, _batch: &Value) -> Result<Value, UploadError> {
            panic!("a batch was uploaded while collection was not permitted");
        }
    }

    /// A provider payload dense with exactly the material that must never
    /// cross the boundary: workspace and client labels, a thread title, a raw
    /// account id, a repository path, and a prompt.
    fn poisoned_payload() -> Value {
        json!({
            "data_refreshed_at": "2026-07-27T06:00:00Z",
            "workspace_name": "must-not-persist workspace",
            "account_id": "acct-must-not-persist",
            "results": [
                {
                    "date": "2026-07-26",
                    "totals": {"credits": 100.0, "text_total_tokens": 9_999_999},
                    "clients": [
                        {
                            "client_id": "CODEX_WEB",
                            "client_label": "must-not-persist label",
                            "credits": 12.5,
                            "uncached_text_input_tokens": 1000,
                            "cached_text_input_tokens": 500,
                            "text_output_tokens": 250,
                            "text_total_tokens": 1750,
                            "threads": 3,
                            "turns": 9,
                            "models": [
                                {
                                    "model": "GPT-5-Codex",
                                    "credits": 0.0,
                                    "text_total_tokens": 1750,
                                    "threads": 3,
                                    "turns": 9,
                                    "title": "must-not-persist title",
                                    "repository": "/Users/someone/must-not-persist-repo",
                                    "prompt": "must-not-persist prompt"
                                },
                                {"model": "!!!", "text_total_tokens": 5}
                            ]
                        },
                        {
                            "client_id": "CODEX_SERVICE_EXEC",
                            "credits": 1.0,
                            "text_total_tokens": 40,
                            "threads": 1,
                            "turns": 2
                        },
                        {
                            "client_id": "SOME_NEW_SURFACE",
                            "credits": 2.0,
                            "text_total_tokens": 10
                        },
                        {
                            "client_id": "ANOTHER_NEW_SURFACE",
                            "credits": 3.0,
                            "text_total_tokens": 20
                        }
                    ]
                },
                {
                    "date": "2026-07-25",
                    "clients": [
                        {
                            "client_id": "CODEX_DESKTOP_APP",
                            "credits": 4.0,
                            "text_output_tokens": 0,
                            "threads": 0
                        }
                    ]
                }
            ]
        })
    }

    fn poison_strings() -> [&'static str; 9] {
        [
            "must-not-persist",
            "workspace_name",
            "client_label",
            "title",
            "repository",
            "prompt",
            "SOME_NEW_SURFACE",
            "ANOTHER_NEW_SURFACE",
            "GPT-5-Codex",
        ]
    }

    fn diagnostic<'a>(cycle: &'a Cycle, code: &str) -> &'a AgentStatusDiagnostic {
        cycle
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("expected diagnostic {code}"))
    }

    fn row_at<'a>(
        rows: &'a [DailyReferenceRow],
        day: &str,
        surface: &str,
        model: &str,
    ) -> Option<&'a DailyReferenceRow> {
        rows.iter()
            .find(|row| row.provider_day == day && row.surface == surface && row.model == model)
    }

    // -- vocabulary -------------------------------------------------------

    #[test]
    fn client_ids_map_onto_the_closed_surface_vocabulary() {
        assert_eq!(surface_for_client_id("CODEX_WEB"), Surface::CodexWeb);
        assert_eq!(
            surface_for_client_id("codex_desktop_app"),
            Surface::CodexDesktopApp
        );
        assert_eq!(
            surface_for_client_id(" CODEX_SERVICE_EXEC "),
            Surface::CodexServiceExec
        );
        assert_eq!(
            surface_for_client_id("CODEX_WORK_DESKTOP"),
            Surface::CodexWorkDesktop
        );
        // The provider's own unattributed bucket keeps its own slot: "the
        // provider could not attribute this" is not the same fact as "Ottto
        // has never seen this client id".
        assert_eq!(
            surface_for_client_id("CODEX_UNKNOWN_DEFAULT"),
            Surface::CodexUnknownDefault
        );
        for unknown in [
            "CODEX_FUTURE_SURFACE",
            "",
            "codex_web_v2",
            "../../etc/passwd",
            "a prompt sneaking in as a client id",
        ] {
            assert_eq!(
                surface_for_client_id(unknown),
                Surface::Other,
                "unknown client id must map to other, never a new surface"
            );
        }
    }

    #[test]
    fn model_identifiers_are_bounded_slugs_or_refused() {
        assert_eq!(
            normalized_model_slug("GPT-5-Codex").as_deref(),
            Some("gpt-5-codex")
        );
        assert_eq!(
            normalized_model_slug("o4 mini/high").as_deref(),
            Some("o4-mini-high")
        );
        assert_eq!(normalized_model_slug("").as_deref(), None);
        assert_eq!(normalized_model_slug("   ").as_deref(), None);
        assert_eq!(normalized_model_slug("__all__").as_deref(), None);
        // Cannot begin with an alphanumeric, so it is refused rather than
        // coerced into an invented identifier.
        assert_eq!(normalized_model_slug("!!!").as_deref(), None);
        assert_eq!(normalized_model_slug("/Users/ron/secret").as_deref(), None);
        let long = normalized_model_slug(&"m".repeat(200)).expect("bounded slug");
        assert_eq!(long.len(), 64);
        assert!(is_model_slug(&long));
    }

    // -- normalization: the must-not-persist proof ------------------------

    #[test]
    fn no_provider_free_text_survives_into_the_uploaded_batch() {
        let (start, end) = collection_window(now());
        let normalized =
            normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
        let batch = DailyReferenceBatch {
            schema_version: SCHEMA_VERSION,
            source: SOURCE,
            collector_id: COLLECTOR_ID,
            collector_version: compiled_release_version(),
            installation_id: INSTALLATION_ID.to_string(),
            grant_scope_fingerprint: format!("hmac-sha256:{}", "a".repeat(64)),
            account_fingerprint: format!("hmac-sha256:{}", "b".repeat(64)),
            grant_version: 1,
            provider_day_timezone: PROVIDER_DAY_TIMEZONE,
            coverage_start: start,
            coverage_end: end,
            collected_at: timestamp(now()),
            provider_data_refreshed_at: normalized.provider_data_refreshed_at.clone(),
            rows: normalized.rows.clone(),
        };
        let encoded = serde_json::to_string(&batch).expect("encode batch");
        for poison in poison_strings() {
            assert!(
                !encoded.contains(poison),
                "the uploaded batch leaked {poison}"
            );
        }
        assert!(!encoded.contains("totals"));
        assert!(!encoded.contains("acct-"));
        let payload = serde_json::to_value(&batch).expect("batch value");
        assert!(wire_payload_is_content_free(&payload));
    }

    #[test]
    fn wire_key_sets_match_the_contract() {
        let (start, end) = collection_window(now());
        let normalized =
            normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
        let batch = DailyReferenceBatch {
            schema_version: SCHEMA_VERSION,
            source: SOURCE,
            collector_id: COLLECTOR_ID,
            collector_version: compiled_release_version(),
            installation_id: INSTALLATION_ID.to_string(),
            grant_scope_fingerprint: format!("hmac-sha256:{}", "a".repeat(64)),
            account_fingerprint: format!("hmac-sha256:{}", "b".repeat(64)),
            grant_version: 1,
            provider_day_timezone: PROVIDER_DAY_TIMEZONE,
            coverage_start: start,
            coverage_end: end,
            collected_at: timestamp(now()),
            provider_data_refreshed_at: None,
            rows: normalized.rows,
        };
        let payload = serde_json::to_value(&batch).expect("batch value");
        let object = payload.as_object().expect("object");
        for key in object.keys() {
            assert!(
                BATCH_KEYS.contains(&key.as_str()),
                "unexpected batch key {key}"
            );
        }
        for row in payload["rows"].as_array().expect("rows") {
            for key in row.as_object().expect("row object").keys() {
                assert!(ROW_KEYS.contains(&key.as_str()), "unexpected row key {key}");
            }
        }
    }

    #[test]
    fn an_injected_extra_key_or_free_text_value_fails_the_content_free_check() {
        let base = json!({
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "collector_id": COLLECTOR_ID,
            "collector_version": compiled_release_version(),
            "installation_id": INSTALLATION_ID,
            "grant_scope_fingerprint": format!("hmac-sha256:{}", "a".repeat(64)),
            "account_fingerprint": format!("hmac-sha256:{}", "b".repeat(64)),
            "grant_version": 1,
            "provider_day_timezone": "UTC",
            "coverage_start": "2026-07-01",
            "coverage_end": "2026-07-26",
            "collected_at": "2026-07-27T09:00:00Z",
            "rows": [{
                "provider_day": "2026-07-26",
                "surface": "codex_web",
                "model": "__all__",
                "total_tokens": 10
            }]
        });
        assert!(wire_payload_is_content_free(&base));

        let mut extra_batch_key = base.clone();
        extra_batch_key["workspace_name"] = json!("must-not-persist");
        assert!(!wire_payload_is_content_free(&extra_batch_key));

        let mut extra_row_key = base.clone();
        extra_row_key["rows"][0]["title"] = json!("must-not-persist");
        assert!(!wire_payload_is_content_free(&extra_row_key));

        let mut invented_surface = base.clone();
        invented_surface["rows"][0]["surface"] = json!("codex_future");
        assert!(!wire_payload_is_content_free(&invented_surface));

        let mut prose_model = base.clone();
        prose_model["rows"][0]["model"] = json!("a prompt that is not a slug");
        assert!(!wire_payload_is_content_free(&prose_model));

        let mut path_model = base.clone();
        path_model["rows"][0]["model"] = json!("/Users/ron/secret");
        assert!(!wire_payload_is_content_free(&path_model));

        let mut bad_fingerprint = base.clone();
        bad_fingerprint["account_fingerprint"] = json!("acct-real-account-id");
        assert!(!wire_payload_is_content_free(&bad_fingerprint));

        let mut local_day = base.clone();
        local_day["provider_day_timezone"] = json!("Asia/Jerusalem");
        assert!(!wire_payload_is_content_free(&local_day));
    }

    #[test]
    fn absent_counters_stay_absent_and_reported_zeros_are_preserved() {
        let (start, end) = collection_window(now());
        let normalized =
            normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
        let desktop = row_at(
            &normalized.rows,
            "2026-07-25",
            "codex_desktop_app",
            "__all__",
        )
        .expect("desktop surface row");
        // The provider reported zero output tokens and zero threads. Zero is a
        // fact; it must not be confused with "not reported".
        assert_eq!(desktop.output_tokens, Some(0));
        assert_eq!(desktop.thread_count, Some(0));
        // It reported no turns at all, so the counter is absent from the wire
        // rather than sent as 0 - that would manufacture a delta.
        assert_eq!(desktop.turn_count, None);
        let encoded = serde_json::to_string(desktop).expect("encode row");
        assert!(!encoded.contains("turn_count"));
        assert!(encoded.contains("\"output_tokens\":0"));
    }

    #[test]
    fn per_model_rows_never_carry_credits() {
        let (start, end) = collection_window(now());
        let normalized =
            normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
        let model_row = row_at(&normalized.rows, "2026-07-26", "codex_web", "gpt-5-codex")
            .expect("per-model row");
        // The provider reports 0.0 for models[].credits, which is not an
        // attribution. Uploading it would publish a false zero.
        assert_eq!(model_row.credits_used, None);
        assert_eq!(model_row.total_tokens, Some(1750));
        assert_eq!(model_row.turn_count, Some(9));

        let surface_row = row_at(&normalized.rows, "2026-07-26", "codex_web", "__all__")
            .expect("surface total row");
        assert_eq!(surface_row.credits_used.as_deref(), Some("12.500000"));
    }

    #[test]
    fn unknown_client_ids_merge_into_one_other_row_per_grain() {
        let (start, end) = collection_window(now());
        let normalized =
            normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
        let other_rows: Vec<_> = normalized
            .rows
            .iter()
            .filter(|row| row.surface == "other" && row.provider_day == "2026-07-26")
            .collect();
        // Two unrecognized client ids collapse onto `other`; the contract
        // rejects a duplicate (day, surface, model) grain, so they must merge.
        assert_eq!(other_rows.len(), 1);
        assert_eq!(other_rows[0].model, "__all__");
        assert_eq!(other_rows[0].credits_used.as_deref(), Some("5.000000"));
        assert_eq!(other_rows[0].total_tokens, Some(30));
        assert_eq!(normalized.dropped_model_rows, 1);
    }

    #[test]
    fn every_normalized_grain_is_unique() {
        let (start, end) = collection_window(now());
        let normalized =
            normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
        let mut seen = std::collections::HashSet::new();
        for row in &normalized.rows {
            assert!(
                seen.insert((row.provider_day.clone(), row.surface, row.model.clone())),
                "duplicate grain would be rejected by the contract"
            );
        }
    }

    #[test]
    fn days_outside_the_declared_window_are_dropped() {
        let payload = json!({
            "results": [
                {"date": "2026-07-26", "clients": [{"client_id": "CODEX_WEB", "credits": 1.0}]},
                {"date": "2020-01-01", "clients": [{"client_id": "CODEX_WEB", "credits": 5.0}]},
                {"date": "not-a-day", "clients": [{"client_id": "CODEX_WEB", "credits": 7.0}]},
                {"date": "2026-13-45", "clients": [{"client_id": "CODEX_WEB", "credits": 9.0}]},
                {"date": "2026-02-30", "clients": [{"client_id": "CODEX_WEB", "credits": 11.0}]}
            ]
        });
        let normalized =
            normalize_provider_window(&payload, "2026-07-01", "2026-07-26").expect("normalize");
        assert_eq!(normalized.rows.len(), 1);
        assert_eq!(normalized.rows[0].provider_day, "2026-07-26");
    }

    #[test]
    fn an_unrecognizable_payload_is_a_shape_failure_not_an_empty_day() {
        // Silently uploading "no usage" for a changed payload shape would read
        // as the customer having stopped working.
        assert!(matches!(
            normalize_provider_window(&json!({"unexpected": true}), "2026-07-01", "2026-07-26"),
            Err(ProviderReadError::ResponseShape(_))
        ));
        assert!(matches!(
            normalize_provider_window(
                &json!({"results": [{"no_date_here": 1}]}),
                "2026-07-01",
                "2026-07-26"
            ),
            Err(ProviderReadError::ResponseShape(_))
        ));
    }

    // -- windows and batching ---------------------------------------------

    #[test]
    fn the_collection_window_never_reaches_the_current_utc_day() {
        let (start, end) = collection_window(now());
        assert_eq!(
            end, "2026-07-26",
            "the current UTC day is still accumulating"
        );
        assert_eq!(day_span(&start, &end), Some(LOOKBACK_DAYS));
        assert!(day_span(&start, &end).is_some_and(|span| span <= MAX_COVERAGE_DAYS));
        // Just after midnight UTC the previous day is the newest complete one.
        let midnight = OffsetDateTime::parse("2026-01-01T00:04:00Z", &Rfc3339).expect("fixture");
        let (_, end) = collection_window(midnight);
        assert_eq!(end, "2025-12-31");
    }

    #[test]
    fn day_spans_are_exact_across_month_and_year_boundaries() {
        assert_eq!(day_span("2026-07-26", "2026-07-26"), Some(1));
        assert_eq!(day_span("2026-02-28", "2026-03-01"), Some(2));
        assert_eq!(day_span("2024-02-28", "2024-03-01"), Some(3));
        assert_eq!(day_span("2025-12-31", "2026-01-01"), Some(2));
    }

    fn day_offset(base: &str, offset: i64) -> String {
        let date = parse_day(base).expect("base day") + TimeDuration::days(offset);
        format!(
            "{:04}-{:02}-{:02}",
            date.year(),
            u8::from(date.month()),
            date.day()
        )
    }

    fn rows_on(day: &str, count: usize) -> Vec<DailyReferenceRow> {
        (0..count)
            .map(|index| DailyReferenceRow {
                provider_day: day.to_string(),
                surface: "codex_web",
                model: format!("model-{index}"),
                credits_used: None,
                uncached_input_tokens: None,
                cached_input_tokens: None,
                output_tokens: None,
                total_tokens: Some(1),
                thread_count: None,
                turn_count: None,
            })
            .collect()
    }

    #[test]
    fn batches_are_bounded_contiguous_and_oldest_first() {
        let mut rows = Vec::new();
        // 40 days x 30 rows = 1200 rows, past the per-batch bound.
        for offset in 0..40 {
            rows.extend(rows_on(&day_offset("2026-06-01", offset), 30));
        }
        let batches = pack_batches(rows, "2026-06-01", "2026-07-10").expect("pack");
        assert!(batches.len() > 1);
        let mut previous_end: Option<String> = None;
        for (start, end, rows) in &batches {
            assert!(rows.len() <= MAX_ROWS_PER_BATCH);
            assert!(day_span(start, end).is_some_and(|span| span <= MAX_COVERAGE_DAYS));
            assert!(start <= end);
            for row in rows {
                assert!(row.provider_day.as_str() >= start.as_str());
                assert!(row.provider_day.as_str() <= end.as_str());
            }
            if let Some(previous_end) = previous_end.as_deref() {
                // Abutting, so the backend's coverage envelope grows
                // contiguously and no untouched day is ever claimed.
                assert_eq!(day_span(previous_end, start), Some(2));
            }
            previous_end = Some(end.clone());
        }
        assert_eq!(batches[0].0, "2026-06-01");
        assert_eq!(batches.last().expect("last").1, "2026-07-10");
    }

    #[test]
    fn an_idle_window_still_declares_its_coverage() {
        // A genuinely idle account uploads an empty batch covering the window.
        // That is complete, not missing, and the backend distinguishes the two.
        let batches = pack_batches(Vec::new(), "2026-06-01", "2026-07-10").expect("pack");
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].0, "2026-06-01");
        assert_eq!(batches[0].1, "2026-07-10");
        assert!(batches[0].2.is_empty());
    }

    #[test]
    fn a_single_day_beyond_the_row_bound_is_refused_not_truncated() {
        let rows = rows_on("2026-07-26", MAX_ROWS_PER_BATCH + 1);
        assert!(pack_batches(rows, "2026-07-26", "2026-07-26").is_err());
    }

    #[test]
    fn batch_windows_abut_exactly_across_a_run_of_idle_days() {
        // Observed days are deliberately far apart. The backend's coverage
        // envelope is one contiguous span, and a window that neither overlaps
        // nor abuts the stored one *replaces* it - so a hole between two
        // batches would silently discard already-uploaded coverage.
        let mut rows = rows_on("2026-06-01", 600);
        rows.extend(rows_on("2026-06-20", 600));
        rows.extend(rows_on("2026-07-05", 600));
        let batches = pack_batches(rows, "2026-06-01", "2026-07-10").expect("pack");
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].0, "2026-06-01");
        // Closed the day before the next window opens, not on the last day that
        // happened to carry rows.
        assert_eq!(batches[0].1, "2026-06-19");
        assert_eq!(batches[1].0, "2026-06-20");
        assert_eq!(batches[1].1, "2026-07-04");
        assert_eq!(batches[2].0, "2026-07-05");
        assert_eq!(batches[2].1, "2026-07-10");
        for pair in batches.windows(2) {
            assert_eq!(
                day_span(&pair[0].1, &pair[1].0),
                Some(2),
                "consecutive coverage windows must abut exactly"
            );
        }
    }

    // -- consent ----------------------------------------------------------

    #[test]
    fn the_grant_file_persists_only_fingerprints() {
        let collector = collector("grant-fingerprints");
        enabled(&collector);
        let encoded = fs::read_to_string(collector.grants().path()).expect("read persisted grant");
        assert!(!encoded.contains(INSTALLATION_ID));
        assert!(!encoded.contains(ORG_SCOPE));
        assert!(!encoded.contains(USER_SCOPE));
        assert!(!encoded.contains(ACCOUNT_SCOPE));
        assert!(encoded.contains("installation_fingerprint"));
        assert!(encoded.contains("grant_scope_fingerprint"));
        assert!(encoded.contains("account_fingerprint"));
        let grant = collector.grants().load().expect("load").expect("grant");
        assert!(is_fingerprint(&grant.account_fingerprint));
        assert!(is_fingerprint(&grant.grant_scope_fingerprint));
        assert!(is_fingerprint(&grant.installation_fingerprint));
    }

    #[test]
    fn local_consent_is_not_live_until_the_backend_binds_it() {
        let collector = collector("consent-pending");
        let local = collector.grants().enable(&setup(), now()).expect("enable");
        assert_eq!(local.status, GrantStatus::ConsentRequired);
        assert!(local.backend_create_pending);
        assert!(!grant_runtime_ready(&local));
        let bound = collector
            .grants()
            .bind_backend_grant(&grant_response(&local, "enabled", 1), INSTALLATION_ID)
            .expect("bind");
        assert!(grant_runtime_ready(&bound));
    }

    #[test]
    fn a_backend_grant_epoch_must_advance() {
        let collector = collector("epoch-advance");
        let grant = enabled(&collector);
        assert!(collector
            .grants()
            .bind_backend_grant(&grant_response(&grant, "enabled", 1), INSTALLATION_ID)
            .is_err());
        let rebound = collector
            .grants()
            .bind_backend_grant(&grant_response(&grant, "enabled", 2), INSTALLATION_ID)
            .expect("advance epoch");
        assert_eq!(
            rebound
                .backend_binding
                .as_ref()
                .map(|binding| binding.grant_version),
            Some(2)
        );
        // A new epoch never inherits the previous epoch's evidence.
        assert_eq!(rebound.last_success_at, None);
    }

    #[test]
    fn a_mismatched_backend_response_is_refused() {
        let collector = collector("grant-response-mismatch");
        let local = collector.grants().enable(&setup(), now()).expect("enable");
        let mut wrong_account = grant_response(&local, "enabled", 1);
        wrong_account.account_fingerprint = format!("hmac-sha256:{}", "c".repeat(64));
        assert!(collector
            .grants()
            .bind_backend_grant(&wrong_account, INSTALLATION_ID)
            .is_err());
        let mut wrong_disclosure = grant_response(&local, "enabled", 1);
        wrong_disclosure.disclosure_version = "provider_daily_reference_disclosure.v2".to_string();
        assert!(collector
            .grants()
            .bind_backend_grant(&wrong_disclosure, INSTALLATION_ID)
            .is_err());
        assert!(collector
            .grants()
            .bind_backend_grant(&grant_response(&local, "enabled", 1), GRANT_ID)
            .is_err());
    }

    #[test]
    fn runtime_readiness_fails_closed_on_every_axis() {
        let collector = collector("runtime-readiness");
        let grant = enabled(&collector);
        assert!(grant_runtime_ready(&grant));

        // A daemon upgrade makes the recorded consent ineligible: the server
        // states the admitted build and consent is per build.
        let mut upgraded = grant.clone();
        upgraded.collector_version = "99.99.99".to_string();
        assert!(!grant_runtime_ready(&upgraded));

        // Server policy defaults closed.
        let mut disabled_policy = grant.clone();
        if let Some(binding) = disabled_policy.backend_binding.as_mut() {
            binding.server_policy_state = ServerPolicyState::Disabled;
        }
        assert!(!grant_runtime_ready(&disabled_policy));

        let mut rollout_off = grant.clone();
        if let Some(binding) = rollout_off.backend_binding.as_mut() {
            binding.server_policy_state = ServerPolicyState::RolloutDisabled;
        }
        assert!(!grant_runtime_ready(&rollout_off));

        let mut revoked_by_server = grant.clone();
        if let Some(binding) = revoked_by_server.backend_binding.as_mut() {
            binding.backend_revoked = true;
        }
        assert!(!grant_runtime_ready(&revoked_by_server));

        let mut unbound = grant.clone();
        unbound.backend_binding = None;
        assert!(!grant_runtime_ready(&unbound));

        let mut wrong_disclosure = grant.clone();
        wrong_disclosure.disclosure_version = "something_else.v1".to_string();
        assert!(!grant_runtime_ready(&wrong_disclosure));

        let mut revoked = grant;
        revoked.status = GrantStatus::Revoked;
        assert!(!grant_runtime_ready(&revoked));
    }

    #[test]
    fn health_never_resurrects_a_revoked_grant() {
        let collector = collector("revoked-health");
        enabled(&collector);
        collector.grants().revoke(now()).expect("revoke");
        collector
            .grants()
            .record_health(Some("2026-07-27T09:00:00Z"), None)
            .expect("record health");
        let grant = collector.grants().load().expect("load").expect("grant");
        assert_eq!(grant.status, GrantStatus::Revoked);
        assert_eq!(grant.last_success_at, None);
        assert!(!grant_runtime_ready(&grant));
    }

    // -- gates before the network -----------------------------------------

    #[test]
    fn absent_consent_is_silent_and_contacts_nothing() {
        let collector = collector("no-consent");
        let cycle =
            collector.collect_once(&runtime(), &ForbiddenReader, &ForbiddenTransport, now());
        assert_eq!(cycle.outcome, CycleOutcome::Disabled);
        assert!(
            cycle.diagnostics.is_empty(),
            "absence of consent is not a fault"
        );
    }

    #[test]
    fn the_sentinel_disables_collection_and_retires_local_state() {
        let collector = collector("sentinel");
        enabled(&collector);
        let transport = RecordingTransport::default();
        let reader = StaticReader::new(poisoned_payload());
        assert_eq!(
            collector
                .collect_once(&runtime(), &reader, &transport, now())
                .outcome,
            CycleOutcome::Uploaded
        );
        assert!(collector.state_path().is_file());

        fs::write(&collector.sentinel, b"disabled\n").expect("write sentinel");
        let cycle = collector.collect_once(
            &runtime(),
            &ForbiddenReader,
            &ForbiddenTransport,
            now() + TimeDuration::days(1),
        );
        assert_eq!(cycle.outcome, CycleOutcome::Disabled);
        assert_eq!(
            cycle.diagnostics[0].code,
            "codex_daily_aggregates_network_disabled"
        );
        assert_eq!(cycle.diagnostics[0].severity, AgentDiagnosticSeverity::Info);
        // The switch turns the data path off, not merely the socket.
        assert!(!collector.state_path().is_file());
    }

    #[test]
    fn an_unadmitted_build_stops_before_the_provider_is_contacted() {
        let collector = collector("unadmitted-build");
        let grant = enabled(&collector);
        let mut upgraded = grant_response(&grant, "enabled", 2);
        upgraded.collector_version = "99.99.99".to_string();
        collector
            .grants()
            .bind_backend_grant(&upgraded, INSTALLATION_ID)
            .expect("bind a build this binary is not");
        let cycle =
            collector.collect_once(&runtime(), &ForbiddenReader, &ForbiddenTransport, now());
        assert_eq!(cycle.outcome, CycleOutcome::Disabled);
    }

    #[test]
    fn a_different_provider_account_can_never_upload_under_this_consent() {
        let collector = collector("account-mismatch");
        enabled(&collector);
        let other_account = Runtime {
            installation_id: INSTALLATION_ID.to_string(),
            provider_account_scope: "acct-a-completely-different-account".to_string(),
        };
        let cycle =
            collector.collect_once(&other_account, &ForbiddenReader, &ForbiddenTransport, now());
        assert_eq!(cycle.outcome, CycleOutcome::Disabled);
        assert_eq!(
            cycle.diagnostics[0].code,
            "codex_daily_aggregates_account_mismatch"
        );
    }

    #[test]
    fn a_different_installation_can_never_upload_under_this_consent() {
        let collector = collector("installation-mismatch");
        enabled(&collector);
        let other_device = Runtime {
            installation_id: "00000000-0000-4000-8000-0000000000ff".to_string(),
            provider_account_scope: ACCOUNT_SCOPE.to_string(),
        };
        let cycle =
            collector.collect_once(&other_device, &ForbiddenReader, &ForbiddenTransport, now());
        assert_eq!(cycle.outcome, CycleOutcome::Disabled);
        assert_eq!(
            cycle.diagnostics[0].code,
            "codex_daily_aggregates_installation_mismatch"
        );
    }

    #[test]
    fn an_unconfigured_transport_defers_before_the_provider_is_contacted() {
        let collector = collector("deferred-transport");
        enabled(&collector);
        let cycle = collector.collect_once(&runtime(), &ForbiddenReader, &DeferredTransport, now());
        assert_eq!(cycle.outcome, CycleOutcome::Deferred);
    }

    // -- cadence ----------------------------------------------------------

    #[test]
    fn the_cadence_gate_stays_in_its_band_and_is_stable_per_installation() {
        for seed in [
            "",
            "a",
            "installation-one",
            "installation-two",
            &"z".repeat(64),
        ] {
            let interval = fetch_interval_seconds(seed);
            assert!(
                (FETCH_INTERVAL_SECONDS - FETCH_INTERVAL_JITTER_SECONDS
                    ..=FETCH_INTERVAL_SECONDS + FETCH_INTERVAL_JITTER_SECONDS)
                    .contains(&interval),
                "{seed} produced {interval}, outside the 5h45m-6h15m band"
            );
            assert_eq!(
                interval,
                fetch_interval_seconds(seed),
                "phase must be stable"
            );
        }
        assert!(
            ["installation-one", "installation-two", "installation-three"]
                .iter()
                .map(|seed| fetch_interval_seconds(seed))
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 1,
            "the spread must actually spread load across installs"
        );
    }

    #[test]
    fn a_second_cycle_inside_the_cadence_window_does_nothing() {
        let collector = collector("cadence-gate");
        enabled(&collector);
        let reader = StaticReader::new(poisoned_payload());
        let transport = RecordingTransport::default();
        assert_eq!(
            collector
                .collect_once(&runtime(), &reader, &transport, now())
                .outcome,
            CycleOutcome::Uploaded
        );
        assert_eq!(reader.calls.get(), 1);
        let cycle = collector.collect_once(
            &runtime(),
            &reader,
            &transport,
            now() + TimeDuration::hours(1),
        );
        assert_eq!(cycle.outcome, CycleOutcome::Noop);
        assert_eq!(reader.calls.get(), 1, "day-grain data is polled sparsely");

        let cycle = collector.collect_once(
            &runtime(),
            &reader,
            &transport,
            now() + TimeDuration::hours(7),
        );
        assert_eq!(cycle.outcome, CycleOutcome::Uploaded);
        assert_eq!(reader.calls.get(), 2);
    }

    // -- circuit breaker ---------------------------------------------------

    #[test]
    fn each_failure_class_opens_the_breaker_at_its_own_threshold() {
        let cases = [
            (ProviderFailure::AuthRejected, BREAKER_AUTH_THRESHOLD),
            (ProviderFailure::ResponseShape, BREAKER_SHAPE_THRESHOLD),
            (ProviderFailure::RateLimited, BREAKER_RATE_LIMIT_THRESHOLD),
        ];
        for (failure, threshold) in cases {
            let mut state = CollectorState::default();
            for attempt in 1..threshold {
                state = state_after_failure(state, "identity", failure, "category", 1_000);
                assert!(
                    !breaker_is_open(&state, 1_000),
                    "{failure:?} opened after {attempt} of {threshold}"
                );
            }
            state = state_after_failure(state, "identity", failure, "category", 1_000);
            assert!(breaker_is_open(&state, 1_000));
            assert_eq!(state.opened_by, failure.code());
            assert!(!breaker_is_open(&state, 1_000 + BREAKER_COOLDOWN_SECONDS));
        }
    }

    #[test]
    fn failure_classes_do_not_pool_and_transients_never_count() {
        let mut state = CollectorState::default();
        state = state_after_failure(
            state,
            "identity",
            ProviderFailure::AuthRejected,
            "category",
            10,
        );
        state = state_after_failure(
            state,
            "identity",
            ProviderFailure::ResponseShape,
            "category",
            10,
        );
        state = state_after_failure(
            state,
            "identity",
            ProviderFailure::RateLimited,
            "category",
            10,
        );
        assert!(!breaker_is_open(&state, 10), "classes must not pool");

        // Transport failures and 5xx say the network or the vendor had a bad
        // moment, not that we should stop asking.
        assert_eq!(
            ProviderReadError::Transient("boom".to_string()).failure_class(),
            None
        );
        assert_eq!(
            ProviderReadError::AuthRejected(403).failure_class(),
            Some(ProviderFailure::AuthRejected)
        );
    }

    #[test]
    fn one_clean_answer_clears_the_failure_counters() {
        let mut state = CollectorState::default();
        for _ in 0..2 {
            state = state_after_failure(
                state,
                "identity",
                ProviderFailure::AuthRejected,
                "category",
                10,
            );
        }
        assert_eq!(state.auth_failures, 2);
        let state = state_after_success(state, "identity", 20);
        assert_eq!(state.auth_failures, 0);
        assert_eq!(state.reopen_after_epoch_seconds, 0);
        assert_eq!(state.last_error_category, None);
    }

    #[test]
    fn breaker_state_is_scoped_to_the_grant_epoch_and_the_call_configuration() {
        let collector = collector("breaker-scope");
        let grant = enabled(&collector);
        let identity = state_identity(&grant, false);
        let state = state_after_failure(
            CollectorState::default(),
            &identity,
            ProviderFailure::AuthRejected,
            "provider_auth_rejected",
            10,
        );
        collector.state.save(&state).expect("save state");
        assert_eq!(collector.state.load(&identity).auth_failures, 1);
        // A re-consent, an account change, or a change to the endpoint or the
        // User-Agent reads as a clean slate rather than inheriting a verdict.
        assert_eq!(collector.state.load("another-identity").auth_failures, 0);
        assert_ne!(identity, state_identity(&grant, true));
    }

    #[test]
    fn repeated_auth_rejections_open_the_breaker_and_stop_the_provider_call() {
        let collector = collector("breaker-through-cycles");
        enabled(&collector);
        let reader = FailingReader::new(vec![
            ProviderReadError::AuthRejected(401),
            ProviderReadError::AuthRejected(403),
            ProviderReadError::AuthRejected(403),
        ]);
        let transport = RecordingTransport::default();
        let mut clock = now();
        for _ in 0..2 {
            assert_eq!(
                collector
                    .collect_once(&runtime(), &reader, &transport, clock)
                    .outcome,
                CycleOutcome::Failed
            );
            clock += TimeDuration::hours(7);
        }
        let cycle = collector.collect_once(&runtime(), &reader, &transport, clock);
        assert_eq!(cycle.outcome, CycleOutcome::CircuitOpen);
        assert_eq!(
            cycle.diagnostics[0].code,
            "codex_daily_aggregates_circuit_open"
        );
        assert_eq!(reader.calls.get(), 3);

        // While open, no request is made at all.
        clock += TimeDuration::hours(7);
        let cycle = collector.collect_once(&runtime(), &ForbiddenReader, &transport, clock);
        assert_eq!(cycle.outcome, CycleOutcome::CircuitOpen);
        assert!(transport.batches.borrow().is_empty());

        // The cool-down closes it.
        let cycle = collector.collect_once(
            &runtime(),
            &StaticReader::new(poisoned_payload()),
            &transport,
            clock + TimeDuration::hours(25),
        );
        assert_eq!(cycle.outcome, CycleOutcome::Uploaded);
    }

    #[test]
    fn a_transient_provider_failure_never_opens_the_breaker() {
        let collector = collector("transient-failures");
        enabled(&collector);
        let reader = FailingReader::new(vec![
            ProviderReadError::Transient("dns".to_string()),
            ProviderReadError::Transient("503".to_string()),
            ProviderReadError::Transient("timeout".to_string()),
            ProviderReadError::Transient("reset".to_string()),
        ]);
        let transport = RecordingTransport::default();
        let mut clock = now();
        for _ in 0..4 {
            assert_eq!(
                collector
                    .collect_once(&runtime(), &reader, &transport, clock)
                    .outcome,
                CycleOutcome::Failed
            );
            clock += TimeDuration::hours(7);
        }
        assert_eq!(reader.calls.get(), 4, "transients must keep being retried");
    }

    // -- upload ------------------------------------------------------------

    #[test]
    fn a_not_admitted_answer_is_typed_expected_and_never_trips_the_breaker() {
        let collector = collector("not-admitted");
        enabled(&collector);
        let reader = StaticReader::new(poisoned_payload());
        let transport = RejectingTransport::new(UploadError::NotAdmitted(403));
        let mut clock = now();
        for _ in 0..5 {
            let cycle = collector.collect_once(&runtime(), &reader, &transport, clock);
            assert_eq!(cycle.outcome, CycleOutcome::NotAdmitted);
            // Expected until a reviewed backend change admits this build, so it
            // is reported at info severity, not as a fault.
            assert_eq!(
                diagnostic(&cycle, "codex_daily_aggregates_collector_not_admitted").severity,
                AgentDiagnosticSeverity::Info
            );
            clock += TimeDuration::hours(7);
        }
        // Five refusals in a row and the provider read is still healthy.
        let state = collector.state.load(&state_identity(
            &collector.grants().load().expect("load").expect("grant"),
            false,
        ));
        assert_eq!(state.auth_failures, 0);
        assert_eq!(state.shape_failures, 0);
        assert_eq!(state.rate_limit_failures, 0);
        assert!(!breaker_is_open(&state, unix_seconds(clock)));
    }

    #[test]
    fn a_stale_consent_epoch_stops_the_cycle_rather_than_retrying() {
        let collector = collector("epoch-conflict");
        enabled(&collector);
        let reader = StaticReader::new(poisoned_payload());
        let transport = RejectingTransport::new(UploadError::GrantEpochConflict);
        let cycle = collector.collect_once(&runtime(), &reader, &transport, now());
        assert_eq!(cycle.outcome, CycleOutcome::Failed);
        assert_eq!(transport.calls.get(), 1, "only re-consent can fix an epoch");
        let grant = collector.grants().load().expect("load").expect("grant");
        assert_eq!(
            grant.last_error_category.as_deref(),
            Some("grant_epoch_conflict")
        );
    }

    #[test]
    fn the_uploaded_batch_declares_the_consented_epoch_and_identity() {
        let collector = collector("batch-envelope");
        let grant = enabled(&collector);
        let reader = StaticReader::new(poisoned_payload());
        let transport = RecordingTransport::default();
        assert_eq!(
            collector
                .collect_once(&runtime(), &reader, &transport, now())
                .outcome,
            CycleOutcome::Uploaded
        );
        let batches = transport.batches.borrow();
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(batch["schema_version"], SCHEMA_VERSION);
        assert_eq!(batch["source"], SOURCE);
        assert_eq!(batch["collector_id"], COLLECTOR_ID);
        assert_eq!(batch["collector_version"], compiled_release_version());
        assert_eq!(batch["installation_id"], INSTALLATION_ID);
        assert_eq!(batch["provider_day_timezone"], "UTC");
        assert_eq!(batch["grant_version"], 1);
        assert_eq!(
            batch["grant_scope_fingerprint"],
            grant.grant_scope_fingerprint
        );
        assert_eq!(batch["account_fingerprint"], grant.account_fingerprint);
        assert_eq!(batch["coverage_end"], "2026-07-26");
        assert!(wire_payload_is_content_free(batch));
        let encoded = serde_json::to_string(batch).expect("encode");
        for poison in poison_strings() {
            assert!(!encoded.contains(poison), "the wire leaked {poison}");
        }
        let grant = collector.grants().load().expect("load").expect("grant");
        assert!(grant.last_success_at.is_some());
        assert_eq!(grant.last_error_category, None);
    }

    #[test]
    fn an_acknowledgement_that_does_not_echo_the_batch_is_refused() {
        assert!(validate_ack(
            &json!({
                "schema_version": ACK_SCHEMA_VERSION,
                "grant_id": GRANT_ID,
                "accepted_row_count": 3,
                "coverage_start": "2026-07-01",
                "coverage_end": "2026-07-26",
            }),
            "2026-07-01",
            "2026-07-26"
        )
        .is_ok());
        assert!(validate_ack(
            &json!({
                "schema_version": "something_else.v1",
                "accepted_row_count": 3,
                "coverage_start": "2026-07-01",
                "coverage_end": "2026-07-26",
            }),
            "2026-07-01",
            "2026-07-26"
        )
        .is_err());
        assert!(validate_ack(
            &json!({
                "schema_version": ACK_SCHEMA_VERSION,
                "accepted_row_count": 3,
                "coverage_start": "2026-07-01",
                "coverage_end": "2026-07-20",
            }),
            "2026-07-01",
            "2026-07-26"
        )
        .is_err());
    }

    // -- credential --------------------------------------------------------

    #[test]
    fn the_account_scope_is_the_account_not_the_token() {
        let credential = codex_credential_from_auth(&json!({
            "account_id": "acct-123",
            "tokens": {"access_token": "secret-token-value"}
        }))
        .expect("credential");
        assert_eq!(credential.account_scope, "acct-123");
        assert_eq!(credential.account_id.as_deref(), Some("acct-123"));
        // A token rotation must not read as a different account and strand the
        // customer's consent.
        let rotated = codex_credential_from_auth(&json!({
            "account_id": "acct-123",
            "tokens": {"access_token": "a-completely-different-token"}
        }))
        .expect("credential");
        assert_eq!(rotated.account_scope, credential.account_scope);
        assert!(codex_credential_from_auth(&json!({"tokens": {}})).is_none());
        assert!(codex_credential_from_auth(&json!({
            "tokens": {"access_token": "   "}
        }))
        .is_none());
    }

    #[test]
    fn the_account_scope_falls_back_to_the_id_token_claim() {
        // {"https://api.openai.com/auth":{"chatgpt_account_id":"acct-from-claim"}}
        let claim = "eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC1mcm9tLWNsYWltIn19";
        let credential = codex_credential_from_auth(&json!({
            "tokens": {"access_token": "token", "id_token": format!("header.{claim}.signature")}
        }))
        .expect("credential");
        assert_eq!(credential.account_scope, "acct-from-claim");
    }

    // -- posture -----------------------------------------------------------

    #[test]
    fn the_capability_reaches_exactly_one_provider_route() {
        assert_eq!(
            PROVIDER_ENDPOINT,
            "https://chatgpt.com/backend-api/wham/analytics/daily-workspace-usage-counts"
        );
        // Content endpoints are permanently out of scope for this capability.
        // Scan production code only, with comments stripped, so the exclusion
        // can be documented in prose without defeating its own guard.
        let source = include_str!("provider_daily_reference.rs");
        let production = source
            .split("\nmod tests {")
            .next()
            .expect("production source");
        let code_only = production
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with('*')
            })
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "wham/tasks",
            "teleport-events",
            "/v1/sessions",
            "claude_code_shared_session_transcripts",
        ] {
            assert!(
                !code_only.contains(forbidden),
                "this module must never reference {forbidden}"
            );
        }
    }

    #[test]
    fn the_provider_read_identifies_itself_honestly() {
        let agent = crate::agent_status::ottto_user_agent();
        assert!(agent.starts_with("ottto/"));
        assert!(agent.contains("subscription-usage-reader"));
        assert!(!agent.to_ascii_lowercase().contains("chatgpt"));
        assert!(!agent.to_ascii_lowercase().contains("codex"));
        assert!(!agent.to_ascii_lowercase().contains("claude"));
    }
}
