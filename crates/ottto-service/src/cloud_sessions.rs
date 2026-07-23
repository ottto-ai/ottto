//! Supported, metadata-only Codex Cloud session collector.
//!
//! The collector invokes only `codex cloud list --json` as the effective user.
//! It never opens `auth.json`, reads OpenAI credentials, or calls provider
//! endpoints directly. After exact consent and destination checks, it reads
//! only Ottto's relay device credential for Ottto backend authentication. Raw
//! CLI JSON, task titles, URLs, provider ids, and cursors are used only in
//! memory to derive content-free observations.

use anyhow::{anyhow, Context, Result};
use getrandom::fill as random_fill;
use hmac::{Hmac, Mac};
use ottto_core::{
    compiled_release_version, default_support_dir, FileAccountStore, FileConnectionStore,
    FileDeviceStore, LocalDeviceBinding,
};
use ottto_protocol::LocalAccountState;
pub use ottto_protocol::{CloudSessionBackendGrantResponseV1, CloudSessionServerPolicyState};
use serde::{Deserialize, Deserializer, Serialize};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

const COLLECTOR_ID: &str = "cloud_sessions";
const COLLECTOR_VERSION: &str = "cloud_session_observations.v1";
const CHUNK_SCHEMA_VERSION: &str = "cloud_session_observation_chunk.v2";
const FINALIZE_SCHEMA_VERSION: &str = "cloud_session_scan_finalize.v2";
const GRANT_SCHEMA_VERSION: &str = "cloud_session_grant.v1";
const CHECKPOINT_SCHEMA_VERSION: &str = "cloud_session_checkpoint.v1";
const CONTROL_TOKEN_LEDGER_SCHEMA_VERSION: &str = "cloud_session_control_token_uses.v1";
const MAX_CONTROL_TOKEN_USES: usize = 64;
const MAX_PAGES: usize = 10;
const MAX_ITEMS: usize = 200;
const MAX_SCAN_PAGES: usize = 100;
const MAX_SCAN_ITEMS: usize = 2_000;
const MAX_SCAN_CHUNKS: usize = 10;
const PAGE_LIMIT: usize = 20;
const MAX_PAGE_OUTPUT_BYTES: u64 = (PAGE_LIMIT * 256 * 1024) as u64;
const CYCLE_BUDGET: Duration = Duration::from_secs(45);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);
const RELAY_IO_TIMEOUT: Duration = COMMAND_TIMEOUT;
pub(crate) const COLLECTOR_IO_STOP_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);
const HEALTH_HEARTBEAT_INTERVAL: TimeDuration = TimeDuration::hours(1);
const MAX_JITTER: Duration = Duration::from_secs(20);
const KILL_SWITCH_ENV: &str = "OTTTO_CODEX_CLOUD_SESSIONS_DISABLED";
const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const LEGACY_API_BASE_URL: &str = "https://ottto.net/backend";

static COLLECTOR_SUPERVISOR_STARTED: AtomicBool = AtomicBool::new(false);

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSessionGrantStatus {
    Off,
    ConsentRequired,
    Enabled,
    Paused,
    Revoked,
    PolicyDisabled,
}

/// Operator/UI status for this collector. The service exposes this without
/// starting the provider CLI, so setup and transport readiness can be shown
/// safely before any cloud-session collection is permitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSessionRuntimeState {
    Off,
    ConsentRequired,
    Enabled,
    Paused,
    Revoked,
    PolicyDisabled,
    TransportDeferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionCollectorStatusV1 {
    pub schema_version: String,
    pub collector_id: String,
    pub grant_status: CloudSessionGrantStatus,
    pub runtime_state: CloudSessionRuntimeState,
    pub transport_configured: bool,
    /// This is false while the typed ingest transport is deferred. Consumers
    /// must not imply that enabling a grant will call the Codex CLI.
    pub provider_cli_invocation_permitted: bool,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionGrant {
    pub schema_version: String,
    pub collector_id: String,
    pub collector_version: String,
    pub release_lane: String,
    pub disclosure_version: String,
    pub status: CloudSessionGrantStatus,
    /// Opaque grant-local fingerprint; the raw installation id is never persisted.
    pub installation_fingerprint: String,
    /// Immutable identity for this exact installation/user/collector grant.
    pub grant_scope_id: String,
    pub organization_fingerprint: String,
    pub effective_user_fingerprint: String,
    /// Opaque local Ottto org/user collector scope. This is not a Codex or
    /// OpenAI provider-account identity; the supported CLI exposes none.
    pub account_fingerprint: String,
    /// Server-owned grant epoch. Absent until an authenticated companion/UI
    /// creates the backend grant and binds its response into this local state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_binding: Option<CloudSessionBackendGrantBindingV1>,
    /// True from authenticated create-payload handoff until its POST is
    /// reconciled. Scope replacement is blocked because a timed-out POST may
    /// still have created a backend grant whose id has not returned yet.
    #[serde(default)]
    pub backend_create_pending: bool,
    /// Content-free identity for the exact create request represented by the
    /// pending tombstone. The raw installation id remains caller-supplied and
    /// is accepted only when it matches `installation_fingerprint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_backend_create: Option<CloudSessionPendingBackendCreateV1>,
    pub granted_at: Option<String>,
    pub paused_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_collector_health: Option<String>,
    pub last_freshness: Option<String>,
    pub last_error_category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionBackendGrantBindingV1 {
    pub grant_id: String,
    pub grant_version: u64,
    #[serde(default)]
    pub backend_revoked: bool,
    /// Missing policy on an older persisted binding fails closed.
    #[serde(default)]
    pub server_policy_state: CloudSessionServerPolicyState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionPendingBackendCreateV1 {
    pub source: String,
    pub collector_id: String,
    pub schema_version: String,
    pub collector_version: String,
    pub grant_scope_fingerprint: String,
    pub account_fingerprint: String,
    pub consent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionBackendGrantCreateRequestV1 {
    pub installation_id: String,
    pub source: String,
    pub collector_id: String,
    pub schema_version: String,
    pub collector_version: String,
    pub grant_scope_fingerprint: String,
    pub account_fingerprint: String,
    pub consent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudSessionBackendGrantRevokeTargetV1 {
    pub grant_id: String,
}

#[derive(Debug, Clone)]
pub struct CloudSessionGrantSetup {
    pub installation_id: String,
    pub organization_scope: String,
    pub effective_user_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedGrant {
    schema_version: String,
    hmac_key_hex: String,
    grant: CloudSessionGrant,
}

/// Upgrade-only representation written before installation scope became
/// content-free. It is never serialized again after a successful read.
#[derive(Debug, Clone, Deserialize)]
struct LegacyPersistedGrantV1 {
    schema_version: String,
    hmac_key_hex: String,
    grant: LegacyCloudSessionGrantV1,
}

#[derive(Debug, Clone, Deserialize)]
struct LegacyCloudSessionGrantV1 {
    schema_version: String,
    collector_id: String,
    collector_version: String,
    release_lane: String,
    disclosure_version: String,
    status: CloudSessionGrantStatus,
    installation_id: String,
    organization_fingerprint: String,
    effective_user_fingerprint: String,
    account_fingerprint: String,
    granted_at: Option<String>,
    paused_at: Option<String>,
    revoked_at: Option<String>,
    last_collector_health: Option<String>,
    last_freshness: Option<String>,
    last_error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CloudSessionControlTokenUseLedger {
    schema_version: String,
    entries: Vec<CloudSessionControlTokenUse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CloudSessionControlTokenUse {
    token_digest: String,
    expires_at_unix: u64,
}

/// Owner-only, bounded replay ledger for device-bound one-time action tokens.
/// Only SHA-256(jti) and expiry are persisted; the signed token and raw jti are
/// never written to disk.
#[derive(Debug, Clone)]
pub struct CloudSessionControlTokenUseStore {
    path: PathBuf,
}

impl CloudSessionControlTokenUseStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn consume(&self, token_id: &str, expires_at_unix: u64, now_unix: u64) -> Result<()> {
        let token_id = token_id.trim();
        if token_id.is_empty()
            || token_id.len() > 128
            || expires_at_unix <= now_unix
            || expires_at_unix > now_unix.saturating_add(300)
        {
            return Err(anyhow!("cloud-session control token lifetime is invalid"));
        }
        let _lock = self.lock()?;
        let mut ledger = if self.path.exists() {
            serde_json::from_slice::<CloudSessionControlTokenUseLedger>(
                &fs::read(&self.path).context("read cloud-session control token ledger")?,
            )
            .context("decode cloud-session control token ledger")?
        } else {
            CloudSessionControlTokenUseLedger {
                schema_version: CONTROL_TOKEN_LEDGER_SCHEMA_VERSION.to_string(),
                entries: Vec::new(),
            }
        };
        if ledger.schema_version != CONTROL_TOKEN_LEDGER_SCHEMA_VERSION {
            return Err(anyhow!("unsupported cloud-session control token ledger"));
        }
        ledger
            .entries
            .retain(|entry| entry.expires_at_unix > now_unix);
        let token_digest = hex(&Sha256::digest(token_id.as_bytes()));
        if ledger
            .entries
            .iter()
            .any(|entry| entry.token_digest == token_digest)
        {
            return Err(anyhow!("cloud-session control token was already used"));
        }
        // Never evict an unexpired digest to make room: that would make its
        // still-valid action token replayable. A full five-minute window fails
        // closed until expiry pruning creates capacity.
        if ledger.entries.len() >= MAX_CONTROL_TOKEN_USES {
            return Err(anyhow!(
                "cloud-session control token replay ledger is at capacity"
            ));
        }
        ledger.entries.push(CloudSessionControlTokenUse {
            token_digest,
            expires_at_unix,
        });
        ledger.entries.sort_by_key(|entry| entry.expires_at_unix);
        atomic_json_write(&self.path, &ledger)
    }

    fn lock(&self) -> Result<CloudSessionGrantLock> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| anyhow!("cloud-session control token ledger path has no parent"))?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let path = self.path.with_extension("lock");
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .context("open cloud-session control token ledger lock")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(unix)]
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) } != 0 {
            return Err(anyhow!("lock cloud-session control token ledger"));
        }
        Ok(CloudSessionGrantLock { file })
    }
}

impl Default for CloudSessionControlTokenUseStore {
    fn default() -> Self {
        Self::new(
            default_support_dir()
                .join("cloud_sessions")
                .join("control-token-uses.json"),
        )
    }
}

#[derive(Debug, Clone)]
pub struct CloudSessionGrantStore {
    path: PathBuf,
}

impl CloudSessionGrantStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<CloudSessionGrant>> {
        Ok(self.read()?.map(|state| state.grant))
    }

    /// Return a collection candidate only when the persisted HMAC scope still
    /// binds the exact local device, organization, and user. This is read-only:
    /// a mismatch cannot rewrite consent or make a stale grant current again.
    fn runtime_candidate_for(
        &self,
        setup: &CloudSessionGrantSetup,
    ) -> Result<Option<CloudSessionGrant>> {
        let Some(state) = self.read()? else {
            return Ok(None);
        };
        if !cloud_grant_preflight_eligible(&state.grant) {
            return Ok(None);
        }
        let key = decode_hex(&state.hmac_key_hex)
            .filter(|key| key.len() == 32)
            .ok_or_else(|| anyhow!("invalid cloud-session HMAC key"))?;
        let exact_scope = state.grant.installation_fingerprint
            == opaque_key(&key, &setup.installation_id)
            && state.grant.organization_fingerprint == opaque_key(&key, &setup.organization_scope)
            && state.grant.effective_user_fingerprint
                == opaque_key(&key, &setup.effective_user_scope)
            && state.grant.account_fingerprint
                == opaque_key(
                    &key,
                    &format!(
                        "{}\u{0}{}",
                        setup.organization_scope, setup.effective_user_scope
                    ),
                )
            && state.grant.grant_scope_id == grant_scope_fingerprint(&key, setup);
        if !exact_scope {
            return Err(anyhow!(
                "cloud-session grant does not match the current local identity"
            ));
        }
        Ok(Some(state.grant))
    }

    /// Prepare explicit local consent. Scope inputs are converted to HMAC
    /// fingerprints before persistence; the raw values are never serialized.
    /// Collection remains blocked in `consent_required` until `bind_backend_grant`
    /// accepts the authenticated backend's grant id and version.
    pub fn enable(
        &self,
        setup: &CloudSessionGrantSetup,
        _now: OffsetDateTime,
    ) -> Result<CloudSessionGrant> {
        if !is_uuid(&setup.installation_id)
            || setup.organization_scope.trim().is_empty()
            || setup.effective_user_scope.trim().is_empty()
        {
            return Err(anyhow!("cloud-session grant scope is incomplete"));
        }
        let _lock = self.lock()?;
        let existing = self.read_locked()?;
        if let Some(mut state) = existing {
            let key = decode_hex(&state.hmac_key_hex)
                .filter(|key| key.len() == 32)
                .ok_or_else(|| anyhow!("invalid cloud-session HMAC key"))?;
            let expected_scope = grant_scope_fingerprint(&key, setup);
            if state.grant.grant_scope_id == expected_scope {
                if state.grant.backend_create_pending {
                    // A browser may lose the loopback prepare response before
                    // issuing the authenticated POST. Repeating the exact
                    // device/user/org action returns the same tombstoned create
                    // payload; scope replacement remains blocked below.
                    if state.grant.status == CloudSessionGrantStatus::ConsentRequired {
                        validate_pending_backend_create(
                            &state.grant,
                            &state
                                .grant
                                .pending_backend_create
                                .clone()
                                .unwrap_or_else(|| pending_backend_create(&state.grant)),
                        )?;
                        return Ok(state.grant);
                    }
                    return Err(anyhow!(
                        "pending cloud-session backend grant creation must be reconciled before setup changes"
                    ));
                }
                if state.grant.revoked_at.is_some()
                    && state
                        .grant
                        .backend_binding
                        .as_ref()
                        .is_some_and(|binding| !binding.backend_revoked)
                {
                    return Err(anyhow!(
                        "revoked cloud-session backend grant must be deleted before re-consent"
                    ));
                }
                if state.grant.status == CloudSessionGrantStatus::Enabled
                    && cloud_grant_runtime_ready(&state.grant)
                {
                    return Ok(state.grant);
                }
                if state.grant.status == CloudSessionGrantStatus::Paused
                    && state.grant.collector_version == compiled_release_version()
                    && state
                        .grant
                        .backend_binding
                        .as_ref()
                        .is_some_and(|binding| !binding.backend_revoked)
                {
                    state.grant.status =
                        if state.grant.backend_binding.as_ref().is_some_and(|binding| {
                            binding.server_policy_state == CloudSessionServerPolicyState::Approved
                        }) {
                            CloudSessionGrantStatus::Enabled
                        } else {
                            CloudSessionGrantStatus::PolicyDisabled
                        };
                    state.grant.paused_at = None;
                    state.grant.last_collector_health = Some(
                        match state.grant.status {
                            CloudSessionGrantStatus::Enabled => "enabled",
                            _ => "policy_disabled",
                        }
                        .to_string(),
                    );
                    self.write(&state)?;
                    return Ok(state.grant);
                }
                if state.grant.status == CloudSessionGrantStatus::PolicyDisabled
                    && state.grant.collector_version == compiled_release_version()
                    && state
                        .grant
                        .backend_binding
                        .as_ref()
                        .is_some_and(|binding| !binding.backend_revoked)
                {
                    return Ok(state.grant);
                }
                state.grant.status = CloudSessionGrantStatus::ConsentRequired;
                state.grant.paused_at = None;
                state.grant.last_collector_health = Some("consent_required".to_string());
                state.grant.last_freshness = Some("unavailable".to_string());
                state.grant.last_error_category = None;
                self.write(&state)?;
                return Ok(state.grant);
            }
            if state.grant.backend_create_pending
                || state
                    .grant
                    .backend_binding
                    .as_ref()
                    .is_some_and(|binding| !binding.backend_revoked)
            {
                return Err(anyhow!(
                    "existing cloud-session grant must be locally stopped and backend-revoked before scope replacement"
                ));
            }
        }
        let key = random_key()?;
        let installation_fingerprint = opaque_key(&key, &setup.installation_id);
        let grant_scope_id = grant_scope_fingerprint(&key, setup);
        let grant = CloudSessionGrant {
            schema_version: GRANT_SCHEMA_VERSION.to_string(),
            collector_id: COLLECTOR_ID.to_string(),
            collector_version: compiled_release_version(),
            release_lane: "supported".to_string(),
            disclosure_version: "cloud_sessions_disclosure.v1".to_string(),
            status: CloudSessionGrantStatus::ConsentRequired,
            installation_fingerprint,
            grant_scope_id,
            organization_fingerprint: opaque_key(&key, &setup.organization_scope),
            effective_user_fingerprint: opaque_key(&key, &setup.effective_user_scope),
            account_fingerprint: opaque_key(
                &key,
                &format!(
                    "{}\u{0}{}",
                    setup.organization_scope, setup.effective_user_scope
                ),
            ),
            backend_binding: None,
            backend_create_pending: false,
            pending_backend_create: None,
            granted_at: None,
            paused_at: None,
            revoked_at: None,
            last_collector_health: Some("consent_required".to_string()),
            last_freshness: Some("unavailable".to_string()),
            last_error_category: None,
        };
        self.write(&PersistedGrant {
            schema_version: GRANT_SCHEMA_VERSION.to_string(),
            hmac_key_hex: hex(&key),
            grant: grant.clone(),
        })?;
        Ok(grant)
    }

    /// Build the exact authenticated backend consent payload without retaining
    /// the raw installation id. The caller must POST it with ordinary-user auth.
    pub fn grant_create_request(
        &self,
        installation_id: &str,
    ) -> Result<CloudSessionBackendGrantCreateRequestV1> {
        let _lock = self.lock()?;
        let mut state = self
            .read_locked()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        let key = decode_hex(&state.hmac_key_hex)
            .filter(|key| key.len() == 32)
            .ok_or_else(|| anyhow!("invalid cloud-session HMAC key"))?;
        if !is_uuid(installation_id)
            || opaque_key(&key, installation_id) != state.grant.installation_fingerprint
        {
            return Err(anyhow!("cloud-session installation binding is invalid"));
        }
        if state.grant.backend_create_pending {
            let pending = state
                .grant
                .pending_backend_create
                .clone()
                .unwrap_or_else(|| pending_backend_create(&state.grant));
            validate_pending_backend_create(&state.grant, &pending)?;
            if state.grant.pending_backend_create.is_none() {
                state.grant.pending_backend_create = Some(pending.clone());
                self.write(&state)?;
            }
            return Ok(backend_create_request(installation_id, &pending));
        }
        if state.grant.status != CloudSessionGrantStatus::ConsentRequired {
            return Err(anyhow!(
                "cloud-session backend grant creation requires fresh local consent"
            ));
        }
        let pending = CloudSessionPendingBackendCreateV1 {
            source: "codex".to_string(),
            collector_id: COLLECTOR_ID.to_string(),
            schema_version: COLLECTOR_VERSION.to_string(),
            collector_version: compiled_release_version(),
            grant_scope_fingerprint: state.grant.grant_scope_id.clone(),
            account_fingerprint: state.grant.account_fingerprint.clone(),
            consent: true,
        };
        state.grant.backend_create_pending = true;
        state.grant.pending_backend_create = Some(pending.clone());
        self.write(&state)?;
        Ok(backend_create_request(installation_id, &pending))
    }

    /// Bind an authenticated backend grant response. Exact scope matching and
    /// monotonic grant versions prevent a pre-revoke batch epoch from being
    /// resurrected after re-consent.
    pub fn bind_backend_grant(
        &self,
        response: &CloudSessionBackendGrantResponseV1,
        expected_installation_id: &str,
    ) -> Result<CloudSessionGrant> {
        let _lock = self.lock()?;
        let mut state = self
            .read_locked()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        let local_status = state.grant.status.clone();
        validate_local_installation_binding(
            &state,
            expected_installation_id,
            "backend cloud-session grant",
        )?;
        if !state.grant.backend_create_pending {
            validate_backend_grant_response(&state, response, &state.grant.collector_version)?;
            if response.installation_id != expected_installation_id || response.status != "enabled"
            {
                return Err(anyhow!("backend cloud-session grant does not match"));
            }
            let existing = state
                .grant
                .backend_binding
                .as_ref()
                .ok_or_else(|| anyhow!("backend cloud-session grant is unbound"))?;
            if existing.grant_id == response.id
                && existing.grant_version == response.grant_version
                && !existing.backend_revoked
                && existing.server_policy_state == response.server_policy_state
            {
                // Lost loopback responses retry the exact authenticated bind.
                // Return the current local state without rewriting timestamps
                // or resurrecting a later pause/revoke.
                return Ok(state.grant);
            }
            return Err(anyhow!(
                "backend cloud-session grant response differs from the bound grant"
            ));
        }
        let pending = state
            .grant
            .pending_backend_create
            .clone()
            .unwrap_or_else(|| pending_backend_create(&state.grant));
        validate_pending_backend_create(&state.grant, &pending)?;
        validate_backend_grant_response(&state, response, &pending.collector_version)?;
        if response.installation_id != expected_installation_id {
            return Err(anyhow!("backend cloud-session grant scope does not match"));
        }
        if response.status != "enabled" {
            return Err(anyhow!("backend cloud-session grant is not enabled"));
        }
        if let Some(existing) = &state.grant.backend_binding {
            if existing.grant_id != response.id {
                return Err(anyhow!("backend cloud-session grant identity changed"));
            }
            if response.grant_version < existing.grant_version
                || (state.grant.status != CloudSessionGrantStatus::Enabled
                    && response.grant_version == existing.grant_version)
            {
                return Err(anyhow!("backend cloud-session grant epoch is stale"));
            }
        }
        state.grant.backend_binding = Some(CloudSessionBackendGrantBindingV1 {
            grant_id: response.id.clone(),
            grant_version: response.grant_version,
            backend_revoked: false,
            server_policy_state: response.server_policy_state.clone(),
        });
        state.grant.backend_create_pending = false;
        state.grant.pending_backend_create = None;
        state.grant.collector_version = response.collector_version.clone();
        if local_status == CloudSessionGrantStatus::Revoked {
            self.write(&state)?;
            // A POST may commit just before local revoke or rollout removal.
            // Preserve only its exact identity for compensating DELETE; local
            // revoked state continues to block every provider admission.
            return Ok(state.grant);
        }
        if local_status == CloudSessionGrantStatus::Paused {
            state.grant.granted_at = Some(timestamp(OffsetDateTime::now_utc()));
            self.write(&state)?;
            return Ok(state.grant);
        }
        if !matches!(
            local_status,
            CloudSessionGrantStatus::ConsentRequired | CloudSessionGrantStatus::Enabled
        ) {
            return Err(anyhow!(
                "local cloud-session consent changed before backend grant binding"
            ));
        }
        state.grant.status = match response.server_policy_state {
            CloudSessionServerPolicyState::Approved => CloudSessionGrantStatus::Enabled,
            CloudSessionServerPolicyState::Disabled => CloudSessionGrantStatus::PolicyDisabled,
        };
        state.grant.granted_at = Some(timestamp(OffsetDateTime::now_utc()));
        state.grant.revoked_at = None;
        state.grant.last_collector_health = Some(
            match response.server_policy_state {
                CloudSessionServerPolicyState::Approved => "enabled",
                CloudSessionServerPolicyState::Disabled => "policy_disabled",
            }
            .to_string(),
        );
        state.grant.last_freshness = Some("unavailable".to_string());
        state.grant.last_error_category = None;
        self.write(&state)?;
        Ok(state.grant)
    }

    /// Apply the server's exact DELETE response after local revocation. A
    /// monotonic version is retained so re-consent must bind a newer epoch.
    pub fn apply_backend_revocation(
        &self,
        response: &CloudSessionBackendGrantResponseV1,
        expected_installation_id: &str,
    ) -> Result<CloudSessionGrant> {
        let _lock = self.lock()?;
        let mut state = self
            .read_locked()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        validate_local_installation_binding(
            &state,
            expected_installation_id,
            "backend cloud-session revocation",
        )?;
        validate_backend_grant_response(&state, response, &state.grant.collector_version)?;
        if response.installation_id != expected_installation_id {
            return Err(anyhow!("backend cloud-session grant scope does not match"));
        }
        let existing = state
            .grant
            .backend_binding
            .as_ref()
            .ok_or_else(|| anyhow!("backend cloud-session grant is unbound"))?;
        if response.status != "revoked"
            || response.id != existing.grant_id
            || response.grant_version < existing.grant_version
        {
            return Err(anyhow!("backend cloud-session revocation does not match"));
        }
        state.grant.backend_binding = Some(CloudSessionBackendGrantBindingV1 {
            grant_id: response.id.clone(),
            grant_version: response.grant_version,
            backend_revoked: true,
            server_policy_state: response.server_policy_state.clone(),
        });
        state.grant.backend_create_pending = false;
        state.grant.pending_backend_create = None;
        state.grant.status = CloudSessionGrantStatus::Revoked;
        state.grant.last_collector_health = Some("revoked".to_string());
        state.grant.last_freshness = Some("unavailable".to_string());
        self.write(&state)?;
        Ok(state.grant)
    }

    /// Apply the bounded authenticated grant-list result required immediately
    /// before each provider collection cycle. Unknown, malformed, stale, or
    /// mismatched responses are rejected without changing runtime readiness.
    pub fn apply_backend_grant_revalidation(
        &self,
        response: &CloudSessionBackendGrantResponseV1,
    ) -> Result<CloudSessionGrant> {
        let _lock = self.lock()?;
        let mut state = self
            .read_locked()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        validate_backend_grant_response(&state, response, &state.grant.collector_version)?;
        let existing = state
            .grant
            .backend_binding
            .as_ref()
            .ok_or_else(|| anyhow!("backend cloud-session grant is unbound"))?;
        if response.id != existing.grant_id || response.grant_version != existing.grant_version {
            return Err(anyhow!(
                "backend cloud-session grant revalidation does not match"
            ));
        }
        if !matches!(response.status.as_str(), "enabled" | "revoked") {
            return Err(anyhow!("backend cloud-session grant status is invalid"));
        }
        let backend_revoked = response.status == "revoked";
        let before = state.grant.clone();
        state.grant.backend_binding = Some(CloudSessionBackendGrantBindingV1 {
            grant_id: response.id.clone(),
            grant_version: response.grant_version,
            backend_revoked,
            server_policy_state: response.server_policy_state.clone(),
        });
        if backend_revoked {
            state.grant.status = CloudSessionGrantStatus::Revoked;
            state.grant.backend_create_pending = false;
            state.grant.pending_backend_create = None;
            state.grant.last_collector_health = Some("revoked".to_string());
            state.grant.last_freshness = Some("unavailable".to_string());
        } else if !matches!(
            state.grant.status,
            CloudSessionGrantStatus::Paused | CloudSessionGrantStatus::Revoked
        ) {
            state.grant.status = match response.server_policy_state {
                CloudSessionServerPolicyState::Approved => CloudSessionGrantStatus::Enabled,
                CloudSessionServerPolicyState::Disabled => CloudSessionGrantStatus::PolicyDisabled,
            };
            state.grant.last_collector_health = Some(
                match state.grant.status {
                    CloudSessionGrantStatus::Enabled => "enabled",
                    _ => "policy_disabled",
                }
                .to_string(),
            );
            state.grant.last_freshness = Some("unavailable".to_string());
        }
        if state.grant != before {
            self.write(&state)?;
        }
        Ok(state.grant)
    }

    /// A list absence cannot resolve an ambiguous POST: its response may have
    /// raced the list. Preserve the tombstone and retry the same idempotent
    /// create until the exact backend grant id is bound, then delete that id if
    /// local consent was revoked.
    pub fn confirm_backend_grant_absent_after_reconciliation(&self) -> Result<()> {
        let _lock = self.lock()?;
        let state = self
            .read_locked()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        if state.grant.backend_binding.is_some() {
            return Err(anyhow!("backend cloud-session grant is already bound"));
        }
        Err(anyhow!(
            "backend grant absence cannot resolve an ambiguous create; retry the exact create"
        ))
    }

    /// Exact DELETE target retained after local stop. The companion/UI uses
    /// ordinary-user auth for `/api/v1/cloud-sessions/grants/{grant_id}`.
    pub fn grant_revoke_target(&self) -> Result<CloudSessionBackendGrantRevokeTargetV1> {
        let grant = self
            .load()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        let binding = grant
            .backend_binding
            .ok_or_else(|| anyhow!("backend cloud-session grant is unbound"))?;
        Ok(CloudSessionBackendGrantRevokeTargetV1 {
            grant_id: binding.grant_id,
        })
    }

    pub fn pause(&self, now: OffsetDateTime) -> Result<()> {
        self.change_status(CloudSessionGrantStatus::Paused, now)
    }

    pub fn revoke(&self, now: OffsetDateTime) -> Result<()> {
        self.change_status(CloudSessionGrantStatus::Revoked, now)
    }

    fn change_status(&self, status: CloudSessionGrantStatus, now: OffsetDateTime) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self
            .read_locked()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        state.grant.status = status.clone();
        state.grant.last_collector_health = Some(
            match status {
                CloudSessionGrantStatus::Paused => "paused",
                CloudSessionGrantStatus::Revoked => "revoked",
                _ => "disabled",
            }
            .to_string(),
        );
        state.grant.last_freshness = Some("unavailable".to_string());
        state.grant.last_error_category = None;
        match status {
            CloudSessionGrantStatus::Paused => state.grant.paused_at = Some(timestamp(now)),
            CloudSessionGrantStatus::Revoked => state.grant.revoked_at = Some(timestamp(now)),
            _ => {}
        }
        self.write(&state)
    }

    fn read(&self) -> Result<Option<PersistedGrant>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let _lock = self.lock()?;
        self.read_locked()
    }

    fn read_locked(&self) -> Result<Option<PersistedGrant>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&self.path).context("read cloud-session grant")?;
        let state = match serde_json::from_slice::<PersistedGrant>(&bytes) {
            Ok(state) => state,
            Err(current_error) => {
                let legacy: LegacyPersistedGrantV1 = serde_json::from_slice(&bytes)
                    .with_context(|| format!("decode cloud-session grant: {current_error}"))?;
                self.migrate_legacy_v1(legacy)?
            }
        };
        if state.schema_version != GRANT_SCHEMA_VERSION
            || state.grant.schema_version != GRANT_SCHEMA_VERSION
        {
            return Err(anyhow!("unsupported cloud-session grant version"));
        }
        Ok(Some(state))
    }

    fn migrate_legacy_v1(&self, legacy: LegacyPersistedGrantV1) -> Result<PersistedGrant> {
        if legacy.schema_version != GRANT_SCHEMA_VERSION
            || legacy.grant.schema_version != GRANT_SCHEMA_VERSION
            || legacy.grant.installation_id.trim().is_empty()
        {
            return Err(anyhow!("unsupported cloud-session grant version"));
        }
        let key = decode_hex(&legacy.hmac_key_hex)
            .filter(|key| key.len() == 32)
            .ok_or_else(|| anyhow!("invalid cloud-session HMAC key"))?;
        let installation_fingerprint = opaque_key(&key, &legacy.grant.installation_id);
        let grant_scope_id = opaque_key(
            &key,
            &format!(
                "{}\u{0}{}\u{0}{}\u{0}{}",
                legacy.grant.installation_id,
                legacy.grant.organization_fingerprint,
                legacy.grant.effective_user_fingerprint,
                legacy.grant.collector_id
            ),
        );
        let state = PersistedGrant {
            schema_version: legacy.schema_version,
            hmac_key_hex: legacy.hmac_key_hex,
            grant: CloudSessionGrant {
                schema_version: legacy.grant.schema_version,
                collector_id: legacy.grant.collector_id,
                collector_version: legacy.grant.collector_version,
                release_lane: legacy.grant.release_lane,
                disclosure_version: legacy.grant.disclosure_version,
                status: legacy.grant.status,
                installation_fingerprint,
                grant_scope_id,
                organization_fingerprint: legacy.grant.organization_fingerprint,
                effective_user_fingerprint: legacy.grant.effective_user_fingerprint,
                account_fingerprint: legacy.grant.account_fingerprint,
                backend_binding: None,
                backend_create_pending: false,
                pending_backend_create: None,
                granted_at: legacy.grant.granted_at,
                paused_at: legacy.grant.paused_at,
                revoked_at: legacy.grant.revoked_at,
                last_collector_health: legacy.grant.last_collector_health,
                last_freshness: legacy.grant.last_freshness,
                last_error_category: legacy.grant.last_error_category,
            },
        };
        self.write(&state)?;
        Ok(state)
    }

    fn write(&self, state: &PersistedGrant) -> Result<()> {
        atomic_json_write(&self.path, state)
    }

    fn record_health(
        &self,
        health: &str,
        freshness: &str,
        error_category: Option<&str>,
    ) -> Result<()> {
        let _lock = self.lock()?;
        let Some(mut state) = self.read_locked()? else {
            return Ok(());
        };
        if state.grant.status != CloudSessionGrantStatus::Enabled {
            return Ok(());
        }
        state.grant.last_collector_health = Some(health.to_string());
        state.grant.last_freshness = Some(freshness.to_string());
        state.grant.last_error_category = error_category.map(str::to_string);
        self.write(&state)
    }

    fn lock(&self) -> Result<CloudSessionGrantLock> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| anyhow!("cloud-session grant path has no parent"))?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let path = self.path.with_extension("lock");
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .context("open cloud-session grant lock")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(unix)]
        {
            // The state can be changed by the local UI/control process while
            // the collector thread records health. Hold a process-wide lock so
            // stale read-modify-write health updates cannot restore consent.
            if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) } != 0 {
                return Err(anyhow!("lock cloud-session grant"));
            }
        }
        Ok(CloudSessionGrantLock { file })
    }
}

impl Default for CloudSessionGrantStore {
    fn default() -> Self {
        Self::new(
            default_support_dir()
                .join("cloud_sessions")
                .join("grant.json"),
        )
    }
}

struct CloudSessionGrantLock {
    file: File,
}

impl Drop for CloudSessionGrantLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN);
        }
    }
}

/// Build the visible collector state without creating a runner or invoking
/// Codex. Runtime readiness is supplied as a credential-free status view;
/// collection still requires exact grant authority inside the supervisor.
pub fn cloud_session_collector_status(
    grants: &CloudSessionGrantStore,
    transport: &dyn CloudSessionTransport,
) -> CloudSessionCollectorStatusV1 {
    let stored_grant = grants.load().ok().flatten();
    let collector_version_rebind_required = stored_grant.as_ref().is_some_and(|grant| {
        grant.status == CloudSessionGrantStatus::Enabled
            && grant.collector_version != compiled_release_version()
    });
    let backend_reconciliation_required = stored_grant
        .as_ref()
        .is_some_and(|grant| grant.backend_create_pending);
    let backend_revocation_confirmation_required = stored_grant.as_ref().is_some_and(|grant| {
        grant.status == CloudSessionGrantStatus::Revoked
            && grant
                .backend_binding
                .as_ref()
                .is_some_and(|binding| !binding.backend_revoked)
    });
    let grant_status = if kill_switch_enabled() {
        CloudSessionGrantStatus::PolicyDisabled
    } else {
        stored_grant
            .clone()
            .map(|grant| {
                if grant.status == CloudSessionGrantStatus::Enabled
                    && grant.backend_binding.as_ref().is_some_and(|binding| {
                        !binding.backend_revoked
                            && binding.server_policy_state
                                != CloudSessionServerPolicyState::Approved
                    })
                {
                    CloudSessionGrantStatus::PolicyDisabled
                } else if grant.status == CloudSessionGrantStatus::Enabled
                    && !cloud_grant_runtime_ready(&grant)
                {
                    CloudSessionGrantStatus::ConsentRequired
                } else {
                    grant.status
                }
            })
            .unwrap_or(CloudSessionGrantStatus::Off)
    };
    let transport_configured = transport.is_configured() && transport.supports_grant_revalidation();
    let provider_cli_invocation_permitted =
        stored_grant.as_ref().is_some_and(cloud_grant_runtime_ready)
            && transport_configured
            && !kill_switch_enabled();
    let (runtime_state, reason_code) = if kill_switch_enabled() {
        (
            CloudSessionRuntimeState::PolicyDisabled,
            "policy_disabled".to_string(),
        )
    } else if grant_status == CloudSessionGrantStatus::Enabled && !transport_configured {
        (
            CloudSessionRuntimeState::TransportDeferred,
            "transport_deferred".to_string(),
        )
    } else {
        let reason_code = if backend_reconciliation_required {
            "backend_grant_reconciliation_required"
        } else if backend_revocation_confirmation_required {
            "backend_revocation_confirmation_required"
        } else if collector_version_rebind_required {
            "collector_version_rebind_required"
        } else {
            match grant_status {
                CloudSessionGrantStatus::Off => "setup_required",
                CloudSessionGrantStatus::ConsentRequired => "consent_required",
                CloudSessionGrantStatus::Enabled => "enabled",
                CloudSessionGrantStatus::Paused => "paused",
                CloudSessionGrantStatus::Revoked => "revoked",
                CloudSessionGrantStatus::PolicyDisabled => "policy_disabled",
            }
        };
        (
            match grant_status {
                CloudSessionGrantStatus::Off => CloudSessionRuntimeState::Off,
                CloudSessionGrantStatus::ConsentRequired => {
                    CloudSessionRuntimeState::ConsentRequired
                }
                CloudSessionGrantStatus::Enabled => CloudSessionRuntimeState::Enabled,
                CloudSessionGrantStatus::Paused => CloudSessionRuntimeState::Paused,
                CloudSessionGrantStatus::Revoked => CloudSessionRuntimeState::Revoked,
                CloudSessionGrantStatus::PolicyDisabled => CloudSessionRuntimeState::PolicyDisabled,
            },
            reason_code.to_string(),
        )
    };
    CloudSessionCollectorStatusV1 {
        schema_version: "cloud_session_collector_status.v1".to_string(),
        collector_id: COLLECTOR_ID.to_string(),
        grant_status,
        runtime_state,
        transport_configured,
        provider_cli_invocation_permitted,
        reason_code,
    }
}

pub fn default_cloud_session_collector_status() -> CloudSessionCollectorStatusV1 {
    let transport_configured = runtime_transport_locally_configured_with(
        &CloudSessionGrantStore::default(),
        &FileAccountStore::default(),
        &FileDeviceStore::default(),
        &FileConnectionStore::default(),
        crate::snapshot_client::load_snapshot_device_credentials,
    );
    cloud_session_collector_status(
        &CloudSessionGrantStore::default(),
        &RuntimeAvailabilityTransport(transport_configured),
    )
}

fn runtime_transport_locally_configured_with<F>(
    grants: &CloudSessionGrantStore,
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
    connections: &FileConnectionStore,
    load_credentials: F,
) -> bool
where
    F: FnOnce() -> Result<(LocalDeviceBinding, String)>,
{
    !kill_switch_enabled()
        && load_cloud_session_runtime_binding(grants, accounts, devices, connections)
            .ok()
            .flatten()
            .and_then(|candidate| {
                load_credentials().ok().map(|(device, secret)| {
                    device == candidate.binding.device && !secret.trim().is_empty()
                })
            })
            .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSessionBatchKind {
    Snapshot,
    Heartbeat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudSessionObservationBatchV1 {
    pub grant_id: String,
    pub grant_version: u64,
    pub grant_scope_fingerprint: String,
    pub collector_id: String,
    pub schema_version: String,
    pub collector_version: String,
    pub account_fingerprint: String,
    pub batch_kind: CloudSessionBatchKind,
    pub snapshot_complete: bool,
    pub collected_at: String,
    pub observations: Vec<CloudSessionObservationEntityV1>,
    pub health: CloudSessionCollectorHealthV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudSessionObservationBatchWireV1 {
    grant_id: String,
    grant_version: u64,
    grant_scope_fingerprint: String,
    collector_id: String,
    schema_version: String,
    collector_version: String,
    account_fingerprint: String,
    batch_kind: CloudSessionBatchKind,
    snapshot_complete: bool,
    collected_at: String,
    observations: Vec<CloudSessionObservationEntityV1>,
    health: CloudSessionCollectorHealthV1,
}

impl CloudSessionObservationBatchV1 {
    fn validate_wire_contract(&self) -> Result<()> {
        if self.observations.len() > MAX_ITEMS {
            return Err(anyhow!(
                "cloud-session batch exceeds {MAX_ITEMS} observations"
            ));
        }
        if self.batch_kind == CloudSessionBatchKind::Heartbeat
            && (!self.observations.is_empty() || self.snapshot_complete)
        {
            return Err(anyhow!(
                "cloud-session heartbeat must be empty and incomplete"
            ));
        }
        Ok(())
    }

    fn validate_relay_wire_contract(&self) -> Result<()> {
        if self.batch_kind != CloudSessionBatchKind::Heartbeat
            || self.snapshot_complete
            || !self.observations.is_empty()
            || !valid_v2_binding(
                &self.grant_id,
                self.grant_version,
                &self.grant_scope_fingerprint,
                &self.collector_id,
                &self.collector_version,
                &self.account_fingerprint,
            )
            || self.schema_version != COLLECTOR_VERSION
            || !valid_rfc3339(&self.collected_at)
            || !valid_v1_heartbeat_health(&self.health)
        {
            return Err(anyhow!(
                "cloud-session v1 relay accepts only a strict empty heartbeat"
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CloudSessionObservationBatchV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CloudSessionObservationBatchWireV1::deserialize(deserializer)?;
        let batch = Self {
            grant_id: wire.grant_id,
            grant_version: wire.grant_version,
            grant_scope_fingerprint: wire.grant_scope_fingerprint,
            collector_id: wire.collector_id,
            schema_version: wire.schema_version,
            collector_version: wire.collector_version,
            account_fingerprint: wire.account_fingerprint,
            batch_kind: wire.batch_kind,
            snapshot_complete: wire.snapshot_complete,
            collected_at: wire.collected_at,
            observations: wire.observations,
            health: wire.health,
        };
        batch
            .validate_wire_contract()
            .map_err(serde::de::Error::custom)?;
        Ok(batch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSessionObservationEntityV1 {
    pub entity_key: String,
    pub entity_kind: String,
    pub lifecycle: String,
    pub attempt_count: Option<u64>,
    pub environment_kind: String,
    pub measurement_basis: String,
    pub coverage: Vec<String>,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub updated_at: Option<String>,
    pub completed_at: Option<String>,
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSessionCollectorHealthV1 {
    pub state: String,
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
}

/// One ordered, idempotent positive-observation upload for a bounded v2 scan.
/// A chunk can never authorize absence; only the server may do that after it
/// accepts a separately validated finalize request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSessionObservationChunkV2 {
    pub grant_id: String,
    pub grant_version: u64,
    pub grant_scope_fingerprint: String,
    pub collector_id: String,
    pub schema_version: String,
    pub collector_version: String,
    pub account_fingerprint: String,
    pub scan_id: String,
    pub scan_started_at: String,
    pub chunk_index: u8,
    pub chunk_identity_digest: String,
    pub chunk_semantic_digest: String,
    pub observations: Vec<CloudSessionObservationEntityV1>,
    pub health: CloudSessionCollectorHealthV1,
}

impl CloudSessionObservationChunkV2 {
    fn validate_wire_contract(&self) -> Result<()> {
        let keys_are_strictly_ordered = self
            .observations
            .windows(2)
            .all(|rows| rows[0].entity_key < rows[1].entity_key);
        let expected_identity_digest = identity_digest(&self.observations);
        let expected_semantic_digest = observation_semantic_digest(&self.observations)?;
        if !is_uuid(&self.scan_id)
            || !valid_v2_binding(
                &self.grant_id,
                self.grant_version,
                &self.grant_scope_fingerprint,
                &self.collector_id,
                &self.collector_version,
                &self.account_fingerprint,
            )
            || self.schema_version != CHUNK_SCHEMA_VERSION
            || !valid_rfc3339(&self.scan_started_at)
            || usize::from(self.chunk_index) >= MAX_SCAN_CHUNKS
            || self.observations.is_empty()
            || self.observations.len() > MAX_ITEMS
            || !valid_sha256_digest(&self.chunk_identity_digest)
            || !valid_sha256_digest(&self.chunk_semantic_digest)
            || !keys_are_strictly_ordered
            || self.chunk_identity_digest != expected_identity_digest
            || self.chunk_semantic_digest != expected_semantic_digest
            || self
                .observations
                .iter()
                .any(|observation| !valid_v2_observation(observation))
            || !valid_v2_health(&self.health)
        {
            return Err(anyhow!("invalid cloud-session v2 observation chunk"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSessionEnumerationConsistencyV2 {
    SingleResponse,
    UnstableCursor,
}

/// Terminal proof for an already uploaded ordered chunk sequence. The server
/// owns all absence authority; `single_response` is the only enumeration mode
/// capable of proving absence and is emitted only for one terminal <=20 row
/// provider response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSessionScanFinalizeV2 {
    pub grant_id: String,
    pub grant_version: u64,
    pub grant_scope_fingerprint: String,
    pub collector_id: String,
    pub schema_version: String,
    pub collector_version: String,
    pub account_fingerprint: String,
    pub scan_id: String,
    pub scan_started_at: String,
    pub chunk_count: u8,
    pub unique_entity_count: u32,
    pub provider_page_count: u16,
    pub terminal_reached: bool,
    pub inventory_digest: String,
    pub epoch_digest: String,
    pub enumeration_consistency: CloudSessionEnumerationConsistencyV2,
}

impl CloudSessionScanFinalizeV2 {
    fn validate_wire_contract(&self) -> Result<()> {
        if !is_uuid(&self.scan_id)
            || !valid_v2_binding(
                &self.grant_id,
                self.grant_version,
                &self.grant_scope_fingerprint,
                &self.collector_id,
                &self.collector_version,
                &self.account_fingerprint,
            )
            || self.schema_version != FINALIZE_SCHEMA_VERSION
            || !valid_rfc3339(&self.scan_started_at)
            || !self.terminal_reached
            || usize::from(self.chunk_count) > MAX_SCAN_CHUNKS
            || self.unique_entity_count as usize > MAX_SCAN_ITEMS
            || self.provider_page_count == 0
            || usize::from(self.provider_page_count) > MAX_SCAN_PAGES
            || !valid_sha256_digest(&self.inventory_digest)
            || !valid_sha256_digest(&self.epoch_digest)
        {
            return Err(anyhow!("invalid cloud-session v2 scan finalize"));
        }
        if self.enumeration_consistency == CloudSessionEnumerationConsistencyV2::SingleResponse
            && (self.provider_page_count != 1 || self.unique_entity_count as usize > PAGE_LIMIT)
        {
            return Err(anyhow!(
                "single-response cloud-session finalization exceeds its proof boundary"
            ));
        }
        Ok(())
    }

    fn validate_against_chunks(&self, chunks: &[CloudSessionObservationChunkV2]) -> Result<()> {
        self.validate_wire_contract()?;
        if usize::from(self.chunk_count) != chunks.len()
            || chunks
                .iter()
                .enumerate()
                .any(|(index, chunk)| usize::from(chunk.chunk_index) != index)
            || chunks.iter().any(|chunk| {
                chunk.scan_id != self.scan_id
                    || chunk.scan_started_at != self.scan_started_at
                    || chunk.grant_id != self.grant_id
                    || chunk.grant_version != self.grant_version
                    || chunk.grant_scope_fingerprint != self.grant_scope_fingerprint
                    || chunk.collector_id != self.collector_id
                    || chunk.collector_version != self.collector_version
                    || chunk.account_fingerprint != self.account_fingerprint
                    || chunk.validate_wire_contract().is_err()
            })
        {
            return Err(anyhow!(
                "cloud-session finalize does not bind the acknowledged chunk sequence"
            ));
        }
        let observations = chunks
            .iter()
            .flat_map(|chunk| chunk.observations.iter())
            .collect::<Vec<_>>();
        let unique_keys = observations
            .iter()
            .map(|observation| observation.entity_key.as_str())
            .collect::<HashSet<_>>();
        if unique_keys.len() != self.unique_entity_count as usize
            || inventory_digest(
                observations
                    .iter()
                    .map(|observation| &observation.entity_key),
            ) != self.inventory_digest
            || epoch_digest(chunks) != self.epoch_digest
        {
            return Err(anyhow!(
                "cloud-session finalize digests do not bind the acknowledged inventory"
            ));
        }
        Ok(())
    }
}

fn valid_v2_binding(
    grant_id: &str,
    grant_version: u64,
    grant_scope_fingerprint: &str,
    collector_id: &str,
    collector_version: &str,
    account_fingerprint: &str,
) -> bool {
    is_uuid(grant_id)
        && grant_version > 0
        && valid_hmac_fingerprint(grant_scope_fingerprint)
        && collector_id == COLLECTOR_ID
        && collector_version == compiled_release_version()
        && valid_hmac_fingerprint(account_fingerprint)
}

fn valid_v2_observation(observation: &CloudSessionObservationEntityV1) -> bool {
    let coverage = observation
        .coverage
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let has_timing = observation.created_at.is_some()
        || observation.started_at.is_some()
        || observation.updated_at.is_some()
        || observation.completed_at.is_some();
    valid_hmac_fingerprint(&observation.entity_key)
        && observation.entity_kind == "task"
        && matches!(
            observation.lifecycle.as_str(),
            "queued" | "running" | "completed" | "failed" | "cancelled" | "unknown"
        )
        && observation
            .attempt_count
            .map_or(true, |attempts| attempts <= 100_000)
        && matches!(
            observation.environment_kind.as_str(),
            "hosted" | "container" | "unknown"
        )
        && observation.measurement_basis == "not_itemized"
        && observation.coverage.len() == coverage.len()
        && coverage
            .iter()
            .all(|field| matches!(*field, "identity" | "status" | "timing" | "attempts"))
        && coverage.contains("identity")
        && coverage.contains("status")
        && coverage.contains("timing") == has_timing
        && coverage.contains("attempts") == observation.attempt_count.is_some()
        && valid_rfc3339(&observation.observed_at)
        && [
            &observation.created_at,
            &observation.started_at,
            &observation.updated_at,
            &observation.completed_at,
        ]
        .into_iter()
        .flatten()
        .all(|value| valid_rfc3339(value))
}

fn valid_v2_health(health: &CloudSessionCollectorHealthV1) -> bool {
    valid_rfc3339(&health.observed_at)
        && matches!(
            (health.state.as_str(), health.error_category.as_deref()),
            ("healthy", None) | ("degraded", Some("provider_error"))
        )
}

fn valid_v1_heartbeat_health(health: &CloudSessionCollectorHealthV1) -> bool {
    valid_rfc3339(&health.observed_at)
        && matches!(
            (health.state.as_str(), health.error_category.as_deref()),
            ("healthy", None) | ("failing", Some("provider_error"))
        )
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CloudSessionCheckpoint {
    schema_version: String,
    semantic_digest: Option<String>,
    /// Digest of the most recent first provider page, never raw page content.
    #[serde(default)]
    head_semantic_digest: Option<String>,
    #[serde(default)]
    grant_epoch_digest: Option<String>,
    /// Grant epoch that owns the current circuit-breaker backoff. A new grant
    /// must not inherit a prior consent epoch's transient failures.
    #[serde(default)]
    circuit_grant_epoch_digest: Option<String>,
    consecutive_failures: u32,
    circuit_open_until: Option<String>,
    last_error_category: Option<String>,
    last_success_at: Option<String>,
    last_health_upload_at: Option<String>,
    last_complete_snapshot_at: Option<String>,
}

pub struct CloudSessionCheckpointStore {
    path: PathBuf,
    /// Active scans are intentionally process-memory only. This mutex also
    /// guarantees one provider subprocess/upload sequence at a time for a
    /// collector instance. Reconstructing the store after restart drops the
    /// cursor and starts a new UUID from page zero.
    runtime: Mutex<CloudSessionScanRuntime>,
    collector_io: Arc<CloudSessionIoFence>,
    #[cfg(test)]
    relay_admission_barrier: Mutex<Option<TestRelayAdmissionBarrier>>,
}

#[derive(Default)]
struct CloudSessionIoFence {
    active_io: Mutex<usize>,
    idle: Condvar,
}

struct CloudSessionIoLease<'a> {
    fence: &'a CloudSessionIoFence,
}

impl Drop for CloudSessionIoLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.fence.active_io.lock() {
            *active = active.saturating_sub(1);
            if *active == 0 {
                self.fence.idle.notify_all();
            }
        }
    }
}

fn default_collector_io_fence() -> Arc<CloudSessionIoFence> {
    static FENCE: OnceLock<Arc<CloudSessionIoFence>> = OnceLock::new();
    FENCE
        .get_or_init(|| Arc::new(CloudSessionIoFence::default()))
        .clone()
}

#[cfg(test)]
struct TestRelayAdmissionBarrier {
    skip: usize,
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[derive(Default)]
struct CloudSessionScanRuntime {
    active: Option<ActiveCloudSessionScan>,
    cycle_in_progress: bool,
    cancel_requested: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CloudSessionScanMode {
    Full,
    Head,
}

struct ActiveCloudSessionScan {
    scan_id: String,
    scan_started_at: String,
    mode: CloudSessionScanMode,
    grant: CloudSessionGrant,
    cursor: Option<String>,
    seen_cursors: HashSet<String>,
    observations: BTreeMap<String, CloudSessionObservationEntityV1>,
    provider_page_count: usize,
    head_semantic_digest: Option<String>,
    prepared: Option<PreparedCloudSessionScan>,
}

struct PreparedCloudSessionScan {
    chunks: Vec<CloudSessionObservationChunkV2>,
    finalize: Option<CloudSessionScanFinalizeV2>,
    next_chunk: usize,
    head_semantic_digest: Option<String>,
    mode: CloudSessionScanMode,
}

impl CloudSessionCheckpointStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            runtime: Mutex::new(CloudSessionScanRuntime::default()),
            collector_io: Arc::new(CloudSessionIoFence::default()),
            #[cfg(test)]
            relay_admission_barrier: Mutex::new(None),
        }
    }

    fn begin_collector_io<'a>(
        &'a self,
        grants: &CloudSessionGrantStore,
        expected: &CloudSessionGrant,
    ) -> Result<Option<CloudSessionIoLease<'a>>> {
        let mut active = self
            .collector_io
            .active_io
            .lock()
            .map_err(|_| anyhow!("cloud-session collector-I/O fence is unavailable"))?;
        if kill_switch_enabled() || !grant_still_current(grants, expected) {
            return Ok(None);
        }
        *active = active.saturating_add(1);
        Ok(Some(CloudSessionIoLease {
            fence: &self.collector_io,
        }))
    }

    /// Wait until every provider subprocess or relay write admitted before a
    /// local stop has returned. Persisted pause/revoke state closes admission;
    /// callers must then complete this wait before reporting the stop or
    /// deleting backend consent.
    pub fn wait_for_collector_io_idle(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut active = self
            .collector_io
            .active_io
            .lock()
            .map_err(|_| anyhow!("cloud-session collector-I/O fence is unavailable"))?;
        while *active > 0 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| anyhow!("cloud-session collector I/O did not stop in time"))?;
            let (next, timeout_result) = self
                .collector_io
                .idle
                .wait_timeout(active, remaining)
                .map_err(|_| anyhow!("cloud-session collector-I/O fence is unavailable"))?;
            active = next;
            if timeout_result.timed_out() && *active > 0 {
                return Err(anyhow!("cloud-session collector I/O did not stop in time"));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_collector_io_active_for_test(&self, active_io: usize) {
        let mut active = self.collector_io.active_io.lock().unwrap();
        *active = active_io;
        if active_io == 0 {
            self.collector_io.idle.notify_all();
        }
    }

    #[cfg(test)]
    fn set_relay_admission_barrier_for_test(
        &self,
        skip: usize,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        *self.relay_admission_barrier.lock().unwrap() = Some(TestRelayAdmissionBarrier {
            skip,
            entered,
            release,
        });
    }

    #[cfg(test)]
    fn wait_at_relay_admission_barrier_for_test(&self) {
        let barrier = {
            let mut configured = self.relay_admission_barrier.lock().unwrap();
            let Some(barrier) = configured.as_mut() else {
                return;
            };
            if barrier.skip > 0 {
                barrier.skip -= 1;
                return;
            }
            configured
                .take()
                .map(|barrier| (barrier.entered, barrier.release))
        };
        if let Some((entered, release)) = barrier {
            entered.wait();
            release.wait();
        }
    }

    #[cfg(not(test))]
    fn wait_at_relay_admission_barrier_for_test(&self) {}
    fn load(&self) -> CloudSessionCheckpoint {
        fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(|state: &CloudSessionCheckpoint| {
                state.schema_version == CHECKPOINT_SCHEMA_VERSION
            })
            .unwrap_or_else(|| CloudSessionCheckpoint {
                schema_version: CHECKPOINT_SCHEMA_VERSION.to_string(),
                ..Default::default()
            })
    }
    fn save(&self, state: &CloudSessionCheckpoint) -> Result<()> {
        atomic_json_write(&self.path, state)
    }
}

impl Default for CloudSessionCheckpointStore {
    fn default() -> Self {
        Self {
            path: default_support_dir()
                .join("cloud_sessions")
                .join("checkpoint.json"),
            runtime: Mutex::new(CloudSessionScanRuntime::default()),
            collector_io: default_collector_io_fence(),
            #[cfg(test)]
            relay_admission_barrier: Mutex::new(None),
        }
    }
}

pub trait CloudSessionRunner {
    /// `cursor` may only be retained by the caller for this single cycle.
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String>;

    /// Production runners must honor the remaining cycle budget. Test runners
    /// may use the default because they perform no blocking I/O.
    fn list_page_bounded(
        &self,
        cursor: Option<&str>,
        limit: usize,
        _timeout: Duration,
    ) -> Result<String> {
        self.list_page(cursor, limit)
    }
}

pub trait CloudSessionTransport {
    /// A backend route must be explicitly wired before collection starts. This
    /// prevents a setup grant from causing provider calls that cannot yield a
    /// permitted upload.
    fn is_configured(&self) -> bool {
        true
    }
    /// Upload wiring alone is insufficient: provider execution also requires
    /// an ordinary-user authenticated grant-list preflight.
    fn supports_grant_revalidation(&self) -> bool {
        false
    }
    /// Perform one bounded authenticated grant-list lookup and return the
    /// exact bound grant. Implementations must fail closed on any network,
    /// authentication, parsing, ambiguity, or absence error.
    fn revalidate_grant(
        &self,
        _grant: &CloudSessionGrant,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        Err(anyhow!(
            "cloud-session backend grant revalidation is not configured"
        ))
    }
    fn revalidate_grant_bounded(
        &self,
        _grant: &CloudSessionGrant,
        _timeout: Duration,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        Err(anyhow!(
            "bounded cloud-session grant revalidation is not configured"
        ))
    }
    fn send_scan_chunk(&self, _chunk: &CloudSessionObservationChunkV2) -> Result<()> {
        Err(anyhow!(
            "cloud-session v2 chunk transport is not configured"
        ))
    }
    fn send_scan_chunk_bounded(
        &self,
        chunk: &CloudSessionObservationChunkV2,
        _timeout: Duration,
    ) -> Result<()> {
        self.send_scan_chunk(chunk)
    }
    fn finalize_scan(&self, _finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
        Err(anyhow!(
            "cloud-session v2 finalize transport is not configured"
        ))
    }
    fn finalize_scan_bounded(
        &self,
        finalize: &CloudSessionScanFinalizeV2,
        _timeout: Duration,
    ) -> Result<()> {
        self.finalize_scan(finalize)
    }
    /// V1 is retained only for observation-empty health heartbeats.
    fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()>;
    fn send_bounded(
        &self,
        batch: &CloudSessionObservationBatchV1,
        _timeout: Duration,
    ) -> Result<()> {
        self.send(batch)
    }
}

/// Deliberately keeps production collection disabled. The strict route and
/// prepared relay transport exist below, but activation remains a separate
/// backend-deploy, retention, consent-composition, and QA decision.
pub struct DeferredCloudSessionTransport;
impl CloudSessionTransport for DeferredCloudSessionTransport {
    fn is_configured(&self) -> bool {
        false
    }

    fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
        Err(anyhow!("cloud-session ingest endpoint is not configured"))
    }
}

/// Status-only view of the process-local runtime composition. It carries no
/// credentials and cannot send; collection always uses the relay transport.
struct RuntimeAvailabilityTransport(bool);

impl CloudSessionTransport for RuntimeAvailabilityTransport {
    fn is_configured(&self) -> bool {
        self.0
    }

    fn supports_grant_revalidation(&self) -> bool {
        self.0
    }

    fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
        Err(anyhow!("cloud-session status transport cannot send"))
    }
}

/// Relay transport for the strict backend route. The consent-gated experimental
/// runtime composes it only after exact local identity/grant checks. Collection
/// then revalidates that exact grant before every provider or upload boundary.
/// It reuses one in-memory relay token and refreshes it once on 401/403.
pub struct RelayCloudSessionTransport {
    client: crate::snapshot_client::SnapshotApiClient,
    device: LocalDeviceBinding,
    device_secret: String,
    relay_token: Mutex<Option<String>>,
    acknowledged_chunks: Mutex<HashMap<String, Vec<CloudSessionObservationChunkV2>>>,
}

impl RelayCloudSessionTransport {
    pub fn new(
        api_base_url: impl Into<String>,
        device: LocalDeviceBinding,
        device_secret: String,
    ) -> Self {
        Self {
            client: crate::snapshot_client::SnapshotApiClient::new(api_base_url),
            device,
            device_secret,
            relay_token: Mutex::new(None),
            acknowledged_chunks: Mutex::new(HashMap::new()),
        }
    }

    fn record_acknowledged_chunk(&self, chunk: &CloudSessionObservationChunkV2) -> Result<()> {
        let mut scans = self
            .acknowledged_chunks
            .lock()
            .map_err(|_| anyhow!("cloud-session acknowledged-chunk lock is unavailable"))?;
        // The collector owns one active scan. Drop an abandoned partial
        // sequence when a later scan begins so truncated scans cannot grow
        // this in-memory receipt ledger without bound.
        scans.retain(|scan_id, _| scan_id == &chunk.scan_id);
        let chunks = scans.entry(chunk.scan_id.clone()).or_default();
        if usize::from(chunk.chunk_index) != chunks.len() {
            return Err(anyhow!(
                "cloud-session chunk acknowledgment is out of sequence"
            ));
        }
        chunks.push(chunk.clone());
        Ok(())
    }

    fn validate_finalize_sequence(&self, finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
        let mut scans = self
            .acknowledged_chunks
            .lock()
            .map_err(|_| anyhow!("cloud-session acknowledged-chunk lock is unavailable"))?;
        scans.retain(|scan_id, _| scan_id == &finalize.scan_id);
        finalize.validate_against_chunks(
            scans
                .get(&finalize.scan_id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
        )
    }

    fn clear_finalized_sequence(&self, scan_id: &str) -> Result<()> {
        self.acknowledged_chunks
            .lock()
            .map_err(|_| anyhow!("cloud-session acknowledged-chunk lock is unavailable"))?
            .remove(scan_id);
        Ok(())
    }

    fn token(&self, force_refresh: bool, deadline: Instant) -> Result<String> {
        {
            let mut cached = self
                .relay_token
                .lock()
                .map_err(|_| anyhow!("cloud-session relay token lock is unavailable"))?;
            if force_refresh {
                *cached = None;
            } else if let Some(token) = cached.as_ref() {
                return Ok(token.clone());
            }
        }
        let timeout = remaining_budget(deadline)
            .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
        let token = self.client.issue_relay_token_with_timeout(
            &self.device,
            &self.device_secret,
            crate::snapshots::SnapshotSource::Codex,
            timeout,
        )?;
        let mut cached = self
            .relay_token
            .lock()
            .map_err(|_| anyhow!("cloud-session relay token lock is unavailable"))?;
        *cached = Some(token.clone());
        Ok(token)
    }

    fn send_with_relay_retry<F>(&self, timeout: Duration, send: F) -> Result<()>
    where
        F: Fn(&crate::snapshot_client::SnapshotApiClient, &str, Duration) -> Result<Value>,
    {
        if !self.is_configured() {
            return Err(anyhow!("cloud-session relay transport is not source-bound"));
        }
        let deadline = Instant::now() + timeout;
        let token = self.token(false, deadline)?;
        let request_timeout = remaining_budget(deadline)
            .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
        match send(&self.client, &token, request_timeout) {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .downcast_ref::<crate::snapshot_client::CloudSessionAuthorizationRejected>()
                    .is_some() =>
            {
                let refreshed = self.token(true, deadline)?;
                let retry_timeout = remaining_budget(deadline)
                    .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
                send(&self.client, &refreshed, retry_timeout).map(|_| ())
            }
            Err(error) => Err(error),
        }
    }
}

impl CloudSessionTransport for RelayCloudSessionTransport {
    fn is_configured(&self) -> bool {
        !self.device_secret.is_empty()
            && is_uuid(&self.device.device_id)
            && self.device.sources.iter().any(|source| source == "codex")
    }

    fn supports_grant_revalidation(&self) -> bool {
        self.is_configured()
    }

    fn revalidate_grant(
        &self,
        grant: &CloudSessionGrant,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        self.revalidate_grant_bounded(grant, CYCLE_BUDGET)
    }

    fn revalidate_grant_bounded(
        &self,
        grant: &CloudSessionGrant,
        timeout: Duration,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        if !self.is_configured() {
            return Err(anyhow!("cloud-session relay transport is not source-bound"));
        }
        let binding = grant
            .backend_binding
            .as_ref()
            .ok_or_else(|| anyhow!("cloud-session backend grant is unbound"))?;
        if !is_uuid(&binding.grant_id) || binding.grant_version == 0 {
            return Err(anyhow!("cloud-session backend grant binding is invalid"));
        }
        let deadline = Instant::now() + timeout;
        let token = self.token(false, deadline)?;
        let request_timeout = remaining_budget(deadline)
            .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
        let first = self.client.get_cloud_session_grant_authority_with_timeout(
            &token,
            &binding.grant_id,
            binding.grant_version,
            request_timeout,
        );
        let value = match first {
            Ok(value) => value,
            Err(error)
                if error
                    .downcast_ref::<crate::snapshot_client::CloudSessionAuthorizationRejected>()
                    .is_some() =>
            {
                let refreshed = self.token(true, deadline)?;
                let retry_timeout = remaining_budget(deadline)
                    .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
                self.client.get_cloud_session_grant_authority_with_timeout(
                    &refreshed,
                    &binding.grant_id,
                    binding.grant_version,
                    retry_timeout,
                )?
            }
            Err(error) => return Err(error),
        };
        serde_json::from_value(value)
            .map_err(|error| anyhow!("invalid cloud-session authority response: {error}"))
    }

    fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
        self.send_bounded(batch, CYCLE_BUDGET)
    }

    fn send_bounded(
        &self,
        batch: &CloudSessionObservationBatchV1,
        timeout: Duration,
    ) -> Result<()> {
        if !self.is_configured() {
            return Err(anyhow!("cloud-session relay transport is not source-bound"));
        }
        batch.validate_relay_wire_contract()?;
        let request = serde_json::to_value(batch)?;
        let deadline = Instant::now() + timeout;
        let token = self.token(false, deadline)?;
        let request_timeout = remaining_budget(deadline)
            .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
        match self
            .client
            .upload_cloud_session_batch_with_timeout(&token, &request, request_timeout)
        {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .downcast_ref::<crate::snapshot_client::CloudSessionAuthorizationRejected>()
                    .is_some() =>
            {
                let refreshed = self.token(true, deadline)?;
                let retry_timeout = remaining_budget(deadline)
                    .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
                self.client
                    .upload_cloud_session_batch_with_timeout(&refreshed, &request, retry_timeout)
                    .map(|_| ())
            }
            Err(error) => Err(error),
        }
    }

    fn send_scan_chunk(&self, chunk: &CloudSessionObservationChunkV2) -> Result<()> {
        self.send_scan_chunk_bounded(chunk, CYCLE_BUDGET)
    }

    fn send_scan_chunk_bounded(
        &self,
        chunk: &CloudSessionObservationChunkV2,
        timeout: Duration,
    ) -> Result<()> {
        chunk.validate_wire_contract()?;
        let request = serde_json::to_value(chunk)?;
        self.send_with_relay_retry(timeout, |client, token, request_timeout| {
            client.upload_cloud_session_scan_chunk_with_timeout(
                token,
                &chunk.scan_id,
                &request,
                request_timeout,
            )
        })?;
        self.record_acknowledged_chunk(chunk)
    }

    fn finalize_scan(&self, finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
        self.finalize_scan_bounded(finalize, CYCLE_BUDGET)
    }

    fn finalize_scan_bounded(
        &self,
        finalize: &CloudSessionScanFinalizeV2,
        timeout: Duration,
    ) -> Result<()> {
        self.validate_finalize_sequence(finalize)?;
        let request = serde_json::to_value(finalize)?;
        self.send_with_relay_retry(timeout, |client, token, request_timeout| {
            client.finalize_cloud_session_scan_with_timeout(
                token,
                &finalize.scan_id,
                &request,
                request_timeout,
            )
        })?;
        self.clear_finalized_sequence(&finalize.scan_id)
    }
}

pub struct CodexCloudCliRunner;
impl CloudSessionRunner for CodexCloudCliRunner {
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String> {
        self.list_page_bounded(cursor, limit, COMMAND_TIMEOUT)
    }

    fn list_page_bounded(
        &self,
        cursor: Option<&str>,
        limit: usize,
        timeout: Duration,
    ) -> Result<String> {
        let program = crate::command_env::executable_path("codex")
            .ok_or_else(|| anyhow!("Codex CLI is unavailable"))?;
        let mut command = Command::new(program);
        command.args([
            "cloud",
            "list",
            "--json",
            "--limit",
            &limit.min(PAGE_LIMIT).to_string(),
        ]);
        if let Some(cursor) = cursor.filter(|value| !value.is_empty()) {
            command.args(["--cursor", cursor]);
        }
        // Codex authenticates through its own effective-user configuration.
        // Never recover or forward provider API keys from the service or an
        // interactive shell for this metadata-only collector.
        command.env_clear();
        if let Some(path) = crate::command_env::path_env() {
            command.env("PATH", path);
        }
        for key in [
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "CODEX_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
        ] {
            if let Some(value) = std::env::var_os(key).filter(|value| !value.is_empty()) {
                command.env(key, value);
            }
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|_| anyhow!("Codex cloud list could not be started"))?;
        // Drain stdout while the child runs. Waiting to read after process exit
        // would deadlock when a valid JSON page fills the OS pipe buffer.
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Codex cloud list stdout could not be opened"))?;
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take(MAX_PAGE_OUTPUT_BYTES)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let started = Instant::now();
        let timeout = timeout.min(COMMAND_TIMEOUT);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let output = reader
                        .join()
                        .map_err(|_| anyhow!("Codex cloud list output reader panicked"))?
                        .map_err(|_| anyhow!("Codex cloud list output could not be read"))?;
                    if !status.success() {
                        return Err(anyhow!("Codex cloud list exited unsuccessfully"));
                    }
                    return String::from_utf8(output)
                        .map_err(|_| anyhow!("Codex cloud list returned non-UTF-8 JSON"));
                }
                Ok(None) if started.elapsed() >= timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(anyhow!("Codex cloud list timed out"));
                }
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(anyhow!("Codex cloud list status could not be read"));
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudSessionCycleOutcome {
    Disabled,
    CircuitOpen,
    Noop,
    Heartbeat,
    Uploaded,
    Failed,
}

pub fn collect_cloud_sessions_once(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    runner: &dyn CloudSessionRunner,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
) -> CloudSessionCycleOutcome {
    collect_cloud_sessions_once_with_budget(
        grants,
        checkpoints,
        runner,
        transport,
        now,
        CYCLE_BUDGET,
    )
}

fn collect_cloud_sessions_once_with_budget(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    runner: &dyn CloudSessionRunner,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
    cycle_budget: Duration,
) -> CloudSessionCycleOutcome {
    if kill_switch_enabled() {
        disable_checkpoint_runtime(checkpoints);
        return CloudSessionCycleOutcome::Disabled;
    }
    let Some(admitted_grant) = grants
        .load()
        .ok()
        .flatten()
        .filter(cloud_grant_preflight_eligible)
    else {
        disable_checkpoint_runtime(checkpoints);
        return CloudSessionCycleOutcome::Disabled;
    };
    if !transport.is_configured() || !transport.supports_grant_revalidation() {
        let _ = grants.record_health("unavailable", "unavailable", Some("transport_unconfigured"));
        return CloudSessionCycleOutcome::Noop;
    }
    let mut checkpoint = checkpoints.load();
    reset_stale_circuit_for_grant(&mut checkpoint, &admitted_grant);
    if circuit_open_for_grant(&checkpoint, &admitted_grant, now) {
        return CloudSessionCycleOutcome::CircuitOpen;
    }
    let mut runtime = match checkpoints.runtime.lock() {
        Ok(mut shared) => {
            if shared.cycle_in_progress {
                return CloudSessionCycleOutcome::Noop;
            }
            shared.cycle_in_progress = true;
            CloudSessionScanRuntime {
                active: shared.active.take(),
                ..Default::default()
            }
        }
        Err(_) => return CloudSessionCycleOutcome::Failed,
    };
    let deadline = Instant::now() + cycle_budget;
    let result = collect_enabled_cycle(
        grants,
        checkpoints,
        &checkpoint,
        &mut runtime,
        runner,
        transport,
        now,
        deadline,
    );
    let preserve_incomplete_health = checkpoint.last_error_category.as_deref()
        == Some("scan_incomplete")
        && runtime
            .active
            .as_ref()
            .is_some_and(|scan| scan.mode == CloudSessionScanMode::Full);
    let mut shared = match checkpoints.runtime.lock() {
        Ok(shared) => shared,
        Err(_) => return CloudSessionCycleOutcome::Failed,
    };
    if !shared.cancel_requested && !kill_switch_enabled() && grant_preflight_eligible(grants) {
        shared.active = runtime.active.take();
    }
    shared.cycle_in_progress = false;
    shared.cancel_requested = false;
    drop(shared);
    match result {
        Ok(CycleResult::Deferred) => CloudSessionCycleOutcome::Noop,
        Ok(CycleResult::Noop) => {
            checkpoint.consecutive_failures = 0;
            checkpoint.circuit_open_until = None;
            checkpoint.circuit_grant_epoch_digest = None;
            checkpoint.last_success_at = Some(timestamp(now));
            if !preserve_incomplete_health {
                checkpoint.last_error_category = None;
            }
            let _ = checkpoints.save(&checkpoint);
            let _ = if preserve_incomplete_health {
                grants.record_health("degraded", "stale", Some("scan_incomplete"))
            } else {
                grants.record_health("ok", "fresh", None)
            };
            CloudSessionCycleOutcome::Noop
        }
        Ok(CycleResult::Heartbeat) => {
            checkpoint.consecutive_failures = 0;
            checkpoint.circuit_open_until = None;
            checkpoint.circuit_grant_epoch_digest = None;
            checkpoint.last_error_category = None;
            checkpoint.last_success_at = Some(timestamp(now));
            checkpoint.last_health_upload_at = Some(timestamp(now));
            let _ = checkpoints.save(&checkpoint);
            let _ = grants.record_health("ok", "fresh", None);
            CloudSessionCycleOutcome::Heartbeat
        }
        Ok(CycleResult::Uploaded {
            digest,
            head_semantic_digest,
            grant_epoch_digest,
            completed_full_scan,
            degraded,
        }) => {
            if let Some(digest) = digest {
                checkpoint.semantic_digest = Some(digest);
            }
            if let Some(head_digest) = head_semantic_digest {
                checkpoint.head_semantic_digest = Some(head_digest);
            }
            checkpoint.consecutive_failures = 0;
            checkpoint.circuit_open_until = None;
            checkpoint.circuit_grant_epoch_digest = None;
            checkpoint.last_success_at = Some(timestamp(now));
            checkpoint.last_health_upload_at = Some(timestamp(now));
            if completed_full_scan {
                checkpoint.last_complete_snapshot_at = Some(timestamp(now));
            }
            if let Some(grant_epoch_digest) = grant_epoch_digest {
                checkpoint.grant_epoch_digest = Some(grant_epoch_digest);
            }
            checkpoint.last_error_category = degraded.then(|| "scan_incomplete".to_string());
            let _ = checkpoints.save(&checkpoint);
            let _ = if degraded {
                grants.record_health("degraded", "stale", Some("scan_incomplete"))
            } else {
                grants.record_health("ok", "fresh", None)
            };
            CloudSessionCycleOutcome::Uploaded
        }
        Err(error) => {
            checkpoint.consecutive_failures = checkpoint.consecutive_failures.saturating_add(1);
            checkpoint.last_error_category = Some(error.category.to_string());
            checkpoint.circuit_grant_epoch_digest = Some(grant_epoch_digest(&admitted_grant));
            checkpoint.circuit_open_until = Some(timestamp(
                now + TimeDuration::seconds(backoff_seconds(checkpoint.consecutive_failures) as i64),
            ));
            if error.health_uploaded {
                checkpoint.last_health_upload_at = Some(timestamp(now));
            }
            let _ = checkpoints.save(&checkpoint);
            let _ = grants.record_health("failing", "stale", Some(error.category));
            CloudSessionCycleOutcome::Failed
        }
    }
}

fn disable_checkpoint_runtime(checkpoints: &CloudSessionCheckpointStore) {
    if let Ok(mut runtime) = checkpoints.runtime.lock() {
        runtime.active = None;
        runtime.cancel_requested = runtime.cycle_in_progress;
    }
}

enum CycleResult {
    Deferred,
    Noop,
    Heartbeat,
    Uploaded {
        digest: Option<String>,
        head_semantic_digest: Option<String>,
        grant_epoch_digest: Option<String>,
        completed_full_scan: bool,
        degraded: bool,
    },
}
#[derive(Debug)]
struct CycleError {
    category: &'static str,
    health_uploaded: bool,
}

#[allow(clippy::too_many_arguments)]
fn collect_enabled_cycle(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    checkpoint: &CloudSessionCheckpoint,
    runtime: &mut CloudSessionScanRuntime,
    runner: &dyn CloudSessionRunner,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
    deadline: Instant,
) -> std::result::Result<CycleResult, CycleError> {
    let state = grants
        .read()
        .map_err(|_| CycleError {
            category: "grant_unavailable",
            health_uploaded: false,
        })?
        .ok_or(CycleError {
            category: "grant_absent",
            health_uploaded: false,
        })?;
    if kill_switch_enabled() || !cloud_grant_preflight_eligible(&state.grant) {
        return Ok(CycleResult::Noop);
    }
    let key = decode_hex(&state.hmac_key_hex)
        .filter(|key| key.len() == 32)
        .ok_or(CycleError {
            category: "grant_invalid",
            health_uploaded: false,
        })?;
    let mut first_page_prevalidated = false;
    if runtime.active.is_none() {
        let current_grant = match revalidate_scan_start(grants, transport, &state.grant, deadline)?
        {
            RevalidationOutcome::Granted(grant) => *grant,
            RevalidationOutcome::Denied => return Ok(CycleResult::Noop),
            RevalidationOutcome::BudgetExpired => return Ok(CycleResult::Deferred),
        };
        first_page_prevalidated = true;
        runtime.active = Some(ActiveCloudSessionScan {
            scan_id: random_scan_id().map_err(|_| CycleError {
                category: "scan_id_unavailable",
                health_uploaded: false,
            })?,
            scan_started_at: timestamp(now),
            mode: if complete_snapshot_due(checkpoint, now)
                || checkpoint.grant_epoch_digest.as_deref()
                    != Some(grant_epoch_digest(&current_grant).as_str())
            {
                CloudSessionScanMode::Full
            } else {
                CloudSessionScanMode::Head
            },
            grant: current_grant,
            cursor: None,
            seen_cursors: HashSet::new(),
            observations: BTreeMap::new(),
            provider_page_count: 0,
            head_semantic_digest: None,
            prepared: None,
        });
    }

    if runtime
        .active
        .as_ref()
        .is_some_and(|scan| scan.prepared.is_some())
    {
        return upload_prepared_scan(grants, checkpoints, runtime, transport, deadline);
    }

    for _ in 0..MAX_PAGES {
        if Instant::now() >= deadline {
            break;
        }
        let expected_grant = runtime
            .active
            .as_ref()
            .map(|scan| scan.grant.clone())
            .ok_or(CycleError {
                category: "scan_unavailable",
                health_uploaded: false,
            })?;
        if first_page_prevalidated {
            first_page_prevalidated = false;
        } else {
            match revalidate_before_io(grants, transport, &expected_grant, deadline)? {
                RevalidationOutcome::Granted(_) => {}
                RevalidationOutcome::Denied => {
                    runtime.active = None;
                    return Ok(CycleResult::Noop);
                }
                RevalidationOutcome::BudgetExpired => return Ok(CycleResult::Deferred),
            }
        }
        let cursor = runtime
            .active
            .as_ref()
            .and_then(|scan| scan.cursor.as_deref());
        let Some(timeout) = remaining_budget(deadline) else {
            return Ok(CycleResult::Deferred);
        };
        let provider_call = checkpoints
            .begin_collector_io(grants, &expected_grant)
            .map_err(|_| CycleError {
                category: "collector_io_fence_unavailable",
                health_uploaded: false,
            })?;
        let Some(provider_call) = provider_call else {
            runtime.active = None;
            return Ok(CycleResult::Noop);
        };
        let raw_result = runner.list_page_bounded(cursor, PAGE_LIMIT, timeout);
        // The lease represents provider-process activity only. Release it as
        // soon as the bounded runner returns so pause/revoke never waits on
        // later backend health or revalidation I/O from an error path.
        drop(provider_call);
        let raw = match raw_result {
            Ok(raw) => raw,
            Err(_) => {
                if remaining_budget(deadline).is_none() {
                    return Ok(CycleResult::Deferred);
                }
                if !grant_still_current(grants, &expected_grant) || kill_switch_enabled() {
                    runtime.active = None;
                    return Ok(CycleResult::Noop);
                }
                if runtime
                    .active
                    .as_ref()
                    .is_some_and(|scan| !scan.observations.is_empty())
                {
                    prepare_active_scan(runtime, now, false)?;
                    break;
                }
                runtime.active = None;
                return match report_provider_failure_revalidated(
                    grants,
                    checkpoints,
                    &expected_grant,
                    transport,
                    now,
                    deadline,
                )? {
                    SendOutcome::Sent => Err(CycleError {
                        category: "provider_unavailable",
                        health_uploaded: true,
                    }),
                    SendOutcome::NotSent => Ok(CycleResult::Noop),
                    SendOutcome::BudgetExpired => Ok(CycleResult::Deferred),
                };
            }
        };
        let page = match parse_cloud_page(&raw, &key, now) {
            Ok(page)
                if page.invalid_required_rows == 0
                    && (page.source_item_count == 0 || !page.entities.is_empty()) =>
            {
                page
            }
            _ => {
                if runtime
                    .active
                    .as_ref()
                    .is_some_and(|scan| !scan.observations.is_empty())
                {
                    prepare_active_scan(runtime, now, false)?;
                    break;
                }
                runtime.active = None;
                return match report_provider_failure_revalidated(
                    grants,
                    checkpoints,
                    &expected_grant,
                    transport,
                    now,
                    deadline,
                )? {
                    SendOutcome::Sent => Err(CycleError {
                        category: "provider_payload_invalid",
                        health_uploaded: true,
                    }),
                    SendOutcome::NotSent => Ok(CycleResult::Noop),
                    SendOutcome::BudgetExpired => Ok(CycleResult::Deferred),
                };
            }
        };

        let page_digest = observation_semantic_digest(&page.entities).map_err(|_| CycleError {
            category: "digest_failed",
            health_uploaded: false,
        })?;
        let page_terminal = page.cursor == CloudPageCursor::OfficialTerminal;
        let page_ambiguous = page.cursor == CloudPageCursor::Ambiguous;
        let page_truncated = page.truncated;
        let scan = runtime.active.as_mut().ok_or(CycleError {
            category: "scan_unavailable",
            health_uploaded: false,
        })?;
        scan.provider_page_count += 1;
        if scan.provider_page_count == 1 {
            scan.head_semantic_digest = Some(page_digest.clone());
        }
        for entity in page.entities {
            if scan.observations.len() >= MAX_SCAN_ITEMS
                && !scan.observations.contains_key(&entity.entity_key)
            {
                break;
            }
            scan.observations.insert(entity.entity_key.clone(), entity);
        }
        let next_cursor = match page.cursor {
            CloudPageCursor::Next(next) => Some(next),
            CloudPageCursor::OfficialTerminal | CloudPageCursor::Ambiguous => None,
        };
        let cursor_churn = next_cursor
            .as_ref()
            .is_some_and(|next| !scan.seen_cursors.insert(next.clone()));
        scan.cursor = next_cursor;

        // Legacy arrays, fieldless objects, and alias-only nulls can preserve
        // valid positive facts, but only the official `cursor: null` contract
        // proves terminal enumeration or healthy absence authority.
        if page_ambiguous {
            prepare_active_scan(runtime, now, false)?;
            break;
        }

        if scan.mode == CloudSessionScanMode::Head {
            if checkpoint.head_semantic_digest.as_deref() == Some(page_digest.as_str()) {
                runtime.active = None;
                if checkpoint.last_error_category.is_none()
                    && !health_heartbeat_due(checkpoint, now)
                {
                    return Ok(CycleResult::Noop);
                }
                return match send_heartbeat_revalidated(
                    grants,
                    checkpoints,
                    &expected_grant,
                    transport,
                    now,
                    deadline,
                )? {
                    SendOutcome::Sent => Ok(CycleResult::Heartbeat),
                    SendOutcome::NotSent => Ok(CycleResult::Noop),
                    SendOutcome::BudgetExpired => Ok(CycleResult::Deferred),
                };
            }
            prepare_active_scan(
                runtime,
                now,
                page_terminal && !page_truncated && !cursor_churn,
            )?;
            break;
        }

        if page_terminal && !page_truncated && !cursor_churn {
            prepare_active_scan(runtime, now, true)?;
            break;
        }
        if page_truncated
            || cursor_churn
            || scan.observations.len() >= MAX_SCAN_ITEMS
            || scan.provider_page_count >= MAX_SCAN_PAGES
        {
            prepare_active_scan(runtime, now, false)?;
            break;
        }
    }

    if runtime
        .active
        .as_ref()
        .is_some_and(|scan| scan.prepared.is_some())
    {
        upload_prepared_scan(grants, checkpoints, runtime, transport, deadline)
    } else {
        Ok(CycleResult::Noop)
    }
}

enum RevalidationOutcome {
    Granted(Box<CloudSessionGrant>),
    Denied,
    BudgetExpired,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    Sent,
    NotSent,
    BudgetExpired,
}

fn remaining_budget(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
}

fn remaining_relay_budget(deadline: Instant) -> Option<Duration> {
    remaining_budget(deadline).map(|remaining| remaining.min(RELAY_IO_TIMEOUT))
}

fn revalidate_before_io(
    grants: &CloudSessionGrantStore,
    transport: &dyn CloudSessionTransport,
    expected: &CloudSessionGrant,
    deadline: Instant,
) -> std::result::Result<RevalidationOutcome, CycleError> {
    if kill_switch_enabled() || !grant_still_current(grants, expected) {
        return Ok(RevalidationOutcome::Denied);
    }
    let Some(timeout) = remaining_relay_budget(deadline) else {
        return Ok(RevalidationOutcome::BudgetExpired);
    };
    let response = match transport.revalidate_grant_bounded(expected, timeout) {
        Ok(response) => response,
        Err(_) if remaining_budget(deadline).is_none() => {
            return Ok(RevalidationOutcome::BudgetExpired)
        }
        Err(_) => {
            return Err(CycleError {
                category: "grant_revalidation_unavailable",
                health_uploaded: false,
            })
        }
    };
    grants
        .apply_backend_grant_revalidation(&response)
        .map_err(|_| CycleError {
            category: "grant_revalidation_invalid",
            health_uploaded: false,
        })?;
    if kill_switch_enabled() || !grant_still_current(grants, expected) {
        return Ok(RevalidationOutcome::Denied);
    }
    let current = grants.load().map_err(|_| CycleError {
        category: "grant_unavailable",
        health_uploaded: false,
    })?;
    Ok(match current {
        Some(grant) => RevalidationOutcome::Granted(Box::new(grant)),
        None => RevalidationOutcome::Denied,
    })
}

fn revalidate_scan_start(
    grants: &CloudSessionGrantStore,
    transport: &dyn CloudSessionTransport,
    expected: &CloudSessionGrant,
    deadline: Instant,
) -> std::result::Result<RevalidationOutcome, CycleError> {
    if kill_switch_enabled() || !cloud_grant_preflight_eligible(expected) {
        return Ok(RevalidationOutcome::Denied);
    }
    let Some(timeout) = remaining_relay_budget(deadline) else {
        return Ok(RevalidationOutcome::BudgetExpired);
    };
    let response = match transport.revalidate_grant_bounded(expected, timeout) {
        Ok(response) => response,
        Err(_) if remaining_budget(deadline).is_none() => {
            return Ok(RevalidationOutcome::BudgetExpired)
        }
        Err(_) => {
            return Err(CycleError {
                category: "grant_revalidation_unavailable",
                health_uploaded: false,
            })
        }
    };
    grants
        .apply_backend_grant_revalidation(&response)
        .map_err(|_| CycleError {
            category: "grant_revalidation_invalid",
            health_uploaded: false,
        })?;
    let current = grants
        .load()
        .map_err(|_| CycleError {
            category: "grant_unavailable",
            health_uploaded: false,
        })?
        .filter(cloud_grant_runtime_ready);
    if kill_switch_enabled()
        || current
            .as_ref()
            .is_some_and(|grant| !same_runtime_grant_identity(grant, expected))
    {
        return Ok(RevalidationOutcome::Denied);
    }
    Ok(match current {
        Some(grant) => RevalidationOutcome::Granted(Box::new(grant)),
        None => RevalidationOutcome::Denied,
    })
}

fn prepare_active_scan(
    runtime: &mut CloudSessionScanRuntime,
    now: OffsetDateTime,
    terminal_reached: bool,
) -> std::result::Result<(), CycleError> {
    let scan = runtime.active.as_mut().ok_or(CycleError {
        category: "scan_unavailable",
        health_uploaded: false,
    })?;
    if scan.prepared.is_some() {
        return Ok(());
    }
    let binding = scan.grant.backend_binding.as_ref().ok_or(CycleError {
        category: "grant_unbound",
        health_uploaded: false,
    })?;
    let health = if terminal_reached {
        CloudSessionCollectorHealthV1 {
            state: "healthy".to_string(),
            observed_at: timestamp(now),
            error_category: None,
        }
    } else {
        CloudSessionCollectorHealthV1 {
            state: "degraded".to_string(),
            observed_at: timestamp(now),
            error_category: Some("provider_error".to_string()),
        }
    };
    let observations = scan.observations.values().cloned().collect::<Vec<_>>();
    let mut chunks = Vec::new();
    for (chunk_index, chunk_observations) in observations.chunks(MAX_ITEMS).enumerate() {
        let chunk = CloudSessionObservationChunkV2 {
            grant_id: binding.grant_id.clone(),
            grant_version: binding.grant_version,
            grant_scope_fingerprint: scan.grant.grant_scope_id.clone(),
            collector_id: COLLECTOR_ID.to_string(),
            schema_version: CHUNK_SCHEMA_VERSION.to_string(),
            collector_version: scan.grant.collector_version.clone(),
            account_fingerprint: scan.grant.account_fingerprint.clone(),
            scan_id: scan.scan_id.clone(),
            scan_started_at: scan.scan_started_at.clone(),
            chunk_index: u8::try_from(chunk_index).map_err(|_| CycleError {
                category: "chunk_index_invalid",
                health_uploaded: false,
            })?,
            chunk_identity_digest: identity_digest(chunk_observations),
            chunk_semantic_digest: observation_semantic_digest(chunk_observations).map_err(
                |_| CycleError {
                    category: "digest_failed",
                    health_uploaded: false,
                },
            )?,
            observations: chunk_observations.to_vec(),
            health: health.clone(),
        };
        chunk.validate_wire_contract().map_err(|_| CycleError {
            category: "chunk_invalid",
            health_uploaded: false,
        })?;
        chunks.push(chunk);
    }
    if chunks.len() > MAX_SCAN_CHUNKS {
        return Err(CycleError {
            category: "chunk_count_invalid",
            health_uploaded: false,
        });
    }
    let finalize = if terminal_reached {
        let inventory_digest = inventory_digest(observations.iter().map(|row| &row.entity_key));
        let epoch_digest = epoch_digest(&chunks);
        let enumeration_consistency =
            if scan.provider_page_count == 1 && observations.len() <= PAGE_LIMIT {
                CloudSessionEnumerationConsistencyV2::SingleResponse
            } else {
                CloudSessionEnumerationConsistencyV2::UnstableCursor
            };
        let finalize = CloudSessionScanFinalizeV2 {
            grant_id: binding.grant_id.clone(),
            grant_version: binding.grant_version,
            grant_scope_fingerprint: scan.grant.grant_scope_id.clone(),
            collector_id: COLLECTOR_ID.to_string(),
            schema_version: FINALIZE_SCHEMA_VERSION.to_string(),
            collector_version: scan.grant.collector_version.clone(),
            account_fingerprint: scan.grant.account_fingerprint.clone(),
            scan_id: scan.scan_id.clone(),
            scan_started_at: scan.scan_started_at.clone(),
            chunk_count: chunks.len() as u8,
            unique_entity_count: observations.len() as u32,
            provider_page_count: scan.provider_page_count as u16,
            terminal_reached: true,
            inventory_digest,
            epoch_digest,
            enumeration_consistency,
        };
        finalize
            .validate_against_chunks(&chunks)
            .map_err(|_| CycleError {
                category: "finalize_invalid",
                health_uploaded: false,
            })?;
        Some(finalize)
    } else {
        None
    };
    scan.prepared = Some(PreparedCloudSessionScan {
        chunks,
        finalize,
        next_chunk: 0,
        head_semantic_digest: scan.head_semantic_digest.clone(),
        mode: scan.mode,
    });
    // The raw provider cursor and cursor history are no longer needed once the
    // immutable upload sequence exists. Drop them before any network upload.
    scan.cursor = None;
    scan.seen_cursors.clear();
    scan.observations.clear();
    Ok(())
}

fn upload_prepared_scan(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    runtime: &mut CloudSessionScanRuntime,
    transport: &dyn CloudSessionTransport,
    deadline: Instant,
) -> std::result::Result<CycleResult, CycleError> {
    loop {
        let (expected_grant, chunk) = {
            let scan = runtime.active.as_ref().ok_or(CycleError {
                category: "scan_unavailable",
                health_uploaded: false,
            })?;
            let prepared = scan.prepared.as_ref().ok_or(CycleError {
                category: "scan_not_prepared",
                health_uploaded: false,
            })?;
            (
                scan.grant.clone(),
                prepared.chunks.get(prepared.next_chunk).cloned(),
            )
        };
        let Some(chunk) = chunk else {
            break;
        };
        match revalidate_before_io(grants, transport, &expected_grant, deadline)? {
            RevalidationOutcome::Granted(_) => {}
            RevalidationOutcome::Denied => {
                runtime.active = None;
                return Ok(CycleResult::Noop);
            }
            RevalidationOutcome::BudgetExpired => return Ok(CycleResult::Deferred),
        }
        checkpoints.wait_at_relay_admission_barrier_for_test();
        let relay_io = checkpoints
            .begin_collector_io(grants, &expected_grant)
            .map_err(|_| CycleError {
                category: "collector_io_fence_unavailable",
                health_uploaded: false,
            })?;
        let Some(relay_io) = relay_io else {
            runtime.active = None;
            return Ok(CycleResult::Noop);
        };
        let Some(timeout) = remaining_relay_budget(deadline) else {
            return Ok(CycleResult::Deferred);
        };
        let send_result = transport.send_scan_chunk_bounded(&chunk, timeout);
        drop(relay_io);
        if send_result.is_err() {
            if remaining_budget(deadline).is_none() {
                return Ok(CycleResult::Deferred);
            }
            return Err(CycleError {
                category: "transport_unavailable",
                health_uploaded: false,
            });
        }
        let prepared = runtime
            .active
            .as_mut()
            .and_then(|scan| scan.prepared.as_mut())
            .ok_or(CycleError {
                category: "scan_not_prepared",
                health_uploaded: false,
            })?;
        prepared.next_chunk += 1;
    }

    let (expected_grant, finalize) = {
        let scan = runtime.active.as_ref().ok_or(CycleError {
            category: "scan_unavailable",
            health_uploaded: false,
        })?;
        (
            scan.grant.clone(),
            scan.prepared
                .as_ref()
                .and_then(|prepared| prepared.finalize.clone()),
        )
    };
    if let Some(finalize) = &finalize {
        match revalidate_before_io(grants, transport, &expected_grant, deadline)? {
            RevalidationOutcome::Granted(_) => {}
            RevalidationOutcome::Denied => {
                runtime.active = None;
                return Ok(CycleResult::Noop);
            }
            RevalidationOutcome::BudgetExpired => return Ok(CycleResult::Deferred),
        }
        checkpoints.wait_at_relay_admission_barrier_for_test();
        let relay_io = checkpoints
            .begin_collector_io(grants, &expected_grant)
            .map_err(|_| CycleError {
                category: "collector_io_fence_unavailable",
                health_uploaded: false,
            })?;
        let Some(relay_io) = relay_io else {
            runtime.active = None;
            return Ok(CycleResult::Noop);
        };
        let Some(timeout) = remaining_relay_budget(deadline) else {
            return Ok(CycleResult::Deferred);
        };
        let send_result = transport.finalize_scan_bounded(finalize, timeout);
        drop(relay_io);
        if send_result.is_err() {
            if remaining_budget(deadline).is_none() {
                return Ok(CycleResult::Deferred);
            }
            return Err(CycleError {
                category: "transport_unavailable",
                health_uploaded: false,
            });
        }
    }
    let finished = runtime.active.take().ok_or(CycleError {
        category: "scan_unavailable",
        health_uploaded: false,
    })?;
    let prepared = finished.prepared.ok_or(CycleError {
        category: "scan_not_prepared",
        health_uploaded: false,
    })?;
    let completed_full_scan =
        prepared.mode == CloudSessionScanMode::Full && prepared.finalize.is_some();
    Ok(CycleResult::Uploaded {
        digest: finalize.map(|value| value.epoch_digest),
        head_semantic_digest: prepared.head_semantic_digest,
        grant_epoch_digest: completed_full_scan.then(|| grant_epoch_digest(&finished.grant)),
        completed_full_scan,
        degraded: prepared.finalize.is_none(),
    })
}

fn send_heartbeat_revalidated(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    expected: &CloudSessionGrant,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
    deadline: Instant,
) -> std::result::Result<SendOutcome, CycleError> {
    match revalidate_before_io(grants, transport, expected, deadline)? {
        RevalidationOutcome::Granted(_) => {}
        RevalidationOutcome::Denied => return Ok(SendOutcome::NotSent),
        RevalidationOutcome::BudgetExpired => return Ok(SendOutcome::BudgetExpired),
    }
    let batch = heartbeat_batch(
        expected,
        now,
        CloudSessionCollectorHealthV1 {
            state: "healthy".to_string(),
            observed_at: timestamp(now),
            error_category: None,
        },
    )?;
    checkpoints.wait_at_relay_admission_barrier_for_test();
    let relay_io = checkpoints
        .begin_collector_io(grants, expected)
        .map_err(|_| CycleError {
            category: "collector_io_fence_unavailable",
            health_uploaded: false,
        })?;
    let Some(relay_io) = relay_io else {
        return Ok(SendOutcome::NotSent);
    };
    let Some(timeout) = remaining_relay_budget(deadline) else {
        return Ok(SendOutcome::BudgetExpired);
    };
    let send_result = transport.send_bounded(&batch, timeout);
    drop(relay_io);
    match send_result {
        Ok(()) => Ok(SendOutcome::Sent),
        Err(_) if remaining_budget(deadline).is_none() => Ok(SendOutcome::BudgetExpired),
        Err(_) => Err(CycleError {
            category: "transport_unavailable",
            health_uploaded: false,
        }),
    }
}

fn report_provider_failure_revalidated(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    expected: &CloudSessionGrant,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
    deadline: Instant,
) -> std::result::Result<SendOutcome, CycleError> {
    match revalidate_before_io(grants, transport, expected, deadline)? {
        RevalidationOutcome::Granted(_) => {}
        RevalidationOutcome::Denied => return Ok(SendOutcome::NotSent),
        RevalidationOutcome::BudgetExpired => return Ok(SendOutcome::BudgetExpired),
    }
    checkpoints.wait_at_relay_admission_barrier_for_test();
    let relay_io = checkpoints
        .begin_collector_io(grants, expected)
        .map_err(|_| CycleError {
            category: "collector_io_fence_unavailable",
            health_uploaded: false,
        })?;
    let Some(relay_io) = relay_io else {
        return Ok(SendOutcome::NotSent);
    };
    let result = report_provider_failure(expected, transport, now, deadline);
    drop(relay_io);
    result
}

struct ParsedPage {
    entities: Vec<CloudSessionObservationEntityV1>,
    cursor: CloudPageCursor,
    source_item_count: usize,
    invalid_required_rows: usize,
    truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CloudPageCursor {
    OfficialTerminal,
    Next(String),
    Ambiguous,
}

fn parse_cloud_page(raw: &str, key: &[u8], observed_at: OffsetDateTime) -> Result<ParsedPage> {
    let root: Value = serde_json::from_str(raw).context("parse Codex cloud list JSON")?;
    let items = if let Some(items) = root.as_array() {
        items
    } else {
        ["tasks", "items", "data"]
            .iter()
            .find_map(|name| root.get(*name).and_then(Value::as_array))
            .ok_or_else(|| anyhow!("Codex cloud list tasks are missing"))?
    };
    let mut entities = Vec::new();
    let source_item_count = items.len();
    let truncated = source_item_count > PAGE_LIMIT;
    let mut invalid_required_rows = 0;
    for item in items.iter().take(PAGE_LIMIT) {
        let Some(object) = item.as_object() else {
            invalid_required_rows += 1;
            continue;
        };
        let Some(provider_id) = string_field(object, &["id", "task_id"]) else {
            invalid_required_rows += 1;
            continue;
        };
        let Some(provider_status) = string_field(object, &["status", "state"]) else {
            invalid_required_rows += 1;
            continue;
        };
        let mut coverage = vec!["identity".to_string(), "status".to_string()];
        let mut created_at = timestamp_field(object, &["created_at", "createdAt"], observed_at);
        if created_at.is_some() {
            coverage.push("timing".to_string());
        }
        let mut started_at = timestamp_field(object, &["started_at", "startedAt"], observed_at);
        if started_at.is_some() && !coverage.contains(&"timing".to_string()) {
            coverage.push("timing".to_string());
        }
        let mut updated_at = timestamp_field(object, &["updated_at", "updatedAt"], observed_at);
        if updated_at.is_some() && !coverage.contains(&"timing".to_string()) {
            coverage.push("timing".to_string());
        }
        let mut completed_at =
            timestamp_field(object, &["completed_at", "completedAt"], observed_at);
        if completed_at.is_some() && !coverage.contains(&"timing".to_string()) {
            coverage.push("timing".to_string());
        }
        let chronology_invalid = [
            (&created_at, &started_at),
            (&started_at, &completed_at),
            (&created_at, &completed_at),
        ]
        .into_iter()
        .any(|(earlier, later)| {
            match (
                earlier
                    .as_deref()
                    .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok()),
                later
                    .as_deref()
                    .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok()),
            ) {
                (Some(earlier), Some(later)) => earlier > later,
                _ => false,
            }
        });
        if chronology_invalid {
            created_at = None;
            started_at = None;
            updated_at = None;
            completed_at = None;
            coverage.retain(|field| field != "timing");
        }
        let attempt_count = u64_field(object, &["attempt_total", "attempt_count", "attempts"])
            .filter(|attempts| *attempts <= 100_000);
        if attempt_count.is_some() {
            coverage.push("attempts".to_string());
        }
        entities.push(CloudSessionObservationEntityV1 {
            entity_key: opaque_key(key, provider_id),
            entity_kind: "task".to_string(),
            lifecycle: lifecycle(Some(provider_status)),
            attempt_count,
            environment_kind: environment_kind(string_field(
                object,
                &["environment_kind", "environment"],
            )),
            measurement_basis: "not_itemized".to_string(),
            coverage,
            created_at,
            started_at,
            updated_at,
            completed_at,
            observed_at: timestamp(observed_at),
        });
    }
    let cursor = if root.is_array() {
        CloudPageCursor::Ambiguous
    } else {
        parse_cloud_cursor(&root)?
    };
    if source_item_count == 0 && cursor == CloudPageCursor::Ambiguous {
        return Err(anyhow!(
            "Codex cloud list empty response lacks official terminal proof"
        ));
    }
    Ok(ParsedPage {
        entities,
        cursor,
        source_item_count,
        invalid_required_rows,
        truncated,
    })
}

fn parse_cloud_cursor(root: &Value) -> Result<CloudPageCursor> {
    let official = root
        .get("cursor")
        .map(parse_cloud_cursor_value)
        .transpose()?;
    let mut alias = None;
    let mut alias_seen = false;
    for name in ["next_cursor", "nextCursor"] {
        let Some(raw) = root.get(name) else {
            continue;
        };
        let parsed = parse_cloud_cursor_value(raw)?;
        if alias_seen && alias != parsed {
            return Err(anyhow!("Codex cloud list cursor aliases conflict"));
        }
        alias = parsed;
        alias_seen = true;
    }
    if official.is_some() && alias_seen && official != Some(alias.clone()) {
        return Err(anyhow!("Codex cloud list cursor aliases conflict"));
    }
    Ok(match official {
        Some(None) => CloudPageCursor::OfficialTerminal,
        Some(Some(cursor)) => CloudPageCursor::Next(cursor),
        None if alias_seen => alias.map_or(CloudPageCursor::Ambiguous, CloudPageCursor::Next),
        None => CloudPageCursor::Ambiguous,
    })
}

fn parse_cloud_cursor_value(raw: &Value) -> Result<Option<String>> {
    match raw {
        Value::Null => Ok(None),
        Value::String(value) if !value.is_empty() && value.len() <= 4_096 => {
            Ok(Some(value.clone()))
        }
        _ => Err(anyhow!("Codex cloud list cursor is invalid")),
    }
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
}
fn timestamp_field(
    object: &serde_json::Map<String, Value>,
    names: &[&str],
    observed_at: OffsetDateTime,
) -> Option<String> {
    string_field(object, names)
        .filter(|value| value.len() <= 64)
        .and_then(|value| {
            OffsetDateTime::parse(value, &Rfc3339)
                .ok()
                .filter(|parsed| *parsed <= observed_at)
                .map(|_| value)
        })
        .map(str::to_string)
}
fn u64_field(object: &serde_json::Map<String, Value>, names: &[&str]) -> Option<u64> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_u64))
}
fn lifecycle(value: Option<&str>) -> String {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "queued" => "queued",
        // The official CLI collapses provider `pending` and `in_progress`
        // into this one status, so it cannot truthfully distinguish queued
        // from running work.
        "pending" => "unknown",
        "running" | "in_progress" => "running",
        "ready" | "applied" | "completed" | "succeeded" | "success" => "completed",
        "failed" | "error" => "failed",
        "cancelled" | "canceled" => "cancelled",
        _ => "unknown",
    }
    .to_string()
}
fn environment_kind(value: Option<&str>) -> String {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "hosted" | "cloud" | "provider_cloud" => "hosted",
        "container" | "containerized" => "container",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(test)]
fn snapshot_batch(
    grant: &CloudSessionGrant,
    observations: Vec<CloudSessionObservationEntityV1>,
    now: OffsetDateTime,
    snapshot_complete: bool,
) -> std::result::Result<CloudSessionObservationBatchV1, CycleError> {
    let health = if snapshot_complete {
        CloudSessionCollectorHealthV1 {
            state: "healthy".to_string(),
            observed_at: timestamp(now),
            error_category: None,
        }
    } else {
        // The backend v1 enum has no coverage-limited category. Use its
        // existing coarse degraded/provider_error pair so a bounded partial
        // scan cannot make UI freshness look complete, while the explicit
        // snapshot_complete bit remains authoritative for absence semantics.
        CloudSessionCollectorHealthV1 {
            state: "degraded".to_string(),
            observed_at: timestamp(now),
            error_category: Some("provider_error".to_string()),
        }
    };
    build_observation_batch(
        grant,
        observations,
        now,
        CloudSessionBatchKind::Snapshot,
        snapshot_complete,
        health,
    )
}

fn heartbeat_batch(
    grant: &CloudSessionGrant,
    now: OffsetDateTime,
    health: CloudSessionCollectorHealthV1,
) -> std::result::Result<CloudSessionObservationBatchV1, CycleError> {
    build_observation_batch(
        grant,
        Vec::new(),
        now,
        CloudSessionBatchKind::Heartbeat,
        false,
        health,
    )
}

fn build_observation_batch(
    grant: &CloudSessionGrant,
    observations: Vec<CloudSessionObservationEntityV1>,
    now: OffsetDateTime,
    batch_kind: CloudSessionBatchKind,
    snapshot_complete: bool,
    health: CloudSessionCollectorHealthV1,
) -> std::result::Result<CloudSessionObservationBatchV1, CycleError> {
    let binding = grant.backend_binding.as_ref().ok_or(CycleError {
        category: "grant_unbound",
        health_uploaded: false,
    })?;
    if !is_uuid(&binding.grant_id)
        || binding.grant_version == 0
        || binding.backend_revoked
        || binding.server_policy_state != CloudSessionServerPolicyState::Approved
        || grant.collector_version != compiled_release_version()
    {
        return Err(CycleError {
            category: "grant_invalid",
            health_uploaded: false,
        });
    }
    let batch = CloudSessionObservationBatchV1 {
        grant_id: binding.grant_id.clone(),
        grant_version: binding.grant_version,
        grant_scope_fingerprint: grant.grant_scope_id.clone(),
        collector_id: COLLECTOR_ID.to_string(),
        schema_version: COLLECTOR_VERSION.to_string(),
        collector_version: grant.collector_version.clone(),
        account_fingerprint: grant.account_fingerprint.clone(),
        batch_kind,
        snapshot_complete,
        collected_at: timestamp(now),
        observations,
        health,
    };
    batch.validate_wire_contract().map_err(|_| CycleError {
        category: "batch_invalid",
        health_uploaded: false,
    })?;
    Ok(batch)
}

fn report_provider_failure(
    grant: &CloudSessionGrant,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
    deadline: Instant,
) -> std::result::Result<SendOutcome, CycleError> {
    let batch = heartbeat_batch(
        grant,
        now,
        CloudSessionCollectorHealthV1 {
            state: "failing".to_string(),
            observed_at: timestamp(now),
            // The strict backend wire intentionally has a coarser enum than
            // local diagnostics. Detailed provider execution/schema categories
            // stay in the checkpoint and local grant health only.
            error_category: Some("provider_error".to_string()),
        },
    )?;
    let Some(timeout) = remaining_relay_budget(deadline) else {
        return Ok(SendOutcome::BudgetExpired);
    };
    match transport.send_bounded(&batch, timeout) {
        Ok(()) => Ok(SendOutcome::Sent),
        Err(_) if remaining_budget(deadline).is_none() => Ok(SendOutcome::BudgetExpired),
        Err(_) => Err(CycleError {
            category: "transport_unavailable",
            health_uploaded: false,
        }),
    }
}

fn grant_scope_fingerprint(key: &[u8], setup: &CloudSessionGrantSetup) -> String {
    opaque_key(
        key,
        &format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            setup.installation_id,
            setup.organization_scope,
            setup.effective_user_scope,
            COLLECTOR_ID
        ),
    )
}

fn pending_backend_create(grant: &CloudSessionGrant) -> CloudSessionPendingBackendCreateV1 {
    CloudSessionPendingBackendCreateV1 {
        source: "codex".to_string(),
        collector_id: COLLECTOR_ID.to_string(),
        schema_version: COLLECTOR_VERSION.to_string(),
        collector_version: grant.collector_version.clone(),
        grant_scope_fingerprint: grant.grant_scope_id.clone(),
        account_fingerprint: grant.account_fingerprint.clone(),
        consent: true,
    }
}

fn validate_pending_backend_create(
    grant: &CloudSessionGrant,
    pending: &CloudSessionPendingBackendCreateV1,
) -> Result<()> {
    if pending.source != "codex"
        || pending.collector_id != COLLECTOR_ID
        || pending.schema_version != COLLECTOR_VERSION
        || pending.collector_version.trim().is_empty()
        || pending.grant_scope_fingerprint != grant.grant_scope_id
        || pending.account_fingerprint != grant.account_fingerprint
        || !pending.consent
    {
        return Err(anyhow!(
            "pending cloud-session backend grant create is invalid"
        ));
    }
    Ok(())
}

fn backend_create_request(
    installation_id: &str,
    pending: &CloudSessionPendingBackendCreateV1,
) -> CloudSessionBackendGrantCreateRequestV1 {
    CloudSessionBackendGrantCreateRequestV1 {
        installation_id: installation_id.to_string(),
        source: pending.source.clone(),
        collector_id: pending.collector_id.clone(),
        schema_version: pending.schema_version.clone(),
        collector_version: pending.collector_version.clone(),
        grant_scope_fingerprint: pending.grant_scope_fingerprint.clone(),
        account_fingerprint: pending.account_fingerprint.clone(),
        consent: pending.consent,
    }
}

fn validate_local_installation_binding(
    state: &PersistedGrant,
    installation_id: &str,
    operation: &str,
) -> Result<()> {
    let key = decode_hex(&state.hmac_key_hex)
        .filter(|key| key.len() == 32)
        .ok_or_else(|| anyhow!("invalid cloud-session HMAC key"))?;
    if !is_uuid(installation_id)
        || opaque_key(&key, installation_id) != state.grant.installation_fingerprint
    {
        return Err(anyhow!("{operation} installation binding is invalid"));
    }
    Ok(())
}

fn validate_backend_grant_response(
    state: &PersistedGrant,
    response: &CloudSessionBackendGrantResponseV1,
    expected_collector_version: &str,
) -> Result<()> {
    let key = decode_hex(&state.hmac_key_hex)
        .filter(|key| key.len() == 32)
        .ok_or_else(|| anyhow!("invalid cloud-session HMAC key"))?;
    if !is_uuid(&response.id)
        || !is_uuid(&response.installation_id)
        || opaque_key(&key, &response.installation_id) != state.grant.installation_fingerprint
        || response.source != "codex"
        || response.collector_id != COLLECTOR_ID
        || response.schema_version != COLLECTOR_VERSION
        || response.collector_version != expected_collector_version
        || response.release_lane != "supported"
        || response.disclosure_version != "cloud_sessions_disclosure.v1"
        || response.grant_scope_fingerprint != state.grant.grant_scope_id
        || response.account_fingerprint != state.grant.account_fingerprint
        || response.grant_version == 0
    {
        return Err(anyhow!("backend cloud-session grant scope does not match"));
    }
    Ok(())
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn grant_preflight_eligible(store: &CloudSessionGrantStore) -> bool {
    store
        .load()
        .ok()
        .flatten()
        .is_some_and(|grant| cloud_grant_preflight_eligible(&grant))
}

fn cloud_grant_preflight_eligible(grant: &CloudSessionGrant) -> bool {
    matches!(
        grant.status,
        CloudSessionGrantStatus::Enabled | CloudSessionGrantStatus::PolicyDisabled
    ) && grant.collector_version == compiled_release_version()
        && !grant.backend_create_pending
        && grant
            .backend_binding
            .as_ref()
            .is_some_and(|binding| !binding.backend_revoked)
}

fn cloud_grant_runtime_ready(grant: &CloudSessionGrant) -> bool {
    grant.status == CloudSessionGrantStatus::Enabled
        && grant.collector_version == compiled_release_version()
        && !grant.backend_create_pending
        && grant.backend_binding.as_ref().is_some_and(|binding| {
            !binding.backend_revoked
                && binding.server_policy_state == CloudSessionServerPolicyState::Approved
        })
}

fn grant_still_current(store: &CloudSessionGrantStore, expected: &CloudSessionGrant) -> bool {
    store.load().ok().flatten().is_some_and(|current| {
        cloud_grant_runtime_ready(&current)
            && same_runtime_grant_identity(&current, expected)
            && current
                .backend_binding
                .is_some_and(|binding| !binding.backend_revoked)
    })
}

fn same_runtime_grant_identity(current: &CloudSessionGrant, expected: &CloudSessionGrant) -> bool {
    current.schema_version == expected.schema_version
        && current.collector_id == expected.collector_id
        && current.collector_version == expected.collector_version
        && current.release_lane == expected.release_lane
        && current.disclosure_version == expected.disclosure_version
        && current.installation_fingerprint == expected.installation_fingerprint
        && current.grant_scope_id == expected.grant_scope_id
        && current.organization_fingerprint == expected.organization_fingerprint
        && current.effective_user_fingerprint == expected.effective_user_fingerprint
        && current.account_fingerprint == expected.account_fingerprint
        && matches!(
            (
                current.backend_binding.as_ref(),
                expected.backend_binding.as_ref(),
            ),
            (Some(current), Some(expected))
                if current.grant_id == expected.grant_id
                    && current.grant_version == expected.grant_version
        )
}

fn health_heartbeat_due(checkpoint: &CloudSessionCheckpoint, now: OffsetDateTime) -> bool {
    match checkpoint
        .last_health_upload_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
    {
        Some(last) => now >= last + HEALTH_HEARTBEAT_INTERVAL,
        None => true,
    }
}

fn complete_snapshot_due(checkpoint: &CloudSessionCheckpoint, now: OffsetDateTime) -> bool {
    match checkpoint
        .last_complete_snapshot_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
    {
        Some(last) => last.date() != now.date(),
        None => true,
    }
}

fn circuit_open_for_grant(
    checkpoint: &CloudSessionCheckpoint,
    grant: &CloudSessionGrant,
    now: OffsetDateTime,
) -> bool {
    checkpoint.circuit_grant_epoch_digest.as_deref() == Some(grant_epoch_digest(grant).as_str())
        && checkpoint
            .circuit_open_until
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .is_some_and(|until| until > now)
}
fn reset_stale_circuit_for_grant(
    checkpoint: &mut CloudSessionCheckpoint,
    grant: &CloudSessionGrant,
) {
    let current_epoch = grant_epoch_digest(grant);
    let has_circuit_state = checkpoint.consecutive_failures > 0
        || checkpoint.circuit_open_until.is_some()
        || checkpoint.circuit_grant_epoch_digest.is_some();
    if has_circuit_state
        && checkpoint.circuit_grant_epoch_digest.as_deref() != Some(current_epoch.as_str())
    {
        checkpoint.consecutive_failures = 0;
        checkpoint.circuit_open_until = None;
        checkpoint.circuit_grant_epoch_digest = None;
        if checkpoint.last_error_category.as_deref() != Some("scan_incomplete") {
            checkpoint.last_error_category = None;
        }
    }
}
fn backoff_seconds(failures: u32) -> u64 {
    60 * (1_u64 << failures.min(6))
}
fn kill_switch_enabled() -> bool {
    truthy_env(KILL_SWITCH_ENV)
}
fn truthy_env(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}
fn timestamp(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}
fn valid_rfc3339(value: &str) -> bool {
    !value.is_empty() && OffsetDateTime::parse(value, &Rfc3339).is_ok()
}
fn valid_hmac_fingerprint(value: &str) -> bool {
    value.len() == 76
        && value.starts_with("hmac-sha256:")
        && value[12..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("sha256:{:x}", digest.finalize())
}
fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn push_length_framed(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}
fn identity_digest(observations: &[CloudSessionObservationEntityV1]) -> String {
    let mut keys = observations
        .iter()
        .map(|observation| observation.entity_key.as_bytes())
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    let mut framed = Vec::new();
    for key in keys {
        push_length_framed(&mut framed, key);
    }
    sha256(&framed)
}
fn observation_semantic_digest(observations: &[CloudSessionObservationEntityV1]) -> Result<String> {
    let mut semantics = observations
        .iter()
        .map(|observation| {
            let mut value = serde_json::to_value(observation)?;
            if let Some(object) = value.as_object_mut() {
                object.remove("observed_at");
                object.remove("collected_at");
            }
            Ok((observation.entity_key.clone(), value))
        })
        .collect::<Result<Vec<_>>>()?;
    semantics.sort_by(|left, right| left.0.cmp(&right.0));
    let canonical = semantics
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    Ok(sha256(&serde_json::to_vec(&canonical)?))
}
fn inventory_digest<'a>(keys: impl IntoIterator<Item = &'a String>) -> String {
    let mut keys = keys.into_iter().map(String::as_bytes).collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    let mut framed = Vec::new();
    for key in keys {
        push_length_framed(&mut framed, key);
    }
    sha256(&framed)
}
fn epoch_digest(chunks: &[CloudSessionObservationChunkV2]) -> String {
    let mut framed = Vec::new();
    for chunk in chunks {
        framed.extend_from_slice(&(chunk.chunk_index as u64).to_be_bytes());
        framed.extend_from_slice(&(chunk.observations.len() as u64).to_be_bytes());
        push_length_framed(&mut framed, chunk.chunk_identity_digest.as_bytes());
        push_length_framed(&mut framed, chunk.chunk_semantic_digest.as_bytes());
    }
    sha256(&framed)
}
fn grant_epoch_digest(grant: &CloudSessionGrant) -> String {
    let mut framed = Vec::new();
    if let Some(binding) = &grant.backend_binding {
        push_length_framed(&mut framed, binding.grant_id.as_bytes());
        framed.extend_from_slice(&binding.grant_version.to_be_bytes());
    }
    sha256(&framed)
}
fn opaque_key(key: &[u8], raw: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(raw.as_bytes());
    format!("hmac-sha256:{}", hex(&mac.finalize().into_bytes()))
}
fn random_key() -> Result<Vec<u8>> {
    let mut key = vec![0_u8; 32];
    random_fill(&mut key).map_err(|_| anyhow!("generate cloud-session HMAC key"))?;
    Ok(key)
}
fn random_scan_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    random_fill(&mut bytes).map_err(|_| anyhow!("generate cloud-session scan id"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
        bytes[15]
    ))
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
fn atomic_json_write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("cloud-session state path has no parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let payload = serde_json::to_vec(value)?;
    let mut nonce = [0_u8; 16];
    random_fill(&mut nonce).map_err(|_| anyhow!("generate cloud-session state nonce"))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("cloud-session state filename is invalid"))?;
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
            .context("create cloud-session temporary state")?;
        file.write_all(&payload)
            .context("write cloud-session temporary state")?;
        file.sync_all()
            .context("sync cloud-session temporary state")?;
        drop(file);
        fs::rename(&temporary, path).context("replace cloud-session state")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("sync cloud-session state directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudSessionCollectorStartup {
    DeferredTransport,
    Started,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CloudSessionRuntimeBinding {
    api_base_url: String,
    device: LocalDeviceBinding,
    grant_id: String,
    grant_version: u64,
    grant_scope_id: String,
}

struct CloudSessionRuntimeCandidate {
    binding: CloudSessionRuntimeBinding,
    grant: CloudSessionGrant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CloudSessionRuntimeTransportKey {
    binding: CloudSessionRuntimeBinding,
    device_secret_digest: String,
}

type ActiveCloudSessionTransport = Option<(
    CloudSessionRuntimeTransportKey,
    Box<dyn CloudSessionTransport + Send>,
)>;

fn load_cloud_session_runtime_binding(
    grants: &CloudSessionGrantStore,
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
    connections: &FileConnectionStore,
) -> Result<Option<CloudSessionRuntimeCandidate>> {
    // The default/off path is intentionally one local grant read. Do not touch
    // account, connection, device, or Keychain state until consent is capable
    // of becoming runtime-ready.
    if !grant_preflight_eligible(grants) {
        return Ok(None);
    }
    let account = accounts.load()?;
    let user_id = account
        .user
        .as_ref()
        .map(|user| user.id.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("cloud-session local user binding is unavailable"))?;
    let organization_id = account
        .organization
        .as_ref()
        .map(|organization| organization.id.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("cloud-session local organization binding is unavailable"))?;
    if account.state != LocalAccountState::Connected {
        return Err(anyhow!("cloud-session local account is not connected"));
    }
    let device = devices
        .load()?
        .ok_or_else(|| anyhow!("cloud-session relay device binding is unavailable"))?;
    if !is_uuid(&device.device_id) || !device.sources.iter().any(|source| source == "codex") {
        return Err(anyhow!(
            "cloud-session relay device is not exactly Codex-bound"
        ));
    }
    let connection = connections
        .load()?
        .ok_or_else(|| anyhow!("cloud-session backend connection is unavailable"))?;
    if connection.setup_run_id.trim().is_empty() || connection.machine_id != device.machine_id {
        return Err(anyhow!(
            "cloud-session backend connection does not match the relay device"
        ));
    }
    // Validate the persisted destination before the caller reads the device
    // secret. Loopback is accepted only when the daemon process explicitly
    // carries the exact same developer override.
    let api_base_url = validated_cloud_session_api_base_url(&connection.api_base_url)?;
    let setup = CloudSessionGrantSetup {
        installation_id: device.device_id.clone(),
        organization_scope: organization_id.to_string(),
        effective_user_scope: user_id.to_string(),
    };
    let Some(grant) = grants.runtime_candidate_for(&setup)? else {
        return Ok(None);
    };
    let backend = grant
        .backend_binding
        .as_ref()
        .ok_or_else(|| anyhow!("cloud-session backend grant is unbound"))?;
    Ok(Some(CloudSessionRuntimeCandidate {
        binding: CloudSessionRuntimeBinding {
            api_base_url,
            device,
            grant_id: backend.grant_id.clone(),
            grant_version: backend.grant_version,
            grant_scope_id: grant.grant_scope_id.clone(),
        },
        grant,
    }))
}

fn validated_cloud_session_api_base_url(raw: &str) -> Result<String> {
    let value = raw.trim().trim_end_matches('/');
    if value.is_empty() || value.contains(['@', '?', '#']) {
        return Err(anyhow!("cloud-session backend destination is untrusted"));
    }
    let production = value == DEFAULT_API_BASE_URL
        || value == LEGACY_API_BASE_URL
        || value.starts_with(&format!("{DEFAULT_API_BASE_URL}/"))
        || value.starts_with(&format!("{LEGACY_API_BASE_URL}/"));
    let exact_developer_override = std::env::var("OTTTO_API_BASE_URL")
        .ok()
        .map(|override_value| override_value.trim().trim_end_matches('/').to_string())
        .is_some_and(|override_value| override_value == value && is_loopback_http_base(value));
    if !production && !exact_developer_override {
        return Err(anyhow!("cloud-session backend destination is untrusted"));
    }
    Ok(value.to_string())
}

fn is_loopback_http_base(value: &str) -> bool {
    ["http://127.0.0.1", "http://localhost"]
        .iter()
        .any(|prefix| {
            value.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.is_empty()
                    || suffix.starts_with('/')
                    || suffix.strip_prefix(':').is_some_and(|port_and_path| {
                        let port = port_and_path.split('/').next().unwrap_or_default();
                        !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
                    })
            })
        })
}

fn deactivate_composed_runtime(
    active_transport: &mut ActiveCloudSessionTransport,
    checkpoints: &CloudSessionCheckpointStore,
) {
    active_transport.take();
    disable_checkpoint_runtime(checkpoints);
}

fn collect_composed_cloud_sessions_once(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    runner: &dyn CloudSessionRunner,
    active_transport: &mut ActiveCloudSessionTransport,
    now: OffsetDateTime,
) -> CloudSessionCycleOutcome {
    let accounts = FileAccountStore::default();
    let devices = FileDeviceStore::default();
    let connections = FileConnectionStore::default();
    collect_composed_cloud_sessions_once_with(
        grants,
        checkpoints,
        runner,
        active_transport,
        &accounts,
        &devices,
        &connections,
        crate::snapshot_client::load_snapshot_device_credentials,
        |api_base_url, device, device_secret| {
            Box::new(RelayCloudSessionTransport::new(
                api_base_url,
                device,
                device_secret,
            ))
        },
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_composed_cloud_sessions_once_with<FLoadCredentials, FComposeTransport>(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    runner: &dyn CloudSessionRunner,
    active_transport: &mut ActiveCloudSessionTransport,
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
    connections: &FileConnectionStore,
    load_credentials: FLoadCredentials,
    compose_transport: FComposeTransport,
    now: OffsetDateTime,
) -> CloudSessionCycleOutcome
where
    FLoadCredentials: FnOnce() -> Result<(LocalDeviceBinding, String)>,
    FComposeTransport:
        FnOnce(String, LocalDeviceBinding, String) -> Box<dyn CloudSessionTransport + Send>,
{
    if kill_switch_enabled() {
        deactivate_composed_runtime(active_transport, checkpoints);
        return CloudSessionCycleOutcome::Disabled;
    }
    let candidate = match load_cloud_session_runtime_binding(grants, accounts, devices, connections)
    {
        Ok(Some(candidate)) => candidate,
        Ok(None) => {
            deactivate_composed_runtime(active_transport, checkpoints);
            return CloudSessionCycleOutcome::Disabled;
        }
        Err(_) => {
            deactivate_composed_runtime(active_transport, checkpoints);
            let _ =
                grants.record_health("unavailable", "unavailable", Some("local_binding_invalid"));
            return CloudSessionCycleOutcome::Failed;
        }
    };
    let mut checkpoint = checkpoints.load();
    reset_stale_circuit_for_grant(&mut checkpoint, &candidate.grant);
    if circuit_open_for_grant(&checkpoint, &candidate.grant, now) {
        return CloudSessionCycleOutcome::CircuitOpen;
    }
    let binding = candidate.binding;
    // `load_cloud_session_runtime_binding` validates the destination first, so
    // an on-disk URL cannot receive this long-lived secret. Reloading the
    // device with the secret also closes an identity-change race.
    let (credential_device, device_secret) = match load_credentials() {
        Ok(credentials) => credentials,
        Err(_) => {
            deactivate_composed_runtime(active_transport, checkpoints);
            let _ = grants.record_health(
                "unavailable",
                "unavailable",
                Some("relay_credentials_unavailable"),
            );
            return CloudSessionCycleOutcome::Failed;
        }
    };
    if credential_device != binding.device || device_secret.trim().is_empty() {
        deactivate_composed_runtime(active_transport, checkpoints);
        let _ = grants.record_health("unavailable", "unavailable", Some("local_binding_changed"));
        return CloudSessionCycleOutcome::Failed;
    }
    let key = CloudSessionRuntimeTransportKey {
        binding: binding.clone(),
        device_secret_digest: sha256(device_secret.as_bytes()),
    };
    let transport_changed = active_transport
        .as_ref()
        .map_or(true, |(current, _)| current != &key);
    if transport_changed {
        // Scan receipt bookkeeping belongs to one transport instance. Restart
        // the in-memory scan before dropping that instance so a replacement
        // never resumes with receipts it cannot prove.
        deactivate_composed_runtime(active_transport, checkpoints);
        let transport = compose_transport(binding.api_base_url, credential_device, device_secret);
        // A candidate transport remains local and unretained until the server
        // confirms this exact grant epoch. This is a one-time activation read
        // per identity/credential change; normal polling keeps the established
        // transport and its relay token.
        let authority = match transport.revalidate_grant_bounded(&candidate.grant, COMMAND_TIMEOUT)
        {
            Ok(authority) => authority,
            Err(_) => {
                deactivate_composed_runtime(active_transport, checkpoints);
                record_runtime_activation_failure(
                    grants,
                    checkpoints,
                    &candidate.grant,
                    now,
                    "grant_revalidation_unavailable",
                );
                return CloudSessionCycleOutcome::Failed;
            }
        };
        let current = match grants.apply_backend_grant_revalidation(&authority) {
            Ok(current) => current,
            Err(_) => {
                deactivate_composed_runtime(active_transport, checkpoints);
                record_runtime_activation_failure(
                    grants,
                    checkpoints,
                    &candidate.grant,
                    now,
                    "grant_revalidation_invalid",
                );
                return CloudSessionCycleOutcome::Failed;
            }
        };
        if !cloud_grant_runtime_ready(&current)
            || !same_runtime_grant_identity(&current, &candidate.grant)
        {
            deactivate_composed_runtime(active_transport, checkpoints);
            return CloudSessionCycleOutcome::Disabled;
        }
        *active_transport = Some((key, transport));
    }
    let transport = active_transport
        .as_ref()
        .expect("cloud-session transport was just composed")
        .1
        .as_ref();
    // The collector performs exact backend grant authority revalidation before
    // its first provider subprocess and at every later provider/upload fence.
    let outcome = collect_cloud_sessions_once(grants, checkpoints, runner, transport, now);
    if kill_switch_enabled() || !grant_preflight_eligible(grants) {
        deactivate_composed_runtime(active_transport, checkpoints);
    }
    outcome
}

fn record_runtime_activation_failure(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    grant: &CloudSessionGrant,
    now: OffsetDateTime,
    category: &'static str,
) {
    let mut checkpoint = checkpoints.load();
    reset_stale_circuit_for_grant(&mut checkpoint, grant);
    checkpoint.consecutive_failures = checkpoint.consecutive_failures.saturating_add(1);
    checkpoint.last_error_category = Some(category.to_string());
    checkpoint.circuit_grant_epoch_digest = Some(grant_epoch_digest(grant));
    checkpoint.circuit_open_until = Some(timestamp(
        now + TimeDuration::seconds(backoff_seconds(checkpoint.consecutive_failures) as i64),
    ));
    let _ = checkpoints.save(&checkpoint);
    let _ = grants.record_health("failing", "stale", Some(category));
}

fn reserve_collector_supervisor(started: &AtomicBool) -> bool {
    started
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .is_ok()
}

pub fn spawn_cloud_session_collector() -> Result<CloudSessionCollectorStartup> {
    // The supervisor is always available so a newly approved local grant can
    // activate without restarting the daemon. Each cycle remains inert until
    // exact local consent and server policy both authorize collection.
    if !reserve_collector_supervisor(&COLLECTOR_SUPERVISOR_STARTED) {
        return Ok(CloudSessionCollectorStartup::Started);
    }
    let spawned = thread::Builder::new()
        .name("ottto-codex-cloud-sessions".to_string())
        .spawn(|| {
            let grants = CloudSessionGrantStore::default();
            let checkpoints = CloudSessionCheckpointStore::default();
            let runner = CodexCloudCliRunner;
            let mut active_transport = None;
            loop {
                let outcome = collect_composed_cloud_sessions_once(
                    &grants,
                    &checkpoints,
                    &runner,
                    &mut active_transport,
                    OffsetDateTime::now_utc(),
                );
                if !matches!(
                    outcome,
                    CloudSessionCycleOutcome::Disabled | CloudSessionCycleOutcome::Noop
                ) {
                    eprintln!("codex_cloud_session_collector outcome={outcome:?}");
                }
                thread::sleep(POLL_INTERVAL + cycle_jitter());
            }
        });
    if let Err(error) = spawned {
        COLLECTOR_SUPERVISOR_STARTED.store(false, AtomicOrdering::Release);
        return Err(anyhow!("spawn Codex cloud-session collector: {error}"));
    }
    Ok(CloudSessionCollectorStartup::Started)
}

fn cycle_jitter() -> Duration {
    // No persisted schedule/cursor: bounded variation prevents synchronized polls.
    let nanos = OffsetDateTime::now_utc().nanosecond() as u64;
    Duration::from_secs(nanos % (MAX_JITTER.as_secs() + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    const INSTALLATION_ID: &str = "00000000-0000-4000-8000-000000000001";
    const GRANT_ID: &str = "00000000-0000-4000-8000-000000000002";
    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ottto-cloud-sessions-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-07-21T12:00:00Z", &Rfc3339).unwrap()
    }
    fn stores(name: &str) -> (CloudSessionGrantStore, CloudSessionCheckpointStore) {
        let root = temp_dir(name);
        (
            CloudSessionGrantStore::new(root.join("grant.json")),
            CloudSessionCheckpointStore::new(root.join("checkpoint.json")),
        )
    }
    fn enabled(store: &CloudSessionGrantStore) {
        let local = store
            .enable(
                &CloudSessionGrantSetup {
                    installation_id: INSTALLATION_ID.to_string(),
                    organization_scope: "org_fixture".to_string(),
                    effective_user_scope: "user_fixture".to_string(),
                },
                now(),
            )
            .unwrap();
        store.grant_create_request(INSTALLATION_ID).unwrap();
        store
            .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
            .unwrap();
    }

    fn runtime_identity_stores(
        root: &Path,
        user_id: &str,
        organization_id: &str,
        api_base_url: &str,
    ) -> (FileAccountStore, FileDeviceStore, FileConnectionStore) {
        let accounts = FileAccountStore::new(root.join("account.json"));
        accounts
            .save(&ottto_protocol::LocalAccountBinding {
                state: LocalAccountState::Connected,
                user: Some(ottto_protocol::LocalAccountUser {
                    id: user_id.to_string(),
                    email: "runtime@example.com".to_string(),
                    display_name: None,
                }),
                organization: Some(ottto_protocol::LocalAccountOrganization {
                    id: organization_id.to_string(),
                    name: "Runtime Org".to_string(),
                }),
                connected_at: None,
                last_refreshed_at: None,
                message: None,
            })
            .unwrap();
        let devices = FileDeviceStore::new(root.join("device.json"));
        devices
            .save(&LocalDeviceBinding {
                device_id: INSTALLATION_ID.to_string(),
                machine_id: Some("machine-runtime".to_string()),
                sources: vec!["codex".to_string()],
            })
            .unwrap();
        let connections = FileConnectionStore::new(root.join("connection.json"));
        connections
            .save(&ottto_core::LocalConnectionBinding {
                setup_run_id: "setup-runtime".to_string(),
                setup_run_token_expires_at: "2030-01-01T00:00:00Z".to_string(),
                machine_id: Some("machine-runtime".to_string()),
                claim_code: None,
                api_base_url: api_base_url.to_string(),
            })
            .unwrap();
        (accounts, devices, connections)
    }

    #[test]
    fn control_token_ledger_is_atomic_bounded_and_replay_safe_across_restart() {
        let root = temp_dir("control-token-ledger");
        let path = root.join("control-token-uses.json");
        let now = 1_800_000_000;
        let token_id = "apps-control-private-jti";
        let store = Arc::new(CloudSessionControlTokenUseStore::new(&path));
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let attempts = (0..2)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.consume(token_id, now + 120, now)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);

        let restarted = CloudSessionControlTokenUseStore::new(&path);
        assert!(restarted.consume(token_id, now + 120, now).is_err());
        let bytes = fs::read_to_string(&path).unwrap();
        assert!(!bytes.contains(token_id));
        assert!(!bytes.contains("header.payload.signature"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        for index in 0..(MAX_CONTROL_TOKEN_USES - 1) {
            restarted
                .consume(&format!("token-{index}"), now + 121 + index as u64, now)
                .unwrap();
        }
        let ledger: CloudSessionControlTokenUseLedger =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(ledger.entries.len(), MAX_CONTROL_TOKEN_USES);
        assert!(restarted.consume("over-cap", now + 240, now).is_err());
        assert!(restarted.consume(token_id, now + 120, now).is_err());
        restarted
            .consume("post-expiry", now + 500, now + 400)
            .unwrap();
        let pruned: CloudSessionControlTokenUseLedger =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(pruned.entries.len(), 1);
    }

    #[test]
    fn revoke_prevents_new_provider_admission_and_waits_for_inflight_io() {
        use std::sync::mpsc;

        struct BlockingRunner {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
        }
        impl CloudSessionRunner for BlockingRunner {
            fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<String> {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                Ok(page("blocked-provider-call", None))
            }
        }
        struct AuthorityTransport;
        impl CloudSessionTransport for AuthorityTransport {
            fn supports_grant_revalidation(&self) -> bool {
                true
            }
            fn revalidate_grant_bounded(
                &self,
                grant: &CloudSessionGrant,
                _timeout: Duration,
            ) -> Result<CloudSessionBackendGrantResponseV1> {
                Ok(backend_grant(grant, "enabled", 1))
            }
            fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
                Ok(())
            }
        }

        let root = temp_dir("provider-call-fence");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
            root.join("checkpoint.json"),
        ));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let collector_grants = grants.clone();
        let collector_checkpoints = Arc::clone(&checkpoints);
        let collector = thread::spawn(move || {
            collect_cloud_sessions_once(
                &collector_grants,
                &collector_checkpoints,
                &BlockingRunner {
                    entered: entered_tx,
                    release: release_rx,
                },
                &AuthorityTransport,
                now(),
            )
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        grants.revoke(now()).unwrap();
        let waiter_checkpoints = Arc::clone(&checkpoints);
        let (stopped_tx, stopped_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let result = waiter_checkpoints.wait_for_collector_io_idle(Duration::from_secs(2));
            stopped_tx.send(result).unwrap();
        });
        assert!(stopped_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).unwrap();
        stopped_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        waiter.join().unwrap();
        assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Noop);

        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let (_second_release_tx, second_release_rx) = mpsc::channel();
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &BlockingRunner {
                    entered: second_entered_tx,
                    release: second_release_rx,
                },
                &AuthorityTransport,
                now(),
            ),
            CloudSessionCycleOutcome::Disabled
        );
        assert!(second_entered_rx.try_recv().is_err());
    }

    #[test]
    fn provider_error_releases_stop_fence_before_backend_health_io() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc;

        struct ErrorRunner;
        impl CloudSessionRunner for ErrorRunner {
            fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<String> {
                Err(anyhow!("provider failed"))
            }
        }
        struct BlockingFailureTransport {
            authority_calls: AtomicUsize,
            backend_entered: mpsc::Sender<()>,
            backend_release: Mutex<mpsc::Receiver<()>>,
        }
        impl CloudSessionTransport for BlockingFailureTransport {
            fn supports_grant_revalidation(&self) -> bool {
                true
            }
            fn revalidate_grant_bounded(
                &self,
                grant: &CloudSessionGrant,
                _timeout: Duration,
            ) -> Result<CloudSessionBackendGrantResponseV1> {
                if self.authority_calls.fetch_add(1, Ordering::SeqCst) > 0 {
                    self.backend_entered.send(()).unwrap();
                    self.backend_release.lock().unwrap().recv().unwrap();
                }
                Ok(backend_grant(grant, "enabled", 1))
            }
            fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
                Ok(())
            }
        }

        let root = temp_dir("provider-error-fence");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
            root.join("checkpoint.json"),
        ));
        let (backend_entered_tx, backend_entered_rx) = mpsc::channel();
        let (backend_release_tx, backend_release_rx) = mpsc::channel();
        let collector_grants = grants.clone();
        let collector_checkpoints = Arc::clone(&checkpoints);
        let collector = thread::spawn(move || {
            collect_cloud_sessions_once(
                &collector_grants,
                &collector_checkpoints,
                &ErrorRunner,
                &BlockingFailureTransport {
                    authority_calls: AtomicUsize::new(0),
                    backend_entered: backend_entered_tx,
                    backend_release: Mutex::new(backend_release_rx),
                },
                now(),
            )
        });
        backend_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();

        checkpoints
            .wait_for_collector_io_idle(Duration::from_millis(100))
            .unwrap();
        backend_release_tx.send(()).unwrap();
        assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Failed);
    }

    fn backend_grant(
        local: &CloudSessionGrant,
        status: &str,
        grant_version: u64,
    ) -> CloudSessionBackendGrantResponseV1 {
        CloudSessionBackendGrantResponseV1 {
            id: GRANT_ID.to_string(),
            installation_id: INSTALLATION_ID.to_string(),
            source: "codex".to_string(),
            collector_id: COLLECTOR_ID.to_string(),
            schema_version: COLLECTOR_VERSION.to_string(),
            collector_version: compiled_release_version(),
            release_lane: "supported".to_string(),
            disclosure_version: "cloud_sessions_disclosure.v1".to_string(),
            grant_scope_fingerprint: local.grant_scope_id.clone(),
            account_fingerprint: local.account_fingerprint.clone(),
            status: status.to_string(),
            grant_version,
            server_policy_state: CloudSessionServerPolicyState::Approved,
        }
    }
    struct Pages {
        pages: RefCell<Vec<String>>,
        calls: Cell<usize>,
        revoke: Option<CloudSessionGrantStore>,
    }
    struct FailingPages {
        calls: Cell<usize>,
    }
    impl CloudSessionRunner for FailingPages {
        fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<String> {
            self.calls.set(self.calls.get() + 1);
            Err(anyhow!("provider unavailable"))
        }
    }
    impl CloudSessionRunner for Pages {
        fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<String> {
            self.calls.set(self.calls.get() + 1);
            if let Some(store) = &self.revoke {
                store.revoke(now()).unwrap();
            }
            Ok(self.pages.borrow_mut().remove(0))
        }
    }
    struct RecordingTransport {
        calls: Cell<usize>,
        batches: RefCell<Vec<CloudSessionObservationBatchV1>>,
        fail: bool,
    }
    impl CloudSessionTransport for RecordingTransport {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }

        fn revalidate_grant(
            &self,
            grant: &CloudSessionGrant,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            Ok(backend_grant(
                grant,
                "enabled",
                grant
                    .backend_binding
                    .as_ref()
                    .map_or(1, |binding| binding.grant_version),
            ))
        }

        fn revalidate_grant_bounded(
            &self,
            grant: &CloudSessionGrant,
            _timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            self.revalidate_grant(grant)
        }

        fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.calls.set(self.calls.get() + 1);
            self.batches.borrow_mut().push(batch.clone());
            if self.fail {
                Err(anyhow!("offline"))
            } else {
                Ok(())
            }
        }

        fn send_scan_chunk(&self, chunk: &CloudSessionObservationChunkV2) -> Result<()> {
            self.calls.set(self.calls.get() + 1);
            self.batches
                .borrow_mut()
                .push(CloudSessionObservationBatchV1 {
                    grant_id: chunk.grant_id.clone(),
                    grant_version: chunk.grant_version,
                    grant_scope_fingerprint: chunk.grant_scope_fingerprint.clone(),
                    collector_id: chunk.collector_id.clone(),
                    schema_version: COLLECTOR_VERSION.to_string(),
                    collector_version: chunk.collector_version.clone(),
                    account_fingerprint: chunk.account_fingerprint.clone(),
                    batch_kind: CloudSessionBatchKind::Snapshot,
                    snapshot_complete: false,
                    collected_at: chunk.scan_started_at.clone(),
                    observations: chunk.observations.clone(),
                    health: chunk.health.clone(),
                });
            if self.fail {
                Err(anyhow!("offline"))
            } else {
                Ok(())
            }
        }

        fn finalize_scan(&self, finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
            if self.fail {
                return Err(anyhow!("offline"));
            }
            let mut batches = self.batches.borrow_mut();
            if let Some(last) = batches.last_mut() {
                last.snapshot_complete = true;
            } else {
                self.calls.set(self.calls.get() + 1);
                batches.push(CloudSessionObservationBatchV1 {
                    grant_id: finalize.grant_id.clone(),
                    grant_version: finalize.grant_version,
                    grant_scope_fingerprint: finalize.grant_scope_fingerprint.clone(),
                    collector_id: finalize.collector_id.clone(),
                    schema_version: COLLECTOR_VERSION.to_string(),
                    collector_version: finalize.collector_version.clone(),
                    account_fingerprint: finalize.account_fingerprint.clone(),
                    batch_kind: CloudSessionBatchKind::Snapshot,
                    snapshot_complete: true,
                    collected_at: finalize.scan_started_at.clone(),
                    observations: Vec::new(),
                    health: CloudSessionCollectorHealthV1 {
                        state: "healthy".to_string(),
                        observed_at: finalize.scan_started_at.clone(),
                        error_category: None,
                    },
                });
            }
            Ok(())
        }
    }
    struct RevalidationTransport {
        response: Option<CloudSessionBackendGrantResponseV1>,
        revalidation_calls: Cell<usize>,
        send_calls: Cell<usize>,
    }
    impl CloudSessionTransport for RevalidationTransport {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }

        fn revalidate_grant(
            &self,
            _grant: &CloudSessionGrant,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            self.revalidation_calls
                .set(self.revalidation_calls.get() + 1);
            self.response
                .clone()
                .ok_or_else(|| anyhow!("backend unavailable"))
        }

        fn revalidate_grant_bounded(
            &self,
            grant: &CloudSessionGrant,
            _timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            self.revalidate_grant(grant)
        }

        fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.send_calls.set(self.send_calls.get() + 1);
            Ok(())
        }

        fn send_scan_chunk(&self, _chunk: &CloudSessionObservationChunkV2) -> Result<()> {
            self.send_calls.set(self.send_calls.get() + 1);
            Ok(())
        }

        fn finalize_scan(&self, _finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
            Ok(())
        }
    }

    struct V2RecordingTransport {
        chunks: RefCell<Vec<CloudSessionObservationChunkV2>>,
        finalizes: RefCell<Vec<CloudSessionScanFinalizeV2>>,
        heartbeats: RefCell<Vec<CloudSessionObservationBatchV1>>,
        revalidation_calls: Cell<usize>,
        fail_next_chunk: Cell<bool>,
    }

    struct SequencedStatusTransport {
        statuses: RefCell<VecDeque<&'static str>>,
        revalidation_calls: Cell<usize>,
        send_calls: Cell<usize>,
    }
    impl CloudSessionTransport for SequencedStatusTransport {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }

        fn revalidate_grant(
            &self,
            grant: &CloudSessionGrant,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            let call = self.revalidation_calls.get() + 1;
            self.revalidation_calls.set(call);
            let status = self
                .statuses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| anyhow!("unexpected revalidation"))?;
            Ok(backend_grant(grant, status, 1))
        }

        fn revalidate_grant_bounded(
            &self,
            grant: &CloudSessionGrant,
            _timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            self.revalidate_grant(grant)
        }

        fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.send_calls.set(self.send_calls.get() + 1);
            Ok(())
        }
    }

    struct SlowBudgetTransport<'a> {
        checkpoints: &'a CloudSessionCheckpointStore,
        revalidation_calls: Cell<usize>,
        send_calls: Cell<usize>,
        timeouts: RefCell<Vec<Duration>>,
        mutex_was_available: Cell<bool>,
    }
    impl SlowBudgetTransport<'_> {
        fn observe_mutex(&self) {
            self.mutex_was_available
                .set(self.mutex_was_available.get() && self.checkpoints.runtime.try_lock().is_ok());
        }
    }
    impl CloudSessionTransport for SlowBudgetTransport<'_> {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }

        fn revalidate_grant(
            &self,
            grant: &CloudSessionGrant,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            Ok(backend_grant(grant, "enabled", 1))
        }

        fn revalidate_grant_bounded(
            &self,
            _grant: &CloudSessionGrant,
            timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            self.observe_mutex();
            self.revalidation_calls
                .set(self.revalidation_calls.get() + 1);
            self.timeouts.borrow_mut().push(timeout);
            thread::sleep(timeout);
            Err(anyhow!("cycle budget exhausted during revalidation"))
        }

        fn send_scan_chunk(&self, _chunk: &CloudSessionObservationChunkV2) -> Result<()> {
            Err(anyhow!("bounded method required"))
        }

        fn send_scan_chunk_bounded(
            &self,
            _chunk: &CloudSessionObservationChunkV2,
            timeout: Duration,
        ) -> Result<()> {
            self.observe_mutex();
            self.send_calls.set(self.send_calls.get() + 1);
            self.timeouts.borrow_mut().push(timeout);
            Err(anyhow!("unexpected upload after expired revalidation"))
        }

        fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
            Err(anyhow!("unexpected heartbeat"))
        }
    }
    impl V2RecordingTransport {
        fn new() -> Self {
            Self {
                chunks: RefCell::new(Vec::new()),
                finalizes: RefCell::new(Vec::new()),
                heartbeats: RefCell::new(Vec::new()),
                revalidation_calls: Cell::new(0),
                fail_next_chunk: Cell::new(false),
            }
        }
    }
    impl CloudSessionTransport for V2RecordingTransport {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }
        fn revalidate_grant(
            &self,
            grant: &CloudSessionGrant,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            self.revalidation_calls
                .set(self.revalidation_calls.get() + 1);
            Ok(backend_grant(
                grant,
                "enabled",
                grant
                    .backend_binding
                    .as_ref()
                    .map_or(1, |binding| binding.grant_version),
            ))
        }

        fn revalidate_grant_bounded(
            &self,
            grant: &CloudSessionGrant,
            _timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            self.revalidate_grant(grant)
        }
        fn send_scan_chunk(&self, chunk: &CloudSessionObservationChunkV2) -> Result<()> {
            self.chunks.borrow_mut().push(chunk.clone());
            if self.fail_next_chunk.replace(false) {
                Err(anyhow!("response lost"))
            } else {
                Ok(())
            }
        }
        fn finalize_scan(&self, finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
            self.finalizes.borrow_mut().push(finalize.clone());
            Ok(())
        }
        fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.heartbeats.borrow_mut().push(batch.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct ThreadRecordingTransport {
        chunks: AtomicUsize,
        finalizes: AtomicUsize,
        v1_sends: AtomicUsize,
        blocking_chunk: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    }

    impl CloudSessionTransport for ThreadRecordingTransport {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }

        fn revalidate_grant_bounded(
            &self,
            grant: &CloudSessionGrant,
            _timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            Ok(backend_grant(
                grant,
                "enabled",
                grant
                    .backend_binding
                    .as_ref()
                    .map_or(1, |binding| binding.grant_version),
            ))
        }

        fn send_scan_chunk(&self, _chunk: &CloudSessionObservationChunkV2) -> Result<()> {
            self.chunks.fetch_add(1, Ordering::SeqCst);
            let barrier = self.blocking_chunk.lock().unwrap().take();
            if let Some((entered, release)) = barrier {
                entered.wait();
                release.wait();
            }
            Ok(())
        }

        fn finalize_scan(&self, _finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
            self.finalizes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.v1_sends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    enum TestPage {
        Json(String),
        Error,
    }
    struct CursorRecordingPages {
        pages: RefCell<VecDeque<TestPage>>,
        cursors: RefCell<Vec<Option<String>>>,
    }
    impl CursorRecordingPages {
        fn new(pages: Vec<String>) -> Self {
            Self {
                pages: RefCell::new(pages.into_iter().map(TestPage::Json).collect()),
                cursors: RefCell::new(Vec::new()),
            }
        }
    }
    impl CloudSessionRunner for CursorRecordingPages {
        fn list_page(&self, cursor: Option<&str>, _limit: usize) -> Result<String> {
            self.cursors.borrow_mut().push(cursor.map(str::to_string));
            match self.pages.borrow_mut().pop_front() {
                Some(TestPage::Json(page)) => Ok(page),
                Some(TestPage::Error) => Err(anyhow!("provider timeout")),
                None => Err(anyhow!("unexpected provider page")),
            }
        }
    }

    fn full_page(start: usize, cursor: Option<&str>) -> String {
        let tasks = (start..start + PAGE_LIMIT)
            .map(|index| {
                json!({
                    "id": format!("provider-{index:04}"),
                    "url": format!("https://chatgpt.com/codex/tasks/task-{index:04}"),
                    "title": format!("private task {index:04}"),
                    "status": "pending",
                    "updated_at": "2026-07-21T11:00:00Z",
                    "environment_id": "env-private",
                    "environment_label": "Private environment",
                    "summary": "private summary",
                    "is_review": false,
                    "attempt_total": 1
                })
            })
            .collect::<Vec<_>>();
        json!({"tasks": tasks, "cursor": cursor}).to_string()
    }

    fn run_full_scan_cycles(
        grants: &CloudSessionGrantStore,
        checkpoints: &CloudSessionCheckpointStore,
        runner: &dyn CloudSessionRunner,
        transport: &dyn CloudSessionTransport,
        start: OffsetDateTime,
    ) -> CloudSessionCycleOutcome {
        let mut outcome = CloudSessionCycleOutcome::Noop;
        for cycle in 0..10 {
            outcome = collect_cloud_sessions_once(
                grants,
                checkpoints,
                runner,
                transport,
                start + TimeDuration::minutes((cycle * 5) as i64),
            );
        }
        outcome
    }
    fn page(id: &str, cursor: Option<&str>) -> String {
        json!({"tasks":[{"id":id,"url":"https://chatgpt.com/codex/tasks/private","title":"private title","status":"applied","updated_at":"2026-07-21T11:00:00Z","environment_id":"provider-environment-private","environment_label":"Private environment","summary":"private summary","is_review":false,"attempt_total":2}], "cursor": cursor}).to_string()
    }

    fn exact_scan_ack(request: &str) -> String {
        let body: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        if request.contains("/chunks HTTP/1.1") {
            json!({
                "schema_version": "cloud_session_scan_chunk_ack.v1",
                "accepted": true,
                "scan_id": body["scan_id"],
                "chunk_index": body["chunk_index"],
                "chunk_identity_digest": body["chunk_identity_digest"],
                "chunk_semantic_digest": body["chunk_semantic_digest"],
            })
            .to_string()
        } else {
            json!({
                "schema_version": "cloud_session_scan_finalize_ack.v1",
                "accepted": true,
                "scan_id": body["scan_id"],
                "chunk_count": body["chunk_count"],
                "unique_entity_count": body["unique_entity_count"],
                "inventory_digest": body["inventory_digest"],
                "epoch_digest": body["epoch_digest"],
            })
            .to_string()
        }
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        use std::io::Read;

        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        while let Ok(read) = stream.read(&mut buffer) {
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|offset| offset + 4)
            {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                });
                if request.len() >= header_end + content_length.unwrap_or(0) {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&request).to_string()
    }

    #[test]
    fn emitted_wire_is_content_free_and_opaque() {
        let parsed = parse_cloud_page(
            &page("provider-task-123", Some("private-cursor")),
            b"fixture-key",
            now(),
        )
        .unwrap();
        let encoded = serde_json::to_string(&parsed.entities).unwrap();
        assert!(!encoded.contains("provider-task-123"));
        assert!(!encoded.contains("private title"));
        assert!(!encoded.contains("example.invalid"));
        assert!(!encoded.contains("private-cursor"));
        assert!(!encoded.contains("provider-account-private"));
        assert!(encoded.contains("hmac-sha256:"));
    }

    #[test]
    fn official_cloud_task_statuses_and_attempt_total_are_normalized_truthfully() {
        let raw = json!({
            "tasks": [
                {
                    "id": "official-pending",
                    "url": "https://chatgpt.com/codex/tasks/pending",
                    "title": "private pending title",
                    "status": "pending",
                    "updated_at": "2026-07-21T11:00:00Z",
                    "environment_id": "env-private",
                    "environment_label": "Private environment",
                    "summary": "private summary",
                    "is_review": false,
                    "attempt_total": 3
                },
                {
                    "id": "official-ready",
                    "url": "https://chatgpt.com/codex/tasks/ready",
                    "title": "private ready title",
                    "status": "ready",
                    "updated_at": "2026-07-21T11:00:00Z",
                    "environment_id": "env-private",
                    "environment_label": "Private environment",
                    "summary": "private summary",
                    "is_review": true,
                    "attempt_total": 4
                },
                {
                    "id": "official-applied",
                    "url": "https://chatgpt.com/codex/tasks/applied",
                    "title": "private applied title",
                    "status": "applied",
                    "updated_at": "2026-07-21T11:00:00Z",
                    "environment_id": "env-private",
                    "environment_label": "Private environment",
                    "summary": "private summary",
                    "is_review": false,
                    "attempt_total": 5
                },
                {
                    "id": "official-error",
                    "url": "https://chatgpt.com/codex/tasks/error",
                    "title": "private error title",
                    "status": "error",
                    "updated_at": "2026-07-21T11:00:00Z",
                    "environment_id": "env-private",
                    "environment_label": "Private environment",
                    "summary": "private summary",
                    "is_review": false,
                    "attempt_total": 6
                }
            ],
            "cursor": null
        })
        .to_string();
        let parsed = parse_cloud_page(&raw, b"fixture-key", now()).unwrap();
        assert_eq!(
            parsed
                .entities
                .iter()
                .map(|row| row.lifecycle.as_str())
                .collect::<Vec<_>>(),
            ["unknown", "completed", "completed", "failed"]
        );
        assert_eq!(
            parsed
                .entities
                .iter()
                .map(|row| row.attempt_count)
                .collect::<Vec<_>>(),
            [Some(3), Some(4), Some(5), Some(6)]
        );
        let encoded = serde_json::to_string(&parsed.entities).unwrap();
        for secret in [
            "official-pending",
            "chatgpt.com",
            "private pending title",
            "env-private",
            "Private environment",
            "private summary",
        ] {
            assert!(!encoded.contains(secret));
        }
    }

    #[test]
    fn cursor_contract_separates_official_terminal_pagination_and_ambiguity() {
        let official_next = parse_cloud_page(
            &json!({"tasks": [], "cursor": "official-next-page"}).to_string(),
            b"fixture-key",
            now(),
        )
        .unwrap();
        assert_eq!(
            official_next.cursor,
            CloudPageCursor::Next("official-next-page".to_string())
        );
        let official_terminal = parse_cloud_page(
            &json!({"tasks": [], "cursor": null}).to_string(),
            b"fixture-key",
            now(),
        )
        .unwrap();
        assert_eq!(official_terminal.cursor, CloudPageCursor::OfficialTerminal);
        let alias_next = parse_cloud_page(
            &json!({
                "tasks": [{"id": "legacy-next", "status": "running"}],
                "next_cursor": "legacy-next-page"
            })
            .to_string(),
            b"fixture-key",
            now(),
        )
        .unwrap();
        assert_eq!(
            alias_next.cursor,
            CloudPageCursor::Next("legacy-next-page".to_string())
        );

        for ambiguous in [
            json!({"tasks": [{"id": "fieldless", "status": "running"}]}),
            json!({
                "tasks": [{"id": "alias-null", "status": "running"}],
                "next_cursor": null
            }),
            json!([{"id": "array-root", "status": "running"}]),
        ] {
            assert_eq!(
                parse_cloud_page(&ambiguous.to_string(), b"fixture-key", now())
                    .unwrap()
                    .cursor,
                CloudPageCursor::Ambiguous
            );
        }

        for conflicting in [
            json!({"tasks": [], "cursor": "official", "next_cursor": "legacy"}),
            json!({"tasks": [], "cursor": "official", "nextCursor": null}),
            json!({"tasks": [], "next_cursor": null, "nextCursor": "legacy"}),
        ] {
            assert!(parse_cloud_page(&conflicting.to_string(), b"fixture-key", now()).is_err());
        }
        assert!(parse_cloud_page(
            &json!({
                "tasks": [],
                "cursor": "same",
                "next_cursor": "same",
                "nextCursor": "same"
            })
            .to_string(),
            b"fixture-key",
            now(),
        )
        .is_ok());
    }

    #[test]
    fn empty_ambiguous_pages_are_rejected_without_absence_authority() {
        for ambiguous in [
            json!({"tasks": []}),
            json!({"tasks": [], "next_cursor": null}),
            json!([]),
        ] {
            assert!(parse_cloud_page(&ambiguous.to_string(), b"fixture-key", now()).is_err());
        }
    }

    #[test]
    fn v2_public_wire_rejects_raw_or_noncanonical_entity_keys_and_open_values() {
        let (grants, checkpoints) = stores("v2-crafted-privacy-boundary");
        enabled(&grants);
        let runner = CursorRecordingPages::new(vec![page("raw-provider-id", None)]);
        let transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let chunk = transport.chunks.borrow()[0].clone();
        assert!(chunk.validate_wire_contract().is_ok());

        let mut raw_key = chunk.clone();
        raw_key.observations[0].entity_key = "raw-provider-id".to_string();
        assert!(raw_key.validate_wire_contract().is_err());

        let mut uppercase_key = chunk.clone();
        uppercase_key.observations[0].entity_key = format!("hmac-sha256:{}", "A".repeat(64));
        assert!(uppercase_key.validate_wire_contract().is_err());

        let mut wrong_identity = chunk.clone();
        wrong_identity.chunk_identity_digest = format!("sha256:{}", "0".repeat(64));
        assert!(wrong_identity.validate_wire_contract().is_err());

        let mut wrong_semantics = chunk.clone();
        wrong_semantics.chunk_semantic_digest = format!("sha256:{}", "0".repeat(64));
        assert!(wrong_semantics.validate_wire_contract().is_err());

        let mut open_lifecycle = chunk;
        open_lifecycle.observations[0].lifecycle = "provider_future_state".to_string();
        assert!(open_lifecycle.validate_wire_contract().is_err());

        let chunks = transport.chunks.borrow().clone();
        let finalize = transport.finalizes.borrow()[0].clone();
        assert!(finalize.validate_against_chunks(&chunks).is_ok());
        let mut wrong_inventory = finalize.clone();
        wrong_inventory.inventory_digest = format!("sha256:{}", "0".repeat(64));
        assert!(wrong_inventory.validate_against_chunks(&chunks).is_err());
        let mut wrong_epoch = finalize;
        wrong_epoch.epoch_digest = format!("sha256:{}", "0".repeat(64));
        assert!(wrong_epoch.validate_against_chunks(&chunks).is_err());
    }

    #[test]
    fn provider_values_outside_backend_bounds_are_dropped_not_uploaded() {
        let raw = json!({
            "tasks": [{
                "id": "provider-task-unsafe-bounds",
                "status": "running",
                "created_at": "2026-07-21T11:30:00Z",
                "started_at": "2026-07-21T11:00:00Z",
                "updated_at": "2026-07-21T12:30:00Z",
                "attempt_total": 100_001,
                "environment": "production"
            }]
        })
        .to_string();
        let parsed = parse_cloud_page(&raw, b"fixture-key", now()).unwrap();
        let row = &parsed.entities[0];
        assert_eq!(row.environment_kind, "unknown");
        assert_eq!(row.attempt_count, None);
        assert_eq!(row.created_at, None);
        assert_eq!(row.started_at, None);
        assert_eq!(row.updated_at, None);
        assert!(!row.coverage.contains(&"timing".to_string()));
        assert!(!row.coverage.contains(&"attempts".to_string()));
    }

    #[test]
    fn persisted_grant_discards_raw_scope_and_uses_private_atomic_state() {
        let (grants, _checkpoints) = stores("private-grant-state");
        enabled(&grants);

        let encoded = String::from_utf8(fs::read(grants.path()).unwrap()).unwrap();
        assert!(!encoded.contains(INSTALLATION_ID));
        assert!(!encoded.contains("org_fixture"));
        assert!(!encoded.contains("user_fixture"));
        assert!(encoded.contains("installation_fingerprint"));
        assert!(encoded.contains("grant_scope_id"));

        let parent = grants.path().parent().unwrap();
        assert!(fs::read_dir(parent).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(parent).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(grants.path()).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(grants.path().with_extension("lock"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn legacy_v1_grant_is_privately_migrated_and_remains_revocable() {
        let (grants, _checkpoints) = stores("legacy-grant-migration");
        let legacy = json!({
            "schema_version": GRANT_SCHEMA_VERSION,
            "hmac_key_hex": "11".repeat(32),
            "grant": {
                "schema_version": GRANT_SCHEMA_VERSION,
                "collector_id": COLLECTOR_ID,
                "collector_version": COLLECTOR_VERSION,
                "release_lane": "supported",
                "disclosure_version": "cloud_sessions_disclosure.v1",
                "status": CloudSessionGrantStatus::Enabled,
                "installation_id": "legacy-installation-raw",
                "organization_fingerprint": "hmac-sha256:legacy-org",
                "effective_user_fingerprint": "hmac-sha256:legacy-user",
                "account_fingerprint": "hmac-sha256:legacy-account",
                "granted_at": "2026-07-20T12:00:00Z",
                "paused_at": null,
                "revoked_at": null,
                "last_collector_health": "enabled",
                "last_freshness": "unavailable",
                "last_error_category": null
            }
        });
        fs::write(grants.path(), serde_json::to_vec(&legacy).unwrap()).unwrap();

        let migrated = grants.load().unwrap().unwrap();
        assert_eq!(migrated.status, CloudSessionGrantStatus::Enabled);
        assert!(migrated.backend_binding.is_none());
        assert!(migrated
            .installation_fingerprint
            .starts_with("hmac-sha256:"));
        assert!(migrated.grant_scope_id.starts_with("hmac-sha256:"));
        let encoded = String::from_utf8(fs::read(grants.path()).unwrap()).unwrap();
        assert!(!encoded.contains("legacy-installation-raw"));
        assert!(!encoded.contains("installation_id"));

        grants.pause(now()).unwrap();
        assert_eq!(
            grants.load().unwrap().unwrap().status,
            CloudSessionGrantStatus::Paused
        );
        grants.revoke(now()).unwrap();
        assert_eq!(
            grants.load().unwrap().unwrap().status,
            CloudSessionGrantStatus::Revoked
        );
    }

    #[test]
    fn repeated_semantics_are_a_transport_noop() {
        let (grants, checkpoints) = stores("noop");
        enabled(&grants);
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        let first = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &first, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let second = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &second, &transport, now()),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(transport.calls.get(), 1);
        let encoded = serde_json::to_string(&transport.batches.borrow()[0]).unwrap();
        assert!(!encoded.contains(INSTALLATION_ID));
        assert!(!encoded.contains("org_fixture"));
        assert!(!encoded.contains("user_fixture"));
        assert!(encoded.contains("grant_scope_fingerprint"));
        assert!(!encoded.contains("semantic_digest"));
        assert!(!encoded.contains("grant_scope_id"));
        assert!(!encoded.contains("execution_location"));
        let wire: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(wire["grant_id"], GRANT_ID);
        assert_eq!(wire["grant_version"], 1);
        assert_eq!(wire["batch_kind"], "snapshot");
        assert_eq!(wire["snapshot_complete"], true);
        assert_eq!(wire["observations"][0]["entity_kind"], "task");
        assert_eq!(wire["observations"][0]["observed_at"], timestamp(now()));
        assert_eq!(wire["health"]["state"], "healthy");
        assert!(wire.get("entities").is_none());
        assert!(wire.get("observed_at").is_none());
    }

    #[test]
    fn strict_batch_schema_rejects_invalid_heartbeat_and_unknown_fields() {
        let (grants, _checkpoints) = stores("strict-batch-wire");
        enabled(&grants);
        let grant = grants.load().unwrap().unwrap();
        let observations = parse_cloud_page(&page("one", None), b"fixture-key", now())
            .unwrap()
            .entities;
        let snapshot = snapshot_batch(&grant, observations, now(), true).unwrap();
        let snapshot_value = serde_json::to_value(&snapshot).unwrap();
        let decoded: CloudSessionObservationBatchV1 =
            serde_json::from_value(snapshot_value.clone()).unwrap();
        assert_eq!(decoded.batch_kind, CloudSessionBatchKind::Snapshot);
        assert!(decoded.snapshot_complete);

        let mut heartbeat_with_rows = snapshot_value.clone();
        heartbeat_with_rows["batch_kind"] = json!("heartbeat");
        heartbeat_with_rows["snapshot_complete"] = json!(false);
        assert!(
            serde_json::from_value::<CloudSessionObservationBatchV1>(heartbeat_with_rows).is_err()
        );

        let mut complete_heartbeat = serde_json::to_value(
            heartbeat_batch(
                &grant,
                now(),
                CloudSessionCollectorHealthV1 {
                    state: "healthy".to_string(),
                    observed_at: timestamp(now()),
                    error_category: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        complete_heartbeat["snapshot_complete"] = json!(true);
        assert!(
            serde_json::from_value::<CloudSessionObservationBatchV1>(complete_heartbeat).is_err()
        );

        let mut unknown_kind = snapshot_value.clone();
        unknown_kind["batch_kind"] = json!("delta");
        assert!(serde_json::from_value::<CloudSessionObservationBatchV1>(unknown_kind).is_err());

        let mut unknown_field = snapshot_value;
        unknown_field["provider_cursor"] = json!("must-not-cross-wire");
        assert!(serde_json::from_value::<CloudSessionObservationBatchV1>(unknown_field).is_err());
    }

    #[test]
    fn empty_terminal_enumeration_is_an_authoritative_complete_snapshot() {
        let (grants, checkpoints) = stores("empty-complete-snapshot");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![json!({"tasks": [], "cursor": null}).to_string()]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };

        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let batches = transport.batches.borrow();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].batch_kind, CloudSessionBatchKind::Snapshot);
        assert!(batches[0].snapshot_complete);
        assert!(batches[0].observations.is_empty());
        assert_eq!(
            checkpoints.load().last_complete_snapshot_at.as_deref(),
            Some("2026-07-21T12:00:00Z")
        );
    }

    #[test]
    fn backend_binding_requires_exact_scope_and_monotonic_reconsent_epoch() {
        let (grants, checkpoints) = stores("grant-epoch");
        let setup = CloudSessionGrantSetup {
            installation_id: INSTALLATION_ID.to_string(),
            organization_scope: "org_fixture".to_string(),
            effective_user_scope: "user_fixture".to_string(),
        };
        let local = grants.enable(&setup, now()).unwrap();
        assert_eq!(local.status, CloudSessionGrantStatus::ConsentRequired);
        assert_eq!(local.granted_at, None);
        assert!(grants
            .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
            .is_err());
        let request = grants.grant_create_request(INSTALLATION_ID).unwrap();
        assert_eq!(request.grant_scope_fingerprint, local.grant_scope_id);
        assert_eq!(
            grants.grant_create_request(INSTALLATION_ID).unwrap(),
            request
        );
        assert!(grants
            .grant_create_request("00000000-0000-4000-8000-000000000099")
            .is_err());
        let mut wrong_installation = backend_grant(&local, "enabled", 1);
        wrong_installation.installation_id = "00000000-0000-4000-8000-000000000099".to_string();
        assert!(grants
            .bind_backend_grant(&wrong_installation, "00000000-0000-4000-8000-000000000099",)
            .is_err());

        let first_response = backend_grant(&local, "enabled", 1);
        let first_bound = grants
            .bind_backend_grant(&first_response, INSTALLATION_ID)
            .unwrap();
        let bound_bytes = fs::read(grants.path()).unwrap();
        assert_eq!(
            grants
                .bind_backend_grant(&first_response, INSTALLATION_ID)
                .unwrap(),
            first_bound
        );
        assert_eq!(fs::read(grants.path()).unwrap(), bound_bytes);
        let mut different_id = first_response.clone();
        different_id.id = "00000000-0000-4000-8000-000000000099".to_string();
        assert!(grants
            .bind_backend_grant(&different_id, INSTALLATION_ID)
            .is_err());
        let mut different_epoch = first_response.clone();
        different_epoch.grant_version += 1;
        assert!(grants
            .bind_backend_grant(&different_epoch, INSTALLATION_ID)
            .is_err());
        let mut different_policy = first_response;
        different_policy.server_policy_state = CloudSessionServerPolicyState::Disabled;
        assert!(grants
            .bind_backend_grant(&different_policy, INSTALLATION_ID)
            .is_err());
        let first_runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &first_runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        grants.revoke(now()).unwrap();
        grants
            .apply_backend_revocation(&backend_grant(&local, "revoked", 2), INSTALLATION_ID)
            .unwrap();
        let pending = grants
            .enable(&setup, now() + TimeDuration::minutes(1))
            .unwrap();
        assert_eq!(pending.status, CloudSessionGrantStatus::ConsentRequired);
        grants.grant_create_request(INSTALLATION_ID).unwrap();
        assert!(grants
            .bind_backend_grant(&backend_grant(&local, "enabled", 2), INSTALLATION_ID)
            .is_err());
        grants
            .bind_backend_grant(&backend_grant(&local, "enabled", 3), INSTALLATION_ID)
            .unwrap();

        let runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let noop_runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &noop_runner, &transport, now()),
            CloudSessionCycleOutcome::Noop
        );
        let batches = transport.batches.borrow();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].grant_version, 1);
        assert_eq!(batches[1].grant_version, 3);
        assert_eq!(batches[1].observations.len(), 1);
    }

    #[test]
    fn backend_policy_response_is_strict_and_persisted_bindings_fail_closed() {
        let (grants, _checkpoints) = stores("strict-server-policy");
        let local = grants
            .enable(
                &CloudSessionGrantSetup {
                    installation_id: INSTALLATION_ID.to_string(),
                    organization_scope: "org_fixture".to_string(),
                    effective_user_scope: "user_fixture".to_string(),
                },
                now(),
            )
            .unwrap();
        let response = serde_json::to_value(backend_grant(&local, "enabled", 1)).unwrap();
        let mut missing = response.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("server_policy_state");
        assert!(serde_json::from_value::<CloudSessionBackendGrantResponseV1>(missing).is_err());
        let mut unknown = response;
        unknown["server_policy_state"] = Value::String("future_state".to_string());
        assert!(serde_json::from_value::<CloudSessionBackendGrantResponseV1>(unknown).is_err());

        let binding: CloudSessionBackendGrantBindingV1 = serde_json::from_value(json!({
            "grant_id": GRANT_ID,
            "grant_version": 1,
            "backend_revoked": false
        }))
        .unwrap();
        assert_eq!(
            binding.server_policy_state,
            CloudSessionServerPolicyState::Disabled
        );
    }

    #[test]
    fn server_policy_transitions_gate_every_provider_cycle() {
        let (grants, checkpoints) = stores("server-policy-transition");
        enabled(&grants);
        let current = grants.load().unwrap().unwrap();
        let mut disabled_response = backend_grant(&current, "enabled", 1);
        disabled_response.server_policy_state = CloudSessionServerPolicyState::Disabled;
        let disabled_transport = RevalidationTransport {
            response: Some(disabled_response),
            revalidation_calls: Cell::new(0),
            send_calls: Cell::new(0),
        };
        let disabled_runner = Pages {
            pages: RefCell::new(vec![page("must-not-run", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &disabled_runner,
                &disabled_transport,
                now(),
            ),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(disabled_transport.revalidation_calls.get(), 1);
        assert_eq!(disabled_runner.calls.get(), 0);
        assert_eq!(disabled_transport.send_calls.get(), 0);
        assert_eq!(
            grants.load().unwrap().unwrap().status,
            CloudSessionGrantStatus::PolicyDisabled
        );

        let disabled = grants.load().unwrap().unwrap();
        let approved_transport = RevalidationTransport {
            response: Some(backend_grant(&disabled, "enabled", 1)),
            revalidation_calls: Cell::new(0),
            send_calls: Cell::new(0),
        };
        let approved_runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &approved_runner,
                &approved_transport,
                now() + TimeDuration::minutes(5),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        // One grant revalidation gates the provider page, one gates the chunk,
        // and one gates finalization.
        assert_eq!(approved_transport.revalidation_calls.get(), 3);
        assert_eq!(approved_runner.calls.get(), 1);
        assert_eq!(approved_transport.send_calls.get(), 1);
        assert_eq!(
            grants.load().unwrap().unwrap().status,
            CloudSessionGrantStatus::Enabled
        );
    }

    #[test]
    fn failed_server_revalidation_stops_provider_before_invocation() {
        let (grants, checkpoints) = stores("server-policy-network-fail");
        enabled(&grants);
        let transport = RevalidationTransport {
            response: None,
            revalidation_calls: Cell::new(0),
            send_calls: Cell::new(0),
        };
        let runner = Pages {
            pages: RefCell::new(vec![page("must-not-run", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(transport.revalidation_calls.get(), 1);
        assert_eq!(runner.calls.get(), 0);
        assert_eq!(transport.send_calls.get(), 0);
        assert_eq!(
            checkpoints.load().last_error_category.as_deref(),
            Some("grant_revalidation_unavailable")
        );
    }

    #[test]
    fn future_authority_epoch_fails_closed_without_changing_local_binding() {
        let (grants, checkpoints) = stores("future-authority-epoch");
        enabled(&grants);
        let current = grants.load().unwrap().unwrap();
        let persisted_before = fs::read(grants.path()).unwrap();
        let future = backend_grant(&current, "enabled", 2);
        assert!(grants.apply_backend_grant_revalidation(&future).is_err());
        assert_eq!(fs::read(grants.path()).unwrap(), persisted_before);

        let transport = RevalidationTransport {
            response: Some(future),
            revalidation_calls: Cell::new(0),
            send_calls: Cell::new(0),
        };
        let runner = Pages {
            pages: RefCell::new(vec![page("must-not-run", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(transport.revalidation_calls.get(), 1);
        assert_eq!(runner.calls.get(), 0);
        assert_eq!(transport.send_calls.get(), 0);
        let unchanged = grants.load().unwrap().unwrap();
        assert_eq!(unchanged.status, CloudSessionGrantStatus::Enabled);
        assert_eq!(unchanged.backend_binding, current.backend_binding);
        assert_eq!(
            checkpoints.load().last_error_category.as_deref(),
            Some("grant_revalidation_invalid")
        );
    }

    #[test]
    fn runtime_authority_identity_covers_device_tenant_scope_and_epoch() {
        let (grants, _checkpoints) = stores("runtime-authority-identity");
        enabled(&grants);
        let expected = grants.load().unwrap().unwrap();
        assert!(same_runtime_grant_identity(&expected, &expected));

        for changed in [
            |grant: &mut CloudSessionGrant| {
                grant.installation_fingerprint = format!("hmac-sha256:{}", "1".repeat(64));
            },
            |grant: &mut CloudSessionGrant| {
                grant.organization_fingerprint = format!("hmac-sha256:{}", "2".repeat(64));
            },
            |grant: &mut CloudSessionGrant| {
                grant.effective_user_fingerprint = format!("hmac-sha256:{}", "3".repeat(64));
            },
            |grant: &mut CloudSessionGrant| {
                grant.grant_scope_id = format!("hmac-sha256:{}", "4".repeat(64));
            },
            |grant: &mut CloudSessionGrant| {
                grant.account_fingerprint = format!("hmac-sha256:{}", "5".repeat(64));
            },
            |grant: &mut CloudSessionGrant| {
                grant.backend_binding.as_mut().unwrap().grant_version += 1;
            },
        ] {
            let mut mismatched = expected.clone();
            changed(&mut mismatched);
            assert!(!same_runtime_grant_identity(&mismatched, &expected));
        }

        let mut policy_transition = expected.clone();
        policy_transition
            .backend_binding
            .as_mut()
            .unwrap()
            .server_policy_state = CloudSessionServerPolicyState::Disabled;
        assert!(same_runtime_grant_identity(&policy_transition, &expected));
    }

    #[test]
    fn revalidation_denial_never_checkpoints_unsent_heartbeat_or_failure_health() {
        let (heartbeat_grants, heartbeat_checkpoints) = stores("denied-heartbeat-checkpoint");
        enabled(&heartbeat_grants);
        let initial_transport = V2RecordingTransport::new();
        let initial_runner = CursorRecordingPages::new(vec![page("stable", None)]);
        assert_eq!(
            collect_cloud_sessions_once(
                &heartbeat_grants,
                &heartbeat_checkpoints,
                &initial_runner,
                &initial_transport,
                now(),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        let original_health_upload = heartbeat_checkpoints.load().last_health_upload_at;
        let heartbeat_transport = SequencedStatusTransport {
            statuses: RefCell::new(VecDeque::from(["enabled", "revoked"])),
            revalidation_calls: Cell::new(0),
            send_calls: Cell::new(0),
        };
        let heartbeat_runner = CursorRecordingPages::new(vec![page("stable", None)]);
        assert_eq!(
            collect_cloud_sessions_once(
                &heartbeat_grants,
                &heartbeat_checkpoints,
                &heartbeat_runner,
                &heartbeat_transport,
                now() + TimeDuration::minutes(61),
            ),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(heartbeat_transport.revalidation_calls.get(), 2);
        assert_eq!(heartbeat_transport.send_calls.get(), 0);
        assert_eq!(
            heartbeat_checkpoints.load().last_health_upload_at,
            original_health_upload
        );

        let (failure_grants, failure_checkpoints) = stores("denied-failure-checkpoint");
        enabled(&failure_grants);
        let failure_transport = SequencedStatusTransport {
            statuses: RefCell::new(VecDeque::from(["enabled", "revoked"])),
            revalidation_calls: Cell::new(0),
            send_calls: Cell::new(0),
        };
        let failure_runner = FailingPages {
            calls: Cell::new(0),
        };
        assert_eq!(
            collect_cloud_sessions_once(
                &failure_grants,
                &failure_checkpoints,
                &failure_runner,
                &failure_transport,
                now(),
            ),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(failure_transport.revalidation_calls.get(), 2);
        assert_eq!(failure_transport.send_calls.get(), 0);
        assert_eq!(failure_checkpoints.load().last_health_upload_at, None);
    }

    #[test]
    fn cycle_budget_defers_prepared_upload_and_does_not_hold_runtime_mutex_during_io() {
        let (grants, checkpoints) = stores("bounded-slow-upload");
        enabled(&grants);
        let runner = CursorRecordingPages::new(vec![page("budgeted", None)]);
        let seed_transport = V2RecordingTransport::new();
        seed_transport.fail_next_chunk.set(true);
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &seed_transport, now(),),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(seed_transport.chunks.borrow().len(), 1);

        let slow_transport = SlowBudgetTransport {
            checkpoints: &checkpoints,
            revalidation_calls: Cell::new(0),
            send_calls: Cell::new(0),
            timeouts: RefCell::new(Vec::new()),
            mutex_was_available: Cell::new(true),
        };
        let unused_runner = CursorRecordingPages::new(Vec::new());
        let started = Instant::now();
        assert_eq!(
            collect_cloud_sessions_once_with_budget(
                &grants,
                &checkpoints,
                &unused_runner,
                &slow_transport,
                now() + TimeDuration::minutes(3),
                Duration::from_millis(40),
            ),
            CloudSessionCycleOutcome::Noop
        );
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(slow_transport.mutex_was_available.get());
        assert_eq!(slow_transport.revalidation_calls.get(), 1);
        assert_eq!(slow_transport.send_calls.get(), 0);
        let timeouts = slow_transport.timeouts.borrow();
        assert_eq!(timeouts.len(), 1);
        assert!(timeouts[0] <= Duration::from_millis(40));
        drop(timeouts);
        {
            let runtime = checkpoints.runtime.lock().unwrap();
            let prepared = runtime
                .active
                .as_ref()
                .and_then(|scan| scan.prepared.as_ref())
                .expect("prepared scan must survive budget exhaustion");
            assert_eq!(prepared.next_chunk, 0);
            assert_eq!(prepared.chunks.len(), 1);
            assert!(prepared.finalize.is_some());
        }
        assert_eq!(checkpoints.load().consecutive_failures, 1);
        assert!(unused_runner.cursors.borrow().is_empty());

        let resumed_transport = V2RecordingTransport::new();
        let resumed_runner = CursorRecordingPages::new(Vec::new());
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &resumed_runner,
                &resumed_transport,
                now() + TimeDuration::minutes(6),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        assert!(resumed_runner.cursors.borrow().is_empty());
        assert_eq!(resumed_transport.chunks.borrow().len(), 1);
        assert_eq!(resumed_transport.finalizes.borrow().len(), 1);
        assert_eq!(resumed_transport.revalidation_calls.get(), 2);
    }

    #[test]
    fn bounded_revalidation_never_falls_back_to_an_unbounded_override() {
        struct UnboundedOnlyTransport {
            calls: Cell<usize>,
        }
        impl CloudSessionTransport for UnboundedOnlyTransport {
            fn supports_grant_revalidation(&self) -> bool {
                true
            }
            fn revalidate_grant(
                &self,
                grant: &CloudSessionGrant,
            ) -> Result<CloudSessionBackendGrantResponseV1> {
                self.calls.set(self.calls.get() + 1);
                Ok(backend_grant(grant, "enabled", 1))
            }
            fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
                Ok(())
            }
        }

        let (grants, checkpoints) = stores("bounded-revalidation-fail-closed");
        enabled(&grants);
        let runner = CursorRecordingPages::new(vec![page("must-not-run", None)]);
        let transport = UnboundedOnlyTransport {
            calls: Cell::new(0),
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(transport.calls.get(), 0);
        assert!(runner.cursors.borrow().is_empty());
        assert_eq!(
            checkpoints.load().last_error_category.as_deref(),
            Some("grant_revalidation_unavailable")
        );
    }

    #[test]
    fn future_server_revocation_epoch_stops_provider_without_adopting_epoch() {
        let (grants, checkpoints) = stores("server-revocation");
        enabled(&grants);
        let current = grants.load().unwrap().unwrap();
        let transport = RevalidationTransport {
            response: Some(backend_grant(&current, "revoked", 2)),
            revalidation_calls: Cell::new(0),
            send_calls: Cell::new(0),
        };
        let runner = Pages {
            pages: RefCell::new(vec![page("must-not-run", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(transport.revalidation_calls.get(), 1);
        assert_eq!(runner.calls.get(), 0);
        assert_eq!(transport.send_calls.get(), 0);
        assert_eq!(
            grants.load().unwrap().unwrap().status,
            CloudSessionGrantStatus::Enabled
        );
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &runner,
                &transport,
                now() + TimeDuration::minutes(5),
            ),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(transport.revalidation_calls.get(), 2);
        assert_eq!(runner.calls.get(), 0);
    }

    #[test]
    fn local_revoke_wins_over_in_flight_backend_grant_response() {
        let (grants, _checkpoints) = stores("bind-revoke-race");
        let setup = CloudSessionGrantSetup {
            installation_id: INSTALLATION_ID.to_string(),
            organization_scope: "org_fixture".to_string(),
            effective_user_scope: "user_fixture".to_string(),
        };
        let local = grants.enable(&setup, now()).unwrap();
        grants.grant_create_request(INSTALLATION_ID).unwrap();
        let response = backend_grant(&local, "enabled", 1);
        grants.revoke(now()).unwrap();
        assert!(grants.enable(&setup, now()).is_err());
        let replacement = CloudSessionGrantSetup {
            installation_id: INSTALLATION_ID.to_string(),
            organization_scope: "replacement_org".to_string(),
            effective_user_scope: "replacement_user".to_string(),
        };
        assert!(grants.enable(&replacement, now()).is_err());
        assert_eq!(
            grants
                .bind_backend_grant(&response, INSTALLATION_ID)
                .unwrap()
                .status,
            CloudSessionGrantStatus::Revoked
        );
        let mut different = response;
        different.id = "00000000-0000-4000-8000-000000000099".to_string();
        assert!(grants
            .bind_backend_grant(&different, INSTALLATION_ID)
            .is_err());
        let stopped = grants.load().unwrap().unwrap();
        assert_eq!(stopped.status, CloudSessionGrantStatus::Revoked);
        assert!(!stopped.backend_create_pending);
        assert_eq!(stopped.backend_binding.as_ref().unwrap().grant_id, GRANT_ID);
        assert_eq!(grants.grant_revoke_target().unwrap().grant_id, GRANT_ID);
    }

    #[test]
    fn ambiguous_backend_create_retries_exact_request_until_late_grant_is_deleted() {
        let (grants, _checkpoints) = stores("bind-create-reconcile");
        let setup = CloudSessionGrantSetup {
            installation_id: INSTALLATION_ID.to_string(),
            organization_scope: "org_fixture".to_string(),
            effective_user_scope: "user_fixture".to_string(),
        };
        let local = grants.enable(&setup, now()).unwrap();
        let first = grants.grant_create_request(INSTALLATION_ID).unwrap();
        let restarted = CloudSessionGrantStore::new(grants.path().to_path_buf());
        assert_eq!(
            restarted.grant_create_request(INSTALLATION_ID).unwrap(),
            first
        );
        restarted.revoke(now()).unwrap();

        let replacement = CloudSessionGrantSetup {
            installation_id: INSTALLATION_ID.to_string(),
            organization_scope: "replacement_org".to_string(),
            effective_user_scope: "replacement_user".to_string(),
        };
        assert!(restarted.enable(&replacement, now()).is_err());
        let pending = restarted.load().unwrap().unwrap();
        assert!(pending.backend_create_pending);
        assert!(pending.pending_backend_create.is_some());
        assert!(pending.backend_binding.is_none());
        assert_eq!(
            cloud_session_collector_status(&restarted, &DeferredCloudSessionTransport).reason_code,
            "backend_grant_reconciliation_required"
        );

        assert!(restarted
            .confirm_backend_grant_absent_after_reconciliation()
            .is_err());
        assert_eq!(
            restarted.grant_create_request(INSTALLATION_ID).unwrap(),
            first
        );
        assert_eq!(
            restarted
                .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
                .unwrap()
                .status,
            CloudSessionGrantStatus::Revoked
        );
        let late = restarted.load().unwrap().unwrap();
        assert_eq!(late.status, CloudSessionGrantStatus::Revoked);
        assert!(!late.backend_create_pending);
        assert!(late.pending_backend_create.is_none());
        assert_eq!(late.backend_binding.as_ref().unwrap().grant_id, GRANT_ID);
        restarted
            .apply_backend_revocation(&backend_grant(&late, "revoked", 2), INSTALLATION_ID)
            .unwrap();
        let prepared = restarted.enable(&replacement, now()).unwrap();
        assert_eq!(prepared.status, CloudSessionGrantStatus::ConsentRequired);
        assert!(!prepared.backend_create_pending);
        assert!(prepared.backend_binding.is_none());
    }

    #[test]
    fn scope_switch_cannot_orphan_bound_grant_before_exact_delete() {
        let (grants, checkpoints) = stores("scope-switch");
        enabled(&grants);
        let original = grants.load().unwrap().unwrap();
        grants.revoke(now()).unwrap();
        let replacement = CloudSessionGrantSetup {
            installation_id: INSTALLATION_ID.to_string(),
            organization_scope: "replacement_org".to_string(),
            effective_user_scope: "replacement_user".to_string(),
        };
        assert!(grants.enable(&replacement, now()).is_err());
        let retained = grants.load().unwrap().unwrap();
        assert_eq!(retained.status, CloudSessionGrantStatus::Revoked);
        assert_eq!(
            retained.backend_binding.as_ref().unwrap().grant_id,
            GRANT_ID
        );
        assert!(!retained.backend_binding.as_ref().unwrap().backend_revoked);
        assert_eq!(grants.grant_revoke_target().unwrap().grant_id, GRANT_ID);
        assert_eq!(
            cloud_session_collector_status(&grants, &DeferredCloudSessionTransport).reason_code,
            "backend_revocation_confirmation_required"
        );

        let runner = Pages {
            pages: RefCell::new(vec![page("must-not-run", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(runner.calls.get(), 0);
        assert_eq!(transport.calls.get(), 0);

        grants
            .apply_backend_revocation(&backend_grant(&original, "revoked", 2), INSTALLATION_ID)
            .unwrap();
        assert_eq!(
            cloud_session_collector_status(&grants, &DeferredCloudSessionTransport).reason_code,
            "revoked"
        );
        let prepared = grants.enable(&replacement, now()).unwrap();
        assert_eq!(prepared.status, CloudSessionGrantStatus::ConsentRequired);
        assert!(prepared.backend_binding.is_none());
        assert_ne!(prepared.grant_scope_id, original.grant_scope_id);
        assert_eq!(prepared.granted_at, None);
    }

    #[test]
    fn binary_upgrade_requires_new_backend_contract_epoch_before_collection() {
        let (grants, checkpoints) = stores("version-upgrade");
        enabled(&grants);
        let mut state = grants.read().unwrap().unwrap();
        state.grant.collector_version = "0.1.89".to_string();
        grants.write(&state).unwrap();

        let runner = Pages {
            pages: RefCell::new(vec![page("must-not-run", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(runner.calls.get(), 0);
        assert_eq!(transport.calls.get(), 0);
        let status = cloud_session_collector_status(&grants, &transport);
        assert_eq!(
            status.runtime_state,
            CloudSessionRuntimeState::ConsentRequired
        );
        assert_eq!(status.reason_code, "collector_version_rebind_required");

        let setup = CloudSessionGrantSetup {
            installation_id: INSTALLATION_ID.to_string(),
            organization_scope: "org_fixture".to_string(),
            effective_user_scope: "user_fixture".to_string(),
        };
        let pending = grants.enable(&setup, now()).unwrap();
        assert_eq!(pending.status, CloudSessionGrantStatus::ConsentRequired);
        assert_eq!(pending.collector_version, "0.1.89");
        grants.grant_create_request(INSTALLATION_ID).unwrap();
        assert!(grants
            .bind_backend_grant(&backend_grant(&pending, "enabled", 1), INSTALLATION_ID)
            .is_err());
        grants
            .bind_backend_grant(&backend_grant(&pending, "enabled", 2), INSTALLATION_ID)
            .unwrap();
        assert_eq!(
            grants.load().unwrap().unwrap().collector_version,
            compiled_release_version()
        );
    }

    #[test]
    fn unchanged_polls_emit_hourly_heartbeats_and_one_complete_snapshot_per_active_day() {
        let (grants, checkpoints) = stores("heartbeat");
        enabled(&grants);
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        let run = |at| {
            let runner = Pages {
                pages: RefCell::new(vec![page("one", None)]),
                calls: Cell::new(0),
                revoke: None,
            };
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, at)
        };

        assert_eq!(run(now()), CloudSessionCycleOutcome::Uploaded);
        assert_eq!(
            run(now() + TimeDuration::minutes(59)),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(
            run(now() + TimeDuration::hours(1)),
            CloudSessionCycleOutcome::Heartbeat
        );
        assert_eq!(
            run(now() + TimeDuration::hours(2)),
            CloudSessionCycleOutcome::Heartbeat
        );
        assert_eq!(
            run(now() + TimeDuration::days(1)),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(transport.calls.get(), 4);
        let batches = transport.batches.borrow();
        assert_eq!(batches[0].observations.len(), 1);
        assert_eq!(batches[0].batch_kind, CloudSessionBatchKind::Snapshot);
        assert!(batches[0].snapshot_complete);
        assert!(batches[1].observations.is_empty());
        assert!(batches[2].observations.is_empty());
        assert_eq!(batches[1].batch_kind, CloudSessionBatchKind::Heartbeat);
        assert!(!batches[1].snapshot_complete);
        assert_eq!(batches[2].health.state, "healthy");
        assert_eq!(batches[3].batch_kind, CloudSessionBatchKind::Snapshot);
        assert!(batches[3].snapshot_complete);
        assert_eq!(batches[3].observations.len(), 1);
        let checkpoint = checkpoints.load();
        assert_eq!(
            checkpoint.last_health_upload_at.as_deref(),
            Some("2026-07-22T12:00:00Z")
        );
        assert_eq!(
            checkpoint.last_complete_snapshot_at.as_deref(),
            Some("2026-07-22T12:00:00Z")
        );
    }

    #[test]
    fn provider_failure_and_recovery_are_visible_without_entity_rewrites() {
        let (grants, checkpoints) = stores("provider-health");
        enabled(&grants);
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        let initial = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &initial, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let failing = FailingPages {
            calls: Cell::new(0),
        };
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &failing,
                &transport,
                now() + TimeDuration::minutes(5),
            ),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(
            checkpoints.load().last_error_category.as_deref(),
            Some("provider_unavailable")
        );
        let recovered = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &recovered,
                &transport,
                now() + TimeDuration::minutes(7),
            ),
            CloudSessionCycleOutcome::Heartbeat
        );
        let batches = transport.batches.borrow();
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].observations.len(), 1);
        assert!(batches[1].observations.is_empty());
        assert_eq!(batches[1].batch_kind, CloudSessionBatchKind::Heartbeat);
        assert!(!batches[1].snapshot_complete);
        assert_eq!(batches[1].health.state, "failing");
        assert_eq!(
            batches[1].health.error_category.as_deref(),
            Some("provider_error")
        );
        assert!(batches[2].observations.is_empty());
        assert_eq!(batches[2].batch_kind, CloudSessionBatchKind::Heartbeat);
        assert!(!batches[2].snapshot_complete);
        assert_eq!(batches[2].health.state, "healthy");
    }

    #[test]
    fn nonempty_provider_page_without_valid_identity_is_failing_not_empty_healthy() {
        let (grants, checkpoints) = stores("provider-invalid-identities");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![json!({"tasks":[{"status":"running"},42]}).to_string()]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(runner.calls.get(), 1);
        let batches = transport.batches.borrow();
        assert_eq!(batches.len(), 1);
        assert!(batches[0].observations.is_empty());
        assert_eq!(batches[0].batch_kind, CloudSessionBatchKind::Heartbeat);
        assert!(!batches[0].snapshot_complete);
        assert_eq!(batches[0].health.state, "failing");
        assert_eq!(
            serde_json::to_value(&batches[0].health).unwrap(),
            json!({
                "state": "failing",
                "observed_at": "2026-07-21T12:00:00Z",
                "error_category": "provider_error"
            })
        );
        let wire = serde_json::to_string(&batches[0]).unwrap();
        assert!(!wire.contains("provider_payload_invalid"));
        assert!(!wire.contains("provider_unavailable"));
        assert_eq!(
            checkpoints.load().last_error_category.as_deref(),
            Some("provider_payload_invalid")
        );
        assert_eq!(
            grants
                .load()
                .unwrap()
                .unwrap()
                .last_collector_health
                .as_deref(),
            Some("failing")
        );
    }

    #[test]
    fn missing_or_wrong_typed_status_rejects_all_invalid_provider_page() {
        let (grants, checkpoints) = stores("provider-invalid-status");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![json!({
                "tasks": [
                    {"id":"missing-status"},
                    {"id":"wrong-status-type","status":42}
                ]
            })
            .to_string()]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(
            transport.batches.borrow()[0]
                .health
                .error_category
                .as_deref(),
            Some("provider_error")
        );
        assert_eq!(
            checkpoints.load().last_error_category.as_deref(),
            Some("provider_payload_invalid")
        );
    }

    #[test]
    fn missing_status_rejects_mixed_provider_page_without_fabricated_coverage() {
        let (grants, checkpoints) = stores("provider-mixed-invalid-status");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![json!({
                "tasks": [
                    {"id":"valid-provider-id","status":"running"},
                    {"id":"missing-status"}
                ]
            })
            .to_string()]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(transport.batches.borrow().len(), 1);
        assert_eq!(
            transport.batches.borrow()[0]
                .health
                .error_category
                .as_deref(),
            Some("provider_error")
        );
        assert_eq!(
            checkpoints.load().last_error_category.as_deref(),
            Some("provider_payload_invalid")
        );
    }

    #[test]
    fn prepared_relay_transport_reuses_auth_and_sends_only_strict_wire() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let server_captured = Arc::clone(&captured);
        let server = thread::spawn(move || {
            for index in 0..5 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = stream.read(&mut buffer) {
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(header_end) = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|offset| offset + 4)
                    {
                        let headers = String::from_utf8_lossy(&request[..header_end]);
                        let content_length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        });
                        if request.len() >= header_end + content_length.unwrap_or(0) {
                            break;
                        }
                    }
                }
                server_captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request).to_string());
                let (status, body) = match index {
                    0 => ("200 OK", r#"{"token":"relay-cloud-old"}"#),
                    1 => ("401 Unauthorized", r#"{"detail":"expired"}"#),
                    2 => ("200 OK", r#"{"token":"relay-cloud-new"}"#),
                    _ => (
                        "200 OK",
                        r#"{"schema_version":"cloud_session_heartbeat_ack.v1","accepted":true,"observations_written":0,"noop":true,"grant_status":"enabled","fresh_at":"2026-07-21T12:00:00Z"}"#,
                    ),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });

        let (grants, _checkpoints) = stores("relay-transport");
        enabled(&grants);
        let grant = grants.load().unwrap().unwrap();
        let batch = heartbeat_batch(
            &grant,
            now(),
            CloudSessionCollectorHealthV1 {
                state: "healthy".to_string(),
                observed_at: timestamp(now()),
                error_category: None,
            },
        )
        .unwrap();
        let transport = RelayCloudSessionTransport::new(
            format!("http://{address}"),
            LocalDeviceBinding {
                device_id: INSTALLATION_ID.to_string(),
                machine_id: None,
                sources: vec!["codex".to_string()],
            },
            "device-secret".to_string(),
        );
        transport.send(&batch).unwrap();
        transport.send(&batch).unwrap();
        server.join().unwrap();

        let requests = captured.lock().unwrap();
        assert_eq!(requests.len(), 5);
        assert!(requests[0].contains("/relay-token"));
        assert!(requests[0].contains("X-Ottto-Device-Secret: device-secret"));
        assert!(requests[1].contains("Authorization: Bearer relay-cloud-old"));
        assert!(requests[2].contains("/relay-token"));
        for request in [&requests[1], &requests[3], &requests[4]] {
            assert!(request.contains("/api/v1/cloud-session-observations/batches"));
            let body = request.split_once("\r\n\r\n").unwrap().1;
            let payload: Value = serde_json::from_str(body).unwrap();
            assert_eq!(payload["grant_version"], 1);
            assert_eq!(payload["batch_kind"], "heartbeat");
            assert_eq!(payload["snapshot_complete"], false);
            assert_eq!(payload["observations"], json!([]));
            assert_eq!(payload["health"]["state"], "healthy");
            assert!(!request.contains("semantic_digest"));
            assert!(!request.contains("private title"));
            assert!(!request.contains("provider-task"));
            assert!(!request.contains("provider-account-private"));
        }
        assert!(requests[3].contains("Authorization: Bearer relay-cloud-new"));
        assert!(requests[4].contains("Authorization: Bearer relay-cloud-new"));
    }

    #[test]
    fn relay_token_redirect_never_forwards_the_device_secret() {
        use std::io::{ErrorKind, Write};
        use std::net::TcpListener;

        let attacker = TcpListener::bind("127.0.0.1:0").unwrap();
        let attacker_address = attacker.local_addr().unwrap();
        attacker.set_nonblocking(true).unwrap();
        let relay = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_address = relay.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(String::new()));
        let server_captured = Arc::clone(&captured);
        let server = thread::spawn(move || {
            let (mut stream, _) = relay.accept().unwrap();
            *server_captured.lock().unwrap() = read_http_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://{attacker_address}/capture\r\nContent-Type: application/json\r\nContent-Length: 31\r\nConnection: close\r\n\r\n{{\"token\":\"redirect-body-token\"}}"
            )
            .unwrap();
        });

        let transport = RelayCloudSessionTransport::new(
            format!("http://{relay_address}"),
            LocalDeviceBinding {
                device_id: INSTALLATION_ID.to_string(),
                machine_id: None,
                sources: vec!["codex".to_string()],
            },
            "redirect-guard-secret".to_string(),
        );
        let error = transport
            .token(false, Instant::now() + Duration::from_secs(2))
            .unwrap_err();
        let diagnostics = error
            .downcast_ref::<crate::snapshot_client::UploadFailureDiagnostics>()
            .unwrap();
        assert_eq!(diagnostics.status_family(), "http_3xx");
        server.join().unwrap();
        assert!(captured
            .lock()
            .unwrap()
            .contains("X-Ottto-Device-Secret: redirect-guard-secret"));
        assert!(matches!(
            attacker.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn relay_transport_revalidates_one_exact_device_bound_grant_epoch() {
        use std::io::Write;
        use std::net::TcpListener;

        let (grants, _checkpoints) = stores("relay-authority-exact");
        enabled(&grants);
        let grant = grants.load().unwrap().unwrap();
        let authority_body = serde_json::to_string(&backend_grant(&grant, "enabled", 1)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let server_captured = Arc::clone(&captured);
        let server = thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                server_captured.lock().unwrap().push(request);
                let body = if index == 0 {
                    r#"{"token":"relay-authority"}"#
                } else {
                    &authority_body
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let transport = RelayCloudSessionTransport::new(
            format!("http://{address}"),
            LocalDeviceBinding {
                device_id: INSTALLATION_ID.to_string(),
                machine_id: None,
                sources: vec!["codex".to_string()],
            },
            "device-secret".to_string(),
        );

        let response = transport
            .revalidate_grant_bounded(&grant, Duration::from_secs(2))
            .unwrap();
        assert_eq!(response.id, GRANT_ID);
        assert_eq!(response.grant_version, 1);
        server.join().unwrap();
        let requests = captured.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("/relay-token"));
        assert!(requests[0].contains("X-Ottto-Device-Secret: device-secret"));
        assert!(requests[1].contains(&format!(
            "GET /api/v1/cloud-session-observations/grants/{GRANT_ID}/authority?grant_version=1"
        )));
        assert!(requests[1].contains("Authorization: Bearer relay-authority"));
        assert!(!requests[1].contains("device-secret"));
    }

    #[test]
    fn authority_absence_or_epoch_conflict_prevents_provider_call() {
        use std::io::Write;
        use std::net::TcpListener;

        for (name, authority_status) in [
            ("absent", "404 Not Found"),
            ("epoch", "409 Conflict"),
            ("future-body", "200 OK"),
        ] {
            let (grants, checkpoints) = stores(&format!("relay-authority-{name}"));
            enabled(&grants);
            let grant = grants.load().unwrap().unwrap();
            let future_body = serde_json::to_string(&backend_grant(&grant, "enabled", 2)).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                for index in 0..2 {
                    let (mut stream, _) = listener.accept().unwrap();
                    let _request = read_http_request(&mut stream);
                    let (status, body) = if index == 0 {
                        ("200 OK", r#"{"token":"relay-authority"}"#.to_string())
                    } else if name == "future-body" {
                        (authority_status, future_body.clone())
                    } else {
                        (authority_status, r#"{"detail":"redacted"}"#.to_string())
                    };
                    write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    )
                    .unwrap();
                }
            });
            let transport = RelayCloudSessionTransport::new(
                format!("http://{address}"),
                LocalDeviceBinding {
                    device_id: INSTALLATION_ID.to_string(),
                    machine_id: None,
                    sources: vec!["codex".to_string()],
                },
                "device-secret".to_string(),
            );
            let runner = Pages {
                pages: RefCell::new(vec![page("must-not-run", None)]),
                calls: Cell::new(0),
                revoke: None,
            };
            assert_eq!(
                collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
                CloudSessionCycleOutcome::Failed,
                "case {name}"
            );
            assert_eq!(runner.calls.get(), 0, "case {name}");
            server.join().unwrap();
        }
    }

    #[test]
    fn v1_relay_rejects_non_heartbeat_payloads_before_network() {
        use std::io::ErrorKind;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (grants, _checkpoints) = stores("v1-relay-local-rejection");
        enabled(&grants);
        let grant = grants.load().unwrap().unwrap();
        let heartbeat = heartbeat_batch(
            &grant,
            now(),
            CloudSessionCollectorHealthV1 {
                state: "healthy".to_string(),
                observed_at: timestamp(now()),
                error_category: None,
            },
        )
        .unwrap();
        let transport = RelayCloudSessionTransport::new(
            format!("http://{address}"),
            LocalDeviceBinding {
                device_id: INSTALLATION_ID.to_string(),
                machine_id: None,
                sources: vec!["codex".to_string()],
            },
            "device-secret".to_string(),
        );

        let mut invalid = Vec::new();
        let mut snapshot = heartbeat.clone();
        snapshot.batch_kind = CloudSessionBatchKind::Snapshot;
        invalid.push(snapshot);
        let mut complete = heartbeat.clone();
        complete.snapshot_complete = true;
        invalid.push(complete);
        let mut nonempty = heartbeat.clone();
        nonempty.observations = parse_cloud_page(&page("private-id", None), b"fixture-key", now())
            .unwrap()
            .entities;
        invalid.push(nonempty.clone());
        nonempty.observations[0].entity_key = "raw-private-id".to_string();
        invalid.push(nonempty);
        let mut raw_scope = heartbeat.clone();
        raw_scope.grant_scope_fingerprint = "raw-scope".to_string();
        invalid.push(raw_scope);
        let mut open_health = heartbeat;
        open_health.health.state = "degraded".to_string();
        invalid.push(open_health);

        for payload in invalid {
            assert!(transport.send(&payload).is_err());
        }
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn v1_heartbeat_checkpoint_requires_an_exact_bound_receipt() {
        use std::io::Write;
        use std::net::TcpListener;

        struct RevalidatingHeartbeatRelay {
            relay: RelayCloudSessionTransport,
            grant: CloudSessionBackendGrantResponseV1,
        }
        impl CloudSessionTransport for RevalidatingHeartbeatRelay {
            fn supports_grant_revalidation(&self) -> bool {
                true
            }
            fn revalidate_grant(
                &self,
                _grant: &CloudSessionGrant,
            ) -> Result<CloudSessionBackendGrantResponseV1> {
                Ok(self.grant.clone())
            }
            fn revalidate_grant_bounded(
                &self,
                grant: &CloudSessionGrant,
                _timeout: Duration,
            ) -> Result<CloudSessionBackendGrantResponseV1> {
                self.revalidate_grant(grant)
            }
            fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
                self.relay.send(batch)
            }
            fn send_bounded(
                &self,
                batch: &CloudSessionObservationBatchV1,
                timeout: Duration,
            ) -> Result<()> {
                self.relay.send_bounded(batch, timeout)
            }
        }

        let exact = json!({
            "schema_version": "cloud_session_heartbeat_ack.v1",
            "accepted": true,
            "observations_written": 0,
            "noop": true,
            "grant_status": "enabled",
            "fresh_at": "2026-07-21T13:00:00Z",
        });
        let mut negative = exact.clone();
        negative["accepted"] = json!(false);
        let mut mismatch = exact.clone();
        mismatch["fresh_at"] = json!("2026-07-21T13:00:01Z");
        let mut unknown = exact.clone();
        unknown["unexpected"] = json!(true);
        let cases = [
            ("negative", negative.to_string(), false),
            ("mismatch", mismatch.to_string(), false),
            ("malformed", r#"{"accepted":true}"#.to_string(), false),
            ("unknown", unknown.to_string(), false),
            ("exact", exact.to_string(), true),
        ];

        for (name, response_body, accepted) in cases {
            let (grants, checkpoints) = stores(&format!("v1-heartbeat-receipt-{name}"));
            enabled(&grants);
            let seed_runner = CursorRecordingPages::new(vec![page("stable", None)]);
            let seed_transport = V2RecordingTransport::new();
            assert_eq!(
                collect_cloud_sessions_once(
                    &grants,
                    &checkpoints,
                    &seed_runner,
                    &seed_transport,
                    now(),
                ),
                CloudSessionCycleOutcome::Uploaded
            );
            assert_eq!(
                checkpoints.load().last_health_upload_at.as_deref(),
                Some("2026-07-21T12:00:00Z")
            );

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                for index in 0..2 {
                    let (mut stream, _) = listener.accept().unwrap();
                    let request = read_http_request(&mut stream);
                    let body = if index == 0 {
                        r#"{"token":"relay-v1"}"#
                    } else {
                        assert!(request.contains("/api/v1/cloud-session-observations/batches"));
                        &response_body
                    };
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                }
            });
            let current = grants.load().unwrap().unwrap();
            let transport = RevalidatingHeartbeatRelay {
                grant: backend_grant(&current, "enabled", 1),
                relay: RelayCloudSessionTransport::new(
                    format!("http://{address}"),
                    LocalDeviceBinding {
                        device_id: INSTALLATION_ID.to_string(),
                        machine_id: None,
                        sources: vec!["codex".to_string()],
                    },
                    "device-secret".to_string(),
                ),
            };
            let runner = CursorRecordingPages::new(vec![page("stable", None)]);
            let outcome = collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &runner,
                &transport,
                now() + TimeDuration::hours(1),
            );
            assert_eq!(
                outcome,
                if accepted {
                    CloudSessionCycleOutcome::Heartbeat
                } else {
                    CloudSessionCycleOutcome::Failed
                },
                "case {name}"
            );
            assert_eq!(
                checkpoints.load().last_health_upload_at.as_deref(),
                Some(if accepted {
                    "2026-07-21T13:00:00Z"
                } else {
                    "2026-07-21T12:00:00Z"
                }),
                "case {name}"
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn v2_relay_uses_exact_paths_and_retries_exact_body_after_auth_refresh() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;

        let (grants, checkpoints) = stores("v2-relay-http-fixture");
        enabled(&grants);
        let fixture_runner = CursorRecordingPages::new(vec![page("raw-provider-private-id", None)]);
        let fixture_transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &fixture_runner,
                &fixture_transport,
                now(),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        let chunk = fixture_transport.chunks.borrow()[0].clone();
        let finalize = fixture_transport.finalizes.borrow()[0].clone();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let server_captured = Arc::clone(&captured);
        let server = thread::spawn(move || {
            for index in 0..5 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = stream.read(&mut buffer) {
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(header_end) = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|offset| offset + 4)
                    {
                        let headers = String::from_utf8_lossy(&request[..header_end]);
                        let content_length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        });
                        if request.len() >= header_end + content_length.unwrap_or(0) {
                            break;
                        }
                    }
                }
                let captured_request = String::from_utf8_lossy(&request).to_string();
                server_captured
                    .lock()
                    .unwrap()
                    .push(captured_request.clone());
                let (status, body) = match index {
                    0 => (
                        "200 OK".to_string(),
                        r#"{"token":"relay-v2-old"}"#.to_string(),
                    ),
                    1 => (
                        "401 Unauthorized".to_string(),
                        r#"{"detail":"expired"}"#.to_string(),
                    ),
                    2 => (
                        "200 OK".to_string(),
                        r#"{"token":"relay-v2-new"}"#.to_string(),
                    ),
                    _ => ("200 OK".to_string(), exact_scan_ack(&captured_request)),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });

        let relay = RelayCloudSessionTransport::new(
            format!("http://{address}"),
            LocalDeviceBinding {
                device_id: INSTALLATION_ID.to_string(),
                machine_id: None,
                sources: vec!["codex".to_string()],
            },
            "device-secret".to_string(),
        );
        relay.send_scan_chunk(&chunk).unwrap();
        relay.finalize_scan(&finalize).unwrap();
        server.join().unwrap();

        let requests = captured.lock().unwrap();
        assert_eq!(requests.len(), 5);
        assert!(requests[0].starts_with(&format!(
            "POST /api/v1/telemetry/devices/{INSTALLATION_ID}/relay-token HTTP/1.1"
        )));
        let chunk_path = format!("/api/v1/cloud-sessions/scans/{}/chunks", chunk.scan_id);
        let finalize_path = format!("/api/v1/cloud-sessions/scans/{}/finalize", finalize.scan_id);
        for request in [&requests[1], &requests[3]] {
            assert!(request.starts_with(&format!("POST {chunk_path} HTTP/1.1")));
            let body = request.split_once("\r\n\r\n").unwrap().1;
            let payload: Value = serde_json::from_str(body).unwrap();
            assert_eq!(payload["scan_id"], chunk.scan_id);
            assert!(!body.contains("raw-provider-private-id"));
            assert!(!body.contains("cursor"));
        }
        assert!(requests[1].contains("Authorization: Bearer relay-v2-old"));
        assert!(requests[3].contains("Authorization: Bearer relay-v2-new"));
        assert_eq!(
            requests[1].split_once("\r\n\r\n").unwrap().1,
            requests[3].split_once("\r\n\r\n").unwrap().1
        );
        assert!(requests[4].starts_with(&format!("POST {finalize_path} HTTP/1.1")));
        let finalize_body = requests[4].split_once("\r\n\r\n").unwrap().1;
        let finalize_payload: Value = serde_json::from_str(finalize_body).unwrap();
        assert_eq!(finalize_payload["scan_id"], finalize.scan_id);
        assert!(!finalize_body.contains("raw-provider-private-id"));
        assert!(!finalize_body.contains("cursor"));
    }

    #[test]
    fn v2_receipts_must_exactly_acknowledge_before_progress_or_completion() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        struct RevalidatingRelay {
            relay: RelayCloudSessionTransport,
            grant: CloudSessionBackendGrantResponseV1,
        }
        impl CloudSessionTransport for RevalidatingRelay {
            fn supports_grant_revalidation(&self) -> bool {
                true
            }
            fn revalidate_grant(
                &self,
                _grant: &CloudSessionGrant,
            ) -> Result<CloudSessionBackendGrantResponseV1> {
                Ok(self.grant.clone())
            }
            fn revalidate_grant_bounded(
                &self,
                grant: &CloudSessionGrant,
                _timeout: Duration,
            ) -> Result<CloudSessionBackendGrantResponseV1> {
                self.revalidate_grant(grant)
            }
            fn send_scan_chunk(&self, chunk: &CloudSessionObservationChunkV2) -> Result<()> {
                self.relay.send_scan_chunk(chunk)
            }
            fn send_scan_chunk_bounded(
                &self,
                chunk: &CloudSessionObservationChunkV2,
                timeout: Duration,
            ) -> Result<()> {
                self.relay.send_scan_chunk_bounded(chunk, timeout)
            }
            fn finalize_scan(&self, finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
                self.relay.finalize_scan(finalize)
            }
            fn finalize_scan_bounded(
                &self,
                finalize: &CloudSessionScanFinalizeV2,
                timeout: Duration,
            ) -> Result<()> {
                self.relay.finalize_scan_bounded(finalize, timeout)
            }
            fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
                self.relay.send(batch)
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for index in 0..5 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = stream.read(&mut buffer) {
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(header_end) = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|offset| offset + 4)
                    {
                        let headers = String::from_utf8_lossy(&request[..header_end]);
                        let content_length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        });
                        if request.len() >= header_end + content_length.unwrap_or(0) {
                            break;
                        }
                    }
                }
                let request = String::from_utf8_lossy(&request).to_string();
                let body = if index == 0 {
                    r#"{"token":"relay-v2"}"#.to_string()
                } else {
                    let mut ack: Value = serde_json::from_str(&exact_scan_ack(&request)).unwrap();
                    if index == 1 {
                        ack["accepted"] = json!(false);
                    } else if index == 3 {
                        ack["epoch_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
                    }
                    ack.to_string()
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });

        let (grants, checkpoints) = stores("v2-strict-receipts");
        enabled(&grants);
        let current = grants.load().unwrap().unwrap();
        let transport = RevalidatingRelay {
            grant: backend_grant(&current, "enabled", 1),
            relay: RelayCloudSessionTransport::new(
                format!("http://{address}"),
                LocalDeviceBinding {
                    device_id: INSTALLATION_ID.to_string(),
                    machine_id: None,
                    sources: vec!["codex".to_string()],
                },
                "device-secret".to_string(),
            ),
        };
        let runner = CursorRecordingPages::new(vec![page("strict-receipt", None)]);

        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        {
            let runtime = checkpoints.runtime.lock().unwrap();
            assert_eq!(
                runtime
                    .active
                    .as_ref()
                    .unwrap()
                    .prepared
                    .as_ref()
                    .unwrap()
                    .next_chunk,
                0
            );
        }
        assert!(checkpoints.load().last_complete_snapshot_at.is_none());

        let unused_runner = CursorRecordingPages::new(Vec::new());
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &unused_runner,
                &transport,
                now() + TimeDuration::minutes(3),
            ),
            CloudSessionCycleOutcome::Failed
        );
        {
            let runtime = checkpoints.runtime.lock().unwrap();
            let prepared = runtime.active.as_ref().unwrap().prepared.as_ref().unwrap();
            assert_eq!(prepared.next_chunk, 1);
            assert!(prepared.finalize.is_some());
        }
        assert!(checkpoints.load().last_complete_snapshot_at.is_none());

        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &unused_runner,
                &transport,
                now() + TimeDuration::minutes(8),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        assert!(checkpoints.load().last_complete_snapshot_at.is_some());
        assert!(checkpoints.runtime.lock().unwrap().active.is_none());
        assert!(unused_runner.cursors.borrow().is_empty());
        server.join().unwrap();
    }

    #[test]
    fn collector_supervisor_has_one_process_owner_under_concurrency() {
        let started = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let attempts = (0..8)
            .map(|_| {
                let started = Arc::clone(&started);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    reserve_collector_supervisor(&started)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        assert_eq!(
            attempts
                .into_iter()
                .map(|attempt| attempt.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
    }

    #[test]
    fn paused_runtime_clears_process_scan_without_provider_or_state_writes() {
        let (grants, checkpoints) = stores("runtime-paused-clear");
        enabled(&grants);
        let grant = grants.load().unwrap().unwrap();
        grants.pause(now()).unwrap();
        let before_grant = fs::read(grants.path()).unwrap();
        let runner = Pages {
            pages: RefCell::new(vec![page("must-not-run", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        checkpoints.runtime.lock().unwrap().active = Some(ActiveCloudSessionScan {
            scan_id: "00000000-0000-4000-8000-000000000099".to_string(),
            scan_started_at: timestamp(now()),
            mode: CloudSessionScanMode::Full,
            grant: grant.clone(),
            cursor: Some("private-cursor".to_string()),
            seen_cursors: HashSet::new(),
            observations: BTreeMap::new(),
            provider_page_count: 1,
            head_semantic_digest: None,
            prepared: None,
        });
        let device = LocalDeviceBinding {
            device_id: INSTALLATION_ID.to_string(),
            machine_id: Some("machine-runtime".to_string()),
            sources: vec!["codex".to_string()],
        };
        let mut active_transport: ActiveCloudSessionTransport = Some((
            CloudSessionRuntimeTransportKey {
                binding: CloudSessionRuntimeBinding {
                    api_base_url: DEFAULT_API_BASE_URL.to_string(),
                    device: device.clone(),
                    grant_id: GRANT_ID.to_string(),
                    grant_version: 1,
                    grant_scope_id: grant.grant_scope_id,
                },
                device_secret_digest: sha256(b"device-secret"),
            },
            Box::new(RelayCloudSessionTransport::new(
                DEFAULT_API_BASE_URL,
                device,
                "device-secret".into(),
            )),
        ));

        assert_eq!(
            collect_composed_cloud_sessions_once(
                &grants,
                &checkpoints,
                &runner,
                &mut active_transport,
                now(),
            ),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(runner.calls.get(), 0);
        assert!(active_transport.is_none());
        assert!(checkpoints.runtime.lock().unwrap().active.is_none());
        assert_eq!(fs::read(grants.path()).unwrap(), before_grant);
        assert!(!checkpoints.path.exists());
    }

    #[test]
    fn no_grant_is_zero_touch_beyond_the_local_grant_read() {
        let root = temp_dir("runtime-no-grant-zero-touch");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        let checkpoints = CloudSessionCheckpointStore::new(root.join("checkpoint.json"));
        let unreadable_account = root.join("unreadable-account");
        let unreadable_device = root.join("unreadable-device");
        let unreadable_connection = root.join("unreadable-connection");
        fs::create_dir(&unreadable_account).unwrap();
        fs::create_dir(&unreadable_device).unwrap();
        fs::create_dir(&unreadable_connection).unwrap();
        let accounts = FileAccountStore::new(unreadable_account);
        let devices = FileDeviceStore::new(unreadable_device);
        let connections = FileConnectionStore::new(unreadable_connection);
        let runner = Pages {
            pages: RefCell::new(vec![page("must-not-run", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let mut active_transport: ActiveCloudSessionTransport = None;

        assert_eq!(
            collect_composed_cloud_sessions_once_with(
                &grants,
                &checkpoints,
                &runner,
                &mut active_transport,
                &accounts,
                &devices,
                &connections,
                || panic!("no grant must not read relay credentials"),
                |_, _, _| panic!("no grant must not compose or contact the relay"),
                now(),
            ),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(runner.calls.get(), 0);
        assert!(active_transport.is_none());
        assert!(!grants.path().exists());
        assert!(!checkpoints.path.exists());
        assert!(checkpoints.runtime.lock().unwrap().active.is_none());
    }

    #[test]
    fn later_consent_activates_the_existing_supervisor_without_restart() {
        let root = temp_dir("runtime-later-consent");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        let checkpoints = CloudSessionCheckpointStore::new(root.join("checkpoint.json"));
        let (accounts, devices, connections) =
            runtime_identity_stores(&root, "user_fixture", "org_fixture", DEFAULT_API_BASE_URL);
        let runner = Pages {
            pages: RefCell::new(vec![page("after-consent", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let credential_reads = Cell::new(0);
        let transport_compositions = Cell::new(0);
        let mut active_transport: ActiveCloudSessionTransport = None;

        assert_eq!(
            collect_composed_cloud_sessions_once_with(
                &grants,
                &checkpoints,
                &runner,
                &mut active_transport,
                &accounts,
                &devices,
                &connections,
                || panic!("dormant supervisor must not read relay credentials"),
                |_, _, _| panic!("dormant supervisor must not compose a relay"),
                now(),
            ),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(runner.calls.get(), 0);
        assert!(active_transport.is_none());
        assert!(!checkpoints.path.exists());

        // A previous consent epoch's relay/provider failure may have left a
        // long backoff. New consent must not inherit that stale circuit.
        checkpoints
            .save(&CloudSessionCheckpoint {
                schema_version: CHECKPOINT_SCHEMA_VERSION.to_string(),
                circuit_grant_epoch_digest: Some(sha256(b"previous-grant-epoch")),
                consecutive_failures: 6,
                circuit_open_until: Some(timestamp(now() + TimeDuration::hours(1))),
                last_error_category: Some("provider_error".to_string()),
                ..Default::default()
            })
            .unwrap();

        enabled(&grants);
        assert_eq!(
            collect_composed_cloud_sessions_once_with(
                &grants,
                &checkpoints,
                &runner,
                &mut active_transport,
                &accounts,
                &devices,
                &connections,
                || {
                    credential_reads.set(credential_reads.get() + 1);
                    Ok((
                        devices.load().unwrap().unwrap(),
                        "device-secret".to_string(),
                    ))
                },
                |_, _, _| {
                    transport_compositions.set(transport_compositions.get() + 1);
                    Box::new(V2RecordingTransport::new())
                },
                now() + TimeDuration::minutes(5),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(credential_reads.get(), 1);
        assert_eq!(transport_compositions.get(), 1);
        assert_eq!(runner.calls.get(), 1);
        assert!(active_transport.is_some());
        let checkpoint = checkpoints.load();
        assert!(checkpoint.circuit_open_until.is_none());
        assert!(checkpoint.circuit_grant_epoch_digest.is_none());
    }

    #[test]
    fn new_grant_failure_starts_a_fresh_circuit_epoch() {
        let root = temp_dir("runtime-new-grant-circuit");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        let checkpoints = CloudSessionCheckpointStore::new(root.join("checkpoint.json"));
        let (accounts, devices, connections) =
            runtime_identity_stores(&root, "user_fixture", "org_fixture", DEFAULT_API_BASE_URL);
        checkpoints
            .save(&CloudSessionCheckpoint {
                schema_version: CHECKPOINT_SCHEMA_VERSION.to_string(),
                circuit_grant_epoch_digest: Some(sha256(b"previous-grant-epoch")),
                consecutive_failures: 6,
                circuit_open_until: Some(timestamp(now() + TimeDuration::hours(1))),
                last_error_category: Some("provider_error".to_string()),
                ..Default::default()
            })
            .unwrap();
        enabled(&grants);
        let grant = grants.load().unwrap().unwrap();
        let runner = Pages {
            pages: RefCell::new(vec![page("must-not-run", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let mut active_transport: ActiveCloudSessionTransport = None;
        let attempt_at = now() + TimeDuration::minutes(5);

        assert_eq!(
            collect_composed_cloud_sessions_once_with(
                &grants,
                &checkpoints,
                &runner,
                &mut active_transport,
                &accounts,
                &devices,
                &connections,
                || Ok((
                    devices.load().unwrap().unwrap(),
                    "device-secret".to_string()
                )),
                |_, _, _| {
                    Box::new(RevalidationTransport {
                        response: None,
                        revalidation_calls: Cell::new(0),
                        send_calls: Cell::new(0),
                    })
                },
                attempt_at,
            ),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(runner.calls.get(), 0);
        assert!(active_transport.is_none());
        let checkpoint = checkpoints.load();
        assert_eq!(checkpoint.consecutive_failures, 1);
        assert_eq!(
            checkpoint.circuit_grant_epoch_digest.as_deref(),
            Some(grant_epoch_digest(&grant).as_str())
        );
        assert_eq!(
            checkpoint.circuit_open_until.as_deref(),
            Some(timestamp(attempt_at + TimeDuration::minutes(2)).as_str())
        );
    }

    #[test]
    fn stale_circuit_reset_preserves_incomplete_scan_health() {
        let (grants, _) = stores("runtime-circuit-scan-health");
        enabled(&grants);
        let grant = grants.load().unwrap().unwrap();
        let mut checkpoint = CloudSessionCheckpoint {
            schema_version: CHECKPOINT_SCHEMA_VERSION.to_string(),
            circuit_grant_epoch_digest: Some(sha256(b"previous-grant-epoch")),
            consecutive_failures: 6,
            circuit_open_until: Some(timestamp(now() + TimeDuration::hours(1))),
            last_error_category: Some("scan_incomplete".to_string()),
            ..Default::default()
        };

        reset_stale_circuit_for_grant(&mut checkpoint, &grant);

        assert_eq!(checkpoint.consecutive_failures, 0);
        assert!(checkpoint.circuit_open_until.is_none());
        assert!(checkpoint.circuit_grant_epoch_digest.is_none());
        assert_eq!(
            checkpoint.last_error_category.as_deref(),
            Some("scan_incomplete")
        );
    }

    #[test]
    fn runtime_composition_requires_the_exact_local_grant_identity() {
        let root = temp_dir("runtime-exact-identity");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let (accounts, devices, connections) =
            runtime_identity_stores(&root, "user_fixture", "org_fixture", DEFAULT_API_BASE_URL);

        let candidate =
            load_cloud_session_runtime_binding(&grants, &accounts, &devices, &connections)
                .unwrap()
                .expect("exact local identity should compose");
        let binding = candidate.binding;
        assert_eq!(binding.device.device_id, INSTALLATION_ID);
        assert_eq!(binding.grant_id, GRANT_ID);
        assert_eq!(binding.grant_version, 1);
        assert_eq!(binding.api_base_url, DEFAULT_API_BASE_URL);

        let mismatched_accounts = FileAccountStore::new(root.join("mismatch-account.json"));
        mismatched_accounts
            .save(&ottto_protocol::LocalAccountBinding {
                state: LocalAccountState::Connected,
                user: Some(ottto_protocol::LocalAccountUser {
                    id: "other-user".to_string(),
                    email: "other@example.com".to_string(),
                    display_name: None,
                }),
                organization: Some(ottto_protocol::LocalAccountOrganization {
                    id: "org_fixture".to_string(),
                    name: "Runtime Org".to_string(),
                }),
                connected_at: None,
                last_refreshed_at: None,
                message: None,
            })
            .unwrap();
        let before_grant = fs::read(grants.path()).unwrap();
        assert!(load_cloud_session_runtime_binding(
            &grants,
            &mismatched_accounts,
            &devices,
            &connections,
        )
        .is_err());
        assert_eq!(fs::read(grants.path()).unwrap(), before_grant);
    }

    #[test]
    fn status_configuration_is_derived_without_process_local_runtime_state() {
        let root = temp_dir("runtime-derived-status");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let (accounts, devices, connections) =
            runtime_identity_stores(&root, "user_fixture", "org_fixture", DEFAULT_API_BASE_URL);
        let credential_reads = Cell::new(0);

        assert!(runtime_transport_locally_configured_with(
            &grants,
            &accounts,
            &devices,
            &connections,
            || {
                credential_reads.set(credential_reads.get() + 1);
                Ok((
                    devices.load().unwrap().unwrap(),
                    "device-secret".to_string(),
                ))
            },
        ));
        assert_eq!(credential_reads.get(), 1);
        let no_grant = CloudSessionGrantStore::new(root.join("no-grant.json"));
        assert!(!runtime_transport_locally_configured_with(
            &no_grant,
            &accounts,
            &devices,
            &connections,
            || panic!("status without consent must not read credentials"),
        ));
    }

    #[test]
    fn dormant_grant_short_circuits_before_other_local_state_reads() {
        let root = temp_dir("runtime-dormant-short-circuit");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        fs::create_dir(root.join("unreadable-account")).unwrap();
        fs::create_dir(root.join("unreadable-device")).unwrap();
        fs::create_dir(root.join("unreadable-connection")).unwrap();

        assert!(load_cloud_session_runtime_binding(
            &grants,
            &FileAccountStore::new(root.join("unreadable-account")),
            &FileDeviceStore::new(root.join("unreadable-device")),
            &FileConnectionStore::new(root.join("unreadable-connection")),
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn runtime_rejects_untrusted_destination_without_mutating_grant() {
        let root = temp_dir("runtime-untrusted-destination");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let (accounts, devices, connections) = runtime_identity_stores(
            &root,
            "user_fixture",
            "org_fixture",
            "https://attacker.example",
        );
        let before_grant = fs::read(grants.path()).unwrap();

        assert!(
            load_cloud_session_runtime_binding(&grants, &accounts, &devices, &connections,)
                .is_err()
        );
        assert_eq!(fs::read(grants.path()).unwrap(), before_grant);
        assert!(validated_cloud_session_api_base_url("http://localhost.evil").is_err());
        assert!(validated_cloud_session_api_base_url("https://api.ottto.net@evil").is_err());
    }

    #[test]
    fn disabled_and_revoked_grants_never_call_provider_or_transport() {
        let (grants, checkpoints) = stores("revoke");
        let runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Disabled
        );
        enabled(&grants);
        grants.revoke(now()).unwrap();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(runner.calls.get(), 0);
        assert_eq!(transport.calls.get(), 0);
    }

    #[test]
    fn revocation_between_page_and_send_stops_upload() {
        let (grants, checkpoints) = stores("race");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![
                page("one", Some("cursor-after-revoke")),
                page("two", None),
            ]),
            calls: Cell::new(0),
            revoke: Some(grants.clone()),
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(runner.calls.get(), 1);
        assert_eq!(transport.calls.get(), 0);
    }

    #[test]
    fn revocation_after_chunk_revalidation_closes_relay_admission() {
        let root = temp_dir("chunk-post-revalidation-race");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
            root.join("checkpoint.json"),
        ));
        let transport = Arc::new(ThreadRecordingTransport::default());
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        checkpoints.set_relay_admission_barrier_for_test(
            0,
            Arc::clone(&entered),
            Arc::clone(&release),
        );

        let collector_grants = grants.clone();
        let collector_checkpoints = Arc::clone(&checkpoints);
        let collector_transport = Arc::clone(&transport);
        let collector = thread::spawn(move || {
            collect_cloud_sessions_once(
                &collector_grants,
                &collector_checkpoints,
                &CursorRecordingPages::new(vec![page("chunk-race", None)]),
                collector_transport.as_ref(),
                now(),
            )
        });
        entered.wait();
        grants.revoke(now()).unwrap();
        release.wait();

        assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Noop);
        assert_eq!(transport.chunks.load(Ordering::SeqCst), 0);
        assert_eq!(transport.finalizes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn revocation_after_finalize_revalidation_closes_relay_admission() {
        let root = temp_dir("finalize-post-revalidation-race");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
            root.join("checkpoint.json"),
        ));
        let transport = Arc::new(ThreadRecordingTransport::default());
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        // Skip the chunk boundary and stop exactly after finalization's
        // backend authority response but before finalization admission.
        checkpoints.set_relay_admission_barrier_for_test(
            1,
            Arc::clone(&entered),
            Arc::clone(&release),
        );

        let collector_grants = grants.clone();
        let collector_checkpoints = Arc::clone(&checkpoints);
        let collector_transport = Arc::clone(&transport);
        let collector = thread::spawn(move || {
            collect_cloud_sessions_once(
                &collector_grants,
                &collector_checkpoints,
                &CursorRecordingPages::new(vec![page("finalize-race", None)]),
                collector_transport.as_ref(),
                now(),
            )
        });
        entered.wait();
        grants.revoke(now()).unwrap();
        release.wait();

        assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Noop);
        assert_eq!(transport.chunks.load(Ordering::SeqCst), 1);
        assert_eq!(transport.finalizes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn revocation_after_heartbeat_revalidation_closes_relay_admission() {
        let root = temp_dir("heartbeat-post-revalidation-race");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
            root.join("checkpoint.json"),
        ));
        let seed_transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &CursorRecordingPages::new(vec![page("stable-heartbeat", None)]),
                &seed_transport,
                now(),
            ),
            CloudSessionCycleOutcome::Uploaded
        );

        let transport = Arc::new(ThreadRecordingTransport::default());
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        checkpoints.set_relay_admission_barrier_for_test(
            0,
            Arc::clone(&entered),
            Arc::clone(&release),
        );
        let collector_grants = grants.clone();
        let collector_checkpoints = Arc::clone(&checkpoints);
        let collector_transport = Arc::clone(&transport);
        let collector = thread::spawn(move || {
            collect_cloud_sessions_once(
                &collector_grants,
                &collector_checkpoints,
                &CursorRecordingPages::new(vec![page("stable-heartbeat", None)]),
                collector_transport.as_ref(),
                now() + TimeDuration::minutes(61),
            )
        });
        entered.wait();
        grants.revoke(now()).unwrap();
        release.wait();

        assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Noop);
        assert_eq!(transport.v1_sends.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn revocation_after_failure_revalidation_closes_relay_admission() {
        let root = temp_dir("failure-post-revalidation-race");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
            root.join("checkpoint.json"),
        ));
        let transport = Arc::new(ThreadRecordingTransport::default());
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        checkpoints.set_relay_admission_barrier_for_test(
            0,
            Arc::clone(&entered),
            Arc::clone(&release),
        );
        let collector_grants = grants.clone();
        let collector_checkpoints = Arc::clone(&checkpoints);
        let collector_transport = Arc::clone(&transport);
        let collector = thread::spawn(move || {
            collect_cloud_sessions_once(
                &collector_grants,
                &collector_checkpoints,
                &FailingPages {
                    calls: Cell::new(0),
                },
                collector_transport.as_ref(),
                now(),
            )
        });
        entered.wait();
        grants.revoke(now()).unwrap();
        release.wait();

        assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Noop);
        assert_eq!(transport.v1_sends.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn revoke_waits_for_an_admitted_relay_chunk_before_returning_idle() {
        use std::sync::mpsc;

        let root = temp_dir("relay-chunk-io-fence");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
            root.join("checkpoint.json"),
        ));
        let transport = Arc::new(ThreadRecordingTransport::default());
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *transport.blocking_chunk.lock().unwrap() =
            Some((Arc::clone(&entered), Arc::clone(&release)));

        let collector_grants = grants.clone();
        let collector_checkpoints = Arc::clone(&checkpoints);
        let collector_transport = Arc::clone(&transport);
        let collector = thread::spawn(move || {
            collect_cloud_sessions_once(
                &collector_grants,
                &collector_checkpoints,
                &CursorRecordingPages::new(vec![page("admitted-chunk", None)]),
                collector_transport.as_ref(),
                now(),
            )
        });
        entered.wait();
        grants.revoke(now()).unwrap();
        let waiter_checkpoints = Arc::clone(&checkpoints);
        let (stopped_tx, stopped_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            stopped_tx
                .send(waiter_checkpoints.wait_for_collector_io_idle(Duration::from_secs(2)))
                .unwrap();
        });
        assert!(stopped_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release.wait();
        stopped_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        waiter.join().unwrap();
        assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Noop);
        assert_eq!(transport.chunks.load(Ordering::SeqCst), 1);
        assert_eq!(transport.finalizes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn health_update_cannot_restore_a_revoked_grant() {
        let (grants, _checkpoints) = stores("grant-lock");
        enabled(&grants);
        grants.revoke(now()).unwrap();
        grants.record_health("ok", "fresh", None).unwrap();
        let grant = grants.load().unwrap().unwrap();
        assert_eq!(grant.status, CloudSessionGrantStatus::Revoked);
        assert_eq!(grant.last_collector_health.as_deref(), Some("revoked"));
    }

    #[test]
    fn pagination_is_bounded_and_cursors_are_not_checkpointed() {
        let (grants, checkpoints) = stores("pages");
        enabled(&grants);
        let mut pages = (0..MAX_PAGES)
            .map(|index| {
                page(
                    &format!("provider-{index}"),
                    Some(&format!("cursor-{index}")),
                )
            })
            .collect::<Vec<_>>();
        pages.push(page("must-not-read", None));
        let runner = Pages {
            pages: RefCell::new(pages),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(runner.calls.get(), MAX_PAGES);
        assert!(transport.batches.borrow().is_empty());
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &runner,
                &transport,
                now() + TimeDuration::minutes(5),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(runner.calls.get(), MAX_PAGES + 1);
        let batches = transport.batches.borrow();
        assert_eq!(batches[0].observations.len(), MAX_PAGES + 1);
        assert_eq!(batches[0].batch_kind, CloudSessionBatchKind::Snapshot);
        assert!(batches[0].snapshot_complete);
        assert_eq!(batches[0].health.state, "healthy");
        assert!(!String::from_utf8(fs::read(&checkpoints.path).unwrap())
            .unwrap()
            .contains("cursor-"));
    }

    #[test]
    fn terminal_multi_page_enumeration_is_complete() {
        let (grants, checkpoints) = stores("terminal-pages");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![
                page("one", Some("cursor-1")),
                page("two", Some("cursor-2")),
                page("three", Some("cursor-3")),
                page("four", None),
            ]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };

        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(runner.calls.get(), 4);
        let batches = transport.batches.borrow();
        assert_eq!(batches[0].observations.len(), 4);
        assert!(batches[0].snapshot_complete);
    }

    #[test]
    fn overfull_provider_page_is_never_absence_authoritative() {
        let (grants, checkpoints) = stores("overfull-page");
        enabled(&grants);
        let tasks = (0..PAGE_LIMIT + 1)
            .map(|id| json!({"id": format!("provider-{id}"), "status": "running"}))
            .collect::<Vec<_>>();
        let runner = Pages {
            pages: RefCell::new(vec![json!({"tasks": tasks, "cursor": null}).to_string()]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };

        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let batches = transport.batches.borrow();
        assert_eq!(batches[0].observations.len(), PAGE_LIMIT);
        assert!(!batches[0].snapshot_complete);
        assert_eq!(batches[0].health.state, "degraded");
        assert_eq!(
            batches[0].health.error_category.as_deref(),
            Some("provider_error")
        );
        assert!(checkpoints.load().last_complete_snapshot_at.is_none());
    }

    #[test]
    fn transport_failures_open_a_bounded_circuit() {
        let (grants, checkpoints) = stores("circuit");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: true,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::CircuitOpen
        );
        assert_eq!(runner.calls.get(), 1);
    }

    #[test]
    fn collector_cadence_and_backoff_remain_load_bounded() {
        assert_eq!(POLL_INTERVAL, Duration::from_secs(5 * 60));
        assert_eq!(MAX_JITTER, Duration::from_secs(20));
        assert!(MAX_JITTER < POLL_INTERVAL);
        assert_eq!(HEALTH_HEARTBEAT_INTERVAL, TimeDuration::hours(1));
        assert_eq!(backoff_seconds(1), 120);
        assert_eq!(backoff_seconds(6), 3_840);
        assert_eq!(backoff_seconds(100), 3_840);
    }

    #[test]
    fn admitted_relay_deadline_fits_inside_local_stop_wait() {
        let timeout = remaining_relay_budget(Instant::now() + CYCLE_BUDGET).unwrap();
        assert_eq!(timeout, RELAY_IO_TIMEOUT);
        assert!(RELAY_IO_TIMEOUT < COLLECTOR_IO_STOP_TIMEOUT);
    }

    #[test]
    fn deferred_transport_does_not_call_the_provider() {
        let (grants, checkpoints) = stores("deferred");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &runner,
                &DeferredCloudSessionTransport,
                now(),
            ),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(runner.calls.get(), 0);
    }

    #[test]
    fn deferred_transport_is_explicit_and_disallows_cli_invocation() {
        let (grants, _checkpoints) = stores("deferred-status");
        enabled(&grants);
        let status = cloud_session_collector_status(&grants, &DeferredCloudSessionTransport);
        assert_eq!(status.schema_version, "cloud_session_collector_status.v1");
        assert_eq!(
            status.runtime_state,
            CloudSessionRuntimeState::TransportDeferred
        );
        assert_eq!(status.reason_code, "transport_deferred");
        assert!(!status.transport_configured);
        assert!(!status.provider_cli_invocation_permitted);
    }

    #[test]
    fn two_hundred_item_fixture_stays_inside_batch_caps() {
        let (grants, checkpoints) = stores("load");
        enabled(&grants);
        let batch_page = |start: u32, cursor: Value| {
            let tasks = (start..start + PAGE_LIMIT as u32)
                .map(|id| {
                    json!({"id":format!("provider-{id}"),"status":"running","updated_at":"2026-07-21T11:00:00Z"})
                })
                .collect::<Vec<_>>();
            json!({"tasks":tasks,"cursor":cursor}).to_string()
        };
        let pages = (0..MAX_PAGES)
            .map(|index| {
                let cursor = if index + 1 == MAX_PAGES {
                    Value::Null
                } else {
                    json!(format!("cursor-{}", index + 1))
                };
                batch_page((index * PAGE_LIMIT) as u32, cursor)
            })
            .collect::<Vec<_>>();
        let runner = Pages {
            pages: RefCell::new(pages),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(runner.calls.get(), MAX_PAGES);
        let batches = transport.batches.borrow();
        assert_eq!(batches[0].observations.len(), MAX_ITEMS);
        assert!(batches[0].snapshot_complete);

        let mut oversized = serde_json::to_value(&batches[0]).unwrap();
        let row = oversized["observations"][0].clone();
        oversized["observations"] = Value::Array(vec![row; MAX_ITEMS + 1]);
        assert!(serde_json::from_value::<CloudSessionObservationBatchV1>(oversized).is_err());
    }

    #[test]
    fn hundred_full_pages_emit_ten_ordered_chunks_with_reproducible_digests() {
        let (grants, checkpoints) = stores("v2-two-thousand");
        enabled(&grants);
        let pages = (0..MAX_SCAN_PAGES)
            .map(|index| {
                let cursor =
                    (index + 1 < MAX_SCAN_PAGES).then(|| format!("private-cursor-{}", index + 1));
                full_page(index * PAGE_LIMIT, cursor.as_deref())
            })
            .collect::<Vec<_>>();
        let first_runner = CursorRecordingPages::new(pages.clone());
        let transport = V2RecordingTransport::new();
        assert_eq!(
            run_full_scan_cycles(&grants, &checkpoints, &first_runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let first_chunks = transport.chunks.borrow().clone();
        let first_finalizes = transport.finalizes.borrow().clone();
        assert_eq!(first_chunks.len(), MAX_SCAN_CHUNKS);
        assert_eq!(first_finalizes.len(), 1);
        assert_eq!(first_runner.cursors.borrow().len(), MAX_SCAN_PAGES);
        for (index, chunk) in first_chunks.iter().enumerate() {
            assert_eq!(usize::from(chunk.chunk_index), index);
            assert_eq!(chunk.observations.len(), MAX_ITEMS);
            assert!(chunk.validate_wire_contract().is_ok());
        }
        let finalize = &first_finalizes[0];
        assert_eq!(finalize.chunk_count, MAX_SCAN_CHUNKS as u8);
        assert_eq!(finalize.unique_entity_count, MAX_SCAN_ITEMS as u32);
        assert_eq!(finalize.provider_page_count, MAX_SCAN_PAGES as u16);
        assert_eq!(
            finalize.enumeration_consistency,
            CloudSessionEnumerationConsistencyV2::UnstableCursor
        );
        assert_eq!(transport.revalidation_calls.get(), 111);

        let second_runner = CursorRecordingPages::new(pages);
        assert_eq!(
            run_full_scan_cycles(
                &grants,
                &checkpoints,
                &second_runner,
                &transport,
                now() + TimeDuration::days(1),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        let all_chunks = transport.chunks.borrow();
        let all_finalizes = transport.finalizes.borrow();
        assert_eq!(all_chunks.len(), MAX_SCAN_CHUNKS * 2);
        assert_eq!(all_finalizes.len(), 2);
        let first_digests = first_chunks
            .iter()
            .map(|chunk| {
                (
                    chunk.chunk_identity_digest.clone(),
                    chunk.chunk_semantic_digest.clone(),
                )
            })
            .collect::<Vec<_>>();
        let second_digests = all_chunks[MAX_SCAN_CHUNKS..]
            .iter()
            .map(|chunk| {
                (
                    chunk.chunk_identity_digest.clone(),
                    chunk.chunk_semantic_digest.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(first_digests, second_digests);
        assert_eq!(
            all_finalizes[0].inventory_digest,
            all_finalizes[1].inventory_digest
        );
        assert_eq!(all_finalizes[0].epoch_digest, all_finalizes[1].epoch_digest);
    }

    #[test]
    fn v2_digest_vectors_are_length_framed_canonical_and_time_independent() {
        let observation =
            |entity_key: &str, lifecycle: &str, attempt_count: u64, observed_at: &str| {
                CloudSessionObservationEntityV1 {
                    entity_key: entity_key.to_string(),
                    entity_kind: "task".to_string(),
                    lifecycle: lifecycle.to_string(),
                    attempt_count: Some(attempt_count),
                    environment_kind: "unknown".to_string(),
                    measurement_basis: "not_itemized".to_string(),
                    coverage: vec![
                        "identity".to_string(),
                        "status".to_string(),
                        "attempts".to_string(),
                    ],
                    created_at: None,
                    started_at: None,
                    updated_at: None,
                    completed_at: None,
                    observed_at: observed_at.to_string(),
                }
            };
        let observations = vec![
            observation("hmac-sha256:bbb", "completed", 2, "2026-07-22T12:00:00Z"),
            observation("hmac-sha256:aaa", "running", 1, "2026-07-21T12:00:00Z"),
        ];
        let identity = identity_digest(&observations);
        let semantic = observation_semantic_digest(&observations).unwrap();
        assert_eq!(
            identity,
            "sha256:0f2a9c1e8c76bc324c48c94f599300459ac7366f20fd55ec694ee3ed6c26acdd"
        );
        assert_eq!(
            semantic,
            "sha256:b2767eb1db14b24806318c50131b712b6ef8fa4a402204e75d462d975fc6112f"
        );
        let mut different_observed_at = observations.clone();
        for row in &mut different_observed_at {
            row.observed_at = "2026-08-01T00:00:00Z".to_string();
        }
        assert_eq!(
            semantic,
            observation_semantic_digest(&different_observed_at).unwrap()
        );
        let chunk = CloudSessionObservationChunkV2 {
            grant_id: GRANT_ID.to_string(),
            grant_version: 1,
            grant_scope_fingerprint: "hmac-sha256:grant".to_string(),
            collector_id: COLLECTOR_ID.to_string(),
            schema_version: CHUNK_SCHEMA_VERSION.to_string(),
            collector_version: compiled_release_version(),
            account_fingerprint: "hmac-sha256:account".to_string(),
            scan_id: "00000000-0000-4000-8000-000000000099".to_string(),
            scan_started_at: "2026-07-21T12:00:00Z".to_string(),
            chunk_index: 0,
            chunk_identity_digest: identity,
            chunk_semantic_digest: semantic,
            observations,
            health: CloudSessionCollectorHealthV1 {
                state: "healthy".to_string(),
                observed_at: "2026-07-21T12:00:00Z".to_string(),
                error_category: None,
            },
        };
        assert_eq!(
            epoch_digest(&[chunk]),
            "sha256:d24b850a0c925663feca0bf99b0e93b1a5ed6a419d5b3096c6693718ddf8a0b9"
        );
    }

    #[test]
    fn hundred_and_one_pages_stop_at_two_thousand_and_never_finalize() {
        let (grants, checkpoints) = stores("v2-cap-partial");
        enabled(&grants);
        let pages = (0..MAX_SCAN_PAGES + 1)
            .map(|index| full_page(index * PAGE_LIMIT, Some(&format!("cursor-{}", index + 1))))
            .collect::<Vec<_>>();
        let runner = CursorRecordingPages::new(pages);
        let transport = V2RecordingTransport::new();
        assert_eq!(
            run_full_scan_cycles(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(runner.cursors.borrow().len(), MAX_SCAN_PAGES);
        assert_eq!(transport.chunks.borrow().len(), MAX_SCAN_CHUNKS);
        assert_eq!(
            transport
                .chunks
                .borrow()
                .iter()
                .map(|chunk| chunk.observations.len())
                .sum::<usize>(),
            MAX_SCAN_ITEMS
        );
        assert!(transport.finalizes.borrow().is_empty());
        assert!(checkpoints.load().last_complete_snapshot_at.is_none());
        assert_eq!(
            grants
                .load()
                .unwrap()
                .unwrap()
                .last_collector_health
                .as_deref(),
            Some("degraded")
        );
        let continuation = CursorRecordingPages::new(
            (0..MAX_PAGES)
                .map(|index| full_page(index * PAGE_LIMIT, Some(&format!("retry-{index}"))))
                .collect(),
        );
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &continuation,
                &transport,
                now() + TimeDuration::minutes(5),
            ),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(
            checkpoints.load().last_error_category.as_deref(),
            Some("scan_incomplete")
        );
        assert_eq!(
            grants
                .load()
                .unwrap()
                .unwrap()
                .last_collector_health
                .as_deref(),
            Some("degraded")
        );
    }

    #[test]
    fn restart_drops_cursor_and_uses_a_new_scan_id_from_page_zero() {
        let root = temp_dir("v2-restart");
        let grants = CloudSessionGrantStore::new(root.join("grant.json"));
        enabled(&grants);
        let checkpoint_path = root.join("checkpoint.json");
        let first_checkpoints = CloudSessionCheckpointStore::new(&checkpoint_path);
        let first_pages = (0..MAX_PAGES)
            .map(|index| full_page(index * PAGE_LIMIT, Some(&format!("cursor-{index}"))))
            .collect::<Vec<_>>();
        let first_runner = CursorRecordingPages::new(first_pages);
        let transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &first_checkpoints,
                &first_runner,
                &transport,
                now(),
            ),
            CloudSessionCycleOutcome::Noop
        );
        let first_scan_id = first_checkpoints
            .runtime
            .lock()
            .unwrap()
            .active
            .as_ref()
            .unwrap()
            .scan_id
            .clone();
        let persisted = String::from_utf8(fs::read(&checkpoint_path).unwrap()).unwrap();
        assert!(!persisted.contains("cursor-"));
        assert!(!persisted.contains(&first_scan_id));

        let restarted = CloudSessionCheckpointStore::new(&checkpoint_path);
        let second_runner = CursorRecordingPages::new(vec![page("after-restart", None)]);
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &restarted,
                &second_runner,
                &transport,
                now() + TimeDuration::minutes(5),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(second_runner.cursors.borrow().as_slice(), &[None]);
        let second_scan_id = transport.finalizes.borrow()[0].scan_id.clone();
        assert_ne!(first_scan_id, second_scan_id);
    }

    #[test]
    fn cross_page_duplicates_collapse_before_chunk_and_inventory_digests() {
        let (grants, checkpoints) = stores("v2-duplicates");
        enabled(&grants);
        let runner = CursorRecordingPages::new(vec![
            json!({"tasks":[
                {"id":"duplicate","status":"queued"},
                {"id":"only-first","status":"running"}
            ],"cursor":"cursor-1"})
            .to_string(),
            json!({"tasks":[
                {"id":"duplicate","status":"completed"},
                {"id":"only-second","status":"running"}
            ],"cursor":null})
            .to_string(),
        ]);
        let transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let chunks = transport.chunks.borrow();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].observations.len(), 3);
        assert_eq!(transport.finalizes.borrow()[0].unique_entity_count, 3);
        assert_eq!(
            chunks[0]
                .observations
                .iter()
                .find(|row| row.lifecycle == "completed")
                .map(|row| row.lifecycle.as_str()),
            Some("completed")
        );
    }

    #[test]
    fn cursor_churn_uploads_only_positive_chunks_and_never_finalizes() {
        let (grants, checkpoints) = stores("v2-cursor-churn");
        enabled(&grants);
        let runner = CursorRecordingPages::new(vec![
            full_page(0, Some("repeated-private-cursor")),
            full_page(PAGE_LIMIT, Some("repeated-private-cursor")),
        ]);
        let transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(
            transport.chunks.borrow()[0].observations.len(),
            PAGE_LIMIT * 2
        );
        assert!(transport.finalizes.borrow().is_empty());
        let wire = serde_json::to_string(&transport.chunks.borrow()[0]).unwrap();
        assert!(!wire.contains("repeated-private-cursor"));
    }

    #[test]
    fn malformed_truncated_and_timeout_paths_cannot_finalize() {
        let scenarios = vec![
            vec![TestPage::Json(
                json!({"tasks":[{"id":"one","status":"running"}],"next_cursor":42}).to_string(),
            )],
            vec![TestPage::Json({
                let tasks = (0..PAGE_LIMIT + 1)
                    .map(|index| json!({"id":format!("over-{index}"),"status":"running"}))
                    .collect::<Vec<_>>();
                json!({"tasks":tasks,"next_cursor":null}).to_string()
            })],
            vec![
                TestPage::Json(page("before-timeout", Some("cursor-before-timeout"))),
                TestPage::Error,
            ],
        ];
        for (index, pages) in scenarios.into_iter().enumerate() {
            let (grants, checkpoints) = stores(&format!("v2-no-finalize-{index}"));
            enabled(&grants);
            let runner = CursorRecordingPages {
                pages: RefCell::new(pages.into_iter().collect()),
                cursors: RefCell::new(Vec::new()),
            };
            let transport = V2RecordingTransport::new();
            let _ = collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now());
            assert!(transport.finalizes.borrow().is_empty(), "scenario {index}");
        }
    }

    #[test]
    fn response_loss_retries_the_exact_same_chunk_before_finalize() {
        let (grants, checkpoints) = stores("v2-response-loss");
        enabled(&grants);
        let runner = CursorRecordingPages::new(vec![page("retry-me", None)]);
        let transport = V2RecordingTransport::new();
        transport.fail_next_chunk.set(true);
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(transport.chunks.borrow().len(), 1);
        assert!(transport.finalizes.borrow().is_empty());
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &runner,
                &transport,
                now() + TimeDuration::minutes(3),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        let chunks = transport.chunks.borrow();
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            serde_json::to_vec(&chunks[0]).unwrap(),
            serde_json::to_vec(&chunks[1]).unwrap()
        );
        assert_eq!(runner.cursors.borrow().len(), 1);
        assert_eq!(transport.finalizes.borrow().len(), 1);
    }

    #[test]
    fn unchanged_head_poll_has_zero_observation_upload_but_revalidates_then_runs_cadence() {
        let (grants, checkpoints) = stores("v2-head-cadence");
        enabled(&grants);
        let transport = V2RecordingTransport::new();
        let initial = CursorRecordingPages::new(vec![page("stable", None)]);
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &initial, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(transport.chunks.borrow().len(), 1);
        assert_eq!(transport.finalizes.borrow().len(), 1);

        let head = CursorRecordingPages::new(vec![page("stable", None)]);
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &head,
                &transport,
                now() + TimeDuration::minutes(5),
            ),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(transport.chunks.borrow().len(), 1);
        assert_eq!(transport.finalizes.borrow().len(), 1);
        assert!(transport.heartbeats.borrow().is_empty());
        assert_eq!(transport.revalidation_calls.get(), 4);

        let hourly = CursorRecordingPages::new(vec![page("stable", None)]);
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &hourly,
                &transport,
                now() + TimeDuration::minutes(61),
            ),
            CloudSessionCycleOutcome::Heartbeat
        );
        assert_eq!(transport.heartbeats.borrow().len(), 1);
        assert_eq!(transport.revalidation_calls.get(), 6);

        let daily = CursorRecordingPages::new(vec![page("stable", None)]);
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &daily,
                &transport,
                now() + TimeDuration::days(1),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(transport.chunks.borrow().len(), 2);
        assert_eq!(transport.finalizes.borrow().len(), 2);
        assert_eq!(transport.revalidation_calls.get(), 9);
    }

    #[test]
    fn single_terminal_provider_response_is_marked_single_response() {
        let (grants, checkpoints) = stores("v2-single-response");
        enabled(&grants);
        let runner = CursorRecordingPages::new(vec![page("single", None)]);
        let transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let finalize = &transport.finalizes.borrow()[0];
        assert_eq!(finalize.provider_page_count, 1);
        assert_eq!(
            finalize.enumeration_consistency,
            CloudSessionEnumerationConsistencyV2::SingleResponse
        );
    }

    #[test]
    fn official_cursor_drives_bounded_multi_page_scan_without_absence_authority() {
        let (grants, checkpoints) = stores("v2-official-cursor");
        enabled(&grants);
        let runner = CursorRecordingPages::new(vec![
            full_page(0, Some("official-page-two")),
            page("official-terminal", None),
        ]);
        let transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(
            runner.cursors.borrow().as_slice(),
            &[None, Some("official-page-two".to_string())]
        );
        let finalizes = transport.finalizes.borrow();
        assert_eq!(finalizes.len(), 1);
        let finalize = &finalizes[0];
        assert_eq!(finalize.provider_page_count, 2);
        assert_eq!(finalize.unique_entity_count, 21);
        assert!(finalize.terminal_reached);
        assert_eq!(
            finalize.enumeration_consistency,
            CloudSessionEnumerationConsistencyV2::UnstableCursor
        );
        assert_ne!(
            finalize.enumeration_consistency,
            CloudSessionEnumerationConsistencyV2::SingleResponse
        );
    }

    #[test]
    fn ambiguous_legacy_shapes_upload_positive_facts_without_finalize() {
        for (name, raw) in [
            (
                "fieldless",
                json!({"tasks": [{"id": "fieldless-positive", "status": "running"}]}),
            ),
            (
                "alias-null",
                json!({
                    "tasks": [{"id": "alias-null-positive", "status": "running"}],
                    "next_cursor": null
                }),
            ),
            (
                "array-root",
                json!([{"id": "array-positive", "status": "running"}]),
            ),
        ] {
            let (grants, checkpoints) = stores(&format!("ambiguous-positive-{name}"));
            enabled(&grants);
            let runner = CursorRecordingPages::new(vec![raw.to_string()]);
            let transport = V2RecordingTransport::new();
            assert_eq!(
                collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
                CloudSessionCycleOutcome::Uploaded,
                "{name}"
            );
            assert_eq!(transport.chunks.borrow().len(), 1, "{name}");
            assert_eq!(transport.chunks.borrow()[0].observations.len(), 1, "{name}");
            assert_eq!(
                transport.chunks.borrow()[0].health.state,
                "degraded",
                "{name}"
            );
            assert!(transport.finalizes.borrow().is_empty(), "{name}");
            assert!(
                checkpoints.load().last_complete_snapshot_at.is_none(),
                "{name}"
            );
        }
    }

    #[test]
    fn ambiguous_empty_shapes_fail_without_chunks_or_finalize() {
        for (name, raw) in [
            ("fieldless", json!({"tasks": []})),
            ("alias-null", json!({"tasks": [], "next_cursor": null})),
            ("array-root", json!([])),
        ] {
            let (grants, checkpoints) = stores(&format!("ambiguous-empty-{name}"));
            enabled(&grants);
            let runner = CursorRecordingPages::new(vec![raw.to_string()]);
            let transport = V2RecordingTransport::new();
            assert_eq!(
                collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
                CloudSessionCycleOutcome::Failed,
                "{name}"
            );
            assert!(transport.chunks.borrow().is_empty(), "{name}");
            assert!(transport.finalizes.borrow().is_empty(), "{name}");
            assert!(
                checkpoints.load().last_complete_snapshot_at.is_none(),
                "{name}"
            );
        }
    }

    #[test]
    fn v2_wire_and_persisted_checkpoint_never_contain_provider_cursor_or_raw_identity() {
        let (grants, checkpoints) = stores("v2-wire-privacy");
        enabled(&grants);
        let runner = CursorRecordingPages::new(
            (0..MAX_PAGES)
                .map(|index| {
                    page(
                        &format!("raw-provider-private-id-{index}"),
                        Some(&format!("raw-private-cursor-{index}")),
                    )
                })
                .collect(),
        );
        let transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Noop
        );
        let persisted = String::from_utf8(fs::read(&checkpoints.path).unwrap()).unwrap();
        assert!(!persisted.contains("raw-private-cursor"));
        assert!(!persisted.contains("raw-provider-private-id"));
        let active = checkpoints.runtime.lock().unwrap();
        let scan = active.active.as_ref().unwrap();
        assert_ne!(scan.cursor.as_deref(), None);
        assert!(!scan
            .observations
            .keys()
            .any(|key| key == "raw-provider-private-id"));
    }
}
