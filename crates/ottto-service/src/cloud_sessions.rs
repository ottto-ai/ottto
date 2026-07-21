//! Supported, metadata-only Codex Cloud session collector.
//!
//! The collector invokes only `codex cloud list --json` as the effective user.
//! It never opens `auth.json`, touches Keychain credentials, or calls provider
//! endpoints directly. Raw CLI JSON, task titles, URLs, provider ids, and
//! cursors are used only in memory to derive content-free observations.

use anyhow::{anyhow, Context, Result};
use getrandom::fill as random_fill;
use hmac::{Hmac, Mac};
use ottto_core::{compiled_release_version, default_support_dir, LocalDeviceBinding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

const COLLECTOR_ID: &str = "cloud_sessions";
const COLLECTOR_VERSION: &str = "cloud_session_observations.v1";
const GRANT_SCHEMA_VERSION: &str = "cloud_session_grant.v1";
const CHECKPOINT_SCHEMA_VERSION: &str = "cloud_session_checkpoint.v1";
const MAX_PAGES: usize = 3;
const MAX_ITEMS: usize = 60;
const PAGE_LIMIT: usize = 20;
const CYCLE_BUDGET: Duration = Duration::from_secs(45);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);
const POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);
const HEALTH_HEARTBEAT_INTERVAL: TimeDuration = TimeDuration::hours(1);
const MAX_JITTER: Duration = Duration::from_secs(20);
const KILL_SWITCH_ENV: &str = "OTTTO_CODEX_CLOUD_SESSIONS_DISABLED";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSessionServerPolicyState {
    Approved,
    Disabled,
}

impl Default for CloudSessionServerPolicyState {
    fn default() -> Self {
        Self::Disabled
    }
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

/// Strict subset of the authenticated backend grant response needed to bind
/// collection. The daemon never acquires or persists the user's web JWT; the
/// companion/UI owns POST/DELETE consent and hands this response back locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionBackendGrantResponseV1 {
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
    /// Required and strictly decoded. Missing or unknown values cannot make a
    /// local grant runtime-ready.
    pub server_policy_state: CloudSessionServerPolicyState,
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
        if !state.grant.backend_create_pending {
            return Err(anyhow!(
                "cloud-session backend grant response has no pending authenticated create"
            ));
        }
        validate_local_installation_binding(
            &state,
            expected_installation_id,
            "backend cloud-session grant",
        )?;
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
            return Err(anyhow!(
                "local cloud-session consent was revoked; backend grant must be deleted"
            ));
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
        if response.id != existing.grant_id || response.grant_version < existing.grant_version {
            return Err(anyhow!(
                "backend cloud-session grant revalidation does not match"
            ));
        }
        if !matches!(response.status.as_str(), "enabled" | "revoked") {
            return Err(anyhow!("backend cloud-session grant status is invalid"));
        }
        let backend_revoked = response.status == "revoked";
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
        self.write(&state)?;
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
/// Codex. The default service wiring deliberately passes the deferred
/// transport, which makes provider CLI use impossible in this public slice.
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
    cloud_session_collector_status(
        &CloudSessionGrantStore::default(),
        &DeferredCloudSessionTransport,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionObservationBatchV1 {
    pub grant_id: String,
    pub grant_version: u64,
    pub grant_scope_fingerprint: String,
    pub collector_id: String,
    pub schema_version: String,
    pub collector_version: String,
    pub account_fingerprint: String,
    pub collected_at: String,
    pub observations: Vec<CloudSessionObservationEntityV1>,
    pub health: CloudSessionCollectorHealthV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct CloudSessionCollectorHealthV1 {
    pub state: String,
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CloudSessionCheckpoint {
    schema_version: String,
    semantic_digest: Option<String>,
    consecutive_failures: u32,
    circuit_open_until: Option<String>,
    last_error_category: Option<String>,
    last_success_at: Option<String>,
    last_health_upload_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CloudSessionCheckpointStore {
    path: PathBuf,
}

impl CloudSessionCheckpointStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
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
        Self::new(
            default_support_dir()
                .join("cloud_sessions")
                .join("checkpoint.json"),
        )
    }
}

pub trait CloudSessionRunner {
    /// `cursor` may only be retained by the caller for this single cycle.
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String>;
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
    fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()>;
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

/// Prepared relay transport for the strict backend route. It deliberately is
/// not used by `spawn_cloud_session_collector`: production activation remains a
/// separate release/deployment/retention gate. When explicitly composed, it
/// reuses one in-memory relay token and refreshes it once on 401/403.
/// Ordinary-user grant revalidation must be supplied separately, so this
/// adapter alone never reports a collection-ready transport.
pub struct RelayCloudSessionTransport {
    client: crate::snapshot_client::SnapshotApiClient,
    device: LocalDeviceBinding,
    device_secret: String,
    relay_token: Mutex<Option<String>>,
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
        }
    }

    fn token(&self, force_refresh: bool) -> Result<String> {
        let mut cached = self
            .relay_token
            .lock()
            .map_err(|_| anyhow!("cloud-session relay token lock is unavailable"))?;
        if force_refresh {
            *cached = None;
        }
        if let Some(token) = cached.as_ref() {
            return Ok(token.clone());
        }
        let token = self.client.issue_relay_token(
            &self.device,
            &self.device_secret,
            crate::snapshots::SnapshotSource::Codex,
        )?;
        *cached = Some(token.clone());
        Ok(token)
    }
}

impl CloudSessionTransport for RelayCloudSessionTransport {
    fn is_configured(&self) -> bool {
        !self.device_secret.is_empty()
            && is_uuid(&self.device.device_id)
            && self.device.sources.iter().any(|source| source == "codex")
    }

    fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
        if !self.is_configured() {
            return Err(anyhow!("cloud-session relay transport is not source-bound"));
        }
        let request = serde_json::to_value(batch)?;
        let token = self.token(false)?;
        match self.client.upload_cloud_session_batch(&token, &request) {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .downcast_ref::<crate::snapshot_client::CloudSessionAuthorizationRejected>()
                    .is_some() =>
            {
                let refreshed = self.token(true)?;
                self.client
                    .upload_cloud_session_batch(&refreshed, &request)
                    .map(|_| ())
            }
            Err(error) => Err(error),
        }
    }
}

pub struct CodexCloudCliRunner;
impl CloudSessionRunner for CodexCloudCliRunner {
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String> {
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
                .take((MAX_ITEMS * 256 * 1024) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let started = Instant::now();
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
                Ok(None) if started.elapsed() >= COMMAND_TIMEOUT => {
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
    if kill_switch_enabled() || !grant_preflight_eligible(grants) {
        return CloudSessionCycleOutcome::Disabled;
    }
    if !transport.is_configured() || !transport.supports_grant_revalidation() {
        let _ = grants.record_health("unavailable", "unavailable", Some("transport_unconfigured"));
        return CloudSessionCycleOutcome::Noop;
    }
    let mut checkpoint = checkpoints.load();
    if circuit_open(&checkpoint, now) {
        return CloudSessionCycleOutcome::CircuitOpen;
    }
    let result = collect_enabled_cycle(grants, &checkpoint, runner, transport, now);
    match result {
        Ok(CycleResult::Noop) => {
            checkpoint.consecutive_failures = 0;
            checkpoint.circuit_open_until = None;
            checkpoint.last_error_category = None;
            checkpoint.last_success_at = Some(timestamp(now));
            let _ = checkpoints.save(&checkpoint);
            let _ = grants.record_health("ok", "fresh", None);
            CloudSessionCycleOutcome::Noop
        }
        Ok(CycleResult::Heartbeat) => {
            checkpoint.consecutive_failures = 0;
            checkpoint.circuit_open_until = None;
            checkpoint.last_error_category = None;
            checkpoint.last_success_at = Some(timestamp(now));
            checkpoint.last_health_upload_at = Some(timestamp(now));
            let _ = checkpoints.save(&checkpoint);
            let _ = grants.record_health("ok", "fresh", None);
            CloudSessionCycleOutcome::Heartbeat
        }
        Ok(CycleResult::Uploaded(digest)) => {
            checkpoint.semantic_digest = Some(digest);
            checkpoint.consecutive_failures = 0;
            checkpoint.circuit_open_until = None;
            checkpoint.last_error_category = None;
            checkpoint.last_success_at = Some(timestamp(now));
            checkpoint.last_health_upload_at = Some(timestamp(now));
            let _ = checkpoints.save(&checkpoint);
            let _ = grants.record_health("ok", "fresh", None);
            CloudSessionCycleOutcome::Uploaded
        }
        Err(error) => {
            checkpoint.consecutive_failures = checkpoint.consecutive_failures.saturating_add(1);
            checkpoint.last_error_category = Some(error.category.to_string());
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

enum CycleResult {
    Noop,
    Heartbeat,
    Uploaded(String),
}
#[derive(Debug)]
struct CycleError {
    category: &'static str,
    health_uploaded: bool,
}

fn collect_enabled_cycle(
    grants: &CloudSessionGrantStore,
    checkpoint: &CloudSessionCheckpoint,
    runner: &dyn CloudSessionRunner,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
) -> std::result::Result<CycleResult, CycleError> {
    let mut state = grants
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
    let response = transport
        .revalidate_grant(&state.grant)
        .map_err(|_| CycleError {
            category: "grant_revalidation_unavailable",
            health_uploaded: false,
        })?;
    grants
        .apply_backend_grant_revalidation(&response)
        .map_err(|_| CycleError {
            category: "grant_revalidation_invalid",
            health_uploaded: false,
        })?;
    state = grants
        .read()
        .map_err(|_| CycleError {
            category: "grant_unavailable",
            health_uploaded: false,
        })?
        .ok_or(CycleError {
            category: "grant_absent",
            health_uploaded: false,
        })?;
    if kill_switch_enabled() || !cloud_grant_runtime_ready(&state.grant) {
        return Ok(CycleResult::Noop);
    }
    let key = decode_hex(&state.hmac_key_hex)
        .filter(|key| key.len() == 32)
        .ok_or(CycleError {
            category: "grant_invalid",
            health_uploaded: false,
        })?;
    let deadline = Instant::now() + CYCLE_BUDGET;
    let mut cursor: Option<String> = None;
    let mut entities = Vec::new();
    for _ in 0..MAX_PAGES {
        if Instant::now() >= deadline || entities.len() >= MAX_ITEMS {
            break;
        }
        // Pause/revoke is a local control boundary, not merely an upload
        // boundary. Check it before every paginated provider call.
        if !grant_still_current(grants, &state.grant) || kill_switch_enabled() {
            return Ok(CycleResult::Noop);
        }
        let raw = match runner.list_page(cursor.as_deref(), PAGE_LIMIT) {
            Ok(raw) => raw,
            Err(_) => {
                if !grant_still_current(grants, &state.grant) || kill_switch_enabled() {
                    return Ok(CycleResult::Noop);
                }
                report_provider_failure(&state.grant, transport, now)?;
                return Err(CycleError {
                    category: "provider_unavailable",
                    health_uploaded: true,
                });
            }
        };
        let page = match parse_cloud_page(&raw, &key, now) {
            Ok(page) => page,
            Err(_) => {
                if !grant_still_current(grants, &state.grant) || kill_switch_enabled() {
                    return Ok(CycleResult::Noop);
                }
                report_provider_failure(&state.grant, transport, now)?;
                return Err(CycleError {
                    category: "provider_payload_invalid",
                    health_uploaded: true,
                });
            }
        };
        if page.invalid_required_rows > 0
            || (page.source_item_count > 0 && page.entities.is_empty())
        {
            if !grant_still_current(grants, &state.grant) || kill_switch_enabled() {
                return Ok(CycleResult::Noop);
            }
            report_provider_failure(&state.grant, transport, now)?;
            return Err(CycleError {
                category: "provider_payload_invalid",
                health_uploaded: true,
            });
        }
        let count = (MAX_ITEMS - entities.len()).min(page.entities.len());
        entities.extend(page.entities.into_iter().take(count));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    entities.sort_by(|left, right| left.entity_key.cmp(&right.entity_key));
    entities.dedup_by(|left, right| left.entity_key == right.entity_key);
    let digest = semantic_digest(&state.grant, &entities).map_err(|_| CycleError {
        category: "digest_failed",
        health_uploaded: false,
    })?;
    if checkpoint.semantic_digest.as_deref() == Some(digest.as_str()) {
        if checkpoint.last_error_category.is_none() && !health_heartbeat_due(checkpoint, now) {
            return Ok(CycleResult::Noop);
        }
        if kill_switch_enabled() || !grant_still_current(grants, &state.grant) {
            return Ok(CycleResult::Noop);
        }
        let batch = observation_batch(&state.grant, Vec::new(), now)?;
        transport.send(&batch).map_err(|_| CycleError {
            category: "transport_unavailable",
            health_uploaded: false,
        })?;
        return Ok(CycleResult::Heartbeat);
    }
    // Re-read immediately before transport so a local pause/revoke wins over a
    // concurrent in-flight parse and stops network use before the next upload.
    if kill_switch_enabled() || !grant_still_current(grants, &state.grant) {
        return Ok(CycleResult::Noop);
    }
    let batch = observation_batch(&state.grant, entities, now)?;
    transport.send(&batch).map_err(|_| CycleError {
        category: "transport_unavailable",
        health_uploaded: false,
    })?;
    Ok(CycleResult::Uploaded(digest))
}

struct ParsedPage {
    entities: Vec<CloudSessionObservationEntityV1>,
    next_cursor: Option<String>,
    source_item_count: usize,
    invalid_required_rows: usize,
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
    let source_item_count = items.len().min(PAGE_LIMIT);
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
        let attempt_count = u64_field(object, &["attempt_count", "attempts"])
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
    Ok(ParsedPage {
        entities,
        next_cursor: string_value(root.get("next_cursor"))
            .or_else(|| string_value(root.get("nextCursor")))
            .map(str::to_string),
        source_item_count,
        invalid_required_rows,
    })
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
}
fn string_value(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
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
        "queued" | "pending" => "queued",
        "running" | "in_progress" => "running",
        "completed" | "succeeded" | "success" => "completed",
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

fn semantic_digest(
    grant: &CloudSessionGrant,
    entities: &[CloudSessionObservationEntityV1],
) -> Result<String> {
    let binding = grant
        .backend_binding
        .as_ref()
        .ok_or_else(|| anyhow!("backend cloud-session grant is unbound"))?;
    let semantics = entities
        .iter()
        .map(|entity| {
            let mut value = serde_json::to_value(entity)?;
            value
                .as_object_mut()
                .map(|object| object.remove("observed_at"));
            Ok(value)
        })
        .collect::<Result<Vec<_>>>()?;
    let payload = serde_json::to_vec(&json!({
        "schema_version":"cloud_session_observations.v1",
        "collector_version": grant.collector_version,
        "grant_id": binding.grant_id,
        "grant_version": binding.grant_version,
        "observations": semantics,
    }))?;
    Ok(sha256(&payload))
}

fn observation_batch(
    grant: &CloudSessionGrant,
    observations: Vec<CloudSessionObservationEntityV1>,
    now: OffsetDateTime,
) -> std::result::Result<CloudSessionObservationBatchV1, CycleError> {
    observation_batch_with_health(
        grant,
        observations,
        now,
        CloudSessionCollectorHealthV1 {
            state: "healthy".to_string(),
            observed_at: timestamp(now),
            error_category: None,
        },
    )
}

fn observation_batch_with_health(
    grant: &CloudSessionGrant,
    observations: Vec<CloudSessionObservationEntityV1>,
    now: OffsetDateTime,
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
    Ok(CloudSessionObservationBatchV1 {
        grant_id: binding.grant_id.clone(),
        grant_version: binding.grant_version,
        grant_scope_fingerprint: grant.grant_scope_id.clone(),
        collector_id: COLLECTOR_ID.to_string(),
        schema_version: COLLECTOR_VERSION.to_string(),
        collector_version: grant.collector_version.clone(),
        account_fingerprint: grant.account_fingerprint.clone(),
        collected_at: timestamp(now),
        observations,
        health,
    })
}

fn report_provider_failure(
    grant: &CloudSessionGrant,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
) -> std::result::Result<(), CycleError> {
    let batch = observation_batch_with_health(
        grant,
        Vec::new(),
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
    transport.send(&batch).map_err(|_| CycleError {
        category: "transport_unavailable",
        health_uploaded: false,
    })
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
            && current.collector_version == expected.collector_version
            && current.grant_scope_id == expected.grant_scope_id
            && current.account_fingerprint == expected.account_fingerprint
            && current.backend_binding == expected.backend_binding
            && current
                .backend_binding
                .is_some_and(|binding| !binding.backend_revoked)
    })
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
fn circuit_open(checkpoint: &CloudSessionCheckpoint, now: OffsetDateTime) -> bool {
    checkpoint
        .circuit_open_until
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .is_some_and(|until| until > now)
}
fn backoff_seconds(failures: u32) -> u64 {
    60 * (1_u64 << failures.min(6))
}
fn kill_switch_enabled() -> bool {
    std::env::var(KILL_SWITCH_ENV).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}
fn timestamp(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}
fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
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

pub fn spawn_cloud_session_collector() -> Result<CloudSessionCollectorStartup> {
    // Public builds have no ingest endpoint. Do not register a poller that
    // merely looks active: deferred transport means no runner is constructed
    // and no provider CLI process can be started.
    let transport = DeferredCloudSessionTransport;
    if !transport.is_configured() || !transport.supports_grant_revalidation() {
        return Ok(CloudSessionCollectorStartup::DeferredTransport);
    }
    thread::Builder::new()
        .name("ottto-codex-cloud-sessions".to_string())
        .spawn(|| {
            let grants = CloudSessionGrantStore::default();
            let checkpoints = CloudSessionCheckpointStore::default();
            let runner = CodexCloudCliRunner;
            let transport = DeferredCloudSessionTransport;
            loop {
                let outcome = collect_cloud_sessions_once(
                    &grants,
                    &checkpoints,
                    &runner,
                    &transport,
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
        })
        .map_err(|error| anyhow!("spawn Codex cloud-session collector: {error}"))?;
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
    use std::sync::atomic::{AtomicU64, Ordering};

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

        fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.calls.set(self.calls.get() + 1);
            self.batches.borrow_mut().push(batch.clone());
            if self.fail {
                Err(anyhow!("offline"))
            } else {
                Ok(())
            }
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

        fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.send_calls.set(self.send_calls.get() + 1);
            Ok(())
        }
    }
    fn page(id: &str, cursor: Option<&str>) -> String {
        json!({"tasks":[{"id":id,"title":"private title","url":"https://example.invalid/private","account_id":"provider-account-private","status":"completed","created_at":"2026-07-21T11:00:00Z","attempt_count":2}], "next_cursor": cursor}).to_string()
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
    fn provider_values_outside_backend_bounds_are_dropped_not_uploaded() {
        let raw = json!({
            "tasks": [{
                "id": "provider-task-unsafe-bounds",
                "status": "running",
                "created_at": "2026-07-21T11:30:00Z",
                "started_at": "2026-07-21T11:00:00Z",
                "updated_at": "2026-07-21T12:30:00Z",
                "attempt_count": 100_001,
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
        assert_eq!(wire["observations"][0]["entity_kind"], "task");
        assert_eq!(wire["observations"][0]["observed_at"], timestamp(now()));
        assert_eq!(wire["health"]["state"], "healthy");
        assert!(wire.get("entities").is_none());
        assert!(wire.get("observed_at").is_none());
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

        grants
            .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
            .unwrap();
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
            response: Some(backend_grant(&disabled, "enabled", 2)),
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
        assert_eq!(approved_transport.revalidation_calls.get(), 1);
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
    fn server_revocation_stops_provider_and_future_preflights() {
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
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(transport.revalidation_calls.get(), 1);
        assert_eq!(runner.calls.get(), 0);
        assert_eq!(transport.send_calls.get(), 0);
        assert_eq!(
            grants.load().unwrap().unwrap().status,
            CloudSessionGrantStatus::Revoked
        );
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &runner,
                &transport,
                now() + TimeDuration::minutes(5),
            ),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(transport.revalidation_calls.get(), 1);
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
        assert!(grants
            .bind_backend_grant(&response, INSTALLATION_ID)
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

        assert!(restarted
            .confirm_backend_grant_absent_after_reconciliation()
            .is_err());
        assert_eq!(
            restarted.grant_create_request(INSTALLATION_ID).unwrap(),
            first
        );
        assert!(restarted
            .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
            .is_err());
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
    fn unchanged_polls_emit_only_hourly_health_heartbeats() {
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
        assert_eq!(transport.calls.get(), 3);
        let batches = transport.batches.borrow();
        assert_eq!(batches[0].observations.len(), 1);
        assert!(batches[1].observations.is_empty());
        assert!(batches[2].observations.is_empty());
        assert_eq!(batches[2].health.state, "healthy");
        let checkpoint = checkpoints.load();
        assert_eq!(
            checkpoint.last_health_upload_at.as_deref(),
            Some("2026-07-21T14:00:00Z")
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
        assert_eq!(batches[1].health.state, "failing");
        assert_eq!(
            batches[1].health.error_category.as_deref(),
            Some("provider_error")
        );
        assert!(batches[2].observations.is_empty());
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
                        r#"{"accepted":1,"observations_written":1,"noop":false,"grant_status":"enabled","fresh_at":"2026-07-21T12:00:00Z"}"#,
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
        let observations = parse_cloud_page(&page("one", None), b"fixture-key", now())
            .unwrap()
            .entities;
        let batch = observation_batch(&grant, observations, now()).unwrap();
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
    fn public_startup_remains_hard_deferred() {
        assert_eq!(
            spawn_cloud_session_collector().unwrap(),
            CloudSessionCollectorStartup::DeferredTransport
        );
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
        assert_eq!(runner.calls.get(), MAX_PAGES);
        assert_eq!(transport.batches.borrow()[0].observations.len(), MAX_PAGES);
        assert!(!String::from_utf8(fs::read(&checkpoints.path).unwrap())
            .unwrap()
            .contains("cursor-"));
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
    fn sixty_item_fixture_stays_inside_page_and_wall_time_caps() {
        let (grants, checkpoints) = stores("load");
        enabled(&grants);
        let batch_page = |start: u32, cursor: Option<&str>| {
            let tasks = (start..start + PAGE_LIMIT as u32)
                .map(|id| {
                    json!({"id":format!("provider-{id}"),"status":"running","updated_at":"2026-07-21T11:00:00Z"})
                })
                .collect::<Vec<_>>();
            json!({"tasks":tasks,"next_cursor":cursor}).to_string()
        };
        let runner = Pages {
            pages: RefCell::new(vec![
                batch_page(0, Some("cursor-1")),
                batch_page(20, Some("cursor-2")),
                batch_page(40, Some("cursor-3")),
            ]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        let started = Instant::now();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(runner.calls.get(), MAX_PAGES);
        assert_eq!(transport.batches.borrow()[0].observations.len(), MAX_ITEMS);
    }
}
