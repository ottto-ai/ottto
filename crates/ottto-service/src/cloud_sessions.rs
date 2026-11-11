//! Supported, metadata-only Codex Cloud session collector.
//!
//! The collector invokes only `codex cloud list --json` as the effective user.
//! It never opens `auth.json`, reads OpenAI credentials, or calls provider
//! endpoints directly. After exact consent and destination checks, it reads
//! only Ottto's relay device credential for Ottto backend authentication. Raw
//! CLI JSON, task titles, URLs, provider ids, and cursors are used only in
//! memory to derive content-free task facts.
//!
//! Each due work slice makes one authority read, lists provider pages and
//! uploads only tasks whose facts changed since their last exact server ACK
//! (`cloud_session_changes.v1`). When it calls the provider is in
//! [`schedule`]; the ACK cache lives in the upload-history SQLite file.

use crate::hex::{decode as decode_hex, encode as hex, is_uuid};
use crate::local_resource_diagnostics::StageWindow;
use crate::locked_state_dir::FileLock;
use crate::snapshots::state_v2::upload_history::{CloudAck, CloudAckWrite};
use anyhow::{anyhow, Context, Result};
use getrandom::fill as random_fill;
use hmac::{Hmac, Mac};
use ottto_core::{
    compiled_release_version, default_support_dir, FileAccountStore, FileConnectionStore,
    FileDeviceStore, LocalDeviceBinding,
};
use ottto_protocol::LocalAccountState;
pub use ottto_protocol::{CloudSessionBackendGrantResponseV1, CloudSessionServerPolicyState};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Date, OffsetDateTime, UtcOffset};

mod schedule;
mod wire;
use schedule::{
    CloudSchedule, Crawl, Due, CRAWL_CONTINUATION_INTERVAL, IDLE_HEAD_INTERVAL, MAX_SLICE_PAGES,
};
pub use wire::{
    CloudSessionChangeAckV1, CloudSessionChangeOutcome, CloudSessionChangeV1,
    CloudSessionChangesAckV1, CloudSessionChangesV1, CloudSessionGrantAuthorityV1,
};
use wire::{Settled, AUTHORITY_SCHEMA_VERSION, CHANGES_SCHEMA_VERSION, MAX_CHANGES_PER_REQUEST};

const COLLECTOR_ID: &str = "cloud_sessions";
const DISCLOSURE_VERSION: &str = "cloud_sessions_disclosure.v1";
const LEGACY_COLLECTION_SCHEMA_VERSION: &str = "cloud_session_observations.v1";
const GRANT_SCHEMA_VERSION: &str = "cloud_session_grant.v1";
const CONTROL_TOKEN_LEDGER_SCHEMA_VERSION: &str = "cloud_session_control_token_uses.v1";
const MAX_CONTROL_TOKEN_USES: usize = 64;
const PAGE_LIMIT: usize = 20;
/// Command-safety bound for one CLI page's stdout, not an inventory ceiling;
/// a page that reaches it fails visibly instead of dropping its suffix.
const MAX_PAGE_OUTPUT_BYTES: u64 = (PAGE_LIMIT * 256 * 1024) as u64;
/// Pacing per work slice; a crawl continues where it stopped.
const CYCLE_BUDGET: Duration = Duration::from_secs(45);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);
const RELAY_IO_TIMEOUT: Duration = COMMAND_TIMEOUT;
pub(crate) const COLLECTOR_IO_STOP_TIMEOUT: Duration = Duration::from_secs(15);
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
    /// The collection contract the server confirmed for this epoch. A binding
    /// written before `cloud_session_changes.v1` has none and needs consent
    /// on the new contract before collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_contract: Option<String>,
    /// The server's provider-creation cutoff after an erasure, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collect_not_before: Option<String>,
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

    fn lock(&self) -> Result<FileLock> {
        lock_state_file(&self.path, "control token ledger")
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
                    && binding_contract_current(&state.grant)
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
                    && binding_contract_current(&state.grant)
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
            disclosure_version: DISCLOSURE_VERSION.to_string(),
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
            schema_version: CHANGES_SCHEMA_VERSION.to_string(),
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
            validate_backend_grant_response(&state, response)?;
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
                && existing.server_policy_state == authority_policy(response)
                && existing.collection_contract.as_deref()
                    == (response.schema_version == CHANGES_SCHEMA_VERSION)
                        .then_some(CHANGES_SCHEMA_VERSION)
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
        validate_backend_grant_response(&state, response)?;
        if response.schema_version != pending.schema_version {
            return Err(anyhow!(
                "backend cloud-session grant contract differs from pending create"
            ));
        }
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
            // The same epoch may be re-bound only to move a binding written
            // before this collection contract onto it.
            if response.grant_version < existing.grant_version
                || (state.grant.status != CloudSessionGrantStatus::Enabled
                    && response.grant_version == existing.grant_version
                    && existing.collection_contract.as_deref() == Some(CHANGES_SCHEMA_VERSION))
            {
                return Err(anyhow!("backend cloud-session grant epoch is stale"));
            }
        }
        state.grant.backend_binding = Some(authority_binding(response, false));
        state.grant.backend_create_pending = false;
        state.grant.pending_backend_create = None;
        state.grant.collector_version = compiled_release_version();
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
        state.grant.status = match authority_policy(response) {
            CloudSessionServerPolicyState::Approved => CloudSessionGrantStatus::Enabled,
            CloudSessionServerPolicyState::Disabled => CloudSessionGrantStatus::PolicyDisabled,
        };
        state.grant.granted_at = Some(timestamp(OffsetDateTime::now_utc()));
        state.grant.revoked_at = None;
        state.grant.last_collector_health = Some(
            match authority_policy(response) {
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
        validate_backend_grant_response(&state, response)?;
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
        state.grant.backend_binding = Some(authority_binding(response, true));
        state.grant.backend_create_pending = false;
        state.grant.pending_backend_create = None;
        state.grant.status = CloudSessionGrantStatus::Revoked;
        state.grant.last_collector_health = Some("revoked".to_string());
        state.grant.last_freshness = Some("unavailable".to_string());
        self.write(&state)?;
        Ok(state.grant)
    }

    /// Apply the one authority read made before each due work slice.
    /// Unknown, malformed, stale, or mismatched responses are rejected without
    /// changing runtime readiness. A remote pause or policy-disabled answer
    /// leaves local consent untouched; a remote revoke revokes locally.
    pub fn apply_backend_authority(
        &self,
        authority: &CloudSessionGrantAuthorityV1,
    ) -> Result<CloudSessionGrant> {
        let _lock = self.lock()?;
        let mut state = self
            .read_locked()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        let existing = state
            .grant
            .backend_binding
            .as_ref()
            .ok_or_else(|| anyhow!("backend cloud-session grant is unbound"))?;
        if authority.schema_version != AUTHORITY_SCHEMA_VERSION
            || !is_uuid(&authority.grant_id)
            || !authority.grant_id.eq_ignore_ascii_case(&existing.grant_id)
            || authority.grant_version != existing.grant_version
            || authority.contract_version != CHANGES_SCHEMA_VERSION
            || authority.disclosure_version != DISCLOSURE_VERSION
            || !matches!(authority.status.as_str(), "enabled" | "paused" | "revoked")
            || authority
                .collect_not_before
                .as_deref()
                .is_some_and(|value| !valid_rfc3339(value))
        {
            return Err(anyhow!("backend cloud-session authority does not match"));
        }
        let backend_revoked = authority.status == "revoked";
        let policy = if authority.status == "enabled" && authority.can_collect {
            CloudSessionServerPolicyState::Approved
        } else {
            CloudSessionServerPolicyState::Disabled
        };
        let before = state.grant.clone();
        // The bound contract is the one consent created; authority never
        // upgrades a grant created on an earlier contract.
        let binding = state
            .grant
            .backend_binding
            .as_mut()
            .expect("binding checked above");
        binding.backend_revoked = backend_revoked;
        binding.server_policy_state = policy.clone();
        binding.collect_not_before = authority.collect_not_before.clone();
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
            state.grant.status = match policy {
                CloudSessionServerPolicyState::Approved => CloudSessionGrantStatus::Enabled,
                CloudSessionServerPolicyState::Disabled => CloudSessionGrantStatus::PolicyDisabled,
            };
            if state.grant.status != before.status {
                state.grant.last_collector_health = Some(
                    match state.grant.status {
                        CloudSessionGrantStatus::Enabled => "enabled",
                        _ => "policy_disabled",
                    }
                    .to_string(),
                );
            }
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
    #[cfg(test)]
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
        if state.grant.status != CloudSessionGrantStatus::Enabled
            || (state.grant.last_collector_health.as_deref() == Some(health)
                && state.grant.last_freshness.as_deref() == Some(freshness)
                && state.grant.last_error_category.as_deref() == error_category)
        {
            return Ok(());
        }
        state.grant.last_collector_health = Some(health.to_string());
        state.grant.last_freshness = Some(freshness.to_string());
        state.grant.last_error_category = error_category.map(str::to_string);
        self.write(&state)
    }

    /// The state can be changed by the local UI/control process while the
    /// collector thread records health. Hold a process-wide lock so stale
    /// read-modify-write health updates cannot restore consent.
    fn lock(&self) -> Result<FileLock> {
        lock_state_file(&self.path, "grant")
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

/// Waits for an exclusive flock on `<state_path>.lock` (0600) in an owner-only
/// (0700) directory.
fn lock_state_file(state_path: &Path, label: &str) -> Result<FileLock> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let parent = state_path
        .parent()
        .ok_or_else(|| anyhow!("cloud-session {label} path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let path = state_path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("open cloud-session {label} lock"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    FileLock::exclusive(file).map_err(|_| anyhow!("lock cloud-session {label}"))
}

/// Build the visible collector state without creating a runner or invoking
/// Codex. Runtime readiness is supplied as a credential-free status view;
/// collection still requires exact grant authority inside the supervisor.
pub fn cloud_session_collector_status(
    grants: &CloudSessionGrantStore,
    transport: &dyn CloudSessionTransport,
) -> CloudSessionCollectorStatusV1 {
    let stored_grant = grants.load().ok().flatten();
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
    let transport_configured = transport.is_configured();
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

/// Process-local collector state shared with local control: the provider and
/// relay I/O fence, and the support directory whose upload-history file holds
/// the cloud-task ACK cache.
pub struct CloudSessionCheckpointStore {
    state_dir: PathBuf,
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

impl CloudSessionCheckpointStore {
    /// `state_dir` is the support directory: the cache is
    /// `<state_dir>/snapshots/upload_history.sqlite`.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
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

    /// Wait until every provider subprocess, relay write or cache commit
    /// admitted before a local stop has returned. Persisted pause/revoke state
    /// closes admission; callers must then complete this wait before reporting
    /// the stop, erasing the cache or deleting backend consent.
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

    /// Erase the cloud-task ACK cache after a local revoke, once collector I/O
    /// is idle. The server-owned cutoff, not this cache, prevents revival.
    pub fn erase_cache(&self) -> Result<()> {
        crate::upload_receipts::cloud_erase_all(&self.state_dir)
    }

    fn read_acks(
        &self,
        scope: &[u8; 32],
        keys: &[&str],
        now_unix: i64,
    ) -> Result<HashMap<String, CloudAck>> {
        crate::upload_receipts::cloud_read_acks(&self.state_dir, scope, keys, now_unix)
    }

    fn crawl_completed(&self, scope: &[u8; 32]) -> Option<Date> {
        let raw = crate::upload_receipts::cloud_crawl_completed_date(&self.state_dir, scope)
            .ok()
            .flatten()?;
        Date::parse(&raw, &time::format_description::well_known::Iso8601::DATE).ok()
    }

    /// Commit one slice's settled tasks under an I/O lease, so a commit racing
    /// a local revoke either finishes before the revoke's erase or is refused.
    fn commit(
        &self,
        grants: &CloudSessionGrantStore,
        expected: &CloudSessionGrant,
        scope: &[u8; 32],
        settled: &HashMap<String, ([u8; 32], Option<String>)>,
        crawl_completed: Option<Date>,
        now_unix: i64,
    ) -> Result<()> {
        if settled.is_empty() && crawl_completed.is_none() {
            return Ok(());
        }
        let Some(lease) = self.begin_collector_io(grants, expected)? else {
            return Ok(());
        };
        let acks = settled
            .iter()
            .map(|(entity_key, (digest, head_etag))| CloudAckWrite {
                entity_key,
                digest: *digest,
                head_etag: head_etag.as_deref(),
            })
            .collect::<Vec<_>>();
        let date = crawl_completed.map(|date| date.to_string());
        let result = crate::upload_receipts::cloud_commit(
            &self.state_dir,
            scope,
            &acks,
            date.as_deref(),
            now_unix,
        );
        drop(lease);
        result
    }

    /// The pre-ACK-cache collector kept a page digest here; it cannot seed
    /// per-task ACKs, so it is removed once the cache is in use.
    fn retire_legacy_checkpoint(&self) {
        let _ = fs::remove_file(
            self.state_dir
                .join("cloud_sessions")
                .join("checkpoint.json"),
        );
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
}

impl Default for CloudSessionCheckpointStore {
    fn default() -> Self {
        Self {
            state_dir: default_support_dir(),
            collector_io: default_collector_io_fence(),
            #[cfg(test)]
            relay_admission_barrier: Mutex::new(None),
        }
    }
}

pub trait CloudSessionRunner {
    /// `cursor` may only be retained by the caller in memory.
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String>;

    /// Production runners must honor the remaining slice budget. Test runners
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
    /// One bounded relay-authenticated read of the exact bound grant epoch on
    /// the `cloud_session_changes.v1` authority. Fails closed on any network,
    /// authentication, parsing or absence error.
    fn read_authority(
        &self,
        grant: &CloudSessionGrant,
        timeout: Duration,
    ) -> Result<CloudSessionGrantAuthorityV1>;
    /// Upload one validated request and return its parsed ACK. Matching the
    /// ACK to the offered tasks is the caller's job.
    fn send_changes(
        &self,
        request: &CloudSessionChangesV1,
        timeout: Duration,
    ) -> Result<CloudSessionChangesAckV1>;
}

/// Used where no relay transport is composed (local control status).
pub struct DeferredCloudSessionTransport;
impl CloudSessionTransport for DeferredCloudSessionTransport {
    fn is_configured(&self) -> bool {
        false
    }

    fn read_authority(
        &self,
        _grant: &CloudSessionGrant,
        _timeout: Duration,
    ) -> Result<CloudSessionGrantAuthorityV1> {
        Err(anyhow!("cloud-session authority is not configured"))
    }

    fn send_changes(
        &self,
        _request: &CloudSessionChangesV1,
        _timeout: Duration,
    ) -> Result<CloudSessionChangesAckV1> {
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

    fn read_authority(
        &self,
        _grant: &CloudSessionGrant,
        _timeout: Duration,
    ) -> Result<CloudSessionGrantAuthorityV1> {
        Err(anyhow!(
            "cloud-session status transport cannot read authority"
        ))
    }

    fn send_changes(
        &self,
        _request: &CloudSessionChangesV1,
        _timeout: Duration,
    ) -> Result<CloudSessionChangesAckV1> {
        Err(anyhow!("cloud-session status transport cannot send"))
    }
}

/// Relay transport for the strict backend routes, composed only after exact
/// local identity/grant checks. It acquires through the shared relay-token
/// cache and retries once on 401/403 within the caller's deadline.
pub struct RelayCloudSessionTransport {
    client: crate::snapshot_client::SnapshotApiClient,
    device: LocalDeviceBinding,
    device_secret: String,
    gzip_enabled: AtomicBool,
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
            gzip_enabled: AtomicBool::new(true),
        }
    }

    fn token(&self, deadline: Instant) -> Result<String> {
        let timeout = remaining_budget(deadline)
            .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
        self.client.issue_relay_token_with_timeout(
            &self.device,
            &self.device_secret,
            crate::snapshots::SnapshotSource::Codex,
            timeout,
        )
    }

    fn with_relay_retry<F>(&self, timeout: Duration, request: F) -> Result<Value>
    where
        F: Fn(&crate::snapshot_client::SnapshotApiClient, &str, Duration) -> Result<Value>,
    {
        if !self.is_configured() {
            return Err(anyhow!("cloud-session relay transport is not source-bound"));
        }
        let deadline = Instant::now() + timeout;
        let token = self.token(deadline)?;
        let request_timeout = remaining_budget(deadline)
            .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
        match request(&self.client, &token, request_timeout) {
            Err(error)
                if error
                    .downcast_ref::<crate::snapshot_client::CloudSessionAuthorizationRejected>()
                    .is_some() =>
            {
                let refreshed = self.token(deadline)?;
                let retry_timeout = remaining_budget(deadline)
                    .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
                request(&self.client, &refreshed, retry_timeout)
            }
            other => other,
        }
    }
}

impl CloudSessionTransport for RelayCloudSessionTransport {
    fn is_configured(&self) -> bool {
        !self.device_secret.is_empty()
            && is_uuid(&self.device.device_id)
            && self.device.sources.iter().any(|source| source == "codex")
    }

    fn read_authority(
        &self,
        grant: &CloudSessionGrant,
        timeout: Duration,
    ) -> Result<CloudSessionGrantAuthorityV1> {
        let binding = grant
            .backend_binding
            .as_ref()
            .ok_or_else(|| anyhow!("cloud-session backend grant is unbound"))?;
        if !is_uuid(&binding.grant_id) || binding.grant_version == 0 {
            return Err(anyhow!("cloud-session backend grant binding is invalid"));
        }
        let value = self.with_relay_retry(timeout, |client, token, request_timeout| {
            client.get_cloud_session_authority_with_timeout(
                token,
                &binding.grant_id,
                binding.grant_version,
                request_timeout,
            )
        })?;
        if value.get("schema_version").and_then(Value::as_str) != Some(AUTHORITY_SCHEMA_VERSION) {
            return Err(
                crate::snapshot_client::CloudSessionRouteUnsupported { status: 200 }.into(),
            );
        }
        serde_json::from_value(value)
            .map_err(|_| anyhow!("invalid cloud-session authority response"))
    }

    fn send_changes(
        &self,
        request: &CloudSessionChangesV1,
        timeout: Duration,
    ) -> Result<CloudSessionChangesAckV1> {
        request.validate()?;
        let body = serde_json::to_value(request)?;
        let value = self.with_relay_retry(timeout, |client, token, request_timeout| {
            client.upload_cloud_session_changes_with_timeout(
                token,
                &body,
                request_timeout,
                &self.gzip_enabled,
            )
        })?;
        serde_json::from_value(value)
            .map_err(|error| anyhow!("invalid cloud-session changes ACK: {error}"))
    }
}
pub struct CodexCloudCliRunner;

#[cfg(unix)]
struct CodexCloudChild {
    child: Option<crate::local_resource_diagnostics::cli_children::MeasuredChild>,
}

#[cfg(unix)]
impl CodexCloudChild {
    fn exited(&self) -> std::io::Result<bool> {
        let child = self.child.as_ref().expect("owned cloud child");
        // Observe exit without reaping: reserve the PID until the owned process
        // group has been stopped, even if a descendant retains stdout.
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(info.si_signo != 0)
    }

    fn stop_and_reap(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let mut child = self.child.take().expect("owned cloud child");
        // Command::process_group(0) created this group; the direct child has
        // never been reaped, so its PID cannot have been reused by another group.
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
        let _ = child.kill();
        child.wait()
    }
}

#[cfg(unix)]
impl Drop for CodexCloudChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.stop_and_reap();
        }
    }
}

/// One provider-call log line per `codex cloud list` run that started: at
/// least one OpenAI request.
#[cfg(unix)]
fn record_codex_cloud_list(result: &Result<String>, started: Instant) {
    use crate::provider_calls::{CallKind, CallResult, Provider, ProviderCall, Trigger};
    let result = match result {
        Ok(_) => CallResult::Ok,
        Err(error) if error.to_string().ends_with("could not be started") => return,
        Err(error) if error.to_string().ends_with("timed out") => CallResult::Timeout,
        Err(error) if error.to_string().ends_with("exited unsuccessfully") => {
            CallResult::Error("exited")
        }
        Err(_) => CallResult::Error("error"),
    };
    crate::provider_calls::record(ProviderCall::subprocess(
        Provider::Openai,
        CallKind::CodexCloudList,
        crate::provider_calls::trigger_or(Trigger::Schedule),
        crate::agent_status::codex_cli_home_claimed_account_hash().as_deref(),
        result,
        started.elapsed(),
        1,
    ));
}

#[cfg(unix)]
fn run_codex_cloud_command(command: &mut Command, deadline: Instant) -> Result<String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    if Instant::now() >= deadline {
        return Err(anyhow!("Codex cloud list timed out"));
    }
    command.process_group(0);
    let mut owned = CodexCloudChild {
        child: Some(
            crate::local_resource_diagnostics::cli_children::spawn(command)
                .map_err(|_| anyhow!("Codex cloud list could not be started"))?,
        ),
    };
    let stdout = owned
        .child
        .as_mut()
        .expect("owned cloud child")
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Codex cloud list stdout could not be opened"))?;
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(anyhow!("Codex cloud list output could not be read"));
    }
    // Read in this thread, checking the same deadline on every chunk, including
    // continuously readable output. No blocked reader can outlive this call.
    let mut stdout = Some(stdout);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| anyhow!("Codex cloud list timed out"))?;
        let mut progressed = false;
        if let Some(pipe) = stdout.as_mut() {
            let available = (MAX_PAGE_OUTPUT_BYTES as usize - bytes.len()).min(buffer.len());
            match pipe.read(&mut buffer[..available]) {
                Ok(0) => stdout = None,
                Ok(read) => {
                    bytes.extend_from_slice(&buffer[..read]);
                    progressed = true;
                    // Preserve take(MAX_PAGE_OUTPUT_BYTES): close the pipe at
                    // the cap and let the child's exit status settle the result.
                    if bytes.len() == MAX_PAGE_OUTPUT_BYTES as usize {
                        stdout = None;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(anyhow!("Codex cloud list output could not be read")),
            }
        }
        if owned
            .exited()
            .map_err(|_| anyhow!("Codex cloud list status could not be read"))?
            && stdout.is_none()
        {
            let status = owned
                .stop_and_reap()
                .map_err(|_| anyhow!("Codex cloud list status could not be read"))?;
            if !status.success() {
                return Err(anyhow!("Codex cloud list exited unsuccessfully"));
            }
            return String::from_utf8(bytes)
                .map_err(|_| anyhow!("Codex cloud list returned non-UTF-8 JSON"));
        }
        if !progressed {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Some(pipe) = stdout.as_ref() {
                let mut ready = libc::pollfd {
                    fd: pipe.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let timeout_ms = remaining.as_millis().min(50) as libc::c_int;
                let result = unsafe { libc::poll(&mut ready, 1, timeout_ms) };
                if result < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    return Err(anyhow!("Codex cloud list output could not be read"));
                }
            } else {
                thread::sleep(remaining.min(Duration::from_millis(50)));
            }
        }
    }
}

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
        #[cfg(unix)]
        let deadline = Instant::now() + timeout.min(COMMAND_TIMEOUT);
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
        #[cfg(unix)]
        {
            let started = Instant::now();
            let result = run_codex_cloud_command(&mut command, deadline);
            // A deadline already spent starts nothing.
            if started < deadline {
                record_codex_cloud_list(&result, started);
            }
            result
        }
        #[cfg(not(unix))]
        {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudSessionCycleOutcome {
    /// No consent, a local pause or revoke, the kill switch, or no binding:
    /// no provider or backend call was made.
    Disabled,
    /// Nothing was due yet.
    NotDue,
    /// The server does not authorize collection now (remote pause, policy,
    /// or an older server without this contract). Rechecked at the idle
    /// cadence or after a local consent change.
    Unsupported,
    /// Work ran and no task changed.
    Noop,
    /// At least one changed task was offered.
    Uploaded,
    /// Provider or transport failed; the cloud-only backoff applies.
    Failed,
}

/// The collector's in-memory schedule; one per supervisor.
#[derive(Default)]
pub struct CloudCollector {
    schedule: CloudSchedule,
}

/// Everything one work slice uses.
pub struct SliceInputs<'a> {
    pub grants: &'a CloudSessionGrantStore,
    pub checkpoints: &'a CloudSessionCheckpointStore,
    pub runner: &'a dyn CloudSessionRunner,
    pub transport: &'a dyn CloudSessionTransport,
    /// The validated backend destination; part of the ACK-cache scope.
    pub destination: &'a str,
    /// The latest local Codex transcript event the file watcher saw.
    pub last_activity: Option<Instant>,
}

#[derive(Debug)]
struct SliceError {
    category: &'static str,
    kind: SliceErrorKind,
}

#[derive(Debug)]
enum SliceErrorKind {
    /// Retry after the cloud-only backoff (a `Retry-After` when given).
    Backoff(Option<Duration>),
    /// The server does not offer this route or epoch now.
    Unsupported,
    /// Local consent closed the I/O fence mid-slice.
    Stopped,
    /// The slice budget ran out; the next slice continues.
    Deferred,
}

impl SliceError {
    fn backoff(category: &'static str) -> Self {
        Self {
            category,
            kind: SliceErrorKind::Backoff(None),
        }
    }

    fn from_request(error: &anyhow::Error, deadline: Instant) -> Self {
        if let Some(shed) = error.downcast_ref::<crate::snapshot_client::UploadShed>() {
            return Self {
                category: "backend_shed",
                kind: SliceErrorKind::Backoff(shed.retry_after),
            };
        }
        if error
            .downcast_ref::<crate::snapshot_client::CloudSessionRouteUnsupported>()
            .is_some()
        {
            return Self {
                category: "server_unsupported",
                kind: SliceErrorKind::Unsupported,
            };
        }
        if remaining_budget(deadline).is_none() {
            return Self {
                category: "budget_exhausted",
                kind: SliceErrorKind::Deferred,
            };
        }
        Self::backoff("transport_unavailable")
    }
}

/// What one listed page contributed.
struct PageFacts {
    next: Option<String>,
    ambiguous: bool,
    nonterminal: bool,
}

/// One slice's working memory: only ACK metadata of tasks it settled.
struct SliceWork<'a, 'b> {
    inputs: &'a SliceInputs<'b>,
    grant: CloudSessionGrant,
    binding: CloudSessionBackendGrantBindingV1,
    key: Vec<u8>,
    scope: [u8; 32],
    cutoff: Option<OffsetDateTime>,
    deadline: Instant,
    wall: OffsetDateTime,
    pages: usize,
    offered: usize,
    settled: HashMap<String, ([u8; 32], Option<String>)>,
}

impl CloudCollector {
    /// When the supervisor should next run a slice; `None` waits for a local
    /// consent change (or the supervisor's idle fallback).
    pub fn next_wake(
        &self,
        now: Instant,
        wall: OffsetDateTime,
        last_activity: Option<Instant>,
    ) -> Option<Instant> {
        if self.schedule.scope.is_none() {
            return self.schedule.retry_not_before;
        }
        Some(self.schedule.next_due(now, wall.date(), last_activity))
    }

    /// Drop transient work (cursor, backoff, unsupported recheck) after a
    /// local consent change; the next slice starts with an immediate head.
    pub fn reset(&mut self) {
        self.schedule.clear();
    }

    fn defer_after_local_failure(&mut self, now: Instant) {
        let backoff = crate::snapshot_sync::full_jitter_backoff(self.schedule.consecutive_failures);
        self.schedule.note_failure(now, backoff);
    }

    /// Run whatever is due: one authority read, then the head and/or the
    /// next crawl pages, uploading only changed tasks, then one cache commit.
    pub fn run_slice(
        &mut self,
        inputs: &SliceInputs<'_>,
        now: Instant,
        wall: OffsetDateTime,
    ) -> CloudSessionCycleOutcome {
        let started = Instant::now();
        if kill_switch_enabled() {
            self.schedule.clear();
            return CloudSessionCycleOutcome::Disabled;
        }
        let state = match inputs.grants.read() {
            Ok(Some(state)) if cloud_grant_preflight_eligible(&state.grant) => state,
            _ => {
                self.schedule.clear();
                return CloudSessionCycleOutcome::Disabled;
            }
        };
        let (Some(binding), Some(key)) = (
            state.grant.backend_binding.clone(),
            decode_hex(&state.hmac_key_hex).filter(|key| key.len() == 32),
        ) else {
            self.schedule.clear();
            return CloudSessionCycleOutcome::Disabled;
        };
        if !inputs.transport.is_configured() {
            let _ = inputs.grants.record_health(
                "unavailable",
                "unavailable",
                Some("transport_unconfigured"),
            );
            self.schedule.clear();
            return CloudSessionCycleOutcome::Disabled;
        }
        let scope = cache_scope(inputs.destination, &state.grant, &binding);
        self.schedule.reset_for_scope(scope);
        if !self.schedule.crawl_completed_loaded {
            self.schedule.crawl_completed = inputs.checkpoints.crawl_completed(&scope);
            self.schedule.crawl_completed_loaded = true;
            inputs.checkpoints.retire_legacy_checkpoint();
        }
        let today = wall.date();
        let due = self.schedule.due(now, today, inputs.last_activity);
        if !due.head && !due.crawl {
            return CloudSessionCycleOutcome::NotDue;
        }
        let deadline = Instant::now() + CYCLE_BUDGET;
        let grant = match self.preflight(inputs, &state.grant, deadline, now + started.elapsed()) {
            Ok(grant) => grant,
            Err(outcome) => return outcome,
        };
        let binding = grant.backend_binding.clone().unwrap_or(binding);
        let cutoff = binding
            .collect_not_before
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
        let mut work = SliceWork {
            inputs,
            grant,
            binding,
            key,
            scope,
            cutoff,
            deadline,
            wall,
            pages: 0,
            offered: 0,
            settled: HashMap::new(),
        };
        let mut crawl_completed = None;
        let failure = self.work(&mut work, due, now, today, &mut crawl_completed);
        let cache_unavailable = inputs
            .checkpoints
            .commit(
                inputs.grants,
                &work.grant,
                &scope,
                &work.settled,
                crawl_completed,
                wall.unix_timestamp(),
            )
            .is_err();
        // A cache failure re-offers tasks next time (server no-op). Preserve
        // its diagnostic instead of overwriting it with an unconditional OK.
        match failure {
            None => {
                self.schedule.note_success();
                if cache_unavailable {
                    let _ = inputs.grants.record_health(
                        "degraded",
                        "fresh",
                        Some("ack_cache_unavailable"),
                    );
                } else {
                    let _ = inputs.grants.record_health("ok", "fresh", None);
                }
                if work.offered > 0 {
                    CloudSessionCycleOutcome::Uploaded
                } else {
                    CloudSessionCycleOutcome::Noop
                }
            }
            Some(error) => self.settle_failure(inputs, error, now + started.elapsed()),
        }
    }

    fn settle_failure(
        &mut self,
        inputs: &SliceInputs<'_>,
        error: SliceError,
        now: Instant,
    ) -> CloudSessionCycleOutcome {
        match error.kind {
            SliceErrorKind::Backoff(retry_after) => {
                let backoff = match retry_after {
                    Some(_) => crate::snapshot_sync::shed_backoff(retry_after),
                    None => crate::snapshot_sync::full_jitter_backoff(
                        self.schedule.consecutive_failures,
                    ),
                };
                self.schedule.note_failure(now, backoff);
                let _ = inputs
                    .grants
                    .record_health("failing", "stale", Some(error.category));
                CloudSessionCycleOutcome::Failed
            }
            SliceErrorKind::Unsupported => {
                self.mark_unsupported(inputs, now);
                CloudSessionCycleOutcome::Unsupported
            }
            SliceErrorKind::Stopped => {
                self.schedule.clear();
                CloudSessionCycleOutcome::Disabled
            }
            SliceErrorKind::Deferred => CloudSessionCycleOutcome::Noop,
        }
    }

    fn mark_unsupported(&mut self, inputs: &SliceInputs<'_>, now: Instant) {
        self.schedule.crawl = None;
        self.schedule.retry_not_before = None;
        self.schedule.unsupported_until = Some(now + IDLE_HEAD_INTERVAL);
        let _ =
            inputs
                .grants
                .record_health("unavailable", "unavailable", Some("server_unsupported"));
    }

    /// The one authority read of a due slice. Local pause/revoke never reach
    /// here; a remote revoke revokes locally and erases the cache.
    fn preflight(
        &mut self,
        inputs: &SliceInputs<'_>,
        expected: &CloudSessionGrant,
        deadline: Instant,
        now: Instant,
    ) -> std::result::Result<CloudSessionGrant, CloudSessionCycleOutcome> {
        let started = Instant::now();
        let Some(timeout) = remaining_relay_budget(deadline) else {
            return Err(CloudSessionCycleOutcome::NotDue);
        };
        let response = match inputs.transport.read_authority(expected, timeout) {
            Ok(response) => response,
            Err(error) => {
                let error = SliceError::from_request(&error, deadline);
                return Err(self.settle_failure(inputs, error, now + started.elapsed()));
            }
        };
        let current = match inputs.grants.apply_backend_authority(&response) {
            Ok(current) => current,
            Err(_) => {
                self.mark_unsupported(inputs, now);
                return Err(CloudSessionCycleOutcome::Unsupported);
            }
        };
        if current.status == CloudSessionGrantStatus::Revoked {
            let _ = inputs.checkpoints.erase_cache();
            self.schedule.clear();
            return Err(CloudSessionCycleOutcome::Disabled);
        }
        if !same_runtime_grant_identity(&current, expected) {
            self.schedule.clear();
            return Err(CloudSessionCycleOutcome::Disabled);
        }
        if !cloud_grant_runtime_ready(&current) {
            self.mark_unsupported(inputs, now);
            return Err(CloudSessionCycleOutcome::Unsupported);
        }
        Ok(current)
    }

    fn work(
        &mut self,
        work: &mut SliceWork<'_, '_>,
        due: Due,
        now: Instant,
        today: Date,
        crawl_completed: &mut Option<Date>,
    ) -> Option<SliceError> {
        let start_crawl = due.crawl && self.schedule.crawl.is_none();
        if due.head || start_crawl {
            // A head that failed with a backoff stays due: the backoff, not
            // the idle cadence, decides when it is retried.
            let page = match work.page(None) {
                Ok(page) => page,
                Err(error) => {
                    if !matches!(error.kind, SliceErrorKind::Backoff(_)) {
                        self.schedule.last_head_attempt = Some(now);
                    }
                    return Some(error);
                }
            };
            self.schedule.last_head_attempt = Some(now);
            // A failed head keeps the previous predicate; a deep page never
            // changes it.
            self.schedule.head_nonterminal = page.nonterminal;
            if start_crawl {
                match page.next {
                    Some(cursor) if !page.ambiguous => {
                        let mut crawl = Crawl {
                            cursor: Some(cursor.clone()),
                            pages_seen: 1,
                            cycle: Default::default(),
                            next_slice: now,
                        };
                        crawl.cycle.repeats(cursor_digest(&cursor));
                        self.schedule.crawl = Some(crawl);
                    }
                    _ if page.ambiguous => self.schedule.crawl_ended = Some(today),
                    _ => {
                        self.schedule.crawl_completed = Some(today);
                        *crawl_completed = Some(today);
                    }
                }
            }
        }
        if !(due.crawl || start_crawl) {
            return None;
        }
        let mut crawl = self.schedule.crawl.take()?;
        let mut failure = None;
        while work.pages < MAX_SLICE_PAGES && remaining_budget(work.deadline).is_some() {
            let Some(cursor) = crawl.cursor.clone() else {
                break;
            };
            let page = match work.page(Some(&cursor)) {
                Ok(page) => page,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            };
            crawl.pages_seen += 1;
            match page.next {
                None if !page.ambiguous => {
                    // Reached the end: the day's crawl is complete, whatever
                    // day it started.
                    self.schedule.crawl_completed = Some(today);
                    *crawl_completed = Some(today);
                    return failure;
                }
                Some(next)
                    if !page.ambiguous
                        && next != cursor
                        && !crawl.cycle.repeats(cursor_digest(&next)) =>
                {
                    crawl.cursor = Some(next);
                }
                _ => {
                    // An ambiguous, repeating or cycling cursor chain ends
                    // this traversal without claiming completion; valid facts
                    // already uploaded stay. A new crawl starts tomorrow.
                    self.schedule.crawl_ended = Some(today);
                    return failure;
                }
            }
        }
        if matches!(
            failure.as_ref().map(|error| &error.kind),
            Some(SliceErrorKind::Unsupported | SliceErrorKind::Stopped)
        ) {
            return failure;
        }
        crawl.next_slice = now + CRAWL_CONTINUATION_INTERVAL;
        self.schedule.crawl = Some(crawl);
        failure
    }
}

impl SliceWork<'_, '_> {
    fn list(&mut self, cursor: Option<&str>) -> std::result::Result<String, SliceError> {
        let Some(timeout) = remaining_budget(self.deadline) else {
            return Err(SliceError {
                category: "budget_exhausted",
                kind: SliceErrorKind::Deferred,
            });
        };
        let lease = self
            .inputs
            .checkpoints
            .begin_collector_io(self.inputs.grants, &self.grant)
            .map_err(|_| SliceError::backoff("collector_io_fence_unavailable"))?
            .ok_or(SliceError {
                category: "stopped",
                kind: SliceErrorKind::Stopped,
            })?;
        self.pages += 1;
        let result =
            self.inputs
                .runner
                .list_page_bounded(cursor, PAGE_LIMIT, timeout.min(COMMAND_TIMEOUT));
        // The lease covers provider-process activity only.
        drop(lease);
        result.map_err(|_| {
            if remaining_budget(self.deadline).is_none() {
                SliceError {
                    category: "budget_exhausted",
                    kind: SliceErrorKind::Deferred,
                }
            } else {
                SliceError::backoff("provider_unavailable")
            }
        })
    }

    fn parse(&self, raw: &str) -> std::result::Result<ParsedPage, SliceError> {
        match parse_cloud_page(raw, &self.key, self.wall) {
            // A nonempty page with no valid task is a provider failure, not
            // an empty healthy page.
            Ok(page) if page.source_item_count == 0 || !page.changes.is_empty() => Ok(page),
            _ => Err(SliceError::backoff("provider_payload_invalid")),
        }
    }

    /// List one page, offer its changed tasks, and retry a head conflict
    /// once with freshly listed facts.
    fn page(&mut self, cursor: Option<&str>) -> std::result::Result<PageFacts, SliceError> {
        let raw = self.list(cursor)?;
        let parsed = self.parse(&raw)?;
        drop(raw);
        let facts = PageFacts {
            next: match &parsed.cursor {
                CloudPageCursor::Next(next) => Some(next.clone()),
                _ => None,
            },
            ambiguous: parsed.cursor == CloudPageCursor::Ambiguous,
            nonterminal: parsed.changes.iter().any(|change| {
                matches!(change.lifecycle.as_str(), "queued" | "running" | "unknown")
            }),
        };
        let conflicts = self.deliver(parsed.changes)?;
        if conflicts.is_empty()
            || self.pages >= MAX_SLICE_PAGES
            || remaining_budget(self.deadline).is_none()
        {
            return Ok(facts);
        }
        // Fresh re-enumeration before replacing a divergent server head. A
        // second conflict is left for the next visit.
        let fresh = match self.list(cursor).and_then(|raw| self.parse(&raw)) {
            Ok(fresh) => fresh,
            Err(_) => return Ok(facts),
        };
        let retry = fresh
            .changes
            .into_iter()
            .filter(|change| self.admissible(change))
            .filter_map(|mut change| {
                let hint = conflicts.get(&change.entity_key)?.clone();
                change.expected_head_etag = Some(hint);
                Some(change)
            })
            .collect::<Vec<_>>();
        self.offer(retry)?;
        Ok(facts)
    }

    /// After an erasure only tasks with a trustworthy provider creation time
    /// after the server's cutoff may be offered. The server enforces this too.
    fn admissible(&self, change: &CloudSessionChangeV1) -> bool {
        self.cutoff.map_or(true, |cutoff| {
            change
                .created_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                .is_some_and(|created| created > cutoff)
        })
    }

    /// Offer only tasks whose digest differs from their last exact ACK in
    /// this slice or the cache. Returns conflict hints by task.
    fn deliver(
        &mut self,
        changes: Vec<CloudSessionChangeV1>,
    ) -> std::result::Result<HashMap<String, String>, SliceError> {
        let mut unique = Vec::with_capacity(changes.len());
        for change in changes {
            if self.admissible(&change)
                && !unique
                    .iter()
                    .any(|seen: &CloudSessionChangeV1| seen.entity_key == change.entity_key)
            {
                unique.push(change);
            }
        }
        if unique.is_empty() {
            return Ok(HashMap::new());
        }
        let keys = unique
            .iter()
            .map(|change| change.entity_key.as_str())
            .filter(|key| !self.settled.contains_key(*key))
            .collect::<Vec<_>>();
        // A cache that cannot be read remembers nothing; the server answers
        // noop for unchanged tasks.
        let cached = if keys.is_empty() {
            HashMap::new()
        } else {
            self.inputs
                .checkpoints
                .read_acks(&self.scope, &keys, self.wall.unix_timestamp())
                .unwrap_or_default()
        };
        let mut offer = Vec::new();
        for mut change in unique {
            let digest = change.semantic_digest();
            let known = self
                .settled
                .get(&change.entity_key)
                .map(|(digest, etag)| (*digest, etag.clone()))
                .or_else(|| {
                    cached
                        .get(&change.entity_key)
                        .map(|ack| (ack.digest, ack.head_etag.clone()))
                });
            match known {
                Some((known, _)) if known == digest => continue,
                Some((_, etag)) => change.expected_head_etag = etag,
                None => change.expected_head_etag = None,
            }
            offer.push(change);
        }
        self.offer(offer)
    }

    fn offer(
        &mut self,
        changes: Vec<CloudSessionChangeV1>,
    ) -> std::result::Result<HashMap<String, String>, SliceError> {
        let mut conflicts = HashMap::new();
        for chunk in changes.chunks(MAX_CHANGES_PER_REQUEST) {
            let request = CloudSessionChangesV1 {
                schema_version: CHANGES_SCHEMA_VERSION.to_string(),
                grant_id: self.binding.grant_id.clone(),
                grant_version: self.binding.grant_version,
                grant_scope_fingerprint: self.grant.grant_scope_id.clone(),
                account_fingerprint: self.grant.account_fingerprint.clone(),
                collector_id: COLLECTOR_ID.to_string(),
                collector_version: compiled_release_version(),
                collected_at: timestamp(self.wall),
                observations: chunk.to_vec(),
            };
            request
                .validate()
                .map_err(|_| SliceError::backoff("request_invalid"))?;
            self.inputs
                .checkpoints
                .wait_at_relay_admission_barrier_for_test();
            let Some(timeout) = remaining_relay_budget(self.deadline) else {
                return Err(SliceError {
                    category: "budget_exhausted",
                    kind: SliceErrorKind::Deferred,
                });
            };
            let lease = self
                .inputs
                .checkpoints
                .begin_collector_io(self.inputs.grants, &self.grant)
                .map_err(|_| SliceError::backoff("collector_io_fence_unavailable"))?
                .ok_or(SliceError {
                    category: "stopped",
                    kind: SliceErrorKind::Stopped,
                })?;
            let result = self.inputs.transport.send_changes(&request, timeout);
            drop(lease);
            let ack = result.map_err(|error| SliceError::from_request(&error, self.deadline))?;
            let settled = request
                .settle(&ack)
                .map_err(|_| SliceError::backoff("ack_invalid"))?;
            self.offered += chunk.len();
            for change in chunk {
                match settled.get(&change.entity_key) {
                    Some(Settled::Acked { head_etag }) => {
                        self.settled.insert(
                            change.entity_key.clone(),
                            (change.semantic_digest(), Some(head_etag.clone())),
                        );
                    }
                    Some(Settled::Refused) => {
                        self.settled
                            .insert(change.entity_key.clone(), (change.semantic_digest(), None));
                    }
                    Some(Settled::Conflict {
                        head_etag: Some(hint),
                    }) => {
                        conflicts.insert(change.entity_key.clone(), hint.clone());
                    }
                    Some(Settled::Conflict { head_etag: None }) | None => {}
                }
            }
        }
        Ok(conflicts)
    }
}

fn remaining_budget(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
}

fn remaining_relay_budget(deadline: Instant) -> Option<Duration> {
    remaining_budget(deadline).map(|remaining| remaining.min(RELAY_IO_TIMEOUT))
}

fn cursor_digest(cursor: &str) -> [u8; 32] {
    Sha256::digest(cursor.as_bytes()).into()
}

/// Cache isolation: the destination, local identity, grant epoch, scope,
/// account and contract. Never a Results identity.
fn cache_scope(
    destination: &str,
    grant: &CloudSessionGrant,
    binding: &CloudSessionBackendGrantBindingV1,
) -> [u8; 32] {
    let mut framed = Vec::new();
    for part in [
        b"ottto.cloud-session.cache-scope.v1".as_slice(),
        destination.as_bytes(),
        grant.installation_fingerprint.as_bytes(),
        grant.organization_fingerprint.as_bytes(),
        grant.effective_user_fingerprint.as_bytes(),
        binding.grant_id.as_bytes(),
        &binding.grant_version.to_be_bytes(),
        grant.grant_scope_id.as_bytes(),
        grant.account_fingerprint.as_bytes(),
        CHANGES_SCHEMA_VERSION.as_bytes(),
    ] {
        push_length_framed(&mut framed, part);
    }
    Sha256::digest(&framed).into()
}

struct ParsedPage {
    changes: Vec<CloudSessionChangeV1>,
    cursor: CloudPageCursor,
    source_item_count: usize,
}

#[derive(Clone, PartialEq, Eq)]
enum CloudPageCursor {
    OfficialTerminal,
    Next(String),
    Ambiguous,
}

impl std::fmt::Debug for CloudPageCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OfficialTerminal => "OfficialTerminal",
            Self::Next(_) => "Next(redacted)",
            Self::Ambiguous => "Ambiguous",
        })
    }
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
    // Every returned row is processed, even beyond the requested limit. A
    // malformed row is skipped alone; its valid siblings still count.
    let mut changes = Vec::new();
    let source_item_count = items.len();
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(provider_id) = string_field(object, &["id", "task_id"]) else {
            continue;
        };
        let Some(provider_status) = string_field(object, &["status", "state"]) else {
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
        coverage.sort();
        changes.push(CloudSessionChangeV1 {
            entity_key: opaque_key(key, provider_id),
            expected_head_etag: None,
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
        changes,
        cursor,
        source_item_count,
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
/// A provider time in canonical UTC RFC 3339, or `None` when absent,
/// unparsable or in the future.
fn timestamp_field(
    object: &serde_json::Map<String, Value>,
    names: &[&str],
    observed_at: OffsetDateTime,
) -> Option<String> {
    string_field(object, names)
        .filter(|value| value.len() <= 64)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .filter(|parsed| *parsed <= observed_at)
        .map(|parsed| timestamp(parsed.to_offset(UtcOffset::UTC)))
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

/// Older pending tombstones predate the explicit descriptor and used the
/// retired observation contract. Reconcile that exact request; never upgrade it.
fn pending_backend_create(grant: &CloudSessionGrant) -> CloudSessionPendingBackendCreateV1 {
    CloudSessionPendingBackendCreateV1 {
        source: "codex".to_string(),
        collector_id: COLLECTOR_ID.to_string(),
        schema_version: LEGACY_COLLECTION_SCHEMA_VERSION.to_string(),
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
        || !matches!(
            pending.schema_version.as_str(),
            CHANGES_SCHEMA_VERSION | LEGACY_COLLECTION_SCHEMA_VERSION
        )
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

/// Consent binds the installation, scope, account, disclosure and the
/// `cloud_session_changes.v1` contract, never a binary release.
fn validate_backend_grant_response(
    state: &PersistedGrant,
    response: &CloudSessionBackendGrantResponseV1,
) -> Result<()> {
    let key = decode_hex(&state.hmac_key_hex)
        .filter(|key| key.len() == 32)
        .ok_or_else(|| anyhow!("invalid cloud-session HMAC key"))?;
    if !is_uuid(&response.id)
        || !is_uuid(&response.installation_id)
        || opaque_key(&key, &response.installation_id) != state.grant.installation_fingerprint
        || response.source != "codex"
        || response.collector_id != COLLECTOR_ID
        || !matches!(
            response.schema_version.as_str(),
            CHANGES_SCHEMA_VERSION | LEGACY_COLLECTION_SCHEMA_VERSION
        )
        || response.disclosure_version != DISCLOSURE_VERSION
        || response.grant_scope_fingerprint != state.grant.grant_scope_id
        || response.account_fingerprint != state.grant.account_fingerprint
        || response.grant_version == 0
    {
        return Err(anyhow!("backend cloud-session grant scope does not match"));
    }
    Ok(())
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
    ) && !grant.backend_create_pending
        && grant
            .backend_binding
            .as_ref()
            .is_some_and(|binding| !binding.backend_revoked)
}

fn cloud_grant_runtime_ready(grant: &CloudSessionGrant) -> bool {
    grant.status == CloudSessionGrantStatus::Enabled
        && !grant.backend_create_pending
        && binding_contract_current(grant)
        && grant.backend_binding.as_ref().is_some_and(|binding| {
            !binding.backend_revoked
                && binding.server_policy_state == CloudSessionServerPolicyState::Approved
        })
}

/// The bound epoch was confirmed on the `cloud_session_changes.v1` contract.
fn binding_contract_current(grant: &CloudSessionGrant) -> bool {
    grant.backend_binding.as_ref().is_some_and(|binding| {
        binding.collection_contract.as_deref() == Some(CHANGES_SCHEMA_VERSION)
    })
}

/// Collection is approved only for an enabled grant on this contract with
/// explicit `can_collect`; anything else, including older responses, is
/// disabled.
fn authority_policy(
    response: &CloudSessionBackendGrantResponseV1,
) -> CloudSessionServerPolicyState {
    if response.status == "enabled"
        && response.can_collect == Some(true)
        && response.schema_version == CHANGES_SCHEMA_VERSION
    {
        CloudSessionServerPolicyState::Approved
    } else {
        CloudSessionServerPolicyState::Disabled
    }
}

fn authority_binding(
    response: &CloudSessionBackendGrantResponseV1,
    backend_revoked: bool,
) -> CloudSessionBackendGrantBindingV1 {
    CloudSessionBackendGrantBindingV1 {
        grant_id: response.id.clone(),
        grant_version: response.grant_version,
        backend_revoked,
        server_policy_state: authority_policy(response),
        collection_contract: (response.schema_version == CHANGES_SCHEMA_VERSION)
            .then(|| CHANGES_SCHEMA_VERSION.to_string()),
        collect_not_before: None,
    }
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
fn push_length_framed(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
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

/// The local inputs a composed slice reads before any network call.
struct ComposedSliceInputs<'a, FLoadCredentials, FComposeTransport> {
    grants: &'a CloudSessionGrantStore,
    checkpoints: &'a CloudSessionCheckpointStore,
    runner: &'a dyn CloudSessionRunner,
    accounts: &'a FileAccountStore,
    devices: &'a FileDeviceStore,
    connections: &'a FileConnectionStore,
    load_credentials: FLoadCredentials,
    compose_transport: FComposeTransport,
    last_activity: Option<Instant>,
}

fn collect_composed_cloud_sessions_once(
    collector: &mut CloudCollector,
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    runner: &dyn CloudSessionRunner,
    active_transport: &mut ActiveCloudSessionTransport,
    now: Instant,
) -> CloudSessionCycleOutcome {
    let _stage = StageWindow::begin("codex", "offpass_cloud_sessions");
    let accounts = FileAccountStore::default();
    let devices = FileDeviceStore::default();
    let connections = FileConnectionStore::default();
    collect_composed_cloud_sessions_once_with(
        collector,
        active_transport,
        ComposedSliceInputs {
            grants,
            checkpoints,
            runner,
            accounts: &accounts,
            devices: &devices,
            connections: &connections,
            load_credentials: crate::snapshot_client::load_snapshot_device_credentials,
            compose_transport: |api_base_url, device, device_secret| {
                Box::new(RelayCloudSessionTransport::new(
                    api_base_url,
                    device,
                    device_secret,
                )) as Box<dyn CloudSessionTransport + Send>
            },
            last_activity: last_local_codex_activity(),
        },
        now,
        OffsetDateTime::now_utc(),
    )
}

fn collect_composed_cloud_sessions_once_with<FLoadCredentials, FComposeTransport>(
    collector: &mut CloudCollector,
    active_transport: &mut ActiveCloudSessionTransport,
    inputs: ComposedSliceInputs<'_, FLoadCredentials, FComposeTransport>,
    now: Instant,
    wall: OffsetDateTime,
) -> CloudSessionCycleOutcome
where
    FLoadCredentials: FnOnce() -> Result<(LocalDeviceBinding, String)>,
    FComposeTransport:
        FnOnce(String, LocalDeviceBinding, String) -> Box<dyn CloudSessionTransport + Send>,
{
    let started = Instant::now();
    let grants = inputs.grants;
    if kill_switch_enabled() {
        active_transport.take();
        collector.reset();
        return CloudSessionCycleOutcome::Disabled;
    }
    let candidate = match load_cloud_session_runtime_binding(
        grants,
        inputs.accounts,
        inputs.devices,
        inputs.connections,
    ) {
        Ok(Some(candidate)) => candidate,
        Ok(None) => {
            active_transport.take();
            collector.reset();
            return CloudSessionCycleOutcome::Disabled;
        }
        Err(_) => {
            active_transport.take();
            let _ =
                grants.record_health("unavailable", "unavailable", Some("local_binding_invalid"));
            collector.defer_after_local_failure(now + started.elapsed());
            return CloudSessionCycleOutcome::Failed;
        }
    };
    let binding = candidate.binding;
    // `load_cloud_session_runtime_binding` validates the destination first, so
    // an on-disk URL cannot receive this long-lived secret. Reloading the
    // device with the secret also closes an identity-change race.
    let (credential_device, device_secret) = match (inputs.load_credentials)() {
        Ok(credentials) => credentials,
        Err(_) => {
            active_transport.take();
            let _ = grants.record_health(
                "unavailable",
                "unavailable",
                Some("relay_credentials_unavailable"),
            );
            collector.defer_after_local_failure(now + started.elapsed());
            return CloudSessionCycleOutcome::Failed;
        }
    };
    if credential_device != binding.device || device_secret.trim().is_empty() {
        active_transport.take();
        let _ = grants.record_health("unavailable", "unavailable", Some("local_binding_changed"));
        collector.defer_after_local_failure(now + started.elapsed());
        return CloudSessionCycleOutcome::Failed;
    }
    let key = CloudSessionRuntimeTransportKey {
        binding: binding.clone(),
        device_secret_digest: sha256(device_secret.as_bytes()),
    };
    if active_transport
        .as_ref()
        .map_or(true, |(current, _)| current != &key)
    {
        let transport = (inputs.compose_transport)(
            binding.api_base_url.clone(),
            credential_device,
            device_secret,
        );
        *active_transport = Some((key, transport));
    }
    let transport = active_transport
        .as_ref()
        .expect("cloud-session transport was just composed")
        .1
        .as_ref();
    let outcome = collector.run_slice(
        &SliceInputs {
            grants,
            checkpoints: inputs.checkpoints,
            runner: inputs.runner,
            transport,
            destination: &binding.api_base_url,
            last_activity: inputs.last_activity,
        },
        now + started.elapsed(),
        wall,
    );
    if kill_switch_enabled() || !grant_preflight_eligible(grants) {
        active_transport.take();
    }
    outcome
}

/// Wakes the supervisor: a local consent change resets its schedule (one
/// immediate head), local Codex activity only re-evaluates the cadence.
struct CollectorWake {
    state: Mutex<WakeCounts>,
    changed: Condvar,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WakeCounts {
    consent: u64,
    activity: u64,
}

static COLLECTOR_WAKE: CollectorWake = CollectorWake {
    state: Mutex::new(WakeCounts {
        consent: 0,
        activity: 0,
    }),
    changed: Condvar::new(),
};
static LAST_CODEX_ACTIVITY: Mutex<Option<Instant>> = Mutex::new(None);

impl CollectorWake {
    fn counts(&self) -> WakeCounts {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn bump(&self, consent: bool) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if consent {
            state.consent = state.consent.wrapping_add(1);
        } else {
            state.activity = state.activity.wrapping_add(1);
        }
        self.changed.notify_all();
    }

    /// Wait until `until` (or the idle fallback) or a wake. True when local
    /// consent changed since `seen`.
    fn wait(&self, until: Option<Instant>, seen: &mut WakeCounts) -> bool {
        let fallback = Instant::now() + IDLE_HEAD_INTERVAL;
        let until = until.map_or(fallback, |until| until.min(fallback));
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if state.consent != seen.consent {
                *seen = *state;
                return true;
            }
            if state.activity != seen.activity {
                *seen = *state;
                return false;
            }
            let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                return false;
            };
            if remaining.is_zero() {
                return false;
            }
            state = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }
}

/// Local control changed cloud-session consent: run a fresh slice now.
pub fn wake_cloud_session_collector() {
    COLLECTOR_WAKE.bump(true);
}

/// The file watcher saw a real local Codex transcript event. Only the first
/// event of a warm window wakes the supervisor; later ones keep the window.
pub(crate) fn note_local_codex_activity() {
    let now = Instant::now();
    let was_warm = {
        let mut last = LAST_CODEX_ACTIVITY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let warm = last.is_some_and(|activity| {
            now.saturating_duration_since(activity)
                <= crate::adaptive_collector::CadenceConfig::default().warm_window
        });
        *last = Some(now);
        warm
    };
    if !was_warm {
        COLLECTOR_WAKE.bump(false);
    }
}

fn last_local_codex_activity() -> Option<Instant> {
    *LAST_CODEX_ACTIVITY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn reserve_collector_supervisor(started: &AtomicBool) -> bool {
    started
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .is_ok()
}

pub fn spawn_cloud_session_collector() -> Result<CloudSessionCollectorStartup> {
    // The supervisor is always available so a newly approved local grant can
    // activate without restarting the daemon. Each slice stays inert until
    // exact local consent and server authority both authorize collection.
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
            let mut collector = CloudCollector::default();
            let mut seen = COLLECTOR_WAKE.counts();
            loop {
                let outcome = collect_composed_cloud_sessions_once(
                    &mut collector,
                    &grants,
                    &checkpoints,
                    &runner,
                    &mut active_transport,
                    Instant::now(),
                );
                if outcome == CloudSessionCycleOutcome::Failed {
                    eprintln!("codex_cloud_session_collector outcome={outcome:?}");
                }
                let wake_at = collector.next_wake(
                    Instant::now(),
                    OffsetDateTime::now_utc(),
                    last_local_codex_activity(),
                );
                let wake_at = wake_at.map(|deadline| {
                    let mut random = [0_u8; 8];
                    let seconds = if random_fill(&mut random).is_ok() {
                        u64::from_ne_bytes(random) % 21
                    } else {
                        0
                    };
                    deadline + Duration::from_secs(seconds)
                });
                if COLLECTOR_WAKE.wait(wake_at, &mut seen) {
                    collector.reset();
                }
            }
        });
    if let Err(error) = spawned {
        COLLECTOR_SUPERVISOR_STARTED.store(false, AtomicOrdering::Release);
        return Err(anyhow!("spawn Codex cloud-session collector: {error}"));
    }
    Ok(CloudSessionCollectorStartup::Started)
}

#[cfg(test)]
mod tests;
