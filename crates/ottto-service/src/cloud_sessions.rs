//! Supported, metadata-only Codex Cloud session collector.
//!
//! The collector invokes only `codex cloud list --json` as the effective user.
//! It never opens `auth.json`, reads OpenAI credentials, or calls provider
//! endpoints directly. After exact consent and destination checks, it reads
//! only Ottto's relay device credential for Ottto backend authentication. Raw
//! CLI JSON, task titles, URLs, provider ids, and cursors are used only in
//! memory to derive content-free observations.

use crate::grant_rebind::{self, GrantKind, RebindProposal, RebindRequest};
use crate::hex::{decode as decode_hex, encode as hex, is_uuid};
use crate::local_resource_diagnostics::StageWindow;
use crate::locked_state_dir::FileLock;
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
                || (state.grant.status == CloudSessionGrantStatus::Revoked
                    && state
                        .grant
                        .backend_binding
                        .as_ref()
                        .is_some_and(|binding| !binding.backend_revoked))
            {
                return Err(anyhow!("pending cloud-session consent mutation must be reconciled before scope replacement"));
            }
            let same_owner = state.grant.organization_fingerprint
                == opaque_key(&key, &setup.organization_scope)
                && state.grant.effective_user_fingerprint
                    == opaque_key(&key, &setup.effective_user_scope);
            let can_resume = same_owner
                && state.grant.backend_binding.as_ref().is_some_and(|binding| {
                    !binding.backend_revoked
                        && binding.server_policy_state == CloudSessionServerPolicyState::Approved
                })
                && matches!(
                    state.grant.status,
                    CloudSessionGrantStatus::Enabled | CloudSessionGrantStatus::Paused
                )
                && matches!(
                    state.grant.last_error_category.as_deref(),
                    None | Some("rebinding" | "rebind_unavailable")
                );
            if can_resume {
                // Explicit resume restores admission to the original approval;
                // the supervisor rebinds it before any provider execution.
                state.grant.status = CloudSessionGrantStatus::Enabled;
                state.grant.paused_at = None;
                state.grant.last_error_category = Some("rebinding".to_string());
                self.write(&state)?;
                return Ok(state.grant);
            }
            // Explicit approval for another owner, or after a terminal refusal,
            // replaces the sole local approval. It never authorizes collection
            // until the ordinary-browser create response has been bound.
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

    fn prepare_rebind(
        &self,
        setup: &CloudSessionGrantSetup,
        hardware_id: String,
    ) -> Result<Option<RebindProposal<CloudSessionGrant>>> {
        let Some(state) = self.read()? else {
            return Ok(None);
        };
        if !cloud_grant_runtime_ready(&state.grant) {
            return Ok(None);
        }
        let key = decode_hex(&state.hmac_key_hex)
            .ok_or_else(|| anyhow!("invalid cloud-session HMAC key"))?;
        let installation_fingerprint = opaque_key(&key, &setup.installation_id);
        if installation_fingerprint == state.grant.installation_fingerprint {
            return Ok(None);
        }
        let version = state
            .grant
            .backend_binding
            .as_ref()
            .expect("runtime-ready binding")
            .grant_version;
        Ok(Some(RebindProposal {
            expected: state.grant.clone(),
            installation_fingerprint,
            request: RebindRequest {
                installation_id: setup.installation_id.clone(),
                grant_version: version,
                grant_scope_fingerprint: grant_scope_fingerprint(&key, setup),
                hardware_id: Some(hardware_id),
                disclosure_version: state.grant.disclosure_version,
            },
        }))
    }

    /// Bind an authenticated backend grant response. Exact scope matching and
    /// monotonic grant versions prevent a pre-revoke batch epoch from being
    /// resurrected after re-consent.
    pub fn bind_backend_grant(
        &self,
        response: &CloudSessionBackendGrantResponseV1,
        expected_installation_id: &str,
    ) -> Result<CloudSessionGrant> {
        self.bind_backend_grant_with_rebind(response, expected_installation_id, None)
    }

    fn bind_backend_grant_with_rebind(
        &self,
        response: &CloudSessionBackendGrantResponseV1,
        expected_installation_id: &str,
        rebind: Option<&RebindProposal<CloudSessionGrant>>,
    ) -> Result<CloudSessionGrant> {
        let _lock = self.lock()?;
        let mut state = self
            .read_locked()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        if let Some(proposal) = rebind {
            if !cloud_grant_runtime_ready(&state.grant)
                || !same_runtime_grant_identity(&state.grant, &proposal.expected)
                || state.grant.backend_binding != proposal.expected.backend_binding
                || response.grant_version != proposal.request.grant_version
                || response.status != "enabled"
            {
                return Err(anyhow!("cloud-session rebind consent changed"));
            }
            state.grant.installation_fingerprint = proposal.installation_fingerprint.clone();
            state.grant.grant_scope_id = proposal.request.grant_scope_fingerprint.clone();
            state
                .grant
                .backend_binding
                .as_mut()
                .expect("bound grant")
                .server_policy_state = response.server_policy_state.clone();
            if response.server_policy_state == CloudSessionServerPolicyState::Disabled {
                state.grant.status = CloudSessionGrantStatus::PolicyDisabled;
            }
        }
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
                if rebind.is_some() {
                    state.grant.last_error_category = None;
                    self.write(&state)?;
                }
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
            &response.installation_id,
            "backend cloud-session revocation",
        )?;
        validate_backend_grant_response(&state, response, &state.grant.collector_version)?;
        if !is_uuid(expected_installation_id) {
            return Err(anyhow!("current cloud-session installation is invalid"));
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
        if state.grant.status != CloudSessionGrantStatus::Enabled {
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
pub(crate) fn lock_state_file(state_path: &Path, label: &str) -> Result<FileLock> {
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
    let transport_configured = transport.is_configured() && transport.supports_grant_revalidation();
    let continuity_reason = stored_grant
        .as_ref()
        .and_then(|grant| grant.last_error_category.as_deref())
        .and_then(grant_rebind::status_reason);
    let provider_cli_invocation_permitted =
        stored_grant.as_ref().is_some_and(cloud_grant_runtime_ready)
            && transport_configured
            && continuity_reason.is_none()
            && !kill_switch_enabled();
    let (runtime_state, reason_code) = if kill_switch_enabled() {
        (
            CloudSessionRuntimeState::PolicyDisabled,
            "policy_disabled".to_string(),
        )
    } else if let Some(reason) = continuity_reason {
        (
            CloudSessionRuntimeState::ConsentRequired,
            reason.to_string(),
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
        transport: &dyn CloudSessionTransport,
    ) -> Result<Option<CloudSessionIoLease<'a>>> {
        let _identity_lock = crate::control::lock_setup_run_binding();
        if crate::control::identity_mutation_in_progress()
            || !transport.local_binding_current(expected)
        {
            return Ok(None);
        }
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
    /// Current local device/account authority must still match at every I/O fence.
    fn local_binding_current(&self, _grant: &CloudSessionGrant) -> bool {
        true
    }

    /// Provider execution also requires exact relay-authenticated grant authority.
    fn supports_grant_revalidation(&self) -> bool {
        false
    }
    /// Perform one bounded authenticated grant-list lookup and return the
    /// exact bound grant. Implementations must fail closed on any network,
    /// authentication, parsing, ambiguity, or absence error.
    #[cfg(test)]
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
/// It acquires through the shared relay-token cache and retries once on 401/403.
pub struct RelayCloudSessionTransport {
    client: crate::snapshot_client::SnapshotApiClient,
    device: LocalDeviceBinding,
    device_secret: String,
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

    fn send_with_relay_retry<F>(&self, timeout: Duration, send: F) -> Result<()>
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
        match send(&self.client, &token, request_timeout) {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .downcast_ref::<crate::snapshot_client::CloudSessionAuthorizationRejected>()
                    .is_some() =>
            {
                let refreshed = self.token(deadline)?;
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

    fn local_binding_current(&self, grant: &CloudSessionGrant) -> bool {
        if grant_rebind::verified_live_hardware().is_err() {
            return false;
        }
        load_cloud_session_runtime_binding(
            &CloudSessionGrantStore::default(),
            &FileAccountStore::default(),
            &FileDeviceStore::default(),
            &FileConnectionStore::default(),
        )
        .ok()
        .flatten()
        .is_some_and(|candidate| {
            candidate.binding.device == self.device
                && same_runtime_grant_identity(&candidate.grant, grant)
        })
    }

    fn supports_grant_revalidation(&self) -> bool {
        self.is_configured()
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
        let token = self.token(deadline)?;
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
                let refreshed = self.token(deadline)?;
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
        let token = self.token(deadline)?;
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
                let refreshed = self.token(deadline)?;
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

#[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
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
            .begin_collector_io(grants, &expected_grant, transport)
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
            collector_version: compiled_release_version(),
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
            collector_version: compiled_release_version(),
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
            .begin_collector_io(grants, &expected_grant, transport)
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
            .begin_collector_io(grants, &expected_grant, transport)
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
        .begin_collector_io(grants, expected, transport)
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
        .begin_collector_io(grants, expected, transport)
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
        collector_version: compiled_release_version(),
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
    let (setup, api_base_url, device) =
        load_cloud_session_local_identity(accounts, devices, connections)?;
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

fn load_cloud_session_local_identity(
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
    connections: &FileConnectionStore,
) -> Result<(CloudSessionGrantSetup, String, LocalDeviceBinding)> {
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
    Ok((setup, api_base_url, device))
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
    let _stage = StageWindow::begin("codex", "offpass_cloud_sessions");
    let accounts = FileAccountStore::default();
    let devices = FileDeviceStore::default();
    let connections = FileConnectionStore::default();
    if !kill_switch_enabled() && grant_preflight_eligible(grants) {
        let hardware = match grant_rebind::verified_live_hardware() {
            Ok(hardware) => hardware,
            Err(reason) => {
                deactivate_composed_runtime(active_transport, checkpoints);
                let _ = grants.record_health("unavailable", "unavailable", Some(reason));
                return CloudSessionCycleOutcome::Disabled;
            }
        };
        let identity = load_cloud_session_local_identity(&accounts, &devices, &connections);
        if let Ok((setup, api_base_url, device)) = identity {
            let proposal = grants.prepare_rebind(&setup, hardware);
            if let Ok(Some(proposal)) = proposal {
                deactivate_composed_runtime(active_transport, checkpoints);
                let _ = grants.record_health("unavailable", "unavailable", Some("rebinding"));
                let credentials = crate::snapshot_client::load_snapshot_device_credentials();
                let result = match credentials {
                    Ok((credential_device, secret)) if credential_device == device => {
                        let client = crate::snapshot_client::SnapshotApiClient::new(api_base_url);
                        let binding = proposal
                            .expected
                            .backend_binding
                            .as_ref()
                            .expect("bound grant");
                        grant_rebind::rebind(
                            &client,
                            GrantKind::CloudSessions,
                            &binding.grant_id,
                            &proposal.request,
                            &device,
                            &secret,
                            COMMAND_TIMEOUT,
                        )
                    }
                    _ => Err(grant_rebind::RebindFailure::unavailable()),
                };
                match result {
                    Ok(value) => {
                        let response =
                            serde_json::from_value::<CloudSessionBackendGrantResponseV1>(value);
                        if response
                            .ok()
                            .and_then(|response| {
                                grants
                                    .bind_backend_grant_with_rebind(
                                        &response,
                                        &setup.installation_id,
                                        Some(&proposal),
                                    )
                                    .ok()
                            })
                            .is_none()
                        {
                            let _ = grants.record_health(
                                "unavailable",
                                "unavailable",
                                Some("stale_binding"),
                            );
                            return CloudSessionCycleOutcome::Failed;
                        }
                    }
                    Err(failure) => {
                        let _ =
                            grants.record_health("unavailable", "unavailable", Some(failure.code));
                        return CloudSessionCycleOutcome::Disabled;
                    }
                }
            }
        }
    }
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

#[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
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
mod tests;
