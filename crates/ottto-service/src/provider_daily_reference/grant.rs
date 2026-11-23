//! Consent for the daily-reference read: the versioned, revocable grant file,
//! its backend binding and rebind, and the single answer to whether this build
//! may collect.

use super::state::StateStore;
use super::wire::is_fingerprint;
use super::{
    atomic_json_write, opaque_key, timestamp, GrantResponse, ServerPolicyState, COLLECTOR_ID,
    DISCLOSURE_VERSION, DISCLOSURE_VERSION_V1, GRANT_DIR, GRANT_FILE, GRANT_FILE_SCHEMA_VERSION,
    RELEASE_LANE, SCHEMA_VERSION, SOURCE, STATE_FILE,
};
use crate::grant_rebind::{RebindProposal, RebindRequest};
use crate::hex::{decode as decode_hex, encode as hex, is_uuid};
use anyhow::{anyhow, Context, Result};
use getrandom::fill as random_fill;
use ottto_core::{compiled_release_version, default_support_dir};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

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
    /// Informational build recorded from the backend grant response. Only
    /// [`GrantStore::bind_backend_grant`] writes it; uploads independently
    /// report the running build for backend admission.
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
    /// The provider account signed in when consent is approved. It supplies
    /// the initial attribution fingerprint only; disclosure v2 authorization
    /// is user + installation scoped and never gates on this value.
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

/// The exact `DELETE /api/v1/provider-daily-reference/grants/{grant_id}` target
/// retained after a local revoke, so the companion/UI finishes revocation with
/// ordinary user auth instead of guessing an id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRevokeTarget {
    pub grant_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PersistedGrant {
    schema_version: String,
    pub(super) hmac_key_hex: String,
    pub(super) grant: DailyReferenceGrant,
    #[serde(default)]
    pub(super) excluded_account_fingerprints: BTreeSet<String>,
}

/// Why the grant file did not yield consent.
#[derive(Debug)]
enum GrantFileGap {
    /// No file: nobody approved on this Mac.
    Absent,
    /// The file exists but could not be read.
    Unreadable(std::io::Error),
    /// The file was read but is not a usable grant. Closed reason code.
    Unusable(&'static str),
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

    pub(super) fn read(&self) -> Result<Option<PersistedGrant>> {
        match self.read_checked() {
            Ok(state) => Ok(Some(state)),
            Err(GrantFileGap::Absent | GrantFileGap::Unusable(_)) => Ok(None),
            Err(GrantFileGap::Unreadable(error)) => {
                Err(error).context("read codex daily aggregates grant")
            }
        }
    }

    /// [`Self::read`] that keeps apart the reasons a file is not consent.
    fn read_checked(&self) -> std::result::Result<PersistedGrant, GrantFileGap> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(GrantFileGap::Absent)
            }
            Err(error) => return Err(GrantFileGap::Unreadable(error)),
        };
        let state: PersistedGrant = match serde_json::from_str(&raw) {
            Ok(state) => state,
            // An unreadable or superseded grant file is not consent. Refuse it
            // rather than repairing it into something that looks live.
            Err(_) => return Err(GrantFileGap::Unusable("grant_file_corrupt")),
        };
        if state.schema_version != GRANT_FILE_SCHEMA_VERSION {
            return Err(GrantFileGap::Unusable("grant_file_schema_unsupported"));
        }
        if !matches!(decode_hex(&state.hmac_key_hex), Some(key) if key.len() == 32) {
            return Err(GrantFileGap::Unusable("grant_file_key_invalid"));
        }
        Ok(state)
    }

    pub fn load(&self) -> Result<Option<DailyReferenceGrant>> {
        Ok(self.read()?.map(|state| state.grant))
    }

    /// [`Self::load`] for the collection cycle, which has to tell "nobody
    /// approved" (`Ok(None)`, silent) from "a consent file is here but cannot
    /// be used" (`Err`, a closed reason code). Both are equally not consent.
    pub(super) fn load_for_cycle(
        &self,
    ) -> std::result::Result<Option<DailyReferenceGrant>, &'static str> {
        match self.read_checked() {
            Ok(state) => Ok(Some(state.grant)),
            Err(GrantFileGap::Absent) => Ok(None),
            Err(GrantFileGap::Unreadable(_)) => Err("grant_file_unreadable"),
            Err(GrantFileGap::Unusable(reason)) => Err(reason),
        }
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

    /// Whether this opaque account is locally suppressed. The set contains no
    /// provider identifier and survives daemon restarts and consent epochs.
    pub fn account_is_excluded(&self, account_fingerprint: &str) -> Result<bool> {
        Ok(self.read()?.is_some_and(|state| {
            state
                .excluded_account_fingerprints
                .contains(account_fingerprint)
        }))
    }

    /// This installation's attribution key, for fingerprinting many logins
    /// with one grant read.
    pub(crate) fn hmac_key(&self) -> Result<Option<Vec<u8>>> {
        let Some(state) = self.read()? else {
            return Ok(None);
        };
        Ok(Some(
            decode_hex(&state.hmac_key_hex).ok_or_else(|| anyhow!("grant key is invalid"))?,
        ))
    }

    /// The collector state that sits next to this grant.
    pub(crate) fn state_store(&self) -> StateStore {
        StateStore::new(self.path.with_file_name(STATE_FILE))
    }

    /// Mirror the backend's durable exclusion locally so future cycles stop
    /// before contacting the provider rather than repeating a refused upload.
    pub fn set_account_excluded(&self, account_fingerprint: &str, excluded: bool) -> Result<()> {
        self.set_account_excluded_where(account_fingerprint, excluded, None)
            .map(|_| ())
    }

    /// [`Self::set_account_excluded`] from inside a tick: writes only while
    /// the grant is still the `expected` binding. `Ok(false)` wrote nothing.
    pub(super) fn set_account_excluded_for(
        &self,
        expected: &BackendGrantBinding,
        account_fingerprint: &str,
    ) -> Result<bool> {
        self.set_account_excluded_where(account_fingerprint, true, Some(expected))
    }

    fn set_account_excluded_where(
        &self,
        account_fingerprint: &str,
        excluded: bool,
        expected: Option<&BackendGrantBinding>,
    ) -> Result<bool> {
        let _lock = crate::cloud_sessions::lock_state_file(&self.path, "daily reference grant")?;
        if !is_fingerprint(account_fingerprint) {
            return Err(anyhow!("account fingerprint is invalid"));
        }
        let mut state = self
            .read()?
            .ok_or_else(|| anyhow!("codex daily aggregates consent is absent"))?;
        if expected
            .is_some_and(|expected| !same_binding(state.grant.backend_binding.as_ref(), expected))
        {
            return Ok(false);
        }
        if excluded {
            state
                .excluded_account_fingerprints
                .insert(account_fingerprint.to_string());
        } else {
            state
                .excluded_account_fingerprints
                .remove(account_fingerprint);
        }
        atomic_json_write(&self.path, &state)?;
        Ok(true)
    }

    /// Record local consent. The grant is not live until the backend binds it:
    /// `backend_create_pending` is set, so [`grant_runtime_ready`] refuses it.
    pub fn enable(&self, setup: &GrantSetup, now: OffsetDateTime) -> Result<DailyReferenceGrant> {
        let _lock = crate::cloud_sessions::lock_state_file(&self.path, "daily reference grant")?;
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
            excluded_account_fingerprints: self
                .read()?
                .map(|state| state.excluded_account_fingerprints)
                .unwrap_or_default(),
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

    pub(super) fn prepare_rebind(
        &self,
        setup: &GrantSetup,
        hardware_id: String,
    ) -> Result<Option<RebindProposal<DailyReferenceGrant>>> {
        let Some(state) = self.read()? else {
            return Ok(None);
        };
        if !grant_runtime_ready(&state.grant) {
            return Ok(None);
        }
        let key = decode_hex(&state.hmac_key_hex).ok_or_else(|| anyhow!("invalid grant key"))?;
        let installation_fingerprint = opaque_key(&key, &setup.installation_id);
        if installation_fingerprint == state.grant.installation_fingerprint {
            return Ok(None);
        }
        if state.grant.disclosure_version == DISCLOSURE_VERSION_V1
            && opaque_key(&key, &setup.provider_account_scope) != state.grant.account_fingerprint
        {
            return Err(anyhow!("v1 account binding changed"));
        }
        let scope = if state.grant.disclosure_version == DISCLOSURE_VERSION_V1 {
            opaque_key(
                &key,
                &format!(
                    "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
                    setup.installation_id,
                    setup.organization_scope,
                    setup.effective_user_scope,
                    setup.provider_account_scope,
                    COLLECTOR_ID
                ),
            )
        } else {
            grant_scope_fingerprint(&key, setup)
        };
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
                grant_scope_fingerprint: scope,
                hardware_id: Some(hardware_id),
                disclosure_version: state.grant.disclosure_version,
            },
        }))
    }

    /// Bind the server's answer. This is the only writer of `collector_version`
    /// and of the backend binding. Build governance remains server-owned: each
    /// upload reports the running release for backend admission.
    pub fn bind_backend_grant(
        &self,
        response: &GrantResponse,
        expected_installation_id: &str,
    ) -> Result<DailyReferenceGrant> {
        self.bind_backend_grant_with_rebind(response, expected_installation_id, None)
    }

    pub(super) fn bind_backend_grant_with_rebind(
        &self,
        response: &GrantResponse,
        expected_installation_id: &str,
        rebind: Option<&RebindProposal<DailyReferenceGrant>>,
    ) -> Result<DailyReferenceGrant> {
        let _lock = crate::cloud_sessions::lock_state_file(&self.path, "daily reference grant")?;
        let mut state = self
            .read()?
            .ok_or_else(|| anyhow!("codex daily aggregates consent is absent"))?;
        let key = decode_hex(&state.hmac_key_hex)
            .ok_or_else(|| anyhow!("stored grant key is invalid"))?;
        if let Some(proposal) = rebind {
            let mut consent_binding = state.grant.backend_binding.clone();
            if state.grant.status == GrantStatus::Revoked {
                // A successful in-flight response may only advance cleanup
                // identity; local revocation and its timestamp remain final.
                if let Some(binding) = consent_binding.as_mut() {
                    binding.backend_revoked = false;
                }
            }
            if !(grant_runtime_ready(&state.grant) || state.grant.status == GrantStatus::Revoked)
                || consent_binding != proposal.expected.backend_binding
                || state.grant.installation_fingerprint
                    != proposal.expected.installation_fingerprint
                || state.grant.grant_scope_fingerprint != proposal.expected.grant_scope_fingerprint
                || state.grant.account_fingerprint != proposal.expected.account_fingerprint
                || state.grant.disclosure_version != proposal.expected.disclosure_version
                || state.grant.collector_version != proposal.expected.collector_version
                || response.grant_version != proposal.request.grant_version
                || response.status != "enabled"
                || response.server_policy_state != ServerPolicyState::Approved
                || response.collector_version != state.grant.collector_version
            {
                return Err(anyhow!("rebind consent changed"));
            }
            state.grant.installation_fingerprint = proposal.installation_fingerprint.clone();
            state.grant.grant_scope_fingerprint = proposal.request.grant_scope_fingerprint.clone();
        }
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
        if response.grant_version == previous_version
            && state.grant.backend_binding.as_ref().is_some_and(|binding| {
                binding.grant_id == response.id
                    && (!binding.backend_revoked
                        || (rebind.is_some() && state.grant.status == GrantStatus::Revoked))
                    && binding.server_policy_state == response.server_policy_state
            })
            && (state.grant.status == GrantStatus::Enabled
                || (rebind.is_some() && state.grant.status == GrantStatus::Revoked))
            && response.status == "enabled"
            && state.grant.collector_version == response.collector_version
        {
            if rebind.is_some() {
                state.grant.last_error_category = None;
                atomic_json_write(&self.path, &state)?;
            }
            return Ok(state.grant);
        }
        if response.grant_version <= previous_version {
            return Err(anyhow!(
                "backend grant epoch did not advance past the recorded epoch"
            ));
        }
        let revoked = response.status == "revoked";
        let local_status = state.grant.status;
        state.grant.collector_version = response.collector_version.clone();
        state.grant.backend_binding = Some(BackendGrantBinding {
            grant_id: response.id.clone(),
            grant_version: response.grant_version,
            backend_revoked: revoked,
            server_policy_state: response.server_policy_state,
        });
        state.grant.backend_create_pending = false;
        if local_status == GrantStatus::Revoked {
            // A create can commit at the backend just before local revoke. Keep
            // only its exact identity, so the compensating DELETE has a target;
            // local revoked state keeps blocking every provider admission and
            // binding never resurrects withdrawn consent.
            state.grant.status = GrantStatus::Revoked;
            state.grant.last_success_at = None;
            state.grant.last_error_category = None;
            atomic_json_write(&self.path, &state)?;
            return Ok(state.grant);
        }
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
        let _lock = crate::cloud_sessions::lock_state_file(&self.path, "daily reference grant")?;
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

    /// The exact backend grant to DELETE after a local revoke.
    ///
    /// A grant whose create was never reconciled has no id to delete, and
    /// guessing one is worse than reporting that there is nothing to delete.
    pub fn grant_revoke_target(&self) -> Result<GrantRevokeTarget> {
        let grant = self
            .load()?
            .ok_or_else(|| anyhow!("codex daily aggregates consent is absent"))?;
        let binding = grant
            .backend_binding
            .ok_or_else(|| anyhow!("backend codex daily aggregates grant is unbound"))?;
        Ok(GrantRevokeTarget {
            grant_id: binding.grant_id,
        })
    }

    /// Apply the server's exact DELETE response after a local revoke.
    ///
    /// Separate from [`GrantStore::bind_backend_grant`] because revocation is
    /// the one transition that must accept an unchanged epoch: the backend's
    /// DELETE is idempotent, so a retried delete answers with the same
    /// `grant_version` it first returned. The epoch is still retained
    /// monotonically, so re-consent has to bind a newer one.
    pub fn apply_backend_revocation(
        &self,
        response: &GrantResponse,
        expected_installation_id: &str,
    ) -> Result<DailyReferenceGrant> {
        let _lock = crate::cloud_sessions::lock_state_file(&self.path, "daily reference grant")?;
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
        let existing = state
            .grant
            .backend_binding
            .as_ref()
            .ok_or_else(|| anyhow!("backend codex daily aggregates grant is unbound"))?;
        if response.status != "revoked"
            || response.id != existing.grant_id
            || response.grant_version < existing.grant_version
        {
            return Err(anyhow!(
                "backend codex daily aggregates revocation does not match"
            ));
        }
        state.grant.backend_binding = Some(BackendGrantBinding {
            grant_id: response.id.clone(),
            grant_version: response.grant_version,
            backend_revoked: true,
            server_policy_state: response.server_policy_state,
        });
        state.grant.backend_create_pending = false;
        state.grant.status = GrantStatus::Revoked;
        state.grant.revoked_at = Some(timestamp(OffsetDateTime::now_utc()));
        state.grant.last_success_at = None;
        state.grant.last_error_category = None;
        atomic_json_write(&self.path, &state)?;
        Ok(state.grant)
    }

    /// Record collector health. Never resurrects a non-enabled grant.
    pub(super) fn record_health(
        &self,
        success_at: Option<&str>,
        error_category: Option<&str>,
    ) -> Result<()> {
        self.record_health_where(None, success_at, error_category)
            .map(|_| ())
    }

    /// [`Self::record_health`] from inside a tick: writes only while the
    /// grant is still the `expected` binding. `Ok(false)` wrote nothing.
    pub(super) fn record_health_for(
        &self,
        expected: &BackendGrantBinding,
        success_at: Option<&str>,
        error_category: Option<&str>,
    ) -> Result<bool> {
        self.record_health_where(Some(expected), success_at, error_category)
    }

    fn record_health_where(
        &self,
        expected: Option<&BackendGrantBinding>,
        success_at: Option<&str>,
        error_category: Option<&str>,
    ) -> Result<bool> {
        let _lock = crate::cloud_sessions::lock_state_file(&self.path, "daily reference grant")?;
        let Some(mut state) = self.read()? else {
            return Ok(false);
        };
        if state.grant.status != GrantStatus::Enabled
            || expected.is_some_and(|expected| {
                !same_binding(state.grant.backend_binding.as_ref(), expected)
            })
        {
            return Ok(false);
        }
        if let Some(success_at) = success_at {
            state.grant.last_success_at = Some(success_at.to_string());
        }
        state.grant.last_error_category = error_category.map(|value| value.to_string());
        atomic_json_write(&self.path, &state)?;
        Ok(true)
    }
}

/// Whether a stored binding is the `(grant_id, grant_version)` a tick began
/// with. Two reads that agree are the same consent.
pub(super) fn same_binding(
    stored: Option<&BackendGrantBinding>,
    expected: &BackendGrantBinding,
) -> bool {
    stored.is_some_and(|binding| {
        binding.grant_id == expected.grant_id && binding.grant_version == expected.grant_version
    })
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
        || response.disclosure_version != grant.disclosure_version
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
/// `disclosure_version` remains the local "what is read" gate and must match.
/// Collector build governance lives in the backend admission list, so a daemon
/// upgrade does not make stored consent ineligible or require re-consent.
pub fn grant_runtime_ready(grant: &DailyReferenceGrant) -> bool {
    grant_runtime_block_reason(grant).is_none()
}

/// Which single condition stops a stored grant from collecting, if any.
///
/// `grant_runtime_ready` is the boolean this answers. Kept separate so a
/// refusal can name its own cause: a grant that exists but cannot collect used
/// to end the cycle in silence, which reads exactly like "nothing to report".
/// Returns a fixed vocabulary, never grant contents.
pub fn grant_runtime_block_reason(grant: &DailyReferenceGrant) -> Option<&'static str> {
    if grant.status != GrantStatus::Enabled {
        return Some("grant_not_enabled");
    }
    if grant.schema_version != SCHEMA_VERSION {
        return Some("schema_version_mismatch");
    }
    if grant.source != SOURCE {
        return Some("source_mismatch");
    }
    if grant.collector_id != COLLECTOR_ID {
        return Some("collector_id_mismatch");
    }
    if !matches!(
        grant.disclosure_version.as_str(),
        DISCLOSURE_VERSION | DISCLOSURE_VERSION_V1
    ) {
        return Some("disclosure_version_mismatch");
    }
    if grant.backend_create_pending {
        return Some("backend_create_pending");
    }
    let Some(binding) = grant.backend_binding.as_ref() else {
        return Some("no_backend_binding");
    };
    if binding.backend_revoked {
        return Some("backend_revoked");
    }
    if binding.server_policy_state != ServerPolicyState::Approved {
        return Some("server_policy_not_approved");
    }
    if binding.grant_version < 1 {
        return Some("grant_version_below_one");
    }
    None
}

fn grant_scope_fingerprint(key: &[u8], setup: &GrantSetup) -> String {
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

fn random_key() -> Result<Vec<u8>> {
    let mut key = vec![0_u8; 32];
    random_fill(&mut key).map_err(|_| anyhow!("generate codex daily aggregates HMAC key"))?;
    Ok(key)
}
