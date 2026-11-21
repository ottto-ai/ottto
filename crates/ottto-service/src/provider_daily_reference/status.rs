//! The credential-free status view served over the control socket, and the local
//! control helpers that act on the signed-in account.

use super::grant::{grant_runtime_ready, DailyReferenceGrant, GrantStatus, GrantStore};
use super::state::StateBinding;
use super::{
    logins, timestamp, unix_seconds, ServerPolicyState, COLLECTOR_ID, DISCLOSURE_VERSION_V1,
    GRANT_DIR, SOURCE,
};
use crate::grant_rebind;
use ottto_core::default_support_dir;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Operator/UI status view
// ---------------------------------------------------------------------------

/// Schema of the credential-free status view served over the control socket.
pub const COLLECTOR_STATUS_SCHEMA_VERSION: &str = "provider_daily_reference_collector_status.v1";

/// What the capability is actually doing right now, as opposed to what the
/// stored grant says. `grant_status` is the persisted consent record;
/// `runtime_state` folds in the local off-switch and server policy. Build
/// admission remains a backend upload decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    /// No consent record exists.
    Off,
    /// A consent record exists but cannot collect yet.
    ConsentRequired,
    /// Every gate passes; the collector may read on its next tick.
    Enabled,
    /// Consent was withdrawn locally, at the server, or both.
    Revoked,
    /// The server has not approved this grant (or has rolled the build back).
    PolicyDisabled,
    /// The local off-switch sentinel is present.
    NetworkDisabled,
    /// Consent remains enabled, but this signed-in account is suppressed.
    AccountExcluded,
}

/// Credential-free status view. Building it reads one local file and never
/// touches the account, device, connection, credential, or provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorStatusV1 {
    pub schema_version: String,
    pub source: String,
    pub collector_id: String,
    pub grant_status: GrantStatus,
    pub runtime_state: RuntimeState,
    /// True only when all five collection gates would pass right now. It is
    /// never an assertion that a read is in flight.
    pub provider_read_permitted: bool,
    /// The local off-switch sentinel.
    pub network_disabled: bool,
    /// True while a create was handed out but its backend response has not
    /// been bound. The UI must retry the idempotent POST and bind its answer.
    pub backend_create_pending: bool,
    pub reason_code: String,
    /// Opaque current-account label for matching the owner-authorized backend
    /// covered-account response. Never render this value as an account name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_account_fingerprint: Option<String>,
    #[serde(default)]
    pub current_account_excluded: bool,
    /// Every account the latest discovery selected under the current consent.
    /// Ordinals, home kinds and closed reasons only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<CollectorAccountStatusV1>,
}

/// One discovered account in the status view. Never a slot id, fingerprint,
/// binding, pair, digest or path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorAccountStatusV1 {
    /// 1-based position in discovery order.
    pub ordinal: u32,
    /// `default` or `slot`.
    pub home_kind: String,
    /// Closed reason of the account's last evaluated attempt.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
}

/// Build the status view for a given store and off-switch state.
///
/// `network_disabled` is a parameter rather than a read so tests can pin both
/// sides of the off-switch without touching the real support directory.
pub fn collector_status(grants: &GrantStore, network_disabled: bool) -> CollectorStatusV1 {
    let stored = grants.load().ok().flatten();
    let grant_status = stored
        .as_ref()
        .map(|grant| grant.status)
        .unwrap_or(GrantStatus::Off);
    let backend_create_pending = stored
        .as_ref()
        .is_some_and(|grant| grant.backend_create_pending);
    let policy_blocked = stored.as_ref().is_some_and(|grant| {
        grant.status == GrantStatus::Enabled
            && grant.backend_binding.as_ref().is_some_and(|binding| {
                binding.backend_revoked
                    || binding.server_policy_state != ServerPolicyState::Approved
            })
    });
    let runtime_ready = stored.as_ref().is_some_and(grant_runtime_ready);
    let provider_read_permitted = runtime_ready && !network_disabled;

    // Order matters: the most restrictive true statement wins, so a status can
    // never read as "enabled" while something above it is stopping collection.
    let (runtime_state, reason_code) = if network_disabled {
        (RuntimeState::NetworkDisabled, "network_disabled")
    } else if grant_status == GrantStatus::Revoked {
        (RuntimeState::Revoked, "revoked")
    } else if policy_blocked {
        (RuntimeState::PolicyDisabled, "policy_disabled")
    } else if backend_create_pending {
        (
            RuntimeState::ConsentRequired,
            "backend_grant_reconciliation_required",
        )
    } else if runtime_ready {
        (RuntimeState::Enabled, "enabled")
    } else if stored.is_some() {
        (RuntimeState::ConsentRequired, "consent_required")
    } else {
        (RuntimeState::Off, "setup_required")
    };

    CollectorStatusV1 {
        schema_version: COLLECTOR_STATUS_SCHEMA_VERSION.to_string(),
        source: SOURCE.to_string(),
        collector_id: COLLECTOR_ID.to_string(),
        grant_status,
        runtime_state,
        provider_read_permitted,
        network_disabled,
        backend_create_pending,
        reason_code: reason_code.to_string(),
        current_account_fingerprint: None,
        current_account_excluded: false,
        accounts: Vec::new(),
    }
}

/// Downgrade an otherwise-ready status when the live binding is not the one
/// consent covers, and report each discovered account.
///
/// [`collector_status`] reads the grant alone, so it cannot see what the
/// collector found. The collector records each tick's discovery in
/// `state.json`; status reads that summary, the grant and the caller's device
/// id. It never reads a credential. Anything a cycle refuses for, the status
/// has to be able to say.
pub fn status_with_live_binding(
    grants: &GrantStore,
    status: CollectorStatusV1,
    installation_id: Option<&str>,
) -> CollectorStatusV1 {
    if status.runtime_state != RuntimeState::Enabled {
        return status;
    }
    let Some(grant) = grants.load().ok().flatten() else {
        return status;
    };
    if let Some(reason) = grant
        .last_error_category
        .as_deref()
        .and_then(grant_rebind::status_reason)
    {
        return CollectorStatusV1 {
            runtime_state: RuntimeState::ConsentRequired,
            provider_read_permitted: false,
            reason_code: reason.to_string(),
            ..status
        };
    }
    let Some(installation_id) = installation_id else {
        return status;
    };
    if let Some(reason) = installation_mismatch(grants, &grant, installation_id) {
        return CollectorStatusV1 {
            runtime_state: RuntimeState::ConsentRequired,
            provider_read_permitted: false,
            reason_code: reason.to_string(),
            ..status
        };
    }
    let Some(binding) = grant.backend_binding.as_ref().map(StateBinding::of) else {
        return status;
    };
    let file = grants.state_store().load_file();
    let Some(summary) = file
        .discovery
        .as_ref()
        .filter(|summary| summary.binding == binding)
    else {
        return CollectorStatusV1 {
            reason_code: "discovery_pending".to_string(),
            ..status
        };
    };
    let live = summary
        .accounts
        .iter()
        .filter_map(|identity| file.entries.get(identity))
        .filter(|entry| entry.binding.as_ref() == Some(&binding))
        .filter_map(|entry| {
            let fingerprint = entry.account_fingerprint.as_deref()?;
            let excluded = grants.account_is_excluded(fingerprint).unwrap_or(false);
            Some((entry, fingerprint, excluded))
        })
        .collect::<Vec<_>>();
    let accounts = live
        .iter()
        .enumerate()
        .map(|(index, (entry, _, excluded))| CollectorAccountStatusV1 {
            ordinal: u32::try_from(index + 1).unwrap_or(u32::MAX),
            home_kind: entry.home_kind.clone().unwrap_or_default(),
            reason: if *excluded {
                "excluded".to_string()
            } else {
                entry
                    .last_reason
                    .clone()
                    .unwrap_or_else(|| "discovery_pending".to_string())
            },
            last_success_at: i64::try_from(entry.last_success_epoch_seconds)
                .ok()
                .filter(|seconds| *seconds > 0)
                .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
                .map(timestamp),
        })
        .collect::<Vec<_>>();
    let current_account_fingerprint = summary.default_home.fingerprint.clone();
    let current_account_excluded = current_account_fingerprint
        .as_deref()
        .is_some_and(|fingerprint| grants.account_is_excluded(fingerprint).unwrap_or(false));
    let status = CollectorStatusV1 {
        current_account_fingerprint,
        current_account_excluded,
        accounts,
        ..status
    };
    // A v1 grant covers one account: only that login can make reading
    // permitted, whatever else is signed in.
    let eligible = live
        .iter()
        .filter(|(_, fingerprint, _)| {
            grant.disclosure_version != DISCLOSURE_VERSION_V1
                || *fingerprint == grant.account_fingerprint
        })
        .collect::<Vec<_>>();
    if grant.disclosure_version == DISCLOSURE_VERSION_V1 && eligible.is_empty() {
        return CollectorStatusV1 {
            runtime_state: RuntimeState::ConsentRequired,
            provider_read_permitted: false,
            reason_code: "account_mismatch".to_string(),
            ..status
        };
    }
    if live.is_empty() {
        return CollectorStatusV1 {
            provider_read_permitted: false,
            reason_code: "no_live_codex_login".to_string(),
            ..status
        };
    }
    if eligible.iter().all(|(_, _, excluded)| *excluded) {
        return CollectorStatusV1 {
            runtime_state: RuntimeState::AccountExcluded,
            provider_read_permitted: false,
            reason_code: "account_excluded".to_string(),
            ..status
        };
    }
    status
}

/// The rebind reason when the caller's installation is not the one consent
/// was recorded for.
///
/// An unreadable fingerprint is NOT reported as a mismatch: failing to derive it
/// is not evidence that the installation differs, and claiming otherwise would
/// send a customer to re-approve for no reason.
fn installation_mismatch(
    grants: &GrantStore,
    grant: &DailyReferenceGrant,
    installation_id: &str,
) -> Option<&'static str> {
    let installation = grants
        .installation_fingerprint_for(installation_id)
        .ok()
        .flatten()?;
    (installation != grant.installation_fingerprint).then(|| {
        grant
            .last_error_category
            .as_deref()
            .and_then(grant_rebind::status_reason)
            .unwrap_or("rebinding")
    })
}

/// The Codex account scope a local privacy control acts on: the default
/// home's login, or with `prepare_fallback` the first live login. Never
/// called by Status, Bind, Revoke or ConfirmRevoked.
pub(crate) fn control_account_scope(prepare_fallback: bool) -> Option<String> {
    logins::control_account_scope(prepare_fallback, unix_seconds(OffsetDateTime::now_utc()))
}

/// Replay ledger for this capability's one-time control tokens.
///
/// It reuses the audited cloud-sessions ledger mechanics under its own file:
/// the ledger fails closed at capacity, so a burst on one capability must not
/// be able to lock the other one out.
pub fn control_token_use_store() -> crate::cloud_sessions::CloudSessionControlTokenUseStore {
    crate::cloud_sessions::CloudSessionControlTokenUseStore::new(
        default_support_dir()
            .join(GRANT_DIR)
            .join("control-token-uses.json"),
    )
}
