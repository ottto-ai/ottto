//! Claude status upkeep operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::bounded_claude_collection_timestamp;
use crate::agent_status::claude_snapshot_has_account_windows;
use crate::agent_status::local_claude_quota_snapshot;
use crate::agent_status::read_persisted_claude_slot_collection_state;
use crate::agent_status::retain_registered_claude_slot_binding;
use crate::agent_status::safe_claude_slot_check_diagnostics;
use crate::agent_status::stale_local_claude_quota_snapshot;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentQuotaWindowScope;
use crate::agent_status::AgentStatusCollectionMethod;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusSnapshot;
#[cfg(test)]
use crate::agent_status::ClaudeConfigDirSlot;
use crate::agent_status::ClaudeConfigSlotCollectionStateV1;
use crate::agent_status::ClaudeConfigSlotCollectionStatusV1;
use crate::agent_status::ClaudeConfigSlotDescriptorV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticCodeV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticV1;
#[cfg(test)]
use crate::agent_status::ClaudeConfigSlotOwnership;
use crate::agent_status::ClaudeConfigSlotUpkeepResultV1;
use crate::agent_status::ClaudeOAuthCredential;
use crate::agent_status::ClaudeSlotProbeFailure;
use crate::agent_status::ClaudeTokenOwner;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Rfc3339;
use crate::agent_status::TimeDuration;

pub(in crate::agent_status) fn claude_default_slot_collection_status(
    snapshot: &AgentStatusSnapshot,
) -> ClaudeConfigSlotCollectionStatusV1 {
    for failure in [
        ClaudeSlotProbeFailure::CredentialUnavailable,
        ClaudeSlotProbeFailure::ProbeFailed,
        ClaudeSlotProbeFailure::ConcurrentMutation,
        ClaudeSlotProbeFailure::OwnerUnproven,
        ClaudeSlotProbeFailure::IdentityMismatch,
        ClaudeSlotProbeFailure::IdentityUnknown,
    ] {
        if snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == failure.diagnostic_code())
        {
            return failure.status(&snapshot.captured_at);
        }
    }
    if snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_auth_status_failed")
    {
        return ClaudeSlotProbeFailure::CredentialUnavailable.status(&snapshot.captured_at);
    }
    let hashes = snapshot.account.as_ref().and_then(|account| {
        Some((
            account.account_identifier_hash.as_deref()?,
            account.organization_identifier_hash.as_deref()?,
        ))
    });
    match hashes {
        Some((account_hash, organization_hash))
            if snapshot.collection_method == AgentStatusCollectionMethod::StatusLine
                && !snapshot.quota_windows.is_empty()
                && snapshot.credit_balances.is_empty()
                && snapshot.quota_windows.iter().all(|window| {
                    window.account_identifier_hash.as_deref() == Some(account_hash)
                        && window.organization_identifier_hash.is_none()
                }) =>
        {
            fresh_slot_status(
                &snapshot.captured_at,
                account_hash,
                organization_hash,
                snapshot
                    .quota_windows
                    .iter()
                    .any(|window| window.name == "session")
                    && snapshot
                        .quota_windows
                        .iter()
                        .any(|window| window.name == "weekly"),
                false,
                false,
            )
        }
        Some((account_hash, organization_hash))
            if !snapshot.quota_windows.is_empty()
                && snapshot.quota_windows.iter().all(|window| {
                    window.account_identifier_hash.as_deref() == Some(account_hash)
                        && window.organization_identifier_hash.as_deref() == Some(organization_hash)
                        && window.freshness == AgentQuotaWindowFreshness::Fresh
                })
                // Credit sections keep their own freshness; the state is the meters'.
                && snapshot.credit_balances.iter().all(|balance| {
                    balance.account_identifier_hash.as_deref() == Some(account_hash)
                        && balance.organization_identifier_hash.as_deref()
                            == Some(organization_hash)
                }) =>
        {
            let mut status = fresh_slot_status(
                &snapshot.captured_at,
                account_hash,
                organization_hash,
                claude_snapshot_has_account_windows(snapshot),
                snapshot.quota_windows.iter().any(|window| {
                    window.scope == AgentQuotaWindowScope::Model
                        || window.model.is_some()
                        || window.group.is_some()
                }),
                !snapshot.credit_balances.is_empty(),
            );
            status.quota_snapshot = Some(local_claude_quota_snapshot(
                &snapshot.captured_at,
                &snapshot.quota_windows,
                &snapshot.credit_balances,
                status.has_account_windows,
                status.has_scoped_limits,
            ));
            status
        }
        Some((account_hash, organization_hash)) => {
            let mut status =
                provider_unavailable_status(&snapshot.captured_at, account_hash, organization_hash);
            let exact_values = !snapshot.quota_windows.is_empty()
                && snapshot.quota_windows.iter().all(|window| {
                    window.account_identifier_hash.as_deref() == Some(account_hash)
                        && window.organization_identifier_hash.as_deref() == Some(organization_hash)
                })
                && snapshot.credit_balances.iter().all(|balance| {
                    balance.account_identifier_hash.as_deref() == Some(account_hash)
                        && balance.organization_identifier_hash.as_deref()
                            == Some(organization_hash)
                });
            if exact_values {
                status.has_account_windows = claude_snapshot_has_account_windows(snapshot);
                status.has_scoped_limits = snapshot.quota_windows.iter().any(|window| {
                    window.scope == AgentQuotaWindowScope::Model
                        || window.model.is_some()
                        || window.group.is_some()
                });
                status.has_credit_balances = !snapshot.credit_balances.is_empty();
                status.quota_snapshot = Some(local_claude_quota_snapshot(
                    &snapshot.captured_at,
                    &snapshot.quota_windows,
                    &snapshot.credit_balances,
                    status.has_account_windows,
                    status.has_scoped_limits,
                ));
            }
            status
        }
        None if snapshot
            .account
            .as_ref()
            .is_some_and(|account| account.login_state != AgentLoginState::SignedIn) =>
        {
            ClaudeSlotProbeFailure::CredentialUnavailable.status(&snapshot.captured_at)
        }
        None => ClaudeSlotProbeFailure::IdentityUnknown.status(&snapshot.captured_at),
    }
}

pub(in crate::agent_status) fn apply_credential_metadata(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    credential: &ClaudeOAuthCredential,
) {
    status.access_expires_at = credential.access_expires_at.clone();
    status.relogin_required_at = credential.relogin_required_at.clone();
}

pub(in crate::agent_status) fn blocked_claude_upkeep_status(
    slot_id: &str,
    observed_at: &str,
    upkeep: ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let mut status = read_persisted_claude_slot_collection_state()
        .slots
        .get(slot_id)
        .cloned()
        .unwrap_or_default();
    status.observed_at = Some(observed_at.to_string());
    if upkeep.due_access_expires_at.is_some() {
        status.access_expires_at = upkeep.due_access_expires_at.clone();
    }
    if upkeep.refresh_token_expires_at.is_some() {
        status.relogin_required_at = upkeep.refresh_token_expires_at.clone();
    }
    let (state, code, message) = upkeep_state_diagnostic(upkeep.result);
    status.state = state;
    status.quota_snapshot = status
        .quota_snapshot
        .as_ref()
        .map(stale_local_claude_quota_snapshot);
    status.diagnostics = vec![ClaudeConfigSlotDiagnosticV1 {
        code,
        message: message.to_string(),
    }];
    status.upkeep = Some(upkeep);
    status
}

/// A registered slot whose access login lapsed while its refresh grant is
/// alive. Ottto does not refresh it (that can sign the account out), so the
/// last reading stays, marked stale, until Claude Code refreshes the login or
/// the user signs in again; the next pass resumes on its own.
///
/// No new wire values: the quiet default is collection `refresh_due` with
/// upkeep `upkeep_disabled` (quota access `paused`), never
/// `stale_access_token`, which tells the app the provider ended the session.
pub(in crate::agent_status) fn paused_claude_refresh_status(
    slot_id: &str,
    observed_at: &str,
    upkeep: ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let mut status = read_persisted_claude_slot_collection_state()
        .slots
        .get(slot_id)
        .cloned()
        .unwrap_or_default();
    status.observed_at = Some(observed_at.to_string());
    if upkeep.due_access_expires_at.is_some() {
        status.access_expires_at = upkeep.due_access_expires_at.clone();
    }
    if upkeep.refresh_token_expires_at.is_some() {
        status.relogin_required_at = upkeep.refresh_token_expires_at.clone();
    }
    let expired_at = upkeep
        .due_access_expires_at
        .clone()
        .unwrap_or_else(|| "an unknown time".to_string());
    let refreshing = upkeep.result == ClaudeConfigSlotUpkeepResultV1::InProgress;
    let message = if refreshing {
        format!(
            "This sign-in expired at {expired_at}; Ottto is refreshing it in the background now. The last reading is shown with its age until the refresh finishes."
        )
    } else {
        format!(
            "Claude Code has not refreshed this sign-in since it expired at {expired_at}. \"Keep my Claude accounts signed in\" is off, so Ottto does not refresh it. The last reading is shown with its age. Sign in again, or turn the setting on, to resume now."
        )
    };
    let (state, code) = (
        ClaudeConfigSlotCollectionStateV1::RefreshDue,
        ClaudeConfigSlotDiagnosticCodeV1::RefreshDue,
    );
    status.state = state;
    status.quota_snapshot = status
        .quota_snapshot
        .as_ref()
        .map(stale_local_claude_quota_snapshot);
    status.diagnostics = vec![ClaudeConfigSlotDiagnosticV1 { code, message }];
    // Old background-worker receipts describe a refresher that no longer
    // runs; they must not escalate or explain this state.
    status
        .quota_check_diagnostics
        .retain(|diagnostic| !diagnostic.code.starts_with("claude_slot_worker_"));
    apply_claude_upkeep_observation(&mut status, upkeep);
    status
}

pub(in crate::agent_status) fn apply_claude_upkeep_observation(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    upkeep: ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) {
    let relogin_warning = claude_relogin_warning(
        upkeep.refresh_token_expires_at.as_deref(),
        OffsetDateTime::now_utc(),
    );
    let deadline_approaching = relogin_warning.is_some();
    match upkeep.result {
        ClaudeConfigSlotUpkeepResultV1::ReloginApproaching => {
            status.diagnostics.push(ClaudeConfigSlotDiagnosticV1 {
                code: ClaudeConfigSlotDiagnosticCodeV1::ReloginApproaching,
                message: relogin_warning.clone().unwrap_or_else(|| {
                    "This Claude login reaches its absolute refresh deadline within 3 days; sign in again before then.".to_string()
                }),
            });
        }
        ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented => {
            status.diagnostics.push(ClaudeConfigSlotDiagnosticV1 {
                code: ClaudeConfigSlotDiagnosticCodeV1::UpkeepNotConsented,
                message: "Background Claude login upkeep is not consented; valid credentials remain readable until they expire.".to_string(),
            });
        }
        _ => {}
    }
    if deadline_approaching && upkeep.result != ClaudeConfigSlotUpkeepResultV1::ReloginApproaching {
        status.diagnostics.push(ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::ReloginApproaching,
            message: relogin_warning.unwrap_or_default(),
        });
    }
    status.upkeep = Some(upkeep);
}

/// The login lifetime warning, from the stored `refreshTokenExpiresAt` (about
/// 28 days after a browser sign-in): 3 days before, then 1 day before. No new
/// wire value: the existing `relogin_approaching` diagnostic carries it.
pub(in crate::agent_status) fn claude_relogin_warning(
    refresh_token_expires_at: Option<&str>,
    now: OffsetDateTime,
) -> Option<String> {
    let deadline = OffsetDateTime::parse(refresh_token_expires_at?, &Rfc3339).ok()?;
    if deadline <= now {
        return None;
    }
    let left = deadline - now;
    if left <= TimeDuration::days(1) {
        Some(
            "This Claude login ends within 1 day; sign in again to keep its limits current."
                .to_string(),
        )
    } else if left <= TimeDuration::days(3) {
        Some(
            "This Claude login ends within 3 days; sign in again to keep its limits current."
                .to_string(),
        )
    } else {
        None
    }
}

pub(in crate::agent_status) fn append_claude_upkeep_result_receipt(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    descriptor: &ClaudeConfigSlotDescriptorV1,
    observed_at: Option<String>,
) {
    if status.account_identifier_hash != descriptor.collection.account_identifier_hash
        || status.organization_identifier_hash != descriptor.collection.organization_identifier_hash
    {
        return;
    }
    let Some(clock) = observed_at.filter(|at| {
        bounded_claude_collection_timestamp(Some(at), OffsetDateTime::now_utc()).is_some()
    }) else {
        return;
    };
    let Some(upkeep) = &status.upkeep else {
        return;
    };
    let suffix = match upkeep.result {
        ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable => "credential_unreadable",
        ClaudeConfigSlotUpkeepResultV1::ProbeFailed => "probe_failed",
        ClaudeConfigSlotUpkeepResultV1::SpawnFailed => "spawn_failed",
        _ => return,
    };
    let diagnostic = AgentStatusDiagnostic::source(format!("claude_slot_upkeep_{suffix}"), AgentDiagnosticSeverity::Info,
        "The exact-slot local upkeep result was observed at this time; no quota provider check or vendor-command attempt is implied.")
        .with_observed_at(Some(clock)).with_quota_binding(status.account_identifier_hash.clone(), status.organization_identifier_hash.clone());
    status.quota_check_diagnostics.retain(|existing| {
        existing.code != diagnostic.code
            || existing.account_identifier_hash != diagnostic.account_identifier_hash
            || existing.organization_identifier_hash != diagnostic.organization_identifier_hash
    });
    status
        .quota_check_diagnostics
        .extend(safe_claude_slot_check_diagnostics(
            &[diagnostic],
            status
                .account_identifier_hash
                .as_deref()
                .unwrap_or_default(),
            status
                .organization_identifier_hash
                .as_deref()
                .unwrap_or_default(),
        ));
}

/// The registered-slot `ConcurrentMutation` outcome exactly as collection
/// stops with it, for the setup-check tests in `control`.
#[cfg(test)]
pub(crate) fn registered_claude_race_status_for_test(
    slot_id: &str,
    config_dir: &str,
    observed_at: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let descriptor = ClaudeConfigDirSlot::registered(config_dir.to_string())
        .expect("registered slot")
        .descriptor(slot_id.to_string(), ClaudeConfigSlotOwnership::Managed);
    registered_claude_failure_status(
        &descriptor,
        None,
        ClaudeSlotProbeFailure::ConcurrentMutation,
        observed_at,
        ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::NotRequired,
            due_access_expires_at: None,
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        },
    )
}

pub(in crate::agent_status) fn registered_claude_failure_status(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    owner: Option<&ClaudeTokenOwner>,
    failure: ClaudeSlotProbeFailure,
    observed_at: &str,
    upkeep: ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let mut status = failure.status(observed_at);
    retain_registered_claude_slot_binding(descriptor, owner, &mut status);
    // A cleared credential's old deadlines are not last-known-good; leaving
    // them out sends the next pass to the live (spawn-free) metadata check.
    if failure != ClaudeSlotProbeFailure::SignedOutByCli {
        retain_last_known_claude_deadlines(&mut status, descriptor, &upkeep);
    }
    apply_claude_upkeep_observation(&mut status, upkeep);
    status
}

/// Keep the last-known, still-unexpired access deadline (and its paired
/// refresh deadline) on a failed probe. Persisting the failure without them
/// made the next upkeep pass read "no deadline" as "credential unreadable"
/// and stop there. An already-past deadline is not carried: upkeep then
/// re-reads the slot's own metadata and routes a truly expired login to the
/// refresh worker.
pub(in crate::agent_status) fn retain_last_known_claude_deadlines(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    descriptor: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) {
    let now = OffsetDateTime::now_utc();
    let unexpired = |at: Option<&str>| {
        at.and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
            .is_some_and(|expiry| expiry > now)
    };
    let (access, relogin) = if unexpired(upkeep.due_access_expires_at.as_deref()) {
        (
            upkeep.due_access_expires_at.clone(),
            upkeep.refresh_token_expires_at.clone(),
        )
    } else if unexpired(descriptor.collection.access_expires_at.as_deref()) {
        (
            descriptor.collection.access_expires_at.clone(),
            descriptor.collection.relogin_required_at.clone(),
        )
    } else {
        return;
    };
    status.access_expires_at = access;
    status.relogin_required_at = relogin;
}

pub(in crate::agent_status) fn upkeep_state_diagnostic(
    result: ClaudeConfigSlotUpkeepResultV1,
) -> (
    ClaudeConfigSlotCollectionStateV1,
    ClaudeConfigSlotDiagnosticCodeV1,
    &'static str,
) {
    match result {
        ClaudeConfigSlotUpkeepResultV1::CollectionPaused => (
            ClaudeConfigSlotCollectionStateV1::CollectionPaused,
            ClaudeConfigSlotDiagnosticCodeV1::CollectionPaused,
            "Claude subscription usage collection and background upkeep are paused by the machine off-switch.",
        ),
        ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented => (
            ClaudeConfigSlotCollectionStateV1::UpkeepNotConsented,
            ClaudeConfigSlotDiagnosticCodeV1::UpkeepNotConsented,
            "This expired Claude slot cannot run background upkeep until machine-level consent is granted.",
        ),
        ClaudeConfigSlotUpkeepResultV1::NeedsLogin => (
            ClaudeConfigSlotCollectionStateV1::NeedsLogin,
            ClaudeConfigSlotDiagnosticCodeV1::NeedsLogin,
            "This Claude slot reached its absolute refresh deadline and needs official Claude Code login again.",
        ),
        ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled => (
            ClaudeConfigSlotCollectionStateV1::ProbeFailed,
            ClaudeConfigSlotDiagnosticCodeV1::UpkeepDisabled,
            "Background Claude upkeep is stopped by the operational kill-switch; consent and account data are unchanged.",
        ),
        ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable => (
            ClaudeConfigSlotCollectionStateV1::CredentialUnavailable,
            ClaudeConfigSlotDiagnosticCodeV1::CredentialUnavailable,
            "Claude Code isn't signed in for this account on this Mac.",
        ),
        ClaudeConfigSlotUpkeepResultV1::Backoff => (
            ClaudeConfigSlotCollectionStateV1::StaleAccessToken,
            ClaudeConfigSlotDiagnosticCodeV1::StaleAccessToken,
            "This expired Claude slot is waiting for its durable upkeep retry deadline; no duplicate command was started.",
        ),
        ClaudeConfigSlotUpkeepResultV1::RefreshDue => (
            ClaudeConfigSlotCollectionStateV1::RefreshDue,
            ClaudeConfigSlotDiagnosticCodeV1::RefreshDue,
            "This expired Claude slot is queued for background upkeep; no vendor-command attempt has been claimed yet.",
        ),
        ClaudeConfigSlotUpkeepResultV1::InProgress => (
            ClaudeConfigSlotCollectionStateV1::RefreshDue,
            ClaudeConfigSlotDiagnosticCodeV1::RefreshDue,
            "This expired Claude slot has one background upkeep attempt in progress.",
        ),
        ClaudeConfigSlotUpkeepResultV1::ReloginApproaching => (
            ClaudeConfigSlotCollectionStateV1::ReloginApproaching,
            ClaudeConfigSlotDiagnosticCodeV1::ReloginApproaching,
            "This Claude login reaches its absolute refresh deadline within 3 days.",
        ),
        _ => (
            ClaudeConfigSlotCollectionStateV1::ProbeFailed,
            ClaudeConfigSlotDiagnosticCodeV1::ProbeFailed,
            "Claude Code background upkeep did not prove that this expired credential advanced; cached readings remain honestly stale.",
        ),
    }
}

/// Classify before suppressing display warnings: these diagnostics also carry
/// the internal failure state, including transient unreadable credentials.
/// Desktop authenticates its own Code sessions; its bundled binary alone does
/// not make an unusable default login actionable. Registered slots never pass
/// through this default-only display preparation.
pub(in crate::agent_status) fn prepare_default_claude_slot_status(
    snapshot: &mut AgentStatusSnapshot,
    claude_cli_installed: bool,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let status = claude_default_slot_collection_status(snapshot);
    if !claude_cli_installed {
        snapshot.diagnostics.retain(|diagnostic| {
            diagnostic.code != ClaudeSlotProbeFailure::CredentialUnavailable.diagnostic_code()
                && diagnostic.code != ClaudeSlotProbeFailure::ProbeFailed.diagnostic_code()
        });
    }
    status
}

pub(in crate::agent_status) fn default_claude_identity_diagnostic(
    failure: ClaudeSlotProbeFailure,
) -> AgentStatusDiagnostic {
    let status = failure.status("");
    AgentStatusDiagnostic::source(
        failure.diagnostic_code(),
        AgentDiagnosticSeverity::Warning,
        if failure == ClaudeSlotProbeFailure::CredentialUnavailable {
            "Claude Code isn't signed in on this Mac".to_string()
        } else {
            status
                .diagnostics
                .first()
                .map(|diagnostic| diagnostic.message.clone())
                .unwrap_or_else(|| "Claude slot identity could not be verified.".to_string())
        },
    )
}

pub(in crate::agent_status) fn fresh_slot_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: &str,
    has_account_windows: bool,
    has_scoped_limits: bool,
    has_credit_balances: bool,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some(organization_hash.to_string()),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        last_full_quota_read_at: (has_account_windows && has_scoped_limits)
            .then(|| observed_at.to_string()),
        has_account_windows,
        has_scoped_limits,
        has_credit_balances,
        diagnostics: Vec::new(),
        ..Default::default()
    }
}

pub(in crate::agent_status) fn provider_unavailable_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some(organization_hash.to_string()),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::ProviderUnavailable,
            message: "Full Claude usage is temporarily unavailable for this exact account slot."
                .to_string(),
        }],
        ..Default::default()
    }
}

pub(in crate::agent_status) fn collection_paused_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::CollectionPaused,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some(organization_hash.to_string()),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::CollectionPaused,
            message: "Claude subscription usage collection is paused by the machine off-switch."
                .to_string(),
        }],
        ..Default::default()
    }
}

pub(in crate::agent_status) fn collection_in_progress_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::CollectionInProgress,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some(organization_hash.to_string()),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::CollectionInProgress,
            message: "Another task is already reading this exact Claude account; no duplicate request was started."
                .to_string(),
        }],
        ..Default::default()
    }
}

#[cfg(test)]
pub(in crate::agent_status) fn duplicate_account_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: Option<&str>,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::DuplicateAccount,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: organization_hash.map(ToString::to_string),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::DuplicateAccount,
            message: "This registered slot resolves to an account already collected by an earlier valid slot."
                .to_string(),
        }],
        relationship: Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::DuplicateAnchor),
        ..Default::default()
    }
}

pub(in crate::agent_status) fn capacity_exceeded_status(
    observed_at: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::CapacityExceeded,
        observed_at: Some(observed_at.to_string()),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::CapacityExceeded,
            message: "This slot is beyond the ten-account collection capacity and remains local."
                .to_string(),
        }],
        ..Default::default()
    }
}
