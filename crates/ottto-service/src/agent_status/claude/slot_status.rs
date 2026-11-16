//! Claude status slot status operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::base_snapshot;
use crate::agent_status::bounded_claude_collection_timestamp;
use crate::agent_status::claude_credit_pools;
use crate::agent_status::claude_oauth_usage_serve_gate_seconds;
use crate::agent_status::claude_slot_owner_rule;
use crate::agent_status::claude_strong_oauth_identity_hashes;
use crate::agent_status::claude_worker_diagnostic_message;
use crate::agent_status::home_dir;
use crate::agent_status::normalize_plan_type;
use crate::agent_status::projected_claude_anchor_health;
use crate::agent_status::read_claude_cli_oauth_account;
use crate::agent_status::read_persisted_claude_slot_collection_state;
use crate::agent_status::read_registered_claude_slot_locally;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::supported_capability;
use crate::agent_status::unsupported_account;
use crate::agent_status::upkeep_state_diagnostic;
use crate::agent_status::AgentAccountStatus;
use crate::agent_status::AgentCreditBalance;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentQuotaWindow;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentStatusCollectionMethod;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::AgentStatusState;
use crate::agent_status::BTreeMap;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeAccountAnchorDurabilityV1;
use crate::agent_status::ClaudeAccountAnchorHealthV1;
use crate::agent_status::ClaudeCliOauthAccount;
use crate::agent_status::ClaudeConfigDirSlot;
use crate::agent_status::ClaudeConfigSlotAccountProfileV1;
use crate::agent_status::ClaudeConfigSlotCollectionStateV1;
use crate::agent_status::ClaudeConfigSlotCollectionStatusV1;
use crate::agent_status::ClaudeConfigSlotDescriptorV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticCodeV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticV1;
use crate::agent_status::ClaudeConfigSlotQuotaSnapshotStateV1;
use crate::agent_status::ClaudeConfigSlotQuotaSnapshotV1;
use crate::agent_status::ClaudeConfigSlotUpkeepResultV1;
use crate::agent_status::ClaudeOAuthUsage;
use crate::agent_status::ClaudeQuotaAccessState;
use crate::agent_status::ClaudeSlotAccountBinding;
use crate::agent_status::ClaudeSlotOwnerRule;
use crate::agent_status::ClaudeSlotProbeFailure;
use crate::agent_status::ClaudeStrongBinding;
use crate::agent_status::ClaudeTokenOwner;
use crate::agent_status::FileClaudeConfigSlotSettingsStore;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::ResolvedClaudeSlot;
use crate::agent_status::Rfc3339;
use crate::agent_status::SourceKind;
use crate::agent_status::TimeDuration;
use crate::agent_status::CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS;
use crate::agent_status::CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE;
use crate::agent_status::CLAUDE_OAUTH_USAGE_RATE_LIMITED_SAVED_RESETS_MESSAGE;
use crate::agent_status::CLAUDE_OAUTH_USAGE_RATE_LIMITED_USAGE_MESSAGE;
use crate::agent_status::CLAUDE_QUOTA_ACCESS_CAPABILITY;
use crate::agent_status::CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE;
use crate::agent_status::CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE;

pub(in crate::agent_status) const CLAUDE_CACHE_REUSED_MESSAGE: &str =
    "Locally cached quota evidence was reused; no provider check was made.";

/// Retain a canonical clock only on a bound cache-reuse or rate-limited outcome. Its deadline
/// was still ahead at the producer's check time; consumers compare it with now.
pub(in crate::agent_status) fn safe_claude_cache_retry_after(
    diagnostic: &AgentStatusDiagnostic,
) -> Option<String> {
    let deadline = diagnostic
        .retry_after
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())?;
    let observed = diagnostic
        .observed_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())?;
    if deadline <= observed {
        return None;
    }
    u64::try_from(deadline.unix_timestamp())
        .ok()
        .and_then(rfc3339_from_unix_seconds)
}

/// Persist only known producer outcomes, never provider errors, slot paths or
/// caller-supplied messages. Both hashes must already match the proven slot.
pub(in crate::agent_status) fn safe_claude_slot_check_diagnostics(
    diagnostics: &[AgentStatusDiagnostic],
    account: &str,
    organization: &str,
) -> Vec<AgentStatusDiagnostic> {
    let mut result = Vec::new();
    for diagnostic in diagnostics {
        if account.is_empty()
            || organization.is_empty()
            || diagnostic.account_identifier_hash.as_deref() != Some(account)
            || diagnostic.organization_identifier_hash.as_deref() != Some(organization)
            || result
                .iter()
                .any(|existing: &AgentStatusDiagnostic| existing.code == diagnostic.code)
        {
            continue;
        }
        let message = match diagnostic.code.as_str() {
            "claude_oauth_usage_check_failed" => "The exact-account quota provider request failed.",
            "claude_oauth_usage_check_suppressed" => "A local hold (quota breaker, credential backoff or this account's read slot) suppressed the provider request; no provider check was made.",
            "claude_oauth_usage_cache_reused" => CLAUDE_CACHE_REUSED_MESSAGE,
            "claude_oauth_usage_check_succeeded" => "A supported exact-account quota response was collected successfully.",
            "claude_oauth_usage_network_disabled" => "Quota network collection is disabled on this machine.",
            "claude_oauth_usage_collection_in_progress" => "Quota collection is already in progress; no duplicate provider check was made.",
            CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE => CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE,
            CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE => {
                if diagnostic.message.contains(" saved-resets read") {
                    CLAUDE_OAUTH_USAGE_RATE_LIMITED_SAVED_RESETS_MESSAGE
                } else {
                    CLAUDE_OAUTH_USAGE_RATE_LIMITED_USAGE_MESSAGE
                }
            }
            // Our own typed auth classification; only the HTTP status is kept.
            "claude_oauth_usage_auth_rejected" => {
                if diagnostic.message.contains(" with HTTP 401 ") {
                    "The quota provider rejected this exact slot's credential with HTTP 401; it backs off before retrying."
                } else if diagnostic.message.contains(" with HTTP 403 ") {
                    "The quota provider rejected this exact slot's credential with HTTP 403; it backs off before retrying."
                } else {
                    "The quota provider rejected this exact slot's credential; it backs off before retrying."
                }
            }
            "claude_oauth_usage_auth_backoff" => "This exact slot's credential is backing off after a provider rejection; no provider check was made.",
            "claude_slot_upkeep_credential_unreadable" | "claude_slot_upkeep_probe_failed" | "claude_slot_upkeep_spawn_failed" => "The exact-slot local upkeep result was observed at this time; no quota provider check or vendor-command attempt is implied.",
            "claude_oauth_usage_circuit_open" => {
                // These classifications come from the existing typed breaker,
                // not an arbitrary transport error or credential string.
                if diagnostic.message == "The local quota circuit is open after authentication rejection."
                    || diagnostic.message.starts_with("Stopped calling the Claude OAuth usage endpoint after auth rejected;") {
                    "The local quota circuit is open after authentication rejection."
                } else if diagnostic.message == "The local quota circuit is open after unsupported response shape."
                    || diagnostic.message.starts_with("Stopped calling the Claude OAuth usage endpoint after response shape;") {
                    "The local quota circuit is open after unsupported response shape."
                } else {
                    "The local quota circuit is open after repeated failures."
                }
            }
            code if claude_worker_diagnostic_message(code).is_some() => {
                claude_worker_diagnostic_message(code).expect("matched closed local worker code")
            }
            _ => continue,
        };
        let clock = bounded_claude_collection_timestamp(
            diagnostic.observed_at.as_deref(),
            OffsetDateTime::now_utc(),
        )
        .and(diagnostic.observed_at.clone());
        if claude_worker_diagnostic_message(&diagnostic.code).is_some() && clock.is_none() {
            continue;
        }
        let mut safe =
            AgentStatusDiagnostic::source(&diagnostic.code, diagnostic.severity.clone(), message)
                .with_observed_at(clock)
                .with_quota_binding(Some(account.to_string()), Some(organization.to_string()));
        if matches!(
            diagnostic.code.as_str(),
            "claude_oauth_usage_cache_reused" | CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE
        ) && safe.observed_at.is_some()
        {
            safe.retry_after = safe_claude_cache_retry_after(diagnostic);
        }
        result.push(safe);
    }
    result
}

pub(in crate::agent_status) fn local_claude_quota_snapshot(
    captured_at: &str,
    quota_windows: &[AgentQuotaWindow],
    credit_balances: &[AgentCreditBalance],
    has_account_windows: bool,
    has_scoped_limits: bool,
) -> ClaudeConfigSlotQuotaSnapshotV1 {
    // Credit sections carry their own per-section freshness (each from its own
    // read time); the snapshot's state is its meters'.
    let stale = quota_windows
        .iter()
        .any(|window| window.freshness != AgentQuotaWindowFreshness::Fresh);
    let state = if stale {
        ClaudeConfigSlotQuotaSnapshotStateV1::Stale
    } else if !has_account_windows || !has_scoped_limits {
        ClaudeConfigSlotQuotaSnapshotStateV1::Partial
    } else {
        ClaudeConfigSlotQuotaSnapshotStateV1::Fresh
    };
    let observed_at = quota_windows
        .iter()
        .filter_map(|window| window.observed_at.as_deref())
        .chain(
            credit_balances
                .iter()
                .filter_map(|balance| balance.updated_at.as_deref()),
        )
        .min()
        .map(ToString::to_string);
    ClaudeConfigSlotQuotaSnapshotV1 {
        state,
        captured_at: captured_at.to_string(),
        observed_at,
        quota_windows: quota_windows.to_vec(),
        credit_balances: credit_balances.to_vec(),
    }
}

pub(in crate::agent_status) fn stale_local_claude_quota_snapshot(
    snapshot: &ClaudeConfigSlotQuotaSnapshotV1,
) -> ClaudeConfigSlotQuotaSnapshotV1 {
    let mut snapshot = snapshot.clone();
    snapshot.state = ClaudeConfigSlotQuotaSnapshotStateV1::Stale;
    for balance in &mut snapshot.credit_balances {
        // A reader-blind row kept from an older daemon (complete, 0) is shown
        // in its §11.10 shape, never as no resets.
        claude_credit_pools::claude_mark_reader_unavailable(balance);
    }
    mark_quota_meters_stale(&mut snapshot.quota_windows, &mut snapshot.credit_balances);
    snapshot
}

/// Mark a kept reading's meters `Stale`. Only freshness changes: read clocks
/// (`observed_at`, `grants_observed_at`) and values stay as read.
pub(in crate::agent_status) fn mark_quota_meters_stale(
    quota_windows: &mut [AgentQuotaWindow],
    credit_balances: &mut [AgentCreditBalance],
) {
    for window in quota_windows {
        window.freshness = AgentQuotaWindowFreshness::Stale;
    }
    for balance in credit_balances {
        balance.freshness = AgentQuotaWindowFreshness::Stale;
    }
}

pub(in crate::agent_status) fn local_claude_quota_snapshot_within_retention(
    snapshot: &ClaudeConfigSlotQuotaSnapshotV1,
    now: OffsetDateTime,
) -> bool {
    let represented_at = snapshot
        .observed_at
        .as_deref()
        .unwrap_or(snapshot.captured_at.as_str());
    let Ok(represented_at) = OffsetDateTime::parse(represented_at, &Rfc3339) else {
        return false;
    };
    let age_seconds = now.unix_timestamp() - represented_at.unix_timestamp();
    (0..=CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS as i64).contains(&age_seconds)
}

pub(in crate::agent_status) fn local_claude_quota_snapshot_is_fresh_for_account(
    snapshot: &ClaudeConfigSlotQuotaSnapshotV1,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: OffsetDateTime,
) -> bool {
    // Credit sections carry their own per-section freshness (each from its own
    // read time); the snapshot's freshness is its meters'.
    if snapshot.state != ClaudeConfigSlotQuotaSnapshotStateV1::Fresh
        || snapshot
            .quota_windows
            .iter()
            .any(|window| window.freshness != AgentQuotaWindowFreshness::Fresh)
    {
        return false;
    }
    let represented_at = snapshot
        .observed_at
        .as_deref()
        .unwrap_or(snapshot.captured_at.as_str());
    let Ok(represented_at) = OffsetDateTime::parse(represented_at, &Rfc3339) else {
        return false;
    };
    let age_seconds = now.unix_timestamp() - represented_at.unix_timestamp();
    // The same gate the cache serve path labels with.
    let gate = claude_oauth_usage_serve_gate_seconds(
        account_identifier_hash,
        organization_identifier_hash,
        u64::try_from(now.unix_timestamp()).unwrap_or_default(),
    );
    (0..=i64::try_from(gate).unwrap_or(i64::MAX)).contains(&age_seconds)
}

/// A retained full snapshot reused as fresh: its meters are fresh, but each
/// credit section is relabelled from its own read time (the label taken at
/// capture can be past that section's own limit by now).
pub(in crate::agent_status) fn claude_retained_snapshot_relabelled(
    snapshot: &ClaudeConfigSlotQuotaSnapshotV1,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: OffsetDateTime,
) -> ClaudeConfigSlotQuotaSnapshotV1 {
    let mut snapshot = snapshot.clone();
    let now = u64::try_from(now.unix_timestamp()).unwrap_or_default();
    let represented_at = snapshot
        .observed_at
        .as_deref()
        .unwrap_or(snapshot.captured_at.as_str());
    let stored_read_at = OffsetDateTime::parse(represented_at, &Rfc3339)
        .ok()
        .and_then(|instant| u64::try_from(instant.unix_timestamp()).ok())
        .unwrap_or(now);
    claude_credit_pools::label_credit_freshness(
        &mut snapshot.credit_balances,
        claude_oauth_usage_serve_gate_seconds(
            account_identifier_hash,
            organization_identifier_hash,
            now,
        ),
        stored_read_at,
        now,
    );
    snapshot
}

pub(in crate::agent_status) fn claude_usage_has_exact_identity(
    usage: &ClaudeOAuthUsage,
    account_hash: &str,
    organization_hash: &str,
) -> bool {
    !usage.windows.is_empty()
        && usage.windows.iter().all(|window| {
            window.account_identifier_hash.as_deref() == Some(account_hash)
                && window.organization_identifier_hash.as_deref() == Some(organization_hash)
        })
        && usage.credit_balances.iter().all(|balance| {
            balance.account_identifier_hash.as_deref() == Some(account_hash)
                && balance.organization_identifier_hash.as_deref() == Some(organization_hash)
        })
}

pub(in crate::agent_status) fn ensure_claude_quota_access_capability(
    snapshot: &mut AgentStatusSnapshot,
) {
    if snapshot
        .capabilities
        .iter()
        .any(|capability| capability.capability == CLAUDE_QUOTA_ACCESS_CAPABILITY)
    {
        return;
    }
    snapshot.capabilities.push(supported_capability(
        CLAUDE_QUOTA_ACCESS_CAPABILITY,
        "This daemon reports exact-slot Claude quota access state for strongly bound accounts.",
    ));
}

pub(in crate::agent_status) fn projected_claude_quota_access_state(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> Option<ClaudeQuotaAccessState> {
    let strongly_bound = status
        .account_identifier_hash
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        && status
            .organization_identifier_hash
            .as_deref()
            .is_some_and(|value| !value.is_empty());
    if !strongly_bound {
        return None;
    }
    if status
        .upkeep
        .as_ref()
        .is_some_and(|upkeep| upkeep.result == ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled)
    {
        return Some(ClaudeQuotaAccessState::Paused);
    }
    if status
        .upkeep
        .as_ref()
        .is_some_and(|upkeep| upkeep.result == ClaudeConfigSlotUpkeepResultV1::MissingBinary)
    {
        return Some(ClaudeQuotaAccessState::AttentionRequired);
    }
    match status.state {
        ClaudeConfigSlotCollectionStateV1::Fresh => {
            Some(if status.has_account_windows && status.has_scoped_limits {
                ClaudeQuotaAccessState::Full
            } else {
                ClaudeQuotaAccessState::Partial
            })
        }
        ClaudeConfigSlotCollectionStateV1::RefreshDue
        | ClaudeConfigSlotCollectionStateV1::StaleAccessToken => Some(
            claude_blocked_refresh_worker_escalation(status, OffsetDateTime::now_utc())
                .unwrap_or(ClaudeQuotaAccessState::TemporarilyUnavailable),
        ),
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
        | ClaudeConfigSlotCollectionStateV1::CollectionInProgress
        | ClaudeConfigSlotCollectionStateV1::ConcurrentMutation
        | ClaudeConfigSlotCollectionStateV1::ProbeFailed
        | ClaudeConfigSlotCollectionStateV1::ReloginApproaching => {
            Some(ClaudeQuotaAccessState::TemporarilyUnavailable)
        }
        ClaudeConfigSlotCollectionStateV1::NeedsLogin => {
            Some(ClaudeQuotaAccessState::ReconnectRequired)
        }
        ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
            if status.upkeep.as_ref().is_some_and(|upkeep| {
                upkeep.result == ClaudeConfigSlotUpkeepResultV1::NeedsLogin
            }) =>
        {
            Some(ClaudeQuotaAccessState::ReconnectRequired)
        }
        ClaudeConfigSlotCollectionStateV1::CollectionPaused
        | ClaudeConfigSlotCollectionStateV1::UpkeepNotConsented => {
            Some(ClaudeQuotaAccessState::Paused)
        }
        ClaudeConfigSlotCollectionStateV1::IdentityUnknown
        | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
        | ClaudeConfigSlotCollectionStateV1::IdentityMismatch => {
            Some(ClaudeQuotaAccessState::AttentionRequired)
        }
        ClaudeConfigSlotCollectionStateV1::Unverified
        | ClaudeConfigSlotCollectionStateV1::DuplicateAccount
        | ClaudeConfigSlotCollectionStateV1::CapacityExceeded => None,
    }
}

/// Worker outcomes that mean the latest refresh pass for a blocked saved
/// anchor did not take, as opposed to a pending, paused or successful pass.
/// `backoff` is included because it only follows a failed attempt for the same
/// credential expiry; omitting it would make the projection flap between runs.
pub(in crate::agent_status) const CLAUDE_BLOCKED_REFRESH_FAILURE_WORKER_CODES: &[&str] = &[
    "claude_slot_worker_expiry_unchanged",
    "claude_slot_worker_nonzero_exit",
    "claude_slot_worker_timed_out",
    "claude_slot_worker_spawn_failed",
    "claude_slot_worker_credential_unreadable",
    "claude_slot_worker_probe_failed",
    "claude_slot_worker_backoff",
    "claude_slot_worker_reconciliation_refused",
    "claude_slot_worker_identity_unknown",
    "claude_slot_worker_identity_credential_unavailable",
    "claude_slot_worker_identity_mismatch",
];

/// How long a blocked saved anchor's access may stay expired, with an exact
/// failed worker receipt, before it stops being presented as temporary.
pub(in crate::agent_status) const CLAUDE_BLOCKED_REFRESH_ESCALATION_SECONDS: i64 = 24 * 60 * 60;

/// Truthful access state for a saved anchor that collection skips because its
/// saved access deadline has expired.
///
/// The fenced local worker receipt is the only current evidence about that
/// anchor's real credential. A worker that read a signed-out or expired refresh
/// grant reports `needs_login`: the saved connection needs sign-in again, not
/// patience. A refresh that keeps failing for a day is an attention state that
/// names its worker reason instead of an indefinitely "temporary" one. Any
/// newer worker pass (refresh, reconciliation) replaces the receipt, so this
/// never sticks after the credential recovers. Meters and quota clocks are
/// untouched; this classifies saved-connection health only.
pub(in crate::agent_status) fn claude_blocked_refresh_worker_escalation(
    status: &ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) -> Option<ClaudeQuotaAccessState> {
    let receipt = latest_exact_claude_worker_receipt_code(status, now)?;
    if receipt == "claude_slot_worker_needs_login" {
        return Some(ClaudeQuotaAccessState::ReconnectRequired);
    }
    let expired_long_ago = bounded_claude_collection_timestamp(
        status.access_expires_at.as_deref(),
        now - TimeDuration::seconds(CLAUDE_BLOCKED_REFRESH_ESCALATION_SECONDS),
    )
    .is_some();
    (expired_long_ago && CLAUDE_BLOCKED_REFRESH_FAILURE_WORKER_CODES.contains(&receipt.as_str()))
        .then_some(ClaudeQuotaAccessState::AttentionRequired)
}

/// Code of the newest exact-binding local worker receipt on one saved slot,
/// bounded by `now`. Forged, foreign-pair and future receipts are ignored.
pub(in crate::agent_status) fn latest_exact_claude_worker_receipt_code(
    status: &ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) -> Option<String> {
    let account = status.account_identifier_hash.as_deref()?;
    let organization = status.organization_identifier_hash.as_deref()?;
    safe_claude_slot_check_diagnostics(&status.quota_check_diagnostics, account, organization)
        .into_iter()
        .filter(|entry| claude_worker_diagnostic_message(&entry.code).is_some())
        .filter_map(|entry| {
            bounded_claude_collection_timestamp(entry.observed_at.as_deref(), now)
                .map(|clock| (entry.code, clock))
        })
        .max_by_key(|(_, clock)| *clock)
        .map(|(code, _)| code)
}

/// Saved state for a blocked slot whose newest exact worker pass read a
/// credential that needs a new sign-in.
///
/// The worker's pre-claim `needs_login` describes the slot's actual
/// credential, but its witness is keyed by that credential's expiry (for a
/// signed-out credential, often the epoch), so the foreground's exact saved
/// deadline match never adopts it and the slot stayed `refresh_due`. That
/// hid both reconnect-required health and the companion's "Sign in again".
/// The receipt is already fenced to this registration, pair and saved
/// deadlines with its original clock, and any newer worker pass replaces it.
/// Only the presented state changes: the saved upkeep result stays
/// `refresh_due`, so collection keeps queuing the worker and a valid
/// credential after sign-in reconciles through the existing worker path.
pub(in crate::agent_status) fn apply_claude_worker_needs_login_state(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) {
    if !matches!(
        status.state,
        ClaudeConfigSlotCollectionStateV1::RefreshDue
            | ClaudeConfigSlotCollectionStateV1::StaleAccessToken
    ) || latest_exact_claude_worker_receipt_code(status, now).as_deref()
        != Some("claude_slot_worker_needs_login")
    {
        return;
    }
    let (state, code, message) =
        upkeep_state_diagnostic(ClaudeConfigSlotUpkeepResultV1::NeedsLogin);
    status.state = state;
    status.diagnostics = vec![ClaudeConfigSlotDiagnosticV1 {
        code,
        message: message.to_string(),
    }];
}

pub(in crate::agent_status) fn claude_slot_status_carries_meters(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> bool {
    matches!(
        projected_claude_quota_access_state(status),
        None | Some(ClaudeQuotaAccessState::Full | ClaudeQuotaAccessState::Partial)
    )
}

pub(in crate::agent_status) fn apply_claude_quota_access_state(
    snapshot: &mut AgentStatusSnapshot,
    status: &ClaudeConfigSlotCollectionStatusV1,
) {
    ensure_claude_quota_access_capability(snapshot);
    let Some(projected) = projected_claude_quota_access_state(status) else {
        return;
    };
    let account_matches = snapshot.account.as_ref().is_some_and(|account| {
        account.account_identifier_hash.as_deref() == status.account_identifier_hash.as_deref()
            && account.organization_identifier_hash.as_deref()
                == status.organization_identifier_hash.as_deref()
    });
    if account_matches {
        snapshot
            .account
            .as_mut()
            .expect("matching Claude account must exist")
            .claude_quota_access_state = Some(projected);
    }
}

pub(in crate::agent_status) fn exact_claude_slot_account_profile(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> Option<&ClaudeConfigSlotAccountProfileV1> {
    let profile = status.account_profile.as_ref()?;
    (status.account_identifier_hash.as_deref() == Some(profile.account_identifier_hash.as_str())
        && status.organization_identifier_hash.as_deref()
            == Some(profile.organization_identifier_hash.as_str())
        && !profile.account_identifier_hash.is_empty()
        && !profile.organization_identifier_hash.is_empty()
        && bounded_claude_collection_timestamp(
            Some(&profile.captured_at),
            OffsetDateTime::now_utc(),
        )
        .is_some())
    .then_some(profile)
}

pub(in crate::agent_status) fn remember_claude_slot_account_profile(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    account: Option<&AgentAccountStatus>,
    captured_at: &str,
) {
    let Some(account) = account.filter(|account| {
        account.login_state == AgentLoginState::SignedIn
            && account.account_identifier_hash == status.account_identifier_hash
            && account.organization_identifier_hash == status.organization_identifier_hash
    }) else {
        return;
    };
    let Some(binding) = account
        .account_identifier_hash
        .as_deref()
        .zip(account.organization_identifier_hash.as_deref())
        .and_then(|(account, organization)| ClaudeStrongBinding::new(account, organization))
    else {
        return;
    };
    if account.email.is_none()
        && account.organization_label.is_none()
        && account.plan_type.is_none()
        && account.subscription_product.is_none()
    {
        return;
    }
    status.account_profile = Some(ClaudeConfigSlotAccountProfileV1 {
        account_identifier_hash: binding.account_identifier_hash,
        organization_identifier_hash: binding.organization_identifier_hash,
        captured_at: captured_at.to_string(),
        email: account.email.clone(),
        organization_label: account.organization_label.clone(),
        plan_type: account.plan_type.clone(),
        subscription_product: account.subscription_product.clone(),
    });
}

pub(in crate::agent_status) fn inherit_claude_slot_account_profile(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
) {
    let previous = previous
        .filter(|previous| {
            previous.account_identifier_hash == status.account_identifier_hash
                && previous.organization_identifier_hash == status.organization_identifier_hash
        })
        .and_then(exact_claude_slot_account_profile)
        .cloned();
    let Some(mut current) = exact_claude_slot_account_profile(status).cloned() else {
        status.account_profile = previous;
        return;
    };
    let Some(previous) = previous else {
        return;
    };
    // Plan and product describe one tier. A newly reported different tier
    // wins; never complete it with a label from the previous tier.
    let tier_compatible = (current.plan_type.is_none() && current.subscription_product.is_none())
        || (current.plan_type.is_some()
            && current.plan_type == previous.plan_type
            && (current.subscription_product.is_none()
                || current.subscription_product == previous.subscription_product))
        || (current.subscription_product.is_some()
            && current.subscription_product == previous.subscription_product
            && (current.plan_type.is_none() || current.plan_type == previous.plan_type));
    let mut retained = false;
    let mut fill_missing = |current: &mut Option<String>, previous: &Option<String>| {
        if current.is_none() && previous.is_some() {
            *current = previous.clone();
            retained = true;
        }
    };
    fill_missing(&mut current.email, &previous.email);
    fill_missing(
        &mut current.organization_label,
        &previous.organization_label,
    );
    if tier_compatible {
        fill_missing(&mut current.plan_type, &previous.plan_type);
        fill_missing(
            &mut current.subscription_product,
            &previous.subscription_product,
        );
    }
    if retained {
        // One conservative profile clock: retained old fields do not acquire
        // the later auth-response time. This is never quota/check freshness.
        let previous_at = OffsetDateTime::parse(&previous.captured_at, &Rfc3339)
            .expect("exact profile clock was validated");
        let current_at = OffsetDateTime::parse(&current.captured_at, &Rfc3339)
            .expect("exact profile clock was validated");
        if previous_at < current_at {
            current.captured_at = previous.captured_at;
        }
    }
    status.account_profile = Some(current);
}

pub(in crate::agent_status) fn retain_exact_claude_slot_binding(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    account_hash: &str,
    organization_hash: &str,
) {
    if account_hash.is_empty() || organization_hash.is_empty() {
        return;
    }
    status.account_identifier_hash = Some(account_hash.to_string());
    status.organization_identifier_hash = Some(organization_hash.to_string());
    status.display_label = Some(format!(
        "Claude account {}",
        &account_hash[..account_hash.len().min(8)]
    ));
}

pub(in crate::agent_status) fn claude_config_slot_for_descriptor(
    descriptor: &ClaudeConfigSlotDescriptorV1,
) -> Option<ClaudeConfigDirSlot> {
    match descriptor.config_dir.as_ref() {
        Some(config_dir) => ClaudeConfigDirSlot::registered(config_dir.clone()).ok(),
        None if descriptor.slot_id == "default" => Some(ClaudeConfigDirSlot::Default),
        None => None,
    }
}

pub(in crate::agent_status) fn clear_claude_slot_binding(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) {
    status.account_identifier_hash = None;
    status.organization_identifier_hash = None;
    status.display_label = None;
    status.account_profile = None;
    status.last_full_quota_read_at = None;
    status.has_account_windows = false;
    status.has_scoped_limits = false;
    status.has_credit_balances = false;
    status.quota_snapshot = None;
    status.quota_check_diagnostics.clear();
}

pub(in crate::agent_status) fn retain_verified_claude_slot_binding(
    slot_id: &str,
    slot: &ClaudeConfigDirSlot,
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) {
    let current_binding = read_claude_cli_oauth_account(&slot.identity_path(&home_dir()))
        .as_ref()
        .and_then(claude_strong_oauth_identity_hashes);
    retain_verified_claude_binding(slot_id, current_binding, status);
}

/// [`retain_verified_claude_slot_binding`] for a registered slot, against the
/// stored token's proven owner where it outranks a stale `.claude.json`.
pub(in crate::agent_status) fn retain_registered_claude_slot_binding(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    owner: Option<&ClaudeTokenOwner>,
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) {
    match (owner, claude_config_slot_for_descriptor(descriptor)) {
        (Some(owner), _) => {
            retain_verified_claude_binding(&descriptor.slot_id, owner.proven_binding(), status);
        }
        (None, Some(slot)) => {
            retain_verified_claude_slot_binding(&descriptor.slot_id, &slot, status)
        }
        (None, None) => clear_claude_slot_binding(status),
    }
}

/// Whether [`retain_verified_claude_binding`] kept the slot's last verified
/// account, or why it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::agent_status) enum ClaudeBindingRetention {
    /// The current login is the last verified account; it was kept.
    Retained,
    /// The current login is proven to be a different account.
    OtherOwner,
    /// No last verified account, or the current login names none.
    OwnerUnknown,
}

/// [`retain_verified_claude_slot_binding`] against a binding the caller
/// already resolved (the default home's proven token owner).
///
/// A `ConcurrentMutation` is a benign retry only while the slot keeps its last
/// verified account. When the account file now names a different owner (A
/// read first, B read last) the race is reported as `IdentityMismatch`, and
/// with no provable owner as `IdentityUnknown`; B is never adopted. Every
/// consumer (attention, setup check, companion) then keys on the state alone.
pub(in crate::agent_status) fn retain_verified_claude_binding(
    slot_id: &str,
    current_binding: Option<(String, String)>,
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) {
    let retention = retain_or_clear_verified_claude_binding(slot_id, current_binding, status);
    if status.state != ClaudeConfigSlotCollectionStateV1::ConcurrentMutation
        || retention == ClaudeBindingRetention::Retained
    {
        return;
    }
    let failure = if retention == ClaudeBindingRetention::OtherOwner {
        ClaudeSlotProbeFailure::IdentityMismatch
    } else {
        ClaudeSlotProbeFailure::IdentityUnknown
    };
    let replacement = failure.status(status.observed_at.as_deref().unwrap_or_default());
    status.state = replacement.state;
    // Swap only the race diagnostic; upkeep diagnostics already on the
    // status stay.
    status.diagnostics.retain(|diagnostic| {
        diagnostic.code != ClaudeConfigSlotDiagnosticCodeV1::ConcurrentMutation
    });
    let mut diagnostics = replacement.diagnostics;
    diagnostics.append(&mut status.diagnostics);
    status.diagnostics = diagnostics;
}

pub(in crate::agent_status) fn retain_or_clear_verified_claude_binding(
    slot_id: &str,
    current_binding: Option<(String, String)>,
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) -> ClaudeBindingRetention {
    let Some(previous) = read_persisted_claude_slot_collection_state()
        .slots
        .get(slot_id)
        .cloned()
    else {
        if status
            .account_identifier_hash
            .as_deref()
            .zip(status.organization_identifier_hash.as_deref())
            != current_binding
                .as_ref()
                .map(|(account, organization)| (account.as_str(), organization.as_str()))
        {
            clear_claude_slot_binding(status);
        }
        return if claude_slot_status_binding(status).is_some() {
            ClaudeBindingRetention::Retained
        } else {
            ClaudeBindingRetention::OwnerUnknown
        };
    };
    let (Some(previous_account), Some(previous_organization)) = (
        previous.account_identifier_hash.as_deref(),
        previous.organization_identifier_hash.as_deref(),
    ) else {
        clear_claude_slot_binding(status);
        return ClaudeBindingRetention::OwnerUnknown;
    };
    let Some((current_account, current_organization)) = current_binding else {
        clear_claude_slot_binding(status);
        return ClaudeBindingRetention::OwnerUnknown;
    };
    if current_account != previous_account || current_organization != previous_organization {
        clear_claude_slot_binding(status);
        return ClaudeBindingRetention::OtherOwner;
    }
    if status
        .account_identifier_hash
        .as_deref()
        .is_some_and(|account| account != current_account)
        || status
            .organization_identifier_hash
            .as_deref()
            .is_some_and(|organization| organization != current_organization)
    {
        clear_claude_slot_binding(status);
        return ClaudeBindingRetention::OtherOwner;
    }
    retain_exact_claude_slot_binding(status, &current_account, &current_organization);
    inherit_claude_slot_account_profile(status, Some(&previous));
    retain_previous_complete_claude_read(status, previous);
    ClaudeBindingRetention::Retained
}

/// Keep the same account's last complete reading, marked stale, when the
/// current pass produced none. Callers prove `previous` is the same binding.
pub(in crate::agent_status) fn retain_previous_complete_claude_read(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    previous: ClaudeConfigSlotCollectionStatusV1,
) {
    let current_has_complete_read = status.last_full_quota_read_at.is_some()
        && status.has_account_windows
        && status.has_scoped_limits;
    if !current_has_complete_read
        && previous.last_full_quota_read_at.is_some()
        && previous.has_account_windows
        && previous.has_scoped_limits
    {
        status.last_full_quota_read_at = previous.last_full_quota_read_at;
        status.has_account_windows = true;
        status.has_scoped_limits = true;
        status.has_credit_balances = previous.has_credit_balances;
        status.quota_snapshot = previous
            .quota_snapshot
            .filter(|snapshot| {
                local_claude_quota_snapshot_within_retention(snapshot, OffsetDateTime::now_utc())
            })
            .map(|snapshot| stale_local_claude_quota_snapshot(&snapshot));
    }
}

/// A registered slot's strong local identity as last recorded by collection.
pub(in crate::agent_status) fn claude_slot_status_binding(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> Option<ClaudeSlotAccountBinding> {
    ClaudeSlotAccountBinding::new(
        status.account_identifier_hash.as_deref()?,
        status.organization_identifier_hash.as_deref()?,
    )
}

/// The account+organization this registered slot is approved to collect for,
/// back-filling the approval once for slots registered before approvals were
/// persisted (see `ensure_approved_slot_binding`). `Ok(None)` leaves the slot
/// ungated, which is exactly the behaviour before approvals existed. When the
/// back-fill cannot be persisted, the binding it would have recorded is still
/// enforced for this pass; `Err` means the approval could not be determined
/// at all, and callers then refuse to collect rather than run ungated.
pub(in crate::agent_status) fn claude_slot_expected_binding(
    slot_id: &str,
    observed: Option<&ClaudeSlotAccountBinding>,
) -> Result<Option<ClaudeSlotAccountBinding>, ()> {
    if slot_id == "default" {
        return Ok(None);
    }
    let store = FileClaudeConfigSlotSettingsStore::default();
    store
        .ensure_approved_slot_binding(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            slot_id,
            observed,
        )
        .or_else(|_| store.prospective_approved_slot_binding(slot_id, observed))
        .map_err(|_| ())
}

/// Collection is refused for one pass when the approval is undeterminable.
/// The slot keeps its last verified pair so its card stays on that account.
pub(in crate::agent_status) fn claude_slot_approval_unavailable_status(
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let mut status = ClaudeSlotProbeFailure::ConcurrentMutation.status(captured_at);
    if let Some(binding) = previous.and_then(claude_slot_status_binding) {
        retain_exact_claude_slot_binding(
            &mut status,
            &binding.account_identifier_hash,
            &binding.organization_identifier_hash,
        );
    }
    status
}

/// Whether this registered slot's current Claude login is not provably the
/// account it is approved for, under collection's owner rule with remembered
/// verdicts only (never a provider call): another account, an unproven owner,
/// or an account file that is missing, unreadable or without strong ids.
/// Read-only; used by the upkeep worker's final spawn and publication fences
/// so a refresh never runs for another or an unknown login. An unreadable
/// approval also refuses.
pub(crate) fn claude_slot_login_unapproved(descriptor: &ClaudeConfigSlotDescriptorV1) -> bool {
    match FileClaudeConfigSlotSettingsStore::default().expected_slot_binding(&descriptor.slot_id) {
        Ok(None) => false,
        Ok(Some(expected)) => !matches!(
            claude_slot_owner_rule(
                &descriptor.slot_id,
                &expected,
                read_registered_claude_slot_locally(descriptor).as_ref(),
                false,
            ),
            ClaudeSlotOwnerRule::Named | ClaudeSlotOwnerRule::Proven(_)
        ),
        Err(_) => true,
    }
}

/// Plan type for local wording only, from `.claude.json` alone. Mirrors the
/// collector's Max 5x/20x and Team seat refinements without an auth status.
pub(in crate::agent_status) fn claude_oauth_plan_type_for_label(
    oauth: &ClaudeCliOauthAccount,
) -> Option<String> {
    let organization_type = normalize_plan_type(oauth.organization_type.clone()?);
    let base = organization_type
        .strip_prefix("claude_")
        .unwrap_or(&organization_type)
        .to_string();
    let tier = |value: &Option<String>| value.clone().map(normalize_plan_type).unwrap_or_default();
    let organization_tier = tier(&oauth.organization_rate_limit_tier);
    let user_tier = tier(&oauth.user_rate_limit_tier);
    let refined = match base.as_str() {
        "max" => [&organization_tier, &user_tier]
            .into_iter()
            .find_map(|tier| {
                if tier.ends_with("max_5x") {
                    Some("max_5x")
                } else if tier.ends_with("max_20x") {
                    Some("max_20x")
                } else {
                    None
                }
            })
            .map(str::to_string),
        "team" => {
            let seat = tier(&oauth.seat_tier);
            if seat.contains("premium") || user_tier.ends_with("max_5x") {
                Some("team_premium".to_string())
            } else if seat.contains("standard") {
                Some("team_standard".to_string())
            } else {
                None
            }
        }
        _ => None,
    };
    Some(refined.unwrap_or(base)).filter(|plan| !plan.is_empty())
}

/// "Claude Ultra", "Claude Team Premium", ... for a local message.
pub(in crate::agent_status) fn claude_plan_label(plan_type: Option<&str>) -> Option<String> {
    claude_plan_name(plan_type).map(|name| format!("Claude {name}"))
}

/// "Ultra", "Team Premium", ... Plan ids keep their old names: `max_5x` is
/// Max, `max_20x` is Ultra, and a bare `max` (tier unknown) is either.
pub(in crate::agent_status) fn claude_plan_name(plan_type: Option<&str>) -> Option<String> {
    let plan = normalize_plan_type(plan_type?.to_string());
    let plan = plan.strip_prefix("claude_").unwrap_or(&plan);
    let label = match plan {
        "" => return None,
        "max_20x" => "Ultra".to_string(),
        "max_5x" => "Max".to_string(),
        "max" => "Max or Ultra".to_string(),
        other => other
            .split('_')
            .filter(|word| !word.is_empty())
            .map(|word| {
                let mut chars = word.chars();
                chars.next().map_or_else(String::new, |first| {
                    first.to_uppercase().collect::<String>() + chars.as_str()
                })
            })
            .collect::<Vec<_>>()
            .join(" "),
    };
    Some(label)
}

/// Local-only explanation naming the plans of both logins. It never names an
/// email and is never uploaded: degraded projections carry codes only.
pub(in crate::agent_status) fn claude_slot_binding_mismatch_message(
    approved_plan: Option<&str>,
    signed_in_plan: Option<&str>,
) -> String {
    let approved = claude_plan_label(approved_plan)
        .map(|label| format!("the {label} account"))
        .unwrap_or_else(|| "the account it was set up with".to_string());
    let signed_in = claude_plan_label(signed_in_plan)
        .map(|label| format!("a different {label} account"))
        .unwrap_or_else(|| "a different Claude account".to_string());
    format!(
        "Claude Code in this connection is now signed in to {signed_in}. This connection is for {approved}, so Ottto paused limit reading, uploads and token refresh here and assigned nothing to the other account. Sign in again with {approved} to resume."
    )
}

/// Collection status for a slot whose current login is not the account it is
/// approved for. It keeps the approved pair, profile and that account's own
/// last complete reading (stale), so local and degraded projections stay on
/// the approved account; nothing from the other login is kept.
pub(in crate::agent_status) fn claude_slot_binding_mismatch_status(
    expected: &ClaudeSlotAccountBinding,
    signed_in_plan: Option<&str>,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    claude_slot_approval_blocked_status(
        expected,
        ClaudeSlotProbeFailure::IdentityMismatch,
        |approved_plan| claude_slot_binding_mismatch_message(approved_plan, signed_in_plan),
        previous,
        captured_at,
    )
}

/// Local message when a bound slot's Claude account file cannot be read.
pub(in crate::agent_status) fn claude_slot_unknown_login_message(
    approved_plan: Option<&str>,
) -> String {
    let approved = claude_plan_label(approved_plan)
        .map(|label| format!("the {label} account"))
        .unwrap_or_else(|| "the account it was set up with".to_string());
    format!(
        "Claude Code's account file for this connection is missing or unreadable, so Ottto cannot confirm it is still signed in to {approved}. Ottto paused limit reading, uploads and token refresh here. Sign in again with {approved} to resume."
    )
}

/// Status for a bound slot that must not be collected or refreshed this
/// pass. It keeps the approved pair, profile and that account's own last
/// complete reading (stale), so local and degraded projections stay on the
/// approved account; nothing from any other login is kept.
pub(in crate::agent_status) fn claude_slot_approval_blocked_status(
    expected: &ClaudeSlotAccountBinding,
    failure: ClaudeSlotProbeFailure,
    message: impl FnOnce(Option<&str>) -> String,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let previous = previous
        .filter(|previous| claude_slot_status_binding(previous).as_ref() == Some(expected))
        .cloned();
    let approved_plan = previous
        .as_ref()
        .and_then(exact_claude_slot_account_profile)
        .and_then(|profile| profile.plan_type.clone());
    let mut status = failure.status(captured_at);
    if let Some(diagnostic) = status.diagnostics.first_mut() {
        diagnostic.message = message(approved_plan.as_deref());
    }
    retain_exact_claude_slot_binding(
        &mut status,
        &expected.account_identifier_hash,
        &expected.organization_identifier_hash,
    );
    if let Some(previous) = previous {
        inherit_claude_slot_account_profile(&mut status, Some(&previous));
        retain_previous_complete_claude_read(&mut status, previous);
    }
    status
}

/// Gate before upkeep, any CLI spawn or usage call: refuse when the slot's
/// approval is undeterminable. `Ok` carries the expected binding (when the
/// slot has one) for the owner rule and the post-resolution check.
#[expect(clippy::result_large_err, reason = "Err is the full slot status")]
pub(in crate::agent_status) fn claude_slot_pre_collection_gate(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> Result<Option<ClaudeSlotAccountBinding>, ClaudeConfigSlotCollectionStatusV1> {
    let observed = previous.and_then(claude_slot_status_binding);
    claude_slot_expected_binding(&descriptor.slot_id, observed.as_ref())
        .map_err(|()| claude_slot_approval_unavailable_status(previous, captured_at))
}

/// Local message when another account's `.claude.json` sits in a slot whose
/// stored sign-in cannot be checked yet.
pub(in crate::agent_status) fn claude_slot_owner_unproven_message(
    approved_plan: Option<&str>,
) -> String {
    let approved = claude_plan_label(approved_plan)
        .map(|label| format!("the {label} account"))
        .unwrap_or_else(|| "the account it was set up with".to_string());
    format!(
        "Claude Code's account file for this connection names a different account, and Ottto could not yet confirm that its saved sign-in is still {approved}. Ottto paused limit reading and uploads here until it can; reconnect if this does not clear."
    )
}

/// Local wording for a slot whose approval was observed, not verified.
pub(in crate::agent_status) fn claude_slot_observed_approval_notice(
    approved_plan: Option<&str>,
) -> String {
    match claude_plan_label(approved_plan) {
        Some(label) => format!(
            "Approved from the current Claude login ({label}). If this is the wrong account, sign in again with the right one."
        ),
        None => "Approved from the current Claude login. If this is the wrong account, sign in again with the right one.".to_string(),
    }
}

/// Mark registered slots whose approval was back-filled from an observed
/// login (trust on first use). The notice is local-only and clears as soon
/// as a verified setup or reconnect approves the slot.
pub(in crate::agent_status) fn apply_claude_slot_approval_notice(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    approval: Option<&ottto_core::ClaudeSlotApproval>,
) {
    status.approval_notice = approval
        .filter(|approval| {
            approval.source == ottto_core::ClaudeSlotApprovalSource::Observed
                && claude_slot_status_binding(status).as_ref() == Some(&approval.binding)
        })
        .map(|_| {
            claude_slot_observed_approval_notice(
                exact_claude_slot_account_profile(status)
                    .and_then(|profile| profile.plan_type.as_deref()),
            )
        });
}

pub(in crate::agent_status) fn claude_slot_approvals(
) -> BTreeMap<String, ottto_core::ClaudeSlotApproval> {
    FileClaudeConfigSlotSettingsStore::default()
        .slot_approvals()
        .unwrap_or_default()
}

/// Gate after the exact slot resolved, before its usage call. A slot without
/// any approval records this first verified identity (trust on first use).
#[expect(clippy::result_large_err, reason = "Err is the full slot status")]
pub(in crate::agent_status) fn claude_slot_post_resolution_gate(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    expected: Option<ClaudeSlotAccountBinding>,
    resolved: &ResolvedClaudeSlot,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> Result<(), ClaudeConfigSlotCollectionStatusV1> {
    let current = ClaudeSlotAccountBinding::new(
        &resolved.account_identifier_hash,
        &resolved.organization_identifier_hash,
    );
    let expected = match expected {
        Some(expected) => Some(expected),
        None => claude_slot_expected_binding(&descriptor.slot_id, current.as_ref())
            .map_err(|()| claude_slot_approval_unavailable_status(previous, captured_at))?,
    };
    match (expected, current) {
        (Some(expected), Some(current)) if expected != current => {
            Err(claude_slot_binding_mismatch_status(
                &expected,
                resolved.account.plan_type.as_deref(),
                previous,
                captured_at,
            ))
        }
        _ => Ok(()),
    }
}

pub(in crate::agent_status) fn degraded_claude_slot_snapshot(
    status: &ClaudeConfigSlotCollectionStatusV1,
    durability: ClaudeAccountAnchorDurabilityV1,
    anchor_health: Option<ClaudeAccountAnchorHealthV1>,
    captured_at: &str,
    expires_at: &str,
) -> Option<AgentStatusSnapshot> {
    let access_state = projected_claude_quota_access_state(status)?;
    if matches!(
        access_state,
        ClaudeQuotaAccessState::Full | ClaudeQuotaAccessState::Partial
    ) {
        return None;
    }
    let account_hash = status.account_identifier_hash.as_ref()?.clone();
    let organization_hash = status.organization_identifier_hash.as_ref()?.clone();
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::CliJson,
        captured_at.to_string(),
        expires_at.to_string(),
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: if access_state == ClaudeQuotaAccessState::ReconnectRequired {
            AgentLoginState::SignedOut
        } else {
            AgentLoginState::Unknown
        },
        provider: Some("anthropic".to_string()),
        auth_method: Some("oauth".to_string()),
        billing_channel: Some("subscription".to_string()),
        account_identifier_hash: Some(account_hash),
        organization_identifier_hash: Some(organization_hash),
        billing_identity_evidence: Some("provider_account_id".to_string()),
        claude_quota_access_state: Some(access_state),
        claude_anchor_durability: Some(durability),
        claude_anchor_health: anchor_health,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
        ..unsupported_account("anthropic")
    });
    if let Some(profile) = exact_claude_slot_account_profile(status) {
        let account = snapshot.account.as_mut().expect("degraded account exists");
        account.email = profile.email.clone();
        account.organization_label = profile.organization_label.clone();
        account.plan_type = profile.plan_type.clone();
        account.subscription_product = profile.subscription_product.clone();
    }
    if let Some(local) = status.quota_snapshot.as_ref().filter(|local| {
        local_claude_quota_snapshot_within_retention(local, OffsetDateTime::now_utc())
    }) {
        snapshot.quota_windows = local
            .quota_windows
            .iter()
            .cloned()
            .map(|mut window| {
                window.freshness = AgentQuotaWindowFreshness::Stale;
                window
            })
            .collect();
        snapshot.credit_balances = local
            .credit_balances
            .iter()
            .cloned()
            .map(|mut balance| {
                balance.freshness = AgentQuotaWindowFreshness::Stale;
                balance
            })
            .collect();
    }
    ensure_claude_quota_access_capability(&mut snapshot);
    let (code, message) = match access_state {
        ClaudeQuotaAccessState::TemporarilyUnavailable => (
            "claude_quota_temporarily_unavailable",
            "Full Claude quota collection is temporarily unavailable for this registered account and will retry automatically.",
        ),
        ClaudeQuotaAccessState::ReconnectRequired => (
            "claude_quota_reconnect_required",
            "This registered Claude account requires customer-owned official Claude Code login before full quota collection can resume.",
        ),
        ClaudeQuotaAccessState::Paused => (
            "claude_quota_collection_paused",
            "Full Claude quota collection is paused for this registered account.",
        ),
        ClaudeQuotaAccessState::AttentionRequired => (
            "claude_quota_attention_required",
            "This registered Claude account needs local attention before full quota collection can resume.",
        ),
        ClaudeQuotaAccessState::Full | ClaudeQuotaAccessState::Partial => unreachable!(),
    };
    snapshot.diagnostics.push(
        AgentStatusDiagnostic::source(code, AgentDiagnosticSeverity::Warning, message)
            .with_quota_binding(
                status.account_identifier_hash.clone(),
                status.organization_identifier_hash.clone(),
            ),
    );
    snapshot
        .diagnostics
        .extend(safe_claude_slot_check_diagnostics(
            &status.quota_check_diagnostics,
            status.account_identifier_hash.as_deref()?,
            status.organization_identifier_hash.as_deref()?,
        ));
    // Enum-derived codes describe local collection/upkeep state only. Their
    // clocks are intentionally absent: slot captured_at is not a provider check.
    let state_code = serde_json::to_value(&status.state)
        .ok()?
        .as_str()?
        .to_string();
    snapshot.diagnostics.push(
        AgentStatusDiagnostic::source(
            format!("claude_slot_collection_{state_code}"),
            AgentDiagnosticSeverity::Warning,
            "The exact registered slot reported this local collection state.",
        )
        .with_quota_binding(
            status.account_identifier_hash.clone(),
            status.organization_identifier_hash.clone(),
        ),
    );
    for diagnostic in &status.diagnostics {
        let code = serde_json::to_value(diagnostic.code)
            .ok()?
            .as_str()?
            .to_string();
        let code = format!("claude_slot_collection_{code}");
        if !snapshot.diagnostics.iter().any(|item| item.code == code) {
            snapshot.diagnostics.push(
                AgentStatusDiagnostic::source(
                    code,
                    AgentDiagnosticSeverity::Warning,
                    "The exact registered slot reported this local collection state.",
                )
                .with_quota_binding(
                    status.account_identifier_hash.clone(),
                    status.organization_identifier_hash.clone(),
                ),
            );
        }
    }
    if let Some(upkeep) = &status.upkeep {
        let result = serde_json::to_value(upkeep.result)
            .ok()?
            .as_str()?
            .to_string();
        let result_code = format!("claude_slot_upkeep_{result}");
        if !snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == result_code)
        {
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            result_code, AgentDiagnosticSeverity::Info,
            "The exact registered slot reported this local credential-upkeep result; it is not a quota provider check.",
        ).with_quota_binding(status.account_identifier_hash.clone(), status.organization_identifier_hash.clone()));
        }
        if bounded_claude_collection_timestamp(
            upkeep.attempted_at.as_deref(),
            OffsetDateTime::now_utc(),
        )
        .is_some()
        {
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "claude_slot_upkeep_attempt_started", AgentDiagnosticSeverity::Info,
                "The last recorded local credential-upkeep attempt started at this time; completion time is unavailable.",
            ).with_observed_at(upkeep.attempted_at.clone()).with_quota_binding(status.account_identifier_hash.clone(), status.organization_identifier_hash.clone()));
        }
    }
    Some(snapshot)
}

pub(in crate::agent_status) fn claude_quota_access_priority(snapshot: &AgentStatusSnapshot) -> u8 {
    match snapshot
        .account
        .as_ref()
        .and_then(|account| account.claude_quota_access_state)
    {
        Some(ClaudeQuotaAccessState::ReconnectRequired) => 4,
        Some(ClaudeQuotaAccessState::AttentionRequired) => 3,
        Some(ClaudeQuotaAccessState::Paused) => 2,
        Some(ClaudeQuotaAccessState::TemporarilyUnavailable) => 1,
        _ => 0,
    }
}

pub(in crate::agent_status) fn degraded_claude_slot_snapshots(
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    canonical_anchors: &BTreeMap<ClaudeStrongBinding, String>,
    winning_bindings: &BTreeSet<ClaudeStrongBinding>,
    captured_at: &str,
    expires_at: &str,
) -> Vec<AgentStatusSnapshot> {
    let mut degraded_by_binding = BTreeMap::<ClaudeStrongBinding, AgentStatusSnapshot>::new();
    for (slot_id, status) in slot_states {
        let Some(binding) = status
            .account_identifier_hash
            .as_deref()
            .and_then(|account| {
                ClaudeStrongBinding::new(account, status.organization_identifier_hash.as_deref()?)
            })
        else {
            continue;
        };
        let canonical_slot_id = canonical_anchors.get(&binding);
        if canonical_slot_id.is_some_and(|canonical| canonical != slot_id) {
            continue;
        }
        let (durability, anchor_health) = canonical_slot_id
            .and_then(|canonical| slot_states.get(canonical))
            .map(|anchor| {
                (
                    ClaudeAccountAnchorDurabilityV1::Anchored,
                    projected_claude_anchor_health(anchor),
                )
            })
            .unwrap_or((ClaudeAccountAnchorDurabilityV1::DefaultOnly, None));
        let Some(snapshot) = degraded_claude_slot_snapshot(
            status,
            durability,
            anchor_health,
            captured_at,
            expires_at,
        ) else {
            continue;
        };
        if winning_bindings.contains(&binding) {
            continue;
        }
        match degraded_by_binding.get(&binding) {
            Some(previous)
                if claude_quota_access_priority(previous)
                    >= claude_quota_access_priority(&snapshot) => {}
            _ => {
                degraded_by_binding.insert(binding, snapshot);
            }
        }
    }
    degraded_by_binding.into_values().collect()
}
