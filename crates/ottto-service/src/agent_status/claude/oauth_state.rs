//! Claude status oauth state operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::default_support_dir;
use crate::agent_status::fs;
use crate::agent_status::open_private_lock_file;
use crate::agent_status::ottto_user_agent;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::write_owner_only_file_atomic_if_changed;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::Arc;
use crate::agent_status::BTreeMap;
use crate::agent_status::ClaudeOAuthCollectionAttemptGuard;
use crate::agent_status::ClaudeOAuthUsageAuthFailureRecord;
use crate::agent_status::ClaudeOAuthUsageBreaker;
use crate::agent_status::ClaudeOAuthUsageCaller;
use crate::agent_status::ClaudeOAuthUsageCallerAuthState;
use crate::agent_status::ClaudeOAuthUsageFailure;
use crate::agent_status::Digest;
use crate::agent_status::Mutex;
use crate::agent_status::Path;
use crate::agent_status::PathBuf;
use crate::agent_status::Sha256;
use crate::agent_status::CLAUDE_OAUTH_ACCOUNT_STATE_LOCKS;
use crate::agent_status::CLAUDE_OAUTH_BETA_HEADER;
use crate::agent_status::CLAUDE_OAUTH_COLLECTION_ATTEMPT_LOCKS;
use crate::agent_status::CLAUDE_OAUTH_USAGE_ACCOUNT_STATE_DIR;
use crate::agent_status::CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS;
use crate::agent_status::CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD;
use crate::agent_status::CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS;
use crate::agent_status::CLAUDE_OAUTH_USAGE_BREAKER_FILE;
use crate::agent_status::CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION;
use crate::agent_status::CLAUDE_OAUTH_USAGE_ENDPOINT;
use crate::agent_status::CLAUDE_OAUTH_USAGE_LEGACY_BREAKER_FILE;
use crate::agent_status::CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE;
use crate::agent_status::CLAUDE_OAUTH_USAGE_RAW_SLOT_CALLER_KEY_PREFIX;
use crate::agent_status::CLAUDE_OAUTH_USAGE_SLOT_CALLER_KEY_PREFIX;

pub(in crate::agent_status) fn claude_oauth_usage_slot_caller_key(slot_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-usage-caller:v1\0");
    hasher.update(slot_id.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!(
        "{CLAUDE_OAUTH_USAGE_SLOT_CALLER_KEY_PREFIX}{}",
        &digest[..32]
    )
}

/// The opaque form of a persisted caller key; raw `slot:<id>` keys are hashed.
pub(in crate::agent_status) fn claude_oauth_usage_opaque_caller_key(key: &str) -> String {
    match key.strip_prefix(CLAUDE_OAUTH_USAGE_RAW_SLOT_CALLER_KEY_PREFIX) {
        Some(slot_id) => claude_oauth_usage_slot_caller_key(slot_id),
        None => key.to_string(),
    }
}

/// Whether the caller's current credential is provably not the one whose
/// rejection this state records (its access expiry changed).
pub(in crate::agent_status) fn claude_oauth_usage_caller_credential_rotated(
    state: &ClaudeOAuthUsageCallerAuthState,
    credential_expires_at: Option<&str>,
) -> bool {
    matches!(
        (state.credential_expires_at.as_deref(), credential_expires_at),
        (Some(recorded), Some(current)) if recorded != current
    )
}

/// Whether a caller's streak is older than the cool-down and so no longer
/// counts toward that caller's threshold.
pub(in crate::agent_status) fn claude_oauth_usage_caller_streak_is_stale(
    state: &ClaudeOAuthUsageCallerAuthState,
    now: u64,
) -> bool {
    state.last_failure_at_epoch_seconds > 0
        && now
            >= state
                .last_failure_at_epoch_seconds
                .saturating_add(CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS)
}

/// Parse a breaker file, migrating raw slot-id caller keys in place.
pub(in crate::agent_status) fn read_claude_oauth_usage_breaker_file_migrating(
    path: &Path,
) -> Option<ClaudeOAuthUsageBreaker> {
    let body = fs::read_to_string(path).ok()?;
    let mut breaker: ClaudeOAuthUsageBreaker = serde_json::from_str(&body).ok()?;
    if breaker.migrate_raw_caller_keys() {
        if let Ok(body) = serde_json::to_vec_pretty(&breaker) {
            let _ = write_owner_only_file_atomic_if_changed(path, &body);
        }
    }
    Some(breaker)
}

/// Whether the off-switch sentinel is present in the daemon support dir.
///
/// Absent means enabled, which keeps the default behaviour unchanged.
pub(crate) fn claude_oauth_usage_network_disabled() -> bool {
    default_support_dir()
        .join(CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE)
        .is_file()
}

pub(in crate::agent_status) fn claude_oauth_binding_key(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-strong-binding:v1\0");
    hasher.update(account_identifier_hash.as_bytes());
    hasher.update(b"\0");
    hasher.update(organization_identifier_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(in crate::agent_status) fn claude_oauth_usage_account_state_dir(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> PathBuf {
    let component = if account_identifier_hash.is_empty() || organization_identifier_hash.is_empty()
    {
        "unresolved".to_string()
    } else {
        claude_oauth_binding_key(account_identifier_hash, organization_identifier_hash)
    };
    default_support_dir()
        .join(CLAUDE_OAUTH_USAGE_ACCOUNT_STATE_DIR)
        .join(component)
}

pub(in crate::agent_status) fn claude_oauth_usage_breaker_path(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> PathBuf {
    claude_oauth_usage_account_state_dir(account_identifier_hash, organization_identifier_hash)
        .join(CLAUDE_OAUTH_USAGE_BREAKER_FILE)
}

pub(in crate::agent_status) fn claude_oauth_usage_legacy_breaker_path() -> PathBuf {
    default_support_dir().join(CLAUDE_OAUTH_USAGE_LEGACY_BREAKER_FILE)
}

pub(in crate::agent_status) fn claude_oauth_account_state_lock(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Arc<Mutex<()>> {
    let mut locks = CLAUDE_OAUTH_ACCOUNT_STATE_LOCKS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks
        .entry(claude_oauth_binding_key(
            account_identifier_hash,
            organization_identifier_hash,
        ))
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

pub(in crate::agent_status) fn try_claude_oauth_collection_attempt(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Option<ClaudeOAuthCollectionAttemptGuard> {
    use std::os::fd::AsRawFd;
    let process_lock = {
        let mut locks = CLAUDE_OAUTH_COLLECTION_ATTEMPT_LOCKS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *locks
            .entry(claude_oauth_binding_key(
                account_identifier_hash,
                organization_identifier_hash,
            ))
            .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
    };
    let process = match process_lock.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return None,
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
    };
    let account_root =
        claude_oauth_usage_account_state_dir(account_identifier_hash, organization_identifier_hash);
    if fs::create_dir_all(&account_root).is_err() {
        return None;
    }
    let file = open_private_lock_file(&account_root.join(".collection-attempt.lock")).ok()?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return None;
    }
    Some(ClaudeOAuthCollectionAttemptGuard {
        _process: process,
        file,
    })
}

/// Fingerprint of everything about the call that could make a past failure
/// irrelevant: the endpoint, the beta header, the User-Agent we identify with,
/// and whether the off-switch is engaged. When any of them changes - a daemon
/// upgrade, or the user toggling the sentinel off and back on - the breaker
/// resets rather than holding a verdict about a call we no longer make.
pub(in crate::agent_status) fn claude_oauth_usage_config_fingerprint() -> String {
    claude_oauth_usage_config_fingerprint_for(
        CLAUDE_OAUTH_USAGE_ENDPOINT,
        CLAUDE_OAUTH_BETA_HEADER,
        &ottto_user_agent(),
        claude_oauth_usage_network_disabled(),
    )
}

pub(in crate::agent_status) fn claude_oauth_usage_config_fingerprint_for(
    endpoint: &str,
    beta_header: &str,
    user_agent: &str,
    network_disabled: bool,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-usage-config:");
    hasher.update(endpoint.as_bytes());
    hasher.update(b"\0");
    hasher.update(beta_header.as_bytes());
    hasher.update(b"\0");
    hasher.update(user_agent.as_bytes());
    hasher.update(b"\0");
    hasher.update(if network_disabled { "off" } else { "on" }.as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}

pub(in crate::agent_status) fn read_claude_oauth_usage_breaker(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
) -> Option<ClaudeOAuthUsageBreaker> {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    read_claude_oauth_usage_breaker_locked(
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
    )
}

pub(in crate::agent_status) fn read_claude_oauth_usage_breaker_locked(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
) -> Option<ClaudeOAuthUsageBreaker> {
    let breaker = read_claude_oauth_usage_breaker_file_migrating(
        &claude_oauth_usage_breaker_path(account_identifier_hash, organization_identifier_hash),
    )?;
    if breaker.schema_version != CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION
        || breaker.account_identifier_hash != account_identifier_hash
        || breaker.organization_identifier_hash != organization_identifier_hash
        || breaker.config_fingerprint != config_fingerprint
    {
        return None;
    }
    Some(breaker)
}

pub(in crate::agent_status) fn write_claude_oauth_usage_breaker_locked(
    breaker: &ClaudeOAuthUsageBreaker,
) -> std::io::Result<()> {
    let path = claude_oauth_usage_breaker_path(
        &breaker.account_identifier_hash,
        &breaker.organization_identifier_hash,
    );
    let body = serde_json::to_vec_pretty(breaker).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic_if_changed(&path, &body)
}

#[cfg(test)]
pub(in crate::agent_status) fn clear_claude_oauth_usage_breaker(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = fs::remove_file(claude_oauth_usage_breaker_path(
        account_identifier_hash,
        organization_identifier_hash,
    ));
}

/// Clear an auth-class open breaker once consented upkeep has replaced the
/// credential whose rejections opened it.
///
/// The breaker's own rule is that a changed call configuration resets it,
/// because the thing that was failing is not the thing we would call next. An
/// expired access token is exactly that: those 401s came from a credential
/// that no longer exists, and holding the full cool-down against a fresh one
/// leaves a healthy account's limits dark for up to a day. Only the auth class
/// is cleared - an unreadable response shape or a sustained 429 is a statement
/// about the endpoint rather than about our token, and keeps its cool-down.
///
/// Auth state is per caller, so only the refreshed slot's own streak and
/// backoff are retired; the default login's rejections, if any, were earned by
/// a different credential and stay. An account-wide auth verdict written by a
/// daemon from before caller attribution has only its auth fields cleared.
#[cfg(test)]
pub(crate) fn clear_claude_oauth_usage_auth_breaker(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    slot_id: &str,
) {
    let caller_key = ClaudeOAuthUsageCaller::RegisteredSlot(slot_id.to_string()).breaker_key();
    let retire = |path: &Path| {
        let Some(mut breaker) =
            read_claude_oauth_usage_breaker_file_migrating(path).filter(|breaker| {
                breaker.account_identifier_hash == account_identifier_hash
                    && breaker.organization_identifier_hash == organization_identifier_hash
            })
        else {
            return;
        };
        let mut changed = breaker.auth_callers.remove(&caller_key).is_some();
        // A pre-attribution account-wide auth verdict: clear only its auth
        // fields. Other callers' attributed holds were earned by credentials
        // this refresh did not touch, and stay.
        if breaker.opened_by == ClaudeOAuthUsageFailure::AuthRejected.code() {
            breaker.auth_failures = 0;
            breaker.opened_by.clear();
            breaker.opened_at_epoch_seconds = 0;
            breaker.reopen_after_epoch_seconds = 0;
            changed = true;
        }
        if !changed {
            return;
        }
        if breaker.holds_no_state() {
            let _ = fs::remove_file(path);
            return;
        }
        if let Ok(body) = serde_json::to_vec_pretty(&breaker) {
            let _ = write_owner_only_file_atomic_if_changed(path, &body);
        }
    };
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    retire(&claude_oauth_usage_breaker_path(
        account_identifier_hash,
        organization_identifier_hash,
    ));
}

pub(in crate::agent_status) fn claude_oauth_usage_breaker_is_open(
    breaker: &ClaudeOAuthUsageBreaker,
    now: u64,
) -> bool {
    // Reset by expiry: once the cool-down passes the breaker is closed again
    // and the next tick re-probes with the counters it carries.
    now < breaker.reopen_after_epoch_seconds
}

/// Fold one failure into the persisted breaker state. Pure so the thresholds
/// and the cool-down can be exercised without touching disk or the network.
pub(in crate::agent_status) fn claude_oauth_usage_breaker_after_failure(
    previous: Option<ClaudeOAuthUsageBreaker>,
    failure: ClaudeOAuthUsageFailure,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
) -> ClaudeOAuthUsageBreaker {
    let mut breaker = previous.unwrap_or_default();
    breaker.schema_version = CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION;
    breaker.account_identifier_hash = account_identifier_hash.to_string();
    breaker.organization_identifier_hash = organization_identifier_hash.to_string();
    breaker.config_fingerprint = config_fingerprint.to_string();
    let counter = match failure {
        ClaudeOAuthUsageFailure::AuthRejected => &mut breaker.auth_failures,
        ClaudeOAuthUsageFailure::ResponseShape => &mut breaker.shape_failures,
        ClaudeOAuthUsageFailure::RateLimited => &mut breaker.rate_limit_failures,
    };
    *counter = counter.saturating_add(1);
    if *counter >= failure.threshold() && !claude_oauth_usage_breaker_is_open(&breaker, now) {
        breaker.opened_at_epoch_seconds = now;
        breaker.reopen_after_epoch_seconds = now + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS;
        breaker.opened_by = failure.code().to_string();
    }
    breaker
}

pub(in crate::agent_status) fn record_claude_oauth_usage_failure(
    failure: ClaudeOAuthUsageFailure,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
) -> Vec<AgentStatusDiagnostic> {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = read_claude_oauth_usage_breaker_locked(
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
    );
    let was_open = previous
        .as_ref()
        .is_some_and(|breaker| claude_oauth_usage_breaker_is_open(breaker, now));
    let breaker = claude_oauth_usage_breaker_after_failure(
        previous,
        failure,
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        now,
    );
    let _ = write_claude_oauth_usage_breaker_locked(&breaker);
    if !was_open && claude_oauth_usage_breaker_is_open(&breaker, now) {
        return vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)];
    }
    Vec::new()
}

/// The backoff one caller holds after `consecutive_failures` rejections in a
/// row: 15 minutes, then doubling, then the full breaker cool-down once the
/// caller reaches the auth threshold. Bounded by that cool-down.
pub(in crate::agent_status) fn claude_oauth_usage_auth_backoff_seconds(
    consecutive_failures: u32,
) -> u64 {
    if consecutive_failures >= CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
        return CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS;
    }
    let doublings = consecutive_failures.saturating_sub(1).min(16);
    CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS
        .saturating_mul(1u64 << doublings)
        .min(CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS)
}

/// This caller's auth state while it is held back, if it is. A rotated
/// credential (different access expiry) is not held by its predecessor's
/// rejections. `None` for the current expiry means unknown: the hold stands.
pub(in crate::agent_status) fn claude_oauth_usage_caller_auth_hold<'a>(
    breaker: &'a ClaudeOAuthUsageBreaker,
    caller: &ClaudeOAuthUsageCaller,
    now: u64,
    credential_expires_at: Option<&str>,
) -> Option<&'a ClaudeOAuthUsageCallerAuthState> {
    breaker
        .auth_callers
        .get(&caller.breaker_key())
        .filter(|state| now < state.backoff_until_epoch_seconds)
        .filter(|state| !claude_oauth_usage_caller_credential_rotated(state, credential_expires_at))
}

/// Fold one 401/403 from one caller into the persisted breaker. Pure so the
/// per-caller streak, backoff, and attribution fields can be tested directly.
///
/// The account-wide counters and open verdict are untouched: one credential's
/// rejection must not stop a different credential for the same account. A
/// caller whose streak is older than the cool-down starts a new streak.
#[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
pub(in crate::agent_status) fn claude_oauth_usage_breaker_after_auth_failure(
    previous: Option<ClaudeOAuthUsageBreaker>,
    caller: &ClaudeOAuthUsageCaller,
    status: u16,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
    credential_expires_at: Option<&str>,
) -> ClaudeOAuthUsageBreaker {
    let mut breaker = previous.unwrap_or_default();
    breaker.schema_version = CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION;
    breaker.account_identifier_hash = account_identifier_hash.to_string();
    breaker.organization_identifier_hash = organization_identifier_hash.to_string();
    breaker.config_fingerprint = config_fingerprint.to_string();
    let key = caller.breaker_key();
    let state = breaker.auth_callers.entry(key.clone()).or_default();
    if claude_oauth_usage_caller_streak_is_stale(state, now)
        || claude_oauth_usage_caller_credential_rotated(state, credential_expires_at)
    {
        *state = ClaudeOAuthUsageCallerAuthState::default();
    }
    state.credential_expires_at = credential_expires_at.map(ToString::to_string);
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    state.last_status = status;
    state.last_failure_at_epoch_seconds = now;
    state.backoff_until_epoch_seconds = now.saturating_add(
        claude_oauth_usage_auth_backoff_seconds(state.consecutive_failures),
    );
    breaker.last_auth_failure = Some(ClaudeOAuthUsageAuthFailureRecord {
        caller: key,
        status,
        at_epoch_seconds: now,
    });
    breaker
}

pub(in crate::agent_status) fn record_claude_oauth_usage_auth_failure(
    caller: &ClaudeOAuthUsageCaller,
    status: u16,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
    credential_expires_at: Option<&str>,
) -> Vec<AgentStatusDiagnostic> {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = read_claude_oauth_usage_breaker_locked(
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
    );
    let was_open = previous
        .as_ref()
        .and_then(|breaker| {
            claude_oauth_usage_caller_auth_hold(breaker, caller, now, credential_expires_at)
        })
        .is_some_and(|state| {
            state.consecutive_failures >= CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD
        });
    let breaker = claude_oauth_usage_breaker_after_auth_failure(
        previous,
        caller,
        status,
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        now,
        credential_expires_at,
    );
    let _ = write_claude_oauth_usage_breaker_locked(&breaker);
    let state = breaker
        .auth_callers
        .get(&caller.breaker_key())
        .cloned()
        .unwrap_or_default();
    let mut diagnostics = vec![AgentStatusDiagnostic::source(
        "claude_oauth_usage_auth_rejected",
        AgentDiagnosticSeverity::Warning,
        format!(
            "The Claude OAuth usage endpoint rejected the {} credential with HTTP {status} at {}; that credential is not retried until {}.",
            caller.credential_kind(),
            rfc3339_from_unix_seconds(now).unwrap_or_default(),
            rfc3339_from_unix_seconds(state.backoff_until_epoch_seconds).unwrap_or_default(),
        ),
    )
    .with_observed_at(rfc3339_from_unix_seconds(now))];
    if !was_open && state.consecutive_failures >= CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
        diagnostics.push(claude_oauth_usage_caller_auth_hold_diagnostic(
            caller, &state, now,
        ));
    }
    diagnostics
}

/// Why this caller made no provider request. Once the caller reached the auth
/// threshold this is the existing circuit-open alert, worded exactly as the
/// account-wide one so every consumer that already reads it keeps working.
pub(in crate::agent_status) fn claude_oauth_usage_caller_auth_hold_diagnostic(
    caller: &ClaudeOAuthUsageCaller,
    state: &ClaudeOAuthUsageCallerAuthState,
    now: u64,
) -> AgentStatusDiagnostic {
    let remaining_minutes = state.backoff_until_epoch_seconds.saturating_sub(now) / 60;
    if state.consecutive_failures >= CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
        return AgentStatusDiagnostic::source(
            "claude_oauth_usage_circuit_open",
            AgentDiagnosticSeverity::Warning,
            format!(
                "Stopped calling the Claude OAuth usage endpoint after auth rejected; quota falls back to Claude Code's local statusLine for the next {remaining_minutes} minute(s)."
            ),
        );
    }
    AgentStatusDiagnostic::source(
        "claude_oauth_usage_auth_backoff",
        AgentDiagnosticSeverity::Info,
        format!(
            "The {} credential was rejected with HTTP {} at {}; it is not retried for the next {remaining_minutes} minute(s).",
            caller.credential_kind(),
            state.last_status,
            rfc3339_from_unix_seconds(state.last_failure_at_epoch_seconds).unwrap_or_default(),
        ),
    )
    .with_observed_at(rfc3339_from_unix_seconds(now))
}

/// A clean answer from `caller`: reset the account-wide counters and this
/// caller's auth streak. Other callers' non-stale streaks are kept, held or
/// not, because this answer was earned by a different credential. With nothing left to keep, the
/// files are removed exactly as before caller attribution.
pub(in crate::agent_status) fn clear_claude_oauth_usage_breaker_after_success(
    caller: &ClaudeOAuthUsageCaller,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
) {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = read_claude_oauth_usage_breaker_locked(
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
    );
    let caller_key = caller.breaker_key();
    // Another caller's streak survives this success, held or not: it ends only
    // on that caller's own success, its credential refresh, or staleness.
    let held_others = previous
        .as_ref()
        .map(|breaker| {
            breaker
                .auth_callers
                .iter()
                .filter(|(key, state)| {
                    **key != caller_key && !claude_oauth_usage_caller_streak_is_stale(state, now)
                })
                .map(|(key, state)| (key.clone(), state.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    if held_others.is_empty() {
        let _ = fs::remove_file(claude_oauth_usage_breaker_path(
            account_identifier_hash,
            organization_identifier_hash,
        ));
        return;
    }
    let retained = ClaudeOAuthUsageBreaker {
        schema_version: CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
        account_identifier_hash: account_identifier_hash.to_string(),
        organization_identifier_hash: organization_identifier_hash.to_string(),
        config_fingerprint: config_fingerprint.to_string(),
        auth_callers: held_others,
        last_auth_failure: previous.and_then(|breaker| breaker.last_auth_failure),
        ..Default::default()
    };
    let _ = write_claude_oauth_usage_breaker_locked(&retained);
}

/// The alert itself. Snapshot diagnostics are uploaded with the agent-status
/// snapshot, so this reaches the backend on the next sync without a separate
/// telemetry channel.
pub(in crate::agent_status) fn claude_oauth_usage_circuit_open_diagnostic(
    breaker: &ClaudeOAuthUsageBreaker,
    now: u64,
) -> AgentStatusDiagnostic {
    let reason = if breaker.opened_by.is_empty() {
        "repeated failures".to_string()
    } else {
        breaker.opened_by.replace('_', " ")
    };
    let remaining_minutes = breaker.reopen_after_epoch_seconds.saturating_sub(now) / 60;
    AgentStatusDiagnostic::source(
        "claude_oauth_usage_circuit_open",
        AgentDiagnosticSeverity::Warning,
        format!(
            "Stopped calling the Claude OAuth usage endpoint after {reason}; quota falls back to Claude Code's local statusLine for the next {remaining_minutes} minute(s)."
        ),
    )
}

/// Which failure class, if any, a transport-level error counts as. `None` means
/// transient: transport errors and server-side 5xx say nothing about whether we
/// should keep calling.
pub(in crate::agent_status) fn claude_oauth_usage_failure_class(
    error: &ureq::Error,
) -> Option<ClaudeOAuthUsageFailure> {
    match error {
        ureq::Error::Status(401 | 403, _) => Some(ClaudeOAuthUsageFailure::AuthRejected),
        // The endpoint answering "gone" is a shape change by another name.
        ureq::Error::Status(404 | 410, _) => Some(ClaudeOAuthUsageFailure::ResponseShape),
        _ => None,
    }
}
