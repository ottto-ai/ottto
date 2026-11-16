//! Claude status statusline operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::current_unix_seconds;
use crate::agent_status::default_support_dir;
use crate::agent_status::percent_quota_status;
use crate::agent_status::read_claude_statusline_cache;
use crate::agent_status::read_claude_statusline_context_cache;
use crate::agent_status::read_claude_statusline_context_history;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::rfc3339_minus_seconds;
use crate::agent_status::unsupported_context;
use crate::agent_status::AgentContextCompleteness;
use crate::agent_status::AgentContextPressureSample;
use crate::agent_status::AgentContextState;
use crate::agent_status::AgentContextStatus;
use crate::agent_status::AgentQuotaWindow;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentQuotaWindowScope;
use crate::agent_status::AgentQuotaWindowStatus;
use crate::agent_status::AgentStatusPlanObservation;
use crate::agent_status::ClaudeStatusLineContextWindowCache;
use crate::agent_status::ClaudeStatusLineContextWindowHistory;
use crate::agent_status::ClaudeStatusLineContextWindowSample;
use crate::agent_status::ClaudeStatusLineRateLimitCache;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Rfc3339;
use crate::agent_status::TimeDuration;
use crate::agent_status::CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS;
use crate::agent_status::CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS;
use crate::agent_status::CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES;

/// What the statusLine rate-limit cache can offer the currently-resolved
/// account. `NotObserved` (nothing usable on disk) and `Unattributable`
/// (something on disk that is not provably ours) are deliberately distinct:
/// they read identically on the surface but mean opposite things about whether
/// collection is working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::agent_status) enum ClaudeStatusLineQuota {
    Windows(Vec<AgentQuotaWindow>),
    NotObserved,
    Unattributable(ClaudeStatusLineUnattributable),
}

/// Why a cached statusLine sample may not be served as the current account's
/// quota. Each variant is a distinct thing an operator can act on, so they stay
/// separate rather than collapsing into "unavailable".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::agent_status) enum ClaudeStatusLineUnattributable {
    /// Written while a different Claude Code credential was signed in -- the
    /// `/login` switch case, the same defect `ClaudeOAuthUsageCache` fixes.
    CredentialReplaced,
    /// A second Claude account is observable on this machine, so no statusLine
    /// sample can be tied to one of them.
    MultipleAccounts,
    /// Nothing on this machine names the account that wrote the sample, or the
    /// account reading it.
    AccountUnknown,
}

impl ClaudeStatusLineUnattributable {
    pub(in crate::agent_status) fn code(&self) -> &'static str {
        match self {
            Self::CredentialReplaced => "claude_statusline_cache_credential_replaced",
            Self::MultipleAccounts => "claude_statusline_cache_multiple_accounts",
            Self::AccountUnknown => "claude_statusline_cache_account_unknown",
        }
    }

    pub(in crate::agent_status) fn detail(&self) -> &'static str {
        match self {
            Self::CredentialReplaced => {
                "Claude Code statusLine quota is not currently observable for this account: the cached sample was written while a different Claude account was signed in."
            }
            Self::MultipleAccounts => {
                "Claude Code statusLine quota is not currently observable for this account: more than one Claude account is present on this machine, and statusLine samples carry no account identity."
            }
            Self::AccountUnknown => {
                "Claude Code statusLine quota is not currently observable for this account: the local Claude account could not be identified."
            }
        }
    }
}

/// Read the statusLine rate-limit cache, but only serve it as `account`'s quota
/// when it can actually be proven to be `account`'s.
///
/// `statusLine` is a Claude *Code* mechanism, not a Claude Desktop one. It is
/// configured once in `~/.claude/settings.json` and invoked by whichever Claude
/// Code surface renders -- the terminal CLI and the Claude Desktop app's "Code"
/// tab pipe to the same Ottto wrapper and overwrite the same machine-global
/// file. The payload names no account. So unlike `ClaudeOAuthUsageCache`, where
/// the daemon fetched the numbers itself and the writer's account key IS proof,
/// here the key records only which credential was visible at write time. Taken
/// alone it would launder a wrong attribution into a confident one: during the
/// live 2026-07-26 repro the CLI credential was the work Team account both when
/// the sample was written and when it was read, while the numbers belonged to
/// the personal Max account rendering in Desktop.
///
/// Proof therefore needs both halves:
///
/// 1. the sample was written under the credential that owns the machine now, and
/// 2. no *other* Claude account is observable on the machine at all.
///
/// Desktop plan observations already carry `account_identifier_hash` derived
/// without any decrypt, which is what makes (2) answerable today; the caller
/// passes them through `claude_account_identifier_hashes_from_observations`.
/// When either half fails the caller falls through to the typed unsupported
/// window rather than rendering another account's numbers.
pub(in crate::agent_status) fn collect_claude_statusline_quota_windows(
    account_identifier_hash: &str,
    observable_account_identifier_hashes: &[String],
) -> Result<ClaudeStatusLineQuota, String> {
    let cache = read_claude_statusline_cache(&default_support_dir())
        .map_err(|_| "Claude Code statusLine cache could not be read safely.".to_string())?;
    let Some(cache) = cache else {
        return Ok(ClaudeStatusLineQuota::NotObserved);
    };
    let now = current_unix_seconds();
    if cache.observed_at_epoch_seconds > now.saturating_add(60)
        || now.saturating_sub(cache.observed_at_epoch_seconds)
            > CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
    {
        return Ok(ClaudeStatusLineQuota::NotObserved);
    }
    if let Some(reason) = claude_statusline_attribution_failure(
        &cache.observed_under_account_identifier_hash,
        &cache.observed_under_account_method,
        account_identifier_hash,
        observable_account_identifier_hashes,
    ) {
        // Refusing to attribute is not an error -- the cache is intact, it just
        // is not ours to serve.
        return Ok(ClaudeStatusLineQuota::Unattributable(reason));
    }

    Ok(ClaudeStatusLineQuota::Windows(
        claude_statusline_quota_windows_from_cache(cache, now),
    ))
}

/// Every Claude account this machine can show us, as billing identity hashes.
/// Anything in here other than the signed-in account is another writer of the
/// shared statusLine cache.
pub(in crate::agent_status) fn claude_account_identifier_hashes_from_observations(
    observations: &[AgentStatusPlanObservation],
) -> Vec<String> {
    observations
        .iter()
        .filter_map(|observation| observation.account_identifier_hash.as_deref())
        .filter(|hash| !hash.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// `None` when the sample provably belongs to the account that owns the local
/// Claude Code credential now, with resolution method taken into account.
///
/// SAFETY INVARIANT: A sample is served ONLY under an account proven for that
/// render. When resolution fails, behavior must be identical to today's fail-closed:
/// unattributable error, typed diagnostic, `unsupported_quota_window("usage")`.
///
/// Resolution method gates the proof requirements:
/// - session_store: Desktop session store proved which account owns this session,
///   so we serve it even when multiple accounts are observable (the whole point
///   of the store join is to break that tie).
/// - config_dir: CLI credential holders' sessions; serve if the stamped hash
///   matches the current credential, even with multiple accounts observable (CLI
///   credential is proof of ownership).
/// - ambiguous: Multiple Desktop store matches that could not be resolved; refuse.
/// - unknown: Unable to resolve; refuse.
/// - v2 cache (no method field): unresolved origin; refuse.
pub(in crate::agent_status) fn claude_statusline_attribution_failure(
    observed_under_account_identifier_hash: &str,
    observed_under_account_method: &str,
    account_identifier_hash: &str,
    _observable_account_identifier_hashes: &[String],
) -> Option<ClaudeStatusLineUnattributable> {
    // Empty hash always means unknown, regardless of method
    if observed_under_account_identifier_hash.is_empty() {
        return Some(ClaudeStatusLineUnattributable::AccountUnknown);
    }
    if account_identifier_hash.is_empty() {
        return Some(ClaudeStatusLineUnattributable::AccountUnknown);
    }

    match observed_under_account_method {
        "session_store" => {
            // Desktop session store proved which account owns this session.
            // Serve it, even if multiple accounts are observable.
            // The store join is itself the proof.
            None
        }
        "config_dir" => {
            // CLI credential: only serve if the stamped hash matches the current holder.
            if observed_under_account_identifier_hash == account_identifier_hash {
                None
            } else {
                Some(ClaudeStatusLineUnattributable::CredentialReplaced)
            }
        }
        "ambiguous" => {
            // Multiple Desktop store matches; cannot resolve.
            Some(ClaudeStatusLineUnattributable::MultipleAccounts)
        }
        _ => {
            // "unknown" or missing/empty method (v2 cache) -> unresolved
            Some(ClaudeStatusLineUnattributable::AccountUnknown)
        }
    }
}

pub(in crate::agent_status) fn collect_claude_statusline_context_status(
) -> Result<AgentContextStatus, String> {
    let support_dir = default_support_dir();
    let cache = read_claude_statusline_context_cache(&support_dir).map_err(|_| {
        "Claude Code statusLine context cache could not be read safely.".to_string()
    })?;
    let history = read_claude_statusline_context_history(&support_dir)
        .ok()
        .flatten();
    let Some(cache) = cache else {
        return Ok(claude_statusline_context_unavailable(
            "statusline_context_not_observed",
            None,
        ));
    };
    let now = current_unix_seconds();
    let observed_at = rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds);
    if cache.observed_at_epoch_seconds > now.saturating_add(60)
        || now.saturating_sub(cache.observed_at_epoch_seconds)
            > CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
    {
        return Ok(claude_statusline_context_unavailable(
            "statusline_context_cache_stale",
            observed_at,
        ));
    }

    Ok(claude_statusline_context_from_cache(cache, history))
}

pub(in crate::agent_status) fn claude_statusline_quota_windows_from_cache(
    cache: ClaudeStatusLineRateLimitCache,
    now: u64,
) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
    let cache_is_stale = cache_age > CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS;
    let observed_at = rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds);
    // The v2 cache records which account's credential was active when the CLI
    // writer observed these numbers, and the serve gate above only lets a
    // same-account cache through -- so the stamp is the writer's observation,
    // not a serve-time guess. An empty hash (unidentifiable writer) stays
    // absent rather than inventing an identity.
    let account_identifier_hash = (!cache.observed_under_account_identifier_hash.is_empty())
        .then(|| cache.observed_under_account_identifier_hash.clone());
    for window in cache.windows {
        if window.resets_at_epoch_seconds <= now {
            continue;
        }
        let Some(resets_at) = rfc3339_from_unix_seconds(window.resets_at_epoch_seconds) else {
            continue;
        };
        let (name, window_seconds) = match window.name.as_str() {
            "five_hour" => ("session", Some(5 * 60 * 60)),
            "seven_day" => ("weekly", Some(7 * 24 * 60 * 60)),
            _ => continue,
        };
        windows.push(AgentQuotaWindow {
            name: name.to_string(),
            scope: AgentQuotaWindowScope::Account,
            status: if cache_is_stale {
                AgentQuotaWindowStatus::Stale
            } else {
                percent_quota_status(window.used_percent)
            },
            freshness: if cache_is_stale {
                AgentQuotaWindowFreshness::Stale
            } else {
                AgentQuotaWindowFreshness::Fresh
            },
            observed_at: observed_at.clone(),
            model: None,
            account_label: None,
            account_identifier_hash: account_identifier_hash.clone(),
            organization_identifier_hash: cache.observed_under_organization_identifier_hash.clone(),
            window_seconds,
            started_at: None,
            resets_at: Some(resets_at),
            quota: None,
            remaining: None,
            used_percent: Some(window.used_percent),
            left_percent: Some(100u8.saturating_sub(window.used_percent)),
            ..Default::default()
        });
    }
    windows
}

/// OAuth usage resets carry microseconds; statusLine resets are whole epoch
/// seconds from response headers. Two resets within this tolerance name the
/// same window; distinct Claude windows are hours apart.
pub(in crate::agent_status) const CLAUDE_STATUSLINE_RESET_MATCH_TOLERANCE_SECONDS: i64 = 1;

pub(in crate::agent_status) fn claude_statusline_same_instant(
    left: OffsetDateTime,
    right: OffsetDateTime,
) -> bool {
    (left - right).abs() <= TimeDuration::seconds(CLAUDE_STATUSLINE_RESET_MATCH_TOLERANCE_SECONDS)
}

/// Replace only a percentage-only meter whose clocks, exact binding and reset
/// prove the statusLine reading newer. Money-bearing readings remain intact;
/// unreported OAuth meters remain in the original vector.
pub(in crate::agent_status) fn prefer_newer_exact_claude_statusline_windows(
    oauth_windows: &mut [AgentQuotaWindow],
    statusline_windows: Vec<AgentQuotaWindow>,
) -> bool {
    let mut replaced = false;
    for newer in statusline_windows {
        if newer.used_percent.is_none() && newer.left_percent.is_none() {
            continue;
        }
        let Some(account) = newer
            .account_identifier_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())
        else {
            continue;
        };
        let Some(organization) = newer
            .organization_identifier_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())
        else {
            continue;
        };
        let Some(new_time) = newer
            .observed_at
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        else {
            continue;
        };
        if new_time.unix_timestamp() > current_unix_seconds() as i64 + 60 {
            continue;
        }
        for older in oauth_windows.iter_mut() {
            if older.account_identifier_hash.as_deref() != Some(account)
                || older.organization_identifier_hash.as_deref() != Some(organization)
                || older.name != newer.name
                || older.scope != newer.scope
                || older.window_seconds != newer.window_seconds
                || older.model != newer.model
                || older.group != newer.group
                || older.limit_id != newer.limit_id
            {
                continue;
            }
            // A statusLine percentage cannot represent independently dated
            // OAuth dollars/totals. Retain the whole reading rather than erase
            // coverage or copy old monetary evidence onto a newer clock.
            if older.limit_cents.is_some()
                || older.used_cents.is_some()
                || older.remaining_cents.is_some()
                || older.quota.is_some()
                || older.remaining.is_some()
            {
                continue;
            }
            let Some(old_reset) = older
                .resets_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            else {
                continue;
            };
            let Some(new_reset) = newer
                .resets_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            else {
                continue;
            };
            // Preserve same-reset tolerance. A later cycle wins only after the
            // old one ended, with a nominal start containing the new reading.
            // All account/org/meter and money gates above still apply.
            let same_cycle = claude_statusline_same_instant(old_reset, new_reset);
            let rolled_over = !same_cycle
                && new_reset > old_reset
                && old_reset <= new_time
                && newer
                    .window_seconds
                    .and_then(|seconds| i64::try_from(seconds).ok())
                    .filter(|seconds| *seconds > 0)
                    .is_some_and(|seconds| new_reset - TimeDuration::seconds(seconds) <= new_time);
            if (!same_cycle && !rolled_over) || new_reset <= new_time {
                continue;
            }
            // A start is a period boundary, not a reading clock. It can survive
            // only when the same verified reset/duration derives that boundary.
            if let Some(start) = older.started_at.as_deref().filter(|_| same_cycle) {
                let start = OffsetDateTime::parse(start, &Rfc3339).ok();
                let derived = newer
                    .window_seconds
                    .and_then(|seconds| i64::try_from(seconds).ok())
                    .map(|seconds| new_reset - TimeDuration::seconds(seconds));
                match (start, derived) {
                    (Some(start), Some(derived))
                        if claude_statusline_same_instant(start, derived) => {}
                    _ => continue,
                }
            }
            let Some(old_time) = older
                .observed_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            else {
                continue;
            };
            if new_time > old_time {
                let mut selected = newer.clone();
                if same_cycle {
                    selected.started_at = older.started_at.clone().or(selected.started_at);
                    selected.started_at_basis =
                        older.started_at_basis.clone().or(selected.started_at_basis);
                } else {
                    selected.started_at = newer.window_seconds.and_then(|seconds| {
                        rfc3339_minus_seconds(newer.resets_at.as_deref()?, seconds)
                    });
                    selected.started_at_basis = selected
                        .started_at
                        .as_ref()
                        .map(|_| "assumed_duration".to_string());
                }
                *older = selected;
                replaced = true;
            }
        }
    }
    replaced
}

pub(in crate::agent_status) fn claude_statusline_context_from_cache(
    cache: ClaudeStatusLineContextWindowCache,
    history: Option<ClaudeStatusLineContextWindowHistory>,
) -> AgentContextStatus {
    let zero_sentinel = claude_statusline_context_is_zero_sentinel(
        cache.active_tokens,
        cache.max_tokens,
        cache.used_percent,
        cache.remaining_tokens,
    );
    let active_tokens = if zero_sentinel {
        None
    } else {
        cache.active_tokens
    };
    let remaining_tokens = if zero_sentinel {
        None
    } else {
        cache.remaining_tokens
    };
    let has_pressure =
        active_tokens.is_some() || cache.used_percent.is_some() || remaining_tokens.is_some();
    let (status, completeness, reason) = if has_pressure {
        (
            AgentContextState::Available,
            AgentContextCompleteness::FullPressure,
            "full_pressure_observed",
        )
    } else if cache.max_tokens.is_some() {
        (
            AgentContextState::Available,
            AgentContextCompleteness::WindowSizeOnly,
            "context_window_size_only",
        )
    } else {
        (
            AgentContextState::Unsupported,
            AgentContextCompleteness::Unavailable,
            "statusline_context_empty",
        )
    };
    AgentContextStatus {
        status,
        active_tokens,
        max_tokens: cache.max_tokens,
        used_percent: cache.used_percent,
        remaining_tokens,
        source: Some("claude_statusline_context_window".to_string()),
        recent_samples: claude_statusline_recent_context_samples(&cache, history),
        observed_at: rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds),
        completeness: Some(completeness),
        reason: Some(reason.to_string()),
        posture: None,
    }
}

pub(in crate::agent_status) fn claude_statusline_recent_context_samples(
    cache: &ClaudeStatusLineContextWindowCache,
    history: Option<ClaudeStatusLineContextWindowHistory>,
) -> Vec<AgentContextPressureSample> {
    let now = current_unix_seconds();
    let mut samples = history.map(|history| history.samples).unwrap_or_default();
    samples.push(ClaudeStatusLineContextWindowSample {
        observed_at_epoch_seconds: cache.observed_at_epoch_seconds,
        active_tokens: cache.active_tokens,
        max_tokens: cache.max_tokens,
        used_percent: cache.used_percent,
        remaining_tokens: cache.remaining_tokens,
    });
    samples.retain(|sample| {
        sample.observed_at_epoch_seconds <= now.saturating_add(60)
            && now.saturating_sub(sample.observed_at_epoch_seconds)
                <= CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
            && !claude_statusline_context_is_zero_sentinel(
                sample.active_tokens,
                sample.max_tokens,
                sample.used_percent,
                sample.remaining_tokens,
            )
            && (sample.active_tokens.is_some()
                || sample.used_percent.is_some()
                || sample.remaining_tokens.is_some())
    });
    samples.sort_by_key(|sample| sample.observed_at_epoch_seconds);
    samples.dedup_by_key(|sample| sample.observed_at_epoch_seconds);
    if samples.len() > CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES {
        let remove_count = samples.len() - CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES;
        samples.drain(0..remove_count);
    }
    samples
        .into_iter()
        .filter_map(|sample| {
            Some(AgentContextPressureSample {
                at: rfc3339_from_unix_seconds(sample.observed_at_epoch_seconds)?,
                active_tokens: sample.active_tokens,
                max_tokens: sample.max_tokens,
                used_percent: sample.used_percent,
                remaining_tokens: sample.remaining_tokens,
            })
        })
        .collect()
}

pub(in crate::agent_status) fn claude_statusline_context_is_zero_sentinel(
    active_tokens: Option<u64>,
    max_tokens: Option<u64>,
    used_percent: Option<u8>,
    remaining_tokens: Option<u64>,
) -> bool {
    let remaining_is_unreported = match (max_tokens, remaining_tokens) {
        (Some(_), None) => true,
        (Some(max), Some(remaining)) => remaining == max,
        _ => false,
    };
    used_percent.is_none() && matches!(active_tokens, None | Some(0)) && remaining_is_unreported
}

pub(in crate::agent_status) fn claude_statusline_context_unavailable(
    reason: &str,
    observed_at: Option<String>,
) -> AgentContextStatus {
    unsupported_context("claude_statusline_context_window", reason, observed_at)
}
