//! Claude status oauth usage operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::claude_background_read_withheld;
use crate::agent_status::claude_credit_pools;
use crate::agent_status::claude_explicit_refresh_request;
use crate::agent_status::claude_explicit_refresh_requested;
use crate::agent_status::claude_oauth_activity;
use crate::agent_status::claude_oauth_binding_key;
use crate::agent_status::claude_oauth_pass_reached_collector;
use crate::agent_status::claude_oauth_passive_config;
use crate::agent_status::claude_oauth_retry_after_epoch_seconds;
use crate::agent_status::claude_oauth_usage_account_state_dir;
use crate::agent_status::claude_oauth_usage_breaker_is_open;
use crate::agent_status::claude_oauth_usage_caller_auth_hold;
use crate::agent_status::claude_oauth_usage_caller_auth_hold_diagnostic;
use crate::agent_status::claude_oauth_usage_circuit_open_diagnostic;
use crate::agent_status::claude_oauth_usage_config_fingerprint;
use crate::agent_status::claude_oauth_usage_error;
use crate::agent_status::claude_oauth_usage_failure_class;
use crate::agent_status::claude_oauth_usage_fresh_age_seconds;
use crate::agent_status::claude_oauth_usage_from_cache;
use crate::agent_status::claude_oauth_usage_network_disabled;
use crate::agent_status::claude_oauth_usage_record_reading;
use crate::agent_status::claude_oauth_usage_slot_seconds;
use crate::agent_status::claude_pass_saved_only;
use crate::agent_status::claude_quota_check_diagnostic;
use crate::agent_status::claude_rate_limit_held;
use crate::agent_status::claude_rate_limit_holds;
use crate::agent_status::claude_statusline_fresh_for_binding;
use crate::agent_status::claude_transient_failure_held;
use crate::agent_status::claude_transient_failures;
use crate::agent_status::clear_claude_oauth_usage_breaker_after_success;
use crate::agent_status::credit_amount_input;
use crate::agent_status::current_unix_seconds;
use crate::agent_status::note_claude_explicit_refresh_attempt;
use crate::agent_status::ottto_user_agent;
use crate::agent_status::read_claude_oauth_usage_breaker;
use crate::agent_status::read_claude_oauth_usage_cache_with_legacy_migration;
use crate::agent_status::record_claude_oauth_usage_auth_failure;
use crate::agent_status::record_claude_oauth_usage_failure;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::set_claude_binding_time;
use crate::agent_status::try_claude_oauth_collection_attempt;
use crate::agent_status::write_claude_oauth_usage_cache;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::ClaudeOAuthReading;
use crate::agent_status::ClaudeOAuthUsage;
use crate::agent_status::ClaudeOAuthUsageCache;
use crate::agent_status::ClaudeOAuthUsageCaller;
use crate::agent_status::ClaudeOAuthUsageFailure;
use crate::agent_status::ClaudeOAuthUsageOutcome;
use crate::agent_status::Instant;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Rfc3339;
#[cfg(test)]
use crate::agent_status::Value;
use crate::agent_status::CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS;
use crate::agent_status::CLAUDE_BACKGROUND_REFRESH_OFF_MESSAGE;
use crate::agent_status::CLAUDE_CACHE_REUSED_MESSAGE;
#[cfg(test)]
use crate::agent_status::CLAUDE_OAUTH_BEFORE_SEND_HOOK;
use crate::agent_status::CLAUDE_OAUTH_BETA_HEADER;
use crate::agent_status::CLAUDE_OAUTH_CALLER_BINDINGS;
#[cfg(test)]
use crate::agent_status::CLAUDE_OAUTH_PROVIDER_CALLS;
#[cfg(test)]
use crate::agent_status::CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN;
#[cfg(test)]
use crate::agent_status::CLAUDE_OAUTH_TEST_RESPONSE;
use crate::agent_status::CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS;
use crate::agent_status::CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION;
use crate::agent_status::CLAUDE_OAUTH_USAGE_ENDPOINT;
use crate::agent_status::CLAUDE_OAUTH_USAGE_REFRESH_SECONDS;
#[cfg(test)]
use crate::agent_status::CLAUDE_SLOT_AFTER_PRE_GATE_HOOK;
use crate::agent_status::COMMAND_TIMEOUT;

#[cfg(test)]
pub(in crate::agent_status) fn collect_claude_oauth_usage_with_access_token(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    access_token: Option<String>,
    caller: &ClaudeOAuthUsageCaller,
) -> ClaudeOAuthUsageOutcome {
    collect_claude_oauth_usage_with_credential(
        account_identifier_hash,
        organization_identifier_hash,
        access_token,
        None,
        caller,
        current_unix_seconds,
    )
}

/// `credential_expires_at` is the access-token expiry metadata of the same
/// credential, used only to notice rotation; it is never the token. `clock`
/// is the wall clock (`current_unix_seconds`) outside fixed-instant tests.
pub(in crate::agent_status) fn collect_claude_oauth_usage_with_credential(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    access_token: Option<String>,
    credential_expires_at: Option<String>,
    caller: &ClaudeOAuthUsageCaller,
    clock: fn() -> u64,
) -> ClaudeOAuthUsageOutcome {
    let mut outcome = collect_claude_oauth_usage_unstamped(
        account_identifier_hash,
        organization_identifier_hash,
        access_token,
        credential_expires_at.as_deref(),
        caller,
        clock,
    );
    if let Ok(usage) = &mut outcome.result {
        claude_oauth_stamp_account_identity(
            usage,
            account_identifier_hash,
            Some(organization_identifier_hash),
        );
    }
    for diagnostic in &mut outcome.diagnostics {
        diagnostic.account_identifier_hash = Some(account_identifier_hash.to_string());
        diagnostic.organization_identifier_hash = Some(organization_identifier_hash.to_string());
    }
    outcome
}

pub(in crate::agent_status) fn claude_oauth_stamp_account_identity(
    usage: &mut ClaudeOAuthUsage,
    account_identifier_hash: &str,
    organization_identifier_hash: Option<&str>,
) {
    let account =
        (!account_identifier_hash.is_empty()).then(|| account_identifier_hash.to_string());
    let organization = organization_identifier_hash
        .filter(|hash| !hash.is_empty())
        .map(ToString::to_string);
    for window in &mut usage.windows {
        window.account_identifier_hash = account.clone();
        window.organization_identifier_hash = organization.clone();
    }
    for balance in &mut usage.credit_balances {
        balance.account_identifier_hash = account.clone();
        balance.organization_identifier_hash = organization.clone();
    }
}

/// Whether an access deadline (RFC 3339) is at or within the expiry margin
/// of `now` (unix seconds). An absent or unparseable deadline is not
/// "expired" here; the local login state already failed those closed.
pub(in crate::agent_status) fn claude_access_token_locally_expired(
    credential_expires_at: Option<&str>,
    now: u64,
) -> bool {
    credential_expires_at
        .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
        .is_some_and(|expiry| {
            let now = i64::try_from(now).unwrap_or(i64::MAX);
            expiry.unix_timestamp() <= now.saturating_add(CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS)
        })
}

pub(in crate::agent_status) fn collect_claude_oauth_usage_unstamped(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    access_token: Option<String>,
    credential_expires_at: Option<&str>,
    caller: &ClaudeOAuthUsageCaller,
    clock: fn() -> u64,
) -> ClaudeOAuthUsageOutcome {
    let now = clock();
    let legacy_root_migration = caller.legacy_root_migration();
    // Every pass is evidence of where this caller's login is signed in; a
    // passive reading must have been fetched inside that continuous run.
    claude_oauth_pass_reached_collector(caller);
    let caller_bound_since = claude_credit_pools::claude_observe_caller_binding(
        &mut CLAUDE_OAUTH_CALLER_BINDINGS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        &caller.breaker_key(),
        &claude_oauth_binding_key(account_identifier_hash, organization_identifier_hash),
        now,
    );

    // Off-switch first, ahead of the cache. Existing account-scoped cache files
    // are retained and continue aging honestly; no endpoint data is served and
    // the network resumes without destroying the last known local evidence.
    if claude_oauth_usage_network_disabled() {
        return ClaudeOAuthUsageOutcome {
            result: Err(
                "Claude OAuth usage endpoint is switched off on this machine.".to_string(),
            ),
            diagnostics: vec![AgentStatusDiagnostic::source(
                "claude_oauth_usage_network_disabled",
                AgentDiagnosticSeverity::Info,
                "Claude subscription quota is read from Claude Code's local statusLine only: the Claude OAuth usage network read is switched off on this machine.",
            )],
        };
    }

    // A registered managed slot owns this exact account and proved last pass
    // that it reads it. Its credential is the one provider caller; the default
    // login only serves the shared per-account cache that slot keeps current.
    if !caller.may_call_provider() {
        let deferred = AgentStatusDiagnostic::source(
            "claude_oauth_usage_deferred_to_registered_slot",
            AgentDiagnosticSeverity::Info,
            "This Claude account's quota is read through its registered account slot; the default Claude Code login made no provider request.",
        );
        let cache = read_claude_oauth_usage_cache_with_legacy_migration(
            account_identifier_hash,
            organization_identifier_hash,
            legacy_root_migration,
        );
        if let Some(cache) = cache.filter(|cache| {
            !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
        }) {
            return ClaudeOAuthUsageOutcome {
                result: Ok(claude_oauth_usage_from_cache(cache, now)),
                diagnostics: vec![deferred],
            }
            .with_check_outcome(
                "claude_oauth_usage_cache_reused",
                "A locally cached quota reading kept by the registered account slot was reused; no provider check was made.",
                now,
            );
        }
        return ClaudeOAuthUsageOutcome {
            result: Err(
                "Claude OAuth usage for this account is read by its registered account slot."
                    .to_string(),
            ),
            diagnostics: vec![deferred],
        };
    }

    let Some(_collection_attempt) =
        try_claude_oauth_collection_attempt(account_identifier_hash, organization_identifier_hash)
    else {
        if let Some(cache) = read_claude_oauth_usage_cache_with_legacy_migration(
            account_identifier_hash,
            organization_identifier_hash,
            legacy_root_migration,
        )
        .filter(|cache| {
            !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
        }) {
            return ClaudeOAuthUsageOutcome::from(Ok(claude_oauth_usage_from_cache(cache, now)))
                .with_check_outcome("claude_oauth_usage_cache_reused", "A locally cached quota reading was reused while collection is in progress; no duplicate provider check was made.", now);
        }
        return ClaudeOAuthUsageOutcome {
            result: Err("Claude usage collection is already in progress for this account.".to_string()),
            diagnostics: vec![AgentStatusDiagnostic::source(
                "claude_oauth_usage_collection_in_progress",
                AgentDiagnosticSeverity::Info,
                "Another daemon task is already reading this exact Claude account; no duplicate provider request was started.",
            )],
        };
    };

    let config_fingerprint = claude_oauth_usage_config_fingerprint();
    let breaker = read_claude_oauth_usage_breaker(
        account_identifier_hash,
        organization_identifier_hash,
        &config_fingerprint,
    );
    let caller_auth_hold = breaker
        .as_ref()
        .and_then(|breaker| {
            claude_oauth_usage_caller_auth_hold(breaker, caller, now, credential_expires_at)
        })
        .cloned();
    // The future cache gate alone also covers ordinary refresh. Require the
    // matching-account rate-limit receipt and no competing auth/circuit hold
    // before naming a Retry-After reason. This changes disclosure only.
    let rate_limit_retry_evidenced = breaker.as_ref().is_some_and(|breaker| {
        breaker.rate_limit_failures > 0
            && breaker.auth_failures == 0
            && !claude_oauth_usage_breaker_is_open(breaker, now)
    }) && caller_auth_hold.is_none()
        && access_token.is_some()
        && !claude_access_token_locally_expired(credential_expires_at, now);
    let breaker_rate_limited = breaker
        .as_ref()
        .is_some_and(|breaker| breaker.rate_limit_failures > 0);
    let open_breaker = breaker.filter(|breaker| claude_oauth_usage_breaker_is_open(breaker, now));

    // Read cadence: one read per binding per slot. The
    // slot follows the account's recent activity; due slots alternate the
    // plain and saved-reset reads.
    let account_state_dir =
        claude_oauth_usage_account_state_dir(account_identifier_hash, organization_identifier_hash);
    let mut read_schedule = claude_credit_pools::read_claude_read_schedule(&account_state_dir);
    let (latest_activity_at, feed_fresh_at) =
        claude_oauth_activity(account_identifier_hash, organization_identifier_hash);
    // The scan lists a session only while its activity advances: keep every
    // sighting, even when this pass serves the stored reading.
    if read_schedule.observe_activity(latest_activity_at) {
        let _ = claude_credit_pools::write_claude_read_schedule(&account_state_dir, &read_schedule);
    }
    let mut slot_seconds = claude_oauth_usage_slot_seconds(
        &read_schedule,
        latest_activity_at,
        feed_fresh_at,
        account_identifier_hash,
        organization_identifier_hash,
        now,
    );
    // In use: Claude Code's own statusLine is the free source. While it is
    // fresh for exactly this binding, the provider is read only at the
    // unused-account gate (for the meters the statusLine does not carry);
    // the collection prefers the newer statusLine windows when it serves.
    // Only the default login's collection merges the statusLine.
    if slot_seconds == claude_credit_pools::ACTIVE_SLOT_SECONDS
        && matches!(caller, ClaudeOAuthUsageCaller::Default)
        && claude_statusline_fresh_for_binding(
            account_identifier_hash,
            organization_identifier_hash,
            now,
        )
    {
        slot_seconds = claude_oauth_usage_fresh_age_seconds(
            account_identifier_hash,
            organization_identifier_hash,
        );
    }
    let mut last_reading_at = None;
    let mut previous_credit_balances = Vec::new();

    // A saved-reset reading that was not usable (or had no windows) moved
    // this binding's next read to its next slot.
    let held = claude_credit_pools::claude_read_held(&mut read_schedule, slot_seconds, now);
    if held.cleared {
        let _ = claude_credit_pools::write_claude_read_schedule(&account_state_dir, &read_schedule);
    }

    let mut exact_stale_fallback = None;
    let mut explicit_refresh_due = false;
    if let Some(cache) = read_claude_oauth_usage_cache_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        legacy_root_migration,
    ) {
        // The last stored reading: its sections are re-sent by a read that
        // does not carry them.
        previous_credit_balances = cache.credit_balances.clone();
        if !cache.windows.is_empty() {
            last_reading_at = Some(cache.observed_at_epoch_seconds);
        }
        let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
        // An explicit refresh reads now, past the slot and the plain spacing
        // after a successful read, but never inside a Retry-After hold: the
        // spacing must be exactly the success floor and no rate limit may be
        // on record, in the breaker or in this run's own 429 record. Every
        // later hold and breaker check still applies.
        explicit_refresh_due = claude_explicit_refresh_requested(
            account_identifier_hash,
            organization_identifier_hash,
            cache.observed_at_epoch_seconds,
            now,
        ) && (now >= cache.next_refresh_after_epoch_seconds
            || (!breaker_rate_limited
                && !claude_rate_limit_held(
                    account_identifier_hash,
                    organization_identifier_hash,
                    now,
                )
                && cache.next_refresh_after_epoch_seconds
                    <= cache
                        .observed_at_epoch_seconds
                        .saturating_add(CLAUDE_OAUTH_USAGE_REFRESH_SECONDS)));
        if explicit_refresh_due {
            note_claude_explicit_refresh_attempt(
                account_identifier_hash,
                organization_identifier_hash,
                now,
            );
        }
        // A window that reset after this reading gets one read shortly after
        // the reset instead of waiting out the slot.
        let reset_read_due = claude_credit_pools::claude_reset_read_due(
            &cache.windows,
            cache.observed_at_epoch_seconds,
            cache.next_refresh_after_epoch_seconds,
            claude_credit_pools::claude_reset_read_delay_seconds(
                account_identifier_hash,
                organization_identifier_hash,
            ),
            now,
        );
        if !cache.windows.is_empty()
            && cache_age <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            && !reset_read_due
            && !explicit_refresh_due
            && !claude_credit_pools::claude_reading_due(
                Some(cache.observed_at_epoch_seconds),
                cache.next_refresh_after_epoch_seconds,
                slot_seconds,
                now,
            )
        {
            let retry_after = (rate_limit_retry_evidenced
                && claude_credit_pools::claude_slot_elapsed(cache_age, slot_seconds)
                && now < cache.next_refresh_after_epoch_seconds)
                .then(|| rfc3339_from_unix_seconds(cache.next_refresh_after_epoch_seconds))
                .flatten();
            let mut outcome =
                ClaudeOAuthUsageOutcome::from(Ok(claude_oauth_usage_from_cache(cache, now)))
                    .with_check_outcome(
                        "claude_oauth_usage_cache_reused",
                        CLAUDE_CACHE_REUSED_MESSAGE,
                        now,
                    );
            if let Some(diagnostic) = outcome.diagnostics.last_mut() {
                diagnostic.retry_after = retry_after;
            }
            return outcome;
        }
        if now < cache.next_refresh_after_epoch_seconds && !explicit_refresh_due {
            // A stored reading without windows under the hold: the saved-reset
            // section of a windowless variant read, served for this slot.
            if held.active && cache.windows.is_empty() {
                return claude_oauth_read_held_outcome(
                    Ok(claude_oauth_usage_from_cache(cache, now)),
                    now,
                );
            }
            return ClaudeOAuthUsageOutcome::from(Err(
                "Claude OAuth usage endpoint is rate limited.".to_string(),
            ));
        }
        if !cache.windows.is_empty() && cache_age <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS {
            exact_stale_fallback = Some(cache);
        }
    } else if claude_explicit_refresh_requested(
        account_identifier_hash,
        organization_identifier_hash,
        0,
        now,
    ) {
        // Nothing stored yet: an explicit refresh may read it now.
        explicit_refresh_due = true;
        note_claude_explicit_refresh_attempt(
            account_identifier_hash,
            organization_identifier_hash,
            now,
        );
    }

    // The hold applies even without a stored reading to serve; a servable
    // stale reading is served.
    if held.active {
        return claude_oauth_read_held_outcome(
            match exact_stale_fallback {
                Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
                None => {
                    Err("Claude usage for this account is read again at its next slot.".to_string())
                }
            },
            now,
        );
    }

    // Passive input (active-account freshness): Claude Code's own
    // plain reading for exactly this binding, newer than ours and inside the
    // slot, stands in for a plain slot's call. Parsed by the same plain-body
    // parser; no provider request.

    // The slot's read is chosen first (same endpoint, same slot: the
    // saved-reset variant replaces the plain read in its slot, never adds a
    // call). A passive body can only stand in for a plain slot, so it never
    // displaces a saved-reset slot.
    let usage_read =
        claude_credit_pools::claude_usage_read_kind(&read_schedule, &previous_credit_balances, now);
    let passive_config = if usage_read == claude_credit_pools::ClaudeUsageRead::Plain {
        claude_oauth_passive_config(
            caller,
            account_identifier_hash,
            organization_identifier_hash,
        )
    } else {
        claude_credit_pools::ClaudePassiveConfig::default()
    };
    if let Some(passive) = passive_config.reading.filter(|passive| {
        claude_credit_pools::claude_passive_reading_usable(
            passive.fetched_at,
            last_reading_at,
            Some(caller_bound_since),
            slot_seconds,
            now,
        )
    }) {
        if let Ok(usage) = claude_oauth_usage_record_reading(
            ClaudeOAuthReading {
                account_identifier_hash,
                organization_identifier_hash,
                body: &passive.body,
                read: claude_credit_pools::ClaudeUsageRead::Plain,
                observed_at_epoch_seconds: passive.fetched_at,
                previous_credit_balances: &previous_credit_balances,
                latest_activity_at,
                now,
                legacy_root_migration,
            },
            &mut read_schedule,
        ) {
            return ClaudeOAuthUsageOutcome::from(Ok(usage)).with_check_outcome(
                "claude_oauth_usage_cache_reused",
                "A newer local quota reading that Claude Code made for this exact account was reused; no provider request was made.",
                now,
            );
        }
    }

    let Some(token) = access_token else {
        if let Some(cache) = exact_stale_fallback {
            return ClaudeOAuthUsageOutcome {
                result: Ok(claude_oauth_usage_from_cache(cache, now)),
                diagnostics: open_breaker
                    .as_ref()
                    .map(|breaker| claude_oauth_usage_circuit_open_diagnostic(breaker, now))
                    .into_iter()
                    .collect(),
            }
            .with_check_outcome(
                "claude_oauth_usage_cache_reused",
                "A prior local quota reading was reused; no provider request was made.",
                now,
            );
        }
        if let Some(breaker) = open_breaker {
            return ClaudeOAuthUsageOutcome {
                result: Err("Claude OAuth usage endpoint is not being called.".to_string()),
                diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
            }
            .with_check_outcome(
                "claude_oauth_usage_check_suppressed",
                "The local quota breaker suppressed this provider request.",
                now,
            );
        }
        return ClaudeOAuthUsageOutcome::from(Err(
            "Claude OAuth credentials were not available locally.".to_string(),
        ));
    };
    // Never send an access token that is expired by the local clock: the
    // request could only be rejected (adding a per-caller hold), and only
    // Claude Code itself may refresh the login. The daemon never uses the
    // refresh token.
    // A fresh clock sample: cache, breaker and lock reads above can block, and
    // the Mac can sleep, after `now` was taken.
    if claude_access_token_locally_expired(credential_expires_at, clock()) {
        drop(token);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "Claude Code has not refreshed this login since its access token expired."
                    .to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome {
            result,
            diagnostics: Vec::new(),
        }
        .with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "This Claude login's access token has expired locally and Claude Code has not refreshed it yet; no provider request was made, and any served readings are last-known local readings.",
            now,
        );
    }
    if let Some(breaker) = open_breaker {
        if let Some(cache) = exact_stale_fallback {
            return ClaudeOAuthUsageOutcome {
                result: Ok(claude_oauth_usage_from_cache(cache, now)),
                diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
            }.with_check_outcome("claude_oauth_usage_check_suppressed", "The local quota breaker suppressed this provider request; last-known local readings were reused.", now);
        }
        return ClaudeOAuthUsageOutcome {
            result: Err("Claude OAuth usage endpoint is not being called.".to_string()),
            diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
        }
        .with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "The local quota breaker suppressed this provider request.",
            now,
        );
    }
    // This caller's own credential was rejected recently. Hold only this
    // caller; another credential for the same account is unaffected.
    if let Some(hold) = caller_auth_hold {
        let held = claude_oauth_usage_caller_auth_hold_diagnostic(caller, &hold, now);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "Claude OAuth usage is backing off after this credential was rejected.".to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome {
            result,
            diagnostics: vec![held],
        }
        .with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "The local quota breaker suppressed this provider request after this credential was rejected.",
            now,
        );
    }
    #[cfg(test)]
    if let Some(hook) = *CLAUDE_OAUTH_BEFORE_SEND_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        hook();
    }
    // Last check, with a clock read immediately before the request.
    if claude_access_token_locally_expired(credential_expires_at, clock()) {
        drop(token);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "Claude Code has not refreshed this login since its access token expired."
                    .to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome {
            result,
            diagnostics: Vec::new(),
        }
        .with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "This Claude login's access token has expired locally and Claude Code has not refreshed it yet; no provider request was made, and any served readings are last-known local readings.",
            clock(),
        );
    }
    if claude_transient_failure_held(account_identifier_hash, organization_identifier_hash, now) {
        let result = match read_claude_oauth_usage_cache_with_legacy_migration(
            account_identifier_hash,
            organization_identifier_hash,
            legacy_root_migration,
        )
        .filter(|cache| {
            !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
        }) {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "The latest Claude OAuth quota request failed; it is retried after a minute."
                    .to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "The latest Claude OAuth quota request failed moments ago; no provider request was made, and any served readings are last-known local readings.",
            clock(),
        );
    }
    // "Background limit refresh" off: the daemon's own passes read no
    // account, the default login included. Only an explicit refresh and setup
    // checks call the provider; stored readings are served and age as usual.
    if !explicit_refresh_due && claude_background_read_withheld() {
        drop(token);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(CLAUDE_BACKGROUND_REFRESH_OFF_MESSAGE.to_string()),
        };
        return ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "Background limit refresh is off: no provider request was made, and any served readings are last-known local readings.",
            now,
        );
    }
    // A status read for the app serves the stored reading: only the daemon's
    // own passes, an explicit refresh and setup checks call the provider. The
    // daemon's next pass reads a due account.
    if claude_pass_saved_only() && !explicit_refresh_due {
        drop(token);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "Claude quota for this account has no stored reading yet; the daemon reads it shortly."
                    .to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
            "claude_oauth_usage_cache_reused",
            "A status read served the stored quota reading; the daemon's own schedule makes the provider requests.",
            now,
        );
    }
    let authorization = format!("Bearer {token}");
    let user_agent = ottto_user_agent();
    // Same endpoint, same slot: the saved-reset variant replaces the plain
    // read in its slot, never adds a call.
    let endpoint = format!("{CLAUDE_OAUTH_USAGE_ENDPOINT}{}", usage_read.query());
    #[cfg(test)]
    CLAUDE_OAUTH_PROVIDER_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    #[cfg(test)]
    if CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN.load(std::sync::atomic::Ordering::SeqCst) {
        return ClaudeOAuthUsageOutcome::from(Err(
            "This test forbids Claude OAuth provider requests.".to_string(),
        ));
    }
    // A test response stands in for the provider's response text.
    #[cfg(test)]
    let injected = CLAUDE_OAUTH_TEST_RESPONSE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .map(|respond| respond(&endpoint).map(|body| body.to_string()));
    #[cfg(not(test))]
    let injected: Option<Result<String, u16>> = None;
    let call_started = Instant::now();
    let record_call = |result: crate::provider_calls::CallResult| {
        use crate::provider_calls::{CallKind, Provider, ProviderCall, Trigger};
        let trigger = if explicit_refresh_due {
            claude_explicit_refresh_request().trigger
        } else {
            crate::provider_calls::trigger_or(Trigger::Schedule)
        };
        crate::provider_calls::record(ProviderCall::observed(
            Provider::Anthropic,
            CallKind::ClaudeOauthUsage,
            trigger,
            Some(account_identifier_hash),
            result,
            call_started.elapsed(),
        ));
    };
    let response = match injected {
        Some(Ok(body)) => {
            record_call(crate::provider_calls::CallResult::Ok);
            let value =
                credit_amount_input::decode(&body, credit_amount_input::CreditBody::ClaudeUsage)
                    .unwrap_or_default();
            return claude_oauth_usage_after_response(
                ClaudeOAuthReading {
                    account_identifier_hash,
                    organization_identifier_hash,
                    body: &value,
                    read: usage_read,
                    observed_at_epoch_seconds: clock(),
                    previous_credit_balances: &previous_credit_balances,
                    latest_activity_at,
                    now,
                    legacy_root_migration,
                },
                caller,
                &config_fingerprint,
                slot_seconds,
                &mut read_schedule,
            );
        }
        Some(Err(status)) => match ureq::Response::new(status, "injected", "") {
            Ok(response) => Err(ureq::Error::Status(status, response)),
            Err(error) => Err(error),
        },
        None => crate::retry_tls::agent()
            .get(&endpoint)
            .set("Accept", "application/json")
            .set("Content-Type", "application/json")
            .set("Authorization", &authorization)
            .set("anthropic-beta", CLAUDE_OAUTH_BETA_HEADER)
            .set("User-Agent", &user_agent)
            .timeout(COMMAND_TIMEOUT)
            .call(),
    };
    record_call(crate::provider_calls::http_result(&response));
    let response = match response {
        Ok(response) => response,
        // The provider rejected the saved-reset variant itself (not auth, not
        // a rate limit): variant state, never an endpoint-breaker strike, and
        // never retried on the next pass.
        Err(ureq::Error::Status(status, _))
            if usage_read == claude_credit_pools::ClaudeUsageRead::SavedResets
                && claude_credit_pools::claude_saved_resets_variant_rejected(status) =>
        {
            return claude_oauth_saved_resets_variant_unusable(
                account_identifier_hash,
                organization_identifier_hash,
                legacy_root_migration,
                slot_seconds,
                &mut read_schedule,
                now,
            );
        }
        Err(ureq::Error::Status(429, response)) => {
            let retry_after = claude_oauth_retry_after_epoch_seconds(&response, now);
            set_claude_binding_time(
                &mut claude_rate_limit_holds(),
                account_identifier_hash,
                organization_identifier_hash,
                retry_after,
            );
            // A cache belonging to another account is not merely skipped here:
            // `unwrap_or` replaces it with an empty cache for the current
            // account, so the write below also clears the stale payload off
            // disk instead of leaving it to be reconsidered next tick.
            let mut cache = read_claude_oauth_usage_cache_with_legacy_migration(
                account_identifier_hash,
                organization_identifier_hash,
                legacy_root_migration,
            )
            .unwrap_or(ClaudeOAuthUsageCache {
                schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                account_identifier_hash: account_identifier_hash.to_string(),
                organization_identifier_hash: organization_identifier_hash.to_string(),
                observed_at_epoch_seconds: now,
                next_refresh_after_epoch_seconds: retry_after,
                windows: Vec::new(),
                credit_balances: Vec::new(),
                account_weekly_not_offered: false,
                account_session_not_offered: false,
            });
            cache.next_refresh_after_epoch_seconds = retry_after;
            let _ = write_claude_oauth_usage_cache(&cache);
            // The retry-after backoff above still handles the transient case
            // unchanged; the breaker only fires once 429s outlive it.
            let mut diagnostics = record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::RateLimited,
                account_identifier_hash,
                organization_identifier_hash,
                &config_fingerprint,
                now,
            );
            diagnostics.push(claude_quota_check_diagnostic("claude_oauth_usage_check_failed", "The latest Claude OAuth quota request failed with rate limiting; any served readings remain locally cached evidence.", clock()));
            diagnostics.push(claude_oauth_usage_rate_limited_diagnostic(
                usage_read,
                retry_after,
                now,
            ));
            if !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            {
                return ClaudeOAuthUsageOutcome {
                    result: Ok(claude_oauth_usage_from_cache(cache, now)),
                    diagnostics,
                };
            }
            return ClaudeOAuthUsageOutcome {
                result: Err("Claude OAuth usage endpoint is rate limited.".to_string()),
                diagnostics,
            };
        }
        Err(error) => {
            let mut diagnostics = match claude_oauth_usage_failure_class(&error) {
                Some(ClaudeOAuthUsageFailure::AuthRejected) => {
                    let status = match &error {
                        ureq::Error::Status(status, _) => *status,
                        ureq::Error::Transport(_) => 0,
                    };
                    record_claude_oauth_usage_auth_failure(
                        caller,
                        status,
                        account_identifier_hash,
                        organization_identifier_hash,
                        &config_fingerprint,
                        now,
                        credential_expires_at,
                    )
                }
                Some(failure) => record_claude_oauth_usage_failure(
                    failure,
                    account_identifier_hash,
                    organization_identifier_hash,
                    &config_fingerprint,
                    now,
                ),
                None => {
                    set_claude_binding_time(
                        &mut claude_transient_failures(),
                        account_identifier_hash,
                        organization_identifier_hash,
                        clock(),
                    );
                    Vec::new()
                }
            };
            diagnostics.push(claude_quota_check_diagnostic("claude_oauth_usage_check_failed", "The latest Claude OAuth quota request failed; any served readings remain locally cached evidence.", clock()));
            if let Some(cache) = read_claude_oauth_usage_cache_with_legacy_migration(
                account_identifier_hash,
                organization_identifier_hash,
                legacy_root_migration,
            ) {
                if !cache.windows.is_empty()
                    && now.saturating_sub(cache.observed_at_epoch_seconds)
                        <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
                {
                    return ClaudeOAuthUsageOutcome {
                        result: Ok(claude_oauth_usage_from_cache(cache, now)),
                        diagnostics,
                    };
                }
            }
            return ClaudeOAuthUsageOutcome {
                result: Err(claude_oauth_usage_error(error)),
                diagnostics,
            };
        }
    };
    let Some(value) = response.into_string().ok().and_then(|body| {
        credit_amount_input::decode(&body, credit_amount_input::CreditBody::ClaudeUsage)
    }) else {
        return ClaudeOAuthUsageOutcome {
            result: Err("Claude OAuth usage endpoint returned an unreadable response.".to_string()),
            diagnostics: record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::ResponseShape,
                account_identifier_hash,
                organization_identifier_hash,
                &config_fingerprint,
                now,
            ),
        }
        .with_check_outcome(
            "claude_oauth_usage_check_failed",
            "The latest Claude OAuth response could not be read as quota data.",
            clock(),
        );
    };
    // This is the local successful response time, never a provider-supplied
    // timestamp. Cache reuse preserves it rather than stamping a later upload.
    claude_oauth_usage_after_response(
        ClaudeOAuthReading {
            account_identifier_hash,
            organization_identifier_hash,
            body: &value,
            read: usage_read,
            observed_at_epoch_seconds: clock(),
            previous_credit_balances: &previous_credit_balances,
            latest_activity_at,
            now,
            legacy_root_migration,
        },
        caller,
        &config_fingerprint,
        slot_seconds,
        &mut read_schedule,
    )
}

/// Test-only: runs between a registered slot's pre-collection gate and its
/// resolution read, to change the slot's login in between.
#[cfg(test)]
pub(in crate::agent_status) type ClaudeSlotTestHook = Box<dyn Fn() + Send>;

#[cfg(test)]
pub(in crate::agent_status) fn claude_slot_after_pre_gate_hook() {
    if let Some(hook) = CLAUDE_SLOT_AFTER_PRE_GATE_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        hook();
    }
}

/// Test-only stand-in for the provider, consulted after every pre-request
/// gate has run: answers the request URL with a 200 body (`Ok`) or an HTTP
/// status (`Err`) that goes through the real response arms.
#[cfg(test)]
pub(in crate::agent_status) type ClaudeOAuthTestResponder = fn(&str) -> Result<Value, u16>;

pub(in crate::agent_status) const CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE: &str =
    "claude_saved_reset_variant_unrecognized";

/// Fixed, value-free text: the same words reach the slot status and upload.
pub(in crate::agent_status) const CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE: &str = "Claude's saved-reset reading had no recognizable saved-reset section; this account uses the plain reading for 24 hours.";

/// Local status only: the upload drops it (`ottto_protocol`).
pub(in crate::agent_status) const CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE: &str =
    ottto_protocol::CLAUDE_OAUTH_USAGE_RATE_LIMITED_DIAGNOSTIC_CODE;

/// Fixed, value-free slot-status text per read; the time is in `retry_after`.
pub(in crate::agent_status) const CLAUDE_OAUTH_USAGE_RATE_LIMITED_USAGE_MESSAGE: &str =
    "Claude asked Ottto to wait before the next usage read; Ottto checks again after the retry time.";

pub(in crate::agent_status) const CLAUDE_OAUTH_USAGE_RATE_LIMITED_SAVED_RESETS_MESSAGE: &str =
    "Claude asked Ottto to wait before the next saved-resets read; Ottto checks again after the retry time.";

/// A 429 on the Claude usage read: which read Claude asked Ottto to hold and
/// until when ("Claude asked Ottto to wait until HH:MM UTC"), with the same
/// deadline in `retry_after`. Reporting only: the Retry-After backoff, the
/// breaker and the calls made are unchanged.
pub(in crate::agent_status) fn claude_oauth_usage_rate_limited_diagnostic(
    read: claude_credit_pools::ClaudeUsageRead,
    retry_after: u64,
    now: u64,
) -> AgentStatusDiagnostic {
    let until = i64::try_from(retry_after)
        .ok()
        .and_then(|at| OffsetDateTime::from_unix_timestamp(at).ok())
        .map_or_else(
            || "later".to_string(),
            |at| format!("{:02}:{:02} UTC", at.hour(), at.minute()),
        );
    let mut diagnostic = claude_quota_check_diagnostic(
        CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE,
        &format!(
            "Claude asked Ottto to wait until {until} before the next {} read.",
            read.label()
        ),
        now,
    );
    diagnostic.retry_after = rfc3339_from_unix_seconds(retry_after);
    diagnostic
}

/// Handle one 200 response body.
///
/// The saved-reset variant is self-checked (owner decision): a body without a
/// recognizable `cedar_ember` adds a code-only diagnostic, sends no
/// saved-reset balance (the last observed one is re-sent), and pauses the
/// variant for this binding for 24 h. That pause is variant state, never a
/// strike on the endpoint breaker. A variant body that also lacks windows is
/// handled like a rejected variant
/// ([`claude_oauth_saved_resets_variant_unusable`]).
pub(in crate::agent_status) fn claude_oauth_usage_after_response(
    reading: ClaudeOAuthReading<'_>,
    caller: &ClaudeOAuthUsageCaller,
    config_fingerprint: &str,
    slot_seconds: u64,
    read_schedule: &mut claude_credit_pools::ClaudeReadSchedule,
) -> ClaudeOAuthUsageOutcome {
    let account_identifier_hash = reading.account_identifier_hash;
    let organization_identifier_hash = reading.organization_identifier_hash;
    let now = reading.now;
    let legacy_root_migration = reading.legacy_root_migration;
    let variant_recognized = (reading.read == claude_credit_pools::ClaudeUsageRead::SavedResets)
        .then(|| claude_credit_pools::claude_saved_resets_recognized(reading.body));
    if let Some(recognized) = variant_recognized {
        read_schedule.after_saved_resets_variant(recognized, now);
    }
    let unrecognized = (variant_recognized == Some(false)).then(|| {
        claude_quota_check_diagnostic(
            CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE,
            CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE,
            now,
        )
    });
    let read = reading.read;
    let usage = match claude_oauth_usage_record_reading(reading, read_schedule) {
        Ok(usage) => usage,
        // The saved-reset variant without windows is variant state, never an
        // endpoint shape failure: a recognizable saved-reset section is kept,
        // anything else pauses the variant.
        Err(_) if read == claude_credit_pools::ClaudeUsageRead::SavedResets => {
            if unrecognized.is_none() {
                return claude_oauth_saved_resets_without_windows(
                    reading,
                    slot_seconds,
                    read_schedule,
                );
            }
            return claude_oauth_saved_resets_variant_unusable(
                account_identifier_hash,
                organization_identifier_hash,
                legacy_root_migration,
                slot_seconds,
                read_schedule,
                now,
            );
        }
        // A plain 200 that carries none of the expected quota fields is a
        // shape change, not an empty account: every plan this endpoint answers
        // for reports at least one window.
        Err(usage) => {
            return ClaudeOAuthUsageOutcome {
                result: Ok(usage),
                diagnostics: record_claude_oauth_usage_failure(
                    ClaudeOAuthUsageFailure::ResponseShape,
                    account_identifier_hash,
                    organization_identifier_hash,
                    config_fingerprint,
                    now,
                ),
            }
            .with_check_outcome(
                "claude_oauth_usage_check_failed",
                "The latest Claude OAuth response contained no supported quota windows.",
                current_unix_seconds(),
            );
        }
    };
    // One clean answer clears the accumulated failure counters: the thresholds
    // below are about *consecutive* failures. Another caller's own auth
    // streak survives: this answer says nothing about that credential.
    clear_claude_oauth_usage_breaker_after_success(
        caller,
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        now,
    );
    ClaudeOAuthUsageOutcome {
        result: Ok(usage),
        diagnostics: unrecognized.into_iter().collect(),
    }
    .with_check_outcome(
        "claude_oauth_usage_check_succeeded",
        "A supported Claude OAuth quota response was collected successfully.",
        current_unix_seconds(),
    )
}

/// The binding is held until its next slot after a saved-reset reading that
/// was not usable (or had no windows): no provider request in this slot.
pub(in crate::agent_status) fn claude_oauth_read_held_outcome(
    result: Result<ClaudeOAuthUsage, String>,
    now: u64,
) -> ClaudeOAuthUsageOutcome {
    ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
        "claude_oauth_usage_check_suppressed",
        "The last Claude saved-reset reading was not usable; no provider request is made before this account's next slot.",
        now,
    )
}

/// The saved-reset variant answered with a recognizable saved-reset section
/// but no windows. Not a shape failure, so no breaker strike: the fresh
/// saved-reset section is kept, the stored windows and other sections are
/// served unchanged, and the binding's next read moves out by one slot (no
/// second call in this slot, with or without a stored reading).
pub(in crate::agent_status) fn claude_oauth_saved_resets_without_windows(
    reading: ClaudeOAuthReading<'_>,
    slot_seconds: u64,
    read_schedule: &mut claude_credit_pools::ClaudeReadSchedule,
) -> ClaudeOAuthUsageOutcome {
    let account_identifier_hash = reading.account_identifier_hash;
    let organization_identifier_hash = reading.organization_identifier_hash;
    let now = reading.now;
    let next_read = now.saturating_add(slot_seconds);
    let observed_at =
        rfc3339_from_unix_seconds(reading.observed_at_epoch_seconds).unwrap_or_default();
    let credit_read = claude_credit_pools::claude_credit_read(
        reading.body,
        claude_credit_pools::ClaudeUsageRead::SavedResets,
        &observed_at,
    );
    let stored = read_claude_oauth_usage_cache_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        reading.legacy_root_migration,
    );
    let mut usage = ClaudeOAuthUsage {
        windows: Vec::new(),
        credit_balances: claude_credit_pools::claude_merge_credit_sections(
            &claude_oauth_binding_key(account_identifier_hash, organization_identifier_hash),
            stored
                .as_ref()
                .map_or(reading.previous_credit_balances, |cache| {
                    cache.credit_balances.as_slice()
                }),
            &credit_read,
        ),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };
    claude_oauth_stamp_account_identity(
        &mut usage,
        account_identifier_hash,
        Some(organization_identifier_hash),
    );
    read_schedule.after_reading(
        claude_credit_pools::ClaudeUsageRead::SavedResets,
        reading.observed_at_epoch_seconds,
        reading.latest_activity_at,
        now,
    );
    read_schedule.next_read_not_before = Some(next_read);
    let _ = claude_credit_pools::write_claude_read_schedule(
        &claude_oauth_usage_account_state_dir(
            account_identifier_hash,
            organization_identifier_hash,
        ),
        read_schedule,
    );
    let mut cache = stored.unwrap_or(ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account_identifier_hash.to_string(),
        organization_identifier_hash: organization_identifier_hash.to_string(),
        observed_at_epoch_seconds: now,
        next_refresh_after_epoch_seconds: next_read,
        windows: Vec::new(),
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    });
    cache.credit_balances = usage.credit_balances;
    cache.next_refresh_after_epoch_seconds = next_read;
    let _ = write_claude_oauth_usage_cache(&cache);
    // Without a stored reading, the cache holds just this saved-reset section
    // (no windows), served as such.
    let result = if now.saturating_sub(cache.observed_at_epoch_seconds)
        <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
    {
        Ok(claude_oauth_usage_from_cache(cache, now))
    } else {
        Err("Claude's saved-reset reading carried no quota windows.".to_string())
    };
    ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
        "claude_oauth_usage_cache_reused",
        "The latest Claude saved-reset reading carried no quota windows; its saved-reset section was kept and the stored windows were reused.",
        current_unix_seconds(),
    )
}

/// The saved-reset variant gave this binding nothing usable this slot: a 200
/// without windows or a recognizable `cedar_ember`, or a 4xx rejection other
/// than auth or rate limiting. Variant state only, never an endpoint-breaker
/// strike:
/// - the variant pauses for 24 h for this binding (every slot reads plain);
/// - the code-only diagnostic is added;
/// - the stored reading is served unchanged, so no section flips off;
/// - the binding's next read moves out by one slot: no second call in this
///   slot, and no retry on every pass.
pub(in crate::agent_status) fn claude_oauth_saved_resets_variant_unusable(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    legacy_root_migration: bool,
    slot_seconds: u64,
    read_schedule: &mut claude_credit_pools::ClaudeReadSchedule,
    now: u64,
) -> ClaudeOAuthUsageOutcome {
    read_schedule.after_saved_resets_variant(false, now);
    // No call before the next slot, with or without a stored reading.
    read_schedule.next_read_not_before = Some(now.saturating_add(slot_seconds));
    let _ = claude_credit_pools::write_claude_read_schedule(
        &claude_oauth_usage_account_state_dir(
            account_identifier_hash,
            organization_identifier_hash,
        ),
        read_schedule,
    );
    let diagnostics = vec![claude_quota_check_diagnostic(
        CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE,
        CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE,
        now,
    )];
    let stored = read_claude_oauth_usage_cache_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        legacy_root_migration,
    );
    let result = match stored {
        Some(mut cache) => {
            cache.next_refresh_after_epoch_seconds = now.saturating_add(slot_seconds);
            let _ = write_claude_oauth_usage_cache(&cache);
            if !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            {
                Ok(claude_oauth_usage_from_cache(cache, now))
            } else {
                Err("Claude's saved-reset reading was not usable.".to_string())
            }
        }
        None => Err("Claude's saved-reset reading was not usable.".to_string()),
    };
    ClaudeOAuthUsageOutcome {
        result,
        diagnostics,
    }
    .with_check_outcome(
        "claude_oauth_usage_check_failed",
        "The latest Claude saved-reset reading was not usable; the stored reading was kept.",
        current_unix_seconds(),
    )
}
