//! Tests for paused Claude usage checks and their account diagnostics.
//! Loaded by the agent-status module under its existing test gate.
//! Exercises saved slot readings and the local quota breaker.

use super::*;

const NOW: u64 = 1_790_000_000;
const ACCOUNT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ACCOUNT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ORG: &str = "oooooooooooooooooooooooooooooooo";

fn stale_quota() -> ClaudeConfigSlotQuotaSnapshotV1 {
    ClaudeConfigSlotQuotaSnapshotV1 {
        state: ClaudeConfigSlotQuotaSnapshotStateV1::Stale,
        captured_at: "2026-10-03T05:04:35Z".to_string(),
        observed_at: Some("2026-10-03T05:04:35Z".to_string()),
        quota_windows: Vec::new(),
        credit_balances: Vec::new(),
    }
}

fn paused_slot(account: &str) -> ClaudeConfigSlotCollectionStatusV1 {
    let mut status = provider_unavailable_status("2026-10-03T06:46:48Z", account, ORG);
    status.quota_snapshot = Some(stale_quota());
    status.quota_check_diagnostics = vec![AgentStatusDiagnostic::source(
        "claude_oauth_usage_circuit_open",
        AgentDiagnosticSeverity::Warning,
        "The local quota circuit is open after authentication rejection.",
    )];
    status
}

fn healthy_slot(account: &str) -> ClaudeConfigSlotCollectionStatusV1 {
    fresh_slot_status("2026-10-03T06:30:56Z", account, ORG, true, true, false)
}

fn current_login() -> AgentStatusSnapshot {
    base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::ConfigFile,
        "2026-10-03T06:46:07Z".to_string(),
        "2026-10-03T06:51:07Z".to_string(),
    )
}

fn auth_breaker(reopen_after: u64) -> ClaudeOAuthUsageBreaker {
    ClaudeOAuthUsageBreaker {
        schema_version: CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
        account_identifier_hash: ACCOUNT_A.to_string(),
        organization_identifier_hash: ORG.to_string(),
        opened_by: "auth_rejected".to_string(),
        reopen_after_epoch_seconds: reopen_after,
        ..Default::default()
    }
}

fn no_breaker(_: &str, _: &str) -> Option<ClaudeOAuthUsageBreaker> {
    None
}

fn paused_account(
    account: &str,
    after_sign_in_rejection: bool,
    provider_asked_to_wait: bool,
    next_check_epoch_seconds: Option<u64>,
) -> ClaudePausedUsageAccount {
    ClaudePausedUsageAccount {
        account_identifier_hash: account.to_string(),
        organization_identifier_hash: ORG.to_string(),
        after_sign_in_rejection,
        provider_asked_to_wait,
        next_check_epoch_seconds,
    }
}

fn only_diagnostic(paused: &[ClaudePausedUsageAccount]) -> AgentStatusDiagnostic {
    let mut diagnostics = claude_usage_checks_paused_diagnostics(paused);
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    diagnostics.remove(0)
}

#[test]
fn paused_account_reports_plain_words_with_next_check() {
    let slots = BTreeMap::from([
        ("slot-paused".to_string(), paused_slot(ACCOUNT_A)),
        ("slot-healthy".to_string(), healthy_slot(ACCOUNT_B)),
    ]);
    let reopen = NOW + 3_600;
    let paused = claude_paused_usage_accounts(
        &slots,
        &current_login(),
        |account, _| (account == ACCOUNT_A).then(|| auth_breaker(reopen)),
        NOW,
    );
    assert_eq!(
        paused,
        vec![paused_account(ACCOUNT_A, true, false, Some(reopen))]
    );
    let diagnostic = only_diagnostic(&paused);
    assert_eq!(diagnostic.code, CLAUDE_USAGE_CHECKS_PAUSED_DIAGNOSTIC_CODE);
    assert_eq!(diagnostic.severity, AgentDiagnosticSeverity::Warning);
    let expected_at = rfc3339_from_unix_seconds(reopen).expect("time");
    assert_eq!(
        diagnostic.message,
        format!(
            "Claude usage checks paused for this account after the provider rejected sign-in; next automatic check {expected_at}. Last readings stay shown until then."
        )
    );
    let lowered = diagnostic.message.to_ascii_lowercase();
    for forbidden in [
        "sign in again",
        "log in",
        "login",
        "reconnect",
        "quota",
        "limit",
    ] {
        assert!(!lowered.contains(forbidden), "{forbidden}: {lowered}");
    }
    // Bound to the paused account, so the app shows it on that row.
    assert_eq!(
        diagnostic.account_identifier_hash.as_deref(),
        Some(ACCOUNT_A)
    );
    assert_eq!(
        diagnostic.organization_identifier_hash.as_deref(),
        Some(ORG)
    );
    // Scope stays absent (provider-wide) so today's apps keep listing it; the
    // binding alone places it on the row.
    assert_eq!(diagnostic.scope, None);
    assert_eq!(
        diagnostic.retry_after, None,
        "a sign-in hold is not a provider wait"
    );
}

fn held(backoff_until: u64) -> ClaudeOAuthUsageCallerAuthState {
    ClaudeOAuthUsageCallerAuthState {
        consecutive_failures: 1,
        last_status: 401,
        last_failure_at_epoch_seconds: NOW - 60,
        backoff_until_epoch_seconds: backoff_until,
        credential_expires_at: None,
    }
}

fn caller_hold_breaker(caller_key: String, backoff_until: u64) -> ClaudeOAuthUsageBreaker {
    let mut breaker = auth_breaker(0);
    breaker.opened_by = String::new();
    breaker.auth_callers.insert(caller_key, held(backoff_until));
    breaker
}

#[test]
fn account_genuinely_served_by_a_second_credential_is_not_paused() {
    // The held slot's own caller is backing off, but a different, eligible
    // credential for the same account is reading it.
    let slots = BTreeMap::from([
        ("slot-held".to_string(), paused_slot(ACCOUNT_A)),
        ("slot-fresh".to_string(), healthy_slot(ACCOUNT_A)),
    ]);
    let paused = claude_paused_usage_accounts(
        &slots,
        &current_login(),
        |_, _| {
            Some(caller_hold_breaker(
                claude_oauth_usage_slot_caller_key("slot-held"),
                NOW + 900,
            ))
        },
        NOW,
    );
    assert!(paused.is_empty());
}

#[test]
fn young_shared_cache_on_a_held_slot_is_paused() {
    // A held slot can look Fresh while the shared per-account cache is
    // young; its caller cannot refresh it, so it does not serve the account.
    let slots = BTreeMap::from([("slot-held".to_string(), healthy_slot(ACCOUNT_A))]);
    let paused = claude_paused_usage_accounts(
        &slots,
        &current_login(),
        |_, _| {
            Some(caller_hold_breaker(
                claude_oauth_usage_slot_caller_key("slot-held"),
                NOW + 900,
            ))
        },
        NOW,
    );
    assert_eq!(
        paused,
        vec![paused_account(ACCOUNT_A, true, false, Some(NOW + 900))]
    );
    // Once the hold has expired the same slot serves the account again.
    let paused = claude_paused_usage_accounts(
        &slots,
        &current_login(),
        |_, _| {
            Some(caller_hold_breaker(
                claude_oauth_usage_slot_caller_key("slot-held"),
                NOW - 1,
            ))
        },
        NOW,
    );
    assert!(paused.is_empty());
}

#[test]
fn provider_unavailable_with_stale_readings_counts_without_auth_evidence() {
    let mut slot = provider_unavailable_status("2026-10-03T06:46:48Z", ACCOUNT_A, ORG);
    slot.quota_snapshot = Some(stale_quota());
    let slots = BTreeMap::from([("slot-a".to_string(), slot.clone())]);
    let paused = claude_paused_usage_accounts(&slots, &current_login(), no_breaker, NOW);
    assert_eq!(paused, vec![paused_account(ACCOUNT_A, false, false, None)]);
    let diagnostic = only_diagnostic(&paused);
    assert_eq!(
        diagnostic.message,
        "Claude usage checks paused for this account while the provider is not answering; Ottto checks again automatically. Last readings stay shown until then."
    );
    assert_eq!(diagnostic.retry_after, None);

    // Provider unavailable but readings not yet stale: not paused.
    slot.quota_snapshot = None;
    let slots = BTreeMap::from([("slot-a".to_string(), slot)]);
    assert!(claude_paused_usage_accounts(&slots, &current_login(), no_breaker, NOW).is_empty());
}

#[test]
fn per_caller_hold_gives_the_earliest_next_check() {
    let mut breaker = auth_breaker(0);
    breaker.opened_by = String::new();
    breaker.auth_callers.insert(
        "default".to_string(),
        ClaudeOAuthUsageCallerAuthState {
            consecutive_failures: 1,
            last_status: 401,
            last_failure_at_epoch_seconds: NOW - 60,
            backoff_until_epoch_seconds: NOW + 900,
            credential_expires_at: None,
        },
    );
    breaker.auth_callers.insert(
        "slot-sha256:expired".to_string(),
        ClaudeOAuthUsageCallerAuthState {
            backoff_until_epoch_seconds: NOW - 1,
            ..Default::default()
        },
    );
    assert_eq!(
        claude_breaker_auth_pause_until(&breaker, NOW),
        Some(NOW + 900)
    );
    // An expired account-wide verdict does not count.
    let expired = auth_breaker(NOW - 1);
    assert_eq!(claude_breaker_auth_pause_until(&expired, NOW), None);
}

#[test]
fn default_login_auth_pause_is_attributed_to_its_account() {
    let mut default_slot = provider_unavailable_status("2026-10-03T06:46:48Z", ACCOUNT_A, ORG);
    default_slot.quota_snapshot = None;
    let mut snapshot = current_login();
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: None,
        auth_method: None,
        email: None,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: None,
        subscription_product: None,
        billing_channel: None,
        subscription_period_start: None,
        subscription_period_end: None,
        subscription_period_last_checked_at: None,
        account_identifier_hash: Some(ACCOUNT_A.to_string()),
        organization_identifier_hash: Some(ORG.to_string()),
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::default(),
        confidence: AgentStatusConfidence::default(),
    });
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "claude_oauth_usage_circuit_open",
        AgentDiagnosticSeverity::Warning,
        "Stopped calling the Claude OAuth usage endpoint after auth rejected; quota falls back to Claude Code's local statusLine for the next 1399 minute(s).",
    ));
    let slots = BTreeMap::from([("default".to_string(), default_slot)]);
    let paused = claude_paused_usage_accounts(&slots, &snapshot, no_breaker, NOW);
    assert_eq!(paused.len(), 1);
    assert!(paused[0].after_sign_in_rejection);

    // A shape-failure circuit is not a sign-in rejection.
    snapshot.diagnostics[0].message =
        "Stopped calling the Claude OAuth usage endpoint after response shape; quota falls back to Claude Code's local statusLine for the next 5 minute(s).".to_string();
    let slots = BTreeMap::from([(
        "default".to_string(),
        provider_unavailable_status("2026-10-03T06:46:48Z", ACCOUNT_A, ORG),
    )]);
    assert!(claude_paused_usage_accounts(&slots, &snapshot, no_breaker, NOW).is_empty());
}

/// [behaviour] A stale slot held by the provider's rate-limit retry time says
/// the provider asked Ottto to wait, names that time as the next check, and
/// is bound to its own account; a second paused account gets its own line.
#[test]
fn provider_wait_names_its_retry_time_and_each_account_gets_its_own_line() {
    let wait_until = NOW + 3_600;
    let at = rfc3339_from_unix_seconds(wait_until).expect("time");
    let mut waiting = provider_unavailable_status("2026-10-03T06:46:48Z", ACCOUNT_A, ORG);
    waiting.quota_snapshot = Some(stale_quota());
    let mut reused = AgentStatusDiagnostic::source(
        "claude_oauth_usage_cache_reused",
        AgentDiagnosticSeverity::Info,
        "Locally cached quota evidence was reused; no provider check was made.",
    );
    reused.retry_after = Some(at.clone());
    waiting.quota_check_diagnostics = vec![reused];
    let mut silent = provider_unavailable_status("2026-10-03T06:46:48Z", ACCOUNT_B, ORG);
    silent.quota_snapshot = Some(stale_quota());
    let slots = BTreeMap::from([
        ("slot-a".to_string(), waiting.clone()),
        ("slot-b".to_string(), silent),
    ]);
    let paused = claude_paused_usage_accounts(&slots, &current_login(), no_breaker, NOW);
    assert_eq!(
        paused,
        vec![
            paused_account(ACCOUNT_A, false, true, Some(wait_until)),
            paused_account(ACCOUNT_B, false, false, None),
        ]
    );
    let diagnostics = claude_usage_checks_paused_diagnostics(&paused);
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(
        diagnostics[0].message,
        format!(
            "Claude usage checks paused for this account while the provider asks Ottto to wait; next automatic check {at}. Last readings stay shown until then."
        )
    );
    assert_eq!(diagnostics[0].retry_after.as_deref(), Some(at.as_str()));
    assert_eq!(
        diagnostics[0].account_identifier_hash.as_deref(),
        Some(ACCOUNT_A)
    );
    assert_eq!(
        diagnostics[1].account_identifier_hash.as_deref(),
        Some(ACCOUNT_B)
    );
    assert!(diagnostics[1].message.contains("not answering"));
    for diagnostic in &diagnostics {
        let lowered = diagnostic.message.to_ascii_lowercase();
        assert!(
            !lowered.contains("limit") && !lowered.contains("quota"),
            "{lowered}"
        );
    }

    // A retry time already passed is not a wait.
    let mut expired = waiting;
    expired.quota_check_diagnostics[0].retry_after = rfc3339_from_unix_seconds(NOW - 1);
    let slots = BTreeMap::from([("slot-a".to_string(), expired)]);
    let paused = claude_paused_usage_accounts(&slots, &current_login(), no_breaker, NOW);
    assert_eq!(paused, vec![paused_account(ACCOUNT_A, false, false, None)]);
}

/// [behaviour] The default login's "sign in again" warning carries that
/// login's account and organization; other diagnostics are left alone, and
/// without a proven identity it stays unbound.
#[test]
fn relogin_warning_names_the_default_logins_account() {
    let warning = || {
        AgentStatusDiagnostic::source(
            CLAUDE_RELOGIN_APPROACHING_CODE,
            AgentDiagnosticSeverity::Warning,
            "This Claude login ends within 3 days; sign in again to keep its limits current.",
        )
    };
    let other = AgentStatusDiagnostic::source(
        "claude_version_detected",
        AgentDiagnosticSeverity::Info,
        "Claude Code CLI version detected.",
    );
    let mut diagnostics = vec![warning(), other.clone()];
    bind_claude_relogin_warning(
        &mut diagnostics,
        Some(&(ACCOUNT_A.to_string(), ORG.to_string())),
    );
    assert_eq!(
        diagnostics[0].account_identifier_hash.as_deref(),
        Some(ACCOUNT_A)
    );
    assert_eq!(
        diagnostics[0].organization_identifier_hash.as_deref(),
        Some(ORG)
    );
    assert_eq!(diagnostics[1], other);

    let mut unproven = vec![warning()];
    bind_claude_relogin_warning(&mut unproven, None);
    assert_eq!(unproven, vec![warning()]);
}
