use super::*;

/// The account resolution `collect_claude_status` performs, for tests that
/// exercise the OAuth path directly.
fn claude_oauth_account_identifier_hash() -> String {
    read_claude_cli_oauth_account(&claude_cli_config_path())
        .as_ref()
        .map(claude_oauth_account_identifier_hash_for)
        .unwrap_or_default()
}

fn local_meter_fixture(
    account_hash: &str,
    organization_hash: &str,
) -> ClaudeConfigSlotQuotaSnapshotV1 {
    local_claude_quota_snapshot(
        "2026-08-05T01:05:00Z",
        &[
            AgentQuotaWindow {
                name: "session".to_string(),
                scope: AgentQuotaWindowScope::Account,
                freshness: AgentQuotaWindowFreshness::Fresh,
                observed_at: Some("2026-08-05T01:02:00Z".to_string()),
                account_identifier_hash: Some(account_hash.to_string()),
                organization_identifier_hash: Some(organization_hash.to_string()),
                used_percent: Some(12),
                ..Default::default()
            },
            AgentQuotaWindow {
                name: "weekly".to_string(),
                scope: AgentQuotaWindowScope::Account,
                freshness: AgentQuotaWindowFreshness::Fresh,
                observed_at: Some("2026-08-05T01:01:00Z".to_string()),
                account_identifier_hash: Some(account_hash.to_string()),
                organization_identifier_hash: Some(organization_hash.to_string()),
                used_percent: Some(34),
                ..Default::default()
            },
            AgentQuotaWindow {
                name: "weekly_sonnet".to_string(),
                scope: AgentQuotaWindowScope::Model,
                freshness: AgentQuotaWindowFreshness::Fresh,
                observed_at: Some("2026-08-05T01:03:00Z".to_string()),
                model: Some("claude-sonnet".to_string()),
                account_identifier_hash: Some(account_hash.to_string()),
                organization_identifier_hash: Some(organization_hash.to_string()),
                used_percent: Some(56),
                ..Default::default()
            },
        ],
        &[AgentCreditBalance {
            name: "Usage credits".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            account_identifier_hash: Some(account_hash.to_string()),
            organization_identifier_hash: Some(organization_hash.to_string()),
            remaining: CreditAmount::whole(789),
            updated_at: Some("2026-08-05T01:04:00Z".to_string()),
            ..Default::default()
        }],
        true,
        true,
    )
}

/// A provider-side read failure is not a repair the operator can make.
///
/// `ProviderUnavailable`, `ProbeFailed`, `CollectionInProgress` and
/// `RefreshDue` all mean the meters could not be read right now: the
/// daemon already classifies them `TemporarilyUnavailable` in
/// `projected_claude_quota_access_state`, the credential is untouched, and
/// the app's own approved copy for them names no user action ("Ottto could
/// not read current limits", "Staged") - unlike `NeedsLogin`,
/// `StaleAccessToken`, `ReloginApproaching` and `IdentityMismatch`, which
/// all tell the operator to sign in again. `ConcurrentMutation` is a
/// same-pass race that keeps the last verified account and retries, so it
/// is benign as well ([regress]: it used to raise the warning).
/// Counting them as actionable raised `secret_expired` - "Claude Code
/// durable connections need attention" - with a Verify button, for an
/// outage at Anthropic that Verify cannot fix and that the daemon's own
/// re-verify backoff clears on its own.
#[test]
fn a_transient_claude_read_failure_does_not_need_attention() {
    use ClaudeConfigSlotCollectionStateV1 as State;

    // Exhaustive by construction: adding a state to the protocol enum
    // fails to compile here until someone decides which side it belongs
    // on, rather than silently defaulting to "the operator must act".
    fn classify(state: &ClaudeConfigSlotCollectionStateV1) -> bool {
        match state {
            State::Fresh
            | State::Unverified
            | State::DuplicateAccount
            | State::ProviderUnavailable
            | State::ProbeFailed
            | State::ConcurrentMutation
            | State::CollectionInProgress
            | State::RefreshDue => false,
            State::IdentityUnknown
            | State::CredentialUnavailable
            | State::IdentityMismatch
            | State::CollectionPaused
            | State::CapacityExceeded
            | State::UpkeepNotConsented
            | State::StaleAccessToken
            | State::ReloginApproaching
            | State::NeedsLogin => true,
        }
    }

    for benign in [
        State::Fresh,
        State::Unverified,
        State::DuplicateAccount,
        State::ProviderUnavailable,
        State::ProbeFailed,
        State::ConcurrentMutation,
        State::CollectionInProgress,
        State::RefreshDue,
    ] {
        assert!(
            !claude_custom_slot_needs_attention(&benign),
            "{benign:?} must not degrade a healthy Claude source"
        );
        assert!(!classify(&benign), "classifier drifted from the lists");
    }

    for actionable in [
        State::IdentityUnknown,
        State::CredentialUnavailable,
        State::IdentityMismatch,
        State::CollectionPaused,
        State::CapacityExceeded,
        State::UpkeepNotConsented,
        State::StaleAccessToken,
        State::ReloginApproaching,
        State::NeedsLogin,
    ] {
        assert!(
            claude_custom_slot_needs_attention(&actionable),
            "{actionable:?} must still reach the operator"
        );
        assert!(classify(&actionable), "classifier drifted from the lists");
    }
}

/// The exact slot set behind the 0.1.132 report, as data: one fresh
/// canonical anchor serving live meters, one duplicate anchor, one
/// canonical anchor whose provider read failed, and a default slot that
/// holds full-meter evidence and also failed its provider read.
///
/// This is the boolean that gates the `secret_expired` warning, so it
/// reproduces the symptom rather than only the helper.
#[test]
fn live_provider_unavailable_slot_set_does_not_degrade_the_source() {
    use ClaudeConfigSlotCollectionStateV1 as State;

    let custom_slots = [
        State::DuplicateAccount,
        State::Fresh,
        State::ProviderUnavailable,
    ];
    let default_state = State::ProviderUnavailable;
    let default_has_full_meter_evidence = true;

    let has_actionable_custom_slot = custom_slots.iter().any(claude_custom_slot_needs_attention);
    let default_full_meter_needs_attention =
        claude_default_full_meter_needs_attention(default_has_full_meter_evidence, &default_state);

    assert!(
        !has_actionable_custom_slot,
        "no custom slot in this set is a repair the operator can make"
    );
    assert!(
        !default_full_meter_needs_attention,
        "the default slot's failed provider read is not a repair either"
    );
    assert!(
        !(has_actionable_custom_slot || default_full_meter_needs_attention),
        "this slot set must leave Claude Code healthy, not `needs attention`"
    );

    // The same set with one genuinely expired sign-in must still warn.
    let with_expired = [State::Fresh, State::NeedsLogin];
    assert!(
        with_expired.iter().any(claude_custom_slot_needs_attention),
        "an expired sign-in must still reach the operator"
    );
}

/// Contract v2.2 §11.10: a reader-blind saved-resets row an older daemon
/// kept as a complete, empty list is carried forward in the unavailable
/// shape, never as no resets.
#[test]
fn retained_slot_snapshot_shows_an_older_reader_blind_row_as_unavailable() {
    let account_hash = "a".repeat(64);
    let organization_hash = "b".repeat(64);
    let now = current_unix_seconds();
    let now_text = rfc3339_from_unix_seconds(now).expect("now");
    let mut snapshot = local_meter_fixture(&account_hash, &organization_hash);
    snapshot.captured_at = now_text.clone();
    snapshot.observed_at = Some(now_text.clone());
    snapshot.credit_balances.push(AgentCreditBalance {
        name: "reset_bank".to_string(),
        status: AgentCreditBalanceStatus::Exhausted,
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Resets,
        remaining: Some(CreditAmount::ZERO),
        observed_at: Some(now_text.clone()),
        grant_count: Some(0),
        grants: Some(Vec::new()),
        grants_state: Some(ottto_protocol::CreditGrantsState::Complete),
        grants_observed_at: Some(now_text.clone()),
        kind: Some(ottto_protocol::CreditBalanceKind::SavedResets),
        eligible: Some(false),
        at_limit: Some(false),
        ineligible_reason: Some("surface".to_string()),
        ..Default::default()
    });
    let previous = ClaudeConfigSlotCollectionStatusV1 {
        last_full_quota_read_at: Some(now_text),
        has_account_windows: true,
        has_scoped_limits: true,
        has_credit_balances: true,
        quota_snapshot: Some(snapshot),
        ..Default::default()
    };
    let mut status = ClaudeConfigSlotCollectionStatusV1::default();
    retain_previous_complete_claude_read(&mut status, previous);
    let retained = status.quota_snapshot.expect("retained snapshot");
    let saved = retained
        .credit_balances
        .iter()
        .find(|balance| balance.kind == Some(ottto_protocol::CreditBalanceKind::SavedResets))
        .expect("saved resets kept");
    assert_eq!(
        saved.grants_unavailable_cause,
        Some(ottto_protocol::CreditGrantsUnavailableCause::Reader)
    );
    assert!(ottto_protocol::credit_grants_unavailable_cause_allowed(
        saved
    ));
    assert_eq!(saved.status, AgentCreditBalanceStatus::Unknown);
    assert_eq!(saved.freshness, AgentQuotaWindowFreshness::Stale);
    assert_eq!(saved.ineligible_reason.as_deref(), Some("surface"));
    // Every other row is kept as it was, only marked stale.
    assert!(retained
        .credit_balances
        .iter()
        .filter(|balance| balance.kind != Some(ottto_protocol::CreditBalanceKind::SavedResets))
        .all(|balance| balance.grants_unavailable_cause.is_none()));
}

#[test]
fn local_claude_meter_values_have_typed_fresh_stale_partial_and_safe_freshness() {
    let account_hash = "a".repeat(64);
    let organization_hash = "b".repeat(64);
    let fresh = local_meter_fixture(&account_hash, &organization_hash);
    assert_eq!(fresh.state, ClaudeConfigSlotQuotaSnapshotStateV1::Fresh);
    assert_eq!(fresh.captured_at, "2026-08-05T01:05:00Z");
    assert_eq!(fresh.observed_at.as_deref(), Some("2026-08-05T01:01:00Z"));
    assert_eq!(fresh.quota_windows.len(), 3);
    assert_eq!(fresh.credit_balances.len(), 1);

    let stale = stale_local_claude_quota_snapshot(&fresh);
    assert_eq!(stale.state, ClaudeConfigSlotQuotaSnapshotStateV1::Stale);
    assert!(stale
        .quota_windows
        .iter()
        .all(|window| window.freshness == AgentQuotaWindowFreshness::Stale));
    assert!(stale
        .credit_balances
        .iter()
        .all(|balance| balance.freshness == AgentQuotaWindowFreshness::Stale));

    let partial = local_claude_quota_snapshot(
        "2026-08-05T01:05:00Z",
        &fresh.quota_windows[..2],
        &[],
        true,
        false,
    );
    assert_eq!(partial.state, ClaudeConfigSlotQuotaSnapshotStateV1::Partial);
    assert!(!local_claude_quota_snapshot_within_retention(
        &fresh,
        OffsetDateTime::parse("2026-08-05T01:00:59Z", &Rfc3339).expect("now")
    ));

    let wire = serde_json::to_string(&fresh).expect("serialize local meters");
    assert!(wire.contains("weekly_sonnet"));
    assert!(wire.contains("Usage credits"));
    for forbidden in [
        "accessToken",
        "refreshToken",
        "claudeAiOauth",
        "CLAUDE_CONFIG_DIR",
        ".credentials.json",
        "Claude Code-credentials",
    ] {
        assert!(!wire.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn local_claude_meter_stale_reuse_requires_same_strong_account_and_org() {
    let account_hash = "a".repeat(64);
    let organization_hash = "b".repeat(64);
    let fresh_now = OffsetDateTime::parse("2026-08-05T02:00:00Z", &Rfc3339).expect("fresh now");
    let expired_now = OffsetDateTime::parse("2026-08-06T02:00:00Z", &Rfc3339).expect("expired now");
    let existing = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some(account_hash.clone()),
        organization_identifier_hash: Some(organization_hash.clone()),
        observed_at: Some("2026-08-05T01:00:00Z".to_string()),
        last_full_quota_read_at: Some("2026-08-05T01:00:00Z".to_string()),
        has_account_windows: true,
        has_scoped_limits: true,
        has_credit_balances: true,
        quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
        ..Default::default()
    };
    let mut slots = BTreeMap::from([("slot-a".to_string(), existing.clone())]);
    merge_claude_slot_collection_state_at(
        &mut slots,
        "slot-a",
        &ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2026-08-05T01:10:00Z".to_string()),
            ..Default::default()
        },
        fresh_now,
    );
    assert_eq!(
        slots["slot-a"]
            .quota_snapshot
            .as_ref()
            .expect("same identity retains values")
            .state,
        ClaudeConfigSlotQuotaSnapshotStateV1::Stale
    );

    let mut expired = BTreeMap::from([("slot-a".to_string(), existing.clone())]);
    merge_claude_slot_collection_state_at(
        &mut expired,
        "slot-a",
        &ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2026-08-06T01:01:01Z".to_string()),
            ..Default::default()
        },
        expired_now,
    );
    assert!(
        expired["slot-a"].quota_snapshot.is_none(),
        "oldest represented meter observation expires after 24 hours"
    );

    for candidate in [
        ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some("c".repeat(64)),
            observed_at: Some("2026-08-05T01:20:00Z".to_string()),
            ..Default::default()
        },
        ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::IdentityMismatch,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2026-08-05T01:30:00Z".to_string()),
            ..Default::default()
        },
    ] {
        let mut isolated = BTreeMap::from([("slot-a".to_string(), existing.clone())]);
        merge_claude_slot_collection_state_at(&mut isolated, "slot-a", &candidate, fresh_now);
        assert!(isolated["slot-a"].quota_snapshot.is_none());
    }

    let sibling = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
        account_identifier_hash: Some(account_hash),
        organization_identifier_hash: Some(organization_hash),
        observed_at: Some("2026-08-05T01:40:00Z".to_string()),
        ..Default::default()
    };
    merge_claude_slot_collection_state_at(&mut slots, "slot-b", &sibling, fresh_now);
    assert!(slots["slot-b"].quota_snapshot.is_none());
}

#[test]
fn fresh_partial_default_observation_does_not_downgrade_fresh_exact_slot_meters() {
    let account_hash = "a".repeat(64);
    let organization_hash = "b".repeat(64);
    let existing = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some(account_hash.clone()),
        organization_identifier_hash: Some(organization_hash.clone()),
        observed_at: Some("2026-08-05T01:05:00Z".to_string()),
        last_full_quota_read_at: Some("2026-08-05T01:05:00Z".to_string()),
        has_account_windows: true,
        has_scoped_limits: true,
        has_credit_balances: true,
        quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
        ..Default::default()
    };
    let partial_snapshot = local_claude_quota_snapshot(
        "2026-08-05T01:20:00Z",
        &existing
            .quota_snapshot
            .as_ref()
            .expect("full snapshot")
            .quota_windows[..2],
        &[],
        true,
        false,
    );
    let partial_statusline = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some(account_hash.clone()),
        organization_identifier_hash: Some(organization_hash),
        observed_at: Some("2026-08-05T01:20:00Z".to_string()),
        has_account_windows: true,
        quota_snapshot: Some(partial_snapshot),
        ..Default::default()
    };
    let mut slots = BTreeMap::from([("default".to_string(), existing)]);

    merge_claude_slot_collection_state_at(
        &mut slots,
        "default",
        &partial_statusline,
        OffsetDateTime::parse("2026-08-05T01:20:00Z", &Rfc3339).expect("now"),
    );

    let merged = &slots["default"];
    assert_eq!(merged.state, ClaudeConfigSlotCollectionStateV1::Fresh);
    assert!(merged.has_account_windows);
    assert!(merged.has_scoped_limits);
    assert!(merged.has_credit_balances);
    assert_eq!(
        merged
            .quota_snapshot
            .as_ref()
            .expect("fresh exact meters")
            .quota_windows
            .len(),
        3,
        "the retained full bundle keeps model-scoped limits"
    );
    assert_eq!(
        merged
            .quota_snapshot
            .as_ref()
            .expect("fresh exact meters")
            .credit_balances
            .len(),
        1,
        "the retained full bundle keeps usage credits"
    );
    assert_eq!(
        merged
            .quota_snapshot
            .as_ref()
            .expect("fresh exact meters")
            .state,
        ClaudeConfigSlotQuotaSnapshotStateV1::Fresh
    );
    assert!(merged
        .quota_snapshot
        .as_ref()
        .expect("fresh exact meters")
        .quota_windows
        .iter()
        .all(|window| window.freshness == AgentQuotaWindowFreshness::Fresh));
}

#[test]
fn slot_collection_merge_parses_timestamps_and_recovers_from_invalid_or_future_state() {
    let now = OffsetDateTime::parse("2026-08-05T02:00:00Z", &Rfc3339).expect("now");
    let account_hash = "a".repeat(64);
    let organization_hash = "b".repeat(64);
    for (observed_at, last_full_quota_read_at) in [
        ("not-a-timestamp", "2026-08-05T01:00:00Z"),
        ("2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
        ("2026-08-05T01:00:00Z", "2099-01-01T00:00:00Z"),
    ] {
        let poisoned = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some(observed_at.to_string()),
            last_full_quota_read_at: Some(last_full_quota_read_at.to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            has_credit_balances: true,
            quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
            ..Default::default()
        };
        let mut slots = BTreeMap::from([("slot-a".to_string(), poisoned)]);
        merge_claude_slot_collection_state_at(
            &mut slots,
            "slot-a",
            &ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
                account_identifier_hash: Some(account_hash.clone()),
                organization_identifier_hash: Some(organization_hash.clone()),
                observed_at: Some("2026-08-05T01:59:00Z".to_string()),
                ..Default::default()
            },
            now,
        );
        let recovered = &slots["slot-a"];
        assert_eq!(
            recovered.state,
            ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
        );
        assert!(recovered.last_full_quota_read_at.is_none());
        assert!(!recovered.has_account_windows);
        assert!(!recovered.has_scoped_limits);
        assert!(!recovered.has_credit_balances);
        assert!(recovered.quota_snapshot.is_none());
    }

    let mut initially_empty = BTreeMap::new();
    merge_claude_slot_collection_state_at(
        &mut initially_empty,
        "slot-a",
        &ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2099-01-01T00:00:00Z".to_string()),
            last_full_quota_read_at: Some("2099-01-01T00:00:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            has_credit_balances: true,
            quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
            ..Default::default()
        },
        now,
    );
    let sanitized = &initially_empty["slot-a"];
    assert!(sanitized.last_full_quota_read_at.is_none());
    assert!(!sanitized.has_account_windows);
    assert!(!sanitized.has_scoped_limits);
    assert!(!sanitized.has_credit_balances);
    assert!(sanitized.quota_snapshot.is_none());

    let mut offset_ordered = BTreeMap::from([(
        "slot-a".to_string(),
        ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::CollectionPaused,
            observed_at: Some("2026-08-05T03:00:00+02:00".to_string()),
            ..Default::default()
        },
    )]);
    merge_claude_slot_collection_state_at(
        &mut offset_ordered,
        "slot-a",
        &ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            observed_at: Some("2026-08-05T01:30:00Z".to_string()),
            ..Default::default()
        },
        now,
    );
    assert_eq!(
        offset_ordered["slot-a"].state,
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
    );
}
use ottto_core::{
    write_claude_statusline_cache, ClaudeStatusLineRateLimitWindow,
    CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
};
use serial_test::serial;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;

/// The credential item shape Claude Code writes after a browser sign-in:
/// both tokens, both deadlines (epoch milliseconds), the inference scope
/// and the plan. Values are fixtures, never real secrets.
fn claude_credential_fixture(
    access_token: &str,
    access_expires_in: TimeDuration,
    subscription_type: Option<&str>,
) -> Value {
    let now = OffsetDateTime::now_utc();
    let mut oauth = serde_json::json!({
        "accessToken": access_token,
        "refreshToken": format!("{access_token}-refresh"),
        "expiresAt": (now + access_expires_in).unix_timestamp() * 1_000,
        "refreshTokenExpiresAt": (now + TimeDuration::days(28)).unix_timestamp() * 1_000,
        "scopes": ["user:inference", "user:profile"],
    });
    if let Some(plan) = subscription_type {
        oauth["subscriptionType"] = serde_json::json!(plan);
    }
    serde_json::json!({ "claudeAiOauth": oauth })
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
    effective_home_previous: Option<Option<OsString>>,
}

impl EnvVarGuard {
    fn set_os(key: &'static str, value: OsString) -> Self {
        let previous = std::env::var_os(key);
        let effective_home_previous =
            (key == "HOME").then(|| std::env::var_os("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS"));
        unsafe { std::env::set_var(key, &value) };
        if key == "HOME" {
            unsafe { std::env::set_var("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &value) };
        }
        Self {
            key,
            previous,
            effective_home_previous,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.previous.as_ref() {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
        if let Some(previous) = self.effective_home_previous.as_ref() {
            match previous {
                Some(value) => unsafe {
                    std::env::set_var("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", value)
                },
                None => unsafe { std::env::remove_var("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS") },
            }
        }
    }
}

fn test_slot_descriptor(index: usize) -> ClaudeConfigSlotDescriptorV1 {
    ClaudeConfigDirSlot::registered(format!("/tmp/claude-slot-{index}"))
        .expect("test slot")
        .descriptor(
            format!("claude_slot_{index:032x}"),
            ClaudeConfigSlotOwnership::External,
        )
}

fn valid_access_reconciliation_fixture() -> (
    ClaudeConfigSlotDescriptorV1,
    ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
    ClaudeLocalIdentityProof,
    OffsetDateTime,
) {
    let mut slot = test_slot_descriptor(0);
    slot.collection = fresh_slot_status(
        "2026-08-05T02:00:00Z",
        "account-a",
        "org-a",
        true,
        true,
        true,
    );
    slot.collection.state = ClaudeConfigSlotCollectionStateV1::RefreshDue;
    slot.collection.access_expires_at = Some("2026-08-05T02:00:00Z".to_string());
    slot.collection.relogin_required_at = Some("2026-09-01T00:00:00Z".to_string());
    slot.collection.last_full_quota_read_at = Some("2026-08-05T01:05:00Z".to_string());
    slot.collection.quota_snapshot = Some(local_meter_fixture("account-a", "org-a"));
    slot.collection.quota_check_diagnostics = vec![AgentStatusDiagnostic::source(
        "claude_oauth_usage_auth_suppressed",
        AgentDiagnosticSeverity::Warning,
        "Fixture prior failure",
    )
    .with_observed_at(Some("2026-08-05T01:06:00Z".to_string()))];
    let upkeep = ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
        result: ClaudeConfigSlotUpkeepResultV1::NotRequired,
        due_access_expires_at: Some("2026-08-05T03:00:00Z".to_string()),
        refresh_token_expires_at: slot.collection.relogin_required_at.clone(),
        attempted_at: None,
        next_allowed_attempt_at: None,
        consecutive_failures: 0,
    };
    let mut collection = fresh_slot_status(
        "2026-08-05T02:29:59Z",
        "account-a",
        "org-a",
        false,
        false,
        false,
    );
    collection.access_expires_at = upkeep.due_access_expires_at.clone();
    collection.relogin_required_at = upkeep.refresh_token_expires_at.clone();
    let proof = ClaudeLocalIdentityProof {
        account_identifier_hash: "account-a".to_string(),
        organization_identifier_hash: "org-a".to_string(),
        collection,
    };
    let now = OffsetDateTime::parse("2026-08-05T02:30:00Z", &Rfc3339).unwrap();
    (slot, upkeep, proof, now)
}

#[test]
fn claude_valid_access_reconciliation_advances_only_verified_deadlines_not_meters() {
    for result in [
        ClaudeConfigSlotUpkeepResultV1::NotRequired,
        ClaudeConfigSlotUpkeepResultV1::ReloginApproaching,
    ] {
        let (slot, mut upkeep, proof, now) = valid_access_reconciliation_fixture();
        upkeep.result = result;
        let next = reconciled_valid_access_status(
            &slot,
            &slot,
            &upkeep,
            &proof,
            "2026-08-05T02:30:00Z",
            now,
        )
        .unwrap();
        let mut expected = slot.collection.clone();
        expected.observed_at = Some("2026-08-05T02:30:00Z".to_string());
        expected.access_expires_at = proof.collection.access_expires_at.clone();
        expected.relogin_required_at = proof.collection.relogin_required_at.clone();
        expected.upkeep = Some(upkeep.clone());
        assert_eq!(next, expected); // Includes all original meter/check clocks and unavailable state.
        assert!(next.upkeep.as_ref().unwrap().attempted_at.is_none());
        let updated = ClaudeConfigSlotDescriptorV1 {
            collection: next,
            ..slot
        };
        assert!(!valid_access_reconciliation_due(&updated, &upkeep, now));
    }
}

#[test]
fn claude_worker_receipt_preserves_saved_health_all_original_clocks_and_backoff() {
    let (mut slot, upkeep, _, now) = valid_access_reconciliation_fixture();
    slot.collection.upkeep = Some(ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
        result: ClaudeConfigSlotUpkeepResultV1::Backoff,
        attempted_at: Some("2026-08-05T01:55:00Z".to_string()),
        next_allowed_attempt_at: Some("2026-08-05T02:40:00Z".to_string()),
        consecutive_failures: 2,
        ..upkeep
    });
    let receipt = claude_worker_receipt_status(
        &slot,
        &slot,
        ClaudeWorkerDiagnostic::IdentityFailed(ClaudeLocalIdentityFailure::IdentityUnknown),
        "2026-08-05T02:30:00Z",
        now,
    )
    .unwrap();
    let mut without_receipt = receipt.clone();
    without_receipt.quota_check_diagnostics = slot.collection.quota_check_diagnostics.clone();
    assert_eq!(without_receipt, slot.collection);
    let local = receipt.quota_check_diagnostics.last().unwrap();
    assert_eq!(local.observed_at.as_deref(), Some("2026-08-05T02:30:00Z"));
    assert_eq!(
        local.account_identifier_hash,
        slot.collection.account_identifier_hash
    );
    assert_eq!(
        local.organization_identifier_hash,
        slot.collection.organization_identifier_hash
    );
    assert!(local.code.starts_with("claude_slot_worker_"));
    assert!(!local.code.starts_with("claude_oauth_usage_"));
}

#[test]
fn claude_worker_receipt_refuses_every_changed_descriptor_and_newer_observation() {
    let (slot, _, _, now) = valid_access_reconciliation_fixture();
    for mutation in 0..9 {
        let mut current = slot.clone();
        match mutation {
            0 => current.config_dir = Some("/fixture/other-root".to_string()),
            1 => current.slot_id = "other-slot".to_string(),
            2 => current.service_name = "other-service".to_string(),
            3 => current.ownership = ClaudeConfigSlotOwnership::Managed,
            4 => current.collection.account_identifier_hash = Some("other-account".to_string()),
            5 => current.collection.organization_identifier_hash = Some("other-org".to_string()),
            6 => current.collection.access_expires_at = Some("2026-08-05T02:01:00Z".to_string()),
            7 => current.collection.relogin_required_at = None,
            _ => current.collection.observed_at = Some("2026-08-05T02:30:01Z".to_string()),
        }
        assert!(
            claude_worker_receipt_status(
                &slot,
                &current,
                ClaudeWorkerDiagnostic::ReconciliationRefused,
                "2026-08-05T02:30:00Z",
                now
            )
            .is_none(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn claude_worker_receipt_refuses_missing_fence_future_and_older_result_clocks() {
    let (mut slot, _, _, now) = valid_access_reconciliation_fixture();
    for completed in ["invalid", "2026-08-05T02:30:01Z"] {
        assert!(claude_worker_receipt_status(
            &slot,
            &slot,
            ClaudeWorkerDiagnostic::Reconciled,
            completed,
            now
        )
        .is_none());
    }
    append_claude_worker_diagnostic(
        &mut slot.collection,
        ClaudeWorkerDiagnostic::Observed(ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable),
        "2026-08-05T02:30:00Z",
        now,
    )
    .unwrap();
    assert!(claude_worker_receipt_status(
        &slot,
        &slot,
        ClaudeWorkerDiagnostic::Reconciled,
        "2026-08-05T02:29:59Z",
        now
    )
    .is_none());
    slot.collection.organization_identifier_hash = None;
    assert!(claude_worker_receipt_status(
        &slot,
        &slot,
        ClaudeWorkerDiagnostic::Reconciled,
        "2026-08-05T02:30:00Z",
        now
    )
    .is_none());
}

#[test]
fn claude_worker_receipt_exact_binding_sanitizer_is_closed_and_never_provider_success() {
    use ClaudeConfigSlotUpkeepResultV1 as R;
    let (slot, _, _, now) = valid_access_reconciliation_fixture();
    let mut outcomes = [
        R::NotRequired,
        R::RefreshDue,
        R::Refreshed,
        R::UpkeepNotConsented,
        R::CollectionPaused,
        R::UpkeepDisabled,
        R::Backoff,
        R::MissingBinary,
        R::SpawnFailed,
        R::TimedOut,
        R::NonzeroExit,
        R::CredentialUnreadable,
        R::ExpiryUnchanged,
        R::ProbeFailed,
        R::ReloginApproaching,
        R::NeedsLogin,
        R::InProgress,
    ]
    .into_iter()
    .map(ClaudeWorkerDiagnostic::Observed)
    .collect::<Vec<_>>();
    outcomes.extend([
        ClaudeWorkerDiagnostic::ReconciliationRefused,
        ClaudeWorkerDiagnostic::Reconciled,
    ]);
    outcomes.extend(
        [
            ClaudeLocalIdentityFailure::IdentityUnknown,
            ClaudeLocalIdentityFailure::CredentialUnavailable,
            ClaudeLocalIdentityFailure::IdentityMismatch,
            ClaudeLocalIdentityFailure::ConcurrentMutation,
        ]
        .into_iter()
        .map(ClaudeWorkerDiagnostic::IdentityFailed),
    );
    for outcome in outcomes {
        let status =
            claude_worker_receipt_status(&slot, &slot, outcome, "2026-08-05T02:30:00Z", now)
                .unwrap();
        let diagnostics = safe_claude_slot_check_diagnostics(
            &status.quota_check_diagnostics,
            "account-a",
            "org-a",
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, outcome.code());
        assert_eq!(
            diagnostics[0].observed_at.as_deref(),
            Some("2026-08-05T02:30:00Z")
        );
        assert!(diagnostics[0].code.starts_with("claude_slot_worker_"));
        assert_ne!(diagnostics[0].code, "claude_oauth_usage_check_succeeded");
        assert!(
            safe_claude_slot_check_diagnostics(&diagnostics, "account-a", "foreign-org").is_empty()
        );
        let mut forged = diagnostics[0].clone();
        forged.code = "claude_slot_worker_arbitrary_secret".to_string();
        assert!(safe_claude_slot_check_diagnostics(&[forged], "account-a", "org-a").is_empty());
    }
}

#[test]
fn claude_worker_receipt_travels_on_winning_default_snapshot_for_same_exact_binding() {
    let (slot, _, _, now) = valid_access_reconciliation_fixture();
    let mut anchor = claude_worker_receipt_status(
        &slot,
        &slot,
        ClaudeWorkerDiagnostic::ReconciliationRefused,
        "2026-08-05T02:30:00Z",
        now,
    )
    .unwrap();
    anchor.quota_check_diagnostics.push(
        claude_quota_check_diagnostic("claude_oauth_usage_cache_reused", "anchor cache", 1)
            .with_quota_binding(Some("account-a".to_string()), Some("org-a".to_string())),
    );
    let binding = ClaudeStrongBinding::new("account-a", "org-a").unwrap();
    let canonical = BTreeMap::from([(binding.clone(), slot.slot_id.clone())]);
    let slot_states = BTreeMap::from([(slot.slot_id.clone(), anchor.clone())]);
    let worker_codes = |snapshot: &AgentStatusSnapshot| {
        snapshot
            .diagnostics
            .iter()
            .filter(|diagnostic| claude_worker_diagnostic_message(&diagnostic.code).is_some())
            .cloned()
            .collect::<Vec<_>>()
    };

    let mut default =
        claude_account_snapshot("a@example.com", "claude_max_20x", "account-a", "org-a");
    let before = default.diagnostics.len();
    append_canonical_anchor_worker_receipts(
        &mut default,
        "default",
        &binding,
        &canonical,
        &slot_states,
    );
    let carried = worker_codes(&default);
    assert_eq!(carried.len(), 1);
    assert_eq!(carried[0].code, "claude_slot_worker_reconciliation_refused");
    assert_eq!(
        carried[0].observed_at.as_deref(),
        Some("2026-08-05T02:30:00Z")
    );
    assert_eq!(
        carried[0].account_identifier_hash.as_deref(),
        Some("account-a")
    );
    assert_eq!(
        carried[0].organization_identifier_hash.as_deref(),
        Some("org-a")
    );
    // Only the closed worker receipt travels; the anchor's provider-check
    // evidence is never re-presented as the default slot's own check.
    assert_eq!(default.diagnostics.len(), before + 1);
    assert!(!default
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message == "anchor cache"));

    // Idempotent: a second pass never duplicates the single receipt.
    append_canonical_anchor_worker_receipts(
        &mut default,
        "default",
        &binding,
        &canonical,
        &slot_states,
    );
    assert_eq!(worker_codes(&default).len(), 1);

    // The anchor uploading itself, a foreign snapshot pair, a foreign
    // anchor pair, and a missing anchor state carry nothing.
    let mut itself =
        claude_account_snapshot("a@example.com", "claude_max_20x", "account-a", "org-a");
    append_canonical_anchor_worker_receipts(
        &mut itself,
        &slot.slot_id,
        &binding,
        &canonical,
        &slot_states,
    );
    assert!(worker_codes(&itself).is_empty());
    let mut foreign =
        claude_account_snapshot("b@example.com", "claude_max_20x", "account-a", "org-b");
    append_canonical_anchor_worker_receipts(
        &mut foreign,
        "default",
        &binding,
        &canonical,
        &slot_states,
    );
    assert!(worker_codes(&foreign).is_empty());
    let mut rebound_anchor = anchor.clone();
    rebound_anchor.organization_identifier_hash = Some("org-b".to_string());
    let rebound_states = BTreeMap::from([(slot.slot_id.clone(), rebound_anchor)]);
    let mut rebound =
        claude_account_snapshot("a@example.com", "claude_max_20x", "account-a", "org-a");
    append_canonical_anchor_worker_receipts(
        &mut rebound,
        "default",
        &binding,
        &canonical,
        &rebound_states,
    );
    assert!(worker_codes(&rebound).is_empty());
    let mut missing =
        claude_account_snapshot("a@example.com", "claude_max_20x", "account-a", "org-a");
    append_canonical_anchor_worker_receipts(
        &mut missing,
        "default",
        &binding,
        &canonical,
        &BTreeMap::new(),
    );
    assert!(worker_codes(&missing).is_empty());

    // A forged worker-looking code on the anchor stays rejected.
    let mut forged_anchor = anchor;
    forged_anchor.quota_check_diagnostics = vec![AgentStatusDiagnostic::source(
        "claude_slot_worker_arbitrary_secret",
        AgentDiagnosticSeverity::Info,
        "forged",
    )
    .with_observed_at(Some("2026-08-05T02:30:00Z".to_string()))
    .with_quota_binding(Some("account-a".to_string()), Some("org-a".to_string()))];
    let forged_states = BTreeMap::from([(slot.slot_id.clone(), forged_anchor)]);
    let mut forged =
        claude_account_snapshot("a@example.com", "claude_max_20x", "account-a", "org-a");
    append_canonical_anchor_worker_receipts(
        &mut forged,
        "default",
        &binding,
        &canonical,
        &forged_states,
    );
    assert!(forged
        .diagnostics
        .iter()
        .all(|diagnostic| !diagnostic.code.starts_with("claude_slot_worker_")));
}

fn blocked_anchor_with_worker_receipt(
    code: &str,
    access_expires_at: OffsetDateTime,
    receipt_at: OffsetDateTime,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let (slot, _, _, _) = valid_access_reconciliation_fixture();
    let mut status = slot.collection;
    status.state = ClaudeConfigSlotCollectionStateV1::RefreshDue;
    status.observed_at = Some(rfc3339_from_offset(receipt_at - TimeDuration::minutes(1)));
    status.access_expires_at = Some(rfc3339_from_offset(access_expires_at));
    status.quota_check_diagnostics = vec![AgentStatusDiagnostic::source(
        code,
        AgentDiagnosticSeverity::Info,
        claude_worker_diagnostic_message(code).unwrap_or("forged"),
    )
    .with_observed_at(Some(rfc3339_from_offset(receipt_at)))
    .with_quota_binding(Some("account-a".to_string()), Some("org-a".to_string()))];
    status
}

fn rfc3339_from_offset(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap()
}

#[test]
fn blocked_anchor_worker_receipt_escalates_saved_health_truthfully() {
    let now = OffsetDateTime::now_utc();
    let week_ago = now - TimeDuration::days(8);
    let receipt_at = now - TimeDuration::minutes(5);
    let project = |status: &ClaudeConfigSlotCollectionStatusV1| {
        projected_claude_quota_access_state(status).unwrap()
    };

    // A worker that read a signed-out refresh grant: sign in again.
    assert_eq!(
        project(&blocked_anchor_with_worker_receipt(
            "claude_slot_worker_needs_login",
            week_ago,
            receipt_at,
        )),
        ClaudeQuotaAccessState::ReconnectRequired
    );
    // A refresh that keeps failing for over a day names attention.
    for code in CLAUDE_BLOCKED_REFRESH_FAILURE_WORKER_CODES {
        assert_eq!(
            project(&blocked_anchor_with_worker_receipt(
                code, week_ago, receipt_at
            )),
            ClaudeQuotaAccessState::AttentionRequired,
            "{code}"
        );
    }
    // Within the first day, or after a non-failure pass, it stays temporary.
    assert_eq!(
        project(&blocked_anchor_with_worker_receipt(
            "claude_slot_worker_expiry_unchanged",
            now - TimeDuration::hours(2),
            receipt_at,
        )),
        ClaudeQuotaAccessState::TemporarilyUnavailable
    );
    for code in [
        "claude_slot_worker_refresh_due",
        "claude_slot_worker_in_progress",
        "claude_slot_worker_metadata_reconciled",
        "claude_slot_worker_refreshed",
    ] {
        assert_eq!(
            project(&blocked_anchor_with_worker_receipt(
                code, week_ago, receipt_at
            )),
            ClaudeQuotaAccessState::TemporarilyUnavailable,
            "{code}"
        );
    }
    // Forged, foreign-pair and future receipts never escalate.
    let forged = blocked_anchor_with_worker_receipt(
        "claude_slot_worker_needs_login_forged",
        week_ago,
        receipt_at,
    );
    assert_eq!(
        project(&forged),
        ClaudeQuotaAccessState::TemporarilyUnavailable
    );
    let mut foreign =
        blocked_anchor_with_worker_receipt("claude_slot_worker_needs_login", week_ago, receipt_at);
    foreign.quota_check_diagnostics[0].organization_identifier_hash = Some("org-b".to_string());
    assert_eq!(
        project(&foreign),
        ClaudeQuotaAccessState::TemporarilyUnavailable
    );
    let future = blocked_anchor_with_worker_receipt(
        "claude_slot_worker_needs_login",
        week_ago,
        now + TimeDuration::hours(1),
    );
    assert_eq!(
        project(&future),
        ClaudeQuotaAccessState::TemporarilyUnavailable
    );
    // Collected states never consult the worker receipt.
    let mut fresh =
        blocked_anchor_with_worker_receipt("claude_slot_worker_needs_login", week_ago, receipt_at);
    fresh.state = ClaudeConfigSlotCollectionStateV1::Fresh;
    assert_eq!(project(&fresh), ClaudeQuotaAccessState::Full);
    let mut provider =
        blocked_anchor_with_worker_receipt("claude_slot_worker_needs_login", week_ago, receipt_at);
    provider.state = ClaudeConfigSlotCollectionStateV1::ProviderUnavailable;
    assert_eq!(
        project(&provider),
        ClaudeQuotaAccessState::TemporarilyUnavailable
    );
}

/// The collection loop's real upload step: the CLI default supplies the
/// pair's meters while its canonical saved anchor is blocked. The uploaded
/// snapshot must carry the anchor's truthful health and its worker reason.
#[test]
fn uploaded_default_candidate_carries_blocked_anchor_health_and_reason() {
    let now = OffsetDateTime::now_utc();
    let binding = ClaudeStrongBinding::new("account-a", "org-a").unwrap();
    let anchor_slot = "claude_slot_anchor".to_string();
    let canonical = BTreeMap::from([(binding.clone(), anchor_slot.clone())]);
    let upload = |anchor: ClaudeConfigSlotCollectionStatusV1| {
        let slot_states = BTreeMap::from([(anchor_slot.clone(), anchor)]);
        let health = canonical_anchor_health(&canonical, &slot_states);
        let snapshot =
            claude_account_snapshot("a@example.com", "claude_max_20x", "account-a", "org-a");
        claude_uploaded_candidate_snapshot(
            ClaudeSnapshotCandidate {
                slot_id: "default".to_string(),
                slot_class: ClaudeSnapshotSlotClass::Default,
                binding: binding.clone(),
                quality: ClaudeSnapshotQuality {
                    tier: 4,
                    provider_observed_at: String::new(),
                },
                snapshot,
            },
            &health,
            &canonical,
            &slot_states,
            &BTreeSet::new(),
        )
    };
    let account = |snapshot: &AgentStatusSnapshot| snapshot.account.clone().unwrap();

    let signed_out = upload(blocked_anchor_with_worker_receipt(
        "claude_slot_worker_needs_login",
        now - TimeDuration::days(8),
        now - TimeDuration::minutes(5),
    ));
    assert_eq!(
        account(&signed_out).claude_anchor_durability,
        Some(ClaudeAccountAnchorDurabilityV1::Anchored)
    );
    assert_eq!(
        account(&signed_out).claude_anchor_health,
        Some(ClaudeAccountAnchorHealthV1::ReconnectRequired)
    );
    assert!(signed_out
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_slot_worker_needs_login"));

    let stuck = upload(blocked_anchor_with_worker_receipt(
        "claude_slot_worker_expiry_unchanged",
        now - TimeDuration::days(8),
        now - TimeDuration::minutes(5),
    ));
    assert_eq!(
        account(&stuck).claude_anchor_health,
        Some(ClaudeAccountAnchorHealthV1::AttentionRequired)
    );
    assert!(stuck
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_slot_worker_expiry_unchanged"));

    let recent = upload(blocked_anchor_with_worker_receipt(
        "claude_slot_worker_refresh_due",
        now - TimeDuration::hours(1),
        now - TimeDuration::minutes(5),
    ));
    assert_eq!(
        account(&recent).claude_anchor_health,
        Some(ClaudeAccountAnchorHealthV1::TemporarilyUnavailable)
    );
}

#[test]
fn claude_worker_receipt_reconciliation_success_changes_only_existing_metadata_plus_local_receipt()
{
    let (slot, upkeep, proof, now) = valid_access_reconciliation_fixture();
    let mut accepted =
        reconciled_valid_access_status(&slot, &slot, &upkeep, &proof, "2026-08-05T02:30:00Z", now)
            .unwrap();
    let expected = accepted.clone();
    append_claude_worker_diagnostic(
        &mut accepted,
        ClaudeWorkerDiagnostic::Reconciled,
        "2026-08-05T02:30:00Z",
        now,
    )
    .unwrap();
    let sanitized =
        safe_claude_slot_check_diagnostics(&accepted.quota_check_diagnostics, "account-a", "org-a");
    assert_eq!(sanitized[0].code, "claude_slot_worker_metadata_reconciled");
    accepted.quota_check_diagnostics = expected.quota_check_diagnostics.clone();
    assert_eq!(accepted, expected);
    assert_eq!(
        accepted.last_full_quota_read_at,
        slot.collection.last_full_quota_read_at
    );
    assert_eq!(accepted.quota_snapshot, slot.collection.quota_snapshot);
    assert_eq!(
        accepted.state,
        ClaudeConfigSlotCollectionStateV1::RefreshDue
    );
    assert!(accepted.upkeep.unwrap().attempted_at.is_none());
}

#[test]
#[serial]
fn claude_worker_receipt_survives_next_blocked_collection_roundtrip() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-worker-receipt-{}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("new isolated fixture root");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    let (slot, mut upkeep, _, now) = valid_access_reconciliation_fixture();
    let receipt = claude_worker_receipt_status(
        &slot,
        &slot,
        ClaudeWorkerDiagnostic::ReconciliationRefused,
        "2026-08-05T02:30:00Z",
        now,
    )
    .unwrap();
    persist_one_claude_slot_collection_state(&slot.slot_id, &receipt).unwrap();
    upkeep.result = ClaudeConfigSlotUpkeepResultV1::RefreshDue;
    upkeep.due_access_expires_at = slot.collection.access_expires_at.clone();
    let blocked = blocked_claude_upkeep_status(&slot.slot_id, "2026-08-05T02:31:00Z", upkeep);
    persist_one_claude_slot_collection_state(&slot.slot_id, &blocked).unwrap();
    let persisted = read_persisted_claude_slot_collection_state();
    let status = persisted.slots.get(&slot.slot_id).unwrap();
    let safe =
        safe_claude_slot_check_diagnostics(&status.quota_check_diagnostics, "account-a", "org-a");
    assert_eq!(safe.len(), 1);
    assert_eq!(safe[0].code, "claude_slot_worker_reconciliation_refused");
    assert_eq!(safe[0].observed_at.as_deref(), Some("2026-08-05T02:30:00Z"));
    assert_eq!(
        status.last_full_quota_read_at,
        slot.collection.last_full_quota_read_at
    );
    assert_eq!(status.access_expires_at, slot.collection.access_expires_at);
    assert_eq!(status.state, ClaudeConfigSlotCollectionStateV1::RefreshDue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn claude_worker_receipt_superseded_diagnostic_cannot_block_valid_metadata_advancement() {
    let (mut slot, upkeep, proof, now) = valid_access_reconciliation_fixture();
    append_claude_worker_diagnostic(
        &mut slot.collection,
        ClaudeWorkerDiagnostic::Observed(ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable),
        "2026-08-05T02:30:00Z",
        now,
    )
    .unwrap();
    let completed = "2026-08-05T02:29:59Z";
    assert!(
        claude_worker_receipt_status(
            &slot,
            &slot,
            ClaudeWorkerDiagnostic::Reconciled,
            completed,
            now
        )
        .is_none(),
        "diagnostic-only old result refused"
    );
    let expected =
        reconciled_valid_access_status(&slot, &slot, &upkeep, &proof, completed, now).unwrap();
    let accepted = reconciled_valid_access_status_with_worker_receipt(
        &slot, &slot, &upkeep, &proof, completed, now,
    )
    .unwrap();
    assert_eq!(
        accepted, expected,
        "original valid proof advances metadata; newer local receipt unchanged"
    );
    assert_eq!(
        accepted.access_expires_at,
        proof.collection.access_expires_at
    );
    assert_eq!(
        accepted
            .quota_check_diagnostics
            .last()
            .unwrap()
            .observed_at
            .as_deref(),
        Some("2026-08-05T02:30:00Z")
    );
    assert_eq!(
        accepted.state,
        ClaudeConfigSlotCollectionStateV1::RefreshDue
    );
    assert_eq!(
        accepted.last_full_quota_read_at,
        slot.collection.last_full_quota_read_at
    );
}

#[test]
fn claude_worker_receipt_blocked_retention_requires_complete_fence_and_local_clock_precedence() {
    let (mut slot, _, _, now) = valid_access_reconciliation_fixture();
    let mut stale = slot.collection.clone();
    stale.observed_at = Some("2026-08-05T02:29:00Z".to_string());
    append_claude_worker_diagnostic(
        &mut slot.collection,
        ClaudeWorkerDiagnostic::ReconciliationRefused,
        "2026-08-05T02:30:00Z",
        now,
    )
    .unwrap();
    for mutation in 0..12 {
        let mut current = slot.clone();
        let mut candidate = stale.clone();
        match mutation {
            0 => current.config_dir = Some("/fixture/changed".to_string()),
            1 => current.slot_id = "changed".to_string(),
            2 => current.service_name = "changed".to_string(),
            3 => current.ownership = ClaudeConfigSlotOwnership::Managed,
            4 => current.collection.organization_identifier_hash = Some("foreign".to_string()),
            5 => current.collection.access_expires_at = Some("2026-08-05T03:00:00Z".to_string()),
            6 => current.collection.relogin_required_at = None,
            7 => candidate.state = ClaudeConfigSlotCollectionStateV1::Fresh,
            8 => candidate.state = ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            9 => candidate.account_identifier_hash = Some("foreign".to_string()),
            10 => candidate.access_expires_at = Some("2026-08-05T03:00:00Z".to_string()),
            _ => current.collection.observed_at = Some("2026-08-05T02:30:01Z".to_string()),
        }
        let original = candidate.clone();
        retain_claude_worker_receipt_for_blocked_candidate(&slot, &current, &mut candidate, now);
        assert_eq!(candidate, original, "negative fence {mutation}");
    }
    let mut same = stale.clone();
    retain_claude_worker_receipt_for_blocked_candidate(&slot, &slot, &mut same, now);
    assert_eq!(
        same.quota_check_diagnostics.last().unwrap().code,
        "claude_slot_worker_reconciliation_refused"
    );
    for state in [
        ClaudeConfigSlotCollectionStateV1::Fresh,
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
    ] {
        let mut current = slot.clone();
        current.collection.state = state;
        let mut candidate = stale.clone();
        retain_claude_worker_receipt_for_blocked_candidate(&slot, &current, &mut candidate, now);
        assert_eq!(
            candidate.quota_check_diagnostics.last().unwrap().code,
            "claude_slot_worker_reconciliation_refused",
            "old saved enum is not new collection proof"
        );
    }
    let mut newer_collection = slot.clone();
    newer_collection.collection.observed_at = Some("2026-08-05T02:30:00Z".to_string());
    newer_collection
        .collection
        .quota_check_diagnostics
        .last_mut()
        .unwrap()
        .observed_at = Some("2026-08-05T02:29:59Z".to_string());
    let mut candidate = stale.clone();
    retain_claude_worker_receipt_for_blocked_candidate(
        &slot,
        &newer_collection,
        &mut candidate,
        now,
    );
    assert_eq!(
        candidate, stale,
        "older local receipt cannot cross genuinely newer collection"
    );
    let mut newer = stale.clone();
    append_claude_worker_diagnostic(
        &mut newer,
        ClaudeWorkerDiagnostic::Observed(ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable),
        "2026-08-05T02:30:00Z",
        now,
    )
    .unwrap();
    let original = newer.clone();
    retain_claude_worker_receipt_for_blocked_candidate(&slot, &slot, &mut newer, now);
    assert_eq!(newer, original, "equal/newer actual local receipt wins");
    append_claude_worker_diagnostic(
        &mut newer,
        ClaudeWorkerDiagnostic::Observed(ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable),
        "2026-08-05T02:30:01Z",
        now + time::Duration::seconds(1),
    )
    .unwrap();
    let original = newer.clone();
    retain_claude_worker_receipt_for_blocked_candidate(
        &slot,
        &slot,
        &mut newer,
        now + time::Duration::seconds(1),
    );
    assert_eq!(newer, original, "genuinely newer local receipt wins");
}

#[test]
#[serial]
fn claude_worker_receipt_stale_clone_worker_batch_interleaving_is_fenced_at_lock_time() {
    use ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION;
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-worker-interleaving-{}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    let config = root.join("registered");
    fs::create_dir(&config).unwrap();
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_path(
            CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            config.to_string_lossy().into_owned(),
        )
        .unwrap();
    store
        .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, true)
        .unwrap();
    let mut slot = registered.external_slots[0].clone();
    let (fixture, mut upkeep, _, _) = valid_access_reconciliation_fixture();
    slot.collection = fixture.collection;
    slot.collection.state = ClaudeConfigSlotCollectionStateV1::Fresh;
    upkeep.result = ClaudeConfigSlotUpkeepResultV1::RefreshDue;
    upkeep.due_access_expires_at = slot.collection.access_expires_at.clone();
    persist_one_claude_slot_collection_state(&slot.slot_id, &slot.collection).unwrap();
    // First expiry: saved enum is still Fresh; the actual blocked branch
    // makes RefreshDue before the t2 worker's diagnostic-only publication.
    let stale = blocked_claude_upkeep_status(&slot.slot_id, "2026-08-05T02:29:00Z", upkeep);
    assert_eq!(stale.state, ClaudeConfigSlotCollectionStateV1::RefreshDue);
    record_registered_claude_worker_observation(
        &slot,
        ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
    );
    let worker = read_persisted_claude_slot_collection_state().slots[&slot.slot_id].clone();
    assert_eq!(worker.state, ClaudeConfigSlotCollectionStateV1::Fresh);
    let receipt = worker.quota_check_diagnostics.last().unwrap().clone();
    assert_eq!(receipt.code, "claude_slot_worker_credential_unreadable");
    let candidates = BTreeMap::from([(slot.slot_id.clone(), stale.clone())]);
    let descriptors = BTreeMap::from([(slot.slot_id.clone(), slot.clone())]);
    // t3: real delayed batch owner sees lock-time receipt, not stale clone.
    persist_claude_slot_collection_states(&candidates, &[], &descriptors).unwrap();
    let merged = read_persisted_claude_slot_collection_state().slots[&slot.slot_id].clone();
    assert_eq!(merged.quota_check_diagnostics.last(), Some(&receipt));
    let mut expected = stale.clone();
    expected.quota_check_diagnostics.push(receipt.clone());
    assert_eq!(merged, expected);

    // Suppression may commit after clone/publication but before batch lock.
    fs::write(root.join("claude-browser-auth-state.json"), b"{corrupt").unwrap();
    persist_claude_slot_collection_states(&candidates, &[], &descriptors).unwrap();
    let suppressed = read_persisted_claude_slot_collection_state().slots[&slot.slot_id].clone();
    assert_eq!(
        suppressed.quota_check_diagnostics,
        stale.quota_check_diagnostics
    );
    fs::remove_file(root.join("claude-browser-auth-state.json")).unwrap();
    // No descriptor transport for a genuine/new provider collection.
    let mut worker = worker;
    worker.observed_at = stale.observed_at.clone();
    persist_one_claude_slot_collection_state(&slot.slot_id, &worker).unwrap();
    assert!(
        read_persisted_claude_slot_collection_state().slots[&slot.slot_id]
            .quota_check_diagnostics
            .iter()
            .any(|entry| claude_worker_diagnostic_message(&entry.code).is_some())
    );
    let mut fresh = stale.clone();
    fresh.state = ClaudeConfigSlotCollectionStateV1::Fresh;
    persist_claude_slot_collection_states(
        &BTreeMap::from([(slot.slot_id.clone(), fresh)]),
        &[],
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(
        !read_persisted_claude_slot_collection_state().slots[&slot.slot_id]
            .quota_check_diagnostics
            .iter()
            .any(|entry| claude_worker_diagnostic_message(&entry.code).is_some())
    );
    let before = read_persisted_claude_slot_collection_state().slots.clone();
    fs::write(store.path(), b"{corrupt").unwrap();
    assert!(
        persist_claude_slot_collection_states(&candidates, &[], &descriptors).is_err(),
        "unavailable registration is surfaced, never unsafe retention success"
    );
    assert_eq!(read_persisted_claude_slot_collection_state().slots, before);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn claude_worker_receipt_publication_respects_controls_rebind_and_removal() {
    use ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION;
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-worker-publication-{}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("new isolated fixture root");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    let config = root.join("registered");
    fs::create_dir(&config).unwrap();
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_path(
            CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            config.to_string_lossy().into_owned(),
        )
        .unwrap();
    let mut slot = registered.external_slots[0].clone();
    slot.collection = valid_access_reconciliation_fixture().0.collection;
    persist_one_claude_slot_collection_state(&slot.slot_id, &slot.collection).unwrap();
    // "Keep my Claude accounts signed in" defaults on; turn it off first.
    store
        .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, false)
        .unwrap();
    let publish = || {
        record_registered_claude_worker_observation(
            &slot,
            ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
        )
    };
    let unchanged = || {
        assert_eq!(
            read_persisted_claude_slot_collection_state()
                .slots
                .get(&slot.slot_id),
            Some(&slot.collection)
        )
    };
    publish();
    unchanged(); // Consent not granted.
    store
        .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, true)
        .unwrap();
    fs::write(
        root.join(CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE),
        b"disabled",
    )
    .unwrap();
    publish();
    unchanged();
    fs::remove_file(root.join(CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE)).unwrap();
    fs::write(
        root.join(crate::claude_upkeep::UPKEEP_DISABLED_FILE),
        b"disabled",
    )
    .unwrap();
    publish();
    unchanged();
    fs::remove_file(root.join(crate::claude_upkeep::UPKEEP_DISABLED_FILE)).unwrap();
    fs::write(root.join("claude-browser-auth-state.json"), b"{corrupt").unwrap();
    publish();
    unchanged();
    fs::remove_file(root.join("claude-browser-auth-state.json")).unwrap();
    publish();
    let receipt = read_persisted_claude_slot_collection_state().slots[&slot.slot_id].clone();
    assert_eq!(
        receipt.quota_check_diagnostics.last().unwrap().code,
        "claude_slot_worker_credential_unreadable"
    );
    let mut rebound = receipt.clone();
    rebound.organization_identifier_hash = Some("other-org".to_string());
    rebound.observed_at = Some(crate::current_rfc3339_timestamp());
    rebound.quota_check_diagnostics.clear();
    persist_one_claude_slot_collection_state(&slot.slot_id, &rebound).unwrap();
    publish();
    assert_eq!(
        read_persisted_claude_slot_collection_state().slots[&slot.slot_id],
        rebound
    );
    store
        .remove(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, &slot.slot_id)
        .unwrap();
    let removed = read_persisted_claude_slot_collection_state();
    publish();
    assert_eq!(
        serde_json::to_value(read_persisted_claude_slot_collection_state()).unwrap(),
        serde_json::to_value(removed).unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}

/// AutoReview P2 on 83657166: an admitted fresh login whose first quota
/// read is unavailable must still become the canonical anchor over a dead
/// slot that only has older complete limits, in both the collector's
/// selection and the persisted anchor coverage readers use.
#[test]
fn usable_connection_outranks_dead_slot_with_complete_history_for_canonical_anchor() {
    use ClaudeConfigSlotCollectionStateV1 as State;
    let now = OffsetDateTime::now_utc();
    let at = |offset: TimeDuration| (now + offset).format(&Rfc3339).unwrap();
    let complete = |state: State, access: TimeDuration| {
        let mut status = fresh_slot_status(
            "2026-09-24T12:21:06Z",
            "account-a",
            "org-a",
            true,
            true,
            true,
        );
        status.state = state;
        status.access_expires_at = Some(at(access));
        status.relogin_required_at = Some(at(TimeDuration::days(7)));
        status.last_full_quota_read_at = Some("2026-09-24T12:21:06Z".to_string());
        status.quota_snapshot = Some(local_meter_fixture("account-a", "org-a"));
        status
    };
    let dead = |state: State| complete(state, -TimeDuration::days(8));
    let working = |state: State| {
        let mut status = fresh_slot_status(
            &at(TimeDuration::ZERO),
            "account-a",
            "org-a",
            false,
            false,
            false,
        );
        status.state = state;
        status.access_expires_at = Some(at(TimeDuration::hours(8)));
        status.relogin_required_at = Some(at(TimeDuration::days(30)));
        status
    };
    let binding = ClaudeStrongBinding::new("account-a", "org-a").unwrap();
    // Slot ids sort the old slot first so a tie would keep it.
    let pick = |old: ClaudeConfigSlotCollectionStatusV1,
                new: ClaudeConfigSlotCollectionStatusV1| {
        let states = BTreeMap::from([
            ("claude_slot_a_old".to_string(), old),
            ("claude_slot_b_new".to_string(), new),
        ]);
        canonical_registered_anchors(states.keys().cloned().collect::<Vec<_>>(), &states)[&binding]
            .clone()
    };
    for dead_state in [
        State::NeedsLogin,
        State::RefreshDue,
        State::StaleAccessToken,
        State::CredentialUnavailable,
        State::IdentityMismatch,
        // Failed refreshes on an expired credential are presented with
        // shared enums; the expired deadline still makes them dead.
        State::ProbeFailed,
        State::ProviderUnavailable,
        State::Fresh,
    ] {
        for working_state in [
            State::ProviderUnavailable,
            State::Fresh,
            State::CollectionPaused,
            State::ProbeFailed,
        ] {
            assert_eq!(
                pick(dead(dead_state.clone()), working(working_state.clone())),
                "claude_slot_b_new",
                "{dead_state:?} vs {working_state:?}"
            );
        }
    }
    // A failed refresh (timed out / expiry unchanged) mapped to
    // `probe_failed` on an expired credential stays below the fresh login.
    for failed in [
        ClaudeConfigSlotUpkeepResultV1::TimedOut,
        ClaudeConfigSlotUpkeepResultV1::ExpiryUnchanged,
        ClaudeConfigSlotUpkeepResultV1::MissingBinary,
    ] {
        let mut old = dead(upkeep_state_diagnostic(failed).0);
        old.upkeep = Some(ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            result: failed,
            due_access_expires_at: old.access_expires_at.clone(),
            refresh_token_expires_at: old.relogin_required_at.clone(),
            attempted_at: Some(at(-TimeDuration::minutes(1))),
            next_allowed_attempt_at: Some(at(TimeDuration::minutes(19))),
            consecutive_failures: 3,
        });
        assert_eq!(
            pick(old, working(State::ProviderUnavailable)),
            "claude_slot_b_new",
            "{failed:?}"
        );
    }
    // A passed refresh deadline or a sign-in upkeep outcome is dead even
    // with an unexpired access deadline.
    let mut relogin_passed = complete(State::ProviderUnavailable, TimeDuration::hours(1));
    relogin_passed.relogin_required_at = Some(at(-TimeDuration::hours(1)));
    assert_eq!(
        pick(relogin_passed, working(State::ProviderUnavailable)),
        "claude_slot_b_new"
    );
    // Among usable slots, meter quality still decides: a valid credential
    // with a transient probe failure keeps its complete limits.
    assert_eq!(
        pick(
            complete(State::ProbeFailed, TimeDuration::hours(1)),
            working(State::ProviderUnavailable)
        ),
        "claude_slot_a_old"
    );
    assert_eq!(
        pick(
            complete(State::Fresh, TimeDuration::hours(1)),
            working(State::ProviderUnavailable)
        ),
        "claude_slot_a_old"
    );
    // A slot labelled duplicate by an earlier selection never takes the
    // anchor back.
    assert_eq!(
        pick(dead(State::RefreshDue), working(State::DuplicateAccount)),
        "claude_slot_a_old"
    );
    assert_eq!(
        pick(
            complete(State::DuplicateAccount, TimeDuration::hours(1)),
            working(State::ProviderUnavailable)
        ),
        "claude_slot_b_new"
    );
}

/// Opus review F1 on 6d43ff24: the limits/upload choice must follow the
/// health-first canonical choice. An old slot with valid access but a
/// passed refresh deadline (fresh, complete limits, unusable) and a new
/// working login with partial limits: the new login is canonical, preferred
/// and uploads; the old slot is the duplicate, never the reverse.
#[test]
fn snapshot_selection_follows_health_first_canonical_anchor() {
    let now = OffsetDateTime::now_utc();
    let at = |offset: TimeDuration| (now + offset).format(&Rfc3339).unwrap();
    let mut old = fresh_slot_status(
        &at(-TimeDuration::minutes(2)),
        "account-a",
        "org-a",
        true,
        true,
        true,
    );
    old.access_expires_at = Some(at(TimeDuration::hours(3)));
    old.relogin_required_at = Some(at(-TimeDuration::hours(1)));
    let mut new = fresh_slot_status(
        &at(-TimeDuration::minutes(1)),
        "account-a",
        "org-a",
        true,
        false,
        false,
    );
    new.access_expires_at = Some(at(TimeDuration::hours(8)));
    new.relogin_required_at = Some(at(TimeDuration::days(30)));
    assert!(!claude_slot_connection_usable(&old, now));
    assert!(claude_slot_connection_usable(&new, now));
    assert!(claude_slot_projection_quality(&old) > claude_slot_projection_quality(&new));

    let binding = ClaudeStrongBinding::new("account-a", "org-a").unwrap();
    let slot_states = BTreeMap::from([
        ("claude_slot_a_old".to_string(), old.clone()),
        ("claude_slot_b_new".to_string(), new.clone()),
    ]);
    let candidate =
        |slot_id: &str, status: &ClaudeConfigSlotCollectionStatusV1| ClaudeSnapshotCandidate {
            slot_id: slot_id.to_string(),
            slot_class: ClaudeSnapshotSlotClass::Registered,
            binding: binding.clone(),
            quality: claude_slot_projection_quality(status),
            snapshot: claude_account_snapshot(
                "a@example.com",
                "claude_max_20x",
                "account-a",
                "org-a",
            ),
        };
    let candidates = vec![
        candidate("claude_slot_a_old", &old),
        candidate("claude_slot_b_new", &new),
    ];

    // The same order the collection loop uses.
    let canonical = canonical_registered_anchors(
        [
            "claude_slot_a_old".to_string(),
            "claude_slot_b_new".to_string(),
        ],
        &slot_states,
    );
    assert_eq!(canonical[&binding], "claude_slot_b_new");
    let selection = select_claude_snapshot_candidates(&candidates, &canonical);
    assert_eq!(selection.winning_by_binding[&binding], 1);
    assert_eq!(selection.preferred_anchor_by_binding[&binding], 1);
    let dispositions = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            claude_snapshot_candidate_disposition(index, candidate, &selection)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        dispositions,
        vec![
            ClaudeSnapshotDisposition::DuplicateRegistered,
            ClaudeSnapshotDisposition::Upload,
        ]
    );

    // Without a canonical map (no registered anchors) meter quality alone
    // still orders candidates, as before.
    let unanchored = select_claude_snapshot_candidates(&candidates, &BTreeMap::new());
    assert_eq!(unanchored.winning_by_binding[&binding], 0);
}

/// Live Gmail anchor, 2026-10-02: the worker read a signed-out
/// credential (expiry epoch) and published `needs_login`, but the saved
/// slot stayed `refresh_due`, so the companion never offered "Sign in
/// again". Exercise the real worker publication and the real blocked
/// collection persistence that the scheduled loop uses.
#[test]
#[serial]
fn claude_worker_needs_login_receipt_presents_saved_needs_login_through_real_paths() {
    use ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION;
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-worker-needs-login-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("new isolated fixture root");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    let config = root.join("registered");
    fs::create_dir(&config).unwrap();
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_path(
            CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            config.to_string_lossy().into_owned(),
        )
        .unwrap();
    store
        .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, true)
        .unwrap();
    let mut slot = registered.external_slots[0].clone();
    slot.collection = valid_access_reconciliation_fixture().0.collection;
    slot.collection.quota_check_diagnostics.clear();
    let blocked_upkeep = ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
        result: ClaudeConfigSlotUpkeepResultV1::RefreshDue,
        due_access_expires_at: slot.collection.access_expires_at.clone(),
        refresh_token_expires_at: slot.collection.relogin_required_at.clone(),
        attempted_at: None,
        next_allowed_attempt_at: None,
        consecutive_failures: 0,
    };
    slot.collection.upkeep = Some(blocked_upkeep.clone());
    persist_one_claude_slot_collection_state(&slot.slot_id, &slot.collection).unwrap();
    let saved = || read_persisted_claude_slot_collection_state().slots[&slot.slot_id].clone();
    let anchor_health = || {
        annotate_claude_accounts_status(store.load().unwrap())
            .anchor_coverage
            .accounts
            .iter()
            .find_map(|account| account.health)
    };
    assert_eq!(saved().state, ClaudeConfigSlotCollectionStateV1::RefreshDue);
    assert_eq!(
        anchor_health(),
        Some(ClaudeAccountAnchorHealthV1::TemporarilyUnavailable)
    );

    assert!(!reconcile_registered_claude_valid_access(
        &slot,
        &blocked_upkeep
    ));
    // Real worker publication of the pre-claim outcome.
    record_registered_claude_worker_observation(&slot, ClaudeConfigSlotUpkeepResultV1::NeedsLogin);
    let published = saved();
    assert_eq!(
        published.state,
        ClaudeConfigSlotCollectionStateV1::NeedsLogin
    );
    assert_eq!(
        published.diagnostics[0].code,
        ottto_protocol::ClaudeConfigSlotDiagnosticCodeV1::NeedsLogin
    );
    // The saved upkeep stays refresh-due: the foreground keeps queuing the
    // worker instead of taking the sticky saved-NeedsLogin early return.
    assert_eq!(
        published.upkeep.as_ref().map(|upkeep| upkeep.result),
        Some(ClaudeConfigSlotUpkeepResultV1::RefreshDue)
    );
    assert_eq!(
        published.access_expires_at,
        slot.collection.access_expires_at
    );
    assert_eq!(
        published.last_full_quota_read_at,
        slot.collection.last_full_quota_read_at
    );
    assert_eq!(
        anchor_health(),
        Some(ClaudeAccountAnchorHealthV1::ReconnectRequired)
    );

    // The next scheduled blocked collection rebuilds `refresh_due` from
    // the saved deadline; persisting it keeps the sign-in requirement.
    let mut descriptor = slot.clone();
    descriptor.collection = published.clone();
    let blocked = blocked_claude_upkeep_status(
        &slot.slot_id,
        &crate::current_rfc3339_timestamp(),
        blocked_upkeep.clone(),
    );
    assert_eq!(blocked.state, ClaudeConfigSlotCollectionStateV1::RefreshDue);
    persist_claude_slot_collection_states(
        &BTreeMap::from([(slot.slot_id.clone(), blocked)]),
        &[],
        &BTreeMap::from([(slot.slot_id.clone(), descriptor)]),
    )
    .unwrap();
    assert_eq!(saved().state, ClaudeConfigSlotCollectionStateV1::NeedsLogin);

    // A newer worker pass with another outcome replaces the receipt, and
    // the next blocked collection presents `refresh_due` again.
    let mut current = slot.clone();
    current.collection = saved();
    record_registered_claude_worker_observation(&current, ClaudeConfigSlotUpkeepResultV1::Backoff);
    let blocked = blocked_claude_upkeep_status(
        &slot.slot_id,
        &crate::current_rfc3339_timestamp(),
        blocked_upkeep,
    );
    persist_one_claude_slot_collection_state(&slot.slot_id, &blocked).unwrap();
    assert_eq!(saved().state, ClaudeConfigSlotCollectionStateV1::RefreshDue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn claude_valid_access_reconciliation_uses_locked_current_state_and_cannot_recreate_removed_slot() {
    let root = std::env::temp_dir().join(format!(
        "ottto-valid-access-reconcile-{}",
        std::process::id()
    ));
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    fs::create_dir_all(&root).unwrap();
    let (slot, upkeep, proof, now) = valid_access_reconciliation_fixture();
    persist_one_claude_slot_collection_state(&slot.slot_id, &slot.collection).unwrap();
    let update = |previous: Option<&ClaudeConfigSlotCollectionStatusV1>| {
        let mut current = slot.clone();
        current.collection = previous?.clone();
        reconciled_valid_access_status(
            &slot,
            &current,
            &upkeep,
            &proof,
            "2026-08-05T02:30:00Z",
            now,
        )
    };
    assert!(persist_one_claude_slot_collection_state_with(&slot.slot_id, update).unwrap());
    let stored = read_persisted_claude_slot_collection_state().slots[&slot.slot_id].clone();
    assert_eq!(stored.access_expires_at, upkeep.due_access_expires_at);
    assert_eq!(
        stored.last_full_quota_read_at,
        slot.collection.last_full_quota_read_at
    );
    assert_eq!(stored.quota_snapshot, slot.collection.quota_snapshot);
    assert_eq!(
        stored.quota_check_diagnostics,
        slot.collection.quota_check_diagnostics
    );
    assert!(
        !persist_one_claude_slot_collection_state_with(&slot.slot_id, update).unwrap(),
        "newer expiry cannot be overwritten by queued old work"
    );
    prune_claude_slot_collection_state(&slot.slot_id).unwrap();
    assert!(!persist_one_claude_slot_collection_state_with(&slot.slot_id, update).unwrap());
    assert!(!read_persisted_claude_slot_collection_state()
        .slots
        .contains_key(&slot.slot_id));
    fs::remove_dir_all(root).unwrap();
}

/// Synthetic Claude and Codex agent-status snapshots exactly as the
/// collector uploads them: the real account-to-plan-observation copy, the
/// real hash function, then the protocol backend redaction. The backend
/// repository consumes the same JSON as its wire fixture, so a change to
/// either side of the raw-id contract fails one of the two test suites.
fn raw_provider_id_backend_wire_snapshots() -> Vec<AgentStatusSnapshot> {
    let cases = [
        (
            SourceKind::ClaudeCode,
            "anthropic",
            "organization",
            "00000000-0000-4000-8000-00000000c1a1",
            "00000000-0000-4000-8000-00000000c1b2",
            "claude_max_20x",
            "max_20x",
        ),
        (
            SourceKind::Codex,
            "openai",
            "workspace",
            "user-SyntheticCodexUser01",
            "00000000-0000-4000-8000-00000000c0d3",
            "chatgpt_pro",
            "pro",
        ),
    ];
    cases
        .into_iter()
        .map(
            |(source, provider, workspace_kind, raw_account, raw_workspace, product, plan)| {
                let mut snapshot = base_snapshot(
                    source,
                    AgentStatusState::Available,
                    AgentStatusCollectionMethod::CliJson,
                    "2026-10-02T08:00:00Z".to_string(),
                    "2026-10-02T08:05:00Z".to_string(),
                );
                let account_identifier_hash =
                    billing_identity_hash(provider, "account", raw_account);
                let organization_identifier_hash =
                    billing_identity_hash(provider, workspace_kind, raw_workspace);
                snapshot.account = Some(AgentAccountStatus {
                    login_state: AgentLoginState::SignedIn,
                    auth_method: Some("oauth".to_string()),
                    email: Some("synthetic-owner@example.invalid".to_string()),
                    account_id: Some(raw_account.to_string()),
                    organization_id: Some(raw_workspace.to_string()),
                    organization_label: Some("Synthetic Workspace Label".to_string()),
                    plan_type: Some(plan.to_string()),
                    subscription_product: Some(product.to_string()),
                    billing_channel: Some("subscription".to_string()),
                    billing_identity_evidence: billing_identity_evidence_for(
                        &account_identifier_hash,
                        &organization_identifier_hash,
                        &None,
                    ),
                    account_identifier_hash,
                    organization_identifier_hash,
                    billing_identity_confidence: AgentStatusConfidence::High,
                    confidence: AgentStatusConfidence::High,
                    ..unsupported_account(provider)
                });
                let observation = plan_observation_from_snapshot_account(&snapshot, true)
                    .expect("account plan observation");
                snapshot.plan_observations.push(observation);
                snapshot.redacted_for_backend()
            },
        )
        .collect()
}

#[test]
fn raw_provider_id_backend_wire_fixture_matches_collector_upload() {
    let value = serde_json::to_value(raw_provider_id_backend_wire_snapshots())
        .expect("serialize backend wire snapshots");
    let wire = value.to_string();
    assert!(wire.contains("synthetic-owner@example.invalid"));
    assert!(wire.contains("Synthetic Workspace Label"));
    for raw in [
        "00000000-0000-4000-8000-00000000c1a1",
        "00000000-0000-4000-8000-00000000c1b2",
        "user-SyntheticCodexUser01",
        "00000000-0000-4000-8000-00000000c0d3",
    ] {
        assert!(
            wire.contains(raw),
            "raw provider id {raw} must reach the backend"
        );
    }
    let fixture = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).expect("pretty-print backend wire snapshots")
    );
    if std::env::var_os("OTTTO_WRITE_RAW_PROVIDER_ID_FIXTURE").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/agent-status/raw-provider-ids-backend-wire.v1.json"
            ),
            &fixture,
        )
        .expect("write fixture");
    }
    assert_eq!(
        fixture,
        include_str!("../../../../fixtures/agent-status/raw-provider-ids-backend-wire.v1.json")
    );
}

#[test]
#[serial]
fn claude_registered_slots_fan_out_full_usage_without_cross_account_mixing() {
    let root =
        std::env::temp_dir().join(format!("ottto-claude-multi-account-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let home = root.join("home");
    let support = root.join("support");
    let bin = root.join("bin");
    fs::create_dir_all(home.join(".claude")).expect("create default config dir");
    fs::create_dir_all(&support).expect("create support dir");
    fs::create_dir_all(&bin).expect("create command dir");

    let claude = bin.join("claude");
    fs::write(
        &claude,
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fixture-version"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ] && [ "$3" = "--json" ]; then
  if [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ] || [ -n "$ANTHROPIC_API_KEY" ] || [ -n "$CLAUDE_CODE_USE_BEDROCK" ] || [ -n "$CLAUDE_CODE_USE_VERTEX" ]; then
    exit 42
  fi
  if [ -n "$CLAUDE_CONFIG_DIR" ]; then
    config="$CLAUDE_CONFIG_DIR/.claude.json"
  else
    config="$HOME/.claude.json"
  fi
  exec /usr/bin/python3 - "$config" <<'PY'
import json, os, sys
account = json.load(open(sys.argv[1]))["oauthAccount"]
mode_path = os.path.join(os.path.dirname(sys.argv[1]), ".auth-mode")
mode = open(mode_path).read().strip() if os.path.exists(mode_path) else ""
if mode == "command_failure":
    raise SystemExit(7)
result = {
  "status": "authenticated",
  "email": account["emailAddress"],
  "organizationId": account["organizationUuid"],
  "subscriptionType": "max"
}
if mode == "missing_email":
    result.pop("email")
if mode == "missing_organization":
    result.pop("organizationId")
if mode == "identity_mismatch":
    result["email"] = "rotated@example.invalid"
    result["organizationId"] = "organization-rotated"
print(json.dumps(result))
PY
fi
exit 1
"#,
    )
    .expect("write fake claude");
    let security = bin.join("security");
    fs::write(&security, "#!/bin/sh\nexit 44\n").expect("write fake security");
    for executable in [&claude, &security] {
        let mut permissions = fs::metadata(executable).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(executable, permissions).expect("chmod executable");
    }

    let write_identity = |dir: &Path, account: &str, organization: &str| {
        fs::create_dir_all(dir).expect("create slot dir");
        fs::write(
            dir.join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "oauthAccount": {
                    "accountUuid": account,
                    "organizationUuid": organization,
                    "emailAddress": "same@example.invalid",
                    "organizationType": "max",
                    "userRateLimitTier": "default_claude_max_20x"
                }
            }))
            .expect("serialize identity"),
        )
        .expect("write identity");
    };
    let write_credential_with_plan = |dir: &Path, plan: &str| {
        fs::write(
            dir.join(".credentials.json"),
            serde_json::to_vec(&claude_credential_fixture(
                "fixture",
                TimeDuration::hours(6),
                Some(plan),
            ))
            .expect("serialize credential fixture"),
        )
        .expect("write credential fixture");
    };
    let write_credential = |dir: &Path| write_credential_with_plan(dir, "max");

    write_identity(&home, "account-primary", "organization-primary");
    write_credential(&home.join(".claude"));
    let managed = root.join("managed-slot");
    write_identity(&managed, "account-secondary", "organization-secondary");
    // A fresh exact same-account, same-organization cache serves this
    // slot without a network fetch.
    write_credential(&managed);
    let healthy_external = root.join("healthy-external-slot");
    write_identity(
        &healthy_external,
        "account-tertiary",
        "organization-tertiary",
    );
    write_credential(&healthy_external);
    let duplicate = root.join("duplicate-slot");
    write_identity(&duplicate, "account-secondary", "organization-secondary");
    write_credential(&duplicate);
    let failed = root.join("failed-slot");
    write_identity(&failed, "account-failed", "organization-failed");
    // Signed in to an account but no stored login at all.
    let auth_failed = root.join("auth-failed-slot");
    write_identity(&auth_failed, "account-secondary", "organization-secondary");
    // `.claude.json` without an email: no complete local identity.
    let missing_identity = root.join("missing-identity-slot");
    write_identity(
        &missing_identity,
        "account-missing-identity",
        "organization-missing-identity",
    );
    let mut identity: Value = serde_json::from_slice(
        &fs::read(missing_identity.join(".claude.json")).expect("read identity"),
    )
    .expect("identity json");
    identity["oauthAccount"]
        .as_object_mut()
        .expect("oauth account")
        .remove("emailAddress");
    fs::write(
        missing_identity.join(".claude.json"),
        serde_json::to_vec(&identity).expect("serialize identity"),
    )
    .expect("write identity without email");
    write_credential(&missing_identity);
    // The stored login names a Team plan while `.claude.json` names a Max
    // organization: the two files were written by different logins.
    let mismatched_identity = root.join("mismatched-identity-slot");
    write_identity(
        &mismatched_identity,
        "account-stale-identity",
        "organization-stale-identity",
    );
    write_credential_with_plan(&mismatched_identity, "team");

    let _home_guard = EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string());
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support.as_os_str().to_os_string(),
    );
    let _command_guard =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string());
    let _oauth_poison = EnvVarGuard::set_os(
        "CLAUDE_CODE_OAUTH_TOKEN",
        OsString::from("ambient-wrong-account"),
    );
    let _api_poison = EnvVarGuard::set_os("ANTHROPIC_API_KEY", OsString::from("ambient-api-key"));
    let _bedrock_poison = EnvVarGuard::set_os("CLAUDE_CODE_USE_BEDROCK", OsString::from("1"));
    let _vertex_poison = EnvVarGuard::set_os("CLAUDE_CODE_USE_VERTEX", OsString::from("1"));
    let store = FileClaudeConfigSlotSettingsStore::default();
    store
        .register_managed_path(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            managed.to_string_lossy().to_string(),
        )
        .expect("register managed slot");
    store
        .register_path(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            healthy_external.to_string_lossy().to_string(),
        )
        .expect("register healthy external slot");
    store
        .register_path(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            duplicate.to_string_lossy().to_string(),
        )
        .expect("register duplicate slot");
    store
        .register_path(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            failed.to_string_lossy().to_string(),
        )
        .expect("register failed slot");
    for path in [&auth_failed, &missing_identity, &mismatched_identity] {
        store
            .register_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                path.to_string_lossy().to_string(),
            )
            .expect("register invalid identity slot");
    }

    let now = current_unix_seconds();
    let primary_hash =
        billing_identity_hash("anthropic", "account", "account-primary").expect("primary hash");
    let primary_org = billing_identity_hash("anthropic", "organization", "organization-primary")
        .expect("primary org hash");
    let secondary_hash =
        billing_identity_hash("anthropic", "account", "account-secondary").expect("secondary hash");
    let secondary_org =
        billing_identity_hash("anthropic", "organization", "organization-secondary")
            .expect("secondary org hash");
    let tertiary_hash =
        billing_identity_hash("anthropic", "account", "account-tertiary").expect("tertiary hash");
    let tertiary_org = billing_identity_hash("anthropic", "organization", "organization-tertiary")
        .expect("tertiary org hash");
    let failed_hash = billing_identity_hash("anthropic", "account", "account-failed")
        .expect("failed account hash");
    let usage_cache =
        |account_hash: &str, organization_hash: &str, used_percent: u8, credits: u64| {
            let mut usage = ClaudeOAuthUsage {
                windows: vec![
                    AgentQuotaWindow {
                        name: "session".to_string(),
                        scope: AgentQuotaWindowScope::Account,
                        status: AgentQuotaWindowStatus::Ok,
                        freshness: AgentQuotaWindowFreshness::Fresh,
                        used_percent: Some(used_percent),
                        ..Default::default()
                    },
                    AgentQuotaWindow {
                        name: "weekly".to_string(),
                        scope: AgentQuotaWindowScope::Account,
                        status: AgentQuotaWindowStatus::Ok,
                        freshness: AgentQuotaWindowFreshness::Fresh,
                        used_percent: Some(used_percent),
                        ..Default::default()
                    },
                    AgentQuotaWindow {
                        name: "weekly_sonnet".to_string(),
                        scope: AgentQuotaWindowScope::Model,
                        status: AgentQuotaWindowStatus::Ok,
                        freshness: AgentQuotaWindowFreshness::Fresh,
                        model: Some("claude-sonnet".to_string()),
                        used_percent: Some(used_percent),
                        ..Default::default()
                    },
                ],
                credit_balances: vec![AgentCreditBalance {
                    name: "Usage credits".to_string(),
                    status: AgentCreditBalanceStatus::Ok,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    remaining: CreditAmount::whole(credits),
                    ..Default::default()
                }],
                account_weekly_not_offered: false,
                account_session_not_offered: false,
            };
            claude_oauth_stamp_account_identity(&mut usage, account_hash, Some(organization_hash));
            ClaudeOAuthUsageCache {
                schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                account_identifier_hash: account_hash.to_string(),
                organization_identifier_hash: organization_hash.to_string(),
                observed_at_epoch_seconds: now,
                next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
                windows: usage.windows,
                credit_balances: usage.credit_balances,
                account_weekly_not_offered: false,
                account_session_not_offered: false,
            }
        };
    write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: primary_hash.clone(),
        organization_identifier_hash: primary_org.clone(),
        observed_at_epoch_seconds: now,
        next_refresh_after_epoch_seconds: u64::MAX,
        windows: Vec::new(),
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    })
    .expect("write unavailable primary cache");
    write_claude_oauth_usage_cache(&usage_cache(&secondary_hash, &secondary_org, 77, 777))
        .expect("write secondary cache");
    write_claude_oauth_usage_cache(&usage_cache(&tertiary_hash, &tertiary_org, 33, 333))
        .expect("write tertiary cache");

    let captured_at = "2026-08-04T12:34:56Z".to_string();
    let collection = collect_agent_status_collection(
        &SourceKind::ClaudeCode,
        captured_at.clone(),
        "2026-08-04T12:49:56Z".to_string(),
    );
    let snapshots = collection.snapshots;

    // A slot with no stored login proves no account locally (as `claude
    // auth status` reported `loggedIn: false` for it), so it emits no
    // strongly bound snapshot; its local state says why.
    assert_eq!(
        snapshots.len(),
        3,
        "two healthy accounts plus the strongly bound degraded default are emitted"
    );
    assert!(snapshots
        .iter()
        .all(|snapshot| snapshot.captured_at == captured_at));
    let by_account = snapshots
        .iter()
        .map(|snapshot| {
            (
                snapshot
                    .account
                    .as_ref()
                    .and_then(|account| account.account_identifier_hash.clone())
                    .expect("strong snapshot account"),
                snapshot,
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(by_account.len(), 3);
    for (account_hash, organization_hash, expected_percent, expected_credits) in [
        (&secondary_hash, &secondary_org, 77, 777),
        (&tertiary_hash, &tertiary_org, 33, 333),
    ] {
        let snapshot = by_account.get(account_hash).expect("account snapshot");
        assert_eq!(snapshot.quota_windows.len(), 3);
        assert!(snapshot.quota_windows.iter().all(|window| {
            window.account_identifier_hash.as_ref() == Some(account_hash)
                && window.organization_identifier_hash.as_ref() == Some(organization_hash)
                && window.used_percent == Some(expected_percent)
        }));
        assert_eq!(snapshot.credit_balances.len(), 1);
        assert_eq!(
            snapshot.credit_balances[0].account_identifier_hash.as_ref(),
            Some(account_hash)
        );
        assert_eq!(
            snapshot.credit_balances[0]
                .organization_identifier_hash
                .as_ref(),
            Some(organization_hash)
        );
        assert_eq!(
            snapshot.credit_balances[0].remaining,
            CreditAmount::whole(expected_credits)
        );
        assert_eq!(
            snapshot
                .account
                .as_ref()
                .and_then(|account| account.claude_quota_access_state),
            Some(ClaudeQuotaAccessState::Full)
        );
    }
    assert!(
        !by_account.contains_key(&failed_hash),
        "no stored login: no account is claimed for the failed slot"
    );
    let primary_snapshot = by_account
        .get(&primary_hash)
        .expect("strongly bound unavailable default snapshot");
    assert_eq!(primary_snapshot.status, AgentStatusState::Degraded);
    assert!(primary_snapshot.quota_windows.is_empty());
    assert!(primary_snapshot.credit_balances.is_empty());
    assert!(primary_snapshot.plan_observations.is_empty());
    assert_eq!(
        primary_snapshot
            .account
            .as_ref()
            .and_then(|account| account.organization_identifier_hash.as_ref()),
        Some(&primary_org)
    );
    assert_eq!(
        primary_snapshot
            .account
            .as_ref()
            .and_then(|account| account.claude_quota_access_state),
        Some(ClaudeQuotaAccessState::TemporarilyUnavailable)
    );

    let status = annotate_claude_accounts_status(store.load().expect("load slot status"));
    let local_full_slots = status
        .managed_slots
        .iter()
        .chain(status.external_slots.iter())
        .filter(|slot| slot.collection.state == ClaudeConfigSlotCollectionStateV1::Fresh)
        .collect::<Vec<_>>();
    assert_eq!(local_full_slots.len(), 2);
    for slot in local_full_slots {
        let local = slot
            .collection
            .quota_snapshot
            .as_ref()
            .expect("fresh exact slot exposes local full meters");
        assert_eq!(local.state, ClaudeConfigSlotQuotaSnapshotStateV1::Fresh);
        assert_eq!(local.quota_windows.len(), 3);
        assert_eq!(local.credit_balances.len(), 1);
        let account = slot
            .collection
            .account_identifier_hash
            .as_deref()
            .expect("slot account hash");
        let organization = slot
            .collection
            .organization_identifier_hash
            .as_deref()
            .expect("slot organization hash");
        assert!(local.quota_windows.iter().all(|window| {
            window.account_identifier_hash.as_deref() == Some(account)
                && window.organization_identifier_hash.as_deref() == Some(organization)
        }));
        assert!(local.credit_balances.iter().all(|balance| {
            balance.account_identifier_hash.as_deref() == Some(account)
                && balance.organization_identifier_hash.as_deref() == Some(organization)
        }));
    }
    assert_eq!(
        status.default_slot.collection.state,
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
    );
    assert_eq!(
        status
            .default_slot
            .collection
            .account_identifier_hash
            .as_ref(),
        Some(&primary_hash)
    );
    assert_eq!(
        status
            .default_slot
            .collection
            .organization_identifier_hash
            .as_ref(),
        Some(&primary_org)
    );
    let managed_status = status
        .managed_slots
        .iter()
        .find(|slot| slot.config_dir.as_deref() == managed.to_str())
        .expect("managed slot status");
    let duplicate_status = status
        .external_slots
        .iter()
        .find(|slot| slot.config_dir.as_deref() == duplicate.to_str())
        .expect("duplicate account slot status");
    let pair_states = [
        managed_status.collection.state.clone(),
        duplicate_status.collection.state.clone(),
    ];
    assert!(pair_states.contains(&ClaudeConfigSlotCollectionStateV1::Fresh));
    assert!(pair_states.contains(&ClaudeConfigSlotCollectionStateV1::DuplicateAccount));
    assert!(
        matches!(
            managed_status.collection.state,
            ClaudeConfigSlotCollectionStateV1::Fresh
                | ClaudeConfigSlotCollectionStateV1::DuplicateAccount
        ),
        "the managed slot must reach candidate ranking via its exact cache"
    );
    assert!(status.external_slots.iter().any(|slot| {
        slot.collection.state == ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
    }));
    assert!(status.external_slots.iter().any(|slot| {
        slot.collection.state == ClaudeConfigSlotCollectionStateV1::IdentityUnknown
    }));
    for (path, expected) in [
        (
            &auth_failed,
            ClaudeConfigSlotCollectionStateV1::CredentialUnavailable,
        ),
        (
            &missing_identity,
            ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
        ),
        // A plan-family contradiction is an unproven owner, not a race.
        (
            &mismatched_identity,
            ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
        ),
    ] {
        let slot = status
            .external_slots
            .iter()
            .find(|slot| slot.config_dir.as_deref() == path.to_str())
            .expect("typed invalid slot status");
        assert_eq!(slot.collection.state, expected);
    }

    let worker_code = "claude_slot_worker_reconciliation_refused";
    let backend_json = serde_json::to_string(
        &snapshots
            .into_iter()
            .enumerate()
            .map(|(index, mut snapshot)| {
                if index == 0 {
                    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                        worker_code,
                        AgentDiagnosticSeverity::Info,
                        claude_worker_diagnostic_message(worker_code)
                            .expect("closed local worker code"),
                    ));
                }
                snapshot.redacted_for_backend()
            })
            .collect::<Vec<_>>(),
    )
    .expect("serialize backend snapshots");
    // Raw provider account and organization ids are uploaded on purpose,
    // but only in their own `account_id` / `organization_id` fields. Strip
    // exactly those field values; the ids must not appear anywhere else.
    let mut residual_json = backend_json.clone();
    for slot in ["primary", "secondary", "tertiary"] {
        residual_json = residual_json
            .replace(&format!("\"account_id\":\"account-{slot}\""), "")
            .replace(&format!("\"organization_id\":\"organization-{slot}\""), "");
    }
    assert!(
        backend_json.contains("\"account_id\":\"account-secondary\""),
        "raw provider account id must reach the backend"
    );
    for forbidden in [
        root.to_string_lossy().as_ref(),
        "account-primary",
        "account-secondary",
        "account-tertiary",
        "organization-primary",
        "organization-secondary",
        "organization-tertiary",
        "fixture",
    ] {
        assert!(
            !residual_json.contains(forbidden),
            "backend snapshots leaked forbidden local material"
        );
    }
    for slot in status.managed_slots.iter().chain(&status.external_slots) {
        assert!(!backend_json.contains(&slot.slot_id), "raw slot id leaked");
        if let Some(path) = &slot.config_dir {
            assert!(
                !backend_json.contains(path),
                "registered config path leaked"
            );
        }
    }
    fn assert_public_fields(value: &Value, context: &str) {
        match value {
            Value::Object(fields) => {
                for (key, child) in fields {
                    assert!(
                        ![
                            "slot_id",
                            "config_dir",
                            "service_name",
                            "account_profile",
                            "quota_check_diagnostics",
                            "access_token",
                            "refresh_token",
                            "identity_path",
                            "credential_path",
                        ]
                        .contains(&key.as_str()),
                        "private field leaked: {key}"
                    );
                    let next = if context == "diagnostic" && key == "code" {
                        "diagnostic_code"
                    } else if key == "diagnostics" {
                        "diagnostics"
                    } else {
                        ""
                    };
                    assert_public_fields(child, next);
                }
            }
            Value::Array(items) => {
                for child in items {
                    assert_public_fields(
                        child,
                        if context == "diagnostics" {
                            "diagnostic"
                        } else {
                            ""
                        },
                    );
                }
            }
            Value::String(text) if text.contains("claude_slot_") => {
                // Only a diagnostic code from a closed enum is public;
                // the same prefix in any other field still fails privacy.
                let safe = claude_worker_diagnostic_message(text).is_some()
                    || text == "claude_slot_upkeep_attempt_started"
                    || text
                        .strip_prefix("claude_slot_collection_")
                        .is_some_and(|suffix| {
                            let value = Value::String(suffix.to_string());
                            serde_json::from_value::<ClaudeConfigSlotCollectionStateV1>(
                                value.clone(),
                            )
                            .is_ok()
                                || serde_json::from_value::<ClaudeConfigSlotDiagnosticCodeV1>(value)
                                    .is_ok()
                        })
                    || text
                        .strip_prefix("claude_slot_upkeep_")
                        .is_some_and(|suffix| {
                            serde_json::from_value::<ClaudeConfigSlotUpkeepResultV1>(Value::String(
                                suffix.to_string(),
                            ))
                            .is_ok()
                        });
                assert!(
                    context == "diagnostic_code" && safe,
                    "slot-identifying value leaked"
                );
            }
            _ => {}
        }
    }
    assert_public_fields(
        &serde_json::from_str(&backend_json).expect("backend payload"),
        "",
    );
    assert!(backend_json.contains(worker_code));
    for forbidden in [
        serde_json::json!({"diagnostics": [{"code": "claude_slot_worker_arbitrary_suffix"}]}),
        serde_json::json!({"diagnostics": [{"message": worker_code}]}),
        serde_json::json!({"code": worker_code}),
    ] {
        assert!(std::panic::catch_unwind(|| assert_public_fields(&forbidden, "")).is_err());
    }
    let local_state =
        fs::read_to_string(claude_slot_collection_state_path()).expect("read local slot state");
    assert!(!local_state.contains(root.to_string_lossy().as_ref()));
    assert!(!local_state.contains("fixture"));

    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn claude_default_and_custom_rotation_during_auth_fail_closed() {
    let root =
        std::env::temp_dir().join(format!("ottto-claude-slot-rotation-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let home = root.join("home");
    let support = root.join("support");
    let custom = root.join("custom");
    let bin = root.join("bin");
    for directory in [&home.join(".claude"), &support, &custom, &bin] {
        fs::create_dir_all(directory).expect("create rotation test directory");
    }
    let write_slot = |identity_dir: &Path, credential_dir: &Path, suffix: &str| {
        fs::write(
            identity_dir.join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "oauthAccount": {
                    "accountUuid": format!("account-{suffix}"),
                    "organizationUuid": format!("organization-{suffix}"),
                    "emailAddress": format!("{suffix}@example.invalid")
                }
            }))
            .expect("serialize rotation identity"),
        )
        .expect("write rotation identity");
        fs::write(
            credential_dir.join(".credentials.json"),
            serde_json::to_vec(&claude_credential_fixture(
                "test-captured-value",
                TimeDuration::hours(6),
                Some("max"),
            ))
            .expect("serialize rotation credential"),
        )
        .expect("write rotation credential");
    };
    write_slot(&home, &home.join(".claude"), "default");
    write_slot(&custom, &custom, "custom");

    let claude = bin.join("claude");
    fs::write(&claude, "#!/bin/sh\necho test-version\n").expect("write fake claude");
    // A login written by another Claude Code process while the stored
    // credential is being read: `.claude.json` differs before and after.
    let security = bin.join("security");
    fs::write(
        &security,
        format!(
            r#"#!/bin/sh
/usr/bin/python3 - '{default}' '{custom}' <<'PY'
import json, sys
for path in sys.argv[1:]:
    value = json.load(open(path))
    account = value["oauthAccount"]
    account["accountUuid"] += "-rotated"
    account["organizationUuid"] += "-rotated"
    account["emailAddress"] = "rotated@example.invalid"
    with open(path, "w") as output:
        json.dump(value, output)
PY
exit 44
"#,
            default = home.join(".claude.json").display(),
            custom = custom.join(".claude.json").display(),
        ),
    )
    .expect("write rotating security");
    for executable in [&claude, &security] {
        let mut permissions = fs::metadata(executable).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(executable, permissions).expect("chmod executable");
    }

    let _home = EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string());
    let _support = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support.as_os_str().to_os_string(),
    );
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string());
    let store = FileClaudeConfigSlotSettingsStore::default();
    store
        .register_path(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            custom.to_string_lossy().to_string(),
        )
        .expect("register rotating custom slot");

    let collection = collect_agent_status_collection(
        &SourceKind::ClaudeCode,
        "2026-08-04T13:00:00Z".to_string(),
        "2026-08-04T13:15:00Z".to_string(),
    );
    assert!(
        collection.snapshots.is_empty(),
        "rotating slots must emit no backend snapshot"
    );
    assert!(collection
        .source_health_snapshot
        .quota_windows
        .iter()
        .all(|window| window.account_identifier_hash.is_none()));
    let status = annotate_claude_accounts_status(store.load().expect("load rotating slots"));
    // Both logins rotated to another account and neither slot had a
    // verified account to keep, so the race is not a benign retry: it
    // fails closed as an unknown owner, with no account adopted.
    assert_eq!(
        status.default_slot.collection.state,
        ClaudeConfigSlotCollectionStateV1::IdentityUnknown
    );
    assert_eq!(status.default_slot.collection.account_identifier_hash, None);
    assert_eq!(status.external_slots.len(), 1);
    assert_eq!(
        status.external_slots[0].collection.state,
        ClaudeConfigSlotCollectionStateV1::IdentityUnknown
    );
    assert_eq!(
        status.external_slots[0].collection.account_identifier_hash,
        None
    );
    let persisted =
        fs::read_to_string(claude_slot_collection_state_path()).expect("read rotation local state");
    assert!(!persisted.contains("test-captured-value"));
    assert!(!persisted.contains(root.to_string_lossy().as_ref()));

    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn run_command_capture_drains_large_stdout_before_waiting() {
    let dir = std::env::temp_dir().join(format!("ottto-command-capture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let executable = dir.join("large-output");
    std::fs::write(
        &executable,
        "#!/bin/sh\nexec /usr/bin/python3 -c 'import sys; sys.stdout.write(\"x\" * 200000)'\n",
    )
    .expect("write executable");
    let mut permissions = std::fs::metadata(&executable)
        .expect("metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&executable, permissions).expect("chmod executable");

    let _guard = EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
    let output = run_command_capture("large-output", &[], Duration::from_secs(5));

    assert!(output.success, "{output:?}");
    assert_eq!(output.stdout.len(), 200000);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[serial]
fn run_command_capture_timeout_does_not_wait_on_inherited_pipe() {
    let dir = std::env::temp_dir().join(format!(
        "ottto-command-capture-held-pipe-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let executable = dir.join("held-pipe");
    std::fs::write(&executable, "#!/bin/sh\n(sh -c 'sleep 2') &\nsleep 30\n")
        .expect("write executable");
    let mut permissions = std::fs::metadata(&executable)
        .expect("metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&executable, permissions).expect("chmod executable");

    let _guard = EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
    let started = Instant::now();
    let output = run_command_capture("held-pipe", &[], Duration::from_millis(200));

    assert!(!output.success, "{output:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "timeout path must not block on a descendant-held stdout pipe"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
fn synthetic_codex_collector_home(label: &str, auth_mode: u32) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!(
        "ottto-codex-collector-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("collector fixture root");
    let root = root.canonicalize().expect("canonical collector root");
    let home = root.join("provider-home");
    std::fs::create_dir(&home).expect("provider home");
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755))
        .expect("provider home mode");

    let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let access_token = synthetic_codex_access_jwt_with_profile_email(
        "synthetic-user",
        "synthetic-workspace",
        "synthetic-account",
        "pro",
        expires_at,
    );
    let id_token = synthetic_codex_jwt(
        "synthetic-user",
        "synthetic-workspace",
        "synthetic-account",
        "pro",
        expires_at,
    );
    let auth = home.join("auth.json");
    std::fs::write(
        &auth,
        serde_json::json!({
            "tokens": {
                "access_token": access_token,
                "id_token": id_token
            },
            "account_id": "synthetic-workspace"
        })
        .to_string(),
    )
    .expect("auth fixture");
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(auth_mode)).expect("auth mode");

    let executable = root.join("codex");
    std::fs::write(
        &executable,
        r#"#!/usr/bin/python3
import sys

if sys.argv[1:] == ["login", "status"]:
    print("Logged in")
    sys.exit(0)
if sys.argv[1:] == ["debug", "models", "--bundled"]:
    print('{"models":[{"id":"synthetic-model"}]}')
    sys.exit(0)
if sys.argv[-2:] != ["app-server", "--stdio"]:
    sys.exit(1)

for line in sys.stdin:
    if '"id":1' in line:
        print('{"id":1,"result":{"userAgent":"synthetic"}}', flush=True)
    elif '"id":"ottto_account"' in line:
        print('{"id":"ottto_account","result":{"account":{"type":"chatgpt","email":"synthetic-account","planType":"pro"},"requiresOpenaiAuth":true}}', flush=True)
    elif "account/rateLimits/read" in line:
        detailed = "ottto_rate_limits_details" in line
        request_id = "ottto_rate_limits_details" if detailed else "ottto_rate_limits"
        credits = ',"credits":[]' if detailed else ''
        print('{"id":"' + request_id + '","result":{"rateLimits":{"limitId":"synthetic-limit","planType":"pro","primary":{"usedPercent":25,"windowDurationMins":300}},"rateLimitResetCredits":{"availableCount":2' + credits + '}}}', flush=True)
"#,
    )
    .expect("fake Codex executable");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("fake Codex mode");

    (root, home)
}

mod cli_metadata_tests {
    include!("cli_metadata_tests.rs");
}

#[cfg(unix)]
#[test]
#[serial]
fn provider_default_0755_home_retains_identity_and_real_quota() {
    let (root, home) = synthetic_codex_collector_home("default-0755", 0o600);
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    assert!(
        read_codex_auth_credentials_at(&home, CodexHomeTrust::ProviderDefault).is_ok(),
        "the safe fixture must be readable before collection"
    );

    let (snapshot, identity, _) = collect_codex_status_for_home(
        "2026-08-26T00:00:00Z".to_string(),
        "2026-08-26T00:15:00Z".to_string(),
        &home,
        CodexHomeTrust::ProviderDefault,
        CodexLoginRefresh::Never,
        CodexQuotaRead::Provider,
    );

    assert!(
        identity.is_some(),
        "diagnostic codes: {:?}; quota names: {:?}",
        snapshot
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>(),
        snapshot
            .quota_windows
            .iter()
            .map(|window| window.name.as_str())
            .collect::<Vec<_>>()
    );
    let account = snapshot.account.expect("provider account");
    assert!(account.account_identifier_hash.is_some());
    assert!(account.organization_identifier_hash.is_some());
    assert!(!snapshot.quota_windows.is_empty());
    assert!(snapshot
        .quota_windows
        .iter()
        .all(|window| window.name != "usage"));
    assert!(snapshot
        .quota_windows
        .iter()
        .all(|window| window.account_identifier_hash.is_some()));

    let check = snapshot
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "codex_app_server_usage_response")
        .expect("successful completion witness");
    assert!(check.observed_at.is_some());
    assert!(snapshot
        .quota_windows
        .iter()
        .all(|window| window.observed_at == check.observed_at));
    assert_eq!(
        check.account_identifier_hash,
        account.account_identifier_hash
    );
    assert_eq!(
        check.organization_identifier_hash,
        account.organization_identifier_hash
    );
    assert!(bounded_claude_collection_timestamp(
        check.observed_at.as_deref(),
        OffsetDateTime::now_utc()
    )
    .is_some());
    assert_ne!(
        check.observed_at.as_deref(),
        Some(snapshot.captured_at.as_str()),
        "snapshot capture is not the read clock"
    );

    let _ = std::fs::remove_dir_all(root);
}

/// A synthetic Codex install whose provider home is the default home
/// (`$HOME/.codex`), with the daemon support dir beside it. The guards
/// restore the environment.
#[cfg(unix)]
fn synthetic_default_codex_install(label: &str) -> (PathBuf, PathBuf, Vec<EnvVarGuard>) {
    let (root, provider_home) = synthetic_codex_collector_home(label, 0o600);
    let home = root.join(".codex");
    std::fs::rename(&provider_home, &home).expect("default Codex home");
    let support = root.join("support");
    std::fs::create_dir(&support).expect("support dir");
    let guards = vec![
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string()),
        EnvVarGuard::set_os("HOME", root.as_os_str().to_os_string()),
        EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support.as_os_str().to_os_string(),
        ),
    ];
    (root, home, guards)
}

fn codex_app_server_runs() -> usize {
    CODEX_APP_SERVER_RUNS.load(std::sync::atomic::Ordering::SeqCst)
}

fn default_codex_slot(home: &Path) -> CodexHomeSlot {
    CodexHomeSlot {
        slot_id: "default".to_string(),
        ownership: CodexAccountSlotOwnershipV1::Default,
        home: home.to_path_buf(),
        registered_binding: None,
    }
}

/// Every status read serves the saved reading: the accounts status (the
/// companion's 3 s poll) and the per-home reads of the collection lane
/// start no `codex app-server`, before and after a provider read, and
/// show exactly what the provider read saved.
#[cfg(unix)]
#[test]
#[serial]
fn codex_status_reads_serve_the_saved_reading_and_never_start_app_server() {
    let (root, home, _guards) = synthetic_default_codex_install("saved-reads");
    let read = |quota_read| {
        collect_codex_home_candidate(
            default_codex_slot(&home),
            "2026-08-26T00:00:00Z",
            "2026-08-26T00:15:00Z",
            quota_read,
        )
    };

    // Before any provider read: nothing saved, no app-server, and an
    // honest "not read yet" rather than a failed read.
    let before = codex_app_server_runs();
    let unread = read(CodexQuotaRead::Saved);
    let annotated = annotate_codex_accounts_status(empty_codex_accounts_status());
    assert_eq!(codex_app_server_runs(), before);
    assert!(unread.binding.is_none());
    assert!(unread
        .snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_quota_not_read_yet"));
    assert!(!unread
        .snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_usage_probe_failed"));
    assert_ne!(unread.snapshot.status, AgentStatusState::Degraded);
    assert!(annotated.default_slot.collection.quota_snapshot.is_none());

    // One provider read (the schedule's) saves the reading.
    let fresh = read(CodexQuotaRead::Provider);
    assert_eq!(codex_app_server_runs(), before + 1);
    assert_eq!(fresh.status.state, CodexAccountSlotCollectionStateV1::Fresh);

    // Status reads now show it, still without any app-server run.
    let saved = read(CodexQuotaRead::Saved);
    let annotated = annotate_codex_accounts_status(empty_codex_accounts_status());
    assert_eq!(codex_app_server_runs(), before + 1);
    assert_eq!(saved.status.state, CodexAccountSlotCollectionStateV1::Fresh);
    assert_eq!(saved.binding, fresh.binding);
    assert_eq!(saved.snapshot.quota_windows, fresh.snapshot.quota_windows);
    assert_eq!(
        saved.snapshot.credit_balances,
        fresh.snapshot.credit_balances
    );
    assert_eq!(
        saved
            .snapshot
            .account
            .as_ref()
            .map(|account| &account.plan_type),
        fresh
            .snapshot
            .account
            .as_ref()
            .map(|account| &account.plan_type)
    );
    let default_slot = &annotated.default_slot.collection;
    assert_eq!(default_slot.state, CodexAccountSlotCollectionStateV1::Fresh);
    assert_eq!(
        default_slot.account_identifier_hash,
        fresh.status.account_identifier_hash
    );

    // A failed provider read is served as that failure by status reads.
    fail_synthetic_codex_app_server(&root);
    let failed = read(CodexQuotaRead::Provider);
    let failed_runs = codex_app_server_runs();
    let served_failure = read(CodexQuotaRead::Saved);
    assert_eq!(codex_app_server_runs(), failed_runs);
    assert_eq!(served_failure.status.state, failed.status.state);
    assert!(served_failure
        .snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_usage_probe_failed"));

    if let Some((account, workspace)) = fresh.binding.as_ref() {
        codex_credit_grants::forget_binding_cadence(&codex_credit_grants::binding_key(
            account, workspace,
        ));
    }
    drop(_guards);
    let _ = std::fs::remove_dir_all(root);
}

/// The explicit refresh reads now, at most once a minute per home; the
/// schedule reads an unused home again only after 15 minutes.
#[cfg(unix)]
#[test]
#[serial]
fn codex_explicit_refresh_is_rate_limited_and_the_schedule_waits_its_interval() {
    use crate::provider_calls::{with_trigger, CallKind, Trigger};
    let (root, home, _guards) = synthetic_default_codex_install("explicit-refresh");
    let support = root.join("support");
    codex_saved_quota::forget_running_homes();
    let before = codex_app_server_runs();

    let first = with_trigger(Trigger::ExplicitRefresh, || refresh_codex_quota_now(0));
    assert_eq!(first.read, 1);
    assert_eq!(first.rate_limited, 0);
    assert_eq!(codex_app_server_runs(), before + 1);

    // A second press within the minute reads nothing.
    let second = refresh_codex_quota_now(0);
    assert_eq!(second.read, 0);
    assert_eq!(second.rate_limited, 1);
    assert_eq!(codex_app_server_runs(), before + 1);

    // The schedule: the home is not in use, so it is not due before 15
    // minutes, and due at 15.
    let now = current_unix_seconds();
    assert_eq!(
        codex_saved_quota::scheduled_round(&support, now + 14 * 60),
        0
    );
    assert_eq!(codex_app_server_runs(), before + 1);
    assert_eq!(
        with_trigger(Trigger::Schedule, || codex_saved_quota::scheduled_round(
            &support,
            now + 15 * 60 + 1
        )),
        1
    );
    assert_eq!(codex_app_server_runs(), before + 2);

    // One provider-call line per app-server run, with the reason its
    // caller gave (the reads run on per-home threads): at least the token
    // refresh and the rate-limits read each.
    let account = codex_home_claimed_account_hash(&home, CodexHomeTrust::ProviderDefault)
        .expect("claimed account");
    let lines = crate::provider_calls::test_lines(CallKind::CodexAppServerQuota, &account);
    let summary = lines
        .iter()
        .map(|line| {
            (
                line.provider.as_str(),
                line.trigger.as_str(),
                line.result.as_str(),
                line.basis.as_str(),
                line.requests_at_least >= 2,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        summary,
        [
            (
                "openai",
                "explicit_refresh",
                "ok",
                "subprocess_lower_bound",
                true
            ),
            ("openai", "schedule", "ok", "subprocess_lower_bound", true),
        ]
    );
    let raw = crate::provider_calls::test_raw_log();
    assert!(!raw.contains("synthetic-account") && !raw.contains("synthetic-workspace"));
    assert!(!raw.contains(&*home.to_string_lossy()));

    let binding = read_codex_auth_credentials_at(&home, CodexHomeTrust::ProviderDefault)
        .ok()
        .flatten()
        .and_then(|credentials| codex_credential_claimed_binding(&credentials));
    if let Some(binding) = binding {
        codex_credit_grants::forget_binding_cadence(&binding);
    }
    drop(_guards);
    let _ = std::fs::remove_dir_all(root);
}

/// "Background limit refresh" off: the schedule reads no Codex home and
/// a never-read home says why. A person's Refresh and the setup check's
/// provider read still read; switching it on resumes the schedule.
#[cfg(unix)]
#[test]
#[serial]
fn codex_background_refresh_off_stops_the_schedule_but_not_refresh_or_setup() {
    use std::os::unix::fs::PermissionsExt;
    let (root, home, _guards) = synthetic_default_codex_install("background-refresh-off");
    let support = root.join("support");
    // The settings writer keeps its lock in a private support dir.
    std::fs::set_permissions(&support, std::fs::Permissions::from_mode(0o700))
        .expect("private support dir");
    codex_saved_quota::forget_running_homes();
    let settings = ottto_core::FileCodexAccountSlotSettingsStore::default();
    let off = settings
        .set_quota_refresh_consent(1, false)
        .expect("turn off");
    assert_eq!(
        off.background_quota_refresh,
        Some(ottto_protocol::CodexQuotaRefreshConsentState::ConsentRequired)
    );
    let before = codex_app_server_runs();
    let now = current_unix_seconds();

    // Never read, due at once: the schedule reads nothing, and the status
    // says background refresh is off instead of "reads it shortly".
    assert_eq!(codex_saved_quota::scheduled_round(&support, now), 0);
    assert_eq!(
        codex_saved_quota::scheduled_round(&support, now + 24 * 60 * 60),
        0
    );
    assert_eq!(codex_app_server_runs(), before);
    assert_eq!(
        codex_saved_quota::serve_saved(&home, CodexHomeTrust::ProviderDefault, now)
            .err()
            .map(|failure| failure.message),
        Some(codex_saved_quota::CODEX_QUOTA_BACKGROUND_REFRESH_OFF.to_string())
    );
    let candidate = collect_codex_home_candidate(
        default_codex_slot(&home),
        "2026-08-26T00:00:00Z",
        "2026-08-26T00:15:00Z",
        CodexQuotaRead::Saved,
    );
    assert!(candidate
        .snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_quota_background_refresh_off"));
    assert_eq!(codex_app_server_runs(), before);

    // A person's Refresh reads.
    let refreshed = refresh_codex_quota_now(0);
    assert_eq!((refreshed.read, refreshed.rate_limited), (1, 0));
    assert_eq!(codex_app_server_runs(), before + 1);
    // The setup check's provider read reads too.
    collect_codex_usage_for_home(
        &home,
        CodexHomeTrust::ProviderDefault,
        CodexLoginRefresh::Never,
        CodexQuotaRead::Provider,
    )
    .expect("setup read");
    assert_eq!(codex_app_server_runs(), before + 2);
    // Still nothing scheduled, however late.
    let now = current_unix_seconds();
    assert_eq!(
        codex_saved_quota::scheduled_round(&support, now + 24 * 60 * 60),
        0
    );
    assert_eq!(codex_app_server_runs(), before + 2);

    // On again: the next due read runs.
    settings
        .set_quota_refresh_consent(1, true)
        .expect("turn on");
    assert_eq!(
        codex_saved_quota::scheduled_round(&support, now + 15 * 60 + 1),
        1
    );
    assert_eq!(codex_app_server_runs(), before + 3);

    let binding = read_codex_auth_credentials_at(&home, CodexHomeTrust::ProviderDefault)
        .ok()
        .flatten()
        .and_then(|credentials| codex_credential_claimed_binding(&credentials));
    if let Some(binding) = binding {
        codex_credit_grants::forget_binding_cadence(&binding);
    }
    drop(_guards);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
#[serial]
fn codex_whole_session_failure_backs_off_the_validated_binding() {
    use std::os::unix::fs::PermissionsExt;

    let (root, home) = synthetic_codex_collector_home("session-failure", 0o600);
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let collect = || {
        collect_codex_status_for_home(
            "2026-08-26T00:00:00Z".to_string(),
            "2026-08-26T00:15:00Z".to_string(),
            &home,
            CodexHomeTrust::ProviderDefault,
            CodexLoginRefresh::Never,
            CodexQuotaRead::Provider,
        )
    };

    // A successful reading validates the binding for this home; its
    // detailed read returned a list, so no failure is on record.
    let (_, identity, _) = collect();
    let binding = codex_credit_binding(&identity.expect("validated identity"));
    assert_eq!(codex_credit_grants::last_detail_failed_at(&binding), None);

    // The app-server now dies before any answer: no reading at all.
    let executable = root.join("codex");
    std::fs::write(&executable, "#!/bin/sh\nexit 1\n").expect("failing codex");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("failing codex mode");
    let (snapshot, identity, _) = collect();
    assert!(identity.is_none());
    assert!(snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_usage_probe_failed"));
    assert!(
        codex_credit_grants::last_detail_failed_at(&binding).is_some(),
        "the failed session feeds the detail back-off of the known binding"
    );

    let _ = std::fs::remove_dir_all(root);
}

/// Replace the synthetic home's credential with another account's.
#[cfg(unix)]
fn write_other_synthetic_codex_account(home: &Path) {
    let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
    std::fs::write(
        home.join("auth.json"),
        serde_json::json!({
            "tokens": {
                "access_token": synthetic_codex_access_jwt_with_profile_email(
                    "other-user",
                    "other-workspace",
                    "other-account",
                    "pro",
                    expires_at,
                ),
                "id_token": synthetic_codex_jwt(
                    "other-user",
                    "other-workspace",
                    "other-account",
                    "pro",
                    expires_at,
                )
            },
            "account_id": "other-workspace"
        })
        .to_string(),
    )
    .expect("other account");
}

/// Make the synthetic app-server end before answering `initialize`; the
/// login and model commands still answer, so the home stays signed in.
#[cfg(unix)]
fn fail_synthetic_codex_app_server(root: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let executable = root.join("codex");
    let script = std::fs::read_to_string(&executable).expect("fake Codex");
    std::fs::write(
        &executable,
        script.replace(
            "for line in sys.stdin:",
            "sys.exit(3)\nfor line in sys.stdin:",
        ),
    )
    .expect("failing app-server");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("fake Codex mode");
}

/// Make the fake app-server rewrite the home's `auth.json` with `body`
/// while it answers `account/read`, as Codex does when that read
/// refreshes the token.
#[cfg(unix)]
fn rewrite_auth_during_synthetic_codex_read(root: &Path, home: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    let replacement = root.join("auth-after-read.json");
    std::fs::write(&replacement, body).expect("auth written by the read");
    let executable = root.join("codex");
    let script = std::fs::read_to_string(&executable).expect("fake Codex");
    let rewrite = format!(
        "        open({}, 'w').write(open({}).read())\n",
        serde_json::Value::from(home.join("auth.json").to_str().unwrap()),
        serde_json::Value::from(replacement.to_str().unwrap()),
    );
    let marker = "    elif '\"id\":\"ottto_account\"' in line:\n";
    assert!(script.contains(marker), "fake Codex answers account/read");
    std::fs::write(
        &executable,
        script.replace(marker, &format!("{marker}{rewrite}")),
    )
    .expect("rewriting app-server");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("fake Codex mode");
}

/// A synthetic `auth.json` for `user` in `workspace`, with tokens that
/// expire at `expires_at` (a new value is a new token).
fn synthetic_codex_auth_body(user: &str, workspace: &str, expires_at: i64) -> String {
    serde_json::json!({
        "tokens": {
            "access_token": synthetic_codex_access_jwt_with_profile_email(
                user,
                workspace,
                "synthetic-account",
                "pro",
                expires_at,
            ),
            "id_token": synthetic_codex_jwt(
                user,
                workspace,
                "synthetic-account",
                "pro",
                expires_at,
            ),
        },
        "account_id": workspace,
    })
    .to_string()
}

/// Every real provider read refreshes the token, so Codex rewrites
/// `auth.json` during it. A rewrite for the same account and workspace
/// keeps the reading and the home waits its full interval; a rewrite to
/// another login discards the reading and that login is read after a
/// minute, then kept.
#[cfg(unix)]
#[test]
#[serial]
fn codex_auth_rewritten_by_the_read_keeps_the_reading_for_the_same_login() {
    let (root, home, _guards) = synthetic_default_codex_install("auth-rewrite");
    let support = root.join("support");
    codex_saved_quota::forget_running_homes();
    let later = OffsetDateTime::now_utc().unix_timestamp() + 7_200;
    rewrite_auth_during_synthetic_codex_read(
        &root,
        &home,
        &synthetic_codex_auth_body("synthetic-user", "synthetic-workspace", later),
    );
    let witness = || {
        std::fs::metadata(home.join("auth.json"))
            .unwrap()
            .modified()
            .unwrap()
    };
    let before_read = witness();
    let before = codex_app_server_runs();

    // One scheduled read: the token is rewritten, the reading is kept. A
    // little ahead of the clock, so every attempt is stamped `now` however
    // long the fake read takes.
    let now = current_unix_seconds() + 30;
    assert_eq!(codex_saved_quota::scheduled_round(&support, now), 1);
    assert_eq!(codex_app_server_runs(), before + 1);
    assert_ne!(witness(), before_read, "the read rewrote auth.json");
    let served = codex_saved_quota::serve_saved(&home, CodexHomeTrust::ProviderDefault, now)
        .expect("the reading is served");
    assert!(!served.quota_windows.is_empty());
    let reading_binding = served.saved_identity.as_ref().map(|identity| {
        codex_credit_grants::binding_key(
            &identity.account_identifier_hash,
            &identity.workspace_identifier_hash,
        )
    });
    // Not read again a minute later, nor before the unused interval.
    assert_eq!(codex_saved_quota::scheduled_round(&support, now + 61), 0);
    assert_eq!(
        codex_saved_quota::scheduled_round(&support, now + 15 * 60 - 30),
        0
    );
    assert_eq!(codex_app_server_runs(), before + 1);
    assert_eq!(
        codex_saved_quota::scheduled_round(&support, now + 15 * 60 + 1),
        1
    );
    assert_eq!(codex_app_server_runs(), before + 2);

    // The next read switches the home to another account: that reading
    // cannot be told apart, so it is not saved, and the old account's
    // reading is not served for the new login.
    rewrite_auth_during_synthetic_codex_read(
        &root,
        &home,
        &synthetic_codex_auth_body("another-user", "another-workspace", later),
    );
    let switch_at = now + 30 * 60 + 2;
    assert_eq!(codex_saved_quota::scheduled_round(&support, switch_at), 1);
    assert_eq!(
        codex_saved_quota::serve_saved(&home, CodexHomeTrust::ProviderDefault, switch_at)
            .err()
            .map(|failure| failure.message),
        Some(codex_saved_quota::CODEX_QUOTA_NOT_READ_YET.to_string())
    );
    // The new login is read after a minute, and that reading is kept.
    assert_eq!(
        codex_saved_quota::scheduled_round(&support, switch_at + 30),
        0
    );
    assert_eq!(
        codex_saved_quota::scheduled_round(&support, switch_at + 61),
        1
    );
    let rebound =
        codex_saved_quota::serve_saved(&home, CodexHomeTrust::ProviderDefault, switch_at + 61)
            .expect("the new login's reading is served");
    let rebound_binding = rebound.saved_identity.as_ref().map(|identity| {
        codex_credit_grants::binding_key(
            &identity.account_identifier_hash,
            &identity.workspace_identifier_hash,
        )
    });
    assert!(rebound_binding.is_some());
    assert_ne!(rebound_binding, reading_binding);
    assert_eq!(
        codex_saved_quota::scheduled_round(&support, switch_at + 5 * 60),
        0
    );

    for binding in [reading_binding, rebound_binding].into_iter().flatten() {
        codex_credit_grants::forget_binding_cadence(&binding);
    }
    drop(_guards);
    let _ = std::fs::remove_dir_all(root);
}

fn has_stale_meters(snapshot: &AgentStatusSnapshot) -> bool {
    snapshot
        .quota_windows
        .iter()
        .any(|window| window.freshness == AgentQuotaWindowFreshness::Stale)
        || snapshot
            .credit_balances
            .iter()
            .any(|balance| balance.freshness == AgentQuotaWindowFreshness::Stale)
}

/// Test oracle: the rules by which the shipped Mac app's Codex accounts
/// decoder reads one slot's `collection` of the local status, described
/// by behaviour. A slot this refuses fails the whole status there.
fn mac_admits_codex_slot_collection(collection: &serde_json::Value) -> Result<(), String> {
    let text = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let rows = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    // The state is a closed set; a missing state is `unverified`.
    let state = text(collection, "state").unwrap_or_else(|| "unverified".to_string());
    if ![
        "unverified",
        "fresh",
        "needs_login",
        "identity_unknown",
        "identity_mismatch",
        "provider_unavailable",
        "duplicate_account",
        "unknown",
    ]
    .contains(&state.as_str())
    {
        return Err(format!("state {state} is not decodable"));
    }
    // An identity hash is 64 lowercase hex.
    let strong_hash = |key: &str| -> Result<Option<String>, String> {
        match text(collection, key) {
            Some(hash) if crate::hex::is_sha256_lower(&hash) => Ok(Some(hash)),
            Some(_) => Err(format!("{key} is not a strong hash")),
            None => Ok(None),
        }
    };
    let account = strong_hash("account_identifier_hash")?;
    let workspace = strong_hash("workspace_identifier_hash")?;
    // Both hashes or neither.
    if account.is_some() != workspace.is_some() {
        return Err("one identity hash without the other".to_string());
    }
    // A diagnostic has a code and a message.
    for diagnostic in rows(collection, "diagnostics") {
        if text(&diagnostic, "code").is_none_or(|code| code.is_empty())
            || text(&diagnostic, "message").is_none_or(|message| message.is_empty())
        {
            return Err("empty diagnostic".to_string());
        }
    }
    let snapshot = collection
        .get("quota_snapshot")
        .filter(|value| !value.is_null());
    let mut fresh_evidence = false;
    if let Some(snapshot) = snapshot {
        // A snapshot has a capture time.
        if text(snapshot, "captured_at").is_none_or(|at| at.is_empty()) {
            return Err("quota_snapshot without captured_at".to_string());
        }
        // A snapshot only on these states.
        if !["unknown", "fresh", "duplicate_account"].contains(&state.as_str()) {
            return Err(format!("quota_snapshot on state {state}"));
        }
        // A snapshot only with both hashes.
        let (Some(account), Some(workspace)) = (account.as_ref(), workspace.as_ref()) else {
            return Err("quota_snapshot without identity hashes".to_string());
        };
        let same_identity = |row: &serde_json::Value| {
            text(row, "account_identifier_hash").as_ref() == Some(account)
                && text(row, "organization_identifier_hash").as_ref() == Some(workspace)
        };
        // Every window carries the slot's hashes.
        for window in rows(snapshot, "quota_windows") {
            if !same_identity(&window) {
                return Err("window of another identity".to_string());
            }
            // Fresh evidence is an active fresh window.
            fresh_evidence |= text(&window, "freshness").as_deref() == Some("fresh")
                && window.get("is_active").and_then(serde_json::Value::as_bool) != Some(false);
        }
        // Every balance carries the slot's hashes
        // and a known status and unit.
        for balance in rows(snapshot, "credit_balances") {
            if !same_identity(&balance) {
                return Err("balance of another identity".to_string());
            }
            if !text(&balance, "status").is_some_and(|status| {
                [
                    "ok",
                    "low",
                    "exhausted",
                    "unlimited",
                    "unsupported",
                    "stale",
                    "error",
                    "unknown",
                ]
                .contains(&status.as_str())
            }) {
                return Err("balance status is not decodable".to_string());
            }
            if text(&balance, "unit").is_some_and(|unit| {
                !["credits", "usd", "tokens", "resets", "unknown"].contains(&unit.as_str())
            }) {
                return Err("balance unit is not decodable".to_string());
            }
            // The oracle counts any fresh balance, which is
            // looser than the app and only matters for `fresh` slots.
            fresh_evidence |= text(&balance, "freshness").as_deref() == Some("fresh");
        }
    }
    // A fresh slot proves its reading.
    if state == "fresh"
        && (account.is_none()
            || text(collection, "observed_at").is_none_or(|at| at.is_empty())
            || !fresh_evidence)
    {
        return Err("fresh without identity, read time or fresh meters".to_string());
    }
    Ok(())
}

/// Test oracle for the whole status as the shipped Mac app reads it:
/// every slot by [`mac_admits_codex_slot_collection`]; slot ids and
/// capacity; managed slots that share one account and workspace are one
/// anchor plus declared duplicates; and the account card rule: the app
/// builds one card per account from every slot with that account's
/// hashes, the default slot included, and a slot in state `unknown` is
/// not actionable, which hides the whole card's meters and actions. So
/// an `unknown` slot with hashes must be the only slot of its account.
/// The setup-operation rules are not ported; these fixtures are idle.
fn mac_admits_codex_accounts_status(status: &CodexAccountsStatusV1) -> Result<(), String> {
    let status = serde_json::to_value(status).expect("status JSON");
    let default_slot = &status["default_slot"];
    let managed = status["managed_slots"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut slot_ids = BTreeSet::new();
    for slot in std::iter::once(default_slot).chain(managed.iter()) {
        let slot_id = slot["slot_id"].as_str().unwrap_or_default().to_string();
        mac_admits_codex_slot_collection(slot.get("collection").unwrap_or(&serde_json::json!({})))
            .map_err(|error| format!("{slot_id}: {error}"))?;
        if !slot_ids.insert(slot_id) {
            return Err("slot ids repeat".to_string());
        }
    }
    if default_slot["slot_id"] != "default"
        || managed.iter().any(|slot| slot["slot_id"] == "default")
    {
        return Err("default slot id".to_string());
    }
    let capacity = &status["capacity"];
    let used = capacity["used_slots"].as_u64().unwrap_or_default();
    if capacity["max_slots"].as_u64() != Some(u64::from(ottto_core::MAX_CODEX_ACCOUNT_SLOTS))
        || used != slot_ids.len() as u64
        || capacity["max_slots"].as_u64()
            != Some(used + capacity["remaining_slots"].as_u64().unwrap_or_default())
    {
        return Err("capacity".to_string());
    }
    let mut by_binding = BTreeMap::<(String, String), (usize, usize)>::new();
    for slot in &managed {
        let collection = &slot["collection"];
        let (Some(account), Some(workspace)) = (
            collection["account_identifier_hash"].as_str(),
            collection["workspace_identifier_hash"].as_str(),
        ) else {
            continue;
        };
        let entry = by_binding
            .entry((account.to_string(), workspace.to_string()))
            .or_default();
        entry.0 += 1;
        if collection["relationship"] == "duplicate_anchor"
            || collection["state"] == "duplicate_account"
        {
            entry.1 += 1;
        }
    }
    if by_binding
        .values()
        .any(|(slots, duplicates)| *slots > 1 && slots - duplicates != 1)
    {
        return Err("managed slots share a binding without one anchor".to_string());
    }
    let binding_of = |slot: &serde_json::Value| {
        let collection = &slot["collection"];
        collection["account_identifier_hash"]
            .as_str()
            .zip(collection["workspace_identifier_hash"].as_str())
            .map(|(account, workspace)| (account.to_string(), workspace.to_string()))
    };
    let all_slots = std::iter::once(default_slot)
        .chain(managed.iter())
        .collect::<Vec<_>>();
    for slot in &all_slots {
        if slot["collection"]["state"] != "unknown" {
            continue;
        }
        let Some(binding) = binding_of(slot) else {
            continue;
        };
        if all_slots
            .iter()
            .filter(|other| binding_of(other).as_ref() == Some(&binding))
            .count()
            > 1
        {
            return Err("an unknown slot hides its account's card".to_string());
        }
    }
    Ok(())
}

fn codex_accounts_status_for(candidates: &[CodexSlotCandidate]) -> CodexAccountsStatusV1 {
    let mut status = empty_codex_accounts_status();
    for candidate in candidates {
        if candidate.slot.ownership == CodexAccountSlotOwnershipV1::Managed {
            status.managed_slots.push(CodexAccountSlotDescriptorV1 {
                slot_id: candidate.slot.slot_id.clone(),
                ownership: CodexAccountSlotOwnershipV1::Managed,
                collection: Default::default(),
            });
        }
    }
    status.capacity.used_slots = 1 + status.managed_slots.len() as u8;
    status.capacity.remaining_slots = status.capacity.max_slots - status.capacity.used_slots;
    apply_codex_candidate_statuses(&mut status, candidates);
    status
}

/// The local status of failed probes must decode on every shipped Mac
/// app (one refused slot fails the whole Codex accounts status there)
/// and must not hide an account's fresh meters.
#[cfg(unix)]
#[test]
#[serial]
fn codex_local_status_of_failed_probes_decodes_on_shipped_mac_apps() {
    use std::os::unix::fs::PermissionsExt;

    // A default home whose probe fails after one good reading.
    let (default_root, default_home) = synthetic_codex_collector_home("mac-default", 0o600);
    let failed_default = {
        let _commands = EnvVarGuard::set_os(
            "OTTTO_COMMAND_SEARCH_PATH",
            default_root.as_os_str().to_os_string(),
        );
        let collect = || {
            collect_codex_home_candidate(
                CodexHomeSlot {
                    slot_id: "default".to_string(),
                    ownership: CodexAccountSlotOwnershipV1::Default,
                    home: default_home.clone(),
                    registered_binding: None,
                },
                "2026-08-26T00:00:00Z",
                "2026-08-26T00:15:00Z",
                CodexQuotaRead::Provider,
            )
        };
        let fresh = collect();
        assert_eq!(fresh.status.state, CodexAccountSlotCollectionStateV1::Fresh);
        fail_synthetic_codex_app_server(&default_root);
        (fresh, collect())
    };
    let (fresh_default, failed_default) = failed_default;
    assert_eq!(failed_default.snapshot.status, AgentStatusState::Degraded);

    // A managed home in the same case.
    let (root, home) = synthetic_codex_collector_home("mac-managed", 0o600);
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
        .expect("managed home mode");
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let collect = |slot_id: &str, registered_binding| {
        collect_codex_home_candidate(
            CodexHomeSlot {
                slot_id: slot_id.to_string(),
                ownership: CodexAccountSlotOwnershipV1::Managed,
                home: home.clone(),
                registered_binding,
            },
            "2026-08-26T00:05:00Z",
            "2026-08-26T00:20:00Z",
            CodexQuotaRead::Provider,
        )
    };
    let mut fresh = collect("codex_slot_mac", None);
    let registered = fresh.binding.clone().expect("validated binding");
    fail_synthetic_codex_app_server(&root);
    let failed = collect("codex_slot_mac", Some(registered.clone()));
    assert_eq!(
        failed.status.state,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    );
    assert!(failed.status.quota_snapshot.is_some());

    // What this slot looked like before the fix is what the Mac refuses.
    let mut refused = codex_accounts_status_for(&[]);
    refused.managed_slots.push(CodexAccountSlotDescriptorV1 {
        slot_id: "codex_slot_mac".to_string(),
        ownership: CodexAccountSlotOwnershipV1::Managed,
        collection: failed.status.clone(),
    });
    refused.capacity.used_slots = 2;
    refused.capacity.remaining_slots = refused.capacity.max_slots - 2;
    assert!(mac_admits_codex_accounts_status(&refused).is_err());

    // Kept binding: `unknown`, the registered hashes, the stale reading.
    let candidates = [failed_default, failed];
    let status = codex_accounts_status_for(&candidates);
    mac_admits_codex_accounts_status(&status).expect("failed probes decode on the Mac");
    let managed = &status.managed_slots[0].collection;
    assert_eq!(managed.state, CodexAccountSlotCollectionStateV1::Unknown);
    assert_eq!(
        serde_json::to_value(managed).expect("slot JSON")["state"],
        "unknown"
    );
    assert_eq!(
        managed.account_identifier_hash.as_deref(),
        Some(registered.0.as_str())
    );
    assert_eq!(
        managed.workspace_identifier_hash.as_deref(),
        Some(registered.1.as_str())
    );
    let reading = managed.quota_snapshot.as_ref().expect("last reading");
    assert!(!reading.quota_windows.is_empty());
    assert!(reading
        .quota_windows
        .iter()
        .all(|window| window.freshness == AgentQuotaWindowFreshness::Stale));
    assert!(managed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_identity_unknown"));
    // The default home: no slot reading, no slot hashes.
    let default = &status.default_slot.collection;
    assert!(default.quota_snapshot.is_none());
    assert!(default.account_identifier_hash.is_none());
    assert_ne!(default.state, CodexAccountSlotCollectionStateV1::Unknown);
    // The wire shape changes nothing the daemon decides from.
    let [failed_default, failed] = candidates;
    assert_eq!(
        failed.status.state,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    );
    assert!(failed.binding.is_none());

    // Another managed slot holds the same account: the failed slot
    // gives way instead of becoming a second anchor.
    fresh.slot.slot_id = "codex_slot_other".to_string();
    let candidates = [failed_default, failed, fresh];
    let shared = codex_accounts_status_for(&candidates);
    let [_, failed, _] = candidates;
    mac_admits_codex_accounts_status(&shared).expect("shared binding decodes on the Mac");
    let gave_way = &shared.managed_slots[0].collection;
    assert_eq!(
        gave_way.state,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    );
    assert!(gave_way.quota_snapshot.is_none());
    assert!(gave_way.account_identifier_hash.is_none());
    assert_eq!(
        shared.managed_slots[1].collection.state,
        CodexAccountSlotCollectionStateV1::Fresh
    );

    // The default login reads the same account fresh while the managed
    // slot fails: the managed slot gives way, so the account's card
    // keeps the default login's fresh meters.
    assert_eq!(fresh_default.binding.as_ref(), Some(&registered));
    let candidates = [fresh_default, failed];
    let same_account = codex_accounts_status_for(&candidates);
    mac_admits_codex_accounts_status(&same_account)
        .expect("the default login's card keeps its meters");
    let default = &same_account.default_slot.collection;
    assert_eq!(default.state, CodexAccountSlotCollectionStateV1::Fresh);
    assert!(default
        .quota_snapshot
        .as_ref()
        .is_some_and(|reading| reading
            .quota_windows
            .iter()
            .any(|window| window.freshness == AgentQuotaWindowFreshness::Fresh)));
    let gave_way = &same_account.managed_slots[0].collection;
    assert_eq!(
        gave_way.state,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    );
    assert!(gave_way.quota_snapshot.is_none());
    assert!(gave_way.account_identifier_hash.is_none());
    // The oracle refuses the shape that would hide that card.
    let [_, failed] = candidates;
    let mut hidden = same_account.clone();
    hidden.managed_slots[0].collection = codex_local_slot_status(&failed);
    assert_eq!(
        hidden.managed_slots[0].collection.state,
        CodexAccountSlotCollectionStateV1::Unknown
    );
    assert!(mac_admits_codex_accounts_status(&hidden).is_err());

    // Binding not kept (the credential names another account): no
    // reading, the state as before.
    write_other_synthetic_codex_account(&home);
    let switched = collect("codex_slot_mac", Some(registered.clone()));
    let status = codex_accounts_status_for(&[switched]);
    mac_admits_codex_accounts_status(&status).expect("unkept binding decodes on the Mac");
    let managed = &status.managed_slots[0].collection;
    assert!(managed.quota_snapshot.is_none());
    assert_ne!(managed.state, CodexAccountSlotCollectionStateV1::Unknown);

    codex_credit_grants::forget_binding_cadence(&codex_credit_grants::binding_key(
        &registered.0,
        &registered.1,
    ));
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(default_root);
}

/// Make the fake app-server answer `account/read` with no account, as
/// Codex does once a refresh of the home's login failed for good.
#[cfg(unix)]
fn null_account_synthetic_codex_app_server(root: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let executable = root.join("codex");
    let script = std::fs::read_to_string(&executable).expect("fake Codex");
    let script = script.replace(
        r#"{"account":{"type":"chatgpt","email":"synthetic-account","planType":"pro"},"requiresOpenaiAuth":true}"#,
        r#"{"account":null,"requiresOpenaiAuth":true}"#,
    );
    assert!(script.contains(r#""account":null"#));
    std::fs::write(&executable, script).expect("null-account app-server");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("fake Codex mode");
}

#[cfg(unix)]
#[test]
#[serial]
fn codex_managed_home_whose_refresh_is_dead_needs_a_new_sign_in() {
    use std::os::unix::fs::PermissionsExt;

    let (root, home) = synthetic_codex_collector_home("dead-refresh", 0o600);
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
        .expect("managed home mode");
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let collect = |slot_id: &str,
                   ownership: CodexAccountSlotOwnershipV1,
                   registered_binding: Option<(String, String)>,
                   quota_read: CodexQuotaRead| {
        collect_codex_home_candidate(
            CodexHomeSlot {
                slot_id: slot_id.to_string(),
                ownership,
                home: home.clone(),
                registered_binding,
            },
            "2026-08-26T00:05:00Z",
            "2026-08-26T00:20:00Z",
            quota_read,
        )
    };
    let codes = |candidate: &CodexSlotCandidate| {
        candidate
            .status
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect::<Vec<_>>()
    };

    // A normal account: accepted, bound, as today.
    let fresh = collect(
        "codex_slot_dead_refresh",
        CodexAccountSlotOwnershipV1::Managed,
        None,
        CodexQuotaRead::Provider,
    );
    assert_eq!(fresh.status.state, CodexAccountSlotCollectionStateV1::Fresh);
    let registered = fresh.binding.clone().expect("validated binding");
    let launch = || {
        session_launch_codex_candidate(
            CodexHomeSlot {
                slot_id: "codex_slot_dead_refresh".to_string(),
                ownership: CodexAccountSlotOwnershipV1::Managed,
                home: home.clone(),
                registered_binding: Some(registered.clone()),
            },
            "2026-08-26T00:05:00Z",
        )
    };
    // Control: the launch projection reads the saved good reading as fresh.
    assert_eq!(
        launch().status.state,
        CodexAccountSlotCollectionStateV1::Fresh
    );

    // The read succeeds with no account: the slot's login is dead.
    null_account_synthetic_codex_app_server(&root);
    let dead = collect(
        "codex_slot_dead_refresh",
        CodexAccountSlotOwnershipV1::Managed,
        Some(registered.clone()),
        CodexQuotaRead::Provider,
    );
    assert_eq!(
        dead.status.state,
        CodexAccountSlotCollectionStateV1::NeedsLogin,
        "codes: {:?}",
        codes(&dead)
    );
    assert!(codes(&dead).contains(&"codex_account_needs_login".to_string()));
    assert!(!codes(&dead).contains(&"codex_identity_unknown".to_string()));
    // Nothing binds to it: identity and placement are unchanged.
    assert!(dead.binding.is_none());
    assert!(dead.status.account_identifier_hash.is_none());
    assert!(dead.status.quota_snapshot.is_none());
    let status = codex_accounts_status_for(&[dead]);
    mac_admits_codex_accounts_status(&status).expect("a dead login decodes on the Mac");
    assert_eq!(
        serde_json::to_value(&status.managed_slots[0].collection).expect("slot JSON")["state"],
        "needs_login"
    );
    // The descriptor names the registered pair a reconnect must present.
    assert_eq!(
        codex_slot_status_binding(&status.managed_slots[0].collection),
        Some(registered.clone())
    );
    // The launch projection says the same.
    assert_eq!(
        launch().status.state,
        CodexAccountSlotCollectionStateV1::NeedsLogin
    );
    // A status read served from the saved reading says the same.
    let served = collect(
        "codex_slot_dead_refresh",
        CodexAccountSlotOwnershipV1::Managed,
        Some(registered.clone()),
        CodexQuotaRead::Saved,
    );
    assert_eq!(
        served.status.state,
        CodexAccountSlotCollectionStateV1::NeedsLogin,
        "codes: {:?}",
        codes(&served)
    );

    // The default home, same answer: unchanged, today's state.
    let default = collect(
        "default",
        CodexAccountSlotOwnershipV1::Default,
        None,
        CodexQuotaRead::Provider,
    );
    assert_eq!(
        default.status.state,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    );
    assert!(codes(&default).contains(&"codex_identity_unknown".to_string()));
    assert!(default.binding.is_none());

    // A new sign-in rewrites the auth file: the dead reading is not served.
    write_other_synthetic_codex_account(&home);
    let signed_in_again = collect(
        "codex_slot_dead_refresh",
        CodexAccountSlotOwnershipV1::Managed,
        Some(registered.clone()),
        CodexQuotaRead::Saved,
    );
    assert_ne!(
        signed_in_again.status.state,
        CodexAccountSlotCollectionStateV1::NeedsLogin
    );

    codex_credit_grants::forget_binding_cadence(&codex_credit_grants::binding_key(
        &registered.0,
        &registered.1,
    ));
    let _ = std::fs::remove_dir_all(root);
}

/// [regress] A dead login (the provider named no account) outranks a home
/// that is otherwise still pending (not read yet, background refresh off):
/// the slot asks for a new sign-in.
#[test]
fn codex_dead_login_outranks_a_pending_read() {
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::AuthRequired,
        AgentStatusCollectionMethod::CommandProbe,
        "2026-08-26T00:00:00Z".to_string(),
        "2026-08-26T00:15:00Z".to_string(),
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedOut,
        ..unsupported_account("openai")
    });
    for code in [
        "codex_quota_not_read_yet",
        "codex_quota_background_refresh_off",
    ] {
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            code,
            AgentDiagnosticSeverity::Info,
            "pending",
        ));
    }
    let status = codex_collection_status_from_snapshot(&snapshot);
    assert_eq!(status.state, CodexAccountSlotCollectionStateV1::NeedsLogin);
    assert_eq!(status.diagnostics[0].code, "codex_account_needs_login");
}

#[test]
fn codex_forced_refresh_logs_its_outcome_class_and_home_digest_only() {
    assert_eq!(
        codex_forced_refresh_outcome(true, true, true),
        "account_null"
    );
    assert_eq!(codex_forced_refresh_outcome(false, true, true), "timeout");
    assert_eq!(
        codex_forced_refresh_outcome(false, false, true),
        "rewritten"
    );
    assert_eq!(
        codex_forced_refresh_outcome(false, false, false),
        "not_rewritten"
    );
    assert!(codex_app_server_account_absent(
        &serde_json::json!({"account": null, "requiresOpenaiAuth": true})
    ));
    // No account field at all, or no sign-in needed, is not a dead login.
    assert!(!codex_app_server_account_absent(&serde_json::json!({})));
    assert!(!codex_app_server_account_absent(
        &serde_json::json!({"account": null, "requiresOpenaiAuth": false})
    ));

    let home = Path::new("/synthetic/private/codex-home");
    let line = codex_forced_refresh_log_line(
        "lapsed_or_unknown",
        "account_null",
        home,
        Duration::from_millis(1234),
        0,
    );
    assert!(line.starts_with(
        "codex usage probe: forcing account home login refresh reason=lapsed_or_unknown "
    ));
    assert!(line.contains(" outcome=account_null "));
    assert!(line.contains(&format!(" home={} ", codex_home_log_label(home))));
    assert!(line.ends_with(" elapsed_ms=1234"));
    assert!(!line.contains("synthetic"));
    // The same digest as the failure line, so the two rows join.
    assert!(codex_probe_failure_log_line("x", home, Duration::ZERO, 0)
        .contains(&format!(" home={} ", codex_home_log_label(home))));
}

/// Make the fake app-server answer the routine rate-limits read with an
/// RPC error (`error`) or not at all (`silent`).
#[cfg(unix)]
fn fail_synthetic_codex_quota_read(root: &Path, mode: &str) {
    use std::os::unix::fs::PermissionsExt;

    let executable = root.join("codex");
    let script = std::fs::read_to_string(&executable).expect("fake Codex");
    let branch = "    elif \"account/rateLimits/read\" in line:\n";
    assert!(script.contains(branch));
    let answer = match mode {
        "error" => "        print('{\"id\":\"ottto_rate_limits\",\"error\":{\"code\":-32603,\"message\":\"synthetic\"}}', flush=True)\n        continue\n",
        _ => "        continue\n",
    };
    std::fs::write(
        &executable,
        script.replace(branch, &format!("{branch}{answer}")),
    )
    .expect("failing quota read");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("fake Codex mode");
}

/// [regress] `account: null` followed by a failed or unanswered quota read
/// is still a dead login: provider, saved and launch reads say needs_login,
/// the descriptor names the registered pair, a new sign-in clears it, and
/// the default home is unchanged.
#[cfg(unix)]
#[test]
#[serial]
fn codex_dead_login_survives_a_failed_quota_read() {
    use std::os::unix::fs::PermissionsExt;

    for mode in ["error", "silent"] {
        let (root, home) = synthetic_codex_collector_home(&format!("dead-quota-{mode}"), 0o600);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
            .expect("managed home mode");
        let _commands =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
        let slot =
            |ownership: CodexAccountSlotOwnershipV1,
             registered_binding: Option<(String, String)>| CodexHomeSlot {
                slot_id: if ownership == CodexAccountSlotOwnershipV1::Default {
                    "default".to_string()
                } else {
                    "codex_slot_dead_quota".to_string()
                },
                ownership,
                home: home.clone(),
                registered_binding,
            };
        let collect = |ownership: CodexAccountSlotOwnershipV1,
                       registered_binding: Option<(String, String)>,
                       quota_read: CodexQuotaRead| {
            with_codex_app_server_test_timeouts(
                Duration::from_secs(3),
                Duration::from_secs(1),
                Duration::from_secs(3),
                || {
                    collect_codex_home_candidate(
                        slot(ownership, registered_binding),
                        "2026-08-26T00:05:00Z",
                        "2026-08-26T00:20:00Z",
                        quota_read,
                    )
                },
            )
        };
        let managed = CodexAccountSlotOwnershipV1::Managed;
        let fresh = collect(managed, None, CodexQuotaRead::Provider);
        let registered = fresh.binding.clone().expect("validated binding");

        null_account_synthetic_codex_app_server(&root);
        fail_synthetic_codex_quota_read(&root, mode);
        let dead = collect(managed, Some(registered.clone()), CodexQuotaRead::Provider);
        assert_eq!(
            dead.status.state,
            CodexAccountSlotCollectionStateV1::NeedsLogin,
            "{mode}"
        );
        assert!(dead.binding.is_none());
        let status = codex_accounts_status_for(&[dead]);
        mac_admits_codex_accounts_status(&status).expect("decodes on the Mac");
        assert_eq!(
            codex_slot_status_binding(&status.managed_slots[0].collection),
            Some(registered.clone())
        );
        let served = collect(managed, Some(registered.clone()), CodexQuotaRead::Saved);
        assert_eq!(
            served.status.state,
            CodexAccountSlotCollectionStateV1::NeedsLogin,
            "{mode}"
        );
        let launched = session_launch_codex_candidate(
            slot(managed, Some(registered.clone())),
            "2026-08-26T00:05:00Z",
        );
        assert_eq!(
            launched.status.state,
            CodexAccountSlotCollectionStateV1::NeedsLogin,
            "{mode}"
        );

        // The default home, same answers: not a dead login.
        let default = collect(
            CodexAccountSlotOwnershipV1::Default,
            None,
            CodexQuotaRead::Provider,
        );
        assert_ne!(
            default.status.state,
            CodexAccountSlotCollectionStateV1::NeedsLogin,
            "{mode}"
        );

        // A new sign-in to the same account and workspace rewrites the
        // credential: the dead failure is not served, in status or launch.
        let mut body = std::fs::read(home.join("auth.json")).expect("auth body");
        body.push(b' ');
        std::fs::write(home.join("auth.json"), body).expect("same-pair sign-in");
        let same_pair = collect(managed, Some(registered.clone()), CodexQuotaRead::Saved);
        assert_ne!(
            same_pair.status.state,
            CodexAccountSlotCollectionStateV1::NeedsLogin,
            "{mode}"
        );
        let relaunched = session_launch_codex_candidate(
            slot(managed, Some(registered.clone())),
            "2026-08-26T00:05:00Z",
        );
        assert_ne!(
            relaunched.status.state,
            CodexAccountSlotCollectionStateV1::NeedsLogin,
            "{mode}"
        );

        // A new sign-in to another account: the dead failure is not served.
        write_other_synthetic_codex_account(&home);
        let signed_in_again = collect(managed, Some(registered.clone()), CodexQuotaRead::Saved);
        assert_ne!(
            signed_in_again.status.state,
            CodexAccountSlotCollectionStateV1::NeedsLogin,
            "{mode}"
        );

        codex_credit_grants::forget_binding_cadence(&codex_credit_grants::binding_key(
            &registered.0,
            &registered.1,
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(unix)]
#[test]
#[serial]
fn codex_managed_failed_probe_keeps_the_last_reading_local_and_uploads_none() {
    use std::os::unix::fs::PermissionsExt;

    let (root, home) = synthetic_codex_collector_home("last-known", 0o600);
    // A managed home is private to its owner.
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
        .expect("managed home mode");
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let slot = |registered_binding| CodexHomeSlot {
        slot_id: "codex_slot_last_known".to_string(),
        ownership: CodexAccountSlotOwnershipV1::Managed,
        home: home.clone(),
        registered_binding,
    };
    let collect = |registered_binding| {
        collect_codex_home_candidate(
            slot(registered_binding),
            "2026-08-26T00:05:00Z",
            "2026-08-26T00:20:00Z",
            CodexQuotaRead::Provider,
        )
    };

    // A successful reading through the collector.
    let fresh = collect(None);
    assert_eq!(fresh.status.state, CodexAccountSlotCollectionStateV1::Fresh);
    let registered = fresh.binding.clone().expect("validated binding");
    assert!(!fresh.snapshot.quota_windows.is_empty());

    fail_synthetic_codex_app_server(&root);
    let failed = collect(Some(registered.clone()));
    assert!(failed.binding.is_none());
    assert_eq!(
        failed.status.state,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    );

    // Local status: the slot shows its last reading, marked stale, with
    // the original read clocks.
    let mut expected_windows = fresh.snapshot.quota_windows.clone();
    let mut expected_balances = fresh.snapshot.credit_balances.clone();
    mark_quota_meters_stale(&mut expected_windows, &mut expected_balances);
    let local = failed.status.quota_snapshot.clone().expect("local reading");
    assert_eq!(local.quota_windows, expected_windows);
    assert_eq!(local.credit_balances, expected_balances);
    assert!(local
        .quota_windows
        .iter()
        .all(|window| window.observed_at.is_some()));

    // Past the cap nothing is shown.
    assert!(codex_last_known_slot_reading(
        &slot(Some(registered.clone())),
        "2026-08-26T00:05:00Z",
        current_unix_seconds() + codex_last_known::LAST_KNOWN_MAX_AGE_SECS + 1,
    )
    .is_none());

    // Upload: the failure shape only, never the last reading.
    let placeholder = configured_unavailable_snapshot(failed);
    assert!(placeholder.quota_windows.is_empty());
    assert!(placeholder.credit_balances.is_empty());
    let uploaded = placeholder.redacted_for_backend();
    assert!(uploaded.quota_windows.is_empty());
    assert!(uploaded.credit_balances.is_empty());
    assert_eq!(
        uploaded
            .account
            .as_ref()
            .and_then(|account| account.account_identifier_hash.as_deref()),
        Some(registered.0.as_str())
    );

    // The home's credential now names another account, never validated
    // here: the registered account's reading is not shown.
    write_other_synthetic_codex_account(&home);
    let switched = collect(Some(registered.clone()));
    assert!(switched.status.quota_snapshot.is_none());

    // Signed out (no credential): nothing either.
    std::fs::remove_file(home.join("auth.json")).expect("sign out");
    let signed_out = collect(Some(registered.clone()));
    assert!(signed_out.status.quota_snapshot.is_none());

    // The failed sessions charged the shared synthetic binding a detail
    // back-off; other collector tests expect none.
    codex_credit_grants::forget_binding_cadence(&codex_credit_grants::binding_key(
        &registered.0,
        &registered.1,
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
#[serial]
fn credential_read_failure_emits_typed_diagnostic_with_fail_closed_meters() {
    let (root, home) = synthetic_codex_collector_home("unsafe-auth", 0o644);
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());

    let (snapshot, identity, _) = collect_codex_status_for_home(
        "2026-08-26T00:00:00Z".to_string(),
        "2026-08-26T00:15:00Z".to_string(),
        &home,
        CodexHomeTrust::ProviderDefault,
        CodexLoginRefresh::Never,
        CodexQuotaRead::Provider,
    );

    assert!(identity.is_none());
    assert!(snapshot.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "codex_credential_read_failed"
            && diagnostic.message
                == "Codex credentials could not be read safely; account-bound meters were suppressed."
    }));
    assert!(snapshot.quota_windows.is_empty());
    assert!(snapshot.credit_balances.is_empty());
    assert!(snapshot
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.code != "codex_app_server_usage_response"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn codex_app_server_read_clock_requires_bound_check_and_stamps_windows() {
    let completed_at = "2026-09-01T10:00:00Z".to_string();
    let probe = codex_usage_probe_from_app_server_observation(CodexAppServerObservation {
        account: serde_json::json!({"account": {"type": "chatgpt", "planType": "pro"}}),
        rate_limits: serde_json::json!({"rateLimits": {"primary": {"usedPercent": 12, "windowDurationMins": 10080}}}),
        refreshed_credentials: None,
        credential_read_failed: false,
        response_completed_at: Some(completed_at.clone()),
        details_requested: true,
        details_answered: true,
    });
    assert_eq!(
        probe.response_completed_at.as_deref(),
        Some(completed_at.as_str())
    );
    assert!(!probe.quota_windows.is_empty());
    assert!(probe
        .quota_windows
        .iter()
        .all(|window| window.observed_at.as_deref() == Some(completed_at.as_str())));
    let identity = CodexStrongIdentity {
        account_identifier_hash: "account-a".to_string(),
        workspace_identifier_hash: "workspace-a".to_string(),
        raw_workspace_id: "unused".to_string(),
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
    };
    let diagnostic = codex_app_server_success_diagnostic(
        Some(completed_at.clone()),
        Some(&CodexIdentityHashes::from(&identity)),
        true,
    )
    .expect("bound check");
    assert_eq!(
        diagnostic.observed_at.as_deref(),
        Some(completed_at.as_str())
    );
    assert_eq!(
        diagnostic.organization_identifier_hash.as_deref(),
        Some("workspace-a")
    );
    assert!(codex_app_server_success_diagnostic(
        None,
        Some(&CodexIdentityHashes::from(&identity)),
        true
    )
    .is_none());
    assert!(codex_app_server_success_diagnostic(Some(completed_at.clone()), None, true).is_none());
    assert!(codex_app_server_success_diagnostic(
        Some(completed_at),
        Some(&CodexIdentityHashes::from(&identity)),
        false
    )
    .is_none());
    assert!(codex_app_server_success_diagnostic(
        Some("2099-01-01T00:00:00Z".to_string()),
        Some(&CodexIdentityHashes::from(&identity)),
        true
    )
    .is_none());
}

/// A fake `codex` in `dir` that answers the limits probe and appends each
/// `account/read` `refreshToken` value to `dir/refresh.log`.
fn write_fake_codex_app_server(dir: &Path) {
    let helper = dir.join("fake_codex.py");
    std::fs::write(
        &helper,
        r#"import json
import os
import sys

if sys.argv[1:] != [
    "-c", "skills.bundled.enabled=false", "-c", "features.plugins=false", "app-server", "--stdio"
]:
    sys.exit(1)
if os.environ.get("CODEX_SQLITE_HOME") != os.environ.get("CODEX_HOME"):
    sys.exit(2)
if "OPENAI_API_KEY" in os.environ:
    sys.exit(3)

account_read = False
for line in sys.stdin:
    if '"id":1' in line:
        print('{"id":1,"result":{"userAgent":"fake"}}', flush=True)
    if '"id":"ottto_account"' in line:
        account_read = True
        refresh = json.loads(line).get("params", {}).get("refreshToken")
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "refresh.log"), "a") as log:
            log.write(json.dumps(refresh) + "\n")
        print('{"id":"ottto_account","result":{"account":{"type":"chatgpt","email":"synthetic-user","planType":"pro"},"requiresOpenaiAuth":true}}', flush=True)
    if "account/rateLimits/read" in line:
        if not account_read:
            sys.exit(5)
        print('{"id":"ottto_rate_limits","result":{"rateLimitResetCredits":{"availableCount":2},"rateLimitsByLimitId":{},"rateLimits":{}}}', flush=True)
"#,
    )
    .expect("write helper");
    let executable = dir.join("codex");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nexec /usr/bin/python3 '{}' \"$@\"\n",
            helper.display()
        ),
    )
    .expect("write executable");
    let mut permissions = std::fs::metadata(&executable)
        .expect("metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&executable, permissions).expect("chmod executable");
}

/// [behaviour] The probe starts Codex with its home-writing startup
/// installers off, shares CODEX_HOME as the SQLite home, drops provider
/// keys and keeps stdin open for the asynchronous default-home answer.
/// The default home never forces a token refresh.
#[test]
#[serial]
fn codex_app_server_reader_keeps_stdin_open_until_async_response() {
    let dir = std::env::temp_dir().join(format!("ottto-app-server-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    write_fake_codex_app_server(&dir);

    let _guard = EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
    let _provider = EnvVarGuard::set_os("OPENAI_API_KEY", OsString::from("must-not-pass"));
    let _sqlite = EnvVarGuard::set_os(
        "CODEX_SQLITE_HOME",
        OsString::from("synthetic-shared-store"),
    );
    let value = call_codex_app_server_rate_limits().expect("rate limits");

    assert_eq!(
        value
            .pointer("/rateLimitResetCredits/availableCount")
            .and_then(Value::as_u64),
        Some(2)
    );
    let refreshes = std::fs::read_to_string(dir.join("refresh.log")).expect("refresh log");
    assert_eq!(refreshes.lines().collect::<Vec<_>>(), ["false"]);

    let _ = std::fs::remove_dir_all(dir);
}

/// [regress] A registered account slot whose login has lapsed is
/// refreshed by the limits probe, and one with a live login is not, so its
/// workspace stays confirmed; Codex 0.163 does not persist a refresh of its
/// own. A home seen only through a running Codex process (a person's own
/// `CODEX_HOME`) is never refreshed. Control: the default home is never
/// refreshed, even with a lapsed login.
#[test]
#[serial]
fn codex_probe_refreshes_only_a_lapsing_registered_slot_login() {
    let dir = std::env::temp_dir().join(format!("ottto-app-server-refresh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    write_fake_codex_app_server(&dir);
    let _guard = EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let home_with_login = |label: &str, expires_at: i64| {
        let home = crate::test_scratch::ScratchDir::canonical(label);
        let token = synthetic_codex_jwt(
            "synthetic-user",
            "synthetic-workspace",
            "synthetic-account",
            "pro",
            expires_at,
        );
        let auth = home.join("auth.json");
        std::fs::write(
            &auth,
            serde_json::json!({"tokens": {"access_token": token, "id_token": token}}).to_string(),
        )
        .expect("auth fixture");
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).expect("auth mode");
        home
    };
    let lapsed = home_with_login("codex-refresh-lapsed", now - 60);
    let live = home_with_login("codex-refresh-live", now + 3600);
    let registered = |home: PathBuf| CodexHomeSlot {
        slot_id: "synthetic-slot".to_string(),
        ownership: CodexAccountSlotOwnershipV1::Managed,
        home,
        registered_binding: Some((
            "synthetic-account-hash".to_string(),
            "synthetic-workspace-hash".to_string(),
        )),
    };
    let default_home = CodexHomeSlot {
        slot_id: "default".to_string(),
        ownership: CodexAccountSlotOwnershipV1::Default,
        home: lapsed.to_path_buf(),
        registered_binding: None,
    };
    for (slot, trust) in [
        (registered(lapsed.to_path_buf()), CodexHomeTrust::Managed),
        (registered(live.to_path_buf()), CodexHomeTrust::Managed),
        (
            CodexHomeSlot::process_home(lapsed.to_path_buf()),
            CodexHomeTrust::Managed,
        ),
        (default_home, CodexHomeTrust::ProviderDefault),
    ] {
        call_codex_app_server_rate_limits_for_home(
            &slot.home,
            trust,
            slot.login_refresh(),
            &|_, _, _| false,
        )
        .expect("rate limits");
    }

    let refreshes = std::fs::read_to_string(dir.join("refresh.log")).expect("refresh log");
    assert_eq!(
        refreshes.lines().collect::<Vec<_>>(),
        ["true", "false", "false", "false"],
        "lapsed registered slot, live registered slot, lapsed process-only home, \
             lapsed default home (control)"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// [regress] A forced-refresh read of a registered slot that times out
/// holds the next forced refresh (`refreshToken: false`, logged as
/// `backoff_after_timeout`); the read itself still runs. A successful read
/// lifts the hold, and the next read forces the refresh again.
#[test]
#[serial]
fn codex_probe_holds_forced_refresh_after_a_timeout_until_a_read_succeeds() {
    let dir = std::env::temp_dir().join(format!("ottto-app-server-backoff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    write_fake_codex_app_server(&dir);
    // While `dir/hang` exists the fake logs `account/read` and never answers.
    let helper = dir.join("fake_codex.py");
    let script = std::fs::read_to_string(&helper).expect("helper");
    let hang = "            log.write(json.dumps(refresh) + \"\\n\")\n";
    assert!(script.contains(hang));
    std::fs::write(
        &helper,
        script.replace(
            hang,
            &format!(
                "{hang}        if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), \"hang\")):\n            continue\n"
            ),
        ),
    )
    .expect("hanging helper");
    let _guard = EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());

    let home = crate::test_scratch::ScratchDir::canonical("codex-refresh-backoff");
    let token = synthetic_codex_jwt(
        "synthetic-user",
        "synthetic-workspace",
        "synthetic-account",
        "pro",
        OffsetDateTime::now_utc().unix_timestamp() - 60,
    );
    let auth = home.join("auth.json");
    std::fs::write(
        &auth,
        serde_json::json!({"tokens": {"access_token": token, "id_token": token}}).to_string(),
    )
    .expect("auth fixture");
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).expect("auth mode");
    let read = || {
        with_codex_app_server_test_timeouts(
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(2),
            || {
                codex_saved_quota::read_provider_and_save(
                    &home,
                    CodexHomeTrust::Managed,
                    CodexLoginRefresh::WhenLapsing,
                    |_, _| true,
                )
                .expect("admitted")
            },
        )
    };

    std::fs::write(dir.join("hang"), b"").expect("hang");
    assert!(read().is_err(), "the forced-refresh read times out");
    assert!(codex_saved_quota::refresh_held(&home));
    assert_eq!(
        codex_probe_refresh_reason(
            &home,
            CodexHomeTrust::Managed,
            CodexLoginRefresh::WhenLapsing,
            current_unix_seconds(),
        ),
        Some(CODEX_REFRESH_BACKOFF_REASON)
    );
    // An unreadable credential is held too.
    let body = std::fs::read(&auth).expect("auth body");
    std::fs::write(&auth, b"not json").expect("unreadable auth");
    assert_eq!(
        codex_probe_refresh_reason(
            &home,
            CodexHomeTrust::Managed,
            CodexLoginRefresh::WhenLapsing,
            current_unix_seconds(),
        ),
        Some(CODEX_REFRESH_BACKOFF_REASON)
    );
    std::fs::write(&auth, body).expect("auth restored");
    std::fs::remove_file(dir.join("hang")).expect("answer again");
    read().expect("held read still reads");
    assert!(!codex_saved_quota::refresh_held(&home));
    read().expect("forcing resumed");

    let refreshes = std::fs::read_to_string(dir.join("refresh.log")).expect("refresh log");
    assert_eq!(
        refreshes.lines().collect::<Vec<_>>(),
        ["true", "false", "true"],
        "timed out, held, resumed"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn codex_app_server_stdout_reader_enforces_line_total_and_message_bounds() {
    let oversized = vec![b'x'; CODEX_APP_SERVER_MAX_LINE_BYTES + 1];
    let (sender, receiver) = mpsc::sync_channel(CODEX_APP_SERVER_CHANNEL_CAPACITY);
    read_bounded_codex_app_server_stdout(std::io::Cursor::new(oversized), sender);

    assert!(receiver
        .recv()
        .expect("bounded reader result")
        .expect_err("oversized output must fail")
        .contains("byte limit"));

    let chunk = vec![b'x'; CODEX_APP_SERVER_MAX_LINE_BYTES / 2];
    let mut total_oversized = Vec::new();
    while total_oversized.len() <= CODEX_APP_SERVER_MAX_TOTAL_BYTES {
        total_oversized.extend_from_slice(&chunk);
        total_oversized.push(b'\n');
    }
    let (sender, receiver) = mpsc::sync_channel(CODEX_APP_SERVER_CHANNEL_CAPACITY);
    read_bounded_codex_app_server_stdout(std::io::Cursor::new(total_oversized), sender);
    assert!(receiver
        .recv()
        .expect("bounded reader result")
        .expect_err("total output must fail")
        .contains("byte limit"));

    let messages = "{}\n".repeat(CODEX_APP_SERVER_MAX_MESSAGES + 1);
    let (sender, receiver) = mpsc::sync_channel(CODEX_APP_SERVER_MAX_MESSAGES + 1);
    read_bounded_codex_app_server_stdout(std::io::Cursor::new(messages), sender);
    let results = receiver.into_iter().collect::<Vec<_>>();
    assert_eq!(results.len(), CODEX_APP_SERVER_MAX_MESSAGES + 1);
    assert!(results
        .last()
        .expect("message-limit result")
        .as_ref()
        .expect_err("message count must fail")
        .contains("message limit"));
}

/// A scripted Codex app-server for the rate-limit probe's failure
/// messages. `mode` picks the failure; provider text and data markers in
/// every error must never reach a returned message.
const CODEX_PROBE_FAILURE_FAKE: &str = r#"import json
import os
import signal
import sys

if sys.argv[-2:] != ["app-server", "--stdio"]:
    sys.exit(1)
mode = os.environ["FAKE_CODEX_MODE"]
if mode in ("early_exit", "signal_exit", "line_bound", "message_bound", "total_bound"):
    # Take initialize, initialized and account/read first, so the collector's
    # opening writes never race this process's exit.
    for _ in range(3):
        sys.stdin.readline()
if mode == "early_exit":
    sys.exit(2)
if mode == "signal_exit":
    os.kill(os.getpid(), signal.SIGTERM)
if mode == "line_bound":
    print("x" * (256 * 1024 + 1), flush=True)
    sys.exit(0)
if mode == "message_bound":
    print("{}\n" * 257, end="", flush=True)
    sys.exit(0)
if mode == "total_bound":
    print(("x" * 20000 + "\n") * 106, end="", flush=True)
    sys.exit(0)
PROVIDER_ERROR = {"message": "sensitive-provider-text", "data": {"url": "private-url-marker"}}

def reply(request_id, result=None, code=None, with_code=True):
    if result is not None:
        print(json.dumps({"id": request_id, "result": result}), flush=True)
        return
    error = dict(PROVIDER_ERROR)
    if with_code:
        error["code"] = code
    print(json.dumps({"id": request_id, "error": error}), flush=True)

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    request_id = request.get("id")
    if method == "initialize":
        if mode in ("initialize_error", "initialize_error_then_account_error"):
            reply(1, code=-32602)
            if mode == "initialize_error":
                sys.exit(0)
        else:
            reply(1, {})
    elif method == "account/read":
        if mode in ("account_error", "initialize_error_then_account_error"):
            reply(request_id, code=-32603)
            sys.exit(0)
        if mode == "account_error_without_code":
            reply(request_id, with_code=False)
            sys.exit(0)
        reply(request_id, {"account": {"type": "chatgpt", "planType": "pro"}})
    elif method == "account/rateLimits/read":
        if mode == "quota_eof":
            # The quota request arrived; go away without answering it.
            sys.exit(0)
        if mode == "quota_error":
            reply(request_id, code=-32603)
            sys.exit(0)
        if mode == "routine_rejected" and request_id == "ottto_rate_limits":
            # An older CLI refuses the routine parameter without asking the
            # provider.
            reply(request_id, code=-32602)
            continue
        reply(request_id, {"rateLimits": {"primary": {"usedPercent": 25, "windowDurationMins": 300}}})
"#;

/// Run the probe against [`CODEX_PROBE_FAILURE_FAKE`] in `mode` with an
/// empty synthetic Codex home.
#[cfg(unix)]
fn run_codex_probe_failure_fake(mode: &str) -> Result<CodexAppServerObservation, String> {
    let dir = crate::test_scratch::ScratchDir::new("codex-probe-failure");
    let home = dir.join("codex-home");
    std::fs::create_dir_all(&home).expect("synthetic codex home");
    let script = dir.join("fake_codex.py");
    std::fs::write(&script, CODEX_PROBE_FAILURE_FAKE).expect("fake app-server");
    // The app-server child gets a cleared environment, so the launcher
    // carries the mode.
    let executable = dir.join("codex");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nFAKE_CODEX_MODE='{mode}' exec /usr/bin/python3 '{}' \"$@\"\n",
            script.display()
        ),
    )
    .expect("fake codex");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("fake codex mode");
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
    call_codex_app_server_rate_limits_for_home(
        &home,
        CodexHomeTrust::Managed,
        CodexLoginRefresh::Never,
        &|_, _, _| false,
    )
}

fn assert_no_provider_text(message: &str) {
    assert!(
        !message.contains("sensitive-provider-text") && !message.contains("private-url-marker"),
        "provider text leaked: {message}"
    );
}

/// [behaviour] A failed probe names its phase and the numeric JSON-RPC
/// code only; provider error text and data never reach the message.
#[cfg(unix)]
#[test]
#[serial]
fn codex_probe_failures_name_the_phase_and_numeric_code_only() {
    for (mode, expected) in [
        (
            "initialize_error",
            "Codex app-server initialize RPC failed with code -32602.",
        ),
        (
            "account_error",
            "Codex app-server account RPC failed with code -32603.",
        ),
        // The earlier initialize rejection, not the account error it
        // caused, is reported.
        (
            "initialize_error_then_account_error",
            "Codex app-server initialize RPC failed with code -32602.",
        ),
        (
            "account_error_without_code",
            "Codex app-server account RPC failed without a numeric code.",
        ),
        (
            "quota_error",
            "Codex app-server quota RPC failed with code -32603.",
        ),
        // The reader bounds are unchanged: 256 KiB line, 256 messages,
        // 2 MiB total.
        (
            "line_bound",
            "Codex app-server output exceeded its byte limit.",
        ),
        (
            "message_bound",
            "Codex app-server output exceeded its message limit.",
        ),
        (
            "total_bound",
            "Codex app-server output exceeded its byte limit.",
        ),
    ] {
        let message = run_codex_probe_failure_fake(mode).err().expect(mode);
        assert_eq!(message, expected, "{mode}");
        assert_no_provider_text(&message);
    }
}

/// A request made with a Codex token is logged under the same user hash
/// as reads of the home that holds it.
#[cfg(unix)]
#[test]
fn a_codex_token_names_the_same_account_as_its_home() {
    let (root, home) = synthetic_codex_collector_home("token-account", 0o600);
    let credentials = read_codex_auth_credentials_at(&home, CodexHomeTrust::ProviderDefault)
        .expect("readable")
        .expect("credential");
    let from_token = codex_access_token_claimed_account_hash(
        credentials.access_token.as_deref().expect("token"),
    );
    assert!(from_token.is_some());
    assert_eq!(
        from_token,
        codex_home_claimed_account_hash(&home, CodexHomeTrust::ProviderDefault)
    );
    assert_eq!(codex_access_token_claimed_account_hash("not-a-jwt"), None);
    let _ = std::fs::remove_dir_all(root);
}

/// Each app-server run that started is one provider-call line counting
/// the requests it sent, answered or not: a failed or timed-out read still
/// counts its token refresh and rate-limits read. A routine read an older
/// CLI refused locally is not counted.
#[cfg(unix)]
#[test]
#[serial]
fn codex_probe_runs_count_sent_provider_requests_even_when_they_fail() {
    use crate::provider_calls::CallKind;
    let support = crate::test_scratch::ScratchDir::new("codex-probe-call-log");
    let _support = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support.as_os_str().to_os_string(),
    );
    let modes = [
        "initialize_error",
        "account_error",
        "quota_error",
        "quota_eof",
        "success",
        "routine_rejected",
    ];
    for mode in modes {
        let _ = run_codex_probe_failure_fake(mode);
    }
    let lines = crate::provider_calls::test_lines(CallKind::CodexAppServerQuota, "unknown");
    assert_eq!(
        lines
            .iter()
            .map(|line| (line.result.as_str(), line.requests_at_least))
            .collect::<Vec<_>>(),
        [
            ("rpc_error", 2),
            ("rpc_error", 2),
            ("rpc_error", 2),
            ("exited", 2),
            ("ok", 2),
            ("ok", 2),
        ]
    );
    assert!(!crate::provider_calls::test_raw_log().contains("sensitive-provider-text"));
}

#[test]
#[serial]
fn codex_slots_pin_sqlite_home_and_drop_all_ambient_credentials() {
    let dir = std::env::temp_dir().join(format!("ottto-codex-exact-home-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let executable = dir.join("codex");
    std::fs::write(
        &executable,
        "#!/bin/sh\nprintf '%s|%s|%s' \"$CODEX_HOME\" \"$CODEX_SQLITE_HOME\" \"${OPENAI_API_KEY+present}\"\n",
    )
    .expect("write executable");
    let mut permissions = std::fs::metadata(&executable)
        .expect("metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&executable, permissions).expect("chmod executable");
    let managed_home = dir.join("managed-home");
    std::fs::create_dir(&managed_home).expect("managed home");

    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
    let _provider = EnvVarGuard::set_os("OPENAI_API_KEY", OsString::from("must-not-pass"));
    let _shared_sqlite = EnvVarGuard::set_os(
        "CODEX_SQLITE_HOME",
        OsString::from("synthetic-shared-store"),
    );
    let output = run_codex_home_command(
        &managed_home,
        &["login", "status"],
        Duration::from_secs(2),
        false,
    );

    assert!(output.success, "{output:?}");
    assert_eq!(
        output.stdout,
        format!("{}|{}|", managed_home.display(), managed_home.display())
    );

    let second_home = dir.join("second-home");
    std::fs::create_dir(&second_home).expect("second home");
    let default_style_output = run_codex_home_command(
        &second_home,
        &["login", "status"],
        Duration::from_secs(2),
        true,
    );
    assert!(default_style_output.success, "{default_style_output:?}");
    assert_eq!(
        default_style_output.stdout,
        format!("{}|{}|", second_home.display(), second_home.display())
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn codex_text_parser_extracts_account_model_quota_and_context() {
    let snapshot = parse_codex_status_fallback(
        "Logged in as test@example.com\nPlan: Pro\nModel: gpt-5.1\nUsage quota: 18% left\nContext: 72% used",
        "2026-05-06T10:00:00Z".to_string(),
        "2026-05-06T10:05:00Z".to_string(),
    );

    assert_eq!(snapshot.status, AgentStatusState::Available);
    assert_eq!(
        snapshot.account.and_then(|account| account.email),
        Some("test@example.com".to_string())
    );
    assert_eq!(
        snapshot.model.and_then(|model| model.active_model),
        Some("gpt-5.1".to_string())
    );
    assert_eq!(
        snapshot.quota_windows[0].status,
        AgentQuotaWindowStatus::NearLimit
    );
    assert_eq!(
        snapshot.context.and_then(|context| context.used_percent),
        Some(72)
    );
}

#[test]
fn codex_bundled_models_preserve_structured_gpt56_metadata() {
    let output = CommandOutput {
        command_found: true,
        success: true,
        status_code: Some(0),
        stdout: serde_json::json!({
            "models": [
                {
                    "slug": "gpt-5.6-sol",
                    "display_name": "GPT-5.6-Sol",
                    "description": "Latest frontier agentic coding model.",
                    "context_window": 372000,
                    "max_context_window": 372000,
                    "supported_reasoning_levels": [
                        {"effort": "low"},
                        {"effort": "max"}
                    ],
                    "input_modalities": ["text", "image"]
                },
                {
                    "slug": "gpt-5.6-terra",
                    "context_window": 372000,
                    "supported_reasoning_levels": [{"effort": "medium"}],
                    "input_modalities": ["text", "image"]
                }
            ]
        })
        .to_string(),
        stderr: String::new(),
    };

    let status = collect_codex_model_status_from_output(&output);

    assert_eq!(status.active_model.as_deref(), Some("gpt-5.6-sol"));
    assert_eq!(status.default_model.as_deref(), Some("gpt-5.6-sol"));
    assert_eq!(status.context_window_tokens, Some(372_000));
    assert_eq!(
        status.available_models,
        vec!["gpt-5.6-sol".to_string(), "gpt-5.6-terra".to_string()]
    );
    assert_eq!(status.available_model_details.len(), 2);
    assert_eq!(
        status.available_model_details[0].context_window_tokens,
        Some(372_000)
    );
    assert_eq!(
        status.available_model_details[0].supports_thinking,
        Some(true)
    );
    assert_eq!(
        status.available_model_details[0].supports_images,
        Some(true)
    );
    assert!(!status
        .available_models
        .iter()
        .any(|model| model.contains("frontier")));
}

fn codex_candidate_for_test(
    slot_id: &str,
    ownership: CodexAccountSlotOwnershipV1,
    account_hash: &str,
    workspace_hash: &str,
    quality: u8,
) -> CodexSlotCandidate {
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::AppServer,
        "2026-08-23T00:00:00Z".to_string(),
        "2026-08-23T00:15:00Z".to_string(),
    );
    let mut account = unsupported_account("openai");
    account.login_state = AgentLoginState::SignedIn;
    account.account_identifier_hash = Some(account_hash.to_string());
    account.organization_identifier_hash = Some(workspace_hash.to_string());
    snapshot.account = Some(account);
    let status = CodexAccountSlotCollectionStatusV1 {
        state: CodexAccountSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some(account_hash.to_string()),
        workspace_identifier_hash: Some(workspace_hash.to_string()),
        ..Default::default()
    };
    CodexSlotCandidate {
        slot: CodexHomeSlot {
            slot_id: slot_id.to_string(),
            ownership,
            home: PathBuf::from("/tmp/codex-candidate-test"),
            registered_binding: (ownership == CodexAccountSlotOwnershipV1::Managed)
                .then(|| (account_hash.to_string(), workspace_hash.to_string())),
        },
        snapshot,
        status,
        binding: Some((account_hash.to_string(), workspace_hash.to_string())),
        workspace_targets: Vec::new(),
        quality,
        auth_modified_at: None,
    }
}

#[test]
fn configured_codex_unavailable_witness_preserves_registration_without_live_authority() {
    let mut unavailable = codex_candidate_for_test(
        "codex_slot_a",
        CodexAccountSlotOwnershipV1::Managed,
        "account-a",
        "workspace-a",
        1,
    );
    unavailable.binding = None;
    unavailable.status = CodexAccountSlotCollectionStatusV1::default();
    unavailable.snapshot.account = None;
    let mut snapshots = Vec::new();
    append_configured_codex_unavailable_snapshots(
        &mut snapshots,
        &[unavailable],
        "2026-09-01T10:00:00Z",
        "2026-09-01T10:15:00Z",
    );
    assert_eq!(snapshots.len(), 1);
    let snapshot = &snapshots[0];
    let account = snapshot.account.as_ref().expect("configured account");
    assert_eq!(
        account.account_identifier_hash.as_deref(),
        Some("account-a")
    );
    assert_eq!(
        account.organization_identifier_hash.as_deref(),
        Some("workspace-a")
    );
    assert_eq!(account.login_state, AgentLoginState::Unknown);
    assert!(account.email.is_none());
    assert!(account.plan_type.is_none());
    assert!(account.subscription_product.is_none());
    assert_eq!(snapshot.status, AgentStatusState::Degraded);
    assert_eq!(
        snapshot.collection_method,
        AgentStatusCollectionMethod::ConfigFile
    );
    assert!(snapshot.quota_windows.is_empty());
    assert!(snapshot.credit_balances.is_empty());
    assert_eq!(snapshot.diagnostics.len(), 1);
    assert_eq!(
        snapshot.diagnostics[0].code,
        "codex_configured_account_unavailable"
    );
    assert!(snapshot.diagnostics[0].observed_at.is_none());
}

/// The same slot after a whole-session probe failure (here the
/// `initialize` deadline): still signed in, but no identity hashes, no
/// live binding and no reading. The state is the production
/// classification (`identity_unknown`).
fn codex_failed_probe_candidate(
    home: &str,
    account_hash: &str,
    workspace_hash: &str,
) -> CodexSlotCandidate {
    let mut candidate = codex_candidate_for_test(
        "codex_slot_last_known",
        CodexAccountSlotOwnershipV1::Managed,
        account_hash,
        workspace_hash,
        1,
    );
    candidate.slot.home = PathBuf::from(home);
    let account = candidate.snapshot.account.as_mut().expect("account");
    account.account_identifier_hash = None;
    account.organization_identifier_hash = None;
    candidate.snapshot.quota_windows = vec![unsupported_quota_window("usage")];
    candidate
        .snapshot
        .diagnostics
        .push(AgentStatusDiagnostic::source(
            "codex_usage_probe_failed",
            AgentDiagnosticSeverity::Warning,
            "Codex app-server initialize read timed out.",
        ));
    candidate.status = codex_collection_status_from_snapshot(&candidate.snapshot);
    candidate.binding = enforce_codex_registered_binding(
        &candidate.slot,
        &mut candidate.snapshot,
        &mut candidate.status,
    );
    assert_eq!(
        candidate.status.state,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    );
    assert!(candidate.binding.is_none());
    candidate
}

fn configured_unavailable_snapshot(candidate: CodexSlotCandidate) -> AgentStatusSnapshot {
    let mut snapshots = Vec::new();
    append_configured_codex_unavailable_snapshots(
        &mut snapshots,
        &[candidate],
        "2026-09-01T10:00:00Z",
        "2026-09-01T10:15:00Z",
    );
    assert_eq!(snapshots.len(), 1);
    snapshots.remove(0)
}

#[test]
fn a_failed_codex_probe_placeholder_is_uploaded_without_meters() {
    // The binding has a recent reading and the home was validated as it.
    let home = "/tmp/codex-last-known-test-placeholder";
    let binding = codex_credit_grants::binding_key("lk-account-1", "lk-workspace-1");
    codex_credit_grants::remember_home_binding(Path::new(home), &binding);
    codex_last_known::record(
        &binding,
        &[AgentQuotaWindow {
            name: "primary".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            used_percent: Some(40),
            ..Default::default()
        }],
        &[AgentCreditBalance {
            name: "reset_bank".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            remaining: CreditAmount::whole(2),
            ..Default::default()
        }],
        current_unix_seconds(),
    );

    let placeholder = configured_unavailable_snapshot(codex_failed_probe_candidate(
        home,
        "lk-account-1",
        "lk-workspace-1",
    ));

    // The upload row is the failure shape; the server carries forward its
    // own last good reading.
    assert!(placeholder.quota_windows.is_empty());
    assert!(placeholder.credit_balances.is_empty());
    assert_eq!(
        placeholder
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>(),
        vec!["codex_configured_account_unavailable"]
    );
}

#[test]
fn a_slot_without_a_readable_matching_credential_shows_no_last_reading() {
    // The binding has a recent reading and the home was validated as it,
    // but the home holds no credential now (a sign-out).
    let home = "/tmp/codex-last-known-test-no-credential";
    let binding = codex_credit_grants::binding_key("lk-account-2", "lk-workspace-2");
    codex_credit_grants::remember_home_binding(Path::new(home), &binding);
    codex_last_known::record(
        &binding,
        &[AgentQuotaWindow::default()],
        &[],
        current_unix_seconds(),
    );
    assert!(codex_last_known::stale_reading(&binding, current_unix_seconds()).is_some());

    let slot = CodexHomeSlot {
        slot_id: "codex_slot_last_known".to_string(),
        ownership: CodexAccountSlotOwnershipV1::Managed,
        home: PathBuf::from(home),
        registered_binding: Some(("lk-account-2".to_string(), "lk-workspace-2".to_string())),
    };
    assert!(
        codex_last_known_slot_reading(&slot, "2026-09-01T10:00:00Z", current_unix_seconds())
            .is_none()
    );
}

#[test]
fn a_failed_codex_upload_never_carries_stale_meters_or_local_plan_words() {
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::CliText,
        "2026-09-01T10:00:00Z".to_string(),
        "2026-09-01T10:15:00Z".to_string(),
    );
    let mut account = unsupported_account("openai");
    account.login_state = AgentLoginState::SignedIn;
    account.account_identifier_hash = Some("kept-account".to_string());
    account.organization_identifier_hash = Some("kept-workspace".to_string());
    account.plan_type = Some("pro".to_string());
    account.subscription_product = Some("chatgpt_pro".to_string());
    account.billing_channel = Some("subscription".to_string());
    account.subscription_period_start = Some("2026-01-01T00:00:00Z".to_string());
    account.subscription_period_end = Some("2026-02-01T00:00:00Z".to_string());
    account.subscription_period_last_checked_at = Some("2026-01-15T00:00:00Z".to_string());
    snapshot.account = Some(account);
    snapshot.quota_windows = vec![AgentQuotaWindow {
        name: "primary".to_string(),
        freshness: AgentQuotaWindowFreshness::Stale,
        used_percent: Some(40),
        ..Default::default()
    }];
    snapshot.credit_balances = vec![AgentCreditBalance {
        name: "reset_bank".to_string(),
        freshness: AgentQuotaWindowFreshness::Stale,
        remaining: CreditAmount::whole(2),
        ..Default::default()
    }];
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "codex_usage_probe_failed",
        AgentDiagnosticSeverity::Warning,
        "Codex app-server initialize read timed out.",
    ));
    append_current_plan_observation(&mut snapshot);
    assert!(has_stale_meters(&snapshot), "the local copy keeps them");

    let uploaded = snapshot.clone().redacted_for_backend();
    assert!(uploaded.quota_windows.is_empty());
    assert!(uploaded.credit_balances.is_empty());
    assert!(uploaded.plan_observations.is_empty());
    let account = uploaded.account.as_ref().expect("account");
    assert!(account.plan_type.is_none());
    assert!(account.subscription_product.is_none());
    assert!(account.subscription_period_start.is_none());
    assert!(account.subscription_period_end.is_none());
    assert!(account.subscription_period_last_checked_at.is_none());
    // The registered route is identity, not a plan fact: it stays.
    assert_eq!(account.billing_channel.as_deref(), Some("subscription"));
    assert_eq!(
        account.account_identifier_hash.as_deref(),
        Some("kept-account")
    );
    assert_eq!(
        account.organization_identifier_hash.as_deref(),
        Some("kept-workspace")
    );
    assert_eq!(uploaded.status, AgentStatusState::Degraded);
    assert!(uploaded
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_usage_probe_failed"));

    // A successful Codex reading is uploaded as read.
    snapshot.diagnostics.clear();
    mark_all_fresh(&mut snapshot);
    let uploaded = snapshot.redacted_for_backend();
    assert_eq!(uploaded.quota_windows.len(), 1);
    assert_eq!(uploaded.credit_balances.len(), 1);
    assert_eq!(
        uploaded
            .account
            .as_ref()
            .and_then(|account| account.plan_type.as_deref()),
        Some("pro")
    );
}

fn mark_all_fresh(snapshot: &mut AgentStatusSnapshot) {
    for window in &mut snapshot.quota_windows {
        window.freshness = AgentQuotaWindowFreshness::Fresh;
    }
    for balance in &mut snapshot.credit_balances {
        balance.freshness = AgentQuotaWindowFreshness::Fresh;
    }
}

#[test]
fn configured_codex_unavailable_witness_rejects_unknowns_and_deduplicates_live_accounts() {
    let mut unavailable = codex_candidate_for_test(
        "codex_slot_a",
        CodexAccountSlotOwnershipV1::Managed,
        "account-a",
        "workspace-a",
        1,
    );
    unavailable.binding = None;
    // Labels on a failed different identity must never leak to registration.
    unavailable
        .snapshot
        .account
        .as_mut()
        .expect("account")
        .email = Some("other@example.invalid".to_string());
    unavailable
        .snapshot
        .account
        .as_mut()
        .expect("account")
        .plan_type = Some("team".to_string());
    let mut unknown = codex_candidate_for_test(
        "unknown",
        CodexAccountSlotOwnershipV1::Managed,
        "",
        "workspace-a",
        1,
    );
    unknown.binding = None;
    let mut unregistered = codex_candidate_for_test(
        "unregistered",
        CodexAccountSlotOwnershipV1::Managed,
        "account-b",
        "workspace-b",
        1,
    );
    unregistered.binding = None;
    unregistered.slot.registered_binding = None;
    let live = codex_candidate_for_test(
        "default",
        CodexAccountSlotOwnershipV1::Default,
        "account-a",
        "workspace-a",
        5,
    );
    let mut snapshots = vec![live.snapshot.clone()];
    append_configured_codex_unavailable_snapshots(
        &mut snapshots,
        &[unavailable, unknown, unregistered],
        "2026-09-01T10:00:00Z",
        "2026-09-01T10:15:00Z",
    );
    assert_eq!(
        snapshots,
        vec![live.snapshot],
        "no duplicate or identifier-less observation"
    );
}

fn codex_workspace_target_token_for(
    account: &str,
    workspace: &str,
    organizations: Value,
) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "email": "private.person@example.test",
            "sub": account,
            "https://api.openai.com/auth": {
                "chatgpt_user_id": account,
                "chatgpt_account_id": workspace,
                "organizations": organizations
            }
        })
        .to_string(),
    );
    format!("{header}.{payload}.raw-secret-signature")
}

fn codex_workspace_target_token(organizations: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "email": "private.person@example.test",
            "sub": "raw-account-123",
            "https://api.openai.com/auth": {
                "chatgpt_user_id": "raw-account-123",
                "chatgpt_account_id": "raw-workspace-default",
                "organizations": organizations
            }
        })
        .to_string(),
    );
    format!("{header}.{payload}.raw-secret-signature")
}

/// The shipped fixture gave `chatgpt_account_id` and the default organization
/// the SAME raw id, which is the one case where the two identifier spaces
/// coincide. Real provider tokens never do that, so every coverage test passed
/// while the live current login rendered twice. This token keeps them distinct.
fn codex_split_identity_token(chatgpt_account_id: &str, organizations: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "email": "private.person@example.test",
            "sub": "raw-account-123",
            "https://api.openai.com/auth": {
                "chatgpt_user_id": "raw-account-123",
                "chatgpt_account_id": chatgpt_account_id,
                "chatgpt_plan_type": "pro",
                "organizations": organizations
            }
        })
        .to_string(),
    );
    format!("{header}.{payload}.raw-secret-signature")
}

#[test]
fn codex_target_coverage_ignores_platform_orgs_that_are_not_the_signed_in_workspace() {
    // `organizations[]` lists platform.openai.com organizations, which govern
    // API keys. Only the one flagged `is_default` corresponds to the
    // chatgpt.com workspace this credential is signed into, and only that
    // workspace carries a subscription. The rest are not connectable: one seen
    // live is not even offered by the ChatGPT workspace picker.
    let token = codex_split_identity_token(
        "raw-workspace-binding",
        serde_json::json!([
            {"id": "raw-org-personal", "title": "Personal", "is_default": true},
            {"id": "raw-org-acme", "title": "Acme", "is_default": false},
            {"id": "raw-org-deprecated", "title": "Acme Deprecated", "is_default": false}
        ]),
    );
    let evidence = codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
        .expect("target evidence");
    let account_hash =
        billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
    let binding_workspace_hash =
        billing_identity_hash("openai", "workspace", "raw-workspace-binding")
            .expect("workspace hash");
    let mut candidate = codex_candidate_for_test(
        "default",
        CodexAccountSlotOwnershipV1::Default,
        &account_hash,
        &binding_workspace_hash,
        5,
    );
    candidate.workspace_targets = evidence;

    let coverage =
        derive_codex_account_target_coverage(&empty_codex_accounts_status(), &[candidate]);

    assert_eq!(
        coverage.targets.len(),
        1,
        "one signed-in workspace, one row"
    );
    let target = &coverage.targets[0];
    assert!(target.is_current);
    assert_eq!(target.workspace_label.as_deref(), Some("Personal"));
    assert_eq!(target.subscription_product.as_deref(), Some("chatgpt_pro"));
    assert!(
        coverage
            .targets
            .iter()
            .all(|target| target.workspace_label.as_deref() != Some("Acme Deprecated")),
        "a platform org the owner cannot sign into must never be offered"
    );
}

#[test]
fn codex_current_login_is_one_target_when_binding_and_default_org_ids_differ() {
    // Live shape: the credential is bound by `chatgpt_account_id`, and its only
    // organization is the default one, named "Personal", carrying a different id.
    let token = codex_split_identity_token(
        "raw-workspace-binding",
        serde_json::json!([
            {"id": "raw-org-personal", "title": "Personal", "is_default": true}
        ]),
    );
    let evidence = codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
        .expect("target evidence");
    let account_hash =
        billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
    let binding_workspace_hash =
        billing_identity_hash("openai", "workspace", "raw-workspace-binding")
            .expect("workspace hash");
    let mut candidate = codex_candidate_for_test(
        "default",
        CodexAccountSlotOwnershipV1::Default,
        &account_hash,
        &binding_workspace_hash,
        5,
    );
    candidate.workspace_targets = evidence;

    let coverage =
        derive_codex_account_target_coverage(&empty_codex_accounts_status(), &[candidate]);

    // One workspace, so one row. Before the alias the binding and the default
    // organization produced two, and the duplicate offered to connect a
    // subscription that was already the current login.
    assert_eq!(coverage.targets.len(), 1);
    assert_eq!(coverage.current_targets, 1);
    let target = &coverage.targets[0];
    assert!(target.is_current);
    assert_eq!(target.durability, CodexAccountTargetDurabilityV1::Current);
    assert_eq!(target.workspace_label.as_deref(), Some("Personal"));
    assert_eq!(
        target.workspace_identifier_hash.as_deref(),
        Some(binding_workspace_hash.as_str()),
        "the binding identity stays canonical so persisted slots keep resolving"
    );
    assert_eq!(target.subscription_product.as_deref(), Some("chatgpt_pro"));
}

#[test]
fn codex_workspace_target_status_serialization_never_leaks_raw_identity() {
    // Two candidates, each signed into its own workspace, so both labels
    // reach the wire: a non-default platform organization would contribute
    // no row at all.
    let token = codex_workspace_target_token(serde_json::json!([
        {"id": "raw-workspace-default", "title": "Personal", "is_default": true}
    ]));
    let acme_token = codex_workspace_target_token_for(
        "raw-account-456",
        "raw-workspace-acme",
        serde_json::json!([
            {"id": "raw-workspace-acme", "title": "Acme", "is_default": true}
        ]),
    );
    let evidence = codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
        .expect("target evidence");
    let account_hash =
        billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
    let workspace_hash = billing_identity_hash("openai", "workspace", "raw-workspace-default")
        .expect("workspace hash");
    let mut candidate = codex_candidate_for_test(
        "default",
        CodexAccountSlotOwnershipV1::Default,
        &account_hash,
        &workspace_hash,
        5,
    );
    candidate.workspace_targets = evidence;
    let acme_account_hash =
        billing_identity_hash("openai", "account", "raw-account-456").expect("account hash");
    let acme_workspace_hash =
        billing_identity_hash("openai", "workspace", "raw-workspace-acme").expect("workspace hash");
    let mut acme = codex_candidate_for_test(
        "codex_slot_acme",
        CodexAccountSlotOwnershipV1::Managed,
        &acme_account_hash,
        &acme_workspace_hash,
        5,
    );
    acme.workspace_targets =
        codex_workspace_target_evidence_from_id_token(&acme_token, "2026-08-27T00:00:00Z")
            .expect("target evidence");
    let mut status = empty_codex_accounts_status();
    status.target_coverage = derive_codex_account_target_coverage(&status, &[candidate, acme]);

    let wire = serde_json::to_string(&status).expect("serialize Codex account status");
    assert!(wire.contains("Personal"));
    assert!(wire.contains("Acme"));
    // Raw provider identifiers and credential material never appear, whatever
    // else the payload carries.
    for forbidden in [
        "raw-account-123",
        "raw-account-456",
        "raw-workspace-default",
        "raw-workspace-acme",
        "raw-secret-signature",
    ] {
        assert!(
            !wire.contains(forbidden),
            "serialized raw identity: {forbidden}"
        );
    }
    // The signed-in email is the one exception, and only as the human-readable
    // account name: two connected Codex accounts are otherwise indistinguishable
    // on screen. This status answers `codex_accounts_status` over the local Unix
    // socket and is never uploaded, so the name stays on this Mac. If that ever
    // stops being true, this assertion is the thing that has to be revisited
    // first.
    let named = status
        .target_coverage
        .targets
        .iter()
        .filter(|target| target.account_label == "private.person@example.test")
        .count();
    assert_eq!(named, status.target_coverage.targets.len());
    assert_eq!(
        wire.matches("private.person@example.test").count(),
        named,
        "the email appears as the account name and nowhere else"
    );
}

#[test]
fn codex_composite_dedup_shadows_default_but_keeps_two_workspaces() {
    let mut candidates = vec![
        codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            "same_user",
            "personal_workspace",
            5,
        ),
        codex_candidate_for_test(
            "codex_slot_a",
            CodexAccountSlotOwnershipV1::Managed,
            "same_user",
            "personal_workspace",
            5,
        ),
        codex_candidate_for_test(
            "codex_slot_b",
            CodexAccountSlotOwnershipV1::Managed,
            "same_user",
            "business_workspace",
            5,
        ),
        codex_candidate_for_test(
            "codex_slot_c",
            CodexAccountSlotOwnershipV1::Managed,
            "same_user",
            "personal_workspace",
            4,
        ),
    ];

    canonicalize_codex_candidates(&mut candidates);

    assert_eq!(
        candidates[0].status.relationship,
        Some(CodexAccountSlotRelationshipV1::ShadowedByAnchor)
    );
    assert_eq!(
        candidates[1].status.relationship,
        Some(CodexAccountSlotRelationshipV1::CanonicalAnchor)
    );
    assert_eq!(
        candidates[2].status.relationship,
        Some(CodexAccountSlotRelationshipV1::CanonicalAnchor)
    );
    assert_eq!(
        candidates[3].status.state,
        CodexAccountSlotCollectionStateV1::DuplicateAccount
    );
    assert_eq!(
        candidates[3].status.relationship,
        Some(CodexAccountSlotRelationshipV1::DuplicateAnchor)
    );
}

#[test]
fn codex_healthy_anchor_restores_source_health_when_default_is_signed_out() {
    let mut default = codex_candidate_for_test(
        "default",
        CodexAccountSlotOwnershipV1::Default,
        "default_user",
        "default_workspace",
        1,
    );
    default.snapshot.status = AgentStatusState::AuthRequired;
    default.status.state = CodexAccountSlotCollectionStateV1::NeedsLogin;
    let managed = codex_candidate_for_test(
        "codex_slot_a",
        CodexAccountSlotOwnershipV1::Managed,
        "managed_user",
        "managed_workspace",
        5,
    );

    let health = codex_source_health_snapshot(
        &[default, managed],
        "2026-08-23T00:00:00Z",
        "2026-08-23T00:15:00Z",
    );

    assert_eq!(health.status, AgentStatusState::Available);
    assert_eq!(
        health
            .account
            .and_then(|account| account.account_identifier_hash),
        Some("managed_user".to_string())
    );
}

fn codex_source_health_codes(health: &AgentStatusSnapshot) -> Vec<&str> {
    health
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

#[test]
fn a_failed_codex_probe_is_a_retrying_read_not_a_connection_needing_attention() {
    let default = codex_candidate_for_test(
        "default",
        CodexAccountSlotOwnershipV1::Default,
        "default_user",
        "default_workspace",
        5,
    );
    let failed = codex_failed_probe_candidate(
        "/tmp/codex-health-test-failed-probe",
        "managed_user",
        "managed_workspace",
    );

    let health = codex_source_health_snapshot(
        &[default, failed],
        "2026-08-23T00:00:00Z",
        "2026-08-23T00:15:00Z",
    );

    assert_eq!(health.status, AgentStatusState::Degraded);
    assert_eq!(
        codex_source_health_codes(&health),
        vec!["codex_usage_read_retrying"]
    );
}

#[test]
fn a_real_connection_problem_still_needs_attention_beside_a_failed_default_probe() {
    let mut default = codex_failed_probe_candidate(
        "/tmp/codex-health-test-default-probe-and-login",
        "default_user",
        "default_workspace",
    );
    default.slot.slot_id = "default".to_string();
    default.slot.ownership = CodexAccountSlotOwnershipV1::Default;
    default.slot.registered_binding = None;
    default.snapshot.status = AgentStatusState::Degraded;
    let mut signed_out = codex_candidate_for_test(
        "codex_slot_a",
        CodexAccountSlotOwnershipV1::Managed,
        "managed_user",
        "managed_workspace",
        1,
    );
    signed_out.status.state = CodexAccountSlotCollectionStateV1::NeedsLogin;

    let health = codex_source_health_snapshot(
        &[default, signed_out],
        "2026-08-23T00:00:00Z",
        "2026-08-23T00:15:00Z",
    );

    // The default login still works; only its usage read failed.
    assert!(codex_source_health_codes(&health)
        .contains(&"codex_registered_slot_needs_attention_current_available"));
    assert!(!codex_source_health_codes(&health).contains(&"codex_usage_read_retrying"));
}

#[test]
fn a_signed_out_default_is_not_hidden_behind_a_retrying_read() {
    let mut default = codex_candidate_for_test(
        "default",
        CodexAccountSlotOwnershipV1::Default,
        "default_user",
        "default_workspace",
        1,
    );
    default.snapshot.status = AgentStatusState::AuthRequired;
    default.status.state = CodexAccountSlotCollectionStateV1::NeedsLogin;
    let failed = codex_failed_probe_candidate(
        "/tmp/codex-health-test-signed-out-default",
        "managed_user",
        "managed_workspace",
    );

    let health = codex_source_health_snapshot(
        &[default, failed],
        "2026-08-23T00:00:00Z",
        "2026-08-23T00:15:00Z",
    );

    assert_eq!(health.status, AgentStatusState::AuthRequired);
    assert!(!codex_source_health_codes(&health).contains(&"codex_usage_read_retrying"));
}

/// The default home's failed probe kept account A's hashes (and its stale
/// reading); a managed slot uploads account B.
fn failed_default_with_kept_hashes(account_hash: &str) -> CodexSlotCandidate {
    let mut default = codex_failed_probe_candidate(
        "/tmp/codex-upload-test-failed-default",
        account_hash,
        "default_workspace",
    );
    default.slot.slot_id = "default".to_string();
    default.slot.ownership = CodexAccountSlotOwnershipV1::Default;
    default.slot.registered_binding = None;
    default.snapshot.status = AgentStatusState::Degraded;
    let account = default.snapshot.account.as_mut().expect("account");
    account.account_identifier_hash = Some(account_hash.to_string());
    account.organization_identifier_hash = Some("default_workspace".to_string());
    default
}

#[test]
fn a_failed_default_with_kept_hashes_is_uploaded_beside_other_accounts() {
    let default = failed_default_with_kept_hashes("default_user");
    assert!(default.binding.is_none(), "no transcript authority");
    let expected = default.snapshot.clone();
    let managed = codex_candidate_for_test(
        "codex_slot_b",
        CodexAccountSlotOwnershipV1::Managed,
        "managed_user",
        "managed_workspace",
        5,
    );
    let mut snapshots = vec![managed.snapshot.clone()];
    append_failed_default_codex_snapshot(&mut snapshots, &[default, managed]);
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[1], expected);

    // Already represented (the same account read fresh elsewhere): no
    // second row.
    let mut snapshots = vec![expected.clone()];
    append_failed_default_codex_snapshot(
        &mut snapshots,
        &[failed_default_with_kept_hashes("default_user")],
    );
    assert_eq!(snapshots.len(), 1);

    // Without kept hashes nothing is added.
    let mut unkeyed = failed_default_with_kept_hashes("default_user");
    let account = unkeyed.snapshot.account.as_mut().expect("account");
    account.account_identifier_hash = None;
    account.organization_identifier_hash = None;
    let mut snapshots = Vec::new();
    append_failed_default_codex_snapshot(&mut snapshots, &[unkeyed]);
    assert!(snapshots.is_empty());
}

#[cfg(unix)]
#[test]
#[serial]
fn codex_default_probe_failure_is_degraded_and_keeps_its_validated_hashes() {
    let (root, home) = synthetic_codex_collector_home("default-failure", 0o600);
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let collect = || {
        collect_codex_home_candidate(
            CodexHomeSlot {
                slot_id: "default".to_string(),
                ownership: CodexAccountSlotOwnershipV1::Default,
                home: home.clone(),
                registered_binding: None,
            },
            "2026-08-26T00:00:00Z",
            "2026-08-26T00:15:00Z",
            CodexQuotaRead::Provider,
        )
    };

    let fresh = collect();
    assert_eq!(fresh.status.state, CodexAccountSlotCollectionStateV1::Fresh);
    let (account, workspace) = fresh.binding.clone().expect("validated binding");

    // The local credential claims exactly the validated binding; the
    // claim is a key only and needs no provider-authentication flag.
    let credentials = read_codex_auth_credentials_at(&home, CodexHomeTrust::ProviderDefault)
        .expect("readable credential")
        .expect("credential");
    assert_eq!(
        codex_credential_claimed_binding(&credentials),
        Some(codex_credit_grants::binding_key(&account, &workspace))
    );
    assert!(
        validated_codex_identity(&credentials, None, None, false).is_none(),
        "an identity still needs provider authentication"
    );
    let mut inconsistent = credentials;
    inconsistent.account_id = Some("another-workspace".to_string());
    assert!(codex_credential_claimed_binding(&inconsistent).is_none());

    fail_synthetic_codex_app_server(&root);

    let failed = collect();
    // Degraded with the stable failure code, never available.
    assert_eq!(failed.snapshot.status, AgentStatusState::Degraded);
    assert!(failed
        .snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_usage_probe_failed"));
    // Keyed to the account last validated here, with its last reading
    // marked stale, but no live binding.
    let kept = failed.snapshot.account.as_ref().expect("account");
    assert_eq!(
        kept.account_identifier_hash.as_deref(),
        Some(account.as_str())
    );
    assert_eq!(
        kept.organization_identifier_hash.as_deref(),
        Some(workspace.as_str())
    );
    assert!(failed.binding.is_none());
    // A remembered identity is never a trusted current login.
    assert_eq!(kept.confidence, AgentStatusConfidence::Low);
    let mut expected_windows = fresh.snapshot.quota_windows.clone();
    let mut expected_balances = fresh.snapshot.credit_balances.clone();
    mark_quota_meters_stale(&mut expected_windows, &mut expected_balances);
    assert_eq!(failed.snapshot.quota_windows, expected_windows);
    assert_eq!(failed.snapshot.credit_balances, expected_balances);

    // Upload: degraded with the stable code and the kept hashes, but no
    // last reading and no plan words from the local credential.
    assert!(failed
        .snapshot
        .account
        .as_ref()
        .is_some_and(|account| account.plan_type.is_some()));
    let uploaded = failed.snapshot.clone().redacted_for_backend();
    assert_eq!(uploaded.status, AgentStatusState::Degraded);
    assert!(uploaded
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_usage_probe_failed"));
    assert!(!has_stale_meters(&uploaded));
    assert!(uploaded.credit_balances.is_empty());
    assert!(uploaded.plan_observations.is_empty());
    let uploaded_account = uploaded.account.as_ref().expect("account");
    assert!(uploaded_account.plan_type.is_none());
    assert!(uploaded_account.subscription_product.is_none());
    assert_eq!(
        uploaded_account.account_identifier_hash.as_deref(),
        Some(account.as_str())
    );
    assert_eq!(
        uploaded_account.organization_identifier_hash.as_deref(),
        Some(workspace.as_str())
    );

    // The home now holds another account's credential: no hashes kept and
    // nothing carried.
    write_other_synthetic_codex_account(&home);
    let switched = collect();
    assert_eq!(switched.snapshot.status, AgentStatusState::Degraded);
    let switched_account = switched.snapshot.account.as_ref().expect("account");
    assert!(switched_account.account_identifier_hash.is_none());
    assert!(switched_account.organization_identifier_hash.is_none());
    assert!(switched
        .snapshot
        .quota_windows
        .iter()
        .all(|window| window.freshness != AgentQuotaWindowFreshness::Stale));
    assert!(switched.snapshot.credit_balances.is_empty());

    codex_credit_grants::forget_binding_cadence(&codex_credit_grants::binding_key(
        &account, &workspace,
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn codex_accepted_slot_suppresses_meters_after_identity_change() {
    let mut candidate = codex_candidate_for_test(
        "codex_slot_a",
        CodexAccountSlotOwnershipV1::Managed,
        "registered_user",
        "registered_workspace",
        5,
    );
    candidate.status.account_identifier_hash = Some("different_user".to_string());
    candidate.status.workspace_identifier_hash = Some("different_workspace".to_string());
    candidate.snapshot.quota_windows.push(AgentQuotaWindow {
        name: "weekly".to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        ..Default::default()
    });
    candidate.snapshot.credit_balances.push(AgentCreditBalance {
        name: "credits".to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        ..Default::default()
    });

    let binding = enforce_codex_registered_binding(
        &candidate.slot,
        &mut candidate.snapshot,
        &mut candidate.status,
    );

    assert_eq!(binding, None);
    assert_eq!(
        candidate.status.state,
        CodexAccountSlotCollectionStateV1::IdentityMismatch
    );
    assert!(candidate.status.quota_snapshot.is_none());
    assert!(candidate.snapshot.quota_windows.is_empty());
    assert!(candidate.snapshot.credit_balances.is_empty());
}

#[test]
fn codex_id_token_parser_extracts_chatgpt_plan_claims() {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        r#"{
                "email": "codex@example.com",
                "sub": "account_sub",
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "account_123",
                    "chatgpt_user_id": "user_123",
                    "chatgpt_plan_type": "Team",
                    "chatgpt_subscription_active_start": 1782864000,
                    "chatgpt_subscription_active_until": 1785542400,
                    "chatgpt_subscription_last_checked": 1785283200,
                    "organizations": [
                        {"id": "org_old", "title": "Old Org", "is_default": false},
                        {"id": "org_current", "title": "Current Org", "is_default": true}
                    ]
                }
            }"#,
    );
    let token = format!("{header}.{payload}.signature");

    let account = parse_codex_id_token_account(&token).expect("account");

    assert_eq!(account.login_state, AgentLoginState::SignedIn);
    assert_eq!(account.provider.as_deref(), Some("openai"));
    assert_eq!(account.email.as_deref(), Some("codex@example.com"));
    assert_eq!(account.account_id.as_deref(), Some("user_123"));
    assert_eq!(account.organization_id.as_deref(), Some("account_123"));
    assert_eq!(account.organization_label, None);
    assert_eq!(account.plan_type.as_deref(), Some("team"));
    assert_eq!(
        account.subscription_product.as_deref(),
        Some("chatgpt_team")
    );
    assert_eq!(
        account.subscription_period_start.as_deref(),
        Some("2026-07-01T00:00:00Z")
    );
    assert_eq!(
        account.subscription_period_end.as_deref(),
        Some("2026-08-01T00:00:00Z")
    );
    assert_eq!(
        account.subscription_period_last_checked_at.as_deref(),
        Some("2026-07-29T00:00:00Z")
    );
    assert_eq!(account.account_identifier_hash, None);
    assert_eq!(account.organization_identifier_hash, None);
    assert_eq!(account.confidence, AgentStatusConfidence::Low);
}

fn synthetic_codex_jwt(
    user: &str,
    workspace: &str,
    account_label: &str,
    plan: &str,
    expires_at: i64,
) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "iss": "https://auth.openai.com",
            "aud": "synthetic-client",
            "exp": expires_at,
            "email": account_label,
            "https://api.openai.com/auth": {
                "chatgpt_user_id": user,
                "chatgpt_account_id": workspace,
                "chatgpt_plan_type": plan
            }
        })
        .to_string(),
    );
    format!("{header}.{payload}.synthetic-signature")
}

fn synthetic_codex_access_jwt_with_profile_email(
    user: &str,
    workspace: &str,
    account_label: &str,
    plan: &str,
    expires_at: i64,
) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "iss": "https://auth.openai.com",
            "aud": "synthetic-client",
            "exp": expires_at,
            "https://api.openai.com/profile": {
                "email": account_label
            },
            "https://api.openai.com/auth": {
                "chatgpt_user_id": user,
                "chatgpt_account_id": workspace,
                "chatgpt_plan_type": plan
            }
        })
        .to_string(),
    );
    format!("{header}.{payload}.synthetic-signature")
}

#[test]
fn unrefreshed_or_mismatched_jwt_identity_never_carries_provider_meters() {
    let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let credentials = CodexAuthCredentials {
        access_token: Some(synthetic_codex_jwt(
            "synthetic-user",
            "synthetic-workspace-b",
            "synthetic-account",
            "pro",
            expires_at,
        )),
        id_token: Some(synthetic_codex_jwt(
            "synthetic-user",
            "synthetic-workspace-a",
            "synthetic-account",
            "pro",
            expires_at,
        )),
        account_id: Some("synthetic-workspace-a".to_string()),
    };
    let provider_account = serde_json::json!({
        "account": {
            "type": "chatgpt",
            "email": "synthetic-account",
            "planType": "pro"
        },
        "requiresOpenaiAuth": true
    });
    let rate_limits = serde_json::json!({
        "rateLimits": {
            "limitId": "synthetic-limit",
            "planType": "pro",
            "primary": {"usedPercent": 25, "windowDurationMins": 300}
        }
    });

    assert!(
        validated_codex_identity(
            &credentials,
            Some(&provider_account),
            Some(&rate_limits),
            false,
        )
        .is_none(),
        "decoded claims are unusable until the provider refreshes the active credential"
    );
    assert!(
        validated_codex_identity(
            &credentials,
            Some(&provider_account),
            Some(&rate_limits),
            true,
        )
        .is_none(),
        "an ID-token workspace cannot override the authenticated access-token workspace"
    );
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::AppServer,
        "2026-08-23T00:00:00Z".to_string(),
        "2026-08-23T00:15:00Z".to_string(),
    );
    snapshot.account =
        parse_codex_id_token_account(credentials.id_token.as_deref().expect("synthetic id token"));
    snapshot.quota_windows = codex_app_server_quota_windows(&rate_limits);
    stamp_codex_meter_identity(&mut snapshot);
    assert!(snapshot.quota_windows.is_empty());

    let correlated = CodexAuthCredentials {
        access_token: Some(synthetic_codex_jwt(
            "synthetic-user",
            "synthetic-workspace-b",
            "synthetic-account",
            "pro",
            expires_at,
        )),
        id_token: Some(synthetic_codex_jwt(
            "synthetic-user",
            "synthetic-workspace-b",
            "synthetic-account",
            "pro",
            expires_at,
        )),
        account_id: Some("synthetic-workspace-b".to_string()),
    };
    assert!(validated_codex_identity(
        &correlated,
        Some(&provider_account),
        Some(&rate_limits),
        true,
    )
    .is_some());

    let mut expired = credentials;
    expired.id_token = Some(synthetic_codex_jwt(
        "synthetic-user",
        "synthetic-workspace-b",
        "synthetic-account",
        "pro",
        OffsetDateTime::now_utc().unix_timestamp() - 1,
    ));
    assert!(
        validated_codex_identity(&expired, Some(&provider_account), Some(&rate_limits), true,)
            .is_none()
    );
}

fn synthetic_codex_jwt_with_organizations(
    user: &str,
    workspace: &str,
    account_label: &str,
    plan: &str,
    expires_at: i64,
    organizations: Value,
) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "iss": "https://auth.openai.com",
            "aud": "synthetic-client",
            "exp": expires_at,
            "email": account_label,
            "https://api.openai.com/auth": {
                "chatgpt_user_id": user,
                "chatgpt_account_id": workspace,
                "chatgpt_plan_type": plan,
                "organizations": organizations
            }
        })
        .to_string(),
    );
    format!("{header}.{payload}.synthetic-signature")
}

#[test]
fn codex_identity_carries_the_hashes_it_produced_before_the_derivation_changed() {
    // The account used to be keyed on `chatgpt_account_id` and the
    // organization on `organizations[].id` under the `organization` kind.
    // Both moved, so a server holding the old digests sees an unrelated
    // account and prices it as a second subscription. These two fields are
    // the only thing that can join them again: nothing downstream holds the
    // raw values, so nothing downstream can derive the equivalence itself.
    let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let organizations = serde_json::json!([
        {"id": "synthetic-org-default", "title": "Personal", "is_default": true},
        {"id": "synthetic-org-other", "title": "Other", "is_default": false}
    ]);
    let credentials = CodexAuthCredentials {
        access_token: Some(synthetic_codex_access_jwt_with_profile_email(
            "synthetic-user",
            "synthetic-workspace",
            "synthetic-account",
            "pro",
            expires_at,
        )),
        id_token: Some(synthetic_codex_jwt_with_organizations(
            "synthetic-user",
            "synthetic-workspace",
            "synthetic-account",
            "pro",
            expires_at,
            organizations,
        )),
        account_id: Some("synthetic-workspace".to_string()),
    };
    let provider_account = serde_json::json!({
        "account": {"type": "chatgpt", "email": "synthetic-account", "planType": "pro"}
    });
    let rate_limits = serde_json::json!({
        "rateLimits": {"limitId": "codex", "planType": "pro"}
    });

    let identity = validated_codex_identity(
        &credentials,
        Some(&provider_account),
        Some(&rate_limits),
        true,
    )
    .expect("identity");

    assert_eq!(
        identity.account_identifier_hash,
        billing_identity_hash("openai", "account", "synthetic-user").expect("account hash"),
        "the account is keyed on the user id now"
    );
    assert_eq!(
        identity.superseded_account_identifier_hash,
        billing_identity_hash("openai", "account", "synthetic-workspace"),
        "and was keyed on the workspace id before"
    );
    assert_eq!(
        identity.workspace_identifier_hash,
        billing_identity_hash("openai", "workspace", "synthetic-workspace")
            .expect("workspace hash"),
    );
    assert_eq!(
        identity.superseded_organization_identifier_hash,
        billing_identity_hash("openai", "organization", "synthetic-org-default"),
        "the DEFAULT organization is the one the credential was signed into"
    );
    assert_ne!(
        identity.superseded_organization_identifier_hash,
        billing_identity_hash("openai", "organization", "synthetic-org-other"),
        "a non-default organization never supplies the superseded identity"
    );
    // Superseded hashes must never collide with current ones, or a consumer
    // adopting them would rewrite an identity onto itself.
    assert_ne!(
        Some(identity.account_identifier_hash.clone()),
        identity.superseded_account_identifier_hash
    );
    assert_ne!(
        Some(identity.workspace_identifier_hash.clone()),
        identity.superseded_organization_identifier_hash
    );
}

#[test]
fn codex_profile_email_identity_retains_provider_meters() {
    let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let credentials = CodexAuthCredentials {
        access_token: Some(synthetic_codex_access_jwt_with_profile_email(
            "synthetic-user",
            "synthetic-workspace",
            "synthetic-account",
            "pro",
            expires_at,
        )),
        id_token: Some(synthetic_codex_jwt(
            "synthetic-user",
            "synthetic-workspace",
            "synthetic-account",
            "pro",
            expires_at,
        )),
        account_id: Some("synthetic-workspace".to_string()),
    };
    let provider_account = serde_json::json!({
        "account": {
            "type": "chatgpt",
            "email": "synthetic-account",
            "planType": "pro"
        }
    });
    let rate_limits = serde_json::json!({
        "rateLimits": {
            "limitId": "synthetic-limit",
            "planType": "pro",
            "primary": {"usedPercent": 25, "windowDurationMins": 300}
        }
    });

    let identity = validated_codex_identity(
        &credentials,
        Some(&provider_account),
        Some(&rate_limits),
        true,
    )
    .expect("profile email should correlate the authenticated identity");
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::AppServer,
        "2026-08-23T00:00:00Z".to_string(),
        "2026-08-23T00:15:00Z".to_string(),
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        account_identifier_hash: Some(identity.account_identifier_hash.clone()),
        organization_identifier_hash: Some(identity.workspace_identifier_hash.clone()),
        ..unsupported_account("openai")
    });
    snapshot.quota_windows.push(AgentQuotaWindow {
        name: "synthetic_primary".to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        ..Default::default()
    });
    snapshot.credit_balances.push(AgentCreditBalance {
        name: "synthetic_credits".to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        ..Default::default()
    });

    stamp_codex_meter_identity(&mut snapshot);

    assert_eq!(snapshot.quota_windows.len(), 1);
    assert_eq!(snapshot.credit_balances.len(), 1);
    assert_eq!(
        snapshot.quota_windows[0].account_identifier_hash.as_deref(),
        Some(identity.account_identifier_hash.as_str())
    );
    assert_eq!(
        snapshot.credit_balances[0]
            .organization_identifier_hash
            .as_deref(),
        Some(identity.workspace_identifier_hash.as_str())
    );
}

#[test]
fn codex_profile_email_mismatch_clears_provider_meters() {
    let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let matching_credentials = CodexAuthCredentials {
        access_token: Some(synthetic_codex_access_jwt_with_profile_email(
            "synthetic-user",
            "synthetic-workspace",
            "synthetic-account",
            "pro",
            expires_at,
        )),
        id_token: Some(synthetic_codex_jwt(
            "synthetic-user",
            "synthetic-workspace",
            "synthetic-account",
            "pro",
            expires_at,
        )),
        account_id: Some("synthetic-workspace".to_string()),
    };
    let provider_account = serde_json::json!({
        "account": {
            "type": "chatgpt",
            "email": "synthetic-account",
            "planType": "pro"
        }
    });
    let rate_limits = serde_json::json!({
        "rateLimits": {
            "limitId": "synthetic-limit",
            "planType": "pro",
            "primary": {"usedPercent": 25, "windowDurationMins": 300}
        }
    });
    assert!(validated_codex_identity(
        &matching_credentials,
        Some(&provider_account),
        Some(&rate_limits),
        true,
    )
    .is_some());

    let mismatched_credentials = CodexAuthCredentials {
        access_token: Some(synthetic_codex_access_jwt_with_profile_email(
            "synthetic-user",
            "synthetic-workspace",
            "different-synthetic-account",
            "pro",
            expires_at,
        )),
        ..matching_credentials
    };
    let identity = validated_codex_identity(
        &mismatched_credentials,
        Some(&provider_account),
        Some(&rate_limits),
        true,
    );
    assert!(identity.is_none());

    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::AppServer,
        "2026-08-23T00:00:00Z".to_string(),
        "2026-08-23T00:15:00Z".to_string(),
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        account_identifier_hash: identity
            .as_ref()
            .map(|value| value.account_identifier_hash.clone()),
        organization_identifier_hash: identity
            .as_ref()
            .map(|value| value.workspace_identifier_hash.clone()),
        ..unsupported_account("openai")
    });
    snapshot.quota_windows.push(AgentQuotaWindow {
        name: "synthetic_primary".to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        ..Default::default()
    });
    snapshot.credit_balances.push(AgentCreditBalance {
        name: "synthetic_credits".to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        ..Default::default()
    });

    stamp_codex_meter_identity(&mut snapshot);

    assert!(snapshot.quota_windows.is_empty());
    assert!(snapshot.credit_balances.is_empty());
}

#[test]
fn codex_partial_identity_never_emits_hash_or_quota_snapshot() {
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::AppServer,
        "2026-08-23T00:00:00Z".to_string(),
        "2026-08-23T00:15:00Z".to_string(),
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        account_identifier_hash: Some("a".repeat(64)),
        organization_identifier_hash: None,
        ..unsupported_account("openai")
    });
    snapshot.quota_windows.push(AgentQuotaWindow {
        name: "synthetic_primary".to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        ..Default::default()
    });
    snapshot.credit_balances.push(AgentCreditBalance {
        name: "synthetic_credits".to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        ..Default::default()
    });

    stamp_codex_meter_identity(&mut snapshot);

    let status = codex_collection_status_from_snapshot(&snapshot);
    assert_eq!(
        status.state,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    );
    assert_eq!(status.account_identifier_hash, None);
    assert_eq!(status.workspace_identifier_hash, None);
    assert!(status.quota_snapshot.is_none());
    assert!(snapshot.quota_windows.is_empty());
    assert!(snapshot.credit_balances.is_empty());
}

fn codex_id_token_with_auth_claim(auth_claim: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(
        r#"{{
                "email": "codex@example.com",
                "sub": "account_sub",
                "https://api.openai.com/auth": {auth_claim}
            }}"#
    ));
    format!("{header}.{payload}.signature")
}

#[test]
fn codex_id_token_subscription_period_reads_rfc3339_strings_as_utc() {
    let token = codex_id_token_with_auth_claim(
        r#"{
                "chatgpt_account_id": "account_123",
                "chatgpt_plan_type": "Pro",
                "chatgpt_subscription_active_start": "2026-07-01T03:00:00+03:00",
                "chatgpt_subscription_active_until": "1785542400",
                "chatgpt_subscription_last_checked": "2026-07-29T03:00:00+03:00"
            }"#,
    );

    let account = parse_codex_id_token_account(&token).expect("account");

    // An offset-bearing string is converted, not reinterpreted: same instant.
    assert_eq!(
        account.subscription_period_start.as_deref(),
        Some("2026-07-01T00:00:00Z")
    );
    assert_eq!(
        account.subscription_period_end.as_deref(),
        Some("2026-08-01T00:00:00Z")
    );
    assert_eq!(
        account.subscription_period_last_checked_at.as_deref(),
        Some("2026-07-29T00:00:00Z")
    );
}

#[test]
fn merged_codex_accounts_carry_the_subscription_period() {
    let mut auth_account = unsupported_account("openai");
    auth_account.login_state = AgentLoginState::SignedIn;
    auth_account.subscription_period_start = Some("2026-07-01T00:00:00Z".to_string());
    auth_account.subscription_period_end = Some("2026-08-01T00:00:00Z".to_string());
    auth_account.subscription_period_last_checked_at = Some("2026-07-29T00:00:00Z".to_string());
    let mut existing = unsupported_account("openai");
    existing.email = Some("codex@example.com".to_string());

    let merged = merge_codex_accounts(Some(existing), auth_account.clone());

    assert_eq!(
        merged.subscription_period_start.as_deref(),
        Some("2026-07-01T00:00:00Z")
    );
    assert_eq!(
        merged.subscription_period_end.as_deref(),
        Some("2026-08-01T00:00:00Z")
    );
    assert_eq!(
        merged.subscription_period_last_checked_at.as_deref(),
        Some("2026-07-29T00:00:00Z")
    );

    // A later probe that reports nothing must not blank a known period.
    let mut silent = unsupported_account("openai");
    silent.login_state = AgentLoginState::SignedIn;
    let preserved = merge_codex_accounts(Some(merged), silent);

    assert_eq!(
        preserved.subscription_period_start.as_deref(),
        Some("2026-07-01T00:00:00Z")
    );
    assert_eq!(
        preserved.subscription_period_end.as_deref(),
        Some("2026-08-01T00:00:00Z")
    );
    assert_eq!(
        preserved.subscription_period_last_checked_at.as_deref(),
        Some("2026-07-29T00:00:00Z")
    );
}

#[cfg(unix)]
#[test]
fn codex_platform_organizations_never_witness_a_subscription() {
    use std::os::unix::fs::PermissionsExt;

    // `organizations[]` lists platform.openai.com organizations, which
    // govern API keys. ChatGPT/Codex subscriptions live in chatgpt.com
    // workspaces keyed by `chatgpt_account_id`, and the id spaces differ
    // even where the names match -- proven live: a platform organization
    // absent from the ChatGPT picker entirely, and a target prepared from a
    // platform organization id titled the same as a ChatGPT workspace
    // returning `identity_mismatch`.
    //
    // "Team Org" below carries a plan name, which used to be uploaded as a
    // plan observation with `billing_channel: "subscription"` and no account
    // identifier at all. The backend materialized that into its own priced
    // subscription row keyed on the account label -- a plan nobody pays for,
    // added to the operator's monthly total.
    let root = std::env::temp_dir().join(format!(
        "ottto-codex-platform-orgs-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("root");
    // macOS `temp_dir()` reaches the real directory through a symlinked
    // `/var`, and the secure reader opens every component with O_NOFOLLOW.
    // Without canonicalizing, the fixture is refused and the assertions
    // below would all pass on an untouched snapshot.
    let root = root.canonicalize().expect("canonical root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
        .expect("provider home mode");

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "email": "codex@example.com",
            "sub": "account_sub",
            "https://api.openai.com/auth": {
                "chatgpt_user_id": "account_sub",
                "chatgpt_account_id": "workspace_binding",
                "chatgpt_plan_type": "Pro",
                "organizations": [
                    {"id": "org_current", "title": "Current Org", "is_default": true},
                    {"id": "org_related", "title": "Related Org", "is_default": false},
                    {"id": "org_team", "title": "Team Org", "subscription_plan": "Team"}
                ]
            }
        })
        .to_string(),
    );
    let id_token = format!("{header}.{payload}.signature");
    std::fs::write(
        root.join("auth.json"),
        serde_json::json!({
            "tokens": {"id_token": id_token},
            "account_id": "workspace_binding"
        })
        .to_string(),
    )
    .expect("auth fixture");
    // `auth.json` must be exactly 0600 or the secure reader refuses it, the
    // collector returns early, and every assertion below would pass for the
    // wrong reason.
    std::fs::set_permissions(
        root.join("auth.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("auth mode");

    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::AppServer,
        "2026-09-01T10:00:00Z".to_string(),
        "2026-09-01T10:15:00Z".to_string(),
    );

    let targets = append_codex_workspace_observations_at(
        &mut snapshot,
        &root,
        CodexHomeTrust::ProviderDefault,
    );

    // Prove the fixture was actually read before trusting any absence.
    assert!(
        !snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "codex_credential_read_failed"),
        "the credential fixture was rejected, so this test would prove nothing"
    );
    assert!(
        !targets.is_empty(),
        "the signed-in workspace must still produce a target"
    );

    assert!(
        snapshot.plan_observations.is_empty(),
        "platform organizations must not claim a subscription: {:?}",
        snapshot.plan_observations
    );
    assert!(
        !snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "codex_workspace_memberships_detected"),
        "the membership diagnostic described observations that are no longer emitted"
    );
    // Target EVIDENCE still enumerates every organization the token names;
    // `derive_codex_account_target_coverage` is what narrows it to the
    // signed-in workspace, so exactly one default target is the shape the
    // coverage step expects to receive.
    assert_eq!(
        targets.iter().filter(|target| target.is_default).count(),
        1,
        "the signed-in workspace must be the one default target"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn codex_app_server_prefers_effective_snapshot_over_internal_limit_map() {
    let json = serde_json::json!({
        "rateLimits": {
            "limitId": "codex",
            "primary": {
                "usedPercent": 37,
                "windowDurationMins": 10080,
                "resetsAt": 1779613200
            },
            "credits": {
                "hasCredits": true,
                "unlimited": false,
                "balance": "4"
            },
            "planType": "pro"
        },
        "rateLimitsByLimitId": {
            "base_model_inference": {
                "limitId": "base_model_inference",
                "primary": {"usedPercent": 0, "windowDurationMins": 10080, "resetsAt": 1779613200}
            },
            "codex_bengalfox": {
                "limitId": "codex_bengalfox",
                "primary": {"usedPercent": 0, "windowDurationMins": 300, "resetsAt": 1779049800},
                "secondary": {"usedPercent": 0, "windowDurationMins": 10080, "resetsAt": 1779613200}
            },
            "codex": {
                "limitId": "codex",
                "primary": {
                    "usedPercent": 37,
                    "windowDurationMins": 10080,
                    "resetsAt": 1779613200
                },
                "planType": "pro"
            }
        },
        "rateLimitResetCredits": {
            "availableCount": 2
        }
    });

    let windows = codex_app_server_quota_windows(&json);
    let credits = codex_app_server_credit_balances(&json);

    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].name, "codex_primary_weekly_reset_known");
    assert_eq!(windows[0].left_percent, Some(63));
    assert_eq!(
        windows[0].started_at.as_deref(),
        Some("2026-05-17T09:00:00Z")
    );
    assert_eq!(credits.len(), 2);
    assert_eq!(credits[0].name, "credits");
    assert_eq!(credits[0].remaining, CreditAmount::whole(4));
    // A payload without the spend-cap fields leaves them unset.
    assert_eq!(credits[0].spend_control_reached, None);
    assert_eq!(credits[0].rate_limit_reached_type, None);
    assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
    assert_eq!(credits[1].name, "reset_bank");
    assert_eq!(credits[1].unit, AgentCreditBalanceUnit::Resets);
    assert_eq!(credits[1].status, AgentCreditBalanceStatus::Ok);
    assert_eq!(credits[1].remaining, CreditAmount::whole(2));
}

#[test]
fn codex_app_server_windows_are_nonpositional_unique_and_preserve_unknowns() {
    let json = serde_json::json!({
        "rateLimitsByLimitId": {
            "synthetic-alpha": {
                "limitId": "ignored-inner-id",
                "primary": {"usedPercent": 10, "windowDurationMins": 300, "resetsAt": 1779049800},
                "secondary": {"usedPercent": 20, "windowDurationMins": 300, "resetsAt": 1779049800},
                "futureWindow": {"usedPercent": 30, "windowDurationMins": 45},
                "spendControlReached": true,
                "rateLimitReachedType": "workspace_owner_usage_limit_reached"
            },
            "synthetic-beta": {
                "primary": {"usedPercent": 40, "windowDurationMins": 10080, "resetsAt": 1779613200}
            },
            "synthetic/alpha": {
                "primary": {"usedPercent": 50}
            },
            "synthetic_alpha": {
                "primary": {"usedPercent": 60}
            }
        }
    });

    let windows = codex_app_server_quota_windows(&json);
    let names = windows
        .iter()
        .map(|window| window.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(windows.len(), 6);
    assert_eq!(names.len(), 6, "distinct windows must never collapse");
    assert!(names.contains("synthetic-alpha_primary_five_hour_reset_known"));
    assert!(names.contains("synthetic-alpha_secondary_five_hour_reset_known"));
    assert!(names.contains("synthetic-alpha_futureWindow_unknown_45m_reset_unknown"));
    assert!(names.contains("synthetic-beta_primary_weekly_reset_known"));
    assert!(names.contains("synthetic_2falpha_primary_unknown_duration_reset_unknown"));
    assert!(names.contains("synthetic_5falpha_primary_unknown_duration_reset_unknown"));
    let reached = windows
        .iter()
        .find(|window| window.name.starts_with("synthetic-alpha_primary"))
        .expect("reached window");
    assert_eq!(reached.limit_id.as_deref(), Some("synthetic-alpha"));
    assert_eq!(reached.spend_control_reached, Some(true));
    assert_eq!(
        reached.rate_limit_reached_type.as_deref(),
        Some("workspaceOwnerUsageLimitReached")
    );
    assert_eq!(reached.status, AgentQuotaWindowStatus::Exhausted);
}

#[test]
fn reset_credit_null_details_never_fabricate_zero_credits() {
    for details in [Value::Null, Value::Array(Vec::new())] {
        let json = serde_json::json!({
            "rateLimits": {},
            "rateLimitResetCredits": {
                "availableCount": 3,
                "credits": details
            }
        });
        let balances = codex_app_server_credit_balances(&json);
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].name, "reset_bank");
        assert_eq!(balances[0].remaining, CreditAmount::whole(3));
        assert_eq!(balances[0].unit, AgentCreditBalanceUnit::Resets);
    }
}

#[test]
fn codex_app_server_parser_carries_credit_spend_control_fields() {
    // The app-server snapshot is the only Codex quota collector, so it must
    // carry the spend-cap contract.
    let json = serde_json::json!({
        "rateLimitsByLimitId": {
            "codex": {
                "limitId": "codex",
                "primary": {
                    "usedPercent": 100,
                    "windowDurationMins": 300,
                    "resetsAt": 1779049800
                },
                "credits": {
                    "hasCredits": true,
                    "unlimited": false,
                    "balance": "9"
                },
                "spendControlReached": true,
                "rateLimitReachedType": "workspaceMemberCreditsDepleted"
            }
        }
    });

    let credits = codex_app_server_credit_balances(&json);

    assert_eq!(credits.len(), 1);
    assert_eq!(credits[0].name, "credits");
    assert_eq!(credits[0].remaining, CreditAmount::whole(9));
    // A reached spend cap is a hard stop even with a nominal balance remaining.
    assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
    assert_eq!(credits[0].spend_control_reached, Some(true));
    assert_eq!(
        credits[0].rate_limit_reached_type.as_deref(),
        Some("workspaceMemberCreditsDepleted")
    );
    assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
}

#[test]
fn codex_app_server_preserves_credit_balances_from_multiple_limit_buckets() {
    let json = serde_json::json!({
        "rateLimitsByLimitId": {
            "codex": {
                "limitId": "codex",
                "credits": {"hasCredits": true, "balance": "12"}
            },
            "codex_business": {
                "limitId": "codex_business",
                "credits": {"hasCredits": true, "balance": "4"}
            }
        }
    });

    let balances = codex_app_server_credit_balances(&json);
    let by_name = balances
        .into_iter()
        .map(|balance| (balance.name.clone(), balance))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(by_name["credits"].remaining, CreditAmount::whole(12));
    assert_eq!(
        by_name["codex_business_credits"].remaining,
        CreditAmount::whole(4)
    );
    assert_eq!(
        by_name["codex_business_credits"].limit_id.as_deref(),
        Some("codex_business")
    );
}

#[test]
fn codex_app_server_parser_carries_workspace_monthly_credit_limit() {
    let json = serde_json::json!({
        "rateLimitsByLimitId": {
            "codex": {
                "limitId": "codex",
                "primary": {
                    "usedPercent": 100,
                    "windowDurationMins": 10080,
                    "resetsAt": 1786431605_u64
                },
                "credits": {
                    "hasCredits": true,
                    "unlimited": false,
                    "balance": null
                },
                "individualLimit": {
                    "limit": "8000",
                    "used": "4841",
                    "remainingPercent": 39,
                    "resetsAt": 1788220800_u64
                },
                "spendControlReached": false
            }
        }
    });

    let windows = codex_app_server_quota_windows(&json);
    let credits = codex_app_server_credit_balances(&json);

    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].status, AgentQuotaWindowStatus::Exhausted);
    assert_eq!(credits.len(), 2);
    assert_eq!(credits[0].name, "credits");
    assert_eq!(credits[0].status, AgentCreditBalanceStatus::Ok);
    let monthly = &credits[1];
    assert_eq!(monthly.name, "workspace_monthly_credits");
    assert_eq!(monthly.status, AgentCreditBalanceStatus::Ok);
    assert_eq!(monthly.used, CreditAmount::whole(4841));
    assert_eq!(monthly.quota, CreditAmount::whole(8000));
    assert_eq!(monthly.remaining, CreditAmount::whole(3159));
    assert_eq!(monthly.used_percent, Some(61));
    assert_eq!(monthly.resets_at.as_deref(), Some("2026-09-01T00:00:00Z"));
    assert_eq!(monthly.spend_control_reached, Some(false));
}

#[test]
fn codex_app_server_falls_back_from_null_effective_snapshot_to_limit_map() {
    let json = serde_json::json!({
        "rateLimits": {
            "limitId": "codex",
            "primary": null,
            "secondary": null,
            "credits": null,
            "individualLimit": null
        },
        "rateLimitsByLimitId": {
            "codex": {
                "limitId": "codex",
                "primary": {
                    "usedPercent": 21,
                    "windowDurationMins": 10080,
                    "resetsAt": 1779613200
                },
                "credits": {
                    "hasCredits": true,
                    "unlimited": false,
                    "balance": "3"
                }
            }
        }
    });

    let windows = codex_app_server_quota_windows(&json);
    let credits = codex_app_server_credit_balances(&json);

    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].left_percent, Some(79));
    assert_eq!(credits.len(), 1);
    assert_eq!(credits[0].remaining, CreditAmount::whole(3));
}

#[test]
fn codex_app_server_parser_preserves_zero_reset_bank_count() {
    let json = serde_json::json!({
        "rateLimits": {
            "limitId": "codex",
            "primary": null,
            "secondary": null,
            "credits": null
        },
        "rateLimitResetCredits": {
            "availableCount": 0
        }
    });

    let credits = codex_app_server_credit_balances(&json);

    assert_eq!(credits.len(), 1);
    assert_eq!(credits[0].name, "reset_bank");
    assert_eq!(credits[0].unit, AgentCreditBalanceUnit::Resets);
    assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
    assert_eq!(credits[0].remaining, CreditAmount::whole(0));
}

/// Codex credit status compares exact amounts: 0.4 is low (not exhausted),
/// 5.4 is ok (not low), `hasCredits: false` with 0.3 keeps a low row, and a
/// fractional monthly headroom is not exhausted. True zero stays exhausted
/// and a negative balance stays absent and unknown, never zero.
#[test]
fn codex_credit_amounts_are_exact_through_status_and_wire() {
    use AgentCreditBalanceStatus as Status;
    let row = |snapshot: Value, name: &str| {
        let balances =
            codex_app_server_credit_balances(&serde_json::json!({"rateLimits": snapshot}));
        let row = balances.into_iter().find(|balance| balance.name == name);
        let wire = row.as_ref().map(|row| serde_json::to_value(row).unwrap());
        let remaining = wire.and_then(|wire| wire.get("remaining").cloned());
        (row.map(|row| row.status), remaining.unwrap_or(Value::Null))
    };
    for (credits, status, remaining) in [
        (
            r#"{"hasCredits":true,"balance":"0.4"}"#,
            Some(Status::Low),
            r#""0.4""#,
        ),
        (
            r#"{"hasCredits":true,"balance":"5.4"}"#,
            Some(Status::Ok),
            r#""5.4""#,
        ),
        (
            r#"{"hasCredits":false,"balance":"0.3"}"#,
            Some(Status::Low),
            r#""0.3""#,
        ),
        (
            r#"{"hasCredits":true,"balance":"0"}"#,
            Some(Status::Exhausted),
            "0",
        ),
        (r#"{"hasCredits":false,"balance":"0"}"#, None, "null"),
        (
            r#"{"hasCredits":true,"balance":"5"}"#,
            Some(Status::Low),
            "5",
        ),
        (
            r#"{"unlimited":false,"balance":"-5"}"#,
            Some(Status::Unknown),
            "null",
        ),
    ] {
        let credits: Value = serde_json::from_str(credits).unwrap();
        let snapshot = serde_json::json!({"limitId": "codex", "credits": credits.clone()});
        let expected = (status, serde_json::from_str::<Value>(remaining).unwrap());
        assert_eq!(row(snapshot, "credits"), expected, "{credits}");
    }
    let monthly = serde_json::json!({
        "limitId": "codex",
        "individualLimit": {"limit": "8000", "used": "7999.5"}
    });
    assert_eq!(
        row(monthly, "workspace_monthly_credits"),
        (Some(Status::Ok), serde_json::json!("0.5"))
    );
}

/// [regress] The provider decodes rounded fractional credit numbers
/// through `f64`. Each decode keeps a raw credit number exact: it reaches
/// the wire with the same six half-even digits as its string form (Claude
/// money: half-even cents on spend, windows, one-time pools and the cached
/// config copy), numbers outside the credit subtrees stay numbers, and a
/// one-time pool is admitted exactly when its limit reads as money.
#[test]
fn provider_decodes_keep_raw_credit_numbers_exact() {
    use super::credit_amount_input::{decode, CreditBody};
    let message = decode(
        r#"{"id":1,"result":{"rateLimits":{"limitId":"codex",
            "primary":{"usedPercent":12.5,"windowDurationMins":300},
            "credits":{"hasCredits":true,"balance":49591.7041935000},
            "individualLimit":{"limit":8000,"used":1.2345665000}}}}"#,
        CreditBody::CodexMessage,
    )
    .expect("codex message");
    let rate_limits = &message["result"];
    assert!(rate_limits["rateLimits"]["primary"]["usedPercent"].is_number());
    let wire = serde_json::to_value(codex_app_server_credit_balances(rate_limits)).unwrap();
    assert_eq!(wire[0]["name"], "credits");
    assert_eq!(wire[0]["remaining"], "49591.704194");
    assert_eq!(wire[1]["name"], "workspace_monthly_credits");
    assert_eq!(wire[1]["used"], "1.234566");
    assert_eq!(wire[1]["quota"], 8000);
    assert_eq!(wire[1]["remaining"], "7998.765434");

    // 12.5 cents is an exact tie: half-even keeps 12 (was 13).
    let usage = r#"{"five_hour":{"utilization":12.5,"used_dollars":0.125},
        "seven_day":{"utilization":3,"used_dollars":2501.367212},
        "spend":{"enabled":true,"used":0.125,"limit":{"amount_minor":5000,"exponent":2}},
        "iguana_necktie":{"limit_dollars":250,"used_dollars":0.125,
            "remaining_dollars":249.875,"resets_at":"2026-11-05T07:59:00+00:00"},
        "amber_ladder":{"limit_dollars":"1","remaining_dollars":1,
            "resets_at":"2026-11-05T07:59:00+00:00"},
        "wattle_ember":{"limit_dollars":{"amount_minor":500,"exponent":2},
            "resets_at":"2026-11-05T07:59:00+00:00"},
        "maple_harbor":{"limit_dollars":-5,"remaining_dollars":1,
            "resets_at":"2026-11-05T07:59:00+00:00"}}"#;
    let body = decode(usage, CreditBody::ClaudeUsage).expect("usage body");
    assert!(body["five_hour"]["utilization"].is_number());
    let windows = claude_oauth_quota_windows(&body)
        .into_iter()
        .map(|window| (window.name, window.used_cents))
        .collect::<Vec<_>>();
    assert_eq!(
        windows,
        [
            ("session".to_string(), Some(12)),
            ("weekly".to_string(), Some(250_137))
        ]
    );
    assert_eq!(
        claude_oauth_credit_balances(&body)[0].used,
        CreditAmount::whole(12)
    );
    let read = claude_credit_pools::claude_credit_read(
        &body,
        claude_credit_pools::ClaudeUsageRead::Plain,
        "2026-10-09T14:06:52Z",
    );
    let pools = claude_credit_pools::claude_merge_credit_sections("b", &[], &read)
        .into_iter()
        .filter(|balance| balance.kind == Some(ottto_protocol::CreditBalanceKind::OneTimeCredit))
        .map(|pool| {
            let wire = serde_json::to_value(&pool).unwrap();
            serde_json::json!([
                wire["limit_id"],
                wire["quota"],
                wire["used"],
                wire["remaining"]
            ])
        })
        .collect::<Vec<_>>();
    assert_eq!(
        pools,
        [
            serde_json::json!(["amber_ladder", 100, null, 100]),
            serde_json::json!(["iguana_necktie", 25_000, 12, 24_988]),
            serde_json::json!(["wattle_ember", 500, null, null]),
        ]
    );
    let config =
        format!(r#"{{"cachedUsageUtilization":{{"fetchedAtMs":1.5,"utilization":{usage}}}}}"#);
    let config = decode(&config, CreditBody::ClaudeConfig).expect("config");
    assert!(config["cachedUsageUtilization"]["fetchedAtMs"].is_number());
    assert_eq!(config["cachedUsageUtilization"]["utilization"], body);
}

#[test]
fn claude_json_parser_accepts_current_camel_case_auth_status() {
    let json = serde_json::json!({
        "loggedIn": true,
        "authMethod": "claude.ai",
        "apiProvider": "firstParty",
        "email": "user@example.com",
        "orgId": "org_2",
        "orgName": "Research Team",
        "subscriptionType": "max"
    });

    let account = parse_claude_auth_json(&json);

    assert_eq!(account.login_state, AgentLoginState::SignedIn);
    assert_eq!(account.auth_method.as_deref(), Some("claude.ai"));
    assert_eq!(account.organization_id.as_deref(), Some("org_2"));
    assert_eq!(account.organization_label.as_deref(), Some("Research Team"));
    assert_eq!(account.plan_type.as_deref(), Some("max"));
    assert_eq!(account.subscription_product.as_deref(), Some("claude_max"));
    assert_eq!(account.billing_channel.as_deref(), Some("subscription"));
}

fn team_auth_account(email: &str, org_id: &str) -> AgentAccountStatus {
    parse_claude_auth_json(&serde_json::json!({
        "loggedIn": true,
        "authMethod": "claude.ai",
        "apiProvider": "firstParty",
        "email": email,
        "orgId": org_id,
        "orgName": "Acme",
        "subscriptionType": "team"
    }))
}

#[test]
fn claude_cli_account_identity_stamps_account_hash_onto_plan_observation() {
    // `claude auth status --json` names the org but not the account uuid;
    // the uuid rides `~/.claude.json` `oauthAccount`. The stamped hash must
    // be the exact `billing_identity_hash` the quota windows carry so plan
    // and quota evidence converge on one billing identity.
    let mut account = team_auth_account("team.member@example.com", "org-1");
    assert!(account.account_id.is_none());
    assert!(account.account_identifier_hash.is_none());
    let oauth = ClaudeCliOauthAccount {
        account_uuid: Some("acct-1".to_string()),
        email_address: Some("team.member@example.com".to_string()),
        organization_uuid: Some("org-1".to_string()),
        ..ClaudeCliOauthAccount::default()
    };

    assert!(stamp_claude_cli_account_identity(&mut account, &oauth));

    assert_eq!(account.account_id.as_deref(), Some("acct-1"));
    assert_eq!(
        account.account_identifier_hash,
        billing_identity_hash("anthropic", "account", "acct-1")
    );
    assert!(account.organization_identifier_hash.is_some());
    assert_eq!(
        account.billing_identity_evidence.as_deref(),
        Some("provider_account_id")
    );

    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-07-28T10:00:00Z".to_string(),
        "2026-07-28T10:30:00Z".to_string(),
    );
    snapshot.account = Some(account);
    append_current_plan_observation(&mut snapshot);

    let observation = snapshot
        .plan_observations
        .first()
        .expect("plan observation");
    assert_eq!(observation.account_id.as_deref(), Some("acct-1"));
    assert_eq!(
        observation.account_identifier_hash,
        billing_identity_hash("anthropic", "account", "acct-1")
    );
    assert!(observation.organization_identifier_hash.is_some());
    assert_eq!(
        observation.billing_identity_evidence.as_deref(),
        Some("provider_account_id")
    );
}

/// One collected Claude account: a snapshot whose account carries the
/// product, the hashes and the email, as a registered slot's collection
/// produces.
fn claude_account_snapshot(
    email: &str,
    subscription_product: &str,
    account_hash: &str,
    organization_hash: &str,
) -> AgentStatusSnapshot {
    let mut account = max_auth_account(email);
    account.subscription_product = Some(subscription_product.to_string());
    account.account_identifier_hash = Some(account_hash.to_string());
    account.organization_identifier_hash = Some(organization_hash.to_string());
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-09-18T10:00:00Z".to_string(),
        "2026-09-18T10:30:00Z".to_string(),
    );
    snapshot.account = Some(account);
    snapshot
}

#[test]
fn registered_claude_accounts_carry_their_product_into_source_health() {
    // The source-health snapshot is the default slot's, so it names only
    // the signed-in account's product. Every other account's product lives
    // on its own slot snapshot, and the app titles its rows from these
    // observations — without the merge they read as a bare email.
    let current = claude_account_snapshot(
        "ron@ottto.net",
        "claude_max_20x",
        "hash-current",
        "org-current",
    );
    let mut source_health = current.clone();
    append_current_plan_observation(&mut source_health);
    let snapshots = vec![
        current,
        claude_account_snapshot(
            "personal.member@example.com",
            "claude_max_20x",
            "hash-personal",
            "org-personal",
        ),
        claude_account_snapshot(
            "team.member@example.com",
            "claude_team_premium",
            "hash-team",
            "org-team",
        ),
    ];

    append_registered_claude_plan_observations(&mut source_health, &snapshots);

    let described = source_health
        .plan_observations
        .iter()
        .map(|observation| {
            (
                observation.account_label.as_deref().unwrap_or_default(),
                observation
                    .subscription_product
                    .as_deref()
                    .unwrap_or_default(),
                observation.is_current,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        described,
        vec![
            ("ron@ottto.net", "claude_max_20x", Some(true)),
            ("personal.member@example.com", "claude_max_20x", Some(false)),
            (
                "team.member@example.com",
                "claude_team_premium",
                Some(false)
            ),
        ]
    );
}

#[test]
fn registered_claude_plan_observations_describe_each_account_once() {
    // The signed-in account is collected twice: once as the default slot
    // and again as its own registered slot. It must not gain a second
    // observation, which would give the app two rows for one account.
    let current = claude_account_snapshot(
        "ron@ottto.net",
        "claude_max_20x",
        "hash-current",
        "org-current",
    );
    let mut source_health = current.clone();
    append_current_plan_observation(&mut source_health);
    let snapshots = vec![current.clone(), current];

    append_registered_claude_plan_observations(&mut source_health, &snapshots);

    assert_eq!(source_health.plan_observations.len(), 1);
    assert_eq!(
        source_health.plan_observations[0].is_current,
        Some(true),
        "the already-described account keeps the current observation"
    );
}

#[test]
fn registered_claude_plan_observations_separate_organizations_of_one_login() {
    // A Team seat and a personal organization share one login, so the
    // account hash alone cannot tell them apart. Each organization is its
    // own subscription and earns its own observation.
    let mut source_health = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-09-18T10:00:00Z".to_string(),
        "2026-09-18T10:30:00Z".to_string(),
    );
    let snapshots = vec![
        claude_account_snapshot(
            "team.member@example.com",
            "claude_max_20x",
            "hash-one",
            "org-personal",
        ),
        claude_account_snapshot(
            "team.member@example.com",
            "claude_team_premium",
            "hash-one",
            "org-team",
        ),
    ];

    append_registered_claude_plan_observations(&mut source_health, &snapshots);

    let products = source_health
        .plan_observations
        .iter()
        .filter_map(|observation| observation.subscription_product.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(products, vec!["claude_max_20x", "claude_team_premium"]);
}

#[test]
fn claude_cli_account_identity_refuses_mismatched_metadata() {
    // `~/.claude.json` lagging behind an account switch must never stamp a
    // different account's uuid onto the signed-in account.
    let mut account = team_auth_account("team.member@example.com", "org-1");
    let stale_email = ClaudeCliOauthAccount {
        account_uuid: Some("acct-other".to_string()),
        email_address: Some("someone.else@example.com".to_string()),
        ..ClaudeCliOauthAccount::default()
    };
    assert!(!stamp_claude_cli_account_identity(
        &mut account,
        &stale_email
    ));
    assert!(account.account_id.is_none());
    assert!(account.account_identifier_hash.is_none());

    let stale_org = ClaudeCliOauthAccount {
        account_uuid: Some("acct-other".to_string()),
        organization_uuid: Some("org-other".to_string()),
        ..ClaudeCliOauthAccount::default()
    };
    assert!(!stamp_claude_cli_account_identity(&mut account, &stale_org));
    assert!(account.account_identifier_hash.is_none());

    // A present auth-status account id that disagrees with `accountUuid`
    // refuses too, and the existing id is left untouched.
    account.account_id = Some("acct-auth-status".to_string());
    let conflicting = ClaudeCliOauthAccount {
        account_uuid: Some("acct-other".to_string()),
        email_address: Some("team.member@example.com".to_string()),
        organization_uuid: Some("org-1".to_string()),
        ..ClaudeCliOauthAccount::default()
    };
    assert!(!stamp_claude_cli_account_identity(
        &mut account,
        &conflicting
    ));
    assert_eq!(account.account_id.as_deref(), Some("acct-auth-status"));
    assert!(account.account_identifier_hash.is_none());

    // No account uuid in the metadata: nothing to stamp.
    let uuid_less = ClaudeCliOauthAccount {
        email_address: Some("team.member@example.com".to_string()),
        ..ClaudeCliOauthAccount::default()
    };
    let mut fresh = team_auth_account("team.member@example.com", "org-1");
    assert!(!stamp_claude_cli_account_identity(&mut fresh, &uuid_less));
    assert!(fresh.account_identifier_hash.is_none());
}

fn max_auth_account(email: &str) -> AgentAccountStatus {
    parse_claude_auth_json(&serde_json::json!({
        "loggedIn": true,
        "authMethod": "claude.ai",
        "apiProvider": "firstParty",
        "email": email,
        "subscriptionType": "max"
    }))
}

/// One registered slot on a throwaway HOME with a fake `claude` that only
/// records that it ran and a fake `security` whose behaviour the test
/// chooses. Nothing touches the real keychain or the real CLI.
struct LocalSlotFixture {
    root: PathBuf,
    slot_dir: PathBuf,
    descriptor: ClaudeConfigSlotDescriptorV1,
    _guards: Vec<EnvVarGuard>,
}

impl LocalSlotFixture {
    fn new(label: &str, security_script: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-local-slot-{label}-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let home = root.join("home");
        let bin = root.join("bin");
        let support = root.join("support");
        let slot_dir = root.join("slot");
        for dir in [&home, &bin, &support, &slot_dir] {
            fs::create_dir_all(dir).expect("create fixture dir");
        }
        let claude = bin.join("claude");
        fs::write(
            &claude,
            "#!/bin/sh\n/usr/bin/touch \"$(/usr/bin/dirname \"$0\")/claude-spawned\"\nexit 0\n",
        )
        .expect("write fake claude");
        let security = bin.join("security");
        fs::write(&security, security_script).expect("write fake security");
        for executable in [&claude, &security] {
            let mut permissions = fs::metadata(executable).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(executable, permissions).expect("chmod executable");
        }
        let guards = vec![
            EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string()),
            EnvVarGuard::set_os(
                "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
                support.as_os_str().to_os_string(),
            ),
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string()),
        ];
        let descriptor = ClaudeConfigDirSlot::registered(slot_dir.to_string_lossy().to_string())
            .expect("registered slot")
            .descriptor(
                format!("claude_slot_{label}"),
                ClaudeConfigSlotOwnership::Managed,
            );
        Self {
            root,
            slot_dir,
            descriptor,
            _guards: guards,
        }
    }

    fn write_identity(&self, oauth_account: Value) {
        fs::write(
            self.slot_dir.join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({ "oauthAccount": oauth_account }))
                .expect("serialize identity"),
        )
        .expect("write slot identity");
    }

    fn write_credential(&self, credential: &Value) {
        fs::write(
            self.slot_dir.join(".credentials.json"),
            serde_json::to_vec(credential).expect("serialize credential"),
        )
        .expect("write slot credential");
    }

    fn slot(&self) -> ClaudeConfigDirSlot {
        ClaudeConfigDirSlot::registered(self.slot_dir.to_string_lossy().to_string()).expect("slot")
    }

    fn claude_spawned(&self) -> bool {
        self.root.join("bin").join("claude-spawned").exists()
    }
}

impl Drop for LocalSlotFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const SECURITY_ITEM_NOT_FOUND: &str = "#!/bin/sh\nexit 44\n";

/// What `claude auth status --json` printed for a slot, rebuilt through
/// the same parse + identity + refinement path the old resolver used, so
/// the local-metadata account can be compared field by field.
fn account_from_legacy_auth_status(
    auth_status: Value,
    oauth: &ClaudeCliOauthAccount,
) -> AgentAccountStatus {
    let mut account = parse_claude_auth_json(&auth_status);
    require_claude_auth_identity_agreement(&account, oauth).expect("legacy agreement");
    refine_claude_local_plan_metadata(&mut account, oauth);
    assert!(stamp_claude_cli_account_identity(&mut account, oauth));
    account
}

/// T8: the plan comes from the stored login's `subscriptionType` and the
/// `.claude.json` refinements, and the account matches what `claude auth
/// status` produced, for Max 20x and Team Premium. No CLI runs.
#[test]
#[serial]
fn local_metadata_resolution_matches_the_auth_status_account() {
    for (label, identity, plan, legacy, expected_plan) in [
        (
            "max-20x",
            serde_json::json!({
                "accountUuid": "account-max-20x",
                "organizationUuid": "organization-max-20x",
                "emailAddress": "max20x@example.invalid",
                "organizationType": "claude_max",
                "organizationRateLimitTier": "default_claude_max_20x"
            }),
            "max",
            serde_json::json!({
                "loggedIn": true,
                "authMethod": "claude.ai",
                "apiProvider": "firstParty",
                "email": "max20x@example.invalid",
                "orgId": "organization-max-20x",
                "subscriptionType": "max"
            }),
            "max_20x",
        ),
        (
            "team-premium",
            serde_json::json!({
                "accountUuid": "account-team",
                "organizationUuid": "organization-team",
                "organizationName": "Example Team",
                "emailAddress": "team@example.invalid",
                "organizationType": "claude_team",
                "seatTier": "premium"
            }),
            "team",
            serde_json::json!({
                "loggedIn": true,
                "authMethod": "claude.ai",
                "apiProvider": "firstParty",
                "email": "team@example.invalid",
                "orgId": "organization-team",
                "orgName": "Example Team",
                "subscriptionType": "team"
            }),
            "team_premium",
        ),
    ] {
        let fixture = LocalSlotFixture::new(label, SECURITY_ITEM_NOT_FOUND);
        fixture.write_identity(identity.clone());
        fixture.write_credential(&claude_credential_fixture(
            "fixture",
            TimeDuration::hours(6),
            Some(plan),
        ));

        let resolved = resolve_registered_claude_slot(fixture.descriptor.clone())
            .expect("resolve from local metadata");

        let oauth = parse_claude_cli_oauth_account(&serde_json::json!({
            "oauthAccount": identity
        }))
        .expect("oauth account");
        let legacy = account_from_legacy_auth_status(legacy, &oauth);
        assert_eq!(resolved.account.plan_type.as_deref(), Some(expected_plan));
        assert_eq!(resolved.account.plan_type, legacy.plan_type, "{label}");
        assert_eq!(
            resolved.account.subscription_product, legacy.subscription_product,
            "{label}"
        );
        assert_eq!(resolved.account.billing_channel, legacy.billing_channel);
        assert_eq!(resolved.account.auth_method, legacy.auth_method);
        assert_eq!(resolved.account.login_state, AgentLoginState::SignedIn);
        assert_eq!(resolved.account.email, legacy.email);
        assert_eq!(resolved.account.organization_id, legacy.organization_id);
        assert_eq!(
            resolved.account.organization_label,
            legacy.organization_label
        );
        assert_eq!(resolved.account.account_id, legacy.account_id);
        assert!(!fixture.claude_spawned(), "no Claude command ran");
    }
}

#[test]
fn local_login_state_follows_the_stored_credential_fields() {
    let now = OffsetDateTime::now_utc();
    let state = |payload: Value| {
        claude_local_login_state(
            &parse_claude_oauth_credential_read(&payload.to_string()),
            now,
        )
    };
    let with = |patch: &[(&str, Value)]| {
        let mut credential =
            claude_credential_fixture("fixture", TimeDuration::hours(2), Some("max"));
        for (key, value) in patch {
            if value.is_null() {
                credential["claudeAiOauth"]
                    .as_object_mut()
                    .expect("oauth object")
                    .remove(*key);
            } else {
                credential["claudeAiOauth"][*key] = value.clone();
            }
        }
        credential
    };
    let ms = |offset: TimeDuration| serde_json::json!((now + offset).unix_timestamp() * 1_000);

    assert_eq!(
        claude_local_login_state(&ClaudeCredentialRead::Absent, now),
        ClaudeLocalLoginState::NotSignedIn
    );
    assert_eq!(
        claude_local_login_state(&ClaudeCredentialRead::Unreadable, now),
        ClaudeLocalLoginState::Unreadable
    );
    assert_eq!(state(with(&[])), ClaudeLocalLoginState::AccessValid);
    // The exact shape Claude Code writes after an `invalid_grant` refresh.
    assert_eq!(
        state(with(&[
            ("accessToken", serde_json::json!("")),
            ("refreshToken", serde_json::json!("")),
            ("expiresAt", serde_json::json!(0)),
        ])),
        ClaudeLocalLoginState::SignedOutByCli
    );
    assert_eq!(
        state(with(&[("refreshToken", serde_json::json!(""))])),
        ClaudeLocalLoginState::NeedsLogin
    );
    assert_eq!(
        state(with(&[(
            "refreshTokenExpiresAt",
            ms(-TimeDuration::seconds(1))
        )])),
        ClaudeLocalLoginState::NeedsLogin
    );
    // Malformed: fail closed, never "signed out".
    for patch in [
        ("expiresAt", Value::Null),
        ("expiresAt", serde_json::json!("soon")),
        ("expiresAt", serde_json::json!(1.5e12)),
        ("accessToken", serde_json::json!("")),
        ("scopes", Value::Null),
        ("scopes", serde_json::json!(["user:profile"])),
    ] {
        assert_eq!(
            state(with(std::slice::from_ref(&patch))),
            ClaudeLocalLoginState::Unreadable,
            "{patch:?}"
        );
    }
    // The 60 s margin: at or inside it the login waits for Claude Code.
    assert_eq!(
        state(with(&[("expiresAt", ms(TimeDuration::seconds(61)))])),
        ClaudeLocalLoginState::AccessValid
    );
    for offset in [
        TimeDuration::seconds(60),
        TimeDuration::seconds(1),
        -TimeDuration::seconds(1),
        -TimeDuration::hours(8),
    ] {
        assert_eq!(
            state(with(&[("expiresAt", ms(offset))])),
            ClaudeLocalLoginState::RefreshPending,
            "{offset}"
        );
    }
}

#[test]
#[serial]
fn keychain_read_failures_fail_closed_and_only_not_found_falls_back_to_the_file() {
    for (label, script, expected) in [
        ("not-found", SECURITY_ITEM_NOT_FOUND, "absent"),
        ("locked", "#!/bin/sh\nexit 36\n", "unreadable"),
        ("garbage", "#!/bin/sh\necho not-json\n", "unreadable"),
        (
            "mcp-only",
            "#!/bin/sh\necho '{\"mcpOAuth\":{}}'\n",
            "absent",
        ),
        (
            "oauth-not-object",
            "#!/bin/sh\necho '{\"claudeAiOauth\":\"x\"}'\n",
            "unreadable",
        ),
    ] {
        let fixture = LocalSlotFixture::new(label, script);
        let read = read_claude_oauth_credential_state_for_slot(&fixture.slot());
        let observed = match read {
            ClaudeCredentialRead::Absent => "absent",
            ClaudeCredentialRead::Unreadable => "unreadable",
            ClaudeCredentialRead::Present(_) => "present",
        };
        assert_eq!(observed, expected, "{label}");
    }
    // Not found in the keychain: the credentials file decides; a corrupt
    // file is unreadable, not absent.
    let fixture = LocalSlotFixture::new("file-fallback", SECURITY_ITEM_NOT_FOUND);
    fs::write(fixture.slot_dir.join(".credentials.json"), "{").expect("corrupt file");
    assert!(matches!(
        read_claude_oauth_credential_state_for_slot(&fixture.slot()),
        ClaudeCredentialRead::Unreadable
    ));
    fixture.write_credential(&claude_credential_fixture(
        "fixture",
        TimeDuration::hours(2),
        None,
    ));
    assert!(matches!(
        read_claude_oauth_credential_state_for_slot(&fixture.slot()),
        ClaudeCredentialRead::Present(_)
    ));
    // A failed keychain read never resolves the slot, and never spawns.
    let locked = LocalSlotFixture::new("locked-resolve", "#!/bin/sh\nexit 36\n");
    locked.write_identity(serde_json::json!({
        "accountUuid": "account-locked",
        "organizationUuid": "organization-locked",
        "emailAddress": "locked@example.invalid"
    }));
    locked.write_credential(&claude_credential_fixture(
        "fixture",
        TimeDuration::hours(2),
        None,
    ));
    assert_eq!(
        resolve_registered_claude_slot(locked.descriptor.clone()).err(),
        Some(ClaudeSlotProbeFailure::ProbeFailed)
    );
    assert!(!locked.claude_spawned());
}

#[test]
#[serial]
fn expired_login_still_proves_identity_and_a_lapsed_grant_needs_login() {
    let fixture = LocalSlotFixture::new("expired-identity", SECURITY_ITEM_NOT_FOUND);
    fixture.write_identity(serde_json::json!({
        "accountUuid": "account-expired",
        "organizationUuid": "organization-expired",
        "emailAddress": "expired@example.invalid"
    }));
    fixture.write_credential(&claude_credential_fixture(
        "fixture",
        -TimeDuration::hours(3),
        Some("max"),
    ));
    let resolved = resolve_registered_claude_slot(fixture.descriptor.clone())
        .expect("an expired but refreshable login still proves its account");
    assert_eq!(
        resolved.account_identifier_hash,
        billing_identity_hash("anthropic", "account", "account-expired").expect("hash")
    );

    let mut lapsed = claude_credential_fixture("fixture", -TimeDuration::hours(3), None);
    lapsed["claudeAiOauth"]["refreshTokenExpiresAt"] = serde_json::json!(
        (OffsetDateTime::now_utc() - TimeDuration::minutes(1)).unix_timestamp() * 1_000
    );
    fixture.write_credential(&lapsed);
    assert_eq!(
        resolve_registered_claude_slot(fixture.descriptor.clone()).err(),
        Some(ClaudeSlotProbeFailure::CredentialUnavailable)
    );
    assert!(!fixture.claude_spawned());
}

#[test]
fn contradicting_local_plan_facts_are_a_different_login() {
    assert!(claude_local_plan_facts_contradict(
        Some("team"),
        Some("claude_max")
    ));
    assert!(claude_local_plan_facts_contradict(
        Some("max"),
        Some("claude_pro")
    ));
    assert!(!claude_local_plan_facts_contradict(
        Some("max"),
        Some("claude_max")
    ));
    assert!(!claude_local_plan_facts_contradict(
        Some("team"),
        Some("claude_team")
    ));
    assert!(!claude_local_plan_facts_contradict(
        None,
        Some("claude_max")
    ));
    assert!(!claude_local_plan_facts_contradict(Some("max"), None));
    // Unknown families are never a contradiction.
    assert!(!claude_local_plan_facts_contradict(
        Some("max"),
        Some("claude_free")
    ));
    assert!(!claude_local_plan_facts_contradict(
        Some("future_plan"),
        Some("claude_team")
    ));
}

/// A signed-in Max login's stored credential.
fn max_login_credential(access_token: &str) -> ClaudeOAuthCredential {
    ClaudeOAuthCredential {
        access_token: Some(access_token.to_string()),
        has_refresh_token: true,
        access_expires_at: None,
        relogin_required_at: None,
        has_inference_scope: Some(true),
        has_profile_scope: true,
        subscription_type: Some("max".to_string()),
    }
}

/// [behaviour] A credential and `.claude.json` from different logins get
/// their own sign-in-again code; a file that changes between the two reads
/// keeps the race code. Neither yields an identity.
#[test]
fn credential_account_mismatch_is_not_a_concurrent_mutation() {
    let oauth = |organization_type: &str| ClaudeCliOauthAccount {
        account_uuid: Some("account-fixture".to_string()),
        email_address: Some("fixture@example.invalid".to_string()),
        organization_uuid: Some("organization-fixture".to_string()),
        organization_type: Some(organization_type.to_string()),
        ..Default::default()
    };
    for (initial, last, expected, code) in [
        (
            "claude_team",
            "claude_team",
            ClaudeSlotProbeFailure::OwnerUnproven,
            "claude_login_owner_unproven",
        ),
        (
            "claude_max",
            "claude_team",
            ClaudeSlotProbeFailure::ConcurrentMutation,
            "claude_slot_concurrent_mutation",
        ),
    ] {
        let credential = max_login_credential("fixture");
        let failure = stable_claude_slot_credential(
            Some(oauth(initial)),
            Some(credential),
            Some(oauth(last)),
        )
        .and_then(|stable| {
            claude_account_from_local_metadata(&stable.oauth_account, &stable.credential)
        })
        .expect_err("no identity");
        assert_eq!(failure, expected);
        assert_eq!(default_claude_identity_diagnostic(failure).code, code);
        // The upload gate refuses either case, even with hashes present.
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-11-02T12:00:00Z".to_string(),
            "2026-11-02T12:15:00Z".to_string(),
        );
        snapshot.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            account_identifier_hash: Some("account-hash".to_string()),
            organization_identifier_hash: Some("organization-hash".to_string()),
            ..unsupported_account("anthropic")
        });
        snapshot
            .diagnostics
            .push(default_claude_identity_diagnostic(failure));
        assert!(!claude_default_snapshot_is_uploadable(&snapshot));
    }
}

/// [regress] The observed split (`.claude.json` names a Team account, the
/// token's owner is a known Max slot) resolves to that owner with the
/// split code, and keeps it while that token waits for its refresh.
/// [behaviour] Only a valid token whose plan contradicts
/// `.claude.json` is checked: proven and known → that account's identity,
/// split code and hashes; proven as the cached account → its identity,
/// the stale plan dropped; proven but unknown, or a failed check →
/// unproven (the caller fails closed); a failure is not retried inside its
/// back-off, and a proven token is not asked again. An expired token or
/// consistent files keep the usual path, consent on or off.
#[test]
#[serial_test::serial]
fn default_home_identity_follows_the_proven_token_owner() {
    use claude_token_owner::PROFILE_TEST_RESPONSE;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn terminal_profile(_token: &str) -> Result<Value, u16> {
        CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "account": {"uuid": "terminal-account", "email": "terminal@example.invalid"},
            "organization": {"uuid": "terminal-org", "organization_type": "claude_max"}
        }))
    }
    fn desktop_profile(_token: &str) -> Result<Value, u16> {
        CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "account": {"uuid": "desktop-account"},
            "organization": {"uuid": "desktop-org"}
        }))
    }
    fn unavailable(_token: &str) -> Result<Value, u16> {
        CALLS.fetch_add(1, Ordering::SeqCst);
        Err(503)
    }
    let oauth =
        |account: &str, organization: &str, organization_type: &str| ClaudeCliOauthAccount {
            account_uuid: Some(account.to_string()),
            email_address: Some(format!("{account}@example.invalid")),
            organization_uuid: Some(organization.to_string()),
            organization_type: Some(organization_type.to_string()),
            ..Default::default()
        };
    // `.claude.json` names Desktop's Team account; the token is a Max
    // login that a registered slot already knows.
    let desktop = oauth("desktop-account", "desktop-org", "claude_team");
    let terminal = oauth("terminal-account", "terminal-org", "claude_max");
    let stable = |token: &str| StableClaudeSlotCredential {
        oauth_account: desktop.clone(),
        credential: max_login_credential(token),
    };
    let known = std::slice::from_ref(&terminal);
    let calls = || CALLS.load(Ordering::SeqCst);
    let valid = ClaudeLocalLoginState::AccessValid;
    let resolve = |stable: &mut StableClaudeSlotCredential, known: &[ClaudeCliOauthAccount]| {
        resolve_claude_default_home_owner(&valid, stable, known).expect("checked")
    };

    // (a) Proven and known: the home is that account, from now on.
    PROFILE_TEST_RESPONSE.with(|respond| respond.set(Some(terminal_profile)));
    let mut proven = stable("owner-check-token-a");
    let owner = resolve(&mut proven, known);
    assert!(owner.split_login());
    assert_eq!(proven.oauth_account, terminal);
    claude_account_from_local_metadata(&proven.oauth_account, &proven.credential)
        .expect("the known owner's identity, without a plan contradiction");
    let mut status = ClaudeConfigSlotCollectionStatusV1::default();
    apply_claude_token_owner(&mut status, Some(&owner));
    let (terminal_account, terminal_org) =
        claude_strong_oauth_identity_hashes(&terminal).expect("terminal hashes");
    let (desktop_account, desktop_org) =
        claude_strong_oauth_identity_hashes(&desktop).expect("desktop hashes");
    assert_eq!(
        (
            status.token_owner_account_hash.as_deref(),
            status.token_owner_organization_hash.as_deref(),
            status.cached_account_hash.as_deref(),
            status.cached_organization_hash.as_deref(),
        ),
        (
            Some(terminal_account.as_str()),
            Some(terminal_org.as_str()),
            Some(desktop_account.as_str()),
            Some(desktop_org.as_str()),
        )
    );
    assert_eq!(
        owner
            .split_login_diagnostic()
            .map(|diagnostic| diagnostic.code),
        Some("claude_default_home_split_login".to_string())
    );
    assert!(status.owner_proven_at.is_some());
    let again = resolve(&mut stable("owner-check-token-a"), known);
    assert!(again.split_login());
    // [regress] The same token, lapsed and waiting for Claude Code's
    // refresh, keeps that owner without a call.
    let pending = resolve_claude_default_home_owner(
        &ClaudeLocalLoginState::RefreshPending,
        &mut stable("owner-check-token-a"),
        known,
    );
    assert!(pending.is_some_and(|owner| owner.split_login()));
    assert_eq!(calls(), 1, "one call per token");

    // (b) Proven but unknown: unproven, `.claude.json` is not used.
    let mut unknown = stable("owner-check-token-b");
    let owner = resolve(&mut unknown, &[]);
    assert!(owner.proven.is_none());
    assert_eq!(owner.binding_override(), Some(None));
    assert_eq!(unknown.oauth_account, desktop);
    assert_eq!(
        ClaudeSlotProbeFailure::OwnerUnproven.diagnostic_code(),
        "claude_login_owner_unproven"
    );

    // (c) The check fails: unproven, and not asked again in its back-off.
    PROFILE_TEST_RESPONSE.with(|respond| respond.set(Some(unavailable)));
    let before = calls();
    for _ in 0..2 {
        let owner = resolve(&mut stable("owner-check-token-c"), known);
        assert!(owner.proven.is_none());
    }
    assert_eq!(calls() - before, 1);

    // (e) Proven as the cached account: its identity, the stale plan dropped.
    PROFILE_TEST_RESPONSE.with(|respond| respond.set(Some(desktop_profile)));
    let mut same = stable("owner-check-token-e");
    let owner = resolve(&mut same, known);
    assert!(owner.proven.is_some() && !owner.split_login());
    assert_eq!(owner.binding_override(), None);
    assert_eq!(same.oauth_account, desktop);
    claude_account_from_local_metadata(&same.oauth_account, &same.credential)
        .expect("a proven owner outranks the stale plan");

    // (f) An expired token with no verdict of its own (another lineage) is
    // never sent: no call, the usual path (owner unproven).
    let before = calls();
    assert!(resolve_claude_default_home_owner(
        &ClaudeLocalLoginState::RefreshPending,
        &mut stable("owner-check-token-f"),
        known,
    )
    .is_none());
    assert_eq!(calls(), before);
    let lapsed = stable("owner-check-token-f");
    assert_eq!(
        claude_account_from_local_metadata(&lapsed.oauth_account, &lapsed.credential).err(),
        Some(ClaudeSlotProbeFailure::OwnerUnproven)
    );

    // (d) "Background limit refresh" off: no call inside a pass, unproven.
    PROFILE_TEST_RESPONSE.with(|respond| respond.set(Some(terminal_profile)));
    let support = std::env::temp_dir().join(format!(
        "ottto-owner-check-consent-off-{}",
        std::process::id()
    ));
    fs::create_dir_all(&support).expect("support dir");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support.as_os_str().to_os_string(),
    );
    FileClaudeConfigSlotSettingsStore::default()
        .set_upkeep_consent(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            false,
        )
        .expect("consent off");
    let before = calls();
    let (owner, consistent) = with_claude_pass(false, current_unix_seconds(), || {
        let mut consistent = StableClaudeSlotCredential {
            oauth_account: terminal.clone(),
            credential: max_login_credential("owner-check-token-g"),
        };
        (
            resolve(&mut stable("owner-check-token-d"), known),
            resolve_claude_default_home_owner(&valid, &mut consistent, known),
        )
    });
    assert!(owner.proven.is_none());
    assert!(consistent.is_none(), "consistent files keep the usual path");
    assert_eq!(calls(), before, "no profile call with consent off");
    PROFILE_TEST_RESPONSE.with(|respond| respond.set(None));
    let _ = fs::remove_dir_all(&support);
}

#[test]
fn default_unusable_login_display_preserves_classification_with_or_without_cli() {
    use ClaudeLocalLoginState as State;
    for state in [
        State::SignedOutByCli,
        State::NeedsLogin,
        State::NotSignedIn,
        State::Unreadable,
        State::AccessValid,
        State::RefreshPending,
    ] {
        let failure = match state {
            State::Unreadable => Some(ClaudeSlotProbeFailure::ProbeFailed),
            State::SignedOutByCli | State::NeedsLogin | State::NotSignedIn => {
                Some(ClaudeSlotProbeFailure::CredentialUnavailable)
            }
            State::AccessValid | State::RefreshPending => None,
        };
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Degraded,
            AgentStatusCollectionMethod::CommandProbe,
            "2026-10-09T06:00:00Z".to_string(),
            "2026-10-09T06:15:00Z".to_string(),
        );
        snapshot.account = Some(unsupported_account("anthropic"));
        if let Some(failure) = failure {
            snapshot
                .diagnostics
                .push(default_claude_identity_diagnostic(failure));
        }
        // Other diagnostics must survive the display filtering.
        snapshot
            .diagnostics
            .push(default_claude_identity_diagnostic(
                ClaudeSlotProbeFailure::IdentityUnknown,
            ));
        let expected = claude_default_slot_collection_status(&snapshot);
        for cli in [false, true] {
            let mut display = snapshot.clone();
            let status = prepare_default_claude_slot_status(&mut display, cli);
            assert_eq!(
                serde_json::to_value(&status).unwrap(),
                serde_json::to_value(&expected).unwrap(),
                "{state:?}, cli={cli}"
            );
            assert_eq!(
                serde_json::to_value(&display.account).unwrap(),
                serde_json::to_value(&snapshot.account).unwrap()
            );
            assert!(display
                .diagnostics
                .iter()
                .any(|d| d.code == ClaudeSlotProbeFailure::IdentityUnknown.diagnostic_code()));
            if let Some(failure) = failure {
                assert_eq!(
                    display
                        .diagnostics
                        .iter()
                        .any(|d| d.code == failure.diagnostic_code()),
                    cli
                );
                if state == State::Unreadable {
                    // A previously verified default retains its binding; this
                    // must still be temporary failure, never a sign-in demand.
                    let mut bound = status;
                    bound.account_identifier_hash = Some("fixture-account".to_string());
                    bound.organization_identifier_hash = Some("fixture-org".to_string());
                    assert_eq!(bound.state, ClaudeConfigSlotCollectionStateV1::ProbeFailed);
                    assert_eq!(
                        projected_claude_quota_access_state(&bound),
                        Some(ClaudeQuotaAccessState::TemporarilyUnavailable)
                    );
                }
            }
        }
    }
}

#[test]
#[serial]
fn cli_cleared_credential_is_signed_out_without_any_spawn_until_rewritten() {
    let fixture = LocalSlotFixture::new("cli-cleared", SECURITY_ITEM_NOT_FOUND);
    fixture.write_identity(serde_json::json!({
        "accountUuid": "account-rotated",
        "organizationUuid": "organization-rotated",
        "emailAddress": "rotated@example.invalid"
    }));
    // The exact shape Claude Code writes after an `invalid_grant` refresh.
    fixture.write_credential(&serde_json::json!({
        "claudeAiOauth": {
            "accessToken": "",
            "refreshToken": "",
            "expiresAt": 0,
            "refreshTokenExpiresAt": 1_793_000_000_000_i64,
            "scopes": ["user:inference"],
            "subscriptionType": "max"
        }
    }));
    fs::remove_file(fixture.root.join("bin/claude")).expect("remove fixture CLI");
    assert!(crate::command_env::claude_default_login_executable_path(&home_dir()).is_none());
    let descriptor = fixture.descriptor.clone();

    let failure = resolve_registered_claude_slot(descriptor.clone())
        .err()
        .expect("cleared credential must not resolve");
    assert_eq!(failure, ClaudeSlotProbeFailure::SignedOutByCli);
    let status = registered_claude_failure_status(
        &descriptor,
        None,
        failure,
        "2026-10-03T17:50:00Z",
        ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::NotRequired,
            due_access_expires_at: Some(
                (OffsetDateTime::now_utc() + TimeDuration::minutes(4))
                    .format(&Rfc3339)
                    .expect("format"),
            ),
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        },
    );
    assert_eq!(status.state, ClaudeConfigSlotCollectionStateV1::NeedsLogin);
    assert_eq!(
        status.diagnostics[0].code,
        ClaudeConfigSlotDiagnosticCodeV1::NeedsLogin
    );
    assert_eq!(
        status.access_expires_at, None,
        "stale pre-wipe deadlines must not look like a valid login"
    );
    let metadata = read_claude_oauth_credential_metadata_for_slot(&fixture.slot())
        .expect("cleared item is still readable");
    assert!(metadata.cleared_by_cli);
    assert!(!metadata.has_refresh_token);

    // A reconnect rewrites the item with tokens; the slot resolves again.
    fixture.write_credential(&claude_credential_fixture(
        "fixture-access",
        TimeDuration::hours(8),
        Some("max"),
    ));
    assert!(resolve_registered_claude_slot(descriptor).is_ok());
    assert!(!fixture.claude_spawned(), "no Claude command ever ran");
}

#[test]
fn registered_failure_status_keeps_last_known_unexpired_deadlines() {
    let access = (OffsetDateTime::now_utc() + TimeDuration::hours(6))
        .format(&Rfc3339)
        .expect("format");
    let relogin = (OffsetDateTime::now_utc() + TimeDuration::days(25))
        .format(&Rfc3339)
        .expect("format");
    let upkeep = ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
        result: ClaudeConfigSlotUpkeepResultV1::NotRequired,
        due_access_expires_at: Some(access.clone()),
        refresh_token_expires_at: Some(relogin.clone()),
        attempted_at: None,
        next_allowed_attempt_at: None,
        consecutive_failures: 0,
    };
    let descriptor = ClaudeConfigSlotDescriptorV1 {
        slot_id: "claude_slot_deadline_fixture".to_string(),
        ownership: ClaudeConfigSlotOwnership::Managed,
        config_dir: None,
        service_name: String::new(),
        collection: Default::default(),
    };

    for failure in [
        ClaudeSlotProbeFailure::ProbeFailed,
        ClaudeSlotProbeFailure::CredentialUnavailable,
    ] {
        let status = registered_claude_failure_status(
            &descriptor,
            None,
            failure,
            "2026-10-03T13:30:00Z",
            upkeep.clone(),
        );
        assert_eq!(status.access_expires_at.as_deref(), Some(access.as_str()));
        assert_eq!(
            status.relogin_required_at.as_deref(),
            Some(relogin.as_str())
        );
    }

    // Fallback: the previously persisted collection deadline.
    let mut persisted = descriptor.clone();
    persisted.collection.access_expires_at = Some(access.clone());
    persisted.collection.relogin_required_at = Some(relogin.clone());
    let status = registered_claude_failure_status(
        &persisted,
        None,
        ClaudeSlotProbeFailure::ProbeFailed,
        "2026-10-03T13:30:00Z",
        ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            due_access_expires_at: None,
            refresh_token_expires_at: None,
            ..upkeep.clone()
        },
    );
    assert_eq!(status.access_expires_at.as_deref(), Some(access.as_str()));

    // An already-past deadline is not carried; upkeep re-reads instead.
    let past = (OffsetDateTime::now_utc() - TimeDuration::minutes(1))
        .format(&Rfc3339)
        .expect("format");
    let status = registered_claude_failure_status(
        &descriptor,
        None,
        ClaudeSlotProbeFailure::CredentialUnavailable,
        "2026-10-03T13:30:00Z",
        ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            due_access_expires_at: Some(past),
            ..upkeep
        },
    );
    assert_eq!(status.access_expires_at, None);
}

#[test]
fn refine_claude_local_plan_metadata_resolves_max_20x_for_a_registered_slot() {
    // Regression: a registered (`CLAUDE_CONFIG_DIR`) slot used to skip the
    // refinements the default slot applied, so a Max 20x account in an
    // external slot shipped a bare `max` and the backend priced it as the
    // conservative Max 5x lower bound ($100 instead of $200). This is the
    // exact on-disk shape of such a slot: bare `max` from
    // `claude auth status --json`, 20x only in the slot's `.claude.json`.
    let mut account = max_auth_account("user@example.com");
    assert_eq!(account.plan_type.as_deref(), Some("max"));
    let oauth = ClaudeCliOauthAccount {
        email_address: Some("user@example.com".to_string()),
        organization_type: Some("claude_max".to_string()),
        organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
        ..ClaudeCliOauthAccount::default()
    };

    let refined = refine_claude_local_plan_metadata(&mut account, &oauth);

    assert_eq!(refined.max_plan, Some("max_20x"));
    assert_eq!(refined.seat_plan, None);
    assert_eq!(account.plan_type.as_deref(), Some("max_20x"));
    assert_eq!(
        account.subscription_product.as_deref(),
        Some("claude_max_20x")
    );
}

#[test]
fn claude_max_tier_ignores_non_max_plans_and_orgs() {
    // Team plan: the max refinement never fires.
    let mut team_account = team_auth_account("team.member@example.com", "org-1");
    let oauth = ClaudeCliOauthAccount {
        organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
        ..ClaudeCliOauthAccount::default()
    };
    assert_eq!(
        refine_claude_max_rate_limit_plan(&mut team_account, &oauth),
        None
    );

    // A stale non-max organizationType blocks refinement even when the
    // auth status says max.
    let mut max_account = max_auth_account("user@example.com");
    let stale_oauth = ClaudeCliOauthAccount {
        organization_type: Some("claude_team".to_string()),
        organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
        ..ClaudeCliOauthAccount::default()
    };
    assert_eq!(
        refine_claude_max_rate_limit_plan(&mut max_account, &stale_oauth),
        None
    );
    assert_eq!(max_account.plan_type.as_deref(), Some("max"));
}

#[test]
fn claude_desktop_metadata_observations_split_current_desktop_account() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-desktop-profile-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create root");
    std::fs::write(
        root.join("config.json"),
        r#"{"lastKnownAccountUuid":"desktop-account-current"}"#,
    )
    .expect("write config");

    let current_code = root
        .join("claude-code-sessions")
        .join("desktop-account-current")
        .join("acme-org-bucket");
    std::fs::create_dir_all(&current_code).expect("create current code bucket");
    std::fs::write(
        current_code.join("local_current.json"),
        r#"{
              "cliSessionId": "current-cli-session",
              "lastActivityAt": "2026-07-08T10:00:00Z",
              "cwd": "/Users/example/private",
              "title": "ignored"
            }"#,
    )
    .expect("write current code metadata");
    let current_identity = root
        .join("local-agent-mode-sessions")
        .join("desktop-account-current")
        .join("different-agent-mode-bucket");
    std::fs::create_dir_all(&current_identity).expect("create current identity bucket");
    std::fs::write(
        current_identity.join("local_identity.json"),
        // lastActivityAt must be explicit and OLDER than the code-session
        // bucket's: without it the reader falls back to file mtime (= test
        // run time), which outranks the code session's fixed timestamp and
        // flips latest_session_id — a wall-clock time bomb.
        r#"{
              "cliSessionId": "identity-cli-session",
              "lastActivityAt": "2026-07-06T10:00:00Z",
              "emailAddress": "team.member@example.com",
              "accountName": "Ron",
              "organizationName": "Acme",
              "subscriptionType": "team",
              "initialMessage": "must not be persisted"
            }"#,
    )
    .expect("write current identity metadata");

    let old_code = root
        .join("claude-code-sessions")
        .join("desktop-account-old")
        .join("gmail-org-bucket");
    std::fs::create_dir_all(&old_code).expect("create old code bucket");
    std::fs::write(
        old_code.join("local_old.json"),
        r#"{"cliSessionId":"old-cli-session","lastActivityAt":"2026-07-07T10:00:00Z"}"#,
    )
    .expect("write old code metadata");
    let old_identity = root
        .join("local-agent-mode-sessions")
        .join("desktop-account-old")
        .join("gmail-org-bucket");
    std::fs::create_dir_all(&old_identity).expect("create old identity bucket");
    std::fs::write(
        old_identity.join("local_identity.json"),
        r#"{"emailAddress":"personal.member@example.com"}"#,
    )
    .expect("write old identity metadata");

    let observations = claude_desktop_plan_observations_from_root(&root, "2026-07-08T10:01:00Z");

    assert_eq!(observations.len(), 2);
    let current = observations
        .iter()
        .find(|observation| observation.is_current == Some(true))
        .expect("current desktop observation");
    assert_eq!(
        current.evidence_method.as_deref(),
        Some("claude_desktop_session_bucket")
    );
    assert_eq!(current.auth_mode.as_deref(), Some("claude_desktop"));
    assert_eq!(current.billing_channel.as_deref(), Some("subscription"));
    assert_eq!(
        current.account_label.as_deref(),
        Some("team.member@example.com")
    );
    assert_eq!(current.organization_label.as_deref(), Some("Acme"));
    assert_eq!(current.plan_type.as_deref(), Some("team"));
    assert_eq!(current.subscription_product.as_deref(), Some("claude_team"));
    assert_eq!(
        current.account_id.as_deref(),
        Some("desktop-account-current")
    );
    assert_eq!(current.organization_id.as_deref(), Some("acme-org-bucket"));
    assert_eq!(
        current.source_session_id.as_deref(),
        Some("current-cli-session")
    );
    assert!(current.account_identifier_hash.is_some());
    assert!(current.organization_identifier_hash.is_some());
    assert_eq!(
        current.billing_identity_evidence.as_deref(),
        Some("provider_account_id")
    );
    assert_eq!(
        current.billing_identity_confidence,
        AgentStatusConfidence::High
    );

    let old = observations
        .iter()
        .find(|observation| {
            observation.account_label.as_deref() == Some("personal.member@example.com")
        })
        .expect("old desktop observation");
    assert_eq!(old.is_current, Some(false));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn claude_desktop_duplicate_session_owner_uses_newest_account_bucket() {
    let builders = vec![
        ClaudeDesktopProfileBuilder {
            account_uuid: "older-account".to_string(),
            session_activity_by_id: BTreeMap::from([(
                "resumed-session".to_string(),
                Some(1_700_000_000),
            )]),
            ..ClaudeDesktopProfileBuilder::default()
        },
        ClaudeDesktopProfileBuilder {
            account_uuid: "newer-account".to_string(),
            session_activity_by_id: BTreeMap::from([(
                "resumed-session".to_string(),
                Some(1_700_000_100),
            )]),
            ..ClaudeDesktopProfileBuilder::default()
        },
    ];

    assert_eq!(
        claude_desktop_unambiguous_duplicate_session_owners(&builders).get("resumed-session"),
        Some(&Some(("newer-account".to_string(), Some(1_700_000_100))))
    );
}

/// Writes `body` to `path` with an explicit modification time.
fn write_desktop_file(path: &Path, body: &str, modified_secs: u64) {
    std::fs::write(path, body).expect("write metadata");
    File::options()
        .write(true)
        .open(path)
        .and_then(|file| {
            file.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(modified_secs))
        })
        .expect("set modified time");
}

/// Desktop session folders with exact, imported, tied, copied and
/// non-UUID cases and agent-mode labels; every file long settled.
fn write_claude_desktop_pairs_fixture(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    let uuid = |n: u32| format!("00000000-0000-4000-8000-{n:012}");
    let (current, other, imported, tied) = (uuid(1), uuid(2), uuid(3), uuid(4));
    let (org_x, org_y, org_z, org_w) = (uuid(11), uuid(12), uuid(13), uuid(14));
    let (contested, agent_copied) = (uuid(5), uuid(6));
    std::fs::create_dir_all(root).expect("create root");
    std::fs::write(
        root.join("config.json"),
        format!(r#"{{"lastKnownAccountUuid":"{current}"}}"#),
    )
    .expect("write config");
    let write = |store: &str, account: &str, org: &str, file: &str, body: String| {
        let directory = root.join(store).join(account).join(org);
        std::fs::create_dir_all(&directory).expect("create bucket");
        write_desktop_file(&directory.join(file), &body, 1_780_000_000);
    };
    let session = |id: &str, activity: i64| {
        format!(r#"{{"cliSessionId":"{id}","lastActivityAt":{activity}}}"#)
    };
    let code = "claude-code-sessions";
    // The current account, plus a non-current account with two orgs.
    write(
        code,
        &current,
        &org_x,
        "local_a.json",
        session("current-x", 300),
    );
    write(
        code,
        &other,
        &org_y,
        "local_b.json",
        session("other-y", 200),
    );
    write(
        code,
        &other,
        &org_z,
        "local_c.json",
        session("other-z", 100),
    );
    // Labels come only from the pair's own agent-mode folder.
    write(
        "local-agent-mode-sessions",
        &other,
        &org_y,
        "local_label.json",
        r#"{"emailAddress":"other@example.com","organizationName":"Org Y"}"#.to_string(),
    );
    // Imported-only (any importedFrom, null included) is not a pair.
    write(
        code,
        &imported,
        &org_w,
        "local_d.json",
        r#"{"cliSessionId":"copied","lastActivityAt":250,"importedFrom":null}"#.to_string(),
    );
    // A tied copy witnesses neither folder; `other`/Y still has its own.
    write(code, &tied, &org_w, "local_e.json", session("tied", 120));
    write(code, &other, &org_y, "local_f.json", session("tied", 120));
    // Non-UUID folders keep their account reading but never form a pair.
    write(
        code,
        "legacy-account",
        "legacy-org",
        "local_g.json",
        session("legacy", 400),
    );
    // Copies the per-account rule sees also decide pair ownership: a tie
    // with a non-UUID folder, and a newer agent-mode copy elsewhere.
    write(
        code,
        &contested,
        &org_w,
        "local_h.json",
        session("contested", 130),
    );
    write(
        code,
        "legacy-account",
        "legacy-org",
        "local_i.json",
        session("contested", 130),
    );
    write(
        code,
        &agent_copied,
        &org_w,
        "local_j.json",
        session("agent-copied", 140),
    );
    write(
        "local-agent-mode-sessions",
        &other,
        &org_y,
        "local_k.json",
        session("agent-copied", 500),
    );
}

#[test]
fn claude_desktop_pairs_are_exact_native_uuid_folders() {
    let root =
        std::env::temp_dir().join(format!("ottto-claude-desktop-pairs-{}", std::process::id()));
    write_claude_desktop_pairs_fixture(&root);
    let uuid = |n: u32| format!("00000000-0000-4000-8000-{n:012}");
    let (current, other) = (uuid(1), uuid(2));
    let (org_x, org_y, org_z) = (uuid(11), uuid(12), uuid(13));
    let scan = claude_desktop_scan_from_root(
        &root,
        "2026-08-12T08:00:00Z",
        &mut ClaudeDesktopMetadataCache::default(),
    );
    let pairs = scan
        .pairs
        .pairs
        .iter()
        .map(|pair| &pair.observation)
        .collect::<Vec<_>>();
    assert_eq!(
        pairs
            .iter()
            .map(|pair| (pair.account_id.clone(), pair.organization_id.clone()))
            .collect::<Vec<_>>(),
        vec![
            (Some(current.clone()), Some(org_x.clone())),
            (Some(other.clone()), Some(org_y.clone())),
            (Some(other.clone()), Some(org_z.clone())),
        ],
        "newest first; imported-only, tied, outranked and non-UUID folders are not pairs"
    );
    for pair in &pairs {
        assert_eq!(
            pair.account_identifier_hash,
            billing_identity_hash("anthropic", "account", pair.account_id.as_deref().unwrap())
        );
        assert_eq!(
            pair.organization_identifier_hash,
            billing_identity_hash(
                "anthropic",
                "organization",
                pair.organization_id.as_deref().unwrap()
            )
        );
        assert_eq!(
            pair.billing_identity_confidence,
            AgentStatusConfidence::High
        );
        assert_eq!(pair.plan_type, None);
        // Never current: a current reading would replace a login's
        // metered row for the same pair on the backend.
        assert_eq!(pair.is_current, Some(false));
    }
    assert_eq!(pairs[0].source_session_id.as_deref(), Some("current-x"));
    assert_eq!(pairs[1].account_label.as_deref(), Some("other@example.com"));
    assert_eq!(pairs[1].organization_label.as_deref(), Some("Org Y"));
    assert_eq!(pairs[2].account_label, None);
    assert_eq!(pairs[2].organization_label, None);
    assert!(scan
        .observations
        .iter()
        .any(|observation| observation.account_id.as_deref() == Some("legacy-account")));

    let _ = std::fs::remove_dir_all(root);
}

/// Scans `root` through `cache`, asserts the result equals a scan with an
/// empty cache, and returns the cached scan's (read attempts, bytes read).
fn claude_desktop_cached_scan_reads(
    root: &Path,
    cache: &mut ClaudeDesktopMetadataCache,
) -> (usize, u64) {
    let outputs = |scan: ClaudeDesktopScan| {
        let pairs = |pairs: Vec<ClaudeDesktopPairObservation>| {
            pairs
                .into_iter()
                .map(|pair| (pair.binding, pair.observation))
                .collect::<Vec<_>>()
        };
        (
            scan.observations,
            pairs(scan.pairs.pairs),
            pairs(scan.pairs.duplicate_sessions),
        )
    };
    let observed_at = "2026-08-12T08:00:00Z";
    CLAUDE_DESKTOP_JSON_READ_RECEIPT.with(|receipt| receipt.set((0, 0)));
    let cached = claude_desktop_scan_from_root(root, observed_at, cache);
    let reads = CLAUDE_DESKTOP_JSON_READ_RECEIPT.with(std::cell::Cell::get);
    let fresh = claude_desktop_scan_from_root(
        root,
        observed_at,
        &mut ClaudeDesktopMetadataCache::default(),
    );
    assert_eq!(outputs(cached), outputs(fresh));
    reads
}

/// [regress] Every Claude status pass read every Desktop session file whole.
#[test]
fn claude_desktop_metadata_cache_unchanged_pass_reads_zero_bytes() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-desktop-cache-unchanged-{}",
        std::process::id()
    ));
    write_claude_desktop_pairs_fixture(&root);
    let mut cache = ClaudeDesktopMetadataCache::default();

    let (attempts, bytes) = claude_desktop_cached_scan_reads(&root, &mut cache);
    assert!(attempts > 0 && bytes > 0);
    assert_eq!(claude_desktop_cached_scan_reads(&root, &mut cache), (0, 0));

    let _ = std::fs::remove_dir_all(root);
}

/// [behaviour] Only new or changed Desktop session files are read again;
/// deleted files and files written too recently to compare are not kept.
#[test]
fn claude_desktop_metadata_cache_rereads_only_changed_files() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-desktop-cache-changed-{}",
        std::process::id()
    ));
    write_claude_desktop_pairs_fixture(&root);
    let uuid = |n: u32| format!("00000000-0000-4000-8000-{n:012}");
    let file = |account: u32, org: u32, name: &str| {
        let bucket = root.join("claude-code-sessions").join(uuid(account));
        bucket.join(uuid(org)).join(name)
    };
    let settled = 1_780_000_000;
    let malformed = file(2, 13, "local_m.json");
    write_desktop_file(&malformed, "{not json", settled);
    let mut cache = ClaudeDesktopMetadataCache::default();
    claude_desktop_cached_scan_reads(&root, &mut cache);

    // A changed size, then the same size with a later modification time.
    let current = r#"{"cliSessionId":"current-x","lastActivityAt":3000}"#;
    write_desktop_file(&file(1, 11, "local_a.json"), current, settled);
    assert_eq!(claude_desktop_cached_scan_reads(&root, &mut cache).0, 1);
    let other = r#"{"cliSessionId":"other-y","lastActivityAt":260}"#;
    write_desktop_file(&file(2, 12, "local_b.json"), other, settled + 60);
    assert_eq!(claude_desktop_cached_scan_reads(&root, &mut cache).0, 1);

    // A new file is read; a deleted one leaves the cache.
    let new_file = file(1, 11, "local_n.json");
    let new = r#"{"cliSessionId":"new","lastActivityAt":400}"#;
    write_desktop_file(&new_file, new, settled);
    std::fs::remove_file(file(3, 14, "local_d.json")).expect("delete imported");
    assert_eq!(claude_desktop_cached_scan_reads(&root, &mut cache).0, 1);
    assert!(cache.code.contains_key(&new_file));
    assert!(!cache.code.contains_key(&file(3, 14, "local_d.json")));

    // Malformed JSON stays unread until it changes.
    assert!(cache.code[&malformed].1.is_none());
    let repaired = r#"{"cliSessionId":"repaired","lastActivityAt":500}"#;
    write_desktop_file(&malformed, repaired, settled);
    assert_eq!(claude_desktop_cached_scan_reads(&root, &mut cache).0, 1);
    assert!(cache.code[&malformed].1.is_some());

    // A file modified "now" is read on every pass until it settles.
    write_desktop_file(&new_file, new, current_unix_seconds() + 3_600);
    assert_eq!(claude_desktop_cached_scan_reads(&root, &mut cache).0, 1);
    assert_eq!(claude_desktop_cached_scan_reads(&root, &mut cache).0, 1);
    assert!(!cache.code.contains_key(&new_file));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn claude_desktop_pairs_snapshot_sends_only_uncovered_pairs_within_upload_limits() {
    let pair = |n: u32| {
        claude_desktop_pair_observation(
            &(
                format!("00000000-0000-4000-8000-{n:012}"),
                format!("00000000-0000-4000-9000-{n:012}"),
            ),
            &ClaudeDesktopPairBuilder::default(),
            1_786_000_000 - i64::from(n),
            format!("session-{n}"),
        )
        .expect("pair")
    };
    let mut duplicate = pair(0);
    duplicate.observation.source_session_id = Some("duplicate-0".to_string());
    let desktop = ClaudeDesktopPairs {
        pairs: (0..22).map(pair).collect(),
        duplicate_sessions: vec![duplicate],
    };
    let at = "2026-08-12T08:00:00Z";
    let until = "2026-08-12T08:15:00Z";

    // Desktop only: newest 20 pairs fill the backend's observation limit.
    let mut uploads = Vec::new();
    append_claude_desktop_pairs_snapshot(&mut uploads, &desktop, at, until);
    assert_eq!(uploads.len(), 1);
    let only = &uploads[0];
    assert_eq!(only.source, SourceKind::ClaudeCode);
    assert!(
        only.account.is_none(),
        "a Desktop pair never becomes the root account"
    );
    assert_eq!(only.quota_windows, vec![unsupported_quota_window("usage")]);
    assert_eq!(
        only.plan_observations.len(),
        CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX
    );
    assert_eq!(
        only.plan_observations[0].source_session_id.as_deref(),
        Some("session-0")
    );
    let codes = |snapshot: &AgentStatusSnapshot| {
        snapshot
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect::<Vec<_>>()
    };
    assert!(codes(only).contains(&"claude_desktop_only_no_cli_login".to_string()));
    assert!(codes(only).contains(&"claude_desktop_pairs_truncated".to_string()));

    // Beside an uploaded login: the pairs it carries (root binding or an
    // exact plan observation) are subtracted, nothing else, and the login
    // snapshot is left exactly as it was.
    let mut metered = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        at.to_string(),
        until.to_string(),
    );
    let mut account = unsupported_account("anthropic");
    account.account_identifier_hash =
        Some(desktop.pairs[0].binding.account_identifier_hash.clone());
    account.organization_identifier_hash = Some(
        desktop.pairs[0]
            .binding
            .organization_identifier_hash
            .clone(),
    );
    metered.account = Some(account);
    metered.plan_observations = vec![desktop.pairs[1].observation.clone()];
    let mut uploads = vec![metered.clone()];
    append_claude_desktop_pairs_snapshot(&mut uploads, &desktop, at, until);
    assert_eq!(uploads.len(), 2);
    assert_eq!(uploads[0], metered);
    let mixed = &uploads[1];
    assert_eq!(
        mixed.plan_observations.len(),
        CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX
    );
    assert_eq!(
        mixed.plan_observations[0].source_session_id.as_deref(),
        Some("session-2")
    );
    assert!(!mixed
        .plan_observations
        .iter()
        .any(|observation| observation.source_session_id.as_deref() == Some("duplicate-0")));
    assert!(codes(mixed).contains(&"claude_desktop_uncovered_pairs".to_string()));

    // A full upload batch is never pushed past the backend's limit.
    let mut full = vec![metered; AGENT_STATUS_UPLOAD_SNAPSHOT_MAX];
    append_claude_desktop_pairs_snapshot(&mut full, &desktop, at, until);
    assert_eq!(full.len(), AGENT_STATUS_UPLOAD_SNAPSHOT_MAX);

    // Every pair covered: no Desktop status at all.
    let mut covered = vec![uploads[1].clone()];
    let covered_desktop = ClaudeDesktopPairs {
        pairs: desktop.pairs[2..22].to_vec(),
        duplicate_sessions: Vec::new(),
    };
    append_claude_desktop_pairs_snapshot(&mut covered, &covered_desktop, at, until);
    assert_eq!(covered.len(), 1);
}

#[test]
fn claude_desktop_duplicate_session_owner_fails_closed_on_tie() {
    let builders = vec![
        ClaudeDesktopProfileBuilder {
            account_uuid: "first-account".to_string(),
            session_activity_by_id: BTreeMap::from([(
                "ambiguous-session".to_string(),
                Some(1_700_000_000),
            )]),
            ..ClaudeDesktopProfileBuilder::default()
        },
        ClaudeDesktopProfileBuilder {
            account_uuid: "second-account".to_string(),
            session_activity_by_id: BTreeMap::from([(
                "ambiguous-session".to_string(),
                Some(1_700_000_000),
            )]),
            ..ClaudeDesktopProfileBuilder::default()
        },
    ];

    assert_eq!(
        claude_desktop_unambiguous_duplicate_session_owners(&builders).get("ambiguous-session"),
        Some(&None)
    );
}

#[test]
fn claude_oauth_token_parser_extracts_access_and_refresh_presence_only() {
    let payload = r#"{
          "claudeAiOauth": {
            "accessToken": " access-token ",
            "refreshToken": "refresh-token",
            "expiresAt": 1782750000000
          }
        }"#;

    assert_eq!(
        parse_claude_oauth_access_token(payload).as_deref(),
        Some("access-token")
    );
    assert!(
        parse_claude_oauth_credential(payload)
            .expect("credential")
            .has_refresh_token
    );

    let signed_out = r#"{
          "claudeAiOauth": {
            "accessToken": "",
            "refreshToken": "   ",
            "expiresAt": 0,
            "refreshTokenExpiresAt": 1782750000000
          }
        }"#;
    let credential = parse_claude_oauth_credential(signed_out).expect("signed-out shape");
    assert!(credential.access_token.is_none());
    assert!(!credential.has_refresh_token);
    assert_eq!(
        credential.access_expires_at.as_deref(),
        Some("1970-01-01T00:00:00Z")
    );
    assert!(credential.relogin_required_at.is_some());
}

#[test]
fn claude_oauth_keychain_lookup_pins_current_account_and_exact_slot_service() {
    assert_eq!(
        claude_oauth_keychain_lookup_arguments(&ClaudeConfigDirSlot::Default, "local-user")
            .expect("default lookup"),
        vec![
            "find-generic-password",
            "-a",
            "local-user",
            "-s",
            "Claude Code-credentials",
            "-w",
        ]
    );
    assert_eq!(
        claude_oauth_keychain_lookup_arguments(
            &ClaudeConfigDirSlot::registered("/tmp/claude-account").expect("slot"),
            "local-user",
        )
        .expect("custom lookup"),
        vec![
            "find-generic-password",
            "-a",
            "local-user",
            "-s",
            "Claude Code-credentials-ae4ef741",
            "-w",
        ]
    );
    assert!(claude_oauth_keychain_lookup_arguments(&ClaudeConfigDirSlot::Default, "").is_none());
}

#[test]
#[serial]
#[cfg(unix)]
fn claude_oauth_keychain_account_comes_from_effective_uid_not_user_environment() {
    let _guard = EnvVarGuard::set_os(
        "USER",
        OsString::from("ottto-environment-account-must-not-win"),
    );
    let account = effective_user_account_name().expect("effective uid account");
    assert_ne!(account, "ottto-environment-account-must-not-win");
    assert!(!account.is_empty());
}

#[test]
fn claude_desktop_multi_org_account_without_current_org_omits_organization() {
    // A non-current account with session buckets under several orgs must
    // not have one picked for it: pairing an account hash with an
    // arbitrary org hash minted a chimera billing identity in production
    // (personal account + employer org). Fail closed: no org at all.
    let observation = claude_desktop_builder_plan_observation(
        ClaudeDesktopProfileBuilder {
            account_uuid: "account-multi".to_string(),
            organization_uuids: BTreeSet::from([
                "employer-org".to_string(),
                "personal-org".to_string(),
            ]),
            code_session_count: 2,
            ..Default::default()
        },
        "2026-07-28T10:00:00Z",
        Some("some-other-account"),
    )
    .expect("multi-org Desktop observation");

    assert_eq!(observation.organization_id, None);
    assert_eq!(observation.organization_identifier_hash, None);
    assert_eq!(
        observation.account_identifier_hash,
        billing_identity_hash("anthropic", "account", "account-multi")
    );
    assert_eq!(
        observation.billing_identity_evidence.as_deref(),
        Some("provider_account_id")
    );
    assert_eq!(observation.is_current, Some(false));
}

#[test]
fn claude_desktop_current_org_wins_over_multi_org_ambiguity() {
    let observation = claude_desktop_builder_plan_observation(
        ClaudeDesktopProfileBuilder {
            account_uuid: "account-current".to_string(),
            organization_uuids: BTreeSet::from([
                "employer-org".to_string(),
                "personal-org".to_string(),
            ]),
            current_organization_uuid: Some("employer-org".to_string()),
            code_session_count: 2,
            ..Default::default()
        },
        "2026-07-28T10:00:00Z",
        Some("account-current"),
    )
    .expect("current multi-org Desktop observation");

    assert_eq!(observation.organization_id.as_deref(), Some("employer-org"));
    assert_eq!(
        observation.organization_identifier_hash,
        billing_identity_hash("anthropic", "organization", "employer-org")
    );
    assert_eq!(observation.is_current, Some(true));
}

#[test]
fn claude_oauth_usage_maps_five_hour_and_weekly_windows() {
    let json = serde_json::json!({
        "five_hour": {
            "utilization": 24.0,
            "resets_at": "2026-06-29T18:10:00.937562+00:00"
        },
        "seven_day": {
            "utilization": 72.0,
            "resets_at": "2026-07-04T05:00:00.937587+00:00"
        },
        "seven_day_sonnet": {
            "utilization": 7.0,
            "resets_at": "2026-07-04T05:00:00.937594+00:00"
        }
    });

    let windows = claude_oauth_quota_windows(&json);

    assert_eq!(windows.len(), 2);
    assert_eq!(windows[0].name, "session");
    assert_eq!(windows[0].scope, AgentQuotaWindowScope::Account);
    assert_eq!(windows[0].status, AgentQuotaWindowStatus::Ok);
    assert_eq!(windows[0].freshness, AgentQuotaWindowFreshness::Fresh);
    assert_eq!(windows[0].used_percent, Some(24));
    assert_eq!(windows[0].left_percent, Some(76));
    assert_eq!(windows[0].window_seconds, Some(5 * 60 * 60));
    assert_eq!(
        windows[0].resets_at.as_deref(),
        Some("2026-06-29T18:10:00.937562Z")
    );
    assert_eq!(windows[1].name, "weekly");
    assert_eq!(windows[1].status, AgentQuotaWindowStatus::Ok);
    assert_eq!(windows[1].used_percent, Some(72));
    assert_eq!(windows[1].left_percent, Some(28));
    assert_eq!(windows[1].window_seconds, Some(7 * 24 * 60 * 60));
    assert_eq!(
        windows[1].resets_at.as_deref(),
        Some("2026-07-04T05:00:00.937587Z")
    );
}

#[test]
fn claude_oauth_usage_cache_covers_collection_gap_then_marks_old_windows_stale() {
    let cache = ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: "account-a".to_string(),
        organization_identifier_hash: "organization-a".to_string(),
        observed_at_epoch_seconds: 100,
        next_refresh_after_epoch_seconds: 400,
        windows: vec![AgentQuotaWindow {
            name: "weekly".to_string(),
            scope: AgentQuotaWindowScope::Account,
            status: AgentQuotaWindowStatus::Ok,
            freshness: AgentQuotaWindowFreshness::Fresh,
            window_seconds: Some(7 * 24 * 60 * 60),
            resets_at: Some("2026-07-04T05:00:00Z".to_string()),
            used_percent: Some(72),
            left_percent: Some(28),
            ..Default::default()
        }],
        credit_balances: vec![AgentCreditBalance {
            name: "Usage credits".to_string(),
            status: AgentCreditBalanceStatus::Ok,
            freshness: AgentQuotaWindowFreshness::Fresh,
            unit: AgentCreditBalanceUnit::Usd,
            used: CreditAmount::whole(321),
            quota: CreditAmount::whole(500),
            enabled: Some(true),
            ..Default::default()
        }],
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };

    let read_gate = claude_oauth_usage_fresh_age_seconds("account-a", "organization-a");
    // Idle accounts remain readable while the next scheduled collection
    // catches up. Cache and retained-slot presentation use the same bound.
    for age in [
        read_gate + 1,
        read_gate + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
    ] {
        let now = 100 + age;
        let usage = claude_oauth_usage_from_cache(cache.clone(), now);
        assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Fresh);
        assert_eq!(usage.windows[0].used_percent, Some(72));
        assert_eq!(
            usage.windows[0].observed_at.as_deref(),
            Some("1970-01-01T00:01:40Z")
        );
        assert_eq!(
            usage.credit_balances[0].freshness,
            AgentQuotaWindowFreshness::Fresh
        );
        let snapshot = local_claude_quota_snapshot(
            "1970-01-01T00:01:40Z",
            &usage.windows,
            &usage.credit_balances,
            true,
            true,
        );
        assert!(local_claude_quota_snapshot_is_fresh_for_account(
            &snapshot,
            "account-a",
            "organization-a",
            OffsetDateTime::from_unix_timestamp(now as i64).unwrap(),
        ));
        // Display tolerance never defers the collection that is due.
        assert!(claude_credit_pools::claude_reading_due(
            Some(100),
            400,
            read_gate,
            now,
        ));
    }

    // Past the account's display deadline, including the collection gap.
    let usage = claude_oauth_usage_from_cache(
        cache,
        100 + claude_oauth_usage_serve_gate_seconds("account-a", "organization-a", 100) + 1,
    );

    assert_eq!(usage.windows.len(), 1);
    assert_eq!(usage.windows[0].status, AgentQuotaWindowStatus::Unknown);
    assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Stale);
    assert_eq!(usage.windows[0].used_percent, Some(72));
    assert_eq!(
        usage.credit_balances[0].freshness,
        AgentQuotaWindowFreshness::Stale
    );
}

#[test]
fn claude_oauth_usage_cache_discards_v2_schema() {
    // Version-2 caches predate `account_identifier_hash`: their numbers
    // cannot be attributed to any account, so they must be discarded on
    // upgrade rather than adopted by whoever is logged in now.
    let v2 = serde_json::json!({
        "schema_version": 2,
        "observed_at_epoch_seconds": 100,
        "next_refresh_after_epoch_seconds": 400,
        "windows": [],
        "credit_balances": []
    });
    let cache: ClaudeOAuthUsageCache = serde_json::from_value(v2).unwrap();
    assert!(cache.account_identifier_hash.is_empty());
    assert_ne!(
        cache.schema_version,
        CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION
    );
}

#[test]
fn claude_oauth_account_identifier_hash_prefers_account_uuid() {
    let account_a = ClaudeCliOauthAccount {
        account_uuid: Some("acct-a".to_string()),
        email_address: Some("a@example.test".to_string()),
        organization_uuid: Some("org-shared".to_string()),
        ..ClaudeCliOauthAccount::default()
    };
    let account_b = ClaudeCliOauthAccount {
        account_uuid: Some("acct-b".to_string()),
        email_address: Some("b@example.test".to_string()),
        organization_uuid: Some("org-shared".to_string()),
        ..ClaudeCliOauthAccount::default()
    };

    let hash_a = claude_oauth_account_identifier_hash_for(&account_a);
    let hash_b = claude_oauth_account_identifier_hash_for(&account_b);

    assert_eq!(
        hash_a,
        billing_identity_hash("anthropic", "account", "acct-a").expect("account hash")
    );
    // Two accounts inside one organization must still separate.
    assert_ne!(hash_a, hash_b);

    // Falls back to organization, then email, then gives up.
    let org_only = ClaudeCliOauthAccount {
        organization_uuid: Some("org-shared".to_string()),
        ..ClaudeCliOauthAccount::default()
    };
    assert_eq!(
        claude_oauth_account_identifier_hash_for(&org_only),
        billing_identity_hash("anthropic", "organization", "org-shared")
            .expect("organization hash")
    );
    let email_only = ClaudeCliOauthAccount {
        email_address: Some("a@example.test".to_string()),
        ..ClaudeCliOauthAccount::default()
    };
    assert_eq!(
        claude_oauth_account_identifier_hash_for(&email_only),
        billing_identity_hash("anthropic", "email", "a@example.test").expect("email hash")
    );
    assert!(claude_oauth_account_identifier_hash_for(&ClaudeCliOauthAccount::default()).is_empty());
}

#[test]
#[serial]
fn claude_oauth_usage_cache_is_not_served_across_accounts() {
    // Regression, observed live 2026-07-26 on Ottto 0.1.96: the Claude Code
    // CLI credential store was historically single-slot, so `/login` as a
    // second account replaced the first while the machine-global cache kept
    // the first account's numbers. Account A's weekly window rendered under account
    // B's Team subscription, complete with A's reset boundary.
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-usage-cache-account-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&support_dir);
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );

    let account_a = claude_oauth_account_identifier_hash_for(&ClaudeCliOauthAccount {
        account_uuid: Some("acct-a".to_string()),
        ..ClaudeCliOauthAccount::default()
    });
    let account_b = claude_oauth_account_identifier_hash_for(&ClaudeCliOauthAccount {
        account_uuid: Some("acct-b".to_string()),
        ..ClaudeCliOauthAccount::default()
    });
    let organization_a = "organization-a";
    let organization_b = "organization-b";
    assert_ne!(account_a, account_b);

    let now = 10_000;
    write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account_a.clone(),
        organization_identifier_hash: organization_a.to_string(),
        observed_at_epoch_seconds: now,
        next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
        windows: vec![AgentQuotaWindow {
            name: "weekly".to_string(),
            scope: AgentQuotaWindowScope::Account,
            status: AgentQuotaWindowStatus::Ok,
            freshness: AgentQuotaWindowFreshness::Fresh,
            window_seconds: Some(7 * 24 * 60 * 60),
            // Account A's reset boundary -- the tell that made the live
            // misattribution unambiguous.
            resets_at: Some("2026-08-01T05:00:00Z".to_string()),
            used_percent: Some(44),
            left_percent: Some(56),
            account_identifier_hash: Some(account_a.clone()),
            organization_identifier_hash: Some(organization_a.to_string()),
            ..Default::default()
        }],
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    })
    .expect("write cache");

    // The account that wrote it still reads it.
    let served =
        read_claude_oauth_usage_cache(&account_a, organization_a).expect("own account is served");
    assert_eq!(served.windows[0].used_percent, Some(44));
    assert!(claude_oauth_usage_cache_path(&account_a, organization_a).is_file());
    assert!(
        read_claude_oauth_usage_cache(&account_a, organization_b).is_none(),
        "an account-only match must not relabel cached meters under another organization"
    );

    // The replacing account must not.
    assert!(
        read_claude_oauth_usage_cache(&account_b, organization_b).is_none(),
        "cache written under account A was served to account B"
    );
    // Nor may an unidentifiable credential inherit a named account's cache.
    assert!(read_claude_oauth_usage_cache("", "").is_none());

    // Same guard on the 429 / transport fallback path, where the 24h max
    // age applies and serving another account's numbers is worse than
    // serving none. This mirrors the `unwrap_or` in
    // `collect_claude_oauth_usage`'s 429 arm.
    let retry_after = now + CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS;
    let fallback = read_claude_oauth_usage_cache(&account_b, organization_b).unwrap_or(
        ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account_b.clone(),
            organization_identifier_hash: organization_b.to_string(),
            observed_at_epoch_seconds: now,
            next_refresh_after_epoch_seconds: retry_after,
            windows: Vec::new(),
            credit_balances: Vec::new(),
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        },
    );
    assert!(
        fallback.windows.is_empty(),
        "429 fallback served account A's windows to account B"
    );
    assert_eq!(fallback.account_identifier_hash, account_b);
    // Writing B's fallback now creates B's physical account store without
    // replacing A's. Future multi-slot collection can therefore maintain
    // both accounts independently.
    write_claude_oauth_usage_cache(&fallback).expect("write fallback cache");
    assert!(read_claude_oauth_usage_cache(&account_a, organization_a).is_some());
    assert!(claude_oauth_usage_cache_path(&account_b, organization_b).is_file());
    assert_ne!(
        claude_oauth_usage_cache_path(&account_a, organization_a),
        claude_oauth_usage_cache_path(&account_b, organization_b)
    );

    let _ = std::fs::remove_dir_all(&support_dir);
}

#[test]
#[serial]
fn same_account_two_organizations_have_independent_state_and_admission() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-composite-state-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let account = "same-account";
    let organization_a = "organization-a";
    let organization_b = "organization-b";
    assert_ne!(
        claude_oauth_usage_cache_path(account, organization_a),
        claude_oauth_usage_cache_path(account, organization_b)
    );
    let held = try_claude_oauth_collection_attempt(account, organization_a)
        .expect("organization A admission");
    assert!(
        try_claude_oauth_collection_attempt(account, organization_a).is_none(),
        "same composite binding must coalesce"
    );
    let other = try_claude_oauth_collection_attempt(account, organization_b)
        .expect("organization B remains independent");
    drop(other);
    drop(held);

    let fingerprint = "composite-fingerprint";
    record_claude_oauth_usage_failure(
        ClaudeOAuthUsageFailure::AuthRejected,
        account,
        organization_a,
        fingerprint,
        1_000,
    );
    assert!(read_claude_oauth_usage_breaker(account, organization_a, fingerprint).is_some());
    assert!(read_claude_oauth_usage_breaker(account, organization_b, fingerprint).is_none());
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn missing_token_serves_exact_two_hour_cache_stale_past_open_breaker() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-no-token-stale-cache-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let _network_guard =
        EnvVarGuard::set_os("OTTTO_DISABLE_CLAUDE_OAUTH_USAGE", OsString::from("0"));
    let account = "account-stale";
    let organization = "organization-stale";
    let now = current_unix_seconds();
    let observed_at = now.saturating_sub(2 * 60 * 60);
    write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account.to_string(),
        organization_identifier_hash: organization.to_string(),
        observed_at_epoch_seconds: observed_at,
        next_refresh_after_epoch_seconds: observed_at + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
        windows: vec![AgentQuotaWindow {
            name: "session".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            account_identifier_hash: Some(account.to_string()),
            organization_identifier_hash: Some(organization.to_string()),
            ..Default::default()
        }],
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    })
    .expect("write exact stale cache");
    let fingerprint = claude_oauth_usage_config_fingerprint();
    for _ in 0..ClaudeOAuthUsageFailure::AuthRejected.threshold() {
        record_claude_oauth_usage_failure(
            ClaudeOAuthUsageFailure::AuthRejected,
            account,
            organization,
            &fingerprint,
            now,
        );
    }
    assert!(
        read_claude_oauth_usage_breaker(account, organization, &fingerprint)
            .is_some_and(|breaker| claude_oauth_usage_breaker_is_open(&breaker, now))
    );
    let calls_before = CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst);

    let outcome = collect_claude_oauth_usage_with_access_token(
        account,
        organization,
        None,
        &ClaudeOAuthUsageCaller::RegisteredSlot("slot-test".to_string()),
    );

    let usage = outcome.result.expect("serve exact stale cache");
    assert_eq!(usage.windows.len(), 1);
    assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Stale);
    assert!(outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_oauth_usage_circuit_open"));
    assert_eq!(
        CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        calls_before,
        "a missing token must never admit a provider call"
    );
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
fn claude_oauth_usage_cache_identity_match_is_exact_both_ways() {
    let cache = |account_hash: &str, organization_hash: &str| ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account_hash.to_string(),
        organization_identifier_hash: organization_hash.to_string(),
        observed_at_epoch_seconds: 0,
        next_refresh_after_epoch_seconds: 0,
        windows: Vec::new(),
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };

    assert!(claude_oauth_usage_cache_belongs_to_identity(
        &cache("account-a", "organization-a"),
        "account-a",
        "organization-a",
    ));
    assert!(!claude_oauth_usage_cache_belongs_to_identity(
        &cache("account-a", "organization-a"),
        "account-b",
        "organization-a",
    ));
    assert!(!claude_oauth_usage_cache_belongs_to_identity(
        &cache("account-a", "organization-a"),
        "account-a",
        "organization-b",
    ));
    assert!(!claude_oauth_usage_cache_belongs_to_identity(
        &cache("account-a", "organization-a"),
        "",
        "",
    ));
    assert!(!claude_oauth_usage_cache_belongs_to_identity(
        &cache("", ""),
        "",
        "",
    ));
}

#[test]
#[serial]
fn legacy_usage_cache_migrates_into_its_physical_account_store() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-cache-migration-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let cache = ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION,
        account_identifier_hash: "account-a".to_string(),
        organization_identifier_hash: "organization-a".to_string(),
        observed_at_epoch_seconds: 100,
        next_refresh_after_epoch_seconds: 200,
        windows: vec![AgentQuotaWindow {
            name: "session".to_string(),
            account_identifier_hash: Some("account-a".to_string()),
            organization_identifier_hash: Some("organization-a".to_string()),
            ..Default::default()
        }],
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };
    fs::write(
        claude_oauth_usage_legacy_cache_path(),
        serde_json::to_vec_pretty(&cache).expect("serialize legacy cache"),
    )
    .expect("write legacy cache");

    assert!(read_claude_oauth_usage_cache("account-b", "organization-b").is_none());
    assert!(claude_oauth_usage_legacy_cache_path().is_file());
    assert_eq!(
        read_claude_oauth_usage_cache("account-a", "organization-a")
            .expect("migrated cache")
            .account_identifier_hash,
        "account-a"
    );
    assert!(claude_oauth_usage_cache_path("account-a", "organization-a").is_file());
    assert!(!claude_oauth_usage_legacy_cache_path().exists());
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn default_account_state_is_mirrored_for_downgrade_without_custom_account_leakage() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-downgrade-mirror-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let default_cache = ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: "account-default".to_string(),
        organization_identifier_hash: "organization-default".to_string(),
        observed_at_epoch_seconds: 100,
        next_refresh_after_epoch_seconds: u64::MAX,
        windows: vec![AgentQuotaWindow {
            name: "session".to_string(),
            used_percent: Some(20),
            account_identifier_hash: Some("account-default".to_string()),
            organization_identifier_hash: Some("organization-default".to_string()),
            ..Default::default()
        }],
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };
    let custom_cache = ClaudeOAuthUsageCache {
        account_identifier_hash: "account-custom".to_string(),
        organization_identifier_hash: "organization-custom".to_string(),
        windows: vec![AgentQuotaWindow {
            name: "session".to_string(),
            used_percent: Some(80),
            account_identifier_hash: Some("account-custom".to_string()),
            organization_identifier_hash: Some("organization-custom".to_string()),
            ..Default::default()
        }],
        ..default_cache.clone()
    };
    write_claude_oauth_usage_cache(&default_cache).expect("write default account cache");
    write_legacy_claude_oauth_usage_cache(&default_cache).expect("mirror legacy cache");
    assert!(read_claude_oauth_usage_cache_with_legacy_migration(
        "account-custom",
        "organization-custom",
        false,
    )
    .is_none());
    assert!(
        claude_oauth_usage_legacy_cache_path().is_file(),
        "a custom-first read must not consume the default downgrade cache"
    );
    write_claude_oauth_usage_cache(&custom_cache).expect("write custom account cache");

    let legacy_cache: ClaudeOAuthUsageCache = serde_json::from_str(
        &fs::read_to_string(claude_oauth_usage_legacy_cache_path()).expect("read legacy cache"),
    )
    .expect("parse legacy cache");
    assert_eq!(legacy_cache.account_identifier_hash, "account-default");
    assert_eq!(
        legacy_cache.schema_version,
        CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION
    );
    assert_eq!(legacy_cache.windows[0].used_percent, Some(20));
    assert_eq!(
        read_claude_oauth_usage_cache("account-custom", "organization-custom")
            .expect("read custom cache")
            .windows[0]
            .used_percent,
        Some(80)
    );

    let fingerprint = "fingerprint-default";
    record_claude_oauth_usage_failure_with_legacy(
        ClaudeOAuthUsageFailure::AuthRejected,
        "account-default",
        "organization-default",
        fingerprint,
        1_000,
        true,
    );
    assert!(read_claude_oauth_usage_breaker_with_legacy_migration(
        "account-custom",
        "organization-custom",
        "fingerprint-custom",
        false,
    )
    .is_none());
    assert!(
        claude_oauth_usage_legacy_breaker_path().is_file(),
        "a custom-first read must not consume the default downgrade breaker"
    );
    record_claude_oauth_usage_failure_with_legacy(
        ClaudeOAuthUsageFailure::ResponseShape,
        "account-custom",
        "organization-custom",
        "fingerprint-custom",
        1_000,
        false,
    );
    let legacy_breaker: ClaudeOAuthUsageBreaker = serde_json::from_str(
        &fs::read_to_string(claude_oauth_usage_legacy_breaker_path()).expect("read legacy breaker"),
    )
    .expect("parse legacy breaker");
    assert_eq!(legacy_breaker.account_identifier_hash, "account-default");
    assert_eq!(legacy_breaker.config_fingerprint, fingerprint);
    assert_eq!(legacy_breaker.auth_failures, 1);
    assert_eq!(legacy_breaker.shape_failures, 0);
    assert_eq!(
        read_claude_oauth_usage_breaker(
            "account-custom",
            "organization-custom",
            "fingerprint-custom"
        )
        .expect("read custom breaker")
        .shape_failures,
        1
    );

    clear_claude_oauth_usage_breaker_with_legacy("account-default", "organization-default", true);
    assert!(!claude_oauth_usage_legacy_breaker_path().exists());
    assert!(read_claude_oauth_usage_breaker(
        "account-default",
        "organization-default",
        fingerprint
    )
    .is_none());
    assert!(read_claude_oauth_usage_breaker(
        "account-custom",
        "organization-custom",
        "fingerprint-custom"
    )
    .is_some());
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn concurrent_legacy_cache_migration_is_single_copy_and_owner_only() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-cache-concurrent-migration-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let cache = ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION,
        account_identifier_hash: "account-concurrent".to_string(),
        organization_identifier_hash: "organization-concurrent".to_string(),
        observed_at_epoch_seconds: 100,
        next_refresh_after_epoch_seconds: 200,
        windows: vec![AgentQuotaWindow {
            name: "session".to_string(),
            account_identifier_hash: Some("account-concurrent".to_string()),
            organization_identifier_hash: Some("organization-concurrent".to_string()),
            ..Default::default()
        }],
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };
    fs::write(
        claude_oauth_usage_legacy_cache_path(),
        serde_json::to_vec_pretty(&cache).expect("serialize legacy cache"),
    )
    .expect("write legacy cache");

    let workers: Vec<_> = (0..12)
        .map(|_| {
            std::thread::spawn(|| {
                read_claude_oauth_usage_cache("account-concurrent", "organization-concurrent")
                    .expect("migrated cache")
                    .account_identifier_hash
            })
        })
        .collect();
    for worker in workers {
        assert_eq!(worker.join().expect("worker"), "account-concurrent");
    }
    let target = claude_oauth_usage_cache_path("account-concurrent", "organization-concurrent");
    assert!(target.is_file());
    assert!(!claude_oauth_usage_legacy_cache_path().exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&target)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn cache_and_breaker_writes_are_atomic_owner_only_and_symlink_safe() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-state-atomic-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let account = "account-atomic";
    let cache = ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account.to_string(),
        organization_identifier_hash: "organization-atomic".to_string(),
        observed_at_epoch_seconds: 100,
        next_refresh_after_epoch_seconds: 200,
        windows: Vec::new(),
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let cache_path = claude_oauth_usage_cache_path(account, "organization-atomic");
        fs::create_dir_all(cache_path.parent().expect("cache parent"))
            .expect("create cache parent");
        let sentinel = support_dir.join("sentinel.json");
        fs::write(&sentinel, b"untouched").expect("write sentinel");
        symlink(&sentinel, &cache_path).expect("plant cache symlink");

        write_claude_oauth_usage_cache(&cache).expect("atomic cache write");
        assert_eq!(fs::read(&sentinel).expect("read sentinel"), b"untouched");
        assert!(!fs::symlink_metadata(&cache_path)
            .expect("cache metadata")
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::metadata(&cache_path)
                .expect("cache metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[cfg(not(unix))]
    write_claude_oauth_usage_cache(&cache).expect("atomic cache write");

    record_claude_oauth_usage_failure(
        ClaudeOAuthUsageFailure::AuthRejected,
        account,
        "organization-atomic",
        "fingerprint-atomic",
        100,
    );
    let breaker_path = claude_oauth_usage_breaker_path(account, "organization-atomic");
    let _: ClaudeOAuthUsageBreaker =
        serde_json::from_slice(&fs::read(&breaker_path).expect("read complete breaker JSON"))
            .expect("parse complete breaker JSON");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&breaker_path)
                .expect("breaker metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    for entry in fs::read_dir(
        claude_oauth_usage_cache_path(account, "organization-atomic")
            .parent()
            .expect("account state dir"),
    )
    .expect("read account state dir")
    {
        let name = entry
            .expect("state entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        assert!(!name.contains(".tmp."), "orphaned atomic temp file: {name}");
    }
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn concurrent_cache_writes_leave_one_complete_account_document() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-cache-concurrent-write-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    const WORKERS: u64 = 20;
    let workers: Vec<_> = (0..WORKERS)
        .map(|observed_at_epoch_seconds| {
            std::thread::spawn(move || {
                write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
                    schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                    account_identifier_hash: "account-concurrent-cache".to_string(),
                    organization_identifier_hash: "organization-concurrent-cache".to_string(),
                    observed_at_epoch_seconds,
                    next_refresh_after_epoch_seconds: observed_at_epoch_seconds + 100,
                    windows: Vec::new(),
                    credit_balances: Vec::new(),
                    account_weekly_not_offered: false,
                    account_session_not_offered: false,
                })
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker").expect("cache write");
    }
    let cache =
        read_claude_oauth_usage_cache("account-concurrent-cache", "organization-concurrent-cache")
            .expect("complete cache after concurrent writes");
    assert!(cache.observed_at_epoch_seconds < WORKERS);
    assert_eq!(
        cache.next_refresh_after_epoch_seconds,
        cache.observed_at_epoch_seconds + 100
    );
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
fn claude_oauth_usage_breaker_opens_on_each_trigger_class() {
    for (failure, threshold, code) in [
        (
            ClaudeOAuthUsageFailure::AuthRejected,
            CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD,
            "auth_rejected",
        ),
        (
            ClaudeOAuthUsageFailure::ResponseShape,
            CLAUDE_OAUTH_USAGE_BREAKER_SHAPE_THRESHOLD,
            "response_shape_changed",
        ),
        (
            ClaudeOAuthUsageFailure::RateLimited,
            CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD,
            "rate_limited",
        ),
    ] {
        let mut breaker = None;
        for attempt in 1..=threshold {
            breaker = Some(claude_oauth_usage_breaker_after_failure(
                breaker,
                failure,
                "account-a",
                "organization-a",
                "fingerprint-a",
                1_000,
            ));
            let current = breaker.as_ref().expect("breaker");
            let open = claude_oauth_usage_breaker_is_open(current, 1_000);
            assert_eq!(
                open,
                attempt >= threshold,
                "{code} opened at attempt {attempt} of {threshold}"
            );
        }
        let opened = breaker.expect("breaker");
        assert_eq!(opened.opened_by, code);
        assert_eq!(opened.opened_at_epoch_seconds, 1_000);
        assert_eq!(
            opened.reopen_after_epoch_seconds,
            1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS
        );
    }
}

#[test]
#[serial]
fn claude_oauth_usage_breaker_state_is_scoped_and_resettable() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-breaker-state-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&support_dir);
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );

    assert!(
        read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-a").is_none()
    );
    for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
        record_claude_oauth_usage_failure(
            ClaudeOAuthUsageFailure::AuthRejected,
            "account-a",
            "organization-a",
            "fingerprint-a",
            1_000,
        );
    }
    let stored = read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-a")
        .expect("stored breaker");
    assert!(claude_oauth_usage_breaker_is_open(&stored, 1_000));
    // Account-keyed and config-keyed, exactly like the usage cache: a
    // different account or a changed call configuration starts clean.
    assert!(
        read_claude_oauth_usage_breaker("account-b", "organization-b", "fingerprint-a").is_none()
    );
    assert!(
        read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-b").is_none()
    );

    clear_claude_oauth_usage_breaker("account-a", "organization-a");
    assert!(
        read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-a").is_none()
    );

    let _ = std::fs::remove_dir_all(&support_dir);
}

#[test]
#[serial]
fn concurrent_breaker_failures_are_one_account_transaction_without_lost_updates() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-breaker-concurrent-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    const WORKERS: usize = 24;
    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            std::thread::spawn(|| {
                record_claude_oauth_usage_failure(
                    ClaudeOAuthUsageFailure::AuthRejected,
                    "account-concurrent-breaker",
                    "organization-concurrent-breaker",
                    "fingerprint-concurrent-breaker",
                    1_000,
                )
            })
        })
        .collect();
    let emitted = workers
        .into_iter()
        .flat_map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    let breaker = read_claude_oauth_usage_breaker(
        "account-concurrent-breaker",
        "organization-concurrent-breaker",
        "fingerprint-concurrent-breaker",
    )
    .expect("concurrent breaker");
    assert_eq!(breaker.auth_failures, WORKERS as u32);
    assert_eq!(emitted.len(), 1, "open transition should emit exactly once");
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn legacy_breaker_migrates_into_its_physical_account_store() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-breaker-migration-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let breaker = ClaudeOAuthUsageBreaker {
        schema_version: CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
        account_identifier_hash: "account-a".to_string(),
        organization_identifier_hash: "organization-a".to_string(),
        config_fingerprint: "fingerprint-a".to_string(),
        auth_failures: 2,
        ..Default::default()
    };
    fs::write(
        claude_oauth_usage_legacy_breaker_path(),
        serde_json::to_vec_pretty(&breaker).expect("serialize legacy breaker"),
    )
    .expect("write legacy breaker");

    assert!(
        read_claude_oauth_usage_breaker("account-b", "organization-b", "fingerprint-a").is_none()
    );
    assert!(claude_oauth_usage_legacy_breaker_path().is_file());
    assert_eq!(
        read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-a")
            .expect("migrated breaker")
            .auth_failures,
        2
    );
    assert!(claude_oauth_usage_breaker_path("account-a", "organization-a").is_file());
    assert!(!claude_oauth_usage_legacy_breaker_path().exists());
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn claude_oauth_usage_breaker_alerts_once_and_then_skips_the_network() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-breaker-alert-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&support_dir);
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    // Pin the account to "unidentifiable" (no `~/.claude.json` under this
    // HOME) so the state this test writes is the state
    // `collect_claude_oauth_usage` reads back, on any machine.
    let _home_guard = EnvVarGuard::set_os("HOME", support_dir.as_os_str().to_os_string());
    let account = claude_oauth_account_identifier_hash();
    let fingerprint = claude_oauth_usage_config_fingerprint();
    let now = current_unix_seconds();

    let mut emitted = Vec::new();
    for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD {
        emitted.extend(record_claude_oauth_usage_failure(
            ClaudeOAuthUsageFailure::RateLimited,
            &account,
            "organization-alert",
            &fingerprint,
            now,
        ));
    }
    assert_eq!(
        emitted.len(),
        1,
        "the breaker alerts on the transition, not on every failure"
    );
    assert_eq!(emitted[0].code, "claude_oauth_usage_circuit_open");
    assert_eq!(emitted[0].severity, AgentDiagnosticSeverity::Warning);
    assert!(emitted[0].message.contains("rate limited"));
    // Further failures while open must not re-alert.
    assert!(record_claude_oauth_usage_failure(
        ClaudeOAuthUsageFailure::RateLimited,
        &account,
        "organization-alert",
        &fingerprint,
        now + 100,
    )
    .is_empty());

    // While open, the collector never reaches the network: it returns the
    // breaker error plus the alert without a token read or a request.
    let outcome = collect_claude_oauth_usage_with_access_token(
        &account,
        "organization-alert",
        None,
        &ClaudeOAuthUsageCaller::RegisteredSlot("slot-test".to_string()),
    );
    assert!(outcome.result.is_err());
    assert!(outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_oauth_usage_circuit_open"));

    let _ = std::fs::remove_dir_all(&support_dir);
}

#[test]
fn claude_oauth_usage_transient_errors_do_not_count_toward_the_breaker() {
    assert_eq!(
        claude_oauth_usage_failure_class(&ureq::Error::Status(
            401,
            ureq::Response::new(401, "Unauthorized", "{}").expect("response")
        )),
        Some(ClaudeOAuthUsageFailure::AuthRejected)
    );
    assert_eq!(
        claude_oauth_usage_failure_class(&ureq::Error::Status(
            403,
            ureq::Response::new(403, "Forbidden", "{}").expect("response")
        )),
        Some(ClaudeOAuthUsageFailure::AuthRejected)
    );
    assert_eq!(
        claude_oauth_usage_failure_class(&ureq::Error::Status(
            404,
            ureq::Response::new(404, "Not Found", "{}").expect("response")
        )),
        Some(ClaudeOAuthUsageFailure::ResponseShape)
    );
    // A 5xx is the vendor having a bad day, not a signal to stop asking.
    assert_eq!(
        claude_oauth_usage_failure_class(&ureq::Error::Status(
            503,
            ureq::Response::new(503, "Unavailable", "{}").expect("response")
        )),
        None
    );
}

#[test]
#[serial]
fn claude_oauth_usage_sentinel_disables_the_network_read() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-off-switch-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&support_dir);
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );

    // Default (no sentinel) is enabled -- unchanged behaviour.
    assert!(!claude_oauth_usage_network_disabled());

    // A previously fetched payload remains local and keeps its original
    // observation time while the sentinel pauses all network reads.
    let account_hash = "off-switch-account";
    let organization_hash = "off-switch-organization";
    write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account_hash.to_string(),
        organization_identifier_hash: organization_hash.to_string(),
        observed_at_epoch_seconds: current_unix_seconds(),
        next_refresh_after_epoch_seconds: current_unix_seconds() + 60,
        windows: vec![AgentQuotaWindow {
            name: "session".to_string(),
            scope: AgentQuotaWindowScope::Account,
            status: AgentQuotaWindowStatus::Ok,
            freshness: AgentQuotaWindowFreshness::Fresh,
            used_percent: Some(25),
            account_identifier_hash: Some(account_hash.to_string()),
            organization_identifier_hash: Some(organization_hash.to_string()),
            ..Default::default()
        }],
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    })
    .expect("write cache fixture");

    // The exact filename is a contract with the macOS Companion toggle.
    std::fs::write(
        support_dir.join("claude-oauth-usage-network-disabled"),
        b"disabled\n",
    )
    .expect("write sentinel");
    assert!(claude_oauth_usage_network_disabled());
    let provider_calls_before =
        CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst);

    let outcome = collect_claude_oauth_usage_with_access_token(
        account_hash,
        organization_hash,
        None,
        &ClaudeOAuthUsageCaller::Default,
    );
    assert!(outcome.result.is_err());
    assert_eq!(outcome.diagnostics.len(), 1);
    assert_eq!(
        outcome.diagnostics[0].code,
        "claude_oauth_usage_network_disabled"
    );
    assert_eq!(
        outcome.diagnostics[0].severity,
        AgentDiagnosticSeverity::Info
    );
    assert!(claude_oauth_usage_cache_path(account_hash, organization_hash).exists());

    std::fs::remove_file(support_dir.join("claude-oauth-usage-network-disabled"))
        .expect("re-enable collection");
    let resumed = collect_claude_oauth_usage_with_access_token(
        account_hash,
        organization_hash,
        None,
        &ClaudeOAuthUsageCaller::Default,
    );
    assert!(
        resumed.result.is_ok(),
        "the retained fresh cache resumes without another prompt"
    );
    assert_eq!(
        CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        provider_calls_before,
        "the off-switch and cache-only resume must never admit a provider call"
    );

    let _ = std::fs::remove_dir_all(&support_dir);
}

#[test]
#[serial]
fn refreshed_credential_clears_only_the_auth_breaker() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-auth-breaker-clear-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&support_dir);
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let _home_guard = EnvVarGuard::set_os("HOME", support_dir.as_os_str().to_os_string());
    let account = claude_oauth_account_identifier_hash();
    let fingerprint = claude_oauth_usage_config_fingerprint();
    let now = current_unix_seconds();

    for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
        let _ = record_claude_oauth_usage_failure(
            ClaudeOAuthUsageFailure::AuthRejected,
            &account,
            "organization-auth",
            &fingerprint,
            now,
        );
    }
    let opened = read_claude_oauth_usage_breaker(&account, "organization-auth", &fingerprint)
        .expect("the auth breaker must be open, or this test proves nothing");
    assert!(claude_oauth_usage_breaker_is_open(&opened, now));

    clear_claude_oauth_usage_auth_breaker(&account, "organization-auth", "slot-test");
    assert!(
        read_claude_oauth_usage_breaker(&account, "organization-auth", &fingerprint).is_none(),
        "a replaced credential must retire the rejections the old one earned"
    );

    for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD {
        let _ = record_claude_oauth_usage_failure(
            ClaudeOAuthUsageFailure::RateLimited,
            &account,
            "organization-rate",
            &fingerprint,
            now,
        );
    }
    clear_claude_oauth_usage_auth_breaker(&account, "organization-rate", "slot-test");
    let rate_limited = read_claude_oauth_usage_breaker(&account, "organization-rate", &fingerprint)
        .expect("a sustained 429 is about the endpoint and keeps its cool-down");
    assert!(claude_oauth_usage_breaker_is_open(&rate_limited, now));

    let _ = std::fs::remove_dir_all(&support_dir);
}

fn single_caller_test_support_dir(name: &str) -> PathBuf {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-oauth-single-caller-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&support_dir);
    fs::create_dir_all(&support_dir).expect("create support dir");
    support_dir
}

fn single_caller_test_cache(account: &str, organization: &str, observed_at: u64) {
    write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account.to_string(),
        organization_identifier_hash: organization.to_string(),
        observed_at_epoch_seconds: observed_at,
        next_refresh_after_epoch_seconds: observed_at + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
        windows: vec![AgentQuotaWindow {
            name: "session".to_string(),
            scope: AgentQuotaWindowScope::Account,
            status: AgentQuotaWindowStatus::Ok,
            freshness: AgentQuotaWindowFreshness::Fresh,
            used_percent: Some(25),
            account_identifier_hash: Some(account.to_string()),
            organization_identifier_hash: Some(organization.to_string()),
            ..Default::default()
        }],
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    })
    .expect("write cache fixture");
}

#[test]
fn auth_rejections_are_counted_and_backed_off_per_caller() {
    let slot = ClaudeOAuthUsageCaller::RegisteredSlot("slot-a".to_string());
    let default = ClaudeOAuthUsageCaller::Default;
    let mut breaker = None;
    // Two default-login rejections and one slot rejection: under the old
    // account-wide streak this was three strikes and an open breaker.
    for (caller, status, now) in [
        (&default, 401, 1_000),
        (&slot, 403, 1_100),
        (&default, 401, 2_000),
    ] {
        breaker = Some(claude_oauth_usage_breaker_after_auth_failure(
            breaker,
            caller,
            status,
            "account-a",
            "organization-a",
            "fingerprint-a",
            now,
            None,
        ));
    }
    let breaker = breaker.expect("breaker");
    assert!(
        !claude_oauth_usage_breaker_is_open(&breaker, 2_000),
        "one credential's rejections must not open the account-wide breaker"
    );
    assert_eq!(breaker.auth_failures, 0);
    let default_state = &breaker.auth_callers["default"];
    assert_eq!(default_state.consecutive_failures, 2);
    assert_eq!(default_state.last_status, 401);
    assert_eq!(default_state.last_failure_at_epoch_seconds, 2_000);
    assert_eq!(
        default_state.backoff_until_epoch_seconds,
        2_000 + 2 * CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS
    );
    let slot_state = &breaker.auth_callers[&claude_oauth_usage_slot_caller_key("slot-a")];
    assert_eq!(slot_state.consecutive_failures, 1);
    assert_eq!(slot_state.last_status, 403);
    assert_eq!(
        slot_state.backoff_until_epoch_seconds,
        1_100 + CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS
    );
    assert_eq!(
        breaker.last_auth_failure,
        Some(ClaudeOAuthUsageAuthFailureRecord {
            caller: "default".to_string(),
            status: 401,
            at_epoch_seconds: 2_000,
        })
    );
    // Each caller is held only by its own state.
    assert!(claude_oauth_usage_caller_auth_hold(&breaker, &default, 2_001, None).is_some());
    assert!(claude_oauth_usage_caller_auth_hold(
        &breaker,
        &slot,
        1_100 + CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS,
        None
    )
    .is_none());
    let other_slot = ClaudeOAuthUsageCaller::RegisteredSlot("slot-b".to_string());
    assert!(claude_oauth_usage_caller_auth_hold(&breaker, &other_slot, 2_001, None).is_none());
    // The deferred default shares the default login's key: same credential.
    assert!(claude_oauth_usage_caller_auth_hold(
        &breaker,
        &ClaudeOAuthUsageCaller::DefaultDeferredToSlot,
        2_001,
        None
    )
    .is_some());
}

#[test]
#[serial]
fn held_caller_makes_no_provider_call_and_says_why() {
    let support_dir = single_caller_test_support_dir("held");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let _network_guard =
        EnvVarGuard::set_os("OTTTO_DISABLE_CLAUDE_OAUTH_USAGE", OsString::from("0"));
    let account = "account-held";
    let organization = "organization-held";
    let caller = ClaudeOAuthUsageCaller::RegisteredSlot("slot-held".to_string());
    let now = current_unix_seconds();
    let fingerprint = claude_oauth_usage_config_fingerprint();
    let emitted = record_claude_oauth_usage_auth_failure(
        &caller,
        401,
        account,
        organization,
        &fingerprint,
        now,
        None,
    );
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].code, "claude_oauth_usage_auth_rejected");
    assert!(emitted[0].message.contains("with HTTP 401 at "));
    assert!(emitted[0].message.contains("registered account slot"));
    assert!(
        !emitted[0].message.contains("slot-held"),
        "uploaded diagnostics must never carry the local slot id"
    );
    assert_eq!(
        emitted[0].observed_at.as_deref(),
        rfc3339_from_unix_seconds(now).as_deref()
    );
    let calls_before = CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst);

    let outcome = collect_claude_oauth_usage_with_access_token(
        account,
        organization,
        Some("test-token-not-sent".to_string()),
        &caller,
    );

    assert!(outcome.result.is_err());
    assert!(outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_oauth_usage_auth_backoff"));
    assert!(outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_oauth_usage_check_suppressed"));
    assert_eq!(
        CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        calls_before,
        "a rejected credential is not retried inside its backoff"
    );
    // The persisted record is attributable and secret-free.
    let stored = read_claude_oauth_usage_breaker(account, organization, &fingerprint)
        .expect("stored breaker");
    let body = serde_json::to_string(&stored).expect("serialize");
    assert!(!body.contains("test-token-not-sent"));
    assert_eq!(
        stored.last_auth_failure.expect("last auth failure").status,
        401
    );
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn success_from_one_caller_keeps_another_callers_auth_hold() {
    let support_dir = single_caller_test_support_dir("success");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let (account, organization, fingerprint) = ("account-s", "organization-s", "fingerprint-s");
    let slot = ClaudeOAuthUsageCaller::RegisteredSlot("slot-s".to_string());
    let now = 10_000;
    record_claude_oauth_usage_auth_failure(
        &slot,
        401,
        account,
        organization,
        fingerprint,
        now,
        None,
    );
    record_claude_oauth_usage_failure(
        ClaudeOAuthUsageFailure::ResponseShape,
        account,
        organization,
        fingerprint,
        now,
    );

    clear_claude_oauth_usage_breaker_after_success(
        &ClaudeOAuthUsageCaller::RegisteredSlot("slot-other".to_string()),
        account,
        organization,
        fingerprint,
        now + 1,
    );
    let kept = read_claude_oauth_usage_breaker(account, organization, fingerprint)
        .expect("the rejected slot's hold survives another credential's success");
    assert_eq!(kept.shape_failures, 0, "endpoint-level counters reset");
    assert!(claude_oauth_usage_caller_auth_hold(&kept, &slot, now + 1, None).is_some());
    assert_eq!(kept.last_auth_failure.expect("history").status, 401);

    clear_claude_oauth_usage_breaker_after_success(
        &slot,
        account,
        organization,
        fingerprint,
        now + 2,
    );
    assert!(
        !claude_oauth_usage_breaker_path(account, organization).exists(),
        "nothing left to hold: the file is removed as before"
    );
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn retry_after_cache_disclosure_requires_exact_rate_limit_evidence() {
    let support_dir = single_caller_test_support_dir("retry-after-copy");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let _network_guard =
        EnvVarGuard::set_os("OTTTO_DISABLE_CLAUDE_OAUTH_USAGE", OsString::from("0"));
    let now = current_unix_seconds();
    let observed = now.saturating_sub(2 * 60 * 60);
    let deadline = now + 60 * 60;
    let account = "retry-account";
    let organization = "retry-organization";
    let caller = ClaudeOAuthUsageCaller::RegisteredSlot("retry-slot".to_string());
    let fingerprint = claude_oauth_usage_config_fingerprint();
    let calls_before = CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst);
    single_caller_test_cache(account, organization, observed);
    let mut cache = read_claude_oauth_usage_cache(account, organization).expect("cache");
    cache.next_refresh_after_epoch_seconds = deadline;
    write_claude_oauth_usage_cache(&cache).expect("retry gate");

    // A future gate and an old sample alone do not prove rate limiting.
    for other_org in [organization, "another-organization"] {
        if other_org != organization {
            record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::RateLimited,
                account,
                other_org,
                &fingerprint,
                now,
            );
        }
        let result = collect_claude_oauth_usage_with_access_token(
            account,
            organization,
            Some("synthetic-not-sent".to_string()),
            &caller,
        );
        assert_eq!(result.diagnostics[0].message, CLAUDE_CACHE_REUSED_MESSAGE);
        assert!(result.diagnostics[0].retry_after.is_none());
    }
    record_claude_oauth_usage_failure(
        ClaudeOAuthUsageFailure::RateLimited,
        account,
        organization,
        &fingerprint,
        now,
    );
    let result = collect_claude_oauth_usage_with_access_token(
        account,
        organization,
        Some("synthetic-not-sent".to_string()),
        &caller,
    );
    assert_eq!(
        result.diagnostics[0].retry_after,
        rfc3339_from_unix_seconds(deadline)
    );
    let usage = result.result.expect("last-known limits");
    assert_eq!(usage.windows[0].used_percent, Some(25));
    assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Stale);
    assert_eq!(
        usage.windows[0].observed_at,
        rfc3339_from_unix_seconds(observed)
    );
    assert_eq!(
        usage.windows[0].organization_identifier_hash.as_deref(),
        Some(organization)
    );

    // Missing/expired credentials and an auth hold must not be described
    // as an automatic rate-limit retry, even if old 429 evidence remains.
    for token in [None, Some("synthetic-not-sent".to_string())] {
        let expiry = token
            .as_ref()
            .map(|_| rfc3339_from_unix_seconds(now - 1).unwrap());
        let result = collect_claude_oauth_usage_with_credential(
            account,
            organization,
            token,
            expiry,
            &caller,
            current_unix_seconds,
        );
        assert_eq!(result.diagnostics[0].message, CLAUDE_CACHE_REUSED_MESSAGE);
        assert!(result.diagnostics[0].retry_after.is_none());
    }
    record_claude_oauth_usage_auth_failure(
        &caller,
        401,
        account,
        organization,
        &fingerprint,
        now,
        None,
    );
    let result = collect_claude_oauth_usage_with_access_token(
        account,
        organization,
        Some("synthetic-not-sent".to_string()),
        &caller,
    );
    assert_eq!(result.diagnostics[0].message, CLAUDE_CACHE_REUSED_MESSAGE);
    assert!(result.diagnostics[0].retry_after.is_none());
    clear_claude_oauth_usage_breaker(account, organization);
    record_claude_oauth_usage_failure(
        ClaudeOAuthUsageFailure::RateLimited,
        account,
        organization,
        &fingerprint,
        now,
    );
    // An ordinary fresh sample still uses ordinary cache wording.
    cache.observed_at_epoch_seconds = now;
    write_claude_oauth_usage_cache(&cache).expect("fresh cache");
    let result = collect_claude_oauth_usage_with_access_token(
        account,
        organization,
        Some("synthetic-not-sent".to_string()),
        &caller,
    );
    assert_eq!(result.diagnostics[0].message, CLAUDE_CACHE_REUSED_MESSAGE);
    assert!(result.diagnostics[0].retry_after.is_none());
    // Expired or absent deadlines are no longer Retry-After holds. Use
    // no credential so this test also proves no provider request occurred.
    cache.observed_at_epoch_seconds = observed;
    for ended in [now - 1, 0] {
        cache.next_refresh_after_epoch_seconds = ended;
        write_claude_oauth_usage_cache(&cache).expect("ended hold");
        let result =
            collect_claude_oauth_usage_with_access_token(account, organization, None, &caller);
        assert!(result
            .diagnostics
            .iter()
            .all(|item| item.retry_after.is_none()));
    }
    assert_eq!(
        CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        calls_before
    );
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
#[serial]
fn deferred_default_serves_the_shared_cache_and_never_calls_the_provider() {
    let support_dir = single_caller_test_support_dir("deferred");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let _network_guard =
        EnvVarGuard::set_os("OTTTO_DISABLE_CLAUDE_OAUTH_USAGE", OsString::from("0"));
    let caller = ClaudeOAuthUsageCaller::DefaultDeferredToSlot;
    let calls_before = CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst);

    // No cache yet: an honest error, still no request with the default token.
    let empty = collect_claude_oauth_usage_with_access_token(
        "account-d",
        "organization-d",
        Some("default-token-not-sent".to_string()),
        &caller,
    );
    assert!(empty.result.is_err());
    assert!(empty
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_oauth_usage_deferred_to_registered_slot"));

    // A cache past the refresh gate would normally trigger a request; the
    // deferred default serves it (marked stale) instead.
    let now = current_unix_seconds();
    single_caller_test_cache(
        "account-d",
        "organization-d",
        now.saturating_sub(2 * 60 * 60),
    );
    let served = collect_claude_oauth_usage_with_access_token(
        "account-d",
        "organization-d",
        Some("default-token-not-sent".to_string()),
        &caller,
    );
    let usage = served.result.expect("serve the slot-kept cache");
    assert_eq!(usage.windows.len(), 1);
    assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Stale);
    assert_eq!(
        usage.windows[0].account_identifier_hash.as_deref(),
        Some("account-d")
    );
    assert!(served
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_oauth_usage_cache_reused"));
    assert_eq!(
        CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        calls_before,
        "the default login is never a second provider caller for a slot-owned account"
    );
    let _ = fs::remove_dir_all(support_dir);
}

fn single_caller_accounts_status(
    managed_slots: Vec<ClaudeConfigSlotDescriptorV1>,
    external_slots: Vec<ClaudeConfigSlotDescriptorV1>,
) -> ClaudeAccountsStatusV1 {
    ClaudeAccountsStatusV1 {
        schema_version: 1,
        consent: ottto_protocol::ClaudeAccountUpkeepConsentState::Granted,
        setup_operation: ottto_protocol::ClaudeAccountSetupOperationV1 {
            kind: ottto_protocol::ClaudeAccountSetupOperationKind::ConnectManagedAccount,
            state: ottto_protocol::ClaudeAccountSetupOperationState::Idle,
            operation_id: None,
            slot_id: None,
            target_id: None,
            expected_account_identifier_hash: None,
            expected_organization_identifier_hash: None,
            account_identifier_hash: None,
            organization_identifier_hash: None,
            launch_command: None,
            browser_auth: None,
            message: None,
        },
        default_slot: ClaudeConfigDirSlot::Default
            .descriptor("default", ClaudeConfigSlotOwnership::External),
        managed_slots,
        external_slots,
        unresolved_accounts: Vec::new(),
        anchor_coverage: ClaudeAccountAnchorCoverageV1::default(),
        anchor_transitions: Vec::new(),
        capacity: ottto_protocol::ClaudeAccountCapacityV1 {
            max_slots: 10,
            used_slots: 1,
            remaining_slots: 9,
        },
        browser_auth_supported: None,
        auth_code_entry_supported: None,
        retained_provisional_login_count: None,
        consent_covers_limit_reads: None,
    }
}

fn single_caller_slot(
    slot_id: &str,
    ownership: ClaudeConfigSlotOwnership,
    state: ClaudeConfigSlotCollectionStateV1,
    relationship: Option<ottto_protocol::ClaudeConfigSlotRelationshipV1>,
) -> ClaudeConfigSlotDescriptorV1 {
    let mut descriptor = ClaudeConfigDirSlot::registered(format!("/tmp/{slot_id}"))
        .expect("test slot")
        .descriptor(slot_id, ownership);
    descriptor.collection.state = state;
    descriptor.collection.relationship = relationship;
    descriptor.collection.account_identifier_hash = Some("account-g".to_string());
    descriptor.collection.organization_identifier_hash = Some("organization-g".to_string());
    descriptor
}

#[test]
fn default_defers_only_to_a_proven_managed_anchor_for_the_same_binding() {
    use ottto_protocol::ClaudeConfigSlotRelationshipV1 as Relationship;
    let binding = ClaudeStrongBinding::new("account-g", "organization-g").expect("binding");
    let same = |_: &ClaudeConfigSlotDescriptorV1| Some(binding.clone());
    let never_suppressed = |_: &str| false;
    let anchor = single_caller_slot(
        "claude_slot_anchor",
        ClaudeConfigSlotOwnership::Managed,
        ClaudeConfigSlotCollectionStateV1::Fresh,
        Some(Relationship::CanonicalAnchor),
    );

    let owned = claude_slot_owned_usage_bindings(
        &single_caller_accounts_status(vec![anchor.clone()], Vec::new()),
        same,
        never_suppressed,
        |_, _| false,
    );
    assert_eq!(owned, BTreeSet::from([binding.clone()]));

    // Every unproven case keeps today's behaviour: the default still calls.
    let mut not_fresh = anchor.clone();
    not_fresh.collection.state = ClaudeConfigSlotCollectionStateV1::ProviderUnavailable;
    let mut needs_login = anchor.clone();
    needs_login.collection.state = ClaudeConfigSlotCollectionStateV1::NeedsLogin;
    let mut not_anchor = anchor.clone();
    not_anchor.collection.relationship = Some(Relationship::DuplicateAnchor);
    let mut unbound = anchor.clone();
    unbound.collection.organization_identifier_hash = None;
    for managed in [not_fresh, needs_login, not_anchor, unbound] {
        assert!(claude_slot_owned_usage_bindings(
            &single_caller_accounts_status(vec![managed], Vec::new()),
            same,
            never_suppressed,
            |_, _| false
        )
        .is_empty());
    }
    // An external slot is not Ottto-managed.
    let external = single_caller_slot(
        "claude_slot_external",
        ClaudeConfigSlotOwnership::External,
        ClaudeConfigSlotCollectionStateV1::Fresh,
        Some(Relationship::CanonicalAnchor),
    );
    assert!(claude_slot_owned_usage_bindings(
        &single_caller_accounts_status(Vec::new(), vec![external]),
        same,
        never_suppressed,
        |_, _| false
    )
    .is_empty());
    // The slot's identity file now names another account, or cannot be read.
    let other = ClaudeStrongBinding::new("account-x", "organization-g").expect("other");
    for current in [Some(other), None] {
        assert!(claude_slot_owned_usage_bindings(
            &single_caller_accounts_status(vec![anchor.clone()], Vec::new()),
            |_| current.clone(),
            never_suppressed,
            |_, _| false
        )
        .is_empty());
    }
    // A browser-auth suppression means the slot is not collected this pass.
    assert!(claude_slot_owned_usage_bindings(
        &single_caller_accounts_status(vec![anchor], Vec::new()),
        same,
        |_| true,
        |_, _| false
    )
    .is_empty());
}

#[test]
fn breaker_file_stays_compatible_in_both_directions() {
    // A file written before caller attribution parses with empty new fields.
    let old: ClaudeOAuthUsageBreaker = serde_json::from_value(serde_json::json!({
        "schema_version": CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
        "account_identifier_hash": "a",
        "organization_identifier_hash": "o",
        "config_fingerprint": "f",
        "auth_failures": 2,
        "shape_failures": 0,
        "rate_limit_failures": 0,
        "opened_at_epoch_seconds": 0,
        "reopen_after_epoch_seconds": 0,
        "opened_by": ""
    }))
    .expect("parse pre-attribution breaker");
    assert_eq!(old.auth_failures, 2);
    assert!(old.auth_callers.is_empty());
    assert!(old.last_auth_failure.is_none());
    assert!(
        !serde_json::to_string(&old)
            .expect("serialize")
            .contains("auth_callers"),
        "unattributed files round-trip byte-shape unchanged"
    );

    // A daemon from before caller attribution reads the new file: the
    // schema version is unchanged and the additive fields are ignored.
    #[derive(Deserialize)]
    #[allow(dead_code, reason = "old file shape; fields only deserialized")]
    struct PreAttributionBreaker {
        schema_version: u16,
        account_identifier_hash: String,
        organization_identifier_hash: String,
        config_fingerprint: String,
        auth_failures: u32,
        shape_failures: u32,
        rate_limit_failures: u32,
        opened_at_epoch_seconds: u64,
        reopen_after_epoch_seconds: u64,
        opened_by: String,
    }
    let new = claude_oauth_usage_breaker_after_auth_failure(
        None,
        &ClaudeOAuthUsageCaller::RegisteredSlot("slot-a".to_string()),
        401,
        "a",
        "o",
        "f",
        1_000,
        None,
    );
    let body = serde_json::to_string(&new).expect("serialize attributed breaker");
    let read_by_old: PreAttributionBreaker =
        serde_json::from_str(&body).expect("pre-attribution daemon parses the new file");
    assert_eq!(
        read_by_old.schema_version,
        CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION
    );
    assert_eq!(read_by_old.reopen_after_epoch_seconds, 0);
    assert_eq!(read_by_old.auth_failures, 0);
}

#[test]
#[serial]
fn breaker_files_never_persist_the_raw_slot_id_and_migrate_raw_keys() {
    let support_dir = single_caller_test_support_dir("opaque-key");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let raw_slot_id = "claude_slot_0123456789abcdef0123456789abcdef";
    let slot = ClaudeOAuthUsageCaller::RegisteredSlot(raw_slot_id.to_string());
    let (account, organization, fingerprint) = ("account-o", "organization-o", "fingerprint-o");
    // The default login mirrors into the legacy file; the slot writes the
    // per-account file. Neither may carry the raw id.
    record_claude_oauth_usage_auth_failure(
        &slot,
        401,
        account,
        organization,
        fingerprint,
        1_000,
        None,
    );
    record_claude_oauth_usage_auth_failure(
        &ClaudeOAuthUsageCaller::Default,
        401,
        account,
        organization,
        fingerprint,
        1_001,
        None,
    );
    for path in [
        claude_oauth_usage_breaker_path(account, organization),
        claude_oauth_usage_legacy_breaker_path(),
    ] {
        let body = fs::read_to_string(&path).expect("breaker body");
        assert!(
            !body.contains(raw_slot_id),
            "raw slot id persisted in {path:?}"
        );
        assert!(body.contains(&claude_oauth_usage_slot_caller_key(raw_slot_id)));
    }
    assert_ne!(
        claude_oauth_usage_slot_caller_key(raw_slot_id),
        claude_oauth_usage_slot_caller_key("claude_slot_other")
    );

    // A file already written with raw `slot:<id>` keys is migrated on read.
    let (account, organization) = ("account-raw", "organization-raw");
    let path = claude_oauth_usage_breaker_path(account, organization);
    fs::create_dir_all(path.parent().expect("parent")).expect("state dir");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
            "account_identifier_hash": account,
            "organization_identifier_hash": organization,
            "config_fingerprint": fingerprint,
            "auth_callers": {
                format!("slot:{raw_slot_id}"): {
                    "consecutive_failures": 2,
                    "last_status": 403,
                    "last_failure_at_epoch_seconds": 1_000,
                    "backoff_until_epoch_seconds": 2_800
                }
            },
            "last_auth_failure": {
                "caller": format!("slot:{raw_slot_id}"),
                "status": 403,
                "at_epoch_seconds": 1_000
            }
        }))
        .expect("raw fixture"),
    )
    .expect("write raw-key breaker");
    let migrated = read_claude_oauth_usage_breaker(account, organization, fingerprint)
        .expect("migrated breaker");
    assert_eq!(
        migrated.auth_callers[&slot.breaker_key()].consecutive_failures,
        2
    );
    assert_eq!(
        migrated.last_auth_failure.expect("history").caller,
        slot.breaker_key()
    );
    assert!(
        !fs::read_to_string(&path)
            .expect("rewritten")
            .contains(raw_slot_id),
        "the migration is persisted"
    );
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
fn rotated_default_credential_is_released_from_its_predecessors_hold() {
    let default = ClaudeOAuthUsageCaller::Default;
    let rejected_expiry = Some("2026-10-03T01:00:00Z");
    let rotated_expiry = Some("2026-10-03T09:00:00Z");
    let mut breaker = None;
    for offset in 0..2 {
        breaker = Some(claude_oauth_usage_breaker_after_auth_failure(
            breaker,
            &default,
            401,
            "a",
            "o",
            "f",
            1_000 + offset,
            rejected_expiry,
        ));
    }
    let breaker = breaker.expect("breaker");
    let state = &breaker.auth_callers["default"];
    assert_eq!(state.credential_expires_at.as_deref(), rejected_expiry);
    // Same credential, or unknown current expiry: still held.
    assert!(
        claude_oauth_usage_caller_auth_hold(&breaker, &default, 1_002, rejected_expiry).is_some()
    );
    assert!(claude_oauth_usage_caller_auth_hold(&breaker, &default, 1_002, None).is_some());
    // Claude Code rotated the token: released at once.
    assert!(
        claude_oauth_usage_caller_auth_hold(&breaker, &default, 1_002, rotated_expiry).is_none()
    );
    // A rejection of the rotated credential starts a new streak.
    let next = claude_oauth_usage_breaker_after_auth_failure(
        Some(breaker),
        &default,
        401,
        "a",
        "o",
        "f",
        1_003,
        rotated_expiry,
    );
    let state = &next.auth_callers["default"];
    assert_eq!(state.consecutive_failures, 1);
    assert_eq!(state.credential_expires_at.as_deref(), rotated_expiry);
    assert_eq!(
        state.backoff_until_epoch_seconds,
        1_003 + CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS
    );
}

#[test]
#[serial]
fn slot_success_is_not_resurrected_from_the_legacy_mirror() {
    let support_dir = single_caller_test_support_dir("legacy-resurrect");
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let (account, organization, fingerprint) = ("account-r", "organization-r", "fingerprint-r");
    let slot_a = ClaudeOAuthUsageCaller::RegisteredSlot("slot-a".to_string());
    let default = ClaudeOAuthUsageCaller::Default;
    record_claude_oauth_usage_auth_failure(
        &slot_a,
        401,
        account,
        organization,
        fingerprint,
        1_000,
        None,
    );
    // The default login succeeds after A's hold expired: A's streak is
    // kept and the default path mirrors it into the legacy file.
    let after_hold = 1_000 + CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS + 60;
    clear_claude_oauth_usage_breaker_after_success(
        &default,
        account,
        organization,
        fingerprint,
        after_hold,
    );
    assert!(fs::read_to_string(claude_oauth_usage_legacy_breaker_path())
        .expect("legacy mirror")
        .contains(&slot_a.breaker_key()));
    // A's own success retires its streak and deletes the account file.
    clear_claude_oauth_usage_breaker_after_success(
        &slot_a,
        account,
        organization,
        fingerprint,
        after_hold + 1,
    );
    assert!(!claude_oauth_usage_breaker_path(account, organization).exists());
    // The next default read migrates the legacy file if present; A's
    // retired streak must not come back.
    let resurrected = read_claude_oauth_usage_breaker(account, organization, fingerprint);
    assert!(
        resurrected
            .as_ref()
            .is_none_or(|breaker| !breaker.auth_callers.contains_key(&slot_a.breaker_key())),
        "a caller's success must permanently retire its streak: {resurrected:?}"
    );
    let _ = fs::remove_dir_all(support_dir);
}

#[test]
fn caller_attribution_diagnostics_survive_the_backend_upload_redaction() {
    let caller = ClaudeOAuthUsageCaller::RegisteredSlot("claude_slot_private".to_string());
    let state = ClaudeOAuthUsageCallerAuthState {
        consecutive_failures: 1,
        last_status: 401,
        last_failure_at_epoch_seconds: 1_790_000_000,
        backoff_until_epoch_seconds: 1_790_000_000 + CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS,
        credential_expires_at: None,
    };
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-10-03T00:00:00Z".to_string(),
        "2026-10-03T00:30:00Z".to_string(),
    );
    snapshot
        .diagnostics
        .push(claude_oauth_usage_caller_auth_hold_diagnostic(
            &caller,
            &state,
            1_790_000_060,
        ));
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "claude_oauth_usage_deferred_to_registered_slot",
        AgentDiagnosticSeverity::Info,
        "This Claude account's quota is read through its registered account slot; the default Claude Code login made no provider request.",
    ));
    let uploaded = snapshot.clone().redacted_for_backend();
    assert_eq!(uploaded.diagnostics.len(), 2);
    for (sent, local) in uploaded.diagnostics.iter().zip(&snapshot.diagnostics) {
        assert_eq!(sent.code, local.code);
        assert_eq!(sent.message, local.message, "message must not be redacted");
        assert!(!sent.message.contains("claude_slot_private"));
    }
    assert!(uploaded.diagnostics[0].message.contains("HTTP 401"));
}

#[test]
fn claude_oauth_usage_diagnostics_survive_the_backend_upload_redaction() {
    // The circuit-breaker alert reaches our servers by riding the
    // agent-status snapshot upload; `redacted_for_backend` is the only
    // transform between the collector and the wire.
    let breaker = ClaudeOAuthUsageBreaker {
        schema_version: CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
        account_identifier_hash: "account-a".to_string(),
        config_fingerprint: "fingerprint-a".to_string(),
        auth_failures: CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD,
        opened_at_epoch_seconds: 1_000,
        reopen_after_epoch_seconds: 1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS,
        opened_by: "auth_rejected".to_string(),
        ..Default::default()
    };
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::StatusLine,
        "2026-07-26T00:00:00Z".to_string(),
        "2026-07-26T00:30:00Z".to_string(),
    );
    snapshot
        .diagnostics
        .push(claude_oauth_usage_circuit_open_diagnostic(&breaker, 1_000));
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "claude_oauth_usage_network_disabled",
        AgentDiagnosticSeverity::Info,
        "Claude subscription quota is read from Claude Code's local statusLine only: the Claude OAuth usage network read is switched off on this machine.",
    ));

    let uploaded = snapshot.redacted_for_backend();
    let codes: Vec<&str> = uploaded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect();
    assert_eq!(
        codes,
        vec![
            "claude_oauth_usage_circuit_open",
            "claude_oauth_usage_network_disabled"
        ]
    );
    // Codes and messages must survive intact -- a redacted message would
    // reach the backend as "diagnostic redacted" and the alert would be
    // useless.
    assert!(uploaded.diagnostics.iter().all(|diagnostic| {
        diagnostic.message != "diagnostic redacted" && diagnostic.code != "redacted"
    }));
}

#[test]
fn claude_oauth_spend_disabled_emits_unknown_amounts() {
    // Live disabled-state sample observed 2026-07-06 (Max account).
    let json = serde_json::json!({
        "spend": {
            "used": {"amount_minor": 0, "currency": "USD", "exponent": 2},
            "limit": null, "cap": null, "balance": null,
            "percent": 0, "severity": "normal", "enabled": false,
            "can_purchase_credits": false, "can_toggle": false
        },
        "extra_usage": {"is_enabled": false, "monthly_limit": null, "used_credits": null}
    });
    let balances = claude_oauth_credit_balances(&json);
    assert_eq!(balances.len(), 1);
    assert_eq!(balances[0].enabled, Some(false));
    assert_eq!(balances[0].status, AgentCreditBalanceStatus::Unknown);
    assert_eq!(balances[0].remaining, None);
    assert_eq!(balances[0].used, None);
    assert_eq!(balances[0].quota, None);
}

#[test]
fn quota_coverage_reset_detail_witness_is_bounded_and_identity_gated() {
    assert_eq!(
        codex_reset_credit_detail_summary(&serde_json::json!({})),
        None
    );
    let missing = codex_reset_credit_detail_summary(
        &serde_json::json!({"rateLimitResetCredits":{"availableCount":3,"credits":null}}),
    )
    .unwrap();
    assert_eq!(missing, "Codex reset details: count 3; list unobserved.");
    let empty = codex_reset_credit_detail_summary(
        &serde_json::json!({"rateLimitResetCredits":{"availableCount":0,"credits":[]}}),
    )
    .unwrap();
    assert!(empty.contains("list rows 0; sampled 0"));
    let rows = vec![
        serde_json::json!({"id":"sensitive-id","title":"sensitive-title","status":"available","expiresAt":10});
        25
    ];
    let summary = codex_reset_credit_detail_summary(
        &serde_json::json!({"rateLimitResetCredits":{"availableCount":30,"credits":rows}}),
    )
    .unwrap();
    assert!(summary.contains("list rows 25; sampled 20; available 20"));
    assert!(!summary.contains("sensitive"));
    assert!(summary.len() < 256);
    // The witness uses this same exact-binding/time envelope before upload.
    assert!(codex_app_server_success_diagnostic(
        Some("2026-10-01T00:00:00Z".to_string()),
        None,
        true
    )
    .is_none());
}

#[test]
fn quota_coverage_credit_states_do_not_invent_amounts() {
    for (value, status, enabled) in [
        (
            serde_json::json!({"extra_usage":{"is_enabled":false,"used_credits":2}}),
            AgentCreditBalanceStatus::Unknown,
            false,
        ),
        (
            serde_json::json!({"extra_usage":{"is_enabled":true}}),
            AgentCreditBalanceStatus::Unknown,
            true,
        ),
        (
            serde_json::json!({"extra_usage":{"is_enabled":true,"monthly_limit":null}}),
            AgentCreditBalanceStatus::Unlimited,
            true,
        ),
        (
            serde_json::json!({"extra_usage":{"is_enabled":true,"monthly_limit":0,"used_credits":0}}),
            AgentCreditBalanceStatus::Exhausted,
            true,
        ),
    ] {
        let rows = claude_oauth_credit_balances(&value);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, status);
        assert_eq!(rows[0].enabled, Some(enabled));
        if status != AgentCreditBalanceStatus::Exhausted {
            assert_eq!(rows[0].remaining, None);
        }
    }
    assert!(claude_oauth_credit_balances(&serde_json::json!({})).is_empty());
    assert!(claude_oauth_credit_balances(
        &serde_json::json!({"extra_usage":{"is_enabled":"true"}})
    )
    .is_empty());
}

#[test]
fn quota_coverage_start_basis_and_provider_clock() {
    let observation = CodexAppServerObservation {
        account: serde_json::json!({}),
        rate_limits: serde_json::json!({"rateLimits":{"primary":{"usedPercent":10,"windowDurationMins":300,"resetsAt":1791150000}}}),
        refreshed_credentials: None,
        credential_read_failed: false,
        response_completed_at: Some("2026-10-04T19:00:00Z".to_string()),
        details_requested: true,
        details_answered: true,
    };
    let probe = codex_usage_probe_from_app_server_observation(observation);
    assert_eq!(probe.quota_windows.len(), 1);
    assert_eq!(
        probe.quota_windows[0].observed_at,
        probe.response_completed_at
    );
    assert_eq!(
        probe.quota_windows[0].started_at_basis.as_deref(),
        Some("provider_duration")
    );
    let claude = claude_oauth_quota_window(
        "session",
        Some(&serde_json::json!({"utilization":1,"resets_at":"2026-10-05T00:00:00Z"})),
        18000,
    )
    .unwrap();
    assert_eq!(claude.started_at_basis.as_deref(), Some("assumed_duration"));
    let absent = codex_app_server_quota_window(
        "session",
        "codex",
        &serde_json::json!({"usedPercent":1}),
        &serde_json::json!({}),
    )
    .unwrap();
    assert_eq!(absent.started_at_basis, None);
}

#[test]
fn quota_coverage_passive_rollover_requires_ended_exact_meter() {
    let old = AgentQuotaWindow {
        name: "session".to_string(),
        scope: AgentQuotaWindowScope::Account,
        account_identifier_hash: Some("synthetic-account".to_string()),
        organization_identifier_hash: Some("synthetic-org".to_string()),
        window_seconds: Some(18000),
        started_at: Some("2026-10-01T00:00:00Z".to_string()),
        started_at_basis: Some("assumed_duration".to_string()),
        resets_at: Some("2026-10-01T05:00:00Z".to_string()),
        observed_at: Some("2026-10-01T04:00:00Z".to_string()),
        used_percent: Some(99),
        ..Default::default()
    };
    let newer = AgentQuotaWindow {
        observed_at: Some("2026-10-01T05:05:00Z".to_string()),
        resets_at: Some("2026-10-01T10:00:00Z".to_string()),
        started_at: None,
        started_at_basis: None,
        used_percent: Some(2),
        ..old.clone()
    };
    let mut windows = vec![old.clone()];
    assert!(prefer_newer_exact_claude_statusline_windows(
        &mut windows,
        vec![newer.clone()]
    ));
    assert_eq!(windows[0].used_percent, Some(2));
    assert_eq!(
        windows[0].started_at.as_deref(),
        Some("2026-10-01T05:00:00Z")
    );
    assert_eq!(
        windows[0].started_at_basis.as_deref(),
        Some("assumed_duration")
    );
    for field in [
        "account",
        "org",
        "model",
        "unfinished",
        "future_start",
        "old_clock",
        "ended_new",
    ] {
        let mut invalid = newer.clone();
        match field {
            "account" => invalid.account_identifier_hash = Some("other".to_string()),
            "org" => invalid.organization_identifier_hash = Some("other".to_string()),
            "model" => invalid.model = Some("other".to_string()),
            "unfinished" => invalid.observed_at = Some("2026-10-01T04:05:00Z".to_string()),
            "future_start" => invalid.resets_at = Some("2026-10-01T11:00:00Z".to_string()),
            "old_clock" => invalid.observed_at = old.observed_at.clone(),
            "ended_new" => invalid.resets_at = Some("2026-10-01T05:04:00Z".to_string()),
            _ => unreachable!(),
        }
        let mut preserved = vec![old.clone()];
        assert!(
            !prefer_newer_exact_claude_statusline_windows(&mut preserved, vec![invalid]),
            "{field}"
        );
        assert_eq!(preserved[0], old);
    }
    let mut money = old.clone();
    money.used_cents = Some(1);
    assert!(!prefer_newer_exact_claude_statusline_windows(
        &mut [money],
        vec![newer]
    ));
}

#[test]
fn claude_oauth_spend_enabled_maps_usage_credit_balance() {
    let json = serde_json::json!({
        "spend": {
            "used": {"amount_minor": 321, "currency": "USD", "exponent": 2},
            "cap": {"amount_minor": 500, "currency": "USD", "exponent": 2},
            "balance": {"amount_minor": 179, "currency": "USD", "exponent": 2},
            "percent": 64, "severity": "warning", "enabled": true
        }
    });
    let balances = claude_oauth_credit_balances(&json);
    assert_eq!(balances.len(), 1);
    let credit = &balances[0];
    assert_eq!(credit.name, "Usage credits");
    assert_eq!(credit.unit, AgentCreditBalanceUnit::Usd);
    assert_eq!(credit.status, AgentCreditBalanceStatus::Low);
    assert_eq!(credit.used, CreditAmount::whole(321));
    assert_eq!(credit.quota, CreditAmount::whole(500));
    assert_eq!(credit.remaining, CreditAmount::whole(179));
    assert_eq!(credit.used_percent, Some(64));
    assert_eq!(credit.currency.as_deref(), Some("USD"));
    assert_eq!(credit.enabled, Some(true));
}

#[test]
fn claude_oauth_spend_falls_back_to_limit_and_derives_remaining() {
    let json = credit_amount_input::usage_body(serde_json::json!({
        "spend": {
            "used": {"amount_minor": 500, "currency": "USD", "exponent": 2},
            "limit": 5.0,
            "severity": "critical",
            "enabled": true
        }
    }));
    let balances = claude_oauth_credit_balances(&json);
    assert_eq!(balances.len(), 1);
    assert_eq!(balances[0].status, AgentCreditBalanceStatus::Exhausted);
    assert_eq!(balances[0].used, CreditAmount::whole(500));
    assert_eq!(balances[0].quota, CreditAmount::whole(500));
    assert_eq!(balances[0].remaining, CreditAmount::whole(0));
}

#[test]
fn claude_oauth_money_cents_normalizes_exponents_and_bare_numbers() {
    let object = serde_json::json!({"amount_minor": 3215, "exponent": 3});
    assert_eq!(claude_oauth_money_cents(Some(&object)), Some(322));
    let zero_exp = serde_json::json!({"amount_minor": 5, "exponent": 0});
    assert_eq!(claude_oauth_money_cents(Some(&zero_exp)), Some(500));
    let bare = serde_json::json!("5.0");
    assert_eq!(claude_oauth_money_cents(Some(&bare)), Some(500));
    let negative = serde_json::json!({"amount_minor": -1, "exponent": 2});
    assert_eq!(claude_oauth_money_cents(Some(&negative)), None);
    assert_eq!(claude_oauth_money_cents(None), None);
    // One exact half-even scaler: an exact half cent rounds to even, and a
    // decimal string keeps its digits.
    for (value, cents) in [
        (
            serde_json::json!({"amount_minor": 12345, "exponent": 3}),
            Some(1_234),
        ),
        (
            serde_json::json!({"amount_minor": 12355, "exponent": 3}),
            Some(1_236),
        ),
        (serde_json::json!("0.125"), Some(12)),
        (serde_json::json!("0.1251"), Some(13)),
    ] {
        assert_eq!(claude_oauth_money_cents(Some(&value)), cents, "{value}");
    }
}

#[test]
fn claude_oauth_extra_usage_fallback_maps_credit_balance() {
    let json = credit_amount_input::usage_body(serde_json::json!({
        "extra_usage": {
            "is_enabled": true,
            "monthly_limit": 5.0,
            "used_credits": 3.21,
            "utilization": 64,
            "currency": "USD"
        }
    }));
    let balances = claude_oauth_credit_balances(&json);
    assert_eq!(balances.len(), 1);
    assert_eq!(balances[0].used, CreditAmount::whole(321));
    assert_eq!(balances[0].quota, CreditAmount::whole(500));
    assert_eq!(balances[0].remaining, CreditAmount::whole(179));
    assert_eq!(balances[0].used_percent, Some(64));
}

#[test]
fn claude_oauth_scoped_limits_map_model_windows_and_skip_account_kinds() {
    let json = serde_json::json!({
        "five_hour": {"utilization": 0.0, "resets_at": "2026-07-06T22:40:00+00:00"},
        "seven_day": {"utilization": 82.0, "resets_at": "2026-07-11T05:00:00+00:00"},
        "limits": [
            {"kind": "session", "group": "session", "percent": 0,
             "severity": "normal", "resets_at": "2026-07-06T22:40:00+00:00",
             "scope": null, "is_active": false},
            {"kind": "weekly_all", "group": "weekly", "percent": 82,
             "severity": "warning", "resets_at": "2026-07-11T05:00:00+00:00",
             "scope": null, "is_active": false},
            {"kind": "weekly_scoped", "group": "weekly", "percent": 98,
             "severity": "critical", "resets_at": "2026-07-11T05:00:00+00:00",
             "scope": {"model": {"id": null, "display_name": "Fable"}},
             "is_active": true}
        ]
    });
    let windows = claude_oauth_quota_windows(&json);
    // session + weekly account windows, plus exactly one scoped model window
    assert_eq!(windows.len(), 3);
    let scoped = &windows[2];
    assert_eq!(scoped.name, "weekly_scoped");
    assert_eq!(scoped.scope, AgentQuotaWindowScope::Model);
    assert_eq!(scoped.model.as_deref(), Some("Fable"));
    assert_eq!(scoped.used_percent, Some(98));
    assert_eq!(scoped.group.as_deref(), Some("weekly"));
    assert_eq!(scoped.severity.as_deref(), Some("critical"));
    assert_eq!(scoped.is_active, Some(true));
}

#[test]
fn claude_oauth_window_dollar_fields_map_to_cents() {
    let json = credit_amount_input::usage_body(serde_json::json!({
        "five_hour": {
            "utilization": 24.0,
            "resets_at": "2026-06-29T18:10:00+00:00",
            "limit_dollars": 25.0,
            "used_dollars": 6.0,
            "remaining_dollars": 19.0
        }
    }));
    let windows = claude_oauth_quota_windows(&json);
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].limit_cents, Some(2500));
    assert_eq!(windows[0].used_cents, Some(600));
    assert_eq!(windows[0].remaining_cents, Some(1900));
}

/// The hash a Claude Desktop plan observation would carry for `account_uuid`
/// -- the same `billing_identity_hash` shape
/// `claude_desktop_builder_plan_observation` produces.
fn observable_account_hashes(account_uuids: &[&str]) -> Vec<String> {
    account_uuids
        .iter()
        .filter_map(|uuid| billing_identity_hash("anthropic", "account", uuid))
        .collect()
}

#[test]
fn claude_statusline_sample_is_attributed_only_to_the_account_that_owns_the_credential() {
    let account_a = claude_account_identifier_hash(Some("acct-a"), None, None);
    let account_b = claude_account_identifier_hash(Some("acct-b"), None, None);
    assert_ne!(account_a, account_b);

    // Same account, nothing else on the machine: provable, so serve it.
    assert_eq!(
        claude_statusline_attribution_failure(&account_a, "config_dir", &account_a, &[]),
        None
    );
    // A Desktop observation for the SAME account is not a second account.
    assert_eq!(
        claude_statusline_attribution_failure(
            &account_a,
            "config_dir",
            &account_a,
            &observable_account_hashes(&["acct-a"])
        ),
        None
    );

    // Written under a credential that has since been replaced.
    assert_eq!(
        claude_statusline_attribution_failure(&account_a, "config_dir", &account_b, &[]),
        Some(ClaudeStatusLineUnattributable::CredentialReplaced)
    );

    // An unnamed account on either side matches nothing. Unlike the OAuth
    // cache, two empty hashes must NOT match here: statusLine re-observes on
    // the next render, so refusing costs nothing.
    assert_eq!(
        claude_statusline_attribution_failure("", "unknown", &account_a, &[]),
        Some(ClaudeStatusLineUnattributable::AccountUnknown)
    );
    assert_eq!(
        claude_statusline_attribution_failure(&account_a, "unknown", "", &[]),
        Some(ClaudeStatusLineUnattributable::AccountUnknown)
    );
    assert_eq!(
        claude_statusline_attribution_failure("", "unknown", "", &[]),
        Some(ClaudeStatusLineUnattributable::AccountUnknown)
    );
}

#[test]
fn claude_statusline_sample_refuses_unknown_resolution() {
    // NEW BEHAVIOR: unknown resolution (no store match, no CLI entrypoint, etc) refuses
    let team = claude_account_identifier_hash(Some("acct-team"), None, None);

    assert_eq!(
        claude_statusline_attribution_failure(&team, "unknown", &team, &[]),
        Some(ClaudeStatusLineUnattributable::AccountUnknown),
        "unknown resolution cannot be proven"
    );

    // Empty method (v2 cache missing method field) is treated as unknown
    assert_eq!(
        claude_statusline_attribution_failure(&team, "", &team, &[]),
        Some(ClaudeStatusLineUnattributable::AccountUnknown),
        "v2 cache with no method field is unresolved"
    );
}

#[test]
#[serial]
fn claude_statusline_quota_is_not_served_across_accounts() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-statusline-account-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&support_dir);
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );

    let account_a = claude_account_identifier_hash(Some("acct-a"), None, None);
    let account_b = claude_account_identifier_hash(Some("acct-b"), None, None);
    let now = current_unix_seconds();
    write_claude_statusline_cache(
        &support_dir,
        &ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: account_a.clone(),
            observed_under_organization_identifier_hash: None,
            observed_under_account_method: "config_dir".to_string(),
            observed_at_epoch_seconds: now,
            windows: vec![ClaudeStatusLineRateLimitWindow {
                name: "seven_day".to_string(),
                used_percent: 44,
                resets_at_epoch_seconds: now + 7 * 24 * 60 * 60,
            }],
        },
    )
    .expect("write cache");

    // Its own account, alone on the machine: served.
    match collect_claude_statusline_quota_windows(&account_a, &[]).expect("collect") {
        ClaudeStatusLineQuota::Windows(windows) => {
            assert_eq!(windows.len(), 1);
            assert_eq!(windows[0].used_percent, Some(44));
        }
        other => panic!("own account was not served: {other:?}"),
    }

    // The replacing account must not be shown account A's 44%.
    assert_eq!(
        collect_claude_statusline_quota_windows(&account_b, &[]).expect("collect"),
        ClaudeStatusLineQuota::Unattributable(ClaudeStatusLineUnattributable::CredentialReplaced)
    );

    // With the new resolution method system, config_dir method serves the cache
    // even when another account is observable, because the method proves it was
    // resolved from the CLI credential holder. The store join is what breaks the
    // old "any second account makes everything ambiguous" logic.
    match collect_claude_statusline_quota_windows(
        &account_a,
        &observable_account_hashes(&["acct-max"]),
    )
    .expect("collect")
    {
        ClaudeStatusLineQuota::Windows(windows) => {
            assert_eq!(windows.len(), 1);
            assert_eq!(windows[0].used_percent, Some(44));
        }
        other => panic!(
            "config_dir method should serve despite multiple accounts when hash matches: {other:?}"
        ),
    }

    // A pre-fix (v1) cache carries no account identity and is discarded
    // outright rather than adopted by whoever is signed in now.
    std::fs::write(
        support_dir.join("claude-code-rate-limits.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "observed_at_epoch_seconds": now,
            "windows": [{
                "name": "seven_day",
                "used_percent": 44,
                "resets_at_epoch_seconds": now + 7 * 24 * 60 * 60
            }]
        }))
        .expect("serialize v1"),
    )
    .expect("write v1 cache");
    assert_eq!(
        collect_claude_statusline_quota_windows(&account_a, &[]).expect("collect"),
        ClaudeStatusLineQuota::NotObserved
    );

    let _ = std::fs::remove_dir_all(&support_dir);
}

#[test]
fn prefer_newer_exact_statusline_keeps_meter_coverage_and_refuses_weak_or_other_binding() {
    let meter = |name: &str, organization: Option<&str>, time: &str, used: u8| AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Account,
        account_identifier_hash: Some("account-a".to_string()),
        organization_identifier_hash: organization.map(str::to_string),
        observed_at: Some(time.to_string()),
        resets_at: Some("2026-10-01T00:00:00Z".to_string()),
        used_percent: Some(used),
        ..Default::default()
    };
    let old = "2026-09-29T10:00:00Z";
    let new = "2026-09-29T10:05:00Z";
    let mut oauth = vec![
        meter("session", Some("org-a"), old, 40),
        meter("weekly", Some("org-a"), old, 70),
        meter("scoped", Some("org-a"), old, 80),
    ];
    for organization in [None, Some("org-b")] {
        assert!(!prefer_newer_exact_claude_statusline_windows(
            &mut oauth,
            vec![meter("session", organization, new, 46)]
        ));
        assert_eq!(oauth[0].used_percent, Some(40));
    }
    let mut other_pool = meter("session", Some("org-a"), new, 96);
    other_pool.limit_id = Some("another-pool".to_string());
    assert!(!prefer_newer_exact_claude_statusline_windows(
        &mut oauth,
        vec![other_pool]
    ));
    assert!(!prefer_newer_exact_claude_statusline_windows(
        &mut oauth,
        vec![meter("session", Some("org-a"), "2099-01-01T00:00:00Z", 96)]
    ));
    let mut no_reading = meter("session", Some("org-a"), new, 96);
    no_reading.used_percent = None;
    assert!(!prefer_newer_exact_claude_statusline_windows(
        &mut oauth,
        vec![no_reading]
    ));
    assert!(prefer_newer_exact_claude_statusline_windows(
        &mut oauth,
        vec![meter("session", Some("org-a"), new, 46)]
    ));
    assert_eq!(
        oauth
            .iter()
            .map(|window| window.used_percent)
            .collect::<Vec<_>>(),
        vec![Some(46), Some(70), Some(80)]
    );
    assert_eq!(oauth[0].observed_at.as_deref(), Some(new));
    assert_eq!(oauth[1].observed_at.as_deref(), Some(old));
    assert!(!prefer_newer_exact_claude_statusline_windows(
        &mut oauth,
        vec![meter("session", Some("org-a"), old, 30)]
    ));
    oauth[0].observed_at = None;
    assert!(!prefer_newer_exact_claude_statusline_windows(
        &mut oauth,
        vec![meter("session", Some("org-a"), new, 50)]
    ));
}

#[test]
fn prefer_newer_exact_statusline_preserves_actual_oauth_money_and_start_coverage() {
    let parsed = |money: Option<&str>| {
        let mut response = serde_json::json!({
            "five_hour": {"utilization": 40, "resets_at": "1970-01-01T00:03:20Z"},
            "seven_day": {"utilization": 70, "resets_at": "1970-01-01T00:05:00Z"},
            "spend": {"enabled": true, "used": 6, "cap": 25}
        });
        if let Some(field) = money {
            response["five_hour"][field] = serde_json::json!(25);
        }
        let mut usage = ClaudeOAuthUsage {
            windows: claude_oauth_quota_windows(&response),
            credit_balances: claude_oauth_credit_balances(&response),
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        };
        claude_oauth_stamp_account_identity(&mut usage, "account-a", Some("org-a"));
        for window in &mut usage.windows {
            window.observed_at = rfc3339_from_unix_seconds(100);
        }
        usage
    };
    let local = || {
        claude_statusline_quota_windows_from_cache(
            ClaudeStatusLineRateLimitCache {
                schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
                observed_under_account_identifier_hash: "account-a".to_string(),
                observed_under_organization_identifier_hash: Some("org-a".to_string()),
                observed_under_account_method: "session_store".to_string(),
                observed_at_epoch_seconds: 180,
                windows: vec![ClaudeStatusLineRateLimitWindow {
                    name: "five_hour".to_string(),
                    used_percent: 46,
                    resets_at_epoch_seconds: 200,
                }],
            },
            150,
        )
    };
    for field in ["limit_dollars", "used_dollars", "remaining_dollars"] {
        let mut usage = parsed(Some(field));
        let before = usage.clone();
        assert!(!prefer_newer_exact_claude_statusline_windows(
            &mut usage.windows,
            local()
        ));
        assert_eq!(usage.windows, before.windows);
        assert_eq!(usage.credit_balances, before.credit_balances);
    }
    let original = parsed(None);
    assert_eq!(original.windows.len(), 2);
    assert_eq!(original.credit_balances.len(), 1);
    let mut usage = original.clone();
    assert!(prefer_newer_exact_claude_statusline_windows(
        &mut usage.windows,
        local()
    ));
    assert_eq!(usage.windows[0].used_percent, Some(46));
    assert_eq!(usage.windows[0].observed_at, rfc3339_from_unix_seconds(180));
    assert_eq!(usage.windows[0].started_at, original.windows[0].started_at);
    assert_eq!(usage.windows[1], original.windows[1]);
    assert_eq!(usage.credit_balances, original.credit_balances);
    for case in 0..4 {
        let mut usage = original.clone();
        let mut candidate = local();
        match case {
            0 => candidate[0].resets_at = rfc3339_from_unix_seconds(300),
            1 => candidate[0].window_seconds = Some(6 * 60 * 60),
            2 => candidate[0].observed_at = None,
            _ => candidate[0].observed_at = Some("2099-01-01T00:00:00Z".to_string()),
        }
        assert!(!prefer_newer_exact_claude_statusline_windows(
            &mut usage.windows,
            candidate
        ));
        assert_eq!(usage.windows, original.windows);
        assert_eq!(usage.credit_balances, original.credit_balances);
    }
    let mut conflicting_start = original.clone();
    conflicting_start.windows[0].started_at = rfc3339_from_unix_seconds(5);
    let before = conflicting_start.windows.clone();
    assert!(!prefer_newer_exact_claude_statusline_windows(
        &mut conflicting_start.windows,
        local()
    ));
    assert_eq!(conflicting_start.windows, before);
}

#[test]
fn prefer_newer_statusline_matches_whole_second_reset_against_microsecond_oauth_reset() {
    // OAuth carries microsecond resets; statusLine carries whole epoch
    // seconds. The same window must still match, and only that window.
    let reset_epoch: u64 = 1_790_961_600; // 2026-10-02T17:20:00Z
    let oauth_observed: u64 = reset_epoch - 8_400; // T = 15:00:00Z
    let oauth = || {
        let response = serde_json::json!({
            "five_hour": {"utilization": 40, "resets_at": "2026-10-02T17:20:00.123456Z"},
            "seven_day": {"utilization": 70, "resets_at": "2026-10-08T00:00:00.654321Z"}
        });
        let mut usage = ClaudeOAuthUsage {
            windows: claude_oauth_quota_windows(&response),
            credit_balances: claude_oauth_credit_balances(&response),
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        };
        claude_oauth_stamp_account_identity(&mut usage, "account-a", Some("org-a"));
        for window in &mut usage.windows {
            window.observed_at = rfc3339_from_unix_seconds(oauth_observed);
        }
        usage
    };
    let statusline = |account: &str, observed: u64, reset: u64| {
        claude_statusline_quota_windows_from_cache(
            ClaudeStatusLineRateLimitCache {
                schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
                observed_under_account_identifier_hash: account.to_string(),
                observed_under_organization_identifier_hash: Some("org-a".to_string()),
                observed_under_account_method: "session_store".to_string(),
                observed_at_epoch_seconds: observed,
                windows: vec![ClaudeStatusLineRateLimitWindow {
                    name: "five_hour".to_string(),
                    used_percent: 55,
                    resets_at_epoch_seconds: reset,
                }],
            },
            observed,
        )
    };
    let newer = oauth_observed + 20 * 60;

    let original = oauth();
    let mut usage = original.clone();
    assert!(prefer_newer_exact_claude_statusline_windows(
        &mut usage.windows,
        statusline("account-a", newer, reset_epoch)
    ));
    assert_eq!(usage.windows[0].used_percent, Some(55));
    assert_eq!(
        usage.windows[0].observed_at,
        rfc3339_from_unix_seconds(newer)
    );
    assert_eq!(usage.windows[0].started_at, original.windows[0].started_at);
    assert_eq!(usage.windows[1], original.windows[1]);

    // Counterexamples leave the OAuth reading untouched.
    let refused: Vec<Vec<AgentQuotaWindow>> = vec![
        // A different window: reset one minute (or two seconds) apart.
        statusline("account-a", newer, reset_epoch + 60),
        statusline("account-a", newer, reset_epoch + 2),
        // An older statusLine reading.
        statusline("account-a", oauth_observed - 20 * 60, reset_epoch),
        // A different account.
        statusline("account-b", newer, reset_epoch),
        // A statusLine reading taken after its own reset passed.
        {
            let mut past = statusline("account-a", newer, reset_epoch);
            past[0].observed_at = rfc3339_from_unix_seconds(reset_epoch + 600);
            past
        },
    ];
    for candidate in refused {
        let mut usage = original.clone();
        assert!(!prefer_newer_exact_claude_statusline_windows(
            &mut usage.windows,
            candidate
        ));
        assert_eq!(usage.windows, original.windows);
    }
    // A statusLine window already past its reset at serve time is dropped
    // before it can compete.
    assert!(statusline("account-a", reset_epoch + 1, reset_epoch).is_empty());
}

#[test]
fn claude_statusline_cache_maps_fresh_windows() {
    let cache = ClaudeStatusLineRateLimitCache {
        schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
        observed_under_account_identifier_hash: "account-a".to_string(),
        observed_under_organization_identifier_hash: None,
        observed_under_account_method: "config_dir".to_string(),
        observed_at_epoch_seconds: 100,
        windows: vec![
            ClaudeStatusLineRateLimitWindow {
                name: "five_hour".to_string(),
                used_percent: 24,
                resets_at_epoch_seconds: 200,
            },
            ClaudeStatusLineRateLimitWindow {
                name: "seven_day".to_string(),
                used_percent: 91,
                resets_at_epoch_seconds: 300,
            },
        ],
    };

    let windows = claude_statusline_quota_windows_from_cache(cache, 150);

    assert_eq!(windows.len(), 2);
    assert_eq!(windows[0].name, "session");
    assert_eq!(windows[0].scope, AgentQuotaWindowScope::Account);
    assert_eq!(windows[0].status, AgentQuotaWindowStatus::Ok);
    assert_eq!(windows[0].used_percent, Some(24));
    assert_eq!(windows[0].left_percent, Some(76));
    assert_eq!(windows[0].window_seconds, Some(5 * 60 * 60));
    assert_eq!(
        windows[0].observed_at.as_deref(),
        Some("1970-01-01T00:01:40Z")
    );
    assert_eq!(windows[1].name, "weekly");
    assert_eq!(windows[1].status, AgentQuotaWindowStatus::NearLimit);
    assert_eq!(windows[1].window_seconds, Some(7 * 24 * 60 * 60));
    // Every served statusLine window names the account whose credential
    // was active when the CLI writer observed it.
    assert_eq!(
        windows[0].account_identifier_hash.as_deref(),
        Some("account-a")
    );
    assert_eq!(
        windows[1].account_identifier_hash.as_deref(),
        Some("account-a")
    );
}

#[test]
fn claude_oauth_usage_stamps_served_windows_and_balances() {
    let mut usage = ClaudeOAuthUsage {
        windows: vec![
            AgentQuotaWindow {
                name: "session".to_string(),
                scope: AgentQuotaWindowScope::Account,
                ..Default::default()
            },
            AgentQuotaWindow {
                name: "weekly".to_string(),
                scope: AgentQuotaWindowScope::Account,
                ..Default::default()
            },
        ],
        credit_balances: vec![AgentCreditBalance {
            name: "Usage credits".to_string(),
            ..Default::default()
        }],
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };

    claude_oauth_stamp_account_identity(&mut usage, "account-hash", Some("org-hash"));

    for window in &usage.windows {
        assert_eq!(
            window.account_identifier_hash.as_deref(),
            Some("account-hash")
        );
        assert_eq!(
            window.organization_identifier_hash.as_deref(),
            Some("org-hash")
        );
    }
    assert_eq!(
        usage.credit_balances[0].account_identifier_hash.as_deref(),
        Some("account-hash")
    );
    assert_eq!(
        usage.credit_balances[0]
            .organization_identifier_hash
            .as_deref(),
        Some("org-hash")
    );

    // Negative control: an unresolved account stamps nothing -- unknown
    // must stay unknown downstream, never become a guessed identity.
    let mut unresolved = ClaudeOAuthUsage {
        windows: vec![AgentQuotaWindow {
            name: "session".to_string(),
            ..Default::default()
        }],
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };
    claude_oauth_stamp_account_identity(&mut unresolved, "", Some(""));
    assert_eq!(unresolved.windows[0].account_identifier_hash, None);
    assert_eq!(unresolved.windows[0].organization_identifier_hash, None);
}

#[test]
fn claude_exact_slot_auth_requires_positive_real_cli_field_agreement() {
    let oauth = ClaudeCliOauthAccount {
        account_uuid: Some("account-a".to_string()),
        email_address: Some("person@example.invalid".to_string()),
        organization_uuid: Some("organization-a".to_string()),
        ..Default::default()
    };
    let auth = AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        email: Some("person@example.invalid".to_string()),
        organization_id: Some("organization-a".to_string()),
        account_id: None,
        ..unsupported_account("anthropic")
    };
    assert_eq!(
        require_claude_auth_identity_agreement(&auth, &oauth),
        Ok(())
    );

    let missing_email = AgentAccountStatus {
        email: None,
        ..auth.clone()
    };
    assert_eq!(
        require_claude_auth_identity_agreement(&missing_email, &oauth),
        Err(ClaudeSlotProbeFailure::IdentityUnknown)
    );
    let missing_organization = AgentAccountStatus {
        organization_id: None,
        ..auth.clone()
    };
    assert_eq!(
        require_claude_auth_identity_agreement(&missing_organization, &oauth),
        Err(ClaudeSlotProbeFailure::IdentityUnknown)
    );
    let rotated_credential = AgentAccountStatus {
        email: Some("rotated@example.invalid".to_string()),
        organization_id: Some("organization-rotated".to_string()),
        ..auth
    };
    assert_eq!(
        require_claude_auth_identity_agreement(&rotated_credential, &oauth),
        Err(ClaudeSlotProbeFailure::IdentityMismatch)
    );
}

#[test]
fn claude_stale_same_account_fallback_is_uploadable_but_not_fresh() {
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-08-04T12:00:00Z".to_string(),
        "2026-08-04T12:15:00Z".to_string(),
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        account_identifier_hash: Some("account-hash".to_string()),
        organization_identifier_hash: Some("organization-hash".to_string()),
        ..unsupported_account("anthropic")
    });
    snapshot.quota_windows = vec![AgentQuotaWindow {
        name: "session".to_string(),
        freshness: AgentQuotaWindowFreshness::Stale,
        account_identifier_hash: Some("account-hash".to_string()),
        organization_identifier_hash: Some("organization-hash".to_string()),
        ..Default::default()
    }];
    snapshot.credit_balances = vec![AgentCreditBalance {
        name: "Usage credits".to_string(),
        freshness: AgentQuotaWindowFreshness::Stale,
        account_identifier_hash: Some("account-hash".to_string()),
        organization_identifier_hash: Some("organization-hash".to_string()),
        ..Default::default()
    }];

    assert!(claude_default_snapshot_is_uploadable(&snapshot));
    assert_eq!(
        claude_snapshot_candidate_rank(&snapshot).map(|quality| quality.tier),
        Some(1)
    );
    assert_eq!(
        claude_default_slot_collection_status(&snapshot).state,
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
    );
    assert!(
        !claude_slot_status_carries_meters(&claude_default_slot_collection_status(&snapshot)),
        "an exact stale bundle is replaced by a meterless degraded current witness"
    );

    snapshot.quota_windows.push(AgentQuotaWindow {
        name: "weekly".to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        account_identifier_hash: Some("account-hash".to_string()),
        organization_identifier_hash: None,
        ..Default::default()
    });
    assert!(
        !claude_default_snapshot_is_uploadable(&snapshot),
        "partial identity must not create a backend row"
    );
    assert_eq!(
        claude_default_slot_collection_status(&snapshot).state,
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
    );

    snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
    snapshot.quota_windows.truncate(1);
    snapshot.quota_windows[0].organization_identifier_hash = None;
    snapshot.credit_balances.clear();
    assert!(
        claude_default_snapshot_is_uploadable(&snapshot),
        "an attributed default statusLine partial remains uploadable"
    );
    assert_eq!(
        claude_snapshot_candidate_rank(&snapshot).map(|quality| quality.tier),
        Some(1),
        "stale statusLine meters are the stale-partial tier"
    );
    let partial = claude_default_slot_collection_status(&snapshot);
    assert_eq!(partial.state, ClaudeConfigSlotCollectionStateV1::Fresh);
    assert_eq!(
        projected_claude_quota_access_state(&partial),
        Some(ClaudeQuotaAccessState::Partial),
        "strongly bound statusLine meters remain an honest partial view"
    );
    assert!(claude_slot_status_carries_meters(&partial));
}

#[test]
fn claude_candidate_selection_prefers_anchor_only_on_equal_quality() {
    let candidate =
        |slot_id: &str, slot_class: ClaudeSnapshotSlotClass, rank: u8| ClaudeSnapshotCandidate {
            slot_id: slot_id.to_string(),
            slot_class,
            binding: ClaudeStrongBinding {
                account_identifier_hash: "account-a".to_string(),
                organization_identifier_hash: "organization-a".to_string(),
            },
            quality: ClaudeSnapshotQuality {
                tier: rank,
                provider_observed_at: "2026-08-23T00:00:00Z".to_string(),
            },
            snapshot: base_snapshot(
                SourceKind::ClaudeCode,
                AgentStatusState::Available,
                AgentStatusCollectionMethod::CliJson,
                "2026-08-23T00:00:00Z".to_string(),
                "2026-08-23T00:05:00Z".to_string(),
            ),
        };

    let equal = vec![
        candidate("default", ClaudeSnapshotSlotClass::Default, 3),
        candidate(
            "claude_slot_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ClaudeSnapshotSlotClass::Registered,
            3,
        ),
        candidate(
            "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ClaudeSnapshotSlotClass::Registered,
            3,
        ),
    ];
    let selected = select_claude_snapshot_candidates(&equal, &BTreeMap::new());
    let binding = ClaudeStrongBinding {
        account_identifier_hash: "account-a".to_string(),
        organization_identifier_hash: "organization-a".to_string(),
    };
    assert_eq!(selected.winning_by_binding[&binding], 2);
    assert_eq!(selected.preferred_anchor_by_binding[&binding], 2);
    assert_eq!(
        claude_snapshot_candidate_disposition(0, &equal[0], &selected),
        ClaudeSnapshotDisposition::ShadowDefault
    );
    assert_eq!(
        claude_snapshot_candidate_disposition(1, &equal[1], &selected),
        ClaudeSnapshotDisposition::DuplicateRegistered
    );
    assert_eq!(
        claude_snapshot_candidate_disposition(2, &equal[2], &selected),
        ClaudeSnapshotDisposition::Upload
    );

    let fresher_default = vec![
        candidate("default", ClaudeSnapshotSlotClass::Default, 3),
        candidate(
            "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ClaudeSnapshotSlotClass::Registered,
            2,
        ),
        candidate(
            "claude_slot_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ClaudeSnapshotSlotClass::Registered,
            2,
        ),
    ];
    let selected = select_claude_snapshot_candidates(&fresher_default, &BTreeMap::new());
    assert_eq!(selected.winning_by_binding[&binding], 0);
    assert_eq!(
        selected.preferred_anchor_by_binding[&binding], 1,
        "the preferred registered anchor remains stable while fresher default meters win"
    );
    assert_eq!(
        claude_snapshot_candidate_disposition(1, &fresher_default[1], &selected),
        ClaudeSnapshotDisposition::PreserveRegisteredAnchor
    );
    assert_eq!(
        claude_snapshot_candidate_disposition(2, &fresher_default[2], &selected),
        ClaudeSnapshotDisposition::DuplicateRegistered
    );

    let shadow = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        relationship: Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor),
        ..Default::default()
    };
    assert_eq!(
        shadow.relationship,
        Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor)
    );
    assert!(!shadow.has_account_windows);
    assert!(shadow.quota_snapshot.is_none());
    let duplicate =
        duplicate_account_status("2026-08-23T00:00:00Z", "account-a", Some("organization-a"));
    assert_eq!(
        duplicate.state,
        ClaudeConfigSlotCollectionStateV1::DuplicateAccount
    );
}

#[test]
fn claude_candidate_selection_keeps_same_account_under_two_organizations() {
    let candidate = |slot_id: &str, organization: &str| ClaudeSnapshotCandidate {
        slot_id: slot_id.to_string(),
        slot_class: ClaudeSnapshotSlotClass::Registered,
        binding: ClaudeStrongBinding {
            account_identifier_hash: "shared-account".to_string(),
            organization_identifier_hash: organization.to_string(),
        },
        quality: ClaudeSnapshotQuality {
            tier: 4,
            provider_observed_at: "2026-08-23T00:00:00Z".to_string(),
        },
        snapshot: base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-08-23T00:00:00Z".to_string(),
            "2026-08-23T00:05:00Z".to_string(),
        ),
    };
    let candidates = vec![
        candidate(
            "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "organization-a",
        ),
        candidate(
            "claude_slot_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "organization-b",
        ),
    ];
    let selected = select_claude_snapshot_candidates(&candidates, &BTreeMap::new());
    assert_eq!(selected.winning_by_binding.len(), 2);
    assert_eq!(selected.preferred_anchor_by_binding.len(), 2);
}

#[test]
fn identical_full_meters_under_different_accounts_quarantine_the_mutable_default() {
    let candidate = |slot_id: &str,
                     slot_class: ClaudeSnapshotSlotClass,
                     account: &str,
                     organization: &str,
                     weekly_used: u8| {
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-09-21T11:00:00Z".to_string(),
            "2026-09-21T11:15:00Z".to_string(),
        );
        snapshot.account = Some(AgentAccountStatus {
            account_identifier_hash: Some(account.to_string()),
            organization_identifier_hash: Some(organization.to_string()),
            ..unsupported_account("anthropic")
        });
        snapshot.quota_windows = [
            ("session", AgentQuotaWindowScope::Account, 2),
            ("weekly", AgentQuotaWindowScope::Account, weekly_used),
            ("fable", AgentQuotaWindowScope::Model, 100),
        ]
        .into_iter()
        .map(|(name, scope, used_percent)| AgentQuotaWindow {
            name: name.to_string(),
            scope,
            status: if used_percent == 100 {
                AgentQuotaWindowStatus::Exhausted
            } else {
                AgentQuotaWindowStatus::Ok
            },
            freshness: AgentQuotaWindowFreshness::Fresh,
            observed_at: Some("2026-09-21T10:42:00Z".to_string()),
            account_identifier_hash: Some(account.to_string()),
            organization_identifier_hash: Some(organization.to_string()),
            resets_at: Some("2026-09-26T04:59:00Z".to_string()),
            used_percent: Some(used_percent),
            left_percent: Some(100 - used_percent),
            ..Default::default()
        })
        .collect();
        ClaudeSnapshotCandidate {
            slot_id: slot_id.to_string(),
            slot_class,
            binding: ClaudeStrongBinding {
                account_identifier_hash: account.to_string(),
                organization_identifier_hash: organization.to_string(),
            },
            quality: ClaudeSnapshotQuality {
                tier: 4,
                provider_observed_at: "2026-09-21T10:42:00Z".to_string(),
            },
            snapshot,
        }
    };

    let default = candidate(
        "default",
        ClaudeSnapshotSlotClass::Default,
        "acme-account",
        "acme-org",
        96,
    );
    let registered = candidate(
        "claude_slot_gmail",
        ClaudeSnapshotSlotClass::Registered,
        "gmail-account",
        "gmail-org",
        96,
    );
    assert_eq!(
        claude_cross_binding_meter_collisions(&[default, registered]),
        BTreeSet::from(["default".to_string()]),
        "the durable account keeps the reading; the mutable login cannot borrow it"
    );

    let distinct_default = candidate(
        "default",
        ClaudeSnapshotSlotClass::Default,
        "acme-account",
        "acme-org",
        12,
    );
    let distinct_registered = candidate(
        "claude_slot_gmail",
        ClaudeSnapshotSlotClass::Registered,
        "gmail-account",
        "gmail-org",
        96,
    );
    assert!(
        claude_cross_binding_meter_collisions(&[distinct_default, distinct_registered]).is_empty()
    );

    let current = candidate(
        "claude_slot_gmail",
        ClaudeSnapshotSlotClass::Registered,
        "gmail-account",
        "gmail-org",
        96,
    );
    let stale_copy = stale_local_claude_quota_snapshot(&local_claude_quota_snapshot(
        &current.snapshot.captured_at,
        &current.snapshot.quota_windows,
        &current.snapshot.credit_balances,
        true,
        true,
    ));
    let stale_states = BTreeMap::from([(
        "default".to_string(),
        ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            account_identifier_hash: Some("acme-account".to_string()),
            organization_identifier_hash: Some("acme-org".to_string()),
            quota_snapshot: Some(stale_copy),
            ..Default::default()
        },
    )]);
    assert_eq!(
        claude_stale_cross_binding_meter_collisions(&[current], &stale_states),
        BTreeSet::from(["default".to_string()]),
        "a retained copy must not survive under another account"
    );

    let different_current = candidate(
        "claude_slot_gmail",
        ClaudeSnapshotSlotClass::Registered,
        "gmail-account",
        "gmail-org",
        12,
    );
    assert!(
        claude_stale_cross_binding_meter_collisions(&[different_current], &stale_states).is_empty(),
        "different retained values remain valid account history"
    );

    let mut state = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        last_full_quota_read_at: Some("2026-09-21T10:42:00Z".to_string()),
        has_account_windows: true,
        has_scoped_limits: true,
        quota_snapshot: Some(ClaudeConfigSlotQuotaSnapshotV1 {
            state: ClaudeConfigSlotQuotaSnapshotStateV1::Fresh,
            captured_at: "2026-09-21T11:00:00Z".to_string(),
            observed_at: Some("2026-09-21T10:42:00Z".to_string()),
            quota_windows: Vec::new(),
            credit_balances: Vec::new(),
        }),
        ..Default::default()
    };
    quarantine_claude_cross_account_meters(&mut state);
    assert_eq!(
        state.state,
        ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    );
    assert!(state.quota_snapshot.is_none());
    assert!(!state.has_account_windows);
    assert!(!state.has_scoped_limits);
}

#[test]
fn fresh_default_meters_do_not_hide_broken_registered_anchor_health() {
    let binding = ClaudeStrongBinding {
        account_identifier_hash: "account-a".to_string(),
        organization_identifier_hash: "organization-a".to_string(),
    };
    let slot_id = "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let slot_states = BTreeMap::from([(
        slot_id.clone(),
        ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::NeedsLogin,
            account_identifier_hash: Some(binding.account_identifier_hash.clone()),
            organization_identifier_hash: Some(binding.organization_identifier_hash.clone()),
            observed_at: Some("2026-08-23T00:00:00Z".to_string()),
            ..Default::default()
        },
    )]);
    let canonical = canonical_registered_anchors([slot_id], &slot_states);
    let health = canonical_anchor_health(&canonical, &slot_states);
    assert_eq!(
        health.get(&binding),
        Some(&Some(ClaudeAccountAnchorHealthV1::ReconnectRequired))
    );
    let mut default_snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-08-23T00:01:00Z".to_string(),
        "2026-08-23T00:06:00Z".to_string(),
    );
    default_snapshot.account = Some(AgentAccountStatus {
        account_identifier_hash: Some(binding.account_identifier_hash),
        organization_identifier_hash: Some(binding.organization_identifier_hash),
        ..unsupported_account("anthropic")
    });
    apply_claude_anchor_continuity(
        &mut default_snapshot,
        ClaudeAccountAnchorDurabilityV1::Anchored,
        *health.values().next().expect("anchor health"),
    );
    assert_eq!(
        default_snapshot
            .account
            .as_ref()
            .and_then(|account| account.claude_anchor_durability),
        Some(ClaudeAccountAnchorDurabilityV1::Anchored)
    );
    assert_eq!(
        default_snapshot
            .account
            .as_ref()
            .and_then(|account| account.claude_anchor_health),
        Some(ClaudeAccountAnchorHealthV1::ReconnectRequired)
    );
}

#[test]
fn claude_anchor_projection_supports_five_accounts_and_default_switching() {
    let collection = |account: &str, organization: &str| ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some(account.to_string()),
        organization_identifier_hash: Some(organization.to_string()),
        observed_at: Some("2026-08-23T00:00:00Z".to_string()),
        last_full_quota_read_at: Some("2026-08-23T00:00:00Z".to_string()),
        has_account_windows: true,
        has_scoped_limits: true,
        ..Default::default()
    };
    let mut managed_slots = (0..5)
        .map(|index| {
            let mut slot = test_slot_descriptor(index);
            slot.ownership = ClaudeConfigSlotOwnership::Managed;
            slot.collection = collection(
                &format!("account-{index}"),
                &format!("organization-{index}"),
            );
            slot
        })
        .collect::<Vec<_>>();
    managed_slots.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    let mut status = ClaudeAccountsStatusV1 {
        schema_version: 1,
        consent: ottto_protocol::ClaudeAccountUpkeepConsentState::Granted,
        setup_operation: ottto_protocol::ClaudeAccountSetupOperationV1 {
            kind: ottto_protocol::ClaudeAccountSetupOperationKind::ConnectManagedAccount,
            state: ottto_protocol::ClaudeAccountSetupOperationState::Idle,
            operation_id: None,
            slot_id: None,
            target_id: None,
            expected_account_identifier_hash: None,
            expected_organization_identifier_hash: None,
            account_identifier_hash: None,
            organization_identifier_hash: None,
            launch_command: None,
            browser_auth: None,
            message: None,
        },
        default_slot: ClaudeConfigDirSlot::Default
            .descriptor("default", ClaudeConfigSlotOwnership::External),
        managed_slots,
        external_slots: Vec::new(),
        unresolved_accounts: Vec::new(),
        anchor_coverage: ClaudeAccountAnchorCoverageV1::default(),
        anchor_transitions: Vec::new(),
        capacity: ottto_protocol::ClaudeAccountCapacityV1 {
            max_slots: 10,
            used_slots: 6,
            remaining_slots: 4,
        },
        browser_auth_supported: None,
        auth_code_entry_supported: None,
        retained_provisional_login_count: None,
        consent_covers_limit_reads: None,
    };

    for switched_to in [0, 1, 4, 2, 0] {
        status.default_slot.collection = collection(
            &format!("account-{switched_to}"),
            &format!("organization-{switched_to}"),
        );
        let coverage = derive_claude_account_anchor_coverage(&status);
        assert_eq!(coverage.observed_accounts, 5);
        assert_eq!(coverage.anchored_accounts, 5);
        assert_eq!(coverage.default_only_accounts, 0);
        assert_eq!(coverage.unresolved_accounts, 0);
        assert_eq!(coverage.capacity_blocked_accounts, 0);
        assert!(coverage
            .accounts
            .iter()
            .all(|account| account.durability == ClaudeAccountAnchorDurabilityV1::Anchored));
    }

    status.default_slot.collection = collection("account-5", "organization-5");
    let coverage = derive_claude_account_anchor_coverage(&status);
    assert_eq!(coverage.observed_accounts, 6);
    assert_eq!(coverage.anchored_accounts, 5);
    assert_eq!(coverage.default_only_accounts, 1);
    assert_eq!(
        coverage
            .accounts
            .iter()
            .find(|account| account.account_identifier_hash == "account-5")
            .map(|account| account.durability),
        Some(ClaudeAccountAnchorDurabilityV1::DefaultOnly)
    );

    status.capacity.remaining_slots = 0;
    let coverage = derive_claude_account_anchor_coverage(&status);
    assert_eq!(coverage.default_only_accounts, 1);
    assert_eq!(coverage.capacity_blocked_accounts, 1);

    // An exact Desktop pair without full limits is a target of its own:
    // the target-bound login then expects that account AND organization.
    // A pair that is already anchored stays the anchor.
    status.capacity.remaining_slots = 4;
    let desktop_pair = |account: &str, organization: &str| ClaudeUnresolvedAccountDescriptorV1 {
        unresolved_id: format!("claude-unresolved-{account}-{organization}"),
        account_identifier_hash: Some(account.to_string()),
        organization_identifier_hash: Some(organization.to_string()),
        account_label: None,
        organization_label: None,
        observed_at: Some("2026-08-23T00:00:00Z".to_string()),
        evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
    };
    // Two organizations of one account are two targets; an account-only
    // row keeps today's shape: no organization, no target, ambiguous.
    status.unresolved_accounts = vec![
        desktop_pair("account-1", "organization-desktop"),
        desktop_pair("account-1", "organization-desktop-2"),
        desktop_pair("account-0", "organization-0"),
        ClaudeUnresolvedAccountDescriptorV1 {
            organization_identifier_hash: None,
            ..desktop_pair("account-legacy", "unused")
        },
    ];
    let coverage = derive_claude_account_anchor_coverage(&status);
    assert_eq!(coverage.observed_accounts, 9);
    assert_eq!(coverage.anchored_accounts, 5);
    assert_eq!(coverage.unresolved_accounts, 3);
    assert_eq!(coverage.ambiguous_identity_accounts, 1);
    let legacy = coverage
        .accounts
        .iter()
        .find(|account| account.account_identifier_hash == "account-legacy")
        .expect("account-only row");
    assert_eq!(legacy.target_id, None);
    assert_eq!(legacy.organization_identifier_hash, None);
    assert_eq!(
        legacy.setup_blockers,
        vec![ClaudeAccountAnchorSetupBlockerV1::AmbiguousIdentity]
    );
    let second = ClaudeStrongBinding::new("account-1", "organization-desktop-2").expect("binding");
    let pair_targets = coverage
        .accounts
        .iter()
        .filter(|account| account.account_identifier_hash == "account-1")
        .filter(|account| account.durability == ClaudeAccountAnchorDurabilityV1::Unresolved)
        .map(|account| account.target_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(pair_targets.len(), 2);
    assert!(pair_targets.contains(&Some(claude_anchor_target_id(&second))));
    let exact = ClaudeStrongBinding::new("account-1", "organization-desktop").expect("binding");
    let target = coverage
        .accounts
        .iter()
        .find(|account| {
            account.organization_identifier_hash.as_deref() == Some("organization-desktop")
        })
        .expect("exact desktop pair target");
    assert_eq!(
        target.durability,
        ClaudeAccountAnchorDurabilityV1::Unresolved
    );
    assert_eq!(target.target_id, Some(claude_anchor_target_id(&exact)));
    assert_eq!(target.health, None);
    assert!(target.setup_blockers.is_empty());
    // No slot left: a pair target is blocked, never silently connectable.
    status.capacity.remaining_slots = 0;
    let coverage = derive_claude_account_anchor_coverage(&status);
    for account in coverage.accounts.iter().filter(|account| {
        account.durability == ClaudeAccountAnchorDurabilityV1::Unresolved
            && account.target_id.is_some()
    }) {
        assert_eq!(
            account.setup_blockers,
            vec![ClaudeAccountAnchorSetupBlockerV1::CapacityReached]
        );
    }
}

#[test]
fn claude_anchor_transition_ledger_is_bounded_and_secret_free() {
    let previous = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some("account-secret-a".to_string()),
        organization_identifier_hash: Some("organization-secret-a".to_string()),
        observed_at: Some("2026-08-23T00:00:00Z".to_string()),
        ..Default::default()
    };
    let current = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some("account-secret-b".to_string()),
        organization_identifier_hash: Some("organization-secret-b".to_string()),
        relationship: Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor),
        observed_at: Some("2026-08-23T00:01:00Z".to_string()),
        ..Default::default()
    };
    let mut transitions = Vec::new();
    record_claude_anchor_transitions(&mut transitions, "default", Some(&previous), &current);
    assert!(transitions.iter().any(|transition| {
        transition.kind
            == ottto_protocol::ClaudeAccountAnchorTransitionKindV1::DefaultIdentityChanged
    }));
    assert!(transitions.iter().any(|transition| {
        transition.kind
            == ottto_protocol::ClaudeAccountAnchorTransitionKindV1::DefaultShadowObserved
    }));
    let wire = serde_json::to_string(&transitions).expect("serialize transitions");
    for forbidden in [
        "account-secret",
        "organization-secret",
        "config_dir",
        "access_token",
        "refresh_token",
    ] {
        assert!(!wire.contains(forbidden), "ledger leaked {forbidden}");
    }

    let bound = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some("same-account".to_string()),
        organization_identifier_hash: Some("same-organization".to_string()),
        ..Default::default()
    };
    for second in 0..80 {
        let mut observed = bound.clone();
        observed.observed_at = Some(format!("2026-08-23T00:{:02}:00Z", second % 60));
        record_claude_anchor_transitions(
            &mut transitions,
            "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some(&bound),
            &observed,
        );
    }
    assert_eq!(transitions.len(), 64);
}

#[test]
fn claude_statusline_cache_marks_old_windows_stale() {
    let cache = ClaudeStatusLineRateLimitCache {
        schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
        observed_under_account_identifier_hash: "account-a".to_string(),
        observed_under_organization_identifier_hash: None,
        observed_under_account_method: "config_dir".to_string(),
        observed_at_epoch_seconds: 100,
        windows: vec![ClaudeStatusLineRateLimitWindow {
            name: "five_hour".to_string(),
            used_percent: 24,
            resets_at_epoch_seconds: 2_000,
        }],
    };

    let windows = claude_statusline_quota_windows_from_cache(
        cache,
        100 + CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS + 1,
    );

    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].name, "session");
    assert_eq!(windows[0].status, AgentQuotaWindowStatus::Stale);
    assert_eq!(windows[0].freshness, AgentQuotaWindowFreshness::Stale);
    assert_eq!(windows[0].used_percent, Some(24));
    assert_eq!(windows[0].left_percent, Some(76));
}

#[test]
fn claude_statusline_context_never_downgrades_full_oauth_quota_provenance() {
    let mut full = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-08-05T01:00:00Z".to_string(),
        "2026-08-05T01:15:00Z".to_string(),
    );
    apply_claude_statusline_context_provenance(&mut full, true);
    assert_eq!(full.collection_method, AgentStatusCollectionMethod::CliJson);

    let mut partial = full;
    apply_claude_statusline_context_provenance(&mut partial, false);
    assert_eq!(
        partial.collection_method,
        AgentStatusCollectionMethod::StatusLine
    );
}

#[test]
fn claude_statusline_context_cache_maps_live_context() {
    let cache = ClaudeStatusLineContextWindowCache {
        schema_version: 1,
        observed_at_epoch_seconds: 100,
        active_tokens: Some(42_000),
        max_tokens: Some(1_000_000),
        used_percent: Some(4),
        remaining_tokens: Some(958_000),
    };

    let context = claude_statusline_context_from_cache(cache, None);

    assert_eq!(context.status, AgentContextState::Available);
    assert_eq!(context.active_tokens, Some(42_000));
    assert_eq!(context.max_tokens, Some(1_000_000));
    assert_eq!(context.used_percent, Some(4));
    assert_eq!(context.remaining_tokens, Some(958_000));
    assert_eq!(
        context.completeness,
        Some(AgentContextCompleteness::FullPressure)
    );
    assert_eq!(context.reason.as_deref(), Some("full_pressure_observed"));
    assert_eq!(
        context.source.as_deref(),
        Some("claude_statusline_context_window")
    );
}

#[test]
fn claude_statusline_context_cache_normalizes_legacy_zero_sentinel() {
    let now = current_unix_seconds();
    let cache = ClaudeStatusLineContextWindowCache {
        schema_version: 1,
        observed_at_epoch_seconds: now,
        active_tokens: Some(0),
        max_tokens: Some(1_000_000),
        used_percent: None,
        remaining_tokens: Some(1_000_000),
    };
    let history = ClaudeStatusLineContextWindowHistory {
        schema_version: 1,
        samples: vec![ClaudeStatusLineContextWindowSample {
            observed_at_epoch_seconds: now.saturating_sub(60),
            active_tokens: Some(0),
            max_tokens: Some(1_000_000),
            used_percent: None,
            remaining_tokens: Some(1_000_000),
        }],
    };

    let context = claude_statusline_context_from_cache(cache, Some(history));

    assert_eq!(context.status, AgentContextState::Available);
    assert_eq!(context.active_tokens, None);
    assert_eq!(context.max_tokens, Some(1_000_000));
    assert_eq!(context.used_percent, None);
    assert_eq!(context.remaining_tokens, None);
    assert_eq!(
        context.completeness,
        Some(AgentContextCompleteness::WindowSizeOnly)
    );
    assert_eq!(context.reason.as_deref(), Some("context_window_size_only"));
    assert!(context.recent_samples.is_empty());
}

#[test]
fn secret_keys_are_removed_from_pi_metadata() {
    let stripped = strip_secret_json(serde_json::json!({
        "email": "pi@example.com",
        "api_key": "secret",
        "nested": {"refresh_token": "secret", "org": "team"}
    }));

    assert_eq!(
        first_json_string(&stripped, &["email"]).as_deref(),
        Some("pi@example.com")
    );
    assert!(first_json_string(&stripped, &["api_key", "refresh_token"]).is_none());
    assert_eq!(
        first_json_string(&stripped, &["org"]).as_deref(),
        Some("team")
    );
}

#[test]
fn pi_model_table_parser_preserves_provider_billing_and_capabilities() {
    let output = CommandOutput {
        command_found: true,
        success: true,
        status_code: Some(0),
        stdout: String::new(),
        stderr: "\
provider        model                                  context  max-out  thinking  images
openai-codex    gpt-5.4-mini                           272K     128K     yes       yes
google-vertex   gemini-2.5-flash-lite                  1.0M     65.5K    yes       yes
amazon-bedrock  global.anthropic.claude-sonnet-4-6     1M       64K      yes       yes
"
        .to_string(),
    };

    let model_status = collect_pi_model_status_from_output(&output, None);

    assert_eq!(model_status.provider.as_deref(), Some("multi_provider"));
    assert_eq!(model_status.available_models.len(), 3);
    assert_eq!(model_status.available_model_details.len(), 3);
    assert_eq!(
        model_status.available_model_details[0]
            .billing_provider
            .as_deref(),
        Some("openai")
    );
    assert_eq!(
        model_status.available_model_details[1]
            .billing_provider
            .as_deref(),
        Some("google")
    );
    assert_eq!(
        model_status.available_model_details[2]
            .billing_provider
            .as_deref(),
        Some("anthropic")
    );
    assert_eq!(
        model_status.available_model_details[0]
            .source_category
            .as_deref(),
        Some("chatgpt_openai_subscription")
    );
    assert_eq!(
        model_status.available_model_details[1]
            .source_category
            .as_deref(),
        Some("google_cloud_vertex")
    );
    assert_eq!(
        model_status.available_model_details[2]
            .model_provider
            .as_deref(),
        Some("anthropic")
    );
    assert_eq!(
        model_status.available_model_details[0].context_window_tokens,
        Some(272_000)
    );
    assert_eq!(
        model_status.available_model_details[1].max_output_tokens,
        Some(65_500)
    );
    assert_eq!(
        model_status.available_model_details[2]
            .billing_channel
            .as_deref(),
        Some("amazon_bedrock")
    );
    assert_eq!(
        model_status.available_model_details[2].supports_images,
        Some(true)
    );
}

#[test]
fn pi_settings_parser_prefers_enabled_default_route() {
    let settings = serde_json::json!({
        "defaultProvider": "openai-codex",
        "defaultModel": "gpt-5.4-mini",
        "defaultThinkingLevel": "high",
        "enabledModels": [
            {"provider": "openai-codex", "model": "gpt-5.4-mini"},
            {"provider": "google-vertex", "model": "gemini-2.5-flash-lite"},
            "amazon-bedrock/global.anthropic.claude-sonnet-4-6"
        ]
    });

    let model_status = collect_pi_model_status_from_settings(&settings, None);

    assert_eq!(model_status.active_model.as_deref(), Some("gpt-5.4-mini"));
    assert_eq!(model_status.default_model.as_deref(), Some("gpt-5.4-mini"));
    assert_eq!(model_status.provider.as_deref(), Some("multi_provider"));
    assert_eq!(model_status.available_model_details.len(), 3);
    assert_eq!(
        model_status.available_model_details[0].provider.as_deref(),
        Some("openai-codex")
    );
    assert_eq!(
        model_status.available_model_details[0].supports_thinking,
        Some(true)
    );
    assert_eq!(
        model_status.available_model_details[2]
            .billing_channel
            .as_deref(),
        Some("amazon_bedrock")
    );

    let routes = collect_pi_routes_from_settings(&settings);
    assert_eq!(routes.len(), 3);
    assert_eq!(routes[0].provider, "openai-codex");
    assert_eq!(routes[0].thinking_level.as_deref(), Some("high"));
    assert_eq!(
        routes[1].classification.source_category.as_deref(),
        Some("google_cloud_vertex")
    );
}

/// [behaviour] Pi's agent directory as Pi resolves it: an empty or unset
/// override is the default, the value is taken as written (no trim), and
/// a leading `~` is the home directory.
#[test]
fn pi_agent_dir_follows_pis_own_override_rule() {
    let home = Path::new("/home/user");
    let dir = |value: Option<&str>| pi_agent_dir_from(home, value.map(Into::into));
    assert_eq!(dir(None), home.join(".pi/agent"));
    assert_eq!(dir(Some("")), home.join(".pi/agent"));
    assert_eq!(dir(Some("/abs/pi")), PathBuf::from("/abs/pi"));
    assert_eq!(dir(Some(" /abs/pi ")), PathBuf::from(" /abs/pi "));
    assert_eq!(dir(Some("~")), home.to_path_buf());
    assert_eq!(dir(Some("~/alt/pi")), home.join("alt/pi"));
    assert_eq!(dir(Some("~alt")), PathBuf::from("~alt"));
    assert_eq!(dir(Some("rel/pi")), PathBuf::from("rel/pi"));
}

/// [behaviour] Every named platform keeps its route; an unnamed provider
/// is a direct API key route billed by that provider.
#[test]
fn pi_route_classifier_maps_supported_platforms() {
    let other = pi_route_classification("Mistral", "mistral-large");
    assert_eq!(other.billing_channel.as_deref(), Some("direct_api"));
    assert_eq!(other.billing_provider.as_deref(), Some("mistral"));
    assert_eq!(other.auth_mode.as_deref(), Some("api_key"));

    let openai = pi_route_classification("openai", "gpt-5.4-mini");
    assert_eq!(openai.source_category.as_deref(), Some("openai_api_key"));
    assert_eq!(openai.auth_mode.as_deref(), Some("api_key"));

    let codex_subscription = pi_route_classification("OpenAI Codex", "gpt-5.5");
    assert_eq!(
        codex_subscription.billing_channel.as_deref(),
        Some("subscription")
    );
    assert_eq!(codex_subscription.auth_mode.as_deref(), Some("oauth"));
    assert_eq!(
        codex_subscription.source_category.as_deref(),
        Some("chatgpt_openai_subscription")
    );

    let vertex = pi_route_classification("google-vertex", "gemini-2.5-flash-lite");
    assert_eq!(vertex.billing_channel.as_deref(), Some("google_vertex"));
    assert_eq!(
        vertex.source_category.as_deref(),
        Some("google_cloud_vertex")
    );

    let display_vertex = pi_route_classification("Google Vertex", "gemini-3.1-pro-preview");
    assert_eq!(
        display_vertex.billing_channel.as_deref(),
        Some("google_vertex")
    );
    assert_eq!(display_vertex.auth_mode.as_deref(), Some("service_account"));
    assert_eq!(
        display_vertex.source_category.as_deref(),
        Some("google_cloud_vertex")
    );

    let bedrock = pi_route_classification("amazon-bedrock", "global.anthropic.claude-sonnet-4-6");
    assert_eq!(bedrock.billing_provider.as_deref(), Some("anthropic"));
    assert_eq!(bedrock.source_category.as_deref(), Some("aws_bedrock"));

    let gateway = pi_route_classification("vercel-ai-gateway", "openai.gpt-5.4-mini");
    assert_eq!(gateway.billing_channel.as_deref(), Some("gateway"));
    assert_eq!(
        gateway.gateway_provider.as_deref(),
        Some("vercel_ai_gateway")
    );
}

fn claude_settings_fixture(name: &str, body: &str) -> (PathBuf, Vec<(String, PathBuf)>) {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-runtime-defaults-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let claude_dir = root.join(".claude");
    std::fs::create_dir_all(&claude_dir).expect("create .claude");
    if !body.is_empty() {
        std::fs::write(claude_dir.join("settings.json"), body).expect("write settings");
    }
    let paths = vec![
        (
            "claude_code.settings".to_string(),
            claude_dir.join("settings.json"),
        ),
        (
            "claude_code.settings_local".to_string(),
            claude_dir.join("settings.local.json"),
        ),
        (
            "claude_code.managed_settings".to_string(),
            root.join("managed-settings.json"),
        ),
    ];
    (root, paths)
}

#[test]
fn claude_runtime_defaults_carry_config_file_provenance() {
    let (root, paths) = claude_settings_fixture(
        "provenance",
        "{\"model\": \"claude-opus-4-7\", \"permissions\": {\"defaultMode\": \"plan\"}}\n",
    );

    let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &paths);
    let defaults = capture.defaults.expect("runtime defaults present");
    assert_eq!(defaults.provenance.as_deref(), Some("config_file"));
    // The backend fills machine_id from the stored snapshot.
    assert_eq!(defaults.machine_id, None);
    assert_eq!(
        defaults.captured_at.as_deref(),
        Some("2026-07-25T10:00:00Z")
    );
    assert_eq!(defaults.model.as_deref(), Some("claude-opus-4-7"));
    assert_eq!(defaults.approval_policy.as_deref(), Some("plan"));
    assert_eq!(capture.capability.capability, "runtime_defaults");
    assert_eq!(capture.capability.status, AgentCapabilityStatus::Supported);
    assert!(capture.diagnostic.is_none());

    // The strict backend schema must accept what we emit unchanged.
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-07-25T10:00:00Z".to_string(),
        "2026-07-25T10:05:00Z".to_string(),
    );
    snapshot.runtime_defaults = Some(defaults);
    let redacted = snapshot.redacted_for_backend();
    let survived = redacted.runtime_defaults.expect("survives redaction");
    assert_eq!(survived.model.as_deref(), Some("claude-opus-4-7"));
    assert_eq!(survived.approval_policy.as_deref(), Some("plan"));

    let _ = std::fs::remove_dir_all(root);
}

/// Claude Code's legacy top-level `effortLevel` still maps straight through
/// to `reasoning_effort` when no `modelSettings` entry applies. Current
/// `/effort` saves per model; see the `modelSettings` tests in snapshots.
#[test]
fn claude_runtime_defaults_report_configured_effort_level() {
    let (root, paths) = claude_settings_fixture(
        "effort-level",
        "{\"model\": \"claude-opus-4-7\", \"effortLevel\": \"xhigh\"}\n",
    );

    let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &paths);
    let defaults = capture.defaults.expect("runtime defaults present");
    assert_eq!(defaults.reasoning_effort.as_deref(), Some("xhigh"));
    assert_eq!(
        defaults
            .selector_sources
            .get("reasoning_effort")
            .map(String::as_str),
        Some("claude_code.settings.effortLevel")
    );
    // The Codex-shaped tier fields Claude's settings have no equivalent for
    // stay unset.
    assert_eq!(defaults.service_tier, None);
    assert_eq!(defaults.speed_mode, None);
    assert_eq!(defaults.priority_enabled, None);

    // The emitted effort value must survive the backend-facing guard.
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-07-25T10:00:00Z".to_string(),
        "2026-07-25T10:05:00Z".to_string(),
    );
    snapshot.runtime_defaults = Some(defaults);
    let survived = snapshot
        .redacted_for_backend()
        .runtime_defaults
        .expect("survives redaction");
    assert_eq!(survived.reasoning_effort.as_deref(), Some("xhigh"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn claude_runtime_defaults_report_fast_off_for_readable_settings_only() {
    let (configured_root, configured_paths) =
        claude_settings_fixture("not-configured", "{\"agentPushNotifEnabled\": true}\n");
    let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &configured_paths);
    let defaults = capture
        .defaults
        .expect("readable settings report the Fast default");
    assert_eq!(defaults.fast_mode_enabled, Some(false));
    assert_eq!(defaults.model, None);
    assert_eq!(
        defaults
            .selector_sources
            .get("fast_mode_enabled")
            .map(String::as_str),
        Some("claude_code.default.fastMode")
    );
    assert_eq!(capture.capability.status, AgentCapabilityStatus::Supported);
    assert!(capture.diagnostic.is_none());
    let _ = std::fs::remove_dir_all(configured_root);

    let (missing_root, missing_paths) = claude_settings_fixture("unreadable", "");
    let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &missing_paths);
    assert!(capture.defaults.is_none());
    assert_eq!(
        capture.diagnostic.as_ref().map(|entry| entry.code.as_str()),
        Some("claude_runtime_defaults_unreadable")
    );
    let _ = std::fs::remove_dir_all(missing_root);
}

#[test]
fn ottto_user_agent_identifies_honestly() {
    let user_agent = ottto_user_agent();
    assert!(
        user_agent.starts_with("ottto/"),
        "usage reads must identify as ottto, got {user_agent}"
    );
    assert!(user_agent.contains("subscription-usage-reader"));
    assert!(
        !user_agent.to_ascii_lowercase().contains("claude"),
        "never present a claude-* client identity: {user_agent}"
    );
}

#[test]
fn claude_quota_access_projection_is_strongly_bound_and_fail_closed() {
    let mut full = fresh_slot_status(
        "2026-08-12T10:00:00Z",
        "account-hash",
        "organization-hash",
        true,
        true,
        false,
    );
    assert_eq!(
        projected_claude_quota_access_state(&full),
        Some(ClaudeQuotaAccessState::Full)
    );
    full.has_scoped_limits = false;
    assert_eq!(
        projected_claude_quota_access_state(&full),
        Some(ClaudeQuotaAccessState::Partial)
    );

    full.state = ClaudeConfigSlotCollectionStateV1::ConcurrentMutation;
    assert_eq!(
        projected_claude_quota_access_state(&full),
        Some(ClaudeQuotaAccessState::TemporarilyUnavailable),
        "a concurrent login mutation retries from stable state"
    );
    full.state = ClaudeConfigSlotCollectionStateV1::CredentialUnavailable;
    assert_eq!(
        projected_claude_quota_access_state(&full),
        Some(ClaudeQuotaAccessState::AttentionRequired),
        "an ambiguous credential failure must not claim reconnect is sufficient"
    );
    full.upkeep = Some(ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
        result: ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
        due_access_expires_at: None,
        refresh_token_expires_at: None,
        attempted_at: None,
        next_allowed_attempt_at: None,
        consecutive_failures: 0,
    });
    assert_eq!(
        projected_claude_quota_access_state(&full),
        Some(ClaudeQuotaAccessState::AttentionRequired),
        "unreadable metadata does not prove that login is the remedy"
    );

    full.state = ClaudeConfigSlotCollectionStateV1::NeedsLogin;
    full.upkeep.as_mut().expect("upkeep").result = ClaudeConfigSlotUpkeepResultV1::NeedsLogin;
    assert_eq!(
        projected_claude_quota_access_state(&full),
        Some(ClaudeQuotaAccessState::ReconnectRequired),
        "only explicit absolute login expiry is reconnect-required"
    );

    full.state = ClaudeConfigSlotCollectionStateV1::ProbeFailed;
    full.upkeep.as_mut().expect("upkeep").result = ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled;
    assert_eq!(
        projected_claude_quota_access_state(&full),
        Some(ClaudeQuotaAccessState::Paused)
    );
    full.upkeep.as_mut().expect("upkeep").result = ClaudeConfigSlotUpkeepResultV1::MissingBinary;
    assert_eq!(
        projected_claude_quota_access_state(&full),
        Some(ClaudeQuotaAccessState::AttentionRequired)
    );

    full.organization_identifier_hash = None;
    assert_eq!(projected_claude_quota_access_state(&full), None);
}

#[test]
fn claude_quota_access_projection_marks_capability_without_guessing_account_state() {
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-08-12T10:00:00Z".to_string(),
        "2026-08-12T10:05:00Z".to_string(),
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        account_identifier_hash: Some("account-hash".to_string()),
        organization_identifier_hash: Some("organization-hash".to_string()),
        ..unsupported_account("anthropic")
    });
    let full = fresh_slot_status(
        "2026-08-12T10:00:00Z",
        "account-hash",
        "organization-hash",
        true,
        true,
        false,
    );
    apply_claude_quota_access_state(&mut snapshot, &full);
    assert_eq!(
        snapshot
            .account
            .as_ref()
            .and_then(|account| account.claude_quota_access_state),
        Some(ClaudeQuotaAccessState::Full)
    );
    assert!(snapshot
        .capabilities
        .iter()
        .any(|capability| capability.capability == CLAUDE_QUOTA_ACCESS_CAPABILITY));

    let mut mismatched = snapshot.clone();
    mismatched
        .account
        .as_mut()
        .expect("account")
        .claude_quota_access_state = None;
    let other = fresh_slot_status(
        "2026-08-12T10:00:00Z",
        "other-account",
        "organization-hash",
        true,
        true,
        false,
    );
    apply_claude_quota_access_state(&mut mismatched, &other);
    assert_eq!(
        mismatched
            .account
            .as_ref()
            .and_then(|account| account.claude_quota_access_state),
        None,
        "a state for another identity must never be stamped onto this account"
    );
    assert!(mismatched
        .capabilities
        .iter()
        .any(|capability| capability.capability == CLAUDE_QUOTA_ACCESS_CAPABILITY));
}

#[test]
fn degraded_claude_slot_preserves_only_exact_known_profile_and_redacts_upload() {
    let account = AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        email: Some("test@example.invalid".to_string()),
        organization_label: Some("Test organization".to_string()),
        plan_type: Some("max_20x".to_string()),
        subscription_product: Some("claude_max_20x".to_string()),
        account_identifier_hash: Some("account-a".to_string()),
        organization_identifier_hash: Some("org-a".to_string()),
        ..unsupported_account("anthropic")
    };
    let mut previous = provider_unavailable_status("2026-09-01T10:00:00Z", "account-a", "org-a");
    remember_claude_slot_account_profile(&mut previous, Some(&account), "2026-09-01T10:00:00Z");
    let mut slots = BTreeMap::from([("slot-a".to_string(), previous)]);
    let current = provider_unavailable_status("2026-09-01T11:00:00Z", "account-a", "org-a");
    merge_claude_slot_collection_state(&mut slots, "slot-a", &current);
    let current = slots.get("slot-a").expect("retained slot");
    let snapshot = degraded_claude_slot_snapshot(
        current,
        ClaudeAccountAnchorDurabilityV1::Anchored,
        None,
        "2026-09-01T11:00:00Z",
        "2026-09-01T11:05:00Z",
    )
    .expect("degraded witness");
    let local = snapshot.account.as_ref().expect("account");
    assert_eq!(local.email, account.email);
    assert_eq!(local.organization_label, account.organization_label);
    assert_eq!(local.plan_type, account.plan_type);
    assert_eq!(local.subscription_product, account.subscription_product);
    assert!(snapshot.quota_windows.is_empty());
    assert!(
        current.last_full_quota_read_at.is_none(),
        "labels cannot create quota proof"
    );
    let upload = snapshot
        .redacted_for_backend()
        .account
        .expect("upload account");
    assert_eq!(upload.email, account.email);
    assert_eq!(upload.organization_label, account.organization_label);
    assert_eq!(upload.plan_type, account.plan_type);
    assert_eq!(
        upload.account_identifier_hash,
        account.account_identifier_hash
    );

    for (account_hash, org_hash) in [
        ("account-b", "org-a"),
        ("account-a", "org-b"),
        ("", "org-a"),
    ] {
        let mut changed =
            provider_unavailable_status("2026-09-01T12:00:00Z", account_hash, org_hash);
        inherit_claude_slot_account_profile(&mut changed, Some(current));
        assert!(
            changed.account_profile.is_none(),
            "changed composite cannot inherit labels"
        );
        changed.account_profile = current.account_profile.clone();
        assert!(
            exact_claude_slot_account_profile(&changed).is_none(),
            "mismatched persisted profile fails closed"
        );
    }
    let mut future = current.clone();
    future
        .account_profile
        .as_mut()
        .expect("profile")
        .captured_at = "2099-01-01T00:00:00Z".to_string();
    assert!(exact_claude_slot_account_profile(&future).is_none());
    clear_claude_slot_binding(&mut future);
    assert!(future.account_profile.is_none());
}

#[test]
fn sparse_claude_slot_profile_retains_known_fields_without_combining_changed_tiers() {
    let account = AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        email: Some("previous@example.invalid".to_string()),
        organization_label: Some("Known organization".to_string()),
        plan_type: Some("max_20x".to_string()),
        subscription_product: Some("claude_max_20x".to_string()),
        account_identifier_hash: Some("account-a".to_string()),
        organization_identifier_hash: Some("org-a".to_string()),
        ..unsupported_account("anthropic")
    };
    let mut previous = provider_unavailable_status("2026-09-01T10:00:00Z", "account-a", "org-a");
    remember_claude_slot_account_profile(&mut previous, Some(&account), "2026-09-01T10:00:00Z");
    for (plan, product, expected_plan, expected_product) in [
        (None, None, Some("max_20x"), Some("claude_max_20x")),
        (
            Some("max_20x"),
            None,
            Some("max_20x"),
            Some("claude_max_20x"),
        ),
        (
            None,
            Some("claude_max_20x"),
            Some("max_20x"),
            Some("claude_max_20x"),
        ),
        (Some("team"), None, Some("team"), None),
        (None, Some("claude_team"), None, Some("claude_team")),
        (
            Some("team"),
            Some("claude_team"),
            Some("team"),
            Some("claude_team"),
        ),
    ] {
        let mut sparse = account.clone();
        sparse.email = Some("current@example.invalid".to_string());
        sparse.organization_label = None;
        sparse.plan_type = plan.map(str::to_string);
        sparse.subscription_product = product.map(str::to_string);
        let mut current = provider_unavailable_status("2026-09-01T11:00:00Z", "account-a", "org-a");
        remember_claude_slot_account_profile(&mut current, Some(&sparse), "2026-09-01T11:00:00Z");
        inherit_claude_slot_account_profile(&mut current, Some(&previous));
        let profile = exact_claude_slot_account_profile(&current).expect("same pair profile");
        assert_eq!(
            profile.email.as_deref(),
            Some("current@example.invalid"),
            "new authoritative email wins"
        );
        assert_eq!(profile.organization_label, account.organization_label);
        assert_eq!(profile.plan_type.as_deref(), expected_plan);
        assert_eq!(profile.subscription_product.as_deref(), expected_product);
        assert_eq!(
            profile.captured_at, "2026-09-01T10:00:00Z",
            "retained fields cannot acquire the new capture clock"
        );
        let degraded = degraded_claude_slot_snapshot(
            &current,
            ClaudeAccountAnchorDurabilityV1::Anchored,
            None,
            "2026-09-01T11:00:00Z",
            "2026-09-01T11:05:00Z",
        )
        .expect("degraded same pair");
        assert_eq!(
            degraded.account.expect("account").plan_type.as_deref(),
            expected_plan
        );
    }

    let mut sparse = account.clone();
    sparse.email = None;
    sparse.organization_label = None;
    let mut current = provider_unavailable_status("2026-09-01T11:00:00Z", "account-a", "org-a");
    remember_claude_slot_account_profile(&mut current, Some(&sparse), "2026-09-01T11:00:00Z");
    inherit_claude_slot_account_profile(&mut current, Some(&previous));
    assert_eq!(
        exact_claude_slot_account_profile(&current)
            .expect("profile")
            .email,
        account.email
    );
    let mut other = previous.clone();
    other.organization_identifier_hash = Some("other-org".to_string());
    let mut changed = provider_unavailable_status("2026-09-01T11:00:00Z", "account-a", "other-org");
    inherit_claude_slot_account_profile(&mut changed, Some(&other));
    assert!(
        changed.account_profile.is_none(),
        "mismatched embedded profile must not transfer labels"
    );
}

#[test]
fn claude_account_without_weekly_limit_reads_complete() {
    // Some Team plans have no account-wide weekly limit: Claude sends
    // `seven_day: null` and lists only the session and model limits.
    let body = serde_json::json!({
        "five_hour": {"utilization": 45, "resets_at": "2026-09-01T13:00:00+00:00"},
        "seven_day": null,
        "limits": [
            {"kind": "session", "group": "session", "percent": 45,
             "resets_at": "2026-09-01T13:00:00+00:00", "scope": null},
            {"kind": "weekly_scoped", "group": "weekly", "percent": 0,
             "resets_at": "2026-09-03T01:00:00+00:00",
             "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}
        ]
    });
    assert!(claude_oauth_account_weekly_not_offered(&body));
    let mut listed = body.clone();
    listed["limits"].as_array_mut().expect("limits").push(
        serde_json::json!({"kind": "weekly_all", "group": "weekly", "percent": 1, "scope": null}),
    );
    assert!(
        !claude_oauth_account_weekly_not_offered(&listed),
        "a listed account weekly limit stays expected"
    );
    for key in ["limits", "seven_day"] {
        let mut missing = body.clone();
        missing.as_object_mut().expect("body").remove(key);
        assert!(
            !claude_oauth_account_weekly_not_offered(&missing),
            "a missing {key} proves nothing"
        );
    }

    let resolved = || ResolvedClaudeSlot {
        account: AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            plan_type: Some("team".to_string()),
            account_identifier_hash: Some("account-a".to_string()),
            organization_identifier_hash: Some("org-a".to_string()),
            ..unsupported_account("anthropic")
        },
        account_identifier_hash: "account-a".to_string(),
        organization_identifier_hash: "org-a".to_string(),
        credential: ClaudeOAuthCredential {
            access_token: None,
            has_refresh_token: true,
            access_expires_at: None,
            relogin_required_at: None,
            has_inference_scope: None,
            has_profile_scope: false,
            subscription_type: None,
        },
    };
    let read = |account_weekly_not_offered: bool| {
        let mut usage = ClaudeOAuthUsage {
            windows: claude_oauth_quota_windows(&body),
            credit_balances: Vec::new(),
            account_weekly_not_offered,
            account_session_not_offered: false,
        };
        claude_oauth_stamp_account_identity(&mut usage, "account-a", Some("org-a"));
        custom_claude_snapshot_from_usage(
            resolved(),
            ClaudeOAuthUsageOutcome::from(Ok(usage)),
            true,
            "2026-09-01T10:00:00Z".to_string(),
            "2026-09-01T10:05:00Z".to_string(),
        )
        .unwrap_or_else(|_| panic!("fresh reading"))
    };
    let (snapshot, status) = read(true);
    assert!(status.has_account_windows);
    assert!(status.last_full_quota_read_at.is_some());
    assert_eq!(
        status.quota_snapshot.expect("snapshot").state,
        ClaudeConfigSlotQuotaSnapshotStateV1::Fresh
    );
    assert!(claude_snapshot_has_account_windows(&snapshot));
    assert!(claude_default_slot_collection_status(&snapshot).has_account_windows);

    // Without Claude's word, the same windows are still a partial reading.
    let (snapshot, status) = read(false);
    assert!(!status.has_account_windows);
    assert_eq!(
        status.quota_snapshot.expect("snapshot").state,
        ClaudeConfigSlotQuotaSnapshotStateV1::Partial
    );
    assert!(!claude_snapshot_has_account_windows(&snapshot));
}

#[test]
fn claude_account_without_session_limit_reads_complete() {
    // Max plans lost the 5-hour limit in late 2026: Claude sends
    // `five_hour: null` and lists only weekly and model limits. Every
    // read used to count as partial, so the slot kept an aging meter.
    let body = serde_json::json!({
        "five_hour": null,
        "seven_day": {"utilization": 6, "resets_at": "2026-11-07T05:00:00+00:00"},
        "limits": [
            {"kind": "weekly_all", "group": "weekly", "percent": 6,
             "resets_at": "2026-11-07T05:00:00+00:00", "scope": null},
            {"kind": "weekly_scoped", "group": "weekly", "percent": 0,
             "resets_at": "2026-11-07T05:00:00+00:00",
             "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}
        ]
    });
    assert!(claude_oauth_account_session_not_offered(&body));
    let windows = claude_oauth_quota_windows(&body);
    assert!(windows.iter().all(|window| window.name != "session"));
    assert!(claude_has_account_windows(&windows, false, true));
    assert!(!claude_has_account_windows(&windows, false, false));
    assert!(!claude_has_account_windows(&[], true, true));

    let mut listed = body.clone();
    listed["limits"].as_array_mut().expect("limits").push(
        serde_json::json!({"kind": "session", "group": "session", "percent": 4, "scope": null}),
    );
    assert!(
        !claude_oauth_account_session_not_offered(&listed),
        "a listed session limit stays expected"
    );
    for key in ["limits", "five_hour"] {
        let mut missing = body.clone();
        missing.as_object_mut().expect("body").remove(key);
        assert!(
            !claude_oauth_account_session_not_offered(&missing),
            "a missing {key} proves nothing"
        );
    }

    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-11-01T10:00:00Z".to_string(),
        "2026-11-01T10:05:00Z".to_string(),
    );
    snapshot.quota_windows = windows;
    assert!(!claude_snapshot_has_account_windows(&snapshot));
    snapshot
        .capabilities
        .push(claude_account_session_not_offered_capability());
    assert!(claude_snapshot_has_account_windows(&snapshot));
}

#[test]
fn claude_slot_with_fresh_meters_stays_fresh_when_a_credit_section_is_stale() {
    // A plain read refreshes the windows but not the saved-reset section,
    // which keeps its own older read time and can go Stale before the next
    // read. That section is labelled Stale on its own; the slot must not
    // become "temporarily unavailable" while its meters are fresh.
    let body = serde_json::json!({
        "five_hour": {"utilization": 0, "resets_at": null},
        "seven_day": {"utilization": 100, "resets_at": "2026-09-03T05:00:00+00:00"},
        "limits": [
            {"kind": "session", "group": "session", "percent": 0,
             "resets_at": null, "scope": null},
            {"kind": "weekly_all", "group": "weekly", "percent": 100,
             "resets_at": "2026-09-03T05:00:00+00:00", "scope": null},
            {"kind": "weekly_scoped", "group": "weekly", "percent": 2,
             "resets_at": "2026-09-03T05:00:00+00:00",
             "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}
        ]
    });
    let resolved = || ResolvedClaudeSlot {
        account: AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            plan_type: Some("max".to_string()),
            account_identifier_hash: Some("account-a".to_string()),
            organization_identifier_hash: Some("org-a".to_string()),
            ..unsupported_account("anthropic")
        },
        account_identifier_hash: "account-a".to_string(),
        organization_identifier_hash: "org-a".to_string(),
        credential: ClaudeOAuthCredential {
            access_token: None,
            has_refresh_token: true,
            access_expires_at: None,
            relogin_required_at: None,
            has_inference_scope: None,
            has_profile_scope: false,
            subscription_type: None,
        },
    };
    let read = |window_freshness: AgentQuotaWindowFreshness| {
        let mut windows = claude_oauth_quota_windows(&body);
        assert!(!windows.is_empty());
        for window in &mut windows {
            window.freshness = window_freshness.clone();
        }
        let mut usage = ClaudeOAuthUsage {
            windows,
            credit_balances: vec![AgentCreditBalance {
                name: "reset_bank".to_string(),
                kind: Some(ottto_protocol::CreditBalanceKind::SavedResets),
                freshness: AgentQuotaWindowFreshness::Stale,
                observed_at: Some("2026-09-01T08:40:00Z".to_string()),
                ..Default::default()
            }],
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        };
        claude_oauth_stamp_account_identity(&mut usage, "account-a", Some("org-a"));
        custom_claude_snapshot_from_usage(
            resolved(),
            ClaudeOAuthUsageOutcome::from(Ok(usage)),
            true,
            "2026-09-01T10:00:00Z".to_string(),
            "2026-09-01T10:05:00Z".to_string(),
        )
        .unwrap_or_else(|_| panic!("reading with windows"))
    };

    let (snapshot, status) = read(AgentQuotaWindowFreshness::Fresh);
    // The default login's path reads the same snapshot the same way.
    let default_status = claude_default_slot_collection_status(&snapshot);
    assert_eq!(
        default_status.state,
        ClaudeConfigSlotCollectionStateV1::Fresh
    );
    assert_ne!(
        default_status
            .quota_snapshot
            .expect("default snapshot")
            .state,
        ClaudeConfigSlotQuotaSnapshotStateV1::Stale
    );
    assert_eq!(status.state, ClaudeConfigSlotCollectionStateV1::Fresh);
    assert!(status.diagnostics.is_empty());
    assert!(matches!(
        projected_claude_quota_access_state(&status),
        Some(ClaudeQuotaAccessState::Full | ClaudeQuotaAccessState::Partial)
    ));
    let quota = status.quota_snapshot.expect("snapshot");
    assert_ne!(quota.state, ClaudeConfigSlotQuotaSnapshotStateV1::Stale);
    let saved = quota
        .credit_balances
        .iter()
        .find(|balance| balance.kind == Some(ottto_protocol::CreditBalanceKind::SavedResets))
        .expect("saved-reset section kept");
    assert_eq!(
        saved.freshness,
        AgentQuotaWindowFreshness::Stale,
        "the section keeps its own Stale label"
    );

    // Stale meters still mean no current reading.
    let (snapshot, status) = read(AgentQuotaWindowFreshness::Stale);
    assert_eq!(
        status.state,
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
    );
    assert_eq!(
        claude_default_slot_collection_status(&snapshot).state,
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
    );
}

#[test]
#[serial]
fn claude_status_lane_wakes_for_a_reset_read_behind_the_spacing_gate() {
    let support_dir = std::env::temp_dir().join(format!(
        "ottto-claude-reset-read-wake-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&support_dir);
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    let _guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support_dir.as_os_str().to_os_string(),
    );
    let (account, organization) = ("account-reset", "org-reset");
    let observed = 1_800_000_000_u64;
    let reset = observed + 3_600;
    let window = AgentQuotaWindow {
        name: "session".to_string(),
        scope: AgentQuotaWindowScope::Account,
        freshness: AgentQuotaWindowFreshness::Fresh,
        resets_at: rfc3339_from_unix_seconds(reset),
        account_identifier_hash: Some(account.to_string()),
        organization_identifier_hash: Some(organization.to_string()),
        ..Default::default()
    };
    let store = |next_refresh_after: u64| {
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account.to_string(),
            organization_identifier_hash: organization.to_string(),
            observed_at_epoch_seconds: observed,
            next_refresh_after_epoch_seconds: next_refresh_after,
            windows: vec![window.clone()],
            credit_balances: Vec::new(),
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        })
        .expect("write cache");
    };
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-09-01T10:00:00Z".to_string(),
        "2026-09-01T10:15:00Z".to_string(),
    );
    snapshot.quota_windows = vec![window.clone()];
    let collection = AgentStatusCollection {
        snapshots: vec![snapshot.clone()],
        source_health_snapshot: snapshot,
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    };
    let delay = claude_credit_pools::claude_reset_read_delay_seconds(account, organization);

    store(observed + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS);
    assert_eq!(
        claude_next_reset_read_at(&collection, observed),
        Some(reset + delay)
    );
    // Behind the binding's spacing gate, the wake waits for the gate.
    store(reset + delay + 200);
    assert_eq!(
        claude_next_reset_read_at(&collection, reset + delay),
        Some(reset + delay + 200)
    );
    // Once that time has passed, the lane keeps its regular interval.
    assert_eq!(
        claude_next_reset_read_at(&collection, reset + delay + 200),
        None
    );
    let _ = std::fs::remove_dir_all(&support_dir);
}

#[test]
fn unavailable_claude_read_keeps_verified_slot_labels_without_quota() {
    let resolved = ResolvedClaudeSlot {
        account: AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            email: Some("test@example.invalid".to_string()),
            plan_type: Some("team".to_string()),
            account_identifier_hash: Some("account-a".to_string()),
            organization_identifier_hash: Some("org-a".to_string()),
            ..unsupported_account("anthropic")
        },
        account_identifier_hash: "account-a".to_string(),
        organization_identifier_hash: "org-a".to_string(),
        credential: ClaudeOAuthCredential {
            access_token: None,
            has_refresh_token: true,
            access_expires_at: None,
            relogin_required_at: None,
            has_inference_scope: None,
            has_profile_scope: false,
            subscription_type: None,
        },
    };
    let status = custom_claude_snapshot_from_usage(
        resolved,
        ClaudeOAuthUsageOutcome {
            result: Err("private provider error must not be retained".to_string()),
            diagnostics: vec![AgentStatusDiagnostic::source(
                "claude_oauth_usage_check_failed",
                AgentDiagnosticSeverity::Warning,
                "private transport detail must not be retained",
            )
            .with_observed_at(Some("2026-09-01T09:59:00Z".to_string()))
            .with_quota_binding(Some("account-a".to_string()), Some("org-a".to_string()))],
        },
        true,
        "2026-09-01T10:00:00Z".to_string(),
        "2026-09-01T10:05:00Z".to_string(),
    )
    .expect_err("quota unavailable");
    let profile = exact_claude_slot_account_profile(&status).expect("verified local labels");
    assert_eq!(profile.email.as_deref(), Some("test@example.invalid"));
    assert_eq!(profile.plan_type.as_deref(), Some("team"));
    assert!(
        profile.subscription_product.is_none(),
        "missing product stays unknown"
    );
    assert!(status.quota_snapshot.is_none());
    assert_eq!(status.quota_check_diagnostics.len(), 1);
    let persisted: ClaudeConfigSlotCollectionStatusV1 =
        serde_json::from_slice(&serde_json::to_vec(&status).expect("serialize exact slot"))
            .expect("reload exact slot");
    let snapshot = degraded_claude_slot_snapshot(
        &persisted,
        ClaudeAccountAnchorDurabilityV1::Anchored,
        None,
        "2026-09-01T11:00:00Z",
        "2026-09-01T11:05:00Z",
    )
    .expect("degraded exact slot");
    let receipt = snapshot
        .diagnostics
        .iter()
        .find(|item| item.code == "claude_oauth_usage_check_failed")
        .expect("failure retained");
    assert_eq!(receipt.observed_at.as_deref(), Some("2026-09-01T09:59:00Z"));
    assert_eq!(
        receipt.account_identifier_hash.as_deref(),
        Some("account-a")
    );
    assert_eq!(
        receipt.organization_identifier_hash.as_deref(),
        Some("org-a")
    );
    assert!(!serde_json::to_string(&snapshot)
        .expect("snapshot json")
        .contains("private"));
}

#[test]
fn retry_after_cache_disclosure_persists_only_a_canonical_bound_clock() {
    let deadline = current_unix_seconds() + 3600;
    let mut diagnostic = AgentStatusDiagnostic::source(
        "claude_oauth_usage_cache_reused",
        AgentDiagnosticSeverity::Info,
        "private message",
    )
    .with_observed_at(rfc3339_from_unix_seconds(deadline - 3600))
    .with_quota_binding(
        Some("account".to_string()),
        Some("organization".to_string()),
    );
    diagnostic.retry_after = rfc3339_from_unix_seconds(deadline);
    let safe = safe_claude_slot_check_diagnostics(&[diagnostic.clone()], "account", "organization");
    assert_eq!(safe[0].message, CLAUDE_CACHE_REUSED_MESSAGE);
    assert_eq!(safe[0].retry_after, diagnostic.retry_after);
    assert_eq!(
        safe_claude_slot_check_diagnostics(&safe, "account", "organization"),
        safe
    );
    assert!(
        safe_claude_slot_check_diagnostics(&[diagnostic.clone()], "account", "foreign").is_empty()
    );
    for clock in [
        None,
        Some("private@example.test"),
        Some("not-a-clock"),
        Some("1960-01-01T00:00:00Z"),
    ] {
        let mut invalid = diagnostic.clone();
        invalid.retry_after = clock.map(ToString::to_string);
        let safe = safe_claude_slot_check_diagnostics(&[invalid], "account", "organization");
        assert!(safe[0].retry_after.is_none());
    }
    let mut no_clock = diagnostic;
    no_clock.observed_at = None;
    assert!(
        safe_claude_slot_check_diagnostics(&[no_clock], "account", "organization")[0]
            .retry_after
            .is_none()
    );
}

#[test]
fn claude_slot_diagnostics_keep_suppression_and_cache_distinct_without_inventing_clocks() {
    let codes = [
        "claude_oauth_usage_check_failed",
        "claude_oauth_usage_check_suppressed",
        "claude_oauth_usage_cache_reused",
    ];
    for code in codes {
        let mut status = provider_unavailable_status("2026-09-01T10:00:00Z", "account-a", "org-a");
        status.quota_check_diagnostics = vec![AgentStatusDiagnostic::for_account(
            code,
            AgentDiagnosticSeverity::Info,
            "private message",
            "private email",
        )
        .with_observed_at(Some("2026-09-01T09:00:00Z".to_string()))
        .with_quota_binding(Some("account-a".to_string()), Some("org-a".to_string()))];
        let snapshot = degraded_claude_slot_snapshot(
            &status,
            ClaudeAccountAnchorDurabilityV1::Anchored,
            None,
            "2026-09-01T11:00:00Z",
            "2026-09-01T11:05:00Z",
        )
        .expect("degraded");
        let receipt = snapshot
            .diagnostics
            .iter()
            .find(|item| item.code == code)
            .expect("outcome");
        assert_eq!(receipt.observed_at.as_deref(), Some("2026-09-01T09:00:00Z"));
        assert!(receipt.account_label.is_none() && receipt.scope.is_none());
        assert_eq!(
            snapshot
                .diagnostics
                .iter()
                .filter(|item| codes.contains(&item.code.as_str()))
                .count(),
            1
        );
        assert!(snapshot.quota_windows.is_empty());
        assert!(snapshot
            .diagnostics
            .iter()
            .filter(|item| item.code != code)
            .all(|item| item.observed_at.is_none()));
        let receipt = receipt.clone();
        let upload = snapshot.redacted_for_backend();
        assert!(upload.diagnostics.iter().any(|item| item == &receipt));
    }
}

#[test]
fn claude_slot_diagnostics_keep_terminal_upkeep_clock_separate_from_attempt() {
    let mut descriptor =
        ClaudeConfigDirSlot::Default.descriptor("fixture", ClaudeConfigSlotOwnership::External);
    descriptor.collection.account_identifier_hash = Some("account-a".to_string());
    descriptor.collection.organization_identifier_hash = Some("org-a".to_string());
    let mut status = provider_unavailable_status("2026-09-01T11:00:00Z", "account-a", "org-a");
    status.upkeep = Some(ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
        result: ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
        due_access_expires_at: Some("2026-09-01T10:00:00Z".to_string()),
        refresh_token_expires_at: None,
        attempted_at: None,
        next_allowed_attempt_at: None,
        consecutive_failures: 0,
    });
    append_claude_upkeep_result_receipt(
        &mut status,
        &descriptor,
        Some("2026-09-01T10:59:00Z".to_string()),
    );
    for _ in 0..3 {
        append_claude_upkeep_result_receipt(
            &mut status,
            &descriptor,
            Some("2026-09-01T11:10:00Z".to_string()),
        );
    }
    assert_eq!(
        status.quota_check_diagnostics.len(),
        1,
        "repeated reads replace the exact-code receipt"
    );
    let persisted: ClaudeConfigSlotCollectionStatusV1 =
        serde_json::from_slice(&serde_json::to_vec(&status).unwrap()).unwrap();
    let snapshot = degraded_claude_slot_snapshot(
        &persisted,
        ClaudeAccountAnchorDurabilityV1::Anchored,
        None,
        "2026-09-01T12:00:00Z",
        "2026-09-01T12:05:00Z",
    )
    .unwrap()
    .redacted_for_backend();
    let receipts = snapshot
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "claude_slot_upkeep_credential_unreadable")
        .collect::<Vec<_>>();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].observed_at.as_deref(),
        Some("2026-09-01T11:10:00Z")
    );
    assert!(!snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code.contains("attempt_started")
            || diagnostic.code.contains("check_succeeded")));
    let mut rebound = status.clone();
    rebound.quota_check_diagnostics.clear();
    rebound.organization_identifier_hash = Some("other-org".to_string());
    append_claude_upkeep_result_receipt(
        &mut rebound,
        &descriptor,
        Some("2026-09-01T10:59:00Z".to_string()),
    );
    assert!(rebound.quota_check_diagnostics.is_empty());
    let mut future = status;
    future.quota_check_diagnostics.clear();
    append_claude_upkeep_result_receipt(
        &mut future,
        &descriptor,
        Some("2099-09-01T10:59:00Z".to_string()),
    );
    assert!(future.quota_check_diagnostics.is_empty());
    assert!(
        upkeep_state_diagnostic(ClaudeConfigSlotUpkeepResultV1::RefreshDue)
            .2
            .contains("queued")
    );
    assert!(
        upkeep_state_diagnostic(ClaudeConfigSlotUpkeepResultV1::InProgress)
            .2
            .contains("in progress")
    );
}

#[test]
fn degraded_claude_slot_witness_is_meterless_planless_and_account_deduplicated() {
    let temporary = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
        account_identifier_hash: Some("account-hash".to_string()),
        organization_identifier_hash: Some("organization-hash".to_string()),
        ..Default::default()
    };
    let reconnect = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::NeedsLogin,
        account_identifier_hash: Some("account-hash".to_string()),
        organization_identifier_hash: Some("organization-hash".to_string()),
        ..Default::default()
    };
    let unbound = ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
        account_identifier_hash: Some("unbound-account".to_string()),
        organization_identifier_hash: None,
        ..Default::default()
    };
    let slots = BTreeMap::from([
        ("claude_slot_a".to_string(), temporary),
        ("claude_slot_b".to_string(), reconnect),
        ("claude_slot_c".to_string(), unbound),
    ]);
    let binding = ClaudeStrongBinding {
        account_identifier_hash: "account-hash".to_string(),
        organization_identifier_hash: "organization-hash".to_string(),
    };
    let anchors = BTreeMap::from([(binding.clone(), "claude_slot_b".to_string())]);

    let snapshots = degraded_claude_slot_snapshots(
        &slots,
        &anchors,
        &BTreeSet::new(),
        "2026-08-12T10:00:00Z",
        "2026-08-12T10:05:00Z",
    );
    assert_eq!(snapshots.len(), 1, "one current row per strong account");
    let snapshot = &snapshots[0];
    assert_eq!(snapshot.status, AgentStatusState::Degraded);
    assert!(snapshot.quota_windows.is_empty());
    assert!(snapshot.credit_balances.is_empty());
    assert!(snapshot.plan_observations.is_empty());
    assert_eq!(
        snapshot
            .account
            .as_ref()
            .and_then(|account| account.claude_quota_access_state),
        Some(ClaudeQuotaAccessState::ReconnectRequired)
    );
    let wire = serde_json::to_string(snapshot).expect("serialize degraded witness");
    assert!(!wire.contains("claude_slot_a"));
    assert!(!wire.contains("claude_slot_b"));
    assert!(!wire.contains("config_dir"));
    assert!(!wire.contains("quota_snapshot"));

    let suppressed = degraded_claude_slot_snapshots(
        &slots,
        &anchors,
        &BTreeSet::from([binding]),
        "2026-08-12T10:00:00Z",
        "2026-08-12T10:05:00Z",
    );
    assert!(
        suppressed.is_empty(),
        "a healthy winner for the account must suppress its failed duplicate slot"
    );
}

#[test]
#[serial]
fn degraded_claude_slot_witness_retains_only_the_same_slots_strong_binding() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-quota-access-witness-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    fs::create_dir_all(&root).expect("support root");
    let config_dir = root.join("exact-config");
    fs::create_dir_all(&config_dir).expect("config dir");
    let write_identity = |account: &str, organization: &str| {
        fs::write(
            config_dir.join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "oauthAccount": {
                    "accountUuid": account,
                    "organizationUuid": organization,
                    "emailAddress": "person@example.invalid"
                }
            }))
            .expect("identity json"),
        )
        .expect("write identity");
    };
    write_identity("account-current", "organization-current");
    let account_hash =
        billing_identity_hash("anthropic", "account", "account-current").expect("account hash");
    let organization_hash =
        billing_identity_hash("anthropic", "organization", "organization-current")
            .expect("organization hash");
    let slot = ClaudeConfigDirSlot::registered(config_dir.to_string_lossy().into_owned())
        .expect("registered slot");
    let slot_id = "claude_slot_strong_binding";
    write_persisted_claude_slot_collection_state(&PersistedClaudeSlotCollectionStateV1 {
        schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
        slots: BTreeMap::from([
            (
                slot_id.to_string(),
                ClaudeConfigSlotCollectionStatusV1 {
                    state: ClaudeConfigSlotCollectionStateV1::Fresh,
                    account_identifier_hash: Some(account_hash.clone()),
                    organization_identifier_hash: Some(organization_hash.clone()),
                    last_full_quota_read_at: Some("2026-08-12T09:00:00Z".to_string()),
                    has_account_windows: true,
                    has_scoped_limits: true,
                    quota_snapshot: Some(ClaudeConfigSlotQuotaSnapshotV1 {
                        state: ClaudeConfigSlotQuotaSnapshotStateV1::Fresh,
                        captured_at: "2026-08-12T09:00:00Z".to_string(),
                        observed_at: Some("2026-08-12T09:00:00Z".to_string()),
                        quota_windows: Vec::new(),
                        credit_balances: Vec::new(),
                    }),
                    ..Default::default()
                },
            ),
            (
                "default".to_string(),
                ClaudeConfigSlotCollectionStatusV1 {
                    state: ClaudeConfigSlotCollectionStateV1::Fresh,
                    account_identifier_hash: Some(account_hash.clone()),
                    organization_identifier_hash: Some(organization_hash.clone()),
                    last_full_quota_read_at: Some("2026-08-12T09:00:00Z".to_string()),
                    has_account_windows: true,
                    has_scoped_limits: true,
                    quota_snapshot: Some(ClaudeConfigSlotQuotaSnapshotV1 {
                        state: ClaudeConfigSlotQuotaSnapshotStateV1::Fresh,
                        captured_at: "2026-08-12T09:00:00Z".to_string(),
                        observed_at: Some("2026-08-12T09:00:00Z".to_string()),
                        quota_windows: Vec::new(),
                        credit_balances: Vec::new(),
                    }),
                    ..Default::default()
                },
            ),
        ]),
        unresolved_accounts: Vec::new(),
        anchor_transitions: Vec::new(),
    })
    .expect("seed exact slot binding");

    let mut failed = ClaudeSlotProbeFailure::IdentityMismatch.status("2026-08-12T10:00:00Z");
    retain_verified_claude_slot_binding(slot_id, &slot, &mut failed);
    assert_eq!(
        failed.account_identifier_hash.as_deref(),
        Some(account_hash.as_str())
    );
    assert_eq!(
        failed.organization_identifier_hash.as_deref(),
        Some(organization_hash.as_str())
    );
    assert_eq!(
        failed.quota_snapshot, None,
        "binding verification must not copy older meters before the bounded merge"
    );
    assert_eq!(
        projected_claude_quota_access_state(&failed),
        Some(ClaudeQuotaAccessState::AttentionRequired)
    );

    let direct_failure = registered_claude_failure_status(
        &slot.descriptor(slot_id, ClaudeConfigSlotOwnership::Managed),
        None,
        ClaudeSlotProbeFailure::CredentialUnavailable,
        "2026-08-12T10:00:30Z",
        ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::NotRequired,
            due_access_expires_at: None,
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        },
    );
    assert_eq!(
        direct_failure.account_identifier_hash.as_deref(),
        Some(account_hash.as_str()),
        "a transient direct workflow probe must not erase the saved anchor"
    );
    assert_eq!(
        direct_failure.organization_identifier_hash.as_deref(),
        Some(organization_hash.as_str())
    );

    let mut current_full = fresh_slot_status(
        "2026-08-12T10:00:00Z",
        &account_hash,
        &organization_hash,
        true,
        true,
        false,
    );
    current_full.quota_snapshot = Some(ClaudeConfigSlotQuotaSnapshotV1 {
        state: ClaudeConfigSlotQuotaSnapshotStateV1::Fresh,
        captured_at: "2026-08-12T10:00:00Z".to_string(),
        observed_at: Some("2026-08-12T10:00:00Z".to_string()),
        quota_windows: Vec::new(),
        credit_balances: Vec::new(),
    });
    retain_verified_claude_slot_binding(slot_id, &slot, &mut current_full);
    assert_eq!(
        current_full.last_full_quota_read_at.as_deref(),
        Some("2026-08-12T10:00:00Z"),
        "a current full read must not be replaced by the prior slot timestamp"
    );
    assert_eq!(
        current_full
            .quota_snapshot
            .as_ref()
            .map(|snapshot| snapshot.captured_at.as_str()),
        Some("2026-08-12T10:00:00Z"),
        "a current full snapshot must remain authoritative"
    );

    write_identity("account-rotated", "organization-rotated");
    let mut rotated = ClaudeSlotProbeFailure::IdentityMismatch.status("2026-08-12T10:01:00Z");
    retain_verified_claude_slot_binding(slot_id, &slot, &mut rotated);
    assert_eq!(rotated.account_identifier_hash, None);
    assert_eq!(rotated.organization_identifier_hash, None);
    assert_eq!(projected_claude_quota_access_state(&rotated), None);

    let mut blocked_rotated = blocked_claude_upkeep_status(
        slot_id,
        "2026-08-12T10:01:30Z",
        ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
            due_access_expires_at: None,
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        },
    );
    retain_verified_claude_slot_binding(slot_id, &slot, &mut blocked_rotated);
    assert_eq!(blocked_rotated.account_identifier_hash, None);
    assert_eq!(blocked_rotated.organization_identifier_hash, None);

    fs::remove_file(config_dir.join(".claude.json")).expect("remove current identity");
    let mut missing = blocked_claude_upkeep_status(
        slot_id,
        "2026-08-12T10:02:00Z",
        ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
            due_access_expires_at: None,
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        },
    );
    assert!(
        missing.account_identifier_hash.is_some(),
        "blocked upkeep starts from the local persisted status"
    );
    retain_verified_claude_slot_binding(slot_id, &slot, &mut missing);
    assert_eq!(missing.account_identifier_hash, None);
    assert_eq!(missing.organization_identifier_hash, None);
    assert_eq!(missing.quota_snapshot, None);

    let home = root.join("home");
    fs::create_dir_all(&home).expect("default home");
    let _home_guard = EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string());
    let mut default_failed =
        ClaudeSlotProbeFailure::CredentialUnavailable.status("2026-08-12T10:03:00Z");
    retain_verified_claude_slot_binding(
        "default",
        &ClaudeConfigDirSlot::Default,
        &mut default_failed,
    );
    assert_eq!(default_failed.account_identifier_hash, None);
    assert_eq!(default_failed.organization_identifier_hash, None);
    let _ = fs::remove_dir_all(root);
}

/// [regress] Approved A, then a race: ending on A keeps A and only retries;
/// ending on B is a mismatch and B is never adopted.
#[test]
#[serial]
fn claude_race_keeps_the_same_owner_and_flags_a_switch() {
    let root =
        std::env::temp_dir().join(format!("ottto-claude-race-switch-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    let config_dir = root.join("raced-config");
    fs::create_dir_all(&config_dir).expect("config dir");
    let write_identity = |account: &str| {
        let identity = serde_json::json!({"oauthAccount": {
            "accountUuid": account, "organizationUuid": "organization-raced"}});
        fs::write(config_dir.join(".claude.json"), identity.to_string()).expect("identity");
    };
    let account = billing_identity_hash("anthropic", "account", "account-a").expect("hash");
    let organization =
        billing_identity_hash("anthropic", "organization", "organization-raced").expect("hash");
    let slot_id = "claude_slot_race_switch";
    persist_one_claude_slot_collection_state(
        slot_id,
        &fresh_slot_status(
            "2026-08-12T09:00:00Z",
            &account,
            &organization,
            false,
            false,
            false,
        ),
    )
    .expect("seed approved account");
    let race = || {
        registered_claude_race_status_for_test(
            slot_id,
            &config_dir.to_string_lossy(),
            "2026-08-12T10:00:00Z",
        )
    };

    write_identity("account-a");
    let same = race();
    assert_eq!(
        same.state,
        ClaudeConfigSlotCollectionStateV1::ConcurrentMutation
    );
    assert_eq!(
        same.account_identifier_hash.as_deref(),
        Some(account.as_str())
    );

    write_identity("account-b");
    let switched = race();
    assert_eq!(
        switched.state,
        ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    );
    assert_eq!(switched.account_identifier_hash, None);
    assert_eq!(switched.organization_identifier_hash, None);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn unresolved_accounts_use_only_strong_desktop_evidence_and_subtract_full_accounts() {
    let mut desktop = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-08-04T10:00:00Z".to_string(),
        "2026-08-04T10:05:00Z".to_string(),
    );
    let observation =
        |hash: Option<&str>, confidence: AgentStatusConfidence| AgentStatusPlanObservation {
            desktop_recent_at: None,
            observed_at: Some("2026-08-04T10:00:00Z".to_string()),
            evidence_method: Some("claude_desktop_session_bucket".to_string()),
            source_session_id: None,
            provider: Some("anthropic".to_string()),
            billing_provider: Some("anthropic".to_string()),
            model_provider: Some("anthropic".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("claude_desktop".to_string()),
            gateway_provider: None,
            subscription_product: None,
            plan_type: None,
            account_label: None,
            account_id: None,
            organization_label: None,
            organization_id: None,
            account_identifier_hash: hash.map(ToString::to_string),
            organization_identifier_hash: None,
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: None,
            billing_identity_confidence: confidence.clone(),
            confidence,
            is_current: None,
        };
    let mut expired = observation(Some("expired"), AgentStatusConfidence::High);
    expired.observed_at = Some("2026-05-05T09:59:59Z".to_string());
    desktop.plan_observations = vec![
        observation(Some("strong-unresolved"), AgentStatusConfidence::High),
        observation(Some("weak"), AgentStatusConfidence::Low),
        observation(None, AgentStatusConfidence::High),
        observation(Some("resolved"), AgentStatusConfidence::High),
        expired,
    ];
    let mut full = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        "2026-08-04T10:00:00Z".to_string(),
        "2026-08-04T10:05:00Z".to_string(),
    );
    full.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("anthropic".to_string()),
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
        account_identifier_hash: Some("resolved".to_string()),
        organization_identifier_hash: None,
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    });
    full.quota_windows = vec![
        AgentQuotaWindow {
            name: "session".to_string(),
            scope: AgentQuotaWindowScope::Account,
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        },
        AgentQuotaWindow {
            name: "weekly".to_string(),
            scope: AgentQuotaWindowScope::Account,
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        },
        AgentQuotaWindow {
            name: "weekly_sonnet".to_string(),
            scope: AgentQuotaWindowScope::Model,
            freshness: AgentQuotaWindowFreshness::Fresh,
            model: Some("claude-sonnet".to_string()),
            ..Default::default()
        },
    ];
    let unresolved = derive_unresolved_claude_accounts(
        &desktop,
        &ClaudeDesktopPairs::default(),
        &[full.clone()],
        &BTreeMap::new(),
        OffsetDateTime::parse("2026-08-04T10:00:00Z", &Rfc3339).expect("fixed now"),
    );
    assert_eq!(unresolved.len(), 1);
    assert_eq!(
        unresolved[0].account_identifier_hash.as_deref(),
        Some("strong-unresolved")
    );
    assert_eq!(unresolved[0].organization_identifier_hash, None);
    assert_eq!(
        unresolved[0].evidence,
        vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession]
    );

    // Exact Desktop folder pairs: full limits resolve only their own exact
    // pair, so the account's other organization stays a connect row, and
    // the account-only row gives way to the exact ones.
    full.account
        .as_mut()
        .expect("full account")
        .organization_identifier_hash = Some("resolved-org".to_string());
    let pair = |account: &str, organization: &str| ClaudeDesktopPairObservation {
        binding: ClaudeStrongBinding::new(account, organization).expect("binding"),
        observation: AgentStatusPlanObservation {
            desktop_recent_at: None,
            account_identifier_hash: Some(account.to_string()),
            organization_identifier_hash: Some(organization.to_string()),
            ..observation(Some(account), AgentStatusConfidence::High)
        },
    };
    let mut pairs = ClaudeDesktopPairs {
        pairs: vec![
            pair("resolved", "resolved-org"),
            pair("resolved", "other-org"),
            pair("strong-unresolved", "unresolved-org"),
        ],
        duplicate_sessions: Vec::new(),
    };
    pairs.pairs[1].observation.organization_label = Some("Other org".to_string());
    let unresolved = derive_unresolved_claude_accounts(
        &desktop,
        &pairs,
        &[full],
        &BTreeMap::new(),
        OffsetDateTime::parse("2026-08-04T10:00:00Z", &Rfc3339).expect("fixed now"),
    );
    assert_eq!(
        unresolved
            .iter()
            .map(|row| (
                row.account_identifier_hash.as_deref(),
                row.organization_identifier_hash.as_deref()
            ))
            .collect::<Vec<_>>(),
        vec![
            (Some("resolved"), Some("other-org")),
            (Some("strong-unresolved"), Some("unresolved-org")),
        ]
    );
    // Labels are the pair's own, display only.
    assert_eq!(
        unresolved[0].organization_label.as_deref(),
        Some("Other org")
    );
    assert_eq!(unresolved[1].organization_label, None);

    // A pair too old for a connect row does not hide the account's recent
    // account-only row.
    pairs
        .pairs
        .retain(|pair| pair.binding.account_identifier_hash == "strong-unresolved");
    pairs.pairs[0].observation.observed_at = Some("2026-05-05T09:59:59Z".to_string());
    let unresolved = derive_unresolved_claude_accounts(
        &desktop,
        &pairs,
        &[],
        &BTreeMap::new(),
        OffsetDateTime::parse("2026-08-04T10:00:00Z", &Rfc3339).expect("fixed now"),
    );
    assert!(unresolved.iter().any(|row| {
        row.account_identifier_hash.as_deref() == Some("strong-unresolved")
            && row.organization_identifier_hash.is_none()
    }));
    assert!(unresolved
        .iter()
        .all(|row| row.organization_identifier_hash.is_none()));
}

#[test]
#[serial]
fn advisory_upkeep_never_overwrites_a_successful_fresh_collection() {
    for result in [
        ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented,
        ClaudeConfigSlotUpkeepResultV1::ReloginApproaching,
    ] {
        let mut status = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some("account-hash".to_string()),
            last_full_quota_read_at: Some("2026-08-04T10:00:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            ..Default::default()
        };
        apply_claude_upkeep_observation(
            &mut status,
            ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
                result,
                due_access_expires_at: Some("2026-08-04T11:00:00Z".to_string()),
                refresh_token_expires_at: Some("2026-08-07T09:00:00Z".to_string()),
                attempted_at: None,
                next_allowed_attempt_at: None,
                consecutive_failures: 0,
            },
        );
        assert_eq!(status.state, ClaudeConfigSlotCollectionStateV1::Fresh);
        assert!(status.upkeep.is_some());
        assert!(!status.diagnostics.is_empty());
    }
}

#[test]
#[serial]
fn paused_upkeep_retains_previous_safe_deadlines_without_a_credential_read() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-paused-deadlines-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    fs::create_dir_all(&root).expect("support root");
    let slot_id = "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_persisted_claude_slot_collection_state(&PersistedClaudeSlotCollectionStateV1 {
        schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
        slots: BTreeMap::from([(
            slot_id.to_string(),
            ClaudeConfigSlotCollectionStatusV1 {
                access_expires_at: Some("2026-08-04T10:00:00Z".to_string()),
                relogin_required_at: Some("2026-08-20T00:00:00Z".to_string()),
                account_identifier_hash: Some("safe-account-hash".to_string()),
                ..Default::default()
            },
        )]),
        unresolved_accounts: Vec::new(),
        anchor_transitions: Vec::new(),
    })
    .expect("seed slot state");

    let status = blocked_claude_upkeep_status(
        slot_id,
        "2026-08-04T11:00:00Z",
        ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
            due_access_expires_at: None,
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        },
    );
    assert_eq!(
        status.access_expires_at.as_deref(),
        Some("2026-08-04T10:00:00Z")
    );
    assert_eq!(
        status.relogin_required_at.as_deref(),
        Some("2026-08-20T00:00:00Z")
    );
    assert_eq!(
        status.account_identifier_hash.as_deref(),
        Some("safe-account-hash")
    );
    assert_eq!(
        status.state,
        ClaudeConfigSlotCollectionStateV1::CollectionPaused
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn exact_full_slot_persistence_atomically_clears_matching_unresolved_account() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-unresolved-clear-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    fs::create_dir_all(&root).expect("support root");
    write_persisted_claude_slot_collection_state(&PersistedClaudeSlotCollectionStateV1 {
        schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
        slots: BTreeMap::new(),
        unresolved_accounts: vec![ClaudeUnresolvedAccountDescriptorV1 {
            unresolved_id: "claude-unresolved-test".to_string(),
            account_identifier_hash: Some("account-full".to_string()),
            organization_identifier_hash: None,
            account_label: None,
            organization_label: None,
            observed_at: Some("2026-08-04T10:00:00Z".to_string()),
            evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
        }],
        anchor_transitions: Vec::new(),
    })
    .expect("seed unresolved state");
    persist_one_claude_slot_collection_state(
        "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some("account-full".to_string()),
            organization_identifier_hash: Some("organization-full".to_string()),
            observed_at: Some("2026-08-04T10:01:00Z".to_string()),
            last_full_quota_read_at: Some("2026-08-04T10:01:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            ..Default::default()
        },
    )
    .expect("persist exact full proof");
    assert!(
        read_persisted_claude_slot_collection_state()
            .unresolved_accounts
            .is_empty(),
        "the same Complete response must not retain a stale unresolved warning"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn stale_bulk_persistence_cannot_resurrect_exactly_resolved_account() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-unresolved-stale-bulk-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    fs::create_dir_all(&root).expect("support root");
    let config_dir = root.join("registered-account");
    fs::create_dir_all(&config_dir).expect("registered config dir");
    let status = FileClaudeConfigSlotSettingsStore::default()
        .register_path(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            config_dir.to_string_lossy().into_owned(),
        )
        .expect("register current slot");
    let slot_id = status
        .external_slots
        .first()
        .expect("registered external slot")
        .slot_id
        .clone();
    let stale_unresolved = ClaudeUnresolvedAccountDescriptorV1 {
        unresolved_id: "claude-unresolved-stale".to_string(),
        account_identifier_hash: Some("account-full".to_string()),
        organization_identifier_hash: None,
        account_label: None,
        organization_label: None,
        observed_at: Some("2026-08-04T10:00:00Z".to_string()),
        evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
    };
    write_persisted_claude_slot_collection_state(&PersistedClaudeSlotCollectionStateV1 {
        schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
        slots: BTreeMap::new(),
        unresolved_accounts: vec![stale_unresolved.clone()],
        anchor_transitions: Vec::new(),
    })
    .expect("seed unresolved state");
    persist_one_claude_slot_collection_state(
        &slot_id,
        &ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some("account-full".to_string()),
            organization_identifier_hash: Some("organization-full".to_string()),
            observed_at: Some("2026-08-04T10:01:00Z".to_string()),
            last_full_quota_read_at: Some("2026-08-04T10:01:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            ..Default::default()
        },
    )
    .expect("persist exact full proof");

    persist_claude_slot_collection_states(&BTreeMap::new(), &[stale_unresolved], &BTreeMap::new())
        .expect("persist delayed stale scheduled state");

    assert!(
        read_persisted_claude_slot_collection_state()
            .unresolved_accounts
            .is_empty(),
        "a delayed bulk writer must subtract newer full proof under its lock"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn claude_collection_attempt_lock_child() {
    let Ok(account) = std::env::var("OTTTO_TEST_CLAUDE_ATTEMPT_ACCOUNT") else {
        return;
    };
    let mode = std::env::var("OTTTO_TEST_CLAUDE_ATTEMPT_MODE").expect("child mode");
    if mode == "contender" {
        assert!(try_claude_oauth_collection_attempt(&account, "organization-a").is_none());
        return;
    }
    let ready =
        PathBuf::from(std::env::var("OTTTO_TEST_CLAUDE_ATTEMPT_READY").expect("ready path"));
    let release =
        PathBuf::from(std::env::var("OTTTO_TEST_CLAUDE_ATTEMPT_RELEASE").expect("release path"));
    let guard =
        try_claude_oauth_collection_attempt(&account, "organization-a").expect("holder lock");
    fs::write(&ready, b"ready").expect("signal ready");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !release.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(release.exists(), "parent released holder");
    drop(guard);
}

#[test]
#[serial]
fn claude_collection_attempt_lock_is_cross_process_and_account_scoped() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-attempt-process-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    let ready = root.join("ready");
    let release = root.join("release");
    let executable = std::env::current_exe().expect("test executable");
    let child_args = [
        "--exact",
        "agent_status::tests::claude_collection_attempt_lock_child",
        "--nocapture",
    ];
    let mut holder = std::process::Command::new(&executable)
        .args(child_args)
        .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root)
        .env("OTTTO_TEST_CLAUDE_ATTEMPT_ACCOUNT", "account-a")
        .env("OTTTO_TEST_CLAUDE_ATTEMPT_MODE", "holder")
        .env("OTTTO_TEST_CLAUDE_ATTEMPT_READY", &ready)
        .env("OTTTO_TEST_CLAUDE_ATTEMPT_RELEASE", &release)
        .spawn()
        .expect("spawn holder");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.exists(), "holder acquired lock");
    let contender = std::process::Command::new(&executable)
        .args(child_args)
        .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root)
        .env("OTTTO_TEST_CLAUDE_ATTEMPT_ACCOUNT", "account-a")
        .env("OTTTO_TEST_CLAUDE_ATTEMPT_MODE", "contender")
        .status()
        .expect("run contender");
    assert!(contender.success());
    fs::write(&release, b"release").expect("release holder");
    assert!(holder.wait().expect("wait holder").success());
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn scheduled_collection_and_exact_check_share_one_account_provider_admission() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-attempt-shared-paths-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        root.as_os_str().to_os_string(),
    );
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let scheduled_calls = Arc::clone(&provider_calls);
    let scheduled = thread::spawn(move || {
        let _guard =
            try_claude_oauth_collection_attempt("same-strong-account", "same-strong-organization")
                .expect("scheduled collector admission");
        scheduled_calls.fetch_add(1, Ordering::SeqCst);
        entered_tx.send(()).expect("entered");
        release_rx.recv().expect("release");
    });
    entered_rx.recv().expect("scheduled admitted");
    let exact_check_admission =
        try_claude_oauth_collection_attempt("same-strong-account", "same-strong-organization");
    if exact_check_admission.is_some() {
        provider_calls.fetch_add(1, Ordering::SeqCst);
    }
    assert!(exact_check_admission.is_none());
    release_tx.send(()).expect("release scheduled");
    scheduled.join().expect("join scheduled");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    let _ = fs::remove_dir_all(root);
}

/// One registered slot on throwaway HOME/support dirs with a fake `claude`
/// that logs every spawn (`<config dir>|<args>`) and a file credential.
struct ClaudeBindingFixture {
    root: PathBuf,
    slot_dir: PathBuf,
    spawn_log: PathBuf,
    _guards: Vec<EnvVarGuard>,
}

const TEAM_PREMIUM: (&str, &str) = ("account-team-premium", "organization-team");
const MAX_20X: (&str, &str) = ("account-max-20x", "organization-max");

impl ClaudeBindingFixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-binding-{label}-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let home = root.join("home");
        let support = root.join("support");
        let bin = root.join("bin");
        let slot_dir = root.join("slot");
        for dir in [&home, &support, &bin, &slot_dir] {
            fs::create_dir_all(dir).expect("create fixture dir");
        }
        let spawn_log = root.join("claude-spawns.log");
        let claude = bin.join("claude");
        fs::write(
            &claude,
            format!(
                r#"#!/bin/sh
echo "$CLAUDE_CONFIG_DIR|$*" >> '{log}'
if [ "$1" = "--version" ]; then
  echo "fixture-version"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ] && [ "$3" = "--json" ]; then
  [ -n "$CLAUDE_CONFIG_DIR" ] || exit 1
  exec /usr/bin/python3 - "$CLAUDE_CONFIG_DIR/.claude.json" <<'FAKE'
import json, sys
account = json.load(open(sys.argv[1]))["oauthAccount"]
print(json.dumps({{
  "status": "authenticated",
  "email": account["emailAddress"],
  "organizationId": account["organizationUuid"],
  "subscriptionType": account["organizationType"].replace("claude_", ""),
}}))
FAKE
fi
exit 0
"#,
                log = spawn_log.display()
            ),
        )
        .expect("write fake claude");
        let security = bin.join("security");
        fs::write(&security, "#!/bin/sh\nexit 44\n").expect("write fake security");
        for executable in [&claude, &security] {
            let mut permissions = fs::metadata(executable).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(executable, permissions).expect("chmod executable");
        }
        let guards = vec![
            EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string()),
            EnvVarGuard::set_os(
                "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
                support.as_os_str().to_os_string(),
            ),
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string()),
        ];
        let fixture = Self {
            root,
            slot_dir,
            spawn_log,
            _guards: guards,
        };
        let now = current_unix_seconds();
        for ((account, organization), percent) in [(TEAM_PREMIUM, 41), (MAX_20X, 92)] {
            let (account_hash, organization_hash) = Self::hashes((account, organization));
            let mut usage = ClaudeOAuthUsage {
                windows: ["session", "weekly"]
                    .into_iter()
                    .map(|name| AgentQuotaWindow {
                        name: name.to_string(),
                        scope: AgentQuotaWindowScope::Account,
                        status: AgentQuotaWindowStatus::Ok,
                        freshness: AgentQuotaWindowFreshness::Fresh,
                        used_percent: Some(percent),
                        ..Default::default()
                    })
                    .chain(std::iter::once(AgentQuotaWindow {
                        name: "weekly_sonnet".to_string(),
                        scope: AgentQuotaWindowScope::Model,
                        status: AgentQuotaWindowStatus::Ok,
                        freshness: AgentQuotaWindowFreshness::Fresh,
                        model: Some("claude-sonnet".to_string()),
                        used_percent: Some(percent),
                        ..Default::default()
                    }))
                    .collect(),
                credit_balances: Vec::new(),
                account_weekly_not_offered: false,
                account_session_not_offered: false,
            };
            claude_oauth_stamp_account_identity(
                &mut usage,
                &account_hash,
                Some(&organization_hash),
            );
            write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
                schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                account_identifier_hash: account_hash,
                organization_identifier_hash: organization_hash,
                observed_at_epoch_seconds: now,
                next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
                windows: usage.windows,
                credit_balances: usage.credit_balances,
                account_weekly_not_offered: false,
                account_session_not_offered: false,
            })
            .expect("write usage cache");
        }
        fixture
    }

    fn hashes((account, organization): (&str, &str)) -> (String, String) {
        (
            billing_identity_hash("anthropic", "account", account).expect("account hash"),
            billing_identity_hash("anthropic", "organization", organization)
                .expect("organization hash"),
        )
    }

    /// What `CLAUDE_CONFIG_DIR=<slot> claude` then `/login` leaves behind.
    fn sign_in(&self, which: (&str, &str)) {
        sign_in_slot_dir(&self.slot_dir, which);
    }

    fn register(&self) -> String {
        FileClaudeConfigSlotSettingsStore::default()
            .register_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                self.slot_dir.to_string_lossy().to_string(),
            )
            .expect("register slot")
            .external_slots[0]
            .slot_id
            .clone()
    }

    fn collect(&self) -> Vec<AgentStatusSnapshot> {
        collect_agent_status_collection(
            &SourceKind::ClaudeCode,
            binding_test_time(0),
            binding_test_time(15),
        )
        .snapshots
    }

    fn slot(&self, slot_id: &str) -> ClaudeConfigSlotDescriptorV1 {
        let status = annotate_claude_accounts_status(
            FileClaudeConfigSlotSettingsStore::default()
                .load()
                .expect("load slots"),
        );
        status
            .external_slots
            .into_iter()
            .find(|slot| slot.slot_id == slot_id)
            .expect("registered slot")
    }

    fn slot_spawns(&self) -> Vec<String> {
        let marker = format!("{}|", self.slot_dir.display());
        fs::read_to_string(&self.spawn_log)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.starts_with(&marker))
            .map(str::to_string)
            .collect()
    }

    fn clear_spawns(&self) {
        let _ = fs::remove_file(&self.spawn_log);
    }

    fn support_files_text(&self) -> String {
        [
            ottto_core::CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME,
            "claude-config-slot-collection-state.json",
        ]
        .into_iter()
        .map(|name| fs::read_to_string(self.root.join("support").join(name)).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
    }
}

/// What `CLAUDE_CONFIG_DIR=<slot> claude` then `/login` leaves behind.
fn sign_in_slot_dir(slot_dir: &Path, which: (&str, &str)) {
    let team = which == TEAM_PREMIUM;
    let mut account = serde_json::json!({
        "accountUuid": which.0,
        "organizationUuid": which.1,
        "emailAddress": if team { "team.person@example.invalid" } else { "max.person@example.invalid" },
        "organizationType": if team { "claude_team" } else { "claude_max" },
    });
    if team {
        account["seatTier"] = serde_json::json!("premium");
    } else {
        account["organizationRateLimitTier"] = serde_json::json!("default_claude_max_20x");
    }
    fs::write(
        slot_dir.join(".claude.json"),
        serde_json::to_vec(&serde_json::json!({ "oauthAccount": account }))
            .expect("serialize identity"),
    )
    .expect("write identity");
    fs::write(
        slot_dir.join(".credentials.json"),
        serde_json::to_vec(&claude_credential_fixture(
            &format!("fixture-secret-token-{}", which.0),
            TimeDuration::hours(6),
            Some(if team { "team" } else { "max" }),
        ))
        .expect("serialize credential"),
    )
    .expect("write credential");
}

impl Drop for ClaudeBindingFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn binding_test_time(minutes_ahead: i64) -> String {
    (OffsetDateTime::now_utc() + TimeDuration::minutes(minutes_ahead))
        .format(&Rfc3339)
        .expect("format time")
}

fn snapshot_binding(snapshot: &AgentStatusSnapshot) -> Option<(String, String)> {
    let account = snapshot.account.as_ref()?;
    Some((
        account.account_identifier_hash.clone()?,
        account.organization_identifier_hash.clone()?,
    ))
}

#[test]
#[serial]
fn terminal_login_with_another_account_is_identity_mismatch_without_collection_upload_or_refresh() {
    let fixture = ClaudeBindingFixture::new("terminal-mismatch");
    let team = ClaudeBindingFixture::hashes(TEAM_PREMIUM);
    let max = ClaudeBindingFixture::hashes(MAX_20X);
    fixture.sign_in(TEAM_PREMIUM);
    let slot_id = fixture.register();

    // Legacy slot without an approval: the first verified identity is
    // back-filled as the approval and collection is unchanged.
    let first = fixture.collect();
    let slot = fixture.slot(&slot_id);
    assert_eq!(
        slot.collection.state,
        ClaudeConfigSlotCollectionStateV1::Fresh
    );
    assert_eq!(
        FileClaudeConfigSlotSettingsStore::default()
            .expected_slot_binding(&slot_id)
            .expect("read approval"),
        ClaudeSlotAccountBinding::new(&team.0, &team.1),
    );
    assert!(first.iter().any(
        |snapshot| snapshot_binding(snapshot).as_ref() == Some(&team)
            && !snapshot.quota_windows.is_empty()
    ));
    assert_eq!(
        FileClaudeConfigSlotSettingsStore::default()
            .slot_approvals()
            .expect("approvals")
            .get(&slot_id)
            .map(|approval| approval.source),
        Some(ottto_core::ClaudeSlotApprovalSource::Observed)
    );
    assert_eq!(
        slot.collection.approval_notice.as_deref(),
        Some(
            "Approved from the current Claude login (Claude Team Premium). If this is the wrong account, sign in again with the right one."
        ),
        "an observed approval is surfaced locally"
    );
    let first_wire = serde_json::to_string(
        &first
            .iter()
            .cloned()
            .map(|snapshot| snapshot.redacted_for_backend())
            .collect::<Vec<_>>(),
    )
    .expect("serialize upload");
    assert!(
        !first_wire.contains("Approved from"),
        "the notice is never uploaded"
    );

    // `CLAUDE_CONFIG_DIR=<slot> claude` + `/login` with the Max account.
    fixture.sign_in(MAX_20X);
    fixture.clear_spawns();
    let provider_calls_before =
        CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst);
    let snapshots = fixture.collect();
    let slot = fixture.slot(&slot_id);

    assert_eq!(
        slot.collection.state,
        ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    );
    assert_eq!(
        slot.collection.account_identifier_hash.as_deref(),
        Some(team.0.as_str()),
        "the slot stays on its approved account"
    );
    assert_eq!(
        slot.collection.organization_identifier_hash.as_deref(),
        Some(team.1.as_str())
    );
    assert_eq!(
        slot.collection
            .account_profile
            .as_ref()
            .and_then(|profile| profile.plan_type.as_deref()),
        Some("team_premium"),
        "the approved account's own profile is kept"
    );
    let message = &slot.collection.diagnostics[0].message;
    assert_eq!(
        slot.collection.diagnostics[0].code,
        ClaudeConfigSlotDiagnosticCodeV1::IdentityMismatch
    );
    assert!(message.contains("Claude Ultra"), "{message}");
    assert!(message.contains("Claude Team Premium"), "{message}");
    assert!(!message.contains('@'), "{message}");
    assert!(
        fixture.slot_spawns().is_empty(),
        "no auth status, doctor or other CLI spawn for a mismatched slot: {:?}",
        fixture.slot_spawns()
    );
    assert_eq!(
        CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        provider_calls_before,
        "no usage call"
    );
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot_binding(snapshot).as_ref() != Some(&max)),
        "nothing is uploaded under the other account"
    );
    assert!(snapshots.iter().all(|snapshot| snapshot
        .quota_windows
        .iter()
        .all(|window| window.used_percent != Some(92))));
    let approved = snapshots
        .iter()
        .find(|snapshot| snapshot_binding(snapshot).as_ref() == Some(&team))
        .expect("approved account health projection");
    assert_eq!(approved.status, AgentStatusState::Degraded);
    assert_eq!(
        approved
            .account
            .as_ref()
            .and_then(|account| account.claude_quota_access_state),
        Some(ClaudeQuotaAccessState::AttentionRequired)
    );
    let wire = serde_json::to_string(
        &snapshots
            .iter()
            .cloned()
            .map(|snapshot| snapshot.redacted_for_backend())
            .collect::<Vec<_>>(),
    )
    .expect("serialize upload");
    for snapshot in &snapshots {
        let diagnostics =
            serde_json::to_string(&snapshot.clone().redacted_for_backend().diagnostics)
                .expect("serialize redacted diagnostics");
        assert!(!diagnostics.contains('@'), "no email in diagnostic uploads");
    }
    assert!(
        !wire.contains("Claude Ultra"),
        "the local message is not uploaded"
    );
    assert!(!wire.contains("fixture-secret"), "no token in uploads");
    assert!(
        crate::agent_status::claude_slot_login_unapproved(&slot),
        "the upkeep worker's spawn and publication fences refuse this slot"
    );
    let persisted = fixture.support_files_text();
    assert!(!persisted.contains("fixture-secret"), "no token persisted");
    assert!(
        !persisted.contains("max.person@"),
        "the other login's email is never persisted"
    );

    // The approved account signs in again from Terminal: collection resumes.
    fixture.sign_in(TEAM_PREMIUM);
    let recovered = fixture.collect();
    let slot = fixture.slot(&slot_id);
    assert_eq!(
        slot.collection.state,
        ClaudeConfigSlotCollectionStateV1::Fresh
    );
    assert!(!crate::agent_status::claude_slot_login_unapproved(&slot));
    let approved = recovered
        .iter()
        .find(|snapshot| snapshot_binding(snapshot).as_ref() == Some(&team))
        .expect("approved account snapshot");
    assert_eq!(
        approved
            .account
            .as_ref()
            .and_then(|account| account.claude_quota_access_state),
        Some(ClaudeQuotaAccessState::Full)
    );
    assert!(approved
        .quota_windows
        .iter()
        .all(|window| window.used_percent == Some(41)));
}

#[test]
#[serial]
fn back_fill_prefers_the_last_verified_identity_over_a_new_login() {
    let fixture = ClaudeBindingFixture::new("backfill-last-verified");
    let team = ClaudeBindingFixture::hashes(TEAM_PREMIUM);
    let max = ClaudeBindingFixture::hashes(MAX_20X);
    fixture.sign_in(TEAM_PREMIUM);
    let slot_id = fixture.register();
    // A collection-state file written before approvals existed records
    // this slot's last verified identity.
    persist_one_claude_slot_collection_state(
        &slot_id,
        &fresh_slot_status(&binding_test_time(0), &team.0, &team.1, true, true, false),
    )
    .expect("legacy collection state");
    // The other account signed in before this daemon version ran.
    fixture.sign_in(MAX_20X);
    fixture.clear_spawns();
    let snapshots = fixture.collect();
    let slot = fixture.slot(&slot_id);
    assert_eq!(
        FileClaudeConfigSlotSettingsStore::default()
            .expected_slot_binding(&slot_id)
            .expect("read approval"),
        ClaudeSlotAccountBinding::new(&team.0, &team.1),
    );
    assert_eq!(
        slot.collection.state,
        ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    );
    assert!(fixture.slot_spawns().is_empty());
    assert!(snapshots
        .iter()
        .all(|snapshot| snapshot_binding(snapshot).as_ref() != Some(&max)));
}

#[cfg(target_os = "macos")]
#[test]
#[serial]
fn approval_back_fill_that_cannot_be_persisted_is_still_enforced() {
    let fixture = ClaudeBindingFixture::new("backfill-unwritable");
    let team = ClaudeBindingFixture::hashes(TEAM_PREMIUM);
    fixture.sign_in(TEAM_PREMIUM);
    let slot_id = fixture.register();
    persist_one_claude_slot_collection_state(
        &slot_id,
        &fresh_slot_status(&binding_test_time(0), &team.0, &team.1, true, true, false),
    )
    .expect("legacy collection state");
    fixture.sign_in(MAX_20X);
    fixture.clear_spawns();
    // An immutable settings file stays readable, but the atomic rename
    // that would persist the back-fill fails.
    let settings = fixture
        .root
        .join("support")
        .join(ottto_core::CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME);
    let chflags = |flag: &str| {
        assert!(std::process::Command::new("/usr/bin/chflags")
            .arg(flag)
            .arg(&settings)
            .status()
            .expect("chflags")
            .success());
    };
    chflags("uchg");
    let status = collect_registered_claude_slot_status(
        &slot_id,
        binding_test_time(0),
        binding_test_time(15),
    );
    let spawns = fixture.slot_spawns();
    chflags("nouchg");
    assert_eq!(
        FileClaudeConfigSlotSettingsStore::default()
            .expected_slot_binding(&slot_id)
            .expect("read"),
        None,
        "the back-fill really was not persisted"
    );
    assert_eq!(
        status.state,
        ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    );
    assert_eq!(
        status.account_identifier_hash.as_deref(),
        Some(team.0.as_str())
    );
    assert!(spawns.is_empty(), "{spawns:?}");
}

#[test]
#[serial]
fn direct_slot_check_refuses_another_account_and_resumes_for_the_approved_one() {
    let fixture = ClaudeBindingFixture::new("direct-check");
    let team = ClaudeBindingFixture::hashes(TEAM_PREMIUM);
    fixture.sign_in(TEAM_PREMIUM);
    let slot_id = fixture.register();
    let first = collect_registered_claude_slot_status(
        &slot_id,
        binding_test_time(0),
        binding_test_time(15),
    );
    assert_eq!(first.state, ClaudeConfigSlotCollectionStateV1::Fresh);

    fixture.sign_in(MAX_20X);
    fixture.clear_spawns();
    let mismatched = collect_registered_claude_slot_status(
        &slot_id,
        binding_test_time(0),
        binding_test_time(15),
    );
    assert_eq!(
        mismatched.state,
        ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    );
    assert_eq!(
        mismatched.account_identifier_hash.as_deref(),
        Some(team.0.as_str())
    );
    assert!(mismatched
        .quota_snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot
            .quota_windows
            .iter()
            .all(|window| window.used_percent == Some(41))));
    assert!(fixture.slot_spawns().is_empty());

    fixture.sign_in(TEAM_PREMIUM);
    let recovered = collect_registered_claude_slot_status(
        &slot_id,
        binding_test_time(0),
        binding_test_time(15),
    );
    assert_eq!(recovered.state, ClaudeConfigSlotCollectionStateV1::Fresh);
}

#[test]
#[serial]
fn bound_slot_with_unreadable_account_file_fails_closed_without_refresh() {
    let fixture = ClaudeBindingFixture::new("unknown-login");
    let team = ClaudeBindingFixture::hashes(TEAM_PREMIUM);
    fixture.sign_in(TEAM_PREMIUM);
    let slot_id = fixture.register();
    fixture.collect();
    assert!(FileClaudeConfigSlotSettingsStore::default()
        .expected_slot_binding(&slot_id)
        .expect("read")
        .is_some());

    for broken in [None, Some("{not json"), Some(r#"{"oauthAccount":{}}"#)] {
        match broken {
            None => {
                fs::remove_file(fixture.slot_dir.join(".claude.json")).expect("remove account file")
            }
            Some(body) => fs::write(fixture.slot_dir.join(".claude.json"), body)
                .expect("write broken account file"),
        }
        fixture.clear_spawns();
        let snapshots = fixture.collect();
        let slot = fixture.slot(&slot_id);
        assert_eq!(
            slot.collection.state,
            ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
            "{broken:?}"
        );
        assert_eq!(
            slot.collection.account_identifier_hash.as_deref(),
            Some(team.0.as_str())
        );
        assert!(slot.collection.diagnostics[0]
            .message
            .contains("missing or unreadable"));
        assert!(
            fixture.slot_spawns().is_empty(),
            "no auth status or refresh for an unknown login: {:?}",
            fixture.slot_spawns()
        );
        assert!(
            crate::agent_status::claude_slot_login_unapproved(&slot),
            "the upkeep worker fences refuse an unknown login"
        );
        assert!(snapshots
            .iter()
            .filter(|snapshot| snapshot_binding(snapshot).as_ref() == Some(&team))
            .all(|snapshot| snapshot.status == AgentStatusState::Degraded));
    }
    fixture.sign_in(TEAM_PREMIUM);
    fixture.collect();
    assert_eq!(
        fixture.slot(&slot_id).collection.state,
        ClaudeConfigSlotCollectionStateV1::Fresh
    );
}

/// Passive Claude Code readings (`cachedUsageUtilization`) carry no
/// organization, so one is adopted only inside a continuous run of passes
/// that all saw the caller signed in to the exact binding. Each harness
/// run proves one way a pass can end that run.
struct PassiveRunHarness<'a> {
    fixture: &'a ClaudeBindingFixture,
    /// The Claude Code config whose passive reading the caller may adopt.
    config: PathBuf,
    team: (String, String),
}

impl PassiveRunHarness<'_> {
    /// Make the binding due, keeping its stored credit sections.
    fn make_due(&self) {
        let observed = current_unix_seconds() - 2 * 60 * 60;
        let credit_balances = read_claude_oauth_usage_cache(&self.team.0, &self.team.1)
            .map(|cache| cache.credit_balances)
            .unwrap_or_default();
        let window = AgentQuotaWindow {
            name: "session".to_string(),
            scope: AgentQuotaWindowScope::Account,
            freshness: AgentQuotaWindowFreshness::Fresh,
            used_percent: Some(10),
            account_identifier_hash: Some(self.team.0.clone()),
            organization_identifier_hash: Some(self.team.1.clone()),
            ..Default::default()
        };
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: self.team.0.clone(),
            organization_identifier_hash: self.team.1.clone(),
            observed_at_epoch_seconds: observed,
            next_refresh_after_epoch_seconds: observed,
            windows: vec![window],
            credit_balances,
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        })
        .expect("write due cache");
    }

    /// Passive input only stands in for a plain slot: make the next slot
    /// plain (the saved-reset variant paused), so only the sign-in run can
    /// refuse the body.
    fn force_plain_slot(&self) {
        let state_dir = claude_oauth_usage_account_state_dir(&self.team.0, &self.team.1);
        let mut schedule = claude_credit_pools::read_claude_read_schedule(&state_dir);
        schedule.saved_resets_variant_paused_until = Some(current_unix_seconds() + 3_600);
        claude_credit_pools::write_claude_read_schedule(&state_dir, &schedule)
            .expect("write schedule");
    }

    fn passive(&self, fetched_at: u64) {
        let mut config: Value =
            serde_json::from_slice(&fs::read(&self.config).expect("read identity")).expect("json");
        config["cachedUsageUtilization"] = serde_json::json!({
            "fetchedAtMs": fetched_at * 1_000,
            "accountUuid": TEAM_PREMIUM.0,
            "utilization": {
                "five_hour": {"utilization": 77, "resets_at": "2026-10-01T15:00:00+00:00"},
                "seven_day": {"utilization": 33, "resets_at": "2026-10-04T05:00:00+00:00"}
            }
        });
        fs::write(
            &self.config,
            serde_json::to_vec(&config).expect("serialize"),
        )
        .expect("write");
    }

    fn calls() -> usize {
        CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn cache_observed_at(&self) -> u64 {
        read_claude_oauth_usage_cache(&self.team.0, &self.team.1)
            .expect("team cache")
            .observed_at_epoch_seconds
    }

    /// Pass 1 opens the run; pass 2 adopts a body fetched inside it;
    /// `skipped_pass` runs a pass that must end the run and `restore`
    /// undoes its cause; pass 4 must call the provider rather than adopt a
    /// body fetched during the skipped pass, which the old run would
    /// still cover.
    fn assert_skipped_pass_ends_run(
        &self,
        pass: &dyn Fn(),
        skipped_pass: &dyn Fn(),
        restore: &dyn Fn(),
    ) {
        struct ForbidProviderCalls;
        impl Drop for ForbidProviderCalls {
            fn drop(&mut self) {
                CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN.store(true, std::sync::atomic::Ordering::SeqCst);
        let _forbid = ForbidProviderCalls;

        self.make_due();
        self.passive(current_unix_seconds() - 60);
        let before = Self::calls();
        pass();
        assert_eq!(
            Self::calls(),
            before + 1,
            "a call, not the older passive body"
        );

        self.make_due();
        let fetched = current_unix_seconds();
        self.passive(fetched);
        let before = Self::calls();
        pass();
        assert_eq!(Self::calls(), before, "the passive body replaced the call");
        assert_eq!(self.cache_observed_at(), fetched);

        // The body is fetched during the skipped pass: after the run
        // opened, before the next accepted pass. Whole-second clocks, so
        // the passes are spaced apart.
        std::thread::sleep(Duration::from_millis(1_100));
        let fetched = current_unix_seconds();
        skipped_pass();
        restore();
        std::thread::sleep(Duration::from_millis(1_100));

        self.make_due();
        self.force_plain_slot();
        self.passive(fetched);
        let before = Self::calls();
        pass();
        assert_eq!(Self::calls(), before + 1, "never adopted across that pass");
        assert_ne!(self.cache_observed_at(), fetched);
    }
}

fn slot_harness(fixture: &ClaudeBindingFixture) -> PassiveRunHarness<'_> {
    PassiveRunHarness {
        fixture,
        config: fixture.slot_dir.join(".claude.json"),
        team: ClaudeBindingFixture::hashes(TEAM_PREMIUM),
    }
}

/// Clears the pre-gate test hook on drop.
struct PreGateHook;

impl PreGateHook {
    /// Between this pass's pre-collection gate and its resolution read,
    /// the slot signs in to another account.
    fn sign_in_between_reads(slot_dir: PathBuf, which: (&'static str, &'static str)) -> Self {
        *CLAUDE_SLOT_AFTER_PRE_GATE_HOOK.lock().unwrap() =
            Some(Box::new(move || sign_in_slot_dir(&slot_dir, which)));
        Self
    }
}

impl Drop for PreGateHook {
    fn drop(&mut self) {
        *CLAUDE_SLOT_AFTER_PRE_GATE_HOOK.lock().unwrap() = None;
    }
}

/// The slot's login changes between the pre-collection gate and the
/// resolution read: the post-resolution gate refuses, in the slot loop.
#[test]
#[serial]
fn slot_post_resolution_gate_never_lets_a_passive_reading_through() {
    let fixture = ClaudeBindingFixture::new("passive-post-gate");
    fixture.sign_in(TEAM_PREMIUM);
    let slot_id = fixture.register();
    fixture.collect();
    let harness = slot_harness(&fixture);
    harness.assert_skipped_pass_ends_run(
        &|| {
            harness.fixture.collect();
        },
        &|| {
            let _hook = PreGateHook::sign_in_between_reads(fixture.slot_dir.clone(), MAX_20X);
            fixture.collect();
            assert_eq!(
                fixture.slot(&slot_id).collection.state,
                ClaudeConfigSlotCollectionStateV1::IdentityMismatch
            );
        },
        &|| fixture.sign_in(TEAM_PREMIUM),
    );
}

static PASSIVE_SLOT_REQUESTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn respond_cedar_fixture(endpoint: &str) -> Result<Value, u16> {
    PASSIVE_SLOT_REQUESTS
        .lock()
        .unwrap()
        .push(endpoint.to_string());
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/agent-status/quota-contract-v2.2/provider");
    let name = if endpoint.contains("cedar_ember") {
        "claude-usage-cedar.json"
    } else {
        "claude-oauth-usage-plain.json"
    };
    Ok(serde_json::from_slice(&fs::read(dir.join(name)).expect("fixture")).expect("json"))
}

/// A slot whose Claude Code keeps a fresh matching body at every pass:
/// the passive body stands in for plain slots only, and the saved-reset
/// slot still makes its variant call.
#[test]
#[serial]
fn passive_body_never_displaces_a_saved_reset_slot() {
    let fixture = ClaudeBindingFixture::new("passive-saved-slot");
    fixture.sign_in(TEAM_PREMIUM);
    fixture.register();
    fixture.collect();
    let harness = slot_harness(&fixture);
    *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(respond_cedar_fixture);
    PASSIVE_SLOT_REQUESTS.lock().unwrap().clear();
    let mut adopted = Vec::new();
    for _ in 0..4 {
        std::thread::sleep(Duration::from_millis(1_100));
        harness.make_due();
        let fetched = current_unix_seconds();
        harness.passive(fetched);
        let before = PASSIVE_SLOT_REQUESTS.lock().unwrap().len();
        fixture.collect();
        adopted.push(PASSIVE_SLOT_REQUESTS.lock().unwrap().len() == before);
    }
    *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
    // plain (passive) → saved resets (call) → plain (passive) → saved resets (call)
    assert_eq!(adopted, [true, false, true, false]);
    assert!(PASSIVE_SLOT_REQUESTS
        .lock()
        .unwrap()
        .iter()
        .all(|endpoint| endpoint.contains("cedar_ember=1")));
}

fn respond_variant_unrecognized(_endpoint: &str) -> Result<Value, u16> {
    Ok(serde_json::json!({
        "five_hour": {"utilization": 12, "resets_at": "2026-10-01T15:00:00+00:00"},
        "seven_day": {"utilization": 34, "resets_at": "2026-10-04T05:00:00+00:00"},
        "cedar_ember": null, "extra_usage": null, "spend": null
    }))
}

fn respond_variant_without_windows(_endpoint: &str) -> Result<Value, u16> {
    Ok(serde_json::json!({}))
}

/// The variant self-check diagnostic survives slot sanitization and
/// reaches the upload, with and without windows in the body.
#[test]
#[serial]
fn unrecognized_variant_diagnostic_reaches_the_upload() {
    for respond in [
        respond_variant_without_windows as ClaudeOAuthTestResponder,
        respond_variant_unrecognized,
    ] {
        let fixture = ClaudeBindingFixture::new("variant-upload");
        fixture.sign_in(TEAM_PREMIUM);
        let slot_id = fixture.register();
        fixture.collect();
        let team = ClaudeBindingFixture::hashes(TEAM_PREMIUM);
        let state_dir = claude_oauth_usage_account_state_dir(&team.0, &team.1);
        let now = current_unix_seconds();
        claude_credit_pools::write_claude_read_schedule(
            &state_dir,
            &claude_credit_pools::ClaudeReadSchedule {
                last_plain_read_at: Some(now - 3_600),
                ..Default::default()
            },
        )
        .expect("write schedule");
        let _ = fs::remove_file(claude_oauth_usage_cache_path(&team.0, &team.1));
        *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(respond);
        let snapshots = fixture.collect();
        *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
        let upload = serde_json::to_string(
            &snapshots
                .into_iter()
                .map(|snapshot| snapshot.redacted_for_backend())
                .collect::<Vec<_>>(),
        )
        .expect("serialize upload");
        assert!(
            upload.contains("claude_saved_reset_variant_unrecognized"),
            "upload carries the code"
        );
        assert!(upload.contains(CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE));
        assert!(fixture
            .slot(&slot_id)
            .collection
            .quota_check_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "claude_saved_reset_variant_unrecognized"));
    }
}

fn respond_rate_limited(_endpoint: &str) -> Result<Value, u16> {
    Err(429)
}

/// The 429 diagnostic is local only: local status (snapshots and the
/// registered slot) keeps it, the upload never carries it.
#[test]
#[serial]
fn rate_limited_diagnostic_stays_local_and_is_never_uploaded() {
    let fixture = ClaudeBindingFixture::new("rate-limited-local");
    fixture.sign_in(TEAM_PREMIUM);
    let slot_id = fixture.register();
    fixture.collect();
    let team = ClaudeBindingFixture::hashes(TEAM_PREMIUM);
    claude_credit_pools::write_claude_read_schedule(
        &claude_oauth_usage_account_state_dir(&team.0, &team.1),
        &claude_credit_pools::ClaudeReadSchedule {
            last_plain_read_at: Some(current_unix_seconds() - 3_600),
            ..Default::default()
        },
    )
    .expect("write schedule");
    let _ = fs::remove_file(claude_oauth_usage_cache_path(&team.0, &team.1));
    *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(respond_rate_limited);
    let snapshots = fixture.collect();
    *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
    let local = serde_json::to_string(&snapshots).expect("local status");
    let slot = fixture.slot(&slot_id);
    assert!(
        local.contains(CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE),
        "local snapshots keep the 429 diagnostic"
    );
    assert!(
        slot.collection
            .quota_check_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE),
        "slot status keeps the 429 diagnostic"
    );
    let upload = serde_json::to_string(
        &snapshots
            .into_iter()
            .map(|snapshot| snapshot.redacted_for_backend())
            .collect::<Vec<_>>(),
    )
    .expect("serialize upload");
    assert!(!upload.contains(CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE));
    assert!(!upload.contains("Claude asked Ottto to wait"));
}

fn respond_variant_reader_blind(_endpoint: &str) -> Result<Value, u16> {
    Ok(serde_json::from_str(include_str!(
        "../../../../fixtures/agent-status/quota-contract-v2.2/provider/claude-usage-cedar-reader-surface.json"
    ))
    .expect("fixture"))
}

/// Contract v2.2 §11.10: a reader-blind saved-reset reading reaches the
/// local status snapshots the Companion decodes and the upload with
/// `grants_unavailable_cause` under the same name, and no count.
#[test]
#[serial]
fn reader_blind_saved_resets_reach_local_status_and_upload() {
    let fixture = ClaudeBindingFixture::new("reader-blind");
    fixture.sign_in(TEAM_PREMIUM);
    fixture.register();
    fixture.collect();
    let team = ClaudeBindingFixture::hashes(TEAM_PREMIUM);
    let state_dir = claude_oauth_usage_account_state_dir(&team.0, &team.1);
    let now = current_unix_seconds();
    claude_credit_pools::write_claude_read_schedule(
        &state_dir,
        &claude_credit_pools::ClaudeReadSchedule {
            last_plain_read_at: Some(now - 3_600),
            ..Default::default()
        },
    )
    .expect("write schedule");
    let _ = fs::remove_file(claude_oauth_usage_cache_path(&team.0, &team.1));
    *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(respond_variant_reader_blind);
    let snapshots = fixture.collect();
    *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
    let reader_blind = |balances: &Value| {
        balances
            .as_array()
            .into_iter()
            .flatten()
            .filter(|balance| balance["kind"] == "saved_resets")
            .cloned()
            .collect::<Vec<_>>()
    };
    let local = serde_json::to_value(&snapshots).expect("local status");
    let saved = local
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|snapshot| reader_blind(&snapshot["credit_balances"]))
        .collect::<Vec<_>>();
    let upload = serde_json::to_value(
        snapshots
            .into_iter()
            .map(|snapshot| snapshot.redacted_for_backend())
            .collect::<Vec<_>>(),
    )
    .expect("upload");
    let uploaded = upload
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|snapshot| reader_blind(&snapshot["credit_balances"]))
        .collect::<Vec<_>>();
    for (label, balances) in [("local", saved), ("upload", uploaded)] {
        assert!(!balances.is_empty(), "{label}: saved resets present");
        for balance in balances {
            assert_eq!(balance["grants_unavailable_cause"], "reader", "{label}");
            assert_eq!(balance["grants_state"], "unavailable", "{label}");
            assert_eq!(balance["status"], "unknown", "{label}");
            assert_eq!(balance["ineligible_reason"], "surface", "{label}");
            assert_eq!(balance["eligible"], false, "{label}");
            for absent in ["remaining", "grant_count", "grants"] {
                assert!(balance.get(absent).is_none(), "{label}: {absent}");
            }
        }
    }
}

#[test]
fn binding_mismatch_message_names_plans_only() {
    assert_eq!(
        claude_plan_label(Some("max_20x")).as_deref(),
        Some("Claude Ultra")
    );
    assert_eq!(
        claude_plan_label(Some("claude_max_5x")).as_deref(),
        Some("Claude Max")
    );
    assert_eq!(
        claude_plan_label(Some("max")).as_deref(),
        Some("Claude Max or Ultra")
    );
    assert_eq!(
        claude_plan_label(Some("claude_team_premium")).as_deref(),
        Some("Claude Team Premium")
    );
    assert_eq!(
        claude_plan_label(Some("pro")).as_deref(),
        Some("Claude Pro")
    );
    assert_eq!(claude_plan_label(None), None);
    let message = claude_slot_binding_mismatch_message(Some("team_premium"), Some("max_20x"));
    assert!(message.contains("a different Claude Ultra account"));
    assert!(message.contains("the Claude Team Premium account"));
    let unknown = claude_slot_binding_mismatch_message(None, None);
    assert!(unknown.contains("a different Claude account"));
    assert!(unknown.contains("the account it was set up with"));
}
