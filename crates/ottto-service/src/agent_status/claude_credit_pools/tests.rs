//! Tests for the Claude credit-pool adapter: decoding provider usage bodies into
//! credit balances, and the explicit refresh and usage-cache paths around it.

use super::*;
use ottto_protocol::{
    AgentCreditBalanceStatus, CreditAmount, CreditGrantStatus, CreditGrantsState,
};
use serde_json::json;

use crate::agent_status::credit_amount_input::{decode, usage_body, CreditBody};

// Synthetic bodies shaped like the redacted real plain and saved-reset
// variant responses (account/org/grant ids are invented).
const READ_AT: &str = "2026-10-09T14:06:52Z";

fn window(utilization: u64, resets_at: Option<&str>) -> Value {
    json!({
        "utilization": utilization, "resets_at": resets_at,
        "limit_dollars": null, "used_dollars": null, "remaining_dollars": null,
        "locked_reason": null
    })
}

fn pool(limit: f64, used: f64, remaining: f64, resets_at: &str) -> Value {
    json!({
        "utilization": 0, "resets_at": resets_at, "limit_dollars": limit,
        "used_dollars": used, "remaining_dollars": remaining, "locked_reason": null
    })
}

/// Plain read of a Max account: the $250 one-time pool, an expired pool,
/// a percent-only pool, usage credits off.
fn plain_max_body() -> Value {
    usage_body(json!({
        "five_hour": window(0, None),
        "seven_day": window(100, Some("2026-10-10T05:00:00.377761+00:00")),
        "seven_day_opus": null,
        "iguana_necktie": pool(250.0, 0.0, 250.0, "2026-11-05T07:59:00+00:00"),
        "amber_ladder": {
            "utilization": 100, "resets_at": "2026-10-02T06:59:59+00:00",
            "limit_dollars": 2500, "used_dollars": 2501.367212,
            "remaining_dollars": 0.0, "locked_reason": null
        },
        "cinder_cove": {"utilization": 4, "resets_at": "2026-11-01T00:00:00+00:00"},
        "nimbus_quill": null,
        "wattle_ember": null,
        "cedar_ember": null,
        "extra_usage": {
            "is_enabled": false, "monthly_limit": null, "used_credits": null,
            "disabled_reason": null, "user_disabled": true
        },
        "spend": {
            "used": {"amount_minor": 0, "currency": "USD", "exponent": 2},
            "limit": null, "percent": 0, "severity": "normal", "enabled": false,
            "disabled_reason": null, "cap": null, "balance": null
        }
    }))
}

fn cedar_grant(id: &str, label: &str, resets_left: u64, usable_now: bool) -> Value {
    json!({
        "id": id, "label": label, "resets_total": 1, "resets_left": resets_left,
        "starts_at": "2026-09-22T16:00:00+00:00", "ends_at": "2026-10-22T16:00:00+00:00",
        "clears": ["five_hour", "seven_day", "seven_day_overage_included"],
        "paused": false, "usable_now": usable_now, "use_requires_limit": false,
        "percent_used": {"five_hour": 0, "seven_day": 0}, "blocking": [], "arm": null
    })
}

fn variant_body(cedar: Value) -> Value {
    usage_body(json!({
        "five_hour": window(38, Some("2026-10-04T20:20:00.508208+00:00")),
        "seven_day": window(100, Some("2026-10-08T17:00:00.508227+00:00")),
        "iguana_necktie": pool(250.0, 0.0, 250.0, "2026-11-05T07:59:00+00:00"),
        "cedar_ember": cedar,
        "extra_usage": null,
        "spend": null
    }))
}

fn cedar_team() -> Value {
    json!({
        "eligible": true, "ineligible_reason": null, "at_limit": false, "exhausted": [],
        "grants": [cedar_grant("grant_team_01", "Launch: one usage-limit reset for Team members", 0, false)],
        "next_grant_id": null, "weekly_resets_at": "2026-09-25T14:00:00+00:00",
        "cooldown_until": "2026-09-23T16:21:19.342795+00:00",
        "event_props": {"tier": "claude_team"}
    })
}

fn cedar_max() -> Value {
    json!({
        "eligible": true, "ineligible_reason": null, "at_limit": true,
        "exhausted": ["seven_day"],
        "grants": [cedar_grant("grant_max_01", "Launch: one usage-limit reset for Pro and Max", 1, true)],
        "next_grant_id": "grant_max_01", "cooldown_until": null
    })
}

fn cedar_ineligible() -> Value {
    json!({
        "eligible": false, "ineligible_reason": "tenure", "at_limit": false,
        "exhausted": [], "grants": [], "next_grant_id": null,
        "cooldown_until": null, "paused_held": false
    })
}

fn saved_resets(cedar: Value) -> AgentCreditBalance {
    let read = claude_credit_read(&variant_body(cedar), ClaudeUsageRead::SavedResets, READ_AT);
    // The variant skips `spend`; its one-time pools are fresh.
    assert!(read.usage_credits.is_none());
    assert_eq!(read.one_time_credits.as_ref().map(Vec::len), Some(1));
    let mut balances = read.saved_resets.expect("cedar_ember observed");
    assert_eq!(balances.len(), 1);
    balances.remove(0)
}

#[test]
fn plain_body_maps_iguana_necktie_one_time_credit() {
    let read = claude_credit_read(&plain_max_body(), ClaudeUsageRead::Plain, READ_AT);
    let pools = read.one_time_credits.clone().unwrap();
    assert_eq!(
        pools.len(),
        1,
        "expired, percent-only and null pools are skipped"
    );
    let credit = &pools[0];
    assert_eq!(credit.name, "one_time_credit");
    assert_eq!(credit.kind, Some(CreditBalanceKind::OneTimeCredit));
    assert_eq!(credit.limit_id.as_deref(), Some("iguana_necktie"));
    assert_eq!(credit.unit, AgentCreditBalanceUnit::Usd);
    assert_eq!(credit.currency.as_deref(), Some("USD"));
    assert_eq!(credit.quota, CreditAmount::whole(25_000));
    assert_eq!(credit.used, CreditAmount::whole(0));
    assert_eq!(credit.remaining, CreditAmount::whole(25_000));
    assert_eq!(credit.expires_at.as_deref(), Some("2026-11-05T07:59:00Z"));
    assert_eq!(credit.resets_at, None);
    assert_eq!(credit.enabled, None);
    assert_eq!(credit.status, AgentCreditBalanceStatus::Ok);
    assert_eq!(credit.observed_at.as_deref(), Some(READ_AT));
    assert_eq!(credit.title, None);
    // The plain read carries the usage-credit section too, and never a
    // saved-reset one (`cedar_ember` is null there).
    let usage = read.usage_credits.clone().unwrap();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].kind, Some(CreditBalanceKind::UsageCredits));
    assert_eq!(usage[0].enabled, Some(false));
    assert_eq!(usage[0].observed_at.as_deref(), Some(READ_AT));
    assert!(read.saved_resets.is_none());
    assert!(read.diagnostics.is_empty());
}

#[test]
fn one_time_pool_label_becomes_title_and_windows_are_never_pools() {
    let body = json!({
        "five_hour": {"utilization": 1, "resets_at": null, "limit_dollars": 9},
        "seven_day_cowork": {"utilization": 1, "resets_at": null, "limit_dollars": 9},
        "wattle_ember": {
            "utilization": 10, "resets_at": "2027-01-01T00:00:00Z", "label": "Promo credit",
            "limit_dollars": 20, "used_dollars": 2, "remaining_dollars": 18
        },
        "Bad Key": {"limit_dollars": 1}
    });
    let pools = claude_one_time_credits(&body, READ_AT, &mut Vec::new());
    assert_eq!(pools.len(), 1);
    assert_eq!(pools[0].limit_id.as_deref(), Some("wattle_ember"));
    assert_eq!(pools[0].title.as_deref(), Some("Promo credit"));
    assert_eq!(pools[0].remaining, CreditAmount::whole(1_800));
}

#[test]
fn usage_credits_off_carries_the_reason_code() {
    let mut body = plain_max_body();
    body["spend"]["disabled_reason"] = json!("out_of_credits");
    let usage = super::super::claude_oauth_credit_balances(&body);
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].name, CLAUDE_USAGE_CREDITS_NAME);
    assert_eq!(usage[0].kind, Some(CreditBalanceKind::UsageCredits));
    assert_eq!(usage[0].enabled, Some(false));
    assert_eq!(usage[0].status, AgentCreditBalanceStatus::Unknown);
    assert_eq!(usage[0].disabled_reason.as_deref(), Some("out_of_credits"));
    // Not a reason code: dropped, never sent as free text.
    body["spend"]["disabled_reason"] = json!("Out of credits!");
    let usage = super::super::claude_oauth_credit_balances(&body);
    assert_eq!(usage[0].disabled_reason, None);
    // The `extra_usage` fallback carries its own reason.
    let fallback = super::super::claude_oauth_credit_balances(&json!({
        "extra_usage": {"is_enabled": false, "disabled_reason": "org_level_disabled"}
    }));
    assert_eq!(
        fallback[0].disabled_reason.as_deref(),
        Some("org_level_disabled")
    );
    // Enabled credits never carry a reason.
    let enabled = super::super::claude_oauth_credit_balances(&json!({
        "spend": {"enabled": true, "disabled_reason": "out_of_credits",
                  "used": {"amount_minor": 1, "exponent": 2}}
    }));
    assert_eq!(enabled[0].disabled_reason, None);
    assert_eq!(enabled[0].enabled, Some(true));
}

#[test]
fn cedar_team_grant_used_with_cooldown() {
    let balance = saved_resets(cedar_team());
    assert_eq!(balance.name, "reset_bank");
    assert_eq!(balance.kind, Some(CreditBalanceKind::SavedResets));
    assert_eq!(balance.unit, AgentCreditBalanceUnit::Resets);
    assert_eq!(balance.limit_id, None);
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
    assert_eq!(balance.grant_count, Some(1));
    assert_eq!(balance.grants_observed_at.as_deref(), Some(READ_AT));
    assert_eq!(balance.observed_at.as_deref(), Some(READ_AT));
    assert_eq!(balance.remaining, CreditAmount::whole(0));
    assert_eq!(balance.status, AgentCreditBalanceStatus::Exhausted);
    assert_eq!(balance.eligible, Some(true));
    assert_eq!(balance.at_limit, Some(false));
    assert_eq!(balance.ineligible_reason, None);
    assert_eq!(
        balance.cooldown_until.as_deref(),
        Some("2026-09-23T16:21:19.342795Z")
    );
    // A redeemed grant is not a basis for the expiry summary.
    assert_eq!(balance.next_expires_at, None);
    assert_eq!(balance.latest_granted_at, None);
    assert_eq!(balance.enabled, None);
    let grants = balance.grants.as_ref().unwrap();
    assert_eq!(grants.len(), 1);
    let grant = &grants[0];
    assert_eq!(
        grant.grant_key,
        crate::quota_credit_model::credit_grant_key(Provider::Anthropic, "grant_team_01")
    );
    assert_eq!(grant.status, CreditGrantStatus::Redeemed);
    assert_eq!(grant.resets_included, Some(1));
    assert_eq!(grant.resets_left, Some(0));
    assert_eq!(grant.usable_now, Some(false));
    assert_eq!(grant.starts_at.as_deref(), Some("2026-09-22T16:00:00Z"));
    assert_eq!(grant.expires_at.as_deref(), Some("2026-10-22T16:00:00Z"));
    assert_eq!(grant.granted_at, None);
    assert_eq!(grant.clears.as_ref().map(Vec::len), Some(3));
    assert_eq!(
        grant.title.as_deref(),
        Some("Launch: one usage-limit reset for Team members")
    );
}

fn cedar_reader_blind(reason: &str, grants: Option<Value>) -> Value {
    let mut cedar = cedar_ineligible();
    cedar["ineligible_reason"] = json!(reason);
    match grants {
        Some(grants) => cedar["grants"] = grants,
        None => {
            cedar.as_object_mut().unwrap().remove("grants");
        }
    }
    cedar
}

fn assert_reader_unavailable(balance: &AgentCreditBalance, reason: &str) {
    assert_eq!(
        balance.grants_unavailable_cause,
        Some(CreditGrantsUnavailableCause::Reader),
        "{reason}"
    );
    assert!(ottto_protocol::credit_grants_unavailable_cause_allowed(
        balance
    ));
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Unavailable));
    assert_eq!(balance.grants, None);
    assert_eq!(balance.remaining, None);
    assert_eq!(balance.grant_count, None);
    assert_eq!(balance.grants_observed_at, None);
    assert_eq!(balance.next_expires_at, None);
    assert_eq!(balance.latest_granted_at, None);
    assert_eq!(balance.status, AgentCreditBalanceStatus::Unknown);
    // Readiness stays exactly as read.
    assert_eq!(balance.eligible, Some(false));
    assert_eq!(balance.at_limit, Some(false));
    assert_eq!(balance.ineligible_reason.as_deref(), Some(reason));
}

/// The cause never appears on any other shape: across every Claude
/// fixture, both reads, re-sends, a stored list followed by a reader-blind
/// answer and back, and an older daemon's stored reader-blind reading.
#[test]
fn grants_unavailable_cause_appears_on_no_other_shape() {
    fn check(balances: &[AgentCreditBalance]) {
        for balance in balances {
            let blind = claude_reader_cannot_see_grants(balance);
            assert_eq!(
                balance.grants_unavailable_cause.is_some(),
                blind,
                "{balance:?}"
            );
            if blind {
                assert_reader_unavailable(
                    balance,
                    balance.ineligible_reason.as_deref().unwrap(),
                );
            }
        }
    }
    for name in [
        "claude-oauth-usage-plain",
        "claude-oauth-usage-credits-off",
        "claude-usage-cedar",
        "claude-usage-cedar-ineligible",
        "claude-usage-cedar-reader-surface",
        "claude-usage-cedar-reader-cli-version",
        "claude-usage-cedar-refused-expiry",
    ] {
        for read in [ClaudeUsageRead::Plain, ClaudeUsageRead::SavedResets] {
            let body = fixture(&format!("provider/{name}.json"));
            let read = claude_credit_read(&body, read, READ_AT);
            check(&claude_merge_credit_sections("fixture", &[], &read));
        }
    }
    let read = |cedar: Value| {
        claude_credit_read(&variant_body(cedar), ClaudeUsageRead::SavedResets, READ_AT)
    };
    let plain = claude_credit_read(&plain_max_body(), ClaudeUsageRead::Plain, READ_AT);
    let listed = claude_merge_credit_sections("b", &[], &read(cedar_max()));
    let blind = claude_merge_credit_sections(
        "b",
        &listed,
        &read(cedar_reader_blind("surface", Some(json!([])))),
    );
    // A readiness-only blind answer never takes the stored list.
    let blind_no_list =
        claude_merge_credit_sections("b", &listed, &read(cedar_reader_blind("surface", None)));
    let resent = claude_merge_credit_sections("b", &blind, &plain);
    // Back to a readable answer: an ordinary list again, without the cause.
    let back = claude_merge_credit_sections("b", &resent, &read(cedar_max()));
    let readiness_only = claude_merge_credit_sections(
        "b",
        &blind,
        &read(json!({"eligible": true, "ineligible_reason": null})),
    );
    for balances in [
        &listed,
        &blind,
        &blind_no_list,
        &resent,
        &back,
        &readiness_only,
    ] {
        check(balances);
    }
    let saved = |balances: &[AgentCreditBalance]| {
        balances
            .iter()
            .find(|balance| balance.kind == Some(CreditBalanceKind::SavedResets))
            .cloned()
            .expect("saved resets")
    };
    assert_reader_unavailable(&saved(&blind_no_list), "surface");
    assert_reader_unavailable(&saved(&resent), "surface");
    assert_eq!(saved(&back).grants_unavailable_cause, None);
    assert_eq!(saved(&back).remaining, CreditAmount::whole(1));
    assert_eq!(saved(&readiness_only).grants_unavailable_cause, None);
    // An older daemon stored the blind answer as a complete, empty list:
    // re-sent and served in the §11.10 shape.
    let mut older = saved(&read_older_blind());
    older.grants_unavailable_cause = None;
    older.grants = Some(Vec::new());
    older.grants_state = Some(CreditGrantsState::Complete);
    older.grant_count = Some(0);
    older.remaining = Some(CreditAmount::ZERO);
    older.grants_observed_at = Some(READ_AT.to_string());
    older.status = AgentCreditBalanceStatus::Exhausted;
    let resent = claude_merge_credit_sections("b", &[older.clone()], &plain);
    assert_reader_unavailable(&saved(&resent), "surface");
    let mut served = vec![older];
    label_credit_freshness(&mut served, 3_600, 0, 0);
    assert_reader_unavailable(&served[0], "surface");
}

fn read_older_blind() -> Vec<AgentCreditBalance> {
    claude_credit_read(
        &variant_body(cedar_reader_blind("surface", Some(json!([])))),
        ClaudeUsageRead::SavedResets,
        READ_AT,
    )
    .saved_resets
    .unwrap()
}

#[test]
fn cedar_drift_is_refused_field_by_field() {
    let mut cedar = cedar_max();
    cedar["ineligible_reason"] = json!("Not Eligible");
    cedar["at_limit"] = json!("yes");
    cedar["cooldown_until"] = json!("soon");
    cedar["grants"][0]["usable_now"] = json!(1);
    let read = claude_credit_read(&variant_body(cedar), ClaudeUsageRead::SavedResets, READ_AT);
    let balance = &read.saved_resets.as_ref().unwrap()[0];
    assert_eq!(balance.ineligible_reason, None);
    assert_eq!(balance.at_limit, None);
    assert_eq!(balance.cooldown_until, None);
    assert_eq!(balance.grants.as_ref().unwrap()[0].usable_now, None);
    // A refused readiness or `usable_now` value never changes the list state.
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
    let fields = read.diagnostics.iter().map(|d| d.field).collect::<Vec<_>>();
    for field in [
        "ineligible_reason",
        "at_limit",
        "cooldown_until",
        "grants[].usable_now",
    ] {
        assert!(fields.contains(&field), "{field} refused with a diagnostic");
    }
    // No grants array: details unavailable, nothing invented.
    let read = claude_credit_read(
        &variant_body(json!({"eligible": true})),
        ClaudeUsageRead::SavedResets,
        READ_AT,
    );
    let balance = &read.saved_resets.as_ref().unwrap()[0];
    assert_eq!(balance.grants, None);
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Unavailable));
    assert_eq!(balance.remaining, None);
    assert_eq!(balance.status, AgentCreditBalanceStatus::Unknown);
}

fn presence(
    balances: &[AgentCreditBalance],
) -> Vec<(String, Option<String>, AgentCreditBalanceStatus)> {
    balances
        .iter()
        .map(|b| (b.name.clone(), b.limit_id.clone(), b.status.clone()))
        .collect()
}

/// Alternation, restart (the stored reading round-trips through
/// JSON) and A→B→A never toggle presence, `grants`, `grants_state` or
/// `status`; a re-sent section keeps its original read times.
#[test]
fn sections_stay_stable_across_alternation_restart_and_account_switch() {
    let plain = plain_max_body();
    let variant = variant_body(cedar_max());
    let t1 = "2026-10-09T10:00:00Z";
    let t2 = "2026-10-09T11:00:00Z";
    let t3 = "2026-10-09T12:00:00Z";

    // Cold: a first saved-reset read sends only what it observed (the
    // pool and saved resets); nothing stands in for the unread usage
    // credits.
    let cold = claude_merge_credit_sections(
        "a",
        &[],
        &claude_credit_read(&variant, ClaudeUsageRead::SavedResets, t1),
    );
    assert_eq!(
        cold.iter().map(|b| b.kind).collect::<Vec<_>>(),
        [
            Some(CreditBalanceKind::OneTimeCredit),
            Some(CreditBalanceKind::SavedResets)
        ]
    );

    let first = claude_merge_credit_sections(
        "a",
        &cold,
        &claude_credit_read(&plain, ClaudeUsageRead::Plain, t1),
    );
    let expected = presence(&first);
    assert_eq!(expected.len(), 3, "usage credits, $250 pool, saved resets");
    let mut stored = first.clone();
    let mut timeline = vec![first];
    for (read, at) in [
        (ClaudeUsageRead::SavedResets, t2),
        (ClaudeUsageRead::Plain, t3),
        (ClaudeUsageRead::SavedResets, "2026-10-09T13:00:00Z"),
    ] {
        // Restart between every read: only the stored reading survives.
        let restored: Vec<AgentCreditBalance> =
            serde_json::from_slice(&serde_json::to_vec(&stored).unwrap()).unwrap();
        let body = if read == ClaudeUsageRead::Plain {
            &plain
        } else {
            &variant
        };
        stored =
            claude_merge_credit_sections("a", &restored, &claude_credit_read(body, read, at));
        assert_eq!(presence(&stored), expected);
        timeline.push(stored.clone());
    }
    for balances in &timeline {
        let saved = balances
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
            .unwrap();
        assert!(saved.grants.is_some());
        assert_eq!(saved.grants_state, Some(CreditGrantsState::Complete));
        assert!(balances.iter().all(|b| b.updated_at.is_none()));
    }
    // After the t2 variant read the usage credits are the t1 section,
    // unchanged.
    let usage_t2 = timeline[1]
        .iter()
        .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
        .unwrap();
    assert_eq!(
        usage_t2,
        timeline[0]
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
            .unwrap()
    );
    assert_eq!(usage_t2.observed_at.as_deref(), Some(t1));
    // After the t3 plain read the saved resets are the t2 section.
    let saved_t3 = timeline[2]
        .iter()
        .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
        .unwrap();
    assert_eq!(saved_t3.grants_observed_at.as_deref(), Some(t2));

    // A→B→A: each binding keeps its own stored reading, so B never
    // empties A and A comes back with its own sections.
    let b_stored = claude_merge_credit_sections(
        "b",
        &[],
        &claude_credit_read(&json!({"spend": null}), ClaudeUsageRead::Plain, t3),
    );
    assert!(b_stored.is_empty());
    let a_again = claude_merge_credit_sections(
        "a",
        &stored,
        &claude_credit_read(
            &variant,
            ClaudeUsageRead::SavedResets,
            "2026-10-09T14:00:00Z",
        ),
    );
    assert_eq!(presence(&a_again), expected);
}

/// A plain-read body without the credit keys (a passive reading that kept
/// only windows) observes no credit section, so it never erases the stored
/// usage credits or one-time pools.
#[test]
fn body_without_credit_keys_keeps_stored_credit_sections() {
    let stored = claude_merge_credit_sections(
        "a",
        &[],
        &claude_credit_read(&plain_max_body(), ClaudeUsageRead::Plain, READ_AT),
    );
    assert_eq!(stored.len(), 2);
    let windows_only = json!({
        "five_hour": window(10, Some("2026-10-09T18:00:00+00:00")),
        "seven_day": window(20, Some("2026-10-10T05:00:00+00:00"))
    });
    let read = claude_credit_read(
        &windows_only,
        ClaudeUsageRead::Plain,
        "2026-10-09T15:00:00Z",
    );
    assert!(read.usage_credits.is_none() && read.one_time_credits.is_none());
    assert_eq!(claude_merge_credit_sections("a", &stored, &read), stored);
    // A full plain body with `spend: null` still observes its sections.
    let mut no_spend = plain_max_body();
    no_spend["spend"] = Value::Null;
    no_spend["extra_usage"] = Value::Null;
    let read = claude_credit_read(&no_spend, ClaudeUsageRead::Plain, READ_AT);
    assert_eq!(read.usage_credits.as_deref(), Some(&[][..]));
    assert_eq!(read.one_time_credits.as_ref().map(Vec::len), Some(1));
}

/// A saved-reset reading whose `cedar_ember` has readiness but no
/// `grants` array keeps the stored complete list (and so its status);
/// readiness is fresh. complete → eligible-only → complete.
#[test]
fn eligible_only_cedar_keeps_the_stored_grant_list() {
    let t1 = "2026-10-09T10:00:00Z";
    let t2 = "2026-10-09T11:00:00Z";
    let t3 = "2026-10-09T12:00:00Z";
    let complete = claude_merge_credit_sections(
        "a",
        &[],
        &claude_credit_read(&variant_body(cedar_max()), ClaudeUsageRead::SavedResets, t1),
    );
    let stored = complete
        .iter()
        .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
        .unwrap()
        .clone();
    assert_eq!(stored.grants_state, Some(CreditGrantsState::Complete));
    let readiness_only = json!({"eligible": true, "at_limit": false});
    let next = claude_merge_credit_sections(
        "a",
        &complete,
        &claude_credit_read(
            &variant_body(readiness_only),
            ClaudeUsageRead::SavedResets,
            t2,
        ),
    );
    let kept = next
        .iter()
        .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
        .unwrap();
    assert_eq!(kept.grants, stored.grants);
    assert_eq!(kept.grants_state, Some(CreditGrantsState::Complete));
    assert_eq!(
        kept.grants_observed_at.as_deref(),
        Some(t1),
        "original list time"
    );
    assert_eq!(kept.grant_count, stored.grant_count);
    assert_eq!(kept.remaining, stored.remaining);
    assert_eq!(kept.status, stored.status, "no ok → unknown flip");
    assert_eq!(kept.at_limit, Some(false), "readiness is fresh");
    assert_eq!(kept.observed_at.as_deref(), Some(t2));
    // The next full list replaces it as usual.
    let after = claude_merge_credit_sections(
        "a",
        &next,
        &claude_credit_read(
            &variant_body(cedar_team()),
            ClaudeUsageRead::SavedResets,
            t3,
        ),
    );
    let replaced = after
        .iter()
        .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
        .unwrap();
    assert_eq!(replaced.grants_observed_at.as_deref(), Some(t3));
    assert_eq!(replaced.remaining, CreditAmount::whole(0));
}

/// The model owns the codename check: a pool whose codename is not a code,
/// or is secret-shaped, is skipped with the model's `limit_id` refusal.
#[test]
fn refused_codename_pools_are_skipped_with_the_model_refusal() {
    let mut body = plain_max_body();
    body["Bad Pool"] = json!({"limit_dollars": 5, "used_dollars": 0, "remaining_dollars": 5});
    body["sk-synthetic"] =
        json!({"limit_dollars": 5, "used_dollars": 0, "remaining_dollars": 5});
    let read = claude_credit_read(&body, ClaudeUsageRead::Plain, READ_AT);
    let pools = read.one_time_credits.unwrap();
    assert_eq!(
        pools
            .iter()
            .map(|pool| pool.limit_id.as_deref())
            .collect::<Vec<_>>(),
        [Some("iguana_necktie")]
    );
    let limit_id_refusals = read
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            **diagnostic
                == crate::quota_credit_model::OneTimeCreditRefusal::LimitId.diagnostic()
        })
        .count();
    assert_eq!(limit_id_refusals, 2);
}

#[test]
fn credit_freshness_follows_each_sections_own_read_time() {
    let now = 1_791_000_000;
    let at = |age: u64| Some(rfc3339(now - age));
    let gate = 3_600;
    let mut balances = vec![
        AgentCreditBalance {
            name: CLAUDE_USAGE_CREDITS_NAME.to_string(),
            kind: Some(CreditBalanceKind::UsageCredits),
            enabled: Some(true),
            observed_at: at(gate + 60),
            ..Default::default()
        },
        AgentCreditBalance {
            name: CLAUDE_USAGE_CREDITS_NAME.to_string(),
            kind: Some(CreditBalanceKind::UsageCredits),
            enabled: Some(false),
            observed_at: at(5 * 3_600),
            ..Default::default()
        },
        AgentCreditBalance {
            name: "reset_bank".to_string(),
            kind: Some(CreditBalanceKind::SavedResets),
            observed_at: at(10),
            grants_observed_at: at(3 * gate),
            ..Default::default()
        },
        AgentCreditBalance {
            name: "legacy".to_string(),
            ..Default::default()
        },
    ];
    // The stored reading itself is brand new (a windows-only read).
    label_credit_freshness(&mut balances, gate, now - 5, now);
    let fresh = |b: &AgentCreditBalance| b.freshness == AgentQuotaWindowFreshness::Fresh;
    assert!(fresh(&balances[0]), "alternated section: two gates");
    assert!(
        !fresh(&balances[1]),
        "credits off: alternated too, two gates"
    );
    assert!(!fresh(&balances[2]), "grant list read 3 gates ago is stale");
    assert!(fresh(&balances[3]), "no own clock: the stored reading's");
}

#[test]
fn legacy_cached_usage_credit_row_is_its_section() {
    let legacy = AgentCreditBalance {
        name: CLAUDE_USAGE_CREDITS_NAME.to_string(),
        enabled: Some(false),
        ..Default::default()
    };
    let merged = claude_merge_credit_sections(
        "a",
        std::slice::from_ref(&legacy),
        &claude_credit_read(
            &variant_body(cedar_max()),
            ClaudeUsageRead::SavedResets,
            READ_AT,
        ),
    );
    assert_eq!(
        merged.len(),
        3,
        "legacy usage row, fresh pool, saved resets"
    );
    assert_eq!(merged[0], legacy);
    assert_eq!(
        balance_section(&merged[0]),
        Some(CreditSection::UsageCredits)
    );
}

fn passive_config(
    cache_account: &str,
    oauth_account: &str,
    org: &str,
    fetched_ms: u64,
) -> Value {
    json!({
        "oauthAccount": {"accountUuid": oauth_account, "organizationUuid": org},
        "cachedUsageUtilization": {
            "fetchedAtMs": fetched_ms, "accountUuid": cache_account,
            "utilization": plain_max_body()
        }
    })
}

fn hashes(account: &str, org: &str) -> (String, String) {
    (
        ottto_core::billing_identity_hash("anthropic", "account", account).unwrap(),
        ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap(),
    )
}

#[test]
fn passive_reading_is_used_only_for_the_exact_binding() {
    let (account, org) = hashes("acct-1", "org-1");
    let config = claude_passive_config(
        &passive_config("acct-1", "acct-1", "org-1", 1_791_000_000_500),
        &account,
        &org,
    );
    assert!(config.bound);
    let passive = config.reading.expect("matching binding");
    assert_eq!(passive.fetched_at, 1_791_000_000);
    // Same plain-body parser: the passive body yields the same pools.
    let read = claude_credit_read(&passive.body, ClaudeUsageRead::Plain, READ_AT);
    assert_eq!(
        read.one_time_credits.unwrap()[0].limit_id.as_deref(),
        Some("iguana_necktie")
    );
    // Signed in to this binding, but the cached body is another account's.
    let other_cache = claude_passive_config(
        &passive_config("acct-2", "acct-1", "org-1", 1),
        &account,
        &org,
    );
    assert!(other_cache.bound && other_cache.reading.is_none());
    let no_cache = claude_passive_config(
        &json!({"oauthAccount": {"accountUuid": "acct-1", "organizationUuid": "org-1"}}),
        &account,
        &org,
    );
    assert!(no_cache.bound && no_cache.reading.is_none());
    // Signed in to another account or organization, or not at all.
    for config in [
        passive_config("acct-1", "acct-2", "org-1", 1),
        passive_config("acct-1", "acct-1", "org-2", 1),
        json!({"cachedUsageUtilization": {"fetchedAtMs": 1, "accountUuid": "acct-1",
                                          "utilization": {}}}),
    ] {
        assert_eq!(
            claude_passive_config(&config, &account, &org),
            ClaudePassiveConfig::default()
        );
    }
    // Newer than our reading and inside the slot, else a call is made.
    let since = Some(0);
    assert!(claude_passive_reading_usable(
        1_000,
        Some(900),
        since,
        3_600,
        1_100
    ));
    assert!(claude_passive_reading_usable(
        1_000, None, since, 3_600, 1_100
    ));
    assert!(!claude_passive_reading_usable(
        900,
        Some(900),
        since,
        3_600,
        1_100
    ));
    assert!(!claude_passive_reading_usable(
        1_000,
        Some(900),
        since,
        3_600,
        5_000
    ));
    assert!(!claude_passive_reading_usable(
        2_000, None, since, 3_600, 1_000
    ));
}

/// The cached body has no organization: it is adopted only when it was
/// fetched inside a continuous run of passes that all saw this caller on
/// this exact binding, so a body fetched while the same account was on
/// another organization is never stamped with this one.
#[test]
fn passive_reading_needs_a_continuous_run_on_the_binding() {
    let mut callers = BTreeMap::new();
    let mut seen = |caller: &str, binding: &str, now: u64| {
        claude_observe_caller_binding(&mut callers, caller, binding, now)
    };
    // First pass: nothing earlier proves the organization.
    assert_eq!(seen("default", "a/x", 1_000), 1_000);
    assert!(!claude_passive_reading_usable(
        900,
        None,
        Some(1_000),
        3_600,
        1_000
    ));
    // Continuous passes keep the run; a body fetched inside it is adopted.
    assert_eq!(seen("default", "a/x", 1_300), 1_000);
    assert_eq!(seen("default", "a/x", 1_600), 1_000);
    assert!(claude_passive_reading_usable(
        1_100,
        None,
        Some(1_000),
        3_600,
        1_600
    ));
    // Same account, other organization, then back: a body fetched while
    // on the other organization predates the new run.
    assert_eq!(seen("default", "a/y", 1_900), 1_900);
    assert_eq!(seen("default", "a/x", 2_200), 2_200);
    assert!(!claude_passive_reading_usable(
        2_000,
        None,
        Some(2_200),
        3_600,
        2_500
    ));
    // A long gap (sleep, restart, unresolved identity) starts a new run.
    assert_eq!(seen("default", "a/x", 2_200 + 16 * 60), 2_200 + 16 * 60);
    // A clock going backwards starts a new run.
    assert_eq!(seen("default", "a/x", 2_000), 2_000);
    // Runs are per caller.
    assert_eq!(seen("slot-sha256:1", "a/x", 2_100), 2_100);
    assert_eq!(seen("default", "a/x", 2_100), 2_000);
}

#[test]
fn in_use_survives_a_stalled_activity_scan() {
    let activity_at = 10_000;
    let now = activity_at + 45 * 60;
    let mut schedule = ClaudeReadSchedule::default();
    schedule.observe_activity(Some(activity_at));
    let mut reconciliation: ActiveSessionReconciliation = serde_json::from_value(json!({
        "scan_started_at": rfc3339(activity_at - 30),
        "reconciled_at": rfc3339(now),
        "changed_session_count": 0,
        "sessions": []
    }))
    .unwrap();
    let slot = |feed: Option<&ActiveSessionReconciliation>, now| {
        claude_usage_slot_seconds(
            &schedule,
            claude_latest_activity_at(feed, "a", "o"),
            claude_activity_feed_fresh_at(feed),
            DEFAULT_SLOT,
            now,
        )
    };
    assert_eq!(slot(Some(&reconciliation), now), ACTIVE_SLOT_SECONDS);
    // A newly completed scan sees no newer activity: return to idle.
    reconciliation.scan_started_at = Some(rfc3339(activity_at + 40 * 60));
    assert_eq!(slot(Some(&reconciliation), now), DEFAULT_SLOT);
    // A dead scanner cannot preserve the active slot indefinitely.
    let scan_at = activity_at - 30;
    reconciliation.scan_started_at = Some(rfc3339(scan_at));
    assert_eq!(
        slot(
            Some(&reconciliation),
            scan_at + MAX_ACTIVITY_FEED_LAG_SECONDS
        ),
        ACTIVE_SLOT_SECONDS
    );
    assert_eq!(
        slot(
            Some(&reconciliation),
            scan_at + MAX_ACTIVITY_FEED_LAG_SECONDS + 1
        ),
        DEFAULT_SLOT
    );
    // Missing, older and invalid feed metadata retain wall-clock judging.
    assert_eq!(slot(None, now), DEFAULT_SLOT);
    for scan_at in [None, Some("invalid".to_string()), Some(rfc3339(now + 60))] {
        reconciliation.scan_started_at = scan_at;
        assert_eq!(slot(Some(&reconciliation), now), DEFAULT_SLOT);
    }
}

/// A stored reading holding the given sections.
fn stored(usage_credits_off: Option<bool>, saved_resets: bool) -> Vec<AgentCreditBalance> {
    let mut balances = Vec::new();
    if let Some(off) = usage_credits_off {
        balances.push(AgentCreditBalance {
            name: CLAUDE_USAGE_CREDITS_NAME.to_string(),
            kind: Some(CreditBalanceKind::UsageCredits),
            enabled: Some(!off),
            ..Default::default()
        });
    }
    if saved_resets {
        balances.push(AgentCreditBalance {
            name: "reset_bank".to_string(),
            unit: AgentCreditBalanceUnit::Resets,
            kind: Some(CreditBalanceKind::SavedResets),
            ..Default::default()
        });
    }
    balances
}

/// The default slot of the simulated binding (inside the 38-42 min band).
const DEFAULT_SLOT: u64 = 2_460;
/// Collection passes run every 5 min.
const PASS: u64 = 300;
const HOUR: u64 = 3_600;

/// A reading the simulated binding took: a provider call or a passive body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reading {
    at: u64,
    read: ClaudeUsageRead,
    passive: bool,
    slot: u64,
}

/// One simulated binding driven like the collection path, one decision
/// per 5-min pass: record the caller's sign-in, keep activity, check the
/// slot, choose the read, then adopt a passive body only in a plain slot,
/// else make one call.
struct Simulation {
    schedule: ClaudeReadSchedule,
    last_reading_at: Option<u64>,
    next_refresh_after: u64,
    usage_credits_off: bool,
    stored: Vec<AgentCreditBalance>,
    callers: BTreeMap<String, ClaudeCallerBinding>,
    readings: Vec<Reading>,
    passes_with_more_than_one_call: usize,
}

impl Simulation {
    fn new(usage_credits_off: bool) -> Self {
        Self {
            schedule: ClaudeReadSchedule::default(),
            last_reading_at: None,
            next_refresh_after: 0,
            usage_credits_off,
            stored: Vec::new(),
            callers: BTreeMap::new(),
            readings: Vec::new(),
            passes_with_more_than_one_call: 0,
        }
    }

    /// One pass at `now`. `passive_fetched_at` is the matching body
    /// Claude Code holds, if any.
    fn pass(&mut self, now: u64, activity: Option<u64>, passive_fetched_at: Option<u64>) {
        let since = claude_observe_caller_binding(&mut self.callers, "default", "a/o", now);
        self.schedule.observe_activity(activity);
        let slot = claude_usage_slot_seconds(&self.schedule, activity, None, DEFAULT_SLOT, now);
        if !claude_reading_due(self.last_reading_at, self.next_refresh_after, slot, now) {
            return;
        }
        let read = claude_usage_read_kind(&self.schedule, &self.stored, now);
        if read == ClaudeUsageRead::Plain {
            if let Some(fetched) = passive_fetched_at.filter(|at| {
                claude_passive_reading_usable(*at, self.last_reading_at, Some(since), slot, now)
            }) {
                self.record(read, fetched, true, slot, activity, now);
                return;
            }
        }
        // The provider answers a few seconds into the pass.
        self.record(read, now + 3, false, slot, activity, now);
    }

    fn record(
        &mut self,
        read: ClaudeUsageRead,
        at: u64,
        passive: bool,
        slot: u64,
        activity: Option<u64>,
        now: u64,
    ) {
        if self
            .readings
            .last()
            // Two calls within half a pass are one pass's calls (passes
            // drift by under 20 s; in-use reads are one pass apart).
            .is_some_and(|last| !last.passive && !passive && last.at + PASS / 2 > at)
        {
            self.passes_with_more_than_one_call += 1;
        }
        self.readings.push(Reading {
            at,
            read,
            passive,
            slot,
        });
        self.last_reading_at = Some(at);
        self.next_refresh_after = now + super::super::CLAUDE_OAUTH_USAGE_REFRESH_SECONDS;
        self.schedule.after_reading(read, at, activity, now);
        let observed = rfc3339(at);
        match read {
            ClaudeUsageRead::Plain => {
                self.stored
                    .retain(|b| b.kind != Some(CreditBalanceKind::UsageCredits));
                let mut usage = stored(Some(self.usage_credits_off), false);
                usage[0].observed_at = Some(observed);
                self.stored.extend(usage);
            }
            ClaudeUsageRead::SavedResets => {
                self.stored
                    .retain(|b| b.kind != Some(CreditBalanceKind::SavedResets));
                let mut saved = stored(None, true);
                saved[0].observed_at = Some(observed);
                self.stored.extend(saved);
            }
        }
    }

    fn calls(&self) -> impl Iterator<Item = &Reading> {
        self.readings.iter().filter(|reading| !reading.passive)
    }
}

fn rfc3339(at: u64) -> String {
    OffsetDateTime::from_unix_timestamp(at as i64)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

const START: u64 = 1_791_000_000;

/// 24 h of 5-min passes: idle start, active 08:00-10:00 (the scan reports
/// activity only while it advances), then idle; the machine sleeps
/// 13:00-16:00 (no passes).
fn run_day(usage_credits_off: bool, passive: &dyn Fn(u64) -> Option<u64>) -> Simulation {
    let mut simulation = Simulation::new(usage_credits_off);
    let mut tick = 0;
    let mut latency = 0;
    while tick * PASS < 24 * HOUR {
        let offset = tick * PASS;
        tick += 1;
        if (13 * HOUR..16 * HOUR).contains(&offset) {
            continue;
        }
        // The lane times each pass from the previous pass's start, and a
        // pass wakes up to a couple of seconds late, so starts drift
        // later, never closer than 5 min.
        latency += (tick * 7) % 3;
        let now = START + offset + latency;
        let activity = (8 * HOUR..10 * HOUR).contains(&offset).then_some(now);
        simulation.pass(now, activity, passive(now));
    }
    simulation
}

fn gaps_between(readings: &[Reading], from: u64, to: u64) -> Vec<u64> {
    readings
        .windows(2)
        .filter(|pair| (START + from..START + to).contains(&pair[1].at))
        .map(|pair| pair[1].at - pair[0].at)
        .collect()
}

#[test]
fn scheduler_day_on_five_minute_passes() {
    let simulation = run_day(false, &|_| None);
    let calls = simulation.calls().copied().collect::<Vec<_>>();
    // One read per slot, never two in one pass, no catch-up burst.
    assert_eq!(simulation.passes_with_more_than_one_call, 0);
    for pair in calls.windows(2) {
        assert!(
            pair[1].at - pair[0].at + 60 >= pair[1].slot,
            "read inside its slot"
        );
    }
    // Credits on: plain and saved-reset reads strictly alternate.
    assert_eq!(calls[0].read, ClaudeUsageRead::Plain);
    for pair in calls.windows(2) {
        assert_ne!(pair[0].read, pair[1].read);
    }
    // Default slot: the first pass at or after the boundary (≤ one pass late).
    let default = gaps_between(&calls, 0, 6 * HOUR);
    assert!(!default.is_empty());
    assert!(default
        .iter()
        .all(|gap| (DEFAULT_SLOT - 60..=DEFAULT_SLOT + PASS).contains(gap)));
    // In use: every 5-min pass (± the pass drift), not every other one.
    let active = gaps_between(&calls, 8 * HOUR + 5 * 60, 10 * HOUR);
    assert!(active.len() >= 20);
    assert!(
        active
            .iter()
            .all(|gap| (5 * 60 - 20..=5 * 60 + 20).contains(gap)),
        "{active:?}"
    );
    // The active slot holds for 30 min after the last activity.
    assert!(calls.iter().any(|call| {
        (START + 10 * HOUR + 10 * 60..=START + 10 * HOUR + 30 * 60).contains(&call.at)
            && call.slot == ACTIVE_SLOT_SECONDS
    }));
    // Unused for more than 6 h: still the unused-account slot.
    let idle = gaps_between(&calls, 17 * HOUR, 24 * HOUR);
    assert!(!idle.is_empty());
    assert!(idle
        .iter()
        .all(|gap| (DEFAULT_SLOT - 60..=DEFAULT_SLOT + PASS).contains(gap)));
    // Waking from a 3 h sleep: one read at the first pass, then the slot.
    let woke = calls
        .iter()
        .filter(|call| call.at >= START + 16 * HOUR)
        .map(|call| call.at)
        .collect::<Vec<_>>();
    assert!(woke[0] < START + 16 * HOUR + PASS);
    assert!(woke[1] - woke[0] >= DEFAULT_SLOT - 60);
    // 2.5 h in use at 5 min plus the unused hours at about 40 min.
    assert!(calls.len() <= 30 + 24 * 2, "{}", calls.len());
}

/// Claude Code keeps a fresh matching body at every pass (an account in
/// constant use): passive input stands in for the plain slots only, and
/// the saved-reset read still happens every other slot.
#[test]
fn continuous_passive_input_never_starves_saved_resets() {
    let simulation = run_day(false, &|now| Some(now - 30));
    assert!(simulation.readings.iter().any(|reading| reading.passive));
    assert!(simulation
        .readings
        .iter()
        .filter(|reading| reading.passive)
        .all(|reading| reading.read == ClaudeUsageRead::Plain));
    for pair in simulation.readings.windows(2) {
        assert_ne!(
            pair[0].read, pair[1].read,
            "plain and saved-reset slots alternate"
        );
    }
    let saved = simulation
        .readings
        .iter()
        .filter(|reading| reading.read == ClaudeUsageRead::SavedResets)
        .collect::<Vec<_>>();
    assert!(saved.iter().all(|reading| !reading.passive));
    // Active hours: a saved-reset read every ~10 min (two 5-min slots).
    let active_saved = saved
        .windows(2)
        .filter(|pair| (START + 8 * HOUR + 30 * 60..START + 10 * HOUR).contains(&pair[1].at))
        .map(|pair| pair[1].at - pair[0].at)
        .collect::<Vec<_>>();
    assert!(!active_saved.is_empty());
    assert!(
        active_saved.iter().all(|gap| *gap <= 10 * 60 + 60),
        "{active_saved:?}"
    );
    // Over the whole day no saved-reset gap exceeds two unused slots
    // (plus the 3 h sleep).
    for pair in saved.windows(2) {
        assert!(pair[1].at - pair[0].at <= 2 * (DEFAULT_SLOT + PASS) + 3 * HOUR + PASS);
    }
    // Passive bodies replace calls; never more than one reading per slot.
    assert!(simulation.calls().count() < run_day(false, &|_| None).calls().count());
    assert_eq!(simulation.passes_with_more_than_one_call, 0);
}

#[test]
fn a_window_reset_after_the_reading_gets_one_read_soon_after_it() {
    let observed = 1_000_000;
    let window = |reset: Option<u64>| AgentQuotaWindow {
        resets_at: reset.map(rfc3339),
        ..Default::default()
    };
    let windows = [
        window(Some(observed + 5 * HOUR)),
        window(Some(observed + 2 * HOUR)),
        window(Some(observed - 10)),
        window(None),
    ];
    let delay = claude_reset_read_delay_seconds("account-a", "org-a");
    assert!((60..=120).contains(&delay), "delay {delay}");
    assert_eq!(
        claude_reset_read_at(&windows, observed, 0, delay),
        Some(observed + 2 * HOUR + delay),
        "the first reset after the reading, plus the delay"
    );
    assert_eq!(
        claude_reset_read_at(&windows, observed, observed + 2 * HOUR + 290, delay),
        Some(observed + 2 * HOUR + 290),
        "never before the stored spacing"
    );
    let reset = observed + 2 * HOUR;
    // Before the delay: not due. After it: due, inside any slot.
    assert!(!claude_reset_read_due(
        &windows,
        observed,
        0,
        delay,
        reset + delay - 1
    ));
    assert!(claude_reset_read_due(
        &windows,
        observed,
        0,
        delay,
        reset + delay
    ));
    // Retry-After/success spacing still holds it back.
    assert!(!claude_reset_read_due(
        &windows,
        observed,
        reset + delay + 300,
        delay,
        reset + delay
    ));
    // The reading after the reset postdates it: no second read.
    assert!(!claude_reset_read_due(
        &windows,
        reset + delay,
        0,
        delay,
        reset + delay + 600
    ));
    assert_eq!(
        claude_reset_read_at(&windows[2..], observed, 0, delay),
        None
    );
}

#[test]
fn read_kind_fills_a_missing_section_first() {
    let none = ClaudeReadSchedule::default();
    let plain_only = ClaudeReadSchedule {
        last_plain_read_at: Some(100),
        ..ClaudeReadSchedule::default()
    };
    let kind = |schedule: &ClaudeReadSchedule, stored: &[AgentCreditBalance]| {
        claude_usage_read_kind(schedule, stored, 1_000)
    };
    assert_eq!(kind(&none, &[]), ClaudeUsageRead::Plain);
    assert_eq!(
        kind(&none, &stored(Some(false), false)),
        ClaudeUsageRead::SavedResets
    );
    assert_eq!(kind(&plain_only, &[]), ClaudeUsageRead::SavedResets);
    assert_eq!(kind(&none, &stored(None, true)), ClaudeUsageRead::Plain);
    // Both sections stored, schedule lost: alternate from plain.
    assert_eq!(
        kind(&none, &stored(Some(false), true)),
        ClaudeUsageRead::Plain
    );
    assert_eq!(
        kind(&plain_only, &stored(Some(false), true)),
        ClaudeUsageRead::SavedResets
    );
    // A paused variant never fills the section.
    let paused = ClaudeReadSchedule {
        saved_resets_variant_paused_until: Some(2_000),
        ..plain_only.clone()
    };
    assert_eq!(
        kind(&paused, &stored(Some(false), false)),
        ClaudeUsageRead::Plain
    );
}

#[test]
fn read_schedule_file_is_owner_only_and_survives_restart() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!(
        "ottto-claude-read-schedule-{}-{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    assert_eq!(
        read_claude_read_schedule(&dir),
        ClaudeReadSchedule::default()
    );
    let schedule = ClaudeReadSchedule {
        last_plain_read_at: Some(1),
        last_saved_resets_read_at: Some(2),
        last_activity_at: Some(3),
        tracked_since: Some(4),
        saved_resets_variant_paused_until: Some(5),
        next_read_not_before: Some(6),
    };
    write_claude_read_schedule(&dir, &schedule).unwrap();
    let mode = std::fs::metadata(dir.join(CLAUDE_READ_SCHEDULE_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "no group/world access: {mode:o}");
    // A restarted daemon reads the same schedule back.
    assert_eq!(read_claude_read_schedule(&dir), schedule);
    std::fs::write(dir.join(CLAUDE_READ_SCHEDULE_FILE), b"{not json").unwrap();
    assert_eq!(
        read_claude_read_schedule(&dir),
        ClaudeReadSchedule::default()
    );
    let _ = std::fs::remove_dir_all(dir);
}

fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/agent-status/quota-contract-v2.2")
}

/// A fixture file; a provider body is read as the response decode reads it.
fn fixture(path: &str) -> Value {
    let text = std::fs::read_to_string(fixture_dir().join(path)).unwrap();
    if path.starts_with("provider/") {
        decode(&text, CreditBody::ClaudeUsage).unwrap()
    } else {
        serde_json::from_str(&text).unwrap()
    }
}

/// The emitted balances without the fields stamped outside the adapter:
/// packaging time (`updated_at`, contract C9) and the binding hashes.
fn comparable(balances: &Value) -> Value {
    let mut balances = balances.clone();
    for balance in balances.as_array_mut().unwrap() {
        let balance = balance.as_object_mut().unwrap();
        for key in [
            "updated_at",
            "account_identifier_hash",
            "organization_identifier_hash",
        ] {
            balance.remove(key);
        }
    }
    balances
}

/// Each canonical Claude provider body, read once on a cold binding,
/// produces the canonical expected wire file byte for byte (rendered the
/// way the model writes it: pretty JSON, sorted keys, trailing newline).
#[test]
fn canonical_claude_fixtures_match_expected_wire() {
    for name in [
        "claude-oauth-usage-plain",
        "claude-oauth-usage-credits-off",
        "claude-usage-cedar",
        "claude-usage-cedar-ineligible",
        "claude-usage-cedar-reader-surface",
        "claude-usage-cedar-reader-cli-version",
        "claude-usage-cedar-refused-expiry",
    ] {
        let body = fixture(&format!("provider/{name}.json"));
        let read = claude_credit_read(&body, ClaudeUsageRead::Plain, "2026-10-01T12:00:00Z");
        let emitted = claude_merge_credit_sections("fixture", &[], &read);
        let mut rendered = serde_json::to_string_pretty(
            &json!({ "credit_balances": serde_json::to_value(&emitted).unwrap() }),
        )
        .unwrap();
        rendered.push('\n');
        let on_disk =
            std::fs::read_to_string(fixture_dir().join(format!("expected/{name}.wire.json")))
                .unwrap();
        assert_eq!(rendered, on_disk, "{name}");
        assert!(emitted.iter().all(|balance| balance.enabled != Some(true)
            || balance.kind != Some(CreditBalanceKind::OneTimeCredit)));
    }
}

/// The canonical alternation sequence, with each binding's stored reading
/// carried between steps. The adapter's stored reading is on disk per
/// binding, so after a restart it is still the last observed section and
/// is re-sent (no presence flip); the in-memory model fixture starts cold.
#[test]
fn canonical_claude_sequence_matches_expected_wire() {
    let sequence = fixture("expected/sequence-claude-plain-saved-resets.wire.json");
    let mut stored: BTreeMap<String, Vec<AgentCreditBalance>> = BTreeMap::new();
    for step in sequence["steps"].as_array().unwrap() {
        let label = step["step"].as_str().unwrap();
        let expected = &step["credit_balances"];
        let binding = expected[0]["account_identifier_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let input = step["provider_inputs"][0].as_str().unwrap();
        let read = if input.ends_with("claude-oauth-usage-plain.json") {
            ClaudeUsageRead::Plain
        } else {
            ClaudeUsageRead::SavedResets
        };
        let observed_at = step["captured_at"]
            .as_str()
            .unwrap()
            .replace(":05Z", ":00Z");
        let previous = stored.get(&binding).cloned().unwrap_or_default();
        let emitted = claude_merge_credit_sections(
            &binding,
            &previous,
            &claude_credit_read(&fixture(input), read, &observed_at),
        );
        let emitted_value = comparable(&serde_json::to_value(&emitted).unwrap());
        if label.starts_with("restart") {
            let saved = emitted
                .iter()
                .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
                .expect("stored saved resets re-sent after a restart");
            assert_eq!(
                saved.grants_observed_at.as_deref(),
                Some("2026-10-01T14:00:00Z")
            );
            let without_saved = Value::Array(
                emitted_value
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|b| b["kind"] != "saved_resets")
                    .cloned()
                    .collect(),
            );
            assert_eq!(without_saved, comparable(expected), "{label}");
        } else {
            assert_eq!(emitted_value, comparable(expected), "{label}");
        }
        stored.insert(binding, emitted);
    }
}

/// Restores one environment variable on drop.
struct EnvGuard(&'static str, Option<std::ffi::OsString>);

impl EnvGuard {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
        let previous = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        Self(key, previous)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.1 {
            Some(value) => unsafe { std::env::set_var(self.0, value) },
            None => unsafe { std::env::remove_var(self.0) },
        }
    }
}

static REQUESTED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn respond_with(endpoint: &str, cedar: Value) -> Value {
    REQUESTED.lock().unwrap().push(endpoint.to_string());
    let mut body = fixture("provider/claude-usage-cedar.json");
    body["cedar_ember"] = cedar;
    body
}

fn respond_recognized(endpoint: &str) -> Result<Value, u16> {
    Ok(respond_with(
        endpoint,
        fixture("provider/claude-usage-cedar.json")["cedar_ember"].clone(),
    ))
}

fn respond_server_error(endpoint: &str) -> Result<Value, u16> {
    REQUESTED.lock().unwrap().push(endpoint.to_string());
    Err(500)
}

fn respond_rate_limited(endpoint: &str) -> Result<Value, u16> {
    REQUESTED.lock().unwrap().push(endpoint.to_string());
    Err(429)
}

fn respond_cedar_null(endpoint: &str) -> Result<Value, u16> {
    Ok(respond_with(endpoint, Value::Null))
}

fn respond_plain(endpoint: &str) -> Result<Value, u16> {
    REQUESTED.lock().unwrap().push(endpoint.to_string());
    Ok(fixture("provider/claude-oauth-usage-plain.json"))
}

fn respond_empty(endpoint: &str) -> Result<Value, u16> {
    REQUESTED.lock().unwrap().push(endpoint.to_string());
    Ok(json!({}))
}

fn respond_cedar_only(endpoint: &str) -> Result<Value, u16> {
    REQUESTED.lock().unwrap().push(endpoint.to_string());
    Ok(json!({"cedar_ember": {"eligible": true}}))
}

fn respond_status(endpoint: &str, status: u16) -> Result<Value, u16> {
    REQUESTED.lock().unwrap().push(endpoint.to_string());
    if endpoint.contains("cedar_ember") {
        Err(status)
    } else {
        Ok(fixture("provider/claude-oauth-usage-plain.json"))
    }
}

fn respond_variant_400(endpoint: &str) -> Result<Value, u16> {
    respond_status(endpoint, 400)
}

thread_local! {
    /// A fixed collector clock for this test thread; `None` is the wall clock.
    static PINNED_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn harness_now() -> u64 {
    PINNED_NOW.with(|now| now.get().unwrap_or_else(super::super::current_unix_seconds))
}

/// End to end through the collector with a stand-in provider: a binding
/// whose plain read is recent and saved resets never read takes the
/// variant in its next due slot.
struct VariantHarness {
    dir: std::path::PathBuf,
    _support: EnvGuard,
    account: &'static str,
    organization: &'static str,
}

impl VariantHarness {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ottto-claude-variant-{label}-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &dir);
        super::super::CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN
            .store(false, std::sync::atomic::Ordering::SeqCst);
        REQUESTED.lock().unwrap().clear();
        PINNED_NOW.with(|now| now.set(None));
        super::super::claude_explicit_refresh_request().at = 0;
        super::super::claude_explicit_refresh_attempts().clear();
        super::super::claude_transient_failures().clear();
        super::super::claude_rate_limit_holds().clear();
        Self {
            dir,
            _support: support,
            account: "account-variant",
            organization: "organization-variant",
        }
    }

    fn state_dir(&self) -> std::path::PathBuf {
        super::super::claude_oauth_usage_account_state_dir(self.account, self.organization)
    }

    /// Make the binding due, with the plain read an hour ago.
    fn due(&self, mut schedule: ClaudeReadSchedule) {
        let _ = std::fs::remove_file(super::super::claude_oauth_usage_cache_path(
            self.account,
            self.organization,
        ));
        let now = harness_now();
        schedule.last_plain_read_at.get_or_insert(now - 3_600);
        schedule.next_read_not_before = None;
        write_claude_read_schedule(&self.state_dir(), &schedule).unwrap();
    }

    /// Make the binding due while keeping its stored reading, as after a
    /// daemon restart that slept past the slot.
    fn due_keeping_reading(&self) {
        let mut cache =
            super::super::read_claude_oauth_usage_cache(self.account, self.organization)
                .expect("stored reading");
        cache.observed_at_epoch_seconds -= 3 * 3_600;
        cache.next_refresh_after_epoch_seconds = 0;
        super::super::write_claude_oauth_usage_cache(&cache).unwrap();
        // The slot has passed: any "not before the next slot" hold is over.
        let mut schedule = self.schedule();
        schedule.next_read_not_before = None;
        write_claude_read_schedule(&self.state_dir(), &schedule).unwrap();
    }

    fn schedule(&self) -> ClaudeReadSchedule {
        read_claude_read_schedule(&self.state_dir())
    }

    fn collect(
        &self,
        respond: super::super::ClaudeOAuthTestResponder,
    ) -> super::super::ClaudeOAuthUsageOutcome {
        *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(respond);
        let outcome = super::super::collect_claude_oauth_usage_with_credential(
            self.account,
            self.organization,
            Some("fixture-token".to_string()),
            None,
            &super::super::ClaudeOAuthUsageCaller::RegisteredSlot("slot-variant".to_string()),
            harness_now,
        );
        *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
        outcome
    }

    fn shape_failures(&self) -> u32 {
        super::super::read_claude_oauth_usage_breaker(
            self.account,
            self.organization,
            &super::super::claude_oauth_usage_config_fingerprint(),
        )
        .map_or(0, |breaker| breaker.shape_failures)
    }
}

impl Drop for VariantHarness {
    fn drop(&mut self) {
        *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl VariantHarness {
    fn collect_as(
        &self,
        caller: super::super::ClaudeOAuthUsageCaller,
        respond: super::super::ClaudeOAuthTestResponder,
    ) -> super::super::ClaudeOAuthUsageOutcome {
        *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(respond);
        let outcome = super::super::collect_claude_oauth_usage_with_credential(
            self.account,
            self.organization,
            Some("fixture-token".to_string()),
            None,
            &caller,
            harness_now,
        );
        *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
        outcome
    }

    /// Let `seconds` pass for the stored reading and any Refresh request,
    /// keeping only the plain spacing after a successful read.
    fn age_reading(&self, seconds: u64) {
        {
            let mut request = super::super::claude_explicit_refresh_request();
            request.at = request.at.saturating_sub(seconds);
        }
        for attempt in super::super::claude_explicit_refresh_attempts().iter_mut() {
            attempt.at -= seconds;
        }
        for failure in super::super::claude_transient_failures().iter_mut() {
            failure.at -= seconds;
        }
        let mut cache =
            super::super::read_claude_oauth_usage_cache(self.account, self.organization)
                .expect("stored reading");
        cache.observed_at_epoch_seconds -= seconds;
        cache.next_refresh_after_epoch_seconds =
            cache.observed_at_epoch_seconds + super::super::CLAUDE_OAUTH_USAGE_REFRESH_SECONDS;
        super::super::write_claude_oauth_usage_cache(&cache).unwrap();
    }

    fn requests(&self) -> usize {
        REQUESTED.lock().unwrap().len()
    }

    /// A statusLine reading Claude Code wrote for exactly this binding.
    fn write_statusline(&self, observed_at: u64) {
        ottto_core::write_claude_statusline_cache(
            &self.dir,
            &ottto_core::ClaudeStatusLineRateLimitCache {
                schema_version: ottto_core::CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
                observed_under_account_identifier_hash: self.account.to_string(),
                observed_under_organization_identifier_hash: Some(
                    self.organization.to_string(),
                ),
                observed_under_account_method: "config_dir".to_string(),
                observed_at_epoch_seconds: observed_at,
                windows: vec![ottto_core::ClaudeStatusLineRateLimitWindow {
                    name: "five_hour".to_string(),
                    used_percent: 12,
                    resets_at_epoch_seconds: observed_at + 3_600,
                }],
            },
        )
        .unwrap();
    }
}

/// A server error records no backoff of its own: the binding still waits
/// a minute before the next provider request, whatever asks for it.
#[test]
#[serial_test::serial]
fn a_server_error_waits_a_minute_before_the_next_request() {
    let harness = VariantHarness::new("server-error");
    harness.due(ClaudeReadSchedule::default());
    harness.collect(respond_server_error);
    assert_eq!(harness.requests(), 1);
    for _ in 0..3 {
        harness.collect(respond_server_error);
    }
    super::super::request_claude_explicit_refresh();
    harness.collect(respond_server_error);
    assert_eq!(harness.requests(), 1);
    for failure in super::super::claude_transient_failures().iter_mut() {
        failure.at -= super::super::CLAUDE_TRANSIENT_FAILURE_RETRY_SECONDS;
    }
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 2);
}

/// Each Anthropic usage request is one provider-call log line saying why
/// it ran and how it ended; a reading served from storage logs nothing.
#[test]
#[serial_test::serial]
fn each_usage_request_is_one_provider_call_line() {
    use crate::provider_calls::{with_trigger, CallKind, Trigger};
    let mut harness = VariantHarness::new("call-log");
    harness.account = "c1a0de0100000000000000000000000000000000000000000000000000000000";
    harness.due(ClaudeReadSchedule::default());
    with_trigger(Trigger::Setup, || harness.collect(respond_recognized));
    // A fresh reading inside its slot: served, no request, no line.
    harness.collect(respond_recognized);
    // A setup check marks the read; the lane thread that makes it keeps
    // that label.
    harness.age_reading(90);
    with_trigger(
        Trigger::Setup,
        super::super::request_claude_explicit_refresh,
    );
    harness.collect(respond_recognized);
    harness.age_reading(90);
    super::super::request_claude_explicit_refresh();
    harness.collect(respond_server_error);
    assert_eq!(harness.requests(), 3);
    let lines = crate::provider_calls::test_lines(CallKind::ClaudeOauthUsage, harness.account);
    let summary = lines
        .iter()
        .map(|line| {
            (
                line.provider.as_str(),
                line.trigger.as_str(),
                line.result.as_str(),
                line.basis.as_str(),
                line.requests_at_least,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        summary,
        [
            ("anthropic", "setup", "ok", "observed", 1),
            ("anthropic", "setup", "ok", "observed", 1),
            ("anthropic", "explicit_refresh", "http_500", "observed", 1),
        ]
    );
    let raw = crate::provider_calls::test_raw_log();
    for secret in [
        "fixture-token",
        "Bearer",
        "api.anthropic.com",
        "organization-variant",
    ] {
        assert!(!raw.contains(secret), "{secret} in the provider-call log");
    }
}

/// The Refresh button reads an account now, at most once a minute, and
/// never inside a Retry-After hold.
#[test]
#[serial_test::serial]
fn explicit_refresh_reads_now_once_a_minute_and_never_inside_retry_after() {
    let harness = VariantHarness::new("explicit-refresh");
    harness.due(ClaudeReadSchedule::default());
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 1);
    // A fresh reading inside its slot: no call without a request.
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 1);
    // A request 30 s after a read waits out the minute.
    harness.age_reading(30);
    super::super::request_claude_explicit_refresh();
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 1);
    // Past the minute (still inside the slot): the request reads now.
    harness.age_reading(90);
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 2);
    // The request is consumed by that read.
    harness.age_reading(90);
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 2);
    // A refresh whose read fails still counts: the request is used up and
    // the next one waits out the minute.
    harness.age_reading(90);
    super::super::request_claude_explicit_refresh();
    harness.collect(respond_server_error);
    assert_eq!(harness.requests(), 3);
    harness.collect(respond_server_error);
    assert_eq!(harness.requests(), 3);
    super::super::request_claude_explicit_refresh();
    harness.collect(respond_server_error);
    assert_eq!(harness.requests(), 3);
    // Retry-After on record: a request never reads inside it.
    let now = super::super::current_unix_seconds();
    let mut cache =
        super::super::read_claude_oauth_usage_cache(harness.account, harness.organization)
            .expect("stored reading");
    cache.observed_at_epoch_seconds = now - 120;
    cache.next_refresh_after_epoch_seconds = now + 600;
    super::super::write_claude_oauth_usage_cache(&cache).unwrap();
    super::super::record_claude_oauth_usage_failure(
        super::super::ClaudeOAuthUsageFailure::RateLimited,
        harness.account,
        harness.organization,
        &super::super::claude_oauth_usage_config_fingerprint(),
        now,
    );
    super::super::request_claude_explicit_refresh();
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 3);
}

#[test]
#[serial_test::serial]
fn post_sign_in_quota_collection_requests_a_fresh_read_and_keeps_limits() {
    let harness = VariantHarness::new("post-sign-in-refresh");
    harness.due(ClaudeReadSchedule::default());
    harness.collect(respond_recognized);
    harness.age_reading(120);
    harness.collect(respond_recognized);
    assert_eq!(
        harness.requests(),
        1,
        "the slot still serves its recent cache"
    );

    let store = ottto_core::FileClaudeConfigSlotSettingsStore::default();
    store.set_upkeep_consent(1, true).expect("consent");
    // Exercise the shared post-sign-in entry point. This fixture drives
    // the binding's collector directly, without a real login or keychain.
    crate::claude_browser_auth::collect_allowed_quota(&store, "slot-variant");
    assert_eq!(
        super::super::claude_explicit_refresh_request().trigger,
        crate::provider_calls::Trigger::Setup
    );
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 2, "sign-in refreshes inside the slot");

    harness.age_reading(30);
    crate::claude_browser_auth::collect_allowed_quota(&store, "slot-variant");
    harness.collect(respond_recognized);
    assert_eq!(
        harness.requests(),
        2,
        "a second request waits out 60 seconds"
    );

    harness.age_reading(90);
    let now = super::super::current_unix_seconds();
    let mut cache =
        super::super::read_claude_oauth_usage_cache(harness.account, harness.organization)
            .expect("stored reading");
    cache.next_refresh_after_epoch_seconds = now + 600;
    super::super::write_claude_oauth_usage_cache(&cache).unwrap();
    super::super::record_claude_oauth_usage_failure(
        super::super::ClaudeOAuthUsageFailure::RateLimited,
        harness.account,
        harness.organization,
        &super::super::claude_oauth_usage_config_fingerprint(),
        now,
    );
    crate::claude_browser_auth::collect_allowed_quota(&store, "slot-variant");
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 2, "sign-in still respects Retry-After");
}

/// A 429 with a short Retry-After inside the success spacing: an explicit
/// refresh still waits it out when the persisted breaker cannot say so
/// (for example after a configuration change).
#[test]
#[serial_test::serial]
fn explicit_refresh_never_reads_inside_a_rate_limit_even_without_the_breaker() {
    let harness = VariantHarness::new("explicit-429");
    harness.due(ClaudeReadSchedule::default());
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 1);
    harness.due_keeping_reading();
    harness.collect(respond_rate_limited);
    assert_eq!(harness.requests(), 2);
    let now = super::super::current_unix_seconds();
    let mut cache =
        super::super::read_claude_oauth_usage_cache(harness.account, harness.organization)
            .expect("stored reading");
    cache.observed_at_epoch_seconds = now - 120;
    cache.next_refresh_after_epoch_seconds = now + 60;
    super::super::write_claude_oauth_usage_cache(&cache).unwrap();
    std::fs::remove_file(super::super::claude_oauth_usage_breaker_path(
        harness.account,
        harness.organization,
    ))
    .expect("the 429 recorded a breaker");
    super::super::request_claude_explicit_refresh();
    harness.collect(respond_recognized);
    assert_eq!(harness.requests(), 2, "Refresh waits out the 429");
}

/// Product rule: a status read an app starts never calls the provider. It
/// serves the stored reading even for a due account; the daemon's own
/// pass reads it, and an explicit refresh is the one read such a request
/// may make.
#[test]
#[serial_test::serial]
fn an_app_status_read_serves_the_stored_reading_and_never_calls_anthropic() {
    let harness = VariantHarness::new("app-status-read");
    harness.due(ClaudeReadSchedule::default());
    let now = super::super::current_unix_seconds();
    let app = |respond| super::super::with_claude_pass(true, now, || harness.collect(respond));
    // Due with nothing stored: no request, and no reading to show yet.
    assert!(app(respond_recognized).result.is_err());
    assert_eq!(harness.requests(), 0);
    // The daemon's pass reads it.
    let daemon =
        super::super::with_claude_pass(false, now, || harness.collect(respond_recognized));
    assert!(daemon.result.is_ok());
    assert_eq!(harness.requests(), 1);
    // Due again: the app is served the stored reading, no request.
    harness.due_keeping_reading();
    assert!(app(respond_recognized).result.is_ok());
    assert_eq!(harness.requests(), 1);
    // An explicit refresh reads now, even in the app's request.
    super::super::request_claude_explicit_refresh();
    assert!(app(respond_recognized).result.is_ok());
    assert_eq!(harness.requests(), 2);
}

/// "Background limit refresh" off: the daemon's own passes read no
/// Claude account, the default login included, and serve the stored
/// reading. A person's Refresh, a setup check and a read outside a pass
/// (an account check) still read; switching it on resumes the schedule.
#[test]
#[serial_test::serial]
fn background_refresh_off_stops_scheduled_reads_for_every_login() {
    use super::super::ClaudeOAuthUsageCaller::{Default as DefaultLogin, RegisteredSlot};
    use crate::provider_calls::{with_trigger, Trigger};
    let harness = VariantHarness::new("background-refresh-off");
    let settings = ottto_core::FileClaudeConfigSlotSettingsStore::default();
    settings.set_upkeep_consent(1, false).expect("turn off");
    let slot = || RegisteredSlot("slot-variant".to_string());
    let now = super::super::current_unix_seconds();
    let pass = |caller| {
        super::super::with_claude_pass(false, now, || {
            harness.collect_as(caller, respond_recognized)
        })
    };

    // Due with nothing stored: no request for either login, and the
    // status says why.
    harness.due(ClaudeReadSchedule::default());
    for caller in [DefaultLogin, slot()] {
        assert_eq!(
            pass(caller).result.err().as_deref(),
            Some(super::super::CLAUDE_BACKGROUND_REFRESH_OFF_MESSAGE)
        );
    }
    assert_eq!(harness.requests(), 0);

    // A setup check reads, even inside a pass.
    assert!(with_trigger(Trigger::Setup, || pass(DefaultLogin))
        .result
        .is_ok());
    assert_eq!(harness.requests(), 1);

    // Due again: the pass serves the stored reading, no request.
    harness.due_keeping_reading();
    assert!(pass(DefaultLogin).result.is_ok());
    assert!(pass(slot()).result.is_ok());
    assert_eq!(harness.requests(), 1);

    // An account check runs outside any pass: it reads.
    assert!(harness
        .collect_as(slot(), respond_recognized)
        .result
        .is_ok());
    assert_eq!(harness.requests(), 2);

    // A person's Refresh reads in the daemon's pass.
    harness.due_keeping_reading();
    super::super::request_claude_explicit_refresh();
    assert!(pass(DefaultLogin).result.is_ok());
    assert_eq!(harness.requests(), 3);

    // On again: the schedule reads a due account.
    harness.due_keeping_reading();
    settings.set_upkeep_consent(1, true).expect("turn on");
    super::super::claude_explicit_refresh_request().at = 0;
    assert!(pass(DefaultLogin).result.is_ok());
    assert_eq!(harness.requests(), 4);
}

/// An in-use account (default login) prefers Claude Code's free
/// statusLine reading: no provider call at the 5-min slot while that
/// reading is fresh for the exact binding; a call once it is older.
#[test]
#[serial_test::serial]
fn in_use_default_login_calls_only_when_the_statusline_is_stale() {
    let harness = VariantHarness::new("statusline-in-use");
    let _home = EnvGuard::set("HOME", &harness.dir);
    let now = super::super::current_unix_seconds();
    harness.due(ClaudeReadSchedule {
        last_activity_at: Some(now - 60),
        ..ClaudeReadSchedule::default()
    });
    let default = || super::super::ClaudeOAuthUsageCaller::Default;
    harness.collect_as(default(), respond_recognized);
    assert_eq!(harness.requests(), 1);
    // Five minutes later the in-use slot is due, but the statusLine wrote
    // this binding's numbers 30 s ago: no call.
    harness.age_reading(5 * 60 + 1);
    harness.write_statusline(now - 30);
    assert!(super::super::claude_statusline_fresh_for_binding(
        harness.account,
        harness.organization,
        super::super::current_unix_seconds(),
    ));
    harness.collect_as(default(), respond_recognized);
    assert_eq!(harness.requests(), 1);
    // A registered slot's collection does not merge the statusLine, so it
    // keeps its 5-min reads.
    harness.collect_as(
        super::super::ClaudeOAuthUsageCaller::RegisteredSlot("slot-variant".to_string()),
        respond_recognized,
    );
    assert_eq!(harness.requests(), 2);
    // StatusLine older than the slot: the default login calls again.
    harness.age_reading(5 * 60 + 1);
    harness.write_statusline(now - 6 * 60);
    harness.collect_as(default(), respond_recognized);
    assert_eq!(harness.requests(), 3);
}

fn saved_resets_of(outcome: &super::super::ClaudeOAuthUsageOutcome) -> Vec<AgentCreditBalance> {
    outcome
        .result
        .as_ref()
        .unwrap()
        .credit_balances
        .iter()
        .filter(|b| b.kind == Some(CreditBalanceKind::SavedResets))
        .cloned()
        .collect()
}

fn has_unrecognized(outcome: &super::super::ClaudeOAuthUsageOutcome) -> bool {
    outcome
        .diagnostics
        .iter()
        .any(|d| d.code == "claude_saved_reset_variant_unrecognized")
}

fn balances_of(outcome: &super::super::ClaudeOAuthUsageOutcome) -> &[AgentCreditBalance] {
    &outcome.result.as_ref().unwrap().credit_balances
}

/// The saved-reset and one-time sections are persisted with the stored
/// reading, so a restarted daemon re-sends them with their original read
/// times instead of dropping them until the next variant read (a
/// disappearance and a return would each be stored by the backend).
#[test]
#[serial_test::serial]
fn restart_resends_persisted_saved_resets_with_original_read_times() {
    let harness = VariantHarness::new("restart");
    // Fixed before the fixture's one-time credit expiry (2026-11-05T07:59Z),
    // so the plain read keeps that pool whatever today's date is.
    PINNED_NOW.with(|now| now.set(Some(1_793_491_200)));
    harness.due(ClaudeReadSchedule::default());
    let first = harness.collect(respond_recognized);
    let saved = saved_resets_of(&first);
    assert_eq!(saved.len(), 1);
    let read_at = saved[0].grants_observed_at.clone().expect("read time");
    assert_eq!(saved[0].observed_at.as_ref(), Some(&read_at));
    PINNED_NOW.with(|now| now.set(Some(1_793_491_202)));

    // Restart: nothing in memory survives; the stored reading is served.
    super::super::CLAUDE_OAUTH_CALLER_BINDINGS
        .lock()
        .unwrap()
        .clear();
    REQUESTED.lock().unwrap().clear();
    let served = harness.collect(respond_plain);
    assert!(
        REQUESTED.lock().unwrap().is_empty(),
        "no call inside the slot"
    );
    assert_eq!(saved_resets_of(&served), saved);

    // The first due slot after the restart reads plain; the saved-reset
    // section is re-sent unchanged, the plain sections are fresh.
    harness.due_keeping_reading();
    let after = harness.collect(respond_plain);
    assert_eq!(
        REQUESTED.lock().unwrap().as_slice(),
        ["https://api.anthropic.com/api/oauth/usage"]
    );
    assert_eq!(saved_resets_of(&after), saved);
    let usage = balances_of(&after)
        .iter()
        .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
        .expect("usage credits");
    assert_ne!(usage.observed_at.as_ref(), Some(&read_at));
    assert!(balances_of(&after)
        .iter()
        .any(|b| b.kind == Some(CreditBalanceKind::OneTimeCredit)));
}

/// A stored plain reading, then a due saved-reset slot that the provider
/// answers with `respond`. The stored reading must be served unchanged,
/// the variant paused, no breaker strike recorded, and the next read
/// moved out by one slot (no second call in this slot or the next pass).
fn assert_unusable_variant_keeps_the_stored_reading(
    respond: super::super::ClaudeOAuthTestResponder,
) {
    let harness = VariantHarness::new("unusable-variant");
    let _ = std::fs::remove_file(harness.state_dir().join(CLAUDE_READ_SCHEDULE_FILE));
    let stored = harness.collect(respond_plain);
    let stored_credits = balances_of(&stored).to_vec();
    assert!(!stored_credits.is_empty());
    harness.due_keeping_reading();
    REQUESTED.lock().unwrap().clear();

    let outcome = harness.collect(respond);
    assert_eq!(
        REQUESTED.lock().unwrap().as_slice(),
        ["https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"]
    );
    assert!(has_unrecognized(&outcome));
    assert_eq!(harness.shape_failures(), 0, "never a breaker strike");
    let usage = outcome.result.as_ref().expect("stored reading served");
    assert!(!usage.windows.is_empty(), "windows do not flip off");
    let kinds = |balances: &[AgentCreditBalance]| {
        balances
            .iter()
            .map(|b| (b.kind, b.observed_at.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(kinds(&usage.credit_balances), kinds(&stored_credits));
    assert!(harness
        .schedule()
        .saved_resets_variant_paused_until
        .is_some());

    // The next passes inside the pushed-out slot make no call.
    REQUESTED.lock().unwrap().clear();
    harness.collect(respond);
    harness.collect(respond);
    assert!(REQUESTED.lock().unwrap().is_empty(), "no retry every pass");

    // One slot later: the paused variant gives way to the plain read.
    harness.due_keeping_reading();
    harness.collect(respond_plain);
    assert_eq!(
        REQUESTED.lock().unwrap().as_slice(),
        ["https://api.anthropic.com/api/oauth/usage"]
    );
}

#[test]
#[serial_test::serial]
fn variant_400_pauses_it_and_keeps_the_stored_reading() {
    assert_unusable_variant_keeps_the_stored_reading(respond_variant_400);
}

fn breaker_open(harness: &VariantHarness) -> bool {
    super::super::read_claude_oauth_usage_breaker(
        harness.account,
        harness.organization,
        &super::super::claude_oauth_usage_config_fingerprint(),
    )
    .is_some_and(|breaker| {
        super::super::claude_oauth_usage_breaker_is_open(
            &breaker,
            super::super::current_unix_seconds(),
        )
    })
}

/// A windowless variant 200 whose `cedar_ember` is recognizable: the
/// saved-reset section is kept fresh, the stored windows and other
/// sections are served, no breaker strike, and no call until the next
/// slot, over several passes.
#[test]
#[serial_test::serial]
fn recognized_windowless_variant_keeps_cedar_and_the_stored_reading() {
    let harness = VariantHarness::new("cedar-only");
    let _ = std::fs::remove_file(harness.state_dir().join(CLAUDE_READ_SCHEDULE_FILE));
    let stored = harness.collect(respond_plain);
    let stored_usage = balances_of(&stored)
        .iter()
        .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
        .unwrap()
        .clone();
    harness.due_keeping_reading();
    REQUESTED.lock().unwrap().clear();

    let outcome = harness.collect(respond_cedar_only);
    assert_eq!(
        REQUESTED.lock().unwrap().as_slice(),
        ["https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"]
    );
    assert!(!has_unrecognized(&outcome));
    let usage = outcome.result.as_ref().expect("stored reading served");
    assert!(!usage.windows.is_empty(), "windows do not flip off");
    let saved = saved_resets_of(&outcome);
    assert_eq!(saved.len(), 1, "the fresh saved-reset section is kept");
    assert_eq!(saved[0].eligible, Some(true));
    let usage_now = balances_of(&outcome)
        .iter()
        .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
        .unwrap();
    assert_eq!(usage_now.observed_at, stored_usage.observed_at);
    assert_eq!(harness.shape_failures(), 0);
    assert_eq!(harness.schedule().saved_resets_variant_paused_until, None);

    // Repeated passes inside the slot: no call, breaker closed.
    REQUESTED.lock().unwrap().clear();
    for _ in 0..3 {
        let served = harness.collect(respond_cedar_only);
        assert_eq!(saved_resets_of(&served).len(), 1);
    }
    assert!(REQUESTED.lock().unwrap().is_empty(), "no retry every pass");
    assert_eq!(harness.shape_failures(), 0);
    assert!(!breaker_open(&harness));

    // Next slot: one read again, alternating back to plain even though
    // usage credits are off in this body.
    harness.due_keeping_reading();
    harness.collect(respond_plain);
    assert_eq!(
        REQUESTED.lock().unwrap().as_slice(),
        ["https://api.anthropic.com/api/oauth/usage"]
    );
}

/// No stored reading at all: a variant that is rejected, or that answers
/// without windows, never leads to a plain call in the same slot.
#[test]
#[serial_test::serial]
fn unusable_variant_without_a_stored_reading_waits_for_the_next_slot() {
    for respond in [
        respond_variant_400 as super::super::ClaudeOAuthTestResponder,
        respond_cedar_only,
    ] {
        let harness = VariantHarness::new("no-stored-reading");
        harness.due(ClaudeReadSchedule::default());
        assert!(super::super::read_claude_oauth_usage_cache(
            harness.account,
            harness.organization
        )
        .is_none());
        harness.collect(respond);
        assert_eq!(
            REQUESTED.lock().unwrap().as_slice(),
            ["https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"]
        );
        REQUESTED.lock().unwrap().clear();
        for _ in 0..3 {
            harness.collect(respond_plain);
        }
        assert!(
            REQUESTED.lock().unwrap().is_empty(),
            "no call in the same slot"
        );
        assert_eq!(harness.shape_failures(), 0);
        // Once the slot has passed, the next read happens.
        let mut schedule = harness.schedule();
        schedule.next_read_not_before = None;
        write_claude_read_schedule(&harness.state_dir(), &schedule).unwrap();
        let _ = std::fs::remove_file(super::super::claude_oauth_usage_cache_path(
            harness.account,
            harness.organization,
        ));
        harness.collect(respond_plain);
        assert_eq!(REQUESTED.lock().unwrap().len(), 1);
    }
}

#[test]
fn read_hold_is_bounded_to_the_longest_slot() {
    let now = 1_000_000;
    let slot = 300;
    let mut schedule = ClaudeReadSchedule {
        next_read_not_before: Some(now + slot),
        ..ClaudeReadSchedule::default()
    };
    assert_eq!(
        claude_read_held(&mut schedule, slot, now),
        ClaudeReadHold {
            active: true,
            cleared: false
        }
    );
    assert!(!claude_read_held(&mut schedule, slot, now + slot).active);
    // Written under the unused-account slot, read under the shorter in-use
    // slot: still a legitimate hold.
    schedule.next_read_not_before = Some(now + LONGEST_SLOT_SECONDS);
    assert_eq!(
        claude_read_held(&mut schedule, 300, now),
        ClaudeReadHold {
            active: true,
            cleared: false
        }
    );
    // Further ahead than the longest slot (42 min): a clock that stepped
    // back. Ignored and cleared.
    schedule.next_read_not_before = Some(now + LONGEST_SLOT_SECONDS + 1);
    assert_eq!(
        claude_read_held(&mut schedule, slot, now),
        ClaudeReadHold {
            active: false,
            cleared: true
        }
    );
    assert_eq!(schedule.next_read_not_before, None);
}

fn respond_429(endpoint: &str) -> Result<Value, u16> {
    REQUESTED.lock().unwrap().push(endpoint.to_string());
    Err(429)
}

/// A 429 adds the rate-limited diagnostic naming the read and the wait,
/// with no extra call and the existing backoff unchanged (one rate-limit
/// strike, the stored reading held until the Retry-After time).
#[test]
#[serial_test::serial]
fn rate_limited_read_names_the_read_and_wait_without_changing_backoff() {
    for (schedule, label) in [
        (ClaudeReadSchedule::default(), "saved-resets"),
        (
            ClaudeReadSchedule {
                saved_resets_variant_paused_until: Some(
                    super::super::current_unix_seconds() + 3_600,
                ),
                ..Default::default()
            },
            "usage",
        ),
    ] {
        let harness = VariantHarness::new("rate-limited");
        harness.due(schedule);
        REQUESTED.lock().unwrap().clear();
        let before = super::super::current_unix_seconds();
        let outcome = harness.collect(respond_429);
        let after = super::super::current_unix_seconds();
        assert_eq!(REQUESTED.lock().unwrap().len(), 1, "{label}: one call");
        let limited = outcome
            .diagnostics
            .iter()
            .filter(|d| d.code == "claude_oauth_usage_rate_limited")
            .collect::<Vec<_>>();
        assert_eq!(limited.len(), 1, "{label}");
        assert!(
            limited[0]
                .message
                .starts_with("Claude asked Ottto to wait until "),
            "{label}"
        );
        assert!(
            limited[0]
                .message
                .ends_with(&format!(" UTC before the next {label} read.")),
            "{label}"
        );
        let retry_after = limited[0]
            .retry_after
            .as_deref()
            .and_then(parse_instant)
            .map(|at| at.unix_timestamp() as u64)
            .expect("retry_after");
        // No Retry-After header: the existing 5-minute fallback.
        assert!(
            (before + 300..=after + 300).contains(&retry_after),
            "{label}"
        );
        let cache =
            super::super::read_claude_oauth_usage_cache(harness.account, harness.organization)
                .expect("cache written");
        assert_eq!(cache.next_refresh_after_epoch_seconds, retry_after);
        let breaker = super::super::read_claude_oauth_usage_breaker(
            harness.account,
            harness.organization,
            &super::super::claude_oauth_usage_config_fingerprint(),
        )
        .expect("breaker");
        assert_eq!(breaker.rate_limit_failures, 1, "{label}");
        assert_eq!(harness.shape_failures(), 0);
    }
}

#[test]
#[serial_test::serial]
fn unrecognized_variant_goes_plain_for_24_hours_without_a_breaker_strike() {
    let harness = VariantHarness::new("unrecognized");
    harness.due(ClaudeReadSchedule::default());
    let outcome = harness.collect(respond_cedar_null);
    assert!(has_unrecognized(&outcome));
    assert!(
        saved_resets_of(&outcome).is_empty(),
        "no saved-reset balance"
    );
    assert!(outcome
        .result
        .as_ref()
        .unwrap()
        .credit_balances
        .iter()
        .all(|b| b.status != AgentCreditBalanceStatus::Unknown
            || b.kind != Some(CreditBalanceKind::SavedResets)));
    assert_eq!(harness.shape_failures(), 0);
    let now = super::super::current_unix_seconds();
    let paused_until = harness
        .schedule()
        .saved_resets_variant_paused_until
        .unwrap();
    assert!((now + 24 * 3_600 - 5..=now + 24 * 3_600).contains(&paused_until));

    // A variant body with no windows at all is still variant state, not a
    // shape strike on the shared endpoint breaker.
    harness.due(ClaudeReadSchedule::default());
    let outcome = harness.collect(respond_empty);
    assert!(has_unrecognized(&outcome));
    assert_eq!(harness.shape_failures(), 0);

    // While paused, the next due slot reads plain.
    harness.due(harness.schedule());
    REQUESTED.lock().unwrap().clear();
    harness.collect(respond_recognized);
    assert_eq!(
        REQUESTED.lock().unwrap().as_slice(),
        ["https://api.anthropic.com/api/oauth/usage"]
    );

    // Recovery after 24 h: the variant is read and re-checked again.
    let mut schedule = harness.schedule();
    schedule.saved_resets_variant_paused_until = Some(now - 1);
    schedule.last_plain_read_at = Some(now - 3_600);
    schedule.last_saved_resets_read_at = Some(now - 7_200);
    harness.due(schedule);
    REQUESTED.lock().unwrap().clear();
    let outcome = harness.collect(respond_recognized);
    assert_eq!(
        REQUESTED.lock().unwrap().as_slice(),
        ["https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"]
    );
    assert_eq!(saved_resets_of(&outcome).len(), 1);
    assert_eq!(harness.schedule().saved_resets_variant_paused_until, None);
}
