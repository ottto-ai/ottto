use super::*;

use std::path::PathBuf;

use serde_json::{json, Value};

const READ_AT: &str = "2026-10-01T12:00:00Z";
const PACKAGED_AT: &str = "2026-10-01T12:00:05Z";

fn unix(text: &str) -> i64 {
    OffsetDateTime::parse(text, &Rfc3339)
        .expect("test instant")
        .unix_timestamp()
}

fn openai_grant(id: &str, granted_at: &str, expires_at: Option<&str>) -> GrantInput {
    GrantInput {
        id: Field::Value(id.to_string()),
        reset_type: Field::Value("codexRateLimits".to_string()),
        status: GrantStatusInput::Reported(Field::Value("available".to_string())),
        granted_at: TimeInput::UnixSeconds(unix(granted_at)),
        expires_at: expires_at.map_or(TimeInput::Absent, |at| TimeInput::UnixSeconds(unix(at))),
        title: Field::Value("Full reset".to_string()),
        ..GrantInput::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn anthropic_grant(
    id: &str,
    label: Option<&str>,
    total: u64,
    left: u64,
    starts_at: &str,
    ends_at: &str,
    clears: &[&str],
    paused: bool,
    usable_now: bool,
) -> GrantInput {
    GrantInput {
        id: Field::Value(id.to_string()),
        status: GrantStatusInput::PausedResetsLeft {
            paused: Field::Value(paused),
            resets_left: Field::Value(left),
        },
        starts_at: TimeInput::Rfc3339(starts_at.to_string()),
        expires_at: TimeInput::Rfc3339(ends_at.to_string()),
        resets_included: Field::Value(total),
        resets_left: Field::Value(left),
        clears: Field::Value(clears.iter().map(|name| name.to_string()).collect()),
        title: label.map_or(Field::Absent, |label| Field::Value(label.to_string())),
        usable_now: Field::Value(usable_now),
        ..GrantInput::default()
    }
}

fn read(provider: Provider, count: Option<u64>, records: Vec<GrantInput>) -> ListObservation {
    ListObservation::Read {
        provider,
        provider_count: count,
        records,
        observed_at: READ_AT.to_string(),
    }
}

/// The saved-resets balance an adapter builds before the model adds grants.
fn saved_resets(remaining: Option<u64>, observed_at: &str) -> AgentCreditBalance {
    AgentCreditBalance {
        name: "reset_bank".to_string(),
        status: match remaining {
            Some(0) => AgentCreditBalanceStatus::Exhausted,
            Some(_) => AgentCreditBalanceStatus::Ok,
            None => AgentCreditBalanceStatus::Unknown,
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Resets,
        remaining,
        kind: Some(CreditBalanceKind::SavedResets),
        observed_at: Some(observed_at.to_string()),
        ..Default::default()
    }
}

fn codex_reset_bank(count: u64, observed_at: &str, obs: ListObservation) -> AgentCreditBalance {
    let mut balance = saved_resets(Some(count), observed_at);
    balance.unlimited = Some(false);
    build_grants(obs).apply_to(&mut balance);
    balance
}

/// Claude sets `remaining` only through the model's Σ `resets_left`.
fn claude_reset_bank(observed_at: &str, obs: ListObservation) -> AgentCreditBalance {
    let mut balance = saved_resets(None, observed_at);
    build_grants(obs).apply_to(&mut balance);
    balance.status = match balance.remaining {
        Some(0) => AgentCreditBalanceStatus::Exhausted,
        Some(_) => AgentCreditBalanceStatus::Ok,
        None => AgentCreditBalanceStatus::Unknown,
    };
    balance
}

fn keys(balance: &AgentCreditBalance) -> Vec<String> {
    balance
        .grants
        .iter()
        .flatten()
        .map(|grant| grant.grant_key.clone())
        .collect()
}

fn codes(diagnostics: &[CreditModelDiagnostic]) -> Vec<(&'static str, &'static str)> {
    diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code, diagnostic.field))
        .collect()
}

// ---- identity -------------------------------------------------------------

#[test]
fn credit_grant_key_matches_backend_reference() {
    // `printf '%s' '<provider>:credit_grant:<id>' | shasum -a 256`
    assert_eq!(
        credit_grant_key(Provider::OpenAi, "abc"),
        "f046fce7d928781b53b3363e5fa279c5d12ad1d48a496b7d9f78d86689ff41af"
    );
    assert_eq!(
        credit_grant_key(Provider::Anthropic, "Grant_01"),
        "2213d165fe6d9ddd7781bebd676341547af6bb3fb1a3b29fae743c62b56a6297"
    );
    // Case-preserving: `ABC` is a different grant from `abc`.
    assert_eq!(
        credit_grant_key(Provider::OpenAi, "ABC"),
        "4f00d656df736e2e89d39b30fee5cadc785f3787a9e5111c1e8e5cfed933b02d"
    );
    // Never trimmed.
    assert_ne!(
        credit_grant_key(Provider::OpenAi, " abc"),
        credit_grant_key(Provider::OpenAi, "abc")
    );
}

// ---- contract v2.1 §10 producer cases ------------------------------------

#[test]
fn v21_case1_codex_complete_list() {
    let balance = codex_reset_bank(
        2,
        READ_AT,
        read(
            Provider::OpenAi,
            Some(2),
            vec![
                openai_grant("a2", "2026-09-28T17:40:00Z", Some("2026-10-28T17:40:00Z")),
                openai_grant("a1", "2026-09-20T09:15:00Z", Some("2026-10-20T09:15:00Z")),
            ],
        ),
    );
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
    assert_eq!(balance.grant_count, Some(2));
    assert_eq!(balance.remaining, Some(2));
    assert_eq!(balance.grants_observed_at.as_deref(), Some(READ_AT));
    let grants = balance.grants.as_ref().unwrap();
    assert_eq!(grants.len(), 2);
    // Soonest expiry first.
    assert_eq!(
        grants[0].grant_key,
        credit_grant_key(Provider::OpenAi, "a1")
    );
    assert_eq!(grants[0].grant_type, CreditGrantType::RateLimitReset);
    assert_eq!(grants[0].status, CreditGrantStatus::Available);
    assert_eq!(
        grants[0].granted_at.as_deref(),
        Some("2026-09-20T09:15:00Z")
    );
    assert_eq!(
        balance.next_expires_at.as_deref(),
        Some("2026-10-20T09:15:00Z")
    );
    assert_eq!(
        balance.latest_granted_at.as_deref(),
        Some("2026-09-28T17:40:00Z")
    );
}

#[test]
fn v21_case2_codex_provider_capped_has_no_summaries() {
    let balance = codex_reset_bank(
        5,
        READ_AT,
        read(
            Provider::OpenAi,
            Some(5),
            vec![
                openai_grant("a1", "2026-09-20T09:15:00Z", Some("2026-10-20T09:15:00Z")),
                openai_grant("a2", "2026-09-28T17:40:00Z", Some("2026-10-28T17:40:00Z")),
            ],
        ),
    );
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Capped));
    assert_eq!(balance.grant_count, Some(5));
    assert_eq!(balance.grants.as_ref().unwrap().len(), 2);
    assert_eq!(balance.remaining, Some(5));
    // The provider chose which rows to return: no exact soonest expiry.
    assert_eq!(balance.next_expires_at, None);
    assert_eq!(balance.latest_granted_at, None);
}

fn overflow(count: usize) -> Vec<GrantInput> {
    (1..=count)
        .map(|k| {
            openai_grant(
                &format!("o{k:02}"),
                "2026-09-01T08:00:00Z",
                Some(&format!("2026-10-{:02}T08:00:00Z", (k % 28) + 1)),
            )
        })
        .collect()
}

#[test]
fn v21_case3_overflow_with_exact_count_is_sender_capped() {
    let build = build_grants(read(Provider::OpenAi, Some(25), overflow(25)));
    assert!(build.sender_capped);
    assert_eq!(codes(&build.diagnostics), vec![("grants_capped", "grants")]);
    let mut balance = saved_resets(Some(25), READ_AT);
    build.apply_to(&mut balance);
    assert_eq!(balance.grants.as_ref().unwrap().len(), GRANTS_MAX);
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Capped));
    assert_eq!(balance.grant_count, Some(25));
    // Sender cap keeps the soonest-expiring prefix: the minimum is exact.
    assert_eq!(
        balance.next_expires_at.as_deref(),
        Some("2026-10-02T08:00:00Z")
    );
    // Granted time needs the whole list.
    assert_eq!(balance.latest_granted_at, None);
}

#[test]
fn v21_case4_overflow_without_count_stays_partial() {
    let build = build_grants(read(Provider::OpenAi, None, overflow(25)));
    assert!(!build.sender_capped);
    let mut balance = saved_resets(None, READ_AT);
    balance.kind = Some(CreditBalanceKind::PlanCredits);
    build.apply_to(&mut balance);
    assert_eq!(balance.grants.as_ref().unwrap().len(), GRANTS_MAX);
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Partial));
    assert_eq!(balance.grant_count, None);
    assert_eq!(balance.next_expires_at, None);
}

#[test]
fn v21_case5_empty_complete_list() {
    let balance = codex_reset_bank(0, READ_AT, read(Provider::OpenAi, Some(0), vec![]));
    assert_eq!(balance.grants, Some(vec![]));
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
    assert_eq!(balance.grant_count, Some(0));
    assert_eq!(balance.remaining, Some(0));
    assert_eq!(balance.next_expires_at, None);
}

#[test]
fn v21_case6_and_12_count_only_is_unavailable() {
    let balance = codex_reset_bank(
        2,
        READ_AT,
        ListObservation::Unavailable {
            provider_count: Some(2),
        },
    );
    assert_eq!(balance.grants, None);
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Unavailable));
    assert_eq!(balance.grant_count, Some(2));
    assert_eq!(balance.grants_observed_at, None);
    assert_eq!(balance.remaining, Some(2));

    let unknown = build_grants(ListObservation::Unavailable {
        provider_count: None,
    });
    assert_eq!(unknown.grant_count, None);
    assert_eq!(unknown.grants_state, Some(CreditGrantsState::Unavailable));
}

#[test]
fn v21_case7_redeemed_and_past_expiry_have_no_expired_status() {
    let mut redeemed = openai_grant("r1", "2026-08-01T00:00:00Z", Some("2026-08-05T00:00:00Z"));
    redeemed.status = GrantStatusInput::Reported(Field::Value("redeemed".to_string()));
    let past = openai_grant("p1", "2026-08-02T00:00:00Z", Some("2026-08-10T00:00:00Z"));
    let balance = codex_reset_bank(
        2,
        READ_AT,
        read(Provider::OpenAi, Some(2), vec![redeemed, past]),
    );
    let grants = balance.grants.as_ref().unwrap();
    assert_eq!(grants[0].status, CreditGrantStatus::Redeemed);
    assert_eq!(grants[1].status, CreditGrantStatus::Available);
    // No clock filter, and redeemed grants never count.
    assert_eq!(
        balance.next_expires_at.as_deref(),
        Some("2026-08-10T00:00:00Z")
    );
    assert_eq!(
        balance.latest_granted_at.as_deref(),
        Some("2026-08-02T00:00:00Z")
    );
}

#[test]
fn v21_case8_claude_grant_fields_and_paused() {
    let balance = claude_reset_bank(
        READ_AT,
        read(
            Provider::Anthropic,
            Some(1),
            vec![anthropic_grant(
                "grant_paused",
                Some("Synthetic reset"),
                2,
                1,
                "2026-09-22T16:00:00+00:00",
                "2026-10-22T16:00:00+00:00",
                &["five_hour", "seven_day"],
                true,
                false,
            )],
        ),
    );
    let grant = &balance.grants.as_ref().unwrap()[0];
    assert_eq!(grant.status, CreditGrantStatus::Paused);
    assert_eq!(grant.grant_type, CreditGrantType::RateLimitReset);
    assert_eq!(grant.resets_included, Some(2));
    assert_eq!(grant.resets_left, Some(1));
    assert_eq!(
        grant.clears,
        Some(vec!["five_hour".to_string(), "seven_day".to_string()])
    );
    assert_eq!(grant.title.as_deref(), Some("Synthetic reset"));
    // Normalized to UTC.
    assert_eq!(grant.starts_at.as_deref(), Some("2026-09-22T16:00:00Z"));
    assert_eq!(grant.usable_now, Some(false));
    assert_eq!(grant.granted_at, None);
    // A paused grant's resets are not available now.
    assert_eq!(balance.remaining, Some(0));
    // Paused still counts toward the next expiry.
    assert_eq!(
        balance.next_expires_at.as_deref(),
        Some("2026-10-22T16:00:00Z")
    );
    assert_eq!(balance.latest_granted_at, None);
}

#[test]
fn v21_case9_claude_zero_resets_included_is_accepted() {
    let build = build_grants(read(
        Provider::Anthropic,
        Some(1),
        vec![anthropic_grant(
            "grant_zero",
            None,
            0,
            0,
            "2026-09-22T16:00:00Z",
            "2026-10-22T16:00:00Z",
            &[],
            false,
            false,
        )],
    ));
    assert!(build.diagnostics.is_empty());
    assert_eq!(build.grants_state, Some(CreditGrantsState::Complete));
    let grant = &build.grants.as_ref().unwrap()[0];
    assert_eq!(grant.resets_included, Some(0));
    assert_eq!(grant.status, CreditGrantStatus::Redeemed);
}

#[test]
fn v21_case10_invalid_expiry_keeps_grant_and_makes_list_partial() {
    let mut bad = openai_grant("e1", "2026-09-20T09:15:00Z", None);
    bad.expires_at = TimeInput::Rfc3339("not-a-time".to_string());
    let mut overflowed = openai_grant("e2", "2026-09-20T09:15:00Z", None);
    overflowed.expires_at = TimeInput::UnixSeconds(i64::MAX);
    let build = build_grants(read(Provider::OpenAi, Some(2), vec![bad, overflowed]));
    assert_eq!(build.grants_state, Some(CreditGrantsState::Partial));
    let grants = build.grants.as_ref().unwrap();
    assert_eq!(grants.len(), 2);
    assert!(grants.iter().all(|grant| grant.expires_at.is_none()));
    assert_eq!(
        codes(&build.diagnostics),
        vec![
            ("field_refused", "grants[].expires_at"),
            ("field_refused", "grants[].expires_at")
        ]
    );
}

#[test]
fn v21_case11_invalid_id_drops_grant_and_makes_list_partial() {
    let mut missing = openai_grant("x", "2026-09-20T09:15:00Z", None);
    missing.id = Field::Absent;
    let mut wrong_type = openai_grant("x", "2026-09-20T09:15:00Z", None);
    wrong_type.id = Field::Invalid;
    let empty = openai_grant("", "2026-09-20T09:15:00Z", None);
    let kept = openai_grant("kept", "2026-09-20T09:15:00Z", None);
    let build = build_grants(read(
        Provider::OpenAi,
        Some(4),
        vec![missing, wrong_type, empty, kept],
    ));
    assert_eq!(build.grants_state, Some(CreditGrantsState::Partial));
    assert_eq!(build.grants.as_ref().unwrap().len(), 1);
    assert_eq!(
        codes(&build.diagnostics),
        vec![("grant_dropped", "grants[].id"); 3]
    );

    // Anthropic ids follow the client schema `^[a-z0-9_-]{1,40}$`.
    let upper = anthropic_grant(
        "Grant_01",
        None,
        1,
        1,
        "2026-09-22T16:00:00Z",
        "2026-10-22T16:00:00Z",
        &[],
        false,
        false,
    );
    let long = anthropic_grant(
        &"g".repeat(41),
        None,
        1,
        1,
        "2026-09-22T16:00:00Z",
        "2026-10-22T16:00:00Z",
        &[],
        false,
        false,
    );
    let build = build_grants(read(Provider::Anthropic, Some(2), vec![upper, long]));
    assert_eq!(build.grants, Some(vec![]));
    assert_eq!(build.grants_state, Some(CreditGrantsState::Partial));
}

#[test]
fn v21_case13_not_supported() {
    let build = build_grants(ListObservation::NotSupported);
    assert_eq!(build.grants, None);
    assert_eq!(build.grants_state, Some(CreditGrantsState::NotSupported));
    assert_eq!(build.grant_count, None);
    assert!(build.diagnostics.is_empty());
}

#[test]
fn v21_case17_oversized_and_unknown_values() {
    let long_title = "Reset ".repeat(40);
    let mut grant = openai_grant("t1", "2026-09-20T09:15:00Z", None);
    grant.title = Field::Value(long_title.clone());
    grant.reset_type = Field::Value("somethingNew".to_string());
    grant.clears = Field::Value((0..9).map(|k| format!("w{k}")).collect());
    let mut odd_status = openai_grant("t2", "2026-09-20T09:15:00Z", None);
    odd_status.status = GrantStatusInput::Reported(Field::Value("expired".to_string()));
    let build = build_grants(read(
        Provider::OpenAi,
        Some(10_001),
        vec![grant, odd_status],
    ));
    let grants = build.grants.as_ref().unwrap();
    let t1 = grants
        .iter()
        .find(|grant| grant.grant_key == credit_grant_key(Provider::OpenAi, "t1"))
        .unwrap();
    let title = t1.title.as_deref().unwrap();
    assert_eq!(title.chars().count(), TITLE_MAX_CHARS);
    assert!(long_title.starts_with(title));
    assert_eq!(t1.grant_type, CreditGrantType::Unknown);
    assert_eq!(t1.clears, None);
    let t2 = grants
        .iter()
        .find(|grant| grant.grant_key == credit_grant_key(Provider::OpenAi, "t2"))
        .unwrap();
    assert_eq!(t2.status, CreditGrantStatus::Unknown);
    // The unknown status (not the type, clears or title) makes the list partial.
    assert_eq!(build.grants_state, Some(CreditGrantsState::Partial));
    assert_eq!(build.grant_count, None);
    let mut found = codes(&build.diagnostics);
    found.sort();
    assert_eq!(
        found,
        vec![
            ("field_refused", "grant_count"),
            ("field_refused", "grants[].clears"),
            ("field_refused", "grants[].grant_type"),
            ("field_refused", "grants[].status"),
            ("title_truncated", "grants[].title"),
        ]
    );
}

#[test]
fn refusals_without_state_change_keep_list_complete() {
    let mut grant = openai_grant("u1", "2026-09-20T09:15:00Z", None);
    grant.reset_type = Field::Invalid;
    grant.clears = Field::Value(vec!["Bad Name".to_string()]);
    grant.usable_now = Field::Invalid;
    grant.title = Field::Value("see /Users/someone/.codex/auth.json".to_string());
    let build = build_grants(read(Provider::OpenAi, Some(1), vec![grant]));
    assert_eq!(build.grants_state, Some(CreditGrantsState::Complete));
    let grant = &build.grants.as_ref().unwrap()[0];
    assert_eq!(grant.title, None);
    assert_eq!(grant.clears, None);
    assert_eq!(grant.usable_now, None);
    assert_eq!(build.diagnostics.len(), 4);
}

#[test]
fn refused_reset_counts_and_times_make_list_partial() {
    for mutate in [
        (|g: &mut GrantInput| g.resets_left = Field::Value(RESETS_MAX + 1)) as fn(&mut GrantInput),
        |g| g.resets_included = Field::Invalid,
        |g| g.granted_at = TimeInput::Invalid,
        |g| g.starts_at = TimeInput::Rfc3339("2026-13-01T00:00:00Z".to_string()),
        |g| {
            g.status = GrantStatusInput::PausedResetsLeft {
                paused: Field::Invalid,
                resets_left: Field::Value(1),
            }
        },
    ] {
        let mut grant = anthropic_grant(
            "grant_x",
            None,
            1,
            1,
            "2026-09-22T16:00:00Z",
            "2026-10-22T16:00:00Z",
            &[],
            false,
            false,
        );
        mutate(&mut grant);
        let build = build_grants(read(Provider::Anthropic, Some(1), vec![grant]));
        assert_eq!(build.grants_state, Some(CreditGrantsState::Partial));
        assert_eq!(build.grants.as_ref().unwrap().len(), 1);
    }
}

#[test]
fn list_longer_than_provider_count_is_partial() {
    let build = build_grants(read(
        Provider::OpenAi,
        Some(1),
        vec![
            openai_grant("a1", "2026-09-20T09:15:00Z", None),
            openai_grant("a2", "2026-09-20T09:15:00Z", None),
        ],
    ));
    assert_eq!(build.grants_state, Some(CreditGrantsState::Partial));
    assert_eq!(build.grant_count, Some(1));
}

#[test]
fn sender_cap_on_a_provider_capped_list_has_no_expiry() {
    // The provider reports 30 but returns 25: rows it omitted may expire first.
    let build = build_grants(read(Provider::OpenAi, Some(30), overflow(25)));
    assert!(!build.sender_capped);
    let mut balance = saved_resets(Some(30), READ_AT);
    build.apply_to(&mut balance);
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Capped));
    assert_eq!(balance.grants.as_ref().unwrap().len(), GRANTS_MAX);
    assert_eq!(balance.next_expires_at, None);
}

#[test]
fn sender_capped_expiry_counts_grants_past_the_cut() {
    // 20 redeemed grants expire before the only available one, which the cap
    // drops; its expiry is still the soonest eligible one.
    let mut records = (0..20)
        .map(|k| {
            anthropic_grant(
                &format!("grant_spent_{k:02}"),
                None,
                1,
                0,
                "2026-09-01T00:00:00Z",
                &format!("2026-10-{:02}T00:00:00Z", k + 1),
                &[],
                false,
                false,
            )
        })
        .collect::<Vec<_>>();
    records.push(anthropic_grant(
        "grant_live",
        None,
        1,
        1,
        "2026-09-01T00:00:00Z",
        "2026-10-25T00:00:00Z",
        &[],
        false,
        false,
    ));
    let balance = claude_reset_bank(READ_AT, read(Provider::Anthropic, Some(21), records));
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Capped));
    assert!(balance
        .grants
        .as_ref()
        .unwrap()
        .iter()
        .all(|grant| grant.status == CreditGrantStatus::Redeemed));
    assert_eq!(
        balance.next_expires_at.as_deref(),
        Some("2026-10-25T00:00:00Z")
    );
    // Capped: the saved-reset count stays unknown.
    assert_eq!(balance.remaining, None);
}

#[test]
fn partial_wins_over_sender_cap() {
    let mut records = overflow(25);
    records[3].id = Field::Absent;
    let build = build_grants(read(Provider::OpenAi, Some(25), records));
    assert_eq!(build.grants_state, Some(CreditGrantsState::Partial));
    assert!(!build.sender_capped);
    let mut balance = saved_resets(Some(25), READ_AT);
    build.apply_to(&mut balance);
    assert_eq!(balance.next_expires_at, None);
}

// ---- v2.2 cases ------------------------------------------------------------

/// The canonical 21-grant case: one more than the cap, provider order
/// reversed, two expiry ties and two grants with no expiry.
fn twenty_one() -> Vec<GrantInput> {
    let mut records = (1..=21)
        .map(|k| {
            let expires = match k {
                1..=17 => Some(format!("2026-10-{:02}T08:00:00Z", k + 1)),
                18 | 19 => Some("2026-10-10T08:00:00Z".to_string()),
                _ => None,
            };
            let granted = if k == 7 {
                "2026-09-15T08:00:00Z"
            } else {
                "2026-09-01T08:00:00Z"
            };
            openai_grant(&format!("rc_synth_c{k:02}"), granted, expires.as_deref())
        })
        .collect::<Vec<_>>();
    records.reverse();
    records
}

#[test]
fn twenty_one_grants_cap_and_order() {
    let balance = codex_reset_bank(21, READ_AT, read(Provider::OpenAi, Some(21), twenty_one()));
    let grants = balance.grants.as_ref().unwrap();
    assert_eq!(grants.len(), 20);
    assert_eq!(balance.grants_state, Some(CreditGrantsState::Capped));
    assert_eq!(balance.grant_count, Some(21));
    // Expiry ascending, ties by grant_key, no expiry last.
    let mut expected = (1..=21)
        .map(|k| {
            let key = credit_grant_key(Provider::OpenAi, &format!("rc_synth_c{k:02}"));
            let expiry = match k {
                1..=17 => Some(k + 1),
                18 | 19 => Some(10),
                _ => None,
            };
            (expiry.is_none(), expiry, key)
        })
        .collect::<Vec<_>>();
    expected.sort();
    let expected_keys = expected
        .into_iter()
        .map(|(_, _, key)| key)
        .take(20)
        .collect::<Vec<_>>();
    assert_eq!(keys(&balance), expected_keys);
    // Exactly one no-expiry grant survives: the one with the smaller key.
    assert_eq!(
        grants
            .iter()
            .filter(|grant| grant.expires_at.is_none())
            .count(),
        1
    );
    assert_eq!(
        balance.next_expires_at.as_deref(),
        Some("2026-10-02T08:00:00Z")
    );
    assert_eq!(balance.latest_granted_at, None);
}

#[test]
fn order_is_independent_of_provider_order() {
    let forward = build_grants(read(Provider::OpenAi, Some(21), {
        let mut records = twenty_one();
        records.reverse();
        records
    }));
    let reversed = build_grants(read(Provider::OpenAi, Some(21), twenty_one()));
    assert_eq!(forward.grants, reversed.grants);
}

#[test]
fn grant_stays_within_one_kibibyte() {
    let mut grant = anthropic_grant(
        "grant_big",
        None,
        1000,
        1000,
        "2026-09-22T16:00:00Z",
        "2026-10-22T16:00:00Z",
        &[],
        false,
        true,
    );
    // Within every per-field bound, but together over 1 KiB.
    grant.title = Field::Value("é".repeat(TITLE_MAX_CHARS));
    grant.clears = Field::Value(
        (0..CLEARS_MAX_ITEMS)
            .map(|k| format!("{k}{}", "w".repeat(63)))
            .collect(),
    );
    let build = build_grants(read(Provider::Anthropic, Some(1), vec![grant]));
    let grant = &build.grants.as_ref().unwrap()[0];
    assert!(grant_wire_size(grant) <= GRANT_MAX_BYTES);
    assert_eq!(grant.title, None);
    assert!(grant.clears.is_some());
    assert_eq!(build.grants_state, Some(CreditGrantsState::Complete));
}

#[test]
fn title_bounds_check_privacy_before_truncation() {
    // An unsafe fragment past the cut still refuses the whole title.
    let leak = format!("{} sk-synthetic-secret", "a".repeat(200));
    let (title, diagnostic) = bounded_title(Field::Value(leak), "title");
    assert_eq!(title, None);
    assert_eq!(
        diagnostic,
        Some(CreditModelDiagnostic::new("field_refused", "title"))
    );
    // Byte bound: 4-byte characters stop at 512 bytes.
    let (title, diagnostic) = bounded_title(Field::Value("😀".repeat(200)), "title");
    assert_eq!(title.as_deref().map(str::len), Some(TITLE_MAX_BYTES));
    assert_eq!(diagnostic.unwrap().code, "title_truncated");
    assert_eq!(
        bounded_title(Field::Value(String::new()), "title"),
        (None, None)
    );
}

#[test]
fn claude_saved_resets_sum_only_when_complete() {
    let launch = || {
        anthropic_grant(
            "grant_launch",
            None,
            2,
            1,
            "2026-09-22T16:00:00Z",
            "2026-10-22T16:00:00Z",
            &[],
            false,
            true,
        )
    };
    let paused = || {
        anthropic_grant(
            "grant_paused",
            None,
            3,
            3,
            "2026-09-22T16:00:00Z",
            "2026-10-15T16:00:00Z",
            &[],
            true,
            false,
        )
    };
    let spent = || {
        anthropic_grant(
            "grant_spent",
            None,
            1,
            0,
            "2026-09-01T16:00:00Z",
            "2026-10-05T16:00:00Z",
            &[],
            false,
            false,
        )
    };
    let complete = claude_reset_bank(
        READ_AT,
        read(
            Provider::Anthropic,
            Some(3),
            vec![launch(), paused(), spent()],
        ),
    );
    assert_eq!(complete.remaining, Some(1));
    assert_eq!(complete.status, AgentCreditBalanceStatus::Ok);
    assert_eq!(
        complete.next_expires_at.as_deref(),
        Some("2026-10-15T16:00:00Z")
    );

    let empty = claude_reset_bank(READ_AT, read(Provider::Anthropic, Some(0), vec![]));
    assert_eq!(empty.remaining, Some(0));
    assert_eq!(empty.status, AgentCreditBalanceStatus::Exhausted);

    // Partial (refused field), partial-by-drop, capped and unavailable: unknown.
    let mut refused = spent();
    refused.expires_at = TimeInput::Invalid;
    let partial = claude_reset_bank(
        READ_AT,
        read(Provider::Anthropic, Some(2), vec![launch(), refused]),
    );
    assert_eq!(partial.grants_state, Some(CreditGrantsState::Partial));
    assert_eq!(partial.remaining, None);
    assert_eq!(partial.status, AgentCreditBalanceStatus::Unknown);

    let mut dropped = launch();
    dropped.id = Field::Invalid;
    let all_dropped = claude_reset_bank(READ_AT, read(Provider::Anthropic, Some(1), vec![dropped]));
    assert_eq!(all_dropped.grants, Some(vec![]));
    assert_eq!(all_dropped.remaining, None);

    let many = (0..21)
        .map(|k| {
            anthropic_grant(
                &format!("grant_{k:02}"),
                None,
                1,
                1,
                "2026-09-22T16:00:00Z",
                "2026-10-22T16:00:00Z",
                &[],
                false,
                false,
            )
        })
        .collect();
    let capped = claude_reset_bank(READ_AT, read(Provider::Anthropic, Some(21), many));
    assert_eq!(capped.grants_state, Some(CreditGrantsState::Capped));
    assert_eq!(capped.remaining, None);
    // The sender-capped prefix still has an exact soonest expiry.
    assert_eq!(
        capped.next_expires_at.as_deref(),
        Some("2026-10-22T16:00:00Z")
    );

    let unavailable = claude_reset_bank(
        READ_AT,
        ListObservation::Unavailable {
            provider_count: None,
        },
    );
    assert_eq!(unavailable.remaining, None);
}

#[test]
fn summarize_recomputes_without_provider_hint() {
    let mut balance = claude_reset_bank(
        READ_AT,
        read(
            Provider::Anthropic,
            Some(1),
            vec![anthropic_grant(
                "grant_one",
                None,
                2,
                2,
                "2026-09-22T16:00:00Z",
                "2026-10-22T16:00:00Z",
                &[],
                false,
                false,
            )],
        ),
    );
    let before = balance.clone();
    summarize(&mut balance);
    assert_eq!(balance, before);
    // The same list downgraded to partial loses every summary.
    balance.grants_state = Some(CreditGrantsState::Partial);
    summarize(&mut balance);
    assert_eq!(balance.remaining, None);
    assert_eq!(balance.next_expires_at, None);

    // A provider count is never replaced (OpenAI grants carry no resets_left),
    // including an empty list read against a stale count.
    let mut codex = codex_reset_bank(3, READ_AT, read(Provider::OpenAi, Some(0), vec![]));
    codex.grants_state = Some(CreditGrantsState::Partial);
    summarize(&mut codex);
    assert_eq!(codex.remaining, Some(3));
}

#[test]
fn summaries_need_saved_resets_kind_for_remaining() {
    let mut balance = saved_resets(Some(7), READ_AT);
    balance.kind = Some(CreditBalanceKind::PlanCredits);
    balance.unit = AgentCreditBalanceUnit::Credits;
    build_grants(read(
        Provider::Anthropic,
        Some(1),
        vec![anthropic_grant(
            "grant_one",
            None,
            2,
            2,
            "2026-09-22T16:00:00Z",
            "2026-10-22T16:00:00Z",
            &[],
            false,
            false,
        )],
    ))
    .apply_to(&mut balance);
    assert_eq!(balance.remaining, Some(7));
}

#[test]
fn one_time_credit_shape() {
    let balance = one_time_credit(
        "iguana_necktie",
        Field::Absent,
        Some(25_000),
        Some(1_250),
        Some(23_750),
        Some("2026-11-05T07:59:00Z".to_string()),
        Some(READ_AT.to_string()),
    );
    assert_eq!(
        serde_json::to_value(&balance).unwrap(),
        json!({
            "name": "one_time_credit",
            "status": "ok",
            "freshness": "fresh",
            "unit": "usd",
            "remaining": 23750,
            "used": 1250,
            "quota": 25000,
            "currency": "USD",
            "limit_id": "iguana_necktie",
            "observed_at": READ_AT,
            "expires_at": "2026-11-05T07:59:00Z",
            "kind": "one_time_credit"
        })
    );
    // No `enabled` flag, no recurring reset.
    assert_eq!(balance.enabled, None);
    assert_eq!(balance.resets_at, None);
    let spent = one_time_credit(
        "pool",
        Field::Absent,
        Some(100),
        Some(100),
        Some(0),
        None,
        None,
    );
    assert_eq!(spent.status, AgentCreditBalanceStatus::Exhausted);
    let unknown = one_time_credit("pool", Field::Absent, None, None, None, None, None);
    assert_eq!(unknown.status, AgentCreditBalanceStatus::Unknown);
    let titled = one_time_credit(
        "pool",
        Field::Value("Synthetic promo credit".to_string()),
        None,
        None,
        None,
        None,
        None,
    );
    assert_eq!(titled.title.as_deref(), Some("Synthetic promo credit"));
}

#[test]
fn time_normalization() {
    assert_eq!(
        normalize_time(TimeInput::Rfc3339(
            "2026-10-06T16:09:59.691850+00:00".into()
        )),
        Ok(Some("2026-10-06T16:09:59.69185Z".to_string()))
    );
    assert_eq!(
        normalize_time(TimeInput::Rfc3339("2026-10-06T18:00:00+02:00".into())),
        Ok(Some("2026-10-06T16:00:00Z".to_string()))
    );
    assert_eq!(
        normalize_time(TimeInput::UnixSeconds(1_789_895_700)),
        Ok(Some("2026-09-20T09:15:00Z".to_string()))
    );
    assert_eq!(normalize_time(TimeInput::Absent), Ok(None));
    assert_eq!(normalize_time(TimeInput::Invalid), Err(()));
    assert_eq!(normalize_time(TimeInput::Rfc3339("soon".into())), Err(()));
}

// ---- R7b SectionCache sequences -------------------------------------------

const CODEX_GRANTS: &str = "codex_reset_grants";
const PLAIN: &str = "plain";
const SAVED: &str = "saved_resets";

fn plain_section(observed_at: &str) -> Vec<AgentCreditBalance> {
    vec![
        AgentCreditBalance {
            name: "Usage credits".to_string(),
            status: AgentCreditBalanceStatus::Unknown,
            freshness: AgentQuotaWindowFreshness::Fresh,
            unit: AgentCreditBalanceUnit::Usd,
            enabled: Some(false),
            disabled_reason: Some("out_of_credits".to_string()),
            kind: Some(CreditBalanceKind::UsageCredits),
            observed_at: Some(observed_at.to_string()),
            ..Default::default()
        },
        one_time_credit(
            "iguana_necktie",
            Field::Absent,
            Some(25_000),
            Some(1_250),
            Some(23_750),
            Some("2026-11-05T07:59:00Z".to_string()),
            Some(observed_at.to_string()),
        ),
    ]
}

fn cedar_section(observed_at: &str) -> Vec<AgentCreditBalance> {
    let mut balance = claude_reset_bank(
        observed_at,
        ListObservation::Read {
            provider: Provider::Anthropic,
            provider_count: Some(3),
            records: claude_cedar_grants(),
            observed_at: observed_at.to_string(),
        },
    );
    balance.eligible = Some(true);
    balance.at_limit = Some(true);
    balance.cooldown_until = Some("2026-10-01T18:00:00Z".to_string());
    vec![balance]
}

fn claude_cedar_grants() -> Vec<GrantInput> {
    vec![
        anthropic_grant(
            "grant_synth_launch",
            Some("Synthetic launch: one usage-limit reset"),
            2,
            1,
            "2026-09-22T16:00:00+00:00",
            "2026-10-22T16:00:00+00:00",
            &["five_hour", "seven_day"],
            false,
            true,
        ),
        anthropic_grant(
            "grant_synth_paused",
            None,
            1,
            1,
            "2026-09-25T16:00:00+00:00",
            "2026-10-15T16:00:00+00:00",
            &["five_hour"],
            true,
            false,
        ),
        anthropic_grant(
            "grant_synth_spent",
            Some("Synthetic welcome reset"),
            1,
            0,
            "2026-09-01T16:00:00+00:00",
            "2026-10-05T16:00:00+00:00",
            &["seven_day"],
            false,
            false,
        ),
    ]
}

#[test]
fn cache_cold_start_sends_nothing_unread() {
    let cache = SectionCache::new();
    assert_eq!(cache.resend_balances("a", SAVED, PACKAGED_AT), None);
    assert_eq!(cache.grant_list_for_count("a", CODEX_GRANTS, 2), None);
}

#[test]
fn cache_resend_keeps_read_clocks_and_stamps_packaging_time() {
    let mut cache = SectionCache::new();
    let observed = cedar_section("2026-10-01T13:00:00Z");
    cache.observe_balances("a", SAVED, &observed);
    for packaged_at in ["2026-10-01T13:05:00Z", "2026-10-01T16:05:00Z"] {
        let resent = cache.resend_balances("a", SAVED, packaged_at).unwrap();
        assert_eq!(resent.len(), 1);
        let mut expected = observed[0].clone();
        expected.updated_at = Some(packaged_at.to_string());
        // Presence, grants, state, status and both read clocks are unchanged;
        // only `updated_at` is the packaging time (never carried over).
        assert_eq!(resent[0], expected);
    }
    // A 3 h sleep changes nothing about what is re-sent.
    let after_sleep = cache
        .resend_balances("a", SAVED, "2026-10-01T19:00:00Z")
        .unwrap();
    assert_eq!(
        after_sleep[0].grants_observed_at.as_deref(),
        Some("2026-10-01T13:00:00Z")
    );
    assert_eq!(after_sleep[0].status, observed[0].status);
}

#[test]
fn cache_restart_is_cold() {
    let mut cache = SectionCache::new();
    cache.observe_balances("a", SAVED, &cedar_section(READ_AT));
    drop(cache);
    let restarted = SectionCache::new();
    assert_eq!(restarted.resend_balances("a", SAVED, PACKAGED_AT), None);
}

#[test]
fn cache_a_b_a_keeps_a_sections() {
    let mut cache = SectionCache::new();
    cache.observe_balances("account-a", SAVED, &cedar_section(READ_AT));
    cache.observe_balances("account-a", PLAIN, &plain_section(READ_AT));
    // B reads only plain; its saved resets were never read.
    cache.observe_balances("account-b", PLAIN, &plain_section(READ_AT));
    assert_eq!(cache.resend_balances("account-b", SAVED, PACKAGED_AT), None);
    // Back on A: A's saved resets are still there, unchanged.
    let resent = cache
        .resend_balances("account-a", SAVED, PACKAGED_AT)
        .unwrap();
    assert_eq!(resent[0].grants, cedar_section(READ_AT)[0].grants);
    // An identity change on A's binding clears only A.
    cache.clear_binding("account-a");
    assert_eq!(cache.resend_balances("account-a", SAVED, PACKAGED_AT), None);
    assert_eq!(cache.resend_balances("account-a", PLAIN, PACKAGED_AT), None);
    assert!(cache
        .resend_balances("account-b", PLAIN, PACKAGED_AT)
        .is_some());
}

#[test]
fn cache_empty_section_is_a_real_observation() {
    let mut cache = SectionCache::new();
    cache.observe_balances("a", PLAIN, &[]);
    assert_eq!(cache.resend_balances("a", PLAIN, PACKAGED_AT), Some(vec![]));
}

#[test]
fn codex_cached_list_only_while_count_matches() {
    let mut cache = SectionCache::new();
    let detailed = codex_reset_bank(
        2,
        READ_AT,
        read(
            Provider::OpenAi,
            Some(2),
            vec![
                openai_grant("a1", "2026-09-20T09:15:00Z", Some("2026-10-20T09:15:00Z")),
                openai_grant("a2", "2026-09-28T17:40:00Z", Some("2026-10-28T17:40:00Z")),
            ],
        ),
    );
    cache.observe_grant_list("a", CODEX_GRANTS, 2, &detailed);

    // Three routine polls at the same count: the list rides along unchanged.
    for minute in ["05", "10", "15"] {
        let read_at = format!("2026-10-01T12:{minute}:00Z");
        let mut routine = saved_resets(Some(2), &read_at);
        routine.unlimited = Some(false);
        let list = cache.grant_list_for_count("a", CODEX_GRANTS, 2).unwrap();
        list.apply_to(&mut routine);
        assert_eq!(routine.grants, detailed.grants);
        assert_eq!(routine.grants_state, Some(CreditGrantsState::Complete));
        assert_eq!(routine.grants_observed_at.as_deref(), Some(READ_AT));
        assert_eq!(routine.next_expires_at, detailed.next_expires_at);
        assert_eq!(routine.latest_granted_at, detailed.latest_granted_at);
        // The count itself was read now.
        assert_eq!(routine.observed_at.as_deref(), Some(read_at.as_str()));
    }
    // The count moved: the caller must read details now.
    assert_eq!(cache.grant_list_for_count("a", CODEX_GRANTS, 1), None);
    assert_eq!(cache.grant_list_for_count("a", CODEX_GRANTS, 3), None);

    // A failed detail read is not cached; the stale list stays unusable.
    let failed = codex_reset_bank(
        1,
        READ_AT,
        ListObservation::Unavailable {
            provider_count: Some(1),
        },
    );
    cache.observe_grant_list("a", CODEX_GRANTS, 1, &failed);
    assert_eq!(cache.grant_list_for_count("a", CODEX_GRANTS, 1), None);
    assert!(cache.grant_list_for_count("a", CODEX_GRANTS, 2).is_some());
}

#[test]
fn cache_is_bounded() {
    let mut cache = SectionCache::new();
    for k in 0..(SECTION_CACHE_MAX_ENTRIES + 5) {
        cache.observe_balances(&format!("binding-{k}"), PLAIN, &[]);
    }
    assert_eq!(cache.len(), SECTION_CACHE_MAX_ENTRIES);
    // The oldest entries went first.
    assert_eq!(cache.resend_balances("binding-0", PLAIN, PACKAGED_AT), None);
    assert!(cache
        .resend_balances(
            &format!("binding-{}", SECTION_CACHE_MAX_ENTRIES + 4),
            PLAIN,
            PACKAGED_AT
        )
        .is_some());
}

#[test]
fn stamp_packaged_at_overwrites_every_balance() {
    let mut balances = plain_section(READ_AT);
    balances[0].updated_at = Some("2026-01-01T00:00:00Z".to_string());
    stamp_packaged_at(&mut balances, PACKAGED_AT);
    assert!(balances
        .iter()
        .all(|balance| balance.updated_at.as_deref() == Some(PACKAGED_AT)));
}

// ---- canonical fixtures ----------------------------------------------------

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/agent-status/quota-contract-v2.2")
}

fn packaged(mut balances: Vec<AgentCreditBalance>) -> Vec<AgentCreditBalance> {
    stamp_packaged_at(&mut balances, PACKAGED_AT);
    balances
}

fn reading(balances: Vec<AgentCreditBalance>) -> Value {
    json!({ "credit_balances": packaged(balances) })
}

fn codex_two() -> Vec<GrantInput> {
    vec![
        openai_grant(
            "rc_synth_a1",
            "2026-09-20T09:15:00Z",
            Some("2026-10-20T09:15:00Z"),
        ),
        openai_grant(
            "rc_synth_a2",
            "2026-09-28T17:40:00Z",
            Some("2026-10-28T17:40:00Z"),
        ),
    ]
}

fn codex_complete_at(read_at: &str) -> AgentCreditBalance {
    codex_reset_bank(
        2,
        read_at,
        ListObservation::Read {
            provider: Provider::OpenAi,
            provider_count: Some(2),
            records: codex_two(),
            observed_at: read_at.to_string(),
        },
    )
}

fn codex_count_changed_at(read_at: &str) -> AgentCreditBalance {
    codex_reset_bank(
        1,
        read_at,
        ListObservation::Read {
            provider: Provider::OpenAi,
            provider_count: Some(1),
            records: vec![codex_two().remove(1)],
            observed_at: read_at.to_string(),
        },
    )
}

/// One reading step of a re-send sequence.
fn step(
    step: &str,
    packaged_at: &str,
    provider_inputs: &[&str],
    mut credit_balances: Vec<AgentCreditBalance>,
) -> Value {
    stamp_packaged_at(&mut credit_balances, packaged_at);
    json!({
        "step": step,
        "packaged_at": packaged_at,
        "provider_inputs": provider_inputs,
        "credit_balances": credit_balances,
    })
}

fn codex_sequence() -> Value {
    let mut cache = SectionCache::new();
    let mut steps = Vec::new();

    // 1. Cold start, routine poll reports count 2: no cached list, so the
    //    details are read now.
    let t1 = "2026-10-01T12:00:00Z";
    assert!(cache
        .grant_list_for_count("account-a", CODEX_GRANTS, 2)
        .is_none());
    let detailed = codex_complete_at(t1);
    cache.observe_grant_list("account-a", CODEX_GRANTS, 2, &detailed);
    steps.push(step(
        "cold start: count 2, no cached list, details read now",
        "2026-10-01T12:00:05Z",
        &[
            "provider/codex-reset-credits-count-only.json",
            "provider/codex-reset-credits-complete.json",
        ],
        vec![detailed],
    ));

    // 2-3. Routine polls at the same count re-send the cached list.
    for (minute, packaged) in [
        ("05", "2026-10-01T12:05:05Z"),
        ("10", "2026-10-01T12:10:05Z"),
    ] {
        let read_at = format!("2026-10-01T12:{minute}:00Z");
        let mut routine = saved_resets(Some(2), &read_at);
        routine.unlimited = Some(false);
        cache
            .grant_list_for_count("account-a", CODEX_GRANTS, 2)
            .expect("cached list at the same count")
            .apply_to(&mut routine);
        steps.push(step(
            "routine poll: count unchanged, cached list re-sent with its original grants_observed_at",
            packaged,
            &["provider/codex-reset-credits-count-only.json"],
            vec![routine],
        ));
    }

    // 4. The count moved: details are read now.
    let t4 = "2026-10-01T12:15:00Z";
    assert!(cache
        .grant_list_for_count("account-a", CODEX_GRANTS, 1)
        .is_none());
    let changed = codex_count_changed_at(t4);
    cache.observe_grant_list("account-a", CODEX_GRANTS, 1, &changed);
    steps.push(step(
        "routine poll: count changed to 1, details read now",
        "2026-10-01T12:15:05Z",
        &["provider/codex-reset-credits-count-changed.json"],
        vec![changed],
    ));

    // 5. Daemon restart (cold cache) and the detail read fails: unavailable,
    //    never a stale or invented list.
    let restarted = SectionCache::new();
    assert!(restarted
        .grant_list_for_count("account-a", CODEX_GRANTS, 1)
        .is_none());
    let failed = codex_reset_bank(
        1,
        "2026-10-01T12:20:00Z",
        ListObservation::Unavailable {
            provider_count: Some(1),
        },
    );
    steps.push(step(
        "restart: cold cache, count 1, detail read failed",
        "2026-10-01T12:20:05Z",
        &["provider/codex-reset-credits-count-only.json"],
        vec![failed],
    ));
    json!({ "sequence": "codex-reset-credits", "steps": steps })
}

/// Synthetic account hash so the A→B→A steps are distinguishable.
fn for_account(account: &str, mut balances: Vec<AgentCreditBalance>) -> Vec<AgentCreditBalance> {
    let digest = Sha256::digest(format!("synthetic:{account}").as_bytes());
    let hash = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    for balance in &mut balances {
        balance.account_identifier_hash = Some(hash.clone());
    }
    balances
}

fn claude_sequence() -> Value {
    let mut cache = SectionCache::new();
    let mut steps = Vec::new();
    let a = "account-a";

    // 1. Cold start, plain read: saved resets were never read, so they are
    //    not sent at all (no `status: unknown` stand-in).
    let plain_1 = for_account(a, plain_section("2026-10-01T13:00:00Z"));
    cache.observe_balances(a, PLAIN, &plain_1);
    assert!(cache.resend_balances(a, SAVED, "x").is_none());
    steps.push(step(
        "cold start: plain read; saved resets never read, not sent",
        "2026-10-01T13:00:05Z",
        &["provider/claude-oauth-usage-plain.json"],
        plain_1,
    ));

    // 2. Saved-reset read; plain re-sent from the cache.
    let saved_2 = for_account(a, cedar_section("2026-10-01T14:00:00Z"));
    cache.observe_balances(a, SAVED, &saved_2);
    let mut balances = cache
        .resend_balances(a, PLAIN, "2026-10-01T14:00:05Z")
        .unwrap();
    balances.extend(saved_2);
    steps.push(step(
        "saved-reset read; plain section re-sent unchanged",
        "2026-10-01T14:00:05Z",
        &["provider/claude-usage-cedar.json"],
        balances,
    ));

    // 3. Plain read after a 3 h sleep; saved resets re-sent from the cache.
    let plain_3 = for_account(a, plain_section("2026-10-01T17:00:00Z"));
    cache.observe_balances(a, PLAIN, &plain_3);
    let mut balances = plain_3;
    balances.extend(
        cache
            .resend_balances(a, SAVED, "2026-10-01T17:00:05Z")
            .unwrap(),
    );
    steps.push(step(
        "plain read after a 3 h sleep; saved-reset section re-sent unchanged",
        "2026-10-01T17:00:05Z",
        &["provider/claude-oauth-usage-plain.json"],
        balances,
    ));

    // 4. The slot now holds account B (cold for B): only B's plain read.
    let plain_b = for_account("account-b", plain_section("2026-10-01T18:00:00Z"));
    cache.observe_balances("account-b", PLAIN, &plain_b);
    assert!(cache.resend_balances("account-b", SAVED, "x").is_none());
    steps.push(step(
        "switch to account B: plain read; B's saved resets never read, not sent",
        "2026-10-01T18:00:05Z",
        &["provider/claude-oauth-usage-plain.json"],
        plain_b,
    ));

    // 5. Back to A: A's saved resets survive the A→B→A switch.
    let plain_5 = for_account(a, plain_section("2026-10-01T19:00:00Z"));
    cache.observe_balances(a, PLAIN, &plain_5);
    let mut balances = plain_5;
    balances.extend(
        cache
            .resend_balances(a, SAVED, "2026-10-01T19:00:05Z")
            .unwrap(),
    );
    steps.push(step(
        "back to account A: plain read; A's saved-reset section re-sent from before the switch",
        "2026-10-01T19:00:05Z",
        &["provider/claude-oauth-usage-plain.json"],
        balances,
    ));

    // 6. Restart: cold again; only the section read now is sent.
    let mut cache = SectionCache::new();
    let plain_6 = for_account(a, plain_section("2026-10-01T20:00:00Z"));
    cache.observe_balances(a, PLAIN, &plain_6);
    assert!(cache.resend_balances(a, SAVED, "x").is_none());
    steps.push(step(
        "restart: cold cache, plain read; saved resets not sent until read",
        "2026-10-01T20:00:05Z",
        &["provider/claude-oauth-usage-plain.json"],
        plain_6,
    ));
    json!({ "sequence": "claude-plain-saved-resets", "steps": steps })
}

/// Every expected file: the model output for the inputs mirrored from the
/// matching `provider/*.json` file.
fn expected_fixtures() -> Vec<(&'static str, Value)> {
    let mut cedar_one_time = plain_section(READ_AT).remove(1);
    cedar_one_time.observed_at = Some(READ_AT.to_string());
    let mut ineligible = claude_reset_bank(READ_AT, read(Provider::Anthropic, Some(0), vec![]));
    ineligible.eligible = Some(false);
    ineligible.ineligible_reason = Some("tenure".to_string());
    ineligible.at_limit = Some(false);
    let mut bad_expiry = claude_cedar_grants().remove(2);
    bad_expiry.id = Field::Value("grant_synth_badexpiry".to_string());
    bad_expiry.expires_at = TimeInput::Rfc3339("not-a-time".to_string());
    bad_expiry.resets_left = Field::Value(1);
    bad_expiry.status = GrantStatusInput::PausedResetsLeft {
        paused: Field::Value(false),
        resets_left: Field::Value(1),
    };
    let mut refused = claude_reset_bank(
        READ_AT,
        read(
            Provider::Anthropic,
            Some(2),
            vec![claude_cedar_grants().remove(0), bad_expiry],
        ),
    );
    refused.eligible = Some(true);
    refused.at_limit = Some(false);

    vec![
        (
            "codex-reset-credits-complete",
            reading(vec![codex_complete_at(READ_AT)]),
        ),
        (
            "codex-reset-credits-provider-capped",
            reading(vec![codex_reset_bank(
                5,
                READ_AT,
                read(Provider::OpenAi, Some(5), codex_two()),
            )]),
        ),
        (
            "codex-reset-credits-21",
            reading(vec![codex_reset_bank(
                21,
                READ_AT,
                read(Provider::OpenAi, Some(21), twenty_one()),
            )]),
        ),
        (
            "codex-reset-credits-details-unavailable",
            reading(vec![codex_reset_bank(
                2,
                READ_AT,
                ListObservation::Unavailable {
                    provider_count: Some(2),
                },
            )]),
        ),
        (
            "claude-usage-cedar",
            reading({
                let mut balances = vec![cedar_one_time];
                balances.extend(cedar_section(READ_AT));
                balances
            }),
        ),
        ("claude-usage-cedar-ineligible", reading(vec![ineligible])),
        ("claude-usage-cedar-refused-expiry", reading(vec![refused])),
        ("claude-oauth-usage-plain", reading(plain_section(READ_AT))),
        ("sequence-codex-reset-credits", codex_sequence()),
        ("sequence-claude-plain-saved-resets", claude_sequence()),
    ]
}

fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("fixture json");
    text.push('\n');
    text
}

/// `OTTTO_WRITE_QUOTA_V22_FIXTURES=1` rewrites `expected/`; otherwise every
/// expected file must equal the model's output byte for byte.
#[test]
fn canonical_expected_fixtures_match_model() {
    let dir = fixture_dir().join("expected");
    let fixtures = expected_fixtures();
    if std::env::var_os("OTTTO_WRITE_QUOTA_V22_FIXTURES").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        for (name, value) in &fixtures {
            std::fs::write(dir.join(format!("{name}.wire.json")), render(value)).unwrap();
        }
    }
    let mut on_disk = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    on_disk.sort();
    let mut listed = fixtures
        .iter()
        .map(|(name, _)| format!("{name}.wire.json"))
        .collect::<Vec<_>>();
    listed.sort();
    assert_eq!(
        on_disk, listed,
        "expected/ holds exactly the model fixtures"
    );
    for (name, value) in &fixtures {
        let path = dir.join(format!("{name}.wire.json"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, render(value), "{name} differs from the model output");
    }
}

fn wire_balances(value: &Value) -> Vec<&Value> {
    if let Some(steps) = value.get("steps").and_then(Value::as_array) {
        return steps
            .iter()
            .flat_map(|step| step["credit_balances"].as_array().unwrap())
            .collect();
    }
    value["credit_balances"]
        .as_array()
        .unwrap()
        .iter()
        .collect()
}

#[test]
fn canonical_fixtures_are_fixed_points_without_spelled_nulls() {
    let dir = fixture_dir();
    for (name, _) in expected_fixtures() {
        let text = std::fs::read_to_string(dir.join(format!("expected/{name}.wire.json"))).unwrap();
        assert!(!text.contains("null"), "{name} spells a null");
        let value: Value = serde_json::from_str(&text).unwrap();
        for raw in wire_balances(&value) {
            // Decodes and re-encodes to the same JSON: nothing unknown, nothing
            // the protocol would drop.
            let balance: AgentCreditBalance = serde_json::from_value(raw.clone()).unwrap();
            assert_eq!(&serde_json::to_value(&balance).unwrap(), raw, "{name}");
            // Every list is in wire order and every grant is in bounds.
            if let Some(grants) = &balance.grants {
                let mut sorted = grants.clone();
                sorted.sort_by(grant_order);
                assert_eq!(&sorted, grants, "{name} grant order");
                assert!(grants.len() <= GRANTS_MAX);
                assert!(grants
                    .iter()
                    .all(|grant| grant_wire_size(grant) <= GRANT_MAX_BYTES));
                assert!(grants.iter().all(|grant| grant.grant_key.len() == 64));
            }
            // Summaries are what the model computes from the list (the sender
            // cap is the one documented exception).
            let mut resummarized = balance.clone();
            summarize(&mut resummarized);
            if balance.grants_state == Some(CreditGrantsState::Capped)
                && balance.grant_count.unwrap_or(0) as usize > GRANTS_MAX
            {
                resummarized.next_expires_at = balance.next_expires_at.clone();
            }
            assert_eq!(resummarized, balance, "{name} summaries");
            assert!(balance.kind.is_some(), "{name}: every balance has a kind");
            assert!(balance.updated_at.is_some(), "{name}: packaging time");
        }
    }
    // Every provider input is referenced by some expected file name or step.
    let mut provider = std::fs::read_dir(dir.join("provider"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    provider.sort();
    let expected = expected_fixtures()
        .into_iter()
        .map(|(_, value)| render(&value))
        .collect::<String>();
    let names = expected_fixtures()
        .into_iter()
        .map(|(name, _)| format!("{name}.json"))
        .collect::<Vec<_>>();
    for file in provider {
        assert!(
            names.contains(&file) || expected.contains(&format!("provider/{file}")),
            "provider/{file} has no expected output"
        );
        let text = std::fs::read_to_string(dir.join("provider").join(&file)).unwrap();
        serde_json::from_str::<Value>(&text).expect("provider fixture is JSON");
    }
}
