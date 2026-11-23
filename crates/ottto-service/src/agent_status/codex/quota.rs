//! Codex status quota operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::codex_credit_grants;
use crate::agent_status::credit_amount_input;
use crate::agent_status::first_json_string;
use crate::agent_status::json_bool;
use crate::agent_status::json_timestamp_rfc3339;
use crate::agent_status::json_u64;
use crate::agent_status::json_u8;
use crate::agent_status::rfc3339_minus_seconds;
use crate::agent_status::AgentCreditBalance;
use crate::agent_status::AgentCreditBalanceStatus;
use crate::agent_status::AgentCreditBalanceUnit;
use crate::agent_status::AgentQuotaWindow;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentQuotaWindowScope;
use crate::agent_status::AgentQuotaWindowStatus;
use crate::agent_status::BTreeMap;
use crate::agent_status::CreditAmount;
use crate::agent_status::Value;
use crate::agent_status::CODEX_LOW_CREDITS;

pub(in crate::agent_status) fn codex_app_server_quota_windows(
    value: &Value,
) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    for (limit_id, rate_limit) in codex_app_server_rate_limit_snapshots(value) {
        let Some(fields) = rate_limit.as_object() else {
            continue;
        };
        let mut window_fields = fields
            .iter()
            .filter(|(_, candidate)| {
                candidate.get("usedPercent").is_some()
                    || candidate.get("used_percent").is_some()
                    || candidate.get("windowDurationMins").is_some()
                    || candidate.get("window_duration_mins").is_some()
            })
            .collect::<Vec<_>>();
        window_fields.sort_by_key(|(field, _)| match field.as_str() {
            "primary" => (0_u8, field.as_str()),
            "secondary" => (1_u8, field.as_str()),
            _ => (2_u8, field.as_str()),
        });
        for (field, raw_window) in window_fields {
            let window_seconds =
                json_u64(raw_window, &["windowDurationMins", "window_duration_mins"])
                    .map(|minutes| minutes.saturating_mul(60));
            let name = codex_usage_window_key(
                &limit_id,
                field,
                window_seconds,
                json_timestamp_rfc3339(raw_window, &["resetsAt", "resets_at"]).is_some(),
            );
            if let Some(window) =
                codex_app_server_quota_window(&name, &limit_id, raw_window, rate_limit)
            {
                windows.push(window);
            }
        }
    }
    windows
}

pub(in crate::agent_status) fn codex_app_server_rate_limit_snapshots(
    value: &Value,
) -> Vec<(String, &Value)> {
    // `rateLimits` is the app server's effective subscription snapshot.  The
    // sibling `rateLimitsByLimitId` map may also contain inactive/model-specific
    // pools whose reset boundaries advance on every read.  Treating that map as
    // the primary source fabricated extra customer quotas and, because the
    // effective snapshot was then skipped, could also hide its credit balance.
    // Keep the map only as a compatibility fallback for app-server versions
    // that do not provide a usable effective snapshot.
    if let Some(snapshot) = value
        .get("rateLimits")
        .filter(|snapshot| codex_rate_limit_snapshot_has_usage(snapshot))
    {
        return vec![(
            first_json_string(snapshot, &["limitId", "limit_id"])
                .unwrap_or_else(|| "codex".to_string()),
            snapshot,
        )];
    }
    if let Some(by_limit_id) = value.get("rateLimitsByLimitId").and_then(Value::as_object) {
        let mut snapshots = by_limit_id
            .iter()
            .filter(|(_, snapshot)| codex_rate_limit_snapshot_has_usage(snapshot))
            .map(|(limit_id, snapshot)| (limit_id.clone(), snapshot))
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| left.0.cmp(&right.0));
        if !snapshots.is_empty() {
            return snapshots;
        }
    }
    Vec::new()
}

pub(in crate::agent_status) fn codex_rate_limit_snapshot_has_usage(value: &Value) -> bool {
    ["primary", "secondary"].iter().any(|field| {
        value.get(field).is_some_and(|window| {
            codex_app_server_quota_window(field, "codex", window, value).is_some()
        })
    }) || value
        .get("credits")
        .is_some_and(|credits| codex_credit_balance_from_credits_snapshot(credits, value).is_some())
        || codex_monthly_credit_limit_from_snapshot(value).is_some()
}

pub(in crate::agent_status) fn codex_app_server_quota_window(
    name: &str,
    limit_id: &str,
    value: &Value,
    snapshot: &Value,
) -> Option<AgentQuotaWindow> {
    let used_percent = json_u8(value, &["usedPercent", "used_percent"]);
    let left_percent = used_percent.map(|used| 100_u8.saturating_sub(used));
    let resets_at = json_timestamp_rfc3339(value, &["resetsAt", "resets_at"]);
    let window_seconds = json_u64(value, &["windowDurationMins", "window_duration_mins"])
        .map(|minutes| minutes.saturating_mul(60));
    let started_at = resets_at
        .as_deref()
        .zip(window_seconds)
        .and_then(|(reset, seconds)| rfc3339_minus_seconds(reset, seconds));
    if used_percent.is_none() && resets_at.is_none() && window_seconds.is_none() {
        return None;
    }
    let spend_control_reached =
        json_bool(snapshot, &["spendControlReached", "spend_control_reached"]);
    let rate_limit_reached_type = codex_rate_limit_reached_type(snapshot);
    Some(AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Account,
        status: match (
            spend_control_reached,
            rate_limit_reached_type.as_deref(),
            left_percent,
        ) {
            (Some(true), _, _) | (_, Some(_), _) => AgentQuotaWindowStatus::Exhausted,
            (_, _, Some(0)) => AgentQuotaWindowStatus::Exhausted,
            (_, _, Some(value)) if value <= 20 => AgentQuotaWindowStatus::NearLimit,
            (_, _, Some(_)) => AgentQuotaWindowStatus::Ok,
            _ => AgentQuotaWindowStatus::Unknown,
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        model: None,
        account_label: None,
        window_seconds,
        started_at_basis: started_at.as_ref().map(|_| "provider_duration".to_string()),
        started_at,
        resets_at,
        quota: None,
        remaining: None,
        used_percent,
        left_percent,
        spend_control_reached,
        rate_limit_reached_type,
        limit_id: Some(limit_id.to_string()),
        ..Default::default()
    })
}

pub(in crate::agent_status) fn codex_rate_limit_reached_type(container: &Value) -> Option<String> {
    let value = first_json_string(
        container,
        &["rateLimitReachedType", "rate_limit_reached_type"],
    )?;
    match value.as_str() {
        "rateLimitReached" | "rate_limit_reached" => Some("rateLimitReached".to_string()),
        "workspaceOwnerCreditsDepleted" | "workspace_owner_credits_depleted" => {
            Some("workspaceOwnerCreditsDepleted".to_string())
        }
        "workspaceMemberCreditsDepleted" | "workspace_member_credits_depleted" => {
            Some("workspaceMemberCreditsDepleted".to_string())
        }
        "workspaceOwnerUsageLimitReached" | "workspace_owner_usage_limit_reached" => {
            Some("workspaceOwnerUsageLimitReached".to_string())
        }
        "workspaceMemberUsageLimitReached" | "workspace_member_usage_limit_reached" => {
            Some("workspaceMemberUsageLimitReached".to_string())
        }
        _ => None,
    }
}

pub(in crate::agent_status) fn codex_app_server_credit_balances(
    value: &Value,
) -> Vec<AgentCreditBalance> {
    let mut balances = BTreeMap::<String, AgentCreditBalance>::new();
    for (limit_id, rate_limit) in codex_app_server_rate_limit_snapshots(value) {
        if let Some(credits) = rate_limit.get("credits") {
            if let Some(mut balance) =
                codex_credit_balance_from_credits_snapshot(credits, rate_limit)
            {
                balance.limit_id = Some(limit_id.clone());
                if limit_id != "codex" {
                    balance.name = format!("{limit_id}_{}", balance.name);
                }
                balances.insert(balance.name.clone(), balance);
            }
        }
        if let Some(mut balance) = codex_monthly_credit_limit_from_snapshot(rate_limit) {
            balance.limit_id = Some(limit_id.clone());
            if limit_id != "codex" {
                balance.name = format!("{limit_id}_{}", balance.name);
            }
            balances.insert(balance.name.clone(), balance);
        }
    }
    if let Some(remaining) = codex_credit_grants::available_count(value) {
        let remaining = CreditAmount::whole(remaining);
        let balance = AgentCreditBalance {
            name: codex_credit_grants::RESET_BANK.to_string(),
            status: crate::quota_credit_model::status_for_remaining(remaining),
            freshness: AgentQuotaWindowFreshness::Fresh,
            unit: AgentCreditBalanceUnit::Resets,
            account_label: None,
            remaining,
            used: None,
            quota: None,
            unlimited: Some(false),
            updated_at: None,
            ..Default::default()
        };
        balances.insert(balance.name.clone(), balance);
    }
    let mut balances = balances.into_values().collect::<Vec<_>>();
    codex_credit_grants::stamp_codex_balance_kinds(&mut balances);
    balances
}

/// Parse Codex's effective workspace monthly credit limit.
///
/// The app-server surface calls this `individualLimit`; the snake_case
/// `individual_limit` spelling is also accepted. It is a recurring budget, not
/// the earned reset bank and not the sparse `credits.balance`, so it gets a
/// stable, separate identity downstream.
pub(in crate::agent_status) fn codex_monthly_credit_limit_from_snapshot(
    container: &Value,
) -> Option<AgentCreditBalance> {
    let individual_limit = container
        .get("individualLimit")
        .or_else(|| container.get("individual_limit"))?;
    if individual_limit.is_null() {
        return None;
    }

    let quota = credit_amount_input::amount_at(individual_limit, &["limit"]);
    let used = credit_amount_input::amount_at(individual_limit, &["used"]);
    let remaining = match (quota, used) {
        (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
        _ => None,
    };
    let remaining_percent = json_u8(individual_limit, &["remainingPercent", "remaining_percent"]);
    let used_percent = remaining_percent.map(|value| 100_u8.saturating_sub(value));
    let resets_at = json_timestamp_rfc3339(individual_limit, &["resetsAt", "resets_at"]);
    if quota.is_none() && used.is_none() && remaining_percent.is_none() && resets_at.is_none() {
        return None;
    }

    let spend_control_reached =
        json_bool(container, &["spend_control_reached", "spendControlReached"]);
    let rate_limit_reached_type = codex_rate_limit_reached_type(container);
    let limit_id = first_json_string(container, &["limit_id", "limitId"]);
    let status = if spend_control_reached == Some(true)
        || remaining == Some(CreditAmount::ZERO)
        || remaining_percent == Some(0)
    {
        AgentCreditBalanceStatus::Exhausted
    } else if remaining_percent.is_some_and(|value| value <= 20) {
        AgentCreditBalanceStatus::Low
    } else {
        AgentCreditBalanceStatus::Ok
    };

    Some(AgentCreditBalance {
        name: codex_credit_grants::WORKSPACE_MONTHLY_CREDITS.to_string(),
        status,
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Credits,
        account_label: None,
        remaining,
        used,
        quota,
        unlimited: Some(false),
        updated_at: None,
        resets_at,
        used_percent,
        enabled: Some(true),
        spend_control_reached,
        rate_limit_reached_type,
        limit_id,
        ..Default::default()
    })
}

pub(in crate::agent_status) fn codex_credit_balance_from_credits_snapshot(
    credits: &Value,
    container: &Value,
) -> Option<AgentCreditBalance> {
    let remaining = credit_amount_input::amount_at(credits, &["balance", "remaining", "credits"]);
    let unlimited = json_bool(credits, &["unlimited"]);
    let has_credits_claim = json_bool(credits, &["hasCredits", "has_credits"]);
    let has_credits = has_credits_claim.unwrap_or(false);
    // `credits` sits beside `primary`/`secondary` on the rate-limit snapshot; the
    // sibling `spend_control_reached`, `rate_limit_reached_type`, and `limit_id`
    // fields (e.g. `limitId: "codex"`) live on that container and carry the
    // spend-cap contract.
    let spend_control_reached =
        json_bool(container, &["spend_control_reached", "spendControlReached"]);
    let rate_limit_reached_type = codex_rate_limit_reached_type(container);
    let limit_id = first_json_string(container, &["limit_id", "limitId"]);
    if remaining.is_none()
        && unlimited.is_none()
        && !has_credits
        && spend_control_reached != Some(true)
    {
        return None;
    }
    if codex_credits_do_not_apply(
        has_credits_claim,
        unlimited,
        remaining,
        spend_control_reached,
    ) {
        return None;
    }
    // A reached spend control means the account is spend-capped even if a nominal
    // credit figure remains, so treat it as exhausted regardless of the balance.
    let status = if spend_control_reached == Some(true) {
        AgentCreditBalanceStatus::Exhausted
    } else {
        codex_credit_balance_status(remaining, unlimited, has_credits)
    };
    Some(AgentCreditBalance {
        name: codex_credit_grants::PLAN_CREDITS.to_string(),
        status,
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Credits,
        account_label: None,
        remaining,
        used: None,
        quota: None,
        unlimited,
        updated_at: None,
        spend_control_reached,
        rate_limit_reached_type,
        limit_id,
        ..Default::default()
    })
}

/// `hasCredits: false` is the provider stating that the credits program does not
/// apply to this account, not that the balance ran out. A nominal `balance: "0"`
/// rides along with that claim, so mapping it through the balance rules invents a
/// red "0 left / exhausted" meter for a concept the account does not have. Suppress
/// the row only when the provider explicitly disowns credits and nothing positive
/// is being reported: an absent claim keeps the old behaviour, an `unlimited` grant
/// or a reached spend control still has something true to say, and a positive
/// balance is never hidden even when the two signals disagree.
pub(in crate::agent_status) fn codex_credits_do_not_apply(
    has_credits_claim: Option<bool>,
    unlimited: Option<bool>,
    remaining: Option<CreditAmount>,
    spend_control_reached: Option<bool>,
) -> bool {
    has_credits_claim == Some(false)
        && unlimited != Some(true)
        && spend_control_reached != Some(true)
        && remaining.map_or(true, CreditAmount::is_zero)
}

pub(in crate::agent_status) fn codex_credit_balance_status(
    remaining: Option<CreditAmount>,
    unlimited: Option<bool>,
    has_credits: bool,
) -> AgentCreditBalanceStatus {
    if unlimited == Some(true) {
        AgentCreditBalanceStatus::Unlimited
    } else if remaining.is_some_and(CreditAmount::is_zero) {
        AgentCreditBalanceStatus::Exhausted
    } else if remaining.is_some_and(|value| value <= CODEX_LOW_CREDITS) {
        AgentCreditBalanceStatus::Low
    } else if remaining.is_some() || has_credits {
        AgentCreditBalanceStatus::Ok
    } else {
        AgentCreditBalanceStatus::Unknown
    }
}

pub(in crate::agent_status) fn codex_usage_window_key(
    limit_id: &str,
    window_key: &str,
    window_seconds: Option<u64>,
    has_reset: bool,
) -> String {
    let semantic = match window_seconds {
        Some(18_000) => "five_hour".to_string(),
        Some(604_800) => "weekly".to_string(),
        Some(seconds) if seconds % 60 == 0 => format!("unknown_{}m", seconds / 60),
        Some(seconds) => format!("unknown_{seconds}s"),
        None => "unknown_duration".to_string(),
    };
    let reset_semantic = if has_reset {
        "reset_known"
    } else {
        "reset_unknown"
    };
    format!(
        "{}_{}_{}_{}",
        codex_bucket_component(limit_id),
        codex_bucket_component(window_key),
        semantic,
        reset_semantic
    )
}

/// Reversibly encode one provider bucket-key component. Underscore is reserved
/// as the escape marker and separator, so unlike lossy punctuation replacement
/// this cannot make two distinct provider identifiers share one emitted name.
pub(in crate::agent_status) fn codex_bucket_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "_{byte:02x}");
        }
    }
    encoded
}
