//! Claude status oauth cache operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::claude_credit_pools;
use crate::agent_status::claude_oauth_account_state_lock;
use crate::agent_status::claude_oauth_usage_cache_path;
use crate::agent_status::claude_oauth_usage_legacy_breaker_path;
use crate::agent_status::claude_oauth_usage_legacy_cache_path;
use crate::agent_status::claude_oauth_usage_serve_gate_seconds;
use crate::agent_status::compiled_release_version;
use crate::agent_status::credit_amount_input;
use crate::agent_status::fs;
use crate::agent_status::json_timestamp_rfc3339;
use crate::agent_status::json_u8;
use crate::agent_status::percent_quota_status;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::rfc3339_minus_seconds;
use crate::agent_status::unsupported_capability;
use crate::agent_status::write_owner_only_file_atomic_if_changed;
use crate::agent_status::AgentCapabilityGap;
use crate::agent_status::AgentCapabilityStatus;
use crate::agent_status::AgentCreditBalance;
use crate::agent_status::AgentCreditBalanceStatus;
use crate::agent_status::AgentCreditBalanceUnit;
use crate::agent_status::AgentQuotaWindow;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentQuotaWindowScope;
use crate::agent_status::AgentQuotaWindowStatus;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::ClaudeOAuthUsage;
use crate::agent_status::ClaudeOAuthUsageCache;
use crate::agent_status::CreditAmount;
use crate::agent_status::Mutex;
use crate::agent_status::Value;
use crate::agent_status::CLAUDE_ACCOUNT_SESSION_NOT_OFFERED_CAPABILITY;
use crate::agent_status::CLAUDE_ACCOUNT_WEEKLY_NOT_OFFERED_CAPABILITY;
use crate::agent_status::CLAUDE_OAUTH_LEGACY_MIGRATION_LOCK;
use crate::agent_status::CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION;
use crate::agent_status::CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION;
use crate::agent_status::CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS;

#[cfg(test)]
pub(in crate::agent_status) fn read_claude_oauth_usage_cache(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Option<ClaudeOAuthUsageCache> {
    read_claude_oauth_usage_cache_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        true,
    )
}

pub(in crate::agent_status) fn read_claude_oauth_usage_cache_with_legacy_migration(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    legacy_root_migration: bool,
) -> Option<ClaudeOAuthUsageCache> {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    read_claude_oauth_usage_cache_locked(
        account_identifier_hash,
        organization_identifier_hash,
        legacy_root_migration,
    )
}

pub(in crate::agent_status) fn read_claude_oauth_usage_cache_locked(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    legacy_root_migration: bool,
) -> Option<ClaudeOAuthUsageCache> {
    if legacy_root_migration {
        static CLEANUP: std::sync::Once = std::sync::Once::new();
        migrate_and_clean_up_legacy_claude_oauth_usage_locked(
            account_identifier_hash,
            organization_identifier_hash,
            &CLEANUP,
        );
    }
    let path = claude_oauth_usage_cache_path(account_identifier_hash, organization_identifier_hash);
    let body = fs::read_to_string(path).ok()?;
    let cache: ClaudeOAuthUsageCache = serde_json::from_str(&body).ok()?;
    if cache.schema_version != CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION {
        // Older cache layouts (v1: windows only; v2: no account identity) are
        // discarded so the next tick refetches under a known account.
        return None;
    }
    if !claude_oauth_usage_cache_belongs_to_identity(
        &cache,
        account_identifier_hash,
        organization_identifier_hash,
    ) {
        return None;
    }
    Some(cache)
}

/// Whether a cached OAuth usage payload may be served for the exact account
/// and organization that currently own the credential.
///
/// Exact match, both directions. Account-only matches and caches whose embedded
/// meters are unattributed or differently attributed are rejected. Empty
/// v4 caches may retain per-identity retry timing, but cannot produce a row.
pub(in crate::agent_status) fn claude_oauth_usage_cache_belongs_to_identity(
    cache: &ClaudeOAuthUsageCache,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> bool {
    cache.account_identifier_hash == account_identifier_hash
        && cache.organization_identifier_hash == organization_identifier_hash
        && !account_identifier_hash.is_empty()
        && !organization_identifier_hash.is_empty()
        && cache.windows.iter().all(|window| {
            window.account_identifier_hash.as_deref() == Some(account_identifier_hash)
                && window.organization_identifier_hash.as_deref()
                    == Some(organization_identifier_hash)
        })
        && cache.credit_balances.iter().all(|balance| {
            balance.account_identifier_hash.as_deref() == Some(account_identifier_hash)
                && balance.organization_identifier_hash.as_deref()
                    == Some(organization_identifier_hash)
        })
}

pub(in crate::agent_status) fn write_claude_oauth_usage_cache(
    cache: &ClaudeOAuthUsageCache,
) -> std::io::Result<()> {
    let lock = claude_oauth_account_state_lock(
        &cache.account_identifier_hash,
        &cache.organization_identifier_hash,
    );
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    write_claude_oauth_usage_cache_locked(cache)
}

pub(in crate::agent_status) fn write_claude_oauth_usage_cache_locked(
    cache: &ClaudeOAuthUsageCache,
) -> std::io::Result<()> {
    let path = claude_oauth_usage_cache_path(
        &cache.account_identifier_hash,
        &cache.organization_identifier_hash,
    );
    let body = serde_json::to_vec_pretty(cache).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic_if_changed(&path, &body)
}

pub(in crate::agent_status) fn migrate_and_clean_up_legacy_claude_oauth_usage_locked(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    cleanup: &std::sync::Once,
) {
    let _migration = CLAUDE_OAUTH_LEGACY_MIGRATION_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    migrate_legacy_claude_oauth_usage_cache_locked(
        account_identifier_hash,
        organization_identifier_hash,
    );
    // Old-release leftover cleanup; remove in the first release after 2026-12-31.
    // Try once after the cache decoder has had its chance, under the same lock.
    // Missing files and all other removal errors must not fail the caller.
    cleanup.call_once(|| {
        let _ = fs::remove_file(claude_oauth_usage_legacy_cache_path());
        let _ = fs::remove_file(claude_oauth_usage_legacy_breaker_path());
    });
}

// Old-release root-cache migration; remove in the first release after 2026-12-31.
// Caller holds the account-state and legacy-migration locks.
pub(in crate::agent_status) fn migrate_legacy_claude_oauth_usage_cache_locked(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) {
    let target =
        claude_oauth_usage_cache_path(account_identifier_hash, organization_identifier_hash);
    if target.exists() {
        return;
    }
    let legacy = claude_oauth_usage_legacy_cache_path();
    let Some(mut cache) = fs::read_to_string(&legacy)
        .ok()
        .and_then(|body| serde_json::from_str::<ClaudeOAuthUsageCache>(&body).ok())
        .filter(|cache| {
            matches!(
                cache.schema_version,
                CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION
                    | CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION
            ) && !cache.windows.is_empty()
                && claude_oauth_usage_cache_belongs_to_identity(
                    cache,
                    account_identifier_hash,
                    organization_identifier_hash,
                )
        })
    else {
        return;
    };
    cache.schema_version = CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION;
    if write_claude_oauth_usage_cache_locked(&cache).is_ok() {
        let _ = fs::remove_file(legacy);
    }
}

pub(in crate::agent_status) fn claude_oauth_retry_after_epoch_seconds(
    response: &ureq::Response,
    now: u64,
) -> u64 {
    response
        .header("retry-after")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS)
        .saturating_add(now)
}

pub(crate) fn ottto_user_agent() -> String {
    // Honest identification: Ottto reads the user's own aggregate usage and
    // says so. Never present a claude-* client identity from an
    // Ottto-originated request (recorded provider-endpoints posture,
    // 2026-07-26). Shared by every Ottto-originated provider read, so one
    // identity change moves them all together.
    // compiled_release_version(), not CARGO_PKG_VERSION: the
    // crate manifest carries the 0.1.0 placeholder and real release versions
    // are injected via OTTTO_RELEASE_VERSION at package time.
    format!(
        "ottto/{} (subscription-usage-reader; +https://ottto.net)",
        compiled_release_version()
    )
}

pub(in crate::agent_status) fn claude_oauth_quota_windows(value: &Value) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    if let Some(window) = claude_oauth_quota_window("session", value.get("five_hour"), 5 * 60 * 60)
    {
        windows.push(window);
    }
    if let Some(window) =
        claude_oauth_quota_window("weekly", value.get("seven_day"), 7 * 24 * 60 * 60)
    {
        windows.push(window);
    }
    windows.extend(claude_oauth_scoped_limit_windows(value));
    windows
}

/// Whether the body says the account has no account-wide weekly limit (some
/// Team plans): `seven_day` is present and null, and `limits[]` lists no
/// account-wide weekly entry. A missing key or a missing `limits[]` proves
/// nothing, so the weekly window stays expected.
pub(in crate::agent_status) fn claude_oauth_account_weekly_not_offered(value: &Value) -> bool {
    let Some(limits) = value.get("limits").and_then(Value::as_array) else {
        return false;
    };
    value.get("seven_day").is_some_and(Value::is_null)
        && !limits.is_empty()
        && !limits.iter().any(|entry| {
            let account_scoped = entry
                .get("scope")
                .and_then(|scope| scope.get("model"))
                .map_or(true, Value::is_null);
            entry.get("kind").and_then(Value::as_str) == Some("weekly_all")
                || account_scoped && entry.get("group").and_then(Value::as_str) == Some("weekly")
        })
}

/// Whether the body says the account has no 5-hour session limit (Max plans
/// since late 2026): `five_hour` is present and null, and `limits[]` lists no
/// account-wide session entry. A missing key or a missing `limits[]` proves
/// nothing, so the session window stays expected.
pub(in crate::agent_status) fn claude_oauth_account_session_not_offered(value: &Value) -> bool {
    let Some(limits) = value.get("limits").and_then(Value::as_array) else {
        return false;
    };
    value.get("five_hour").is_some_and(Value::is_null)
        && !limits.is_empty()
        && !limits.iter().any(|entry| {
            let account_scoped = entry
                .get("scope")
                .and_then(|scope| scope.get("model"))
                .map_or(true, Value::is_null);
            account_scoped
                && (entry.get("kind").and_then(Value::as_str) == Some("session")
                    || entry.get("group").and_then(Value::as_str) == Some("session"))
        })
}

pub(in crate::agent_status) fn claude_account_weekly_not_offered_capability() -> AgentCapabilityGap
{
    unsupported_capability(
        CLAUDE_ACCOUNT_WEEKLY_NOT_OFFERED_CAPABILITY,
        "Claude reports no account-wide weekly limit for this account.",
    )
}

pub(in crate::agent_status) fn claude_snapshot_account_weekly_not_offered(
    snapshot: &AgentStatusSnapshot,
) -> bool {
    claude_snapshot_capability_unsupported(snapshot, CLAUDE_ACCOUNT_WEEKLY_NOT_OFFERED_CAPABILITY)
}

pub(in crate::agent_status) fn claude_account_session_not_offered_capability() -> AgentCapabilityGap
{
    unsupported_capability(
        CLAUDE_ACCOUNT_SESSION_NOT_OFFERED_CAPABILITY,
        "Claude reports no 5-hour session limit for this account.",
    )
}

pub(in crate::agent_status) fn claude_snapshot_account_session_not_offered(
    snapshot: &AgentStatusSnapshot,
) -> bool {
    claude_snapshot_capability_unsupported(snapshot, CLAUDE_ACCOUNT_SESSION_NOT_OFFERED_CAPABILITY)
}

pub(in crate::agent_status) fn claude_snapshot_capability_unsupported(
    snapshot: &AgentStatusSnapshot,
    name: &str,
) -> bool {
    snapshot.capabilities.iter().any(|capability| {
        capability.capability == name && capability.status == AgentCapabilityStatus::Unsupported
    })
}

pub(in crate::agent_status) fn claude_snapshot_has_account_windows(
    snapshot: &AgentStatusSnapshot,
) -> bool {
    claude_has_account_windows(
        &snapshot.quota_windows,
        claude_snapshot_account_weekly_not_offered(snapshot),
        claude_snapshot_account_session_not_offered(snapshot),
    )
}

pub(in crate::agent_status) fn fresh_quota_windows(
    windows: &[AgentQuotaWindow],
) -> Vec<AgentQuotaWindow> {
    windows
        .iter()
        .filter(|window| window.freshness == AgentQuotaWindowFreshness::Fresh)
        .cloned()
        .collect()
}

/// Every account-wide window the account has: the session and weekly windows,
/// minus any Claude said the account does not have, and at least one of them.
pub(in crate::agent_status) fn claude_has_account_windows(
    windows: &[AgentQuotaWindow],
    account_weekly_not_offered: bool,
    account_session_not_offered: bool,
) -> bool {
    let has = |name: &str| {
        windows
            .iter()
            .any(|window| window.scope == AgentQuotaWindowScope::Account && window.name == name)
    };
    (has("session") || has("weekly"))
        && (account_session_not_offered || has("session"))
        && (account_weekly_not_offered || has("weekly"))
}

/// Per-model scoped limits from the `limits[]` array (e.g. `weekly_scoped`
/// for one model at 98% while the account-level `seven_day` shows 82%).
/// Entries without a model scope duplicate `five_hour`/`seven_day` account
/// windows (`session`, `weekly_all`) and are skipped.
pub(in crate::agent_status) fn claude_oauth_scoped_limit_windows(
    value: &Value,
) -> Vec<AgentQuotaWindow> {
    let Some(limits) = value.get("limits").and_then(Value::as_array) else {
        return Vec::new();
    };
    limits
        .iter()
        .filter_map(|entry| {
            let model = entry
                .get("scope")
                .and_then(|scope| scope.get("model"))
                .and_then(|model| {
                    model
                        .get("display_name")
                        .or_else(|| model.get("id"))
                        .and_then(Value::as_str)
                })
                .map(str::trim)
                .filter(|name| !name.is_empty())?;
            let used_percent = json_u8(entry, &["percent"]);
            let resets_at = json_timestamp_rfc3339(entry, &["resets_at", "reset_at"]);
            if used_percent.is_none() && resets_at.is_none() {
                return None;
            }
            let name = entry
                .get("kind")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|kind| !kind.is_empty())
                .unwrap_or("scoped")
                .to_string();
            Some(AgentQuotaWindow {
                name,
                scope: AgentQuotaWindowScope::Model,
                status: used_percent
                    .map(percent_quota_status)
                    .unwrap_or(AgentQuotaWindowStatus::Unknown),
                freshness: AgentQuotaWindowFreshness::Fresh,
                model: Some(model.to_string()),
                resets_at,
                used_percent,
                left_percent: used_percent.map(|used| 100_u8.saturating_sub(used)),
                group: json_trimmed_string(entry, "group"),
                severity: json_trimmed_string(entry, "severity"),
                is_active: entry.get("is_active").and_then(Value::as_bool),
                ..Default::default()
            })
        })
        .collect()
}

/// Usage-credit balances from the OAuth usage response. The newer `spend`
/// object is authoritative; the older `extra_usage` shape is the fallback.
/// Disabled accounts emit nothing (no credit chrome downstream), and a missing
/// or unrecognized shape fails soft to an empty list so quota windows are
/// never hidden by credit parsing.
pub(in crate::agent_status) fn claude_oauth_credit_balances(
    value: &Value,
) -> Vec<AgentCreditBalance> {
    claude_oauth_credit_balances_and_refusals(value).0
}

/// The usage-credit balances plus the model's field refusals (a disabled
/// reason that is not a reason code), for the adapter's diagnostics.
pub(in crate::agent_status) fn claude_oauth_credit_balances_and_refusals(
    value: &Value,
) -> (
    Vec<AgentCreditBalance>,
    Vec<crate::quota_credit_model::CreditModelDiagnostic>,
) {
    let mut refusals = Vec::new();
    let balance =
        claude_oauth_spend_credit_balance(value.get("spend"), &mut refusals).or_else(|| {
            claude_oauth_extra_usage_credit_balance(value.get("extra_usage"), &mut refusals)
        });
    (balance.into_iter().collect(), refusals)
}

pub(in crate::agent_status) fn claude_oauth_spend_credit_balance(
    spend: Option<&Value>,
    refusals: &mut Vec<crate::quota_credit_model::CreditModelDiagnostic>,
) -> Option<AgentCreditBalance> {
    let spend = spend?;
    let enabled = spend.get("enabled").and_then(Value::as_bool)?;
    if !enabled {
        return Some(claude_credit_pools::claude_disabled_usage_credits(
            spend, refusals,
        ));
    }
    let used = claude_oauth_money_cents(spend.get("used"));
    let quota = claude_oauth_money_cents(spend.get("cap"))
        .or_else(|| claude_oauth_money_cents(spend.get("limit")));
    let remaining =
        claude_oauth_money_cents(spend.get("balance")).or_else(|| match (quota, used) {
            (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
            _ => None,
        });
    let used_percent = json_u8(spend, &["percent"]).or_else(|| match (used, quota) {
        (Some(used), Some(quota)) if quota > 0 => {
            Some(((used.saturating_mul(100)) / quota).min(100) as u8)
        }
        _ => None,
    });
    let severity = spend.get("severity").and_then(Value::as_str).unwrap_or("");
    Some(AgentCreditBalance {
        name: claude_credit_pools::CLAUDE_USAGE_CREDITS_NAME.to_string(),
        status: if used.is_none() && quota.is_none() && remaining.is_none() {
            AgentCreditBalanceStatus::Unknown
        } else {
            claude_oauth_credit_status(severity, used, quota, remaining)
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        remaining: remaining.and_then(CreditAmount::whole),
        used: used.and_then(CreditAmount::whole),
        quota: quota.and_then(CreditAmount::whole),
        currency: claude_oauth_money_currency(spend.get("used"))
            .or_else(|| json_trimmed_string(spend, "currency")),
        resets_at: json_timestamp_rfc3339(spend, &["resets_at", "reset_at"]),
        used_percent,
        enabled: Some(true),
        ..Default::default()
    })
}

pub(in crate::agent_status) fn claude_oauth_extra_usage_credit_balance(
    extra: Option<&Value>,
    refusals: &mut Vec<crate::quota_credit_model::CreditModelDiagnostic>,
) -> Option<AgentCreditBalance> {
    let extra = extra?;
    let enabled = extra.get("is_enabled").and_then(Value::as_bool)?;
    if !enabled {
        return Some(claude_credit_pools::claude_disabled_usage_credits(
            extra, refusals,
        ));
    }
    // Latent, deliberately untouched: real `extra_usage` bare numbers are minor
    // units (`monthly_limit 1000` beside `spend.limit.amount_minor 1000`,
    // `decimal_places: 2`), so this fallback would read them x100. It is never
    // reached on observed data: every plain body since July 2026 carries
    // `spend`, which wins above.
    let quota = claude_oauth_money_cents(extra.get("monthly_limit"));
    let used = claude_oauth_money_cents(extra.get("used_credits"));
    let remaining = match (quota, used) {
        (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
        _ => None,
    };
    // The client uses an explicitly null monthly_limit for unlimited usage;
    // an omitted or malformed limit remains unknown.
    let unlimited = extra.get("monthly_limit").is_some_and(Value::is_null);
    let used_percent = json_u8(extra, &["utilization"]);
    Some(AgentCreditBalance {
        name: claude_credit_pools::CLAUDE_USAGE_CREDITS_NAME.to_string(),
        status: if unlimited {
            AgentCreditBalanceStatus::Unlimited
        } else {
            claude_oauth_credit_status("", used, quota, remaining)
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        remaining: remaining
            .filter(|_| !unlimited)
            .and_then(CreditAmount::whole),
        used: used.and_then(CreditAmount::whole),
        quota: quota.and_then(CreditAmount::whole),
        currency: json_trimmed_string(extra, "currency"),
        resets_at: None,
        used_percent,
        enabled: Some(true),
        unlimited: unlimited.then_some(true),
        ..Default::default()
    })
}

pub(in crate::agent_status) fn claude_oauth_credit_status(
    severity: &str,
    used: Option<u64>,
    quota: Option<u64>,
    remaining: Option<u64>,
) -> AgentCreditBalanceStatus {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => return AgentCreditBalanceStatus::Exhausted,
        "warning" => return AgentCreditBalanceStatus::Low,
        "normal" => return AgentCreditBalanceStatus::Ok,
        _ => {}
    }
    match (used, quota, remaining) {
        (_, _, Some(0)) => AgentCreditBalanceStatus::Exhausted,
        (Some(used), Some(quota), _) if quota > 0 && used >= quota => {
            AgentCreditBalanceStatus::Exhausted
        }
        (Some(used), Some(quota), _) if quota > 0 && used.saturating_mul(10) >= quota * 9 => {
            AgentCreditBalanceStatus::Low
        }
        (Some(_), _, _) | (_, Some(_), _) => AgentCreditBalanceStatus::Ok,
        _ => AgentCreditBalanceStatus::Unknown,
    }
}

/// Normalize a provider money value to integer minor units (cents).
///
/// Accepts either the structured shape `{"amount_minor": 321, "currency":
/// "USD", "exponent": 2}` (exponent 0..=6) or a bare non-negative number of
/// whole dollars: an integer, or a decimal lexeme kept by the provider decode
/// ([`credit_amount_input::decode`]). Both scale through the one exact scaler,
/// rounding half-even; a float that bypassed that decode is refused.
pub(in crate::agent_status) fn claude_oauth_money_cents(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    if let Some(object) = value.as_object() {
        let amount_minor = object.get("amount_minor").and_then(Value::as_u64)?;
        let exponent = object.get("exponent").and_then(Value::as_u64).unwrap_or(2);
        if exponent > 6 {
            return None;
        }
        return ottto_protocol::scale_minor(amount_minor, 2 - exponent as i64);
    }
    credit_amount_input::scaled(value, 2)
}

pub(in crate::agent_status) fn claude_oauth_money_currency(
    value: Option<&Value>,
) -> Option<String> {
    value
        .and_then(Value::as_object)
        .and_then(|object| object.get("currency"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|currency| !currency.is_empty())
        .map(ToString::to_string)
}

pub(in crate::agent_status) fn json_trimmed_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
}

pub(in crate::agent_status) fn claude_oauth_quota_window(
    name: &str,
    value: Option<&Value>,
    window_seconds: u64,
) -> Option<AgentQuotaWindow> {
    let value = value?;
    let used_percent = json_u8(value, &["utilization", "used_percentage", "used_percent"]);
    let resets_at = json_timestamp_rfc3339(value, &["resets_at", "reset_at"]);
    if used_percent.is_none() && resets_at.is_none() {
        return None;
    }
    let left_percent = used_percent.map(|used| 100_u8.saturating_sub(used));
    let started_at = resets_at
        .as_deref()
        .and_then(|reset| rfc3339_minus_seconds(reset, window_seconds));
    Some(AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Account,
        status: used_percent
            .map(percent_quota_status)
            .unwrap_or(AgentQuotaWindowStatus::Unknown),
        freshness: AgentQuotaWindowFreshness::Fresh,
        model: None,
        account_label: None,
        window_seconds: Some(window_seconds),
        started_at_basis: started_at.as_ref().map(|_| "assumed_duration".to_string()),
        started_at,
        resets_at,
        quota: None,
        remaining: None,
        used_percent,
        left_percent,
        limit_cents: claude_oauth_money_cents(value.get("limit_dollars")),
        used_cents: claude_oauth_money_cents(value.get("used_dollars")),
        remaining_cents: claude_oauth_money_cents(value.get("remaining_dollars")),
        ..Default::default()
    })
}

pub(in crate::agent_status) fn claude_oauth_usage_from_cache(
    cache: ClaudeOAuthUsageCache,
    now: u64,
) -> ClaudeOAuthUsage {
    let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
    // The refresh slot, seeded from the account the cache belongs to: a
    // payload served as fresh must not be labelled stale. A shorter active
    // slot never labels a reading stale sooner than the default gate.
    let gate = claude_oauth_usage_serve_gate_seconds(
        &cache.account_identifier_hash,
        &cache.organization_identifier_hash,
        now,
    );
    let cache_is_stale = cache_age > gate;
    let observed_at = rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds);
    ClaudeOAuthUsage {
        windows: cache
            .windows
            .into_iter()
            .map(|mut window| {
                window.observed_at = observed_at.clone();
                if cache_is_stale {
                    window.status = AgentQuotaWindowStatus::Unknown;
                    window.freshness = AgentQuotaWindowFreshness::Stale;
                } else {
                    window.freshness = AgentQuotaWindowFreshness::Fresh;
                }
                window
            })
            .collect(),
        // Each credit section by its own read time: a newer windows or
        // passive read never relabels an older section Fresh.
        credit_balances: {
            let mut credits = cache.credit_balances;
            claude_credit_pools::label_credit_freshness(
                &mut credits,
                gate,
                cache.observed_at_epoch_seconds,
                now,
            );
            credits
        },
        account_weekly_not_offered: cache.account_weekly_not_offered,
        account_session_not_offered: cache.account_session_not_offered,
    }
}
