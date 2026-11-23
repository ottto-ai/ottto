//! Display-safe metadata parsing and shared status projections.
//! Called by the agent-status collectors and their sibling modules.
//! Owns JSON field extraction, redaction, and unsupported-value builders.

use crate::agent_status::fs;
use crate::agent_status::AgentAccountStatus;
use crate::agent_status::AgentCapabilityGap;
use crate::agent_status::AgentCapabilityStatus;
use crate::agent_status::AgentContextCompleteness;
use crate::agent_status::AgentContextState;
use crate::agent_status::AgentContextStatus;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentQuotaWindow;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentQuotaWindowScope;
use crate::agent_status::AgentQuotaWindowStatus;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::BTreeSet;
use crate::agent_status::CommandOutput;
use crate::agent_status::Deserialize;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Path;
use crate::agent_status::Rfc3339;
use crate::agent_status::TimeDuration;
use crate::agent_status::Value;
#[cfg(test)]
use crate::agent_status::CLAUDE_DESKTOP_JSON_READ_RECEIPT;

pub(super) fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    #[cfg(test)]
    CLAUDE_DESKTOP_JSON_READ_RECEIPT.with(|receipt| {
        let (attempts, bytes) = receipt.get();
        receipt.set((attempts + 1, bytes));
    });
    let body = fs::read_to_string(path).ok()?;
    #[cfg(test)]
    CLAUDE_DESKTOP_JSON_READ_RECEIPT.with(|receipt| {
        let (attempts, bytes) = receipt.get();
        receipt.set((attempts, bytes + body.len() as u64));
    });
    serde_json::from_str(&body).ok()
}

pub(super) fn looks_like_local_json_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with("local_") && name.ends_with(".json")
}

pub(super) fn safe_local_identifier(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        Some(value)
    } else {
        None
    }
}

pub(super) fn first_non_empty<'a>(
    values: impl IntoIterator<Item = Option<&'a str>>,
) -> Option<&'a str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

pub(super) fn safe_display_label(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty()
        || value.len() > 255
        || value.contains('/')
        || value.contains('\\')
        || value.to_ascii_lowercase().contains("token")
        || value.to_ascii_lowercase().contains("secret")
    {
        return None;
    }
    Some(value.to_string())
}

pub(super) fn timestamp_value_epoch_seconds(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(seconds) = value.as_i64() {
        return Some(normalize_unix_epoch_seconds(seconds));
    }
    if let Some(seconds) = value.as_u64().and_then(|value| i64::try_from(value).ok()) {
        return Some(normalize_unix_epoch_seconds(seconds));
    }
    if let Some(seconds) = value.as_f64() {
        if seconds.is_finite() {
            return Some(normalize_unix_epoch_seconds(seconds.round() as i64));
        }
    }
    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(seconds) = text.parse::<i64>() {
        return Some(normalize_unix_epoch_seconds(seconds));
    }
    if let Ok(seconds) = text.parse::<f64>() {
        if seconds.is_finite() {
            return Some(normalize_unix_epoch_seconds(seconds.round() as i64));
        }
    }
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(|value| value.unix_timestamp())
}

pub(super) fn normalize_unix_epoch_seconds(mut value: i64) -> i64 {
    // Claude Desktop currently stores JavaScript millisecond epochs, while
    // older fixtures and some builds use seconds. Reduce higher-precision
    // integer epochs until they are in the Unix-seconds range.
    while value.unsigned_abs() >= 10_000_000_000 {
        value /= 1_000;
    }
    value
}

pub(super) fn file_modified_epoch_seconds(path: &Path) -> Option<i64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let duration = modified
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()?;
    i64::try_from(duration.as_secs()).ok()
}

pub(super) fn current_unix_seconds() -> u64 {
    crate::scan_clock::utc_seconds()
}

pub(super) fn rfc3339_from_unix_seconds(seconds: u64) -> Option<String> {
    let timestamp = i64::try_from(seconds).ok()?;
    OffsetDateTime::from_unix_timestamp(timestamp)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

pub(super) fn percent_quota_status(used_percent: u8) -> AgentQuotaWindowStatus {
    if used_percent >= 100 {
        AgentQuotaWindowStatus::Exhausted
    } else if used_percent >= 90 {
        AgentQuotaWindowStatus::NearLimit
    } else {
        AgentQuotaWindowStatus::Ok
    }
}

pub(super) fn command_output_text(output: &CommandOutput) -> String {
    match (
        output.stdout.trim().is_empty(),
        output.stderr.trim().is_empty(),
    ) {
        (true, true) => String::new(),
        (false, true) => output.stdout.clone(),
        (true, false) => output.stderr.clone(),
        (false, false) => format!("{}\n{}", output.stdout, output.stderr),
    }
}

pub(super) fn parse_yes_no(value: &str) -> Option<bool> {
    match value {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

pub(super) fn collect_model_names_from_json(value: &Value, models: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if matches!(key.as_str(), "id" | "model" | "name" | "slug") {
                    if let Some(model) =
                        nested.as_str().filter(|value| looks_like_model_name(value))
                    {
                        models.insert(model.to_string());
                    }
                }
                collect_model_names_from_json(nested, models);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_model_names_from_json(item, models);
            }
        }
        Value::String(value) if looks_like_model_name(value) => {
            models.insert(value.clone());
        }
        _ => {}
    }
}

pub(super) fn looks_like_model_name(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 2 || value.len() > 128 || value.contains('/') || value.contains('\\') {
        return false;
    }
    if is_codex_automatic_review_model_label(value) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    lower.contains("gpt")
        || lower.contains("claude")
        || lower.contains("gemini")
        || lower.contains("o3")
        || lower.contains("o4")
        || lower.contains("o5")
        || lower.contains("model")
}

pub(super) fn is_codex_automatic_review_model_label(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let tokens = lower
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    tokens.contains(&"automatic")
        && tokens.contains(&"approval")
        && tokens.contains(&"review")
        && tokens.contains(&"codex")
}

pub(super) fn looks_like_safe_model_id(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 2 || value.len() > 128 || value.contains('\\') {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    !lower.contains("/users/")
        && !lower.contains("/home/")
        && !lower.contains("/.codex")
        && !lower.contains("/.claude")
        && !lower.contains("/.pi/")
}

pub(super) fn strip_secret_json(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter_map(|(key, nested)| {
                    let lower = key.to_ascii_lowercase();
                    if lower.contains("token")
                        || lower.contains("secret")
                        || lower.contains("password")
                        || lower.contains("key")
                        || lower.contains("cookie")
                    {
                        None
                    } else {
                        Some((key, strip_secret_json(nested)))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(strip_secret_json).collect()),
        other => other,
    }
}

pub(super) fn first_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(nested) = map.get(*key) {
                    match nested {
                        Value::String(value) if !value.trim().is_empty() => {
                            return Some(value.trim().to_string())
                        }
                        Value::Bool(value) => return Some(value.to_string()),
                        Value::Number(value) => return Some(value.to_string()),
                        _ => {}
                    }
                }
            }
            for nested in map.values() {
                if let Some(value) = first_json_string(nested, keys) {
                    return Some(value);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(|item| first_json_string(item, keys)),
        _ => None,
    }
}

pub(super) fn json_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        let Some(nested) = value.get(*key) else {
            continue;
        };
        if let Some(number) = nested.as_u64() {
            return Some(number);
        }
        if let Some(number) = nested.as_i64().and_then(|value| u64::try_from(value).ok()) {
            return Some(number);
        }
        if let Some(number) = nested.as_f64() {
            if number.is_finite() && number >= 0.0 {
                return Some(number.round() as u64);
            }
        }
        if let Some(text) = nested.as_str() {
            if let Ok(number) = text.trim().parse::<u64>() {
                return Some(number);
            }
            if let Ok(number) = text.trim().parse::<f64>() {
                if number.is_finite() && number >= 0.0 {
                    return Some(number.round() as u64);
                }
            }
        }
    }
    None
}

pub(super) fn json_u8(value: &Value, keys: &[&str]) -> Option<u8> {
    json_u64(value, keys).map(|value| value.min(100) as u8)
}

pub(super) fn json_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    for key in keys {
        let Some(nested) = value.get(*key) else {
            continue;
        };
        if let Some(boolean) = nested.as_bool() {
            return Some(boolean);
        }
        if let Some(text) = nested.as_str() {
            match text.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => return Some(true),
                "false" | "0" | "no" => return Some(false),
                _ => {}
            }
        }
    }
    None
}

pub(super) fn rfc3339_minus_seconds(timestamp: &str, seconds: u64) -> Option<String> {
    let parsed = OffsetDateTime::parse(timestamp, &Rfc3339).ok()?;
    let duration = TimeDuration::seconds(i64::try_from(seconds).ok()?);
    (parsed - duration).format(&Rfc3339).ok()
}

pub(super) fn json_timestamp_rfc3339(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        let Some(nested) = value.get(*key) else {
            continue;
        };
        if let Some(text) = nested
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if let Ok(parsed) = OffsetDateTime::parse(text, &Rfc3339) {
                return parsed.format(&Rfc3339).ok();
            }
            if let Ok(seconds) = text.parse::<i64>() {
                return OffsetDateTime::from_unix_timestamp(seconds)
                    .ok()
                    .and_then(|value| value.format(&Rfc3339).ok());
            }
            if let Ok(seconds) = text.parse::<f64>() {
                if seconds.is_finite() {
                    return OffsetDateTime::from_unix_timestamp(seconds.round() as i64)
                        .ok()
                        .and_then(|value| value.format(&Rfc3339).ok());
                }
            }
        }
        if let Some(seconds) = nested.as_i64() {
            return OffsetDateTime::from_unix_timestamp(seconds)
                .ok()
                .and_then(|value| value.format(&Rfc3339).ok());
        }
        if let Some(seconds) = nested.as_u64().and_then(|value| i64::try_from(value).ok()) {
            return OffsetDateTime::from_unix_timestamp(seconds)
                .ok()
                .and_then(|value| value.format(&Rfc3339).ok());
        }
        if let Some(seconds) = nested.as_f64() {
            if seconds.is_finite() {
                return OffsetDateTime::from_unix_timestamp(seconds.round() as i64)
                    .ok()
                    .and_then(|value| value.format(&Rfc3339).ok());
            }
        }
    }
    None
}

pub(super) fn nested_json_string(
    value: &Value,
    object_keys: &[&str],
    value_keys: &[&str],
) -> Option<String> {
    let Value::Object(map) = value else {
        return None;
    };
    for key in object_keys {
        if let Some(nested) = map.get(*key) {
            if let Some(value) = first_json_string(nested, value_keys) {
                return Some(value);
            }
        }
    }
    None
}

pub(super) fn unsupported_account(provider: &str) -> AgentAccountStatus {
    AgentAccountStatus {
        login_state: AgentLoginState::Unsupported,
        provider: Some(provider.to_string()),
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
        account_identifier_hash: None,
        organization_identifier_hash: None,
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::Unknown,
        confidence: AgentStatusConfidence::Unknown,
    }
}

pub(super) fn unsupported_quota_window(name: &str) -> AgentQuotaWindow {
    AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Source,
        status: AgentQuotaWindowStatus::Unsupported,
        freshness: AgentQuotaWindowFreshness::Unsupported,
        model: None,
        account_label: None,
        window_seconds: None,
        started_at: None,
        resets_at: None,
        quota: None,
        remaining: None,
        used_percent: None,
        left_percent: None,
        ..Default::default()
    }
}

pub(super) fn unsupported_context(
    source: &str,
    reason: &str,
    observed_at: Option<String>,
) -> AgentContextStatus {
    AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some(source.to_string()),
        recent_samples: Vec::new(),
        observed_at,
        completeness: Some(AgentContextCompleteness::Unavailable),
        reason: Some(reason.to_string()),
        posture: None,
    }
}

pub(super) fn supported_capability(capability: &str, detail: &str) -> AgentCapabilityGap {
    AgentCapabilityGap {
        capability: capability.to_string(),
        status: AgentCapabilityStatus::Supported,
        detail: Some(detail.to_string()),
    }
}

pub(super) fn unsupported_capability(capability: &str, detail: &str) -> AgentCapabilityGap {
    AgentCapabilityGap {
        capability: capability.to_string(),
        status: AgentCapabilityStatus::Unsupported,
        detail: Some(detail.to_string()),
    }
}

pub(super) fn command_diagnostic(
    code: &str,
    message: &str,
    output: &CommandOutput,
) -> AgentStatusDiagnostic {
    let status = output
        .status_code
        .map(|code| format!(" exit {code}"))
        .unwrap_or_default();
    let stderr_hint = if output.stderr.trim().is_empty() {
        String::new()
    } else {
        " stderr redacted".to_string()
    };
    AgentStatusDiagnostic::source(
        code,
        AgentDiagnosticSeverity::Warning,
        format!("{message}{status}.{stderr_hint}"),
    )
}

pub(super) fn extract_email(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|token| {
            token.trim_matches(|c: char| {
                c == '<' || c == '>' || c == ',' || c == ';' || c == ':' || c == '"' || c == '\''
            })
        })
        .find(|token| {
            let parts: Vec<&str> = token.split('@').collect();
            parts.len() == 2
                && !parts[0].is_empty()
                && parts[1].contains('.')
                && !token.contains('/')
        })
        .map(ToString::to_string)
}

pub(super) fn extract_plan_type(text: &str, candidates: &[&str]) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    candidates
        .iter()
        .find(|candidate| lower.contains(**candidate))
        .map(|candidate| candidate.to_string())
}

#[cfg(test)]
pub(super) fn extract_percent_before(text: &str, markers: &[&str]) -> Option<u8> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let mut start = index;
            while start > 0 && bytes[start - 1].is_ascii_digit() {
                start -= 1;
            }
            if start < index {
                if let Ok(value) = text[start..index].parse::<u8>() {
                    let context_start = start.saturating_sub(24);
                    let context_end = (index + 24).min(text.len());
                    let context = &text[context_start..context_end];
                    if markers.iter().any(|marker| context.contains(marker)) {
                        return Some(value.min(100));
                    }
                }
            }
        }
        index += 1;
    }
    None
}
