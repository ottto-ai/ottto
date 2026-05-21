use ottto_protocol::RedactedValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionPolicy {
    pub policy_version: u16,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self { policy_version: 1 }
    }
}

pub fn redact_key_value(key: &str, value: &str) -> RedactedValue {
    if is_secret_key(key) {
        RedactedValue::String("[REDACTED]".to_string())
    } else if is_local_path_key(key) {
        RedactedValue::String("[path]".to_string())
    } else if is_machine_identifier_key(key) {
        RedactedValue::String("[machine_id]".to_string())
    } else if is_account_identifier_key(key) {
        RedactedValue::String("[account_id]".to_string())
    } else if is_raw_prompt_key(key) {
        RedactedValue::String("[prompt]".to_string())
    } else {
        RedactedValue::String(redact_inline(value))
    }
}

pub fn redact_inline(input: &str) -> String {
    let mut redacted = Vec::new();
    let mut prompt_tail_redacted = false;

    for token in input.split_whitespace() {
        if prompt_tail_redacted {
            continue;
        }

        if looks_like_secret(token) {
            redacted.push("[REDACTED]".to_string());
        } else if looks_like_local_path(token) {
            redacted.push("[path]".to_string());
        } else if looks_like_machine_identifier(token) {
            redacted.push("[machine_id]".to_string());
        } else if looks_like_account_identifier(token) {
            redacted.push("[account_id]".to_string());
        } else if looks_like_raw_prompt_assignment(token) {
            redacted.push("[prompt]".to_string());
            prompt_tail_redacted = true;
        } else {
            redacted.push(token.to_string());
        }
    }

    redacted.join(" ")
}

fn is_secret_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "authorization",
        "api_key",
        "apikey",
        "bearer",
        "client_secret",
        "cookie",
        "otel_exporter_otlp_headers",
        "password",
        "refresh_token",
        "secret",
        "token",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn is_local_path_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized.contains("path")
        || normalized == "file"
        || normalized.ends_with("_file")
        || normalized.contains("file_path")
}

fn is_account_identifier_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized.contains("account_id")
        || normalized.contains("organization_id")
        || normalized == "account"
        || normalized == "organization"
        || normalized == "user_id"
}

fn is_machine_identifier_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized == "machine_id" || normalized == "installation_id"
}

fn is_raw_prompt_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized.contains("raw_prompt")
        || normalized.contains("user_prompt")
        || normalized == "prompt"
        || normalized.ends_with("_prompt")
}

fn looks_like_secret(token: &str) -> bool {
    let normalized = trimmed_token(token);

    let lower = normalized.to_ascii_lowercase();
    lower.starts_with("bearer=")
        || lower.starts_with("authorization=")
        || lower.starts_with("api_key=")
        || lower.starts_with("x-api-key=")
        || lower.starts_with("token=")
        || lower.starts_with("setup_run_token=")
        || lower.starts_with("claim_token=")
        || lower.starts_with("ingest_key=")
        || lower.starts_with("sk-")
        || lower.starts_with("ottto_")
        || (normalized.len() >= 32 && normalized.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn looks_like_local_path(token: &str) -> bool {
    let normalized = trimmed_token(token);
    let value = token_value(normalized);
    let lower = value.to_ascii_lowercase();
    lower.starts_with("/users/")
        || lower.starts_with("/home/")
        || lower.starts_with("/private/")
        || lower.starts_with("~/")
        || lower.starts_with("file:/")
        || lower.starts_with("c:\\users\\")
}

fn looks_like_account_identifier(token: &str) -> bool {
    let normalized = trimmed_token(token);
    let lower = token_value(normalized).to_ascii_lowercase();
    let prefixes = ["acct_", "org_", "user_"];
    prefixes.iter().any(|prefix| {
        lower
            .strip_prefix(prefix)
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(id_char))
    })
}

fn looks_like_machine_identifier(token: &str) -> bool {
    let normalized = trimmed_token(token);
    let lower = token_value(normalized).to_ascii_lowercase();
    let prefixes = ["machine_", "install_"];
    prefixes.iter().any(|prefix| {
        lower
            .strip_prefix(prefix)
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(id_char))
    })
}

fn looks_like_raw_prompt_assignment(token: &str) -> bool {
    let normalized = trimmed_token(token).to_ascii_lowercase();
    normalized.starts_with("prompt=")
        || normalized.starts_with("raw_prompt=")
        || normalized.starts_with("user_prompt=")
}

fn token_value(token: &str) -> &str {
    token
        .split_once('=')
        .map(|(_, value)| value)
        .unwrap_or(token)
}

fn trimmed_token(token: &str) -> &str {
    token.trim_matches(|ch: char| {
        matches!(
            ch,
            '"' | '\'' | ',' | ';' | ')' | '(' | '[' | ']' | '{' | '}'
        )
    })
}

fn id_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secret_keys() {
        assert_eq!(
            redact_key_value("api_key", "ottto_live_secret"),
            RedactedValue::String("[REDACTED]".to_string())
        );
    }

    #[test]
    fn redacts_secret_like_inline_tokens() {
        assert_eq!(
            redact_inline("header bearer=ottto_live_secret endpoint ok"),
            "header [REDACTED] endpoint ok"
        );
    }

    #[test]
    fn preserves_plain_text() {
        assert_eq!(
            redact_inline("codex config path exists"),
            "codex config path exists"
        );
    }

    #[test]
    fn redacts_paths_account_ids_and_raw_prompt_inline() {
        let redacted = redact_inline(
            "failed path=/Users/ron/.codex/config.toml account=org_123 raw_prompt=explain my code",
        );

        assert_eq!(redacted, "failed [path] [account_id] [prompt]");
        assert!(!redacted.contains("/Users/ron"));
        assert!(!redacted.contains("org_123"));
        assert!(!redacted.contains("explain my code"));
    }

    #[test]
    fn redacts_sensitive_key_families() {
        assert_eq!(
            redact_key_value("machine_id", "machine_123"),
            RedactedValue::String("[machine_id]".to_string())
        );
        assert_eq!(
            redact_key_value("config_path", "/Users/ron/.codex/config.toml"),
            RedactedValue::String("[path]".to_string())
        );
        assert_eq!(
            redact_key_value("raw_prompt", "summarize private repo"),
            RedactedValue::String("[prompt]".to_string())
        );
    }
}
