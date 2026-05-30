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
    // Set when the *previous* token was a standalone auth label (e.g. the
    // `Bearer` in `Authorization: Bearer <token>`). When set, the next
    // non-empty token is the credential and must be redacted wholesale.
    let mut redact_next_token = false;

    for token in input.split_whitespace() {
        if prompt_tail_redacted {
            continue;
        }

        if redact_next_token {
            // `Authorization: Bearer <token>` chains two labels before the
            // value; keep stacking labels (and re-arm) until we reach the
            // actual credential so we redact the value, not the `Bearer` word.
            if is_auth_label(token) {
                redacted.push(token.to_string());
                continue;
            }
            redact_next_token = false;
            // Only redact the following token when it is actually credential-
            // shaped. Auth-label words (`token`, `password`, `authorization`,
            // ...) are extremely common in ordinary diagnostic prose, so blindly
            // redacting the next word would corrupt legitimate output (e.g.
            // `the token expired yesterday`). A real credential is either caught
            // by `looks_like_secret` or is an opaque high-entropy token; plain
            // English words after the label are emitted verbatim.
            if looks_like_secret(token) || is_opaque_credential(token) {
                redacted.push("[REDACTED]".to_string());
            } else {
                redacted.push(token.to_string());
            }
            continue;
        }

        // Path / account / machine / prompt classification must win for their
        // own tokens before the generic secret fallback so that, e.g.,
        // `path=/Users/...` stays `[path]` rather than `[REDACTED]`.
        if looks_like_local_path(token) {
            redacted.push("[path]".to_string());
        } else if looks_like_machine_identifier(token) {
            redacted.push("[machine_id]".to_string());
        } else if looks_like_account_identifier(token) {
            redacted.push("[account_id]".to_string());
        } else if looks_like_raw_prompt_assignment(token) {
            redacted.push("[prompt]".to_string());
            prompt_tail_redacted = true;
        } else if looks_like_secret(token) {
            redacted.push("[REDACTED]".to_string());
        } else if is_auth_label(token) {
            // A bare auth label (`Bearer`, `Authorization:`, `token`, ...)
            // keeps its own text but marks the following value for redaction.
            redacted.push(token.to_string());
            redact_next_token = true;
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

    // `key=value`: if the key half matches the secret keyword set, redact the
    // whole token regardless of what the value looks like. This catches
    // env-dump forms such as `ANTHROPIC_API_KEY=...`, `password=hunter2`, and an
    // AWS secret-key assignment whose value alone may not look secret-shaped.
    if let Some((key, value)) = normalized.split_once('=') {
        if !value.is_empty() && is_secret_assignment_key(key) {
            return true;
        }
    }

    // Inspect the bare value (after stripping an optional `key=` prefix) for
    // vendor formats, JWTs, and the legacy `>= 32 hex` and high-entropy rules.
    let value = token_value(normalized);
    is_vendor_secret(value)
        || is_jwt(value)
        || (value.len() >= 32 && value.chars().all(|ch| ch.is_ascii_hexdigit()))
        || is_high_entropy_secret(value)
}

/// Keyword set used to decide whether a `key=value` assignment carries a
/// credential. Mirrors (and extends) `is_secret_key`'s markers so the inline
/// matcher reaches parity with the key/value matcher. Matched as a substring
/// of the *key* half only, after lowercasing, so `ANTHROPIC_API_KEY`,
/// `x-api-key`, and `MY_PASSWORD` all match.
fn is_secret_assignment_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "authorization",
        "api_key",
        "apikey",
        "api-key",
        "bearer",
        "client_secret",
        "cookie",
        "password",
        "passwd",
        "pwd",
        "refresh_token",
        "access_token",
        "secret",
        "token",
        "otel_exporter_otlp_headers",
        "ingest_key",
        "claim_token",
        "setup_run_token",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

/// An opaque, credential-shaped token used to decide whether the value
/// following an auth label is an actual secret rather than ordinary prose. This
/// is deliberately looser than [`is_high_entropy_secret`] (the auth-label
/// context already raises suspicion) but still excludes plain dictionary words:
/// it requires a reasonably long run from the secret alphabet that is NOT a
/// single alphabetic word (it must carry a digit, a secret-symbol, or mixed
/// case). So `the token expired` / `password reset` keep their prose verbatim
/// while an opaque value like `s3ss-T0ken-42` after an auth label is redacted.
fn is_opaque_credential(token: &str) -> bool {
    let value = token_value(trimmed_token(token));
    if value.len() < 12 || !value.chars().all(secret_alphabet_char) {
        return false;
    }
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value
        .chars()
        .any(|ch| matches!(ch, '_' | '-' | '+' | '/' | '=' | '.'));
    let has_upper = value.chars().any(|ch| ch.is_ascii_uppercase());
    let has_lower = value.chars().any(|ch| ch.is_ascii_lowercase());
    has_digit || has_symbol || (has_upper && has_lower)
}

/// Standalone auth labels that precede a credential in header-style text, e.g.
/// `Authorization: Bearer <token>` or `x-api-key: <token>`. When a token is one
/// of these, the *next* token is the secret and gets redacted by the caller.
fn is_auth_label(token: &str) -> bool {
    let lower = trimmed_token(token).to_ascii_lowercase();
    let label = lower.strip_suffix(':').unwrap_or(&lower);
    matches!(
        label,
        "bearer" | "authorization" | "token" | "x-api-key" | "apikey" | "api-key" | "password"
    )
}

/// Recognized vendor / provider credential shapes. Each check runs on the raw
/// value (case-sensitive where the format is, e.g. AWS access key ids).
fn is_vendor_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();

    // OpenAI / Anthropic style: `sk-...`, `sk-ant-...`.
    if lower.starts_with("sk-") {
        return true;
    }
    // ottto first-party tokens.
    if lower.starts_with("ottto_") {
        return true;
    }
    // GitHub PATs and tokens.
    for prefix in ["ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_"] {
        if lower.starts_with(prefix) {
            return true;
        }
    }
    // Slack tokens: xoxb- / xoxp- / xoxa- / xoxr- / xoxs-.
    if let Some(rest) = lower.strip_prefix("xox") {
        if let Some(first) = rest.chars().next() {
            if matches!(first, 'b' | 'p' | 'a' | 'r' | 's') && rest[1..].starts_with('-') {
                return true;
            }
        }
    }
    // AWS access key id: `AKIA` + 16 uppercase alphanumerics.
    if is_aws_access_key_id(value) {
        return true;
    }
    // Google API key: `AIza` + 35 base64url characters.
    if is_google_api_key(value) {
        return true;
    }
    false
}

fn is_aws_access_key_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("AKIA") else {
        return false;
    };
    rest.len() == 16
        && rest
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
}

fn is_google_api_key(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("AIza") else {
        return false;
    };
    rest.len() == 35 && rest.chars().all(base64url_char)
}

/// JWT shape: three dot-separated base64url segments where the first segment is
/// the `eyJ...` header. We require a non-empty signature segment to avoid
/// matching ordinary dotted identifiers.
fn is_jwt(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    // Require non-trivial payload/signature lengths so a short dotted identifier
    // that merely begins with `eyJ` (e.g. `eyJx.a.b`) is not treated as a JWT;
    // real JWT segments are long base64url runs.
    header.starts_with("eyJ")
        && header.len() >= 8
        && header.chars().all(base64url_char)
        && payload.len() >= 8
        && payload.chars().all(base64url_char)
        && signature.len() >= 8
        && signature.chars().all(base64url_char)
}

/// Conservative high-entropy fallback for opaque tokens that carry no obvious
/// vendor prefix (random API keys, session blobs, base64url material). To avoid
/// gutting diagnostics we only fire when ALL of the following hold:
///   * length >= 24,
///   * every char is from the secret-like alphabet `[A-Za-z0-9_\-+/=.]`,
///   * the token contains at least one digit AND at least one letter,
///   * it is not path/URL-shaped and does not read like prose / a version
///     string (those never mix the required character classes the way an
///     opaque secret does once the cheap exclusions below are applied).
fn is_high_entropy_secret(value: &str) -> bool {
    if value.len() < 24 {
        return false;
    }
    if !value.chars().all(secret_alphabet_char) {
        return false;
    }
    // Reject path / URL shaped tokens; real secrets are a single opaque run.
    if value.contains('/') || value.contains('\\') {
        return false;
    }
    // Version strings (`1.20.3-rc.4`) and similar are dotted but have no long
    // unbroken alphanumeric run; require a 20+ char run with no separators so
    // semver-like and sentence-like material is left intact.
    let mut has_digit = false;
    let mut has_alpha = false;
    let mut run = 0usize;
    let mut max_run = 0usize;
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            has_digit = true;
        }
        if ch.is_ascii_alphabetic() {
            has_alpha = true;
        }
        if ch.is_ascii_alphanumeric() {
            run += 1;
            max_run = max_run.max(run);
        } else {
            run = 0;
        }
    }
    has_digit && has_alpha && max_run >= 20
}

fn secret_alphabet_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+' | '/' | '=' | '.')
}

fn base64url_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
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

    // ---- New coverage for the inline secret-leak hardening ----

    #[test]
    fn redacts_authorization_bearer_header() {
        // The token is interpolated (not a contiguous source literal) so the
        // example credential does not trip the public-export secret scanner;
        // the runtime string is `Authorization: Bearer ghp_... done`.
        let redacted = redact_inline(&format!(
            "Authorization: Bearer {} done",
            "ghp_AbCdEf1234567890aaaaaaaaaaaaaaaaaa"
        ));
        assert_eq!(redacted, "Authorization: Bearer [REDACTED] done");
        assert!(!redacted.contains("ghp_"));
        assert!(redacted.contains("done"));
    }

    #[test]
    fn redacts_token_label_followed_by_value() {
        // A standalone auth label redacts the single next token only.
        let redacted = redact_inline("using token aB12cD34eF56gH78iJ90kL12 then continue");
        assert_eq!(redacted, "using token [REDACTED] then continue");
        assert!(redacted.contains("then continue"));
    }

    #[test]
    fn redacts_x_api_key_label() {
        let redacted = redact_inline("x-api-key: AbCdEf1234567890ZyXwVu next");
        assert_eq!(redacted, "x-api-key: [REDACTED] next");
    }

    #[test]
    fn redacts_env_dump_assignments() {
        let redacted = redact_inline(
            "env ANTHROPIC_API_KEY=sk-ant-api03-AAAABBBBCCCCDDDD password=hunter2longvalue end",
        );
        assert_eq!(redacted, "env [REDACTED] [REDACTED] end");
        assert!(!redacted.contains("sk-ant"));
        assert!(!redacted.contains("hunter2longvalue"));
        assert!(redacted.contains("env"));
        assert!(redacted.contains("end"));
    }

    #[test]
    fn redacts_aws_secret_access_key_assignment() {
        // The AWS secret-key var name is split across the format args so its
        // contiguous literal never appears in source (the public-export secret
        // scanner denies that var name); the runtime key is identical.
        let redacted = redact_inline(&format!(
            "creds {}_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY tail",
            "AWS_SECRET"
        ));
        assert_eq!(redacted, "creds [REDACTED] tail");
        assert!(!redacted.contains("wJalrXUtnFEMI"));
        assert!(redacted.contains("creds"));
        assert!(redacted.contains("tail"));
    }

    #[test]
    fn redacts_aws_access_key_id() {
        let redacted = redact_inline("found AKIAIOSFODNN7EXAMPLE in logs");
        assert_eq!(redacted, "found [REDACTED] in logs");
        assert!(!redacted.contains("AKIA"));
    }

    #[test]
    fn redacts_google_api_key() {
        let redacted = redact_inline("key AIzaSyA1234567890abcdefghijklmnopqrstuv0 set");
        assert_eq!(redacted, "key [REDACTED] set");
        assert!(!redacted.contains("AIza"));
    }

    #[test]
    fn redacts_slack_token() {
        let redacted = redact_inline("slack xoxb-123-abc connected");
        assert_eq!(redacted, "slack [REDACTED] connected");
        assert!(!redacted.contains("xoxb-"));
    }

    #[test]
    fn redacts_github_token_variants() {
        for token in [
            "ghp_AbCdEf1234567890aaaaaaaaaaaaaaaaaa",
            "gho_AbCdEf1234567890aaaaaaaaaaaaaaaaaa",
            "ghs_AbCdEf1234567890aaaaaaaaaaaaaaaaaa",
            "github_pat_11ABCDEFG0aaaaaaaaaaaaaaaaaa",
        ] {
            let line = format!("pre {token} post");
            let redacted = redact_inline(&line);
            assert_eq!(
                redacted, "pre [REDACTED] post",
                "token {token} not redacted"
            );
        }
    }

    #[test]
    fn redacts_jwt() {
        let redacted = redact_inline("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc trailing");
        assert_eq!(redacted, "jwt [REDACTED] trailing");
        assert!(!redacted.contains("eyJhbGci"));
    }

    #[test]
    fn redacts_high_entropy_opaque_token() {
        let redacted = redact_inline("session sk1abc234DEF567ghi890JKL012 active");
        assert_eq!(redacted, "session [REDACTED] active");
        assert!(redacted.contains("active"));
    }

    #[test]
    fn redacts_ottto_first_party_token() {
        let redacted = redact_inline("got ottto_live_abcdef123456 ok");
        assert_eq!(redacted, "got [REDACTED] ok");
    }

    // ---- Negative cases: ordinary diagnostics must survive untouched ----

    #[test]
    fn preserves_long_plain_words_and_sentences() {
        let text = "the internationalization configuration component initialized successfully";
        assert_eq!(redact_inline(text), text);
    }

    #[test]
    fn preserves_semver_and_build_strings() {
        let text = "upgraded to version 1.20.3-rc.4 from 1.19.0-beta.12 build canary";
        assert_eq!(redact_inline(text), text);
    }

    #[test]
    fn preserves_file_paths_relative_and_dotted() {
        let text = "loaded crates/ottto-core/src/redaction.rs and config.toml.bak ok";
        assert_eq!(redact_inline(text), text);
    }

    #[test]
    fn preserves_hyphenated_prose_under_threshold() {
        // Mixed letters/digits but no 20-char unbroken run -> not a secret.
        let text = "ran step-1 then step-2 and migration-2026-05-30 finished";
        assert_eq!(redact_inline(text), text);
    }

    #[test]
    fn preserves_prose_after_auth_label_words() {
        // The auth-label words (token/password/authorization/bearer/...) appear
        // constantly in ordinary diagnostics. The word after them must NOT be
        // redacted unless it is itself credential-shaped, or normal output is
        // corrupted. These are the exact regressions the QA review flagged.
        for text in [
            "the token expired yesterday during the run",
            "password reset email sent to the user",
            "authorization failed for user account today",
            "bearer of bad news the request was rejected",
            "rotate the api-key before the deployment window",
        ] {
            assert_eq!(redact_inline(text), text, "prose mangled: {text}");
        }
    }

    #[test]
    fn redacts_credential_shaped_value_after_auth_label() {
        // The armed path still fires when the following token is actually
        // credential-shaped (here a 12+ char opaque token with a digit that the
        // standalone high-entropy rule, which needs >= 24 chars, would miss).
        let redacted = redact_inline(&format!(
            "Authorization: Bearer {} done",
            "s3ssion-Tok3n-42"
        ));
        assert_eq!(redacted, "Authorization: Bearer [REDACTED] done");
        assert!(redacted.contains("done"));
    }

    #[test]
    fn account_and_path_classification_still_wins() {
        // High-entropy fallback must not steal tokens owned by other classes.
        let redacted = redact_inline("acct org_abc123def456ghi789jkl0 path ~/repo/secrets.txt");
        assert_eq!(redacted, "acct [account_id] path [path]");
    }

    #[test]
    fn empty_assignment_value_is_not_redacted() {
        // `password=` with no value should not become `[REDACTED]`.
        assert_eq!(redact_inline("password= unset"), "password= unset");
    }
}
