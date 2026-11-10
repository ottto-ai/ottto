//! Agent display labels: the sanitizer for provider-supplied labels and its length limit.

/// Hard cap for a subagent display label (workflow `label` or Task
/// `description`). Longer values are truncated, not rejected: the leading
/// characters of a title-shaped value are still a useful title, and the cap is
/// what keeps a pathological description from smuggling prompt content.
pub(in crate::snapshots) const MAX_CLAUDE_AGENT_LABEL_CHARS: usize = 80;

/// Sanitize a provider-supplied subagent display label.
///
/// Unlike `safe_attribution_token` (identifiers only), a label is short human
/// text: whitespace is collapsed, then the value must pass a conservative
/// printable-ASCII allowlist — anything with control characters, non-ASCII, or
/// separator-smuggling backslashes is dropped rather than repaired. Values are
/// truncated to `MAX_CLAUDE_AGENT_LABEL_CHARS`, and anything that still looks
/// like a path escapes the allowlist via the same forbidden fragments the
/// attribution tokens use.
pub(in crate::snapshots) fn safe_claude_agent_display_label(value: String) -> Option<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | '.'
                    | ','
                    | ':'
                    | ';'
                    | '_'
                    | '-'
                    | '+'
                    | '#'
                    | '('
                    | ')'
                    | '\''
                    | '&'
                    | '/'
                    | '?'
                    | '!'
            )
    }) {
        return None;
    }
    let truncated: String = normalized
        .chars()
        .take(MAX_CLAUDE_AGENT_LABEL_CHARS)
        .collect();
    let lowered = truncated.to_ascii_lowercase();
    if crate::session_attribution::ATTRIBUTION_FORBIDDEN_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
        || lowered.contains("/users/")
        || lowered.contains("/home/")
    {
        return None;
    }
    Some(truncated)
}
