//! Session display titles: normalization of explicit and first-prompt titles,
//! and the filters that keep identifiers, commands and setup text out of them.

use crate::snapshots::first_prompt_title;
use crate::snapshots::scan::source_session_id::codex_identity_is_uuid_shaped;
use crate::snapshots::wire::SnapshotSource;

pub(in crate::snapshots) fn normalize_title(value: String) -> Option<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.chars().take(255).collect())
    }
}

pub(in crate::snapshots) fn normalize_display_title(value: String, source: &str) -> Option<String> {
    let normalized = normalize_title(value)?;
    if is_safe_display_title(&normalized, source) {
        Some(normalized)
    } else {
        None
    }
}

pub(crate) fn claude_registration_display_title(value: String) -> Option<String> {
    normalize_display_title(value, "custom_title")
}

/// A Codex prompt-prefix label is already a bounded prefix, so it takes the
/// shared first-prompt rule without the full-prompt role rewrite and size gate.
pub(crate) fn prompt_prefix_display_title(value: String) -> Option<String> {
    first_prompt_title(SnapshotSource::Codex, &value, false)
}

pub(in crate::snapshots) fn agent_role_prompt_display_title(raw: &str) -> Option<String> {
    let first_line = raw.lines().find_map(|line| {
        let trimmed = line.trim();
        (!trimmed.is_empty()).then_some(trimmed)
    })?;
    let lowered = first_line.to_ascii_lowercase();
    let mut role = lowered.strip_prefix("you are ")?;
    role = role
        .strip_prefix("the ")
        .or_else(|| role.strip_prefix("an "))
        .or_else(|| role.strip_prefix("a "))
        .unwrap_or(role);

    let role_end = [" agent", " worker", " orchestrator"]
        .into_iter()
        .filter_map(|suffix| {
            role.match_indices(suffix).find_map(|(index, _)| {
                let end = index + suffix.len();
                let boundary = role[end..].chars().next();
                (boundary.is_none()
                    || boundary.is_some_and(|character| {
                        character.is_whitespace()
                            || matches!(character, '.' | ',' | ':' | ';' | '(' | ')' | '—' | '–')
                    }))
                .then_some(end)
            })
        })
        .min()?;
    let role = role[..role_end].trim();
    let word_count = role.split_whitespace().count();
    if !(2..=8).contains(&word_count)
        || role.chars().count() > 64
        || role.contains(['/', '\\', '<', '>', '{', '}', '@'])
    {
        return None;
    }

    let mut words = role
        .split_whitespace()
        .map(|word| match word {
            "ai" | "api" | "ci" | "mcp" | "pr" | "qa" | "ui" => word.to_ascii_uppercase(),
            _ => word.to_string(),
        })
        .collect::<Vec<_>>();
    let first = words.first_mut()?;
    if !matches!(
        first.as_str(),
        "AI" | "API" | "CI" | "MCP" | "PR" | "QA" | "UI"
    ) {
        let mut chars = first.chars();
        let initial = chars.next()?.to_uppercase().collect::<String>();
        *first = initial + chars.as_str();
    }
    normalize_display_title(words.join(" "), "first_prompt")
}

pub(in crate::snapshots) fn claude_custom_title_display_title(value: String) -> Option<String> {
    let normalized = normalize_title(value)?;
    let lowered = normalized.to_ascii_lowercase();
    if let Some(rest) = lowered.strip_prefix("pr-fixer-") {
        let pr_number = rest.split('-').next()?;
        if !pr_number.is_empty() && pr_number.chars().all(|ch| ch.is_ascii_digit()) {
            return Some(format!("Fix PR #{pr_number}"));
        }
    }
    normalize_display_title(normalized, "custom_title")
}

fn is_safe_display_title(value: &str, source: &str) -> bool {
    let char_count = value.chars().count();
    if char_count == 0 || char_count > 120 {
        return false;
    }
    let lowered = value.to_ascii_lowercase();
    if matches!(
        lowered.as_str(),
        "assistant"
            | "chat"
            | "codex"
            | "codex session"
            | "conversation"
            | "new chat"
            | "new session"
            | "session"
            | "untitled"
            | "untitled session"
    ) {
        return false;
    }
    if is_codex_tool_call_name(&lowered)
        || looks_like_raw_identifier(value, source)
        || looks_like_shell_command(&lowered)
        || looks_like_setup_text(&lowered)
        || contains_blocked_prompt_fragment(value)
    {
        return false;
    }
    if source == "first_prompt"
        && lowered.len() <= 8
        && matches!(
            lowered.as_str(),
            "fix" | "fix it" | "help" | "help me" | "question"
        )
    {
        return false;
    }
    true
}

pub(in crate::snapshots) fn contains_blocked_prompt_fragment(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("<instructions>")
        || lowered.contains("<environment_context>")
        || lowered.contains("agents.md instructions")
        || lowered.contains("a previous agent produced the plan below")
        || (lowered.contains("## summary") && lowered.contains("## test plan"))
        || lowered.contains("knowledge cutoff:")
        || lowered.contains("current date:")
}

pub(in crate::snapshots) fn looks_like_resume_boilerplate(lowered: &str) -> bool {
    let stripped = lowered
        .strip_prefix("continue ")
        .map(str::trim_start)
        .and_then(|value| value.strip_prefix("the ").or(Some(value)))
        .map(|value| value.trim_start_matches(['"', '\'']));
    stripped.is_some_and(|value| value.starts_with("same "))
}

fn looks_like_setup_text(lowered: &str) -> bool {
    lowered.starts_with("you are ")
        || lowered.starts_with("system:")
        || lowered.starts_with("developer:")
        || lowered.starts_with("assistant:")
        || lowered.starts_with("tool:")
        || lowered.starts_with("environment_context")
        || lowered.starts_with("<environment_context")
        || lowered.starts_with("<instructions")
}

fn looks_like_shell_command(lowered: &str) -> bool {
    const COMMAND_PREFIXES: &[&str] = &[
        "$ ", "cargo ", "cat ", "cd ", "curl ", "docker ", "gcloud ", "git ", "jq ", "kubectl ",
        "ls ", "npm ", "pnpm ", "python ", "python3 ", "rg ", "sed ", "sqlite3 ", "uv ", "wt ",
        "yarn ",
    ];
    COMMAND_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
}

fn is_codex_tool_call_name(lowered: &str) -> bool {
    const TOOL_NAMES: &[&str] = &[
        "apply_patch",
        "close_agent",
        "create_goal",
        "exec_command",
        "find",
        "get_goal",
        "imagegen",
        "list_mcp_resource_templates",
        "list_mcp_resources",
        "open",
        "parallel",
        "read_mcp_resource",
        "request_user_input",
        "resume_agent",
        "screenshot",
        "send_input",
        "spawn_agent",
        "tool_search_tool",
        "update_goal",
        "update_plan",
        "view_image",
        "wait_agent",
        "weather",
        "write_stdin",
    ];
    const TOOL_PREFIXES: &[&str] = &[
        "functions.",
        "image_gen.",
        "multi_tool_use.",
        "tool_search.",
        "web.",
    ];
    TOOL_NAMES.contains(&lowered)
        || TOOL_PREFIXES
            .iter()
            .any(|prefix| lowered.starts_with(prefix))
}

fn looks_like_raw_identifier(value: &str, source: &str) -> bool {
    let trimmed = value.trim();
    if codex_identity_is_uuid_shaped(trimmed) {
        return true;
    }
    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("rollout-") && (source == "custom_title" || lowered.len() >= 44) {
        return true;
    }
    if lowered.starts_with("session_") || lowered.starts_with("sess_") {
        return true;
    }
    let has_space = trimmed.chars().any(char::is_whitespace);
    let ascii_token = trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':'));
    let has_digit = trimmed.chars().any(|ch| ch.is_ascii_digit());
    if source == "custom_title" {
        // Explicit names may be dated word slugs. Keep known credential shapes
        // blocked even when their opaque suffix happens to contain no digits.
        if lowered.starts_with("ghp_")
            || lowered.starts_with("sk-ant-")
            || (matches!(trimmed.len(), 32 | 40 | 64)
                && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return true;
        }
        if !has_space && ascii_token && has_digit && trimmed.len() >= 24 {
            let segments = trimmed.split(['-', '_', ':']).collect::<Vec<_>>();
            return segments.len() < 2
                || !segments.iter().any(|segment| {
                    segment.len() >= 3 && segment.bytes().all(|byte| byte.is_ascii_alphabetic())
                })
                || segments.iter().any(|segment| {
                    segment.len() > 16 && segment.bytes().any(|byte| byte.is_ascii_digit())
                });
        }
        return false;
    }
    !has_space && ascii_token && has_digit && trimmed.len() >= 24
}
