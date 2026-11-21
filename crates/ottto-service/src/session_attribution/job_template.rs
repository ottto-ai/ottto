//! Frozen v1 normalization. Changing these rules requires a new domain/version.
use super::*;
use regex::Regex;

pub(crate) const MAX_BYTES: usize = 64 * 1024;

/// Leading, balanced injected envelopes only. A literal mention later in a
/// task is content. Malformed envelopes fail closed; empty ones stay pending.
pub(crate) fn task(raw: &str) -> Result<Option<&str>, &'static str> {
    if raw.len() > MAX_BYTES {
        return Err("oversize");
    }
    let mut text = raw.trim_start();
    loop {
        let lower = text.to_ascii_lowercase();
        let envelope = if let Some(rest) = lower.strip_prefix("# agents.md instructions") {
            if !(rest.is_empty() || rest.starts_with(char::is_whitespace)) {
                break;
            }
            let start = lower.find("<instructions>").ok_or("malformed_wrapper")?;
            Some(("<instructions>", "</instructions>", start))
        } else {
            [
                "environment_context",
                "recommended_plugins",
                "system_instruction",
            ]
            .into_iter()
            .find_map(|tag| {
                let open = format!("<{tag}>");
                lower.starts_with(&open).then_some((tag, 0))
            })
            .map(|(tag, start)| match tag {
                "environment_context" => ("<environment_context>", "</environment_context>", start),
                "recommended_plugins" => ("<recommended_plugins>", "</recommended_plugins>", start),
                _ => ("<system_instruction>", "</system_instruction>", start),
            })
        };
        let Some((open, close, start)) = envelope else {
            break;
        };
        // Match nesting too, rather than accepting the first closing tag.
        let mut depth = 1;
        let mut at = start + open.len();
        while depth != 0 {
            let end = lower[at..].find(close).ok_or("malformed_wrapper")? + at;
            if let Some(next) = lower[at..end].find(open) {
                depth += 1;
                at += next + open.len();
            } else {
                depth -= 1;
                at = end + close.len();
            }
        }
        text = text[at..].trim_start();
    }
    let lower = text.to_ascii_lowercase();
    if text.is_empty()
        || [
            "this session is being continued from a previous conversation",
            "<artifact-content-authored-by-others",
            "[request interrupted",
            "<command-",
            "<local-command",
            "<system-reminder",
            "<task-notification",
            "<tool_result",
        ]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return Ok(None);
    }
    // A recognized envelope opener with broken syntax must never become a task.
    if [
        "<environment_context",
        "<recommended_plugins",
        "<system_instruction",
    ]
    .iter()
    .any(|p| lower.starts_with(p))
    {
        return Err("malformed_wrapper");
    }
    Ok(Some(text))
}

/// Unicode regex word boundaries; case-sensitive masks precede Unicode
/// lowercase. Whitespace words retain punctuation. Reserved placeholders do
/// not count toward the eight-word evidence floor, even when typed literally.
pub(crate) fn material(task: &str) -> Option<String> {
    static MASKS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let masks = MASKS.get_or_init(|| [
        (r"https?://\S+", " <url> "),
        (r"[\w.+-]+@[\w-]+\.[\w.]+", " <email> "),
        (r"(?:~|\.{1,2})?/(?:[\w.@%+-]+/)*[\w.@%+-]*", " <path> "),
        (r"\b[\w-]+\.(?:md|py|rs|ts|tsx|js|json|jsonl|yml|yaml|toml|sh|sql|html|txt|log|csv|swift|plist)\b", " <file> "),
        (r"`[^`\n]{1,200}`", " <code> "),
        (r#""[^"\n]{1,200}"|“[^”\n]{1,200}”"#, " <quoted> "),
        (r"\b[0-9a-f]{7,}\b", " <hex> "),
        (r"\b\d{1,2}:\d{2}(?::\d{2})?\b", " <time> "),
        (r"\b\w*\d\w*\b", " <n> "),
    ].into_iter().map(|(p,r)| (Regex::new(p).expect("constant regex"), r)).collect());
    let mut masked = task.to_owned();
    for (rx, replacement) in masks {
        masked = rx.replace_all(&masked, *replacement).into_owned();
    }
    let masked = masked.to_lowercase();
    let words: Vec<_> = masked.split_whitespace().collect();
    let placeholders = [
        "<url>", "<email>", "<path>", "<file>", "<code>", "<quoted>", "<hex>", "<time>", "<n>",
    ];
    if words
        .iter()
        .filter(|w| !placeholders.contains(w) && w.chars().any(char::is_alphabetic))
        .count()
        < 8
    {
        return None;
    }
    Some(format!(
        "{}\0{}",
        words.iter().take(30).copied().collect::<Vec<_>>().join(" "),
        words[words.len().saturating_sub(60)..].join(" ")
    ))
}

impl SessionAttributionContext {
    pub(crate) fn job_fact(
        &self,
        stored: Option<&(Option<String>, String)>,
        session: &str,
        observed: &str,
    ) -> Option<SessionAttributionFact> {
        let (id, epoch) = stored?;
        let id = id.as_deref()?;
        if epoch != &self.checkpoint_namespace() {
            return None;
        }
        let mut facts = Vec::new();
        push_fact(
            &mut facts,
            "job_template_id",
            id,
            "local_template",
            "inferred",
            &EvidenceContext {
                source_session_id: session,
                observed_at: observed,
                source_version: "job_template:v1",
            },
        );
        facts.pop()
    }
}

#[cfg(test)]
pub(crate) fn context(key: u8) -> SessionAttributionContext {
    SessionAttributionContext {
        key: Zeroizing::new(vec![key; 32]),
        provider_schedules: ProviderScheduleInventory::default(),
        external_schedulers: Default::default(),
        launch_events: Default::default(),
    }
}
