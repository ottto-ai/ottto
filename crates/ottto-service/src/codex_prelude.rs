//! Codex request-1 prelude: the developer and user blocks Codex injects
//! before the first model request (AGENTS.md chain, skills listing, deferred
//! tool namespaces, permissions, environment, hooks, the prompt).
//!
//! One parser for both readers of that prelude: the snapshot pass
//! (`SnapshotItem.session_start`) and the Codex session-start footprint. Codex
//! labels every injected block in
//! `internal_chat_message_metadata_passthrough.content_item_kinds`
//! (`agents_md.instructions`, `host_skills.instructions`, ...). A message
//! without matching labels is not classified; no text-prefix guessing.

use serde_json::Value;

pub(crate) const AGENTS_MD_KIND: &str = "agents_md.instructions";
pub(crate) const HOST_SKILLS_KIND: &str = "host_skills.instructions";
pub(crate) const DEFERRED_NAMESPACES_KIND: &str = "tools.deferred_namespaces";
/// The developer copy of `session_meta.base_instructions`; count one of them.
pub(crate) const BASE_INSTRUCTIONS_KIND: &str = "model.base_instructions";

/// `(kind, block)` for each content block of one prelude message, or `None`
/// when the client did not label the message's blocks one-to-one.
pub(crate) fn labeled_blocks(payload: &Value) -> Option<impl Iterator<Item = (&str, &Value)>> {
    let blocks = payload.get("content")?.as_array()?;
    let kinds = payload
        .get("internal_chat_message_metadata_passthrough")?
        .get("content_item_kinds")?
        .as_array()?;
    (kinds.len() == blocks.len()).then(|| {
        kinds
            .iter()
            .zip(blocks)
            .map(|(kind, block)| (kind.as_str().unwrap_or(""), block))
    })
}

/// `session_meta.payload.base_instructions` text (a string or `{text}`).
pub(crate) fn base_instructions_text(meta: &Value) -> Option<&str> {
    match meta.get("base_instructions")? {
        Value::String(text) => Some(text),
        value => value.get("text")?.as_str(),
    }
}

/// The loaded instruction text of `# AGENTS.md instructions for <dir>\n\n<INSTRUCTIONS>\n...\n</INSTRUCTIONS>`.
pub(crate) fn agents_md_instructions(text: &str) -> &str {
    unwrap_tag(text, "INSTRUCTIONS")
}

pub(crate) fn unwrap_tag<'a>(text: &'a str, tag: &str) -> &'a str {
    let open = format!("<{tag}>\n");
    let close = format!("\n</{tag}>");
    match (text.find(&open), text.rfind(&close)) {
        (Some(start), Some(end)) if start + open.len() <= end => &text[start + open.len()..end],
        _ => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn labels_pair_one_to_one_or_not_at_all() {
        let labeled = json!({"content": [{"text": "a"}, {"text": "b"}],
            "internal_chat_message_metadata_passthrough": {"content_item_kinds": [AGENTS_MD_KIND, "user.text"]}});
        let kinds = labeled_blocks(&labeled)
            .expect("labeled")
            .map(|(kind, _)| kind)
            .collect::<Vec<_>>();
        assert_eq!(kinds, [AGENTS_MD_KIND, "user.text"]);
        let mismatched = json!({"content": [{"text": "a"}],
            "internal_chat_message_metadata_passthrough": {"content_item_kinds": []}});
        assert!(labeled_blocks(&mismatched).is_none());
        assert!(labeled_blocks(&json!({"content": [{"text": "a"}]})).is_none());
        assert_eq!(
            agents_md_instructions(
                "# AGENTS.md instructions for /r\n\n<INSTRUCTIONS>\nbody\n</INSTRUCTIONS>"
            ),
            "body"
        );
    }
}
