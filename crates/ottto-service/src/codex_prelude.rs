//! Codex request-1 prelude: what Codex injects before the first model request
//! (base instructions, the AGENTS.md chain, the skills listing, deferred tool
//! namespaces, permissions, environment, hooks, the prompt).
//!
//! [`CodexPreludeParser`] is the one Codex prelude parser (CROSS-LANE R1). It
//! takes rollout rows already decoded: the snapshot pass
//! (`SnapshotItem.session_start`) feeds it from its own line pass, and the
//! Codex prelude footprint feeds it through [`parse_prelude`] from a bounded
//! read of a new rollout. It holds no file, config or disk state.
//!
//! Codex labels every injected message block in
//! `internal_chat_message_metadata_passthrough.content_item_kinds`; a message
//! without one string label per block is not classified (no text-prefix
//! guessing). The loaded AGENTS.md text and skills listing come from the first
//! `world_state` (cli >= 0.159; older rollouts are not supported), not from
//! their rendered message copies.
//!
//! Sizes are UTF-16 code units; the backend owns the conversion to tokens.

use serde_json::Value;
use std::io::BufRead;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(crate) const AGENTS_MD_KIND: &str = "agents_md.instructions";
pub(crate) const HOST_SKILLS_KIND: &str = "host_skills.instructions";
pub(crate) const DEFERRED_NAMESPACES_KIND: &str = "tools.deferred_namespaces";
/// The developer copy of `session_meta.base_instructions`; count one of them.
pub(crate) const BASE_INSTRUCTIONS_KIND: &str = "model.base_instructions";

/// Rows [`parse_prelude`] reads at most.
#[cfg_attr(not(test), allow(dead_code))] // The footprint reader (ottto#599).
pub(crate) const MAX_PRELUDE_LINES: usize = 200;
/// Rows read past the first request while its context window is unknown.
const MAX_LINES_FOR_WINDOW: usize = 8;
/// Ids, paths and model names longer than this are treated as absent, so the
/// parser's retained size has a fixed bound beside the AGENTS.md cap.
pub(crate) const MAX_SMALL_TEXT_BYTES: usize = 1024;

/// What one labeled request-1 message block is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockKind {
    BaseInstructions,
    AgentsMd,
    Skills,
    DeferredTools,
    Hooks,
    /// Permissions, environment, collaboration mode, plugins and apps.
    Environment,
    Prompt,
    Other,
}
pub(crate) const BLOCK_KINDS: usize = 8;

impl BlockKind {
    pub(crate) fn of(label: &str) -> Self {
        match label {
            BASE_INSTRUCTIONS_KIND => Self::BaseInstructions,
            AGENTS_MD_KIND => Self::AgentsMd,
            HOST_SKILLS_KIND => Self::Skills,
            DEFERRED_NAMESPACES_KIND => Self::DeferredTools,
            label if label.starts_with("user.") => Self::Prompt,
            label if label.starts_with("hooks.") => Self::Hooks,
            label
                if [
                    "permissions.",
                    "environments.",
                    "collaboration_mode.",
                    "plugins.",
                    "apps.",
                ]
                .iter()
                .any(|prefix| label.starts_with(prefix)) =>
            {
                Self::Environment
            }
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LoadedAgentsMd {
    pub(crate) directory: Option<String>,
    pub(crate) text: String,
}

/// What one rollout loaded before its first model request.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct CodexPrelude {
    pub(crate) cwd: Option<String>,
    /// Session creation (unix seconds) from `session_meta.timestamp`. File
    /// mtime tracks later activity, so it cannot order session starts.
    pub(crate) started_at: Option<i64>,
    /// Same rule as the session sink's `codex_is_fork`: the session starts
    /// with a parent's context, so its prelude is not an owned fresh start.
    pub(crate) is_fork: bool,
    /// A first token record was seen, so the prelude is final.
    pub(crate) complete: bool,
    pub(crate) model: Option<String>,
    pub(crate) context_window: Option<u64>,
    pub(crate) first_input_tokens: Option<u64>,
    pub(crate) base_instructions_chars: u64,
    /// The rendered developer/user blocks of request 1, by kind.
    pub(crate) block_chars: [u64; BLOCK_KINDS],
    /// A request-1 message without one string label per block, or an image
    /// block: `block_chars` misses part of request 1.
    pub(crate) blocks_incomplete: bool,
    /// Request 1's input ended: the model answered, or its usage was logged.
    pub(crate) input_closed: bool,
    pub(crate) world_state_seen: bool,
    pub(crate) agents_md: Option<LoadedAgentsMd>,
    /// The AGENTS.md text was longer than the caller keeps; `agents_md` holds
    /// its prefix.
    pub(crate) agents_md_capped: bool,
    pub(crate) skills_body: Option<String>,
}

impl CodexPrelude {
    #[cfg_attr(not(test), allow(dead_code))] // The footprint reader (ottto#599).
    pub(crate) fn is_owned_fresh_start(&self) -> bool {
        self.complete && !self.is_fork && self.cwd.is_some()
    }

    pub(crate) fn chars(&self, kind: BlockKind) -> u64 {
        self.block_chars[kind as usize]
    }

    #[cfg_attr(not(test), allow(dead_code))] // The footprint reader (ottto#599).
    pub(crate) fn hook_chars(&self) -> u64 {
        self.chars(BlockKind::Hooks)
    }

    /// Injected developer/user text other than base instructions, AGENTS.md,
    /// skills, hooks and the user's own text.
    #[cfg_attr(not(test), allow(dead_code))] // The footprint reader (ottto#599).
    pub(crate) fn other_harness_chars(&self) -> u64 {
        self.chars(BlockKind::DeferredTools)
            + self.chars(BlockKind::Environment)
            + self.chars(BlockKind::Other)
    }
}

/// Reads rows until the parser is done, at most [`MAX_PRELUDE_LINES`]. The
/// caller bounds the bytes.
#[cfg_attr(not(test), allow(dead_code))] // The footprint reader (ottto#599).
pub(crate) fn parse_prelude(mut reader: impl BufRead) -> std::io::Result<CodexPrelude> {
    let mut parser = CodexPreludeParser::default();
    let mut line = Vec::new();
    for _ in 0..MAX_PRELUDE_LINES {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        // Rows that are not JSON still count toward the window bound.
        let value = serde_json::from_slice::<Value>(&line).unwrap_or(Value::Null);
        if parser.observe(&value) == PreludeStep::Done {
            break;
        }
    }
    Ok(parser.finish())
}

/// Whether the caller should feed the next rollout row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreludeStep {
    More,
    Done,
}

/// The one Codex prelude parser (CROSS-LANE R1). Feed rollout rows in order,
/// already decoded, until it says [`PreludeStep::Done`].
#[derive(Debug, Clone)]
pub(crate) struct CodexPreludeParser {
    prelude: CodexPrelude,
    session_id: Option<String>,
    /// Rows after the first request are read only for its context window,
    /// which a `token_count` event can carry right after the usage record.
    rows_after_first_request: usize,
    /// Most bytes of AGENTS.md text kept.
    agents_md_cap: usize,
    keep_skills_body: bool,
}

impl Default for CodexPreludeParser {
    /// Keeps every loaded text; the caller bounds what it feeds.
    fn default() -> Self {
        Self {
            prelude: CodexPrelude::default(),
            session_id: None,
            rows_after_first_request: 0,
            agents_md_cap: usize::MAX,
            keep_skills_body: true,
        }
    }
}

impl CodexPreludeParser {
    /// Keeps at most `agents_md_cap` bytes of the AGENTS.md text (for path
    /// matching) and no skills body.
    pub(crate) fn matching_only(agents_md_cap: usize) -> Self {
        Self {
            agents_md_cap,
            keep_skills_body: false,
            ..Self::default()
        }
    }

    pub(crate) fn prelude(&self) -> &CodexPrelude {
        &self.prelude
    }

    /// Drops the kept texts; every count stays.
    pub(crate) fn release_text(&mut self) {
        self.prelude.agents_md = None;
        self.prelude.skills_body = None;
    }

    #[cfg_attr(not(test), allow(dead_code))] // The footprint reader (ottto#599).
    pub(crate) fn observe(&mut self, value: &Value) -> PreludeStep {
        self.observe_with(value, |_, _| {})
    }

    /// [`Self::observe`], also lending each counted request-1 block's text to
    /// `on_block`. Nothing is copied for it.
    pub(crate) fn observe_with(
        &mut self,
        value: &Value,
        on_block: impl FnMut(BlockKind, &str),
    ) -> PreludeStep {
        let prelude = &mut self.prelude;
        if prelude.complete {
            self.rows_after_first_request += 1;
            if self.rows_after_first_request > MAX_LINES_FOR_WINDOW {
                return PreludeStep::Done;
            }
        }
        let payload = value.get("payload").unwrap_or(&Value::Null);
        let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
        if prelude.complete && kind != "event_msg" {
            return PreludeStep::More;
        }
        match kind {
            "session_meta" => {
                note_session_meta(prelude, &mut self.session_id, payload);
                if prelude.started_at.is_none() {
                    prelude.started_at = payload
                        .get("timestamp")
                        .or_else(|| value.get("timestamp"))
                        .and_then(Value::as_str)
                        .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
                        .map(OffsetDateTime::unix_timestamp);
                }
            }
            "turn_context" if prelude.model.is_none() => {
                prelude.model = small_text(payload.get("model"));
            }
            "world_state" if !prelude.world_state_seen => {
                if let Some(state) = payload.get("state").filter(|s| s.is_object()) {
                    prelude.world_state_seen = true;
                    let agents = state.get("agents_md");
                    if let Some(text) = agents.and_then(|a| a.get("text")).and_then(Value::as_str) {
                        let mut end = text.len().min(self.agents_md_cap);
                        while !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        prelude.agents_md_capped = end < text.len();
                        prelude.agents_md = Some(LoadedAgentsMd {
                            directory: small_text(agents.and_then(|a| a.get("directory"))),
                            text: text[..end].to_string(),
                        });
                    }
                    if self.keep_skills_body {
                        prelude.skills_body = state
                            .get("host_skills")
                            .and_then(|skills| skills.get("body"))
                            .and_then(Value::as_str)
                            .map(str::to_string);
                    }
                }
            }
            "token_usage_record" => {
                prelude.first_input_tokens = payload
                    .get("usage")
                    .and_then(|usage| usage.get("input_tokens"))
                    .and_then(Value::as_u64);
                prelude.complete = true;
                prelude.input_closed = true;
                if prelude.context_window.is_some() {
                    return PreludeStep::Done;
                }
            }
            "event_msg" if payload.get("type").and_then(Value::as_str) == Some("token_count") => {
                let info = payload.get("info").unwrap_or(&Value::Null);
                let Some(input) = info
                    .get("last_token_usage")
                    .and_then(|usage| usage.get("input_tokens"))
                    .and_then(Value::as_u64)
                else {
                    return PreludeStep::More;
                };
                if !prelude.complete {
                    prelude.first_input_tokens = Some(input);
                    prelude.complete = true;
                    prelude.input_closed = true;
                }
                if let Some(window) = info.get("model_context_window").and_then(Value::as_u64) {
                    prelude.context_window.get_or_insert(window);
                }
                return PreludeStep::Done;
            }
            "response_item" if !prelude.input_closed => {
                match payload.get("type").and_then(Value::as_str) {
                    Some("message") => match payload.get("role").and_then(Value::as_str) {
                        Some("developer" | "user") => note_message(prelude, payload, on_block),
                        _ => prelude.input_closed = true,
                    },
                    // The model's own output: request 1's input is over.
                    Some(
                        "reasoning" | "function_call" | "custom_tool_call" | "local_shell_call"
                        | "web_search_call",
                    ) => prelude.input_closed = true,
                    _ => {}
                }
            }
            _ => {}
        }
        PreludeStep::More
    }

    #[cfg_attr(not(test), allow(dead_code))] // The footprint reader (ottto#599).
    pub(crate) fn finish(self) -> CodexPrelude {
        self.prelude
    }
}

fn note_session_meta(prelude: &mut CodexPrelude, session_id: &mut Option<String>, meta: &Value) {
    let id = small_text(meta.get("id").or_else(|| meta.get("session_id")));
    if let Some(first) = session_id.as_ref() {
        // A second meta row with another id is a copied parent thread.
        if id.as_ref().is_some_and(|id| id != first) {
            prelude.is_fork = true;
        }
        return;
    }
    *session_id = id.or_else(|| Some(String::new()));
    prelude.cwd = small_text(meta.get("cwd"));
    prelude.context_window = meta.get("context_window").and_then(Value::as_u64);
    let present = |key: &str| meta.get(key).is_some_and(|value| !value.is_null());
    prelude.is_fork = meta.get("thread_source").and_then(Value::as_str)
        == Some("agent_created_thread")
        || meta
            .get("forked_from_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
        || present("history_base")
        || present("subagent_history_start_ordinal");
    prelude.base_instructions_chars = base_instructions_text(meta).map_or(0, char_count);
}

/// Request-1 developer/user text by its `content_item_kinds` label.
fn note_message(
    prelude: &mut CodexPrelude,
    payload: &Value,
    mut on_block: impl FnMut(BlockKind, &str),
) {
    let Some(blocks) = labeled_blocks(payload) else {
        prelude.blocks_incomplete = true;
        return;
    };
    for (label, block) in blocks {
        if block.get("type").and_then(Value::as_str) == Some("input_image") {
            prelude.blocks_incomplete = true;
            continue;
        }
        let Some(text) = block.get("text").and_then(Value::as_str) else {
            continue;
        };
        let kind = BlockKind::of(label);
        prelude.block_chars[kind as usize] += char_count(text);
        on_block(kind, text);
    }
}

/// `(label, block)` for each content block of one prelude message, or `None`
/// unless the client labeled the blocks one-to-one with string kinds.
fn labeled_blocks(payload: &Value) -> Option<impl Iterator<Item = (&str, &Value)>> {
    let blocks = payload.get("content")?.as_array()?;
    let kinds = payload
        .get("internal_chat_message_metadata_passthrough")?
        .get("content_item_kinds")?
        .as_array()?;
    (kinds.len() == blocks.len() && kinds.iter().all(Value::is_string)).then(|| {
        kinds
            .iter()
            .zip(blocks)
            .map(|(kind, block)| (kind.as_str().unwrap_or_default(), block))
    })
}

/// `session_meta.payload.base_instructions` text (a string or `{text}`).
fn base_instructions_text(meta: &Value) -> Option<&str> {
    match meta.get("base_instructions")? {
        Value::String(text) => Some(text),
        value => value.get("text")?.as_str(),
    }
}

fn small_text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| text.len() <= MAX_SMALL_TEXT_BYTES)
        .map(str::to_string)
}

/// UTF-16 code units, the unit of the Claude file counts and the backend ratio.
pub(crate) fn char_count(text: &str) -> u64 {
    // ASCII, the common case, is one unit per byte; `is_ascii` is vectorized.
    if text.is_ascii() {
        text.len() as u64
    } else {
        text.encode_utf16().count() as u64
    }
}

crate::heap_layout_bound::fields!(LoadedAgentsMd; directory, text);
crate::heap_layout_bound::fields!(CodexPrelude; cwd, started_at, is_fork, complete, model, context_window, first_input_tokens, base_instructions_chars, block_chars, blocks_incomplete, input_closed, world_state_seen, agents_md, agents_md_capped, skills_body);
crate::heap_layout_bound::fields!(CodexPreludeParser; prelude, session_id, rows_after_first_request, agents_md_cap, keep_skills_body);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rollout(records: &[Value]) -> Vec<u8> {
        let mut out = Vec::new();
        for record in records {
            out.extend_from_slice(record.to_string().as_bytes());
            out.push(b'\n');
        }
        out
    }

    fn parse(records: &[Value]) -> CodexPrelude {
        parse_prelude(std::io::Cursor::new(rollout(records))).unwrap()
    }

    fn meta(extra: Value) -> Value {
        let mut payload = json!({
            "id": "s1",
            "cwd": "/repo",
            "context_window": 258400,
            "base_instructions": {"text": "BASE-INSTRUCTIONS"},
        });
        for (key, value) in extra.as_object().unwrap() {
            payload[key] = value.clone();
        }
        json!({"type": "session_meta", "payload": payload})
    }

    fn message(role: &str, kind: Option<&str>, text: &str) -> Value {
        let mut payload = json!({
            "type": "message",
            "role": role,
            "content": [{"type": "input_text", "text": text}],
        });
        if let Some(kind) = kind {
            payload["internal_chat_message_metadata_passthrough"] =
                json!({"content_item_kinds": [kind]});
        }
        json!({"type": "response_item", "payload": payload})
    }

    fn usage(input: u64) -> Value {
        json!({"type": "token_usage_record", "payload": {"usage": {"input_tokens": input}}})
    }

    const SKILLS_BODY: &str =
        "## Skills\n### Available skills\n- deploy: Ship it. (file: r1/deploy/SKILL.md)\n";

    #[test]
    fn prelude_reads_world_state_and_stops_at_first_request() {
        let prelude = parse(&[
            meta(json!({})),
            json!({"type": "turn_context", "payload": {"model": "gpt-6.1-sol"}}),
            json!({"type": "world_state", "payload": {"full": true, "state": {
                "agents_md": {"directory": "/repo", "text": "GLOBAL"},
                "host_skills": {"body": SKILLS_BODY},
            }}}),
            message("developer", Some("permissions.instructions"), "PERMS"),
            message("developer", Some(HOST_SKILLS_KIND), "<skills>X</skills>"),
            message("developer", Some("hooks.additional_context"), "HOOK"),
            message(
                "user",
                Some(AGENTS_MD_KIND),
                "# AGENTS.md instructions for /repo\n\n<INSTRUCTIONS>\nGLOBAL\n</INSTRUCTIONS>",
            ),
            message("user", Some("multi_agent.role_instructions"), "ROLE"),
            message("user", Some("user.text"), "typed prompt"),
            usage(25_000),
            // After the first request: never read.
            json!({"type": "world_state", "payload": {"state": {"agents_md": {"text": "LATER"}}}}),
        ]);
        assert!(prelude.complete && prelude.input_closed && prelude.world_state_seen);
        assert!(prelude.is_owned_fresh_start());
        assert_eq!(prelude.cwd.as_deref(), Some("/repo"));
        assert_eq!(prelude.model.as_deref(), Some("gpt-6.1-sol"));
        assert_eq!(prelude.context_window, Some(258_400));
        assert_eq!(prelude.first_input_tokens, Some(25_000));
        assert_eq!(prelude.base_instructions_chars, 17);
        assert_eq!(prelude.hook_chars(), 4);
        assert_eq!(prelude.other_harness_chars(), 5 + 4);
        // Rendered copies are counted by kind; the loaded texts come from world_state.
        assert_eq!(prelude.chars(BlockKind::Skills), 18);
        assert_eq!(prelude.chars(BlockKind::AgentsMd), 73);
        assert_eq!(prelude.chars(BlockKind::Prompt), 12);
        let agents = prelude.agents_md.unwrap();
        assert_eq!(agents.text, "GLOBAL");
        assert_eq!(agents.directory.as_deref(), Some("/repo"));
        assert_eq!(prelude.skills_body.as_deref(), Some(SKILLS_BODY));
    }

    #[test]
    fn model_output_closes_request_one_input() {
        let prelude = parse(&[
            meta(json!({})),
            message("user", Some("user.text"), "go"),
            json!({"type": "response_item", "payload": {"type": "reasoning"}}),
            // Injected after the model answered: request 2's input.
            message("developer", Some("hooks.additional_context"), "LATE"),
            usage(10),
        ]);
        assert!(prelude.input_closed);
        assert_eq!(prelude.hook_chars(), 0);
        assert_eq!(prelude.chars(BlockKind::Prompt), 2);
    }

    #[test]
    fn unlabeled_or_image_blocks_mark_request_one_incomplete() {
        let mut malformed = message("user", None, "x");
        malformed["payload"]["internal_chat_message_metadata_passthrough"] =
            json!({"content_item_kinds": [7]});
        let image = json!({"type": "response_item", "payload": {"type": "message", "role": "user",
            "content": [{"type": "input_image", "image_url": "data:"}],
            "internal_chat_message_metadata_passthrough": {"content_item_kinds": ["user.image"]}}});
        for row in [message("user", None, "unlabeled"), malformed, image] {
            let prelude = parse(&[meta(json!({})), row, usage(1)]);
            assert!(prelude.blocks_incomplete);
            assert_eq!(prelude.block_chars, [0; BLOCK_KINDS]);
        }
    }

    #[test]
    fn rows_fed_one_by_one_match_the_reader() {
        let records = [
            meta(json!({})),
            message("user", Some(AGENTS_MD_KIND), "RULES"),
            usage(100),
            json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
                "last_token_usage": {"input_tokens": 100}, "model_context_window": 1000}}}),
            json!({"type": "event_msg", "payload": {"type": "never_read"}}),
        ];
        let mut parser = CodexPreludeParser::default();
        let fed = records
            .iter()
            .take_while(|row| parser.observe(row) == PreludeStep::More);
        assert_eq!(fed.count(), 2);
        let prelude = parser.finish();
        assert_eq!(prelude, parse(&records));
        // Without world_state (cli < 0.159) no loaded text is known.
        assert!(!prelude.world_state_seen);
        assert_eq!(prelude.agents_md, None);
    }

    #[test]
    fn matching_only_caps_agents_md_and_skips_skills() {
        let mut parser = CodexPreludeParser::matching_only(4);
        parser.observe(&json!({"type": "world_state", "payload": {"state": {
            "agents_md": {"text": "abc\u{e9}def"}, "host_skills": {"body": SKILLS_BODY}}}}));
        let prelude = parser.prelude();
        assert_eq!(prelude.agents_md.as_ref().unwrap().text, "abc");
        assert!(prelude.agents_md_capped);
        assert_eq!(prelude.skills_body, None);
        parser.release_text();
        assert_eq!(parser.prelude().agents_md, None);
    }

    #[test]
    fn forks_and_copied_parents_are_not_fresh_starts() {
        for extra in [
            json!({"forked_from_id": "parent"}),
            json!({"history_base": {"thread_id": "parent", "end_ordinal_exclusive": 4}}),
            json!({"subagent_history_start_ordinal": 3}),
            json!({"thread_source": "agent_created_thread"}),
        ] {
            let prelude = parse(&[meta(extra.clone()), usage(1)]);
            assert!(prelude.is_fork, "{extra}");
            assert!(!prelude.is_owned_fresh_start());
        }
        let copied = parse(&[
            meta(json!({})),
            json!({"type": "session_meta", "payload": {"id": "parent"}}),
            usage(1),
        ]);
        assert!(copied.is_fork);
        let plain = parse(&[meta(json!({"forked_from_id": null})), usage(1)]);
        assert!(!plain.is_fork);
        let incomplete = parse(&[meta(json!({})), message("user", Some("user.text"), "hi")]);
        assert!(!incomplete.complete && !incomplete.is_owned_fresh_start());
    }

    #[test]
    fn token_count_event_also_closes_the_prelude() {
        let prelude = parse(&[
            meta(json!({"context_window": null})),
            json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
                "last_token_usage": {"input_tokens": 777}, "model_context_window": 400000}}}),
        ]);
        assert!(prelude.complete);
        assert_eq!(prelude.first_input_tokens, Some(777));
        assert_eq!(prelude.context_window, Some(400_000));
    }
}
