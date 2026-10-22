//! Claude Code lines, one at a time.
//!
//! Each call handles one complete line with the file's parse state, so a
//! transcript can be read in any number of pieces with the same result as
//! one read. Measurement and record order follow the kinds_version 1 parser
//! (`super::super::claude`); the differences are deliberate and listed in
//! the module tests: a result's call is looked up among calls seen earlier
//! in the file (and used once), the session id is fixed by the first lines,
//! an undated line counts on the day it is read, and the client's
//! prompt-snapshot and deferred-tools records are never counted.

use super::super::measure::{basename, basename_stem, serialize_attachment};
use super::super::IMAGE_NOMINAL_TOKENS;
use super::aggregate::{Day, Slot};
use super::checkpoint::{LastAssistant, OpenCall, ParseState};
use super::decode::{
    claude_never_counted, claude_never_counted_type, content_chars_and_images, decode_view,
    line_timestamp, tokens_for_chars, BlockView, ClaudeLine, Joined, MessageView, Raw,
};
use super::file::LineSink;
use super::ownership::stable_hash;
use super::MAX_OPEN_CALLS;
use crate::composition_kinds::{
    self as kinds, Agent, Author, CallClass, ClaudeAttachment, LineCtx, Request1, Verdict,
};
use serde_json::Value;
use std::path::Path;

/// Session identity from the first lines of a transcript.
pub(super) fn head_identity(lines: &[&str], path: &Path) -> (String, bool) {
    let mut session: Option<String> = None;
    let mut sidechain: Option<bool> = None;
    let mut agent_id: Option<String> = None;
    for text in lines {
        let owned: Option<String>;
        let Some(view) = decode_view!(text, owned, ClaudeLine) else {
            continue;
        };
        if session.is_none() {
            session = view.session_id.str().map(|id| id.into_owned());
        }
        if sidechain.is_none() {
            sidechain = view.is_sidechain.bool();
        }
        if agent_id.is_none() {
            agent_id = view.agent_id.str().map(|id| id.into_owned());
        }
    }
    let in_subagents_dir = path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "subagents");
    let is_sub = in_subagents_dir || sidechain == Some(true);
    let session = session.unwrap_or_else(|| basename_stem(path));
    if is_sub {
        let agent_id = agent_id.unwrap_or_else(|| basename(path));
        (format!("{session} (subagent:{agent_id})"), true)
    } else {
        (session, false)
    }
}

/// Handle one Claude Code line.
pub(super) fn handle_line(out: &mut LineSink, state: &mut ParseState, line: &[u8]) {
    if claude_never_counted(line) {
        out.stats.prefix_skipped += 1;
        return;
    }
    let Ok(text) = std::str::from_utf8(line) else {
        out.stats.bad_lines += 1;
        return;
    };
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    if !text.starts_with('{') {
        // Valid JSON that is not an object carries nothing the reader uses.
        if serde_json::from_str::<serde::de::IgnoredAny>(text).is_err() {
            out.stats.bad_lines += 1;
        }
        return;
    }
    let owned: Option<String>;
    let Some(view) = decode_view!(text, owned, ClaudeLine) else {
        out.stats.bad_lines += 1;
        return;
    };
    out.stats.lines += 1;

    let ts = line_timestamp(view.timestamp, view.ts);
    let ts_secs = ts.map(|ts| ts.unix_timestamp());
    state.note_ts(ts_secs);
    let day: Day = ts.map_or(out.fallback_day, |ts| ts.date().to_julian_day());
    let line_type = view.kind.str();
    let line_type = line_type.as_deref().unwrap_or("");

    let copied = match (view.uuid.str(), out.ownership.as_deref_mut()) {
        (Some(uuid), Some(ownership)) => {
            let hash = stable_hash(uuid.as_bytes());
            let copied = ownership.counted_elsewhere(hash, out.file_id);
            if !copied {
                ownership.add(hash, out.file_id);
            }
            copied
        }
        _ => false,
    };
    if copied {
        state.copied_lines += 1;
    } else {
        state.own_lines += 1;
    }
    if let Some(cwd) = view.cwd.str() {
        if state.cwd.as_deref() != Some(cwd.as_ref()) {
            state.cwd = Some(cwd.as_ref().into());
        }
    }

    // A compaction ends the residency of everything before it.
    let compaction = view.is_compact_summary.truthy()
        || line_type == "summary"
        || view.subtype.str().as_deref() == Some("compact_boundary");
    if compaction {
        state.open.clear();
    }

    let message_owned: Option<String>;
    let message: Option<MessageView> = match view.message.text() {
        Some(message_text) if view.message.is_object() => {
            decode_view!(message_text, message_owned, MessageView)
        }
        _ => None,
    };
    if line_type == "assistant" {
        let id: Option<Box<str>> = message
            .as_ref()
            .and_then(|message| message.id.str().map(|id| id.as_ref().into()));
        let counted = id.is_none()
            || match &state.last_assistant {
                LastAssistant::Sentinel => true,
                LastAssistant::Id(previous) => previous.as_deref() != id.as_deref(),
            };
        // Copied turns were requests of the session that wrote them.
        if counted && !copied {
            out.request(state);
        }
        state.last_assistant = LastAssistant::Id(id);
    }

    let author = if state.agent_author || view.is_sidechain.bool() == Some(true) {
        Author::Agent
    } else {
        Author::You
    };
    let cwd = state.cwd.clone();
    let ctx = LineCtx {
        agent: Agent::Claude,
        request_1: Request1::No,
        cwd: cwd.as_deref().map(Path::new),
        file_has_rendered: state.has_rendered,
        author,
    };

    let blocks: Vec<Raw> = message
        .as_ref()
        .and_then(|message| message.content.elements())
        .unwrap_or_default();
    // Calls first, so a result in the same line finds its call.
    for block in &blocks {
        let Some(block_text) = block.text() else {
            continue;
        };
        let block_owned: Option<String>;
        let Some(block) = decode_view!(block_text, block_owned, BlockView) else {
            continue;
        };
        if block.kind.str().as_deref() != Some("tool_use") {
            continue;
        }
        let Some(id) = block.id.str() else { continue };
        let name = block.name.str();
        let input = block.input.value().unwrap_or(Value::Null);
        let class = kinds::claude_tool(&ctx, name.as_deref().unwrap_or(""), &input);
        if state.open_calls.len() >= MAX_OPEN_CALLS {
            out.stats.dropped_calls += 1;
            state.open_calls.pop_first();
        }
        state.open_calls.insert(
            id.as_ref().into(),
            OpenCall {
                class,
                items: Vec::new(),
            },
        );
    }

    if line_type == "attachment" {
        attachment(out, state, &ctx, view.attachment, day, ts_secs, copied);
        return;
    }

    let mut user_text = Joined::default();
    let mut has_result = false;
    let content_is_string = message
        .as_ref()
        .is_some_and(|message| message.content.str().is_some());
    for block in &blocks {
        let Some(block_text) = block.text() else {
            continue;
        };
        let block_owned: Option<String>;
        let Some(block) = decode_view!(block_text, block_owned, BlockView) else {
            continue;
        };
        match block.kind.str().as_deref().unwrap_or("") {
            "tool_result" => {
                has_result = true;
                let call = block
                    .tool_use_id
                    .str()
                    .and_then(|id| state.open_calls.remove(id.as_ref()))
                    .map(|call| call.class)
                    .unwrap_or_else(CallClass::unmatched);
                let (chars, images) = content_chars_and_images(block.content);
                let tokens = tokens_for_chars(chars);
                let slot = Slot::new(call.kind, call.part, call.tool.as_str());
                out.record(
                    state,
                    day,
                    slot,
                    tokens,
                    0,
                    call.file.as_deref(),
                    ts_secs,
                    copied,
                );
                if !copied {
                    out.tool(
                        day,
                        call.tool.as_str(),
                        call.kind,
                        &state.session,
                        tokens,
                        true,
                    );
                }
                if images > 0 {
                    if let Verdict::Count { kind, part } = kinds::image(&ctx, Some(&call)) {
                        let tokens = images * IMAGE_NOMINAL_TOKENS;
                        let slot = Slot::new(kind, part, call.tool.as_str());
                        out.record(state, day, slot, tokens, images, None, ts_secs, copied);
                        if !copied {
                            out.tool(
                                day,
                                call.tool.as_str(),
                                call.kind,
                                &state.session,
                                tokens,
                                false,
                            );
                        }
                    }
                }
            }
            "image" => {
                if let Verdict::Count { kind, part } = kinds::image(&ctx, None) {
                    let slot = Slot::plain(kind, part);
                    out.record(
                        state,
                        day,
                        slot,
                        IMAGE_NOMINAL_TOKENS,
                        1,
                        None,
                        ts_secs,
                        copied,
                    );
                }
            }
            "text" => {
                if let Some(text) = block.text.str() {
                    user_text.push(&text);
                }
            }
            _ => {}
        }
    }

    // A user record's own text (prompts, notifications, summaries): the
    // classifier decides; kinds_version 1 does not count it.
    if line_type == "user" && !has_result && (content_is_string || !user_text.is_empty()) {
        if let Ok(line_value) = serde_json::from_str::<Value>(text) {
            if let Verdict::Count { kind, part } = kinds::claude_user_text(&ctx, &line_value) {
                let chars = match message.as_ref().and_then(|message| message.content.str()) {
                    Some(content) => content.chars().count(),
                    None => user_text.chars(),
                };
                let slot = Slot::plain(kind, part);
                out.record(
                    state,
                    day,
                    slot,
                    tokens_for_chars(chars),
                    0,
                    None,
                    ts_secs,
                    copied,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn attachment(
    out: &mut LineSink,
    state: &mut ParseState,
    ctx: &LineCtx,
    raw: Raw,
    day: Day,
    ts: Option<i64>,
    copied: bool,
) {
    let att = if raw.is_present() {
        raw.value().unwrap_or(Value::Null)
    } else {
        Value::Object(Default::default())
    };
    let att_type = att.get("type").and_then(Value::as_str).unwrap_or("");
    if claude_never_counted_type(att_type) {
        out.stats.prefix_skipped += 1;
        return;
    }
    let filename = att.get("filename").and_then(Value::as_str);
    let has_rendered = att.get("rendered").is_some();
    if has_rendered {
        state.has_rendered = true;
    }
    let file_type = att
        .get("files")
        .and_then(Value::as_array)
        .and_then(|files| files.first())
        .and_then(|file| file.get("type"))
        .and_then(Value::as_str);
    let facts = ClaudeAttachment {
        att_type,
        filename,
        file_type,
        has_rendered,
    };
    let ctx = LineCtx {
        file_has_rendered: state.has_rendered,
        ..*ctx
    };
    match kinds::claude_attachment(&ctx, &facts) {
        Verdict::Count { kind, part } => {
            let text = serialize_attachment(&att);
            let tokens = tokens_for_chars(text.chars().count());
            let slot = Slot::plain(kind, part);
            out.record(state, day, slot, tokens, 0, filename, ts, copied);
        }
        Verdict::Skip(_) => out.stats.classifier_skipped += 1,
    }
}
