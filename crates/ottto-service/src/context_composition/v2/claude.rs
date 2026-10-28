//! Claude Code lines, one at a time.
//!
//! Each call handles one complete line with the file's parse state, so a
//! transcript can be read in any number of pieces with the same result as
//! one read. Measurement and record order follow the kinds_version 1 parser
//! (`super::super::claude`); the differences are deliberate and listed in
//! the module tests: a result's call is looked up among calls seen earlier
//! in the file (and used once), the session id is fixed by the first lines,
//! an undated line counts on the day it is read, the client's
//! prompt-snapshot and deferred-tools records are never counted, and copied
//! history is found by its timestamp, not its record id.

use super::super::measure::{basename_stem, python_json_dumps, serialize_attachment};
use super::super::IMAGE_NOMINAL_TOKENS;
use super::aggregate::{Day, Slot};
use super::checkpoint::{LastAssistant, ParseState};
use super::decode::{
    claude_never_counted, claude_never_counted_type, content_chars_and_images, decode_view,
    line_timestamp, tokens_for_chars, BlockView, ClaudeLine, Joined, MessageView, Raw,
};
use super::file::LineSink;
use crate::composition_kinds::{
    self as kinds, Author, ClaudeAttachment, Kind, KindsVersion, LineCtx, Part, Verdict,
};
use serde_json::Value;
use std::path::Path;

/// Session identity from the first lines of a transcript.
pub(super) fn head_identity(lines: &[&str], path: &Path) -> (String, bool) {
    let mut session: Option<String> = None;
    let mut sidechain: Option<bool> = None;
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
    }
    let in_subagents_dir = path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "subagents");
    let is_sub = in_subagents_dir || sidechain == Some(true);
    let session = session.unwrap_or_else(|| basename_stem(path));
    let canonical = crate::snapshots::snapshot_source_session_id(
        crate::snapshots::SnapshotSource::ClaudeCode,
        path,
        session.clone(),
    );
    let is_sub = is_sub || canonical != session;
    (canonical, is_sub)
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

    // A resume or fork copies earlier records with their original
    // timestamps; a record dated before this transcript was born entered
    // context where it was first written.
    let copied = matches!(
        (ts_secs, out.copied_before),
        (Some(ts), Some(before)) if ts < before
    );
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

    // Keep the pair across checkpoint chunks: a linked summary belongs to
    // the boundary that already cleared residency, even far apart in time.
    let uuid = view.uuid.str();
    let parent = view.parent_uuid.str();
    let subtype = view.subtype.str();
    let timestamp = view.timestamp.str().or_else(|| view.ts.str());
    if state.compactions.observe(
        line_type,
        subtype.as_deref(),
        view.is_compact_summary.truthy(),
        uuid.as_deref(),
        parent.as_deref(),
        timestamp.as_deref(),
    ) || line_type == "summary"
    {
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
        state.request1_closed = true;
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
    let ctx = out.ctx(
        state,
        cwd.as_deref().map(Path::new),
        state.has_rendered,
        author,
    );

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
        if state.open_call(id.as_ref().into(), class) {
            out.stats.dropped_calls += 1;
        }
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
                // A result whose call is not in the file: the classifier's
                // class for a call with no name.
                let call = block
                    .tool_use_id
                    .str()
                    .and_then(|id| state.open_calls.remove(id.as_ref()))
                    .map(|call| call.class)
                    .unwrap_or_else(|| kinds::claude_tool(&ctx, "", &Value::Null));
                let (chars, images) = content_chars_and_images(block.content);
                let tokens = tokens_for_chars(chars);
                // Split over the call's shares (a command's segments, a read
                // of several files).
                let cells = kinds::codex_cell(&call, &[], tokens);
                out.result(state, day, &call, cells, ts_secs, copied);
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
    // An instructions attachment's first `files[]` type, or a queued
    // command's `commandMode` (a typed prompt or a background report).
    let file_type = att
        .get("files")
        .and_then(Value::as_array)
        .and_then(|files| files.first())
        .and_then(|file| file.get("type"))
        .or_else(|| att.get("commandMode"))
        .and_then(Value::as_str);
    let facts = ClaudeAttachment {
        att_type,
        filename,
        file_type,
        has_rendered,
    };
    // This line may be the file's first with `rendered` text.
    let ctx = out.ctx(state, ctx.cwd, state.has_rendered, ctx.author);
    match kinds::claude_attachment(&ctx, &facts) {
        Verdict::Count { kind, part } => {
            let text = serialize_attachment(&att);
            let tokens = tokens_for_chars(text.chars().count());
            if out.kinds == KindsVersion::V2 && att_type == "instructions" {
                if let Some(shares) = instruction_shares(&ctx, &att, &facts) {
                    let weights: Vec<u64> = shares.iter().map(|(_, _, weight)| *weight).collect();
                    for ((kind, part, _), tokens) in shares
                        .into_iter()
                        .zip(kinds::split_tokens(tokens, &weights))
                    {
                        let slot = Slot::plain(kind, part);
                        out.record(state, day, slot, tokens, 0, None, ts, copied);
                    }
                    return;
                }
            }
            // kinds_version 2 lists only files read (the top-file parts);
            // a mentioned or changed file is context, not a read.
            let file =
                filename.filter(|_| out.kinds == KindsVersion::V1 || kind == Kind::FilesRead);
            let slot = Slot::plain(kind, part);
            out.record(state, day, slot, tokens, 0, file, ts, copied);
        }
        Verdict::Skip(_) => out.stats.classifier_skipped += 1,
    }
}

/// An instructions attachment's `files[]` entries, each classified with its
/// own `type` (project instructions and auto-memory reload together) and
/// weighted by its size; equal parts merge. `None` when it lists at most one
/// kind of entry (the attachment counts whole).
fn instruction_shares(
    ctx: &LineCtx,
    att: &Value,
    facts: &ClaudeAttachment,
) -> Option<Vec<(Kind, Part, u64)>> {
    let files = att.get("files")?.as_array()?;
    let mut shares: Vec<(Kind, Part, u64)> = Vec::new();
    for entry in files {
        let entry_facts = ClaudeAttachment {
            file_type: entry.get("type").and_then(Value::as_str),
            ..*facts
        };
        let Verdict::Count { kind, part } = kinds::claude_attachment(ctx, &entry_facts) else {
            continue;
        };
        let weight = python_json_dumps(entry).chars().count() as u64;
        match shares
            .iter_mut()
            .find(|(known, known_part, _)| (*known, *known_part) == (kind, part))
        {
            Some((_, _, total)) => *total += weight,
            None => shares.push((kind, part, weight)),
        }
    }
    (shares.len() > 1).then_some(shares)
}
