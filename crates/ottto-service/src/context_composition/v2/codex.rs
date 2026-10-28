//! Codex lines, one at a time.
//!
//! Resumable like the Claude handler. Measurement follows the kinds_version 1
//! parser (`super::super::codex`); in addition the inner items Codex writes
//! while a call runs (`item_completed`: commands with their parsed reads,
//! add-on calls, web searches) are kept with the open call and handed to the
//! classifier with the call's output.

use super::super::codex::codex_mcp_result_text_and_images;
use super::super::measure::{basename_stem, estimate_text_tokens, python_json_dumps};
use super::super::IMAGE_NOMINAL_TOKENS;
use super::aggregate::{Day, Slot};
use super::checkpoint::{CopiedMode, ParseState, SavedItem};
use super::decode::{
    codex_never_counted, content_chars_and_images, decode_view, line_timestamp,
    output_chars_and_images, tokens_for_chars, BlockView, CodexLine, CodexPayload, ItemView,
    Joined, Raw, SessionMetaView,
};
use super::file::LineSink;
use super::MAX_ITEMS_PER_CALL;
use crate::composition_kinds::{
    self as kinds, Author, ContentLabel, InnerItem, Kind, KindsVersion, LineCtx, ParsedCommand,
    Part, Verdict,
};
use serde_json::Value;
use std::borrow::Cow;
use std::path::Path;

/// Session identity and copied-history mode from the first `session_meta`
/// record (as the kinds_version 1 parser and the session sink read it).
pub(super) struct HeadIdentity {
    pub(super) session: String,
    pub(super) copied: CopiedMode,
    pub(super) agent_author: bool,
    pub(super) cwd: Option<String>,
}

pub(super) fn head_identity(lines: &[&str], path: &Path) -> HeadIdentity {
    for text in lines {
        let owned: Option<String>;
        let Some(view) = decode_view!(text, owned, CodexLine) else {
            continue;
        };
        if view.kind.str().as_deref() != Some("session_meta") {
            continue;
        }
        let Some(meta_text) = view.payload.text() else {
            break;
        };
        let meta_owned: Option<String>;
        let meta = if view.payload.is_object() {
            decode_view!(meta_text, meta_owned, SessionMetaView)
        } else {
            None
        };
        let Some(meta) = meta else {
            break;
        };
        let session = meta
            .id
            .str()
            .or_else(|| meta.session_id.str())
            .map(Cow::into_owned)
            .unwrap_or_else(|| basename_stem(path));
        let thread_source = meta.thread_source.str();
        let thread_source = thread_source.as_deref();
        let is_subagent = thread_source == Some("subagent")
            || meta
                .source
                .value()
                .and_then(|source| {
                    source
                        .as_object()
                        .map(|source| source.contains_key("subagent"))
                })
                .unwrap_or(false);
        let forked = meta
            .forked_from_id
            .str()
            .is_some_and(|id| !id.trim().is_empty());
        let history_base = meta.history_base.is_present() && !meta.history_base.is_null();
        let start = meta.subagent_history_start_ordinal.u64();
        let copied =
            if thread_source == Some("agent_created_thread") || (start.is_none() && history_base) {
                // Inherited history stays outside the file.
                CopiedMode::Own
            } else if let Some(start) = start {
                CopiedMode::BeforeOrdinal(start)
            } else if !forked {
                CopiedMode::Own
            } else if !is_subagent {
                CopiedMode::Excluded
            } else {
                CopiedMode::UntilTrigger
            };
        return HeadIdentity {
            session: crate::snapshots::snapshot_source_session_id(
                crate::snapshots::SnapshotSource::Codex,
                path,
                session,
            ),
            copied,
            agent_author: is_subagent || thread_source == Some("agent_created_thread"),
            cwd: meta.cwd.str().map(Cow::into_owned),
        };
    }
    HeadIdentity {
        session: crate::snapshots::snapshot_source_session_id(
            crate::snapshots::SnapshotSource::Codex,
            path,
            basename_stem(path),
        ),
        copied: CopiedMode::Own,
        agent_author: false,
        cwd: None,
    }
}

/// Ask the shared prelude parser only about rows that can close input.
/// Developer/world-state text can be large; borrowed views avoid building
/// a Value tree for content the prefix path will intentionally skip.
pub(super) fn request1_input_closed(line: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(line) else {
        return false;
    };
    let owned: Option<String>;
    let Some(view) = decode_view!(text, owned, CodexLine) else {
        return false;
    };
    let kind = view.kind.str();
    let kind = kind.as_deref().unwrap_or("");
    let minimal = match kind {
        "response_item" => {
            let Some(text) = view.payload.text() else {
                return false;
            };
            let payload_owned: Option<String>;
            let Some(payload) = decode_view!(text, payload_owned, CodexPayload) else {
                return false;
            };
            let payload_type = payload.kind.str();
            let payload_type = payload_type.as_deref().unwrap_or("");
            if payload_type == "agent_message" {
                return true;
            }
            serde_json::json!({"type":kind,"payload":{"type":payload_type,"role":payload.role.str()}})
        }
        "token_usage_record" | "event_msg" => {
            // Usage records are small. Other event messages can contain
            // large outputs and never close the prelude.
            let Some(text) = view.payload.text() else {
                return false;
            };
            let payload_owned: Option<String>;
            let Some(payload) = decode_view!(text, payload_owned, CodexPayload) else {
                return false;
            };
            if kind == "event_msg" && payload.kind.str().as_deref() != Some("token_count") {
                return false;
            }
            let Ok(row) = serde_json::from_slice::<Value>(line) else {
                return false;
            };
            row
        }
        _ => return false,
    };
    let mut parser = crate::codex_prelude_footprint::CodexPreludeParser::matching_only(0);
    parser.observe(&minimal);
    parser.prelude().input_closed
}

/// Handle one Codex line.
pub(super) fn handle_line(out: &mut LineSink, state: &mut ParseState, line: &[u8]) {
    if !state.request1_closed && out.kinds == KindsVersion::V2 {
        state.request1_closed = request1_input_closed(line);
    }
    if codex_never_counted(line) {
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
        if serde_json::from_str::<serde::de::IgnoredAny>(text).is_err() {
            out.stats.bad_lines += 1;
        }
        return;
    }
    let owned: Option<String>;
    let Some(view) = decode_view!(text, owned, CodexLine) else {
        out.stats.bad_lines += 1;
        return;
    };
    out.stats.lines += 1;
    let ts = line_timestamp(view.timestamp, view.ts);
    let ts_secs = ts.map(|ts| ts.unix_timestamp());
    state.note_ts(ts_secs);
    if state.copied == CopiedMode::Excluded {
        state.copied_lines += 1;
        return;
    }
    let payload_owned: Option<String>;
    let payload: Option<CodexPayload> = match view.payload.text() {
        Some(payload_text) if view.payload.is_object() => {
            decode_view!(payload_text, payload_owned, CodexPayload)
        }
        _ => None,
    };
    let Some(payload) = payload else {
        return;
    };
    let line_type = view.kind.str();
    if state.copied == CopiedMode::UntilTrigger
        && line_type.as_deref() == Some("inter_agent_communication_metadata")
        && payload.trigger_turn.bool() == Some(true)
    {
        // The session's own records start at the trigger turn.
        state.copied = CopiedMode::Own;
    }
    let copied = match state.copied {
        CopiedMode::Own => false,
        CopiedMode::BeforeOrdinal(start) => {
            view.ordinal.u64().map_or(true, |ordinal| ordinal < start)
        }
        CopiedMode::UntilTrigger | CopiedMode::Excluded => true,
    };
    if copied {
        state.copied_lines += 1;
    } else {
        state.own_lines += 1;
    }
    if let Some(cwd) = payload.cwd.str() {
        if state.cwd.as_deref() != Some(cwd.as_ref()) {
            state.cwd = Some(cwd.as_ref().into());
        }
    }
    let day: Day = ts.map_or(out.fallback_day, |ts| ts.date().to_julian_day());
    let cwd = state.cwd.clone();
    let author = if state.agent_author {
        Author::Agent
    } else {
        Author::You
    };
    let ctx = out.ctx(state, cwd.as_deref().map(Path::new), false, author);
    let payload_type = payload.kind.str();
    let payload_type = payload_type.as_deref().unwrap_or("");
    match payload_type {
        "function_call" | "custom_tool_call" | "local_shell_call" => {
            if let Some(call_id) = payload.call_id.str() {
                let name = payload.name.str().or_else(|| {
                    (payload_type == "local_shell_call").then_some(Cow::Borrowed("local_shell"))
                });
                let input = call_input(payload_type, &payload);
                let class = kinds::codex_call(&ctx, name.as_deref(), &input);
                let id: Box<str> = call_id.as_ref().into();
                if state.open_call(id.clone(), class) {
                    out.stats.dropped_calls += 1;
                }
                state.last_call = Some(id);
            }
            // Copied turns were requests of the session that wrote them.
            if !copied {
                out.request(state);
            }
        }
        "agent_message" => {
            if !copied {
                out.request(state);
            }
        }
        "context_compacted" => state.open.clear(),
        "function_call_output" | "custom_tool_call_output" | "local_shell_call_output" => {
            let call_id = payload.call_id.str();
            let call = call_id
                .as_deref()
                .and_then(|id| state.open_calls.remove(id));
            if call_id.is_some() && state.last_call.as_deref() == call_id.as_deref() {
                state.last_call = None;
            }
            let (class, items) = match call {
                Some(call) => (call.class, call.items),
                // A result whose call is not in the file: the classifier's
                // class for a call with no name.
                None => (kinds::codex_call(&ctx, None, ""), Vec::new()),
            };
            let (chars, images) = output_chars_and_images(payload.output);
            let tokens = tokens_for_chars(chars);
            let parsed: Vec<Vec<ParsedCommand>> = items
                .iter()
                .map(|item| match item {
                    SavedItem::Command { parsed, .. } => parsed
                        .iter()
                        .map(|(kind, path)| ParsedCommand {
                            kind,
                            path: path.as_deref(),
                        })
                        .collect(),
                    _ => Vec::new(),
                })
                .collect();
            let inner: Vec<InnerItem> = items
                .iter()
                .zip(&parsed)
                .map(|(item, parsed)| inner_item(item, parsed))
                .collect();
            // Split over the inner items (a code cell's commands, add-on
            // calls and searches), else the call's own shares; an add-on
            // call inside a cell counts under its own tool.
            let cells = kinds::codex_cell(&class, &inner, tokens);
            out.result(state, day, &class, cells, ts_secs, copied);
            if images > 0 {
                if let Verdict::Count { kind, part } = kinds::image(&ctx, Some(&class)) {
                    let tokens = images * IMAGE_NOMINAL_TOKENS;
                    let slot = Slot::new(kind, part, class.tool.as_str());
                    out.record(state, day, slot, tokens, images, None, ts_secs, copied);
                    if !copied {
                        out.tool(
                            day,
                            class.tool.as_str(),
                            class.kind,
                            &state.session,
                            tokens,
                            false,
                        );
                    }
                }
            }
        }
        "mcp_tool_call_end" => {
            let invocation = payload.invocation.value();
            let class = kinds::codex_mcp(&ctx, invocation.as_ref());
            let result = payload.result.value();
            let (text, images) = codex_mcp_result_text_and_images(result.as_ref());
            let tokens = estimate_text_tokens(&text);
            let cells = kinds::codex_cell(&class, &[], tokens);
            out.result(state, day, &class, cells, ts_secs, copied);
            if images > 0 {
                if let Verdict::Count { kind, part } = kinds::image(&ctx, Some(&class)) {
                    let tokens = images * IMAGE_NOMINAL_TOKENS;
                    let slot = Slot::new(kind, part, class.tool.as_str());
                    out.record(state, day, slot, tokens, images, None, ts_secs, copied);
                    if !copied {
                        out.tool(
                            day,
                            class.tool.as_str(),
                            class.kind,
                            &state.session,
                            tokens,
                            false,
                        );
                    }
                }
            }
        }
        "message" => message(out, state, &ctx, &payload, day, ts_secs, copied),
        "item_completed" => {
            if let Some(item) = saved_item(payload.item) {
                match state
                    .last_call
                    .as_deref()
                    .and_then(|id| state.open_calls.get_mut(id))
                {
                    Some(call) if call.items.len() < MAX_ITEMS_PER_CALL => call.items.push(item),
                    _ => out.stats.dropped_items += 1,
                }
            }
        }
        "session_meta" | "" => {}
        // A search run inside an open call is in that call's output (an
        // in-cell `web.search` item): count it once, there.
        "web_search_end"
            if out.kinds == KindsVersion::V2
                && state
                    .last_call
                    .as_deref()
                    .is_some_and(|id| state.open_calls.contains_key(id)) =>
        {
            out.stats.web_search_in_call += 1;
        }
        other => {
            if let Verdict::Count { kind, part } = kinds::codex_event(&ctx, other) {
                let chars = view
                    .payload
                    .value()
                    .map_or(0, |value| python_json_dumps(&value).chars().count());
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
    let _ = owned;
}

#[allow(clippy::too_many_arguments)]
fn message(
    out: &mut LineSink,
    state: &mut ParseState,
    ctx: &LineCtx,
    payload: &CodexPayload,
    day: Day,
    ts: Option<i64>,
    copied: bool,
) {
    let role = payload.role.str();
    let role = role.as_deref().unwrap_or("");
    if role != "developer" && role != "user" {
        return;
    }
    let (chars, images) = content_chars_and_images(payload.content);
    if role == "developer" && out.kinds == KindsVersion::V1 {
        // kinds_version 1 counts a developer message whole, even when empty.
        if let Verdict::Count { kind, part } =
            kinds::codex_message(ctx, role, ContentLabel::Absent, "")
        {
            let slot = Slot::plain(kind, part);
            out.record(
                state,
                day,
                slot,
                tokens_for_chars(chars),
                0,
                None,
                ts,
                copied,
            );
        }
    } else {
        // kinds_version 2 classifies every text block of both roles.
        for (kind, part, joined) in text_groups(ctx, role, payload) {
            if !joined.is_empty() {
                let slot = Slot::plain(kind, part);
                out.record(
                    state,
                    day,
                    slot,
                    tokens_for_chars(joined.chars()),
                    0,
                    None,
                    ts,
                    copied,
                );
            }
        }
    }
    if images > 0 {
        if let Verdict::Count { kind, part } = kinds::image(ctx, None) {
            let slot = Slot::plain(kind, part);
            let tokens = images * IMAGE_NOMINAL_TOKENS;
            out.record(state, day, slot, tokens, images, None, ts, copied);
        }
    }
}

/// The counted text blocks of a message, joined per kind and part in
/// first-seen order. Codex's per-block `content_item_kinds` labels apply only
/// when they line up with the blocks.
fn text_groups(ctx: &LineCtx, role: &str, payload: &CodexPayload) -> Vec<(Kind, Part, Joined)> {
    let Some(blocks) = payload.content.elements() else {
        return Vec::new();
    };
    let label_texts: Option<Vec<Option<String>>> = payload
        .internal_chat_message_metadata_passthrough
        .value()
        .and_then(|meta| {
            let labels = meta.get("content_item_kinds")?.as_array()?;
            Some(
                labels
                    .iter()
                    .map(|label| label.as_str().map(str::to_string))
                    .collect(),
            )
        })
        .filter(|labels: &Vec<Option<String>>| labels.len() == blocks.len());
    let mut groups: Vec<(Kind, Part, Joined)> = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let Some(block_text) = block.text() else {
            continue;
        };
        let block_owned: Option<String>;
        let Some(view) = decode_view!(block_text, block_owned, BlockView) else {
            continue;
        };
        let Some(text) = view.text.str() else {
            continue;
        };
        let label = match &label_texts {
            Some(labels) => ContentLabel::Present(labels[index].as_deref()),
            None => ContentLabel::Absent,
        };
        let Verdict::Count { kind, part } = kinds::codex_message(ctx, role, label, &text) else {
            continue;
        };
        match groups
            .iter_mut()
            .find(|(group, group_part, _)| *group == kind && *group_part == part)
        {
            Some((_, _, joined)) => joined.push(&text),
            None => {
                let mut joined = Joined::default();
                joined.push(&text);
                groups.push((kind, part, joined));
            }
        }
    }
    groups
}

/// A call's own input text: `input` (custom-tool calls), else `arguments`
/// (function calls), else the local-shell action's command words joined by
/// spaces; "" when it has none.
fn call_input<'a>(payload_type: &str, payload: &CodexPayload<'a>) -> Cow<'a, str> {
    if let Some(input) = payload.input.str() {
        return input;
    }
    match payload_type {
        "function_call" => payload.arguments.str().unwrap_or_default(),
        "local_shell_call" => payload
            .action
            .value()
            .and_then(|action| {
                let words = action.get("command")?.as_array()?;
                let words: Vec<&str> = words.iter().filter_map(Value::as_str).collect();
                Some(Cow::Owned(words.join(" ")))
            })
            .unwrap_or_default(),
        _ => Cow::Borrowed(""),
    }
}

fn saved_item(raw: Raw) -> Option<SavedItem> {
    let text = raw.text()?;
    if !raw.is_object() {
        return None;
    }
    let owned: Option<String>;
    let item = decode_view!(text, owned, ItemView)?;
    let kind = item.kind.str();
    let words = |raw: Raw| -> String {
        if let Some(text) = raw.str() {
            return text.into_owned();
        }
        raw.elements()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|word| word.str().map(Cow::into_owned))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let saved = match kind.as_deref()? {
        "CommandExecution" => SavedItem::Command {
            cwd: item.cwd.str().map(Cow::into_owned),
            command: words(item.command),
            parsed: item
                .parsed_cmd
                .elements()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|entry| {
                    let entry = entry.value()?;
                    Some((
                        entry.get("type")?.as_str()?.to_string(),
                        entry
                            .get("path")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    ))
                })
                .collect(),
            output_chars: item
                .aggregated_output
                .str()
                .map_or(0, |output| output.chars().count() as u64),
        },
        "McpToolCall" => SavedItem::Mcp {
            server: item.server.str().map(Cow::into_owned).unwrap_or_default(),
            tool: item.tool.str().map(Cow::into_owned).unwrap_or_default(),
            output_chars: item
                .result
                .value()
                .and_then(|result| result.get("content").cloned())
                .map_or(0, |content| {
                    super::super::measure::extract_blocks_text_and_images(Some(&content))
                        .0
                        .chars()
                        .count() as u64
                }),
        },
        "Extension" => {
            let name = item
                .extension_kind
                .str()
                .map(Cow::into_owned)
                .unwrap_or_default();
            let output_chars = item.results.raw_len() as u64;
            if name == "web.search" {
                SavedItem::WebSearch { output_chars }
            } else {
                SavedItem::Extension { name, output_chars }
            }
        }
        _ => return None,
    };
    Some(saved)
}

fn inner_item<'a>(item: &'a SavedItem, parsed: &'a [ParsedCommand<'a>]) -> InnerItem<'a> {
    match item {
        SavedItem::Command {
            cwd,
            command,
            output_chars,
            ..
        } => InnerItem::Command {
            cwd: cwd.as_deref(),
            command,
            parsed,
            output_chars: *output_chars,
        },
        SavedItem::Mcp {
            server,
            tool,
            output_chars,
        } => InnerItem::Mcp {
            server,
            tool,
            output_chars: *output_chars,
        },
        SavedItem::Extension { name, output_chars } => InnerItem::Extension {
            name,
            output_chars: *output_chars,
        },
        SavedItem::WebSearch { output_chars } => InnerItem::WebSearch {
            output_chars: *output_chars,
        },
    }
}
