//! Shared Codex MCP decoding and a test-only whole-file parser oracle.

#[cfg(test)]
use super::measure::{
    basename_stem, estimate_text_tokens, line_date, parse_timestamp, read_jsonl, ResidencyModel,
};
use super::measure::{extract_blocks_text_and_images, python_json_dumps};
#[cfg(test)]
use super::report::{Weight, WorkspaceReport};
#[cfg(test)]
use super::IMAGE_NOMINAL_TOKENS;
#[cfg(test)]
use crate::composition_kinds::{self as kinds, CallClass, ContentLabel, Kind, LineCtx, Verdict};
use serde_json::Value;
#[cfg(test)]
use std::borrow::Cow;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use time::{Date, OffsetDateTime};

// -------------------------------------------------------------------------
// Codex parsing (ported 1:1 from the reference).
// -------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn parse_codex_session(
    path: &Path,
    report: &mut WorkspaceReport,
    fallback: Date,
) -> std::io::Result<()> {
    let lines = read_jsonl(path)?;
    if lines.is_empty() {
        return Ok(());
    }

    let mut session_id: Option<String> = None;
    for o in &lines {
        if o.get("type").and_then(Value::as_str) == Some("session_meta") {
            if let Some(p) = o.get("payload").and_then(Value::as_object) {
                session_id = p
                    .get("id")
                    .and_then(Value::as_str)
                    .or_else(|| p.get("session_id").and_then(Value::as_str))
                    .map(str::to_string);
            }
            break;
        }
    }
    let session_id = session_id.unwrap_or_else(|| basename_stem(path));

    let Some(copied) = codex_copied_records(&lines) else {
        report.excluded_not_fresh += 1;
        return Ok(());
    };
    if copied.iter().any(|copied| *copied) {
        report.copied_history_sessions += 1;
    }

    let ctx = LineCtx::v1();

    // Pass 1: call_id -> call class; residency markers.
    let mut callmap: BTreeMap<String, CallClass> = BTreeMap::new();
    let mut assistant_ordinals: Vec<usize> = Vec::new();
    let mut compaction_ordinals: Vec<usize> = Vec::new();
    let mut session_min_ts: Option<OffsetDateTime> = None;

    for (i, o) in lines.iter().enumerate() {
        if let Some(ts) = parse_timestamp(o) {
            session_min_ts = Some(match session_min_ts {
                Some(existing) if existing <= ts => existing,
                _ => ts,
            });
        }
        let Some(p) = o.get("payload").and_then(Value::as_object) else {
            continue;
        };
        let pt = p.get("type").and_then(Value::as_str).unwrap_or("");
        match pt {
            "function_call" | "custom_tool_call" | "local_shell_call" => {
                if let Some(cid) = p.get("call_id").and_then(Value::as_str) {
                    let name = p
                        .get("name")
                        .and_then(Value::as_str)
                        .or_else(|| (pt == "local_shell_call").then_some("local_shell"));
                    let input = codex_call_input(pt, p);
                    callmap.insert(cid.to_string(), kinds::codex_call(&ctx, name, &input));
                }
                // Copied turns were requests of the session that wrote them.
                if !copied[i] {
                    assistant_ordinals.push(i);
                }
            }
            "agent_message" if !copied[i] => assistant_ordinals.push(i),
            "context_compacted" => compaction_ordinals.push(i),
            _ => {}
        }
    }
    let residency = ResidencyModel::new(assistant_ordinals, compaction_ordinals);

    // Pass 2.
    for (i, o) in lines.iter().enumerate() {
        let Some(p) = o.get("payload").and_then(Value::as_object) else {
            continue;
        };
        let pt = p.get("type").and_then(Value::as_str).unwrap_or("");
        let weight = Weight {
            mult: residency.multiplier(i),
            copied: copied[i],
        };
        let (date, ts) = line_date(o, fallback);

        match pt {
            "function_call_output" | "custom_tool_call_output" | "local_shell_call_output" => {
                let unmatched;
                let call = match p
                    .get("call_id")
                    .and_then(Value::as_str)
                    .and_then(|cid| callmap.get(cid))
                {
                    Some(call) => call,
                    None => {
                        unmatched = CallClass::unmatched();
                        &unmatched
                    }
                };
                let (text, images) = codex_output_text_and_images(p.get("output"));
                let toks = estimate_text_tokens(&text);
                for share in kinds::codex_cell(call, &[], toks) {
                    let file = share.file.as_deref();
                    report.record(
                        &session_id,
                        share.kind,
                        share.tokens,
                        weight,
                        0,
                        file,
                        date,
                        ts,
                    );
                }
                if images > 0 {
                    if let Verdict::Count { kind, .. } = kinds::image(&ctx, Some(call)) {
                        report.record(
                            &session_id,
                            kind,
                            images * IMAGE_NOMINAL_TOKENS,
                            weight,
                            images,
                            None,
                            date,
                            ts,
                        );
                    }
                }
            }
            "web_search_end" => {
                if let Verdict::Count { kind, .. } = kinds::codex_event(&ctx, pt) {
                    let text = python_json_dumps(&Value::Object(p.clone()));
                    report.record(
                        &session_id,
                        kind,
                        estimate_text_tokens(&text),
                        weight,
                        0,
                        None,
                        date,
                        ts,
                    );
                }
            }
            "mcp_tool_call_end" => {
                let call = kinds::codex_mcp(&ctx, p.get("invocation"));
                let (text, images) = codex_mcp_result_text_and_images(p.get("result"));
                report.record(
                    &session_id,
                    call.kind,
                    estimate_text_tokens(&text),
                    weight,
                    0,
                    call.file.as_deref(),
                    date,
                    ts,
                );
                if images > 0 {
                    if let Verdict::Count { kind, .. } = kinds::image(&ctx, Some(&call)) {
                        report.record(
                            &session_id,
                            kind,
                            images * IMAGE_NOMINAL_TOKENS,
                            weight,
                            images,
                            None,
                            date,
                            ts,
                        );
                    }
                }
            }
            "message" => {
                let role = p.get("role").and_then(Value::as_str).unwrap_or("");
                if role == "developer" || role == "user" {
                    let (text, images) = extract_blocks_text_and_images(p.get("content"));
                    if role == "developer" {
                        // A developer message counts whole, even when empty.
                        let verdict = kinds::codex_message(&ctx, role, ContentLabel::Absent, "");
                        if let Verdict::Count { kind, .. } = verdict {
                            report.record(
                                &session_id,
                                kind,
                                estimate_text_tokens(&text),
                                weight,
                                0,
                                None,
                                date,
                                ts,
                            );
                        }
                    } else {
                        for (kind, text) in codex_user_counted_text(&ctx, p) {
                            if !text.is_empty() {
                                report.record(
                                    &session_id,
                                    kind,
                                    estimate_text_tokens(&text),
                                    weight,
                                    0,
                                    None,
                                    date,
                                    ts,
                                );
                            }
                        }
                    }
                    if images > 0 {
                        if let Verdict::Count { kind, .. } = kinds::image(&ctx, None) {
                            report.record(
                                &session_id,
                                kind,
                                images * IMAGE_NOMINAL_TOKENS,
                                weight,
                                images,
                                None,
                                date,
                                ts,
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    report.note_session_start(&session_id, session_min_ts);
    Ok(())
}

/// A call's own input text: `input` (custom-tool calls), else `arguments`
/// (function calls), else the local-shell action's command words joined by
/// spaces; "" when it has none.
#[cfg(test)]
fn codex_call_input<'a>(
    payload_type: &str,
    payload: &'a serde_json::Map<String, Value>,
) -> Cow<'a, str> {
    let text = |key| payload.get(key).and_then(Value::as_str);
    if let Some(input) = text("input") {
        return Cow::Borrowed(input);
    }
    match payload_type {
        "function_call" => Cow::Borrowed(text("arguments").unwrap_or("")),
        "local_shell_call" => payload
            .get("action")
            .and_then(|action| action.get("command"))
            .and_then(Value::as_array)
            .map(|words| {
                let words: Vec<&str> = words.iter().filter_map(Value::as_str).collect();
                Cow::Owned(words.join(" "))
            })
            .unwrap_or_default(),
        _ => Cow::Borrowed(""),
    }
}

/// The counted text blocks of a user message, joined per kind (first-seen
/// order). Codex's per-block `content_item_kinds` labels apply only when they
/// line up with the blocks.
#[cfg(test)]
pub(super) fn codex_user_counted_text(
    ctx: &LineCtx,
    payload: &serde_json::Map<String, Value>,
) -> Vec<(Kind, String)> {
    let Some(blocks) = payload.get("content").and_then(Value::as_array) else {
        return Vec::new();
    };
    let labels = payload
        .get("internal_chat_message_metadata_passthrough")
        .and_then(|meta| meta.get("content_item_kinds"))
        .and_then(Value::as_array)
        .filter(|labels| labels.len() == blocks.len());
    let mut groups: Vec<(Kind, Vec<&str>)> = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let Some(text) = block.get("text").and_then(Value::as_str) else {
            continue;
        };
        let label = match labels {
            Some(labels) => ContentLabel::Present(labels[index].as_str()),
            None => ContentLabel::Absent,
        };
        let Verdict::Count { kind, .. } = kinds::codex_message(ctx, "user", label, text) else {
            continue;
        };
        match groups.iter_mut().find(|(group, _)| *group == kind) {
            Some((_, texts)) => texts.push(text),
            None => groups.push((kind, vec![text])),
        }
    }
    groups
        .into_iter()
        .map(|(kind, texts)| (kind, texts.join("\n")))
        .collect()
}

/// Which records of a Codex rollout are copied parent history, using the
/// session header's fork markers as the session sink does. `None` means the
/// rollout is a fork whose copied part has no boundary in the file (a legacy
/// user fork, or a legacy subagent fork without its trigger turn).
#[cfg(test)]
pub(super) fn codex_copied_records(lines: &[Value]) -> Option<Vec<bool>> {
    let meta = lines
        .iter()
        .find(|line| line.get("type").and_then(Value::as_str) == Some("session_meta"))
        .and_then(|line| line.get("payload"));
    let Some(meta) = meta else {
        return Some(vec![false; lines.len()]);
    };
    let thread_source = meta.get("thread_source").and_then(Value::as_str);
    let is_subagent = thread_source == Some("subagent")
        || meta
            .get("source")
            .and_then(Value::as_object)
            .is_some_and(|source| source.contains_key("subagent"));
    let forked = meta
        .get("forked_from_id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.trim().is_empty());
    let history_base = meta.get("history_base").is_some_and(|base| !base.is_null());
    let start = meta
        .get("subagent_history_start_ordinal")
        .and_then(Value::as_u64);

    if thread_source == Some("agent_created_thread") || (start.is_none() && history_base) {
        // Created threads and paginated forks keep inherited history outside
        // the file: every physical record is the session's own.
        return Some(vec![false; lines.len()]);
    }
    if let Some(start) = start {
        return Some(
            lines
                .iter()
                .map(|line| {
                    line.get("ordinal")
                        .and_then(Value::as_u64)
                        .map_or(true, |ordinal| ordinal < start)
                })
                .collect(),
        );
    }
    if !forked {
        return Some(vec![false; lines.len()]);
    }
    if !is_subagent {
        return None;
    }
    // Legacy subagent forks: the session's own records start at the trigger.
    let trigger = lines.iter().position(|line| {
        line.get("type").and_then(Value::as_str) == Some("inter_agent_communication_metadata")
            && line
                .pointer("/payload/trigger_turn")
                .and_then(Value::as_bool)
                == Some(true)
    })?;
    Some((0..lines.len()).map(|index| index < trigger).collect())
}

/// Extract the content an MCP call injected into context (result only, NOT the
/// model's invocation arguments).
pub(super) fn codex_mcp_result_text_and_images(result: Option<&Value>) -> (String, u64) {
    let Some(result) = result else {
        return (String::new(), 0);
    };
    let Some(obj) = result.as_object() else {
        return (String::new(), 0);
    };
    let inner = match obj.get("Ok") {
        Some(Value::Object(_)) => obj.get("Ok").unwrap(),
        _ => result,
    };
    let content = inner.as_object().and_then(|m| m.get("content"));
    match content {
        None => (python_json_dumps(result), 0),
        Some(c) => extract_blocks_text_and_images(Some(c)),
    }
}

#[cfg(test)]
pub(super) fn codex_output_text_and_images(output: Option<&Value>) -> (String, u64) {
    match output {
        Some(Value::String(s)) => (s.clone(), 0),
        other => extract_blocks_text_and_images(other),
    }
}
