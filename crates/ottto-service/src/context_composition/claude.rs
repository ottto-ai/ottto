//! Claude Code transcript parsing.

use super::measure::{
    basename, basename_stem, estimate_text_tokens, extract_blocks_text_and_images, is_truthy_json,
    line_date, parse_timestamp, read_jsonl, serialize_attachment, ResidencyModel,
};
use super::report::{Weight, WorkspaceReport};
use super::IMAGE_NOMINAL_TOKENS;
use crate::composition_kinds::{self as kinds, CallClass, ClaudeAttachment, LineCtx, Verdict};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use time::{Date, OffsetDateTime};

// -------------------------------------------------------------------------
// Claude Code parsing (ported 1:1 from the reference).
// -------------------------------------------------------------------------

pub(super) enum LastAssistantId {
    Sentinel,
    Value(Option<String>),
}

pub(crate) fn parse_claude_session(
    path: &Path,
    report: &mut WorkspaceReport,
    fallback: Date,
    include_subagents: bool,
) -> std::io::Result<()> {
    let lines = read_jsonl(path)?;
    if lines.is_empty() {
        return Ok(());
    }

    let mut session_id: Option<String> = None;
    let mut is_sub = false;
    for o in &lines {
        if let Some(sid) = o.get("sessionId").and_then(Value::as_str) {
            session_id = Some(sid.to_string());
        }
        if o.get("isSidechain")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            is_sub = true;
        }
    }
    let mut session_id = session_id.unwrap_or_else(|| basename_stem(path));

    if is_sub {
        if !include_subagents {
            return Ok(());
        }
        let agent_id = lines
            .iter()
            .find_map(|o| o.get("agentId").and_then(Value::as_str))
            .map(str::to_string)
            .unwrap_or_else(|| basename(path));
        session_id = format!("{session_id} (subagent:{agent_id})");
    }

    let copied = claude_copied_records(&lines, report);
    if copied.iter().any(|copied| *copied) {
        if lines
            .iter()
            .zip(&copied)
            .all(|(line, copied)| *copied || line.get("uuid").is_none())
        {
            report.excluded_not_fresh += 1;
            return Ok(());
        }
        report.copied_history_sessions += 1;
    }

    let ctx = LineCtx::v1();

    // Pass 1: tool_use id -> call class; residency markers.
    let mut tooluse: BTreeMap<String, CallClass> = BTreeMap::new();
    let mut assistant_ordinals: Vec<usize> = Vec::new();
    let mut compaction_ordinals: Vec<usize> = Vec::new();
    let mut last = LastAssistantId::Sentinel;
    let mut session_min_ts: Option<OffsetDateTime> = None;

    for (i, o) in lines.iter().enumerate() {
        if let Some(ts) = parse_timestamp(o) {
            session_min_ts = Some(match session_min_ts {
                Some(existing) if existing <= ts => existing,
                _ => ts,
            });
        }
        let t = o.get("type").and_then(Value::as_str).unwrap_or("");
        if t == "assistant" {
            let mid = o
                .get("message")
                .filter(|m| m.is_object())
                .and_then(|m| m.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let append = mid.is_none()
                || match &last {
                    LastAssistantId::Sentinel => true,
                    LastAssistantId::Value(prev) => prev.as_deref() != mid.as_deref(),
                };
            // Copied turns were requests of the session that wrote them.
            if append && !copied[i] {
                assistant_ordinals.push(i);
            }
            last = LastAssistantId::Value(mid);
        }
        let is_compaction = o
            .get("isCompactSummary")
            .map(is_truthy_json)
            .unwrap_or(false)
            || t == "summary"
            || o.get("subtype").and_then(Value::as_str) == Some("compact_boundary");
        if is_compaction {
            compaction_ordinals.push(i);
        }
        if let Some(content) = o
            .get("message")
            .and_then(Value::as_object)
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
        {
            for b in content {
                if b.get("type").and_then(Value::as_str) == Some("tool_use") {
                    if let Some(tid) = b.get("id").and_then(Value::as_str) {
                        let name = b.get("name").and_then(Value::as_str).unwrap_or("");
                        let input = b.get("input").unwrap_or(&Value::Null);
                        tooluse.insert(tid.to_string(), kinds::claude_tool(&ctx, name, input));
                    }
                }
            }
        }
    }
    let residency = ResidencyModel::new(assistant_ordinals, compaction_ordinals);

    // Pass 2: attribute entered items.
    for (i, o) in lines.iter().enumerate() {
        let t = o.get("type").and_then(Value::as_str).unwrap_or("");
        let weight = Weight {
            mult: residency.multiplier(i),
            copied: copied[i],
        };
        let (date, ts) = line_date(o, fallback);

        if t == "attachment" {
            let empty = Value::Object(Default::default());
            let att = o.get("attachment").unwrap_or(&empty);
            let fname = att.get("filename").and_then(Value::as_str);
            let facts = ClaudeAttachment {
                att_type: att.get("type").and_then(Value::as_str).unwrap_or(""),
                filename: fname,
                // The v1 reader does not read `files[]`.
                file_type: None,
                has_rendered: att.get("rendered").is_some(),
            };
            if let Verdict::Count { kind, .. } = kinds::claude_attachment(&ctx, &facts) {
                let text = serialize_attachment(att);
                let toks = estimate_text_tokens(&text);
                report.record(&session_id, kind, toks, weight, 0, fname, date, ts);
            }
            continue;
        }

        let Some(content) = o
            .get("message")
            .and_then(Value::as_object)
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
        else {
            continue;
        };

        for b in content {
            let bt = b.get("type").and_then(Value::as_str).unwrap_or("");
            match bt {
                "tool_use" => {
                    // Memory WRITES are tracked separately in the reference and
                    // never counted as recall or in any category, so this
                    // collector simply does not record their written content.
                    continue;
                }
                "tool_result" => {
                    let tid = b.get("tool_use_id").and_then(Value::as_str);
                    let resolved = tid.and_then(|tid| tooluse.get(tid));
                    let (text, images) = extract_blocks_text_and_images(b.get("content"));
                    let toks = estimate_text_tokens(&text);
                    let unmatched;
                    let call = match resolved {
                        Some(call) => call,
                        None => {
                            unmatched = CallClass::unmatched();
                            &unmatched
                        }
                    };
                    report.record(
                        &session_id,
                        call.kind,
                        toks,
                        weight,
                        0,
                        call.file.as_deref(),
                        date,
                        ts,
                    );
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
                "image" => {
                    if let Verdict::Count { kind, .. } = kinds::image(&ctx, None) {
                        report.record(
                            &session_id,
                            kind,
                            IMAGE_NOMINAL_TOKENS,
                            weight,
                            1,
                            None,
                            date,
                            ts,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    report.note_session_start(&session_id, session_min_ts);
    Ok(())
}

/// Which records of a Claude transcript repeat records already counted in this
/// workspace (same uuid). Resumed and forked transcripts copy earlier records
/// with their uuids; the copy is history, not new context. Records this file
/// adds are then remembered for later files.
pub(super) fn claude_copied_records(lines: &[Value], report: &mut WorkspaceReport) -> Vec<bool> {
    let hashes = lines
        .iter()
        .map(|line| line.get("uuid").and_then(Value::as_str).map(record_hash))
        .collect::<Vec<_>>();
    let copied = hashes
        .iter()
        .map(|hash| hash.is_some_and(|hash| report.claude_records.contains(&hash)))
        .collect();
    report.claude_records.extend(hashes.into_iter().flatten());
    copied
}

pub(super) fn record_hash(uuid: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    uuid.hash(&mut hasher);
    hasher.finish()
}
