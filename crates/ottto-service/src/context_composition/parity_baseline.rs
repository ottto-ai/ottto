//! Frozen whole-file reader oracle for parser representation parity.
//! Baseline preserves the pre-streaming implementation; test-only.
use super::super::*;
pub(super) fn read_jsonl(path: &Path) -> std::io::Result<Vec<Value>> {
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for raw in text.lines() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            out.push(value);
        }
    }
    Ok(out)
}

// -------------------------------------------------------------------------
// Claude Code parsing (ported 1:1 from the reference).
// -------------------------------------------------------------------------

enum LastAssistantId {
    Sentinel,
    Value(Option<String>),
}

pub(super) fn parse_claude_session(
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

    // Pass 1: tool_use id -> (name, file_path); residency markers.
    let mut tooluse: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
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
            if append {
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
                        let name = b.get("name").and_then(Value::as_str).map(str::to_string);
                        let fp = b
                            .get("input")
                            .and_then(Value::as_object)
                            .and_then(|input| input.get("file_path"))
                            .and_then(Value::as_str)
                            .map(str::to_string);
                        tooluse.insert(tid.to_string(), (name, fp));
                    }
                }
            }
        }
    }
    let residency = ResidencyModel::new(assistant_ordinals, compaction_ordinals);

    // Pass 2: attribute entered items.
    for (i, o) in lines.iter().enumerate() {
        let t = o.get("type").and_then(Value::as_str).unwrap_or("");
        let mult = residency.multiplier(i);
        let (date, ts) = line_date(o, fallback);

        if t == "attachment" {
            let empty = Value::Object(Default::default());
            let att = o.get("attachment").unwrap_or(&empty);
            let fname = att.get("filename").and_then(Value::as_str);
            let text = serialize_attachment(att);
            let toks = estimate_text_tokens(&text);
            match fname {
                Some(fname) if is_memory_path(fname) => report.record(
                    &session_id,
                    Category::MemoryNotes,
                    toks,
                    mult,
                    0,
                    Some(fname),
                    date,
                    ts,
                ),
                other => report.record(
                    &session_id,
                    Category::HarnessAttachments,
                    toks,
                    mult,
                    0,
                    other,
                    date,
                    ts,
                ),
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
                    match resolved {
                        None => report.record(
                            &session_id,
                            Category::OtherTools,
                            toks,
                            mult,
                            0,
                            None,
                            date,
                            ts,
                        ),
                        Some((name, fp)) => {
                            let name = name.as_deref().unwrap_or("");
                            let fp_str = fp.as_deref().unwrap_or("");
                            let cat = cc_tool_category(name, fp_str);
                            report.record(&session_id, cat, toks, mult, 0, fp.as_deref(), date, ts);
                        }
                    }
                    if images > 0 {
                        report.record(
                            &session_id,
                            Category::BrowserAndImages,
                            images * IMAGE_NOMINAL_TOKENS,
                            mult,
                            images,
                            None,
                            date,
                            ts,
                        );
                    }
                }
                "image" => {
                    report.record(
                        &session_id,
                        Category::BrowserAndImages,
                        IMAGE_NOMINAL_TOKENS,
                        mult,
                        1,
                        None,
                        date,
                        ts,
                    );
                }
                _ => {}
            }
        }
    }

    report.note_session_start(&session_id, session_min_ts);
    Ok(())
}

// -------------------------------------------------------------------------
// Codex parsing (ported 1:1 from the reference).
// -------------------------------------------------------------------------

pub(super) fn parse_codex_session(
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

    // Pass 1: call_id -> name; residency markers.
    let mut callmap: BTreeMap<String, Option<String>> = BTreeMap::new();
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
                        .map(str::to_string)
                        .or_else(|| (pt == "local_shell_call").then(|| "local_shell".to_string()));
                    callmap.insert(cid.to_string(), name);
                }
                assistant_ordinals.push(i);
            }
            "agent_message" => assistant_ordinals.push(i),
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
        let mult = residency.multiplier(i);
        let (date, ts) = line_date(o, fallback);

        match pt {
            "function_call_output" | "custom_tool_call_output" | "local_shell_call_output" => {
                let name = p
                    .get("call_id")
                    .and_then(Value::as_str)
                    .and_then(|cid| callmap.get(cid))
                    .and_then(|n| n.clone());
                let (text, images) = codex_output_text_and_images(p.get("output"));
                let toks = estimate_text_tokens(&text);
                let cat = match name.as_deref() {
                    Some(n) => codex_tool_category(n),
                    None => Category::OtherTools,
                };
                report.record(&session_id, cat, toks, mult, 0, None, date, ts);
                if images > 0 {
                    report.record(
                        &session_id,
                        Category::BrowserAndImages,
                        images * IMAGE_NOMINAL_TOKENS,
                        mult,
                        images,
                        None,
                        date,
                        ts,
                    );
                }
            }
            "web_search_end" => {
                let text = python_json_dumps(&Value::Object(p.clone()));
                report.record(
                    &session_id,
                    Category::WebFetchSearch,
                    estimate_text_tokens(&text),
                    mult,
                    0,
                    None,
                    date,
                    ts,
                );
            }
            "mcp_tool_call_end" => {
                let cat = codex_mcp_category(p.get("invocation"));
                let (text, images) = codex_mcp_result_text_and_images(p.get("result"));
                report.record(
                    &session_id,
                    cat,
                    estimate_text_tokens(&text),
                    mult,
                    0,
                    None,
                    date,
                    ts,
                );
                if images > 0 {
                    report.record(
                        &session_id,
                        Category::BrowserAndImages,
                        images * IMAGE_NOMINAL_TOKENS,
                        mult,
                        images,
                        None,
                        date,
                        ts,
                    );
                }
            }
            "message" => {
                let role = p.get("role").and_then(Value::as_str).unwrap_or("");
                if role == "developer" || role == "user" {
                    let (text, images) = extract_blocks_text_and_images(p.get("content"));
                    if role == "developer" {
                        report.record(
                            &session_id,
                            Category::HarnessAttachments,
                            estimate_text_tokens(&text),
                            mult,
                            0,
                            None,
                            date,
                            ts,
                        );
                    }
                    if images > 0 {
                        report.record(
                            &session_id,
                            Category::BrowserAndImages,
                            images * IMAGE_NOMINAL_TOKENS,
                            mult,
                            images,
                            None,
                            date,
                            ts,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    report.note_session_start(&session_id, session_min_ts);
    Ok(())
}
