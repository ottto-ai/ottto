//! Context-composition harvest for Claude Code and Codex transcripts.
//!
//! This is a low-cadence, per-workspace collector that answers "what kinds of
//! content flowed INTO the agent's context window over a capture window" --
//! harness attachments, shell output, file reads, docs, memory notes,
//! browser/images, web fetch/search, agent results, and other tool output.
//!
//! Unlike `context_footprint` (a point-in-time `/context` snapshot of static
//! config), this surface is a per-day *composition* aggregate derived from a
//! deterministic scan of the local transcript files
//! (`~/.claude/projects/<slug>/*.jsonl` and `~/.codex/sessions/**/*.jsonl`).
//!
//! The measurement methodology is a straight Rust port of the reference
//! implementation `context_composition_audit.py` and its `methodology.md`; the
//! golden tests below pin the same hand-computed numbers, so this collector
//! produces numerically identical per-category / per-file / per-session results
//! on the same inputs. Every number is an ESTIMATE (chars/4 tokenizer proxy;
//! nominal per-image cost); nothing here reproduces a provider tokenizer.
//!
//! Privacy: aggregates only, never message bodies. Top-file names are made
//! repo-relative or reduced to a bare basename; session ids are hashed with
//! sha256. Identity fields (machine_id, workspace_hash, repository_hash,
//! labels) reuse the exact values `context_footprint` computes for the same
//! workspace so backend scoping joins line up.

use crate::context_footprint::{
    collect_recent_jsonl_files, cwd_values_from_jsonl, resolve_repository_identity, safe_text,
    sha256_hex, workspace_label, RepositoryIdentity,
};
use crate::snapshot_client::{load_snapshot_device_credentials, SnapshotApiClient};
use crate::snapshots::SnapshotSource;
use anyhow::{anyhow, Result};
use ottto_core::{default_support_dir, LocalDeviceBinding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use time::{format_description::well_known::Rfc3339, Date, OffsetDateTime, UtcOffset};

// -------------------------------------------------------------------------
// Methodology knobs (see references/methodology.md in the audit skill).
// -------------------------------------------------------------------------

/// Tokenizer proxy: ~4 chars per token. ESTIMATE ONLY.
const CHARS_PER_TOKEN: usize = 4;
/// Images bill by DIMENSIONS, never by base64 byte length. A single image block
/// is charged a nominal cost (real range ~1,100-1,600, capped near ~1,600).
const IMAGE_NOMINAL_TOKENS: u64 = 1300;

const COLLECTOR_VERSION: &str = "context-composition-0.1.0";
const COUNTER_SOURCE: &str = "context_composition_v1";
/// Aggregate rows bucket by the UTC calendar day. `time` in this crate has no
/// timezone database (formatting/parsing features only) and local-offset lookup
/// is unsound in a multithreaded daemon, so UTC is the deterministic,
/// explicit day boundary. The backend stores this so the boundary is never
/// guessed at read time.
const BUCKET_TIMEZONE: &str = "UTC";

// -------------------------------------------------------------------------
// Cadence / bounds.
// -------------------------------------------------------------------------

/// Daily cadence. The slow harvest loop wakes once a day.
const CONTEXT_COMPOSITION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Per-cycle wall-clock budget so one slow disk never wedges the loop.
const CONTEXT_COMPOSITION_CYCLE_BUDGET: Duration = Duration::from_secs(5 * 60);
/// A single very large transcript is skipped to bound per-file work.
const MAX_TRANSCRIPT_BYTES: u64 = 50 * 1024 * 1024;
const MAX_WORKSPACES_PER_CYCLE: usize = 12;
/// Capture window (inclusive) must not exceed the backend cap (92 days).
const MAX_WINDOW_DAYS: i64 = 92;
const MAX_TOP_FILES: usize = 100;
const MAX_SESSIONS: usize = 200;
/// Re-upload at least this often even when nothing changed, so a stale row
/// eventually refreshes.
const CONTEXT_MAX_STALENESS_SECS: i64 = 7 * 24 * 60 * 60;

const LOCAL_DISABLE_ENV: &str = "OTTTO_CONTEXT_COMPOSITION_HARVEST_DISABLED";

// -------------------------------------------------------------------------
// Category taxonomy (closed enum; must map every contributor into exactly one).
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Category {
    HarnessAttachments,
    ShellOutput,
    CodeReads,
    DocReadsMd,
    DocReadsHtml,
    MemoryNotes,
    BrowserAndImages,
    WebFetchSearch,
    AgentResults,
    OtherTools,
}

impl Category {
    const ALL: [Category; 10] = [
        Category::HarnessAttachments,
        Category::ShellOutput,
        Category::CodeReads,
        Category::DocReadsMd,
        Category::DocReadsHtml,
        Category::MemoryNotes,
        Category::BrowserAndImages,
        Category::WebFetchSearch,
        Category::AgentResults,
        Category::OtherTools,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Category::HarnessAttachments => "harness_attachments",
            Category::ShellOutput => "shell_output",
            Category::CodeReads => "code_reads",
            Category::DocReadsMd => "doc_reads_md",
            Category::DocReadsHtml => "doc_reads_html",
            Category::MemoryNotes => "memory_notes",
            Category::BrowserAndImages => "browser_and_images",
            Category::WebFetchSearch => "web_fetch_search",
            Category::AgentResults => "agent_results",
            Category::OtherTools => "other_tools",
        }
    }

    fn index(self) -> usize {
        Category::ALL.iter().position(|c| *c == self).unwrap_or(0)
    }
}

// -------------------------------------------------------------------------
// Primitive measurement helpers (ported 1:1 from the reference).
// -------------------------------------------------------------------------

/// `ceil(chars / 4)`. Uses Unicode scalar count (Python `len`), not bytes.
pub(crate) fn estimate_text_tokens(text: &str) -> u64 {
    let chars = text.chars().count();
    if chars == 0 {
        return 0;
    }
    chars.div_ceil(CHARS_PER_TOKEN) as u64
}

/// Auto-memory recall channel: basename `MEMORY.md`, or `AutoMem/`, or
/// `/memory/` in the path (either separator).
pub(crate) fn is_memory_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let basename = path.rsplit(['/', '\\']).next().unwrap_or("");
    if basename == "MEMORY.md" {
        return true;
    }
    path.contains("AutoMem/")
        || path.contains("AutoMem\\")
        || path.contains("/memory/")
        || path.contains("\\memory\\")
}

/// A file-read tool result -> category based on the read path.
fn classify_by_read_path(path: &str) -> Category {
    if is_memory_path(path) {
        return Category::MemoryNotes;
    }
    let low = path.to_ascii_lowercase();
    if low.ends_with(".md") || low.ends_with(".markdown") {
        Category::DocReadsMd
    } else if low.ends_with(".html") || low.ends_with(".htm") {
        Category::DocReadsHtml
    } else {
        Category::CodeReads
    }
}

/// Python-compatible `json.dumps(x, ensure_ascii=False)` LENGTH. Only the
/// character length matters (it feeds `estimate_text_tokens`), and length is
/// independent of object key order, so a sorted-key serialization with Python's
/// default `", "` / `": "` separators produces the same length Python would.
fn python_json_dumps(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(_) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(python_json_dumps).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(k, v)| {
                    let key = serde_json::to_string(&Value::String(k.clone()))
                        .unwrap_or_else(|_| "\"\"".to_string());
                    format!("{}: {}", key, python_json_dumps(v))
                })
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Best-effort reconstruction of the text a Claude Code attachment injects.
fn serialize_attachment(att: &Value) -> String {
    let Some(obj) = att.as_object() else {
        return python_json_dumps(att);
    };
    let mut parts: Vec<String> = Vec::new();
    for key in [
        "content",
        "snippet",
        "banner",
        "prompt",
        "command",
        "blockingError",
    ] {
        if let Some(Value::String(s)) = obj.get(key) {
            if !s.is_empty() {
                parts.push(s.clone());
            }
        }
    }
    for key in ["addedLines", "addedBlocks", "removedLines"] {
        if let Some(Value::Array(items)) = obj.get(key) {
            if !items.is_empty() {
                for item in items {
                    match item {
                        Value::String(s) => parts.push(s.clone()),
                        other => parts.push(python_json_dumps(other)),
                    }
                }
            }
        }
    }
    if !parts.is_empty() {
        parts.join("\n")
    } else {
        python_json_dumps(att)
    }
}

/// Return `(text, image_count)` for a tool_result / message content value.
fn extract_blocks_text_and_images(content: Option<&Value>) -> (String, u64) {
    let content = match content {
        None | Some(Value::Null) => return (String::new(), 0),
        Some(Value::String(s)) => return (s.clone(), 0),
        Some(other) => other,
    };
    // Normalize a single object into a one-element list.
    let blocks: Vec<Value> = match content {
        Value::Array(items) => items.clone(),
        Value::Object(_) => vec![content.clone()],
        other => return (python_json_dumps(other), 0),
    };
    let mut texts: Vec<String> = Vec::new();
    let mut images: u64 = 0;
    for block in &blocks {
        let Some(obj) = block.as_object() else {
            // Non-dict element: str(block). For a JSON string that is the raw
            // string; otherwise the compact python repr length is dominated by
            // the same characters, so a json-length proxy is used.
            match block {
                Value::String(s) => texts.push(s.clone()),
                other => texts.push(python_json_dumps(other)),
            }
            continue;
        };
        let bt = obj.get("type").and_then(Value::as_str).unwrap_or("");
        if matches!(bt, "image" | "input_image" | "output_image") {
            images += 1;
            continue;
        }
        if matches!(bt, "text" | "input_text" | "output_text") {
            if let Some(Value::String(t)) = obj.get("text") {
                texts.push(t.clone());
            }
            continue;
        }
        // tool_reference / unknown structured sub-block -> serialize as text.
        texts.push(python_json_dumps(block));
    }
    (texts.join("\n"), images)
}

// -------------------------------------------------------------------------
// Residency model (ported 1:1).
// -------------------------------------------------------------------------

/// residency_multiplier(L) = number of assistant/model turns strictly after L
/// and strictly before the next compaction boundary.
struct ResidencyModel {
    assistant: Vec<usize>,
    compaction: Vec<usize>,
}

impl ResidencyModel {
    fn new(mut assistant: Vec<usize>, mut compaction: Vec<usize>) -> Self {
        assistant.sort_unstable();
        compaction.sort_unstable();
        Self {
            assistant,
            compaction,
        }
    }

    fn multiplier(&self, ordinal: usize) -> u64 {
        // next compaction boundary strictly after this ordinal (cap).
        let ci = self.compaction.partition_point(|&x| x <= ordinal);
        let cap = self.compaction.get(ci).copied();
        // assistant turns with ordinal in (L, cap).
        let lo = self.assistant.partition_point(|&x| x <= ordinal);
        let hi = match cap {
            Some(c) => self.assistant.partition_point(|&x| x < c),
            None => self.assistant.len(),
        };
        hi.saturating_sub(lo) as u64
    }
}

// -------------------------------------------------------------------------
// Category classifiers (ported 1:1).
// -------------------------------------------------------------------------

fn cc_tool_category(name: &str, file_path: &str) -> Category {
    if name == "Bash" {
        return Category::ShellOutput;
    }
    if name == "Read" || name == "NotebookRead" {
        return classify_by_read_path(file_path);
    }
    if name == "Task" || name == "Agent" {
        return Category::AgentResults;
    }
    if name == "WebFetch" || name == "WebSearch" {
        return Category::WebFetchSearch;
    }
    let low = name.to_ascii_lowercase();
    if low.contains("browser")
        || low.contains("chrome")
        || low.contains("computer")
        || low.starts_with("preview_")
        || low.contains("screenshot")
    {
        return Category::BrowserAndImages;
    }
    Category::OtherTools
}

fn codex_tool_category(name: &str) -> Category {
    let low = name.to_ascii_lowercase();
    let shell_names = [
        "exec",
        "shell",
        "local_shell",
        "bash",
        "shell_command",
        "container.exec",
        "run_command",
        "wait",
        "write_stdin",
        "read_stdout",
        "kill",
        "kill_command",
    ];
    if shell_names.contains(&low.as_str()) || low.contains("exec") || low.contains("shell") {
        return Category::ShellOutput;
    }
    if low.contains("web") || low.contains("search") || low.contains("fetch") {
        return Category::WebFetchSearch;
    }
    if low.contains("browser") || low.contains("computer") || low.contains("screenshot") {
        return Category::BrowserAndImages;
    }
    if low.contains("agent") || low == "spawn_agent" {
        return Category::AgentResults;
    }
    if low == "read_file" || low == "view" || low == "read" {
        return Category::CodeReads;
    }
    Category::OtherTools
}

fn codex_mcp_category(invocation: Option<&Value>) -> Category {
    let Some(obj) = invocation.and_then(Value::as_object) else {
        return Category::OtherTools;
    };
    let server = obj.get("server").and_then(Value::as_str).unwrap_or("");
    let tool = obj.get("tool").and_then(Value::as_str).unwrap_or("");
    let ident = format!("{server} {tool}").to_ascii_lowercase();
    let any = |keys: &[&str]| keys.iter().any(|k| ident.contains(k));
    if any(&[
        "chrome",
        "browser",
        "playwright",
        "screenshot",
        "dom_snapshot",
        "domsnapshot",
    ]) {
        Category::BrowserAndImages
    } else if any(&["web", "search", "fetch"]) {
        Category::WebFetchSearch
    } else if any(&["repl", "exec", "shell", "node", "python", "js"]) {
        Category::ShellOutput
    } else if ident.contains("agent") {
        Category::AgentResults
    } else {
        Category::OtherTools
    }
}

/// Extract the content an MCP call injected into context (result only, NOT the
/// model's invocation arguments).
fn codex_mcp_result_text_and_images(result: Option<&Value>) -> (String, u64) {
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

fn codex_output_text_and_images(output: Option<&Value>) -> (String, u64) {
    match output {
        Some(Value::String(s)) => (s.clone(), 0),
        other => extract_blocks_text_and_images(other),
    }
}

// -------------------------------------------------------------------------
// Per-workspace accumulator.
// -------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Bucket {
    events: u64,
    tokens: u64,
    residency: u64,
    images: u64,
}

impl Bucket {
    fn add(&mut self, tokens: u64, mult: u64, images: u64) {
        self.events += 1;
        self.tokens += tokens;
        self.residency += tokens * mult;
        self.images += images;
    }
}

#[derive(Clone)]
struct FileAgg {
    category: Category,
    events: u64,
    tokens: u64,
    last_accessed: Option<OffsetDateTime>,
}

#[derive(Default, Clone)]
struct SessionAgg {
    cat_tokens: [u64; 10],
    total: u64,
    started_at: Option<OffsetDateTime>,
}

/// Inclusive `[floor, today]` window (UTC dates). Events outside are dropped so
/// the captured window never exceeds the backend's 92-day cap.
#[derive(Clone, Copy)]
pub(crate) struct DateWindow {
    floor: Date,
    today: Date,
}

impl DateWindow {
    fn current() -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            floor: (now - time::Duration::days(MAX_WINDOW_DAYS - 1)).date(),
            today: now.date(),
        }
    }

    fn contains(&self, date: Date) -> bool {
        date >= self.floor && date <= self.today
    }
}

pub(crate) struct WorkspaceReport {
    window: DateWindow,
    daily: BTreeMap<(Date, Category), Bucket>,
    files: BTreeMap<String, FileAgg>,
    sessions: BTreeMap<String, SessionAgg>,
}

impl WorkspaceReport {
    pub(crate) fn new(window: DateWindow) -> Self {
        Self {
            window,
            daily: BTreeMap::new(),
            files: BTreeMap::new(),
            sessions: BTreeMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        session_id: &str,
        category: Category,
        tokens: u64,
        mult: u64,
        images: u64,
        file_path: Option<&str>,
        date: Date,
        ts: Option<OffsetDateTime>,
    ) {
        if !self.window.contains(date) {
            return;
        }
        self.daily
            .entry((date, category))
            .or_default()
            .add(tokens, mult, images);
        if let Some(fp) = file_path {
            let entry = self.files.entry(fp.to_string()).or_insert(FileAgg {
                category,
                events: 0,
                tokens: 0,
                last_accessed: None,
            });
            entry.category = category;
            entry.events += 1;
            entry.tokens += tokens;
            if let Some(ts) = ts {
                entry.last_accessed = Some(match entry.last_accessed {
                    Some(existing) if existing >= ts => existing,
                    _ => ts,
                });
            }
        }
        let session = self.sessions.entry(session_id.to_string()).or_default();
        session.cat_tokens[category.index()] += tokens;
        session.total += tokens;
    }

    fn note_session_start(&mut self, session_id: &str, ts: Option<OffsetDateTime>) {
        let Some(ts) = ts else { return };
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.started_at = Some(match session.started_at {
                Some(existing) if existing <= ts => existing,
                _ => ts,
            });
        }
    }

    /// Test-only view of a category's totals summed across every day.
    #[cfg(test)]
    fn category_totals(&self, category: Category) -> (u64, u64, u64, u64) {
        let mut out = (0, 0, 0, 0);
        for ((_, cat), bucket) in &self.daily {
            if *cat == category {
                out.0 += bucket.events;
                out.1 += bucket.tokens;
                out.2 += bucket.residency;
                out.3 += bucket.images;
            }
        }
        out
    }
}

// -------------------------------------------------------------------------
// Line timestamp / date helpers.
// -------------------------------------------------------------------------

fn parse_timestamp(value: &Value) -> Option<OffsetDateTime> {
    let text = value
        .get("timestamp")
        .and_then(Value::as_str)
        .or_else(|| value.get("ts").and_then(Value::as_str))?;
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(|dt| dt.to_offset(UtcOffset::UTC))
}

/// The UTC date to bucket a line under, and its parsed timestamp. Falls back to
/// the transcript file's date when the line carries no parseable timestamp.
fn line_date(value: &Value, fallback: Date) -> (Date, Option<OffsetDateTime>) {
    match parse_timestamp(value) {
        Some(ts) => (ts.date(), Some(ts)),
        None => (fallback, None),
    }
}

fn date_ymd(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

fn iso_utc(ts: OffsetDateTime) -> String {
    ts.to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
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
    out
}

// -------------------------------------------------------------------------
// Claude Code parsing (ported 1:1 from the reference).
// -------------------------------------------------------------------------

enum LastAssistantId {
    Sentinel,
    Value(Option<String>),
}

pub(crate) fn parse_claude_session(
    path: &Path,
    report: &mut WorkspaceReport,
    fallback: Date,
    include_subagents: bool,
) {
    let lines = read_jsonl(path);
    if lines.is_empty() {
        return;
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
            return;
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
}

// -------------------------------------------------------------------------
// Codex parsing (ported 1:1 from the reference).
// -------------------------------------------------------------------------

pub(crate) fn parse_codex_session(path: &Path, report: &mut WorkspaceReport, fallback: Date) {
    let lines = read_jsonl(path);
    if lines.is_empty() {
        return;
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
}

fn is_truthy_json(value: &Value) -> bool {
    match value {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|v| v != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Null => false,
    }
}

fn basename(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("session")
        .to_string()
}

fn basename_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or("session")
        .to_string()
}

// -------------------------------------------------------------------------
// Payload contract (serialized to /api/v1/context-composition/snapshot).
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
struct DailyAggregate {
    date: String,
    category: String,
    events: u64,
    tokens_entered_est: u64,
    residency_weighted_tokens_est: u64,
    image_count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct FileInput {
    relative_path_or_name: String,
    category: String,
    events: u64,
    tokens_entered_est: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_accessed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct SessionInput {
    session_id_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<String>,
    total_tokens_entered_est: u64,
    top_category: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct ContextCompositionIngestRequest {
    agent_source: String,
    machine_id: String,
    workspace_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_identity_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_kind: Option<String>,
    config_hash: String,
    window_start: String,
    window_end: String,
    bucket_timezone: String,
    captured_at: String,
    collector_version: String,
    counter_source: String,
    daily_aggregates: Vec<DailyAggregate>,
    top_files: Vec<FileInput>,
    sessions: Vec<SessionInput>,
}

/// Make a transcript-referenced path safe for the aggregate payload: strip the
/// workspace prefix to a repo-relative path, else reduce to a bare basename.
/// Returns `None` when even the basename would leak a path/secret.
fn to_relative_or_name(workspace: &Path, raw: &str) -> Option<String> {
    let candidate = Path::new(raw)
        .strip_prefix(workspace)
        .ok()
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .filter(|rel| !rel.is_empty())
        .or_else(|| {
            Path::new(raw)
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_string)
        })?;
    if candidate.starts_with('/')
        || candidate.starts_with('~')
        || candidate.starts_with('\\')
        || candidate.contains("..")
        || candidate.contains(":/")
        || candidate.contains(":\\")
    {
        return None;
    }
    // Reuse the footprint secret/path guard; require the value to survive it.
    let safe = safe_text(&candidate, 512)?;
    if safe != candidate {
        // safe_text collapses internal whitespace; a name that changed under
        // normalization is suspicious, keep the normalized form only if it is
        // still a plain relative token.
        if safe.starts_with('/') || safe.contains("..") {
            return None;
        }
    }
    Some(safe.chars().take(512).collect())
}

fn top_category(session: &SessionAgg) -> Category {
    let mut best = Category::OtherTools;
    let mut best_tokens = 0u64;
    let mut first = true;
    for cat in Category::ALL {
        let tokens = session.cat_tokens[cat.index()];
        if first || tokens > best_tokens {
            best = cat;
            best_tokens = tokens;
            first = false;
        }
    }
    best
}

fn build_daily_aggregates(report: &WorkspaceReport) -> Vec<DailyAggregate> {
    report
        .daily
        .iter()
        .filter(|(_, bucket)| bucket.events > 0)
        .map(|((date, category), bucket)| DailyAggregate {
            date: date_ymd(*date),
            category: category.as_str().to_string(),
            events: bucket.events,
            tokens_entered_est: bucket.tokens,
            residency_weighted_tokens_est: bucket.residency,
            image_count: bucket.images,
        })
        .collect()
}

fn build_top_files(report: &WorkspaceReport, workspace: &Path) -> Vec<FileInput> {
    let mut files: Vec<FileInput> = report
        .files
        .iter()
        .filter_map(|(path, agg)| {
            let name = to_relative_or_name(workspace, path)?;
            Some(FileInput {
                relative_path_or_name: name,
                category: agg.category.as_str().to_string(),
                events: agg.events,
                tokens_entered_est: agg.tokens,
                last_accessed_at: agg.last_accessed.map(iso_utc),
            })
        })
        .collect();
    files.sort_by(|a, b| {
        b.tokens_entered_est
            .cmp(&a.tokens_entered_est)
            .then_with(|| a.relative_path_or_name.cmp(&b.relative_path_or_name))
    });
    files.truncate(MAX_TOP_FILES);
    files
}

fn build_sessions(report: &WorkspaceReport) -> Vec<SessionInput> {
    let mut sessions: Vec<SessionInput> = report
        .sessions
        .iter()
        .filter(|(_, agg)| agg.total > 0)
        .map(|(sid, agg)| SessionInput {
            session_id_hash: format!("sha256:{}", sha256_hex(&[sid.as_str()])),
            started_at: agg.started_at.map(iso_utc),
            total_tokens_entered_est: agg.total,
            top_category: top_category(agg).as_str().to_string(),
        })
        .collect();
    sessions.sort_by(|a, b| {
        b.total_tokens_entered_est
            .cmp(&a.total_tokens_entered_est)
            .then_with(|| a.session_id_hash.cmp(&b.session_id_hash))
    });
    sessions.truncate(MAX_SESSIONS);
    sessions
}

/// Stable per-collector configuration fingerprint. Footprint's own
/// `config_hash` is a `/context` content hash that cannot be reproduced without
/// running the CLI, so composition uses a methodology fingerprint; the
/// join-relevant identity (machine_id, workspace_hash, repository_hash, labels)
/// is computed identically to footprint.
fn composition_config_hash(agent_source: &str) -> String {
    let categories = Category::ALL
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let descriptor = format!(
        "chars_per_token={CHARS_PER_TOKEN};image_nominal={IMAGE_NOMINAL_TOKENS};bucket_tz={BUCKET_TIMEZONE};categories={categories}"
    );
    sha256_hex(&[COUNTER_SOURCE, agent_source, COLLECTOR_VERSION, &descriptor])
}

fn build_request(
    report: &WorkspaceReport,
    workspace: &Path,
    machine_id: &str,
    agent_source: &str,
    labels_enabled: bool,
) -> Option<ContextCompositionIngestRequest> {
    let daily_aggregates = build_daily_aggregates(report);
    if daily_aggregates.is_empty() {
        return None;
    }
    let dates: Vec<Date> = report.daily.keys().map(|(date, _)| *date).collect();
    let window_start = *dates.iter().min()?;
    let window_end = *dates.iter().max()?;

    let workspace_text = workspace.to_string_lossy();
    let workspace_hash = sha256_hex(&[workspace_text.as_ref()]);
    let identity: RepositoryIdentity = resolve_repository_identity(workspace, labels_enabled);

    // The workspace label mirrors the repository name for a repository-scoped
    // capture; fall back to the directory name otherwise.
    let (workspace_label_value, workspace_label_source) = if !labels_enabled {
        (None, None)
    } else if let Some(repo_label) = identity.repository_label.clone() {
        (Some(repo_label), Some("repository".to_string()))
    } else {
        (
            workspace_label(workspace),
            Some("directory_name".to_string()),
        )
    };

    Some(ContextCompositionIngestRequest {
        agent_source: agent_source.to_string(),
        machine_id: machine_id.to_string(),
        workspace_hash,
        workspace_label: workspace_label_value,
        workspace_label_source,
        repository_hash: identity.repository_hash,
        repository_label: identity.repository_label,
        repository_label_source: identity.repository_label_source,
        repository_identity_source: identity.repository_identity_source,
        workspace_kind: identity.workspace_kind,
        config_hash: composition_config_hash(agent_source),
        window_start: date_ymd(window_start),
        window_end: date_ymd(window_end),
        bucket_timezone: BUCKET_TIMEZONE.to_string(),
        captured_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        collector_version: COLLECTOR_VERSION.to_string(),
        counter_source: COUNTER_SOURCE.to_string(),
        daily_aggregates,
        top_files: build_top_files(report, workspace),
        sessions: build_sessions(report),
    })
}

// -------------------------------------------------------------------------
// Discovery.
// -------------------------------------------------------------------------

#[derive(Clone)]
struct WorkspaceScan {
    workspace: PathBuf,
    files: Vec<(PathBuf, SystemTime)>,
    last_seen: SystemTime,
}

fn discover_workspaces(root_dir: &Path, now: SystemTime) -> Vec<WorkspaceScan> {
    let mut files = Vec::new();
    collect_recent_jsonl_files(root_dir, now, &mut files);
    files.sort_by_key(|item| std::cmp::Reverse(item.1));

    // Map each transcript to a single workspace (its first resolvable cwd).
    let mut by_cwd: BTreeMap<String, WorkspaceScan> = BTreeMap::new();
    for (file, mtime) in files {
        let Some(cwd) = cwd_values_from_jsonl(&file).into_iter().find(|cwd| {
            let path = Path::new(cwd);
            path.is_dir()
        }) else {
            continue;
        };
        let entry = by_cwd.entry(cwd.clone()).or_insert_with(|| WorkspaceScan {
            workspace: PathBuf::from(&cwd),
            files: Vec::new(),
            last_seen: mtime,
        });
        entry.files.push((file, mtime));
        if entry.last_seen < mtime {
            entry.last_seen = mtime;
        }
    }

    // Collapse cwds that share a repository scope onto the most-recent
    // representative workspace, matching footprint's dedupe so identities line
    // up. All the scope's transcripts are aggregated into that one snapshot.
    let mut by_scope: BTreeMap<String, WorkspaceScan> = BTreeMap::new();
    for (_, scan) in by_cwd {
        let identity = resolve_repository_identity(&scan.workspace, false);
        let fallback = scan.workspace.to_string_lossy();
        let scope = identity
            .repository_hash
            .unwrap_or_else(|| sha256_hex(&[fallback.as_ref()]));
        match by_scope.get_mut(&scope) {
            Some(existing) => {
                existing.files.extend(scan.files.iter().cloned());
                if existing.last_seen < scan.last_seen {
                    existing.last_seen = scan.last_seen;
                    existing.workspace = scan.workspace.clone();
                }
            }
            None => {
                by_scope.insert(scope, scan);
            }
        }
    }

    let mut out: Vec<WorkspaceScan> = by_scope.into_values().collect();
    out.sort_by_key(|scan| std::cmp::Reverse(scan.last_seen));
    out.truncate(MAX_WORKSPACES_PER_CYCLE);
    out
}

fn file_date(mtime: SystemTime) -> Date {
    OffsetDateTime::from(mtime).to_offset(UtcOffset::UTC).date()
}

fn build_report_for_scan(
    scan: &WorkspaceScan,
    agent_source: SnapshotSource,
    window: DateWindow,
    deadline: Instant,
) -> WorkspaceReport {
    let mut report = WorkspaceReport::new(window);
    for (file, mtime) in &scan.files {
        if Instant::now() >= deadline {
            break;
        }
        if fs::metadata(file)
            .map(|m| m.len() > MAX_TRANSCRIPT_BYTES)
            .unwrap_or(false)
        {
            continue;
        }
        let fallback = file_date(*mtime);
        match agent_source {
            SnapshotSource::ClaudeCode => parse_claude_session(file, &mut report, fallback, true),
            SnapshotSource::Codex => parse_codex_session(file, &mut report, fallback),
            _ => {}
        }
    }
    report
}

// -------------------------------------------------------------------------
// Incremental watermark + upload cache.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompositionCacheEntry {
    identity: String,
    agent_source: String,
    files: BTreeMap<String, i64>,
    payload_sha256: String,
    posted_at: String,
}

fn workspace_files_signature(files: &[(PathBuf, SystemTime)]) -> BTreeMap<String, i64> {
    let mut sig = BTreeMap::new();
    for (path, mtime) in files {
        let secs = mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        sig.insert(path.to_string_lossy().to_string(), secs);
    }
    sig
}

/// A workspace is rescanned when there is no cache for it, the destination or
/// agent changed, any transcript's mtime changed (the watermark), or the cached
/// upload is older than the staleness bound.
fn should_rescan(
    cache: Option<&CompositionCacheEntry>,
    identity: &str,
    agent_source: &str,
    signature: &BTreeMap<String, i64>,
    now: OffsetDateTime,
) -> bool {
    let Some(cache) = cache else {
        return true;
    };
    if cache.identity != identity || cache.agent_source != agent_source {
        return true;
    }
    if &cache.files != signature {
        return true;
    }
    cache_is_stale(cache, now)
}

fn cache_is_stale(entry: &CompositionCacheEntry, now: OffsetDateTime) -> bool {
    let Ok(posted) = OffsetDateTime::parse(&entry.posted_at, &Rfc3339) else {
        return true;
    };
    (now - posted).whole_seconds() >= CONTEXT_MAX_STALENESS_SECS
}

/// Content hash over the stable fields (excludes the volatile `captured_at`).
fn request_content_hash(request: &ContextCompositionIngestRequest) -> Result<String> {
    let canonical = serde_json::to_vec(&json!({
        "cache_schema": "context_composition_request_v1",
        "agent_source": &request.agent_source,
        "machine_id": &request.machine_id,
        "workspace_hash": &request.workspace_hash,
        "workspace_label": &request.workspace_label,
        "workspace_label_source": &request.workspace_label_source,
        "repository_hash": &request.repository_hash,
        "repository_label": &request.repository_label,
        "repository_label_source": &request.repository_label_source,
        "repository_identity_source": &request.repository_identity_source,
        "workspace_kind": &request.workspace_kind,
        "config_hash": &request.config_hash,
        "window_start": &request.window_start,
        "window_end": &request.window_end,
        "bucket_timezone": &request.bucket_timezone,
        "collector_version": &request.collector_version,
        "counter_source": &request.counter_source,
        "daily_aggregates": &request.daily_aggregates,
        "top_files": &request.top_files,
        "sessions": &request.sessions,
    }))
    .map_err(|error| anyhow!("hash encode failed: {error}"))?;
    Ok(sha256_bytes(&canonical))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn cache_path(support_dir: &Path, agent_source: &str, workspace_hash: &str) -> PathBuf {
    support_dir
        .join("context_composition")
        .join(format!("{agent_source}-{workspace_hash}.json"))
}

fn read_cache(path: &Path) -> Option<CompositionCacheEntry> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_cache(path: &Path, entry: &CompositionCacheEntry) {
    let Some(dir) = path.parent() else {
        return;
    };
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let Ok(payload) = serde_json::to_vec(entry) else {
        return;
    };
    let temp = path.with_extension("json.tmp");
    if fs::write(&temp, &payload).is_ok() {
        let _ = fs::rename(&temp, path);
    }
}

// -------------------------------------------------------------------------
// Harvest loop.
// -------------------------------------------------------------------------

pub fn spawn_context_composition_sync() -> Result<()> {
    let home = crate::snapshot_sync::home_dir()?;
    let support_dir = default_support_dir();
    std::thread::Builder::new()
        .name("ottto-context-composition-sync".to_string())
        .spawn(move || loop {
            if let Err(error) = harvest_all_once(&home, &support_dir) {
                eprintln!(
                    "context composition harvest skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            std::thread::sleep(CONTEXT_COMPOSITION_INTERVAL);
        })
        .map_err(|error| anyhow!("spawn context composition sync: {error}"))?;
    Ok(())
}

fn harvest_all_once(home: &Path, support_dir: &Path) -> Result<()> {
    if local_harvest_disabled(support_dir) {
        return Ok(());
    }
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = crate::snapshot_sync::snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = crate::snapshot_sync::snapshot_api_base_url();
    let client = SnapshotApiClient::new(api_base_url.clone());
    let enabled = crate::snapshot_sync::enabled_snapshot_sources(&device);

    let mut any_source = false;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        if !enabled.contains(&source) {
            continue;
        }
        any_source = true;
        if let Err(error) = harvest_source(
            &client,
            &device,
            &device_secret,
            &machine_id,
            &api_base_url,
            home,
            support_dir,
            source,
        ) {
            eprintln!(
                "context composition harvest skipped for {}: {}",
                agent_source_label(source),
                crate::snapshot_sync::safe_error(&error)
            );
        }
    }
    let _ = any_source;
    Ok(())
}

fn agent_source_label(source: SnapshotSource) -> &'static str {
    match source {
        SnapshotSource::ClaudeCode => "claude-code",
        SnapshotSource::Codex => "codex",
        _ => "unknown",
    }
}

#[allow(clippy::too_many_arguments)]
fn harvest_source(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    machine_id: &str,
    api_base_url: &str,
    home: &Path,
    support_dir: &Path,
    source: SnapshotSource,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let identity = destination_identity(device, machine_id, api_base_url);
    let marker = org_disabled_marker_path(support_dir, source);

    // Reuse the shared context-harvest activity gate: the backend resolves the
    // full opt-out cascade behind `context_footprint_harvest_enabled`.
    let labels_enabled = match client.get_activity_hint(&relay_token) {
        Ok(hint) => {
            if !hint.context_footprint_harvest_enabled {
                write_marker(&marker, &identity);
                return Ok(());
            }
            let _ = fs::remove_file(&marker);
            hint.workspace_labels_enabled
        }
        Err(_) if read_marker(&marker).as_deref() == Some(identity.as_str()) => return Ok(()),
        Err(_) => true,
    };

    let now = SystemTime::now();
    let root_dir = match source {
        SnapshotSource::ClaudeCode => home.join(".claude").join("projects"),
        SnapshotSource::Codex => home.join(".codex").join("sessions"),
        _ => return Ok(()),
    };
    let workspaces = discover_workspaces(&root_dir, now);
    if workspaces.is_empty() {
        return Ok(());
    }

    let window = DateWindow::current();
    let deadline = Instant::now() + CONTEXT_COMPOSITION_CYCLE_BUDGET;
    let agent_source = agent_source_label(source);
    let mut uploaded = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    for scan in workspaces {
        if Instant::now() >= deadline {
            break;
        }
        let workspace_text = scan.workspace.to_string_lossy();
        let workspace_hash = sha256_hex(&[workspace_text.as_ref()]);
        let signature = workspace_files_signature(&scan.files);
        let path = cache_path(support_dir, agent_source, &workspace_hash);
        let cache = read_cache(&path);
        let now_dt = OffsetDateTime::now_utc();
        if !should_rescan(cache.as_ref(), &identity, agent_source, &signature, now_dt) {
            skipped += 1;
            continue;
        }

        let report = build_report_for_scan(&scan, source, window, deadline);
        let Some(request) = build_request(
            &report,
            &scan.workspace,
            machine_id,
            agent_source,
            labels_enabled,
        ) else {
            skipped += 1;
            continue;
        };

        let payload_sha = match request_content_hash(&request) {
            Ok(hash) => hash,
            Err(error) => {
                failed += 1;
                eprintln!(
                    "context composition hash failed for workspace_hash={workspace_hash}: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
                continue;
            }
        };

        let unchanged_payload = cache
            .as_ref()
            .map(|c| {
                c.identity == identity
                    && c.agent_source == agent_source
                    && c.payload_sha256 == payload_sha
                    && !cache_is_stale(c, now_dt)
            })
            .unwrap_or(false);

        if !unchanged_payload {
            let payload = match serde_json::to_value(&request) {
                Ok(value) => value,
                Err(error) => {
                    failed += 1;
                    eprintln!(
                        "context composition encode failed for workspace_hash={workspace_hash}: {error}"
                    );
                    continue;
                }
            };
            if let Err(error) = client.upload_context_composition(&relay_token, &payload) {
                failed += 1;
                eprintln!(
                    "context composition upload skipped for workspace_hash={workspace_hash}: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
                continue;
            }
            uploaded += 1;
        } else {
            skipped += 1;
        }

        write_cache(
            &path,
            &CompositionCacheEntry {
                identity: identity.clone(),
                agent_source: agent_source.to_string(),
                files: signature,
                payload_sha256: payload_sha,
                posted_at: now_dt.format(&Rfc3339).unwrap_or_default(),
            },
        );
    }

    eprintln!(
        "context_composition_harvest_metrics source={agent_source} discovered={} uploaded={uploaded} skipped={skipped} failed={failed}",
        uploaded + skipped + failed
    );
    if failed > 0 && uploaded == 0 && skipped == 0 {
        return Err(anyhow!(
            "context composition harvest failed for all workspaces"
        ));
    }
    Ok(())
}

fn local_harvest_disabled(support_dir: &Path) -> bool {
    if std::env::var(LOCAL_DISABLE_ENV)
        .map(|value| is_truthy(&value))
        .unwrap_or(false)
    {
        return true;
    }
    support_dir
        .join("context_composition")
        .join("disabled")
        .exists()
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn destination_identity(
    device: &LocalDeviceBinding,
    machine_id: &str,
    api_base_url: &str,
) -> String {
    format!("{}|{}|{}", device.device_id, machine_id, api_base_url)
}

fn org_disabled_marker_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("context_composition")
        .join(format!("org_disabled-{}", agent_source_label(source)))
}

fn read_marker(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn write_marker(path: &Path, identity: &str) {
    if let Some(dir) = path.parent() {
        if fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    let _ = fs::write(path, identity.as_bytes());
}

#[cfg(test)]
mod tests;
