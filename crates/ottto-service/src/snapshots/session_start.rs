//! Session-start facts (`SnapshotItem.session_start`): what a fresh session
//! sent in its first request and what it read in its opening window
//! (requests 1-3).
//!
//! Computed inline from transcript lines the snapshot parser already decodes:
//! zero extra reads, no job, no cache. The window freezes at request 3; after
//! that each line costs one branch. The value is a pure function of the
//! transcript bytes (plus the device salt and the tenant attribution key), so
//! it is computed for any session the daemon parses and a reparse reproduces
//! it. It stays outside content, fingerprint and witness identity, so no bump
//! forces a republish.
//!
//! Units: every `chars` field counts UTF-16 code units, the unit of the
//! instruction-file counts (`context_file_counts`). The backend owns the
//! character-to-token ratios.
//!
//! Privacy: lengths, counts and the identity of files the injected
//! instructions name or the client itself loaded. Repo-relative paths follow
//! workspace-label consent; every other path travels as the tenant attribution
//! HMAC and follows attribution consent. No text leaves the Mac.

use super::UsageTotals;
use crate::codex_prelude;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

pub(crate) const MAX_OPENING_FILES: usize = 64;
/// Retained capacity of the whole in-window state, charged with the daemon's
/// heap model (`heap_layout_bound`). Held instruction text (for path matching,
/// 2x the largest seen) gets half; tracked files, calls, blobs and their keys
/// share the other half, less 1 KiB for the inline state and small strings.
/// Over budget a file only counts, a call goes unattributed and request 1's
/// parts become unmeasurable.
const MAX_HELD_BYTES: usize = 256 * 1024;
const MAX_HELD_INSTRUCTION_BYTES: usize = MAX_HELD_BYTES / 2;
const MAX_HELD_COLLECTION_BYTES: usize = MAX_HELD_BYTES - MAX_HELD_INSTRUCTION_BYTES - 1024;
const MAX_SHELL_PATH_TOKENS: usize = 16;
const MAX_PATH_BYTES: usize = 512;
/// Tool call ids are short; a longer one is not tracked.
const MAX_CALL_ID_BYTES: usize = 256;
const MAX_TOOL_LABEL_CHARS: usize = 64;
const WINDOW_REQUESTS: usize = 3;
/// Claude Code appends this line to the request-1 auto-memory entry when it
/// loaded only part of MEMORY.md.
const MEMORY_CUT_MARKER: &str = "> WARNING: MEMORY.md is";
const CLAUDE_INSTRUCTIONS_PREFIX: &str = "<system-reminder>\nCodebase and user instructions";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Tools,
    System,
    Instructions,
    Memory,
    Skills,
    Agents,
    McpNames,
    McpInstructions,
    HooksEnv,
    Prompt,
    Other,
}
const PARTS: usize = 11;

impl Part {
    /// "Yours": the configuration text a user controls. Feeds the start
    /// configuration fingerprint.
    fn is_config(self) -> bool {
        matches!(
            self,
            Part::Instructions
                | Part::Memory
                | Part::Skills
                | Part::Agents
                | Part::McpNames
                | Part::McpInstructions
        )
    }
}

/// Section headers of Claude Code's request-1 system blob, in any order. Each
/// starts a line.
const CLAUDE_SYSTEM_SECTIONS: [(&str, Part); 7] = [
    ("# Environment", Part::HooksEnv),
    ("The following deferred tools", Part::McpNames),
    ("Available agent types", Part::Agents),
    ("The following skills are available", Part::Skills),
    ("While bypass permissions mode", Part::Other),
    ("# MCP Server Instructions", Part::McpInstructions),
    ("<total_tokens>", Part::Other),
];
/// Written mid-line (`SessionStart hook additional context: ...`).
const CLAUDE_HOOK_SECTION: &str = "hook additional context";

fn units(text: &str) -> u64 {
    // ASCII, the common case, is one unit per byte; `is_ascii` is vectorized.
    if text.is_ascii() {
        text.len() as u64
    } else {
        text.encode_utf16().count() as u64
    }
}

/// UTF-16 units of `value` serialized with Python `json.dumps` separators
/// (`", "`, `": "`), the basis the tool-schema ratio was calibrated on. Counted
/// while serializing; nothing is allocated.
fn json_units(value: &Value) -> u64 {
    json_units_digest(value, None)
}

/// `json_units`, also folding the serialized bytes into `digest` in the same
/// pass.
fn json_units_digest(value: &Value, digest: Option<&mut ConfigDigest>) -> u64 {
    struct PythonSeparators;
    impl serde_json::ser::Formatter for PythonSeparators {
        fn begin_array_value<W: ?Sized + io::Write>(
            &mut self,
            writer: &mut W,
            first: bool,
        ) -> io::Result<()> {
            if first {
                Ok(())
            } else {
                writer.write_all(b", ")
            }
        }
        fn begin_object_key<W: ?Sized + io::Write>(
            &mut self,
            writer: &mut W,
            first: bool,
        ) -> io::Result<()> {
            if first {
                Ok(())
            } else {
                writer.write_all(b", ")
            }
        }
        fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
            writer.write_all(b": ")
        }
    }
    struct Utf16Counter<'a>(u64, Option<&'a mut ConfigDigest>);
    impl io::Write for Utf16Counter<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            for byte in bytes {
                // One unit per UTF-8 leading byte, two for a 4-byte scalar.
                if byte & 0xc0 != 0x80 {
                    self.0 += 1 + u64::from(*byte >= 0xf0);
                }
            }
            if let Some(digest) = self.1.as_deref_mut() {
                digest.update(bytes);
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Utf16Counter(0, digest);
    let mut serializer = serde_json::Serializer::with_formatter(&mut counter, PythonSeparators);
    let _ = value.serialize(&mut serializer);
    counter.0
}

/// Running digest of the configuration text: stable across builds and
/// platforms, word-at-a-time (SHA-256 in software would dominate the opening
/// cost). Change detection only; the wire value is the device-salted SHA-256
/// of this digest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ConfigDigest {
    a: u64,
    b: u64,
    len: u64,
}

impl ConfigDigest {
    fn mix(&mut self, word: u64) {
        self.a = (self.a ^ word)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(29);
        self.b = (self.b.rotate_left(17) ^ word).wrapping_mul(0xc2b2_ae3d_27d4_eb4f);
    }

    /// One block; block boundaries are part of the digest.
    fn update(&mut self, bytes: &[u8]) {
        let mut words = bytes.chunks_exact(8);
        for word in &mut words {
            self.mix(u64::from_le_bytes(word.try_into().expect("8-byte chunk")));
        }
        let rest = words.remainder();
        let mut tail = [0u8; 8];
        tail[..rest.len()].copy_from_slice(rest);
        self.mix(u64::from_le_bytes(tail) ^ ((rest.len() as u64 + 1) << 56));
        self.len = self.len.wrapping_add(bytes.len() as u64);
    }

    fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(&self.a.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.b.to_le_bytes());
        bytes[16..].copy_from_slice(&self.len.to_le_bytes());
        bytes
    }
}

fn fold_digest(digest: &mut Option<ConfigDigest>, bytes: &[u8]) {
    digest
        .get_or_insert_with(ConfigDigest::default)
        .update(bytes);
}

fn push_capped(held: &mut String, text: &str) {
    let room = MAX_HELD_INSTRUCTION_BYTES.saturating_sub(held.len() + 1);
    if room == 0 {
        return;
    }
    let mut end = text.len().min(room);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    // Exact growth: the cap bounds capacity, not only length.
    held.reserve_exact(end + 1);
    if !held.is_empty() {
        held.push('\n');
    }
    held.push_str(&text[..end]);
}

/// One B-tree node per entry, as `heap_layout_bound::tree_nodes` charges it.
fn node_bytes<V>() -> usize {
    256 + 12 * std::mem::size_of::<usize>()
        + 11 * (std::mem::size_of::<String>() + std::mem::size_of::<V>())
}

/// The empty root each map is charged even before its first entry.
fn root_bytes() -> usize {
    node_bytes::<OpeningFileState>() + node_bytes::<OpeningCall>() + node_bytes::<ClaudeBlob>()
}

fn file_bytes(key: &str, file: &OpeningFileState) -> usize {
    node_bytes::<OpeningFileState>()
        + key.len()
        + file.tool.capacity()
        + file.repo_path.as_ref().map_or(0, String::capacity)
}

fn call_bytes(id: &str, call: &OpeningCall) -> usize {
    node_bytes::<OpeningCall>()
        + id.len()
        + call.tool.capacity()
        + call.files.capacity() * std::mem::size_of::<String>()
        + call.files.iter().map(String::capacity).sum::<usize>()
}

fn blob_bytes(hash: &str) -> usize {
    node_bytes::<ClaudeBlob>() + hash.len()
}

fn is_client_version(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

/// Raw client tool name; MCP tools collapse to `mcp` (their server and tool
/// names already travel through the activity counters).
fn tool_label(name: &str) -> String {
    if name.starts_with("mcp__") {
        "mcp".to_string()
    } else {
        name.chars().take(MAX_TOOL_LABEL_CHARS).collect()
    }
}

/// `ext` of a path's last segment: 1-8 ASCII alphanumerics after the last dot.
fn extension(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    let (_, ext) = name.rsplit_once('.')?;
    ((1..=8).contains(&ext.len()) && ext.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then_some(ext)
}

/// File-like tokens of a shell command, taken lexically (no `stat`): not a
/// flag, no URL or shell syntax, and either a path (`/`) or a file extension.
fn shell_path_tokens(command: &str) -> impl Iterator<Item = &str> {
    command
        .split(|ch: char| {
            ch.is_whitespace() || matches!(ch, ';' | '|' | '&' | '(' | ')' | '<' | '>' | '`')
        })
        .map(|token| token.trim_matches(|ch| matches!(ch, '"' | '\'' | ',')))
        .filter(|token| {
            !token.is_empty()
                && !token.starts_with('-')
                && !token.contains("://")
                && !token.contains(['*', '?', '$', '{', '}', '=', '[', ']'])
                && (token.contains('/') || extension(token).is_some())
        })
        .take(MAX_SHELL_PATH_TOKENS)
}

/// True when a shell command may change its working directory, so its
/// relative paths cannot be shown to be inside the session's checkout.
fn shell_changes_directory(command: &str) -> bool {
    // Quotes and braces split too, so `bash -lc 'cd x && ...'` is caught.
    command
        .split(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    ';' | '|' | '&' | '(' | ')' | '`' | '\'' | '"' | '{' | '}'
                )
        })
        .any(|word| {
            matches!(word, "cd" | "pushd" | "popd" | "chdir" | "-C")
                || [
                    "--directory",
                    "--git-dir",
                    "--work-tree",
                    "-chdir",
                    "--cwd",
                    "--prefix",
                ]
                .iter()
                .any(|flag| word.starts_with(flag))
        })
}

/// A Claude response spanning several model requests (`usage.iterations[]`):
/// its counters are not request 1's and later ordinals shift.
fn claude_multi_request(value: &Value) -> bool {
    super::claude_code_usage_root(value)
        .and_then(|usage| usage.get("iterations"))
        .and_then(Value::as_array)
        .is_some_and(|iterations| iterations.len() > 1)
}

fn is_repo_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('~')
        && !path.split('/').any(|segment| segment == "..")
}

/// `(key, repo-relative path)`: the key is the repo-relative path when the file
/// is inside the session's working directory (a lexical prefix test), else
/// the path as written, which can only travel hashed. A relative path counts
/// as inside only when `trust_relative` (its base is the session directory).
fn normalize_path(
    raw: &str,
    cwd: Option<&Path>,
    trust_relative: bool,
) -> Option<(String, Option<String>)> {
    let raw = raw.trim();
    let raw = raw.strip_prefix("./").unwrap_or(raw);
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES {
        return None;
    }
    if raw.starts_with('/') {
        let inside = cwd
            .and_then(Path::to_str)
            .and_then(|cwd| raw.strip_prefix(cwd.trim_end_matches('/')))
            .and_then(|rest| rest.strip_prefix('/'))
            .filter(|rest| is_repo_relative(rest));
        return Some(match inside {
            Some(rest) => (rest.to_string(), Some(rest.to_string())),
            None => (raw.to_string(), None),
        });
    }
    Some((
        raw.to_string(),
        (trust_relative && is_repo_relative(raw)).then(|| raw.to_string()),
    ))
}

/// How many trailing path segments (basename, then parent/basename, ...)
/// appear verbatim in the injected instruction text, stopping at the first
/// miss. The backend owns the threshold.
fn instruction_segments(path: &str, haystack: &str) -> u8 {
    let path = path.trim_end_matches('/');
    let mut count = 0u8;
    let mut end = path.len();
    loop {
        let start = path[..end].rfind('/').map_or(0, |slash| slash + 1);
        let suffix = &path[start..];
        if suffix.is_empty() || !haystack.contains(suffix) {
            return count;
        }
        count = count.saturating_add(1);
        if start <= 1 {
            return count;
        }
        end = start - 1;
    }
}

fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// Model-visible length of a tool result: text blocks (or a plain string).
fn tool_output_units(content: Option<&Value>) -> u64 {
    match content {
        Some(Value::String(text)) => units(text),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|block| block.as_str().or_else(|| str_at(block, "text")))
            .map(units)
            .sum(),
        _ => 0,
    }
}

/// The client's own truncation record inside a Codex tool output.
fn codex_output_truncated(content: Option<&Value>) -> bool {
    // The mid-output marker carries `…`, so ASCII output cannot hold it.
    let truncated = |text: &str| {
        text.starts_with("Warning: truncated output")
            || (!text.is_ascii() && text.contains("tokens truncated\u{2026}"))
    };
    match content {
        Some(Value::String(text)) => truncated(text),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|block| block.as_str().or_else(|| str_at(block, "text")))
            .any(truncated),
        _ => false,
    }
}

/// Model-visible length of a Claude attachment: its rendered text when logged.
fn attachment_units(line: &Value, attachment: &Value) -> u64 {
    if let Some(rendered) = line.get("rendered").and_then(Value::as_array) {
        return rendered
            .iter()
            .filter_map(|block| str_at(block, "content"))
            .map(units)
            .sum();
    }
    tool_output_units(attachment.get("content"))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OpeningRequest {
    context_tokens: u64,
    uncached_input_tokens: u64,
    cache_read_tokens: u64,
    cache_write_5m_tokens: Option<u64>,
    cache_write_1h_tokens: Option<u64>,
    output_tokens: u64,
}

/// One Claude `api-request-blob`, measured on arrival so request 1 never
/// holds message text.
#[derive(Debug, Clone, Default)]
struct ClaudeBlob {
    parts: [u64; PARTS],
    unmeasurable: bool,
    config_digest: Option<ConfigDigest>,
}

#[derive(Debug, Clone, Default)]
struct OpeningCall {
    /// Response (1 or 2) that issued the call; its output arrives in the next request.
    response: u8,
    tool: String,
    candidates: u64,
    files: Vec<String>,
    answered: bool,
    truncated: bool,
}

#[derive(Debug, Clone, Default)]
struct OpeningFileState {
    ordinal: u64,
    request: u8,
    tool: String,
    repo_path: Option<String>,
    instruction_segments: u8,
    chars: u64,
    reads: u64,
    client_loaded: bool,
    truncated: bool,
}

/// Per-transcript accumulator. Everything but the counters is dropped at the
/// window freeze.
#[derive(Debug, Clone, Default)]
pub(super) struct SessionStartState {
    client_version: Option<String>,
    user_turns: u8,
    inherited_prefix: bool,
    frozen: bool,
    requests: [Option<OpeningRequest>; WINDOW_REQUESTS],
    codex_requests: u8,
    response_tool_calls: [u64; 2],
    truncated_outputs: u64,
    parts: [u64; PARTS],
    parts_closed: bool,
    parts_unmeasurable: bool,
    codex_tools_logged: bool,
    config_digest: Option<ConfigDigest>,
    claude_shape: Option<(String, u64, u64)>,
    claude_blobs: BTreeMap<String, ClaudeBlob>,
    memory_units: Option<u64>,
    instruction_load_cut: Option<bool>,
    instructions: Option<String>,
    calls: BTreeMap<String, OpeningCall>,
    last_codex_call: Option<String>,
    files: BTreeMap<String, OpeningFileState>,
    files_untracked: u64,
    /// Collection bytes charged against `MAX_HELD_COLLECTION_BYTES`.
    held_bytes: usize,
    /// A Claude Bash command changed directory; the shell keeps that cwd, so
    /// later relative shell paths are no longer known to be in the checkout.
    shell_moved: bool,
    /// An opening Claude response spanned several requests.
    collapsed_requests: bool,
}

crate::heap_layout_bound::fields!(OpeningRequest; context_tokens, uncached_input_tokens, cache_read_tokens, cache_write_5m_tokens, cache_write_1h_tokens, output_tokens);
crate::heap_layout_bound::fields!(ClaudeBlob; parts, unmeasurable, config_digest);
crate::heap_layout_bound::fields!(ConfigDigest; a, b, len);
crate::heap_layout_bound::fields!(OpeningCall; response, tool, candidates, files, answered, truncated);
crate::heap_layout_bound::fields!(OpeningFileState; ordinal, request, tool, repo_path, instruction_segments, chars, reads, client_loaded, truncated);
crate::heap_layout_bound::fields!(SessionStartState; client_version, user_turns, inherited_prefix, frozen, requests, codex_requests, response_tool_calls, truncated_outputs, parts, parts_closed, parts_unmeasurable, codex_tools_logged, config_digest, claude_shape, claude_blobs, memory_units, instruction_load_cut, instructions, calls, last_codex_call, files, files_untracked, held_bytes, shell_moved, collapsed_requests);

impl SessionStartState {
    pub(super) fn note_user_turn(&mut self) {
        self.user_turns = (self.user_turns + 1).min(2);
    }

    /// The transcript starts with records copied from another session.
    pub(super) fn note_inherited_prefix(&mut self) {
        self.inherited_prefix = true;
    }

    fn note_client_version(&mut self, version: Option<&str>) {
        if self.client_version.is_none() {
            self.client_version = version.filter(|v| is_client_version(v)).map(str::to_string);
        }
    }

    fn freeze(&mut self) {
        self.frozen = true;
        if !self.parts_closed {
            self.parts_closed = true;
            self.parts_unmeasurable = true;
        }
        self.instructions = None;
        self.calls = BTreeMap::new();
        self.claude_blobs = BTreeMap::new();
        self.claude_shape = None;
        self.last_codex_call = None;
        self.recount_held();
    }

    fn charge(&mut self, bytes: usize) -> bool {
        let held = self.held_bytes.saturating_add(bytes);
        if root_bytes().saturating_add(held) > MAX_HELD_COLLECTION_BYTES {
            return false;
        }
        self.held_bytes = held;
        true
    }

    fn recount_held(&mut self) {
        self.held_bytes = self
            .files
            .iter()
            .map(|(key, file)| file_bytes(key, file))
            .sum::<usize>()
            + self
                .calls
                .iter()
                .map(|(id, call)| call_bytes(id, call))
                .sum::<usize>()
            + self
                .claude_blobs
                .keys()
                .map(|hash| blob_bytes(hash))
                .sum::<usize>()
            + self
                .claude_shape
                .as_ref()
                .map_or(0, |(hash, _, _)| hash.capacity());
    }

    // ---- Claude Code ----------------------------------------------------

    /// One owned Claude line. `responses` = distinct responses seen so far, so
    /// content on this line arrives in request `responses + 1`.
    pub(super) fn observe_claude_line(
        &mut self,
        value: &Value,
        responses: u64,
        cwd: Option<&Path>,
    ) {
        if self.client_version.is_none() {
            self.note_client_version(str_at(value, "version"));
        }
        // Response 3 can finish after the freeze; check through it.
        if responses <= WINDOW_REQUESTS as u64
            && !self.collapsed_requests
            && claude_multi_request(value)
        {
            self.collapsed_requests = true;
        }
        if self.frozen {
            return;
        }
        if responses >= WINDOW_REQUESTS as u64 {
            self.freeze();
            return;
        }
        match str_at(value, "type") {
            Some("attachment") => {
                if let Some(attachment) = value.get("attachment") {
                    self.claude_attachment(value, attachment, responses, cwd);
                }
            }
            Some("api-request-shape") if responses == 0 && !self.parts_closed => {
                self.claude_shape(value)
            }
            Some("api-request-blob") if responses == 0 && !self.parts_closed => {
                self.claude_blob(value)
            }
            Some("api-request") if responses == 0 && !self.parts_closed => {
                self.claude_request(value)
            }
            Some("assistant") if responses >= 1 => {
                self.claude_tool_uses(value, responses as u8, cwd)
            }
            Some("user") if responses >= 1 => self.claude_tool_results(value),
            _ => {}
        }
    }

    fn claude_attachment(
        &mut self,
        line: &Value,
        attachment: &Value,
        responses: u64,
        cwd: Option<&Path>,
    ) {
        let request = responses as u8 + 1;
        match str_at(attachment, "type") {
            Some("instructions") if responses == 0 && self.memory_units.is_none() => {
                let files = attachment
                    .get("files")
                    .and_then(Value::as_array)
                    .map_or(&[][..], Vec::as_slice);
                let total = files
                    .iter()
                    .map(|file| str_at(file, "content").map_or(0, str::len) + 1)
                    .sum::<usize>();
                let mut held = String::with_capacity(total.min(MAX_HELD_INSTRUCTION_BYTES));
                let mut memory = 0;
                let mut cut = false;
                for file in files {
                    let content = str_at(file, "content").unwrap_or("");
                    if str_at(file, "type") == Some("AutoMem") {
                        memory += units(content);
                        cut |= content.contains(MEMORY_CUT_MARKER);
                    }
                    push_capped(&mut held, content);
                }
                self.instructions = Some(held);
                self.memory_units = Some(memory);
                self.instruction_load_cut = Some(cut);
            }
            Some("nested_memory") if responses >= 1 => {
                if let Some(path) = str_at(attachment, "path") {
                    let chars = attachment_units(line, attachment);
                    self.note_client_load(path, "nested_memory", chars, request, cwd);
                }
            }
            Some("hook_additional_context") if responses >= 1 => {
                // No path field: the client writes `Contents of <path>:` first.
                let path = attachment
                    .get("content")
                    .and_then(Value::as_array)
                    .and_then(|content| content.first())
                    .and_then(Value::as_str)
                    .and_then(|text| text.lines().next())
                    .and_then(|line| line.strip_prefix("Contents of "))
                    .and_then(|line| line.strip_suffix(':'));
                if let Some(path) = path {
                    let chars = attachment_units(line, attachment);
                    self.note_client_load(path, "hook_additional_context", chars, request, cwd);
                }
            }
            Some("read_truncation_notice") if responses >= 1 => {
                if let Some(id) = str_at(attachment, "toolUseID") {
                    self.note_call_truncated(id);
                }
            }
            _ => {}
        }
    }

    fn claude_shape(&mut self, value: &Value) {
        let Some(shape) = value.get("shape") else {
            return;
        };
        let system = shape
            .get("system")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|block| str_at(block, "text"))
            .map(units)
            .sum();
        let tools = shape
            .get("tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(json_units)
            .sum();
        let hash = str_at(value, "shapeHash").unwrap_or("").to_string();
        if !self.charge(hash.capacity()) {
            self.parts_unmeasurable = true;
            return;
        }
        self.claude_shape = Some((hash, system, tools));
    }

    fn claude_blob(&mut self, value: &Value) {
        let (Some(hash), Some(message)) = (str_at(value, "hash"), value.get("message")) else {
            return;
        };
        if !self.claude_blobs.contains_key(hash) && !self.charge(blob_bytes(hash)) {
            self.parts_unmeasurable = true;
            return;
        }
        let role = str_at(message, "role").unwrap_or("");
        let mut blob = ClaudeBlob {
            unmeasurable: role == "assistant",
            ..ClaudeBlob::default()
        };
        for item in message
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            match (str_at(item, "type"), str_at(item, "text")) {
                (Some("text"), Some(text)) if role == "system" => {
                    split_claude_system_text(text, &mut blob)
                }
                (Some("text"), Some(text)) => {
                    let part = if text.starts_with(CLAUDE_INSTRUCTIONS_PREFIX) {
                        Part::Instructions
                    } else if text.starts_with("<system-reminder>") {
                        Part::Other
                    } else {
                        Part::Prompt
                    };
                    blob.add(part, text);
                }
                (Some("tool_addition"), _) => {
                    let tool = item.get("tool").unwrap_or(&Value::Null);
                    let digest = blob.config_digest.get_or_insert_with(ConfigDigest::default);
                    blob.parts[Part::McpNames as usize] += json_units_digest(tool, Some(digest));
                }
                (Some("image" | "document"), _) => blob.unmeasurable = true,
                _ => blob.parts[Part::Other as usize] += json_units(item),
            }
        }
        self.claude_blobs.insert(hash.to_string(), blob);
    }

    /// The first `api-request`: request 1's tail of measured blobs.
    fn claude_request(&mut self, value: &Value) {
        self.parts_closed = true;
        let shape = self.claude_shape.take();
        let blobs = std::mem::take(&mut self.claude_blobs);
        self.recount_held();
        let tail = value.get("tail").and_then(Value::as_array);
        let (Some((shape_hash, system, tools)), Some(tail)) = (shape, tail) else {
            self.parts_unmeasurable = true;
            return;
        };
        // A `base` continues an earlier request: history was copied in.
        if value.get("base").is_some() || str_at(value, "shapeHash") != Some(shape_hash.as_str()) {
            self.parts_unmeasurable = true;
            return;
        }
        self.parts[Part::System as usize] += system;
        self.parts[Part::Tools as usize] += tools;
        for hash in tail {
            match hash.as_str().and_then(|hash| blobs.get(hash)) {
                Some(blob) if !blob.unmeasurable => {
                    for (total, part) in self.parts.iter_mut().zip(blob.parts) {
                        *total += part;
                    }
                    if let Some(digest) = blob.config_digest {
                        fold_digest(&mut self.config_digest, &digest.to_bytes());
                    }
                }
                _ => {
                    self.parts_unmeasurable = true;
                    return;
                }
            }
        }
    }

    fn claude_tool_uses(&mut self, value: &Value, response: u8, cwd: Option<&Path>) {
        let Some(content) = value.pointer("/message/content").and_then(Value::as_array) else {
            return;
        };
        for item in content {
            if str_at(item, "type") != Some("tool_use") {
                continue;
            }
            let (Some(id), Some(name)) = (str_at(item, "id"), str_at(item, "name")) else {
                continue;
            };
            if self.calls.contains_key(id) {
                continue;
            }
            let input = item.get("input").unwrap_or(&Value::Null);
            if name == "Bash" && str_at(input, "command").is_some_and(shell_changes_directory) {
                self.shell_moved = true;
            }
            let paths: Vec<&str> = match name {
                "Read" | "Edit" | "Write" | "MultiEdit" => {
                    str_at(input, "file_path").into_iter().collect()
                }
                "NotebookEdit" => str_at(input, "notebook_path").into_iter().collect(),
                "Bash" => str_at(input, "command")
                    .map(|command| shell_path_tokens(command).collect())
                    .unwrap_or_default(),
                "Grep" | "Glob" => str_at(input, "path")
                    .filter(|path| extension(path).is_some())
                    .into_iter()
                    .collect(),
                _ => Vec::new(),
            };
            self.open_call(id, response, name);
            let trust_relative = !self.shell_moved;
            self.add_call_paths(id, paths, cwd, trust_relative);
        }
    }

    fn claude_tool_results(&mut self, value: &Value) {
        let Some(content) = value.pointer("/message/content").and_then(Value::as_array) else {
            return;
        };
        for item in content {
            if str_at(item, "type") == Some("tool_result") {
                if let Some(id) = str_at(item, "tool_use_id") {
                    self.answer_call(id, tool_output_units(item.get("content")), false);
                }
            }
        }
    }

    /// One resolved Claude response, in transcript order (`sequence` 0-based).
    pub(super) fn note_claude_response(
        &mut self,
        sequence: u64,
        usage: &UsageTotals,
        context_tokens: u64,
        tool_calls: usize,
    ) {
        let Some(slot) = self.requests.get_mut(sequence as usize) else {
            return;
        };
        *slot = Some(OpeningRequest {
            context_tokens,
            uncached_input_tokens: usage.input_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            cache_write_5m_tokens: Some(usage.cache_creation_5m_tokens),
            cache_write_1h_tokens: Some(usage.cache_creation_1h_tokens),
            output_tokens: usage.output_tokens,
        });
        if let Some(calls) = self.response_tool_calls.get_mut(sequence as usize) {
            *calls = tool_calls as u64;
        }
    }

    // ---- Codex ----------------------------------------------------------

    /// `session_meta`, read before ownership so a fork keeps its version.
    pub(super) fn note_codex_session_meta(&mut self, meta: &Value) {
        self.note_client_version(str_at(meta, "cli_version"));
        if !self.parts_closed && self.parts[Part::System as usize] == 0 {
            self.parts[Part::System as usize] =
                codex_prelude::base_instructions_text(meta).map_or(0, units);
        }
    }

    /// One owned Codex line.
    pub(super) fn observe_codex_line(&mut self, value: &Value, cwd: Option<&Path>) {
        if self.frozen {
            return;
        }
        let Some(payload) = value.get("payload") else {
            return;
        };
        match (str_at(value, "type"), str_at(payload, "type")) {
            (Some("response_item"), Some("message")) => {
                if matches!(str_at(payload, "role"), Some("developer" | "user")) {
                    if !self.parts_closed {
                        self.codex_prelude_message(payload);
                    }
                } else {
                    self.parts_closed = true;
                }
            }
            (Some("response_item"), Some("additional_tools")) if !self.parts_closed => {
                self.codex_tools_logged = true;
                self.parts[Part::Tools as usize] += payload
                    .get("tools")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(json_units)
                    .sum::<u64>();
            }
            (Some("response_item"), Some("reasoning")) => self.parts_closed = true,
            (Some("response_item"), Some("function_call" | "custom_tool_call")) => {
                self.parts_closed = true;
                let response = self.codex_requests + 1;
                if response <= 2 {
                    self.response_tool_calls[usize::from(response - 1)] += 1;
                    if let (Some(id), Some(name)) =
                        (str_at(payload, "call_id"), str_at(payload, "name"))
                    {
                        self.open_call(id, response, name);
                        self.last_codex_call = self.calls.contains_key(id).then(|| id.to_string());
                    }
                }
            }
            (Some("response_item"), Some("function_call_output" | "custom_tool_call_output")) => {
                if let Some(id) = str_at(payload, "call_id") {
                    let output = payload.get("output");
                    self.answer_call(
                        id,
                        tool_output_units(output),
                        codex_output_truncated(output),
                    );
                }
            }
            (Some("event_msg"), Some("exec_command_end")) => {
                if let Some(id) = str_at(payload, "call_id").map(str::to_string) {
                    self.codex_parsed_command(&id, payload, cwd);
                }
            }
            (Some("event_msg"), Some("item_completed")) => {
                let item = payload.get("item").unwrap_or(&Value::Null);
                if str_at(item, "type") == Some("CommandExecution") {
                    if let Some(id) = self.last_codex_call.clone() {
                        self.codex_parsed_command(&id, item, cwd);
                    }
                }
            }
            _ => {}
        }
    }

    fn codex_prelude_message(&mut self, payload: &Value) {
        let Some(blocks) = codex_prelude::labeled_blocks(payload) else {
            self.parts_unmeasurable = true;
            return;
        };
        for (kind, block) in blocks {
            if str_at(block, "type") == Some("input_image") {
                self.parts_unmeasurable = true;
                continue;
            }
            let Some(text) = str_at(block, "text") else {
                continue;
            };
            let part = match kind {
                codex_prelude::AGENTS_MD_KIND => {
                    push_capped(
                        self.instructions.get_or_insert_with(String::new),
                        codex_prelude::agents_md_instructions(text),
                    );
                    Part::Instructions
                }
                codex_prelude::HOST_SKILLS_KIND => Part::Skills,
                codex_prelude::DEFERRED_NAMESPACES_KIND => Part::McpNames,
                codex_prelude::BASE_INSTRUCTIONS_KIND => continue,
                kind if kind.starts_with("user.") => Part::Prompt,
                kind if [
                    "hooks.",
                    "permissions.",
                    "environments.",
                    "collaboration_mode.",
                    "plugins.",
                    "apps.",
                ]
                .iter()
                .any(|prefix| kind.starts_with(prefix)) =>
                {
                    Part::HooksEnv
                }
                _ => Part::Other,
            };
            self.add_part(part, text);
        }
    }

    fn codex_parsed_command(&mut self, call_id: &str, record: &Value, cwd: Option<&Path>) {
        // `exec_command_end` and `item_completed` can both describe one call.
        if self
            .calls
            .get(call_id)
            .is_some_and(|call| call.candidates > 0)
        {
            return;
        }
        // Each Codex command runs in a fresh shell at its own `cwd`; relative
        // paths are in the checkout only when that is the session directory
        // and the command does not change directory.
        let session_dir = cwd
            .and_then(Path::to_str)
            .map(|dir| dir.trim_end_matches('/'));
        let mut trust_relative = str_at(record, "cwd")
            .is_none_or(|dir| Some(dir.trim_end_matches('/')) == session_dir)
            && match record.get("command") {
                Some(Value::String(command)) => !shell_changes_directory(command),
                Some(Value::Array(parts)) => !parts
                    .iter()
                    .filter_map(Value::as_str)
                    .any(shell_changes_directory),
                _ => true,
            };
        let mut paths = Vec::new();
        for item in record
            .get("parsed_cmd")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let command = str_at(item, "cmd");
            trust_relative &= !command.is_some_and(shell_changes_directory);
            match (str_at(item, "type"), str_at(item, "path"), command) {
                (Some("read"), Some(path), _) => paths.push(path),
                (Some("unknown"), _, Some(command)) => paths.extend(shell_path_tokens(command)),
                _ => {}
            }
        }
        self.add_call_paths(call_id, paths, cwd, trust_relative);
    }

    /// One admitted Codex usage record with a positive input.
    pub(super) fn note_codex_request(&mut self, usage: &UsageTotals) {
        let index = usize::from(self.codex_requests);
        if index >= WINDOW_REQUESTS || usage.input_tokens == 0 {
            return;
        }
        // Codex input already includes cached input; no cache writes are logged.
        self.requests[index] = Some(OpeningRequest {
            context_tokens: usage.input_tokens,
            uncached_input_tokens: usage.input_tokens.saturating_sub(usage.cache_read_tokens),
            cache_read_tokens: usage.cache_read_tokens,
            cache_write_5m_tokens: None,
            cache_write_1h_tokens: None,
            output_tokens: usage.output_tokens,
        });
        self.codex_requests += 1;
        self.parts_closed = true;
        if index + 1 == WINDOW_REQUESTS {
            self.freeze();
        }
    }

    // ---- shared ---------------------------------------------------------

    fn add_part(&mut self, part: Part, text: &str) {
        self.parts[part as usize] += units(text);
        if part.is_config() {
            fold_digest(&mut self.config_digest, text.as_bytes());
        }
    }

    fn open_call(&mut self, id: &str, response: u8, name: &str) {
        if id.len() > MAX_CALL_ID_BYTES || self.calls.contains_key(id) {
            return;
        }
        let call = OpeningCall {
            response,
            tool: tool_label(name),
            ..OpeningCall::default()
        };
        if self.charge(call_bytes(id, &call)) {
            self.calls.insert(id.to_string(), call);
        }
    }

    fn add_call_paths(
        &mut self,
        call_id: &str,
        paths: Vec<&str>,
        cwd: Option<&Path>,
        trust_relative: bool,
    ) {
        let Some(call) = self.calls.get(call_id) else {
            return;
        };
        let (request, tool) = (call.response + 1, call.tool.clone());
        let mut keys = Vec::new();
        for raw in paths.iter().take(MAX_SHELL_PATH_TOKENS) {
            let Some((key, repo_path)) = normalize_path(raw, cwd, trust_relative) else {
                continue;
            };
            let segments = self
                .instructions
                .as_deref()
                .map_or(0, |haystack| instruction_segments(&key, haystack));
            if self.upsert_file(&key, repo_path, segments, &tool, request, false) {
                keys.push(key);
            }
        }
        let added = keys
            .iter()
            .map(|key| key.capacity() + std::mem::size_of::<String>())
            .sum();
        if !self.charge(added) {
            keys.clear();
        }
        let call = self.calls.get_mut(call_id).expect("call checked above");
        call.candidates += paths.len() as u64;
        call.files.reserve_exact(keys.len());
        call.files.extend(keys);
    }

    /// The call's output is split evenly over every file the call named.
    fn answer_call(&mut self, id: &str, output_units: u64, client_truncated: bool) {
        let Some(call) = self.calls.get_mut(id).filter(|call| !call.answered) else {
            return;
        };
        call.answered = true;
        let share = output_units / call.candidates.max(1);
        for key in &call.files {
            if let Some(file) = self.files.get_mut(key) {
                file.chars += share;
            }
        }
        if client_truncated {
            self.note_call_truncated(id);
        }
    }

    fn note_call_truncated(&mut self, id: &str) {
        let Some(call) = self.calls.get_mut(id).filter(|call| !call.truncated) else {
            return;
        };
        call.truncated = true;
        self.truncated_outputs += 1;
        for key in &call.files {
            if let Some(file) = self.files.get_mut(key) {
                file.truncated = true;
            }
        }
    }

    fn note_client_load(
        &mut self,
        raw: &str,
        record_type: &str,
        chars: u64,
        request: u8,
        cwd: Option<&Path>,
    ) {
        let Some((key, repo_path)) = normalize_path(raw, cwd, true) else {
            return;
        };
        let segments = self
            .instructions
            .as_deref()
            .map_or(0, |haystack| instruction_segments(&key, haystack));
        if self.upsert_file(&key, repo_path, segments, record_type, request, true) {
            if let Some(file) = self.files.get_mut(&key) {
                file.chars += chars;
            }
        }
    }

    /// Merge one observation into its file entry; true when the entry exists.
    fn upsert_file(
        &mut self,
        key: &str,
        repo_path: Option<String>,
        segments: u8,
        tool: &str,
        request: u8,
        client_loaded: bool,
    ) -> bool {
        if let Some(file) = self.files.get_mut(key) {
            file.reads += 1;
            file.client_loaded |= client_loaded;
            return true;
        }
        if segments == 0 && !client_loaded {
            return false;
        }
        let file = OpeningFileState {
            ordinal: self.files.len() as u64,
            request,
            tool: tool_label(tool),
            repo_path,
            instruction_segments: segments,
            reads: 1,
            client_loaded,
            ..OpeningFileState::default()
        };
        if !self.charge(file_bytes(key, &file)) {
            self.files_untracked += 1;
            return false;
        }
        self.files.insert(key.to_string(), file);
        true
    }

    /// The wire value. `fresh_start` is false for forks and copied prefixes,
    /// which keep only `client_version`. Path hashes need the tenant
    /// attribution key; the configuration fingerprint uses the device salt.
    pub(super) fn finish(
        self,
        fresh_start: bool,
        method: &'static str,
        attribution: Option<&crate::session_attribution::SessionAttributionContext>,
        device_salt: Option<&[u8; 32]>,
    ) -> Option<SnapshotSessionStart> {
        let mut start = SnapshotSessionStart {
            client_version: self.client_version,
            ..SnapshotSessionStart::default()
        };
        if !fresh_start || self.inherited_prefix {
            return start.into_measured();
        }
        start.user_turn_count = (self.user_turns > 0).then_some(u64::from(self.user_turns));
        start.instruction_load_cut = self.instruction_load_cut;
        // Collapsed responses leave no request index: keep only request-1
        // parts, which come from the logged request itself.
        let requests = if self.collapsed_requests {
            [None; WINDOW_REQUESTS]
        } else {
            self.requests
        };
        if let Some(first) = requests[0] {
            start.first_request_uncached_input_tokens = Some(first.uncached_input_tokens);
            start.first_request_cache_read_tokens = Some(first.cache_read_tokens);
            start.first_request_cache_write_5m_tokens = first.cache_write_5m_tokens;
            start.first_request_cache_write_1h_tokens = first.cache_write_1h_tokens;
        }
        let observed = requests
            .iter()
            .take_while(|request| request.is_some())
            .count();
        if observed > 0 {
            start.opening_request_count = Some(observed as u64);
            start.request_2_context_tokens = requests[1].map(|r| r.context_tokens);
            start.request_3_context_tokens = requests[2].map(|r| r.context_tokens);
            start.opening_output_tokens = Some(
                requests[..2]
                    .iter()
                    .flatten()
                    .map(|r| r.output_tokens)
                    .sum(),
            );
            start.opening_tool_calls = Some(self.response_tool_calls.iter().sum());
            start.opening_truncated_outputs = Some(self.truncated_outputs);
            let mut files = self.files.into_iter().collect::<Vec<_>>();
            files.sort_by_key(|(_, file)| file.ordinal);
            start.files_over_guard =
                self.files_untracked + files.len().saturating_sub(MAX_OPENING_FILES) as u64;
            files.truncate(MAX_OPENING_FILES);
            start.file_candidates = files
                .into_iter()
                .map(|(key, file)| OpeningFileCandidate {
                    path_hash: attribution
                        .and_then(|context| context.opaque_id("opening_path", &key)),
                    ext: extension(&key).map(str::to_string),
                    repo_path: file.repo_path,
                    row: SnapshotOpeningFile {
                        request: file.request,
                        tool: file.tool,
                        repo_path: None,
                        path_hash: None,
                        ext: None,
                        chars: file.chars,
                        reads: file.reads,
                        instruction_segments: file.instruction_segments,
                        client_loaded: file.client_loaded,
                        truncated: file.truncated,
                    },
                })
                .collect();
        }
        if self.parts_closed && !self.parts_unmeasurable {
            let mut parts = self.parts;
            if let Some(memory) = self.memory_units {
                // Claude carries memory inside the instruction block.
                parts[Part::Instructions as usize] =
                    parts[Part::Instructions as usize].saturating_sub(memory);
                parts[Part::Memory as usize] = memory;
            }
            start.start_parts_method = Some(method);
            let [tools, system, instructions, memory, skills, agents, mcp_names, mcp_instructions, hooks_env, prompt, other] =
                parts;
            start.start_chars_tools =
                (method != CODEX_PARTS_METHOD || self.codex_tools_logged).then_some(tools);
            start.start_chars_system = Some(system);
            start.start_chars_instructions = Some(instructions);
            start.start_chars_memory = Some(memory);
            start.start_chars_skills = Some(skills);
            start.start_chars_agents = Some(agents);
            start.start_chars_mcp_names = Some(mcp_names);
            start.start_chars_mcp_instructions = Some(mcp_instructions);
            start.start_chars_hooks_env = Some(hooks_env);
            start.start_chars_prompt = Some(prompt);
            start.start_chars_other = Some(other);
        }
        if let (Some(salt), Some(digest)) = (device_salt, self.config_digest) {
            let mut material = b"config:".to_vec();
            material.extend_from_slice(&digest.to_bytes());
            let hash = crate::context_file_counts::salted_content_hash(salt, &material);
            start.start_config_fingerprint = Some(hash[..16].to_string());
        }
        // Nothing crosses the wire until the upload policy is known.
        start.apply_upload_policy(false, false);
        start.into_measured()
    }
}

pub(super) const CLAUDE_PARTS_METHOD: &str = "cc_wire_v1";
pub(super) const CODEX_PARTS_METHOD: &str = "codex_items_v1";

impl ClaudeBlob {
    fn add(&mut self, part: Part, text: &str) {
        self.parts[part as usize] += units(text);
        if part.is_config() {
            fold_digest(&mut self.config_digest, text.as_bytes());
        }
    }
}

fn split_claude_system_text(text: &str, blob: &mut ClaudeBlob) {
    // One pass over line starts; the first occurrence of each header cuts.
    let mut cuts = Vec::with_capacity(CLAUDE_SYSTEM_SECTIONS.len() + 1);
    let mut found = [false; CLAUDE_SYSTEM_SECTIONS.len()];
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        for (index, (marker, part)) in CLAUDE_SYSTEM_SECTIONS.iter().enumerate() {
            if !found[index] && line.starts_with(marker) {
                found[index] = true;
                cuts.push((at, *part));
            }
        }
        at += line.len();
    }
    if let Some(hook) = text.find(CLAUDE_HOOK_SECTION) {
        cuts.push((hook, Part::HooksEnv));
    }
    cuts.sort_by_key(|(at, _)| *at);
    let first = cuts.first().map_or(text.len(), |(at, _)| *at);
    blob.add(Part::Other, &text[..first]);
    for (index, (at, part)) in cuts.iter().enumerate() {
        let end = cuts.get(index + 1).map_or(text.len(), |(next, _)| *next);
        blob.add(*part, &text[*at..end]);
    }
}

/// One opening-window file the injected instructions name or the client
/// loaded. Exactly one of `repo_path` (workspace labels on, inside the
/// checkout) or `path_hash` + `ext` (attribution on) is sent.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SnapshotOpeningFile {
    pub request: u8,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,
    pub chars: u64,
    pub reads: u64,
    pub instruction_segments: u8,
    pub client_loaded: bool,
    pub truncated: bool,
}

/// Local-only: both identities of an entry until the upload policy picks one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpeningFileCandidate {
    pub(crate) row: SnapshotOpeningFile,
    pub(crate) repo_path: Option<String>,
    pub(crate) path_hash: Option<String>,
    pub(crate) ext: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SnapshotSessionStart {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_turn_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_request_uncached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_request_cache_read_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_request_cache_write_5m_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_request_cache_write_1h_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opening_request_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_2_context_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_3_context_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opening_output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opening_tool_calls: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opening_truncated_outputs: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub opening_files: Vec<SnapshotOpeningFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opening_file_overflow: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_load_cut: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_parts_method: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_tools: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_system: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_instructions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_memory: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_skills: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_agents: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_mcp_names: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_mcp_instructions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_hooks_env: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_prompt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_chars_other: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_config_fingerprint: Option<String>,
    #[serde(skip)]
    pub(crate) file_candidates: Vec<OpeningFileCandidate>,
    #[serde(skip)]
    pub(crate) files_over_guard: u64,
}

crate::heap_layout_bound::fields!(SnapshotOpeningFile; request, tool, repo_path, path_hash, ext, chars, reads, instruction_segments, client_loaded, truncated);
crate::heap_layout_bound::fields!(OpeningFileCandidate; row, repo_path, path_hash, ext);
crate::heap_layout_bound::fields!(SnapshotSessionStart; client_version, user_turn_count, first_request_uncached_input_tokens, first_request_cache_read_tokens, first_request_cache_write_5m_tokens, first_request_cache_write_1h_tokens, opening_request_count, request_2_context_tokens, request_3_context_tokens, opening_output_tokens, opening_tool_calls, opening_truncated_outputs, opening_files, opening_file_overflow, instruction_load_cut, start_parts_method, start_chars_tools, start_chars_system, start_chars_instructions, start_chars_memory, start_chars_skills, start_chars_agents, start_chars_mcp_names, start_chars_mcp_instructions, start_chars_hooks_env, start_chars_prompt, start_chars_other, start_config_fingerprint, file_candidates, files_over_guard);

impl SnapshotSessionStart {
    /// Picks each entry's identity under the current consent: a plain path
    /// needs workspace labels, a hash needs attribution. Entries with neither
    /// are counted in `opening_file_overflow`, with those over the 64 guard.
    pub(crate) fn apply_upload_policy(&mut self, labels_enabled: bool, attribution_enabled: bool) {
        if self.opening_request_count.is_none() {
            return;
        }
        let mut withheld = self.files_over_guard;
        self.opening_files.clear();
        for candidate in &self.file_candidates {
            let mut row = candidate.row.clone();
            if labels_enabled && candidate.repo_path.is_some() {
                row.repo_path = candidate.repo_path.clone();
            } else if attribution_enabled && candidate.path_hash.is_some() {
                row.path_hash = candidate.path_hash.clone();
                row.ext = candidate.ext.clone();
            } else {
                withheld += 1;
                continue;
            }
            self.opening_files.push(row);
        }
        self.opening_file_overflow = Some(withheld);
    }

    /// A fork or copied prefix keeps only the client version.
    pub(crate) fn inherited(self) -> Option<Self> {
        SnapshotSessionStart {
            client_version: self.client_version,
            ..SnapshotSessionStart::default()
        }
        .into_measured()
    }

    fn into_measured(self) -> Option<Self> {
        (self != SnapshotSessionStart::default()).then_some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        parse_claude_code_jsonl_file_with_title_metadata_and_attribution, parse_codex_jsonl_file,
        ClaudeTitleMetadata, SnapshotSource,
    };
    use super::*;
    use crate::session_attribution::{
        SessionAttributionContext, SESSION_ATTRIBUTION_HMAC_KEY_VERSION,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::json;

    const SALT: [u8; 32] = [0x5a; 32];

    fn write_lines(path: &Path, common: Value, lines: Vec<Value>) {
        let body = lines
            .into_iter()
            .map(|mut line| {
                for (key, value) in common.as_object().expect("common fields") {
                    line[key] = value.clone();
                }
                line.to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, body + "\n").expect("write fixture");
    }

    /// Takes the measured fingerprint out after checking its shape: 16
    /// lowercase hex of the device-salted config digest.
    fn take_fingerprint(start: &mut Value) -> Value {
        let fingerprint = start
            .as_object_mut()
            .expect("session_start object")
            .remove("start_config_fingerprint")
            .expect("config fingerprint");
        let text = fingerprint.as_str().expect("fingerprint string");
        assert_eq!(text.len(), 16);
        assert!(text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
        fingerprint
    }

    #[test]
    fn claude_fixture_yields_exact_session_start() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-claude");
        let path = dir.join("ss-claude-1.jsonl");
        let usage = |input: u64, read: u64, output: u64| json!({"input_tokens": input, "cache_read_input_tokens": read, "output_tokens": output});
        write_lines(
            &path,
            json!({"sessionId": "ss-claude-1", "cwd": "/w/repo", "version": "2.1.300", "timestamp": "2026-10-18T10:00:00Z"}),
            vec![
                json!({"type": "attachment", "attachment": {"type": "instructions", "files": [
                    {"type": "Project", "content": "Read docs/guide.md first."},
                    {"type": "AutoMem", "content": "mem note"}]}}),
                json!({"type": "user", "message": {"role": "user", "content": "hello \u{1f600}"}}),
                json!({"type": "api-request-shape", "shapeHash": "s1", "shape": {
                    "system": [{"type": "text", "text": "You are Claude."}],
                    "tools": [{"name": "Read"}]}}),
                json!({"type": "api-request-blob", "hash": "b1", "message": {"role": "user", "content": [
                    {"type": "text", "text": "<system-reminder>\nCodebase and user instructions Read docs/guide.md first. mem note"},
                    {"type": "text", "text": "hello \u{1f600}"},
                    {"type": "tool_addition", "tool": {"name": "mcp__x__y"}}]}}),
                json!({"type": "api-request-blob", "hash": "b2", "message": {"role": "system", "content": [
                    {"type": "text", "text": "intro\n# Environment cwd"}]}}),
                json!({"type": "api-request", "shapeHash": "s1", "tail": ["b1", "b2"]}),
                json!({"type": "assistant", "requestId": "r1", "message": {"id": "m1", "role": "assistant", "model": "claude-fable-5-1",
                    "usage": {"input_tokens": 10, "cache_read_input_tokens": 100, "cache_creation_input_tokens": 50,
                        "cache_creation": {"ephemeral_5m_input_tokens": 20, "ephemeral_1h_input_tokens": 30}, "output_tokens": 7},
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/w/repo/docs/guide.md"}},
                        {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "cat docs/guide.md README.md"}}]}}),
                json!({"type": "user", "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "abcdefghij"},
                    {"type": "tool_result", "tool_use_id": "t2", "content": [{"type": "text", "text": "0123456789AB"}]}]}}),
                json!({"type": "attachment", "attachment": {"type": "nested_memory", "path": "/w/repo/src/CLAUDE.md", "content": "nested!"}}),
                json!({"type": "attachment", "attachment": {"type": "read_truncation_notice", "toolUseID": "t1"}}),
                json!({"type": "assistant", "requestId": "r2", "message": {"id": "m2", "role": "assistant", "model": "claude-fable-5-1",
                    "usage": usage(5, 300, 3),
                    "content": [{"type": "tool_use", "id": "t3", "name": "Read", "input": {"file_path": "/other/docs/guide.md"}}]}}),
                json!({"type": "user", "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t3", "content": "xyz"}]}}),
                // Request 3 is cache-only (no uncached input) and still counts.
                json!({"type": "assistant", "requestId": "r3", "message": {"id": "m3", "role": "assistant", "model": "claude-fable-5-1",
                    "usage": usage(0, 400, 2), "content": [{"type": "text", "text": "done"}]}}),
            ],
        );
        let context = SessionAttributionContext::from_activity_hint(
            SnapshotSource::ClaudeCode,
            &dir,
            true,
            Some(&URL_SAFE_NO_PAD.encode([11u8; 32])),
            Some(SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .expect("attribution context");
        let items = parse_claude_code_jsonl_file_with_title_metadata_and_attribution(
            &path,
            "2026-10-18T10:05:00Z",
            "file-fingerprint".to_string(),
            &ClaudeTitleMetadata::default(),
            false,
            Some(&context),
        )
        .expect("parse");
        let mut start = items[0].session_start.clone().expect("session_start");
        // Nothing identifies a file until the upload policy is applied.
        assert!(start.opening_files.is_empty());
        assert_eq!(start.opening_file_overflow, Some(3));
        start.apply_upload_policy(true, true);
        let mut actual = serde_json::to_value(&start).expect("serialize");
        let fingerprint = take_fingerprint(&mut actual);
        let outside_hash = context
            .opaque_id("opening_path", "/other/docs/guide.md")
            .expect("hash");
        assert!(outside_hash.starts_with("hmac-sha256:v1:"));
        assert_eq!(
            actual,
            json!({
                "client_version": "2.1.300",
                "user_turn_count": 1,
                "first_request_uncached_input_tokens": 10,
                "first_request_cache_read_tokens": 100,
                "first_request_cache_write_5m_tokens": 20,
                "first_request_cache_write_1h_tokens": 30,
                "opening_request_count": 3,
                "request_2_context_tokens": 305,
                "request_3_context_tokens": 400,
                "opening_output_tokens": 10,
                "opening_tool_calls": 3,
                "opening_truncated_outputs": 1,
                "opening_files": [
                    {"request": 2, "tool": "Read", "repo_path": "docs/guide.md", "chars": 16, "reads": 2,
                        "instruction_segments": 2, "client_loaded": false, "truncated": true},
                    {"request": 2, "tool": "nested_memory", "repo_path": "src/CLAUDE.md", "chars": 7, "reads": 1,
                        "instruction_segments": 0, "client_loaded": true, "truncated": false},
                    {"request": 3, "tool": "Read", "path_hash": outside_hash, "ext": "md", "chars": 3, "reads": 1,
                        "instruction_segments": 2, "client_loaded": false, "truncated": false}
                ],
                "opening_file_overflow": 0,
                "instruction_load_cut": false,
                "start_parts_method": "cc_wire_v1",
                "start_chars_tools": 16,
                "start_chars_system": 15,
                "start_chars_instructions": 75,
                "start_chars_memory": 8,
                "start_chars_skills": 0,
                "start_chars_agents": 0,
                "start_chars_mcp_names": 21,
                "start_chars_mcp_instructions": 0,
                "start_chars_hooks_env": 17,
                // "hello " + one astral emoji = 6 + 2 UTF-16 units.
                "start_chars_prompt": 8,
                "start_chars_other": 6
            })
        );
        // Request-1 parts reconcile with the first request's usage (D6).
        assert_eq!(items[0].first_turn_context_tokens, Some(10 + 100 + 20 + 30));
        // Labels off: every entry travels hashed, no plain path.
        start.apply_upload_policy(false, true);
        assert_eq!(start.opening_files.len(), 3);
        assert_eq!(start.opening_file_overflow, Some(0));
        assert!(start
            .opening_files
            .iter()
            .all(|file| file.repo_path.is_none() && file.path_hash.is_some()));
        // The same configuration text yields the same fingerprint.
        let reparsed = parse_claude_code_jsonl_file_with_title_metadata_and_attribution(
            &path,
            "2026-10-18T10:06:00Z",
            "file-fingerprint".to_string(),
            &ClaudeTitleMetadata::default(),
            false,
            None,
        )
        .expect("reparse");
        let reparsed = reparsed[0].session_start.clone().expect("session_start");
        assert_eq!(
            reparsed.start_config_fingerprint.as_deref(),
            fingerprint.as_str()
        );
        // Without attribution the outside file has no identity to send.
        let mut without_attribution = reparsed;
        without_attribution.apply_upload_policy(true, true);
        assert_eq!(without_attribution.opening_files.len(), 2);
        assert_eq!(without_attribution.opening_file_overflow, Some(1));
    }

    #[test]
    fn codex_fixture_yields_exact_session_start() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-codex");
        let session = "019e253c-7777-7000-9000-aaaaaaaaaaaa";
        let path = dir.join(format!("rollout-2026-10-18T10-00-00-{session}.jsonl"));
        let token_count = |total: (u64, u64, u64), last: (u64, u64, u64)| {
            let usage = |(input, cached, output): (u64, u64, u64)| json!({"input_tokens": input, "cached_input_tokens": cached, "output_tokens": output});
            json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
                "total_token_usage": usage(total), "last_token_usage": usage(last), "model": "gpt-5.5"}}})
        };
        let call = |id: &str| json!({"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": id, "arguments": "{}"}});
        write_lines(
            &path,
            json!({"timestamp": "2026-10-18T10:00:00Z"}),
            vec![
                json!({"type": "session_meta", "payload": {"id": session, "cwd": "/w/repo", "cli_version": "0.160.0",
                    "base_instructions": {"text": "BASE instructions"}}}),
                json!({"type": "response_item", "payload": {"type": "message", "role": "developer",
                    "content": [{"type": "input_text", "text": "BASE instructions"},
                        {"type": "input_text", "text": "<permissions>p</permissions>"}],
                    "internal_chat_message_metadata_passthrough": {"content_item_kinds": [
                        codex_prelude::BASE_INSTRUCTIONS_KIND, "permissions.instructions"]}}}),
                json!({"type": "response_item", "payload": {"type": "message", "role": "user",
                    "content": [
                        {"type": "input_text", "text": "# AGENTS.md instructions for /w/repo\n\n<INSTRUCTIONS>\nSee docs/guide.md\n</INSTRUCTIONS>"},
                        {"type": "input_text", "text": "<skills>s</skills>"},
                        {"type": "input_text", "text": "fix it"}],
                    "internal_chat_message_metadata_passthrough": {"content_item_kinds": [
                        codex_prelude::AGENTS_MD_KIND, codex_prelude::HOST_SKILLS_KIND, "user.text"]}}}),
                json!({"type": "response_item", "payload": {"type": "additional_tools", "tools": [{"name": "x"}]}}),
                json!({"type": "event_msg", "payload": {"type": "task_started", "turn_id": "turn-1"}}),
                call("c1"),
                json!({"type": "event_msg", "payload": {"type": "exec_command_end", "call_id": "c1", "parsed_cmd": [
                    {"type": "read", "cmd": "cat docs/guide.md", "name": "guide.md", "path": "docs/guide.md"}]}}),
                json!({"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c1",
                    "output": "Warning: truncated output\nabc"}}),
                token_count((1000, 800, 50), (1000, 800, 50)),
                // A re-emitted record is not a second request.
                token_count((1000, 800, 50), (1000, 800, 50)),
                call("c2"),
                json!({"type": "event_msg", "payload": {"type": "exec_command_end", "call_id": "c2", "parsed_cmd": [
                    {"type": "unknown", "cmd": "sed -n 1,5p /w/repo/docs/guide.md"}]}}),
                json!({"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c2", "output": "0123456789"}}),
                token_count((2100, 1800, 80), (1100, 1000, 30)),
                token_count((3300, 2900, 100), (1200, 1100, 20)),
            ],
        );
        let items =
            parse_codex_jsonl_file(&path, "2026-10-18T10:05:00Z", "file-fingerprint".into())
                .expect("parse");
        let mut start = items[0].session_start.clone().expect("session_start");
        start.apply_upload_policy(true, false);
        let mut actual = serde_json::to_value(&start).expect("serialize");
        take_fingerprint(&mut actual);
        assert_eq!(
            actual,
            json!({
                "client_version": "0.160.0",
                "user_turn_count": 1,
                // Codex input includes cached input; it logs no cache writes.
                "first_request_uncached_input_tokens": 200,
                "first_request_cache_read_tokens": 800,
                "opening_request_count": 3,
                "request_2_context_tokens": 1100,
                "request_3_context_tokens": 1200,
                "opening_output_tokens": 80,
                "opening_tool_calls": 2,
                "opening_truncated_outputs": 1,
                "opening_files": [
                    {"request": 2, "tool": "exec_command", "repo_path": "docs/guide.md", "chars": 39, "reads": 2,
                        "instruction_segments": 2, "client_loaded": false, "truncated": true}
                ],
                "opening_file_overflow": 0,
                "start_parts_method": "codex_items_v1",
                "start_chars_tools": 13,
                "start_chars_system": 17,
                "start_chars_instructions": 86,
                "start_chars_memory": 0,
                "start_chars_skills": 18,
                "start_chars_agents": 0,
                "start_chars_mcp_names": 0,
                "start_chars_mcp_instructions": 0,
                "start_chars_hooks_env": 28,
                "start_chars_prompt": 6,
                "start_chars_other": 0
            })
        );
        assert_eq!(items[0].first_turn_context_tokens, Some(1000));
    }

    fn measured_codex_state() -> SessionStartState {
        let mut state = SessionStartState::default();
        state.note_codex_session_meta(
            &json!({"cli_version": "0.160.0", "base_instructions": "BASE"}),
        );
        state.note_user_turn();
        state.note_codex_request(&UsageTotals {
            input_tokens: 10,
            ..UsageTotals::default()
        });
        state
    }

    #[test]
    fn forks_and_copied_prefixes_keep_only_client_version() {
        let only_version = Some(SnapshotSessionStart {
            client_version: Some("0.160.0".to_string()),
            ..SnapshotSessionStart::default()
        });
        let fresh = measured_codex_state()
            .finish(true, CODEX_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        assert_eq!(fresh.opening_request_count, Some(1));
        assert_eq!(
            measured_codex_state().finish(false, CODEX_PARTS_METHOD, None, Some(&SALT)),
            only_version
        );
        let mut copied = measured_codex_state();
        copied.note_inherited_prefix();
        assert_eq!(
            copied.finish(true, CODEX_PARTS_METHOD, None, Some(&SALT)),
            only_version
        );
        assert_eq!(fresh.inherited(), only_version);
        // Nothing measured: the field is omitted.
        assert_eq!(
            SessionStartState::default().finish(true, CODEX_PARTS_METHOD, None, Some(&SALT)),
            None
        );
        assert_eq!(SnapshotSessionStart::default().inherited(), None);
    }

    #[test]
    fn opening_files_cap_at_64_and_count_withheld_entries() {
        let cwd = Path::new("/w/repo");
        let mut state = measured_codex_state();
        state.note_client_load("/elsewhere/x.md", "nested_memory", 1, 2, Some(cwd));
        for index in 0..70 {
            state.note_client_load(
                &format!("/w/repo/f{index}.md"),
                "nested_memory",
                1,
                2,
                Some(cwd),
            );
        }
        let mut start = state
            .finish(true, CODEX_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        assert!(start.opening_files.is_empty());
        assert_eq!(start.opening_file_overflow, Some(71));
        start.apply_upload_policy(true, false);
        // 64 kept; the outside path has no consented identity.
        assert_eq!(start.opening_files.len(), 63);
        assert_eq!(start.opening_file_overflow, Some(7 + 1));
        assert_eq!(start.opening_files[0].repo_path.as_deref(), Some("f0.md"));
        assert_eq!(start.opening_files[62].repo_path.as_deref(), Some("f62.md"));
        assert!(start
            .opening_files
            .iter()
            .all(|file| file.path_hash.is_none()));
        let wire = serde_json::to_value(&start).expect("serialize");
        assert_eq!(wire["opening_files"].as_array().expect("files").len(), 63);
        assert!(wire.get("file_candidates").is_none());
    }

    #[test]
    fn held_state_stays_within_its_capacity_budget() {
        let mut state = measured_codex_state();
        let mut held = String::new();
        push_capped(&mut held, &"x".repeat(300 * 1024));
        push_capped(&mut held, "more");
        assert_eq!(held.capacity(), MAX_HELD_INSTRUCTION_BYTES);
        state.instructions = Some(held);
        let deep = "d/".repeat(200);
        for index in 0..2000 {
            state.note_client_load(
                &format!("/w/repo/{deep}f{index}.md"),
                "nested_memory",
                1,
                2,
                Some(Path::new("/w/repo")),
            );
            state.open_call(&format!("call-{index}"), 1, "exec_command");
        }
        assert!(state.files_untracked > 1900);
        let held = crate::heap_layout_bound::bound(&state, usize::MAX).expect("layout");
        assert!(held <= MAX_HELD_BYTES, "held {held}");
        state.freeze();
        assert!(state.instructions.is_none() && state.calls.is_empty());
        let frozen = crate::heap_layout_bound::bound(&state, usize::MAX).expect("layout");
        assert!(frozen <= MAX_HELD_COLLECTION_BYTES, "frozen {frozen}");
    }

    #[test]
    fn instruction_segments_and_paths_stay_lexical() {
        assert_eq!(
            instruction_segments("docs/guide.md", "See docs/guide.md"),
            2
        );
        assert_eq!(
            instruction_segments("/x/docs/guide.md", "See docs/guide.md"),
            2
        );
        assert_eq!(instruction_segments("guide.md", "nothing"), 0);
        assert_eq!(
            normalize_path("/w/repo/a/b.rs", Some(Path::new("/w/repo")), true),
            Some(("a/b.rs".to_string(), Some("a/b.rs".to_string())))
        );
        assert_eq!(
            normalize_path("/w/repo-other/b.rs", Some(Path::new("/w/repo")), true),
            Some(("/w/repo-other/b.rs".to_string(), None))
        );
        assert_eq!(
            normalize_path("../up.rs", None, true),
            Some(("../up.rs".to_string(), None))
        );
        assert_eq!(
            normalize_path("a/b.rs", None, false),
            Some(("a/b.rs".to_string(), None))
        );
        assert!(shell_changes_directory("cd /tmp && cat x.md"));
        assert!(shell_changes_directory("(pushd d; ls)"));
        assert!(shell_changes_directory("git -C ../other status"));
        assert!(shell_changes_directory("bash -lc 'cd /p && cat x.md'"));
        assert!(shell_changes_directory("sh -c \"cd /p; cat x.md\""));
        assert!(!shell_changes_directory("cat docs/cdn.md"));
        assert_eq!(
            shell_path_tokens("sed -n 1,5p a/b.md | grep x > out.txt").collect::<Vec<_>>(),
            ["a/b.md", "out.txt"]
        );
        assert_eq!(json_units(&json!({"a": [1, "\u{1f600}"]})), 16);
    }

    #[test]
    fn relative_shell_paths_after_a_directory_change_stay_private() {
        let cwd = Path::new("/w/repo");
        let mut state = SessionStartState {
            instructions: Some("Notes live in customer-plan.md and docs/guide.md".to_string()),
            ..SessionStartState::default()
        };
        let bash = |id: &str, command: &str| {
            json!({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": id, "name": "Bash", "input": {"command": command}}]}})
        };
        state.observe_claude_line(&bash("t1", "cat docs/guide.md"), 1, Some(cwd));
        state.observe_claude_line(
            &bash("t2", "cd /private/notes && cat customer-plan.md"),
            1,
            Some(cwd),
        );
        // Claude's shell keeps the new directory for later calls too.
        state.observe_claude_line(&bash("t3", "cat other/customer-plan.md"), 2, Some(cwd));
        state.note_claude_response(0, &UsageTotals::default(), 1, 2);
        let mut start = state
            .finish(true, CLAUDE_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        start.apply_upload_policy(true, false);
        let shown = start
            .opening_files
            .iter()
            .map(|file| file.repo_path.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(shown, [Some("docs/guide.md")]);
        assert_eq!(start.opening_file_overflow, Some(2));

        // Codex: a command at another cwd, or one that changes directory.
        let mut codex = measured_codex_state();
        codex.instructions = Some("customer-plan.md docs/guide.md".to_string());
        for (id, record) in [
            (
                "c1",
                json!({"cwd": "/private/notes", "parsed_cmd": [{"type": "read", "cmd": "cat customer-plan.md", "path": "customer-plan.md"}]}),
            ),
            (
                "c2",
                json!({"cwd": "/w/repo/", "command": ["bash", "-lc", "cd .. && cat docs/guide.md"], "parsed_cmd": [{"type": "read", "cmd": "cat docs/guide.md", "path": "docs/guide.md"}]}),
            ),
        ] {
            codex.open_call(id, 2, "exec_command");
            codex.codex_parsed_command(id, &record, Some(cwd));
        }
        let mut start = codex
            .finish(true, CODEX_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        start.apply_upload_policy(true, false);
        assert!(start.opening_files.is_empty());
        assert_eq!(start.opening_file_overflow, Some(2));
    }

    #[test]
    fn collapsed_claude_responses_drop_request_indexed_facts() {
        let mut state = SessionStartState::default();
        state.observe_claude_line(
            &json!({"type": "assistant", "version": "2.1.300", "message": {"id": "m1", "usage": {
                "input_tokens": 3, "iterations": [{"input_tokens": 5}, {"input_tokens": 3}]}}}),
            1,
            None,
        );
        state.note_claude_response(
            0,
            &UsageTotals {
                input_tokens: 3,
                ..UsageTotals::default()
            },
            3,
            0,
        );
        let start = state
            .finish(true, CLAUDE_PARTS_METHOD, None, Some(&SALT))
            .expect("client version");
        assert_eq!(start.client_version.as_deref(), Some("2.1.300"));
        assert_eq!(start.opening_request_count, None);
        assert_eq!(start.first_request_uncached_input_tokens, None);
        // Every usage root the parser accepts is checked.
        assert!(claude_multi_request(&json!({"payload": {"usage": {
            "iterations": [{"input_tokens": 1}, {"input_tokens": 2}]}}})));
    }

    #[test]
    fn oversized_call_ids_are_not_retained() {
        let mut state = measured_codex_state();
        let id = "x".repeat(300 * 1024);
        state.observe_codex_line(
            &json!({"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": id}}),
            None,
        );
        assert!(state.calls.is_empty());
        assert!(state.last_codex_call.is_none());
    }

    /// Cost receipt over local transcripts listed in
    /// `OTTTO_SESSION_START_COST_FILES` (`claude|codex<TAB>path` per line).
    /// A shadow state replays each file beside the real parser (its own state
    /// pre-frozen) so the timer covers only session-start work. Prints
    /// aggregates only; no transcript text leaves the test.
    #[test]
    #[ignore = "local cost receipt over real transcripts"]
    fn session_start_cost_receipt() {
        use super::super::{
            apply_claude_code_line, apply_codex_line, codex_last_usage, CodexOwnershipBoundary,
            SnapshotAccumulator,
        };
        use std::time::{Duration, Instant};
        let Ok(list) = std::env::var("OTTTO_SESSION_START_COST_FILES") else {
            return;
        };
        let list = String::from_utf8(std::fs::read(list).expect("file list")).expect("utf-8");
        #[derive(Default)]
        struct Totals {
            files: usize,
            lines: usize,
            bytes: usize,
            decode: Duration,
            parse: Duration,
            shadow: Duration,
            measured: usize,
            peak_held: Vec<usize>,
            retained: Vec<usize>,
            wire: Vec<usize>,
        }
        let mut totals = [Totals::default(), Totals::default()];
        for entry in list.lines() {
            let Some((kind, path)) = entry.split_once('\t') else {
                continue;
            };
            let (source, slot) = match kind {
                "claude" => (SnapshotSource::ClaudeCode, 0),
                "codex" => (SnapshotSource::Codex, 1),
                _ => continue,
            };
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            let total = &mut totals[slot];
            let started = Instant::now();
            let values = bytes
                .split(|byte| *byte == b'\n')
                .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
                .collect::<Vec<_>>();
            total.decode += started.elapsed();
            total.files += 1;
            total.lines += values.len();
            total.bytes += bytes.len();
            let mut parser = SnapshotAccumulator::new(source);
            parser.session_start.frozen = true;
            let mut shadow = SessionStartState::default();
            let mut peak = 0usize;
            for value in &values {
                let started = Instant::now();
                if source == SnapshotSource::ClaudeCode {
                    apply_claude_code_line(value, &mut parser);
                } else {
                    apply_codex_line(value, &mut parser);
                }
                total.parse += started.elapsed();
                let started = Instant::now();
                if source == SnapshotSource::ClaudeCode {
                    shadow.observe_claude_line(
                        value,
                        parser.claude_response_sequence,
                        parser.workspace_path.as_deref(),
                    );
                } else {
                    if str_at(value, "type") == Some("session_meta") {
                        if let Some(meta) = value.get("payload") {
                            shadow.note_codex_session_meta(meta);
                        }
                    }
                    if parser.codex_ownership_boundary == CodexOwnershipBoundary::AllLocal {
                        shadow.observe_codex_line(value, parser.workspace_path.as_deref());
                        if let Some(usage) = codex_last_usage(value) {
                            shadow.note_codex_request(&usage);
                        }
                    }
                }
                total.shadow += started.elapsed();
                if !shadow.frozen {
                    peak =
                        peak.max(crate::heap_layout_bound::bound(&shadow, usize::MAX).unwrap_or(0));
                }
            }
            if source == SnapshotSource::ClaudeCode {
                // The parser resolves responses at finish; replay them.
                for response in parser.claude_responses.values() {
                    shadow.note_claude_response(
                        response.sequence,
                        &response.usage,
                        response.usage.effective_input_context(),
                        response.tool_uses.len(),
                    );
                }
            }
            let started = Instant::now();
            let method = if slot == 0 {
                CLAUDE_PARTS_METHOD
            } else {
                CODEX_PARTS_METHOD
            };
            let finished = shadow.finish(true, method, None, Some(&SALT));
            total.shadow += started.elapsed();
            total.peak_held.push(peak);
            if let Some(mut start) = finished {
                start.apply_upload_policy(true, false);
                total.measured += 1;
                total
                    .retained
                    .push(crate::heap_layout_bound::bound(&start, usize::MAX).unwrap_or(0));
                total
                    .wire
                    .push(serde_json::to_vec(&start).expect("serialize").len());
            }
        }
        let quantile = |values: &mut Vec<usize>, q: f64| -> usize {
            values.sort_unstable();
            values
                .get((values.len().saturating_sub(1) as f64 * q).round() as usize)
                .copied()
                .unwrap_or(0)
        };
        for (name, total) in ["claude", "codex"].iter().zip(totals.iter_mut()) {
            let per_file =
                |duration: Duration| duration.as_secs_f64() * 1e6 / total.files.max(1) as f64;
            println!(
                "session_start_cost {name}: files={} lines={} bytes={} measured={} decode_us_per_file={:.1} parse_us_per_file={:.1} session_start_us_per_file={:.1} pct_of_parse={:.3} pct_of_decode_plus_parse={:.3} peak_held_p50={} peak_held_max={} retained_p50={} retained_max={} wire_p50={} wire_max={}",
                total.files,
                total.lines,
                total.bytes,
                total.measured,
                per_file(total.decode),
                per_file(total.parse),
                per_file(total.shadow),
                100.0 * total.shadow.as_secs_f64() / total.parse.as_secs_f64().max(1e-9),
                100.0 * total.shadow.as_secs_f64()
                    / (total.parse + total.decode).as_secs_f64().max(1e-9),
                quantile(&mut total.peak_held, 0.5),
                quantile(&mut total.peak_held, 1.0),
                quantile(&mut total.retained, 0.5),
                quantile(&mut total.retained, 1.0),
                quantile(&mut total.wire, 0.5),
                quantile(&mut total.wire, 1.0),
            );
        }
    }
}
