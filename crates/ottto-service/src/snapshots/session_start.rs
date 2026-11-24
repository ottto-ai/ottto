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

use crate::codex_prelude_footprint::{char_count as units, BlockKind, CodexPreludeParser};
use crate::composition_kinds::shell::{
    extension, normalize_path, shell_changes_directory, shell_path_tokens, MAX_SHELL_PATH_TOKENS,
};
use crate::snapshots::UsageTotals;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

pub(crate) const MAX_OPENING_FILES: usize = 64;
/// `start_config_fingerprint`: the first 16 hex digits of
/// `context_file_counts::salted_content_hash` (64-hex SHA-256), copied exactly.
const CONFIG_FINGERPRINT_LEN: usize = 16;
/// Retained capacity of the whole in-window state, charged with the daemon's
/// heap model (`heap_layout_bound`). Held instruction text (for path matching,
/// 2x the largest seen) gets half; tracked files, calls, blobs and their keys
/// share the other half, less 1 KiB for the inline state and small strings.
/// Over budget a file only counts, a call goes unattributed and request 1's
/// parts become unmeasurable.
const MAX_HELD_BYTES: usize = 256 * 1024;
const MAX_HELD_INSTRUCTION_BYTES: usize = MAX_HELD_BYTES / 2;
const MAX_HELD_COLLECTION_BYTES: usize = MAX_HELD_BYTES - MAX_HELD_INSTRUCTION_BYTES - 1024;
/// Codex keeps its AGENTS.md text inside the shared prelude parser, beside
/// the parser's own small strings (`codex_prelude_footprint::MAX_SMALL_TEXT_BYTES` each).
const MAX_CODEX_AGENTS_MD_BYTES: usize = MAX_HELD_INSTRUCTION_BYTES - 8 * 1024;
/// Tool call ids are short; a longer one is not tracked.
const MAX_CALL_ID_BYTES: usize = 256;
const MAX_TOOL_LABEL_CHARS: usize = 64;
pub(in crate::snapshots) const WINDOW_REQUESTS: usize = 3;
/// Claude Code appends this line to the request-1 auto-memory entry when it
/// loaded only part of MEMORY.md.
const MEMORY_CUT_MARKER: &str = "> WARNING: MEMORY.md is";
const CLAUDE_INSTRUCTIONS_PREFIX: &str = "<system-reminder>\nCodebase and user instructions";

/// Append-only: stored heads keep `parts` by this order (`G` class), and a
/// shorter stored array pads the appended parts with 0, i.e. not seen.
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

/// Appends what fits under the instruction budget; false when text was cut.
fn push_capped(held: &mut String, text: &str) -> bool {
    let room = MAX_HELD_INSTRUCTION_BYTES.saturating_sub(held.len() + 1);
    if room == 0 {
        return text.is_empty();
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
    end == text.len()
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

/// A blob entry: its node plus its inline key, charged in full (the node
/// estimate already holds a `String`-sized key slot).
fn blob_bytes() -> usize {
    node_bytes::<ClaudeBlob>() + std::mem::size_of::<ClaudeRequestKey>()
}

/// A Claude `api-request-shape` or `api-request-blob` key (`shapeHash`, blob
/// `hash`): a client-minted content hash of instruction or system text, not a
/// provider id. Held only as its domain-separated SHA-256 (`H`,
/// never `L`); every incoming key is hashed before any lookup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct ClaudeRequestKey([u8; 32]);

impl ClaudeRequestKey {
    const SHAPE_DOMAIN: &'static [u8] = b"ottto-dt-claude-shape-key:v1\0";
    const BLOB_DOMAIN: &'static [u8] = b"ottto-dt-claude-blob-key:v1\0";

    fn shape(raw: &str) -> Self {
        Self::of(Self::SHAPE_DOMAIN, raw)
    }

    fn blob(raw: &str) -> Self {
        Self::of(Self::BLOB_DOMAIN, raw)
    }

    fn of(domain: &[u8], raw: &str) -> Self {
        use sha2::Digest as _;
        Self(
            sha2::Sha256::new()
                .chain_update(domain)
                .chain_update(raw.as_bytes())
                .finalize()
                .into(),
        )
    }
}

// 32 inline bytes: no heap, one walker visit like the key it replaced.
crate::heap_layout_bound::no_heap!(true; ClaudeRequestKey);

/// An opening call's provider call or tool-use id, apart from the tool name
/// its `OpeningCall` holds, so a record's `L` span is the id alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
struct OpeningCallId {
    id: String,
}

impl std::borrow::Borrow<str> for OpeningCallId {
    fn borrow(&self) -> &str {
        &self.id
    }
}

fn is_client_version(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

/// Raw client tool name; MCP tools collapse to `mcp` (their server and tool
/// names already travel through the activity counters). A name outside
/// admission's `[A-Za-z0-9_.:-]{1,64}` travels as `unknown`.
fn tool_label(name: &str) -> String {
    if name.starts_with("mcp__") {
        return "mcp".to_string();
    }
    // A valid label is ASCII, so a non-boundary cut is invalid anyway.
    name.get(..name.len().min(MAX_TOOL_LABEL_CHARS))
        .filter(|label| {
            !label.is_empty()
                && label.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
                })
        })
        .unwrap_or("unknown")
        .to_string()
}

/// A Claude response spanning several model requests (`usage.iterations[]`):
/// its counters are not request 1's and later ordinals shift.
fn claude_multi_request(value: &Value) -> bool {
    crate::snapshots::claude_code_usage_root(value)
        .and_then(|usage| usage.get("iterations"))
        .and_then(Value::as_array)
        .is_some_and(|iterations| iterations.len() > 1)
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
    /// The parts above add up to `context_tokens` (the first-request breakdown is exact).
    parts_reconcile: bool,
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
    /// The first observation's tool.
    tool: String,
    repo_path: Option<String>,
    instruction_segments: u8,
    // By the request the observation arrives in (2, 3), so a request the
    // transcript never reached contributes nothing.
    reads: [u64; 2],
    chars: [u64; 2],
    client_loaded: [bool; 2],
    truncated: [bool; 2],
}

/// Index of an opening request (2 or 3) in per-request arrays.
fn slot(request: u8) -> usize {
    usize::from(request.clamp(2, 3) - 2)
}

/// Per-transcript accumulator. Everything but the counters is dropped at the
/// window freeze.
#[derive(Debug, Clone, Default)]
pub(in crate::snapshots) struct SessionStartState {
    client_version: Option<String>,
    user_turns: u8,
    inherited_prefix: bool,
    frozen: bool,
    requests: [Option<OpeningRequest>; WINDOW_REQUESTS],
    codex_requests: u8,
    response_tool_calls: [u64; 2],
    /// Client-recorded truncations by the request they arrive in (2, 3).
    truncated_outputs: [u64; 2],
    parts: [u64; PARTS],
    parts_closed: bool,
    parts_unmeasurable: bool,
    codex_tools_logged: bool,
    config_digest: Option<ConfigDigest>,
    claude_shape: Option<(ClaudeRequestKey, u64, u64)>,
    claude_blobs: BTreeMap<ClaudeRequestKey, ClaudeBlob>,
    memory_units: Option<u64>,
    instruction_load_cut: Option<bool>,
    /// Claude's request-1 instruction text, held for path matching.
    instructions: Option<String>,
    /// The instruction text outgrew its budget, so path matching is
    /// incomplete and no file fact is sent.
    instructions_capped: bool,
    /// Codex: the one prelude parser, which also holds the AGENTS.md text
    /// for path matching.
    codex_prelude: Option<Box<CodexPreludeParser>>,
    calls: BTreeMap<OpeningCallId, OpeningCall>,
    last_codex_call: Option<String>,
    files: BTreeMap<String, OpeningFileState>,
    /// Files refused by the memory budget, by the request they arrive in.
    files_untracked: [u64; 2],
    /// Collection bytes charged against `MAX_HELD_COLLECTION_BYTES`.
    held_bytes: usize,
    /// A Claude Bash command changed directory; the shell keeps that cwd, so
    /// later relative shell paths are no longer known to be in the checkout.
    shell_moved: bool,
    /// An opening Claude response spanned several requests.
    collapsed_requests: bool,
}

crate::heap_layout_bound::fields!(OpeningRequest; context_tokens, uncached_input_tokens, cache_read_tokens, cache_write_5m_tokens, cache_write_1h_tokens, parts_reconcile, output_tokens);
crate::durable_tail_codec::durable_struct!(OpeningRequest {
    N context_tokens: u64,
    N uncached_input_tokens: u64,
    N cache_read_tokens: u64,
    N cache_write_5m_tokens: Option<u64>,
    N cache_write_1h_tokens: Option<u64>,
    N parts_reconcile: bool,
    N output_tokens: u64,
});
crate::heap_layout_bound::fields!(ClaudeBlob; parts, unmeasurable, config_digest);
crate::durable_tail_codec::durable_struct!(ClaudeBlob {
    G parts: [u64; PARTS],
    N unmeasurable: bool,
    // A reversible rolling digest of instruction text: content, never
    // in a record body; stored with the opening-settings session fact.
    X config_digest: Option<ConfigDigest>,
});
crate::heap_layout_bound::fields!(ConfigDigest; a, b, len);
// Not a cryptographic digest: its state reverses to short instruction text,
// so it is content (X) everywhere and cannot be classed H (no `HDigest`).
crate::durable_tail_codec::durable_struct!(ConfigDigest {
    X a: u64,
    X b: u64,
    X len: u64,
});
crate::durable_tail_codec::durable_struct!(key ClaudeRequestKey(H digest: [u8; 32]));
crate::heap_layout_bound::fields!(OpeningCallId; id);
crate::durable_tail_codec::durable_struct!(key OpeningCallId { L id: String });
crate::heap_layout_bound::fields!(OpeningCall; response, tool, candidates, files, answered, truncated);
crate::durable_tail_codec::durable_struct!(OpeningCall {
    N response: u8,
    U tool: String,
    N candidates: u64,
    E files: Vec<String>,
    N answered: bool,
    N truncated: bool,
});
crate::heap_layout_bound::fields!(OpeningFileState; ordinal, tool, repo_path, instruction_segments, reads, chars, client_loaded, truncated);
crate::durable_tail_codec::durable_struct!(OpeningFileState {
    N ordinal: u64,
    U tool: String,
    X repo_path: Option<String>,
    N instruction_segments: u8,
    N reads: [u64; 2],
    N chars: [u64; 2],
    N client_loaded: [bool; 2],
    N truncated: [bool; 2],
});
crate::heap_layout_bound::fields!(SessionStartState; client_version, user_turns, inherited_prefix, frozen, requests, codex_requests, response_tool_calls, truncated_outputs, parts, parts_closed, parts_unmeasurable, codex_tools_logged, config_digest, claude_shape, claude_blobs, memory_units, instruction_load_cut, instructions, instructions_capped, codex_prelude, calls, last_codex_call, files, files_untracked, held_bytes, shell_moved, collapsed_requests);
crate::durable_tail_codec::durable_struct!(SessionStartState {
    U client_version: Option<String>,
    N user_turns: u8,
    N inherited_prefix: bool,
    N frozen: bool,
    G requests: [Option<OpeningRequest>; WINDOW_REQUESTS],
    N codex_requests: u8,
    N response_tool_calls: [u64; 2],
    N truncated_outputs: [u64; 2],
    G parts: [u64; PARTS],
    N parts_closed: bool,
    N parts_unmeasurable: bool,
    N codex_tools_logged: bool,
    X config_digest: Option<ConfigDigest>,
    D claude_shape: Option<(ClaudeRequestKey, u64, u64)>,
    D claude_blobs: BTreeMap<ClaudeRequestKey, ClaudeBlob>,
    N memory_units: Option<u64>,
    N instruction_load_cut: Option<bool>,
    X instructions: Option<String>,
    N instructions_capped: bool,
    X codex_prelude: Option<Box<CodexPreludeParser>>,
    D calls: BTreeMap<OpeningCallId, OpeningCall>,
    L last_codex_call: Option<String>,
    X files: BTreeMap<String, OpeningFileState>,
    N files_untracked: [u64; 2],
    N held_bytes: usize,
    N shell_moved: bool,
    N collapsed_requests: bool,
});

#[cfg(test)]
impl SessionStartState {
    /// Distinct opening parts and three present requests, so their stored
    /// bytes occur once in a head.
    pub(in crate::snapshots) fn set_grown_for_test(&mut self) {
        for (i, part) in self.parts.iter_mut().enumerate() {
            *part = 7_000_001 + i as u64;
        }
        for (i, request) in self.requests.iter_mut().enumerate() {
            *request = Some(OpeningRequest {
                context_tokens: 9_000_001 + i as u64,
                output_tokens: 8_000_001 + i as u64,
                ..OpeningRequest::default()
            });
        }
    }

    pub(in crate::snapshots) fn parts_for_test(&self) -> Vec<u64> {
        self.parts.to_vec()
    }

    pub(in crate::snapshots) fn requests_present_for_test(&self) -> Vec<bool> {
        self.requests.iter().map(Option::is_some).collect()
    }

    /// `parts` and `requests` stored as a build with these lengths wrote them.
    pub(in crate::snapshots) fn grown_bytes_for_test(
        &self,
        parts: usize,
        requests: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            crate::durable_tail_codec::grown_bytes_for_test(&self.parts, parts),
            crate::durable_tail_codec::grown_bytes_for_test(&self.requests, requests),
        )
    }

    /// `Part` in stored order. The match is exhaustive, so a new variant
    /// must be listed here.
    pub(in crate::snapshots) fn part_order_for_test() -> Vec<&'static str> {
        let name = |part: Part| match part {
            Part::Tools => "Tools",
            Part::System => "System",
            Part::Instructions => "Instructions",
            Part::Memory => "Memory",
            Part::Skills => "Skills",
            Part::Agents => "Agents",
            Part::McpNames => "McpNames",
            Part::McpInstructions => "McpInstructions",
            Part::HooksEnv => "HooksEnv",
            Part::Prompt => "Prompt",
            Part::Other => "Other",
        };
        let all = [
            Part::Tools,
            Part::System,
            Part::Instructions,
            Part::Memory,
            Part::Skills,
            Part::Agents,
            Part::McpNames,
            Part::McpInstructions,
            Part::HooksEnv,
            Part::Prompt,
            Part::Other,
        ];
        assert_eq!(all.len(), PARTS);
        all.iter()
            .enumerate()
            .map(|(i, part)| {
                assert_eq!(*part as usize, i, "{part:?}");
                name(*part)
            })
            .collect()
    }
}

impl SessionStartState {
    pub(in crate::snapshots) fn client_version(&self) -> Option<&str> {
        self.client_version.as_deref()
    }

    pub(in crate::snapshots) fn note_user_turn(&mut self) {
        self.user_turns = (self.user_turns + 1).min(2);
    }

    /// The transcript starts with records copied from another session.
    pub(in crate::snapshots) fn note_inherited_prefix(&mut self) {
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
        if let Some(parser) = self.codex_prelude.as_mut() {
            parser.release_text();
        }
        self.calls = BTreeMap::new();
        self.claude_blobs = BTreeMap::new();
        self.claude_shape = None;
        self.last_codex_call = None;
        self.recount_held();
    }

    /// Whether there is opening content a record body never carries (`X`:
    /// instruction text, opening files with their paths, config digests, each
    /// opening call's file paths). The Codex prelude is its own fact.
    pub(in crate::snapshots) fn has_opening_fact(&self) -> bool {
        self.instructions.is_some()
            || !self.files.is_empty()
            || self.config_digest.is_some()
            || self
                .claude_blobs
                .values()
                .any(|blob| blob.config_digest.is_some())
            || self.calls.values().any(|call| !call.files.is_empty())
    }

    /// The opening-settings session fact: that content, beside the
    /// record body that keeps its keys (blob and call ids, in key order).
    pub(in crate::snapshots) fn put_opening_fact(
        &self,
        e: &mut crate::durable_tail_codec::Enc<'_>,
    ) -> Result<(), crate::durable_tail_codec::Refuse> {
        use crate::durable_tail_codec::Durable;
        let digest = |digest: &Option<ConfigDigest>| digest.map(|d| (d.a, d.b, d.len));
        self.instructions.put(e)?;
        digest(&self.config_digest).put(e)?;
        e.varint(self.files.len() as u64)?;
        for (path, file) in &self.files {
            path.put(e)?;
            file.put(e)?;
            file.repo_path.put(e)?;
        }
        e.varint(self.claude_blobs.len() as u64)?;
        for blob in self.claude_blobs.values() {
            digest(&blob.config_digest).put(e)?;
        }
        e.varint(self.calls.len() as u64)?;
        for call in self.calls.values() {
            call.files.put(e)?;
        }
        Ok(())
    }

    /// Whether the Codex prelude parser is held: content (`X`) a record body
    /// never carries, stored as the Codex prelude session fact.
    pub(in crate::snapshots) fn has_codex_prelude(&self) -> bool {
        self.codex_prelude.is_some()
    }

    /// The Codex prelude session fact: the held parser, in full.
    pub(in crate::snapshots) fn put_codex_prelude_fact(
        &self,
        e: &mut crate::durable_tail_codec::Enc<'_>,
    ) -> Result<(), crate::durable_tail_codec::Refuse> {
        match self.codex_prelude.as_deref() {
            Some(parser) => parser.put_fact(e),
            None => Err(crate::durable_tail_codec::Refuse::NonEmpty(
                "SessionStartState.codex_prelude",
            )),
        }
    }

    /// Restores the Codex prelude fact into a decoded body.
    pub(in crate::snapshots) fn take_codex_prelude_fact(
        &mut self,
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<(), crate::durable_tail_codec::Corrupt> {
        self.codex_prelude = Some(Box::new(CodexPreludeParser::take_fact(d)?));
        Ok(())
    }

    /// Restores the opening-settings fact into a decoded body: its blob and
    /// call keys must be the ones the fact was written beside.
    pub(in crate::snapshots) fn take_opening_fact(
        &mut self,
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<(), crate::durable_tail_codec::Corrupt> {
        use crate::durable_tail_codec::{Corrupt, Durable};
        let digest =
            |d: &mut crate::durable_tail_codec::Dec<'_>| {
                Ok::<_, Corrupt>(
                    <Option<(u64, u64, u64)> as Durable>::take(d)?
                        .map(|(a, b, len)| ConfigDigest { a, b, len }),
                )
            };
        self.instructions = <Option<String> as Durable>::take(d)?;
        self.config_digest = digest(d)?;
        self.files = BTreeMap::new();
        for _ in 0..d.varint()? {
            let path = String::take(d)?;
            let mut file = OpeningFileState::take(d)?;
            file.repo_path = <Option<String> as Durable>::take(d)?;
            if self.files.insert(path, file).is_some() {
                return Err(Corrupt);
            }
        }
        if d.varint()? != self.claude_blobs.len() as u64 {
            return Err(Corrupt);
        }
        for blob in self.claude_blobs.values_mut() {
            blob.config_digest = digest(d)?;
        }
        if d.varint()? != self.calls.len() as u64 {
            return Err(Corrupt);
        }
        for call in self.calls.values_mut() {
            call.files = Vec::<String>::take(d)?;
        }
        Ok(())
    }

    /// Opening-settings content: request-1 instructions, one opening file at
    /// `path`, and an opening call that read it.
    #[cfg(test)]
    pub(in crate::snapshots) fn opening_fact_for_test(&mut self, instructions: &str, path: &str) {
        self.instructions = Some(instructions.into());
        self.files.insert(path.into(), OpeningFileState::default());
        self.open_call_for_test("toolu_opening", &[path]);
    }

    /// An opening call holding `files`, as a read in the window records it.
    #[cfg(test)]
    pub(in crate::snapshots) fn open_call_for_test(&mut self, id: &str, files: &[&str]) {
        let call = OpeningCall {
            files: files.iter().map(|file| file.to_string()).collect(),
            ..OpeningCall::default()
        };
        self.calls.insert(OpeningCallId { id: id.into() }, call);
    }
    #[cfg(test)]
    pub(in crate::snapshots) fn call_files_for_test(&self, id: &str) -> Option<&[String]> {
        self.calls.get(id).map(|call| call.files.as_slice())
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
                .map(|(id, call)| call_bytes(&id.id, call))
                .sum::<usize>()
            + self.claude_blobs.len().saturating_mul(blob_bytes())
            + self
                .claude_shape
                .as_ref()
                .map_or(0, |_| std::mem::size_of::<ClaudeRequestKey>());
    }

    // ---- Claude Code ----------------------------------------------------

    /// One owned Claude line. `responses` = distinct responses seen so far, so
    /// content on this line arrives in request `responses + 1`.
    pub(in crate::snapshots) fn observe_claude_line(
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
                    self.instructions_capped |= !push_capped(&mut held, content);
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
        let key = ClaudeRequestKey::shape(str_at(value, "shapeHash").unwrap_or(""));
        if !self.charge(std::mem::size_of::<ClaudeRequestKey>()) {
            self.parts_unmeasurable = true;
            return;
        }
        self.claude_shape = Some((key, system, tools));
    }

    fn claude_blob(&mut self, value: &Value) {
        let (Some(hash), Some(message)) = (str_at(value, "hash"), value.get("message")) else {
            return;
        };
        let key = ClaudeRequestKey::blob(hash);
        if !self.claude_blobs.contains_key(&key) && !self.charge(blob_bytes()) {
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
        self.claude_blobs.insert(key, blob);
    }

    /// The first `api-request`: request 1's tail of measured blobs.
    fn claude_request(&mut self, value: &Value) {
        self.parts_closed = true;
        let shape = self.claude_shape.take();
        let blobs = std::mem::take(&mut self.claude_blobs);
        self.recount_held();
        let tail = value.get("tail").and_then(Value::as_array);
        let (Some((shape_key, system, tools)), Some(tail)) = (shape, tail) else {
            self.parts_unmeasurable = true;
            return;
        };
        // A `base` continues an earlier request: history was copied in.
        if value.get("base").is_some()
            || str_at(value, "shapeHash").map(ClaudeRequestKey::shape) != Some(shape_key)
        {
            self.parts_unmeasurable = true;
            return;
        }
        self.parts[Part::System as usize] += system;
        self.parts[Part::Tools as usize] += tools;
        for hash in tail {
            match hash
                .as_str()
                .and_then(|hash| blobs.get(&ClaudeRequestKey::blob(hash)))
            {
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
    pub(in crate::snapshots) fn note_claude_response(
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
            // The item's first turn takes the larger of the billing counters
            // and any single `usage.iterations[]` entry; the breakdown must equal it.
            parts_reconcile: usage.effective_input_context() == context_tokens,
            output_tokens: usage.output_tokens,
        });
        if let Some(calls) = self.response_tool_calls.get_mut(sequence as usize) {
            *calls = tool_calls as u64;
        }
    }

    // ---- Codex ----------------------------------------------------------

    /// Codex `session_meta` row, read before ownership so a fork keeps its
    /// version. It starts the shared prelude parser.
    pub(in crate::snapshots) fn note_codex_session_meta(&mut self, row: &Value) {
        if let Some(meta) = row.get("payload") {
            self.note_client_version(str_at(meta, "cli_version"));
        }
        if self.frozen {
            return;
        }
        self.feed_codex_prelude(row);
    }

    /// Feeds the one Codex prelude parser and folds the
    /// configuration blocks it counts into the start fingerprint.
    fn feed_codex_prelude(&mut self, row: &Value) {
        let parser = self.codex_prelude.get_or_insert_with(|| {
            Box::new(CodexPreludeParser::matching_only(MAX_CODEX_AGENTS_MD_BYTES))
        });
        let digest = &mut self.config_digest;
        parser.observe_with(row, |kind, text| {
            if codex_part(kind).is_some_and(Part::is_config) {
                fold_digest(&mut *digest, text.as_bytes());
            }
        });
    }

    fn codex_input_closed(&self) -> bool {
        self.codex_prelude
            .as_ref()
            .is_some_and(|parser| parser.prelude().input_closed)
    }

    /// One owned Codex line.
    pub(in crate::snapshots) fn observe_codex_line(&mut self, value: &Value, cwd: Option<&Path>) {
        if self.frozen {
            return;
        }
        // `session_meta` rows reach the parser before ownership.
        if str_at(value, "type") != Some("session_meta") {
            self.feed_codex_prelude(value);
        }
        let Some(payload) = value.get("payload") else {
            return;
        };
        match (str_at(value, "type"), str_at(payload, "type")) {
            (Some("response_item"), Some("additional_tools")) if !self.codex_input_closed() => {
                self.codex_tools_logged = true;
                self.parts[Part::Tools as usize] += payload
                    .get("tools")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(json_units)
                    .sum::<u64>();
            }
            (Some("response_item"), Some("function_call" | "custom_tool_call")) => {
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
        // paths are in the checkout only when the record states that `cwd`,
        // it is the session directory, and the command does not change
        // directory. A record without `cwd` proves no base.
        let session_dir = cwd
            .and_then(Path::to_str)
            .map(|dir| dir.trim_end_matches('/'));
        let mut trust_relative = str_at(record, "cwd")
            .is_some_and(|dir| Some(dir.trim_end_matches('/')) == session_dir)
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
    pub(in crate::snapshots) fn note_codex_request(&mut self, usage: &UsageTotals) {
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
            parts_reconcile: usage.cache_read_tokens <= usage.input_tokens,
            output_tokens: usage.output_tokens,
        });
        self.codex_requests += 1;
        if index + 1 == WINDOW_REQUESTS {
            self.freeze();
        }
    }

    /// Request-1 parts from the prelude parser: `None` unless request 1's
    /// input is over, every block was labeled and `world_state` was logged.
    fn codex_parts(&self) -> Option<[u64; PARTS]> {
        let prelude = self.codex_prelude.as_ref()?.prelude();
        if !prelude.input_closed || prelude.blocks_incomplete || !prelude.world_state_seen {
            return None;
        }
        let mut parts = [0; PARTS];
        parts[Part::Tools as usize] = self.parts[Part::Tools as usize];
        parts[Part::System as usize] = prelude.base_instructions_chars;
        for kind in [
            BlockKind::AgentsMd,
            BlockKind::Skills,
            BlockKind::DeferredTools,
            BlockKind::Hooks,
            BlockKind::Environment,
            BlockKind::Prompt,
            BlockKind::Other,
        ] {
            if let Some(part) = codex_part(kind) {
                parts[part as usize] += prelude.chars(kind);
            }
        }
        Some(parts)
    }

    // ---- shared ---------------------------------------------------------

    /// The injected instruction text paths are matched against: Claude's
    /// request-1 instructions, or the AGENTS.md body Codex loaded.
    fn haystack(&self) -> Option<&str> {
        self.instructions.as_deref().or_else(|| {
            let agents = self.codex_prelude.as_ref()?.prelude().agents_md.as_ref()?;
            Some(agents.text.as_str())
        })
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
            self.calls
                .insert(OpeningCallId { id: id.to_string() }, call);
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
                .haystack()
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
        let arrives = slot(call.response + 1);
        for key in &call.files {
            if let Some(file) = self.files.get_mut(key) {
                file.chars[arrives] += share;
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
        let arrives = slot(call.response + 1);
        self.truncated_outputs[arrives] += 1;
        for key in &call.files {
            if let Some(file) = self.files.get_mut(key) {
                file.truncated[arrives] = true;
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
            .haystack()
            .map_or(0, |haystack| instruction_segments(&key, haystack));
        if self.upsert_file(&key, repo_path, segments, record_type, request, true) {
            if let Some(file) = self.files.get_mut(&key) {
                file.chars[slot(request)] += chars;
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
        let arrives = slot(request);
        if let Some(file) = self.files.get_mut(key) {
            file.reads[arrives] += 1;
            file.client_loaded[arrives] |= client_loaded;
            return true;
        }
        if segments == 0 && !client_loaded {
            return false;
        }
        let mut file = OpeningFileState {
            ordinal: self.files.len() as u64,
            tool: tool_label(tool),
            repo_path,
            instruction_segments: segments,
            ..OpeningFileState::default()
        };
        file.reads[arrives] = 1;
        file.client_loaded[arrives] = client_loaded;
        if !self.charge(file_bytes(key, &file)) {
            self.files_untracked[arrives] += 1;
            return false;
        }
        self.files.insert(key.to_string(), file);
        true
    }

    /// The wire value. `fresh_start` is false for forks and copied prefixes,
    /// which keep only `client_version`; so is a Codex prelude the shared
    /// parser found copied. `first_turn_context_tokens` is the item's own
    /// first-turn context, which the breakdown must add up to. Path hashes need the
    /// tenant attribution key; the configuration fingerprint uses the device
    /// salt.
    ///
    /// Everything request-indexed is cut to the contiguous requests actually
    /// observed: a file, truncation or tool call staged for a request the
    /// transcript has not reached yet is not sent (nor counted as overflow).
    pub(in crate::snapshots) fn finish(
        self,
        fresh_start: bool,
        first_turn_context_tokens: Option<u64>,
        method: &'static str,
        attribution: Option<&crate::session_attribution::SessionAttributionContext>,
        device_salt: Option<&[u8; 32]>,
    ) -> Option<SnapshotSessionStart> {
        let matching_incomplete = self.file_matching_incomplete();
        let parts = if method == CODEX_PARTS_METHOD {
            self.codex_parts()
        } else {
            (self.parts_closed && !self.parts_unmeasurable).then_some(self.parts)
        };
        let mut start = SnapshotSessionStart {
            client_version: self.client_version,
            ..SnapshotSessionStart::default()
        };
        let copied_prelude = self
            .codex_prelude
            .as_ref()
            .is_some_and(|parser| parser.prelude().is_fork);
        if !fresh_start || self.inherited_prefix || copied_prelude {
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
        let observed = requests
            .iter()
            .take_while(|request| request.is_some())
            .count();
        // The first-request breakdown only when its parts add up to the item's
        // first-turn context: the first request must reconcile exactly and be that turn. Codex takes
        // the first turn from a response the request count may not admit.
        if let Some(first) = requests[0].filter(|r| {
            r.parts_reconcile
                && r.context_tokens > 0
                && Some(r.context_tokens) == first_turn_context_tokens
        }) {
            start.first_request_uncached_input_tokens = Some(first.uncached_input_tokens);
            start.first_request_cache_read_tokens = Some(first.cache_read_tokens);
            start.first_request_cache_write_5m_tokens = first.cache_write_5m_tokens;
            start.first_request_cache_write_1h_tokens = first.cache_write_1h_tokens;
        }
        if observed > 0 {
            let reached = |request: usize| request <= observed;
            // Responses 1-2 issue the window's calls; response N is request N.
            let responses = observed.min(2);
            start.opening_request_count = Some(observed as u64);
            start.request_2_context_tokens =
                requests[1].filter(|_| reached(2)).map(|r| r.context_tokens);
            start.request_3_context_tokens =
                requests[2].filter(|_| reached(3)).map(|r| r.context_tokens);
            start.opening_output_tokens = Some(
                requests[..responses]
                    .iter()
                    .flatten()
                    .map(|r| r.output_tokens)
                    .sum(),
            );
            start.opening_tool_calls = Some(self.response_tool_calls[..responses].iter().sum());
            // Request N+1 carries the outputs of response N's calls.
            let arrived = observed.saturating_sub(1);
            start.opening_truncated_outputs = Some(self.truncated_outputs[..arrived].iter().sum());
            if matching_incomplete {
                // Unknown, not zero: a file named past the cap went unseen.
                start.opening_files_unknown = true;
            } else {
                // Only what arrived in reached requests; a file first seen in
                // an unreached request is dropped, not counted.
                let mut files = self
                    .files
                    .into_iter()
                    .filter_map(|(key, file)| {
                        let first = file.reads[..arrived].iter().position(|reads| *reads > 0)?;
                        Some((key, first, file))
                    })
                    .collect::<Vec<_>>();
                files.sort_by_key(|(_, _, file)| file.ordinal);
                start.files_over_guard = self.files_untracked[..arrived].iter().sum::<u64>()
                    + files.len().saturating_sub(MAX_OPENING_FILES) as u64;
                files.truncate(MAX_OPENING_FILES);
                start.file_candidates = files
                    .into_iter()
                    .map(|(key, first, file)| OpeningFileCandidate {
                        path_hash: attribution
                            .and_then(|context| context.opaque_id("opening_path", &key)),
                        ext: extension(&key).map(str::to_string),
                        repo_path: file.repo_path,
                        row: SnapshotOpeningFile {
                            request: first as u8 + 2,
                            tool: file.tool,
                            repo_path: None,
                            path_hash: None,
                            ext: None,
                            chars: file.chars[..arrived].iter().sum(),
                            reads: file.reads[..arrived].iter().sum(),
                            instruction_segments: file.instruction_segments,
                            client_loaded: file.client_loaded[..arrived].contains(&true),
                            truncated: file.truncated[..arrived].contains(&true),
                        },
                    })
                    .collect();
                // Nothing identifies a file until the upload policy is known.
                start.opening_file_overflow =
                    Some(start.files_over_guard + start.file_candidates.len() as u64);
            }
        }
        if let Some(mut parts) = parts {
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
            start.start_config_fingerprint = Some(hash[..CONFIG_FINGERPRINT_LEN].to_string());
        }
        start.into_measured()
    }

    /// Path matching saw only part of the injected instruction text (its
    /// budget, or a Codex rollout without `world_state`).
    fn file_matching_incomplete(&self) -> bool {
        self.instructions_capped
            || self.codex_prelude.as_ref().is_some_and(|parser| {
                let prelude = parser.prelude();
                prelude.agents_md_capped || !prelude.world_state_seen
            })
    }
}

pub(in crate::snapshots) const CLAUDE_PARTS_METHOD: &str = "cc_wire_v1";
pub(in crate::snapshots) const CODEX_PARTS_METHOD: &str = "codex_items_v1";

impl ClaudeBlob {
    fn add(&mut self, part: Part, text: &str) {
        self.parts[part as usize] += units(text);
        if part.is_config() {
            fold_digest(&mut self.config_digest, text.as_bytes());
        }
    }
}

/// Where a labeled Codex prelude block counts; base instructions come from
/// `session_meta` (the System part) instead.
fn codex_part(kind: BlockKind) -> Option<Part> {
    Some(match kind {
        BlockKind::BaseInstructions => return None,
        BlockKind::AgentsMd => Part::Instructions,
        BlockKind::Skills => Part::Skills,
        BlockKind::DeferredTools => Part::McpNames,
        BlockKind::Hooks | BlockKind::Environment => Part::HooksEnv,
        BlockKind::Prompt => Part::Prompt,
        BlockKind::Other => Part::Other,
    })
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
    /// Local only until the upload policy picks each entry's identity; then
    /// released (only `opening_files` stays).
    #[serde(skip)]
    pub(crate) file_candidates: Vec<OpeningFileCandidate>,
    #[serde(skip)]
    pub(crate) files_over_guard: u64,
    /// The candidates were consumed by an upload policy.
    #[serde(skip)]
    pub(crate) policy_applied: bool,
    /// Path matching was incomplete: no file row and a NULL overflow.
    #[serde(skip)]
    pub(crate) opening_files_unknown: bool,
}

crate::heap_layout_bound::fields!(SnapshotOpeningFile; request, tool, repo_path, path_hash, ext, chars, reads, instruction_segments, client_loaded, truncated);
crate::heap_layout_bound::fields!(OpeningFileCandidate; row, repo_path, path_hash, ext);
crate::heap_layout_bound::fields!(SnapshotSessionStart; client_version, user_turn_count, first_request_uncached_input_tokens, first_request_cache_read_tokens, first_request_cache_write_5m_tokens, first_request_cache_write_1h_tokens, opening_request_count, request_2_context_tokens, request_3_context_tokens, opening_output_tokens, opening_tool_calls, opening_truncated_outputs, opening_files, opening_file_overflow, instruction_load_cut, start_parts_method, start_chars_tools, start_chars_system, start_chars_instructions, start_chars_memory, start_chars_skills, start_chars_agents, start_chars_mcp_names, start_chars_mcp_instructions, start_chars_hooks_env, start_chars_prompt, start_chars_other, start_config_fingerprint, file_candidates, files_over_guard, policy_applied, opening_files_unknown);

impl SnapshotSessionStart {
    /// Picks each entry's identity under the current consent: a plain path
    /// needs workspace labels, a hash needs attribution. Entries with neither
    /// are counted in `opening_file_overflow`, with those over the 64 guard.
    /// The local candidates are released here, so a later application (the
    /// same cycle's policy again) can only narrow what is sent.
    pub(crate) fn apply_upload_policy(&mut self, labels_enabled: bool, attribution_enabled: bool) {
        if self.opening_request_count.is_none() || self.opening_files_unknown {
            return;
        }
        let mut withheld = if self.policy_applied {
            self.opening_file_overflow.unwrap_or(0)
        } else {
            self.files_over_guard
        };
        let allowed = |row: &SnapshotOpeningFile| {
            (labels_enabled && row.repo_path.is_some())
                || (attribution_enabled && row.path_hash.is_some())
        };
        let before = self.opening_files.len();
        self.opening_files.retain(allowed);
        withheld += (before - self.opening_files.len()) as u64;
        if !self.policy_applied {
            self.policy_applied = true;
            let candidates = std::mem::take(&mut self.file_candidates);
            self.opening_files.reserve_exact(candidates.len());
            for candidate in candidates {
                let OpeningFileCandidate {
                    mut row,
                    repo_path,
                    path_hash,
                    ext,
                } = candidate;
                if labels_enabled && repo_path.is_some() {
                    row.repo_path = repo_path;
                } else if attribution_enabled && path_hash.is_some() {
                    row.path_hash = path_hash;
                    row.ext = ext;
                } else {
                    withheld += 1;
                    continue;
                }
                self.opening_files.push(row);
            }
            self.opening_files.shrink_to_fit();
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

/// Whether session-start measured a session's opening, so another reader can
/// leave request 1 to it instead of counting the same content twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartVerdict {
    Measured,
    NotMeasured,
}

/// The start verdict of one transcript file's snapshot item, read after the
/// cycle's ownership fold (copied openings, forks and withheld files keep the
/// client version only). Measured when the item carries any start value the
/// server stores besides the client version and the config fingerprint; the
/// server calls the same start "measured". Reads only the item: no file IO.
pub(crate) fn session_start_verdict(item: &crate::snapshots::SnapshotItem) -> StartVerdict {
    let Some(start) = item.session_start.as_deref() else {
        return StartVerdict::NotMeasured;
    };
    // Exhaustive, so a new wire field must pick a side here.
    let SnapshotSessionStart {
        client_version: _,
        start_config_fingerprint: _,
        opening_files: _,
        file_candidates: _,
        files_over_guard: _,
        policy_applied: _,
        opening_files_unknown: _,
        user_turn_count,
        first_request_uncached_input_tokens,
        first_request_cache_read_tokens,
        first_request_cache_write_5m_tokens,
        first_request_cache_write_1h_tokens,
        opening_request_count,
        request_2_context_tokens,
        request_3_context_tokens,
        opening_output_tokens,
        opening_tool_calls,
        opening_truncated_outputs,
        opening_file_overflow,
        instruction_load_cut,
        start_parts_method,
        start_chars_tools,
        start_chars_system,
        start_chars_instructions,
        start_chars_memory,
        start_chars_skills,
        start_chars_agents,
        start_chars_mcp_names,
        start_chars_mcp_instructions,
        start_chars_hooks_env,
        start_chars_prompt,
        start_chars_other,
    } = start;
    let measured = instruction_load_cut.is_some()
        || start_parts_method.is_some()
        || [
            user_turn_count,
            first_request_uncached_input_tokens,
            first_request_cache_read_tokens,
            first_request_cache_write_5m_tokens,
            first_request_cache_write_1h_tokens,
            opening_request_count,
            request_2_context_tokens,
            request_3_context_tokens,
            opening_output_tokens,
            opening_tool_calls,
            opening_truncated_outputs,
            opening_file_overflow,
            start_chars_tools,
            start_chars_system,
            start_chars_instructions,
            start_chars_memory,
            start_chars_skills,
            start_chars_agents,
            start_chars_mcp_names,
            start_chars_mcp_instructions,
            start_chars_hooks_env,
            start_chars_prompt,
            start_chars_other,
        ]
        .iter()
        .any(|value| value.is_some());
    if measured {
        StartVerdict::Measured
    } else {
        StartVerdict::NotMeasured
    }
}

/// Test oracle from the uploaded bytes: the item's `session_start` object
/// holds a non-null value outside the client version, the config fingerprint
/// and the opening-file rows (those go to their own table).
#[cfg(test)]
pub(crate) fn uploaded_start_verdict(item: &crate::snapshots::SnapshotItem) -> StartVerdict {
    let body = serde_json::to_value(item).expect("serialize item");
    let measured = body
        .get("session_start")
        .and_then(Value::as_object)
        .is_some_and(|start| {
            start.iter().any(|(key, value)| {
                !matches!(
                    key.as_str(),
                    "client_version" | "start_config_fingerprint" | "opening_files"
                ) && !value.is_null()
            })
        });
    if measured {
        StartVerdict::Measured
    } else {
        StartVerdict::NotMeasured
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests;
