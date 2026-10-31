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
use crate::codex_prelude_footprint::{char_count as units, BlockKind, CodexPreludeParser};
use crate::composition_kinds::shell::{
    extension, normalize_path, shell_changes_directory, shell_path_tokens, MAX_SHELL_PATH_TOKENS,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

pub(crate) const MAX_OPENING_FILES: usize = 64;
/// `start_config_fingerprint`: the first 16 hex digits of
/// `context_file_counts::salted_content_hash` (64-hex SHA-256), copied exactly.
const CONFIG_FINGERPRINT_LEN: usize = 16;
/// An opening file's `path_hash`: `session_attribution::opaque_hmac_id`, i.e.
/// "<key version>:" + URL-safe unpadded base64 of the 32-byte HMAC-SHA256 (43).
const PATH_HASH_LEN: usize =
    crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION.len() + 1 + 43;
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
pub(super) const WINDOW_REQUESTS: usize = 3;
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
/// provider id. Held only as its domain-separated SHA-256 (M1, SOURCE P2-5:
/// `H`, never `L`); every incoming key is hashed before any lookup.
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

impl crate::heap_layout_bound::HeapLayoutBound for ClaudeRequestKey {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    // 32 inline bytes: no heap, one walker visit like the key it replaced.
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// An opening call's provider call or tool-use id, apart from the tool name
/// its `OpeningCall` holds, so a record's `L` span is the id alone (M1,
/// SOURCE P2-5).
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
    super::claude_code_usage_root(value)
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
    /// The parts above add up to `context_tokens` (D6 is exact).
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
pub(super) struct SessionStartState {
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
    /// End offset of the last line applied while the window was open (the
    /// line that froze it, once frozen), when the reader knew it. The opening
    /// content (M1 durable warm-cache) equals a re-parse of the file through
    /// it; `None` after any line at an unknown position.
    content_end: Option<u64>,
}

crate::durable_tail_codec::durable_struct!(heap OpeningRequest {
    N context_tokens: u64,
    N uncached_input_tokens: u64,
    N cache_read_tokens: u64,
    N cache_write_5m_tokens: Option<u64>,
    N cache_write_1h_tokens: Option<u64>,
    N parts_reconcile: bool,
    N output_tokens: u64,
});
crate::durable_tail_codec::durable_struct!(heap ClaudeBlob {
    N parts: [u64; PARTS],
    N unmeasurable: bool,
    // A reversible rolling digest of instruction text (F1): content, never
    // stored; re-derived with the opening content and hash-verified.
    X config_digest: Option<ConfigDigest>,
});
// Not a cryptographic digest: its state reverses to short instruction text,
// so it is content (X) everywhere and cannot be classed H (no `HDigest`).
crate::durable_tail_codec::durable_struct!(heap ConfigDigest {
    X a: u64,
    X b: u64,
    X len: u64,
});
crate::durable_tail_codec::durable_struct!(key ClaudeRequestKey(H digest: [u8; 32]));
crate::durable_tail_codec::durable_struct!(heap key OpeningCallId { L id: String });
crate::durable_tail_codec::durable_struct!(heap OpeningCall {
    N response: u8,
    U tool: String,
    N candidates: u64,
    E files: Vec<String>,
    N answered: bool,
    N truncated: bool,
});
crate::durable_tail_codec::durable_struct!(heap OpeningFileState {
    N ordinal: u64,
    U tool: String,
    X repo_path: Option<String>,
    N instruction_segments: u8,
    N reads: [u64; 2],
    N chars: [u64; 2],
    N client_loaded: [bool; 2],
    N truncated: [bool; 2],
});
crate::durable_tail_codec::durable_struct!(heap SessionStartState {
    U client_version: Option<String>,
    N user_turns: u8,
    N inherited_prefix: bool,
    N frozen: bool,
    N requests: [Option<OpeningRequest>; WINDOW_REQUESTS],
    N codex_requests: u8,
    N response_tool_calls: [u64; 2],
    N truncated_outputs: [u64; 2],
    N parts: [u64; PARTS],
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
    N content_end: Option<u64>,
});

impl SessionStartState {
    pub(super) fn client_version(&self) -> Option<&str> {
        self.client_version.as_deref()
    }

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
        self.note_line_applied();
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

    /// M1: after each applied line, while the window is open, the end of
    /// that line: the opening content is final through it.
    pub(super) fn note_line_applied(&mut self) {
        if !self.frozen {
            self.content_end = crate::durable_tail_codec::current_line()
                .map(|(offset, len)| offset.saturating_add(len));
        }
    }

    /// M1 durable warm-cache reuse: the digest of the opening content a
    /// record never carries (instruction text, the Codex prelude with its cwd
    /// and AGENTS.md, opening file paths), or `None` when there is none. It
    /// is re-derived by re-parsing the file head through `content_end`, which
    /// must be known and within `bound`.
    pub(super) fn durable_content_digest(
        &self,
        bound: u64,
    ) -> Result<Option<([u8; 32], u64)>, crate::durable_tail_codec::Refuse> {
        use crate::durable_tail_codec::Refuse;
        if self.instructions.is_none()
            && self.codex_prelude.is_none()
            && self.files.is_empty()
            && self.config_digest.is_none()
            && self
                .claude_blobs
                .values()
                .all(|blob| blob.config_digest.is_none())
        {
            return Ok(None);
        }
        let end = self
            .content_end
            .filter(|end| *end <= bound)
            .ok_or(Refuse::NotRederivable("SessionStartState.content_end"))?;
        Ok(Some((self.durable_content_hash()?, end)))
    }

    /// The opening content's digest alone, for a head re-parse (which has no
    /// line positions) to compare with the recorded one.
    pub(super) fn durable_content_hash(
        &self,
    ) -> Result<[u8; 32], crate::durable_tail_codec::Refuse> {
        use crate::durable_tail_codec::{Durable, Enc};
        let mut e = Enc::hash("ottto-dt-rederive:session_start:v2");
        self.instructions.put(&mut e)?;
        self.codex_prelude.put(&mut e)?;
        self.files.put(&mut e)?;
        self.config_digest.put(&mut e)?;
        // The blobs' own digests, by key (their keys and parts are stored).
        e.varint(self.claude_blobs.len() as u64)?;
        for blob in self.claude_blobs.values() {
            blob.config_digest.put(&mut e)?;
        }
        Ok(e.finish_hash())
    }

    /// Moves the re-derived opening content from a head re-parse.
    pub(super) fn adopt_durable_content(&mut self, from: &mut Self) {
        self.instructions = from.instructions.take();
        self.codex_prelude = from.codex_prelude.take();
        self.files = std::mem::take(&mut from.files);
        self.config_digest = from.config_digest.take();
        for (key, blob) in &mut self.claude_blobs {
            blob.config_digest = from
                .claude_blobs
                .get_mut(key)
                .and_then(|from| from.config_digest.take());
        }
    }

    /// Where the opening content is final (`content_end`), when known.
    pub(super) fn durable_content_end(&self) -> Option<u64> {
        self.content_end
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
            // The item's first turn takes the larger of the billing counters
            // and any single `usage.iterations[]` entry; D6 must equal it.
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
    pub(super) fn note_codex_session_meta(&mut self, row: &Value) {
        if let Some(meta) = row.get("payload") {
            self.note_client_version(str_at(meta, "cli_version"));
        }
        if self.frozen {
            return;
        }
        self.feed_codex_prelude(row);
    }

    /// Feeds the one Codex prelude parser (CROSS-LANE R1) and folds the
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
    pub(super) fn observe_codex_line(&mut self, value: &Value, cwd: Option<&Path>) {
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
    /// first-turn context, which D6 must add up to. Path hashes need the
    /// tenant attribution key; the configuration fingerprint uses the device
    /// salt.
    ///
    /// Everything request-indexed is cut to the contiguous requests actually
    /// observed: a file, truncation or tool call staged for a request the
    /// transcript has not reached yet is not sent (nor counted as overflow).
    pub(super) fn finish(
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
        // D6 only when its parts add up to the item's first-turn context: the
        // first request must reconcile exactly and be that turn. Codex takes
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

    /// X_out family U2 (#665, c22 amendment 2): an upper bound on the heap the
    /// boxed `finish` output owns, read from this state without consuming it.
    /// Moved strings (`client_version`, each file's `tool` and `repo_path`) are
    /// charged at their resident capacity, `ext` (a <= 8-byte key suffix) at
    /// its key's suffix, and `path_hash` / the config fingerprint at their
    /// fixed output length (`PATH_HASH_LEN` at most doubled by `format!`'s
    /// growth; `CONFIG_FINGERPRINT_LEN` exact). Every tracked file is charged,
    /// not only the <= 64 `finish` keeps. `None` past `limit`.
    pub(super) fn finished_heap_bound(
        &self,
        attribution: bool,
        device_salt: bool,
        limit: usize,
    ) -> Option<usize> {
        use std::mem::{align_of, size_of};
        // The `Box` slot, charged as `heap_layout_bound` charges it.
        let mut bytes = size_of::<SnapshotSessionStart>()
            .checked_add(align_of::<SnapshotSessionStart>())?
            .checked_add(self.client_version.as_ref().map_or(0, String::capacity))?;
        // `finish` collects the arrived files (amortized growth from 4, so a
        // power-of-two capacity) and maps them into candidates, which std may
        // do in that same allocation: charge the larger of the two.
        let files = self.files.len();
        let collected = if files == 0 {
            0
        } else {
            files.checked_next_power_of_two()?.max(4)
        };
        let in_place = collected.checked_mul(size_of::<(String, usize, OpeningFileState)>())?;
        let fresh = files
            .min(MAX_OPENING_FILES)
            .checked_mul(size_of::<OpeningFileCandidate>())?;
        bytes = bytes.checked_add(in_place.max(fresh))?;
        let path_hash = if attribution { 2 * PATH_HASH_LEN } else { 0 };
        for (key, file) in &self.files {
            bytes = bytes
                .checked_add(file.tool.capacity())?
                .checked_add(file.repo_path.as_ref().map_or(0, String::capacity))?
                .checked_add(extension(key).map_or(0, str::len))?
                .checked_add(path_hash)?;
        }
        if device_salt && self.config_digest.is_some() {
            bytes = bytes.checked_add(CONFIG_FINGERPRINT_LEN)?;
        }
        (bytes <= limit).then_some(bytes)
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
pub(crate) fn session_start_verdict(item: &super::SnapshotItem) -> StartVerdict {
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
pub(crate) fn uploaded_start_verdict(item: &super::SnapshotItem) -> StartVerdict {
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
mod tests {
    use super::super::{
        parse_claude_code_jsonl_file_with_title_metadata_and_attribution, parse_codex_jsonl_file,
        ClaudeTitleMetadata, SnapshotItem, SnapshotSource,
    };
    use super::*;
    use crate::codex_prelude_footprint;
    use crate::composition_kinds::shell::is_plain_path;
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

    /// The accessor agrees with the uploaded body, and both with `expected`.
    fn assert_start_verdict(item: &SnapshotItem, expected: StartVerdict) {
        assert_eq!(uploaded_start_verdict(item), expected, "uploaded body");
        assert_eq!(session_start_verdict(item), expected, "accessor");
    }

    fn attribution_context(dir: &Path) -> SessionAttributionContext {
        SessionAttributionContext::from_activity_hint(
            SnapshotSource::ClaudeCode,
            dir,
            true,
            Some(&URL_SAFE_NO_PAD.encode([11u8; 32])),
            Some(SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .expect("attribution context")
    }

    fn parse_claude(
        path: &Path,
        attribution: Option<&SessionAttributionContext>,
    ) -> Vec<SnapshotItem> {
        parse_claude_code_jsonl_file_with_title_metadata_and_attribution(
            path,
            "2026-10-18T10:05:00Z",
            "file-fingerprint".to_string(),
            &ClaudeTitleMetadata::default(),
            false,
            attribution,
        )
        .expect("parse")
    }

    const CLAUDE_COMMON: &str = r#"{"sessionId": "ss-claude-1", "cwd": "/w/repo", "version": "2.1.300", "timestamp": "2026-10-18T10:00:00Z"}"#;

    /// Requests 1-3 of a fresh Claude session; responses end at lines 6, 10
    /// and 12.
    fn claude_fixture_lines() -> Vec<Value> {
        let usage = |input: u64, read: u64, output: u64| json!({"input_tokens": input, "cache_read_input_tokens": read, "output_tokens": output});
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
        ]
    }

    /// X_out family U2 (#665, c22 amendment 2): the observed-input bound
    /// covers the boxed start `finish` builds, and the two fixed-length derived
    /// ids have exactly the length the bound charges.
    #[test]
    fn finished_heap_bound_covers_the_finished_start() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-u2-bound");
        let context = attribution_context(&dir);
        let common: Value = serde_json::from_str(CLAUDE_COMMON).unwrap();
        let mut accumulator = super::super::SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
        for mut line in claude_fixture_lines() {
            for (key, value) in common.as_object().expect("common fields") {
                line[key] = value.clone();
            }
            super::super::apply_claude_code_line(&line, &mut accumulator);
        }
        accumulator.finalize_claude_responses();
        let state = (*accumulator.session_start).clone();
        assert!(!state.files.is_empty());
        let bound = state
            .finished_heap_bound(true, true, usize::MAX)
            .expect("bound");
        assert_eq!(state.finished_heap_bound(true, true, bound - 1), None);
        let start = state
            .finish(
                true,
                accumulator.first_turn_context_tokens,
                CLAUDE_PARTS_METHOD,
                Some(&context),
                Some(&SALT),
            )
            .expect("start");
        assert!(!start.file_candidates.is_empty());
        for candidate in &start.file_candidates {
            let hash = candidate.path_hash.as_ref().expect("path hash");
            assert_eq!(hash.len(), PATH_HASH_LEN);
            assert!(hash.capacity() <= 2 * PATH_HASH_LEN, "{}", hash.capacity());
        }
        let fingerprint = start
            .start_config_fingerprint
            .as_ref()
            .expect("fingerprint");
        assert_eq!(
            (fingerprint.len(), fingerprint.capacity()),
            (CONFIG_FINGERPRINT_LEN, CONFIG_FINGERPRINT_LEN)
        );
        if crate::heap_layout_bound::layout_supported() {
            let boxed = Box::new(start);
            let finished = crate::heap_layout_bound::completed_bound(&boxed, usize::MAX)
                .expect("finished bound")
                - std::mem::size_of::<Box<SnapshotSessionStart>>();
            assert!(finished <= bound, "{finished} > {bound}");
        }
    }

    #[test]
    fn claude_fixture_yields_exact_session_start() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-claude");
        let path = dir.join("ss-claude-1.jsonl");
        write_lines(
            &path,
            serde_json::from_str(CLAUDE_COMMON).unwrap(),
            claude_fixture_lines(),
        );
        let context = attribution_context(&dir);
        let items = parse_claude(&path, Some(&context));
        assert_start_verdict(&items[0], StartVerdict::Measured);
        let parsed = items[0].session_start.clone().expect("session_start");
        // Nothing identifies a file until the upload policy is applied.
        assert!(parsed.opening_files.is_empty());
        assert_eq!(parsed.opening_file_overflow, Some(3));
        let mut start = (*parsed).clone();
        start.apply_upload_policy(true, true);
        // The policy releases the local candidates (no duplicate retention).
        assert!(start.file_candidates.is_empty());
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
        let mut hashed = (*parsed).clone();
        hashed.apply_upload_policy(false, true);
        assert_eq!(hashed.opening_files.len(), 3);
        assert_eq!(hashed.opening_file_overflow, Some(0));
        assert!(hashed
            .opening_files
            .iter()
            .all(|file| file.repo_path.is_none() && file.path_hash.is_some()));
        // A later, narrower application can only withhold more.
        hashed.apply_upload_policy(false, false);
        assert!(hashed.opening_files.is_empty());
        assert_eq!(hashed.opening_file_overflow, Some(3));
        // The same configuration text yields the same fingerprint.
        let reparsed = parse_claude(&path, None);
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
    fn partial_windows_send_only_reached_requests() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-partial");
        // Ends after response 1 and its tool results, then after response 2.
        for (end, count) in [(10, 1), (12, 2)] {
            let path = dir.join(format!("ss-claude-partial-{count}.jsonl"));
            let mut lines = claude_fixture_lines();
            lines.truncate(end);
            write_lines(&path, serde_json::from_str(CLAUDE_COMMON).unwrap(), lines);
            let items = parse_claude(&path, None);
            let mut start = (*items[0].session_start.clone().expect("session_start")).clone();
            start.apply_upload_policy(true, true);
            assert_eq!(start.opening_request_count, Some(count));
            assert_eq!(start.request_3_context_tokens, None);
            assert_eq!(start.opening_file_overflow, Some(0));
            // Admission drops a row beyond the count; none is sent.
            assert!(start
                .opening_files
                .iter()
                .all(|file| u64::from(file.request) <= count));
            if count == 1 {
                assert_eq!(start.request_2_context_tokens, None);
                assert!(start.opening_files.is_empty());
                assert_eq!(start.opening_tool_calls, Some(2));
                assert_eq!(start.opening_truncated_outputs, Some(0));
            } else {
                assert_eq!(start.request_2_context_tokens, Some(305));
                let shown = start
                    .opening_files
                    .iter()
                    .map(|file| file.repo_path.as_deref())
                    .collect::<Vec<_>>();
                assert_eq!(shown, [Some("docs/guide.md"), Some("src/CLAUDE.md")]);
                assert_eq!(start.opening_tool_calls, Some(3));
                assert_eq!(start.opening_truncated_outputs, Some(1));
            }
        }
    }

    /// A file read in request 2 and again in an unreached request 3 reports
    /// only its request-2 observation.
    #[test]
    fn later_observations_of_a_file_wait_for_their_request() {
        let cwd = Path::new("/w/repo");
        let mut state = SessionStartState {
            instructions: Some("See docs/guide.md".to_string()),
            ..SessionStartState::default()
        };
        let read = |id: &str| {
            json!({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": id, "name": "Read", "input": {"file_path": "/w/repo/docs/guide.md"}}]}})
        };
        let result = |id: &str, text: &str| {
            json!({"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": id, "content": text}]}})
        };
        state.observe_claude_line(&read("t1"), 1, Some(cwd));
        state.observe_claude_line(&result("t1", "abcd"), 1, Some(cwd));
        state.observe_claude_line(&read("t2"), 2, Some(cwd));
        state.observe_claude_line(&result("t2", "efghij"), 2, Some(cwd));
        state.observe_claude_line(
            &json!({"type": "attachment", "attachment": {"type": "read_truncation_notice", "toolUseID": "t2"}}),
            2,
            Some(cwd),
        );
        state.note_claude_response(0, &UsageTotals::default(), 1, 1);
        state.note_claude_response(1, &UsageTotals::default(), 2, 1);
        let mut start = state
            .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        start.apply_upload_policy(true, false);
        assert_eq!(start.opening_request_count, Some(2));
        assert_eq!(start.opening_truncated_outputs, Some(0));
        assert_eq!(
            start.opening_files,
            [SnapshotOpeningFile {
                request: 2,
                tool: "Read".to_string(),
                repo_path: Some("docs/guide.md".to_string()),
                chars: 4,
                reads: 1,
                instruction_segments: 2,
                ..SnapshotOpeningFile::default()
            }]
        );
    }

    #[test]
    fn single_iteration_context_omits_unreconciled_first_request_parts() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-iteration");
        let path = dir.join("ss-claude-iteration.jsonl");
        write_lines(
            &path,
            serde_json::from_str(CLAUDE_COMMON).unwrap(),
            vec![
                json!({"type": "user", "message": {"role": "user", "content": "hi"}}),
                json!({"type": "assistant", "requestId": "r1", "message": {"id": "m1", "role": "assistant", "model": "claude-fable-5-1",
                    "usage": {"input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 1,
                        "iterations": [{"input_tokens": 100, "cache_read_input_tokens": 200}]},
                    "content": [{"type": "text", "text": "ok"}]}}),
            ],
        );
        let items = parse_claude(&path, None);
        // The item's first turn is the iteration's context; billing usage says 0.
        assert_eq!(items[0].first_turn_context_tokens, Some(300));
        let start = items[0].session_start.clone().expect("session_start");
        assert_eq!(start.opening_request_count, Some(1));
        assert_eq!(start.first_request_uncached_input_tokens, None);
        assert_eq!(start.first_request_cache_read_tokens, None);
        assert_eq!(start.first_request_cache_write_5m_tokens, None);
        assert_eq!(start.first_request_cache_write_1h_tokens, None);
    }

    const CODEX_SESSION: &str = "019e253c-7777-7000-9000-aaaaaaaaaaaa";

    fn codex_token_count(total: (u64, u64, u64), last: (u64, u64, u64)) -> Value {
        let usage = |(input, cached, output): (u64, u64, u64)| json!({"input_tokens": input, "cached_input_tokens": cached, "output_tokens": output});
        json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
            "total_token_usage": usage(total), "last_token_usage": usage(last), "model": "gpt-5.5"}}})
    }

    fn codex_call(id: &str) -> Value {
        json!({"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": id, "arguments": "{}"}})
    }

    fn codex_message(role: &str, blocks: &[(&str, &str)]) -> Value {
        json!({"type": "response_item", "payload": {"type": "message", "role": role,
            "content": blocks.iter().map(|(_, text)| json!({"type": "input_text", "text": text})).collect::<Vec<_>>(),
            "internal_chat_message_metadata_passthrough": {"content_item_kinds":
                blocks.iter().map(|(kind, _)| *kind).collect::<Vec<_>>()}}})
    }

    fn write_codex(dir: &Path, name: &str, lines: Vec<Value>) -> std::path::PathBuf {
        let path = dir.join(format!("rollout-2026-10-18T10-00-00-{name}.jsonl"));
        write_lines(&path, json!({"timestamp": "2026-10-18T10:00:00Z"}), lines);
        path
    }

    #[test]
    fn codex_fixture_yields_exact_session_start() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-codex");
        let path = write_codex(
            &dir,
            CODEX_SESSION,
            vec![
                json!({"type": "session_meta", "payload": {"id": CODEX_SESSION, "cwd": "/w/repo", "cli_version": "0.160.0",
                    "base_instructions": {"text": "BASE instructions"}}}),
                codex_message(
                    "developer",
                    &[
                        (codex_prelude_footprint::BASE_INSTRUCTIONS_KIND, "BASE instructions"),
                        ("permissions.instructions", "<permissions>p</permissions>"),
                    ],
                ),
                codex_message(
                    "user",
                    &[
                        (codex_prelude_footprint::AGENTS_MD_KIND, "# AGENTS.md instructions for /w/repo\n\n<INSTRUCTIONS>\nSee docs/guide.md\n</INSTRUCTIONS>"),
                        (codex_prelude_footprint::HOST_SKILLS_KIND, "<skills>s</skills>"),
                        ("user.text", "fix it"),
                    ],
                ),
                json!({"type": "world_state", "payload": {"full": true, "state": {
                    "agents_md": {"directory": "/w/repo", "text": "See docs/guide.md"}}}}),
                json!({"type": "response_item", "payload": {"type": "additional_tools", "tools": [{"name": "x"}]}}),
                json!({"type": "event_msg", "payload": {"type": "task_started", "turn_id": "turn-1"}}),
                codex_call("c1"),
                json!({"type": "event_msg", "payload": {"type": "exec_command_end", "call_id": "c1", "cwd": "/w/repo", "parsed_cmd": [
                    {"type": "read", "cmd": "cat docs/guide.md", "name": "guide.md", "path": "docs/guide.md"}]}}),
                json!({"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c1",
                    "output": "Warning: truncated output\nabc"}}),
                codex_token_count((1000, 800, 50), (1000, 800, 50)),
                // A re-emitted record is not a second request.
                codex_token_count((1000, 800, 50), (1000, 800, 50)),
                codex_call("c2"),
                json!({"type": "event_msg", "payload": {"type": "exec_command_end", "call_id": "c2", "parsed_cmd": [
                    {"type": "unknown", "cmd": "sed -n 1,5p /w/repo/docs/guide.md"}]}}),
                json!({"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c2", "output": "0123456789"}}),
                codex_token_count((2100, 1800, 80), (1100, 1000, 30)),
                codex_token_count((3300, 2900, 100), (1200, 1100, 20)),
            ],
        );
        let items =
            parse_codex_jsonl_file(&path, "2026-10-18T10:05:00Z", "file-fingerprint".into())
                .expect("parse");
        assert_start_verdict(&items[0], StartVerdict::Measured);
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

    /// The snapshot pass and the footprint reader see one prelude: the same
    /// rows through `parse_prelude` and through the snapshot's decoded-line
    /// hooks give the same parse, and the wire parts are its counts.
    #[test]
    fn codex_prelude_parity_between_reader_and_decoded_lines() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-codex-parity");
        let cwd = Path::new("/w/repo");
        let rows = |malformed: bool| {
            let mut rows = vec![
                json!({"type": "session_meta", "payload": {"id": CODEX_SESSION, "cwd": "/w/repo", "cli_version": "0.160.0",
                    "base_instructions": "BASE"}}),
                codex_message("developer", &[("permissions.instructions", "PERMS")]),
                // The rendered copy differs from the loaded body in world_state.
                codex_message(
                    "user",
                    &[
                        (codex_prelude_footprint::AGENTS_MD_KIND, "# AGENTS.md instructions for /w/repo\n\n<INSTRUCTIONS>\nWRAPPED copy\n</INSTRUCTIONS>"),
                        ("environments.environment_context", "<env/>"),
                    ],
                ),
                json!({"type": "world_state", "payload": {"full": true, "state": {
                    "agents_md": {"directory": "/w/repo", "text": "Body names docs/guide.md"},
                    "host_skills": {"body": "SKILLS BODY"}}}}),
                codex_message("developer", &[("hooks.additional_context", "HOOK")]),
                json!({"type": "response_item", "payload": {"type": "additional_tools", "tools": [{"name": "x"}]}}),
                codex_message("user", &[("user.text", "go")]),
                json!({"type": "response_item", "payload": {"type": "reasoning"}}),
                // After the model answered: request 2's input, never request 1's.
                codex_message("developer", &[("hooks.additional_context", "LATE")]),
                codex_call("c1"),
                json!({"type": "event_msg", "payload": {"type": "exec_command_end", "call_id": "c1", "cwd": "/w/repo", "parsed_cmd": [
                    {"type": "read", "cmd": "cat docs/guide.md", "path": "docs/guide.md"}]}}),
                json!({"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c1", "output": "abc"}}),
                codex_token_count((1000, 800, 50), (1000, 800, 50)),
                codex_token_count((2100, 1800, 80), (1100, 1000, 30)),
            ];
            if malformed {
                let mut row = codex_message("user", &[("user.text", "x")]);
                row["payload"]["internal_chat_message_metadata_passthrough"]
                    ["content_item_kinds"] = json!([7]);
                rows.insert(6, row);
            }
            rows
        };
        let reader = |rows: &[Value]| {
            let bytes = rows
                .iter()
                .map(|row| row.to_string() + "\n")
                .collect::<String>();
            codex_prelude_footprint::parse_prelude(std::io::Cursor::new(bytes)).expect("reader")
        };
        let decoded = |rows: &[Value]| {
            let mut state = SessionStartState::default();
            for row in rows {
                if str_at(row, "type") == Some("session_meta") {
                    state.note_codex_session_meta(row);
                } else {
                    state.observe_codex_line(row, Some(cwd));
                }
            }
            state.codex_prelude.expect("parser").finish()
        };
        let read = reader(&rows(false));
        assert!(read.world_state_seen && read.input_closed && !read.blocks_incomplete);
        // The footprint's prelude totals run to the first usage record;
        // request-1 parts stop at the model's first output.
        assert_eq!((read.hook_chars, read.chars(BlockKind::Hooks)), (8, 4));
        assert_eq!(read.skills_body.as_deref(), Some("SKILLS BODY"));
        // The snapshot keeps no skills body; everything else is identical.
        assert_eq!(
            decoded(&rows(false)),
            codex_prelude_footprint::CodexPrelude {
                skills_body: None,
                ..read.clone()
            }
        );
        let path = write_codex(&dir, CODEX_SESSION, rows(false));
        let items =
            parse_codex_jsonl_file(&path, "2026-10-18T10:05:00Z", "fp".into()).expect("parse");
        let mut start = items[0].session_start.clone().expect("session_start");
        assert_eq!(start.start_chars_system, Some(read.base_instructions_chars));
        assert_eq!(
            start.start_chars_instructions,
            Some(read.chars(BlockKind::AgentsMd))
        );
        assert_eq!(
            start.start_chars_hooks_env,
            Some(read.chars(BlockKind::Hooks) + read.chars(BlockKind::Environment))
        );
        assert_eq!(start.start_chars_prompt, Some(2));
        assert_eq!(start.start_chars_skills, Some(0));
        assert_eq!(start.start_chars_tools, Some(13));
        // Paths match the loaded body, not its rendered copy.
        start.apply_upload_policy(true, false);
        assert_eq!(start.opening_files.len(), 1);
        assert_eq!(
            start.opening_files[0].repo_path.as_deref(),
            Some("docs/guide.md")
        );
        assert_eq!(start.opening_files[0].instruction_segments, 2);

        // A request-1 block without a string label: no parts on either path.
        let read = reader(&rows(true));
        assert!(read.blocks_incomplete);
        assert!(decoded(&rows(true)).blocks_incomplete);
        let path = write_codex(&dir, "019e253c-7777-7000-9000-bbbbbbbbbbbb", rows(true));
        let items =
            parse_codex_jsonl_file(&path, "2026-10-18T10:05:00Z", "fp".into()).expect("parse");
        let start = items[0].session_start.clone().expect("session_start");
        assert_eq!(start.start_parts_method, None);
        assert_eq!(start.opening_request_count, Some(2));
    }

    fn measured_codex_state(agents_md: &str, requests: usize) -> SessionStartState {
        let mut state = SessionStartState::default();
        state.note_codex_session_meta(&json!({"type": "session_meta", "payload": {
            "id": "s1", "cwd": "/w/repo", "cli_version": "0.160.0", "base_instructions": "BASE"}}));
        state.observe_codex_line(
            &json!({"type": "world_state", "payload": {"state": {"agents_md": {"text": agents_md}}}}),
            None,
        );
        state.note_user_turn();
        for _ in 0..requests {
            state.note_codex_request(&UsageTotals {
                input_tokens: 10,
                ..UsageTotals::default()
            });
        }
        state
    }

    #[test]
    fn forks_and_copied_prefixes_keep_only_client_version() {
        let only_version = Some(SnapshotSessionStart {
            client_version: Some("0.160.0".to_string()),
            ..SnapshotSessionStart::default()
        });
        let fresh = measured_codex_state("", 1)
            .finish(true, None, CODEX_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        assert_eq!(fresh.opening_request_count, Some(1));
        assert_eq!(
            measured_codex_state("", 1).finish(false, None, CODEX_PARTS_METHOD, None, Some(&SALT)),
            only_version
        );
        let mut copied = measured_codex_state("", 1);
        copied.note_inherited_prefix();
        assert_eq!(
            copied.finish(true, None, CODEX_PARTS_METHOD, None, Some(&SALT)),
            only_version
        );
        assert_eq!(fresh.inherited(), only_version);
        // Nothing measured: the field is omitted.
        assert_eq!(
            SessionStartState::default().finish(true, None, CODEX_PARTS_METHOD, None, Some(&SALT)),
            None
        );
        assert_eq!(SnapshotSessionStart::default().inherited(), None);
    }

    #[test]
    fn full_parser_forks_keep_only_client_version() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-forks");
        // Claude: a fork copies its parent's records first.
        let path = dir.join("ss-claude-fork.jsonl");
        let mut lines = claude_fixture_lines();
        lines.insert(
            0,
            json!({"type": "user", "forkedFrom": {"sessionId": "parent", "messageUuid": "u0"},
                "message": {"role": "user", "content": "copied"}}),
        );
        write_lines(&path, serde_json::from_str(CLAUDE_COMMON).unwrap(), lines);
        let items = parse_claude(&path, None);
        assert_eq!(
            items[0].session_start.as_deref(),
            Some(&SnapshotSessionStart {
                client_version: Some("2.1.300".to_string()),
                ..SnapshotSessionStart::default()
            })
        );
        assert_start_verdict(&items[0], StartVerdict::NotMeasured);
        // Codex: a subagent fork with its parent's copied prefix (the shape
        // of `codex_legacy_full_fork_excludes_inherited_usage_activity_and_posture`).
        let token = |at: &str, total: (u64, u64, u64), last: (u64, u64, u64)| {
            let mut row = codex_token_count(total, last);
            row["timestamp"] = json!(at);
            row
        };
        let path = dir.join("rollout-2026-08-02T06-00-00-child-fork.jsonl");
        let rows = [
            json!({"timestamp": "2026-08-02T06:00:00Z", "type": "session_meta", "payload": {
                "id": "child-fork", "forked_from_id": "root", "cli_version": "0.160.0",
                "thread_source": "subagent",
                "source": {"subagent": {"thread_spawn": {"parent_thread_id": "root"}}}}}),
            token("2026-08-02T06:00:01Z", (1_000, 800, 100), (1_000, 800, 100)),
            json!({"timestamp": "2026-08-02T06:00:02Z", "type": "compacted", "payload": {"replacement_history": []}}),
            json!({"timestamp": "2026-08-02T06:00:03Z", "type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": "inherited"}}),
            json!({"timestamp": "2026-08-02T06:00:04Z", "type": "event_msg", "payload": {"type": "task_complete", "duration_ms": 900, "time_to_first_token_ms": 90}}),
            json!({"timestamp": "2026-08-02T06:00:05Z", "type": "session_meta", "payload": {"id": "root", "thread_source": "user"}}),
            json!({"timestamp": "2026-08-02T06:00:58Z", "type": "event_msg", "payload": {"type": "task_started"}}),
            json!({"timestamp": "2026-08-02T06:00:59Z", "type": "turn_context", "payload": {"model": "gpt-5.6-sol", "turn_id": "owned-turn", "effort": "high"}}),
            json!({"timestamp": "2026-08-02T06:01:00Z", "type": "inter_agent_communication_metadata", "payload": {"trigger_turn": true}}),
            token("2026-08-02T06:01:02Z", (1_100, 880, 110), (100, 80, 10)),
            json!({"timestamp": "2026-08-02T06:01:04Z", "type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": "owned"}}),
            json!({"timestamp": "2026-08-02T06:01:05Z", "type": "event_msg", "payload": {"type": "task_complete", "duration_ms": 100, "time_to_first_token_ms": 10}}),
        ];
        std::fs::write(
            &path,
            rows.iter()
                .map(|row| row.to_string() + "\n")
                .collect::<String>(),
        )
        .expect("write fork fixture");
        let items =
            parse_codex_jsonl_file(&path, "2026-10-18T10:05:00Z", "fp".into()).expect("parse");
        assert!(!items.is_empty());
        for item in items {
            assert_eq!(
                item.session_start.as_deref(),
                Some(&SnapshotSessionStart {
                    client_version: Some("0.160.0".to_string()),
                    ..SnapshotSessionStart::default()
                })
            );
            assert_start_verdict(&item, StartVerdict::NotMeasured);
        }
    }

    /// Version and config fingerprint alone are not a measured start; any
    /// other stored value is.
    #[test]
    fn start_verdict_needs_a_value_beyond_version_and_fingerprint() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-verdict");
        let path = dir.join("ss-claude-verdict.jsonl");
        write_lines(
            &path,
            serde_json::from_str(CLAUDE_COMMON).unwrap(),
            claude_fixture_lines(),
        );
        let mut item = parse_claude(&path, None).remove(0);
        let version_only = SnapshotSessionStart {
            client_version: Some("2.1.300".to_string()),
            start_config_fingerprint: Some("0123456789abcdef".to_string()),
            ..SnapshotSessionStart::default()
        };
        let cases = [
            (None, StartVerdict::NotMeasured),
            (Some(version_only.clone()), StartVerdict::NotMeasured),
            (
                Some(SnapshotSessionStart {
                    user_turn_count: Some(1),
                    ..version_only.clone()
                }),
                StartVerdict::Measured,
            ),
            (
                Some(SnapshotSessionStart {
                    instruction_load_cut: Some(false),
                    ..version_only.clone()
                }),
                StartVerdict::Measured,
            ),
            (
                Some(SnapshotSessionStart {
                    start_chars_other: Some(0),
                    ..version_only
                }),
                StartVerdict::Measured,
            ),
        ];
        for (start, expected) in cases {
            item.session_start = start.map(Box::new);
            assert_start_verdict(&item, expected);
        }
    }

    /// The shared prelude parser's copied-history verdict also gates the
    /// snapshot: an ordinary first header followed by another session's
    /// header before the first usage is not a fresh start.
    #[test]
    fn copied_codex_prelude_keeps_only_client_version() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-copied-prelude");
        let path = write_codex(
            &dir,
            CODEX_SESSION,
            vec![
                json!({"type": "session_meta", "payload": {"id": CODEX_SESSION, "cwd": "/w/repo",
                    "cli_version": "0.160.0", "thread_source": "user"}}),
                json!({"type": "session_meta", "payload": {"id": "019e253c-7777-7000-9000-bbbbbbbbbbbb",
                    "cwd": "/w/repo", "thread_source": "user"}}),
                codex_message("user", &[("user.text", "fix it")]),
                json!({"type": "world_state", "payload": {"full": true, "state": {
                    "agents_md": {"directory": "/w/repo", "text": "See docs/guide.md"}}}}),
                codex_token_count((1000, 800, 50), (1000, 800, 50)),
            ],
        );
        let items =
            parse_codex_jsonl_file(&path, "2026-10-18T10:05:00Z", "file-fingerprint".into())
                .expect("parse");
        assert!(!items.is_empty());
        for item in items {
            assert_eq!(
                item.session_start.as_deref(),
                Some(&SnapshotSessionStart {
                    client_version: Some("0.160.0".to_string()),
                    ..SnapshotSessionStart::default()
                })
            );
            assert_start_verdict(&item, StartVerdict::NotMeasured);
        }
    }

    /// The item's first turn can come from a response the request count does
    /// not admit (no cumulative usage); D6 then describes another request.
    #[test]
    fn codex_first_turn_without_cumulative_usage_omits_first_request_parts() {
        let dir = crate::test_scratch::ScratchDir::new("session-start-codex-first-turn");
        let usage = |input: u64, cached: u64| json!({"input_tokens": input, "cached_input_tokens": cached, "output_tokens": 1});
        let path = write_codex(
            &dir,
            CODEX_SESSION,
            vec![
                json!({"type": "session_meta", "payload": {"id": CODEX_SESSION, "cwd": "/w/repo",
                    "cli_version": "0.160.0", "thread_source": "user"}}),
                codex_message("user", &[("user.text", "fix it")]),
                json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
                    "last_token_usage": usage(100, 20), "model": "gpt-5.5"}}}),
                json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
                    "total_token_usage": usage(200, 50), "last_token_usage": usage(200, 50),
                    "model": "gpt-5.5"}}}),
            ],
        );
        let items =
            parse_codex_jsonl_file(&path, "2026-10-18T10:05:00Z", "file-fingerprint".into())
                .expect("parse");
        assert_eq!(items[0].first_turn_context_tokens, Some(100));
        let start = items[0].session_start.clone().expect("session_start");
        assert_eq!(start.opening_request_count, Some(1));
        assert_eq!(start.first_request_uncached_input_tokens, None);
        assert_eq!(start.first_request_cache_read_tokens, None);
        assert_eq!(start.first_request_cache_write_5m_tokens, None);
        assert_eq!(start.first_request_cache_write_1h_tokens, None);
    }

    #[test]
    fn opening_files_cap_at_64_and_count_withheld_entries() {
        let cwd = Path::new("/w/repo");
        let mut state = measured_codex_state("", 2);
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
        // Staged for request 3, which the session never reached.
        state.note_client_load("/w/repo/late.md", "nested_memory", 1, 3, Some(cwd));
        let mut start = state
            .finish(true, None, CODEX_PARTS_METHOD, None, Some(&SALT))
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
            .all(|file| file.path_hash.is_none() && file.request == 2));
        // Applying the same policy again changes nothing.
        let applied = start.clone();
        start.apply_upload_policy(true, false);
        assert_eq!(start, applied);
        let wire = serde_json::to_value(&start).expect("serialize");
        assert_eq!(wire["opening_files"].as_array().expect("files").len(), 63);
        assert!(wire.get("file_candidates").is_none());
    }

    #[test]
    fn instruction_cap_makes_file_facts_unknown() {
        let cwd = Path::new("/w/repo");
        let mut state = SessionStartState::default();
        let content = "x".repeat(MAX_HELD_INSTRUCTION_BYTES) + " docs/late.md";
        state.observe_claude_line(
            &json!({"type": "attachment", "version": "2.1.300", "attachment": {"type": "instructions",
                "files": [{"type": "Project", "content": content}]}}),
            0,
            Some(cwd),
        );
        state.observe_claude_line(
            &json!({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/w/repo/docs/late.md"}}]}}),
            1,
            Some(cwd),
        );
        state.note_claude_response(0, &UsageTotals::default(), 1, 1);
        state.note_claude_response(1, &UsageTotals::default(), 2, 0);
        let mut start = state
            .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        start.apply_upload_policy(true, true);
        assert!(start.opening_files.is_empty());
        assert_eq!(start.opening_file_overflow, None);
        // Every other fact stays.
        assert_eq!(start.opening_request_count, Some(2));
        assert_eq!(start.request_2_context_tokens, Some(2));
        assert_eq!(start.opening_tool_calls, Some(1));
        let wire = serde_json::to_value(&start).expect("serialize");
        assert!(wire.get("opening_files").is_none() && wire.get("opening_file_overflow").is_none());
    }

    #[test]
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux")),
        ignore = "needs macOS heap layout"
    )]
    fn held_state_stays_within_its_capacity_budget() {
        let mut held = String::new();
        assert!(!push_capped(&mut held, &"x".repeat(300 * 1024)));
        assert!(!push_capped(&mut held, "more"));
        assert_eq!(held.capacity(), MAX_HELD_INSTRUCTION_BYTES);
        // Codex: the shared parser holds the AGENTS.md text and its own small
        // strings beside the collections.
        let mut state = SessionStartState::default();
        let long = "p".repeat(codex_prelude_footprint::MAX_SMALL_TEXT_BYTES);
        state.note_codex_session_meta(&json!({"type": "session_meta", "payload": {
            "id": long, "cwd": long, "cli_version": "0.160.0"}}));
        state.observe_codex_line(
            &json!({"type": "turn_context", "payload": {"model": long}}),
            None,
        );
        state.observe_codex_line(
            &json!({"type": "world_state", "payload": {"state": {"agents_md": {
                "directory": long, "text": "y".repeat(300 * 1024)}}}}),
            None,
        );
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
        assert!(state.files_untracked[0] > 1900);
        assert!(state.file_matching_incomplete());
        let held = crate::heap_layout_bound::bound(&state, usize::MAX).expect("layout");
        assert!(held <= MAX_HELD_BYTES, "held {held}");
        state.freeze();
        assert!(state.instructions.is_none() && state.calls.is_empty());
        let frozen = crate::heap_layout_bound::bound(&state, usize::MAX).expect("layout");
        assert!(
            frozen
                <= MAX_HELD_COLLECTION_BYTES + MAX_HELD_INSTRUCTION_BYTES
                    - MAX_CODEX_AGENTS_MD_BYTES,
            "frozen {frozen}"
        );
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
        let cwd = Some(Path::new("/w/repo"));
        assert_eq!(
            normalize_path("/w/repo/a/b.rs", cwd, true),
            Some(("a/b.rs".to_string(), Some("a/b.rs".to_string())))
        );
        assert_eq!(
            normalize_path("/w/repo-other/b.rs", cwd, true),
            Some(("/w/repo-other/b.rs".to_string(), None))
        );
        assert_eq!(
            normalize_path("../up.rs", cwd, true),
            Some(("../up.rs".to_string(), None))
        );
        assert_eq!(
            normalize_path("a/b.rs", cwd, false),
            Some(("a/b.rs".to_string(), None))
        );
        // No session directory: a relative path has no proven base.
        assert_eq!(
            normalize_path("a/b.rs", None, true),
            Some(("a/b.rs".to_string(), None))
        );
        assert!(shell_changes_directory("cd /tmp && cat x.md"));
        assert!(shell_changes_directory("(pushd d; ls)"));
        assert!(shell_changes_directory("git -C ../other status"));
        assert!(shell_changes_directory("env -C/private/notes cat x.md"));
        assert!(shell_changes_directory("make -Cdir all"));
        assert!(shell_changes_directory("env --chdir=/p cat x.md"));
        assert!(shell_changes_directory("bash -lc 'cd /p && cat x.md'"));
        assert!(shell_changes_directory("sh -c \"cd /p; cat x.md\""));
        assert!(!shell_changes_directory("cat docs/cdn.md"));
        assert_eq!(
            shell_path_tokens("sed -n 1,5p a/b.md | grep x > out.txt").collect::<Vec<_>>(),
            ["a/b.md", "out.txt"]
        );
        assert_eq!(json_units(&json!({"a": [1, "\u{1f600}"]})), 16);
    }

    /// Plain paths follow admission's `_safe_relative_path`; anything it would
    /// reject travels hashed or is withheld, never sent plain.
    #[test]
    fn plain_paths_and_tool_labels_follow_admission() {
        for path in [
            "src/users/model.rs",
            "docs/home/setup.md",
            "Docs/Transcript_Path.md",
            "a\\..\\b.md",
            "C:/x.md",
            "a  b.md",
            " x.md",
            "x.md ",
            "a\tb.md",
            "../x.md",
            "~/x.md",
            "/x.md",
            "",
        ] {
            assert!(!is_plain_path(path), "{path:?}");
        }
        for path in [
            "docs/guide.md",
            "users/model.rs",
            "a b.md",
            "src/.hidden/x.rs",
        ] {
            assert!(is_plain_path(path), "{path:?}");
        }
        assert_eq!(tool_label("mcp__server__tool"), "mcp");
        assert_eq!(tool_label("exec_command"), "exec_command");
        assert_eq!(tool_label("Bad Name"), "unknown");
        assert_eq!(tool_label(""), "unknown");
        assert_eq!(tool_label(&"x".repeat(70)).len(), MAX_TOOL_LABEL_CHARS);

        // End to end: an ordinary path admission would refuse travels hashed.
        let dir = crate::test_scratch::ScratchDir::new("session-start-plain-path");
        let context = attribution_context(&dir);
        let cwd = Path::new("/w/repo");
        let mut state = SessionStartState {
            instructions: Some("Models live in src/users/model.rs".to_string()),
            ..SessionStartState::default()
        };
        state.observe_claude_line(
            &json!({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/w/repo/src/users/model.rs"}}]}}),
            1,
            Some(cwd),
        );
        state.note_claude_response(0, &UsageTotals::default(), 1, 1);
        state.note_claude_response(1, &UsageTotals::default(), 2, 0);
        let start = state
            .finish(true, None, CLAUDE_PARTS_METHOD, Some(&context), Some(&SALT))
            .expect("measured");
        let mut labels_only = start.clone();
        labels_only.apply_upload_policy(true, false);
        assert!(labels_only.opening_files.is_empty());
        assert_eq!(labels_only.opening_file_overflow, Some(1));
        let mut hashed = start;
        hashed.apply_upload_policy(true, true);
        let wire = serde_json::to_value(&hashed).expect("serialize");
        assert_eq!(
            wire["opening_files"],
            json!([{"request": 2, "tool": "Read",
                "path_hash": context.opaque_id("opening_path", "src/users/model.rs").expect("hash"),
                "ext": "rs", "chars": 0, "reads": 1, "instruction_segments": 3,
                "client_loaded": false, "truncated": false}])
        );
    }

    #[test]
    fn relative_shell_paths_without_a_proven_base_stay_private() {
        let cwd = Path::new("/w/repo");
        let bash = |id: &str, command: &str| {
            json!({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": id, "name": "Bash", "input": {"command": command}}]}})
        };
        let mut state = SessionStartState {
            instructions: Some(
                "Notes live in customer-plan.md, plan.md and docs/guide.md".to_string(),
            ),
            ..SessionStartState::default()
        };
        state.observe_claude_line(&bash("t1", "cat docs/guide.md"), 1, Some(cwd));
        // An attached `-C<dir>` moves the shell too.
        state.observe_claude_line(
            &bash("t2", "env -C/private/notes cat plan.md"),
            1,
            Some(cwd),
        );
        // Claude's shell keeps the new directory for later calls too.
        state.observe_claude_line(&bash("t3", "cat other/customer-plan.md"), 2, Some(cwd));
        for sequence in 0..3 {
            state.note_claude_response(sequence, &UsageTotals::default(), 1, 1);
        }
        let mut start = state
            .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        start.apply_upload_policy(true, false);
        let shown = start
            .opening_files
            .iter()
            .map(|file| file.repo_path.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(shown, [Some("docs/guide.md")]);
        assert_eq!(start.opening_file_overflow, Some(2));

        // No session directory: nothing relative is shown.
        let mut state = SessionStartState {
            instructions: Some("docs/guide.md".to_string()),
            ..SessionStartState::default()
        };
        state.observe_claude_line(&bash("t1", "cat docs/guide.md"), 1, None);
        state.note_claude_response(0, &UsageTotals::default(), 1, 1);
        state.note_claude_response(1, &UsageTotals::default(), 1, 0);
        let mut start = state
            .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        start.apply_upload_policy(true, false);
        assert!(start.opening_files.is_empty());
        assert_eq!(start.opening_file_overflow, Some(1));

        // Codex: a record at another cwd, one that changes directory, or one
        // without a cwd (whatever its call's `workdir`) proves no base.
        let mut codex = measured_codex_state("customer-plan.md docs/guide.md notes/todo.md", 2);
        for (id, record) in [
            (
                "c1",
                json!({"cwd": "/private/notes", "parsed_cmd": [{"type": "read", "cmd": "cat customer-plan.md", "path": "customer-plan.md"}]}),
            ),
            (
                "c2",
                json!({"cwd": "/w/repo/", "command": ["bash", "-lc", "cd .. && cat docs/guide.md"], "parsed_cmd": [{"type": "read", "cmd": "cat docs/guide.md", "path": "docs/guide.md"}]}),
            ),
            (
                "c3",
                json!({"parsed_cmd": [{"type": "read", "cmd": "cat docs/guide.md", "path": "docs/guide.md"}]}),
            ),
            (
                "c4",
                json!({"cwd": "/w/repo", "parsed_cmd": [{"type": "read", "cmd": "cat notes/todo.md", "path": "notes/todo.md"}]}),
            ),
        ] {
            codex.open_call(id, 1, "exec_command");
            codex.codex_parsed_command(id, &record, Some(cwd));
        }
        let mut start = codex
            .finish(true, None, CODEX_PARTS_METHOD, None, Some(&SALT))
            .expect("measured");
        start.apply_upload_policy(true, false);
        let shown = start
            .opening_files
            .iter()
            .map(|file| file.repo_path.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(shown, [Some("notes/todo.md")]);
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
            .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT))
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
        let mut state = measured_codex_state("", 1);
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
                        shadow.note_codex_session_meta(value);
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
                let mut responses = parser
                    .claude_responses
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                responses.sort_by_key(|response| response.sequence);
                for response in responses.into_iter().filter_map(|response| {
                    response.resolve_with(&parser.claude_responses.selectors)
                }) {
                    shadow.note_claude_response(
                        response.sequence,
                        &response.usage,
                        response
                            .computed_effective_input_context
                            .unwrap_or_else(|| response.usage.effective_input_context()),
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
            // Upper bound on the wire: D6 is kept whenever request 1 reconciles.
            let first_turn = shadow.requests[0].map(|request| request.context_tokens);
            let finished = shadow.finish(true, first_turn, method, None, Some(&SALT));
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

    /// M1, SOURCE P2-5: an opening call's `L` span is its id alone, apart
    /// from the tool name its `OpeningCall` holds (`U`); request-shape and
    /// blob keys are held only as their domain-separated digests, and an
    /// incoming raw key still finds its entry.
    #[test]
    fn opening_call_ids_are_the_only_l_span_and_request_keys_are_digests() {
        use crate::durable_tail_codec::{take_l_spans, Durable, Enc};
        let mut state = SessionStartState::default();
        state.open_call("call_CANARYSPLITcx", 1, "call_NAMEHALFcx");
        assert!(state.calls.contains_key("call_CANARYSPLITcx"));
        state.claude_blob(&json!({"hash": "blob-RAWKEY", "message": {"role": "user",
            "content": [{"type": "text", "text": "hello"}]}}));
        state.claude_shape(
            &json!({"shapeHash": "shape-RAWKEY", "shape": {"system": [], "tools": []}}),
        );
        assert!(state
            .claude_blobs
            .contains_key(&ClaudeRequestKey::blob("blob-RAWKEY")));
        assert_eq!(
            state.claude_shape.map(|(key, ..)| key),
            Some(ClaudeRequestKey::shape("shape-RAWKEY"))
        );
        take_l_spans();
        let mut e = Enc::bytes(1 << 20);
        state.put(&mut e).unwrap();
        let body = e.into_bytes();
        let spans = take_l_spans();
        let at = |needle: &str| {
            body.windows(needle.len())
                .position(|window| window == needle.as_bytes())
        };
        assert!(at("RAWKEY").is_none(), "a raw request key reached the body");
        let id = at("call_CANARYSPLITcx").unwrap();
        let leaf = spans
            .iter()
            .filter(|(start, end, _)| *start <= id && id + 18 <= *end)
            .min_by_key(|(start, end, _)| end - start)
            .map(|(_, _, path)| *path);
        assert_eq!(leaf, Some("OpeningCallId.id"));
        let label = tool_label("call_NAMEHALFcx");
        let name = at(&label).unwrap();
        assert!(
            spans
                .iter()
                .all(|(start, end, _)| name >= *end || name + label.len() <= *start),
            "the tool name sits inside an L span"
        );
        // The request then measures through the hashed keys.
        state.claude_request(&json!({"shapeHash": "shape-RAWKEY", "tail": ["blob-RAWKEY"]}));
        assert!(!state.parts_unmeasurable);
    }

    /// F1: `ConfigDigest` is a reversible rolling digest of instruction text,
    /// so it is content (`X`) on both sources: an encoded record carries none
    /// of its state (the body equals the body of the same state with every
    /// config digest cleared), a decoded record has none, and the head
    /// re-parse brings it back so the content hash verifies.
    #[test]
    fn config_digest_is_content_and_never_reaches_a_record_body() {
        use crate::durable_tail_codec::{Dec, Durable, Enc};
        let claude = || {
            let mut state = SessionStartState::default();
            for line in claude_fixture_lines().iter().take(6) {
                state.observe_claude_line(line, 0, Some(Path::new("/w/repo")));
            }
            state
        };
        let codex = || {
            let mut state = SessionStartState::default();
            state.observe_codex_line(
                &codex_message(
                    "user",
                    &[(
                        codex_prelude_footprint::AGENTS_MD_KIND,
                        "# AGENTS.md instructions for /w/repo\n\n<INSTRUCTIONS>\nSECRET_RULES\n</INSTRUCTIONS>",
                    )],
                ),
                None,
            );
            state
        };
        let body = |state: &SessionStartState| {
            let mut e = Enc::bytes(1 << 20);
            state.put(&mut e).unwrap();
            e.into_bytes()
        };
        let build: [(&str, &dyn Fn() -> SessionStartState); 2] =
            [("claude", &claude), ("codex", &codex)];
        for (name, build) in build {
            let state = build();
            let digest = state
                .config_digest
                .unwrap_or_else(|| panic!("{name}: instruction text folds a config digest"));
            let recorded = state.durable_content_hash().unwrap();
            let encoded = body(&state);
            for word in [digest.a, digest.b] {
                assert!(
                    !encoded.windows(8).any(|w| w == word.to_le_bytes()),
                    "{name}: a config digest word reached the body"
                );
            }
            assert!(
                !encoded.windows(12).any(|w| w == b"SECRET_RULES")
                    && !encoded.windows(10).any(|w| w == b"guide.md f"),
                "{name}: instruction text reached the body"
            );
            let mut cleared = state.clone();
            cleared.config_digest = None;
            for blob in cleared.claude_blobs.values_mut() {
                blob.config_digest = None;
            }
            assert_eq!(body(&cleared), encoded, "{name}");
            let mut decoded = SessionStartState::take(&mut Dec::new(&encoded)).unwrap();
            assert!(decoded.config_digest.is_none(), "{name}");
            assert!(
                decoded
                    .claude_blobs
                    .values()
                    .all(|blob| blob.config_digest.is_none()),
                "{name}"
            );
            decoded.adopt_durable_content(&mut build());
            assert_eq!(
                decoded.config_digest.map(ConfigDigest::to_bytes),
                Some(digest.to_bytes()),
                "{name}"
            );
            assert_eq!(decoded.durable_content_hash().unwrap(), recorded, "{name}");
        }
    }
}
