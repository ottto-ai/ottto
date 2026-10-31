//! Codex prelude footprint: what every new Codex session loads before its
//! first model request (the AGENTS.md chain and the skills listing).
//!
//! [`CodexPreludeParser`] is the one Codex prelude parser (CROSS-LANE R1): it
//! takes rollout rows already decoded, so the session sink can share it. This
//! uploader consumes bounded RAM from main line delivery, uploading each scope's
//! newest owned fresh start as a context-footprint snapshot with
//! `agent_source = "codex"`, dated at that session's start: one rollout is one
//! observation and is never sent again.
//!
//! Codex records what it injected in `world_state` (cli >= 0.159; older
//! rollouts are not supported): `state.agents_md` holds the loaded AGENTS.md
//! text and `state.host_skills.body` the skills listing. The project part of
//! the AGENTS.md text is split back into its files with a metadata-only `stat`
//! of the root-to-cwd chain, mirroring Codex's own loader: files joined by a
//! blank line, the total capped at `project_doc_max_bytes` (32 KiB by default)
//! with the tail silently dropped ([`agents_md_cut`]).
//!
//! Sizes are UTF-16 character counts; the backend owns the conversion to
//! tokens (see [`COUNTER_SOURCE`]).
//!
//! Rollouts come from every registered Codex home (`~/.codex` and accepted
//! Ottto slot homes, `sessions` and `archived_sessions`); each session is
//! read against its own home's user file, skills and `config.toml`. The pass
//! runs inside the Claude Code footprint thread, not on its own schedule.
//!
//! Privacy: sizes only. No instruction or skill text leaves the Mac. File
//! paths are repository-relative. A file loaded whole also gets the Claude
//! file-count collector's counts and device-salted hash (same function, same
//! recipe); a trimmed or cut file sends only its `stat` size, and none above
//! the 1 MiB admission bound.

use crate::context_file_counts::{load_or_create_salt, measure_bytes, FileCounts, MAX_FILE_BYTES};
use crate::context_footprint::{
    request_content_hash_for_request, resolve_repository_identity, safe_text, sha256_hex,
    workspace_label, ContextFootprintCategoryInput, ContextFootprintIngestRequest,
    ContextFootprintItemInput, RepositoryIdentity,
};
use crate::locked_state_dir::write_json_atomic;
use crate::snapshot_client::{
    load_snapshot_device_credentials, workspace_labels_allowed, SnapshotApiClient,
};
use crate::snapshot_roots::registered_scan_roots;
use crate::snapshots::SnapshotSource;
use anyhow::{anyhow, Result};
use ottto_core::{
    compiled_release_version, read_codex_config_file_secure, CodexHomeTrust, LocalDeviceBinding,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(test)]
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use toml_edit::{DocumentMut, Item};

const CYCLE_BUDGET: Duration = Duration::from_secs(2 * 60);
const MAX_PRELUDE_LINES: usize = 200;
/// Rows read past the first request while its context window is unknown.
const MAX_LINES_FOR_WINDOW: usize = 8;
const MAX_WORKSPACES_PER_CYCLE: usize = 12;
const MAX_SKILL_ITEMS: usize = 512;
const MAX_STALENESS_SECS: i64 = 7 * 24 * 60 * 60;
const DEFAULT_PROJECT_DOC_MAX_BYTES: u64 = 32 * 1024;
const PROJECT_DOC_SEPARATOR: &str = "\n\n--- project-doc ---\n\n";
const PROJECT_DOC_JOIN: &str = "\n\n";
/// Per directory Codex loads the first existing name, override first.
const AGENTS_FILENAMES: [&str; 2] = ["AGENTS.override.md", "AGENTS.md"];
const COMBINED_CHAIN_NAME: &str = "AGENTS.md (chain)";
/// Item and category `tokens` carry UTF-16 character counts, not tokens: the
/// backend owns the character-to-token ratio and converts on admission.
/// Category `pct` is 0 for the same reason.
const COUNTER_SOURCE: &str = "codex_rollout_prelude_chars_v1";
const STATE_DIR: &str = "codex_session_start";
const LOCAL_DISABLE_ENV: &str = "OTTTO_CODEX_SESSION_START_HARVEST_DISABLED";

// -------------------------------------------------------------------------
// Prelude parsing.
// -------------------------------------------------------------------------

/// Labels of the request-1 blocks whose loaded text is counted elsewhere.
pub(crate) const AGENTS_MD_KIND: &str = "agents_md.instructions";
pub(crate) const HOST_SKILLS_KIND: &str = "host_skills.instructions";
/// The developer copy of `session_meta.base_instructions`; count one of them.
pub(crate) const BASE_INSTRUCTIONS_KIND: &str = "model.base_instructions";
const HOOK_CONTEXT_KIND: &str = "hooks.additional_context";
const DEFERRED_NAMESPACES_KIND: &str = "tools.deferred_namespaces";
/// Ids, paths and model names longer than this are treated as absent, so a
/// held parser has a fixed size beside its AGENTS.md cap.
pub(crate) const MAX_SMALL_TEXT_BYTES: usize = 1024;

/// What one labeled prelude message block is, by its `content_item_kinds`
/// label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockKind {
    BaseInstructions,
    AgentsMd,
    Skills,
    DeferredTools,
    Hooks,
    /// Permissions, environment, collaboration mode, plugins and apps.
    Environment,
    Prompt,
    Other,
}
pub(crate) const BLOCK_KINDS: usize = 8;

impl BlockKind {
    pub(crate) fn of(label: &str) -> Self {
        match label {
            BASE_INSTRUCTIONS_KIND => Self::BaseInstructions,
            AGENTS_MD_KIND => Self::AgentsMd,
            HOST_SKILLS_KIND => Self::Skills,
            DEFERRED_NAMESPACES_KIND => Self::DeferredTools,
            HOOK_CONTEXT_KIND => Self::Hooks,
            label if label.starts_with("user.") => Self::Prompt,
            label
                if [
                    "permissions.",
                    "environments.",
                    "collaboration_mode.",
                    "plugins.",
                    "apps.",
                ]
                .iter()
                .any(|prefix| label.starts_with(prefix)) =>
            {
                Self::Environment
            }
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LoadedAgentsMd {
    pub(crate) directory: Option<String>,
    pub(crate) text: String,
}

/// What one rollout loaded before its first model request.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct CodexPrelude {
    pub(crate) cwd: Option<String>,
    /// Session creation (unix seconds) from `session_meta.timestamp`. File
    /// mtime tracks later activity, so it cannot order session starts.
    pub(crate) started_at: Option<i64>,
    /// Same rule as the session sink's `codex_is_fork`: the session starts
    /// with a parent's context, so its prelude is not an owned fresh start.
    pub(crate) is_fork: bool,
    /// A first token record was seen, so the prelude is final.
    pub(crate) complete: bool,
    pub(crate) model: Option<String>,
    pub(crate) context_window: Option<u64>,
    pub(crate) first_input_tokens: Option<u64>,
    pub(crate) base_instructions_chars: u64,
    /// Injected developer/user text other than AGENTS.md, skills and hooks.
    pub(crate) other_harness_chars: u64,
    pub(crate) hook_chars: u64,
    /// Request 1's rendered developer/user blocks by kind, counted until the
    /// model's first output (the session-start snapshot's parts).
    pub(crate) block_chars: [u64; BLOCK_KINDS],
    /// A request-1 message without one string label per block, or an image
    /// block: `block_chars` misses part of request 1.
    pub(crate) blocks_incomplete: bool,
    /// Request 1's input ended: the model answered, or its usage was logged.
    pub(crate) input_closed: bool,
    pub(crate) world_state_seen: bool,
    pub(crate) agents_md: Option<LoadedAgentsMd>,
    /// The AGENTS.md text was longer than the parser keeps; `agents_md` holds
    /// its prefix.
    pub(crate) agents_md_capped: bool,
    pub(crate) skills_body: Option<String>,
}

impl CodexPrelude {
    pub(crate) fn is_owned_fresh_start(&self) -> bool {
        self.complete && !self.is_fork && self.cwd.is_some()
    }

    pub(crate) fn chars(&self, kind: BlockKind) -> u64 {
        self.block_chars[kind as usize]
    }
}

#[cfg(test)]
pub(crate) fn parse_prelude(mut reader: impl BufRead) -> std::io::Result<CodexPrelude> {
    let mut parser = CodexPreludeParser::default();
    let mut line = Vec::new();
    for _ in 0..MAX_PRELUDE_LINES {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        // Rows that are not JSON still count toward the window bound.
        let value = serde_json::from_slice::<Value>(&line).unwrap_or(Value::Null);
        if parser.observe(&value) == PreludeStep::Done {
            break;
        }
    }
    Ok(parser.finish())
}

/// Whether the caller should feed the next rollout row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreludeStep {
    More,
    Done,
}

/// The one Codex prelude parser (CROSS-LANE R1). Feed rollout rows in order,
/// already decoded, until it says [`PreludeStep::Done`]; callers that decode
/// rows for another purpose share this instead of parsing the prelude again.
/// Requires `world_state` (cli >= 0.159); older rollouts are not supported.
#[derive(Debug, Clone)]
pub(crate) struct CodexPreludeParser {
    prelude: CodexPrelude,
    session_id: Option<String>,
    /// Rows after the first request are read only for its context window,
    /// which a `token_count` event can carry right after the usage record.
    rows_after_first_request: usize,
    /// Most bytes of AGENTS.md text kept.
    agents_md_cap: usize,
    keep_skills_body: bool,
}

impl Default for CodexPreludeParser {
    /// Keeps every loaded text; the caller bounds what it feeds.
    fn default() -> Self {
        Self {
            prelude: CodexPrelude::default(),
            session_id: None,
            rows_after_first_request: 0,
            agents_md_cap: usize::MAX,
            keep_skills_body: true,
        }
    }
}

impl CodexPreludeParser {
    /// For a caller that holds the parser while it reads on (the session-start
    /// snapshot): keeps at most `agents_md_cap` bytes of the AGENTS.md text,
    /// for path matching, and no skills body.
    pub(crate) fn matching_only(agents_md_cap: usize) -> Self {
        Self {
            agents_md_cap,
            keep_skills_body: false,
            ..Self::default()
        }
    }

    pub(crate) fn prelude(&self) -> &CodexPrelude {
        &self.prelude
    }

    /// Drops the kept texts; every count stays.
    pub(crate) fn release_text(&mut self) {
        self.prelude.agents_md = None;
        self.prelude.skills_body = None;
    }

    pub(crate) fn observe(&mut self, value: &Value) -> PreludeStep {
        self.observe_with(value, |_, _| {})
    }

    /// [`Self::observe`], also lending each request-1 block counted in
    /// `block_chars` to `on_block`. Nothing is copied for it.
    pub(crate) fn observe_with(
        &mut self,
        value: &Value,
        on_block: impl FnMut(BlockKind, &str),
    ) -> PreludeStep {
        self.observe_inner(value, on_block, usize::MAX, &mut false)
    }

    fn observe_bounded(&mut self, value: &Value, skills_cap: usize) -> (PreludeStep, bool) {
        let mut capped = false;
        let step = self.observe_inner(value, |_, _| {}, skills_cap, &mut capped);
        (step, capped)
    }

    fn observe_inner(
        &mut self,
        value: &Value,
        on_block: impl FnMut(BlockKind, &str),
        skills_cap: usize,
        capped: &mut bool,
    ) -> PreludeStep {
        let prelude = &mut self.prelude;
        if prelude.complete {
            self.rows_after_first_request += 1;
            if self.rows_after_first_request > MAX_LINES_FOR_WINDOW {
                return PreludeStep::Done;
            }
        }
        let payload = value.get("payload").unwrap_or(&Value::Null);
        let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
        if prelude.complete && kind != "event_msg" {
            return PreludeStep::More;
        }
        match kind {
            "session_meta" => {
                note_session_meta(prelude, &mut self.session_id, payload);
                if prelude.started_at.is_none() {
                    prelude.started_at = payload
                        .get("timestamp")
                        .or_else(|| value.get("timestamp"))
                        .and_then(Value::as_str)
                        .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
                        .map(OffsetDateTime::unix_timestamp);
                }
            }
            "turn_context" if prelude.model.is_none() => {
                prelude.model = small_text(payload.get("model"));
            }
            "world_state" if !prelude.world_state_seen => {
                if let Some(state) = payload.get("state").filter(|s| s.is_object()) {
                    prelude.world_state_seen = true;
                    let agents = state.get("agents_md");
                    if let Some(text) = agents.and_then(|a| a.get("text")).and_then(Value::as_str) {
                        let mut end = text.len().min(self.agents_md_cap);
                        while !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        prelude.agents_md_capped = end < text.len();
                        prelude.agents_md = Some(LoadedAgentsMd {
                            directory: small_text(agents.and_then(|a| a.get("directory"))),
                            text: text[..end].to_string(),
                        });
                    }
                    if self.keep_skills_body {
                        prelude.skills_body = state
                            .get("host_skills")
                            .and_then(|skills| skills.get("body"))
                            .and_then(Value::as_str)
                            .map(|text| {
                                let mut end = text.len().min(skills_cap);
                                while !text.is_char_boundary(end) {
                                    end -= 1;
                                }
                                *capped = end < text.len();
                                text[..end].to_string()
                            });
                    }
                }
            }
            "token_usage_record" => {
                let input = payload
                    .get("usage")
                    .and_then(|usage| usage.get("input_tokens"))
                    .and_then(Value::as_u64);
                // A zero-input record is a context estimate, not a request.
                if input == Some(0) {
                    return PreludeStep::More;
                }
                prelude.first_input_tokens = input;
                prelude.complete = true;
                prelude.input_closed = true;
                if prelude.context_window.is_some() {
                    return PreludeStep::Done;
                }
            }
            "event_msg" if payload.get("type").and_then(Value::as_str) == Some("token_count") => {
                let info = payload.get("info").unwrap_or(&Value::Null);
                // An all-zero context estimate before the first request is
                // not a request.
                let Some(input) = info
                    .get("last_token_usage")
                    .and_then(|usage| usage.get("input_tokens"))
                    .and_then(Value::as_u64)
                    .filter(|input| *input > 0 || prelude.complete)
                else {
                    return PreludeStep::More;
                };
                if !prelude.complete {
                    prelude.first_input_tokens = Some(input);
                    prelude.complete = true;
                    prelude.input_closed = true;
                }
                if let Some(window) = info.get("model_context_window").and_then(Value::as_u64) {
                    prelude.context_window.get_or_insert(window);
                }
                return PreludeStep::Done;
            }
            "response_item" => match payload.get("type").and_then(Value::as_str) {
                Some("message") => match payload.get("role").and_then(Value::as_str) {
                    Some("developer" | "user") => note_message(prelude, payload, on_block),
                    _ => prelude.input_closed = true,
                },
                // The model's own output: request 1's input is over.
                Some(
                    "reasoning" | "function_call" | "custom_tool_call" | "local_shell_call"
                    | "web_search_call",
                ) => prelude.input_closed = true,
                _ => {}
            },
            _ => {}
        }
        PreludeStep::More
    }

    pub(crate) fn finish(self) -> CodexPrelude {
        self.prelude
    }
}

fn note_session_meta(prelude: &mut CodexPrelude, session_id: &mut Option<String>, meta: &Value) {
    let id = small_text(meta.get("id").or_else(|| meta.get("session_id")));
    if let Some(first) = session_id.as_ref() {
        // A second meta row with another id is a copied parent thread.
        if id.as_ref().is_some_and(|id| id != first) {
            prelude.is_fork = true;
        }
        return;
    }
    *session_id = id.or_else(|| Some(String::new()));
    prelude.cwd = small_text(meta.get("cwd"));
    prelude.context_window = meta.get("context_window").and_then(Value::as_u64);
    let present = |key: &str| meta.get(key).is_some_and(|value| !value.is_null());
    prelude.is_fork = meta.get("thread_source").and_then(Value::as_str)
        == Some("agent_created_thread")
        || meta
            .get("forked_from_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
        || present("history_base")
        || present("subagent_history_start_ordinal");
    prelude.base_instructions_chars = match meta.get("base_instructions") {
        Some(Value::String(text)) => char_count(text),
        Some(value) => value
            .get("text")
            .and_then(Value::as_str)
            .map(char_count)
            .unwrap_or(0),
        None => 0,
    };
}

/// Harness text outside `world_state`, by its `content_item_kinds` label.
/// Every supported rollout labels its message blocks; unlabeled blocks are
/// not counted. AGENTS.md and the skills listing come from `world_state`.
/// Until the model's first output the blocks also go to `block_chars`, but
/// only from a message labeled one string per block.
fn note_message(
    prelude: &mut CodexPrelude,
    payload: &Value,
    mut on_block: impl FnMut(BlockKind, &str),
) {
    let request_1 = !prelude.input_closed;
    let labeled = payload
        .get("content")
        .and_then(Value::as_array)
        .zip(
            payload
                .get("internal_chat_message_metadata_passthrough")
                .and_then(|meta| meta.get("content_item_kinds"))
                .and_then(Value::as_array),
        )
        .filter(|(blocks, kinds)| blocks.len() == kinds.len());
    let Some((blocks, kinds)) = labeled else {
        prelude.blocks_incomplete |= request_1;
        return;
    };
    let request_1 = request_1 && kinds.iter().all(Value::is_string);
    prelude.blocks_incomplete |= !prelude.input_closed && !request_1;
    for (block, kind) in blocks.iter().zip(kinds) {
        if request_1 && block.get("type").and_then(Value::as_str) == Some("input_image") {
            prelude.blocks_incomplete = true;
            continue;
        }
        let (Some(text), Some(kind)) = (block.get("text").and_then(Value::as_str), kind.as_str())
        else {
            continue;
        };
        let kind = BlockKind::of(kind);
        let chars = char_count(text);
        match kind {
            BlockKind::Hooks => prelude.hook_chars += chars,
            // Counted from world_state / session_meta, or the user's own text.
            BlockKind::AgentsMd
            | BlockKind::Skills
            | BlockKind::BaseInstructions
            | BlockKind::Prompt => {}
            BlockKind::DeferredTools | BlockKind::Environment | BlockKind::Other => {
                prelude.other_harness_chars += chars
            }
        }
        if request_1 {
            prelude.block_chars[kind as usize] += chars;
            on_block(kind, text);
        }
    }
}

fn small_text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| text.len() <= MAX_SMALL_TEXT_BYTES)
        .map(str::to_string)
}

/// UTF-16 code units, the unit of the Claude file counts and the backend ratio.
pub(crate) fn char_count(text: &str) -> u64 {
    // ASCII, the common case, is one unit per byte; `is_ascii` is vectorized.
    if text.is_ascii() {
        text.len() as u64
    } else {
        text.encode_utf16().count() as u64
    }
}

crate::heap_layout_bound::fields!(LoadedAgentsMd; directory, text);
crate::durable_tail_codec::durable_struct!(LoadedAgentsMd {
    X directory: Option<String>,
    X text: String,
});
crate::heap_layout_bound::fields!(CodexPrelude; cwd, started_at, is_fork, complete, model, context_window, first_input_tokens, base_instructions_chars, other_harness_chars, hook_chars, block_chars, blocks_incomplete, input_closed, world_state_seen, agents_md, agents_md_capped, skills_body);
crate::durable_tail_codec::durable_struct!(CodexPrelude {
    X cwd: Option<String>,
    N started_at: Option<i64>,
    N is_fork: bool,
    N complete: bool,
    U model: Option<String>,
    N context_window: Option<u64>,
    N first_input_tokens: Option<u64>,
    N base_instructions_chars: u64,
    N other_harness_chars: u64,
    N hook_chars: u64,
    N block_chars: [u64; BLOCK_KINDS],
    N blocks_incomplete: bool,
    N input_closed: bool,
    N world_state_seen: bool,
    X agents_md: Option<LoadedAgentsMd>,
    N agents_md_capped: bool,
    E skills_body: Option<String>,
});
crate::heap_layout_bound::fields!(CodexPreludeParser; prelude, session_id, rows_after_first_request, agents_md_cap, keep_skills_body);
crate::durable_tail_codec::durable_struct!(CodexPreludeParser {
    X prelude: CodexPrelude,
    U session_id: Option<String>,
    N rows_after_first_request: usize,
    N agents_md_cap: usize,
    N keep_skills_body: bool,
});

// -------------------------------------------------------------------------
// AGENTS.md chain -> per-file items.
// -------------------------------------------------------------------------

/// One AGENTS.md file Codex would load for the session directory.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ChainFile {
    pub(crate) relative_path: String,
    pub(crate) name: String,
    pub(crate) size: u64,
}

/// Codex's project root: the nearest ancestor holding `.git`; without one,
/// only the session directory itself is searched.
fn project_root(directory: &Path) -> Option<PathBuf> {
    directory
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

/// Metadata-only walk from the project root down to `directory`.
pub(crate) fn agents_md_chain(directory: &Path, root: Option<&Path>) -> Vec<ChainFile> {
    let root = root.unwrap_or(directory);
    let Ok(below) = directory.strip_prefix(root) else {
        return Vec::new();
    };
    let mut dirs = vec![root.to_path_buf()];
    let mut current = root.to_path_buf();
    for part in below.components() {
        current.push(part);
        dirs.push(current.clone());
    }
    let mut chain = Vec::new();
    for dir in dirs {
        for name in AGENTS_FILENAMES {
            let Ok(metadata) = fs::metadata(dir.join(name)) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let relative = dir
                .strip_prefix(root)
                .ok()
                .map(|rel| rel.join(name))
                .map(|rel| {
                    rel.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .unwrap_or_else(|| name.to_string());
            chain.push(ChainFile {
                relative_path: relative,
                name: name.to_string(),
                size: metadata.len(),
            });
            break;
        }
    }
    chain
}

/// `project_doc_max_bytes` from the home's `config.toml`, else 32 KiB.
pub(crate) fn project_doc_max_bytes(codex_home: &Path, trust: CodexHomeTrust) -> u64 {
    read_codex_config_file_secure(codex_home, trust)
        .ok()
        .flatten()
        .and_then(|body| String::from_utf8(body).ok())
        .and_then(|raw| configured_project_doc_max_bytes(&raw))
        .unwrap_or(DEFAULT_PROJECT_DOC_MAX_BYTES)
}

pub(crate) fn configured_project_doc_max_bytes(raw: &str) -> Option<u64> {
    let document = raw.parse::<DocumentMut>().ok()?;
    let value = document
        .get("project_doc_max_bytes")
        .and_then(Item::as_value)?
        .as_integer()?;
    u64::try_from(value).ok()
}

/// Whether Codex cut the project part of a loaded AGENTS.md text at its
/// `project_doc_max_bytes` budget (the text Codex loaded, as in `world_state`).
/// The shared truncation rule for the per-file items and the per-session flag
/// (CROSS-LANE S5). The user-level part before the separator is not budgeted.
pub(crate) fn agents_md_cut(text: &str, limit: u64) -> bool {
    let project = text
        .find(PROJECT_DOC_SEPARATOR)
        .map_or(text, |at| &text[at + PROJECT_DOC_SEPARATOR.len()..]);
    limit > 0 && project.len() as u64 >= limit
}

/// Inputs for splitting one loaded AGENTS.md text into file items.
pub(crate) struct InstructionInputs<'a> {
    pub(crate) text: &'a str,
    pub(crate) chain: &'a [ChainFile],
    /// `(name, size)` of the user-level file in the Codex home, if any.
    pub(crate) user_file: Option<(&'a str, u64)>,
    pub(crate) limit: u64,
    pub(crate) salt: Option<&'a [u8; 32]>,
}

pub(crate) fn instruction_items(inputs: &InstructionInputs<'_>) -> Vec<ContextFootprintItemInput> {
    let text = inputs.text;
    let user_name = inputs
        .user_file
        .map(|(name, _)| name)
        .unwrap_or("AGENTS.md");
    let (user_part, project_part) = match text.find(PROJECT_DOC_SEPARATOR) {
        Some(at) => (
            Some(&text[..at]),
            Some(&text[at + PROJECT_DOC_SEPARATOR.len()..]),
        ),
        None if text.trim().is_empty() => (None, None),
        None if exact_split(text, inputs.chain, inputs.limit).is_some() => (None, Some(text)),
        // Codex trims the user file, so it is at most a little larger.
        None if inputs.user_file.is_some_and(|(_, size)| {
            size >= text.len() as u64 && size - text.len() as u64 <= 64
        }) =>
        {
            (Some(text), None)
        }
        None if !inputs.chain.is_empty() => (None, Some(text)),
        None => (Some(text), None),
    };
    let mut items = Vec::new();
    if let Some(user) = user_part.filter(|part| !part.trim().is_empty()) {
        items.push(sized_item(
            user_name,
            "User",
            Some(user_name),
            user.as_bytes(),
            inputs.user_file.map(|(_, size)| size),
            false,
            inputs.salt,
        ));
    }
    if let Some(project) = project_part.filter(|part| !part.trim().is_empty()) {
        items.extend(project_items(project, inputs));
    }
    items
}

/// Byte ranges of each loaded file, when the text is exactly what Codex's
/// loader would build from the files' current sizes.
fn exact_split(project: &str, chain: &[ChainFile], limit: u64) -> Option<Vec<(usize, u64, u64)>> {
    let mut remaining = limit;
    let mut loaded = Vec::new();
    for (index, file) in chain.iter().enumerate() {
        if remaining == 0 {
            break;
        }
        if file.size == 0 {
            continue;
        }
        let take = file.size.min(remaining);
        loaded.push((index, take, file.size));
        remaining -= take;
    }
    if loaded.is_empty() {
        return None;
    }
    let joins = (loaded.len() as u64 - 1) * PROJECT_DOC_JOIN.len() as u64;
    let expected: u64 = loaded.iter().map(|(_, take, _)| take).sum::<u64>() + joins;
    if expected != project.len() as u64 {
        return None;
    }
    let bytes = project.as_bytes();
    let mut offset = 0usize;
    for (position, (_, take, _)) in loaded.iter().enumerate() {
        offset += *take as usize;
        if position + 1 < loaded.len() {
            if bytes.get(offset..offset + PROJECT_DOC_JOIN.len())
                != Some(PROJECT_DOC_JOIN.as_bytes())
            {
                return None;
            }
            offset += PROJECT_DOC_JOIN.len();
        }
    }
    Some(loaded)
}

fn project_items(project: &str, inputs: &InstructionInputs<'_>) -> Vec<ContextFootprintItemInput> {
    let bytes = project.as_bytes();
    if let Some(loaded) = exact_split(project, inputs.chain, inputs.limit) {
        let mut items = Vec::new();
        let mut offset = 0usize;
        for (index, take, size) in loaded {
            let file = &inputs.chain[index];
            let end = offset + take as usize;
            items.push(sized_item(
                &file.name,
                "Project",
                Some(&file.relative_path),
                &bytes[offset..end],
                Some(size),
                take < size,
                inputs.salt,
            ));
            offset = end + PROJECT_DOC_JOIN.len();
        }
        return items;
    }
    // The files changed after the session started. One file is still that
    // file; several can no longer be split honestly.
    let at_limit = agents_md_cut(project, inputs.limit);
    match inputs.chain {
        [only] => vec![sized_item(
            &only.name,
            "Project",
            Some(&only.relative_path),
            bytes,
            Some(only.size),
            at_limit,
            inputs.salt,
        )],
        _ => vec![sized_item(
            COMBINED_CHAIN_NAME,
            "Project",
            None,
            bytes,
            None,
            at_limit,
            inputs.salt,
        )],
    }
}

/// One file item. `tokens` is the loaded slice. When the slice is the whole
/// file (its length equals the `stat` size), `file_*` and the salted hash come
/// from the shared file-count measurement of those bytes; otherwise (Codex
/// trims the user file and cuts the last file at the limit) only the `stat`
/// size is sent, never a partial prefix presented as the file.
fn sized_item(
    name: &str,
    source: &str,
    relative_path: Option<&str>,
    bytes: &[u8],
    disk_size: Option<u64>,
    truncated: bool,
    salt: Option<&[u8; 32]>,
) -> ContextFootprintItemInput {
    let whole_file = disk_size == Some(bytes.len() as u64);
    let counts = whole_file
        .then(|| measure_bytes(bytes, false, salt))
        .flatten()
        .unwrap_or(FileCounts {
            // Never an uncapped size: admission bounds file_bytes at 1 MiB (BR4).
            file_bytes: disk_size.filter(|size| *size <= MAX_FILE_BYTES as u64),
            ..FileCounts::default()
        });
    ContextFootprintItemInput {
        kind: "memory_file".to_string(),
        name: name.to_string(),
        tokens: char_count(&String::from_utf8_lossy(bytes)),
        pct: None,
        source: Some(source.to_string()),
        relative_path: relative_path.map(str::to_string),
        loading_mode: "always_on".to_string(),
        file_counts: FileCounts {
            truncated_by_limit: Some(truncated),
            ..counts
        },
        local_path: None,
    }
}

// -------------------------------------------------------------------------
// Skills listing -> per-skill items.
// -------------------------------------------------------------------------

/// Where a skill root lives, without sending the path.
pub(crate) struct SkillRootContext<'a> {
    pub(crate) project_root: Option<&'a Path>,
    pub(crate) codex_home: &'a Path,
    pub(crate) home: &'a Path,
}

fn skill_root_kind(path: &str, context: &SkillRootContext<'_>) -> &'static str {
    let path = Path::new(path);
    if context
        .project_root
        .is_some_and(|root| path.starts_with(root))
    {
        "Project"
    } else if path.starts_with(context.codex_home.join("skills").join(".system")) {
        "System"
    } else if path.starts_with(context.codex_home.join("plugins"))
        || path.components().any(|part| part.as_os_str() == "plugins")
    {
        "Plugin"
    } else if path.starts_with(context.codex_home.join("skills"))
        || path.starts_with(context.home.join(".agents"))
    {
        "User"
    } else {
        "Other"
    }
}

/// One `skill` item per listed skill (`- name: description (file: rN/...)`),
/// sized by its listing line: the part every session pays for.
pub(crate) fn skill_items(
    body: &str,
    context: &SkillRootContext<'_>,
) -> Vec<ContextFootprintItemInput> {
    let mut roots: BTreeMap<&str, &'static str> = BTreeMap::new();
    let mut in_skills = false;
    let mut items = Vec::new();
    for line in body.lines() {
        if line.starts_with("### ") {
            in_skills = line.starts_with("### Available skills");
            continue;
        }
        let Some(entry) = line.strip_prefix("- ") else {
            continue;
        };
        if !in_skills {
            // "- `r0` = `/path/to/skills`"
            if let Some((id, path)) = entry.split_once(" = ") {
                let id = id.trim().trim_matches('`');
                let path = path.trim().trim_matches('`');
                roots.insert(id, skill_root_kind(path, context));
            }
            continue;
        }
        if items.len() >= MAX_SKILL_ITEMS {
            break;
        }
        let Some(name) = entry.split_once(": ").map(|(name, _)| name) else {
            continue;
        };
        let Some(name) = safe_text(name, 256) else {
            continue;
        };
        let source = entry
            .rfind("(file: ")
            .map(|at| &entry[at + "(file: ".len()..])
            .and_then(|rest| rest.split('/').next())
            .and_then(|id| roots.get(id.trim_matches('`')).copied())
            .unwrap_or("Other");
        items.push(ContextFootprintItemInput {
            kind: "skill".to_string(),
            name,
            tokens: char_count(line),
            pct: None,
            source: Some(source.to_string()),
            relative_path: None,
            loading_mode: "always_on".to_string(),
            file_counts: FileCounts::default(),
            local_path: None,
        });
    }
    items
}

// -------------------------------------------------------------------------
// Request.
// -------------------------------------------------------------------------

pub(crate) struct RequestInputs<'a> {
    pub(crate) prelude: &'a CodexPrelude,
    pub(crate) workspace: &'a Path,
    pub(crate) identity: RepositoryIdentity,
    pub(crate) machine_id: &'a str,
    pub(crate) labels_enabled: bool,
    pub(crate) codex_home: &'a Path,
    pub(crate) home: &'a Path,
    pub(crate) salt: Option<&'a [u8; 32]>,
}

pub(crate) fn build_request(inputs: RequestInputs<'_>) -> Option<ContextFootprintIngestRequest> {
    let prelude = inputs.prelude;
    let window = prelude.context_window.filter(|window| *window > 0)?;
    let directory = prelude
        .agents_md
        .as_ref()
        .and_then(|agents| agents.directory.as_deref())
        .map(PathBuf::from)
        .unwrap_or_else(|| inputs.workspace.to_path_buf());
    let root = project_root(&directory);
    let user_file = AGENTS_FILENAMES.iter().find_map(|name| {
        let metadata = fs::metadata(inputs.codex_home.join(name)).ok()?;
        metadata.is_file().then_some((*name, metadata.len()))
    });

    let memory_files = match prelude.agents_md.as_ref() {
        Some(agents) => {
            let chain = agents_md_chain(&directory, root.as_deref());
            let trust = if inputs.codex_home == inputs.home.join(".codex") {
                CodexHomeTrust::ProviderDefault
            } else {
                CodexHomeTrust::Managed
            };
            instruction_items(&InstructionInputs {
                text: &agents.text,
                chain: &chain,
                user_file,
                limit: project_doc_max_bytes(inputs.codex_home, trust),
                salt: inputs.salt,
            })
        }
        None => Vec::new(),
    };
    let skills = prelude
        .skills_body
        .as_deref()
        .map(|body| {
            skill_items(
                body,
                &SkillRootContext {
                    project_root: root.as_deref(),
                    codex_home: inputs.codex_home,
                    home: inputs.home,
                },
            )
        })
        .unwrap_or_default();

    let category = |name: &str, chars: u64| ContextFootprintCategoryInput {
        name: name.to_string(),
        tokens: chars,
        pct: 0.0,
        loading_mode: "always_on".to_string(),
    };
    let mut categories = vec![
        category(
            "System prompt",
            prelude.base_instructions_chars + prelude.other_harness_chars,
        ),
        category(
            "Memory files",
            memory_files.iter().map(|item| item.tokens).sum(),
        ),
        category(
            "Skills",
            prelude.skills_body.as_deref().map(char_count).unwrap_or(0),
        ),
    ];
    if prelude.hook_chars > 0 {
        categories.push(category("Hook context", prelude.hook_chars));
    }

    let model = prelude
        .model
        .as_deref()
        .and_then(|model| safe_text(model, 128))
        .unwrap_or_else(|| "unknown".to_string());
    let used_tokens = prelude.first_input_tokens.unwrap_or(0);
    // The source observation is the session start, not this upload (a
    // replayed prelude is the same observation; BR3).
    let captured_at = OffsetDateTime::from_unix_timestamp(prelude.started_at?)
        .ok()?
        .format(&Rfc3339)
        .ok()?;
    let content = serde_json::to_string(&json!({
        "categories": &categories,
        "memory_files": &memory_files,
        "skills": &skills,
    }))
    .ok()?;
    let config_hash = sha256_hex(&[COUNTER_SOURCE, content.as_str()]);
    let workspace_text = inputs.workspace.to_string_lossy();
    let identity = inputs.identity;
    Some(ContextFootprintIngestRequest {
        agent_source: "codex".to_string(),
        machine_id: inputs.machine_id.to_string(),
        workspace_hash: sha256_hex(&[workspace_text.as_ref()]),
        workspace_label: inputs
            .labels_enabled
            .then(|| workspace_label(inputs.workspace))
            .flatten(),
        workspace_label_source: inputs.labels_enabled.then(|| "directory_name".to_string()),
        repository_hash: identity.repository_hash,
        repository_label: identity.repository_label,
        repository_label_source: identity.repository_label_source,
        repository_identity_source: identity.repository_identity_source,
        workspace_kind: identity.workspace_kind,
        config_hash,
        captured_at,
        collector_version: compiled_release_version(),
        counter_source: COUNTER_SOURCE.to_string(),
        model,
        used_tokens,
        context_window_tokens: window,
        pct_context: ((used_tokens as f64 / window as f64) * 10_000.0).round() / 100.0,
        free_space_tokens: None,
        categories,
        memory_files,
        skills,
        custom_agents: Vec::new(),
        mcp_tools: Vec::new(),
        instruction_inventory: None,
    })
}

mod feed;
pub(crate) use feed::CodexPreludeFeed;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadCacheEntry {
    identity: String,
    request_sha256: String,
    posted_at: String,
    /// Watermark: start (unix seconds) of the newest session this workspace
    /// (the backend's snapshot series) has sent or matched. A start at or
    /// before it is never sent again, even when an older session resumes
    /// later (BR3). Another directory of the same repository is its own
    /// series, so its unsent start is a first observation, not a replay.
    #[serde(default)]
    started_at: Option<i64>,
}

impl UploadCacheEntry {
    fn posted_within_week(&self) -> bool {
        OffsetDateTime::parse(&self.posted_at, &Rfc3339)
            .map(|posted| (OffsetDateTime::now_utc() - posted).whole_seconds() < MAX_STALENESS_SECS)
            .unwrap_or(false)
    }
}

/// The scope's last upload to this destination, of any age.
fn last_upload(
    support_dir: &Path,
    identity: &str,
    workspace_hash: &str,
) -> Option<UploadCacheEntry> {
    fs::read(upload_cache_path(support_dir, workspace_hash))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<UploadCacheEntry>(&bytes).ok())
        .filter(|entry| entry.identity == identity)
}

fn upload_cache_path(support_dir: &Path, workspace_hash: &str) -> PathBuf {
    support_dir
        .join(STATE_DIR)
        .join(format!("{workspace_hash}.json"))
}

// -------------------------------------------------------------------------
// Harvest loop.
// -------------------------------------------------------------------------

/// One pass, called from the Claude Code footprint thread after its cycle.
pub(crate) fn harvest_once(home: &Path, support_dir: &Path, feed: &CodexPreludeFeed) -> Result<()> {
    feed.cleanup_index(support_dir);
    if local_harvest_disabled(support_dir) {
        return Ok(());
    }
    let (device, device_secret) = load_snapshot_device_credentials()?;
    if !crate::snapshot_sync::enabled_snapshot_sources(&device).contains(&SnapshotSource::Codex) {
        return Ok(());
    }
    let Some(machine_id) = crate::snapshot_sync::snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = crate::snapshot_sync::snapshot_api_base_url()?;
    let client = SnapshotApiClient::new(api_base_url.clone());
    let relay_token = client.issue_relay_token(&device, &device_secret, SnapshotSource::Codex)?;
    let identity = destination_identity(&device, &machine_id, &api_base_url);
    let marker = support_dir.join(STATE_DIR).join("org_disabled");
    // Same backend opt-out cascade as the Claude Code footprint.
    let labels_enabled = match client.get_activity_hint(&relay_token) {
        Ok(hint) => {
            if !hint.context_footprint_harvest_enabled {
                write_json_atomic(&marker, &identity);
                return Ok(());
            }
            let _ = fs::remove_file(&marker);
            workspace_labels_allowed(Some(&hint))
        }
        Err(_) if marker_matches(&marker, &identity) => return Ok(()),
        Err(_) => workspace_labels_allowed(None),
    };

    let roots = registered_scan_roots(SnapshotSource::Codex, home)?;
    let salt = load_or_create_salt(support_dir);
    let deadline = Instant::now() + CYCLE_BUDGET;
    let candidates = select_candidates(feed, &roots, support_dir, &identity, deadline);
    let (mut uploaded, mut skipped, mut failed) = (0usize, 0usize, 0usize);
    for (prelude, workspace, codex_home) in candidates {
        if Instant::now() >= deadline {
            break;
        }
        let request = build_request(RequestInputs {
            prelude: &prelude,
            workspace: &workspace,
            identity: resolve_repository_identity(&workspace, labels_enabled),
            machine_id: &machine_id,
            labels_enabled,
            codex_home: &codex_home,
            home,
            salt: salt.as_ref(),
        });
        let Some(request) = request else {
            skipped += 1;
            continue;
        };
        match upload_if_changed(
            &client,
            &relay_token,
            support_dir,
            &identity,
            &request,
            prelude.started_at,
        ) {
            Ok(true) => uploaded += 1,
            Ok(false) => skipped += 1,
            Err(error) => {
                failed += 1;
                eprintln!(
                    "codex session start upload skipped for workspace_hash={}: {}",
                    request.workspace_hash,
                    crate::snapshot_sync::safe_error(&error)
                );
            }
        }
    }
    eprintln!(
        "codex_session_start_harvest_metrics discovered={} uploaded={uploaded} skipped={skipped} failed={failed} {}",
        uploaded + skipped + failed, feed.metrics()
    );
    Ok(())
}

fn select_candidates(
    feed: &CodexPreludeFeed,
    roots: &[PathBuf],
    support_dir: &Path,
    identity: &str,
    deadline: Instant,
) -> Vec<(CodexPrelude, PathBuf, PathBuf)> {
    let (mut starts, mut scopes) = feed.snapshot(SystemTime::now());
    starts.retain(|(_, p, home, _, _)| {
        p.is_owned_fresh_start() && roots.iter().any(|r| r.parent() == Some(home.as_path()))
    });
    let rank = |s: &feed::Start| {
        s.1.started_at
            .unwrap_or(OffsetDateTime::from(s.4).unix_timestamp())
    };
    starts.sort_by(|a, b| rank(b).cmp(&rank(a)).then_with(|| a.0.cmp(&b.0)));
    let mut seen_cwds = BTreeSet::new();
    let mut seen_scopes = BTreeSet::new();
    let mut chosen = Vec::new();
    for (_, prelude, codex_home, capped, mtime) in starts {
        if Instant::now() >= deadline || chosen.len() >= MAX_WORKSPACES_PER_CYCLE {
            break;
        }
        let cwd = prelude.cwd.as_ref().expect("fresh start has cwd");
        if !seen_cwds.insert(cwd.clone()) {
            continue;
        }
        let workspace = PathBuf::from(cwd);
        if !workspace.is_dir() {
            continue;
        }
        let scope = if let Some((_, scope)) = scopes.iter().find(|(key, _)| key == cwd) {
            scope.clone()
        } else {
            let scope = resolve_repository_identity(&workspace, false)
                .repository_hash
                .unwrap_or_else(|| sha256_hex(&[cwd.as_str()]));
            scopes.push((cwd.clone(), scope.clone()));
            scope
        };
        if !seen_scopes.insert(scope) {
            continue;
        }
        let started = prelude
            .started_at
            .unwrap_or(OffsetDateTime::from(mtime).unix_timestamp());
        let sent = last_upload(support_dir, identity, &sha256_hex(&[cwd.as_str()]))
            .and_then(|entry| entry.started_at)
            .is_some_and(|sent| started <= sent);
        if !sent && !capped {
            chosen.push((prelude, workspace, codex_home));
        }
    }
    feed.remember_scopes(scopes);
    chosen
}

fn upload_if_changed(
    client: &SnapshotApiClient,
    relay_token: &str,
    support_dir: &Path,
    identity: &str,
    request: &ContextFootprintIngestRequest,
    started_at: Option<i64>,
) -> Result<bool> {
    let hash = request_content_hash_for_request(request)?;
    let path = upload_cache_path(support_dir, &request.workspace_hash);
    let now = OffsetDateTime::now_utc();
    if let Some(entry) = last_upload(support_dir, identity, &request.workspace_hash) {
        if entry
            .started_at
            .zip(started_at)
            .is_some_and(|(sent, start)| start <= sent)
        {
            return Ok(false);
        }
        // A newer start with the same sizes is sent at most weekly; between
        // those, the scope's latest observation stays the one already sent.
        if entry.request_sha256 == hash && entry.posted_within_week() {
            write_json_atomic(
                &path,
                &UploadCacheEntry {
                    started_at: started_at.max(entry.started_at),
                    ..entry
                },
            );
            return Ok(false);
        }
    }
    let payload = serde_json::to_value(request)
        .map_err(|error| anyhow!("encode codex session start footprint: {error}"))?;
    client.upload_context_footprint(relay_token, &payload)?;
    write_json_atomic(
        &path,
        &UploadCacheEntry {
            identity: identity.to_string(),
            request_sha256: hash,
            posted_at: now.format(&Rfc3339).unwrap_or_default(),
            started_at,
        },
    );
    Ok(true)
}

fn destination_identity(
    device: &LocalDeviceBinding,
    machine_id: &str,
    api_base_url: &str,
) -> String {
    format!("{}|{}|{}", device.device_id, machine_id, api_base_url)
}

fn marker_matches(path: &Path, identity: &str) -> bool {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<String>(&bytes).ok())
        .as_deref()
        == Some(identity)
}

fn local_harvest_disabled(support_dir: &Path) -> bool {
    let env_disabled = |name: &str| {
        std::env::var(name)
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    };
    // The Claude Code footprint switch also covers this footprint.
    env_disabled(LOCAL_DISABLE_ENV)
        || env_disabled("OTTTO_CONTEXT_FOOTPRINT_HARVEST_DISABLED")
        || support_dir.join(STATE_DIR).join("disabled").exists()
        || support_dir
            .join("context_footprint")
            .join("disabled")
            .exists()
}

#[cfg(test)]
pub(crate) mod tests;
