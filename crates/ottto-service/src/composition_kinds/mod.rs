//! Composition kinds: which kind (and part) of context one transcript
//! contributor is.
//!
//! Pure classification over its arguments: no IO and no state beyond a cache
//! the caller owns. The context-composition reader owns reading, the
//! request-1 phase, residency, copied history, local state and upload; this
//! module only answers "what is this content".
//!
//! This is the interface between the two, kept stable so each side can change
//! on its own. Today every function reproduces the kinds_version 1
//! classification exactly: the ten v1 categories and no parts. The
//! kinds_version 2 values are declared so the interface does not change when
//! classification moves to them; nothing emits them yet.
//!
//! `shell` holds the lexical shell-command parser shared with the
//! session-start facts, so there is one parser for both.

pub(crate) mod shell;

use crate::context_footprint::safe_text;
use serde_json::Value;
use std::path::Path;

// -------------------------------------------------------------------------
// Kinds and parts.
// -------------------------------------------------------------------------

/// Kind of context (the daily row's `category` wire id). Declaration order is
/// the row order inside a day, so the v1 variants keep their original order.
#[allow(dead_code)] // kinds_version 2 variants are not emitted yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Kind {
    // kinds_version 1 (emitted today).
    HarnessAttachments,
    ShellOutput,
    CodeReads,
    DocReadsMd,
    DocReadsHtml,
    MemoryNotes,
    BrowserAndImages,
    WebFetchSearch,
    AgentResults,
    /// Shared by both versions (`other_tools`).
    OtherTools,
    // kinds_version 2 (not emitted yet).
    FilesRead,
    CommandOutput,
    ComputerUse,
    WebAndBrowser,
    AutomaticAdditions,
    YourPrompts,
}

impl Kind {
    /// The kinds_version 1 categories in wire order. The methodology
    /// fingerprint (`config_hash`) and per-session totals use this list.
    pub(crate) const ALL: [Kind; 10] = [
        Kind::HarnessAttachments,
        Kind::ShellOutput,
        Kind::CodeReads,
        Kind::DocReadsMd,
        Kind::DocReadsHtml,
        Kind::MemoryNotes,
        Kind::BrowserAndImages,
        Kind::WebFetchSearch,
        Kind::AgentResults,
        Kind::OtherTools,
    ];

    /// The kinds_version 2 kinds in wire order.
    #[allow(dead_code)] // Not emitted yet.
    pub(crate) const V2: [Kind; 7] = [
        Kind::FilesRead,
        Kind::CommandOutput,
        Kind::ComputerUse,
        Kind::WebAndBrowser,
        Kind::OtherTools,
        Kind::AutomaticAdditions,
        Kind::YourPrompts,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Kind::HarnessAttachments => "harness_attachments",
            Kind::ShellOutput => "shell_output",
            Kind::CodeReads => "code_reads",
            Kind::DocReadsMd => "doc_reads_md",
            Kind::DocReadsHtml => "doc_reads_html",
            Kind::MemoryNotes => "memory_notes",
            Kind::BrowserAndImages => "browser_and_images",
            Kind::WebFetchSearch => "web_fetch_search",
            Kind::AgentResults => "agent_results",
            Kind::OtherTools => "other_tools",
            Kind::FilesRead => "files_read",
            Kind::CommandOutput => "command_output",
            Kind::ComputerUse => "computer_use",
            Kind::WebAndBrowser => "web_and_browser",
            Kind::AutomaticAdditions => "automatic_additions",
            Kind::YourPrompts => "your_prompts",
        }
    }

    /// Position in `ALL` (the v1 per-session slot). Only kinds_version 1
    /// kinds have a slot; a kinds_version 2 kind is a bug (debug builds
    /// panic, release builds use slot 0).
    pub(crate) fn index(self) -> usize {
        let index = Kind::ALL.iter().position(|c| *c == self);
        debug_assert!(index.is_some(), "{self:?} has no kinds_version 1 slot");
        index.unwrap_or(0)
    }
}

/// Part of a kind. kinds_version 1 has no parts (`Unsplit`).
#[allow(dead_code)] // kinds_version 2 parts are not emitted yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Part {
    /// kinds_version 1: the kind is not split into parts.
    Unsplit,
    // files_read
    ShellRead,
    FileTool,
    SkillFile,
    InstructionsLater,
    MemoryFile,
    // command_output
    Git,
    Search,
    TestsBuilds,
    OtherCommands,
    // computer_use
    AppControl,
    Screenshots,
    // web_and_browser
    Web,
    Browser,
    // other_tools
    /// Add-on (MCP) results; the server travels with the call's tool key.
    Addon,
    AgentReports,
    BackgroundReports,
    BuiltInOther,
    // automatic_additions
    /// Request-1 content of a session whose start the session-start facts
    /// did not measure.
    StartNotMeasured,
    ToolDescriptionsLater,
    ListsUpdated,
    InstructionsReloaded,
    MemoryReloaded,
    CompactionSummary,
    Reminders,
    Environment,
    HookOutput,
    FilesMentioned,
    FilesChanged,
    Other,
    // your_prompts
    ByYou,
    ByAgent,
}

#[allow(dead_code)] // Read once parts are emitted.
impl Part {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Part::Unsplit => "unsplit",
            Part::ShellRead => "shell_read",
            Part::FileTool => "file_tool",
            Part::SkillFile => "skill_file",
            Part::InstructionsLater => "instructions_later",
            Part::MemoryFile => "memory_file",
            Part::Git => "git",
            Part::Search => "search",
            Part::TestsBuilds => "tests_builds",
            Part::OtherCommands => "other_commands",
            Part::AppControl => "app_control",
            Part::Screenshots => "screenshots",
            Part::Web => "web",
            Part::Browser => "browser",
            Part::Addon => "addon",
            Part::AgentReports => "agent_reports",
            Part::BackgroundReports => "background_reports",
            Part::BuiltInOther => "built_in_other",
            Part::StartNotMeasured => "start_not_measured",
            Part::ToolDescriptionsLater => "tool_descriptions_later",
            Part::ListsUpdated => "lists_updated",
            Part::InstructionsReloaded => "instructions_reloaded",
            Part::MemoryReloaded => "memory_reloaded",
            Part::CompactionSummary => "compaction_summary",
            Part::Reminders => "reminders",
            Part::Environment => "environment",
            Part::HookOutput => "hook_output",
            Part::FilesMentioned => "files_mentioned",
            Part::FilesChanged => "files_changed",
            Part::Other => "other",
            Part::ByYou => "by_you",
            Part::ByAgent => "by_agent",
        }
    }

    /// The kinds_version 2 kind a part belongs to; `None` for `Unsplit`.
    pub(crate) fn kind(self) -> Option<Kind> {
        Some(match self {
            Part::Unsplit => return None,
            Part::ShellRead
            | Part::FileTool
            | Part::SkillFile
            | Part::InstructionsLater
            | Part::MemoryFile => Kind::FilesRead,
            Part::Git | Part::Search | Part::TestsBuilds | Part::OtherCommands => {
                Kind::CommandOutput
            }
            Part::AppControl | Part::Screenshots => Kind::ComputerUse,
            Part::Web | Part::Browser => Kind::WebAndBrowser,
            Part::Addon | Part::AgentReports | Part::BackgroundReports | Part::BuiltInOther => {
                Kind::OtherTools
            }
            Part::StartNotMeasured
            | Part::ToolDescriptionsLater
            | Part::ListsUpdated
            | Part::InstructionsReloaded
            | Part::MemoryReloaded
            | Part::CompactionSummary
            | Part::Reminders
            | Part::Environment
            | Part::HookOutput
            | Part::FilesMentioned
            | Part::FilesChanged
            | Part::Other => Kind::AutomaticAdditions,
            Part::ByYou | Part::ByAgent => Kind::YourPrompts,
        })
    }
}

// -------------------------------------------------------------------------
// Line context and verdicts.
// -------------------------------------------------------------------------

#[allow(dead_code)] // Read once classification depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Agent {
    Claude,
    Codex,
}

/// Who wrote a prompt.
#[allow(dead_code)] // kinds_version 2 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Author {
    You,
    Agent,
}

/// Whether a line belongs to the session's first request, and if so whether
/// the session-start facts measured that start.
#[allow(dead_code)] // kinds_version 1 tracks no request-1 phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Request1 {
    /// The line is after the first request.
    No,
    /// The session-start facts measured this session's start, so composition
    /// skips the line.
    StartMeasured,
    /// The session-start facts did not measure this session's start, so
    /// composition counts the line under `automatic_additions`
    /// `start_not_measured`.
    StartNotMeasured,
}

/// What the reader knows about the line being classified.
#[allow(dead_code)] // kinds_version 1 classification reads none of it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LineCtx<'a> {
    pub(crate) agent: Agent,
    /// Whether the line belongs to the session's first request.
    pub(crate) request_1: Request1,
    pub(crate) cwd: Option<&'a Path>,
    /// The transcript writes the client's `rendered` text on attachments.
    pub(crate) file_has_rendered: bool,
    pub(crate) author: Author,
}

impl LineCtx<'_> {
    /// The context the kinds_version 1 reader supplies: it tracks no
    /// request-1 phase, folder, rendered text or author.
    pub(crate) fn v1(agent: Agent) -> Self {
        Self {
            agent,
            request_1: Request1::No,
            cwd: None,
            file_has_rendered: false,
            author: Author::You,
        }
    }
}

#[allow(dead_code)] // Only `NotMeasured` is returned today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SkipReason {
    /// kinds_version 1 does not count this content (typed prompts, Claude
    /// user text, events it has no category for).
    NotMeasured,
    /// The session-start facts measure request 1.
    RequestOne,
    /// The client's record of the system prompt and tool list.
    PromptSnapshot,
    /// Bookkeeping for tool descriptions loaded later.
    DeferredToolsRecord,
    /// An attachment without `rendered` text in a file that has it.
    Unrendered,
}

#[allow(dead_code)] // Only `NotMeasured` skips are returned today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Skip(SkipReason),
    Count { kind: Kind, part: Part },
}

impl Verdict {
    const fn v1(kind: Kind) -> Self {
        Verdict::Count {
            kind,
            part: Part::Unsplit,
        }
    }
}

/// The tool a call used: the raw client tool name, `server/tool` for an
/// add-on (MCP) call. Upload labels and consent are the reader's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolKey(Box<str>);

#[allow(dead_code)] // Read once tool totals are uploaded.
impl ToolKey {
    pub(crate) fn new(name: &str) -> Self {
        Self(name.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a tool call's result counts, decided when the call is seen. The reader
/// keeps it with the open call without looking inside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallClass {
    pub(crate) kind: Kind,
    pub(crate) part: Part,
    #[allow(dead_code)] // Read once tool totals are uploaded.
    pub(crate) tool: ToolKey,
    /// The file the call read, as written in the transcript.
    pub(crate) file: Option<Box<str>>,
}

impl CallClass {
    fn v1(kind: Kind, tool: ToolKey, file: Option<Box<str>>) -> Self {
        Self {
            kind,
            part: Part::Unsplit,
            tool,
            file,
        }
    }

    /// A result whose call is not in the transcript (or has no name).
    pub(crate) fn unmatched() -> Self {
        Self::v1(Kind::OtherTools, ToolKey::new(""), None)
    }
}

// -------------------------------------------------------------------------
// Claude Code.
// -------------------------------------------------------------------------

/// The fields of a Claude Code attachment record classification reads.
#[allow(dead_code)] // kinds_version 1 reads only `filename`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ClaudeAttachment<'a> {
    pub(crate) att_type: &'a str,
    pub(crate) filename: Option<&'a str>,
    /// `files[].type` of an instructions attachment (`AutoMem`, `Project`, ...).
    pub(crate) file_type: Option<&'a str>,
    pub(crate) has_rendered: bool,
}

pub(crate) fn claude_attachment(_ctx: &LineCtx, att: &ClaudeAttachment) -> Verdict {
    match att.filename {
        Some(filename) if is_memory_path(filename) => Verdict::v1(Kind::MemoryNotes),
        _ => Verdict::v1(Kind::HarnessAttachments),
    }
}

/// A `tool_use` block: `name` is "" when the block has none.
pub(crate) fn claude_tool(_ctx: &LineCtx, name: &str, input: &Value) -> CallClass {
    let file = input.get("file_path").and_then(Value::as_str);
    CallClass::v1(
        cc_tool_category(name, file.unwrap_or("")),
        ToolKey::new(name),
        file.map(Into::into),
    )
}

/// A user record's own text (not a tool result).
#[allow(dead_code)] // kinds_version 1 does not measure user text.
pub(crate) fn claude_user_text(_ctx: &LineCtx, _line: &Value) -> Verdict {
    Verdict::Skip(SkipReason::NotMeasured)
}

/// Image blocks: in a tool result (`call`) or directly in a message.
pub(crate) fn image(_ctx: &LineCtx, _call: Option<&CallClass>) -> Verdict {
    Verdict::v1(Kind::BrowserAndImages)
}

// -------------------------------------------------------------------------
// Codex.
// -------------------------------------------------------------------------

/// A function, custom-tool or local-shell call. `input` is the call's own
/// input text: `input` for a custom-tool call, `arguments` for a function
/// call, the action's command for a local-shell call ("" when it has none).
pub(crate) fn codex_call(_ctx: &LineCtx, name: Option<&str>, _input: &str) -> CallClass {
    match name {
        Some(name) => CallClass::v1(codex_tool_category(name), ToolKey::new(name), None),
        None => CallClass::unmatched(),
    }
}

/// An add-on (MCP) call and its result, from its `invocation`.
pub(crate) fn codex_mcp(_ctx: &LineCtx, invocation: Option<&Value>) -> CallClass {
    let field = |key| {
        invocation
            .and_then(|invocation| invocation.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    let tool = ToolKey::new(&format!("{}/{}", field("server"), field("tool")));
    CallClass::v1(codex_mcp_category(invocation), tool, None)
}

/// An inner item Codex writes between a call and its output.
#[allow(dead_code)] // kinds_version 2 only.
#[derive(Debug, Clone, Copy)]
pub(crate) enum InnerItem<'a> {
    Command {
        cwd: Option<&'a str>,
        command: &'a str,
        parsed: &'a [ParsedCommand<'a>],
        output_chars: u64,
    },
    Mcp {
        server: &'a str,
        tool: &'a str,
        output_chars: u64,
    },
    Extension {
        name: &'a str,
        output_chars: u64,
    },
    /// A web search the call ran.
    WebSearch {
        output_chars: u64,
    },
}

/// One entry of Codex's own `parsed_cmd` (`read`, `search`, `list_files`,
/// `unknown`).
#[allow(dead_code)] // kinds_version 2 only.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedCommand<'a> {
    pub(crate) kind: &'a str,
    pub(crate) path: Option<&'a str>,
}

/// One share of a call output's tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CellShare {
    pub(crate) kind: Kind,
    pub(crate) part: Part,
    pub(crate) tokens: u64,
    pub(crate) file: Option<Box<str>>,
}

/// Split a call output's tokens across the inner items the call wrote. The
/// shares sum to `output_tokens`; kinds_version 1 gives the call's whole
/// output to the call's class.
pub(crate) fn codex_cell(
    call: &CallClass,
    _items: &[InnerItem],
    output_tokens: u64,
) -> Vec<CellShare> {
    vec![CellShare {
        kind: call.kind,
        part: call.part,
        tokens: output_tokens,
        file: call.file.clone(),
    }]
}

/// A standalone event record (`payload.type`) outside any call.
pub(crate) fn codex_event(_ctx: &LineCtx, event_type: &str) -> Verdict {
    match event_type {
        "web_search_end" => Verdict::v1(Kind::WebFetchSearch),
        _ => Verdict::Skip(SkipReason::NotMeasured),
    }
}

/// Codex's label for one content block of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentLabel<'a> {
    /// The message carries no per-block labels (older rollouts).
    Absent,
    /// The block's `content_item_kinds` entry; `None` when it is not a string.
    Present(Option<&'a str>),
}

/// Codex labels each user-role content block with a `content_item_kinds`
/// entry. Only `user.*` blocks are typed by the person; every other kind
/// (`agents_md.instructions`, `environments.environment_context`, ...) is
/// harness-injected and enters context like a developer message. Rollouts
/// without labels fall back to the injected-block text prefixes.
const CODEX_INJECTED_USER_PREFIXES: [&str; 3] = [
    "# AGENTS.md instructions",
    "<environment_context>",
    "<user_instructions>",
];

/// A `message` record: a developer message as a whole (`label` is `Absent`
/// and `text` unused), or one text block of a user message.
pub(crate) fn codex_message(
    _ctx: &LineCtx,
    role: &str,
    label: ContentLabel,
    text: &str,
) -> Verdict {
    let injected = match role {
        "developer" => true,
        "user" => match label {
            ContentLabel::Present(kind) => kind.is_some_and(|kind| !kind.starts_with("user.")),
            ContentLabel::Absent => CODEX_INJECTED_USER_PREFIXES
                .iter()
                .any(|prefix| text.trim_start().starts_with(prefix)),
        },
        _ => false,
    };
    if injected {
        Verdict::v1(Kind::HarnessAttachments)
    } else {
        Verdict::Skip(SkipReason::NotMeasured)
    }
}

// -------------------------------------------------------------------------
// File names.
// -------------------------------------------------------------------------

/// Folder-to-repository lookups shared across one workspace's files. Empty
/// in kinds_version 1, which only strips the workspace prefix.
#[derive(Debug, Default)]
pub(crate) struct GitRootCache {}

/// Make a transcript-referenced path safe for the aggregate payload: strip the
/// workspace prefix to a repo-relative path, else reduce to a bare basename.
/// Returns `None` when even the basename would leak a path/secret.
pub(crate) fn repo_relative(
    raw: &str,
    workspace: &Path,
    _ws_repo_hash: Option<&str>,
    _cache: &mut GitRootCache,
) -> Option<String> {
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

// -------------------------------------------------------------------------
// kinds_version 1 classifiers (ported 1:1 from the reference).
// -------------------------------------------------------------------------

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
pub(crate) fn classify_by_read_path(path: &str) -> Kind {
    if is_memory_path(path) {
        return Kind::MemoryNotes;
    }
    let low = path.to_ascii_lowercase();
    if low.ends_with(".md") || low.ends_with(".markdown") {
        Kind::DocReadsMd
    } else if low.ends_with(".html") || low.ends_with(".htm") {
        Kind::DocReadsHtml
    } else {
        Kind::CodeReads
    }
}

pub(crate) fn cc_tool_category(name: &str, file_path: &str) -> Kind {
    if name == "Bash" {
        return Kind::ShellOutput;
    }
    if name == "Read" || name == "NotebookRead" {
        return classify_by_read_path(file_path);
    }
    if name == "Task" || name == "Agent" {
        return Kind::AgentResults;
    }
    if name == "WebFetch" || name == "WebSearch" {
        return Kind::WebFetchSearch;
    }
    let low = name.to_ascii_lowercase();
    if low.contains("browser")
        || low.contains("chrome")
        || low.contains("computer")
        || low.starts_with("preview_")
        || low.contains("screenshot")
    {
        return Kind::BrowserAndImages;
    }
    Kind::OtherTools
}

pub(crate) fn codex_tool_category(name: &str) -> Kind {
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
        return Kind::ShellOutput;
    }
    if low.contains("web") || low.contains("search") || low.contains("fetch") {
        return Kind::WebFetchSearch;
    }
    if low.contains("browser") || low.contains("computer") || low.contains("screenshot") {
        return Kind::BrowserAndImages;
    }
    if low.contains("agent") || low == "spawn_agent" {
        return Kind::AgentResults;
    }
    if low == "read_file" || low == "view" || low == "read" {
        return Kind::CodeReads;
    }
    Kind::OtherTools
}

pub(crate) fn codex_mcp_category(invocation: Option<&Value>) -> Kind {
    let Some(obj) = invocation.and_then(Value::as_object) else {
        return Kind::OtherTools;
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
        Kind::BrowserAndImages
    } else if any(&["web", "search", "fetch"]) {
        Kind::WebFetchSearch
    } else if any(&["repl", "exec", "shell", "node", "python", "js"]) {
        Kind::ShellOutput
    } else if ident.contains("agent") {
        Kind::AgentResults
    } else {
        Kind::OtherTools
    }
}

#[cfg(test)]
mod tests;
