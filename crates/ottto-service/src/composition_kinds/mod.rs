//! Composition kinds: which kind (and part) of context one transcript
//! contributor is.
//!
//! Pure classification over its arguments: no IO and no state beyond a cache
//! the caller owns. The context-composition reader owns reading, the
//! request-1 phase, residency, copied history, local state and upload; this
//! module only answers "what is this content".
//!
//! This is the interface between the two, kept stable so each side can change
//! on its own. Every function answers for both methodologies; the reader
//! picks one per line through `LineCtx::kinds_version` (`LineCtx::v1` or
//! `LineCtx::v2`). kinds_version 1 output is exactly today's: the ten v1
//! categories and no parts. kinds_version 2 classifies into the seven kinds
//! and their parts (`v2`). A call classified under kinds_version 2 carries
//! parts, so `codex_cell` splits it the kinds_version 2 way; `GitRootCache`
//! looks up repository folders only when built with `GitRootCache::v2`.
//!
//! `shell` holds the lexical shell-command parser shared with the
//! session-start facts, so there is one parser for both.

pub(crate) mod shell;
mod v2;

use crate::context_footprint::safe_text;
use serde_json::Value;
use std::path::Path;

// -------------------------------------------------------------------------
// Kinds and parts.
// -------------------------------------------------------------------------

/// Kind of context (the daily row's `category` wire id). Declaration order is
/// the row order inside a day, so the v1 variants keep their original order.
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
    /// The kinds_version 1 categories in wire order, used by the test-only
    /// kinds_version 1 oracle and the kinds tests.
    #[cfg(test)]
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
    /// panic, release builds use slot 0). Test-only, like `ALL`.
    #[cfg(test)]
    pub(crate) fn index(self) -> usize {
        let index = Kind::ALL.iter().position(|c| *c == self);
        debug_assert!(index.is_some(), "{self:?} has no kinds_version 1 slot");
        index.unwrap_or(0)
    }
}

/// Part of a kind. kinds_version 1 has no parts (`Unsplit`).
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

/// Who wrote a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Author {
    You,
    Agent,
}

/// Whether a line belongs to the session's first request, and if so whether
/// the session-start facts measured that start.
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

/// The classification methodology a reader uploads (`kinds_version`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KindsVersion {
    V1,
    V2,
}

/// What the reader knows about the line being classified.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LineCtx<'a> {
    /// Whether the line belongs to the session's first request.
    pub(crate) request_1: Request1,
    /// The folder the session (or this line's command) runs in.
    pub(crate) cwd: Option<&'a Path>,
    /// The transcript writes the client's `rendered` text on attachments.
    pub(crate) file_has_rendered: bool,
    /// Who wrote the session's prompts: `Agent` for a session another agent
    /// or program drives (Claude `isSidechain` or an SDK entry point; Codex
    /// `exec`/subagent sources or an agent-created thread).
    pub(crate) author: Author,
    /// kinds_version 1 reads none of the fields above.
    pub(crate) kinds_version: KindsVersion,
}

impl<'a> LineCtx<'a> {
    /// The context the kinds_version 1 reader supplies: it tracks no
    /// request-1 phase, folder, rendered text or author.
    pub(crate) fn v1() -> Self {
        Self {
            request_1: Request1::No,
            cwd: None,
            file_has_rendered: false,
            author: Author::You,
            kinds_version: KindsVersion::V1,
        }
    }

    /// A kinds_version 2 context.
    pub(crate) fn v2(
        request_1: Request1,
        cwd: Option<&'a Path>,
        file_has_rendered: bool,
        author: Author,
    ) -> Self {
        Self {
            request_1,
            cwd,
            file_has_rendered,
            author,
            kinds_version: KindsVersion::V2,
        }
    }

    fn is_v1(&self) -> bool {
        self.kinds_version == KindsVersion::V1
    }
}

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

impl ToolKey {
    pub(crate) fn new(name: &str) -> Self {
        Self(name.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a tool call's result counts, decided when the call is seen. The reader
/// keeps it with the open call without looking inside, and splits the
/// result with `codex_cell` (any agent's call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallClass {
    /// The call's largest share.
    pub(crate) kind: Kind,
    pub(crate) part: Part,
    pub(crate) tool: ToolKey,
    /// The file the call read: as written in the transcript (kinds_version 1),
    /// or joined to the folder the read ran in (kinds_version 2).
    pub(crate) file: Option<Box<str>>,
    /// kinds_version 2: every share when the result shows more than one thing
    /// (a shell command with several parts, a read of several files) or its
    /// one share names an add-on tool. Empty when `kind`, `part` and `file`
    /// are the whole result.
    pub(crate) shares: Box<[CallShare]>,
}

/// One weighted share of a call's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallShare {
    pub(crate) kind: Kind,
    pub(crate) part: Part,
    /// Relative size: shares split the result in proportion.
    pub(crate) weight: u32,
    pub(crate) file: Option<Box<str>>,
    /// The add-on (MCP) tool behind the share, `server/tool`: a code cell's
    /// call names `exec`, not the add-on tools it ran.
    pub(crate) tool: Option<ToolKey>,
}

impl CallClass {
    fn v1(kind: Kind, tool: ToolKey, file: Option<Box<str>>) -> Self {
        Self {
            kind,
            part: Part::Unsplit,
            tool,
            file,
            shares: Box::default(),
        }
    }

    /// A result whose call is not in the transcript (or has no name), for the
    /// kinds_version 1 reader. kinds_version 2 readers classify it with
    /// `claude_tool(ctx, "", &Value::Null)` or `codex_call(ctx, None, "")`.
    pub(crate) fn unmatched() -> Self {
        Self::v1(Kind::OtherTools, ToolKey::new(""), None)
    }

    /// A kinds_version 2 class from its shares; equal (kind, part, file,
    /// tool) shares merge.
    fn from_shares(tool: ToolKey, shares: Vec<CallShare>) -> Self {
        let mut merged: Vec<CallShare> = Vec::with_capacity(shares.len());
        for share in shares {
            match merged.iter_mut().find(|known| {
                (known.kind, known.part, &known.file, &known.tool)
                    == (share.kind, share.part, &share.file, &share.tool)
            }) {
                Some(known) => known.weight = known.weight.saturating_add(share.weight),
                None => merged.push(share),
            }
        }
        let largest = merged
            .iter()
            .enumerate()
            .max_by(|(left_index, left), (right_index, right)| {
                left.weight
                    .cmp(&right.weight)
                    .then(right_index.cmp(left_index))
            })
            .map(|(_, share)| share.clone())
            .unwrap_or(CallShare {
                kind: Kind::OtherTools,
                part: Part::BuiltInOther,
                weight: 1,
                file: None,
                tool: None,
            });
        Self {
            kind: largest.kind,
            part: largest.part,
            tool,
            file: largest.file,
            shares: if merged.len() > 1 || largest.tool.is_some() {
                merged.into_boxed_slice()
            } else {
                Box::default()
            },
        }
    }

    /// The call's shares (one when `shares` is empty).
    fn share_list(&self) -> Vec<CallShare> {
        if self.shares.is_empty() {
            vec![CallShare {
                kind: self.kind,
                part: self.part,
                weight: 1,
                file: self.file.clone(),
                tool: None,
            }]
        } else {
            self.shares.to_vec()
        }
    }
}

// -------------------------------------------------------------------------
// Claude Code.
// -------------------------------------------------------------------------

/// The fields of a Claude Code attachment record classification reads.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ClaudeAttachment<'a> {
    pub(crate) att_type: &'a str,
    pub(crate) filename: Option<&'a str>,
    /// The attachment's sub-type: `files[].type` of an instructions
    /// attachment (`AutoMem`, `Project`, ...; the reader classifies each
    /// `files[]` entry on its own), or `commandMode` of a `queued_command`
    /// (`prompt`, `task-notification`).
    pub(crate) file_type: Option<&'a str>,
    /// The record carries the client's `rendered` text.
    pub(crate) has_rendered: bool,
}

pub(crate) fn claude_attachment(ctx: &LineCtx, att: &ClaudeAttachment) -> Verdict {
    if !ctx.is_v1() {
        return v2::claude_attachment(ctx, att);
    }
    match att.filename {
        Some(filename) if is_memory_path(filename) => Verdict::v1(Kind::MemoryNotes),
        _ => Verdict::v1(Kind::HarnessAttachments),
    }
}

/// Whether kinds_version 2 knows a Claude attachment type; unknown types
/// count as `automatic_additions` / `other` (a health counter's input).
#[cfg(test)]
pub(crate) fn claude_attachment_known(att_type: &str) -> bool {
    v2::claude_attachment_known(att_type)
}

/// A `tool_use` block: `name` is "" when the block has none.
pub(crate) fn claude_tool(ctx: &LineCtx, name: &str, input: &Value) -> CallClass {
    if !ctx.is_v1() {
        return v2::claude_tool(ctx, name, input);
    }
    let file = input.get("file_path").and_then(Value::as_str);
    CallClass::v1(
        cc_tool_category(name, file.unwrap_or("")),
        ToolKey::new(name),
        file.map(Into::into),
    )
}

/// A user record's own text (not a tool result): the whole record, so its
/// flags (`isMeta`, `isCompactSummary`, `isSidechain`, `entrypoint`) count.
pub(crate) fn claude_user_text(ctx: &LineCtx, line: &Value) -> Verdict {
    if !ctx.is_v1() {
        return v2::claude_user_text(ctx, line);
    }
    Verdict::Skip(SkipReason::NotMeasured)
}

/// Image blocks: in a tool result (`call`) or directly in a message.
pub(crate) fn image(ctx: &LineCtx, call: Option<&CallClass>) -> Verdict {
    debug_assert!(
        ctx.is_v1() || call.map_or(true, |call| call.part != Part::Unsplit),
        "a kinds_version 2 line got a kinds_version 1 call class"
    );
    if !ctx.is_v1() && call.map_or(true, |call| call.part != Part::Unsplit) {
        return v2::image(ctx, call);
    }
    Verdict::v1(Kind::BrowserAndImages)
}

// -------------------------------------------------------------------------
// Codex.
// -------------------------------------------------------------------------

/// A function, custom-tool or local-shell call. `input` is the call's own
/// input text: `input` for a custom-tool call, `arguments` for a function
/// call, the action's command for a local-shell call ("" when it has none).
/// kinds_version 2 readers pass `namespace/name` when the call has a
/// `namespace` (`mcp__cua_repl/js`, `collaboration/spawn_agent`).
pub(crate) fn codex_call(ctx: &LineCtx, name: Option<&str>, input: &str) -> CallClass {
    if !ctx.is_v1() {
        return v2::codex_call(ctx, name, input);
    }
    match name {
        Some(name) => CallClass::v1(codex_tool_category(name), ToolKey::new(name), None),
        None => CallClass::unmatched(),
    }
}

/// An add-on (MCP) call and its result, from its `invocation`.
pub(crate) fn codex_mcp(ctx: &LineCtx, invocation: Option<&Value>) -> CallClass {
    if !ctx.is_v1() {
        return v2::codex_mcp(ctx, invocation);
    }
    let field = |key| {
        invocation
            .and_then(|invocation| invocation.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    let tool = ToolKey::new(&format!("{}/{}", field("server"), field("tool")));
    CallClass::v1(codex_mcp_category(invocation), tool, None)
}

/// An inner item Codex writes between a call and its output
/// (`event_msg` / `item_completed`).
#[derive(Debug, Clone, Copy)]
pub(crate) enum InnerItem<'a> {
    /// `CommandExecution`. `cwd` as written (a `file://` prefix is fine);
    /// `command` is the script: for a `[shell, -lc, script]` array the last
    /// element (see `command_words_script`); `output_chars` is the length of
    /// `aggregated_output`.
    Command {
        cwd: Option<&'a str>,
        command: &'a str,
        parsed: &'a [ParsedCommand<'a>],
        output_chars: u64,
    },
    /// `McpToolCall`; `output_chars` is the length of `result`.
    Mcp {
        server: &'a str,
        tool: &'a str,
        output_chars: u64,
    },
    /// `Extension` (its `kind`, such as `web.search`) or a nested function
    /// call (`namespace/name`).
    Extension { name: &'a str, output_chars: u64 },
    /// A web search the call ran.
    WebSearch { output_chars: u64 },
}

/// The script of a Codex command array: the last element of
/// `[shell, -lc, script]`, else the words joined by spaces.
#[cfg(test)] // The reader calls `v2::command_words_script` directly.
pub(crate) fn command_words_script(words: &[Value]) -> String {
    v2::command_words_script(words)
}

/// One entry of Codex's own `parsed_cmd` (`read`, `search`, `list_files`,
/// `unknown`).
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
    /// The add-on (MCP) tool behind the share, `server/tool`.
    pub(crate) tool: Option<ToolKey>,
}

/// Split a call output's tokens: across the inner items the call wrote (a
/// Codex cell, in proportion to each item's output length), else across the
/// call's own shares (any agent's call). The shares sum to `output_tokens`;
/// shares that round to nothing are dropped, keeping at least one.
/// kinds_version 1 gives the call's whole output to the call's class, inner
/// items or not; this function has no line context, so a kinds_version 2
/// reader must never hand it a kinds_version 1 class (`CallClass::unmatched`).
pub(crate) fn codex_cell(
    call: &CallClass,
    items: &[InnerItem],
    output_tokens: u64,
) -> Vec<CellShare> {
    if call.part == Part::Unsplit {
        return vec![CellShare {
            kind: call.kind,
            part: call.part,
            tokens: output_tokens,
            file: call.file.clone(),
            tool: None,
        }];
    }
    let mut cells: Vec<CellShare> = Vec::new();
    let mut add = |shares: Vec<CallShare>, tokens: u64| {
        let weights: Vec<u64> = shares.iter().map(|share| u64::from(share.weight)).collect();
        for (share, tokens) in shares.into_iter().zip(split_tokens(tokens, &weights)) {
            match cells.iter_mut().find(|cell| {
                (cell.kind, cell.part, &cell.file, &cell.tool)
                    == (share.kind, share.part, &share.file, &share.tool)
            }) {
                Some(cell) => cell.tokens += tokens,
                None => cells.push(CellShare {
                    kind: share.kind,
                    part: share.part,
                    tokens,
                    file: share.file,
                    tool: share.tool,
                }),
            }
        }
    };
    if items.is_empty() {
        add(call.share_list(), output_tokens);
    } else {
        let lengths: Vec<u64> = items.iter().map(InnerItem::output_chars).collect();
        let weights = if lengths.iter().all(|length| *length == 0) {
            vec![1; items.len()]
        } else {
            lengths
        };
        for (item, tokens) in items.iter().zip(split_tokens(output_tokens, &weights)) {
            add(v2::item_shares(item), tokens);
        }
    }
    if cells.iter().any(|cell| cell.tokens > 0) {
        cells.retain(|cell| cell.tokens > 0);
    } else {
        cells.truncate(1);
    }
    cells
}

impl InnerItem<'_> {
    fn output_chars(&self) -> u64 {
        match *self {
            InnerItem::Command { output_chars, .. }
            | InnerItem::Mcp { output_chars, .. }
            | InnerItem::Extension { output_chars, .. }
            | InnerItem::WebSearch { output_chars } => output_chars,
        }
    }
}

/// `total` split in proportion to `weights`, summing to `total` exactly
/// (largest remainders first, earlier shares on ties). All weights zero: the
/// first share takes everything.
pub(crate) fn split_tokens(total: u64, weights: &[u64]) -> Vec<u64> {
    let sum: u128 = weights.iter().map(|weight| u128::from(*weight)).sum();
    if sum == 0 {
        let mut even = vec![0; weights.len()];
        if let Some(first) = even.first_mut() {
            *first = total;
        }
        return even;
    }
    let mut shares: Vec<u64> = Vec::with_capacity(weights.len());
    let mut remainders: Vec<(u128, usize)> = Vec::with_capacity(weights.len());
    for (index, weight) in weights.iter().enumerate() {
        let exact = u128::from(total) * u128::from(*weight);
        shares.push((exact / sum) as u64);
        remainders.push((exact % sum, index));
    }
    let mut left = total - shares.iter().sum::<u64>();
    remainders.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    for (_, index) in remainders {
        if left == 0 {
            break;
        }
        shares[index] += 1;
        left -= 1;
    }
    shares
}

/// A standalone record outside any call: an event's `payload.type`, or
/// `compacted` for a compaction record.
pub(crate) fn codex_event(ctx: &LineCtx, event_type: &str) -> Verdict {
    if !ctx.is_v1() {
        return v2::codex_event(ctx, event_type);
    }
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
/// and `text` unused), or one text block of a user message. kinds_version 2
/// readers pass every text block of both roles with its label.
pub(crate) fn codex_message(ctx: &LineCtx, role: &str, label: ContentLabel, text: &str) -> Verdict {
    if !ctx.is_v1() {
        return v2::codex_message(ctx, role, label, text);
    }
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

/// Most folders remembered by one cache.
const MAX_CACHED_FOLDERS: usize = 4096;

/// Folder-to-repository lookups shared across one workspace's files. The
/// default (kinds_version 1) looks nothing up and only strips the workspace
/// prefix; `GitRootCache::v2` also finds each folder's checkout root (the
/// nearest folder holding `.git`, one `stat` per folder walked) and that
/// checkout's repository hash (once per root, from the files under `.git`,
/// without running git), so a file in another checkout of the same
/// repository keeps its repo-relative path. Once a map holds
/// `MAX_CACHED_FOLDERS` entries, new folders and roots are not looked up
/// (the file keeps its basename) and `skipped` counts them.
#[derive(Debug)]
pub(crate) struct GitRootCache {
    lookup: bool,
    /// Folder -> its checkout root, or `None` outside any checkout.
    roots: std::collections::HashMap<String, Option<String>>,
    /// Checkout root -> repository hash.
    hashes: std::collections::HashMap<String, Option<String>>,
    /// Lookups not made because a map was full.
    skipped: u64,
    repository_hash: fn(&Path) -> Option<String>,
}

impl Default for GitRootCache {
    fn default() -> Self {
        Self {
            lookup: false,
            roots: Default::default(),
            hashes: Default::default(),
            skipped: 0,
            repository_hash,
        }
    }
}

/// Largest `.git` or `commondir` file read.
const MAX_GIT_POINTER_BYTES: u64 = 4096;

/// The repository hash `resolve_repository_identity` gives a checkout root,
/// read from the files git itself reads instead of running git: the hash of
/// the canonical shared git folder (`--git-common-dir`). `<root>/.git` is that
/// folder in a main checkout; in a linked worktree or submodule `.git` is a
/// file naming the checkout's own git folder (`gitdir: ...`), whose
/// `commondir` file, when present, names the shared one. `None` when the
/// folder is not a git folder as git itself checks it: `HEAD` in the git
/// folder, `objects` and `refs` in the shared one.
fn repository_hash(root: &Path) -> Option<String> {
    /// A pointer file's text. Only a regular file is opened, so a FIFO or a
    /// device in its place never blocks the reader.
    fn read_small(path: &Path) -> Option<String> {
        use std::io::Read as _;
        if !path.is_file() {
            return None;
        }
        let mut text = String::new();
        std::fs::File::open(path)
            .ok()?
            .take(MAX_GIT_POINTER_BYTES)
            .read_to_string(&mut text)
            .ok()?;
        Some(text)
    }
    let dot_git = root.join(".git");
    let git_dir = if dot_git.is_dir() {
        dot_git
    } else {
        let text = read_small(&dot_git)?;
        // git reads `gitdir: ` with its space.
        let target = text.lines().next()?.strip_prefix("gitdir: ")?.trim();
        if target.is_empty() {
            return None;
        }
        root.join(target)
    };
    if !git_dir.join("HEAD").is_file() {
        return None;
    }
    let common_dir = match read_small(&git_dir.join("commondir")) {
        Some(text) if !text.trim().is_empty() => git_dir.join(text.trim()),
        _ => git_dir,
    };
    if !common_dir.join("objects").is_dir() || !common_dir.join("refs").is_dir() {
        return None;
    }
    let common_dir = common_dir.canonicalize().unwrap_or(common_dir);
    Some(crate::context_footprint::sha256_hex(&[common_dir
        .to_string_lossy()
        .as_ref()]))
}

impl GitRootCache {
    /// A cache that looks up checkout roots (kinds_version 2).
    pub(crate) fn v2() -> Self {
        Self {
            lookup: true,
            ..Self::default()
        }
    }

    /// Lookups not made because the cache was full (a health counter's
    /// input).
    pub(crate) fn skipped(&self) -> u64 {
        self.skipped
    }

    /// The checkout root holding `folder` (absolute, normalized).
    fn root_of(&mut self, folder: &str) -> Option<String> {
        let mut walked = Vec::new();
        let mut found = None;
        let mut current = Some(Path::new(folder));
        while let Some(dir) = current {
            let key = dir.to_string_lossy();
            if let Some(cached) = self.roots.get(key.as_ref()) {
                found = cached.clone();
                break;
            }
            if self.roots.len() + walked.len() >= MAX_CACHED_FOLDERS {
                self.skipped += 1;
                return None;
            }
            walked.push(key.into_owned());
            if dir.join(".git").symlink_metadata().is_ok() {
                found = Some(dir.to_string_lossy().into_owned());
                break;
            }
            current = dir.parent();
        }
        for dir in walked {
            self.roots.insert(dir, found.clone());
        }
        found
    }

    fn root_hash(&mut self, root: &str) -> Option<String> {
        if let Some(hash) = self.hashes.get(root) {
            return hash.clone();
        }
        if self.hashes.len() >= MAX_CACHED_FOLDERS {
            self.skipped += 1;
            return None;
        }
        let hash = (self.repository_hash)(Path::new(root));
        self.hashes.insert(root.to_string(), hash.clone());
        hash
    }

    /// `raw` relative to its checkout root, when that checkout is the
    /// workspace's repository.
    fn in_repository(&mut self, raw: &str, ws_repo_hash: &str) -> Option<String> {
        let folder = Path::new(raw).parent()?.to_str()?;
        let root = self.root_of(folder)?;
        if self.root_hash(&root).as_deref() != Some(ws_repo_hash) {
            return None;
        }
        Path::new(raw)
            .strip_prefix(&root)
            .ok()
            .map(|rel| rel.to_string_lossy().into_owned())
            .filter(|rel| !rel.is_empty())
    }
}

/// Make a transcript-referenced path safe for the aggregate payload: strip the
/// workspace prefix to a repo-relative path (with a `GitRootCache::v2`, also
/// the root of another checkout of the workspace's repository), else reduce to
/// a bare basename. Returns `None` when even the basename would leak a
/// path/secret.
pub(crate) fn repo_relative(
    raw: &str,
    workspace: &Path,
    ws_repo_hash: Option<&str>,
    cache: &mut GitRootCache,
) -> Option<String> {
    let normalized;
    let raw = if cache.lookup && raw.starts_with('/') {
        normalized = shell::normalize_lexically(raw);
        normalized.as_str()
    } else {
        raw
    };
    let candidate = Path::new(raw)
        .strip_prefix(workspace)
        .ok()
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .filter(|rel| !rel.is_empty())
        .or_else(|| {
            let hash = ws_repo_hash.filter(|_| cache.lookup && raw.starts_with('/'))?;
            cache.in_repository(raw, hash)
        })
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
// kinds_version 1 classifiers (unchanged; kinds_version 1 output must not
// move).
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
#[cfg(test)]
mod tests_v2;
