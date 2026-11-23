//! kinds_version 2 classification: the seven kinds and their parts.
//!
//! Rules, in the order they apply to one line:
//! - Never counted: the Claude client's `prompt_snapshot` (its own record of
//!   the system prompt and tool list) and `deferred_tools_record`
//!   (bookkeeping); in a file whose attachments carry the client's `rendered`
//!   text, an attachment without it never reached the model.
//! - Request 1: skipped when the session-start facts measured that start,
//!   else counted as `automatic_additions` / `start_not_measured`.
//! - Everything else by what it is. Add-on servers decide computer use and
//!   browser by server name, never by tool name (browser servers have a tool
//!   called `computer`).

use super::shell::{classify_shell, is_script_flag, join_to, ShellClass, ShellSegment, SHELLS};
use super::{
    is_memory_path, Author, CallClass, CallShare, ContentLabel, InnerItem, Kind, LineCtx, Part,
    Request1, SkipReason, ToolKey, Verdict,
};
use serde_json::Value;
use std::path::Path;

fn count(part: Part) -> Verdict {
    Verdict::Count {
        kind: part.kind().unwrap_or(Kind::AutomaticAdditions),
        part,
    }
}

/// The verdict for request-1 content, when the line is in request 1.
fn request_1(ctx: &LineCtx) -> Option<Verdict> {
    match ctx.request_1 {
        Request1::No => None,
        Request1::StartMeasured => Some(Verdict::Skip(SkipReason::RequestOne)),
        Request1::StartNotMeasured => Some(count(Part::StartNotMeasured)),
    }
}

fn prompt(ctx: &LineCtx, agent_written: bool) -> Verdict {
    if agent_written || ctx.author == Author::Agent {
        count(Part::ByAgent)
    } else {
        count(Part::ByYou)
    }
}

// -------------------------------------------------------------------------
// Files.
// -------------------------------------------------------------------------

/// Instruction files an agent loads on its own; reading one is
/// `instructions_later`.
const INSTRUCTION_FILES: [&str; 5] = [
    "AGENTS.md",
    "AGENTS.override.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "GEMINI.md",
];

/// The files_read part of a read of `path`: skill, memory and instruction
/// files have their own parts; everything else takes `default`.
pub(super) fn read_part(path: &str, default: Part) -> Part {
    let basename = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if basename == "SKILL.md" {
        Part::SkillFile
    } else if is_memory_file(path) {
        Part::MemoryFile
    } else if INSTRUCTION_FILES.contains(&basename) {
        Part::InstructionsLater
    } else {
        default
    }
}

/// Auto-memory files: `MEMORY.md`, anything under `AutoMem/`, and Markdown
/// notes under a `memory/` folder (a source folder named `memory` is code).
fn is_memory_file(path: &str) -> bool {
    let markdown = path.to_ascii_lowercase().ends_with(".md");
    is_memory_path(path) && (markdown || path.contains("AutoMem/") || path.contains("AutoMem\\"))
}

fn read_share(path: Option<&str>, default: Part, weight: u32) -> CallShare {
    CallShare {
        kind: Kind::FilesRead,
        part: path.map_or(default, |path| read_part(path, default)),
        weight,
        file: path.map(Into::into),
        tool: None,
    }
}

fn share(part: Part, weight: u32) -> CallShare {
    CallShare {
        kind: part.kind().unwrap_or(Kind::OtherTools),
        part,
        weight,
        file: None,
        tool: None,
    }
}

/// The share of an add-on (MCP) tool's result, labelled `server/tool`.
fn server_share(server: &str, tool: &str, part: Part) -> CallShare {
    CallShare {
        tool: Some(ToolKey::new(&format!("{server}/{tool}"))),
        ..share(part, 1)
    }
}

/// Least common multiple of 1..=16: every read's path count divides it, so
/// equal shares stay whole numbers.
const SEGMENT_WEIGHT: u32 = 720_720;

/// A shell command's output split evenly across its output-producing
/// segments, and a read's share evenly across its files.
pub(super) fn shell_shares(segments: &[ShellSegment]) -> Vec<CallShare> {
    if segments.is_empty() {
        // Only writes or directory changes: what it prints is errors.
        return vec![share(Part::OtherCommands, 1)];
    }
    let mut shares = Vec::new();
    for segment in segments {
        let part = match segment.class {
            ShellClass::Read => {
                let files = segment.paths.len().clamp(1, 16) as u32;
                let weight = SEGMENT_WEIGHT / files;
                if segment.paths.is_empty() {
                    shares.push(read_share(None, Part::ShellRead, weight));
                }
                for path in segment.paths.iter().take(16) {
                    shares.push(read_share(Some(path), Part::ShellRead, weight));
                }
                continue;
            }
            ShellClass::Git => Part::Git,
            ShellClass::Search => Part::Search,
            ShellClass::TestsBuilds => Part::TestsBuilds,
            ShellClass::Other => Part::OtherCommands,
        };
        shares.push(share(part, SEGMENT_WEIGHT));
    }
    shares
}

// -------------------------------------------------------------------------
// Add-on servers.
// -------------------------------------------------------------------------

/// Browser add-on servers (lowercase, `-` as `_`). A plugin (`plugin_<p>_<s>`)
/// or connector (`claude_ai_<s>`) form ends with the same name.
const BROWSER_SERVERS: [&str; 7] = [
    "claude_browser",
    "claude_in_chrome",
    "control_chrome",
    "claude_preview",
    "puppeteer",
    "browser_use",
    "browsermcp",
];

/// Browser server names matched anywhere in the name (`chrome_devtools_mcp`).
const BROWSER_SERVER_WORDS: [&str; 2] = ["chrome_devtools", "playwright"];

/// Computer-use add-on servers, same form.
const COMPUTER_SERVERS: [&str; 3] = ["computer_use", "cua_repl", "remote_devices"];

/// Kind and part of an add-on (MCP) server's results, by server name.
pub(super) fn server_part(server: &str, tool: &str) -> Part {
    let server = server.to_ascii_lowercase().replace('-', "_");
    if COMPUTER_SERVERS.iter().any(|name| server.ends_with(name)) {
        let tool = tool.to_ascii_lowercase();
        return if tool.contains("screenshot") || tool.contains("zoom") {
            Part::Screenshots
        } else {
            Part::AppControl
        };
    }
    if BROWSER_SERVERS.iter().any(|name| server.ends_with(name))
        || BROWSER_SERVER_WORDS
            .iter()
            .any(|word| server.contains(word))
    {
        return Part::Browser;
    }
    // Codex's own thread tools report other threads' work.
    if server == "codex_app" {
        return Part::AgentReports;
    }
    Part::Addon
}

fn server_call(server: &str, tool: &str) -> CallClass {
    CallClass::from_shares(
        ToolKey::new(&format!("{server}/{tool}")),
        vec![server_share(server, tool, server_part(server, tool))],
    )
}

/// `mcp__<server>__<tool>` -> (server, tool).
fn split_mcp_name(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("mcp__")?;
    match rest.split_once("__") {
        Some((server, tool)) => Some((server, tool)),
        None => Some((rest, "")),
    }
}

// -------------------------------------------------------------------------
// Claude Code.
// -------------------------------------------------------------------------

/// Claude attachment types and their parts. Types not listed count as
/// `automatic_additions` / `other`.
const CLAUDE_ATTACHMENT_PARTS: [(&str, Part); 45] = [
    ("nested_memory", Part::InstructionsLater),
    ("invoked_skills", Part::InstructionsReloaded),
    ("deferred_tools_delta", Part::ToolDescriptionsLater),
    ("skill_listing", Part::ListsUpdated),
    ("agent_listing_delta", Part::ListsUpdated),
    ("mcp_instructions_delta", Part::ListsUpdated),
    ("skill_mention", Part::ListsUpdated),
    ("total_tokens_reminder", Part::Reminders),
    ("silent_turn_reminder", Part::Reminders),
    ("task_reminder", Part::Reminders),
    ("todo_reminder", Part::Reminders),
    ("batching_reminder_sent", Part::Reminders),
    ("critical_system_reminder", Part::Reminders),
    ("auto_mode", Part::Reminders),
    ("auto_mode_exit", Part::Reminders),
    ("plan_mode", Part::Reminders),
    ("plan_mode_exit", Part::Reminders),
    ("plan_mode_reentry", Part::Reminders),
    ("ultra_effort_enter", Part::Reminders),
    ("ultra_effort_exit", Part::Reminders),
    ("environment", Part::Environment),
    ("session_context", Part::Environment),
    ("model", Part::Environment),
    ("date", Part::Environment),
    ("date_change", Part::Environment),
    ("remote_session_change", Part::Environment),
    ("credential_org", Part::Environment),
    ("command_permissions", Part::Environment),
    ("hook_additional_context", Part::HookOutput),
    ("hook_blocking_error", Part::HookOutput),
    ("hook_non_blocking_error", Part::HookOutput),
    ("hook_success", Part::HookOutput),
    ("hook_cancelled", Part::HookOutput),
    ("async_hook_response", Part::HookOutput),
    ("file", Part::FilesMentioned),
    ("compact_file_reference", Part::FilesMentioned),
    ("already_read_file", Part::FilesMentioned),
    ("directory", Part::FilesMentioned),
    ("pdf_reference", Part::FilesMentioned),
    ("selected_lines_in_ide", Part::FilesMentioned),
    ("opened_file_in_ide", Part::FilesMentioned),
    ("inlined_image_paths", Part::FilesMentioned),
    ("edited_text_file", Part::FilesChanged),
    ("edited_image_file", Part::FilesChanged),
    ("task_status", Part::BackgroundReports),
];

/// Types handled by rule rather than by the table above.
#[cfg(test)]
const CLAUDE_ATTACHMENT_RULES: [&str; 4] = [
    "prompt_snapshot",
    "deferred_tools_record",
    "instructions",
    "queued_command",
];

#[cfg(test)]
pub(super) fn claude_attachment_known(att_type: &str) -> bool {
    CLAUDE_ATTACHMENT_RULES.contains(&att_type)
        || CLAUDE_ATTACHMENT_PARTS
            .iter()
            .any(|(known, _)| *known == att_type)
}

pub(super) fn claude_attachment(ctx: &LineCtx, att: &super::ClaudeAttachment) -> Verdict {
    match att.att_type {
        "prompt_snapshot" => return Verdict::Skip(SkipReason::PromptSnapshot),
        "deferred_tools_record" => return Verdict::Skip(SkipReason::DeferredToolsRecord),
        _ => {}
    }
    // A measured start skips everything in request 1, rendered or not, so
    // the unrendered count holds only what would otherwise have counted.
    if ctx.request_1 == Request1::StartMeasured {
        return Verdict::Skip(SkipReason::RequestOne);
    }
    if ctx.file_has_rendered && !att.has_rendered {
        return Verdict::Skip(SkipReason::Unrendered);
    }
    if let Some(verdict) = request_1(ctx) {
        return verdict;
    }
    match att.att_type {
        // One call per `files[]` entry, with that entry's `type`.
        "instructions" => match att.file_type {
            Some("AutoMem") => count(Part::MemoryReloaded),
            _ => count(Part::InstructionsReloaded),
        },
        // A message typed while the agent worked, or a background task's
        // report, by its `commandMode`.
        "queued_command" => match att.file_type {
            Some("task-notification") => count(Part::BackgroundReports),
            _ => prompt(ctx, false),
        },
        att_type => count(
            CLAUDE_ATTACHMENT_PARTS
                .iter()
                .find(|(known, _)| *known == att_type)
                .map_or(Part::Other, |(_, part)| *part),
        ),
    }
}

/// Claude Code entry points that are another program driving the agent.
const CLAUDE_SDK_ENTRYPOINTS: [&str; 3] = ["sdk-cli", "sdk-ts", "sdk-py"];

/// The first text of a user record's message, `None` when it has none (a
/// record of tool results only).
fn claude_user_text_head(line: &Value) -> Option<&str> {
    match line.pointer("/message/content")? {
        Value::String(text) => Some(text),
        Value::Array(blocks) => blocks.iter().find_map(|block| {
            (block.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| block.get("text").and_then(Value::as_str))
                .flatten()
        }),
        _ => None,
    }
}

fn truthy(line: &Value, key: &str) -> bool {
    match line.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::Null) | None => false,
        Some(Value::String(value)) => !value.is_empty(),
        Some(_) => true,
    }
}

pub(super) fn claude_user_text(ctx: &LineCtx, line: &Value) -> Verdict {
    let Some(text) = claude_user_text_head(line) else {
        return Verdict::Skip(SkipReason::NotMeasured);
    };
    if let Some(verdict) = request_1(ctx) {
        return verdict;
    }
    if truthy(line, "isCompactSummary") {
        return count(Part::CompactionSummary);
    }
    let text = text.trim_start();
    if text.starts_with("<task-notification>") {
        return count(Part::BackgroundReports);
    }
    if truthy(line, "isMeta") {
        // A skill's body, loaded when the skill is used.
        return if text.starts_with("Base directory for this skill:") {
            count(Part::SkillFile)
        } else {
            count(Part::Other)
        };
    }
    if text.starts_with("<system-reminder>") {
        return count(Part::Reminders);
    }
    if text.starts_with("<local-command-stdout>") || text.starts_with("<local-command-stderr>") {
        return count(Part::Other);
    }
    let entrypoint = line.get("entrypoint").and_then(Value::as_str);
    let agent_written = truthy(line, "isSidechain")
        || entrypoint.is_some_and(|entrypoint| CLAUDE_SDK_ENTRYPOINTS.contains(&entrypoint));
    prompt(ctx, agent_written)
}

pub(super) fn claude_tool(ctx: &LineCtx, name: &str, input: &Value) -> CallClass {
    let text = |key| input.get(key).and_then(Value::as_str);
    if let Some((server, tool)) = split_mcp_name(name) {
        return server_call(server, tool);
    }
    let tool = ToolKey::new(name);
    let shares = match name {
        "Bash" => shell_shares(&classify_shell(text("command").unwrap_or(""), ctx.cwd)),
        "Read" | "NotebookRead" => {
            let path = text("file_path").and_then(|path| join_to(ctx.cwd, path));
            vec![read_share(path.as_deref(), Part::FileTool, 1)]
        }
        "Skill" => vec![share(Part::SkillFile, 1)],
        "Grep" | "Glob" | "LS" => vec![share(Part::Search, 1)],
        "BashOutput" => vec![share(Part::OtherCommands, 1)],
        "Task" | "Agent" | "SendMessage" | "ListAgents" | "SubagentHandback" => {
            vec![share(Part::AgentReports, 1)]
        }
        "TaskOutput" => vec![share(Part::BackgroundReports, 1)],
        "WebFetch" | "WebSearch" => vec![share(Part::Web, 1)],
        _ => vec![share(Part::BuiltInOther, 1)],
    };
    CallClass::from_shares(tool, shares)
}

pub(super) fn image(ctx: &LineCtx, call: Option<&CallClass>) -> Verdict {
    match call {
        Some(call) => match call.kind {
            Kind::ComputerUse => count(Part::Screenshots),
            Kind::WebAndBrowser => count(Part::Browser),
            kind => Verdict::Count {
                kind,
                part: call.part,
            },
        },
        // An image in a message: pasted or attached with the prompt.
        None => request_1(ctx).unwrap_or_else(|| prompt(ctx, false)),
    }
}

// -------------------------------------------------------------------------
// Codex.
// -------------------------------------------------------------------------

/// Codex's built-in tool namespaces.
const CODEX_AGENT_NAMESPACES: [&str; 2] = ["collaboration", "codex_app"];
const CODEX_AGENT_TOOLS: [&str; 9] = [
    "spawn_agent",
    "send_input",
    "wait_agent",
    "close_agent",
    "list_agents",
    "resume_agent",
    "followup_task",
    "interrupt_agent",
    "send_message",
];
const CODEX_COMMAND_POLLS: [&str; 5] =
    ["write_stdin", "wait", "read_stdout", "kill", "kill_command"];
const CODEX_SHELLS: [&str; 6] = [
    "shell",
    "local_shell",
    "shell_command",
    "container.exec",
    "run_command",
    "bash",
];
const CODEX_WEB_TOOLS: [&str; 7] = [
    "web_search",
    "web.search",
    "web.run",
    "search_query",
    "image_query",
    "web_fetch",
    "fetch",
];
const CODEX_FILE_TOOLS: [&str; 4] = ["view_image", "read_file", "view", "read"];

/// Most bytes of a cell's code searched for its first tool call.
const MAX_FALLBACK_SCAN: usize = 64 * 1024;

pub(super) fn codex_call(ctx: &LineCtx, name: Option<&str>, input: &str) -> CallClass {
    let Some(name) = name else {
        return CallClass::from_shares(ToolKey::new(""), vec![share(Part::BuiltInOther, 1)]);
    };
    CallClass::from_shares(ToolKey::new(name), codex_function(name, input, ctx.cwd, 0))
}

/// Shares of one Codex function by its name (`namespace/name` when the call
/// has a namespace) and its input.
fn codex_function(name: &str, input: &str, cwd: Option<&Path>, depth: u8) -> Vec<CallShare> {
    let (namespace, base) = name.split_once('/').unwrap_or(("", name));
    if let Some(server) = namespace.strip_prefix("mcp__") {
        return vec![server_share(server, base, server_part(server, base))];
    }
    if let Some((server, tool)) = split_mcp_name(base) {
        return vec![server_share(server, tool, server_part(server, tool))];
    }
    if CODEX_AGENT_NAMESPACES.contains(&namespace) {
        return vec![share(Part::AgentReports, 1)];
    }
    if let Some((server, tool)) = base.split_once("__") {
        // A code cell's `tools.<server>__<tool>(` form.
        let part = if CODEX_AGENT_NAMESPACES.contains(&server) {
            Part::AgentReports
        } else if matches!(server, "clock" | "tool_search") {
            Part::BuiltInOther
        } else {
            server_part(server, tool)
        };
        return vec![server_share(server, tool, part)];
    }
    if namespace.is_empty() && base == "exec" && depth == 0 {
        return codex_code_cell(input, cwd);
    }
    if base == "exec_command" || CODEX_SHELLS.contains(&base) {
        return codex_shell_call(input, cwd);
    }
    if CODEX_COMMAND_POLLS.contains(&base) {
        return vec![share(Part::OtherCommands, 1)];
    }
    if CODEX_WEB_TOOLS.contains(&base) {
        return vec![share(Part::Web, 1)];
    }
    if CODEX_FILE_TOOLS.contains(&base) {
        let arguments = serde_json::from_str::<Value>(input).ok();
        let arguments = arguments.as_ref();
        let workdir = arguments
            .and_then(|arguments| arguments.get("workdir"))
            .and_then(Value::as_str)
            .map(Path::new);
        let path = arguments
            .and_then(|arguments| arguments.get("path").or_else(|| arguments.get("file_path")))
            .and_then(Value::as_str)
            .and_then(|path| join_to(workdir.or(cwd), path));
        return vec![read_share(path.as_deref(), Part::FileTool, 1)];
    }
    if CODEX_AGENT_TOOLS.contains(&base) {
        return vec![share(Part::AgentReports, 1)];
    }
    vec![share(Part::BuiltInOther, 1)]
}

/// A function call running a shell command: `{"cmd": ".."}` (exec_command),
/// `{"command": [..]}` (shell), or the command words themselves.
fn codex_shell_call(input: &str, cwd: Option<&Path>) -> Vec<CallShare> {
    let arguments = serde_json::from_str::<Value>(input).ok();
    let workdir = arguments
        .as_ref()
        .and_then(|arguments| arguments.get("workdir"))
        .and_then(Value::as_str)
        .map(Path::new);
    let command = match arguments
        .as_ref()
        .and_then(|arguments| arguments.get("cmd").or_else(|| arguments.get("command")))
    {
        Some(Value::String(command)) => command.clone(),
        Some(Value::Array(words)) => command_words_script(words),
        Some(_) => String::new(),
        None if arguments.is_some() => String::new(),
        None => input.to_string(),
    };
    shell_shares(&classify_shell(&command, workdir.or(cwd)))
}

/// `["bash", "-lc", "script", ...]` -> `script` (a shell executable and its
/// script flag); any other array becomes one command whose words are quoted,
/// so an argument keeps its boundaries (`["cat", "my notes.md"]`) and never
/// reads as shell syntax (`["python", "-c", "..."]` is not a shell script).
pub(super) fn command_words_script(words: &[Value]) -> String {
    let words: Vec<&str> = words.iter().filter_map(Value::as_str).collect();
    let shell = words
        .first()
        .is_some_and(|program| SHELLS.contains(&program.rsplit('/').next().unwrap_or(program)));
    let script = shell
        .then(|| words.iter().position(|word| is_script_flag(word)))
        .flatten()
        .and_then(|flag| words.get(flag + 1));
    match script {
        Some(script) => (*script).to_string(),
        None => words
            .iter()
            .map(|word| shell_quote(word))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// `word` as one shell word: unchanged when plain, else single-quoted.
fn shell_quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_./:=@%+,-".contains(ch));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// A code cell with no inner items: its first `tools.<name>(` call decides.
fn codex_code_cell(input: &str, cwd: Option<&Path>) -> Vec<CallShare> {
    let mut end = input.len().min(MAX_FALLBACK_SCAN);
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    let code = &input[..end];
    let Some((name, args)) = first_tool_call(code) else {
        return vec![share(Part::BuiltInOther, 1)];
    };
    if name == "exec_command" {
        return match js_string_field(args, "cmd") {
            Some(command) => {
                let workdir = js_string_field(args, "workdir");
                let workdir = workdir.as_deref().map(Path::new);
                shell_shares(&classify_shell(&command, workdir.or(cwd)))
            }
            None => vec![share(Part::OtherCommands, 1)],
        };
    }
    codex_function(name, "", cwd, 1)
}

/// The first `tools.<name>(` in a code cell: the name and the text after `(`.
fn first_tool_call(code: &str) -> Option<(&str, &str)> {
    let mut rest = code;
    while let Some(at) = rest.find("tools.") {
        let after = &rest[at + "tools.".len()..];
        let end = after
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
            .unwrap_or(after.len());
        let name = &after[..end];
        let tail = after[end..].trim_start();
        let preceded_by_ident = rest[..at]
            .chars()
            .next_back()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.');
        if !name.is_empty() && !preceded_by_ident {
            if let Some(args) = tail.strip_prefix('(') {
                return Some((name, args));
            }
        }
        rest = &after[end..];
    }
    None
}

/// The string value of `key` in a JavaScript object literal's text
/// (`key: "..."`, `"key": '...'` or a template string without `${`).
fn js_string_field(args: &str, key: &str) -> Option<String> {
    let mut rest = args;
    loop {
        let at = rest.find(key)?;
        let before = rest[..at].chars().next_back();
        let after = rest[at + key.len()..].trim_start_matches(['"', '\'']);
        rest = &rest[at + key.len()..];
        if before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
            continue;
        }
        let Some(value) = after.trim_start().strip_prefix(':') else {
            continue;
        };
        let value = value.trim_start();
        let quote = value.chars().next()?;
        if !matches!(quote, '"' | '\'' | '`') {
            return None;
        }
        let mut text = String::new();
        let mut chars = value[1..].chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => match chars.next()? {
                    'n' => text.push('\n'),
                    't' => text.push('\t'),
                    other => text.push(other),
                },
                '$' if quote == '`' && chars.clone().next() == Some('{') => return None,
                ch if ch == quote => return Some(text),
                ch => text.push(ch),
            }
        }
        return None;
    }
}

pub(super) fn codex_mcp(_ctx: &LineCtx, invocation: Option<&Value>) -> CallClass {
    let field = |key| {
        invocation
            .and_then(|invocation| invocation.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    server_call(field("server"), field("tool"))
}

/// One inner item's shares of its cell.
pub(super) fn item_shares(item: &InnerItem) -> Vec<CallShare> {
    match *item {
        InnerItem::Command {
            cwd,
            command,
            parsed,
            ..
        } => {
            let cwd = cwd.map(|cwd| cwd.strip_prefix("file://").unwrap_or(cwd));
            let cwd = cwd.map(Path::new);
            // Codex's own parse for reads and searches; ours when it gave up
            // on any part (it calls `nl -ba f | sed -n ..` unknown).
            let known = !parsed.is_empty()
                && parsed
                    .iter()
                    .all(|entry| matches!(entry.kind, "read" | "search" | "list_files"));
            if !known {
                return shell_shares(&classify_shell(command, cwd));
            }
            parsed
                .iter()
                .map(|entry| match entry.kind {
                    "read" => {
                        let path = entry.path.and_then(|path| join_to(cwd, path));
                        read_share(path.as_deref(), Part::ShellRead, 1)
                    }
                    _ => share(Part::Search, 1),
                })
                .collect()
        }
        InnerItem::Mcp { server, tool, .. } => {
            vec![server_share(server, tool, server_part(server, tool))]
        }
        InnerItem::Extension { name, .. } => codex_function(name, "", None, 1),
        InnerItem::WebSearch { .. } => vec![share(Part::Web, 1)],
    }
}

pub(super) fn codex_event(ctx: &LineCtx, event_type: &str) -> Verdict {
    match event_type {
        "web_search_end" => count(Part::Web),
        // A `compacted` record's summary replaces the history.
        "compacted" => request_1(ctx).unwrap_or_else(|| count(Part::CompactionSummary)),
        _ => Verdict::Skip(SkipReason::NotMeasured),
    }
}

/// Part of a labelled Codex content block (`content_item_kinds`).
fn codex_label_part(ctx: &LineCtx, label: &str) -> Verdict {
    let family = label.split('.').next().unwrap_or(label);
    match family {
        _ if label == "user.heartbeat" => count(Part::Other),
        "user" => prompt(ctx, false),
        "tools" => count(Part::ToolDescriptionsLater),
        "host_skills" | "plugins" | "apps" => count(Part::ListsUpdated),
        "agents_md" => count(Part::InstructionsReloaded),
        "hooks" => count(Part::HookOutput),
        _ if label.contains("environment_context") || label.contains("client_time_context") => {
            count(Part::Environment)
        }
        _ => count(Part::Other),
    }
}

/// Text prefixes of injected blocks in rollouts without labels.
const CODEX_INJECTED_PREFIXES: [(&str, Part); 7] = [
    ("# AGENTS.md instructions", Part::InstructionsReloaded),
    ("<user_instructions>", Part::InstructionsReloaded),
    ("<environment_context>", Part::Environment),
    ("<skills_instructions>", Part::ListsUpdated),
    ("<plugins_instructions>", Part::ListsUpdated),
    ("<recommended_plugins>", Part::ListsUpdated),
    ("<heartbeat", Part::Other),
];

pub(super) fn codex_message(ctx: &LineCtx, role: &str, label: ContentLabel, text: &str) -> Verdict {
    if !matches!(role, "developer" | "user") {
        return Verdict::Skip(SkipReason::NotMeasured);
    }
    if let Some(verdict) = request_1(ctx) {
        return verdict;
    }
    if let ContentLabel::Present(Some(label)) = label {
        return codex_label_part(ctx, label);
    }
    let head = text.trim_start();
    if let Some((_, part)) = CODEX_INJECTED_PREFIXES
        .iter()
        .find(|(prefix, _)| head.starts_with(prefix))
    {
        return count(*part);
    }
    match role {
        "developer" => count(Part::Other),
        _ => prompt(ctx, false),
    }
}
