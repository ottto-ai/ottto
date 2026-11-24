//! MCP-shaped lines for a fixed share of the generated corpus. Server and tool
//! names are made up; the record shapes follow real Claude and Codex
//! transcripts. The share is a function of the file's index and size bucket,
//! so the same seed gives the same bytes, and every file keeps its bucket size.
use super::*;

/// Lines before response 1, and lines after it.
pub(super) type Lines = (Vec<Value>, Vec<Value>);

const WORDS: [&str; 16] = [
    "amber", "birch", "cedar", "delta", "ember", "fjord", "garnet", "harbor", "indigo", "juniper",
    "kestrel", "lumen", "meadow", "nimbus", "orchid", "pebble",
];
const SUFFIXES: [&str; 4] = ["tools", "docs", "sync", "hub"];
const VERBS: [&str; 10] = [
    "search", "get", "list", "create", "update", "delete", "fetch", "send", "read", "write",
];
const NOUNS: [&str; 12] = [
    "items", "records", "threads", "notes", "events", "files", "pages", "tasks", "users", "labels",
    "comments", "reports",
];
const CONNECTORS: [&str; 5] = [
    "Amber_Mail",
    "Birch_Calendar",
    "Cedar_Drive",
    "Delta_Chat",
    "Ember_Notes",
];
/// Request 1 of a Desktop session sends 32 MCP tools in full from 7 servers,
/// as (server, tools). Server 17 has an opaque id for a name.
const FULL: [(usize, usize); 7] = [(0, 5), (1, 5), (2, 5), (3, 5), (4, 5), (5, 4), (17, 3)];
/// Deferred names of built-in tools ride the same attachment.
const BUILT_IN_DEFERRED: usize = 22;
/// Codex lists app namespaces under one hub, plus name-only namespaces.
const HUB: &str = "amber_apps";
const NAME_ONLY: [&str; 2] = ["fjord_solo", "zeta"];
const DEFERRED: &str = "tools.deferred_namespaces";
const PERMISSIONS: &str = "<permissions>synthetic</permissions>";
const AT: &str = "2026-08-02T07:59:00Z";
const SYSTEM_HEAD: &str = "You are a synthetic agent.\n\n# Environment\nSynthetic line.\n\n";
const PREAMBLE: &str = concat!(
    "# MCP Server Instructions\n\n",
    "The following MCP servers have provided instructions for how to use their tools ",
    "and resources:\n\n"
);
const SKILLS: &str = concat!(
    "The following skills are available for use with the Skill tool:\n\n",
    "- synthetic-skill: example\n"
);

/// Claude, per hundred files: the 1MiB file is a Desktop session with 739
/// MCP names from 31 servers; the nine 64KiB files are Desktop sessions with
/// 635 names from 26 servers; six of these ten get some names after the first
/// response. Ten 4KiB files are headless sessions with 58 connector names
/// from 5 servers. Codex: twenty per hundred carry 19 deferred namespaces at
/// start; 16 per thousand re-send the block after the first response, 11 of
/// them with a new namespace. Pi has no MCP lines.
pub(super) fn lines(source: SnapshotSource, n: usize, bucket: usize) -> Lines {
    let id = session(n);
    let late = if bucket % 5 < 3 { 1 + bucket % 2 } else { 0 };
    match (source, bucket) {
        (SnapshotSource::ClaudeCode, 0) => claude_desktop(&id, 31, 739, 1, 480),
        (SnapshotSource::ClaudeCode, 1..=9) => claude_desktop(&id, 26, 635, late, 300),
        (SnapshotSource::ClaudeCode, 10..=19) => claude_headless(&id, bucket % 4 == 3),
        (SnapshotSource::Codex, 0..=19) => {
            // Each thousand files has 200 with the block, ranked 0 to 199.
            let rank = n / 100 % 10 * 20 + bucket;
            codex(&id, rank < 16, rank < 11)
        }
        _ => Default::default(),
    }
}

/// Servers 17 to 19 of every twenty have an opaque id for a name.
fn server(n: usize) -> String {
    if n % 20 >= 17 {
        format!("{n:08x}-0000-4000-8000-{n:012x}")
    } else {
        format!("{}_{}", WORDS[n % 16], SUFFIXES[n / 16 % 4])
    }
}

/// The instructions heading of a server: it folds (lowercase, runs of other
/// characters to `_`) to the same key as the server's name segment.
fn display(n: usize) -> String {
    let mut name = server(n).replace('_', " ");
    if let Some(first) = name.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    name
}

fn tool(n: usize) -> String {
    format!("{}_{}", VERBS[n % 10], NOUNS[n / 10 % 12])
}

fn mcp_name(server: &str, tool: &str) -> String {
    format!("mcp__{server}__{tool}")
}

fn full_tools(server: usize) -> usize {
    let mut tools = 0;
    for (s, count) in FULL {
        if s == server {
            tools = count;
        }
    }
    tools
}

/// Plain words only, so no path or link reaches the artifact scan.
fn text(subject: &str, len: usize) -> String {
    let mut text = format!("{subject}: ");
    while text.len() < len {
        text.push_str("synthetic tool text for resource tests. ");
    }
    text.truncate(len);
    text
}

fn line_text(n: usize) -> String {
    text(&format!("{} {}", VERBS[n % 10], NOUNS[n / 10 % 12]), 60)
}

/// One `shape.tools` entry; `size` is its description length.
fn schema(name: &str, defer: bool, size: usize) -> Value {
    let mut tool = json!({"name":name, "description":text(name, size), "input_schema":{
        "type":"object", "properties":{
            "query":{"type":"string", "description":text("query", size / 3)},
            "limit":{"type":"integer", "description":text("limit", size / 4)},
            "cursor":{"type":"string", "description":text("cursor", size / 4)}},
        "required":["query"], "additionalProperties":false}});
    if defer {
        tool["defer_loading"] = json!(true);
    }
    tool
}

fn delta(id: &str, n: usize, added: Vec<String>, removed: Vec<String>) -> Value {
    json!({"type":"attachment", "sessionId":id, "uuid":format!("attachment-{id}-{n}"),
        "timestamp":AT, "attachment":{"type":"deferred_tools_delta",
        "addedNames":added, "removedNames":removed}, "renderedRole":"system"})
}

fn block(n: usize) -> String {
    format!("## {}\n{}", display(n), text("Use this server", 72))
}

/// An `mcp_instructions_delta` with the reminder text it renders.
fn instructions(id: &str, n: usize, servers: &[usize]) -> Value {
    let names: Vec<String> = servers.iter().map(|s| display(*s)).collect();
    let blocks: Vec<String> = servers.iter().map(|s| block(*s)).collect();
    let body = blocks.join("\n\n");
    let rendered = format!("<system-reminder>\n{PREAMBLE}{body}\n</system-reminder>");
    json!({"type":"attachment", "sessionId":id, "uuid":format!("instructions-{id}-{n}"),
        "timestamp":AT, "attachment":{"type":"mcp_instructions_delta", "addedNames":names,
        "addedBlocks":blocks, "removedNames":[]}, "renderedRole":"system",
        "rendered":[{"content":rendered}]})
}

/// Request 1 records (tool delta, instructions delta, shape, system blob,
/// request), then late deltas. `names` distinct MCP names over `servers`
/// servers, in full and deferred together; with `late` deltas, the last two
/// servers arrive after response 1.
fn claude_desktop(id: &str, servers: usize, names: usize, late: usize, size: usize) -> Lines {
    let per_server = |s: usize| names / servers + usize::from(s < names % servers);
    let held = if late > 0 { 2 } else { 0 };
    let mut deferred = Vec::new();
    for n in 0..BUILT_IN_DEFERRED {
        deferred.push(format!("LocalTool{n:02}"));
    }
    // In-full names are never repeated as deferred names.
    for s in 0..servers - held {
        for t in full_tools(s)..per_server(s) {
            deferred.push(mcp_name(&server(s), &tool(t)));
        }
    }
    // Built-in tools first: two in full, two with `defer_loading`.
    let mut tools = Vec::new();
    for n in 0..4 {
        let name = format!("LocalTool{:02}", BUILT_IN_DEFERRED + n);
        tools.push(schema(&name, n >= 2, size));
    }
    for (s, count) in FULL {
        for t in 0..count {
            tools.push(schema(&mcp_name(&server(s), &tool(t)), false, size));
        }
    }
    // Some servers send instructions at start; the last two never do.
    let mut instructed = Vec::new();
    for s in 0..servers - 2 {
        if s % 3 == 0 || s == 17 {
            instructed.push(s);
        }
    }
    let shown: Vec<String> = instructed.iter().map(|s| block(*s)).collect();
    let shown = shown.join("\n\n");
    let system = format!("{SYSTEM_HEAD}{PREAMBLE}{shown}\n\n{SKILLS}");
    let shape = json!({"type":"api-request-shape", "sessionId":id, "timestamp":AT,
        "shapeHash":format!("shape-{id}"), "shape":{
        "system":[{"type":"text", "text":"You are a synthetic assistant."}], "tools":tools}});
    let blob = json!({"type":"api-request-blob", "sessionId":id, "timestamp":AT,
        "hash":format!("blob-{id}"), "message":{"role":"system", "content":[
        {"type":"text", "text":system}]}});
    let request = json!({"type":"api-request", "sessionId":id, "timestamp":AT,
        "shapeHash":format!("shape-{id}"), "tail":[format!("blob-{id}")]});
    // One late delta carries both held servers, or two carry one each. The
    // first also re-announces a known name and removes an id-named one.
    let mut after = Vec::new();
    for n in 0..late {
        let first = servers - 2 + n;
        let end = if late == 1 { servers } else { first + 1 };
        let mut added = Vec::new();
        for s in first..end {
            for t in 0..per_server(s) {
                added.push(mcp_name(&server(s), &tool(t)));
            }
        }
        let mut removed = Vec::new();
        if n == 0 {
            added.push(deferred[BUILT_IN_DEFERRED].clone());
            removed.push(mcp_name(&server(18), &tool(0)));
        }
        after.push(delta(id, n + 1, added, removed));
    }
    // The late instructions re-send repeats one server and adds another.
    after.push(instructions(id, 1, &[0, servers - 1]));
    let opening = delta(id, 0, deferred, Vec::new());
    let notes = instructions(id, 0, &instructed);
    (vec![opening, notes, shape, blob, request], after)
}

/// 58 names over 5 connectors: 12, 12, 12, 11, 11.
fn connector_names(n: usize) -> Vec<String> {
    let server = format!("claude_ai_{}", CONNECTORS[n]);
    let count = 11 + usize::from(n < 3);
    (0..count).map(|t| mcp_name(&server, &tool(t))).collect()
}

/// Deltas only; with `late`, the fifth connector arrives after response 1.
fn claude_headless(id: &str, late: bool) -> Lines {
    let mut deferred = Vec::new();
    for s in 0..5 - usize::from(late) {
        deferred.extend(connector_names(s));
    }
    let mut after = Vec::new();
    if late {
        after.push(delta(id, 1, connector_names(4), Vec::new()));
    }
    (vec![delta(id, 0, deferred, Vec::new())], after)
}

/// Codex's labeled developer message, one label per content item.
fn codex_message(id: &str, turn: u64, items: Vec<(&str, String)>) -> Value {
    let mut kinds = Vec::new();
    let mut content = Vec::new();
    let mut metadata = Vec::new();
    for (kind, text) in items {
        let provenance = if kind == DEFERRED {
            json!({"type":"tool", "namespace":"tool_search"})
        } else {
            json!({"type":"harness", "hook":false})
        };
        kinds.push(kind);
        content.push(json!({"type":"input_text", "text":text}));
        metadata.push(json!({"provenance":provenance}));
    }
    json!({"timestamp":AT, "type":"response_item", "payload":{"type":"message",
        "id":format!("msg-{id}-{turn}"), "role":"developer", "content":content,
        "internal_chat_message_metadata_passthrough":{"turn_id":format!("turn-{id}"),
        "content_item_kinds":kinds, "content_item_metadata":metadata}}})
}

/// One namespace per line: `- <token>: <description>`, the token ending at
/// the first `:`. One app namespace has a third `__` part.
fn app_line(n: usize) -> String {
    let mut token = mcp_name(HUB, &tool(n));
    if n == 16 {
        token.push_str("__v2");
    }
    format!("- {token}: {}\n", line_text(n))
}

/// 19 namespaces at start: 17 apps under one hub and 2 name-only lines. A
/// re-send re-lists a start namespace and may add a new app namespace.
fn codex(id: &str, resend: bool, add: bool) -> Lines {
    let mut body = String::from("<tools>\nDeferred namespaces available:\n");
    for n in 0..17 {
        body.push_str(&app_line(n));
    }
    for name in NAME_ONLY {
        body.push_str(&format!("- mcp__{name}\n"));
    }
    body.push_str("</tools>");
    let items = vec![
        ("permissions.instructions", PERMISSIONS.to_owned()),
        (DEFERRED, body),
    ];
    let start = codex_message(id, 1, items);
    let mut after = Vec::new();
    if resend {
        let mut body = String::from("<tools>\nDeferred namespaces now available:\n");
        body.push_str(&format!("- mcp__{}\n", NAME_ONLY[0]));
        if add {
            body.push_str(&app_line(17));
        }
        body.push_str("</tools>");
        after.push(codex_message(id, 2, vec![(DEFERRED, body)]));
    }
    (vec![start], after)
}
