//! MCP-shaped lines for a fixed share of the generated corpus. Server and tool
//! names are made up; the record shapes follow real Claude and Codex
//! transcripts. The share is a function of the file's size bucket, so the
//! same seed gives the same bytes, and every file keeps its bucket size.
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
/// One Codex namespace carries most deferred tools; two carry one each.
const CODEX_TOOLS: [usize; 3] = [16, 1, 1];
const DEFERRED: &str = "tools.deferred_namespaces";
const PERMISSIONS: &str = "<permissions>synthetic</permissions>";
const AT: &str = "2026-08-02T07:59:00Z";

/// Claude, per hundred files: the 1MiB file is a Desktop session whose delta
/// names 2,000 tools from 60 servers; the nine 64KiB files are Desktop
/// sessions with 400 names from 20 servers; ten 4KiB files are headless
/// sessions with 55 connector names only. Codex: twenty files carry the
/// deferred namespaces block at start and five re-send it after response 1;
/// the 1MiB file lists 19 namespaces. Pi has no MCP lines.
pub(super) fn lines(source: SnapshotSource, id: &str, bucket: usize) -> Lines {
    match (source, bucket) {
        (SnapshotSource::ClaudeCode, 0) => claude_desktop(id, 60, 2_000, 2),
        (SnapshotSource::ClaudeCode, 1..=9) => claude_desktop(id, 20, 400, 1 + bucket % 2),
        (SnapshotSource::ClaudeCode, 10..=19) => claude_headless(id, bucket % 4 == 3),
        (SnapshotSource::Codex, 0) => codex(id, &[1; 19], true),
        (SnapshotSource::Codex, 1..=19) => codex(id, &CODEX_TOOLS, bucket <= 4),
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

fn schema(name: &str, defer: bool) -> Value {
    let mut tool = json!({"name":name, "description":text(name, 480), "input_schema":{
        "type":"object", "properties":{
            "query":{"type":"string", "description":text("query", 180)},
            "limit":{"type":"integer", "description":text("limit", 120)},
            "cursor":{"type":"string", "description":text("cursor", 120)}},
        "required":["query"], "additionalProperties":false}});
    if defer {
        tool["defer_loading"] = json!(true);
    }
    tool
}

fn delta(id: &str, n: usize, added: Vec<String>, removed: Vec<String>) -> Value {
    json!({"type":"attachment", "sessionId":id, "uuid":format!("attachment-{id}-{n}"),
        "timestamp":AT, "attachment":{"type":"deferred_tools_delta",
        "addedNames":added, "removedNames":removed}})
}

/// Request 1 records (delta, shape, system blob, request), then late deltas.
fn claude_desktop(id: &str, servers: usize, names: usize, late: usize) -> Lines {
    let mut deferred = Vec::new();
    for n in 0..BUILT_IN_DEFERRED {
        deferred.push(format!("LocalTool{n:02}"));
    }
    // In-full names are never repeated as deferred names.
    for s in 0..servers {
        let first = full_tools(s);
        let count = names / servers + usize::from(s < names % servers);
        for t in first..first + count {
            deferred.push(mcp_name(&server(s), &tool(t)));
        }
    }
    // Built-in tools first: two in full, two with `defer_loading`.
    let mut tools = Vec::new();
    for n in 0..4 {
        let name = format!("LocalTool{:02}", BUILT_IN_DEFERRED + n);
        tools.push(schema(&name, n >= 2));
    }
    for (s, count) in FULL {
        for t in 0..count {
            tools.push(schema(&mcp_name(&server(s), &tool(t)), false));
        }
    }
    let shape = json!({"type":"api-request-shape", "sessionId":id, "timestamp":AT,
        "shapeHash":format!("shape-{id}"), "shape":{
        "system":[{"type":"text", "text":"You are a synthetic assistant."}], "tools":tools}});
    let blob = json!({"type":"api-request-blob", "sessionId":id, "timestamp":AT,
        "hash":format!("blob-{id}"), "message":{"role":"system", "content":[
        {"type":"text", "text":"Synthetic system text."}]}});
    let request = json!({"type":"api-request", "sessionId":id, "timestamp":AT,
        "shapeHash":format!("shape-{id}"), "tail":[format!("blob-{id}")]});
    // Each late delta adds a new server; the first also re-announces a known
    // name and removes one of an id-named server's tools.
    let mut after = Vec::new();
    for n in 0..late {
        let new = server(servers + n);
        let mut added = Vec::new();
        for t in 0..10 {
            added.push(mcp_name(&new, &tool(t)));
        }
        let mut removed = Vec::new();
        if n == 0 {
            added.push(deferred[BUILT_IN_DEFERRED].clone());
            removed.push(mcp_name(&server(18), &tool(0)));
        }
        after.push(delta(id, n + 1, added, removed));
    }
    let before = vec![delta(id, 0, deferred, Vec::new()), shape, blob, request];
    (before, after)
}

fn connector_names(n: usize, count: usize) -> Vec<String> {
    let server = format!("claude_ai_{}", CONNECTORS[n]);
    (0..count).map(|t| mcp_name(&server, &tool(t))).collect()
}

/// Four connector servers and 55 names, deferred only; a late delta may add
/// a fifth connector.
fn claude_headless(id: &str, late: bool) -> Lines {
    let mut deferred = Vec::new();
    for s in 0..4 {
        deferred.extend(connector_names(s, 14 - usize::from(s == 3)));
    }
    let mut after = Vec::new();
    if late {
        after.push(delta(id, 1, connector_names(4, 6), Vec::new()));
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

/// `- mcp__<namespace>__<tool>: <description>` lines, where a tool part may
/// itself contain `__`.
fn codex(id: &str, namespaces: &[usize], resend: bool) -> Lines {
    let mut body = String::from("<tools>\nDeferred tools available:\n");
    for (n, tools) in namespaces.iter().enumerate() {
        for t in 0..*tools {
            let mut name = tool(t);
            if t % 8 == 7 {
                name.push_str("__v2");
            }
            let name = mcp_name(&server(n), &name);
            body.push_str(&format!("- {name}: {}\n", line_text(t)));
        }
    }
    body.push_str("</tools>");
    let items = vec![
        ("permissions.instructions", PERMISSIONS.to_owned()),
        (DEFERRED, body),
    ];
    let start = codex_message(id, 1, items);
    // A re-send lists a known namespace alone and one new namespace.
    let mut after = Vec::new();
    if resend {
        let known = server(0);
        let new = mcp_name(&server(namespaces.len()), &tool(0));
        let body = format!(
            "<tools>\nDeferred tools now available:\n- mcp__{known}\n- {new}: {}\n</tools>",
            line_text(0)
        );
        after.push(codex_message(id, 2, vec![(DEFERRED, body)]));
    }
    (vec![start], after)
}
