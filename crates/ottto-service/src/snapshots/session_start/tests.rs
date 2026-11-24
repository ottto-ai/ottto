//! Tests for session-start facts: what a fresh session sent first and what it
//! read in its opening window.

use super::*;
use crate::codex_prelude_footprint;
use crate::composition_kinds::shell::is_plain_path;
use crate::session_attribution::{
    SessionAttributionContext, SESSION_ATTRIBUTION_HMAC_KEY_VERSION,
};
use crate::snapshots::{
    parse_claude_code_jsonl_file_with_title_metadata_and_attribution, parse_codex_jsonl_file,
    ClaudeTitleMetadata, SnapshotItem, SnapshotSource,
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
    // Request-1 parts reconcile with the first request's usage.
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
        .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT), None)
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
                "usage": {"input_tokens": 150, "cache_read_input_tokens": 0, "output_tokens": 1,
                    "iterations": [{"input_tokens": 100, "cache_read_input_tokens": 200}]},
                "content": [{"type": "text", "text": "ok"}]}}),
        ],
    );
    let items = parse_claude(&path, None);
    // The item's first turn is the iteration's context (300); billing takes
    // each kind's larger figure (150 + 200), so the parts don't reconcile.
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
            json!({"type":"event_msg","payload":{"type":"task_complete","turn_id":"turn-1"}}),
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
        .finish(true, None, CODEX_PARTS_METHOD, None, Some(&SALT), None)
        .expect("measured");
    assert_eq!(fresh.opening_request_count, Some(1));
    assert_eq!(
        measured_codex_state("", 1).finish(
            false,
            None,
            CODEX_PARTS_METHOD,
            None,
            Some(&SALT),
            None
        ),
        only_version
    );
    let mut copied = measured_codex_state("", 1);
    copied.note_inherited_prefix();
    assert_eq!(
        copied.finish(true, None, CODEX_PARTS_METHOD, None, Some(&SALT), None),
        only_version
    );
    assert_eq!(fresh.inherited(), only_version);
    // Nothing measured: the field is omitted.
    assert_eq!(
        SessionStartState::default().finish(
            true,
            None,
            CODEX_PARTS_METHOD,
            None,
            Some(&SALT),
            None
        ),
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
/// not admit (no cumulative usage); the breakdown then describes another request.
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
        .finish(true, None, CODEX_PARTS_METHOD, None, Some(&SALT), None)
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
        .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT), None)
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
        .finish(
            true,
            None,
            CLAUDE_PARTS_METHOD,
            Some(&context),
            Some(&SALT),
            None,
        )
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
        .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT), None)
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
        .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT), None)
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
        .finish(true, None, CODEX_PARTS_METHOD, None, Some(&SALT), None)
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
        .finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT), None)
        .expect("client version");
    assert_eq!(start.client_version.as_deref(), Some("2.1.300"));
    assert_eq!(start.opening_request_count, None);
    assert_eq!(start.first_request_uncached_input_tokens, None);
    // Every usage root the parser accepts is checked.
    assert!(claude_multi_request(&json!({"payload": {"usage": {
        "iterations": [{"input_tokens": 1}, {"input_tokens": 2}]}}})));
}

/// [behaviour] Sizes at counted positions ride only on a start that is
/// sent without them: a collapsed opening with nothing else measured gets
/// no block, and clearing them leaves the start as it was.
#[test]
fn counted_sizes_never_create_a_start_block() {
    let sizes = Some([Some(10_000), Some(20_000), None]);
    let collapsed = |version: Option<&str>| {
        let mut line = json!({"type": "assistant", "message": {"id": "m1", "usage": {
            "input_tokens": 3, "iterations": [{"input_tokens": 5}, {"input_tokens": 3}]}}});
        if let Some(version) = version {
            line["version"] = json!(version);
        }
        let mut state = SessionStartState::default();
        state.observe_claude_line(&line, 1, None);
        let usage = UsageTotals {
            input_tokens: 3,
            ..UsageTotals::default()
        };
        state.note_claude_response(0, &usage, 3, 0);
        state.finish(true, None, CLAUDE_PARTS_METHOD, None, Some(&SALT), sizes)
    };
    assert_eq!(collapsed(None), None);
    let start = collapsed(Some("2.1.300")).expect("client version");
    assert_eq!(
        [
            start.counted_request_10_context_tokens,
            start.counted_request_20_context_tokens,
            start.counted_request_50_context_tokens,
        ],
        [Some(10_000), Some(20_000), None]
    );
    let mut cleared = start;
    crate::snapshots::compaction_events::clear_counted_start_sizes(&mut cleared);
    assert_eq!(
        cleared,
        SnapshotSessionStart {
            client_version: Some("2.1.300".to_string()),
            ..SnapshotSessionStart::default()
        }
    );
}

/// Cost receipt over local transcripts listed in
/// `OTTTO_SESSION_START_COST_FILES` (`claude|codex<TAB>path` per line).
/// A shadow state replays each file beside the real parser (its own state
/// pre-frozen) so the timer covers only session-start work. Prints
/// aggregates only; no transcript text leaves the test.
#[test]
#[ignore = "local cost receipt over real transcripts"]
fn session_start_cost_receipt() {
    use crate::snapshots::{
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
        // Upper bound on the wire: the breakdown is kept whenever request 1 reconciles.
        let first_turn = shadow.requests[0].map(|request| request.context_tokens);
        let finished = shadow.finish(true, first_turn, method, None, Some(&SALT), None);
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

/// An opening call's `L` span is its id alone, apart
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
    let body = Enc::count_write(1 << 20, |e| state.put(e)).unwrap();
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
/// config digest cleared), a decoded record has none, and the Claude
/// opening-settings fact brings it back with the opening content.
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
    let body = |state: &SessionStartState| Enc::count_write(1 << 20, |e| state.put(e)).unwrap();
    let build: [(&str, &dyn Fn() -> SessionStartState); 2] =
        [("claude", &claude), ("codex", &codex)];
    for (name, build) in build {
        let state = build();
        let digest = state
            .config_digest
            .unwrap_or_else(|| panic!("{name}: instruction text folds a config digest"));
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
        if name == "codex" {
            // The prelude is its own session fact: it round-trips in full.
            assert!(state.has_codex_prelude(), "{name}");
            assert!(decoded.codex_prelude.is_none(), "{name}: the body drops it");
            let prelude =
                Enc::count_write(1 << 20, |e| state.put_codex_prelude_fact(e)).unwrap();
            let mut d = Dec::new(&prelude);
            decoded.take_codex_prelude_fact(&mut d).unwrap();
            d.finish().unwrap();
            let again =
                Enc::count_write(1 << 20, |e| decoded.put_codex_prelude_fact(e)).unwrap();
            assert_eq!(again, prelude, "{name}");
        }
        assert!(state.has_opening_fact(), "{name}");
        let fact = Enc::count_write(1 << 20, |e| state.put_opening_fact(e)).unwrap();
        let mut d = Dec::new(&fact);
        decoded.take_opening_fact(&mut d).unwrap();
        d.finish().unwrap();
        assert_eq!(
            decoded.config_digest.map(ConfigDigest::to_bytes),
            Some(digest.to_bytes()),
            "{name}"
        );
        let again = Enc::count_write(1 << 20, |e| decoded.put_opening_fact(e)).unwrap();
        assert_eq!(again, fact, "{name}");
        assert_eq!(body(&decoded), encoded, "{name}");
    }
}
