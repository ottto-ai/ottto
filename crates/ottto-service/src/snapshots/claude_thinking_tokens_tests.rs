//! Claude Code thinking tokens reach `reasoning_output_tokens`.
//!
//! Claude Code writes the count as `usage.output_tokens_details.thinking_tokens`,
//! a part of `output_tokens`. Fixtures are synthetic usage blocks only.
use super::*;
use serde_json::json;

fn assistant(usage: Value) -> Value {
    json!({
        "type": "assistant",
        "requestId": "req_thinking",
        "message": {"id": "msg_thinking", "model": "claude-opus-4-8", "usage": usage}
    })
}

#[test]
fn thinking_tokens_fill_reasoning_output_tokens() {
    let usage = claude_code_delta_usage(&assistant(json!({
        "input_tokens": 12,
        "output_tokens": 900,
        "cache_read_input_tokens": 4000,
        "output_tokens_details": {"thinking_tokens": 300}
    })))
    .expect("usage");
    assert_eq!(usage.output_tokens, 900);
    assert_eq!(usage.reasoning_output_tokens, 300);
}

#[test]
fn usage_without_thinking_tokens_keeps_zero_reasoning() {
    let usage = claude_code_delta_usage(&assistant(json!({
        "input_tokens": 12,
        "output_tokens": 900,
        "cache_read_input_tokens": 4000
    })))
    .expect("usage");
    assert_eq!(usage.output_tokens, 900);
    assert_eq!(usage.reasoning_output_tokens, 0);
}

#[test]
fn thinking_tokens_never_exceed_output_tokens() {
    let usage = claude_code_delta_usage(&assistant(json!({
        "input_tokens": 12,
        "output_tokens": 40,
        "output_tokens_details": {"thinking_tokens": 300}
    })))
    .expect("usage");
    assert_eq!(usage.reasoning_output_tokens, 40);
}

#[test]
fn explicit_reasoning_output_tokens_wins_over_thinking_tokens() {
    let usage = claude_code_delta_usage(&assistant(json!({
        "input_tokens": 12,
        "output_tokens": 900,
        "reasoning_output_tokens": 200,
        "output_tokens_details": {"thinking_tokens": 300}
    })))
    .expect("usage");
    assert_eq!(usage.reasoning_output_tokens, 200);
}

#[test]
fn unreported_sidecar_reasoning_matches_transcript_thinking() {
    // Claude Code's api_request event has no thinking count (sidecar 0).
    assert!(claude_api_reasoning_matches(0u64, 300u64));
    assert!(claude_api_reasoning_matches(0u64, 0u64));
    assert!(claude_api_reasoning_matches(300u64, 300u64));
    assert!(!claude_api_reasoning_matches(200u64, 300u64));
    assert!(!claude_api_reasoning_matches(300u64, 0u64));
}

fn sidecar_row(output_tokens: u64) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    crate::claude_local_otel::ClaudeLocalOtelEvidence {
        input_tokens: 12,
        output_tokens,
        request_count: 1,
        ..Default::default()
    }
}

fn parsed_session() -> SnapshotItem {
    let path = std::env::temp_dir().join(format!(
        "ottto-claude-thinking-{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    let lines = [
        json!({"timestamp":"2026-10-01T10:00:00Z","type":"assistant","sessionId":"claude-thinking","requestId":"req-1","message":{"id":"msg-1","model":"claude-opus-4-8","usage":{"input_tokens":12,"output_tokens":900,"output_tokens_details":{"thinking_tokens":300}}}}),
        json!({"timestamp":"2026-10-01T10:01:00Z","type":"assistant","sessionId":"claude-thinking","requestId":"req-2","message":{"id":"msg-2","model":"claude-opus-4-8","usage":{"input_tokens":12,"output_tokens":100}}}),
    ];
    fs::write(
        &path,
        lines
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("write transcript");
    let item = parse_claude_code_jsonl_file(&path, "2026-10-01T10:02:00Z", "fp".to_string())
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
    let _ = fs::remove_file(&path);
    item
}

#[test]
fn aggregate_account_coverage_accepts_transcript_thinking_with_unreported_sidecar() {
    let item = parsed_session();
    assert_eq!(item.output_tokens, 1000);
    assert_eq!(item.reasoning_output_tokens, 300);
    let rows = [sidecar_row(900), sidecar_row(100)];
    let evidence: Vec<_> = rows.iter().collect();
    assert!(claude_account_evidence_covers_snapshot(&item, &evidence));

    let mut reported = rows.clone();
    reported[0].reasoning_output_tokens = 200;
    let evidence: Vec<_> = reported.iter().collect();
    assert!(!claude_account_evidence_covers_snapshot(&item, &evidence));
}
