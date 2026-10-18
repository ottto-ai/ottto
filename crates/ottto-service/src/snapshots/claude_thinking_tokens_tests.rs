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
    assert!(claude_api_reasoning_matches(0, 300));
    assert!(claude_api_reasoning_matches(0, 0));
    assert!(claude_api_reasoning_matches(300, 300));
    assert!(!claude_api_reasoning_matches(200, 300));
    assert!(!claude_api_reasoning_matches(300, 0));
}
