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
    let unique = crate::test_scratch::unique_name("ottto-claude-thinking");
    let path = std::env::temp_dir().join(format!("{unique}.jsonl"));
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

fn sidecar_request(
    request_id: &str,
    output_tokens: u64,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    crate::claude_local_otel::ClaudeLocalOtelEvidence {
        session_id: "claude-thinking".to_string(),
        request_id: request_id.to_string(),
        observed_at: "2026-10-01T10:00:00Z".to_string(),
        model: "claude-opus-4-8".to_string(),
        cost_usd_micros: Some(100),
        ..sidecar_row(output_tokens)
    }
}

#[test]
fn per_request_match_accepts_transcript_thinking_with_unreported_sidecar() {
    let item = parsed_session();
    let occurrence =
        ClaudeTranscriptUsageOccurrenceWitness::from(&item.claude_usage_occurrences["req-1"]);
    assert_eq!(occurrence.reasoning_output_tokens, 300);
    let mut row = sidecar_request("req-1", 900);
    assert!(claude_api_matches_transcript_occurrence(&row, &occurrence));

    row.reasoning_output_tokens = 300;
    assert!(claude_api_matches_transcript_occurrence(&row, &occurrence));
    row.reasoning_output_tokens = 200;
    assert!(!claude_api_matches_transcript_occurrence(&row, &occurrence));
}

#[test]
fn reported_usage_rows_keep_transcript_thinking_with_unreported_sidecar() {
    let item = parsed_session();
    let rows = [sidecar_request("req-1", 900), sidecar_request("req-2", 100)];
    let prepared = prepare_claude_reported_usage(&item, &rows, &BTreeSet::new(), None)
        .expect("sidecar 0 is not a thinking count");
    assert_eq!(prepared.totals.output_tokens, 1000);
    assert_eq!(prepared.totals.reasoning_output_tokens, 300);
    assert_eq!(
        prepared
            .model_usage
            .iter()
            .map(|row| row.reasoning_output_tokens)
            .sum::<u64>(),
        300
    );

    let mut reported = rows.clone();
    reported[0].reasoning_output_tokens = 200;
    assert!(prepare_claude_reported_usage(&item, &reported, &BTreeSet::new(), None).is_none());
}

#[test]
fn progressive_rows_of_one_response_keep_the_final_clamped_thinking() {
    // One response written as three rows under one message id. Thinking is
    // ahead of output in the first row (clamped to 50), then rises.
    let path = std::env::temp_dir().join(format!(
        "ottto-claude-thinking-progressive-{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    let row = |second: u64, output: u64, thinking: u64| json!({"timestamp":format!("2026-10-01T10:00:0{second}Z"),"type":"assistant","sessionId":"claude-thinking","requestId":"req-1","message":{"id":"msg-1","model":"claude-opus-4-8","usage":{"input_tokens":12,"output_tokens":output,"output_tokens_details":{"thinking_tokens":thinking}}}});
    let lines = [row(0, 50, 300), row(1, 400, 300), row(2, 900, 300)];
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
    assert_eq!(item.request_count, 1);
    assert_eq!(item.output_tokens, 900);
    assert_eq!(item.reasoning_output_tokens, 300);
    assert_eq!(
        item.claude_usage_occurrences["req-1"]
            .usage
            .reasoning_output_tokens,
        300
    );
}

const FAMILY_ROOT: &str = "4338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const FAMILY_AGENT: &str = "b4d1585d310070d0f";

fn write_family(dir: &Path, root_thinking: Option<u64>) -> (PathBuf, PathBuf) {
    let root_path = dir.join(format!("{FAMILY_ROOT}.jsonl"));
    let root_lines = (1..=2)
        .map(|request| {
            let mut usage = json!({"input_tokens": 10, "output_tokens": 10});
            if let Some(thinking) = root_thinking {
                usage["output_tokens_details"] = json!({"thinking_tokens": thinking});
            }
            json!({"timestamp":format!("2026-08-02T07:00:0{request}Z"),"type":"assistant","sessionId":FAMILY_ROOT,"requestId":format!("req_{request}"),"message":{"model":"claude-haiku-4-5","usage":usage}})
                .to_string()
        })
        .collect::<Vec<_>>();
    fs::write(&root_path, root_lines.join("\n") + "\n").expect("write root");
    let child_dir = dir.join(FAMILY_ROOT).join("subagents");
    fs::create_dir_all(&child_dir).expect("create child dir");
    let child_path = child_dir.join(format!("agent-{FAMILY_AGENT}.jsonl"));
    let child_line = json!({"timestamp":"2026-08-02T07:00:03Z","type":"assistant","sessionId":FAMILY_ROOT,"agentId":FAMILY_AGENT,"isSidechain":true,"requestId":"req_3","message":{"model":"claude-haiku-4-5","usage":{"input_tokens":10,"output_tokens":1}}});
    fs::write(&child_path, child_line.to_string() + "\n").expect("write child");
    (root_path, child_path)
}

fn parse_member(path: &Path, fingerprint: &str) -> SnapshotItem {
    parse_claude_code_jsonl_file(path, "2026-08-02T07:01:00Z", fingerprint.to_string())
        .expect("parse member")
        .remove(0)
}

/// A family proven before the thinking reader hashed reasoning 0 into its
/// witness. After the upgrade a member re-parses with thinking and the same
/// request set. The sidecar still reports 0, so the next complete, healthy
/// census re-proves the family and uploads it; it never ends terminal.
#[test]
fn family_proven_before_thinking_reader_reproves_after_upgrade() {
    // Legacy reported-usage rebuild and selectors; E2 attaches telemetry to native grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use super::tests::{complete_api_row, complete_trace_row, manifest_index_entry};
    let dir = std::env::temp_dir().join(format!(
        "ottto-claude-thinking-family-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    fs::create_dir_all(&dir).expect("create family dir");
    let api_report = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
        evidence: BTreeMap::from([(
            FAMILY_ROOT.to_string(),
            vec![
                complete_api_row(FAMILY_ROOT, "req_1", 1, 10, 10, 0),
                complete_api_row(FAMILY_ROOT, "req_2", 2, 10, 10, 0),
                complete_api_row(FAMILY_ROOT, "req_3", 3, 10, 1, 0),
            ],
        )]),
        health: Default::default(),
    };
    let trace_report = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
        evidence: BTreeMap::from([(
            FAMILY_ROOT.to_string(),
            vec![
                complete_trace_row(FAMILY_ROOT, "req_1", ""),
                complete_trace_row(FAMILY_ROOT, "req_2", ""),
                complete_trace_row(FAMILY_ROOT, "req_3", FAMILY_AGENT),
            ],
        )]),
        ..Default::default()
    };
    let exclusive = Some("session_exclusive_reported_usage:v1");
    let never_terminal = |index: &ScanIndex| {
        assert!(index
            .claude_usage_authority_quarantine
            .get(FAMILY_ROOT)
            .map_or(true, |record| record.disposition
                != ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal));
    };

    // Before the upgrade: the old reader saw no thinking count.
    let (root_path, child_path) = write_family(&dir, None);
    let mut index = ScanIndex::default();
    index
        .files
        .insert(local_index_key(&root_path), manifest_index_entry(None));
    index
        .files
        .insert(local_index_key(&child_path), manifest_index_entry(None));
    let mut items = vec![
        parse_member(&root_path, "root-fp-1"),
        parse_member(&child_path, "child-fp-1"),
    ];
    apply_claude_reported_usage_with_index(
        &mut items,
        &api_report,
        &trace_report,
        &mut index,
        true,
        "2026-08-02T07:10:00Z",
    );
    assert!(items
        .iter()
        .all(|item| item.usage_accounting_contract.as_deref() == exclusive));
    let proven_before = index
        .claude_usage_family_witnesses
        .get(FAMILY_ROOT)
        .cloned()
        .expect("family proven with reasoning 0");

    // After the upgrade: the root re-parses with thinking, same requests.
    let (root_path, child_path) = write_family(&dir, Some(4));
    let mut reparsed = vec![parse_member(&root_path, "root-fp-2")];
    assert_eq!(reparsed[0].reasoning_output_tokens, 8);
    assert_eq!(
        reparsed[0].claude_usage_request_ids,
        items[0].claude_usage_request_ids
    );
    // The witness hashed reasoning 0, so this member alone cannot be
    // reconstructed: it is held for one bounded retry, not lost.
    let held = apply_claude_reported_usage_with_index(
        &mut reparsed,
        &api_report,
        &trace_report,
        &mut index,
        true,
        "2026-08-02T07:11:00Z",
    );
    never_terminal(&index);
    assert_eq!(reparsed[0].usage_accounting_contract, None);
    assert_eq!(held.quarantined_entity_count(), 1);
    let record = &index.claude_usage_authority_quarantine[FAMILY_ROOT];
    assert_eq!(
        record.disposition,
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending
    );
    assert_eq!(record.failed_reconstruction_count, 1);
    assert_eq!(
        index.claude_usage_family_witnesses.get(FAMILY_ROOT),
        Some(&proven_before)
    );

    // The next complete, healthy census re-parses the family.
    let mut census = vec![
        parse_member(&root_path, "root-fp-2"),
        parse_member(&child_path, "child-fp-1"),
    ];
    let disposition = apply_claude_reported_usage_with_index(
        &mut census,
        &api_report,
        &trace_report,
        &mut index,
        true,
        "2026-08-02T07:12:00Z",
    );
    never_terminal(&index);
    assert_eq!(disposition.quarantined_entity_count(), 0);
    assert!(census
        .iter()
        .all(|item| item.usage_accounting_contract.as_deref() == exclusive));
    assert_eq!(census[0].reasoning_output_tokens, 8);
    assert_eq!(census[0].output_tokens, 20);
    let mut uploadable = census;
    disposition.retain_uploadable(&mut uploadable);
    assert_eq!(uploadable.len(), 2, "re-proven revisions reach upload");
    assert!(!index
        .claude_usage_authority_quarantine
        .contains_key(FAMILY_ROOT));
    assert_ne!(
        index.claude_usage_family_witnesses.get(FAMILY_ROOT),
        Some(&proven_before),
        "the new witness hashes the thinking count"
    );
    let _ = fs::remove_dir_all(dir);
}
