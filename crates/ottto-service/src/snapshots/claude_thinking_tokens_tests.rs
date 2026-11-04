//! Claude Code thinking tokens reach `reasoning_output_tokens`.
//!
//! Claude Code writes the count as `usage.output_tokens_details.thinking_tokens`,
//! a part of `output_tokens`. Fixtures are synthetic usage blocks only.
use super::*;
use serde_json::json;

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
    crate::snapshots::e2_pipeline_scan_fixture::parse_ordinary(
        path,
        "2026-08-02T07:01:00Z",
        fingerprint.to_string(),
    )
    .expect("parse member")
    .remove(0)
}

/// [regress] Reader upgrade: a family witness stored before the thinking
/// reader hashed reasoning 0. After the upgrade a member re-parses with
/// thinking and the same request set. It cannot be rebuilt against the stored
/// witness, so it is held for a bounded retry, never lost or terminal.
#[test]
fn family_stored_before_thinking_reader_is_held_after_upgrade() {
    // Legacy reported-usage rebuild and selectors; `e2` attaches telemetry to native grains.

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
    let mut index =
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(ScanIndex::default());
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
    // An upgraded store's witness, stored before the thinking reader: no
    // build proves a new one.
    assert!(index.install_stored_claude_family_witness_for_test(
        FAMILY_ROOT,
        &items,
        &api_report,
        &trace_report,
    ));
    apply_claude_reported_usage_with_index(&mut items, &api_report, &trace_report, &mut index);
    assert!(items
        .iter()
        .all(|item| item.usage_accounting_contract.as_deref() == exclusive));
    let proven_before = index
        .claude_usage_family_witnesses
        .get(FAMILY_ROOT)
        .cloned()
        .expect("family proven with reasoning 0");

    // After the upgrade: the root re-parses with thinking, same requests.
    let (root_path, _) = write_family(&dir, Some(4));
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

    let _ = fs::remove_dir_all(dir);
}
