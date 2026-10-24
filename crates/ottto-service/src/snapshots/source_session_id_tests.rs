use super::*;

#[test]
fn snapshot_source_session_id_matches_snapshot_wire() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ottto-session-id-parity-{}-{unique}",
        std::process::id()
    ));
    let cases = [
        (SnapshotSource::ClaudeCode, "root.jsonl", "ROOT", "ROOT"),
        (
            SnapshotSource::ClaudeCode,
            "PARENT/subagents/agent-task.jsonl",
            "IN-FILE-PARENT",
            "PARENT_agent-task",
        ),
        (
            SnapshotSource::ClaudeCode,
            "PARENT/subagents/workflows/wf-test/inner/agent-nested.jsonl",
            "IN-FILE-PARENT",
            "PARENT_agent-nested",
        ),
        (
            SnapshotSource::Codex,
            "rollout-01A03E99-49CF-7460-9FD7-F7DBFD2F05E4.jsonl",
            "01A03E99-49CF-7460-9FD7-F7DBFD2F05E4",
            "01a03e99-49cf-7460-9fd7-f7dbfd2f05e4",
        ),
        (
            SnapshotSource::Codex,
            "rollout-Provider-Case-Sensitive.jsonl",
            "Provider-Case-Sensitive",
            "Provider-Case-Sensitive",
        ),
    ];
    for (source, relative_path, first_id, expected) in cases {
        let path = root.join(relative_path);
        fs::create_dir_all(path.parent().expect("parent")).expect("create fixture directory");
        let lines = match source {
            SnapshotSource::ClaudeCode => vec![
                json!({"timestamp":"2026-08-02T06:00:00Z","type":"user","sessionId":first_id,"message":{"role":"user","content":"hello"}}),
                // A later id must never replace the first id, even at the root.
                json!({"timestamp":"2026-08-02T06:01:00Z","type":"assistant","sessionId":"LATER-ID","requestId":"req-parity","message":{"id":"msg-parity","model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":2}}}),
            ],
            SnapshotSource::Codex => vec![
                json!({"timestamp":"2026-08-02T06:00:00Z","type":"session_meta","payload":{"id":first_id}}),
                json!({"timestamp":"2026-08-02T06:01:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"output_tokens":2,"request_count":1},"model":"gpt-5.6"}}}),
            ],
            SnapshotSource::Pi => unreachable!(),
        };
        let contents = lines
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&path, &contents).expect("write fixture");
        let parse = match source {
            SnapshotSource::ClaudeCode => parse_claude_code_jsonl_file,
            SnapshotSource::Codex => parse_codex_jsonl_file,
            SnapshotSource::Pi => unreachable!(),
        };
        let items = parse(&path, "2026-08-02T06:02:00Z", "fp".to_string()).expect("parse fixture");
        assert_eq!(items.len(), 1, "{relative_path}");
        let wire = serde_json::to_value(&items[0]).expect("serialize snapshot");
        assert_eq!(wire["source_session_id"], expected, "{relative_path}");
        assert_eq!(
            snapshot_source_session_id(source, &path, first_id.to_string()),
            items[0].source_session_id,
            "{relative_path}"
        );
        if source == SnapshotSource::ClaudeCode && relative_path.contains("subagents") {
            let journal = path.with_file_name("journal.jsonl");
            fs::write(&journal, &contents).expect("write journal control");
            assert!(parse(&journal, "2026-08-02T06:02:00Z", "fp".to_string())
                .expect("parse journal")
                .is_empty());
        }
    }
    fs::remove_dir_all(root).expect("remove fixtures");
}
