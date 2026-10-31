use super::*;
use crate::claude_local_otel::{ClaudeLocalOtelEvidence, ClaudeTraceOwnershipEvidence};

fn append_pair(support: &Path, request: &str, agent: &str, account: &str) {
    let mut api = ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: "root".into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        observed_at: "2026-10-31T10:36:00Z".into(),
        model: "claude-sonnet-4-6".into(),
        request_count: 1,
        account_identity_checked: true,
        account_identifier_hash: Some(account.into()),
        input_tokens: 10,
        output_tokens: 1,
        ..Default::default()
    };
    api.fingerprint = format!(
        "sha256:{:x}",
        serialized_json_digest(&api, b"").unwrap().finalize()
    );
    let mut trace = ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".into(),
        fingerprint: String::new(),
        session_id: "root".into(),
        request_id: request.into(),
        client_request_id: api.client_request_id.clone(),
        agent_id: agent.into(),
        parent_agent_id: String::new(),
        workflow_run_id: String::new(),
        observed_at: api.observed_at.clone(),
    };
    trace.fingerprint = format!(
        "sha256:{:x}",
        serialized_json_digest(&trace, b"").unwrap().finalize()
    );
    for (dir, value) in [
        (
            crate::claude_local_otel::STORE_DIR,
            serde_json::to_string(&api).unwrap(),
        ),
        (
            "local-otel/claude-code-trace-ownership",
            serde_json::to_string(&trace).unwrap(),
        ),
    ] {
        let dir = support.join(dir);
        fs::create_dir_all(&dir).unwrap();
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(format!("{:x}.jsonl", Sha256::digest(b"root"))))
            .unwrap();
        writeln!(file, "{value}").unwrap();
    }
}

fn child(stem: &str) -> ClaudeSubagentIdentity {
    ClaudeSubagentIdentity {
        root_session_id: "root".into(),
        file_stem: stem.into(),
        workflow_ref: None,
    }
}
fn fingerprint(page: &mut Page, support: &Path, child: &ClaudeSubagentIdentity) -> String {
    claude_subagent_sidecar_fingerprint(
        Path::new("root/subagents/agent-a.jsonl"),
        child,
        Some(support),
        page.digest(Some(support), child).as_deref(),
    )
}

/// [off=main] No marker means the existing stat fingerprint, with no sidecar reads.
#[test]
fn off_preserves_stat_selection_and_does_not_read_sidecars() {
    let scratch = crate::test_scratch::ScratchDir::new("d3-off");
    append_pair(&scratch, "req-a", "a", &"a".repeat(64));
    assert!(!terminal_off_policy::child_evidence_digest());
    crate::claude_local_otel::reset_evidence_read_counts_for_test();
    let mut page = Page::new(false);
    let expected = claude_subagent_sidecar_fingerprint(
        Path::new("root/subagents/agent-a.jsonl"),
        &child("agent-a"),
        Some(&scratch),
        None,
    );
    assert_eq!(
        fingerprint(&mut page, &scratch, &child("agent-a")),
        expected
    );
    assert_eq!(
        crate::claude_local_otel::evidence_read_counts_for_test(),
        (0, 0)
    );
    append_pair(&scratch, "req-b", "b", &"a".repeat(64));
    assert_ne!(
        fingerprint(&mut page, &scratch, &child("agent-a")),
        expected
    );
}

/// [regress] A live root's other-agent append no longer reselects unchanged children.
#[test]
fn sibling_appends_stay_stable_and_one_page_reads_the_family_once() {
    let scratch = crate::test_scratch::ScratchDir::new("d3-siblings");
    append_pair(&scratch, "req-a", "a", &"a".repeat(64));
    let before = fingerprint(&mut Page::new(true), &scratch, &child("agent-a"));
    append_pair(&scratch, "req-b", "b", &"a".repeat(64));
    crate::claude_local_otel::reset_evidence_read_counts_for_test();
    let mut page = Page::new(true);
    assert_eq!(fingerprint(&mut page, &scratch, &child("agent-a")), before);
    for i in 0..181 {
        fingerprint(&mut page, &scratch, &child(&format!("agent-{i}")));
    }
    assert_eq!(
        crate::claude_local_otel::evidence_read_counts_for_test(),
        (1, 1)
    );
    assert!(page.bytes_read > 0);
    eprintln!(
        "d3_digest_measurement children=182 bytes={} bytes_per_child={}",
        page.bytes_read,
        page.bytes_read / 182
    );
}

/// [money] Late account evidence and this agent's request evidence must reselect it.
#[test]
fn consumed_account_and_request_entries_move_the_fingerprint() {
    let scratch = crate::test_scratch::ScratchDir::new("d3-money");
    append_pair(&scratch, "req-a", "a", &"a".repeat(64));
    let first = fingerprint(&mut Page::new(true), &scratch, &child("agent-a"));
    append_pair(&scratch, "req-b", "b", &"b".repeat(64));
    let account_changed = fingerprint(&mut Page::new(true), &scratch, &child("agent-a"));
    assert_ne!(first, account_changed);
    append_pair(&scratch, "req-a2", "a", &"a".repeat(64));
    let request_changed = fingerprint(&mut Page::new(true), &scratch, &child("agent-a"));
    assert_ne!(account_changed, request_changed);
}
