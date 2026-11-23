// Synthetic Claude family line builders shared by the pipeline tests: a root
// with two subagents, its transcript lines and the paired local OTEL API and
// trace rows. Fixtures are synthetic.
use super::*;

const REARM_ROOT: &str = "a1111111-1111-4111-8111-111111111111";
const REARM_AGENTS: [&str; 2] = ["a4d1585d310070d0f", "b7c2696e421181e1a"];

pub(super) fn rearm_transcript_line(
    session: &str,
    agent: Option<&str>,
    request: &str,
    second: u32,
) -> String {
    let agent = agent
        .map(|agent| format!("\"agentId\":\"{agent}\",\"isSidechain\":true,"))
        .unwrap_or_default();
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",{agent}\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
    )
}

pub(super) fn rearm_member_session(agent: Option<&str>) -> String {
    match agent {
        Some(agent) => format!("{REARM_ROOT}_agent-{agent}"),
        None => REARM_ROOT.to_string(),
    }
}

pub(super) fn rearm_family_sessions() -> BTreeSet<String> {
    std::iter::once(rearm_member_session(None))
        .chain(
            REARM_AGENTS
                .iter()
                .map(|agent| rearm_member_session(Some(*agent))),
        )
        .collect()
}

/// Paired API and trace rows for one root-session request, as the local OTEL
/// receiver writes them.
pub(super) fn rearm_evidence_lines(
    agent: Option<&str>,
    request: &str,
    sequence: u64,
) -> (String, String) {
    use sha2::{Digest, Sha256};
    let mut api = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: REARM_ROOT.into(),
        request_id: request.to_string(),
        client_request_id: format!("client-{request}"),
        observed_at: format!("2026-08-02T07:00:{sequence:02}Z"),
        model: "claude-haiku-4-5".into(),
        effort: "high".into(),
        query_source: "user".into(),
        speed: "fast".into(),
        cost_usd_micros: Some(100),
        event_sequence: Some(sequence),
        app_version: "2.1.226".into(),
        input_tokens: 10,
        output_tokens: 10,
        request_count: 1,
        ..Default::default()
    };
    api.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&api).expect("serialize API evidence"))
    );
    let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".into(),
        session_id: REARM_ROOT.into(),
        request_id: request.to_string(),
        client_request_id: format!("client-{request}"),
        agent_id: agent.unwrap_or_default().to_string(),
        observed_at: "2026-08-02T07:00:30Z".to_string(),
        ..Default::default()
    };
    trace.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&trace).expect("serialize trace evidence"))
    );
    (
        serde_json::to_string(&api).expect("encode API evidence") + "\n",
        serde_json::to_string(&trace).expect("encode trace evidence") + "\n",
    )
}
