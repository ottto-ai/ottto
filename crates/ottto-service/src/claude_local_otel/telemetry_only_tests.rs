use super::*;

fn assert_excluded(dir: &Path) {
    assert!(telemetry_stems(dir).unwrap().is_empty());
    assert!(telemetry_notices::detach(dir).unwrap().roots.is_empty());
}

#[test]
fn reserved_smoke_json_and_protobuf_api_and_trace_never_write_or_notify() {
    let dir = std::env::temp_dir().join(format!(
        "otel-smoke-exclusion-{}",
        crate::claude_spawn_gate::internal_session_id()
    ));
    fs::create_dir_all(&dir).unwrap();
    telemetry_notices::configure(&dir, true).unwrap();
    let reserved = crate::claude_spawn_gate::internal_session_id();
    let json_api = String::from_utf8(parent_and_subagent_body().to_vec())
        .unwrap()
        .replace("sess-mixed", &reserved);
    assert_eq!(
        capture_claude_api_request_logs(&dir, json_api.as_bytes(), "application/json").unwrap(),
        0
    );
    assert_excluded(&dir);
    let mut api = otlp_proto::ExportLogsServiceRequest::decode(api_log_body().as_slice()).unwrap();
    api.resource_logs[0].resource.as_mut().unwrap().attributes[0] =
        proto_string("session.id", &reserved);
    assert_eq!(
        capture_claude_api_request_logs(&dir, &api.encode_to_vec(), "application/x-protobuf")
            .unwrap(),
        0
    );
    assert_excluded(&dir);
    let json_trace = serde_json::json!({"resourceSpans":[{"resource":{"attributes":[
        {"key":"session.id","value":{"stringValue":reserved}}]},"scopeSpans":[{"spans":[{
        "name":"claude_code.llm_request","startTimeUnixNano":"1785708000000000000",
        "attributes":[{"key":"request_id","value":{"stringValue":"request"}},
            {"key":"client_request_id","value":{"stringValue":"client-request"}}]}]}]}]});
    assert_eq!(
        capture_claude_llm_request_traces(
            &dir,
            &serde_json::to_vec(&json_trace).unwrap(),
            "application/json"
        )
        .unwrap(),
        0
    );
    assert_excluded(&dir);
    let mut traces = otlp_proto::ExportTraceServiceRequest::decode(
        trace_body(vec![llm_span("request", None)]).as_slice(),
    )
    .unwrap();
    traces.resource_spans[0]
        .resource
        .as_mut()
        .unwrap()
        .attributes[0] = proto_string("session.id", &reserved);
    assert_eq!(
        capture_claude_llm_request_traces(&dir, &traces.encode_to_vec(), "application/x-protobuf")
            .unwrap(),
        0
    );
    assert_excluded(&dir);
    // Same payloads with an ordinary SDK root are positive controls, including
    // a mixed user/internal export. Query source never decides exclusion.
    let mut mixed: Value = serde_json::from_slice(json_api.as_bytes()).unwrap();
    let ordinary = serde_json::from_slice::<Value>(parent_and_subagent_body()).unwrap();
    mixed["resourceLogs"]
        .as_array_mut()
        .unwrap()
        .push(ordinary["resourceLogs"][0].clone());
    assert_eq!(
        capture_claude_api_request_logs(
            &dir,
            &serde_json::to_vec(&mixed).unwrap(),
            "application/json"
        )
        .unwrap(),
        2
    );
    api.resource_logs[0].resource.as_mut().unwrap().attributes[0] =
        proto_string("session.id", "sdk-proto");
    assert_eq!(
        capture_claude_api_request_logs(&dir, &api.encode_to_vec(), "application/x-protobuf")
            .unwrap(),
        1
    );
    traces.resource_spans[0]
        .resource
        .as_mut()
        .unwrap()
        .attributes[0] = proto_string("session.id", "sdk-trace");
    assert_eq!(
        capture_claude_llm_request_traces(&dir, &traces.encode_to_vec(), "application/x-protobuf")
            .unwrap(),
        1
    );
    let json_trace = json_trace.to_string().replace(&reserved, "sdk-json-trace");
    assert_eq!(
        capture_claude_llm_request_traces(&dir, json_trace.as_bytes(), "application/json").unwrap(),
        1
    );
    let notices = telemetry_notices::detach(&dir).unwrap();
    assert_eq!(notices.roots.len(), 4);
    assert!(!notices.roots.contains(&reserved));
    notices.committed();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn detached_notice_restores_on_failure_and_keeps_concurrent_append() {
    let dir = std::env::temp_dir().join(format!(
        "otel-notice-{}",
        crate::claude_spawn_gate::internal_session_id()
    ));
    telemetry_notices::configure(&dir, true).unwrap();
    assert_eq!(
        capture_claude_api_request_logs(&dir, parent_and_subagent_body(), "application/json")
            .unwrap(),
        2
    );
    let failed_save = telemetry_notices::detach(&dir).unwrap();
    assert!(failed_save.roots.contains("sess-mixed"));
    let next = String::from_utf8(parent_and_subagent_body().to_vec())
        .unwrap()
        .replace("sess-mixed", "next-append");
    capture_claude_api_request_logs(&dir, next.as_bytes(), "application/json").unwrap();
    drop(failed_save);
    let retry = telemetry_notices::detach(&dir).unwrap();
    assert_eq!(
        retry.roots,
        BTreeSet::from(["sess-mixed".into(), "next-append".into()])
    );
    retry.committed();
    assert!(telemetry_notices::detach(&dir).unwrap().roots.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
