use super::*;

fn capture(logs: bool, dir: &Path, bytes: &[u8], mime: &str) -> usize {
    if logs {
        capture_claude_api_request_logs(dir, bytes, mime)
    } else {
        capture_claude_llm_request_traces(dir, bytes, mime)
    }
    .unwrap()
}
fn assert_excluded(dir: &Path) {
    assert!(telemetry_stems(dir).unwrap().is_empty());
    assert!(telemetry_notices::pending(dir).unwrap().is_empty());
}

#[test]
fn reserved_smoke_json_and_protobuf_api_and_trace_never_write_or_notify() {
    let dir = crate::test_scratch::ScratchDir::new("otel-smoke-exclusion");
    telemetry_notices::configure(&dir, true).unwrap();
    let reserved = crate::claude_spawn_gate::internal_session_id();
    let json_api = String::from_utf8(parent_and_subagent_body().to_vec())
        .unwrap()
        .replace("sess-mixed", &reserved);
    let mut api = otlp_proto::ExportLogsServiceRequest::decode(api_log_body().as_slice()).unwrap();
    api.resource_logs[0].resource.as_mut().unwrap().attributes[0] =
        proto_string("session.id", &reserved);
    let json_trace = serde_json::json!({"resourceSpans":[{"resource":{"attributes":[
        {"key":"session.id","value":{"stringValue":reserved}}]},"scopeSpans":[{"spans":[{
        "name":"claude_code.llm_request","startTimeUnixNano":"1785708000000000000",
        "attributes":[{"key":"request_id","value":{"stringValue":"request"}},
            {"key":"client_request_id","value":{"stringValue":"client-request"}}]}]}]}]});
    let mut traces = otlp_proto::ExportTraceServiceRequest::decode(
        trace_body(vec![llm_span("request", None)]).as_slice(),
    )
    .unwrap();
    traces.resource_spans[0]
        .resource
        .as_mut()
        .unwrap()
        .attributes[0] = proto_string("session.id", &reserved);
    for (logs, mime, bytes) in [
        (true, "application/json", json_api.as_bytes().to_vec()),
        (true, "application/x-protobuf", api.encode_to_vec()),
        (
            false,
            "application/json",
            serde_json::to_vec(&json_trace).unwrap(),
        ),
        (false, "application/x-protobuf", traces.encode_to_vec()),
    ] {
        assert_eq!(capture(logs, &dir, &bytes, mime), 0);
        assert_excluded(&dir);
    }
    // Same payloads with an ordinary SDK root are positive controls, including
    // a mixed user/internal export. Query source never decides exclusion.
    let mut mixed: Value = serde_json::from_slice(json_api.as_bytes()).unwrap();
    let ordinary = serde_json::from_slice::<Value>(parent_and_subagent_body()).unwrap();
    mixed["resourceLogs"]
        .as_array_mut()
        .unwrap()
        .push(ordinary["resourceLogs"][0].clone());
    api.resource_logs[0].resource.as_mut().unwrap().attributes[0] =
        proto_string("session.id", "sdk-proto");
    traces.resource_spans[0]
        .resource
        .as_mut()
        .unwrap()
        .attributes[0] = proto_string("session.id", "sdk-trace");
    let ordinary_trace = json_trace.to_string().replace(&reserved, "sdk-json-trace");
    for (logs, mime, bytes, count) in [
        (
            true,
            "application/json",
            serde_json::to_vec(&mixed).unwrap(),
            2,
        ),
        (true, "application/x-protobuf", api.encode_to_vec(), 1),
        (false, "application/json", ordinary_trace.into_bytes(), 1),
        (false, "application/x-protobuf", traces.encode_to_vec(), 1),
    ] {
        assert_eq!(capture(logs, &dir, &bytes, mime), count);
    }
    let notices = telemetry_notices::pending(&dir).unwrap();
    assert_eq!(notices.len(), 4);
    assert!(!notices.contains(&reserved));
    telemetry_notices::forget(&dir, &notices).unwrap();
}
