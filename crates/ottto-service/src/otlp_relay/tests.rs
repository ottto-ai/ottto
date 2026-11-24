//! Tests and shared test fixtures for the local telemetry relay.

use super::*;
use crate::ControlToken;
use ottto_protocol::{
    LocalAccountBinding, LocalAccountOrganization, LocalAccountState, LocalAccountUser,
    MachineIdentity, OperatingSystem,
};

const TOKEN: &str = "test-control-token";

// The relay candidates are fixed numbers inside the Linux ephemeral range,
// so a parallel test's ephemeral listener or outbound connection can hold
// one at any moment. A plan feeds each candidate bind its result in order.
type BindPlan = std::collections::VecDeque<(u16, io::Result<TcpListener>)>;

thread_local! {
    static BIND_PLAN: std::cell::RefCell<Option<BindPlan>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn planned_bind(port: u16) -> Option<io::Result<TcpListener>> {
    BIND_PLAN.with(|plan| {
        let mut plan = plan.borrow_mut();
        let (expected, result) = plan.as_mut()?.pop_front().expect("unexpected relay bind");
        assert_eq!(port, expected, "relay binds follow the candidate order");
        Some(result)
    })
}

pub(crate) fn with_bind_plan<T>(
    plan: impl IntoIterator<Item = (u16, io::Result<TcpListener>)>,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<BindPlan>);
    impl Drop for Reset {
        fn drop(&mut self) {
            BIND_PLAN.with(|plan| *plan.borrow_mut() = self.0.take());
        }
    }
    let plan = plan.into_iter().collect();
    let _reset = Reset(BIND_PLAN.with(|slot| slot.replace(Some(plan))));
    let value = run();
    BIND_PLAN.with(|plan| {
        assert!(
            plan.borrow().as_ref().unwrap().is_empty(),
            "every planned relay bind must be attempted"
        );
    });
    value
}

pub(super) fn test_daemon() -> LocalDaemon {
    LocalDaemon::new(
        MachineIdentity {
            machine_id: "machine_test".to_string(),
            installation_id: "install_test".to_string(),
            display_name: "Test Mac".to_string(),
            hostname: "test-mac.local".to_string(),
            os: OperatingSystem::Macos,
            arch: "arm64".to_string(),
            local_platform_version: "0.1.31-rc1".to_string(),
            hardware_uuid: None,
            account_scope: None,
        },
        ControlToken::new(TOKEN).expect("token should be valid"),
        "2026-06-15T19:12:48Z",
    )
}

#[test]
fn control_origin_allowlist_accepts_production_only() {
    assert!(is_allowed_control_origin("https://ottto.net"));
    assert!(is_allowed_control_origin("https://www.ottto.net"));
    assert!(is_allowed_control_origin("https://app.ottto.net"));
    assert!(!is_allowed_control_origin("http://localhost:3000"));
    assert!(!is_allowed_control_origin("http://127.0.0.1:3001"));
    assert!(!is_allowed_control_origin("https://ottto.net.evil"));
    assert!(!is_allowed_control_origin("http://127.0.0.1.evil:3000"));
}

#[test]
fn control_preflight_refuses_loopback_origins_before_cors() {
    let daemon = test_daemon();
    for (origin, allowed) in [
        ("http://localhost:3000", false),
        ("http://127.0.0.1:3001", false),
        ("https://app.ottto.net", true),
    ] {
        let (mut client, mut server) = loopback_pair();
        let port = server.local_addr().unwrap().port();
        let request = HttpRequest {
            method: "OPTIONS".into(),
            path: "/control".into(),
            headers: BTreeMap::from([
                ("host".into(), format!("127.0.0.1:{port}")),
                ("origin".into(), origin.into()),
            ]),
            body: vec![],
        };
        handle_control_request(&mut server, &daemon, request).unwrap();
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        if allowed {
            assert!(headers.starts_with("HTTP/1.1 204"), "{response}");
            assert!(headers.contains(&format!("Access-Control-Allow-Origin: {origin}")));
        } else {
            assert!(headers.starts_with("HTTP/1.1 403"), "{response}");
            assert!(
                !headers.to_ascii_lowercase().contains("access-control-"),
                "{response}"
            );
            let payload: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(payload["error"], "origin_forbidden");
        }
    }
}

#[test]
#[serial_test::serial]
fn forbidden_origin_body_keeps_each_message_verbatim() {
    fn keys(value: &serde_json::Value) -> Vec<&str> {
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }
    let files = crate::control::tests::ControlFilesFixture::new();
    FileDeviceStore::default()
        .save(&ottto_core::LocalDeviceBinding {
            device_id: "device_probe".into(),
            machine_id: None,
            sources: vec![],
        })
        .unwrap();
    for noun in ["control", "identity", "health"] {
        for (origin, host_kind, error) in [
            (None, "loopback", Some("origin_forbidden")),
            (Some("null"), "loopback", Some("origin_forbidden")),
            (
                Some("https://ottto.net.evil"),
                "loopback",
                Some("origin_forbidden"),
            ),
            // A loopback dev page gets liveness only from the probes.
            (
                Some("http://localhost:3000"),
                "loopback",
                Some("origin_forbidden"),
            ),
            (
                Some("https://app.ottto.net"),
                "remote",
                Some("host_forbidden"),
            ),
            (
                Some("https://app.ottto.net"),
                "missing",
                Some("host_forbidden"),
            ),
            (
                Some("https://app.ottto.net"),
                "wrong_port",
                Some("host_forbidden"),
            ),
            (Some("https://app.ottto.net"), "loopback", None),
            (Some("https://app.ottto.net"), "localhost", None),
            (Some("https://app.ottto.net"), "ipv6", None),
        ] {
            for method in ["OPTIONS", "GET", "POST"] {
                if method == "GET" && noun == "control" {
                    continue;
                }
                if method == "POST" && (noun != "control" || error.is_none()) {
                    continue;
                }
                for token in [None, Some("wrong-token"), Some(TOKEN)] {
                    let (mut client, mut server) = loopback_pair();
                    let port = server.local_addr().unwrap().port();
                    let mut headers = BTreeMap::new();
                    if let Some(origin) = origin {
                        headers.insert("origin".into(), origin.into());
                    }
                    let host = match host_kind {
                        "missing" => None,
                        "remote" => Some(format!("example.test:{port}")),
                        "wrong_port" => Some(format!("127.0.0.1:{}", port.saturating_sub(1))),
                        "localhost" => Some(format!("localhost:{port}")),
                        "ipv6" => Some(format!("[::1]:{port}")),
                        _ => Some(format!("127.0.0.1:{port}")),
                    };
                    if let Some(host) = host {
                        headers.insert("host".into(), host);
                    }
                    if let Some(token) = token {
                        headers.insert("authorization".into(), format!("Bearer {token}"));
                    }
                    let request = HttpRequest {
                        method: method.into(),
                        path: match noun {
                            "control" => "/control",
                            "identity" => "/whoami",
                            _ => "/local-health",
                        }
                        .into(),
                        headers,
                        body: vec![],
                    };
                    files
                        .assert_unchanged(|| match noun {
                            "control" => {
                                handle_control_request(&mut server, &test_daemon(), request)
                            }
                            "identity" => {
                                handle_whoami_request(&mut server, &test_daemon(), request)
                            }
                            _ => handle_local_health_request(
                                &mut server,
                                &test_daemon(),
                                request,
                            ),
                        })
                        .unwrap();
                    drop(server);
                    let mut response = String::new();
                    client.read_to_string(&mut response).unwrap();
                    let status = if error.is_some() && noun == "control" {
                        403
                    } else if error.is_some() {
                        200
                    } else if method == "OPTIONS" {
                        204
                    } else {
                        200
                    };
                    assert!(
                        response.starts_with(&format!("HTTP/1.1 {status}")),
                        "{response}"
                    );
                    if status == 204 {
                        continue;
                    }
                    let (_, body) = response.split_once("\r\n\r\n").unwrap();
                    let payload: serde_json::Value = serde_json::from_str(body).unwrap();
                    if let Some(error) = error.filter(|_| noun == "control") {
                        assert_eq!(payload["error"], error);
                        if error == "origin_forbidden" {
                            assert_eq!(
                                payload["message"],
                                format!("Origin is not allowed for local Ottto {noun}")
                            );
                        }
                    } else if error.is_some() {
                        assert_eq!(
                            payload,
                            json!({"ok":true, "version":crate::compiled_release_version()})
                        );
                    } else {
                        assert_eq!(payload["machine_id"], "machine_test");
                        assert_eq!(payload["machine_name"], "Test Mac");
                        if noun == "health" {
                            assert_eq!(
                                keys(&payload),
                                ["health", "machine_id", "machine_name"]
                            );
                            assert_eq!(
                                keys(&payload["health"]),
                                [
                                    "account",
                                    "blockers",
                                    "capabilities",
                                    "computed_at",
                                    "device_id",
                                    "event_schema_version",
                                    "evidence",
                                    "fresh_until",
                                    "machine_id",
                                    "observed_at",
                                    "overall",
                                    "projection_revision",
                                    "projection_version",
                                    "protocol_version",
                                    "revision",
                                    "runtime",
                                    "schema_version",
                                    "schema_version_name",
                                    "sources",
                                ]
                            );
                            assert_eq!(payload["health"]["device_id"], "device_probe");
                            assert_eq!(payload["health"]["machine_id"], "machine_test");
                        } else {
                            assert_eq!(keys(&payload), ["machine_id", "machine_name"]);
                        }
                    }
                }
            }
        }
    }
}

/// Past the Origin and Host gate, the browser route forwards only its two
/// backend-token commands, and never as a trusted Companion.
#[test]
#[serial_test::serial]
fn browser_control_forwards_only_backend_token_commands_untrusted() {
    use crate::test_effects::{Effect, Recording, Scalar};
    use ottto_protocol::{
        CliErrorCode, LocalClientKind, LocalControlResponse, SourceKind, TelemetryControlAction,
    };
    let files = crate::control::tests::ControlFilesFixture::new();
    // A loopback stub stands in for the public release manifest, so a
    // regressed allowlist cannot reach the network; it must see no request.
    let manifest = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind manifest stub");
    manifest.set_nonblocking(true).unwrap();
    let _manifest_url = crate::control::tests::EnvVarGuard::set_str(
        "OTTTO_RELEASE_MANIFEST_URL",
        &format!("http://{}/manifest.json", manifest.local_addr().unwrap()),
    );
    let launch = || LocalControlCommand::SessionLaunchPrepare {
        schema_version: 1,
        provider: ottto_protocol::SessionLaunchProviderV1::Codex,
        slot_id: "missing".into(),
        expected_account_identifier_hash: "".into(),
        expected_organization_identifier_hash: None,
        folder: ottto_protocol::SessionLaunchFolderV1 {
            path: None,
            recent_id: None,
        },
        terminal: None,
    };
    let status = || LocalControlCommand::Status {
        refresh_agent_status: true,
        retry_relay_authorization: true,
    };
    let telemetry = || LocalControlCommand::TelemetryControl {
        action: TelemetryControlAction::Status,
        source: SourceKind::Codex,
        control_token: String::new(),
        api_base_url: None,
        key_id: None,
        organization_id: None,
        otlp_endpoint: None,
        ingest_key: None,
    };
    let mut cases = Vec::new();
    // Even the daemon's own token cannot widen the browser route.
    for token in ["forged-token", TOKEN] {
        for (command, mismatched) in [
            (status(), false),
            (LocalControlCommand::UpdateCheck, false),
            (LocalControlCommand::UpdateCheck, true),
            (launch(), false),
        ] {
            let error = if mismatched {
                "bad_request"
            } else {
                "unsupported_command"
            };
            cases.push((command, mismatched, Some(token), Err(error)));
        }
    }
    // A mismatched protocol version fails request parsing, before command
    // filtering, so even an allowed command is a bad request.
    cases.push((telemetry(), true, None, Err("bad_request")));
    // A Companion claim without a token reaches dispatch untrusted.
    cases.push((
        telemetry(),
        false,
        None,
        Ok(CliErrorCode::LocalClientNotTrusted),
    ));
    for (command, mismatched, token, expected) in cases {
        let context = format!("{command:?} mismatched={mismatched}");
        let version = ottto_protocol::expected_local_control_protocol_version(&command);
        let body = serde_json::to_vec(&LocalControlRequest {
            request_id: "browser-allowlist".into(),
            protocol_version: version + u16::from(mismatched),
            token: token.map(str::to_owned),
            client_kind: Some(LocalClientKind::CompanionApp),
            client_install_owner: None,
            command,
        })
        .unwrap();
        let (mut client, mut server) = loopback_pair();
        let port = server.local_addr().unwrap().port();
        let request = HttpRequest {
            method: "POST".into(),
            path: "/control".into(),
            headers: BTreeMap::from([
                ("origin".to_string(), "https://app.ottto.net".to_string()),
                ("host".to_string(), format!("127.0.0.1:{port}")),
            ]),
            body,
        };
        let recording = Recording::start();
        files
            .assert_unchanged(|| handle_control_request(&mut server, &test_daemon(), request))
            .unwrap();
        let entered = recording.take();
        drop(recording);
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        let (_, payload) = response.split_once("\r\n\r\n").unwrap();
        let expected = match expected {
            Ok(code) => code,
            Err(error) => {
                assert!(
                    response.starts_with("HTTP/1.1 400"),
                    "{context}: {response}"
                );
                let payload: serde_json::Value = serde_json::from_str(payload).unwrap();
                assert_eq!(payload["error"], error, "{context}");
                assert!(entered.is_empty(), "{context}");
                continue;
            }
        };
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{context}: {response}"
        );
        let payload: LocalControlResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(payload.error.unwrap().code, expected, "{context}");
        let dispatched = vec![Effect {
            label: "control_dispatch_entered",
            fields: vec![("trusted_companion", Scalar::Bool(false))],
        }];
        assert_eq!(entered, dispatched, "{context}");
    }
    let hits = manifest.accept();
    assert!(
        matches!(&hits, Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "the release manifest stub saw a request: {hits:?}"
    );
}

#[test]
fn control_cors_headers_allow_private_network_preflight() {
    let headers = control_cors_headers(Some("https://ottto.net"))
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        headers
            .get("Access-Control-Allow-Origin")
            .map(String::as_str),
        Some("https://ottto.net")
    );
    assert_eq!(
        headers
            .get("Access-Control-Allow-Private-Network")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        headers.get("Vary").map(String::as_str),
        Some("Origin, Access-Control-Request-Private-Network")
    );
}

#[test]
fn local_health_response_payload_strips_account_identifiers() {
    let daemon = test_daemon().with_account(LocalAccountBinding {
        state: LocalAccountState::Connected,
        user: Some(LocalAccountUser {
            id: "user_1".to_string(),
            email: "ron@example.com".to_string(),
            display_name: Some("Alex".to_string()),
        }),
        organization: Some(LocalAccountOrganization {
            id: "org_1".to_string(),
            name: "Ottto".to_string(),
        }),
        connected_at: Some("2026-06-15T19:00:00Z".to_string()),
        last_refreshed_at: Some("2026-06-15T19:10:00Z".to_string()),
        message: None,
        can_reconnect: None,
    });

    let payload = local_health_response_payload(&daemon, None).expect("payload");

    assert_eq!(payload["machine_id"], "machine_test");
    assert_eq!(payload["machine_name"], "Test Mac");
    assert_eq!(payload["health"]["machine_id"], "machine_test");
    assert!(payload["health"].get("user_id").is_none());
    assert!(payload["health"].get("org_id").is_none());
    assert!(payload["health"].get("device_id").is_none());
    assert_eq!(payload["health"]["account"]["state"], "connected");
}

#[test]
fn local_health_device_identity_requires_a_validated_browser_origin() {
    assert_eq!(
        local_health_browser_device_id(None, || {
            panic!("origin-less callers must not load device identity")
        }),
        None
    );
    assert_eq!(
        local_health_browser_device_id(Some("https://app.ottto.net"), || {
            Some("device_current_installation".to_string())
        }),
        Some("device_current_installation".to_string())
    );
}

#[test]
fn read_http_request_parses_well_formed_post() {
    let body = b"hello-otlp";
    let raw = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut bytes = raw.into_bytes();
    bytes.extend_from_slice(body);
    let mut reader = BufReader::new(bytes.as_slice());

    let request = read_http_request_from(&mut reader).expect("request parses");
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/logs");
    assert_eq!(
        request.headers.get("content-type").map(String::as_str),
        Some("application/x-protobuf")
    );
    assert_eq!(request.body, body);
}

#[test]
fn read_http_request_decodes_chunked_claude_logs_with_extensions_and_trailers() {
    let body = br#"{"resourceLogs":[{"scopeLogs":[]}] }"#;
    let split = 17;
    let raw = format!(
        concat!(
            "POST /v1/logs HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "Content-Type: application/json\r\n",
            "Transfer-Encoding: chunked\r\n\r\n",
            "{:x};source=claude\r\n{}\r\n",
            "{:x}\r\n{}\r\n",
            "0\r\nX-Exporter-Finished: true\r\n\r\n"
        ),
        split,
        String::from_utf8_lossy(&body[..split]),
        body.len() - split,
        String::from_utf8_lossy(&body[split..]),
    );
    let mut reader = BufReader::new(raw.as_bytes());

    let request = read_http_request_from(&mut reader).expect("chunked request parses");

    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/logs");
    assert_eq!(request.body, body);
}

#[test]
fn read_http_request_rejects_over_long_header_line() {
    for (raw, expected) in [
        {
            let mut raw = String::from("POST /v1/logs HTTP/1.1\r\nX-Big: ");
            raw.push_str(&"a".repeat(MAX_HEADER_LINE_BYTES + 64));
            raw.push_str("\r\n\r\n");
            raw
        },
        {
            let mut raw = String::from("POST /v1/logs HTTP/1.1\r\n");
            let value = "b".repeat(MAX_HEADER_LINE_BYTES / 2);
            let lines_needed = (MAX_HEADER_TOTAL_BYTES / value.len()) + 2;
            for index in 0..lines_needed {
                raw.push_str(&format!("X-Pad-{index}: {value}\r\n"));
            }
            raw.push_str("\r\n");
            raw
        },
        {
            let mut raw = String::from("POST /v1/logs HTTP/1.1\r\n");
            for index in 0..(MAX_HEADER_COUNT + 5) {
                raw.push_str(&format!("X-H-{index}: v\r\n"));
            }
            raw.push_str("\r\n");
            raw
        },
        format!(
            "POST /v1/logs HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_OTLP_BODY_BYTES + 1
        ),
        format!(
            "POST /v1/logs HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            MAX_OTLP_BODY_BYTES + 1
        ),
        {
            let mut raw =
                String::from("POST /v1/logs HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
            for _ in 0..MAX_CHUNK_COUNT {
                raw.push_str("1\r\na\r\n");
            }
            raw.push_str("1\r\nb\r\n0\r\n\r\n");
            raw
        },
        {
            let extension = "a".repeat(MAX_HEADER_LINE_BYTES - 4);
            let mut raw =
                String::from("POST /v1/logs HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
            for _ in 0..=(MAX_CHUNK_FRAMING_BYTES / MAX_HEADER_LINE_BYTES) {
                raw.push_str(&format!("1;{extension}\r\na\r\n"));
            }
            raw.push_str("0\r\n\r\n");
            raw
        },
    ]
    .into_iter()
    .zip([
        "read header",
        "headers too large",
        "too many request headers",
        "request body too large",
        "request body too large",
        "too many chunks",
        "chunk framing too large",
    ]) {
        let mut reader = BufReader::new(raw.as_bytes());
        let error =
            read_http_request_from(&mut reader).expect_err("oversized HTTP framing rejected");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn read_http_request_rejects_ambiguous_or_unsupported_transfer_framing() {
    for (header, value) in [
        ("Host", "127.0.0.1:43119"),
        ("Origin", "https://app.ottto.net"),
        ("Authorization", "Bearer synthetic-token"),
    ] {
        let raw =
            format!("GET /whoami HTTP/1.1\r\n{header}: {value}\r\n{header}: {value}\r\n\r\n");
        let mut reader = BufReader::new(raw.as_bytes());
        read_http_request_from(&mut reader).expect_err("duplicate request header");
    }
    for raw in [
        concat!(
            "POST /v1/logs HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 5\r\n\r\n0\r\n\r\n"
        ),
        concat!(
            "POST /v1/logs HTTP/1.1\r\n",
            "Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"
        ),
        concat!(
            "POST /v1/logs HTTP/1.1\r\n",
            "Content-Length: 0\r\n",
            "Content-Length: 0\r\n\r\n"
        ),
    ] {
        let mut reader = BufReader::new(raw.as_bytes());
        read_http_request_from(&mut reader).expect_err("unsafe framing rejected");
    }
}

#[test]
fn connection_guard_rejects_over_the_cap_without_leaking_slots() {
    let baseline = ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst);
    // Saturate the remaining slots up to the cap.
    let mut guards = Vec::new();
    while ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst) < MAX_CONCURRENT_RELAY_CONNECTIONS {
        guards.push(ConnectionGuard::acquire().expect("slot available below cap"));
    }
    assert_eq!(
        ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst),
        MAX_CONCURRENT_RELAY_CONNECTIONS
    );

    // At the cap, acquisition is refused and the rejected attempt must not
    // leave the counter inflated.
    assert!(ConnectionGuard::acquire().is_none());
    assert_eq!(
        ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst),
        MAX_CONCURRENT_RELAY_CONNECTIONS
    );
    let (_client, server) = loopback_pair();
    let ((), counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
        dispatch_relay_connection(server, SnapshotSource::ClaudeCode, &test_daemon())
    });
    assert_eq!(counts.otlp_relay_busy_503, 1);

    drop(guards);
    assert_eq!(ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst), baseline);
}

fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let client = TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
    (client, listener.accept().expect("accept").0)
}

/// [behaviour] A refused or unstored relay request counts its closed reason.
#[test]
fn refused_relay_requests_count_their_reason() {
    let dir = crate::test_scratch::ScratchDir::new("relay-refusal-reasons");
    let mut encoded = otlp_post("/v1/traces", "application/json", CLAUDE_LLM_REQUEST_TRACE);
    encoded
        .headers
        .insert("content-encoding".to_string(), "br".to_string());
    let ((), counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
        let (mut client, server) = loopback_pair();
        client.write_all(b"POST v1/logs HTTP/1.1\r\n\r\n").unwrap();
        handle_client_at(
            server,
            SnapshotSource::ClaudeCode,
            test_daemon(),
            None,
            &dir,
        )
        .unwrap();
        let response = local_otlp_export_response(SnapshotSource::ClaudeCode, &encoded, &dir);
        assert_eq!(
            response.status, 200,
            "not granted: acknowledged, not stored"
        );
        grant_claude(&dir);
        let response = local_otlp_export_response(SnapshotSource::ClaudeCode, &encoded, &dir);
        assert_eq!(response.status, 400);
    });
    assert_eq!(counts.otlp_relay_bad_framing_400, 1);
    assert_eq!(counts.otlp_relay_collection_disabled, 1);
    assert_eq!(counts.otlp_relay_unknown_content_encoding, 1);
}

/// One scripted `accept` result for [`ScriptedAcceptor`].
enum AcceptStep {
    /// Fail with this errno, as the kernel would.
    Fail(i32),
    /// Accept a real pending connection.
    Accept,
}

/// A relay acceptor whose `accept` fails on cue, in front of a real
/// listener. Running out of script is a test failure: it means the loop
/// kept going after it should have given up.
struct ScriptedAcceptor {
    listener: TcpListener,
    steps: std::collections::VecDeque<AcceptStep>,
    draining: Option<bool>,
}

impl ScriptedAcceptor {
    fn new(steps: Vec<AcceptStep>, draining: Option<bool>) -> Self {
        Self {
            listener: TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind test listener"),
            steps: steps.into(),
            draining,
        }
    }

    fn connect_client(&self) -> TcpStream {
        let stream = TcpStream::connect(self.listener.local_addr().expect("local addr"))
            .expect("connect to the test listener");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("client read timeout");
        stream
    }
}

impl RelayAcceptor for ScriptedAcceptor {
    fn accept_stream(&mut self) -> io::Result<TcpStream> {
        match self
            .steps
            .pop_front()
            .expect("the accept loop kept going after its script ended")
        {
            AcceptStep::Fail(code) => Err(io::Error::from_raw_os_error(code)),
            AcceptStep::Accept => self.listener.accept().map(|(stream, _)| stream),
        }
    }

    fn draining(&self) -> Option<bool> {
        self.draining
    }
}

fn serve_marker(mut stream: TcpStream) {
    let _ = stream.write_all(b"served");
}

fn read_marker(mut client: TcpStream) -> Vec<u8> {
    let mut received = Vec::new();
    let _ = client.read_to_end(&mut received);
    received
}

#[test]
fn accept_loop_keeps_serving_after_per_connection_and_resource_errors() {
    // The incident: one ECONNABORTED ended the loop and the port stayed
    // dead until the daemon restarted. Every error before the final EBADF
    // must leave the loop serving.
    let mut acceptor = ScriptedAcceptor::new(
        vec![
            AcceptStep::Fail(libc::ECONNABORTED),
            AcceptStep::Accept,
            AcceptStep::Fail(libc::ECONNRESET),
            AcceptStep::Fail(libc::EINTR),
            AcceptStep::Fail(libc::EAGAIN),
            AcceptStep::Fail(libc::EMFILE),
            AcceptStep::Fail(libc::ENOBUFS),
            AcceptStep::Accept,
            AcceptStep::Fail(libc::EBADF),
        ],
        Some(false),
    );
    let first = acceptor.connect_client();
    let second = acceptor.connect_client();

    let mut served = 0;
    let failure = run_relay_accept_loop(&mut acceptor, &mut |stream| {
        served += 1;
        serve_marker(stream);
    });

    assert_eq!(served, 2);
    assert_eq!(read_marker(first), b"served");
    assert_eq!(read_marker(second), b"served");
    assert!(acceptor.steps.is_empty());
    assert!(
        matches!(&failure, RelayListenerFailure::Unusable(error) if error.raw_os_error() == Some(libc::EBADF)),
        "{failure}"
    );
}

#[test]
fn accept_loop_gives_up_on_a_draining_listener() {
    let mut acceptor = ScriptedAcceptor::new(
        vec![AcceptStep::Accept, AcceptStep::Fail(libc::ECONNABORTED)],
        Some(true),
    );
    let client = acceptor.connect_client();

    let failure = run_relay_accept_loop(&mut acceptor, &mut serve_marker);

    assert_eq!(read_marker(client), b"served");
    assert!(
        matches!(failure, RelayListenerFailure::Draining(_)),
        "{failure}"
    );
}

#[test]
fn accept_loop_rebinds_only_after_failures_with_no_success_between() {
    // Where the drain cannot be read, a run of failures with no accepted
    // connection is the signal. Aborts from clients that hung up early
    // are interleaved with successes and must never add up to it.
    let aborts = |count| (0..count).map(|_| AcceptStep::Fail(libc::ECONNABORTED));
    let limit = RELAY_ACCEPT_FAILURE_LIMIT as usize;
    let mut steps: Vec<AcceptStep> = aborts(limit - 1).collect();
    steps.push(AcceptStep::Accept);
    steps.extend(aborts(limit));
    let mut acceptor = ScriptedAcceptor::new(steps, None);
    let client = acceptor.connect_client();

    let failure = run_relay_accept_loop(&mut acceptor, &mut serve_marker);

    assert_eq!(read_marker(client), b"served");
    assert!(acceptor.steps.is_empty());
    assert!(
        matches!(
            failure,
            RelayListenerFailure::RepeatedFailures { count, .. }
                if count == RELAY_ACCEPT_FAILURE_LIMIT
        ),
        "{failure}"
    );
}

/// Drains a live relay listener the way XNU does (see
/// `unix_socket::tests::drain_listener`) and proves the supervisor reports
/// `Failed`, binds a fresh listener on the same port, reports `Connected`
/// again, and serves.
#[cfg(target_os = "macos")]
#[test]
fn supervisor_rebinds_a_drained_listener_on_the_same_port() {
    use std::sync::mpsc;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind relay");
    let addr = listener.local_addr().expect("relay addr");
    // SAFETY: dup of a descriptor we own; the copy is closed below.
    let duplicate = unsafe { libc::dup(listener.as_raw_fd()) };
    assert!(duplicate >= 0, "dup listener");

    let (state_tx, state_rx) = mpsc::channel();
    thread::spawn(move || {
        supervise_relay_listener(
            listener,
            |port, _attempt| {
                TcpListener::bind((Ipv4Addr::LOCALHOST, port)).context("rebind test relay")
            },
            move |state| {
                let _ = state_tx.send(state);
            },
            serve_marker,
        )
    });
    let served = || {
        TcpStream::connect_timeout(&addr, Duration::from_secs(1))
            .ok()
            .map(|client| {
                let _ = client.set_read_timeout(Some(Duration::from_secs(1)));
                read_marker(client) == b"served"
            })
            .unwrap_or(false)
    };
    assert!(served(), "the relay serves before the drain");

    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        // SAFETY: accept on an open listening descriptor; the peer address
        // is not requested.
        let rc = unsafe { libc::accept(duplicate, std::ptr::null_mut(), std::ptr::null_mut()) };
        let _ = done_tx.send((rc, io::Error::last_os_error().raw_os_error()));
    });
    thread::sleep(Duration::from_millis(200));
    // SAFETY: closes only the duplicate, while the thread above is blocked
    // in accept on it.
    unsafe { libc::close(duplicate) };
    assert_eq!(
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("closing the descriptor wakes the blocked accept"),
        (-1, Some(libc::ECONNABORTED)),
        "the listener must now be draining for this test to mean anything"
    );

    // A connection that reaches the drained listener is lost; the next
    // one must reach its replacement.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !served() {
        assert!(
            std::time::Instant::now() < deadline,
            "the relay never served again after the drain"
        );
        thread::sleep(Duration::from_millis(50));
    }

    let failed = state_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("failed state");
    assert_eq!(failed.state, RelayRuntimeState::Failed);
    assert_eq!(
        failed.last_error.map(|error| error.code).as_deref(),
        Some("relay_listener_failed")
    );
    let connected = state_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("connected state");
    assert_eq!(connected.state, RelayRuntimeState::Connected);
    assert_eq!(connected.endpoint, Some(format!("http://{addr}")));
}

pub(super) const CLAUDE_API_REQUEST_LOG: &[u8] = br#"{"resourceLogs":[{"resource":{"attributes":[{"key":"session.id","value":{"stringValue":"retired-forward-session"}}]},"scopeLogs":[{"logRecords":[{"timeUnixNano":"1783728000000000000","body":{"stringValue":"claude_code.api_request"},"attributes":[{"key":"request_id","value":{"stringValue":"req-retired-forward"}},{"key":"model","value":{"stringValue":"claude-opus-4-7"}},{"key":"effort","value":{"stringValue":"high"}},{"key":"input_tokens","value":{"intValue":"12"}},{"key":"output_tokens","value":{"intValue":"3"}},{"key":"prompt","value":{"stringValue":"must-not-persist"}}]}]}]}]}"#;
const CLAUDE_LLM_REQUEST_TRACE: &[u8] = br#"{"resourceSpans":[{"resource":{"attributes":[{"key":"session.id","value":{"stringValue":"retired-forward-session"}}]},"scopeSpans":[{"spans":[{"name":"claude_code.llm_request","startTimeUnixNano":"1783728000000000000","attributes":[{"key":"request_id","value":{"stringValue":"req-retired-forward"}},{"key":"client_request_id","value":{"stringValue":"client-req-retired-forward"}},{"key":"prompt","value":{"stringValue":"must-not-persist"}}]}]}]}]}"#;

fn otlp_post(path: &str, content_type: &str, body: &[u8]) -> HttpRequest {
    HttpRequest {
        method: "POST".to_string(),
        path: path.to_string(),
        headers: BTreeMap::from([("content-type".to_string(), content_type.to_string())]),
        body: body.to_vec(),
    }
}

/// Grant Claude to this support dir's device, as a connected install has.
pub(super) fn grant_claude(support_dir: &Path) {
    ottto_core::FileDeviceStore::new(
        support_dir.join(ottto_core::account_store::DEVICE_FILE_NAME),
    )
    .save(&ottto_core::LocalDeviceBinding {
        device_id: "device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    })
    .expect("save device grant");
}

/// [behaviour] Collection stops while Claude is not granted or is paused:
/// the export is acknowledged and nothing is appended. Once the pause
/// marker is gone, appends resume.
#[test]
fn claude_capture_stores_nothing_while_the_source_is_off() {
    let dir = crate::test_scratch::ScratchDir::new("relay-capture-off");
    let request = otlp_post("/v1/logs", "application/json", CLAUDE_API_REQUEST_LOG);
    let export = || {
        let response = local_otlp_export_response(SnapshotSource::ClaudeCode, &request, &dir);
        assert_export_success(&response, "application/json", b"{}");
        crate::claude_local_otel::load_claude_effort_evidence(
            &dir,
            ["retired-forward-session".to_string()],
        )
        .ok()
        .and_then(|evidence| evidence.get("retired-forward-session").map(Vec::len))
        .unwrap_or(0)
    };
    assert_eq!(export(), 0, "not granted");
    grant_claude(&dir);
    crate::snapshot_sync::disable_snapshot_source(&dir, SnapshotSource::ClaudeCode)
        .expect("pause Claude");
    assert_eq!(export(), 0, "paused");
    std::fs::remove_file(dir.join("snapshots/claude_code.source-disabled"))
        .expect("clear the pause marker");
    assert_eq!(export(), 1, "resumed");
}

fn assert_export_success(response: &LocalExportResponse, content_type: &str, body: &[u8]) {
    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, content_type);
    assert_eq!(response.body, body);
}

#[test]
fn retired_forward_keeps_claude_log_evidence_identical_to_direct_capture() {
    let relay_dir = crate::test_scratch::ScratchDir::new("relay-retired-logs");
    grant_claude(&relay_dir);
    let direct_dir = crate::test_scratch::ScratchDir::new("relay-retired-logs-direct");
    let request = otlp_post("/v1/logs", "application/json", CLAUDE_API_REQUEST_LOG);

    let response = local_otlp_export_response(SnapshotSource::ClaudeCode, &request, &relay_dir);
    crate::claude_local_otel::capture_claude_api_request_logs(
        &direct_dir,
        CLAUDE_API_REQUEST_LOG,
        "application/json",
    )
    .expect("direct capture succeeds");

    assert_export_success(&response, "application/json", b"{}");
    let session = ["retired-forward-session".to_string()];
    let relayed =
        crate::claude_local_otel::load_claude_effort_evidence(&relay_dir, session.clone())
            .expect("relayed evidence loads");
    let direct = crate::claude_local_otel::load_claude_effort_evidence(&direct_dir, session)
        .expect("direct evidence loads");
    assert_eq!(relayed["retired-forward-session"].len(), 1);
    assert_eq!(
        serde_json::to_value(&relayed).expect("serialize relayed"),
        serde_json::to_value(&direct).expect("serialize direct")
    );
    assert!(!serde_json::to_string(&relayed)
        .expect("serialize relayed")
        .contains("must-not-persist"));
}

#[test]
fn retired_forward_keeps_claude_trace_ownership_identical_to_direct_capture() {
    let relay_dir = crate::test_scratch::ScratchDir::new("relay-retired-traces");
    grant_claude(&relay_dir);
    let direct_dir = crate::test_scratch::ScratchDir::new("relay-retired-traces-direct");
    let request = otlp_post(
        "/v1/traces",
        "application/x-protobuf",
        CLAUDE_LLM_REQUEST_TRACE,
    );
    let json_request = otlp_post("/v1/traces", "application/json", CLAUDE_LLM_REQUEST_TRACE);

    // A protobuf exporter sending a JSON body is undecodable, not stored.
    let response = local_otlp_export_response(SnapshotSource::ClaudeCode, &request, &relay_dir);
    assert_eq!(response.status, 400);
    let response =
        local_otlp_export_response(SnapshotSource::ClaudeCode, &json_request, &relay_dir);
    crate::claude_local_otel::capture_claude_llm_request_traces(
        &direct_dir,
        CLAUDE_LLM_REQUEST_TRACE,
        "application/json",
    )
    .expect("direct capture succeeds");

    assert_export_success(&response, "application/json", b"{}");
    let session = ["retired-forward-session".to_string()];
    let relayed = crate::claude_local_otel::load_claude_trace_ownership_evidence(
        &relay_dir,
        session.clone(),
    );
    let direct =
        crate::claude_local_otel::load_claude_trace_ownership_evidence(&direct_dir, session);
    assert_eq!(relayed.evidence["retired-forward-session"].len(), 1);
    assert_eq!(relayed, direct);
}

#[test]
fn retired_forward_acknowledges_protobuf_exports_without_a_local_consumer() {
    let support_dir = crate::test_scratch::ScratchDir::new("relay-retired-ack");
    for (source, path) in [
        (SnapshotSource::ClaudeCode, "/v1/metrics"),
        (SnapshotSource::Codex, "/v1/logs"),
        (SnapshotSource::Codex, "/v1/traces"),
    ] {
        let request = otlp_post(path, "application/x-protobuf", b"\x0a\x00");
        let response = local_otlp_export_response(source, &request, &support_dir);
        assert_export_success(&response, "application/x-protobuf", b"");
    }
    assert_eq!(
        std::fs::read_dir(&*support_dir)
            .expect("scratch dir lists")
            .count(),
        0,
        "exports without a local consumer store nothing"
    );
}

#[test]
fn retired_forward_reports_local_failures_with_non_retryable_statuses() {
    let support_dir = crate::test_scratch::ScratchDir::new("relay-retired-failures");
    grant_claude(&support_dir);
    let malformed = otlp_post("/v1/logs", "application/json", b"{not json");
    let response =
        local_otlp_export_response(SnapshotSource::ClaudeCode, &malformed, &support_dir);
    assert_eq!(response.status, 400);

    // A regular file where the evidence directory should be makes the
    // evidence append fail after a successful decode.
    std::fs::write(support_dir.join("local-otel"), b"").expect("write blocking file");
    let request = otlp_post("/v1/logs", "application/json", CLAUDE_API_REQUEST_LOG);
    let response =
        local_otlp_export_response(SnapshotSource::ClaudeCode, &request, &support_dir);
    assert_eq!(response.status, 500);
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("JSON error body");
    assert_eq!(body["error"], "local_capture_failed");
}

#[test]
fn claude_rows_are_in_the_relay_journal_before_the_exporter_is_answered() {
    let support_dir = crate::test_scratch::ScratchDir::new("relay-journal-answer");
    grant_claude(&support_dir);
    let journal = crate::claude_local_otel::relay_journal_path_for_test(&support_dir);
    crate::claude_local_otel::keep_relay_rows_waiting_for_test(true);
    let request = otlp_post("/v1/logs", "application/json", CLAUDE_API_REQUEST_LOG);
    let response =
        local_otlp_export_response(SnapshotSource::ClaudeCode, &request, &support_dir);
    assert_export_success(&response, "application/json", b"{}");
    let stored = std::fs::read(&journal).expect("journal written before the answer");
    assert!(stored.starts_with(b"a{") && stored.ends_with(b"\n"));
    assert!(String::from_utf8_lossy(&stored).contains("req-retired-forward"));
    let unread = crate::claude_local_otel::load_claude_effort_evidence(
        &support_dir,
        ["retired-forward-session".to_string()],
    )
    .expect("per-session files read");
    assert!(
        unread.is_empty(),
        "rows reach the session file at the drain"
    );

    // A journal that cannot be appended to fails the request as today.
    std::fs::remove_file(&journal).expect("remove journal");
    std::fs::create_dir(&journal).expect("block journal");
    let response =
        local_otlp_export_response(SnapshotSource::ClaudeCode, &request, &support_dir);
    crate::claude_local_otel::keep_relay_rows_waiting_for_test(false);
    assert_eq!(response.status, 500);
}

#[test]
fn retired_forward_inflates_gzip_claude_exports_and_refuses_unknown_encodings() {
    use std::io::Write as _;
    let support_dir = crate::test_scratch::ScratchDir::new("relay-retired-gzip");
    grant_claude(&support_dir);
    let gzip_member = |bytes: &[u8]| {
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).expect("compress fixture");
        encoder.finish().expect("finish gzip")
    };
    // An empty first member must not hide the export in the next one.
    let mut body = gzip_member(b"");
    body.extend(gzip_member(CLAUDE_API_REQUEST_LOG));
    let mut request = otlp_post("/v1/logs", "application/json", &body);
    request
        .headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    let response =
        local_otlp_export_response(SnapshotSource::ClaudeCode, &request, &support_dir);
    assert_export_success(&response, "application/json", b"{}");
    let evidence = crate::claude_local_otel::load_claude_effort_evidence(
        &support_dir,
        ["retired-forward-session".to_string()],
    )
    .expect("gzip evidence loads");
    assert_eq!(evidence["retired-forward-session"].len(), 1);

    request
        .headers
        .insert("content-encoding".to_string(), "br".to_string());
    let response =
        local_otlp_export_response(SnapshotSource::ClaudeCode, &request, &support_dir);
    assert_eq!(response.status, 400);
}
