/// [regress] A pass that ends without a finish (prepare had nothing to
/// do) closes at the cycle owner's outcome: a later off-pass window is clean.
#[test]
fn cycle_outcome_closes_unfinished_pass_for_offpass_overlap() {
    use crate::local_resource_diagnostics::{capture, source_prepare, StageWindow};
    use crate::source_rotation::Owner as _;
    let client = SnapshotApiClient::new("http://127.0.0.1:9");
    let device = LocalDeviceBinding {
        device_id: "device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["codex".into()],
    };
    let daemon = test_daemon("otm_test");
    let mut transport_cycle = crate::net_resilience::TransportCycleOutcome::default();
    let mut failed_sources = Vec::new();
    let mut owner = SnapshotCycleOwner {
        account_witness: [0; 32],
        client: &client,
        device: &device,
        device_secret: "secret",
        machine_id: "otm_test",
        home: Path::new("/nonexistent-home"),
        support_dir: Path::new("/nonexistent-support"),
        daemon: &daemon,
        transport_cycle: &mut transport_cycle,
        failed_sources: &mut failed_sources,
        started: Instant::now(),
        codex_started: None,
        paced_qos: None,
    };
    let quota = || drop(StageWindow::begin("codex", "offpass_codex_quota"));
    let (_, rows) = capture(|| {
        source_prepare("codex", || None::<()>, |_| false);
        quota(); // the pass is open
        owner.outcome(SnapshotSource::Codex, Ok(()));
        quota(); // clean once the outcome closed it
        source_prepare("unknown", || (), |_| false); // flushes
    });
    let flags: Vec<_> = rows
        .iter()
        .filter(|row| row["stage"] == "offpass_codex_quota")
        .map(|row| {
            (
                row["counts"]["count"].as_u64(),
                row["counts"].get("pass_overlap").cloned(),
            )
        })
        .collect();
    assert_eq!(flags, [(Some(1), None), (Some(1), Some(true.into()))]);
}

fn agent_status_upload_server(captured: Arc<Mutex<Vec<String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent status backend");
    let address = listener.local_addr().expect("local address");
    std::thread::spawn(move || {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept agent status request");
            let request = read_complete_http_request(&mut stream);
            captured
                .lock()
                .expect("capture agent status request")
                .push(request);
            let body = if index == 0 {
                r#"{"token":"relay-token-codex","expires_at":"2026-06-01T10:15:00Z"}"#
            } else {
                r#"{"accepted":1,"machine_id":"otm_test","sources":["codex"]}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write agent status response");
        }
    });
    format!("http://{address}")
}

fn agent_status_partial_failure_server(captured: Arc<Mutex<Vec<String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent status backend");
    let address = listener.local_addr().expect("local address");
    std::thread::spawn(move || {
        for index in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept agent status request");
            let request = read_complete_http_request(&mut stream);
            captured
                .lock()
                .expect("capture agent status request")
                .push(request);
            let (status, body) = match index {
                0 => ("500 Internal Server Error", r#"{"error":"temporary"}"#),
                1 => (
                    "200 OK",
                    r#"{"token":"relay-token-claude","expires_at":"2026-06-01T10:15:00Z"}"#,
                ),
                _ => (
                    "200 OK",
                    r#"{"accepted":1,"machine_id":"otm_test","sources":["claude_code"]}"#,
                ),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write agent status response");
        }
    });
    format!("http://{address}")
}

fn local_health_reactivation_server(
    captured: Arc<Mutex<Vec<String>>>,
    reject_retry: bool,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local health backend");
    let address = listener.local_addr().expect("local address");
    std::thread::spawn(move || {
        for index in 0..if reject_retry { 3 } else { 5 } {
            let (mut stream, _) = listener.accept().expect("accept local health request");
            let request = read_complete_http_request(&mut stream);
            captured
                .lock()
                .expect("capture local health request")
                .push(request);
            let (status, body) = match index {
                0 => ("403 Forbidden", r#"{"error":"inactive"}"#),
                1 => (
                    "200 OK",
                    r#"{"setup_run_id":"setup_fresh","setup_run_token":"otsr_fresh","expires_at":"2026-06-11T18:30:00Z"}"#,
                ),
                2 if reject_retry => ("401 Unauthorized", r#"{"error":"still inactive"}"#),
                2 => (
                    "200 OK",
                    r#"{"token":"relay-token-codex","expires_at":"2026-06-01T10:15:00Z"}"#,
                ),
                _ => ("200 OK", r#"{"ok":true}"#),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write local health response");
        }
    });
    format!("http://{address}")
}

/// Answers relay tokens and projections, and each heartbeat with the
/// next of `replies` (then `{}`).
fn source_control_heartbeat_server(
    captured: Arc<Mutex<Vec<String>>>,
    replies: Vec<serde_json::Value>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind source control backend");
    let address = listener.local_addr().expect("local address");
    std::thread::spawn(move || {
        let mut replies = replies.into_iter();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let request = read_complete_http_request(&mut stream);
            let body = if request.contains("/relay-token") {
                serde_json::json!({"token": "relay-token-codex", "expires_at": "2026-06-01T10:15:00Z"})
            } else if request.contains("/apps/health/heartbeat") {
                replies.next().unwrap_or_else(|| serde_json::json!({}))
            } else {
                serde_json::json!({"ok": true})
            }
            .to_string();
            captured.lock().expect("capture request").push(request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{address}")
}

fn snapshot_status_server(captured: Arc<Mutex<Vec<String>>>) -> String {
    snapshot_status_server_with_hints(captured, vec![30])
}

fn snapshot_status_server_with_hints(captured: Arc<Mutex<Vec<String>>>, hints: Vec<u64>) -> String {
    snapshot_status_server_with_hint_extras(
        captured,
        hints.into_iter().map(|days| (days, "")).collect(),
    )
}

/// One `(backfill_window_days, extra JSON members)` pair per receipt; the
/// extra members are appended verbatim to the activity hint body.
fn snapshot_status_server_with_hint_extras(
    captured: Arc<Mutex<Vec<String>>>,
    hints: Vec<(u64, &'static str)>,
) -> String {
    snapshot_status_server_with_hint_extras_and_batch(captured, hints, None)
}

fn snapshot_status_server_with_hint_extras_and_batch(
    captured: Arc<Mutex<Vec<String>>>,
    hints: Vec<(u64, &'static str)>,
    batch: Option<Vec<SnapshotItem>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind snapshot status backend");
    let address = listener.local_addr().expect("local address");
    std::thread::spawn(move || {
        let receipt_count = hints.len();
        let mut hints = hints.into_iter();
        let mut ordinary_requests = receipt_count * 3;
        loop {
            let (mut stream, _) = listener.accept().expect("accept snapshot status request");
            let request = read_complete_http_request(&mut stream);
            // A batch fixture exercises ordinary uploads and fresh relay
            // acquisition too; its terminal status ends the conversation.
            let terminal = batch.is_some()
                && request.starts_with("POST /api/v1/agent-session-snapshots/status ");
            let body = if request.contains("/telemetry/devices/") {
                captured
                    .lock()
                    .expect("capture snapshot status request")
                    .push(request);
                r#"{"token":"relay-token-codex","expires_at":"2026-06-01T10:15:00Z"}"#.to_string()
            } else if request.contains("/agent-session-snapshots/batches") {
                let items = batch.as_ref().expect("expected snapshot upload");
                let entities = items
                    .iter()
                    .map(|item| {
                        let version =
                            crate::snapshot_client::snapshot_ack_body_witness_version(item)
                                .unwrap();
                        serde_json::json!({"source_session_id":item.source_session_id,
                        "snapshot_fingerprint":item.snapshot_fingerprint,"occurrence_count":1,
                        "body_witness_version":version,
                        "body_witness_digest":version.map(|_|snapshot_upload_body_witness(item))})
                    })
                    .collect::<Vec<_>>();
                captured.lock().unwrap().push(request);
                serde_json::json!({"accepted":items.len(),"sessions_reconciled":items.len(),
                    "session_ids":[],"disabled":false,"disabled_reason":null,
                    "entity_ack_contract":crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
                    "accepted_entities":entities})
                .to_string()
            } else if request.contains("/activity-hints") {
                let (hint, extra) = hints.next().expect("one hint per receipt");
                format!(
                    r#"{{"source":"codex","server_time":"2026-06-01T10:00:00Z","last_data_at":null,"record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,"backfill_window_days":{hint}{extra},"recommended_scan_after":"2026-06-01T10:05:00Z"}}"#
                )
            } else {
                captured
                    .lock()
                    .expect("capture snapshot status request")
                    .push(request);
                r#"{"accepted":true,"source":"codex","machine_id":"otm_test","disabled":false}"#
                    .to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write snapshot status response");
            if terminal {
                break;
            }
            if batch.is_none() {
                ordinary_requests -= 1;
                if ordinary_requests == 0 {
                    break;
                }
            }
        }
    });
    format!("http://{address}")
}

fn http_request_json(request: &str) -> serde_json::Value {
    serde_json::from_str(request.split("\r\n\r\n").nth(1).expect("HTTP request body"))
        .expect("JSON request body")
}

fn read_complete_http_request(stream: &mut std::net::TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                request.extend_from_slice(&buffer[..bytes_read]);
                if http_request_complete(&request) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    decoded_http_request(&request)
}

// For server fixtures that inspect decoded JSON.
fn decoded_http_request(request: &[u8]) -> String {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return String::from_utf8_lossy(request).into_owned();
    };
    let headers = std::str::from_utf8(&request[..header_end]).unwrap();
    if !headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("Content-Encoding: gzip"))
    {
        return String::from_utf8_lossy(request).into_owned();
    }
    let mut body = String::new();
    flate2::read::GzDecoder::new(&request[header_end + 4..])
        .read_to_string(&mut body)
        .expect("decode gzip fixture request");
    let headers = headers
        .lines()
        .filter(|line| {
            !line.split_once(':').is_some_and(|(name, _)| {
                name.eq_ignore_ascii_case("Content-Length")
                    || name.eq_ignore_ascii_case("Content-Encoding")
            })
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    format!("{headers}\r\nContent-Length: {}\r\n\r\n{body}", body.len())
}

fn http_request_complete(request: &[u8]) -> bool {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    content_length
        .map(|length| request.len() >= body_start + length)
        .unwrap_or(true)
}

/// Pending cache head whose current head was offered on a saved cycle and
/// answered "unchanged": the ACK carries the server's body, not the request's.
fn unchanged_head_answer_progress() -> (ScanIndex, SnapshotItem, SnapshotUploadProgress, String) {
    let (index, mut item) = pending_head_index_item();
    let mut progress = test_upload_progress();
    progress
        .record_pending_cache_head(&item, &cache_head_file_groups(&index), true)
        .unwrap();
    let session = cache_session_key(&item.source_session_id);
    let head = "e".repeat(64);
    progress
        .accepted_cache_heads
        .insert(session.clone(), head.clone());
    progress
        .accepted_fingerprints
        .insert(item.snapshot_fingerprint.clone());
    progress.record_body(&item.snapshot_fingerprint, &"f".repeat(64));
    item.cache_base_head_etag = Some(head);
    (index, item, progress, session)
}

/// [money] Same cycle as the head-bearing offer: the exact-body rule still
/// decides, and an "unchanged" ACK does not settle there.
#[test]
fn cache_pending_head_unchanged_answer_same_cycle_keeps_row() {
    let (index, item, mut progress, session) = unchanged_head_answer_progress();
    let retired = progress.retire_pending_cache_heads(
        &index,
        std::slice::from_ref(&item),
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert_eq!(retired, 0);
    assert_eq!(progress.pending_cache_heads.len(), 1);
    let pending = progress.pending_cache_heads.values().next().unwrap();
    assert_eq!(
        pending.reselected_heads.get(&session),
        Some(&cache_head_selection_witness(&"e".repeat(64))),
        "the offer recorded its head, so reselect will not select the file again"
    );
}

/// [money] RED on main: a later cycle settles the exhausted row instead of
/// keeping a permanent pending cache head.
#[test]
fn cache_pending_head_unchanged_answer_retires_on_later_cycle() {
    let (index, item, mut progress, _) = unchanged_head_answer_progress();
    progress.retire_pending_cache_heads(
        &index,
        std::slice::from_ref(&item),
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    let mut reselect_index = index.clone();
    assert_eq!(
        progress.reselect_pending_cache_heads(&mut reselect_index, true),
        0
    );
    let retired = progress.retire_pending_cache_heads(
        &index,
        &[],
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert!(progress.pending_cache_heads.is_empty());
    assert_eq!(retired, 1);
}

/// [money] A newer accepted head is still owed: the row stays and reselect
/// selects the file for the new head.
#[test]
fn cache_pending_head_advanced_head_keeps_row_and_reselects() {
    let (index, item, mut progress, session) = unchanged_head_answer_progress();
    progress.retire_pending_cache_heads(
        &index,
        std::slice::from_ref(&item),
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    progress
        .accepted_cache_heads
        .insert(session, "9".repeat(64));
    let retired = progress.retire_pending_cache_heads(
        &index,
        &[],
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert_eq!(retired, 0);
    assert_eq!(progress.pending_cache_heads.len(), 1);
    let mut reselect_index = index.clone();
    assert_eq!(
        progress.reselect_pending_cache_heads(&mut reselect_index, true),
        1
    );
}

/// [money] A retryable quarantine still owns the body: the row stays.
#[test]
fn cache_pending_head_quarantined_entity_keeps_row() {
    let (index, item, mut progress, _) = unchanged_head_answer_progress();
    progress.retire_pending_cache_heads(
        &index,
        std::slice::from_ref(&item),
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    progress.quarantine_retryable_body(
        &item.snapshot_fingerprint,
        &snapshot_upload_body_witness(&item),
        u64::MAX,
    );
    progress
        .accepted_fingerprints
        .insert(item.snapshot_fingerprint.clone());
    let retired = progress.retire_pending_cache_heads(
        &index,
        &[],
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert_eq!(retired, 0);
    assert_eq!(progress.pending_cache_heads.len(), 1);
}
