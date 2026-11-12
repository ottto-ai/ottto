// In-place resend of short, explicitly transient batch-upload failures.
// Driver-level fakes plus one real prepare/finish Claude cycle against a
// loopback backend. Every response, transcript and credential is synthetic.
use super::*;

type BatchResponse = crate::snapshot_client::SnapshotBatchResponse;

fn shed(retry_after_seconds: Option<u64>) -> anyhow::Error {
    anyhow::Error::new(UploadShed {
        status: 503,
        retry_after: retry_after_seconds.map(Duration::from_secs),
        code: None,
    })
}

fn batch_server_error(status: u16) -> anyhow::Error {
    anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
        "local snapshot upload",
        "snapshot_batch",
        status,
        true,
    ))
}

struct Driven {
    result: Result<ResumableUploadResult>,
    posts: Vec<Vec<String>>,
    progress: SnapshotUploadProgress,
    waits: Vec<Duration>,
}

/// Drive the real batch loop over `count` synthetic fingerprints. `respond`
/// answers each POST by its zero-based attempt number.
fn drive(
    count: usize,
    failed_after: Option<Duration>,
    mut respond: impl FnMut(usize, &[String]) -> Result<BatchResponse>,
) -> Driven {
    let items = test_fingerprints(count);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut posts = Vec::new();
    let (result, waits) = with_inplace_retry_test_clock(failed_after, || {
        upload_resumable_batches(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                let attempt = posts.len();
                posts.push(batch.clone());
                respond(attempt, &batch)
            },
            |_| Ok(()),
        )
    });
    Driven {
        result,
        posts,
        progress,
        waits,
    }
}

/// A shed whose Retry-After is at most 5 s is resent in place after the
/// server's own wait (plus at most 20 %, never past 5 s), and the page settles
/// exactly as a first-try success would.
#[test]
#[serial(client_report)]
fn short_retry_after_shed_is_retried_in_place_and_settles() {
    for (status, retry_after, lowest, highest) in [
        (503, 1, 1_000, 1_200),
        (429, 1, 1_000, 1_200),
        (503, 5, 5_000, 5_000),
    ] {
        let driven = drive(3, None, |attempt, batch| match attempt {
            0 => Err(anyhow::Error::new(UploadShed {
                status,
                retry_after: Some(Duration::from_secs(retry_after)),
                code: None,
            })),
            _ => Ok(accepted_batch(batch.len())),
        });
        assert_eq!(
            driven.result.unwrap(),
            ResumableUploadResult::Completed,
            "{status} Retry-After {retry_after}"
        );
        assert_eq!(driven.posts.len(), 2);
        assert_eq!(
            driven.posts[0], driven.posts[1],
            "the resend is the same page"
        );
        assert_eq!(driven.waits.len(), 1);
        assert!(
            (Duration::from_millis(lowest)..=Duration::from_millis(highest))
                .contains(&driven.waits[0]),
            "{status} Retry-After {retry_after}: waited {:?}",
            driven.waits[0]
        );
        assert_eq!(driven.progress.accepted_fingerprints.len(), 3);
    }
}

/// T2: a fast 500 or 502 from the batch endpoint is resent in place.
#[test]
#[serial(client_report)]
fn fast_server_error_is_retried_in_place_and_settles() {
    for status in [500, 502] {
        let driven = drive(3, None, |attempt, batch| match attempt {
            0 => Err(batch_server_error(status)),
            _ => Ok(accepted_batch(batch.len())),
        });
        assert_eq!(
            driven.result.unwrap(),
            ResumableUploadResult::Completed,
            "HTTP {status}"
        );
        assert_eq!(driven.posts.len(), 2);
        assert_eq!(driven.posts[0], driven.posts[1]);
        assert_eq!(driven.waits.len(), 1);
        assert!(
            (Duration::from_secs(2)..=Duration::from_millis(2_400)).contains(&driven.waits[0]),
            "HTTP {status}: waited {:?}",
            driven.waits[0]
        );
        assert_eq!(driven.progress.accepted_fingerprints.len(), 3);
    }
}

/// T3: earlier pages stay checkpointed; the resend carries exactly the
/// failed page's still-unsettled bodies, then the pass continues.
#[test]
#[serial(client_report)]
fn inplace_retry_resends_only_unsettled_bodies() {
    let items = test_fingerprints(75);
    let driven = drive(75, None, |attempt, batch| match attempt {
        1 => Err(shed(Some(1))),
        _ => Ok(accepted_batch(batch.len())),
    });
    assert_eq!(driven.result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(
        driven.posts,
        vec![
            items[..SNAPSHOT_BATCH_LIMIT].to_vec(),
            items[SNAPSHOT_BATCH_LIMIT..].to_vec(),
            items[SNAPSHOT_BATCH_LIMIT..].to_vec(),
        ]
    );
    assert_eq!(driven.progress.accepted_fingerprints.len(), 75);
}

/// T5: at most two resends and 10 s of waiting per upload call, across all of
/// its pages. A failure that outlasts the budget takes today's path unchanged.
#[test]
#[serial(client_report)]
fn inplace_retry_is_bounded() {
    let driven = drive(3, None, |_, _| Err(shed(Some(1))));
    assert_eq!(
        driven.result.unwrap(),
        ResumableUploadResult::Shed {
            retry_after: Some(Duration::from_secs(1))
        }
    );
    assert_eq!(driven.posts.len(), 3);
    assert_eq!(driven.waits.len(), 2);
    assert!(driven.waits.iter().sum::<Duration>() <= Duration::from_secs(10));
    assert!(driven.progress.accepted_fingerprints.is_empty());

    let driven = drive(3, None, |_, _| Err(batch_server_error(500)));
    let error = driven.result.unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<UploadFailureDiagnostics>()
            .map(UploadFailureDiagnostics::status_family),
        Some("http_5xx"),
        "the last error is returned unchanged"
    );
    assert_eq!(driven.posts.len(), 3);
    assert_eq!(driven.waits.len(), 2);

    // The budget is per call, not per page: page one spends one resend, so
    // page two gets only one more before the shed stands.
    let driven = drive(75, None, |attempt, batch| match attempt {
        0 | 2 | 3 => Err(shed(Some(1))),
        _ => Ok(accepted_batch(batch.len())),
    });
    assert_eq!(
        driven.result.unwrap(),
        ResumableUploadResult::Shed {
            retry_after: Some(Duration::from_secs(1))
        }
    );
    assert_eq!(
        driven.posts.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50, 50, 25, 25]
    );
    assert_eq!(driven.waits.len(), 2);
    assert_eq!(
        driven.progress.accepted_fingerprints.len(),
        SNAPSHOT_BATCH_LIMIT,
        "the recovered first page stays checkpointed"
    );
}

fn never_retried_failure(name: &str) -> anyhow::Error {
    match name {
        "400" => anyhow::Error::new(BatchRejected {
            status: 400,
            snapshot_indexes: None,
        }),
        "422" => anyhow::Error::new(BatchRejected {
            status: 422,
            snapshot_indexes: None,
        }),
        "401" => anyhow::Error::new(BatchAuthorizationRejected { status: 401 }),
        "403" => anyhow::Error::new(BatchAuthorizationRejected { status: 403 }),
        "409" => batch_server_error(409),
        "single-item 504" => batch_server_error(504),
        "503 outside the shed class" => batch_server_error(503),
        "transport" => anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "transport_connection",
            true,
            false,
        )),
        "relay token 500" => anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
            "relay token request",
            "relay_token",
            500,
            true,
        )),
        "ack decode" => anyhow::Error::new(SnapshotAckRejected {
            reason: "snapshot batch response could not be decoded",
        }),
        "authority" => anyhow!("snapshot destination changed"),
        other => unreachable!("unknown failure {other}"),
    }
}

/// T7: no 4xx, transport, relay-token, ACK, authority or disabled outcome is
/// ever resent in place, and a multi-item 504 still bisects.
#[test]
#[serial(client_report)]
fn never_retried_in_place() {
    for name in [
        "400",
        "422",
        "401",
        "403",
        "409",
        "single-item 504",
        "503 outside the shed class",
        "transport",
        "relay token 500",
        "ack decode",
        "authority",
    ] {
        let driven = drive(1, None, |attempt, batch| match attempt {
            0 => Err(never_retried_failure(name)),
            _ => Ok(accepted_batch(batch.len())),
        });
        assert!(driven.result.is_err(), "{name}");
        assert_eq!(driven.posts.len(), 1, "{name}");
        assert!(driven.waits.is_empty(), "{name}");
        assert!(driven.progress.accepted_fingerprints.is_empty(), "{name}");
    }

    let driven = drive(1, None, |_, _| {
        let mut response = accepted_batch(0);
        response.disabled = true;
        Ok(response)
    });
    assert_eq!(
        driven.result.unwrap(),
        ResumableUploadResult::Disabled(None)
    );
    assert_eq!(driven.posts.len(), 1);

    // A conflict inside a 200 is not an error: it keeps its bounded
    // quarantine and is never resent in place.
    let driven = drive(2, None, |_, batch| {
        Ok(entity_ack_batch(&batch[..1], &[], &batch[1..]))
    });
    assert_eq!(
        driven.result.unwrap(),
        ResumableUploadResult::Deferred {
            count: 1,
            isolated: 1
        }
    );
    assert_eq!(driven.posts.len(), 1);
    assert!(driven.waits.is_empty());

    let driven = drive(4, None, |_, batch| {
        if batch.len() == 4 {
            Err(batch_server_error(504))
        } else {
            Ok(accepted_batch(batch.len()))
        }
    });
    assert_eq!(driven.result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(
        driven.posts.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![4, 2, 2],
        "a multi-item 504 keeps the existing bisect"
    );
    assert!(driven.waits.is_empty());
}

/// T7: a head-CAS bootstrap probe that met a fast 500 is resent once. When
/// the first write had in fact applied, the resend sees a CAS conflict and
/// the probe is quarantined as today's next-cycle replay would leave it,
/// never double-acknowledged.
#[test]
#[serial(client_report)]
fn bootstrap_probe_resent_after_server_error_settles_as_conflict() {
    let (_, mut probe) = pending_head_index_item();
    probe.cache_observations = None;
    probe.cache_observations_state = None;
    let mut progress = test_upload_progress();
    let mut posts = 0;
    let (deferred, waits) = with_inplace_retry_test_clock(None, || {
        bootstrap_cache_heads(
            std::slice::from_ref(&probe),
            &unique_poison_scope(),
            &mut progress,
            false,
            |items, enforce_head_cas| {
                assert!(enforce_head_cas);
                posts += 1;
                if posts == 1 {
                    return Err(batch_server_error(500));
                }
                let mut response = accepted_batch(0);
                response.entity_ack_contract =
                    Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into());
                response
                    .conflict_entities
                    .push(crate::snapshot_client::SnapshotEntityRef {
                        source_session_id: items[0].source_session_id.clone(),
                        snapshot_fingerprint: items[0].snapshot_fingerprint.clone(),
                        occurrence_count: 1,
                        unchanged_basis: None,
                        retained_proof_missing: Vec::new(),
                        body_witness_version: None,
                        body_witness_digest: None,
                        head_etag: None,
                        head_challenge: None,
                        cache_observations_state: None,
                    });
                Ok(response)
            },
            |_| Ok(()),
        )
    });
    assert_eq!(deferred.unwrap(), 0);
    assert_eq!(posts, 2);
    assert_eq!(waits.len(), 1);
    assert!(!progress
        .accepted_fingerprints
        .contains(&probe.snapshot_fingerprint));
    assert!(progress
        .quarantined_fingerprints
        .contains_key(&probe.snapshot_fingerprint));
    assert!(progress.accepted_cache_heads.is_empty());
}

/// T9: each resend re-runs the upload boundary. An account switch during the
/// wait fails that boundary; the result is that error and nothing is ACKed.
#[test]
#[serial(client_report)]
fn account_switch_during_inplace_wait_aborts() {
    let driven = drive(2, None, |attempt, _| match attempt {
        0 => Err(shed(Some(1))),
        _ => Err(anyhow!("snapshot destination changed during upload")),
    });
    let error = driven.result.unwrap_err();
    assert!(
        error.to_string().contains("destination changed"),
        "{error:#}"
    );
    assert_eq!(driven.posts.len(), 2);
    assert_eq!(driven.waits.len(), 1);
    assert!(driven.progress.accepted_fingerprints.is_empty());
}

// --- Client to driver: a shed's backend code reaches the admission ---

/// A loopback batch endpoint that answers every POST with the backend's
/// error envelope: `status`, `Retry-After` and one fixed `code`.
struct EnvelopeShedServer {
    url: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    posts: Arc<std::sync::atomic::AtomicUsize>,
}

impl EnvelopeShedServer {
    fn new(status: u16, retry_after_seconds: u64, code: &'static str) -> Self {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let posts = Arc::new(AtomicUsize::new(0));
        let counted = posts.clone();
        let reason = if status == 429 {
            "Too Many Requests"
        } else {
            "Service Unavailable"
        };
        let body = serde_json::json!({
            "error": "ServiceOverloadedError",
            "detail": "Synthetic temporary deferral",
            "request_id": "synthetic-envelope-request",
            "code": code,
        })
        .to_string();
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic envelope shed accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let request = read_complete_http_request(&mut stream);
                assert!(http_request_complete(request.as_bytes()));
                counted.fetch_add(1, Ordering::SeqCst);
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nRetry-After: {retry_after_seconds}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            posts,
        }
    }
}

impl Drop for EnvelopeShedServer {
    fn drop(&mut self) {
        super::permanent_finish_pipeline_tests::stop_server(&self.stop, &mut self.worker);
    }
}

/// Drive the real batch loop whose every POST goes through the real
/// `SnapshotApiClient` to a loopback endpoint that always sheds with `code`.
/// Returns the driver's view, the POSTs the endpoint received during the
/// drive, and the typed shed of one further direct client POST.
fn drive_through_client(
    status: u16,
    retry_after_seconds: u64,
    code: &'static str,
) -> (Driven, usize, UploadShed) {
    let server = EnvelopeShedServer::new(status, retry_after_seconds, code);
    let client = SnapshotApiClient::new(server.url.clone());
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "claude_code".into(),
        machine_id: "otm_test".into(),
        collector_version: None,
        snapshots: Vec::new(),
        upload_policy: crate::snapshots::SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let driven = drive(3, None, |_, _| {
        client.upload_batch("synthetic-inplace-token", &request, false)
    });
    let received = server.posts.load(std::sync::atomic::Ordering::SeqCst);
    let shed = client
        .upload_batch("synthetic-inplace-token", &request, false)
        .unwrap_err()
        .downcast_ref::<UploadShed>()
        .copied()
        .expect("the client keeps the shed typed");
    (driven, received, shed)
}

/// The identity deferral is recognized by its fixed body code and never
/// resent in place, whatever Retry-After accompanies it: it keeps today's
/// single-POST shed and its backoff.
#[test]
#[serial(client_report)]
fn identity_shed_code_is_never_retried_in_place_through_the_client() {
    for retry_after in [1, 5, 60] {
        let (driven, received, shed) =
            drive_through_client(503, retry_after, "snapshot_original_identity_unavailable");
        assert_eq!(
            shed.code,
            Some(crate::snapshot_client::UploadShedCode::OriginalIdentityUnavailable)
        );
        assert!(shed.is_original_identity_unavailable());
        assert_eq!(
            shed.code
                .map(crate::snapshot_client::UploadShedCode::as_str),
            Some(crate::snapshot_client::SNAPSHOT_ORIGINAL_IDENTITY_UNAVAILABLE)
        );
        assert_eq!(shed.retry_after, Some(Duration::from_secs(retry_after)));
        assert_eq!(
            driven.result.unwrap(),
            ResumableUploadResult::Shed {
                retry_after: Some(Duration::from_secs(retry_after))
            },
            "identity Retry-After {retry_after}"
        );
        assert_eq!(received, 1, "identity Retry-After {retry_after}");
        assert_eq!(driven.posts.len(), 1, "identity Retry-After {retry_after}");
        assert!(
            driven.waits.is_empty(),
            "identity Retry-After {retry_after}"
        );
        assert!(driven.progress.accepted_fingerprints.is_empty());
    }
}

/// Ordinary cursor and lock contention sheds carry their own codes with
/// `Retry-After: 1`; they are still resent in place, up to the budget.
#[test]
#[serial(client_report)]
fn cursor_and_lock_shed_codes_are_retried_in_place_through_the_client() {
    for code in [
        "cursor_allocation_timeout",
        "accept_discovery_shared_lock_timeout",
        "accepted_log_head_conflict",
    ] {
        let (driven, received, shed) = drive_through_client(503, 1, code);
        assert_eq!(shed.code, None, "{code} is not a recognized code");
        assert_eq!(
            driven.result.unwrap(),
            ResumableUploadResult::Shed {
                retry_after: Some(Duration::from_secs(1))
            },
            "{code}: the shed stands once the budget is spent"
        );
        assert_eq!(received, 3, "{code}: one POST and two resends");
        assert_eq!(driven.posts.len(), 3, "{code}");
        assert_eq!(driven.waits.len(), 2, "{code}");
        for wait in &driven.waits {
            assert!(
                (Duration::from_secs(1)..=Duration::from_millis(1_200)).contains(wait),
                "{code}: waited {wait:?}"
            );
        }
    }
}

// --- T4: one real Claude prepare/finish cycle against a loopback backend ---

/// How the loopback backend answers snapshot batch POSTs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatchFault {
    /// Every batch is accepted.
    None,
    /// The first batch POST is answered `503` with `Retry-After: 1`, the
    /// cursor-allocation class.
    FirstShedRetryAfterOne,
    /// Every batch: a plain `503` with no `Retry-After` and no named item.
    PlainShed,
    /// Every batch: HTTP `500`.
    ServerError,
    /// Every batch: the connection closes with no response.
    Dropped,
}

struct InplaceRetryServer {
    url: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    /// Every batch POST's snapshots, in order, across every cycle.
    batch_posts: Arc<Mutex<Vec<Vec<serde_json::Value>>>>,
    fault: Arc<Mutex<BatchFault>>,
    terminal: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl InplaceRetryServer {
    fn new(fault: BatchFault) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let batch_posts = Arc::new(Mutex::new(Vec::new()));
        let posts = batch_posts.clone();
        let fault = Arc::new(Mutex::new(fault));
        let faults = fault.clone();
        let terminal = Arc::new(Mutex::new(Vec::new()));
        let statuses = terminal.clone();
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic in-place retry accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let request = read_complete_http_request(&mut stream);
                assert!(http_request_complete(request.as_bytes()));
                let raw = request.split_once("\r\n\r\n").unwrap().1;
                let value: serde_json::Value = if raw.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_str(raw).unwrap()
                };
                let response = if request.contains("/relay-token") {
                    serde_json::json!({"token":"synthetic-inplace-token","expires_at":"2099-01-01T00:00:00Z"})
                } else if request.contains("/activity-hints") {
                    serde_json::json!({"source":"claude_code","server_time":current_rfc3339(),
                        "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
                        "local_usage_reconciliation_enabled":true,"backfill_window_days":183,
                        "recommended_scan_after":"2099-01-01T00:00:00Z"})
                } else if request.contains("/agent-status/snapshots") {
                    serde_json::json!({"accepted":1,"machine_id":"otm_test","sources":["claude_code"]})
                } else if let Some(items) = value.get("snapshots").and_then(|v| v.as_array()) {
                    let first = {
                        let mut posts = posts.lock().unwrap();
                        posts.push(items.clone());
                        posts.len() == 1
                    };
                    let failure = match *faults.lock().unwrap() {
                        BatchFault::FirstShedRetryAfterOne if first => {
                            Some("503 Service Unavailable\r\nRetry-After: 1")
                        }
                        BatchFault::PlainShed => Some("503 Service Unavailable"),
                        BatchFault::ServerError => Some("500 Internal Server Error"),
                        BatchFault::Dropped => {
                            drop(stream);
                            continue;
                        }
                        _ => None,
                    };
                    if let Some(status) = failure {
                        let body = r#"{"detail":"cursor_allocation_timeout"}"#;
                        write!(
                            stream,
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .unwrap();
                        continue;
                    }
                    let entities = items
                        .iter()
                        .map(|item| {
                            let mut payload = serde_json::Map::new();
                            for key in [
                                "session_account_evidence",
                                "tool_usage",
                                "tool_usage_truncated",
                            ] {
                                if let Some(value) = item.get(key) {
                                    payload.insert(key.into(), value.clone());
                                }
                            }
                            let exclusive = item
                                .get("usage_accounting_contract")
                                .and_then(|v| v.as_str())
                                == Some("session_exclusive_reported_usage:v1");
                            let version = item
                                .get("session_account_evidence")
                                .is_some()
                                .then_some(if exclusive { 8u64 } else { 7u64 });
                            let digest = format!(
                                "{:x}",
                                Sha256::digest(
                                    crate::canonical_json::canonicalize(
                                        &serde_json::Value::Object(payload)
                                    )
                                    .unwrap()
                                )
                            );
                            serde_json::json!({"source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],"occurrence_count":1,
                                "body_witness_version":version,"body_witness_digest":version.map(|_|digest)})
                        })
                        .collect::<Vec<_>>();
                    serde_json::json!({"accepted":items.len(),"sessions_reconciled":items.len(),
                        "session_ids":[],"disabled":false,"disabled_reason":null,
                        "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":entities,
                        "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]})
                } else {
                    if value["report_kind"] == "scan_status" {
                        statuses.lock().unwrap().push(value.clone());
                    }
                    serde_json::json!({"accepted":true,"source":"claude_code","machine_id":"otm_test","disabled":false})
                };
                let body = response.to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            batch_posts,
            fault,
            terminal,
        }
    }
}

impl Drop for InplaceRetryServer {
    fn drop(&mut self) {
        super::permanent_finish_pipeline_tests::stop_server(&self.stop, &mut self.worker);
    }
}

struct InplaceRetryCycle {
    finished_ok: bool,
    /// This cycle's batch POSTs, as fingerprints.
    batch_posts: Vec<Vec<String>>,
    /// The semantic envelope of each body this cycle POSTed.
    envelopes: BTreeMap<String, serde_json::Value>,
    offered: BTreeSet<String>,
    accepted: BTreeSet<String>,
    waits: Vec<Duration>,
    sweep_unsettled: bool,
    last_error_code: Option<serde_json::Value>,
    /// Transcript bytes the cycle's scan consumed.
    consumed: u64,
}

/// One synthetic Claude home, support directory and loopback backend that
/// every cycle on it shares, as the passes of one installed daemon do.
struct InplaceRetryHome {
    server: InplaceRetryServer,
    fixture: IdentityPipelineHome,
    cadence: IdentityPipelineCadence,
    support: PathBuf,
    device: LocalDeviceBinding,
    client: SnapshotApiClient,
    daemon: LocalDaemon,
    _env: [EnvVarGuard; 3],
}

impl InplaceRetryHome {
    fn new(fault: BatchFault) -> Self {
        let fixture = IdentityPipelineHome::new();
        let cadence = IdentityPipelineCadence::new();
        let support = fixture.base.join("inplace-retry-support");
        let secrets = fixture.base.join("inplace-retry-secrets");
        std::fs::create_dir_all(&support).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        let server = InplaceRetryServer::new(fault);
        let env = [
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
            EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets),
            EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url),
        ];
        let device = LocalDeviceBinding {
            device_id: "inplace-retry-device".into(),
            machine_id: Some("otm_test".into()),
            sources: vec!["claude_code".into()],
        };
        FileDeviceStore::default().save(&device).unwrap();
        std::fs::write(
            secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .unwrap();
        let client = SnapshotApiClient::new(server.url.clone());
        Self {
            server,
            fixture,
            cadence,
            support,
            device,
            client,
            daemon: test_daemon("otm_test"),
            _env: env,
        }
    }

    /// A daemon restart: nothing in RAM survives, only the durable state.
    fn restart(&mut self) {
        self.daemon = test_daemon("otm_test");
        self.client = SnapshotApiClient::new(self.server.url.clone());
    }

    /// One real `prepare_sync_source` + `finish_sync_source` Claude cycle on
    /// this home, then what its durable index and the backend saw.
    fn cycle(&self) -> InplaceRetryCycle {
        let mut transport = crate::net_resilience::TransportCycleOutcome::default();
        let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
        let collection = || AgentStatusCollection {
            snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
            source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
            codex_scan_homes: Vec::new(),
            codex_home_bindings: Vec::new(),
        };
        let posts_before = self.server.batch_posts.lock().unwrap().len();
        self.cadence.next_due_cycle();
        let ((preparation, index, scan), consumed) =
            crate::snapshots::sampled_scan::transition_fixture::observe_consumed(|| {
                let frame = crate::agent_status_refresh::with_test_collection(collection(), || {
                    prepare_sync_source(
                        &self.client,
                        &self.device,
                        "device-secret",
                        SnapshotSource::ClaudeCode,
                        "otm_test",
                        &self.fixture.home,
                        &self.support,
                        &self.daemon,
                        &mut transport,
                        self.daemon.snapshot_scan_account_witness().unwrap(),
                        false,
                    )
                })
                .unwrap()
                .expect("a due Claude cycle prepares a scan");
                collect_preparation_with_rotation(frame)
            });
        let index_path = preparation.index_path.clone();
        let (result, waits) = with_inplace_retry_test_clock(None, || {
            crate::agent_status_refresh::with_test_collection(collection(), || {
                finish_sync_source(
                    preparation,
                    index,
                    scan,
                    &self.client,
                    &self.device,
                    "device-secret",
                    SnapshotSource::ClaudeCode,
                    "otm_test",
                    &self.fixture.home,
                    &self.support,
                    &self.daemon,
                    &mut transport,
                    &mut retry,
                )
            })
        });
        let saved = ScanIndex::load(&index_path).unwrap();
        let posted = self.server.batch_posts.lock().unwrap()[posts_before..].to_vec();
        let fingerprint =
            |item: &serde_json::Value| item["snapshot_fingerprint"].as_str().unwrap().to_string();
        let batch_posts = posted
            .iter()
            .map(|batch| batch.iter().map(fingerprint).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let envelopes = posted
            .iter()
            .flatten()
            .map(|item| (fingerprint(item), item["semantic_envelope"].clone()))
            .collect::<BTreeMap<_, _>>();
        let offered = envelopes.keys().cloned().collect::<BTreeSet<_>>();
        let last_error_code = self
            .server
            .terminal
            .lock()
            .unwrap()
            .last()
            .map(|status| status["last_error_code"].clone());
        InplaceRetryCycle {
            finished_ok: result.is_ok(),
            accepted: offered
                .iter()
                .filter(|fingerprint| saved.accepted_snapshot_fingerprint_recorded(fingerprint))
                .cloned()
                .collect(),
            offered,
            envelopes,
            batch_posts,
            waits,
            sweep_unsettled: saved.bounded_sweep_had_unsettled_upload(),
            last_error_code,
            consumed,
        }
    }
}

/// One cycle on a fresh synthetic home.
fn inplace_retry_claude_cycle(shed_first_batch: bool) -> InplaceRetryCycle {
    InplaceRetryHome::new(if shed_first_batch {
        BatchFault::FirstShedRetryAfterOne
    } else {
        BatchFault::None
    })
    .cycle()
}

/// T4: a Claude cycle whose first batch is shed with `Retry-After: 1` and
/// recovered in place saves exactly what a clean cycle saves: every offered
/// body ACKed, no unsettled-upload mark on the bounded sweep, and the same
/// terminal status. Without the resend the shed abandons the page and marks
/// the sweep, which withholds the census and forces a clean follow-up.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
#[serial(source_upload_deadlines)]
fn sync_cycle_with_recovered_shed_leaves_sweep_settled() {
    run_on_scan_worker_stack(|| {
        if !crate::heap_layout_bound::layout_supported() {
            writeln!(
                std::io::stderr().lock(),
                "inplace_retry_sync_cycle: supported_positive=UNEXECUTED layout_supported=false"
            )
            .unwrap();
            return;
        }
        clear_source_upload_deadlines_for_test();
        let clean = inplace_retry_claude_cycle(false);
        assert!(!clean.batch_posts.is_empty());
        assert!(clean.waits.is_empty());
        assert_eq!(clean.accepted, clean.offered);

        let recovered = inplace_retry_claude_cycle(true);
        clear_source_upload_deadlines_for_test();

        assert_eq!(
            recovered.batch_posts.len(),
            clean.batch_posts.len() + 1,
            "exactly one in-place resend"
        );
        assert_eq!(
            recovered.batch_posts[0], recovered.batch_posts[1],
            "the resend is the shed page"
        );
        assert_eq!(recovered.waits.len(), 1);
        assert_eq!(
            recovered.accepted, recovered.offered,
            "every offered body is ACKed after the resend"
        );
        assert!(
            !recovered.sweep_unsettled,
            "a recovered page never marks the bounded sweep unsettled"
        );
        assert_eq!(recovered.sweep_unsettled, clean.sweep_unsettled);
        assert_eq!(recovered.finished_ok, clean.finished_ok);
        assert_eq!(recovered.last_error_code, clean.last_error_code);
    });
}

/// [regress] [money] An upload outage keeps the read: a page whose upload
/// ends in a plain shed, a 5xx or a dropped connection holds its unACKed
/// bodies in retryable custody, so its file and head commit. The recovery
/// pass, with or without a restart between them, re-sends the same bodies
/// from the head without reading one transcript byte, and they are accepted
/// with the money and placement the outage page carried. The outage records
/// no ACK and no poison loss. Without custody the recovery pass reads the
/// whole file again.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
#[serial(source_upload_deadlines)]
fn upload_outage_keeps_the_read_and_resends_from_the_head() {
    use super::permanent_finish_pipeline_tests::prior_index_lifetime_tests::Guard as RetryClock;
    run_on_scan_worker_stack(|| {
        if !crate::heap_layout_bound::layout_supported() {
            writeln!(
                std::io::stderr().lock(),
                "upload_outage_custody: supported_positive=UNEXECUTED layout_supported=false"
            )
            .unwrap();
            return;
        }
        for fault in [
            BatchFault::PlainShed,
            BatchFault::ServerError,
            BatchFault::Dropped,
        ] {
            for restart in [false, true] {
                let label = format!("{fault:?} restart={restart}");
                clear_source_upload_deadlines_for_test();
                let mut home = InplaceRetryHome::new(fault);
                let outage = home.cycle();
                assert!(
                    outage.consumed > 0,
                    "{label}: the outage page reads the file"
                );
                assert!(!outage.offered.is_empty(), "{label}: the outage page POSTs");
                assert!(outage.accepted.is_empty(), "{label}: nothing is ACKed");
                assert!(
                    counted_poison_fingerprints_for_test(SnapshotSource::ClaudeCode.api_slug())
                        .is_disjoint(&outage.offered),
                    "{label}: an outage is no poison loss"
                );

                *home.server.fault.lock().unwrap() = BatchFault::None;
                if restart {
                    home.restart();
                }
                // Past the custody's backoff, so its retry is due.
                let recovery = {
                    let _clock = RetryClock::new(false, None, Some(current_unix_seconds() + 3_600));
                    home.cycle()
                };
                clear_source_upload_deadlines_for_test();
                assert_eq!(
                    recovery.consumed, 0,
                    "{label}: the recovery pass reads no transcript byte"
                );
                assert_eq!(
                    recovery.offered, outage.offered,
                    "{label}: the recovery pass re-sends the outage page's bodies"
                );
                assert_eq!(
                    recovery.envelopes, outage.envelopes,
                    "{label}: the same money and placement"
                );
                assert_eq!(
                    recovery.accepted, recovery.offered,
                    "{label}: every body is ACKed exactly"
                );
            }
        }
    });
}
