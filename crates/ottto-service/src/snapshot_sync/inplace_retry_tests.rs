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

/// T1: a shed whose Retry-After is at most 5 s is resent in place after the
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
            body_excerpt: None,
        }),
        "422" => anyhow::Error::new(BatchRejected {
            status: 422,
            body_excerpt: Some(r#"{"detail":[{"loc":["body","snapshots",0]}]}"#.into()),
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
        ResumableUploadResult::Deferred { count: 1 }
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
                    });
                Ok(response)
            },
            |_| Ok(()),
        )
    });
    assert_eq!(deferred.unwrap(), 1);
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
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let result = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
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
