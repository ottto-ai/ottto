// Real loopback transport around the same native complete-page ACK/index path.
use super::bounded_snapshot_retry::PreparedRetry;

fn bounded_native_capture(f: &SameSourceAckFixture, now: Instant) -> PreparedRetry {
    PreparedRetry::capture(
        SnapshotSource::Codex,
        &"a".repeat(64),
        SnapshotUploadPolicy::default(),
        [1; 32],
        std::slice::from_ref(&f.items[0]),
        &f.working,
        &f.baseline,
        &f.progress,
        &f.index_path,
        &f.progress_path,
        now,
        Duration::from_secs(60),
        4 * 1024 * 1024,
    )
    .unwrap()
}
fn bounded_native_device() -> LocalDeviceBinding {
    LocalDeviceBinding {
        device_id: "synthetic".into(),
        machine_id: Some("a".repeat(64)),
        sources: vec!["codex".into()],
    }
}
fn bounded_native_ack(item: &SnapshotItem) -> String {
    let version = match crate::snapshots::snapshot_upload_body_witness_version(item) {
        Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_CONTEXT_CURVE_VERSION) => Some(crate::snapshot_client::SNAPSHOT_BODY_WITNESS_PUBLIC_CONTEXT_CURVE_VERSION),
        Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_CONTEXT_CURVE_VERSION) => Some(crate::snapshot_client::SNAPSHOT_BODY_WITNESS_PUBLIC_EXCLUSIVE_CONTEXT_CURVE_VERSION),
        None | Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_TOOL_VERSION) | Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_TOOL_VERSION) => None,
        other => panic!("unexpected fixture witness: {other:?}"),
    };
    serde_json::json!({"accepted":1,"sessions_reconciled":1,"session_ids":[],"disabled":false,
        "entity_ack_contract":crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
        "accepted_entities":[{"source_session_id":item.source_session_id,"snapshot_fingerprint":item.snapshot_fingerprint,
        "occurrence_count":1,"body_witness_version":version,"body_witness_digest":version.map(|_|snapshot_upload_body_witness(item))}]}).to_string()
}
fn bounded_native_response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    use std::io::Write;
    write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
}
fn bounded_native_read(stream: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::Read;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let deadline = Instant::now() + BOUNDED_NATIVE_FIXTURE_WAIT;
    let mut bytes = Vec::new();
    let mut buf = [0; 4096];
    while !http_request_complete(&bytes) {
        assert!(
            Instant::now() < deadline,
            "fixture request incomplete after {BOUNDED_NATIVE_FIXTURE_WAIT:?}: {} bytes",
            bytes.len()
        );
        let n = stream
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("fixture request read after {} bytes: {e}", bytes.len()));
        assert!(
            n > 0,
            "client closed fixture request after {} bytes",
            bytes.len()
        );
        bytes.extend_from_slice(&buf[..n]);
    }
    bytes
}

// Loopback fixture server. The client turn is synchronous, so once it returns
// no further connection can arrive: `join` cancels a pending accept instead of
// waiting forever, and dropping the guard (client early return or panic) stops
// the server too. Both are bounded, so a stranded fixture cannot keep holding
// SNAPSHOT_SYNC_LOCK for every later retry test.
const BOUNDED_NATIVE_FIXTURE_WAIT: Duration = Duration::from_secs(10);
struct BoundedNativeListener {
    listener: std::net::TcpListener,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl BoundedNativeListener {
    fn accept(&self) -> std::io::Result<(std::net::TcpStream, std::net::SocketAddr)> {
        use std::sync::atomic::Ordering::SeqCst;
        let started = Instant::now();
        let mut reported = false;
        loop {
            // Drain any queued connection before honoring cancellation.
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    // BSD accept inherits the listener's non-blocking flag.
                    stream.set_nonblocking(false)?;
                    self.accepted.fetch_add(1, SeqCst);
                    return Ok((stream, peer));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            let next = self.accepted.load(SeqCst) + 1;
            if self.stop.load(SeqCst) {
                return Err(std::io::Error::other(format!(
                    "client returned before fixture connection {next}"
                )));
            }
            if !reported && started.elapsed() > BOUNDED_NATIVE_FIXTURE_WAIT {
                reported = true;
                eprintln!(
                    "fixture still waiting for connection {next} after {BOUNDED_NATIVE_FIXTURE_WAIT:?}; client turn has not returned"
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn into_inner(self) -> std::net::TcpListener {
        self.listener
    }
}
struct BoundedNativeServer<T> {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    done: std::sync::mpsc::Receiver<()>,
    handle: Option<std::thread::JoinHandle<T>>,
}
fn bounded_native_server<T: Send + 'static>(
    listener: std::net::TcpListener,
    serve: impl FnOnce(BoundedNativeListener) -> T + Send + 'static,
) -> BoundedNativeServer<T> {
    listener.set_nonblocking(true).unwrap();
    let listener = BoundedNativeListener {
        listener,
        stop: Default::default(),
        accepted: Default::default(),
    };
    let (stop, accepted) = (listener.stop.clone(), listener.accepted.clone());
    // A panicking server drops `finished`, which also ends the wait below.
    let (finished, done) = std::sync::mpsc::sync_channel(1);
    let handle = std::thread::spawn(move || {
        let result = serve(listener);
        let _ = finished.send(());
        result
    });
    BoundedNativeServer {
        stop,
        accepted,
        done,
        handle: Some(handle),
    }
}
impl<T> BoundedNativeServer<T> {
    fn stop_and_wait(&mut self) -> Option<std::thread::JoinHandle<T>> {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let handle = self.handle.take()?;
        match self.done.recv_timeout(BOUNDED_NATIVE_FIXTURE_WAIT) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
            _ => Some(handle),
        }
    }
    /// Call only after the client turn returned.
    fn join(mut self) -> std::thread::Result<T> {
        match self.stop_and_wait() {
            Some(handle) => handle.join(),
            None => panic!(
                "fixture server still running {BOUNDED_NATIVE_FIXTURE_WAIT:?} after the client returned; accepted {} connection(s)",
                self.accepted.load(std::sync::atomic::Ordering::SeqCst)
            ),
        }
    }
}
impl<T> Drop for BoundedNativeServer<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.stop_and_wait() {
            let _ = handle.join();
        }
    }
}

#[test]
fn bounded_retry_plain_http_is_declined_before_token_or_batch_io() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    // Default construction has the production HTTPS requirement even in tests.
    // With no connection, a slow-reading plaintext peer cannot extend a write.
    let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()));
    let mut budget =
        crate::snapshot_retry::RetryBudget::after_shed(Instant::now(), Duration::ZERO).unwrap();
    budget.enter(Instant::now()).unwrap();
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::Codex.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some(collector_version()),
        snapshots: Vec::new(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let token_error = client
        .issue_relay_token_bounded(
            &bounded_native_device(),
            "synthetic-secret",
            SnapshotSource::Codex,
            &budget,
            &mut || Ok(()),
        )
        .unwrap_err();
    let batch_error = client
        .upload_batch_bounded("synthetic-token", &request, false, &mut budget, &mut || {
            Ok(())
        })
        .unwrap_err();
    assert_eq!(
        token_error.to_string(),
        "optional snapshot retry requires HTTPS"
    );
    assert_eq!(
        batch_error.to_string(),
        "optional snapshot retry requires HTTPS"
    );
    assert_eq!(budget.posts_left(), 3);
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
// The bounded turn leases the shared client_report counters across its token/batch I/O.
#[serial(client_report)]
fn bounded_retry_native_transport_fallback_auth_exact_ack_checkpoint_and_recovery() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut f = SameSourceAckFixture::new();
    // Runtime-only pressure diagnostics cannot invalidate durable equality.
    f.progress.retained_stale_ack_count = 1;
    let item = f.items[0].clone();
    let fingerprint = item.snapshot_fingerprint.clone();
    let mut page = bounded_native_capture(&f, Instant::now() - Duration::from_secs(61));
    page.budget.force_gzip_for_test();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let ack = bounded_native_ack(&item);
    let server = bounded_native_server(listener, move |listener| {
        let mut trace = Vec::new();
        for (status, body) in [
            ("200 OK", "{\"token\":\"fresh-one\"}"),
            ("415 Unsupported Media Type", "{}"),
            ("401 Unauthorized", "{}"),
            ("200 OK", "{\"token\":\"fresh-two\"}"),
            ("200 OK", ack.as_str()),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let bytes = bounded_native_read(&mut stream);
            trace.push(
                String::from_utf8_lossy(
                    &bytes[..bytes.windows(4).position(|s| s == b"\r\n\r\n").unwrap()],
                )
                .into_owned(),
            );
            bounded_native_response(&mut stream, status, body);
        }
        trace
    });
    let client = SnapshotApiClient::new(format!("http://{address}"))
        .with_bounded_retry_loopback_http_for_test();
    let current = f.items.clone();
    assert!(page.bound() <= 4 * 1024 * 1024);
    let outcome = page
        .turn(
            &client,
            &bounded_native_device(),
            "synthetic-secret",
            &current,
            &[1; 32],
            &mut || Ok(()),
        )
        .unwrap();
    assert!(matches!(
        outcome,
        SnapshotPageOutcome::Settled { conflicted: 0 }
    ));
    assert_eq!(page.budget.posts_left(), 0);
    let trace = server.join().unwrap();
    assert_eq!(trace.iter().filter(|s| s.contains("/batches ")).count(), 3);
    assert_eq!(
        trace.iter().filter(|s| s.contains("/relay-token ")).count(),
        2
    );
    assert!(trace[1]
        .to_ascii_lowercase()
        .contains("content-encoding: gzip"));
    assert!(!trace[2]
        .to_ascii_lowercase()
        .contains("content-encoding: gzip"));
    assert!(trace[4].contains("Bearer fresh-two"));
    f.restart_preparation();
    assert_eq!(f.baseline.files.len(), 2); // accepted A and previously settled C; pending B survives.
    assert_eq!(f.items.len(), 1);
    assert!(!f
        .items
        .iter()
        .any(|item| item.snapshot_fingerprint == fingerprint));
    SameSourceAckFixture::stable_context(&f.baseline);
    eprintln!("bounded native batch_posts=3 fresh_tokens=2 exact_A_and_C_recovery=true pending_B=true no_census_completion=true");
}
#[test]
// The bounded turn leases the shared client_report counters across its token/batch I/O.
#[serial(client_report)]
fn bounded_retry_native_response_cap_and_post_ack_cancellation_preserve_durable_recovery() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for oversized in [true, false] {
        let mut f = SameSourceAckFixture::new();
        let current = f.items.clone();
        let before = std::fs::read(&f.index_path).unwrap();
        let mut page = bounded_native_capture(&f, Instant::now() - Duration::from_secs(61));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let server_live = live.clone();
        let ack = bounded_native_ack(&f.items[0]);
        let server = bounded_native_server(listener, move |listener| {
            let (mut stream, _) = listener.accept().unwrap();
            bounded_native_read(&mut stream);
            bounded_native_response(&mut stream, "200 OK", "{\"token\":\"fresh\"}");
            let (mut stream, _) = listener.accept().unwrap();
            bounded_native_read(&mut stream);
            if oversized {
                bounded_native_response(
                    &mut stream,
                    "200 OK",
                    &" ".repeat(crate::snapshot_retry::RESPONSE_BYTES + 1),
                );
            } else {
                server_live.store(false, std::sync::atomic::Ordering::SeqCst);
                bounded_native_response(&mut stream, "200 OK", &ack);
            }
        });
        let client = SnapshotApiClient::new(format!("http://{address}"))
            .with_bounded_retry_loopback_http_for_test();
        let result = page.turn(
            &client,
            &bounded_native_device(),
            "synthetic-secret",
            &current,
            &[1; 32],
            &mut || {
                if live.load(std::sync::atomic::Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(anyhow!("authority revoked after remote ACK"))
                }
            },
        );
        assert!(result.is_err());
        server.join().unwrap();
        assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
        f.restart_preparation();
        if oversized {
            assert_eq!(f.progress.accepted_fingerprints.len(), 1);
        } else {
            assert_eq!(f.progress.accepted_fingerprints.len(), 2);
        }
        // Ordinary preparation still derives the uncheckpointed body; durable
        // exact ACK suppresses a new POST even after cancellation after ACK.
        let mut calls = 0;
        f.send(0, |items| {
            calls += 1;
            same_source_fixture_ack(items)
        })
        .unwrap();
        assert_eq!(calls, usize::from(oversized));
    }
}

struct NativeRetryRotation {
    scan: OwnedRotationProof,
    retry: super::bounded_snapshot_retry::RetryOwner,
    client: SnapshotApiClient,
    turns: usize,
    expected_account: u64,
}
impl crate::source_rotation::Owner for NativeRetryRotation {
    type Source = SnapshotSource;
    type Frame = SourcePreparation;
    type Completed = (SourcePreparation, ScanIndex, SourceScanResult);
    fn prepare(
        &mut self,
        source: SnapshotSource,
        remaining: Option<usize>,
    ) -> Result<Option<Self::Frame>> {
        crate::source_rotation::Owner::prepare(&mut self.scan, source, remaining)
    }
    fn validate(&mut self, frame: &Self::Frame) -> Result<()> {
        crate::source_rotation::Owner::validate(&mut self.scan, frame)
    }
    fn step(
        &mut self,
        frame: Self::Frame,
        remaining: Option<usize>,
    ) -> crate::source_rotation::Step<Self::Frame, Self::Completed> {
        crate::source_rotation::Owner::step(&mut self.scan, frame, remaining)
    }
    fn bound(&self, frame: &Self::Frame, limit: usize) -> Option<usize> {
        crate::source_rotation::Owner::bound(&self.scan, frame, limit)
    }
    fn finish(&mut self, completed: Self::Completed, remaining: Option<usize>) -> Result<()> {
        crate::source_rotation::Owner::finish(&mut self.scan, completed, remaining)
    }
    fn outcome(&mut self, source: SnapshotSource, result: Result<()>) {
        crate::source_rotation::Owner::outcome(&mut self.scan, source, result)
    }
    fn monotonic(&self) -> Duration {
        crate::source_rotation::Owner::monotonic(&self.scan)
    }
    fn parked(&mut self, bytes: usize) {
        crate::source_rotation::Owner::parked(&mut self.scan, bytes);
    }
    fn boundary(&mut self, busy: impl Iterator<Item = SnapshotSource>) {
        assert_eq!(
            self.scan.offered.len(),
            3,
            "every due sibling offered first"
        );
        assert_eq!(self.scan.owner, std::thread::current().id());
        assert!(SNAPSHOT_SYNC_LOCK.get().unwrap().try_lock().is_err());
        let scan = &self.scan;
        let expected = self.expected_account;
        let turns = &mut self.turns;
        self.retry.boundary(busy, Instant::now(), |page| {
            *turns += 1;
            page.turn(
                &self.client,
                &bounded_native_device(),
                "synthetic-secret",
                &scan.a.items,
                &[1; 32],
                &mut || {
                    if scan.authority.account == expected {
                        Ok(())
                    } else {
                        Err(anyhow!("owner account changed"))
                    }
                },
            )
        });
    }
}
#[test]
// The bounded turn leases the shared client_report counters across its token/batch I/O.
#[serial(client_report)]
fn bounded_retry_actual_owner_boundary_fairness_same_source_block_and_recovery() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let (_, allocation) = crate::retry_allocation_probe::measure(|| {
        for cancel in [false, true] {
            let mut scan =
                OwnedRotationProof::new(1, None, false, crate::source_rotation::PARKED_BUDGET);
            scan.slots = [None, None]; // This oracle uses the native bounded transport, never the scripted uploader.
            let mut retry = super::bounded_snapshot_retry::RetryOwner::default();
            let page = bounded_native_capture(&scan.a, Instant::now() - Duration::from_secs(61));
            let ordinary = Instant::now() + SNAPSHOT_SYNC_INTERVAL;
            assert!(retry.admit(page));
            assert!(retry.wake_before(ordinary) < ordinary);
            let mut blocked_calls = 0;
            retry.boundary(
                std::iter::once(SnapshotSource::Codex),
                Instant::now(),
                |_| {
                    blocked_calls += 1;
                    unreachable!("same-source parser is still owned");
                },
            );
            assert_eq!(blocked_calls, 0);
            let before = std::fs::read(&scan.a.index_path).unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let expected = scan.authority.account;
            let server = if cancel {
                scan.authority.account += 1;
                None
            } else {
                let ack = bounded_native_ack(&scan.a.items[0]);
                Some(bounded_native_server(listener, move |listener| {
                    let (mut stream, _) = listener.accept().unwrap();
                    bounded_native_read(&mut stream);
                    bounded_native_response(&mut stream, "200 OK", "{\"token\":\"fresh\"}");
                    let (mut stream, _) = listener.accept().unwrap();
                    bounded_native_read(&mut stream);
                    bounded_native_response(&mut stream, "200 OK", &ack);
                }))
            };
            let mut owner = NativeRetryRotation {
                scan,
                retry,
                client: SnapshotApiClient::new(format!("http://{address}"))
                    .with_bounded_retry_loopback_http_for_test(),
                turns: 0,
                expected_account: expected,
            };
            crate::source_rotation::run(
                &mut owner,
                &[
                    SnapshotSource::Pi,
                    SnapshotSource::Codex,
                    SnapshotSource::ClaudeCode,
                ],
                crate::source_rotation::PARKED_BUDGET,
            );
            assert_eq!(owner.turns, 1);
            assert!(owner.scan.errors.is_empty());
            assert_eq!(owner.scan.line_count, 120);
            assert_eq!(
                owner.retry.wake_before(ordinary),
                ordinary,
                "ordinary wake is not reanchored by optional work"
            );
            if let Some(server) = server {
                server.join().unwrap();
            }
            if cancel {
                assert_eq!(std::fs::read(&owner.scan.a.index_path).unwrap(), before);
            }
            owner.scan.a.restart_preparation();
            assert_eq!(
                owner.scan.a.baseline.files.len(),
                if cancel { 1 } else { 2 }
            );
        }
    });
    eprintln!(
        "native owner requested-allocation peak={} (finite loopback proof)",
        allocation.requested_peak
    );
}

#[test]
fn bounded_retry_native_stale_authority_body_and_checkpoint_stop_before_token() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for mutation in [
        "authority",
        "body",
        "device",
        "progress",
        "index",
        "large-progress",
        "large-index",
        "stop",
    ] {
        let f = SameSourceAckFixture::new();
        let mut current = f.items.clone();
        let mut page = bounded_native_capture(&f, Instant::now() - Duration::from_secs(61));
        let mut authority = [1; 32];
        let mut device = bounded_native_device();
        match mutation {
            "authority" => authority[0] = 2,
            "body" => current[0].output_tokens += 1,
            "device" => device.machine_id = Some("b".repeat(64)),
            "progress" => {
                let mut progress = f.progress.clone();
                progress.generation += 1;
                std::fs::write(&f.progress_path, serde_json::to_vec(&progress).unwrap()).unwrap();
            }
            "index" => {
                let mut index = f.baseline.clone();
                index.generation += 1;
                std::fs::write(&f.index_path, serde_json::to_vec(&index).unwrap()).unwrap();
            }
            "large-progress" => std::fs::write(
                &f.progress_path,
                vec![b' '; crate::snapshot_retry::RESPONSE_BYTES + 1],
            )
            .unwrap(),
            "large-index" => std::fs::write(
                &f.index_path,
                vec![b' '; crate::snapshot_retry::RESPONSE_BYTES + 1],
            )
            .unwrap(),
            "stop" => {}
            _ => unreachable!(),
        }
        let index = std::fs::read(&f.index_path).unwrap();
        let progress = std::fs::read(&f.progress_path).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()))
            .with_bounded_retry_loopback_http_for_test();
        let result = page.turn(
            &client,
            &device,
            "synthetic-secret",
            &current,
            &authority,
            &mut || {
                if mutation == "stop" {
                    Err(anyhow!("owner stopped"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err(), "{mutation}");
        if matches!(
            mutation,
            "progress" | "index" | "large-progress" | "large-index"
        ) {
            assert!(result
                .unwrap_err()
                .downcast_ref::<SnapshotLocalStateRejected>()
                .is_some());
        }
        assert_eq!(page.budget.posts_left(), 3);
        assert!(matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        assert_eq!(std::fs::read(&f.index_path).unwrap(), index);
        assert_eq!(std::fs::read(&f.progress_path).unwrap(), progress);
    }
}
// Fixed-slot monotonic stage clock for the deadline fixture. Each slot holds
// microseconds since the listener bound (u64::MAX = not reached). A mark is one
// atomic store, so the client and server threads share one timeline without
// locks, allocation, or per-byte logging, and a panicking side keeps its marks.
#[derive(Clone, Copy)]
enum BoundedDeadlineStage {
    ListenerReady,
    ServerStarted,
    TokenAccepted,
    TokenRead,
    TokenSleepStart,
    TokenSleepEnd,
    TokenWriteStart,
    TokenWriteEnd,
    AckAccepted,
    AckRead,
    AckHeadWritten,
    AckTrickleEnd,
    ServerReturned,
    ClientCall,
    ClientResult,
    ServerJoined,
}
const BOUNDED_DEADLINE_STAGES: [&str; 16] = [
    "listener_ready",
    "server_started",
    "token_accepted",
    "token_read",
    "token_sleep_start",
    "token_sleep_end",
    "token_write_start",
    "token_write_end",
    "ack_accepted",
    "ack_read",
    "ack_head_written",
    "ack_trickle_end",
    "server_returned",
    "client_call",
    "client_result",
    "server_joined",
];
struct BoundedDeadlineStages {
    origin: Instant,
    at: [std::sync::atomic::AtomicU64; BOUNDED_DEADLINE_STAGES.len()],
}
impl BoundedDeadlineStages {
    fn new(origin: Instant) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            origin,
            at: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(u64::MAX)),
        })
    }
    fn mark(&self, stage: BoundedDeadlineStage) {
        let micros = u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX - 1);
        self.at[stage as usize].store(micros, std::sync::atomic::Ordering::SeqCst);
    }
}
impl std::fmt::Display for BoundedDeadlineStages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (name, at) in BOUNDED_DEADLINE_STAGES.iter().zip(&self.at) {
            match at.load(std::sync::atomic::Ordering::SeqCst) {
                u64::MAX => write!(f, " {name}=-")?,
                micros => write!(f, " {name}={}.{:03}ms", micros / 1000, micros % 1000)?,
            }
        }
        Ok(())
    }
}

// Wait for a fixed end point in sleeps of at most 1ms, comparing monotonic
// time each wake. A late wake shortens what is left instead of adding a whole
// fixed sleep on top (CI showed one 120ms sleep taking 248.7ms). Best effort,
// not a real-time guarantee: the stage clock records the actual delay.
fn bounded_native_wait_until(end: Instant) {
    loop {
        let now = Instant::now();
        if now >= end {
            return;
        }
        std::thread::sleep((end - now).min(Duration::from_millis(1)));
    }
}

#[test]
// The bounded turn leases the shared client_report counters across its token/batch I/O.
#[serial(client_report)]
fn bounded_retry_native_absolute_deadline_covers_token_and_trickling_ack() {
    use self::BoundedDeadlineStage as Stage;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for stalled_token in [true, false] {
        let f = SameSourceAckFixture::new();
        let current = f.items.clone();
        let before = std::fs::read(&f.index_path).unwrap();
        let mut page = bounded_native_capture(&f, Instant::now() - Duration::from_secs(61));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stages = BoundedDeadlineStages::new(Instant::now());
        stages.mark(Stage::ListenerReady);
        let address = listener.local_addr().unwrap();
        let ack = bounded_native_ack(&current[0]);
        let server_stages = stages.clone();
        let server = bounded_native_server(listener, move |listener| {
            use std::io::Write;
            let stages = server_stages;
            stages.mark(Stage::ServerStarted);
            let (mut stream, _) = listener.accept().unwrap();
            stages.mark(Stage::TokenAccepted);
            bounded_native_read(&mut stream);
            let token_read = Instant::now();
            stages.mark(Stage::TokenRead);
            stages.mark(Stage::TokenSleepStart);
            if stalled_token {
                std::thread::sleep(Duration::from_millis(600));
                stages.mark(Stage::TokenSleepEnd);
                stages.mark(Stage::ServerReturned);
                return 0;
            }
            bounded_native_wait_until(token_read + Duration::from_millis(120));
            stages.mark(Stage::TokenSleepEnd);
            stages.mark(Stage::TokenWriteStart);
            bounded_native_response(&mut stream, "200 OK", "{\"token\":\"fresh\"}");
            stages.mark(Stage::TokenWriteEnd);
            let (mut stream, _) = listener.accept().unwrap();
            stages.mark(Stage::AckAccepted);
            bounded_native_read(&mut stream);
            stages.mark(Stage::AckRead);
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",ack.len()).unwrap();
            stages.mark(Stage::AckHeadWritten);
            for byte in ack.bytes().take(30) {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            stages.mark(Stage::AckTrickleEnd);
            stages.mark(Stage::ServerReturned);
            1
        });
        // Start the 500ms retained budget with the measured turn, not before
        // fixture setup (listener, ACK body, server thread).
        page.budget = crate::snapshot_retry::RetryBudget::after_shed(
            Instant::now() - crate::snapshot_retry::RETENTION + Duration::from_millis(500),
            Duration::ZERO,
        )
        .unwrap();
        stages.mark(Stage::ClientCall);
        let started = Instant::now();
        let result = page.turn(
            &SnapshotApiClient::new(format!("http://{address}"))
                .with_bounded_retry_loopback_http_for_test(),
            &bounded_native_device(),
            "synthetic-secret",
            &current,
            &[1; 32],
            &mut || Ok(()),
        );
        let elapsed = started.elapsed();
        stages.mark(Stage::ClientResult);
        // Record the client outcome and the stage clock before joining: a
        // fixture panic must not hide the client's own error or timing.
        let client = format!(
            "stalled_token={stalled_token} elapsed={elapsed:?} posts_left={} result={:?} stages:{stages}",
            page.budget.posts_left(),
            result.as_ref().map_err(|e| format!("{e:#}"))
        );
        eprintln!("bounded deadline client: {client}");
        assert!(result.is_err(), "{client}");
        assert!(
            elapsed < Duration::from_millis(900),
            "absolute timeout failed: {client}"
        );
        let served = server.join();
        stages.mark(Stage::ServerJoined);
        assert_eq!(
            served.unwrap_or_else(|_| panic!(
                "fixture server failed; client {client}; joined stages:{stages}"
            )),
            usize::from(!stalled_token),
            "{client}; joined stages:{stages}"
        );
        assert_eq!(
            page.budget.posts_left(),
            if stalled_token { 3 } else { 2 },
            "{client}"
        );
        assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
        let durable: SnapshotUploadProgress =
            serde_json::from_slice(&std::fs::read(&f.progress_path).unwrap()).unwrap();
        assert_eq!(durable.accepted_fingerprints.len(), 1);
        eprintln!(
            "bounded deadline stalled_token={stalled_token} elapsed_ms={} stages:{stages}",
            elapsed.as_millis()
        );
    }
}

#[test]
#[serial(source_upload_deadlines)]
// The bounded turn leases the shared client_report counters across its token/batch I/O.
#[serial(client_report)]
fn bounded_retry_native_reshed_keeps_original_expiry_and_shared_posts() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut f = SameSourceAckFixture::new();
    let current = f.items.clone();
    let page = bounded_native_capture(&f, Instant::now() - Duration::from_secs(61));
    let expiry = page.budget.expires();
    let mut retry = super::bounded_snapshot_retry::RetryOwner::default();
    assert!(retry.admit(page));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let ack = bounded_native_ack(&current[0]);
    let server = bounded_native_server(listener, move |listener| {
        use std::io::Write;
        for n in 0..4 {
            let (mut stream, _) = listener.accept().unwrap();
            let bytes = bounded_native_read(&mut stream);
            if n % 2 == 0 {
                bounded_native_response(&mut stream, "200 OK", "{\"token\":\"fresh\"}");
            } else if n == 1 {
                write!(stream,"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\nRetry-After: 0\r\nConnection: close\r\n\r\n{{}}").unwrap();
            } else {
                bounded_native_response(&mut stream, "200 OK", &ack);
            }
            if n % 2 == 1 {
                assert!(String::from_utf8_lossy(&bytes).contains("/batches "));
            }
        }
    });
    let client = SnapshotApiClient::new(format!("http://{address}"))
        .with_bounded_retry_loopback_http_for_test();
    let mut turns = 0;
    for expected_posts in [3, 2] {
        retry.boundary(std::iter::empty(), Instant::now(), |page| {
            turns += 1;
            assert_eq!(page.budget.expires(), expiry);
            assert_eq!(page.budget.posts_left(), expected_posts);
            page.turn(
                &client,
                &bounded_native_device(),
                "synthetic-secret",
                &current,
                &[1; 32],
                &mut || Ok(()),
            )
        });
    }
    assert_eq!(turns, 2);
    server.join().unwrap();
    let ordinary = Instant::now() + SNAPSHOT_SYNC_INTERVAL;
    assert_eq!(retry.wake_before(ordinary), ordinary);
    clear_shed_streak(SnapshotSource::Codex);
    source_upload_deadlines()
        .lock()
        .unwrap()
        .remove(SnapshotSource::Codex.api_slug());
    f.restart_preparation();
    assert_eq!(f.baseline.files.len(), 2);
}

// #660 D2: Codex side state that enlarges the index past `RESPONSE_BYTES`
// must not loosen any cap. Bounded retry declines before any copy (the
// caller's existing `None` → ordinary path), and the ordinary unbounded
// checkpoint then settles the ACK and keeps the side state.
fn bounded_native_enlarged_by_side_state() -> SameSourceAckFixture {
    let mut f = SameSourceAckFixture::new();
    f.baseline.add_codex_side_state_for_test(100);
    f.baseline.save(&f.index_path).unwrap();
    f.working.add_codex_side_state_for_test(100);
    f.working.generation = f.baseline.generation;
    assert!(
        std::fs::metadata(&f.index_path).unwrap().len()
            > crate::snapshot_retry::RESPONSE_BYTES as u64
    );
    assert!(!crate::snapshot_retry::json_fits(
        &f.working,
        crate::snapshot_retry::RESPONSE_BYTES
    ));
    f
}

// #660 D2: the bounded checkpoint's capped read refuses the enlarged index
// with an error: the index and progress files are byte-identical (no
// truncation), and the durable ACK is still settled by the ordinary
// checkpoint afterwards (no ACK or debt loss).
#[test]
fn bounded_checkpoint_cap_refuses_an_enlarged_index_without_truncation_or_ack_loss() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut f = bounded_native_enlarged_by_side_state();
    f.send(0, same_source_fixture_ack).unwrap();
    let accepted = f.progress.accepted_fingerprints.len();
    let index = std::fs::read(&f.index_path).unwrap();
    let progress = std::fs::read(&f.progress_path).unwrap();
    let result = checkpoint_partial_snapshot_index_with_read_limit(
        &f.working,
        &f.baseline,
        &f.progress,
        &f.items,
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
        Some(crate::snapshot_retry::RESPONSE_BYTES),
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(&f.index_path).unwrap(), index);
    assert_eq!(std::fs::read(&f.progress_path).unwrap(), progress);

    assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 1);
    f.restart_preparation();
    assert_eq!(f.progress.accepted_fingerprints.len(), accepted);
    assert!(f.baseline.files.contains_key(&f.keys[0]));
    assert_eq!(f.baseline.codex_side_state_len_for_test(), (100, 100));
}
