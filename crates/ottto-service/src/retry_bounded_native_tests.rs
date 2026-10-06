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
    let mut bytes = Vec::new();
    let mut buf = [0; 4096];
    while !http_request_complete(&bytes) {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
    }
    bytes
}

#[test]
fn bounded_retry_plain_http_is_declined_before_token_or_batch_io() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    // Default construction has the production HTTPS requirement even in tests.
    // With no connection, a slow-reading plaintext peer cannot extend a write.
    let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()));
    let mut budget = crate::snapshot_retry::RetryBudget::after_shed(
        Instant::now(),
        Duration::ZERO,
    )
    .unwrap();
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
        .upload_batch_bounded("synthetic-token", &request, false, &mut budget, &mut || Ok(()))
        .unwrap_err();
    assert_eq!(token_error.to_string(), "optional snapshot retry requires HTTPS");
    assert_eq!(batch_error.to_string(), "optional snapshot retry requires HTTPS");
    assert_eq!(budget.posts_left(), 3);
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn bounded_retry_native_transport_fallback_auth_exact_ack_checkpoint_and_recovery() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut f = SameSourceAckFixture::new();
    let item = f.items[0].clone();
    let fingerprint = item.snapshot_fingerprint.clone();
    let mut page = bounded_native_capture(&f, Instant::now() - Duration::from_secs(61));
    page.budget.force_gzip_for_test();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let ack = bounded_native_ack(&item);
    let server = std::thread::spawn(move || {
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
    let client = SnapshotApiClient::new(format!("http://{address}")).with_bounded_retry_loopback_http_for_test();
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
        let server = std::thread::spawn(move || {
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
        let client = SnapshotApiClient::new(format!("http://{address}")).with_bounded_retry_loopback_http_for_test();
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
    fn prepare(&mut self, source: SnapshotSource) -> Result<Option<Self::Frame>> {
        crate::source_rotation::Owner::prepare(&mut self.scan, source)
    }
    fn validate(&mut self, frame: &Self::Frame) -> Result<()> {
        crate::source_rotation::Owner::validate(&mut self.scan, frame)
    }
    fn step(
        &mut self,
        frame: Self::Frame,
    ) -> crate::source_rotation::Step<Self::Frame, Self::Completed> {
        crate::source_rotation::Owner::step(&mut self.scan, frame)
    }
    fn bound(&self, frame: &Self::Frame, limit: usize) -> Option<usize> {
        crate::source_rotation::Owner::bound(&self.scan, frame, limit)
    }
    fn finish(&mut self, completed: Self::Completed) -> Result<()> {
        crate::source_rotation::Owner::finish(&mut self.scan, completed)
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
                Some(std::thread::spawn(move || {
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
                client: SnapshotApiClient::new(format!("http://{address}")).with_bounded_retry_loopback_http_for_test(),
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
    assert!(!super::bounded_snapshot_retry::production_activation_reviewed());
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
        let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap())).with_bounded_retry_loopback_http_for_test();
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
#[test]
fn bounded_retry_native_absolute_deadline_covers_token_and_trickling_ack() {
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
        page.budget = crate::snapshot_retry::RetryBudget::after_shed(
            Instant::now() - crate::snapshot_retry::RETENTION + Duration::from_millis(500),
            Duration::ZERO,
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let ack = bounded_native_ack(&current[0]);
        let server = std::thread::spawn(move || {
            use std::io::Write;
            let (mut stream, _) = listener.accept().unwrap();
            bounded_native_read(&mut stream);
            if stalled_token {
                std::thread::sleep(Duration::from_millis(600));
                return 0;
            }
            std::thread::sleep(Duration::from_millis(120));
            bounded_native_response(&mut stream, "200 OK", "{\"token\":\"fresh\"}");
            let (mut stream, _) = listener.accept().unwrap();
            bounded_native_read(&mut stream);
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",ack.len()).unwrap();
            for byte in ack.bytes().take(30) {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            1
        });
        let started = Instant::now();
        let result = page.turn(
            &SnapshotApiClient::new(format!("http://{address}")).with_bounded_retry_loopback_http_for_test(),
            &bounded_native_device(),
            "synthetic-secret",
            &current,
            &[1; 32],
            &mut || Ok(()),
        );
        let elapsed = started.elapsed();
        assert!(result.is_err());
        assert!(
            elapsed < Duration::from_millis(900),
            "absolute timeout failed: {elapsed:?}"
        );
        assert_eq!(server.join().unwrap(), usize::from(!stalled_token));
        assert_eq!(page.budget.posts_left(), if stalled_token { 3 } else { 2 });
        assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
        let durable: SnapshotUploadProgress =
            serde_json::from_slice(&std::fs::read(&f.progress_path).unwrap()).unwrap();
        assert_eq!(durable.accepted_fingerprints.len(), 1);
        eprintln!(
            "bounded deadline stalled_token={stalled_token} elapsed_ms={}",
            elapsed.as_millis()
        );
    }
}

#[test]
#[serial(source_upload_deadlines)]
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
    let server = std::thread::spawn(move || {
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
    let client = SnapshotApiClient::new(format!("http://{address}")).with_bounded_retry_loopback_http_for_test();
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

#[test]
fn bounded_retry_native_tls_trickle_cannot_extend_token_or_batch_deadline() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for token in [true, false] {
        let f = SameSourceAckFixture::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0; 4096];
            assert!(stream.read(&mut hello).unwrap() > 0);
            // Incomplete TLS handshake record: every byte arrives within the
            // fixed socket timeout, but completing the record exceeds expiry.
            stream.write_all(&[22, 3, 3, 64, 0]).unwrap();
            for _ in 0..60 {
                if stream.write_all(&[0]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let client = SnapshotApiClient::new(format!("https://{address}"));
        let mut budget = crate::snapshot_retry::RetryBudget::after_shed(
            Instant::now() - crate::snapshot_retry::RETENTION + Duration::from_millis(500),
            Duration::ZERO,
        )
        .unwrap();
        budget.enter(Instant::now()).unwrap();
        let started = Instant::now();
        let result = if token {
            client
                .issue_relay_token_bounded(
                    &bounded_native_device(),
                    "synthetic-secret",
                    SnapshotSource::Codex,
                    &budget,
                    &mut || Ok(()),
                )
                .map(|_| ())
        } else {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: None,
                snapshots: vec![f.items[0].clone()],
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            client
                .upload_batch_bounded("synthetic-token", &request, false, &mut budget, &mut || {
                    Ok(())
                })
                .map(|_| ())
        };
        let elapsed = started.elapsed();
        assert!(result.is_err());
        assert!(
            elapsed < Duration::from_millis(900),
            "TLS trickle escaped expiry: {elapsed:?}"
        );
        assert_eq!(budget.posts_left(), if token { 3 } else { 2 });
        server.join().unwrap();
        eprintln!(
            "bounded TLS token={token} elapsed_ms={}",
            elapsed.as_millis()
        );
    }
}
