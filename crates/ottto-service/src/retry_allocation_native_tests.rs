// Native allocation audit of the optional Pi transport's auxiliary state.
#[test]
fn bounded_retry_envelope_receipt_limit_rejects_before_decoded_amplification() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = test_dir("retry-envelope-receipt");
    std::fs::create_dir_all(&root).unwrap();
    let root = RotationRoot(root);
    crate::upload_receipts::append_transport_error(&root.0, SourceKind::Pi, 1).unwrap();
    let path = crate::upload_receipts::upload_receipts_path(&root.0);
    let seed: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for count in [24_000, 900_000] {
        let mut row = seed["receipts"][0].to_string();
        row.pop();
        row.push_str(",\"unrecognized_extension\":[");
        row.push_str(&"\"\",".repeat(count));
        row.push_str("\"\"]}");
        let body = format!("{{\"schema_version\":1,\"receipts\":[{row}]}}");
        assert!(body.len() < 4 * 1024 * 1024);
        std::fs::write(&path, &body).unwrap();
        let (_, allocation) = crate::retry_allocation_probe::measure(|| {
            assert!(
                crate::upload_receipts::append_transport_error_with_context_bounded(
                    &root.0,
                    SourceKind::Pi,
                    1,
                    &crate::upload_receipts::UploadReceiptContext::default(),
                )
                .is_err()
            );
        });
        eprintln!(
            "receipt_decode_refusal bytes={} requested_peak={} usable_peak={}",
            body.len(),
            allocation.requested_peak,
            allocation.usable_peak
        );
        assert!(allocation.requested_peak < 1024 * 1024);
        assert_eq!(std::fs::read(&path).unwrap(), body.as_bytes());
    }
}

#[test]
fn bounded_retry_envelope_auxiliary_shape_refuses_before_native_decode() {
    let shallow = format!("{{\"future\":[{}0]}}", "0,".repeat(24_000));
    assert!(shallow.len() < crate::snapshot_retry::RESPONSE_BYTES);
    let (_, allocation) = crate::retry_allocation_probe::measure(|| {
        assert!(
            crate::snapshot_retry::decode_state::<serde_json::Value>(shallow.as_bytes()).is_err()
        );
        let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        assert!(crate::snapshot_retry::decode_state::<serde_json::Value>(deep.as_bytes()).is_err());
        assert!(crate::snapshot_retry::decode_state::<serde_json::Value>(b"{} {}").is_err());
    });
    assert!(allocation.requested_peak < 64 * 1024);
    // The response body has a separate cap: legal ACK arrays are not auxiliary
    // checkpoint state and must keep their existing native response contract.
    assert!(serde_json::from_str::<serde_json::Value>(&shallow).is_ok());
}

#[test]
fn bounded_retry_envelope_receipt_node_pressure_evicts_oldest_and_keeps_recording() {
    let root = RotationRoot(test_dir("retry-envelope-receipt-nodes"));
    std::fs::create_dir_all(&root.0).unwrap();
    crate::upload_receipts::append_transport_error(&root.0, SourceKind::Pi, 1).unwrap();
    let path = crate::upload_receipts::upload_receipts_path(&root.0);
    let seed: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let row = seed["receipts"][0].clone();
    let nodes = crate::snapshot_retry::state_nodes(&serde_json::to_vec(&row).unwrap()).unwrap();
    let count = (crate::snapshot_retry::STATE_NODES - 5) / nodes;
    let seeded = serde_json::to_vec(&serde_json::json!({"schema_version":1,"receipts":vec![row;count]})).unwrap();
    assert!(seeded.len() < crate::snapshot_retry::RESPONSE_BYTES);
    crate::snapshot_retry::state_shape(&seeded).unwrap();
    std::fs::write(&path, seeded).unwrap();
    let context = crate::upload_receipts::UploadReceiptContext::default();
    crate::upload_receipts::append_http_failure_with_context_bounded(&root.0, SourceKind::Pi, 1,
        ottto_protocol::UploadReceiptOutcomeV1::AuthRejected, 401, None, None, &context).unwrap();
    let receipts = crate::upload_receipts::read(&root.0, 500, None, None).unwrap().receipts;
    assert_eq!(receipts.len(), count);
    assert_eq!(receipts[0].http_status, Some(401));
    // A second append must advance history again, instead of freezing the ring.
    crate::upload_receipts::append_transport_error_with_context_bounded(&root.0, SourceKind::Pi, 2, &context).unwrap();
    let receipts = crate::upload_receipts::read(&root.0, 500, None, None).unwrap().receipts;
    assert_eq!(receipts.len(), count);
    assert_eq!(receipts[0].batch_item_count, 2);
    assert_eq!(receipts[1].http_status, Some(401));
    crate::snapshot_retry::state_shape(&std::fs::read(path).unwrap()).unwrap();
}

#[test]
fn bounded_retry_envelope_competing_state_refusal_preserves_native_files() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for progress in [false, true] {
        let mut f = PiLiveFixture::new();
        let mut owner = f.capture(Duration::ZERO);
        let path = if progress {
            &f.progress_path
        } else {
            &f.index_path
        };
        let mut value = std::fs::read_to_string(path).unwrap();
        value.pop();
        value.push_str(",\"unknown_future_state\":[");
        value.push_str(&"0,".repeat(24_000));
        value.push_str("0]}");
        assert!(value.len() < crate::snapshot_retry::RESPONSE_BYTES);
        std::fs::write(path, &value).unwrap();
        let before_index = std::fs::read(&f.index_path).unwrap();
        let before_progress = std::fs::read(&f.progress_path).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()))
            .with_bounded_retry_loopback_http_for_test();
        let device = LocalDeviceBinding {
            sources: vec!["pi".into()],
            ..bounded_native_device()
        };
        let mut attempted = 0;
        owner.isolated_boundary(|page| {
            attempted += 1;
            let live = page.take_live_authority()?;
            let result = page.turn_live(
                &client,
                &device,
                "synthetic-secret",
                live.policy(),
                &mut || Ok(()),
            );
            assert!(result.is_err());
            assert_eq!(page.budget.posts_left(), 3);
            page.restore_live_authority(live);
            result
        });
        assert_eq!(attempted, 1);
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
        // Both native optional CAS writers also refuse the same amplified
        // competing shape. A successful remote ACK must never authorize it.
        if progress {
            assert!(f
                .progress
                .save_with_read_limit(
                    &f.progress_path,
                    Some(crate::snapshot_retry::RESPONSE_BYTES)
                )
                .is_err());
        } else {
            assert!(f
                .baseline
                .save_with_read_limit(&f.index_path, crate::snapshot_retry::RESPONSE_BYTES)
                .is_err());
            assert!(checkpoint_partial_snapshot_index_with_read_limit(
                &f.working,
                &f.baseline,
                &f.progress,
                &f.items,
                &BTreeSet::new(),
                &f.index_path,
                &f.progress_path,
                || Ok(()),
                Some(crate::snapshot_retry::RESPONSE_BYTES)
            )
            .is_err());
        }
        assert_eq!(std::fs::read(&f.index_path).unwrap(), before_index);
        assert_eq!(std::fs::read(&f.progress_path).unwrap(), before_progress);
    }
}

#[test]
#[ignore = "process-wide allocation audit requires an isolated --test-threads=1 run"]
fn bounded_retry_envelope_probe_charges_child_threads_and_realloc_overlap() {
    // This audit is run in its own native unit-test process for a heap receipt.
    let old = vec![0u8; 1024 * 1024];
    let (_, allocation) = crate::retry_allocation_probe::measure_process(|| {
        drop(old);
        std::thread::spawn(|| {
            let mut bytes = Vec::with_capacity(512 * 1024);
            bytes.resize(512 * 1024, 7u8);
            bytes.reserve_exact(512 * 1024);
            std::hint::black_box(bytes);
        })
        .join()
        .unwrap();
    });
    assert!(allocation.requested_peak >= 1536 * 1024);
}

struct EnvelopeTls {
    _root: RotationRoot,
    client: std::sync::Arc<ureq::rustls::ClientConfig>,
    server: std::sync::Arc<ureq::rustls::ServerConfig>,
}
impl EnvelopeTls {
    fn new() -> Self {
        use ureq::rustls::pki_types::pem::PemObject;
        let root = RotationRoot(test_dir("retry-envelope-tls"));
        std::fs::create_dir_all(&root.0).unwrap();
        std::fs::write(root.0.join("certificate.cnf"), "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
        // Ephemeral synthetic trust material, never a provider or user secret.
        // Fixture creation is outside the transport allocation scope.
        let output = std::process::Command::new("/usr/bin/openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-config",
                "certificate.cnf",
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem",
            ])
            .current_dir(&root.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic certificate generation failed"
        );
        let certificate = ureq::rustls::pki_types::CertificateDer::from_pem_slice(
            &std::fs::read(root.0.join("cert.pem")).unwrap(),
        )
        .unwrap();
        let key = ureq::rustls::pki_types::PrivateKeyDer::from_pem_slice(
            &std::fs::read(root.0.join("key.pem")).unwrap(),
        )
        .unwrap();
        let mut roots = ureq::rustls::RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let provider = std::sync::Arc::new(ureq::rustls::crypto::ring::default_provider());
        let client = ureq::rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&ureq::rustls::version::TLS12, &ureq::rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server = ureq::rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&ureq::rustls::version::TLS12, &ureq::rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
        Self {
            _root: root,
            client: std::sync::Arc::new(client),
            server: std::sync::Arc::new(server),
        }
    }
    fn serve(&self, responses: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<Vec<Vec<u8>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let config = self.server.clone();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut trace = Vec::new();
            for response in responses {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let connection = ureq::rustls::ServerConnection::new(config.clone()).unwrap();
                let mut stream = ureq::rustls::StreamOwned::new(connection, socket);
                let mut request = Vec::new();
                let mut bytes = [0; 4096];
                while !http_request_complete(&request) {
                    let count = stream.read(&mut bytes).unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&bytes[..count]);
                }
                trace.push(request);
                // An intentionally refused response may close while writing.
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
            trace
        });
        (address, server)
    }
}
fn envelope_response(status: &str, body: &[u8], extra: &str) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
#[ignore = "process-wide allocation audit requires an isolated --test-threads=1 run"]
fn bounded_retry_envelope_native_tls_refuses_aggregate_headers_and_decoded_body() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let tls = EnvelopeTls::new();
    for mode in ["accepted", "headers", "malformed_headers", "gzip", "chunk"] {
        use std::io::Write;
        let (body, extra) = match mode {
            "headers" => (
                b"{\"token\":\"fresh\"}".to_vec(),
                format!(
                    "X-One: {}\r\nX-Two: {}\r\n",
                    "x".repeat(9000),
                    "y".repeat(9000)
                ),
            ),
            "malformed_headers" => (b"{\"token\":\"fresh\"}".to_vec(), format!("\r\r\nX-One: {}\r\n", "x".repeat(18_000))),
            "chunk" => (format!("{}11\r\n{{\"token\":\"fresh\"}}\r\n0\r\n\r\n", "0".repeat(1024 * 1024)).into_bytes(), "Transfer-Encoding: chunked\r\n".into()),
            "gzip" => {
                let body = format!(
                    "{{\"token\":\"{}\"}}",
                    "x".repeat(crate::snapshot_retry::TOKEN_RESPONSE_BYTES)
                );
                let mut compressed =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                compressed.write_all(body.as_bytes()).unwrap();
                (
                    compressed.finish().unwrap(),
                    "Content-Encoding: gzip\r\n".into(),
                )
            }
            _ => (
                b"{\"token\":\"fresh\"}".to_vec(),
                format!("X-One: {}\r\n", "x".repeat(15_000)),
            ),
        };
        let (address, server) = tls.serve(vec![envelope_response("200 OK", &body, &extra)]);
        let (_, allocation) = crate::retry_allocation_probe::measure_process(|| {
            crate::retry_tls::with_test_config(tls.client.clone(), || {
                let client = SnapshotApiClient::new(address);
                let mut budget =
                    crate::snapshot_retry::RetryBudget::after_shed(Instant::now(), Duration::ZERO)
                        .unwrap();
                budget.enter(Instant::now()).unwrap();
                let result = client.issue_relay_token_bounded(
                    &bounded_native_device(),
                    "synthetic-secret",
                    SnapshotSource::Pi,
                    &budget,
                    &mut || Ok(()),
                );
                assert_eq!(result.is_ok(), mode == "accepted", "{mode}");
                assert_eq!(server.join().unwrap().len(), 1);
            });
        });
        eprintln!(
            "native_tls_{mode} requested_peak={} usable_peak={} allocations={}",
            allocation.requested_peak, allocation.usable_peak, allocation.allocations
        );
        assert!(allocation.requested_peak < 20 * 1024 * 1024);
    }
}

#[test]
#[ignore = "process-wide allocation audit requires an isolated --test-threads=1 run"]
fn bounded_retry_envelope_native_max_model_tls_ack_receipt_checkpoint_restart() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let tls = EnvelopeTls::new();
    // Keep the existing wire contract's maximum100model rows, then find the
    // largest admitted escaped labels in this native fixture family. This is
    // a finite boundary fixture, not a claim over every legal shape.
    let invalid = PiLiveFixture::with_models(101);
    let invalid_request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION, source: "pi".into(),
        machine_id: "a".repeat(64), collector_version: Some(collector_version()),
        snapshots: invalid.items.clone(), upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    assert!(validate_snapshot_batch_request(&invalid_request).is_err());
    drop(invalid_request);
    drop(invalid);
    let (mut low, mut high) = (0, 2048);
    while low + 1 < high {
        let middle = (low + high) / 2;
        let mut fixture = PiLiveFixture::with_shape(100, middle);
        if fixture.try_capture(Duration::ZERO).is_some() {
            low = middle;
        } else {
            high = middle;
        }
    }
    let mut refused = PiLiveFixture::with_shape(100, high);
    assert!(refused.try_capture(Duration::ZERO).is_none());
    for replay in [false, true] {
        let (_, allocation) = crate::retry_allocation_probe::measure_process(|| {
            let mut f = PiLiveFixture::with_shape(100, low);
            let mut owner = f.capture(Duration::ZERO);
            let mut ack: serde_json::Value =
                serde_json::from_str(&bounded_native_ack(&f.items[0])).unwrap();
            ack["session_ids"] = serde_json::json!(vec![""; 43_000]);
            let ack = ack.to_string();
            assert!(ack.len() <= crate::snapshot_retry::RESPONSE_BYTES);
            let hint = br#"{"source":"pi","server_time":"2026-10-06T10:05:00Z","last_data_at":null,"record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,"backfill_window_days":30,"recommended_scan_after":"2026-10-06T10:10:00Z"}"#;
            let token = format!("{{\"token\":\"{}\"}}", "t".repeat(15_800));
            let mut responses = vec![
                envelope_response("200 OK", token.as_bytes(), ""),
                envelope_response("200 OK", hint, ""),
            ];
            if replay {
                responses.extend([
                    envelope_response("415 Unsupported Media Type", b"{}", ""),
                    envelope_response("401 Unauthorized", b"{}", ""),
                    envelope_response("200 OK", token.as_bytes(), ""),
                    envelope_response("200 OK", hint, ""),
                ]);
            }
            responses.push(envelope_response("200 OK", ack.as_bytes(), ""));
            let (address, server) = tls.serve(responses);
            let client = SnapshotApiClient::new(address).with_receipt_state_dir(&f.support);
            let device = LocalDeviceBinding {
                sources: vec!["pi".into()],
                ..bounded_native_device()
            };
            let mut turns = 0;
            crate::retry_tls::with_test_config(tls.client.clone(), || {
                owner.isolated_boundary(|page| {
                    turns += 1;
                    assert!(page.bound() <= 1024 * 1024);
                    page.budget.force_gzip_for_test();
                    let live = page.take_live_authority()?;
                    let result = page.turn_live(
                        &client,
                        &device,
                        "synthetic-secret",
                        live.policy(),
                        &mut || live.validate_inputs(&f.home.0),
                    );
                    assert!(
                        matches!(result, Ok(SnapshotPageOutcome::Settled { conflicted: 0 })),
                        "{result:?}"
                    );
                    page.restore_live_authority(live);
                    result
                });
            });
            assert_eq!(turns, 1);
            let trace = server.join().unwrap();
            assert_eq!(trace.len(), if replay { 7 } else { 3 });
            assert_eq!(
                trace
                    .iter()
                    .filter(|bytes| String::from_utf8_lossy(bytes).contains("/batches "))
                    .count(),
                if replay { 3 } else { 1 }
            );
            assert!(String::from_utf8_lossy(&trace[2])
                .to_ascii_lowercase()
                .contains("content-encoding: gzip"));
            let durable = SnapshotUploadProgress::load(
                &f.progress_path,
                &f.progress.destination_namespace_hash,
                test_quarantine_witness(),
            )
            .unwrap();
            assert!(durable.contains_body(
                &f.items[0].snapshot_fingerprint,
                &snapshot_upload_body_witness(&f.items[0])
            ));
            let mut recovered = ScanIndex::load(&f.index_path).unwrap();
            assert_eq!(
                crate::upload_receipts::read(&f.support, 500, None, None)
                    .unwrap()
                    .receipts
                    .len(),
                if replay { 2 } else { 1 }
            );
            let scan = crate::snapshots::scan_source_roots_with_test_limit(
                SnapshotSource::Pi,
                &f.roots,
                &mut recovered,
                "2026-10-06T10:06:00Z",
                30,
                MAX_BACKFILL_FILES_PER_SOURCE,
                false,
            )
            .unwrap();
            assert!(scan.snapshots.is_empty());
            eprintln!("native_envelope models=100 label_bytes_admitted={low} next_refused={high} ack_bytes={} item_json_bytes={} checkpoint_ack_restart=true", ack.len(), serde_json::to_vec(&f.items).unwrap().len());
        });
        eprintln!(
            "native_envelope replay={replay} requested_peak={} usable_peak={} allocations={}",
            allocation.requested_peak, allocation.usable_peak, allocation.allocations
        );
        assert!(allocation.requested_peak < 20 * 1024 * 1024);
    }
}
