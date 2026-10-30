// Native capture/wait/policy/ACK execution; credentials are synthetic adapters.
include!("retry_allocation_native_tests.rs");

#[test]
fn bounded_retry_cutoff_shape_refuses_before_typed_map_decode() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let f = PiLiveFixture::new();
    let path = crate::backfill::backfill_state_path(&f.support);
    let entries = (0..9000)
        .map(|i| format!("\"{i:05}\":\"v\""))
        .collect::<Vec<_>>()
        .join(",");
    let bytes = format!("{{\"completed_parser_versions\":{{{entries}}}}}");
    assert!(bytes.len() < crate::snapshot_retry::RESPONSE_BYTES);
    std::fs::write(&path, &bytes).unwrap();
    let ordinary = crate::backfill::load_backfill_state(&f.support);
    assert_eq!(ordinary.completed_parser_versions.len(), 9000);
    let (live, allocation) = crate::retry_allocation_probe::measure(|| {
        live_snapshot_retry::LiveAuthority::capture(
            SnapshotSource::Pi,
            &f.home.0,
            &f.support,
            &f.hint,
            &f.progress.destination_namespace_hash,
            &ordinary,
            [0; 32],
        )
    });
    eprintln!(
        "cutoff_preparation bytes={} requested_peak={} usable_peak={} optional_admitted={}",
        bytes.len(),
        allocation.requested_peak,
        allocation.usable_peak,
        live.is_some()
    );
    assert!(live.is_none());
    assert!(allocation.requested_peak < 256 * 1024);
    assert_eq!(std::fs::read(&path).unwrap(), bytes.as_bytes());
    assert_eq!(crate::backfill::load_backfill_state(&f.support), ordinary);
}

#[test]
fn bounded_retry_cutoff_node_boundary_preserves_ordinary_state() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let f = PiLiveFixture::new();
    let path = crate::backfill::backfill_state_path(&f.support);
    // One root, one key and one map, then a key/value pair per entry.
    let admitted = (crate::snapshot_retry::STATE_NODES - 3) / 2;
    for (count, expected) in [(admitted, true), (admitted + 1, false)] {
        let entries = (0..count)
            .map(|i| format!("\"{i:05}\":\"v\""))
            .collect::<Vec<_>>()
            .join(",");
        let bytes = format!("{{\"completed_parser_versions\":{{{entries}}}}}");
        assert!(bytes.len() < crate::snapshot_retry::RESPONSE_BYTES);
        assert_eq!(
            crate::snapshot_retry::state_nodes(bytes.as_bytes()).unwrap(),
            3 + count * 2
        );
        std::fs::write(&path, &bytes).unwrap();
        let ordinary = crate::backfill::load_backfill_state(&f.support);
        assert_eq!(ordinary.completed_parser_versions.len(), count);
        let live = live_snapshot_retry::LiveAuthority::capture(
            SnapshotSource::Pi,
            &f.home.0,
            &f.support,
            &f.hint,
            &f.progress.destination_namespace_hash,
            &ordinary,
            [0; 32],
        );
        assert_eq!(live.is_some(), expected);
        if let Some(live) = live {
            live.validate_capture(&f.home.0, &f.items, &f.working)
                .unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes.as_bytes());
        assert_eq!(crate::backfill::load_backfill_state(&f.support), ordinary);
    }
}

struct PiLiveFixture {
    home: RotationRoot,
    daemon: LocalDaemon,
    support: PathBuf,
    roots: Vec<PathBuf>,
    hint: crate::snapshot_client::ActivityHintResponse,
    index_path: PathBuf,
    progress_path: PathBuf,
    baseline: ScanIndex,
    working: ScanIndex,
    items: Vec<SnapshotItem>,
    progress: SnapshotUploadProgress,
    live: Option<live_snapshot_retry::LiveAuthority>,
    native_publication: Option<crate::snapshots::NativePublication>,
}
impl PiLiveFixture {
    fn new() -> Self {
        Self::with_models(1)
    }
    fn with_models(models: usize) -> Self {
        Self::with_shape(models, 0)
    }
    fn with_shape(models: usize, label_bytes: usize) -> Self {
        Self::with_page(1, models, label_bytes)
    }
    fn with_page(files: usize, models: usize, label_bytes: usize) -> Self {
        assert!(
            std::env::var_os("PI_CODING_AGENT_DIR").is_none(),
            "synthetic live retry tests require an isolated Pi root"
        );
        let home = test_dir("retry-live-pi");
        std::fs::create_dir_all(&home).unwrap();
        let home = RotationRoot(home.canonicalize().unwrap());
        let roots = SnapshotSource::Pi.default_roots(&home.0);
        std::fs::create_dir_all(&roots[0]).unwrap();
        let row = r#"{"type":"message_end","message":{"model":"gpt-5.4","timestamp":1791280801000,"usage":{"input":100,"output":1}}}"#;
        let bytes = if models == 1 && label_bytes == 0 {
            format!("{row}\n")
        } else {
            (0..models)
                .map(|i| {
                    let label = (0..label_bytes)
                        .map(|j| match j % 23 {
                            0 => '\\',
                            1 => '\"',
                            2 => '\u{1}',
                            _ => char::from(b'a' + ((i * 17 + j * 31) % 26) as u8),
                        })
                        .collect::<String>();
                    serde_json::json!({"type":"message_end","message":{
                    "model":format!("synthetic-{i:04}-{label}"),"timestamp":1791280801000i64,
                    "usage":{"input":100,"output":1}}})
                    .to_string()
                        + "\n"
                })
                .collect::<String>()
        };
        for file in 0..files {
            let name = if file == 0 {
                "one.jsonl".into()
            } else {
                format!("{file}.jsonl")
            };
            std::fs::write(roots[0].join(name), &bytes).unwrap();
        }
        let support = home.0.join("support");
        std::fs::create_dir_all(&support).unwrap();
        let hint = Self::hint();
        let index_path = support.join("index.json");
        let progress_path = support.join("progress.json");
        let mut baseline = ScanIndex::default();
        baseline.save(&index_path).unwrap();
        let mut progress = test_upload_progress();
        progress.save(&progress_path).unwrap();
        // The real hook freezes inputs before the native parser starts.
        let opens_before = crate::snapshots::all_transcript_opens_for_test();
        let live = live_snapshot_retry::LiveAuthority::capture(
            SnapshotSource::Pi,
            &home.0,
            &support,
            &hint,
            &progress.destination_namespace_hash,
            &Default::default(),
            [0; 32],
        )
        .unwrap();
        assert_eq!(
            crate::snapshots::all_transcript_opens_for_test(),
            opens_before
        );
        let mut working = baseline.clone();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Pi,
            &roots,
            &mut working,
            "2026-10-06T10:05:00Z",
            30,
            MAX_BACKFILL_FILES_PER_SOURCE,
            false,
        )
        .unwrap();
        apply_upload_policy(
            SnapshotSource::Pi,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::Pi, &mut scan, &mut working);
        assert_eq!(scan.snapshots.len(), files);
        assert!(crate::snapshots::all_transcript_opens_for_test() > opens_before);
        let native_publication = scan.native_publication;
        let items = scan.snapshots;
        let opens_after_scan = crate::snapshots::all_transcript_opens_for_test();
        live.validate_capture(&home.0, &items, &working).unwrap();
        assert_eq!(
            crate::snapshots::all_transcript_opens_for_test(),
            opens_after_scan
        );
        Self {
            daemon: test_daemon(&"a".repeat(64)),
            home,
            support,
            roots,
            hint,
            index_path,
            progress_path,
            baseline,
            working,
            items,
            progress,
            live: Some(live),
            native_publication,
        }
    }
    fn hint() -> crate::snapshot_client::ActivityHintResponse {
        serde_json::from_value(
            serde_json::json!({"source":"pi", "server_time":"2026-10-06T10:05:00Z",
            "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
            "local_usage_reconciliation_enabled":true,"backfill_window_days":30,
            "recommended_scan_after":"2026-10-06T10:10:00Z"}),
        )
        .unwrap()
    }
    // Exercise production store reads while keeping every credential synthetic.
    fn bind_turn(
        &mut self,
        client: &SnapshotApiClient,
        endpoint: &str,
        device: &LocalDeviceBinding,
    ) -> [EnvVarGuard; 2] {
        let secrets = self.support.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let guards = [
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &self.support),
            EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets),
        ];
        FileDeviceStore::default().save(device).unwrap();
        std::fs::write(
            secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "synthetic-secret",
        )
        .unwrap();
        std::fs::write(
            self.support.join("connection.json"),
            serde_json::to_vec(&serde_json::json!({
                "setup_run_id":"synthetic", "setup_run_token_expires_at":"synthetic",
                "machine_id":null, "api_base_url":endpoint
            }))
            .unwrap(),
        )
        .unwrap();
        // A destination gets a fresh checkpoint, never a cross-destination CAS.
        self.progress_path = self.support.join("bound-progress.json");
        self.progress = SnapshotUploadProgress::new(
            snapshot_upload_destination_namespace(device, "synthetic-secret"),
            snapshot_quarantine_witness(SnapshotSource::Pi),
        );
        self.progress.save(&self.progress_path).unwrap();
        self.live = Some(
            live_snapshot_retry::LiveAuthority::capture(
                SnapshotSource::Pi,
                &self.home.0,
                &self.support,
                &self.hint,
                &self.progress.destination_namespace_hash,
                &Default::default(),
                client.api_base_seal(),
            )
            .unwrap(),
        );
        guards
    }
    fn capture(&mut self, delay: Duration) -> live_snapshot_retry::LiveRetryOwner {
        self.try_capture(delay).expect("supported native fixture")
    }
    fn try_capture(&mut self, delay: Duration) -> Option<live_snapshot_retry::LiveRetryOwner> {
        self.baseline = checkpoint_partial_snapshot_index(
            &self.working,
            &self.baseline,
            &self.progress,
            &self.items,
            None,
            &BTreeSet::new(),
            &self.index_path,
            &self.progress_path,
            || Ok(()),
        )
        .unwrap();
        let mut owner = live_snapshot_retry::LiveRetryOwner::isolated();
        let opens_before = crate::snapshots::all_transcript_opens_for_test();
        let admitted = owner.capture_after_shed(
            self.live.take().unwrap(),
            &self.home.0,
            SnapshotSource::Pi,
            self.native_publication,
            &"a".repeat(64),
            SnapshotUploadPolicy::default(),
            self.daemon.snapshot_scan_account_witness().unwrap(),
            &self.items,
            &mut self.working,
            &self.baseline,
            &self.progress,
            &self.index_path,
            &self.progress_path,
            Instant::now(),
            delay,
        );
        assert_eq!(
            crate::snapshots::all_transcript_opens_for_test(),
            opens_before
        );
        admitted.then_some(owner)
    }
}

#[test]
fn bounded_retry_live_inputs_decline_rewrites_replacements_new_paths_and_cutoff() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for change in [
        "rewrite",
        "replace",
        "new_file",
        "new_directory",
        "cutoff",
        "uncovered",
        "workspace",
    ] {
        let mut f = PiLiveFixture::new();
        match change {
            "rewrite" => {
                let path = f.roots[0].join("one.jsonl");
                let bytes = std::fs::read_to_string(&path).unwrap();
                std::fs::write(path, bytes.replace("100", "200")).unwrap();
            }
            "replace" => {
                let path = f.roots[0].join("one.jsonl");
                let bytes = std::fs::read(&path).unwrap();
                std::fs::remove_file(&path).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            "new_file" => {
                std::fs::write(f.roots[0].join("two.jsonl"), "{}\n").unwrap();
            }
            "new_directory" => {
                std::fs::create_dir(f.roots[0].join("new")).unwrap();
            }
            "cutoff" => {
                crate::backfill::save_backfill_state(
                    &f.support,
                    &crate::backfill::BackfillState {
                        backfill_cutoff_at: Some("2026-10-06T11:00:00Z".into()),
                        ..Default::default()
                    },
                )
                .unwrap();
            }
            "workspace" => f.items[0].workspace_hash = Some("b".repeat(64)),
            _ => f.items[0].source_file_fingerprint = Some("b".repeat(64)),
        }
        assert!(
            f.live
                .as_ref()
                .unwrap()
                .validate_capture(&f.home.0, &f.items, &f.working)
                .is_err(),
            "{change}"
        );
    }
    let f = PiLiveFixture::new();
    assert!(live_snapshot_retry::LiveAuthority::capture(
        SnapshotSource::Codex,
        &f.home.0,
        &f.support,
        &f.hint,
        "synthetic",
        &Default::default(),
        [0; 32],
    )
    .is_none());
    let mut hint = PiLiveFixture::hint();
    hint.session_attribution_enabled = true;
    assert!(live_snapshot_retry::policy_seal(&hint).is_none());
    hint.session_attribution_enabled = false;
    hint.snapshot_head_cas_required = true;
    assert!(live_snapshot_retry::policy_seal(&hint).is_none());
    assert!(live_snapshot_retry::LiveRetryOwner::production().enabled());
    let closed = live_snapshot_retry::LiveRetryOwner::closed();
    assert!(!closed.enabled());
    let deadline = Instant::now() + Duration::from_secs(300);
    assert_eq!(closed.wake_before(deadline), deadline);
}

#[test]
fn bounded_retry_owner_due_boundary_preserves_ordinary_deadline() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let f = SameSourceAckFixture::new();
    let now = Instant::now();
    let due = now + Duration::from_secs(60);
    let ordinary = now + Duration::from_secs(90);
    let mut owner = super::bounded_snapshot_retry::RetryOwner::default();
    assert!(owner.admit(bounded_native_capture(&f, now)));
    assert_eq!(owner.wake_before(ordinary), due);
    let mut turns = 0;
    owner.boundary(std::iter::empty(), due - Duration::from_nanos(1), |_| {
        turns += 1;
        Ok(SnapshotPageOutcome::Settled { conflicted: 0 })
    });
    assert_eq!(turns, 0);
    assert_eq!(owner.wake_before(ordinary), due);
    owner.boundary(std::iter::empty(), due, |_| {
        turns += 1;
        Ok(SnapshotPageOutcome::Settled { conflicted: 0 })
    });
    assert_eq!(turns, 1);
    assert_eq!(owner.wake_before(ordinary), ordinary);
    owner.boundary(std::iter::empty(), ordinary, |_| {
        turns += 1;
        Ok(SnapshotPageOutcome::Settled { conflicted: 0 })
    });
    assert_eq!(turns, 1);
}

#[test]
// The bounded turn leases the shared client_report counters across its token/batch I/O.
#[serial(client_report)]
fn bounded_retry_live_ack_lost_resends_same_revision_without_second_contribution() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut f = PiLiveFixture::new();
    let item = &f.items[0];
    let witness = snapshot_upload_body_witness(item);
    let revision = serde_json::to_value(crate::snapshots::snapshot_semantic_envelope(
        SnapshotSource::Pi,
        item,
        SnapshotUploadPolicy::default(),
    ))
    .unwrap();
    assert!(revision["revision_v2_hash"].as_str().unwrap().len() >= 64);
    let expected_tokens = item.input_tokens + item.output_tokens;
    assert_eq!(expected_tokens, 101);
    let ack = bounded_native_ack(item);
    let hint = serde_json::json!({"source":"pi", "server_time":"2026-10-06T10:05:00Z",
        "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
        "local_usage_reconciliation_enabled":true,"backfill_window_days":30,
        "recommended_scan_after":"2026-10-06T10:10:00Z"})
    .to_string();
    let initial = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "pi".into(),
        machine_id: "a".repeat(64),
        collector_version: Some(collector_version()),
        snapshots: f.items.clone(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()))
        .with_bounded_retry_loopback_http_for_test();
    let expected_witness = witness.clone();
    let expected_revision = revision.clone();
    let server = bounded_native_server(listener, move |listener| {
        // Synthetic backend revision store: an identical already-accepted
        // revision has one contribution. Assert the actual wire bodies agree,
        // rather than teaching a second client-side equality rule to the test.
        let mut revisions = BTreeMap::new();
        let mut contributions = 0;
        let mut tokens = 0;
        let mut posts = Vec::new();
        for step in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            let bytes = bounded_native_read(&mut stream);
            let request = String::from_utf8(bytes).unwrap();
            if step == 2 {
                assert!(request.contains("/relay-token "));
                bounded_native_response(&mut stream, "200 OK", "{\"token\":\"fresh\"}");
                continue;
            }
            if step == 3 {
                assert!(request.contains("/activity-hints "));
                bounded_native_response(&mut stream, "200 OK", &hint);
                continue;
            }
            assert!(request.contains("/batches "));
            let request: serde_json::Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            let body = &request["snapshots"][0];
            assert_eq!(body["semantic_envelope"], expected_revision);
            let body_bytes = serde_json::to_vec(&request["snapshots"]).unwrap();
            posts.push(body_bytes.clone());
            if step == 1 {
                bounded_native_response(&mut stream, "429 Too Many Requests", "{}");
                continue;
            }
            let key = (
                body["source_session_id"].as_str().unwrap().to_owned(),
                body["semantic_envelope"]["revision_v2_hash"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
            match revisions.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    contributions += 1;
                    tokens += body["input_tokens"].as_u64().unwrap()
                        + body["output_tokens"].as_u64().unwrap();
                    entry.insert((body_bytes, expected_witness.clone()));
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    assert_eq!(entry.get(), &(body_bytes, expected_witness.clone()));
                }
            }
            if step == 0 {
                // The backend committed, then the ACK was lost. No response.
                drop(stream);
            } else {
                bounded_native_response(&mut stream, "200 OK", &ack);
            }
        }
        assert_eq!(posts.len(), 3);
        assert!(posts.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(revisions.len(), 1);
        assert_eq!(contributions, 1);
        assert_eq!(tokens, expected_tokens);
        revisions.into_values().next().unwrap()
    });
    let before_index = std::fs::read(&f.index_path).unwrap();
    let before_progress = std::fs::read(&f.progress_path).unwrap();
    assert!(client.upload_batch("initial", &initial, false).is_err());
    assert_eq!(std::fs::read(&f.index_path).unwrap(), before_index);
    assert_eq!(std::fs::read(&f.progress_path).unwrap(), before_progress);
    assert!(!f
        .progress
        .contains_body(&f.items[0].snapshot_fingerprint, &witness));
    let shed = attempt_snapshot_page(
        &f.items,
        &[0],
        "pi",
        &mut f.progress,
        &mut 0,
        &|item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
        &snapshot_upload_body_witness,
        &|item: &SnapshotItem| Some(item.source_session_id.as_str()),
        &mut |snapshots| {
            client.upload_batch(
                "ordinary-retry",
                &SnapshotBatchRequest {
                    snapshots,
                    ..initial.clone()
                },
                false,
            )
        },
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(shed.downcast_ref::<UploadShed>().unwrap().status, 429);
    let mut owner = f.capture(Duration::ZERO);
    let device = LocalDeviceBinding {
        sources: vec!["pi".into()],
        ..bounded_native_device()
    };
    let opens = crate::snapshots::all_transcript_opens_for_test();
    let mut turns = 0;
    owner.isolated_boundary(|page| {
        turns += 1;
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
    assert_eq!(turns, 1);
    assert_eq!(crate::snapshots::all_transcript_opens_for_test(), opens);
    let (accepted_body, accepted_witness) = server.join().unwrap();
    assert_eq!(
        accepted_body,
        serde_json::to_vec(&serde_json::to_value(&initial).unwrap()["snapshots"]).unwrap()
    );
    assert_eq!(accepted_witness, witness);
    assert_eq!(snapshot_upload_body_witness(&f.items[0]), witness);
    let durable = SnapshotUploadProgress::load(
        &f.progress_path,
        &f.progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .unwrap();
    assert!(durable.contains_body(&f.items[0].snapshot_fingerprint, &witness));
    let mut recovered = ScanIndex::load(&f.index_path).unwrap();
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
    eprintln!("native_ack_lost snapshots_identical=true same_revision=true contributions=1 tokens={expected_tokens} witness_unchanged=true checkpoint_ack_restart=true");
}

#[test]
// The bounded turn leases the shared client_report counters across its token/batch I/O.
#[serial(client_report)]
fn bounded_retry_live_wait_sends_without_scan_and_preserves_ordinary_deadline_and_ack() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let (_, allocation) = crate::retry_allocation_probe::measure(|| {
        let mut f = PiLiveFixture::new();
        let ordinary_body = {
            let mut index = f.baseline.clone();
            let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
                SnapshotSource::Pi,
                &f.roots,
                &mut index,
                "2026-10-06T10:05:00Z",
                30,
                MAX_BACKFILL_FILES_PER_SOURCE,
                false,
            )
            .unwrap();
            apply_upload_policy(
                SnapshotSource::Pi,
                &mut scan.snapshots,
                SnapshotUploadPolicy::default(),
            );
            finalize_scan_after_policy(SnapshotSource::Pi, &mut scan, &mut index);
            serde_json::to_value(SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "pi".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: scan.snapshots,
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            })
            .unwrap()["snapshots"]
                .clone()
        };
        let shed = attempt_snapshot_page(
            &f.items,
            &[0],
            "pi",
            &mut f.progress,
            &mut 0,
            &|item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
            &snapshot_upload_body_witness,
            &|item: &SnapshotItem| Some(item.source_session_id.as_str()),
            &mut |items| {
                assert_eq!(
                    serde_json::to_value(&items).unwrap(),
                    serde_json::to_value(&f.items).unwrap()
                );
                Err(anyhow::Error::new(UploadShed {
                    status: 429,
                    retry_after: Some(Duration::from_millis(30)),
                    code: None,
                }))
            },
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(shed.downcast_ref::<UploadShed>().unwrap().status, 429);
        let mut owner = f.capture(Duration::from_millis(30));
        assert!(owner.enabled());
        let opens_before_retry = crate::snapshots::all_transcript_opens_for_test();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()))
            .with_bounded_retry_loopback_http_for_test();
        let mut ack: serde_json::Value =
            serde_json::from_str(&bounded_native_ack(&f.items[0])).unwrap();
        // Legal response amplification: every empty array string still owns
        // its native String slot. Exercise the byte cap's decoded allocation.
        ack["session_ids"] = serde_json::json!(vec![""; 20_000]);
        let ack = ack.to_string();
        assert!(ack.len() < crate::snapshot_retry::RESPONSE_BYTES);
        let hint=serde_json::to_string(&serde_json::json!({"source":"pi", "server_time":"2026-10-06T10:05:00Z",
            "last_data_at":null,"record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,
            "backfill_window_days":30,"recommended_scan_after":"2026-10-06T10:10:00Z"})).unwrap();
        let server = bounded_native_server(listener, move |listener| {
            let mut trace = Vec::new();
            for body in ["{\"token\":\"fresh\"}", hint.as_str(), ack.as_str()] {
                let (mut stream, _) = listener.accept().unwrap();
                trace.push(String::from_utf8_lossy(&bounded_native_read(&mut stream)).into_owned());
                bounded_native_response(&mut stream, "200 OK", body);
            }
            trace
        });
        let device = LocalDeviceBinding {
            sources: vec!["pi".into()],
            ..bounded_native_device()
        };
        let daemon = &f.daemon;
        let mut turns = 0;
        let mut anchored = None;
        // Synchronize fixture eligibility before starting the ordinary wait.
        // A 30ms sleep inside that 150ms wait can resume after its deadline;
        // the production loop then correctly returns without entering a turn.
        // Due/wake ordering is tested above with explicit Instants, independent
        // of scheduler latency. This native test retains the real idle boundary,
        // transport, exact ACK and unchanged ordinary wait/anchor assertions.
        let due = owner.wake_before(Instant::now() + Duration::from_secs(1));
        bounded_native_wait_until(due);
        assert!(Instant::now() >= due);
        let started = Instant::now();
        collect_file_activity_with_retry(
            Duration::from_millis(150),
            None,
            &mut ClaudeAccountSwitchProbe::default(),
            |ordinary| {
                assert_eq!(*anchored.get_or_insert(ordinary), ordinary);
                owner.isolated_boundary(|page| {
                    turns += 1;
                    assert!(page.bound() <= 1024 * 1024);
                    let expected_account = page.authority();
                    let live = page.take_live_authority()?;
                    let result = page.turn_live(
                        &client,
                        &device,
                        "synthetic-secret",
                        live.policy(),
                        &mut || {
                            anyhow::ensure!(daemon.snapshot_retry_running().unwrap(), "stopped");
                            anyhow::ensure!(
                                daemon.snapshot_scan_account_witness().unwrap() == expected_account,
                                "account changed"
                            );
                            live.validate_inputs(&f.home.0)
                        },
                    );
                    assert!(
                        matches!(result, Ok(SnapshotPageOutcome::Settled { conflicted: 0 })),
                        "live retry failed: {}",
                        result
                            .as_ref()
                            .err()
                            .map(|e| e.to_string())
                            .unwrap_or_default()
                    );
                    page.restore_live_authority(live);
                    result
                });
                owner.wake_before(ordinary)
            },
            || None,
        );
        assert_eq!(turns, 1);
        assert!(started.elapsed() >= Duration::from_millis(150));
        let trace = server.join().unwrap();
        assert!(trace[0].starts_with("POST ") && trace[0].contains("/relay-token "));
        assert!(trace[1].starts_with("GET ") && trace[1].contains("/activity-hints "));
        assert!(trace[2].contains("/batches "));
        let request_body = trace[2].split_once("\r\n\r\n").unwrap().1;
        let request: serde_json::Value = serde_json::from_str(request_body).unwrap();
        assert_eq!(request["snapshots"], ordinary_body);
        assert_eq!(
            crate::snapshots::all_transcript_opens_for_test(),
            opens_before_retry
        );
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
        let checkpoint = ScanIndex::load(&f.index_path).unwrap();
        assert!(checkpoint.files.len() == 1);
        let mut recovered = checkpoint.clone();
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
        assert!(serde_json::to_value(checkpoint)
            .unwrap()
            .get("completed_historical_replay_generation")
            .is_none());
        eprintln!("native_live_wait turns=1 tokens=1 policy_gets=1 batches=1 fresh_scan=0 exact_ack_restart=true ordinary_anchor_preserved=true");
    });
    eprintln!(
        "native_live_allocation requested_peak={} usable_peak={} allocations={}",
        allocation.requested_peak, allocation.usable_peak, allocation.allocations
    );
    assert!(allocation.requested_peak < 20 * 1024 * 1024);
}

#[test]
// The bounded turn leases the shared client_report counters across its token/batch I/O.
#[serial]
#[serial(client_report)]
fn bounded_retry_live_policy_and_stop_fences_prevent_batch_and_publication() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for change in [
        "policy",
        "stop",
        "account",
        "file",
        "cutoff",
        "destination",
        "grant",
    ] {
        let mut f = PiLiveFixture::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let client = SnapshotApiClient::new(&endpoint).with_bounded_retry_loopback_http_for_test();
        let device = LocalDeviceBinding {
            sources: vec!["pi".into()],
            ..bounded_native_device()
        };
        let _stores = f.bind_turn(&client, &endpoint, &device);
        // Matching stores pass every production check before one fence changes.
        f.live
            .as_ref()
            .unwrap()
            .validate_turn(
                &client,
                &f.daemon,
                (
                    &device,
                    SnapshotSource::Pi,
                    &f.daemon.snapshot_scan_account_witness().unwrap(),
                ),
                &f.home.0,
            )
            .unwrap();
        let mut owner = f.capture(Duration::ZERO);
        let before = std::fs::read(&f.index_path).unwrap();
        let no_post = listener.try_clone().unwrap();
        let server = if change != "policy" {
            None
        } else {
            Some(bounded_native_server(listener, move |listener| {
                for body in [
                    "{\"token\":\"fresh\"}",
                    r#"{"source":"pi","server_time":"2026-10-06T10:05:00Z","last_data_at":null,"record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,"backfill_window_days":30,"session_titles_enabled":false,"recommended_scan_after":"2026-10-06T10:10:00Z"}"#,
                ] {
                    let (mut stream, _) = listener.accept().unwrap();
                    bounded_native_read(&mut stream);
                    bounded_native_response(&mut stream, "200 OK", body);
                }
                let listener = listener.into_inner();
                listener.set_nonblocking(true).unwrap();
                listener
            }))
        };
        let daemon = &f.daemon;
        if change == "stop" {
            daemon.stop_for_trusted_client().unwrap();
        }
        if change == "account" {
            let mut account = daemon.account_for_trusted_client().unwrap();
            account.connected_at = Some("changed".into());
            daemon.clone().with_account(account);
        }
        if change == "file" {
            std::fs::write(f.roots[0].join("one.jsonl"), "{}\n").unwrap();
        }
        if change == "cutoff" {
            crate::backfill::save_backfill_state(
                &f.support,
                &crate::backfill::BackfillState {
                    backfill_cutoff_at: Some("2026-10-06T11:00:00Z".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        }
        if change == "destination" {
            std::fs::write(
                f.support
                    .join("secrets")
                    .join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
                "changed-secret",
            )
            .unwrap();
        }
        if change == "grant" {
            FileDeviceStore::default()
                .save(&LocalDeviceBinding {
                    sources: vec![],
                    ..device.clone()
                })
                .unwrap();
        }
        let mut attempted = 0;
        owner.isolated_boundary(|page| {
            attempted += 1;
            let expected_account = page.authority();
            let live = page.take_live_authority()?;
            let result = page.turn_live(
                &client,
                &device,
                "synthetic-secret",
                live.policy(),
                &mut || {
                    live.validate_turn(
                        &client,
                        daemon,
                        (&device, SnapshotSource::Pi, &expected_account),
                        &f.home.0,
                    )
                },
            );
            assert!(result.is_err());
            assert_eq!(page.budget.posts_left(), 3);
            page.restore_live_authority(live);
            result
        });
        assert_eq!(attempted, 1);
        assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
        no_post.set_nonblocking(true).unwrap();
        assert!(matches!(no_post.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
        if let Some(server) = server {
            let listener = server.join().unwrap();
            assert!(matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        }
    }
}

#[test]
fn bounded_retry_live_legacy_reconciliation_declines_without_count_only_settlement() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut f = PiLiveFixture::new();
    // Reopen an actual native index in the pre-settlement-ledger shape.
    let mut value = serde_json::to_value(&f.working).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("accepted_snapshot_fingerprint_ledger_version");
    object.remove("accepted_snapshot_fingerprints");
    f.working = serde_json::from_value(value).unwrap();
    let (pending, changed) = f
        .working
        .prepare_legacy_settlement_reconciliation(SnapshotSource::Pi, 50);
    assert!(changed && pending.contains(&f.items[0].snapshot_fingerprint));
    assert!(f.working.legacy_settlement_ledger_needs_migration());
    f.working.save(&f.index_path).unwrap();
    f.baseline = f.working.clone();
    let checkpoint = checkpoint_partial_snapshot_index(
        &f.working,
        &f.baseline,
        &f.progress,
        &f.items,
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
    let before = std::fs::read(&f.index_path).unwrap();
    let mut owner = live_snapshot_retry::LiveRetryOwner::isolated();
    assert!(!owner.capture_after_shed(
        f.live.take().unwrap(),
        &f.home.0,
        SnapshotSource::Pi,
        None,
        &"a".repeat(64),
        SnapshotUploadPolicy::default(),
        f.daemon.snapshot_scan_account_witness().unwrap(),
        &f.items,
        &mut f.working,
        &checkpoint,
        &f.progress,
        &f.index_path,
        &f.progress_path,
        Instant::now(),
        Duration::ZERO
    ));
    let mut turns = 0;
    owner.isolated_boundary(|_| {
        turns += 1;
        unreachable!("legacy reconciliation cannot reach a retained token or POST")
    });
    assert_eq!(turns, 0);
    assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
    // Existing ordinary delivery still refuses a count-only ACK for these
    // native legacy fingerprints. No alternative classifier is introduced.
    assert!(require_normal_write_ack_for_legacy_reconciliation(
        &accepted_batch(1),
        &pending,
        &pending
    )
    .is_err());
    let durable = SnapshotUploadProgress::load(
        &f.progress_path,
        &f.progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .unwrap();
    assert!(!durable.contains_body(
        &f.items[0].snapshot_fingerprint,
        &snapshot_upload_body_witness(&f.items[0])
    ));
    eprintln!("native_live_legacy_refusal turns=0 no_token_or_post=true count_only_ack_rejected=true no_index_publish=true");
}

#[test]
fn bounded_retry_json_escape_admission_declines_before_retained_copy_and_wire_growth() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut f = PiLiveFixture::new();
    f.items[0].session_display_name = Some("\u{0001}".repeat(30_000));
    assert!(!crate::snapshot_retry::json_fits(
        &f.items,
        crate::snapshot_retry::REQUEST_BYTES / 2
    ));
    let (_, stats) = crate::retry_allocation_probe::measure(|| {
        assert!(bounded_snapshot_retry::PreparedRetry::capture(
            SnapshotSource::Pi,
            &"a".repeat(64),
            SnapshotUploadPolicy::default(),
            [1; 32],
            &f.items,
            &f.working,
            &f.baseline,
            &f.progress,
            &f.index_path,
            &f.progress_path,
            Instant::now(),
            Duration::ZERO,
            1024 * 1024
        )
        .is_none());
    });
    assert!(stats.requested_peak < 16 * 1024);
    assert!(
        crate::snapshot_retry::encode_json(&f.items, crate::snapshot_retry::REQUEST_BYTES / 2)
            .is_err()
    );
    eprintln!(
        "native_escape_refusal requested_peak={} no_retained_copy=true",
        stats.requested_peak
    );
}

#[cfg(unix)]
#[test]
fn pi_retry_stat_witness_ignores_chmod_but_refuses_append_and_mtime() {
    use std::os::unix::fs::PermissionsExt;
    for change in ["chmod", "append", "mtime", "mtime_ns"] {
        let f = PiLiveFixture::new();
        let path = f.roots[0].join("one.jsonl");
        let opens = crate::snapshots::all_transcript_opens_for_test();
        match change {
            "chmod" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap()
            }
            "append" => {
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"\n")
                    .unwrap();
            }
            "mtime_ns" => {
                use std::os::unix::fs::MetadataExt;
                let before = std::fs::symlink_metadata(&path).unwrap();
                let ns = (before.mtime_nsec() as u32 + 1) % 1_000_000_000;
                let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                file.set_times(std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + Duration::new(before.mtime() as u64, ns),
                ))
                .unwrap();
                let after = std::fs::symlink_metadata(&path).unwrap();
                assert_eq!(after.mtime(), before.mtime());
                assert_ne!(after.mtime_nsec(), before.mtime_nsec());
            }
            _ => {
                let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                file.set_times(
                    std::fs::FileTimes::new()
                        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1)),
                )
                .unwrap();
            }
        }
        assert_eq!(
            f.live
                .as_ref()
                .unwrap()
                .validate_capture(&f.home.0, &f.items, &f.working)
                .is_ok(),
            change == "chmod",
            "{change}"
        );
        assert_eq!(crate::snapshots::all_transcript_opens_for_test(), opens);
    }
}

#[test]
fn pi_retry_index_representation_transition_refuses_before_post() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut f = PiLiveFixture::new();
    let mut owner = f.capture(Duration::ZERO);
    let mut representation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&f.index_path).unwrap()).unwrap();
    // E1's existing V-row contract: a changed index schema is a new
    // representation even with unchanged checkpoint generation and Pi bytes.
    representation["schema_version"] = serde_json::json!(f.baseline.schema_version + 1);
    std::fs::write(&f.index_path, serde_json::to_vec(&representation).unwrap()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()))
        .with_bounded_retry_loopback_http_for_test();
    let device = LocalDeviceBinding {
        sources: vec!["pi".into()],
        ..bounded_native_device()
    };
    let mut turns = 0;
    owner.isolated_boundary(|page| {
        turns += 1;
        let live = page.take_live_authority()?;
        let result = page.turn_live(
            &client,
            &device,
            "synthetic-secret",
            live.policy(),
            &mut || live.validate_inputs(&f.home.0),
        );
        assert!(result.is_err());
        assert_eq!(page.budget.posts_left(), 3);
        page.restore_live_authority(live);
        result
    });
    assert_eq!(turns, 1);
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn pi_retry_checkpoint_comparison_accepts_both_native_encodings() {
    let f = PiLiveFixture::new();
    for pretty in [false, true] {
        let bytes = if pretty {
            serde_json::to_vec_pretty(&f.baseline).unwrap()
        } else {
            serde_json::to_vec(&f.baseline).unwrap()
        };
        std::fs::write(&f.index_path, bytes).unwrap();
        assert!(
            bounded_snapshot_retry::checkpoint_matches(&f.index_path, &f.baseline, false).unwrap()
        );
        let mut changed = f.baseline.clone();
        changed.schema_version += 1;
        assert!(
            !bounded_snapshot_retry::checkpoint_matches(&f.index_path, &changed, false).unwrap()
        );
    }
}

#[test]
#[serial]
#[serial(client_report)]
fn retained_endpoint_change_refuses_before_relay_token_or_post() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut f = PiLiveFixture::new();
    let original = SnapshotApiClient::new("https://original.invalid");
    let device = LocalDeviceBinding {
        sources: vec!["pi".into()],
        ..bounded_native_device()
    };
    let _stores = f.bind_turn(&original, "https://original.invalid", &device);
    assert!(f
        .live
        .as_ref()
        .unwrap()
        .validate_turn(
            &original,
            &f.daemon,
            (
                &device,
                SnapshotSource::Pi,
                &f.daemon.snapshot_scan_account_witness().unwrap()
            ),
            &f.home.0
        )
        .is_ok());
    let mut owner = f.capture(Duration::ZERO);
    let before = std::fs::read(&f.index_path).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    // Match the fresh client to the changed persisted endpoint: only the
    // retained endpoint fence can distinguish this from a valid new turn.
    let mut connection = FileConnectionStore::default().load().unwrap().unwrap();
    connection.api_base_url = format!("http://{}", listener.local_addr().unwrap());
    FileConnectionStore::default().save(&connection).unwrap();
    let changed = SnapshotApiClient::new(&connection.api_base_url)
        .with_bounded_retry_loopback_http_for_test();
    assert!(changed.matches_api_base(&snapshot_api_base_url().unwrap()));
    let mut attempted = 0;
    owner.isolated_boundary(|page| {
        attempted += 1;
        let authority = page.authority();
        let live = page.take_live_authority()?;
        let result = page.turn_live(
            &changed,
            &device,
            "synthetic-secret",
            live.policy(),
            &mut || {
                live.validate_turn(
                    &changed,
                    &f.daemon,
                    (&device, SnapshotSource::Pi, &authority),
                    &f.home.0,
                )
            },
        );
        assert!(result.is_err());
        assert_eq!(page.budget.posts_left(), 3);
        page.restore_live_authority(live);
        result
    });
    assert_eq!(attempted, 1);
    assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
    listener.set_nonblocking(true).unwrap();
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

// Exercise the real native consumer and the ordinary/retained HTTP ACK paths.
// Non-receipt cases inject typed e4 outcomes, never NativePublication values.
fn pi_publication_ack(items: &[SnapshotItem]) -> String {
    let mut ack: serde_json::Value = serde_json::from_str(&bounded_native_ack(&items[0])).unwrap();
    ack["accepted"] = items.len().into();
    ack["sessions_reconciled"] = items.len().into();
    ack["accepted_entities"] = items
        .iter()
        .map(|item| {
            let one: serde_json::Value = serde_json::from_str(&bounded_native_ack(item)).unwrap();
            one["accepted_entities"][0].clone()
        })
        .collect::<Vec<_>>()
        .into();
    ack.to_string()
}

fn pi_publication_post(f: &mut PiLiveFixture, retained: bool) {
    let items = f.items.clone();
    assert!(!items.is_empty());
    let wire = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "pi".into(),
        machine_id: "a".repeat(64),
        collector_version: Some(collector_version()),
        snapshots: items.clone(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let expected = serde_json::to_value(&wire).unwrap()["snapshots"].clone();
    let expected_post = expected.clone();
    let ack = pi_publication_ack(&items);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()))
        .with_bounded_retry_loopback_http_for_test();
    let server = bounded_native_server(listener, move |listener| {
        let (mut stream, _) = listener.accept().unwrap();
        let bytes = bounded_native_read(&mut stream);
        let request = String::from_utf8(bytes).unwrap();
        assert!(request.contains("/batches "));
        let body: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            body["snapshots"], expected_post,
            "actual accepted POST body"
        );
        bounded_native_response(&mut stream, "200 OK", &ack);
        body["snapshots"].clone()
    });
    if retained {
        let mut owner = f.capture(Duration::ZERO);
        let device = LocalDeviceBinding {
            sources: vec!["pi".into()],
            ..bounded_native_device()
        };
        let mut turns = 0;
        owner.isolated_boundary(|page| {
            turns += 1;
            let live = page.take_live_authority()?;
            let result = page.turn_live(
                &client,
                &device,
                "synthetic-secret",
                live.policy(),
                &mut || live.validate_inputs(&f.home.0),
            );
            page.restore_live_authority(live);
            result
        });
        assert_eq!(turns, 1, "exactly one retained retry");
        owner.isolated_boundary(|_| panic!("settled retry must have been removed"));
        f.progress = SnapshotUploadProgress::load(
            &f.progress_path,
            &f.progress.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .unwrap();
        f.baseline = ScanIndex::load(&f.index_path).unwrap();
    } else {
        let indices = (0..items.len()).collect::<Vec<_>>();
        attempt_snapshot_page(
            &items,
            &indices,
            "pi",
            &mut f.progress,
            &mut 0,
            &|item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
            &snapshot_upload_body_witness,
            &|item: &SnapshotItem| Some(item.source_session_id.as_str()),
            &mut |snapshots| {
                client.upload_batch(
                    "synthetic",
                    &SnapshotBatchRequest {
                        schema_version: SNAPSHOT_SCHEMA_VERSION,
                        source: "pi".into(),
                        machine_id: "a".repeat(64),
                        collector_version: Some(collector_version()),
                        snapshots,
                        upload_policy: SnapshotUploadPolicy::default(),
                        client_report: crate::client_report::ClientReport::empty(),
                    },
                    false,
                )
            },
            &mut |progress| progress.save(&f.progress_path),
        )
        .unwrap();
        f.baseline = checkpoint_partial_snapshot_index(
            &f.working,
            &f.baseline,
            &f.progress,
            &items,
            None,
            &BTreeSet::new(),
            &f.index_path,
            &f.progress_path,
            || Ok(()),
        )
        .unwrap();
    }
    let accepted = server.join().unwrap();
    assert_eq!(accepted, expected);
    for item in &items {
        let witness = snapshot_upload_body_witness(item);
        assert!(f
            .progress
            .contains_body(&item.snapshot_fingerprint, &witness));
        let entry = f
            .baseline
            .files
            .values()
            .find(|entry| {
                Some(entry.source_file_fingerprint.as_str())
                    == item.source_file_fingerprint.as_deref()
            })
            .expect("accepted native file entry");
        assert_eq!(
            entry.last_snapshot_fingerprint.as_deref(),
            Some(item.snapshot_fingerprint.as_str())
        );
        assert_eq!(
            entry.last_upload_body_witness.as_deref(),
            Some(witness.as_str())
        );
    }
}

fn pi_native_publication_page(
    files: usize,
    outcome: Option<crate::snapshots::native_publication_tests::E4Outcome>,
) -> (PiLiveFixture, BTreeMap<String, serde_json::Value>) {
    use crate::snapshots::{e2_pipeline_scan_fixture::E2ScanFixture, native_publication_tests};
    let mut f = PiLiveFixture::with_page(files, 1, 0);
    pi_publication_post(&mut f, false);
    f.working = f.baseline.clone();
    let accepted = f
        .baseline
        .files
        .iter()
        .map(|(key, entry)| (key.clone(), serde_json::to_value(entry).unwrap()))
        .collect::<BTreeMap<_, _>>();
    let target = accepted.keys().next().unwrap().clone();
    let _outcome =
        outcome.map(|outcome| native_publication_tests::inject_settlement(target, outcome));
    for key in accepted.keys() {
        use std::io::Write;
        std::fs::OpenOptions::new().append(true).open(key).unwrap().write_all(
            b"{\"type\":\"message_end\",\"message\":{\"id\":\"synthetic-growth\",\"model\":\"gpt-5.4\",\"timestamp\":1791280861000,\"usage\":{\"input\":200,\"output\":2}}}\n"
        ).unwrap();
    }
    f.live = Some(
        live_snapshot_retry::LiveAuthority::capture(
            SnapshotSource::Pi,
            &f.home.0,
            &f.support,
            &f.hint,
            &f.progress.destination_namespace_hash,
            &Default::default(),
            [0; 32],
        )
        .unwrap(),
    );
    crate::locked_state_dir::test_locks::hold(&f.support);
    let scanner = E2ScanFixture::default();
    scanner.begin_durable(SnapshotSource::Pi, &f.support, &f.index_path);
    let (mut working, mut scan, mode) = scanner.scan_other(
        SnapshotSource::Pi,
        &f.roots,
        &f.support,
        f.baseline.clone(),
        true,
    );
    assert_eq!(mode, (files, 0, 0), "first actual native Pi acquisitions");
    native_publication_tests::assert_settlement_consumed();

    apply_upload_policy(
        SnapshotSource::Pi,
        &mut scan.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy(SnapshotSource::Pi, &mut scan, &mut working);
    f.native_publication = scan.native_publication;
    f.items = scan.snapshots;
    f.working = working;
    (f, accepted)
}

fn pi_native_receipt_restores_tail(f: &PiLiveFixture) {
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let path = f.roots[0].join("one.jsonl");
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(
        b"{\"type\":\"message_end\",\"message\":{\"id\":\"synthetic-restore\",\"model\":\"gpt-5.4\",\"timestamp\":1791280921000,\"usage\":{\"input\":10,\"output\":1}}}\n"
    ).unwrap();
    let restarted = E2ScanFixture::default();
    restarted.begin_durable(SnapshotSource::Pi, &f.support, &f.index_path);
    let (mut disk_index, mut disk, mode) = restarted.scan_other(
        SnapshotSource::Pi,
        &f.roots,
        &f.support,
        f.baseline.clone(),
        true,
    );
    assert_eq!(
        mode,
        (0, 1, 0),
        "real native receipt restores + Tail after restart"
    );
    assert_eq!(
        disk.native_publication,
        Some(crate::snapshots::NativePublication::Receipted)
    );
    assert_eq!(
        restarted
            .cache
            .durable_counters(SnapshotSource::Pi)
            .unwrap()
            .0
            .restored,
        1
    );
    apply_upload_policy(
        SnapshotSource::Pi,
        &mut disk.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy(SnapshotSource::Pi, &mut disk, &mut disk_index);
    let (mut cold_index, mut cold, _) = E2ScanFixture::default().scan_other(
        SnapshotSource::Pi,
        &f.roots,
        &f.support,
        f.baseline.clone(),
        true,
    );
    apply_upload_policy(
        SnapshotSource::Pi,
        &mut cold.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy(SnapshotSource::Pi, &mut cold, &mut cold_index);
    assert_eq!(
        serde_json::to_value(&disk.snapshots).unwrap(),
        serde_json::to_value(&cold.snapshots).unwrap()
    );
    assert_eq!(disk.snapshots.len(), 1);
    assert_eq!(
        snapshot_upload_body_witness(&disk.snapshots[0]),
        snapshot_upload_body_witness(&cold.snapshots[0])
    );
}

fn pi_publication_case(
    expected: crate::snapshots::NativePublication,
    outcome: Option<crate::snapshots::native_publication_tests::E4Outcome>,
) {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let (mut f, accepted) = pi_native_publication_page(1, outcome);
    assert_eq!(
        f.native_publication,
        Some(expected),
        "carried real native decision"
    );
    if expected.publishes() {
        assert_eq!(f.items.len(), 1);
        assert_eq!(f.items[0].input_tokens, 300);
        pi_publication_post(&mut f, true);
        if expected == crate::snapshots::NativePublication::Receipted {
            pi_native_receipt_restores_tail(&f);
        }
    } else {
        assert!(
            f.items.is_empty(),
            "held native completion must emit no body"
        );
        assert!(
            f.try_capture(Duration::ZERO).is_none(),
            "no retained retry for held completion"
        );
        for (key, before) in accepted {
            assert_eq!(
                serde_json::to_value(&f.working.files[&key]).unwrap(),
                before
            );
            assert_eq!(
                serde_json::to_value(&ScanIndex::load(&f.index_path).unwrap().files[&key]).unwrap(),
                before
            );
        }
        // A held carrier must refuse even an otherwise capture-ready page.
        // Reuse the actual e4 decision; never fabricate a publishing class.
        let mut offered = PiLiveFixture::new();
        assert!(!offered.items.is_empty());
        offered
            .live
            .as_ref()
            .unwrap()
            .validate_capture(&offered.home.0, &offered.items, &offered.working)
            .unwrap();
        offered.native_publication = f.native_publication;
        assert!(offered.try_capture(Duration::ZERO).is_none());
        let mut control = PiLiveFixture::new();
        assert!(
            control.try_capture(Duration::ZERO).is_some(),
            "ordinary RAM retry premise"
        );
    }
}

use crate::snapshots::native_publication_tests::E4Outcome as PiE4;
use crate::snapshots::native_publication_tests::{
    Degraded as PiDegraded, DegradedCause as PiDegradedCause, HeldCause as PiHeldCause,
    NotPersisted as PiNotPersisted, Unprepared as PiUnprepared,
    UnpreparedDisposition as PiUnpreparedDisposition, WriteOutcome as PiWriteOutcome,
};
#[test]
#[serial(client_report)]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_e4_receipted_captures_and_posts() {
    pi_publication_case(crate::snapshots::NativePublication::Receipted, None);
}

#[test]
#[serial(client_report)]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_e4_publish_without_record_captures_and_posts() {
    pi_publication_case(
        crate::snapshots::NativePublication::PublishWithoutRecord,
        Some(PiE4::Unprepared(
            PiUnpreparedDisposition::PublishWithoutRecord {
                cause: PiUnprepared::NotPersisted(PiNotPersisted::Codec),
            },
        )),
    );
}

#[test]
#[serial(client_report)]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_e4_failed_published_without_record_captures_and_posts() {
    pi_publication_case(
        crate::snapshots::NativePublication::FailedPublishedWithoutRecord,
        Some(PiE4::Write(PiWriteOutcome::FailedPublishedWithoutRecord(
            PiDegradedCause::WriteFailedRetired,
        ))),
    );
}

#[test]
#[serial(client_report)]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_e4_publish_retaining_prior_captures_and_posts() {
    pi_publication_case(
        crate::snapshots::NativePublication::PublishRetainingPrior,
        Some(PiE4::Unprepared(
            PiUnpreparedDisposition::PublishRetainingPrior {
                format: 3,
                cause: PiUnprepared::NotPersisted(PiNotPersisted::Codec),
            },
        )),
    );
}

#[test]
#[serial(client_report)]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_e4_publish_store_untouched_captures_and_posts() {
    pi_publication_case(
        crate::snapshots::NativePublication::PublishStoreUntouched,
        Some(PiE4::Unprepared(
            PiUnpreparedDisposition::PublishStoreUntouched {
                cause: PiDegraded::Disabled,
            },
        )),
    );
}

#[test]
#[serial(client_report)]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_e4_failed_held_refuses_retained_retry() {
    pi_publication_case(
        crate::snapshots::NativePublication::FailedHeld,
        Some(PiE4::Write(PiWriteOutcome::FailedHeld(PiHeldCause::Fence))),
    );
}

#[test]
#[serial(client_report)]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_e4_receipt_pending_refuses_retained_retry() {
    pi_publication_case(
        crate::snapshots::NativePublication::ReceiptPending,
        Some(PiE4::Write(PiWriteOutcome::ReceiptPending)),
    );
}

#[test]
#[serial(client_report)]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_e4_unprepared_hold_and_strict_rebind_refuse_retained_retry() {
    for outcome in [
        PiE4::Unprepared(PiUnpreparedDisposition::Hold(PiHeldCause::Fence)),
        PiE4::Unprepared(PiUnpreparedDisposition::PublishStrictRebind),
        PiE4::Write(PiWriteOutcome::FailedPublishedWithoutRecord(
            PiDegradedCause::StrictRebind,
        )),
    ] {
        pi_publication_case(crate::snapshots::NativePublication::Hold, Some(outcome));
    }
}

#[test]
#[serial(client_report)]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_e4_mixed_page_hold_blocks_only_retained_retry_and_sibling_posts() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let (mut f, accepted) = pi_native_publication_page(
        2,
        Some(PiE4::Write(PiWriteOutcome::FailedHeld(PiHeldCause::Fence))),
    );
    assert_eq!(
        f.native_publication,
        Some(crate::snapshots::NativePublication::FailedHeld)
    );
    assert_eq!(
        f.items.len(),
        1,
        "publishing sibling survives the held completion"
    );
    assert_eq!(f.items[0].input_tokens, 300);
    assert!(
        !f.progress.contains_body(
            &f.items[0].snapshot_fingerprint,
            &snapshot_upload_body_witness(&f.items[0])
        ),
        "sibling retry is still pending"
    );
    assert!(
        f.try_capture(Duration::ZERO).is_none(),
        "the page hold blocks retained retry only"
    );
    // The capture stop must leave the sibling's ordinary POST/ACK path enabled.
    pi_publication_post(&mut f, false);
    let held_key = accepted.keys().next().unwrap();
    let saved = ScanIndex::load(&f.index_path).unwrap();
    assert_eq!(
        serde_json::to_value(&saved.files[held_key]).unwrap(),
        accepted[held_key]
    );
    assert!(f.progress.contains_body(
        &f.items[0].snapshot_fingerprint,
        &snapshot_upload_body_witness(&f.items[0])
    ));
}
