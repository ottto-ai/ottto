// Included in mcp_inventory::tests: synthetic inputs only.
fn sample_at(start: &str, version: Option<&str>) -> Sample {
    Sample::new(start, version).unwrap()
}
const VERSION_START: &str = "2026-10-07T10:00:00Z";

#[test]
fn version_samples_bound_validate_and_rank_instants() {
    let old = sample_at(VERSION_START, Some("0.148.9"));
    let tie = sample_at("2026-10-07T12:00:00+02:00", Some("0.162.0"));
    assert_eq!(
        Sample::newest(Some(old), Some(tie)).unwrap().version(),
        Some("0.162.0")
    );
    assert!(
        Sample::newest(Some(old), Some(sample_at(VERSION_START, None)))
            .unwrap()
            .version()
            .is_none(),
        "an equal-start real observation without a version also beats the seed"
    );
    let newer = sample_at("2026-10-07T10:00:01Z", None);
    assert_eq!(
        Sample::newest(Some(old), Some(newer)).unwrap().version(),
        None
    );
    assert!(Sample::new("invalid", Some("0.162.0")).is_none());
    for invalid in [
        "",
        "0.149.0 text",
        "é",
        "garbage",
        "0.149.garbage",
        &"0".repeat(65),
    ] {
        assert_eq!(sample_at(VERSION_START, Some(invalid)).version(), None);
    }
    let bound = format!("0.149.0-{}", "x".repeat(56));
    assert_eq!(bound.len(), 64);
    assert_eq!(
        sample_at(VERSION_START, Some(&bound)).version(),
        Some(bound.as_str())
    );
    let seed = sample_at("2026-10-07T11:00:00Z", Some("0.149.0"));
    assert_eq!(
        Sample::newest(Some(seed), Some(old)).unwrap().version(),
        Some("0.149.0")
    );
    assert_eq!(
        Sample::newest(Some(old), Some(seed)).unwrap().version(),
        Some("0.149.0")
    );
}

#[test]
fn codex_wire_loading_pins_and_version_independent_hash() {
    let home = test_home("codex-wire");
    let config = ConfiguredServer {
        name: "synthetic".into(),
        transport: Transport::Http {
            url: "http://invalid.test".into(),
        },
        disabled: false,
        always_load: false,
        config_dir: None,
    };
    for (version, mode, basis) in [
        (Some("0.148.9"), "unknown", "legacy_client"),
        (Some("0.149.0"), "on_demand", "client_default"),
        (None, "on_demand", "client_default"),
    ] {
        let policy = LoadingPolicy::read(&home, SnapshotSource::Codex, version);
        let mut servers = vec![unreachable_server(&config)];
        apply_loading_policy(&mut servers, std::slice::from_ref(&config), &policy);
        let mut inventory = sample_inventory("synthetic", "description");
        inventory.client_version = policy.client_version();
        inventory.servers = servers;
        let wire = serde_json::to_value(&inventory).unwrap();
        assert_eq!(wire["servers"][0]["loading_mode"], mode);
        assert_eq!(wire["servers"][0]["loading_mode_basis"], basis);
        assert_eq!(wire["servers"][0]["loading_mode_inferred"], true);
        assert_eq!(wire.get("client_version").and_then(Value::as_str), version);
        let hash = inventory_hash(&inventory).unwrap();
        inventory.client_version = Some("0.999.0".into());
        assert_eq!(inventory_hash(&inventory).unwrap(), hash);
    }
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn upload_cache_seed_supports_old_and_new_readers() {
    // Exact old cache shape, with no seed field.
    const OLD: &[u8] = br#"{"identity":"device|machine|destination","inventory_sha256":"abc","posted_at":"2026-10-07T10:00:00Z"}"#;
    let mut current: InventoryCacheEntry = serde_json::from_slice(OLD).unwrap();
    assert!(current.seed.is_none());
    current.seed = Some(VersionSeed::from_sample(sample_at(
        VERSION_START,
        Some("0.148.9"),
    )));
    #[derive(Deserialize)]
    struct OldCache {
        identity: String,
        inventory_sha256: String,
        posted_at: String,
    }
    let old: OldCache = serde_json::from_slice(&serde_json::to_vec(&current).unwrap()).unwrap();
    assert_eq!(old.identity, current.identity);
    assert_eq!(old.inventory_sha256, current.inventory_sha256);
    assert_eq!(old.posted_at, current.posted_at);
    let decoded: InventoryCacheEntry =
        serde_json::from_slice(&serde_json::to_vec(&current).unwrap()).unwrap();
    assert_eq!(
        decoded.seed.unwrap().sample().unwrap().version(),
        Some("0.148.9")
    );
}

/// Real Full -> the production EOF callback -> the MCP builder.
#[cfg(unix)]
fn full_version_feed(home: &Path, start: &str, version: &str) -> Arc<CodexVersionFeed> {
    use crate::snapshots::{OwnedSourceScan, OwnedSourceScanStep, ScanIndex};
    let root = home.join(".codex/sessions");
    let path = version_rollout_path(home);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let rows = [
        json!({"type":"session_meta","timestamp":start,"payload":{
            "id":"019fa111-2222-7333-8444-555555555555","cli_version":version}}),
        json!({"type":"turn_context","timestamp":start,"payload":{"turn_id":"t1","model":"fixture-model"}}),
        json!({"type":"event_msg","timestamp":start,"payload":{"type":"token_count","info":{
            "total_token_usage":{"input_tokens":100,"output_tokens":10},
            "last_token_usage":{"input_tokens":100,"output_tokens":10}}}}),
    ];
    fs::write(
        &path,
        rows.iter()
            .map(|r| r.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let feed = Arc::new(CodexVersionFeed::new(Some(home)));
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root],
        ScanIndex::default(),
        "2026-10-07T12:00:00Z",
        30,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_codex_versions(feed.clone());
    loop {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { scan, .. } => {
                assert_eq!(scan.scanned_file_count, 1);
                break;
            }
        }
    }
    assert_eq!(feed.snapshot().0.unwrap().version(), Some(version));
    feed
}

#[cfg(unix)]
fn version_rollout_path(home: &Path) -> PathBuf {
    home.join(".codex/sessions/2026/10/07/rollout-2026-10-07T10-00-00-019fa111-2222-7333-8444-555555555555.jsonl")
}

/// Watch a regular rollout at the kernel boundary, including independent
/// File::open/read_line calls that bypass the shared scanner's denial seams.
/// Other Unix platforms retain seam coverage and static call-graph evidence.
#[cfg(target_os = "linux")]
struct RolloutOpenWatch(std::os::fd::OwnedFd);
#[cfg(target_os = "linux")]
impl RolloutOpenWatch {
    fn new(path: &Path) -> Self {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(raw >= 0, "{}", std::io::Error::last_os_error());
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let watch = unsafe {
            libc::inotify_add_watch(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::IN_OPEN | libc::IN_ACCESS,
            )
        };
        assert!(watch >= 0, "{}", std::io::Error::last_os_error());
        Self(fd)
    }
    fn saw_io(&self) -> bool {
        use std::os::fd::AsRawFd;
        let mut seen = false;
        let mut events = [0u8; 4096];
        loop {
            let count =
                unsafe { libc::read(self.0.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock, "{error}");
                return seen;
            }
            assert!(count > 0);
            seen = true;
        }
    }
}

#[test]
#[cfg(unix)]
#[serial_test::serial]
fn harvest_seed_post_success_failure_restart_and_read_free_dumps() {
    use crate::snapshots::with_transcript_io_denied;
    use std::sync::Mutex;
    let home = test_home("version-lifecycle");
    let support = home.join("support");
    let _home = EnvGuard::set("HOME", home.to_str().unwrap());
    let _support = EnvGuard::set(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support.to_str().unwrap(),
    );
    let device = LocalDeviceBinding {
        device_id: "version-device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["codex".into()],
    };
    ottto_core::FileDeviceStore::default()
        .save(&device)
        .unwrap();
    let feed = full_version_feed(&home, VERSION_START, "0.148.9");
    #[cfg(target_os = "linux")]
    let watch = {
        let path = version_rollout_path(&home);
        assert!(fs::metadata(&path).unwrap().is_file());
        let watch = RolloutOpenWatch::new(&path);
        // Prove that a direct open/read, independent of scanner seams, fires.
        let mut reader = std::io::BufReader::new(fs::File::open(path).unwrap());
        assert!(reader.read_line(&mut String::new()).unwrap() > 0);
        drop(reader);
        assert!(watch.saw_io()); // Drain the positive control before harvest.
        watch
    };
    let live = feed.snapshot().0.unwrap();
    let built = build_inventory(
        &home,
        SnapshotSource::Codex,
        None,
        unbounded_deadline(),
        live.version(),
    );
    assert_eq!(built.inventory.client_version.as_deref(), Some("0.148.9"));
    let captured = Arc::new(Mutex::new(Vec::new()));
    // Full feed uploads once; restart with an empty feed must reuse the seed.
    let (base, server) = mock_backend(captured.clone(), 5, HintMode::Enabled);
    let client = SnapshotApiClient::new(base.clone());
    let _api = EnvGuard::set("OTTTO_API_BASE_URL", &base);
    with_transcript_io_denied(|| {
        harvest_source(
            &client,
            &device,
            "secret",
            SnapshotSource::Codex,
            "otm_test",
            &base,
            &home,
            &support,
            Some(&feed),
        )
        .unwrap();
        let empty = CodexVersionFeed::new(Some(&home));
        harvest_source(
            &client,
            &device,
            "secret",
            SnapshotSource::Codex,
            "otm_test",
            &base,
            &home,
            &support,
            Some(&empty),
        )
        .unwrap();
        assert_eq!(
            dump_inventory("codex").unwrap()["client_version"],
            "0.148.9"
        );
        let all = dump_all_inventories().unwrap();
        assert_eq!(
            all.as_array()
                .unwrap()
                .iter()
                .find(|v| v["agent_source"] == "codex")
                .unwrap()["client_version"],
            "0.148.9"
        );
    });
    server.join().unwrap();
    #[cfg(target_os = "linux")]
    assert!(
        !watch.saw_io(),
        "harvest/dumps opened or read the regular rollout"
    );
    assert_eq!(inventory_post_count(&captured.lock().unwrap()), 1);
    let carried = captured
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.contains("POST /api/v1/mcp/inventory"))
        .unwrap()
        .split_once("\r\n\r\n")
        .unwrap()
        .1
        .to_string();
    let carried: Value = serde_json::from_str(&carried).unwrap();
    assert!(
        carried.get("seed").is_none(),
        "seed is local, not a wire field"
    );
    assert_eq!(carried["client_version"], "0.148.9");
    let path = cache_path(&support, SnapshotSource::Codex);
    assert_eq!(
        read_cache(&path)
            .unwrap()
            .seed
            .unwrap()
            .sample()
            .unwrap()
            .version(),
        Some("0.148.9")
    );
    assert_eq!(
        serde_json::to_value(read_cache(&path).unwrap().seed.unwrap()).unwrap()["cli_version"],
        carried["client_version"]
    );
    let newer = full_version_feed(&home, "2026-10-07T11:00:00Z", "0.149.0");
    let version_only = full_version_feed(&home, "2026-10-07T11:00:01Z", "0.149.1");
    let (base, server) = mock_backend(captured.clone(), 7, HintMode::Enabled);
    with_transcript_io_denied(|| {
        harvest_source(
            &SnapshotApiClient::new(base.clone()),
            &device,
            "secret",
            SnapshotSource::Codex,
            "otm_test",
            &base,
            &home,
            &support,
            Some(&newer),
        )
    })
    .unwrap();
    with_transcript_io_denied(|| {
        for candidate in [&feed, &version_only] {
            harvest_source(
                &SnapshotApiClient::new(base.clone()),
                &device,
                "secret",
                SnapshotSource::Codex,
                "otm_test",
                &base,
                &home,
                &support,
                Some(candidate),
            )
            .unwrap();
        }
    });
    server.join().unwrap();
    assert_eq!(
        read_cache(&path)
            .unwrap()
            .seed
            .unwrap()
            .sample()
            .unwrap()
            .version(),
        Some("0.149.0")
    );
    let before = fs::read(&path).unwrap();
    let newest = full_version_feed(&home, "2026-10-07T11:01:00Z", "0.150.0");
    let (base, server) = mock_backend(captured, 3, HintMode::UploadError);
    assert!(with_transcript_io_denied(|| harvest_source(
        &SnapshotApiClient::new(base.clone()),
        &device,
        "secret",
        SnapshotSource::Codex,
        "otm_test",
        &base,
        &home,
        &support,
        Some(&newest)
    ))
    .is_err());
    server.join().unwrap();
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "failed POST never advances seed"
    );
    fs::remove_file(path).unwrap();
    with_transcript_io_denied(|| {
        assert!(dump_inventory("codex")
            .unwrap()
            .get("client_version")
            .is_none())
    });
    fs::remove_dir_all(home).unwrap();
}

#[test]
#[serial_test::serial]
fn seed_validation_on_write_and_load_drops_and_counts_bad_values() {
    let home = test_home("seed-validation");
    let path = cache_path(&home, SnapshotSource::Codex);
    let valid = format!("0.149.0-{}", "x".repeat(56));
    assert_eq!(valid.len(), 64);
    let mut raw = json!({"identity":"same-account","inventory_sha256":"unchanged-hash",
        "posted_at":VERSION_START,"seed":{"started_at":VERSION_START,"cli_version":valid}});
    let entry: InventoryCacheEntry = serde_json::from_value(raw.clone()).unwrap();
    write_cache(&path, &entry);
    assert_eq!(
        read_cache(&path)
            .unwrap()
            .seed
            .unwrap()
            .cli_version
            .as_deref(),
        Some(valid.as_str())
    );
    let before = SEED_REJECTED.load(Ordering::Relaxed);
    let bad = [
        json!("0".repeat(65)),
        json!("é"),
        json!("0.149.0\n"),
        json!("invalid version"),
        json!("0.149.garbage"),
        json!("0.149.18446744073709551616"),
        json!(""),
        Value::Null,
        json!({"wrapped":"0.149.0"}),
    ];
    for value in &bad {
        raw["seed"]["cli_version"] = value.clone();
        let decoded: InventoryCacheEntry = serde_json::from_value(raw.clone()).unwrap();
        assert!(
            decoded.seed.is_none(),
            "bad seed is absent, never a version-less candidate"
        );
        assert_eq!(decoded.inventory_sha256, "unchanged-hash");
        let sample = Sample::newest(
            decoded.seed.as_ref().and_then(VersionSeed::sample),
            Some(sample_at("2026-10-07T09:00:00Z", Some("0.148.9"))),
        )
        .unwrap();
        assert_eq!(codex_loading_decision(sample.version()).mode, "unknown");
    }
    assert!(SEED_REJECTED.load(Ordering::Relaxed) >= before + bad.len() as u64);
    for bad in [
        "0".repeat(65),
        "é".into(),
        "0.149.0\n".into(),
        "0.149.garbage".into(),
        "".into(),
    ] {
        let mut entry = entry.clone();
        entry.seed.as_mut().unwrap().cli_version = Some(bad);
        write_cache(&path, &entry);
        let stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(
            stored["seed"].is_null(),
            "write boundary rejects malformed values"
        );
    }
    raw["seed"] = json!({"started_at":"invalid","cli_version":"0.149.0"});
    let before = SEED_REJECTED.load(Ordering::Relaxed);
    let decoded: InventoryCacheEntry = serde_json::from_value(raw).unwrap();
    assert!(decoded.seed.is_none());
    assert!(SEED_REJECTED.load(Ordering::Relaxed) > before);
    fs::remove_dir_all(home).unwrap();
}

#[test]
#[cfg(unix)]
#[serial_test::serial]
fn observed_seed_tie_wins_and_destination_changes_drop_seed() {
    let home = test_home("seed-account-tie");
    let support = home.join("support");
    let _home = EnvGuard::set("HOME", home.to_str().unwrap());
    let _support = EnvGuard::set(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support.to_str().unwrap(),
    );
    let device = LocalDeviceBinding {
        device_id: "account-a".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["codex".into()],
    };
    ottto_core::FileDeviceStore::default()
        .save(&device)
        .unwrap();
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::write(
        home.join(".codex/config.toml"),
        "[mcp_servers.synthetic]\nurl = \"https://example.test/mcp\"\n",
    )
    .unwrap();
    let feed = full_version_feed(&home, VERSION_START, "0.149.0");
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (base, server) = mock_backend(captured.clone(), 6, HintMode::Enabled);
    let _api = EnvGuard::set("OTTTO_API_BASE_URL", &base);
    let path = cache_path(&support, SnapshotSource::Codex);
    write_cache(
        &path,
        &InventoryCacheEntry {
            identity: destination_identity(&device, "otm_test", &base),
            inventory_sha256: "force-post".into(),
            posted_at: VERSION_START.into(),
            seed: Some(VersionSeed::from_sample(sample_at(
                VERSION_START,
                Some("0.148.9"),
            ))),
        },
    );
    harvest_source(
        &SnapshotApiClient::new(base.clone()),
        &device,
        "secret",
        SnapshotSource::Codex,
        "otm_test",
        &base,
        &home,
        &support,
        Some(&feed),
    )
    .unwrap();
    let stored = read_cache(&path).unwrap();
    assert_eq!(
        stored.seed.unwrap().sample().unwrap().version(),
        Some("0.149.0")
    );
    assert_eq!(
        dump_seed(SnapshotSource::Codex).unwrap().version(),
        Some("0.149.0")
    );
    let mut other = device.clone();
    other.device_id = "account-b".into();
    ottto_core::FileDeviceStore::default().save(&other).unwrap();
    assert!(
        dump_seed(SnapshotSource::Codex).is_none(),
        "dump never borrows another account's seed"
    );
    let empty = CodexVersionFeed::new(Some(&home));
    harvest_source(
        &SnapshotApiClient::new(base.clone()),
        &other,
        "secret",
        SnapshotSource::Codex,
        "otm_test",
        &base,
        &home,
        &support,
        Some(&empty),
    )
    .unwrap();
    server.join().unwrap();
    let stored = read_cache(&path).unwrap();
    assert_eq!(
        stored.identity,
        destination_identity(&other, "otm_test", &base)
    );
    assert!(
        stored.seed.is_none(),
        "replacing the account's entry drops the prior seed"
    );
    let posts: Vec<Value> = captured
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.contains("POST /api/v1/mcp/inventory"))
        .map(|r| serde_json::from_str(r.split_once("\r\n\r\n").unwrap().1).unwrap())
        .collect();
    assert_eq!(posts.len(), 2);
    assert_eq!(
        posts[0]["client_version"], "0.149.0",
        "observed value wins same-start seed tie"
    );
    assert_eq!(posts[0]["servers"][0]["loading_mode"], "on_demand");
    assert!(
        posts[1].get("client_version").is_none(),
        "no seed crosses the destination boundary"
    );
    assert!(posts.iter().all(|p| p.get("seed").is_none()));
    // A cache from another connection or install also supplies no seed to dumps.
    for identity in [
        destination_identity(&other, "otm_other", &base),
        destination_identity(&other, "otm_test", "https://different.test"),
    ] {
        write_cache(
            &path,
            &InventoryCacheEntry {
                identity,
                inventory_sha256: "hash".into(),
                posted_at: VERSION_START.into(),
                seed: Some(VersionSeed::from_sample(sample_at(
                    VERSION_START,
                    Some("0.149.0"),
                ))),
            },
        );
        assert!(dump_seed(SnapshotSource::Codex).is_none());
    }
    fs::remove_file(&path).unwrap();
    assert!(
        dump_seed(SnapshotSource::Codex).is_none(),
        "deletion drops the seed"
    );
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn version_diagnostics_expose_counts_and_redact_values() {
    let source = include_str!("mcp_inventory.rs");
    let log = source
        .split("impl HarvestMetrics {")
        .nth(1)
        .unwrap()
        .split("/// Peak RSS")
        .next()
        .unwrap();
    assert!(log.contains("seed_rejected={}"));
    assert!(!log.contains("cli_version"));
    assert!(!log.contains("client_version"));
    assert!(!log.contains("Sample::version"));
    assert_eq!(
        format!("{:?}", CodexVersionFeed::new(None)),
        "CodexVersionFeed { .. }"
    );
}
