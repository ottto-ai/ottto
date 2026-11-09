use super::*;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

const INSTALLATION_ID: &str = "00000000-0000-4000-8000-000000000001";
const GRANT_ID: &str = "00000000-0000-4000-8000-000000000002";
fn temp_dir(name: &str) -> PathBuf {
    crate::test_scratch::private_dir(&format!("ottto-cloud-sessions-{name}"))
}
fn now() -> OffsetDateTime {
    OffsetDateTime::parse("2026-07-21T12:00:00Z", &Rfc3339).unwrap()
}

#[cfg(unix)]
struct CloudCliFixture {
    root: PathBuf,
    previous_search_path: Option<std::ffi::OsString>,
}

#[cfg(unix)]
impl CloudCliFixture {
    fn new(mode: &str, output: &[u8], exit_code: u8) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_dir("cloud-cli-process");
        fs::write(root.join("output"), output).unwrap();
        let quote = |path: &Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
        let body = if mode == "output" {
            format!(
                "/bin/cat {}\nexit {exit_code}\n",
                quote(&root.join("output"))
            )
        } else if mode == "escape" {
            format!(
                "echo $$ > {}\nexport OTTTO_CLOUD_CLI_FIXTURE_DIR={}\n{} --ignored --exact cloud_sessions::tests::cloud_cli_fixture_process --nocapture --test-threads=1 &\nwhile [ ! -s {} ]; do /bin/sleep 0.01; done\nexit 0\n",
                quote(&root.join("direct")),
                quote(&root),
                quote(&std::env::current_exe().unwrap()),
                quote(&root.join("descendant")),
            )
        } else {
            format!(
                "echo $$ > {}\n/bin/sleep 4 &\necho $! > {}\n{}\n",
                quote(&root.join("direct")),
                quote(&root.join("descendant")),
                if mode == "hold-exit" {
                    "exit 0"
                } else {
                    "wait"
                },
            )
        };
        let script = root.join("codex");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n{body}",
                quote(&root.join("arguments"))
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let previous_search_path = std::env::var_os("OTTTO_COMMAND_SEARCH_PATH");
        unsafe { std::env::set_var("OTTTO_COMMAND_SEARCH_PATH", &root) };
        Self {
            root,
            previous_search_path,
        }
    }

    fn pid(&self, label: &str) -> libc::pid_t {
        fs::read_to_string(self.root.join(label))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn wait_started(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while fs::read_to_string(self.root.join("descendant"))
            .ok()
            .and_then(|pid| pid.trim().parse::<libc::pid_t>().ok())
            .is_none()
        {
            assert!(Instant::now() < deadline, "fake descendant did not start");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn alive(pid: libc::pid_t) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    fn wait_gone(&self, label: &str) {
        let pid = self.pid(label);
        assert!(Self::wait_for_exit(pid), "fake {label} remained alive");
    }

    fn wait_for_exit(pid: libc::pid_t) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Self::alive(pid) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        !Self::alive(pid)
    }
}

#[cfg(unix)]
impl Drop for CloudCliFixture {
    fn drop(&mut self) {
        match self.previous_search_path.take() {
            Some(value) => unsafe { std::env::set_var("OTTTO_COMMAND_SEARCH_PATH", value) },
            None => unsafe { std::env::remove_var("OTTTO_COMMAND_SEARCH_PATH") },
        }
        // Even a failing oracle releases the finite escaped fixture. All
        // fake processes also self-terminate after four seconds.
        let _ = fs::write(self.root.join("release"), []);
        for label in ["direct", "descendant"] {
            if let Some(pid) = fs::read_to_string(self.root.join(label))
                .ok()
                .and_then(|pid| pid.trim().parse::<libc::pid_t>().ok())
            {
                let _ = Self::wait_for_exit(pid);
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
#[test]
#[ignore = "bounded fake child invoked only by cloud CLI process tests"]
fn cloud_cli_fixture_process() {
    let Some(root) = std::env::var_os("OTTTO_CLOUD_CLI_FIXTURE_DIR").map(PathBuf::from) else {
        return;
    };
    assert!(unsafe { libc::setsid() } >= 0);
    fs::write(root.join("descendant"), std::process::id().to_string()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline && !root.join("release").exists() {
        thread::sleep(Duration::from_millis(10));
    }
    std::process::exit(0);
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn cloud_cli_drains_large_output_and_preserves_arguments_and_cap() {
    let payload =
        json!({"tasks": [], "has_more": false, "padding": "x".repeat(1024 * 1024)}).to_string();
    let fixture = CloudCliFixture::new("output", payload.as_bytes(), 0);
    assert_eq!(
        CodexCloudCliRunner
            .list_page_bounded(
                Some("fixture-cursor"),
                PAGE_LIMIT + 1,
                Duration::from_secs(2)
            )
            .unwrap(),
        payload
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("arguments")).unwrap(),
        "cloud\nlist\n--json\n--limit\n20\n--cursor\nfixture-cursor\n"
    );
    drop(fixture);
    for size in [
        MAX_PAGE_OUTPUT_BYTES as usize,
        MAX_PAGE_OUTPUT_BYTES as usize + 8192,
    ] {
        let _fixture = CloudCliFixture::new("output", &vec![b'x'; size], 0);
        let output = CodexCloudCliRunner
            .list_page_bounded(None, PAGE_LIMIT, Duration::from_secs(2))
            .unwrap();
        assert_eq!(output.len(), MAX_PAGE_OUTPUT_BYTES as usize);
        assert!(output.bytes().all(|byte| byte == b'x'));
    }
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn cloud_cli_escaped_writer_cannot_hold_deadline_or_kill_other_groups() {
    let fixture = CloudCliFixture::new("escape", &[], 0);
    let mut sentinel = Command::new("/bin/sleep").arg("4").spawn().unwrap();
    let caller_group = unsafe { libc::getpgrp() };
    let started = Instant::now();
    let result = CodexCloudCliRunner.list_page_bounded(None, PAGE_LIMIT, Duration::from_secs(2));
    // Always reap the separately owned sentinel before an oracle can panic.
    let sentinel_alive = sentinel.try_wait().unwrap().is_none();
    let _ = sentinel.kill();
    sentinel.wait().unwrap();
    assert!(result.unwrap_err().to_string().contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(unsafe { libc::getpgrp() }, caller_group);
    assert!(sentinel_alive);
    fixture.wait_started();
    fixture.wait_gone("direct");
    assert!(CloudCliFixture::alive(fixture.pid("descendant")));
    fs::write(fixture.root.join("release"), []).unwrap();
    fixture.wait_gone("descendant");
}

fn stores(name: &str) -> (CloudSessionGrantStore, CloudSessionCheckpointStore) {
    let root = temp_dir(name);
    (
        CloudSessionGrantStore::new(root.join("grant.json")),
        CloudSessionCheckpointStore::new(root.join("checkpoint.json")),
    )
}
fn enabled(store: &CloudSessionGrantStore) {
    let local = store
        .enable(
            &CloudSessionGrantSetup {
                installation_id: INSTALLATION_ID.to_string(),
                organization_scope: "org_fixture".to_string(),
                effective_user_scope: "user_fixture".to_string(),
            },
            now(),
        )
        .unwrap();
    store.grant_create_request(INSTALLATION_ID).unwrap();
    store
        .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
        .unwrap();
}

fn runtime_identity_stores(
    root: &Path,
    user_id: &str,
    organization_id: &str,
    api_base_url: &str,
) -> (FileAccountStore, FileDeviceStore, FileConnectionStore) {
    let accounts = FileAccountStore::new(root.join("account.json"));
    accounts
        .save(&ottto_protocol::LocalAccountBinding {
            state: LocalAccountState::Connected,
            user: Some(ottto_protocol::LocalAccountUser {
                id: user_id.to_string(),
                email: "runtime@example.com".to_string(),
                display_name: None,
            }),
            organization: Some(ottto_protocol::LocalAccountOrganization {
                id: organization_id.to_string(),
                name: "Runtime Org".to_string(),
            }),
            connected_at: None,
            last_refreshed_at: None,
            message: None,
            can_reconnect: None,
        })
        .unwrap();
    let devices = FileDeviceStore::new(root.join("device.json"));
    devices
        .save(&LocalDeviceBinding {
            device_id: INSTALLATION_ID.to_string(),
            machine_id: Some("machine-runtime".to_string()),
            sources: vec!["codex".to_string()],
        })
        .unwrap();
    let connections = FileConnectionStore::new(root.join("connection.json"));
    connections
        .save(&ottto_core::LocalConnectionBinding {
            setup_run_id: "setup-runtime".to_string(),
            setup_run_token_expires_at: "2030-01-01T00:00:00Z".to_string(),
            machine_id: Some("machine-runtime".to_string()),
            claim_code: None,
            api_base_url: api_base_url.to_string(),
        })
        .unwrap();
    (accounts, devices, connections)
}

#[test]
fn control_token_ledger_is_atomic_bounded_and_replay_safe_across_restart() {
    let root = temp_dir("control-token-ledger");
    let path = root.join("control-token-uses.json");
    let now = 1_800_000_000;
    let token_id = "apps-control-private-jti";
    let store = Arc::new(CloudSessionControlTokenUseStore::new(&path));
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let attempts = (0..2)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store.consume(token_id, now + 120, now)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = attempts
        .into_iter()
        .map(|attempt| attempt.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);

    let restarted = CloudSessionControlTokenUseStore::new(&path);
    assert!(restarted.consume(token_id, now + 120, now).is_err());
    let bytes = fs::read_to_string(&path).unwrap();
    assert!(!bytes.contains(token_id));
    assert!(!bytes.contains("header.payload.signature"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    for index in 0..(MAX_CONTROL_TOKEN_USES - 1) {
        restarted
            .consume(&format!("token-{index}"), now + 121 + index as u64, now)
            .unwrap();
    }
    let ledger: CloudSessionControlTokenUseLedger =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(ledger.entries.len(), MAX_CONTROL_TOKEN_USES);
    assert!(restarted.consume("over-cap", now + 240, now).is_err());
    assert!(restarted.consume(token_id, now + 120, now).is_err());
    restarted
        .consume("post-expiry", now + 500, now + 400)
        .unwrap();
    let pruned: CloudSessionControlTokenUseLedger =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(pruned.entries.len(), 1);
}

#[test]
fn revoke_prevents_new_provider_admission_and_waits_for_inflight_io() {
    use std::sync::mpsc;

    struct BlockingRunner {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl CloudSessionRunner for BlockingRunner {
        fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<String> {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(page("blocked-provider-call", None))
        }
    }
    struct AuthorityTransport;
    impl CloudSessionTransport for AuthorityTransport {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }
        fn revalidate_grant_bounded(
            &self,
            grant: &CloudSessionGrant,
            _timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            Ok(backend_grant(grant, "enabled", 1))
        }
        fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
            Ok(())
        }
    }

    let root = temp_dir("provider-call-fence");
    let grants = CloudSessionGrantStore::new(root.join("grant.json"));
    enabled(&grants);
    let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
        root.join("checkpoint.json"),
    ));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let collector_grants = grants.clone();
    let collector_checkpoints = Arc::clone(&checkpoints);
    let collector = thread::spawn(move || {
        collect_cloud_sessions_once(
            &collector_grants,
            &collector_checkpoints,
            &BlockingRunner {
                entered: entered_tx,
                release: release_rx,
            },
            &AuthorityTransport,
            now(),
        )
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    grants.revoke(now()).unwrap();
    let waiter_checkpoints = Arc::clone(&checkpoints);
    let (stopped_tx, stopped_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let result = waiter_checkpoints.wait_for_collector_io_idle(Duration::from_secs(2));
        stopped_tx.send(result).unwrap();
    });
    assert!(stopped_rx.recv_timeout(Duration::from_millis(50)).is_err());
    release_tx.send(()).unwrap();
    stopped_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    waiter.join().unwrap();
    assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Noop);

    let (second_entered_tx, second_entered_rx) = mpsc::channel();
    let (_second_release_tx, second_release_rx) = mpsc::channel();
    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &checkpoints,
            &BlockingRunner {
                entered: second_entered_tx,
                release: second_release_rx,
            },
            &AuthorityTransport,
            now(),
        ),
        CloudSessionCycleOutcome::Disabled
    );
    assert!(second_entered_rx.try_recv().is_err());
}

#[test]
fn provider_error_releases_stop_fence_before_backend_health_io() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    struct ErrorRunner;
    impl CloudSessionRunner for ErrorRunner {
        fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<String> {
            Err(anyhow!("provider failed"))
        }
    }
    struct BlockingFailureTransport {
        authority_calls: AtomicUsize,
        backend_entered: mpsc::Sender<()>,
        backend_release: Mutex<mpsc::Receiver<()>>,
    }
    impl CloudSessionTransport for BlockingFailureTransport {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }
        fn revalidate_grant_bounded(
            &self,
            grant: &CloudSessionGrant,
            _timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            if self.authority_calls.fetch_add(1, Ordering::SeqCst) > 0 {
                self.backend_entered.send(()).unwrap();
                self.backend_release.lock().unwrap().recv().unwrap();
            }
            Ok(backend_grant(grant, "enabled", 1))
        }
        fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
            Ok(())
        }
    }

    let root = temp_dir("provider-error-fence");
    let grants = CloudSessionGrantStore::new(root.join("grant.json"));
    enabled(&grants);
    let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
        root.join("checkpoint.json"),
    ));
    let (backend_entered_tx, backend_entered_rx) = mpsc::channel();
    let (backend_release_tx, backend_release_rx) = mpsc::channel();
    let collector_grants = grants.clone();
    let collector_checkpoints = Arc::clone(&checkpoints);
    let collector = thread::spawn(move || {
        collect_cloud_sessions_once(
            &collector_grants,
            &collector_checkpoints,
            &ErrorRunner,
            &BlockingFailureTransport {
                authority_calls: AtomicUsize::new(0),
                backend_entered: backend_entered_tx,
                backend_release: Mutex::new(backend_release_rx),
            },
            now(),
        )
    });
    backend_entered_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();

    checkpoints
        .wait_for_collector_io_idle(Duration::from_millis(100))
        .unwrap();
    backend_release_tx.send(()).unwrap();
    assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Failed);
}

fn backend_grant(
    local: &CloudSessionGrant,
    status: &str,
    grant_version: u64,
) -> CloudSessionBackendGrantResponseV1 {
    CloudSessionBackendGrantResponseV1 {
        id: GRANT_ID.to_string(),
        installation_id: INSTALLATION_ID.to_string(),
        source: "codex".to_string(),
        collector_id: COLLECTOR_ID.to_string(),
        schema_version: COLLECTOR_VERSION.to_string(),
        collector_version: compiled_release_version(),
        release_lane: "supported".to_string(),
        disclosure_version: "cloud_sessions_disclosure.v1".to_string(),
        grant_scope_fingerprint: local.grant_scope_id.clone(),
        account_fingerprint: local.account_fingerprint.clone(),
        status: status.to_string(),
        grant_version,
        server_policy_state: CloudSessionServerPolicyState::Approved,
    }
}
struct Pages {
    pages: RefCell<Vec<String>>,
    calls: Cell<usize>,
    revoke: Option<CloudSessionGrantStore>,
}
impl CloudSessionRunner for Pages {
    fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<String> {
        self.calls.set(self.calls.get() + 1);
        if let Some(store) = &self.revoke {
            store.revoke(now()).unwrap();
        }
        Ok(self.pages.borrow_mut().remove(0))
    }
}
struct RecordingTransport {
    calls: Cell<usize>,
    batches: RefCell<Vec<CloudSessionObservationBatchV1>>,
    fail: bool,
}
impl CloudSessionTransport for RecordingTransport {
    fn supports_grant_revalidation(&self) -> bool {
        true
    }

    fn revalidate_grant(
        &self,
        grant: &CloudSessionGrant,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        Ok(backend_grant(
            grant,
            "enabled",
            grant
                .backend_binding
                .as_ref()
                .map_or(1, |binding| binding.grant_version),
        ))
    }

    fn revalidate_grant_bounded(
        &self,
        grant: &CloudSessionGrant,
        _timeout: Duration,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        self.revalidate_grant(grant)
    }

    fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.batches.borrow_mut().push(batch.clone());
        if self.fail {
            Err(anyhow!("offline"))
        } else {
            Ok(())
        }
    }

    fn send_scan_chunk(&self, chunk: &CloudSessionObservationChunkV2) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.batches
            .borrow_mut()
            .push(CloudSessionObservationBatchV1 {
                grant_id: chunk.grant_id.clone(),
                grant_version: chunk.grant_version,
                grant_scope_fingerprint: chunk.grant_scope_fingerprint.clone(),
                collector_id: chunk.collector_id.clone(),
                schema_version: COLLECTOR_VERSION.to_string(),
                collector_version: chunk.collector_version.clone(),
                account_fingerprint: chunk.account_fingerprint.clone(),
                batch_kind: CloudSessionBatchKind::Snapshot,
                snapshot_complete: false,
                collected_at: chunk.scan_started_at.clone(),
                observations: chunk.observations.clone(),
                health: chunk.health.clone(),
            });
        if self.fail {
            Err(anyhow!("offline"))
        } else {
            Ok(())
        }
    }

    fn finalize_scan(&self, finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
        if self.fail {
            return Err(anyhow!("offline"));
        }
        let mut batches = self.batches.borrow_mut();
        if let Some(last) = batches.last_mut() {
            last.snapshot_complete = true;
        } else {
            self.calls.set(self.calls.get() + 1);
            batches.push(CloudSessionObservationBatchV1 {
                grant_id: finalize.grant_id.clone(),
                grant_version: finalize.grant_version,
                grant_scope_fingerprint: finalize.grant_scope_fingerprint.clone(),
                collector_id: finalize.collector_id.clone(),
                schema_version: COLLECTOR_VERSION.to_string(),
                collector_version: finalize.collector_version.clone(),
                account_fingerprint: finalize.account_fingerprint.clone(),
                batch_kind: CloudSessionBatchKind::Snapshot,
                snapshot_complete: true,
                collected_at: finalize.scan_started_at.clone(),
                observations: Vec::new(),
                health: CloudSessionCollectorHealthV1 {
                    state: "healthy".to_string(),
                    observed_at: finalize.scan_started_at.clone(),
                    error_category: None,
                },
            });
        }
        Ok(())
    }
}
struct RevalidationTransport {
    response: Option<CloudSessionBackendGrantResponseV1>,
    revalidation_calls: Cell<usize>,
    send_calls: Cell<usize>,
}
impl CloudSessionTransport for RevalidationTransport {
    fn supports_grant_revalidation(&self) -> bool {
        true
    }

    fn revalidate_grant(
        &self,
        _grant: &CloudSessionGrant,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        self.revalidation_calls
            .set(self.revalidation_calls.get() + 1);
        self.response
            .clone()
            .ok_or_else(|| anyhow!("backend unavailable"))
    }

    fn revalidate_grant_bounded(
        &self,
        grant: &CloudSessionGrant,
        _timeout: Duration,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        self.revalidate_grant(grant)
    }

    fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
        self.send_calls.set(self.send_calls.get() + 1);
        Ok(())
    }

    fn send_scan_chunk(&self, _chunk: &CloudSessionObservationChunkV2) -> Result<()> {
        self.send_calls.set(self.send_calls.get() + 1);
        Ok(())
    }

    fn finalize_scan(&self, _finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
        Ok(())
    }
}

struct V2RecordingTransport {
    chunks: RefCell<Vec<CloudSessionObservationChunkV2>>,
    finalizes: RefCell<Vec<CloudSessionScanFinalizeV2>>,
    heartbeats: RefCell<Vec<CloudSessionObservationBatchV1>>,
    revalidation_calls: Cell<usize>,
    fail_next_chunk: Cell<bool>,
}

impl V2RecordingTransport {
    fn new() -> Self {
        Self {
            chunks: RefCell::new(Vec::new()),
            finalizes: RefCell::new(Vec::new()),
            heartbeats: RefCell::new(Vec::new()),
            revalidation_calls: Cell::new(0),
            fail_next_chunk: Cell::new(false),
        }
    }
}
impl CloudSessionTransport for V2RecordingTransport {
    fn supports_grant_revalidation(&self) -> bool {
        true
    }
    fn revalidate_grant(
        &self,
        grant: &CloudSessionGrant,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        self.revalidation_calls
            .set(self.revalidation_calls.get() + 1);
        Ok(backend_grant(
            grant,
            "enabled",
            grant
                .backend_binding
                .as_ref()
                .map_or(1, |binding| binding.grant_version),
        ))
    }

    fn revalidate_grant_bounded(
        &self,
        grant: &CloudSessionGrant,
        _timeout: Duration,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        self.revalidate_grant(grant)
    }
    fn send_scan_chunk(&self, chunk: &CloudSessionObservationChunkV2) -> Result<()> {
        self.chunks.borrow_mut().push(chunk.clone());
        if self.fail_next_chunk.replace(false) {
            Err(anyhow!("response lost"))
        } else {
            Ok(())
        }
    }
    fn finalize_scan(&self, finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
        self.finalizes.borrow_mut().push(finalize.clone());
        Ok(())
    }
    fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
        self.heartbeats.borrow_mut().push(batch.clone());
        Ok(())
    }
}

#[derive(Default)]
struct ThreadRecordingTransport {
    chunks: AtomicUsize,
    finalizes: AtomicUsize,
    v1_sends: AtomicUsize,
    blocking_chunk: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

impl CloudSessionTransport for ThreadRecordingTransport {
    fn supports_grant_revalidation(&self) -> bool {
        true
    }

    fn revalidate_grant_bounded(
        &self,
        grant: &CloudSessionGrant,
        _timeout: Duration,
    ) -> Result<CloudSessionBackendGrantResponseV1> {
        Ok(backend_grant(
            grant,
            "enabled",
            grant
                .backend_binding
                .as_ref()
                .map_or(1, |binding| binding.grant_version),
        ))
    }

    fn send_scan_chunk(&self, _chunk: &CloudSessionObservationChunkV2) -> Result<()> {
        self.chunks.fetch_add(1, Ordering::SeqCst);
        let barrier = self.blocking_chunk.lock().unwrap().take();
        if let Some((entered, release)) = barrier {
            entered.wait();
            release.wait();
        }
        Ok(())
    }

    fn finalize_scan(&self, _finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
        self.finalizes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
        self.v1_sends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

enum TestPage {
    Json(String),
}
struct CursorRecordingPages {
    pages: RefCell<VecDeque<TestPage>>,
    cursors: RefCell<Vec<Option<String>>>,
}
impl CursorRecordingPages {
    fn new(pages: Vec<String>) -> Self {
        Self {
            pages: RefCell::new(pages.into_iter().map(TestPage::Json).collect()),
            cursors: RefCell::new(Vec::new()),
        }
    }
}
impl CloudSessionRunner for CursorRecordingPages {
    fn list_page(&self, cursor: Option<&str>, _limit: usize) -> Result<String> {
        self.cursors.borrow_mut().push(cursor.map(str::to_string));
        match self.pages.borrow_mut().pop_front() {
            Some(TestPage::Json(page)) => Ok(page),
            None => Err(anyhow!("unexpected provider page")),
        }
    }
}

fn full_page(start: usize, cursor: Option<&str>) -> String {
    let tasks = (start..start + PAGE_LIMIT)
        .map(|index| {
            json!({
                "id": format!("provider-{index:04}"),
                "url": format!("https://chatgpt.com/codex/tasks/task-{index:04}"),
                "title": format!("private task {index:04}"),
                "status": "pending",
                "updated_at": "2026-07-21T11:00:00Z",
                "environment_id": "env-private",
                "environment_label": "Private environment",
                "summary": "private summary",
                "is_review": false,
                "attempt_total": 1
            })
        })
        .collect::<Vec<_>>();
    json!({"tasks": tasks, "cursor": cursor}).to_string()
}

fn run_full_scan_cycles(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    runner: &dyn CloudSessionRunner,
    transport: &dyn CloudSessionTransport,
    start: OffsetDateTime,
) -> CloudSessionCycleOutcome {
    let mut outcome = CloudSessionCycleOutcome::Noop;
    for cycle in 0..10 {
        outcome = collect_cloud_sessions_once(
            grants,
            checkpoints,
            runner,
            transport,
            start + TimeDuration::minutes((cycle * 5) as i64),
        );
    }
    outcome
}
fn page(id: &str, cursor: Option<&str>) -> String {
    json!({"tasks":[{"id":id,"url":"https://chatgpt.com/codex/tasks/private","title":"private title","status":"applied","updated_at":"2026-07-21T11:00:00Z","environment_id":"provider-environment-private","environment_label":"Private environment","summary":"private summary","is_review":false,"attempt_total":2}], "cursor": cursor}).to_string()
}

fn exact_scan_ack(request: &str) -> String {
    let body: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
    if request.contains("/chunks HTTP/1.1") {
        json!({
            "schema_version": "cloud_session_scan_chunk_ack.v1",
            "accepted": true,
            "scan_id": body["scan_id"],
            "chunk_index": body["chunk_index"],
            "chunk_identity_digest": body["chunk_identity_digest"],
            "chunk_semantic_digest": body["chunk_semantic_digest"],
        })
        .to_string()
    } else {
        json!({
            "schema_version": "cloud_session_scan_finalize_ack.v1",
            "accepted": true,
            "scan_id": body["scan_id"],
            "chunk_count": body["chunk_count"],
            "unique_entity_count": body["unique_entity_count"],
            "inventory_digest": body["inventory_digest"],
            "epoch_digest": body["epoch_digest"],
        })
        .to_string()
    }
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    use std::io::Read;

    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| offset + 4)
        {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            });
            if request.len() >= header_end + content_length.unwrap_or(0) {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).to_string()
}

#[test]
fn emitted_wire_is_content_free_and_opaque() {
    let parsed = parse_cloud_page(
        &page("provider-task-123", Some("private-cursor")),
        b"fixture-key",
        now(),
    )
    .unwrap();
    let encoded = serde_json::to_string(&parsed.entities).unwrap();
    assert!(!encoded.contains("provider-task-123"));
    assert!(!encoded.contains("private title"));
    assert!(!encoded.contains("example.invalid"));
    assert!(!encoded.contains("private-cursor"));
    assert!(!encoded.contains("provider-account-private"));
    assert!(encoded.contains("hmac-sha256:"));
}

#[test]
fn official_cloud_task_statuses_and_attempt_total_are_normalized_truthfully() {
    let raw = json!({
        "tasks": [
            {
                "id": "official-pending",
                "url": "https://chatgpt.com/codex/tasks/pending",
                "title": "private pending title",
                "status": "pending",
                "updated_at": "2026-07-21T11:00:00Z",
                "environment_id": "env-private",
                "environment_label": "Private environment",
                "summary": "private summary",
                "is_review": false,
                "attempt_total": 3
            },
            {
                "id": "official-ready",
                "url": "https://chatgpt.com/codex/tasks/ready",
                "title": "private ready title",
                "status": "ready",
                "updated_at": "2026-07-21T11:00:00Z",
                "environment_id": "env-private",
                "environment_label": "Private environment",
                "summary": "private summary",
                "is_review": true,
                "attempt_total": 4
            },
            {
                "id": "official-applied",
                "url": "https://chatgpt.com/codex/tasks/applied",
                "title": "private applied title",
                "status": "applied",
                "updated_at": "2026-07-21T11:00:00Z",
                "environment_id": "env-private",
                "environment_label": "Private environment",
                "summary": "private summary",
                "is_review": false,
                "attempt_total": 5
            },
            {
                "id": "official-error",
                "url": "https://chatgpt.com/codex/tasks/error",
                "title": "private error title",
                "status": "error",
                "updated_at": "2026-07-21T11:00:00Z",
                "environment_id": "env-private",
                "environment_label": "Private environment",
                "summary": "private summary",
                "is_review": false,
                "attempt_total": 6
            }
        ],
        "cursor": null
    })
    .to_string();
    let parsed = parse_cloud_page(&raw, b"fixture-key", now()).unwrap();
    assert_eq!(
        parsed
            .entities
            .iter()
            .map(|row| row.lifecycle.as_str())
            .collect::<Vec<_>>(),
        ["unknown", "completed", "completed", "failed"]
    );
    assert_eq!(
        parsed
            .entities
            .iter()
            .map(|row| row.attempt_count)
            .collect::<Vec<_>>(),
        [Some(3), Some(4), Some(5), Some(6)]
    );
    let encoded = serde_json::to_string(&parsed.entities).unwrap();
    for secret in [
        "official-pending",
        "chatgpt.com",
        "private pending title",
        "env-private",
        "Private environment",
        "private summary",
    ] {
        assert!(!encoded.contains(secret));
    }
}

#[test]
fn cursor_contract_separates_official_terminal_pagination_and_ambiguity() {
    let official_next = parse_cloud_page(
        &json!({"tasks": [], "cursor": "official-next-page"}).to_string(),
        b"fixture-key",
        now(),
    )
    .unwrap();
    assert_eq!(
        official_next.cursor,
        CloudPageCursor::Next("official-next-page".to_string())
    );
    let official_terminal = parse_cloud_page(
        &json!({"tasks": [], "cursor": null}).to_string(),
        b"fixture-key",
        now(),
    )
    .unwrap();
    assert_eq!(official_terminal.cursor, CloudPageCursor::OfficialTerminal);
    let alias_next = parse_cloud_page(
        &json!({
            "tasks": [{"id": "legacy-next", "status": "running"}],
            "next_cursor": "legacy-next-page"
        })
        .to_string(),
        b"fixture-key",
        now(),
    )
    .unwrap();
    assert_eq!(
        alias_next.cursor,
        CloudPageCursor::Next("legacy-next-page".to_string())
    );

    for ambiguous in [
        json!({"tasks": [{"id": "fieldless", "status": "running"}]}),
        json!({
            "tasks": [{"id": "alias-null", "status": "running"}],
            "next_cursor": null
        }),
        json!([{"id": "array-root", "status": "running"}]),
    ] {
        assert_eq!(
            parse_cloud_page(&ambiguous.to_string(), b"fixture-key", now())
                .unwrap()
                .cursor,
            CloudPageCursor::Ambiguous
        );
    }

    for conflicting in [
        json!({"tasks": [], "cursor": "official", "next_cursor": "legacy"}),
        json!({"tasks": [], "cursor": "official", "nextCursor": null}),
        json!({"tasks": [], "next_cursor": null, "nextCursor": "legacy"}),
    ] {
        assert!(parse_cloud_page(&conflicting.to_string(), b"fixture-key", now()).is_err());
    }
    assert!(parse_cloud_page(
        &json!({
            "tasks": [],
            "cursor": "same",
            "next_cursor": "same",
            "nextCursor": "same"
        })
        .to_string(),
        b"fixture-key",
        now(),
    )
    .is_ok());
}

#[test]
fn v2_public_wire_rejects_raw_or_noncanonical_entity_keys_and_open_values() {
    let (grants, checkpoints) = stores("v2-crafted-privacy-boundary");
    enabled(&grants);
    let runner = CursorRecordingPages::new(vec![page("raw-provider-id", None)]);
    let transport = V2RecordingTransport::new();
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Uploaded
    );
    let chunk = transport.chunks.borrow()[0].clone();
    assert!(chunk.validate_wire_contract().is_ok());

    let mut raw_key = chunk.clone();
    raw_key.observations[0].entity_key = "raw-provider-id".to_string();
    assert!(raw_key.validate_wire_contract().is_err());

    let mut uppercase_key = chunk.clone();
    uppercase_key.observations[0].entity_key = format!("hmac-sha256:{}", "A".repeat(64));
    assert!(uppercase_key.validate_wire_contract().is_err());

    let mut wrong_identity = chunk.clone();
    wrong_identity.chunk_identity_digest = format!("sha256:{}", "0".repeat(64));
    assert!(wrong_identity.validate_wire_contract().is_err());

    let mut wrong_semantics = chunk.clone();
    wrong_semantics.chunk_semantic_digest = format!("sha256:{}", "0".repeat(64));
    assert!(wrong_semantics.validate_wire_contract().is_err());

    let mut open_lifecycle = chunk;
    open_lifecycle.observations[0].lifecycle = "provider_future_state".to_string();
    assert!(open_lifecycle.validate_wire_contract().is_err());

    let chunks = transport.chunks.borrow().clone();
    let finalize = transport.finalizes.borrow()[0].clone();
    assert!(finalize.validate_against_chunks(&chunks).is_ok());
    let mut wrong_inventory = finalize.clone();
    wrong_inventory.inventory_digest = format!("sha256:{}", "0".repeat(64));
    assert!(wrong_inventory.validate_against_chunks(&chunks).is_err());
    let mut wrong_epoch = finalize;
    wrong_epoch.epoch_digest = format!("sha256:{}", "0".repeat(64));
    assert!(wrong_epoch.validate_against_chunks(&chunks).is_err());
}

#[test]
fn persisted_grant_discards_raw_scope_and_uses_private_atomic_state() {
    let (grants, _checkpoints) = stores("private-grant-state");
    enabled(&grants);

    let encoded = String::from_utf8(fs::read(grants.path()).unwrap()).unwrap();
    assert!(!encoded.contains(INSTALLATION_ID));
    assert!(!encoded.contains("org_fixture"));
    assert!(!encoded.contains("user_fixture"));
    assert!(encoded.contains("installation_fingerprint"));
    assert!(encoded.contains("grant_scope_id"));

    let parent = grants.path().parent().unwrap();
    assert!(fs::read_dir(parent).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(grants.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(grants.path().with_extension("lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn legacy_v1_grant_is_privately_migrated_and_remains_revocable() {
    let (grants, _checkpoints) = stores("legacy-grant-migration");
    let legacy = json!({
        "schema_version": GRANT_SCHEMA_VERSION,
        "hmac_key_hex": "11".repeat(32),
        "grant": {
            "schema_version": GRANT_SCHEMA_VERSION,
            "collector_id": COLLECTOR_ID,
            "collector_version": COLLECTOR_VERSION,
            "release_lane": "supported",
            "disclosure_version": "cloud_sessions_disclosure.v1",
            "status": CloudSessionGrantStatus::Enabled,
            "installation_id": "legacy-installation-raw",
            "organization_fingerprint": "hmac-sha256:legacy-org",
            "effective_user_fingerprint": "hmac-sha256:legacy-user",
            "account_fingerprint": "hmac-sha256:legacy-account",
            "granted_at": "2026-07-20T12:00:00Z",
            "paused_at": null,
            "revoked_at": null,
            "last_collector_health": "enabled",
            "last_freshness": "unavailable",
            "last_error_category": null
        }
    });
    fs::write(grants.path(), serde_json::to_vec(&legacy).unwrap()).unwrap();

    let migrated = grants.load().unwrap().unwrap();
    assert_eq!(migrated.status, CloudSessionGrantStatus::Enabled);
    assert!(migrated.backend_binding.is_none());
    assert!(migrated
        .installation_fingerprint
        .starts_with("hmac-sha256:"));
    assert!(migrated.grant_scope_id.starts_with("hmac-sha256:"));
    let encoded = String::from_utf8(fs::read(grants.path()).unwrap()).unwrap();
    assert!(!encoded.contains("legacy-installation-raw"));
    assert!(!encoded.contains("installation_id"));

    grants.pause(now()).unwrap();
    assert_eq!(
        grants.load().unwrap().unwrap().status,
        CloudSessionGrantStatus::Paused
    );
    grants.revoke(now()).unwrap();
    assert_eq!(
        grants.load().unwrap().unwrap().status,
        CloudSessionGrantStatus::Revoked
    );
}

#[test]
fn empty_terminal_enumeration_is_an_authoritative_complete_snapshot() {
    let (grants, checkpoints) = stores("empty-complete-snapshot");
    enabled(&grants);
    let runner = Pages {
        pages: RefCell::new(vec![json!({"tasks": [], "cursor": null}).to_string()]),
        calls: Cell::new(0),
        revoke: None,
    };
    let transport = RecordingTransport {
        calls: Cell::new(0),
        batches: RefCell::new(Vec::new()),
        fail: false,
    };

    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Uploaded
    );
    let batches = transport.batches.borrow();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].batch_kind, CloudSessionBatchKind::Snapshot);
    assert!(batches[0].snapshot_complete);
    assert!(batches[0].observations.is_empty());
    assert_eq!(
        checkpoints.load().last_complete_snapshot_at.as_deref(),
        Some("2026-07-21T12:00:00Z")
    );
}

#[test]
fn backend_binding_requires_exact_scope_and_monotonic_reconsent_epoch() {
    let (grants, checkpoints) = stores("grant-epoch");
    let setup = CloudSessionGrantSetup {
        installation_id: INSTALLATION_ID.to_string(),
        organization_scope: "org_fixture".to_string(),
        effective_user_scope: "user_fixture".to_string(),
    };
    let local = grants.enable(&setup, now()).unwrap();
    assert_eq!(local.status, CloudSessionGrantStatus::ConsentRequired);
    assert_eq!(local.granted_at, None);
    assert!(grants
        .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
        .is_err());
    let request = grants.grant_create_request(INSTALLATION_ID).unwrap();
    assert_eq!(request.grant_scope_fingerprint, local.grant_scope_id);
    assert_eq!(
        grants.grant_create_request(INSTALLATION_ID).unwrap(),
        request
    );
    assert!(grants
        .grant_create_request("00000000-0000-4000-8000-000000000099")
        .is_err());
    let mut wrong_installation = backend_grant(&local, "enabled", 1);
    wrong_installation.installation_id = "00000000-0000-4000-8000-000000000099".to_string();
    assert!(grants
        .bind_backend_grant(&wrong_installation, "00000000-0000-4000-8000-000000000099",)
        .is_err());

    let first_response = backend_grant(&local, "enabled", 1);
    let first_bound = grants
        .bind_backend_grant(&first_response, INSTALLATION_ID)
        .unwrap();
    let bound_bytes = fs::read(grants.path()).unwrap();
    assert_eq!(
        grants
            .bind_backend_grant(&first_response, INSTALLATION_ID)
            .unwrap(),
        first_bound
    );
    assert_eq!(fs::read(grants.path()).unwrap(), bound_bytes);
    let mut different_id = first_response.clone();
    different_id.id = "00000000-0000-4000-8000-000000000099".to_string();
    assert!(grants
        .bind_backend_grant(&different_id, INSTALLATION_ID)
        .is_err());
    let mut different_epoch = first_response.clone();
    different_epoch.grant_version += 1;
    assert!(grants
        .bind_backend_grant(&different_epoch, INSTALLATION_ID)
        .is_err());
    let mut different_policy = first_response;
    different_policy.server_policy_state = CloudSessionServerPolicyState::Disabled;
    assert!(grants
        .bind_backend_grant(&different_policy, INSTALLATION_ID)
        .is_err());
    let first_runner = Pages {
        pages: RefCell::new(vec![page("one", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    let transport = RecordingTransport {
        calls: Cell::new(0),
        batches: RefCell::new(Vec::new()),
        fail: false,
    };
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &first_runner, &transport, now()),
        CloudSessionCycleOutcome::Uploaded
    );
    grants.revoke(now()).unwrap();
    grants
        .apply_backend_revocation(&backend_grant(&local, "revoked", 2), INSTALLATION_ID)
        .unwrap();
    let pending = grants
        .enable(&setup, now() + TimeDuration::minutes(1))
        .unwrap();
    assert_eq!(pending.status, CloudSessionGrantStatus::ConsentRequired);
    grants.grant_create_request(INSTALLATION_ID).unwrap();
    assert!(grants
        .bind_backend_grant(&backend_grant(&local, "enabled", 2), INSTALLATION_ID)
        .is_err());
    grants
        .bind_backend_grant(&backend_grant(&local, "enabled", 3), INSTALLATION_ID)
        .unwrap();

    let runner = Pages {
        pages: RefCell::new(vec![page("one", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Uploaded
    );
    let noop_runner = Pages {
        pages: RefCell::new(vec![page("one", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &noop_runner, &transport, now()),
        CloudSessionCycleOutcome::Noop
    );
    let batches = transport.batches.borrow();
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].grant_version, 1);
    assert_eq!(batches[1].grant_version, 3);
    assert_eq!(batches[1].observations.len(), 1);
}

#[test]
fn server_policy_transitions_gate_every_provider_cycle() {
    let (grants, checkpoints) = stores("server-policy-transition");
    enabled(&grants);
    let current = grants.load().unwrap().unwrap();
    let mut disabled_response = backend_grant(&current, "enabled", 1);
    disabled_response.server_policy_state = CloudSessionServerPolicyState::Disabled;
    let disabled_transport = RevalidationTransport {
        response: Some(disabled_response),
        revalidation_calls: Cell::new(0),
        send_calls: Cell::new(0),
    };
    let disabled_runner = Pages {
        pages: RefCell::new(vec![page("must-not-run", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &checkpoints,
            &disabled_runner,
            &disabled_transport,
            now(),
        ),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(disabled_transport.revalidation_calls.get(), 1);
    assert_eq!(disabled_runner.calls.get(), 0);
    assert_eq!(disabled_transport.send_calls.get(), 0);
    assert_eq!(
        grants.load().unwrap().unwrap().status,
        CloudSessionGrantStatus::PolicyDisabled
    );

    let disabled = grants.load().unwrap().unwrap();
    let approved_transport = RevalidationTransport {
        response: Some(backend_grant(&disabled, "enabled", 1)),
        revalidation_calls: Cell::new(0),
        send_calls: Cell::new(0),
    };
    let approved_runner = Pages {
        pages: RefCell::new(vec![page("one", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &checkpoints,
            &approved_runner,
            &approved_transport,
            now() + TimeDuration::minutes(5),
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    // One grant revalidation gates the provider page, one gates the chunk,
    // and one gates finalization.
    assert_eq!(approved_transport.revalidation_calls.get(), 3);
    assert_eq!(approved_runner.calls.get(), 1);
    assert_eq!(approved_transport.send_calls.get(), 1);
    assert_eq!(
        grants.load().unwrap().unwrap().status,
        CloudSessionGrantStatus::Enabled
    );
}

#[test]
fn ambiguous_backend_create_retries_exact_request_until_late_grant_is_deleted() {
    let (grants, _checkpoints) = stores("bind-create-reconcile");
    let setup = CloudSessionGrantSetup {
        installation_id: INSTALLATION_ID.to_string(),
        organization_scope: "org_fixture".to_string(),
        effective_user_scope: "user_fixture".to_string(),
    };
    let local = grants.enable(&setup, now()).unwrap();
    let first = grants.grant_create_request(INSTALLATION_ID).unwrap();
    let restarted = CloudSessionGrantStore::new(grants.path().to_path_buf());
    assert_eq!(
        restarted.grant_create_request(INSTALLATION_ID).unwrap(),
        first
    );
    restarted.revoke(now()).unwrap();

    let replacement = CloudSessionGrantSetup {
        installation_id: INSTALLATION_ID.to_string(),
        organization_scope: "replacement_org".to_string(),
        effective_user_scope: "replacement_user".to_string(),
    };
    assert!(restarted.enable(&replacement, now()).is_err());
    let pending = restarted.load().unwrap().unwrap();
    assert!(pending.backend_create_pending);
    assert!(pending.pending_backend_create.is_some());
    assert!(pending.backend_binding.is_none());
    assert_eq!(
        cloud_session_collector_status(&restarted, &DeferredCloudSessionTransport).reason_code,
        "backend_grant_reconciliation_required"
    );

    assert!(restarted
        .confirm_backend_grant_absent_after_reconciliation()
        .is_err());
    assert_eq!(
        restarted.grant_create_request(INSTALLATION_ID).unwrap(),
        first
    );
    assert_eq!(
        restarted
            .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
            .unwrap()
            .status,
        CloudSessionGrantStatus::Revoked
    );
    let late = restarted.load().unwrap().unwrap();
    assert_eq!(late.status, CloudSessionGrantStatus::Revoked);
    assert!(!late.backend_create_pending);
    assert!(late.pending_backend_create.is_none());
    assert_eq!(late.backend_binding.as_ref().unwrap().grant_id, GRANT_ID);
    restarted
        .apply_backend_revocation(&backend_grant(&late, "revoked", 2), INSTALLATION_ID)
        .unwrap();
    let prepared = restarted.enable(&replacement, now()).unwrap();
    assert_eq!(prepared.status, CloudSessionGrantStatus::ConsentRequired);
    assert!(!prepared.backend_create_pending);
    assert!(prepared.backend_binding.is_none());
}

#[test]
fn unchanged_polls_emit_hourly_heartbeats_and_one_complete_snapshot_per_active_day() {
    let (grants, checkpoints) = stores("heartbeat");
    enabled(&grants);
    let transport = RecordingTransport {
        calls: Cell::new(0),
        batches: RefCell::new(Vec::new()),
        fail: false,
    };
    let run = |at| {
        let runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, at)
    };

    assert_eq!(run(now()), CloudSessionCycleOutcome::Uploaded);
    assert_eq!(
        run(now() + TimeDuration::minutes(59)),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(
        run(now() + TimeDuration::hours(1)),
        CloudSessionCycleOutcome::Heartbeat
    );
    assert_eq!(
        run(now() + TimeDuration::hours(2)),
        CloudSessionCycleOutcome::Heartbeat
    );
    assert_eq!(
        run(now() + TimeDuration::days(1)),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(transport.calls.get(), 4);
    let batches = transport.batches.borrow();
    assert_eq!(batches[0].observations.len(), 1);
    assert_eq!(batches[0].batch_kind, CloudSessionBatchKind::Snapshot);
    assert!(batches[0].snapshot_complete);
    assert!(batches[1].observations.is_empty());
    assert!(batches[2].observations.is_empty());
    assert_eq!(batches[1].batch_kind, CloudSessionBatchKind::Heartbeat);
    assert!(!batches[1].snapshot_complete);
    assert_eq!(batches[2].health.state, "healthy");
    assert_eq!(batches[3].batch_kind, CloudSessionBatchKind::Snapshot);
    assert!(batches[3].snapshot_complete);
    assert_eq!(batches[3].observations.len(), 1);
    let checkpoint = checkpoints.load();
    assert_eq!(
        checkpoint.last_health_upload_at.as_deref(),
        Some("2026-07-22T12:00:00Z")
    );
    assert_eq!(
        checkpoint.last_complete_snapshot_at.as_deref(),
        Some("2026-07-22T12:00:00Z")
    );
}

#[test]
fn nonempty_provider_page_without_valid_identity_is_failing_not_empty_healthy() {
    let (grants, checkpoints) = stores("provider-invalid-identities");
    enabled(&grants);
    let runner = Pages {
        pages: RefCell::new(vec![json!({"tasks":[{"status":"running"},42]}).to_string()]),
        calls: Cell::new(0),
        revoke: None,
    };
    let transport = RecordingTransport {
        calls: Cell::new(0),
        batches: RefCell::new(Vec::new()),
        fail: false,
    };
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Failed
    );
    assert_eq!(runner.calls.get(), 1);
    let batches = transport.batches.borrow();
    assert_eq!(batches.len(), 1);
    assert!(batches[0].observations.is_empty());
    assert_eq!(batches[0].batch_kind, CloudSessionBatchKind::Heartbeat);
    assert!(!batches[0].snapshot_complete);
    assert_eq!(batches[0].health.state, "failing");
    assert_eq!(
        serde_json::to_value(&batches[0].health).unwrap(),
        json!({
            "state": "failing",
            "observed_at": "2026-07-21T12:00:00Z",
            "error_category": "provider_error"
        })
    );
    let wire = serde_json::to_string(&batches[0]).unwrap();
    assert!(!wire.contains("provider_payload_invalid"));
    assert!(!wire.contains("provider_unavailable"));
    assert_eq!(
        checkpoints.load().last_error_category.as_deref(),
        Some("provider_payload_invalid")
    );
    assert_eq!(
        grants
            .load()
            .unwrap()
            .unwrap()
            .last_collector_health
            .as_deref(),
        Some("failing")
    );
}

#[test]
fn relay_token_redirect_never_forwards_the_device_secret() {
    use std::io::{ErrorKind, Write};
    use std::net::TcpListener;

    let attacker = TcpListener::bind("127.0.0.1:0").unwrap();
    let attacker_address = attacker.local_addr().unwrap();
    attacker.set_nonblocking(true).unwrap();
    let relay = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_address = relay.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(String::new()));
    let server_captured = Arc::clone(&captured);
    let server = thread::spawn(move || {
        let (mut stream, _) = relay.accept().unwrap();
        *server_captured.lock().unwrap() = read_http_request(&mut stream);
        write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: http://{attacker_address}/capture\r\nContent-Type: application/json\r\nContent-Length: 31\r\nConnection: close\r\n\r\n{{\"token\":\"redirect-body-token\"}}"
        )
        .unwrap();
    });

    let transport = RelayCloudSessionTransport::new(
        format!("http://{relay_address}"),
        LocalDeviceBinding {
            device_id: INSTALLATION_ID.to_string(),
            machine_id: None,
            sources: vec!["codex".to_string()],
        },
        "redirect-guard-secret".to_string(),
    );
    let error = transport
        .token(false, Instant::now() + Duration::from_secs(2))
        .unwrap_err();
    let diagnostics = error
        .downcast_ref::<crate::snapshot_client::UploadFailureDiagnostics>()
        .unwrap();
    assert_eq!(diagnostics.status_family(), "http_3xx");
    server.join().unwrap();
    assert!(captured
        .lock()
        .unwrap()
        .contains("X-Ottto-Device-Secret: redirect-guard-secret"));
    assert!(matches!(
        attacker.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
}

#[test]
fn v1_heartbeat_checkpoint_requires_an_exact_bound_receipt() {
    use std::io::Write;
    use std::net::TcpListener;

    struct RevalidatingHeartbeatRelay {
        relay: RelayCloudSessionTransport,
        grant: CloudSessionBackendGrantResponseV1,
    }
    impl CloudSessionTransport for RevalidatingHeartbeatRelay {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }
        fn revalidate_grant(
            &self,
            _grant: &CloudSessionGrant,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            Ok(self.grant.clone())
        }
        fn revalidate_grant_bounded(
            &self,
            grant: &CloudSessionGrant,
            _timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            self.revalidate_grant(grant)
        }
        fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.relay.send(batch)
        }
        fn send_bounded(
            &self,
            batch: &CloudSessionObservationBatchV1,
            timeout: Duration,
        ) -> Result<()> {
            self.relay.send_bounded(batch, timeout)
        }
    }

    let exact = json!({
        "schema_version": "cloud_session_heartbeat_ack.v1",
        "accepted": true,
        "observations_written": 0,
        "noop": true,
        "grant_status": "enabled",
        "fresh_at": "2026-07-21T13:00:00Z",
    });
    let mut negative = exact.clone();
    negative["accepted"] = json!(false);
    let mut mismatch = exact.clone();
    mismatch["fresh_at"] = json!("2026-07-21T13:00:01Z");
    let mut unknown = exact.clone();
    unknown["unexpected"] = json!(true);
    let cases = [
        ("negative", negative.to_string(), false),
        ("mismatch", mismatch.to_string(), false),
        ("malformed", r#"{"accepted":true}"#.to_string(), false),
        ("unknown", unknown.to_string(), false),
        ("exact", exact.to_string(), true),
    ];

    for (name, response_body, accepted) in cases {
        let (grants, checkpoints) = stores(&format!("v1-heartbeat-receipt-{name}"));
        enabled(&grants);
        let seed_runner = CursorRecordingPages::new(vec![page("stable", None)]);
        let seed_transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &seed_runner,
                &seed_transport,
                now(),
            ),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(
            checkpoints.load().last_health_upload_at.as_deref(),
            Some("2026-07-21T12:00:00Z")
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                let body = if index == 0 {
                    r#"{"token":"relay-v1"}"#
                } else {
                    assert!(request.contains("/api/v1/cloud-session-observations/batches"));
                    &response_body
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let current = grants.load().unwrap().unwrap();
        let transport = RevalidatingHeartbeatRelay {
            grant: backend_grant(&current, "enabled", 1),
            relay: RelayCloudSessionTransport::new(
                format!("http://{address}"),
                LocalDeviceBinding {
                    device_id: INSTALLATION_ID.to_string(),
                    machine_id: None,
                    sources: vec!["codex".to_string()],
                },
                "device-secret".to_string(),
            ),
        };
        let runner = CursorRecordingPages::new(vec![page("stable", None)]);
        let outcome = collect_cloud_sessions_once(
            &grants,
            &checkpoints,
            &runner,
            &transport,
            now() + TimeDuration::hours(1),
        );
        assert_eq!(
            outcome,
            if accepted {
                CloudSessionCycleOutcome::Heartbeat
            } else {
                CloudSessionCycleOutcome::Failed
            },
            "case {name}"
        );
        assert_eq!(
            checkpoints.load().last_health_upload_at.as_deref(),
            Some(if accepted {
                "2026-07-21T13:00:00Z"
            } else {
                "2026-07-21T12:00:00Z"
            }),
            "case {name}"
        );
        server.join().unwrap();
    }
}

#[test]
fn v2_relay_uses_exact_paths_and_retries_exact_body_after_auth_refresh() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    let (grants, checkpoints) = stores("v2-relay-http-fixture");
    enabled(&grants);
    let fixture_runner = CursorRecordingPages::new(vec![page("raw-provider-private-id", None)]);
    let fixture_transport = V2RecordingTransport::new();
    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &checkpoints,
            &fixture_runner,
            &fixture_transport,
            now(),
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    let chunk = fixture_transport.chunks.borrow()[0].clone();
    let finalize = fixture_transport.finalizes.borrow()[0].clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let server_captured = Arc::clone(&captured);
    let server = thread::spawn(move || {
        for index in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(header_end) = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|offset| offset + 4)
                {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    });
                    if request.len() >= header_end + content_length.unwrap_or(0) {
                        break;
                    }
                }
            }
            let captured_request = String::from_utf8_lossy(&request).to_string();
            server_captured
                .lock()
                .unwrap()
                .push(captured_request.clone());
            let (status, body) = match index {
                0 => (
                    "200 OK".to_string(),
                    r#"{"token":"relay-v2-old"}"#.to_string(),
                ),
                1 => (
                    "401 Unauthorized".to_string(),
                    r#"{"detail":"expired"}"#.to_string(),
                ),
                2 => (
                    "200 OK".to_string(),
                    r#"{"token":"relay-v2-new"}"#.to_string(),
                ),
                _ => ("200 OK".to_string(), exact_scan_ack(&captured_request)),
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });

    let relay = RelayCloudSessionTransport::new(
        format!("http://{address}"),
        LocalDeviceBinding {
            device_id: INSTALLATION_ID.to_string(),
            machine_id: None,
            sources: vec!["codex".to_string()],
        },
        "device-secret".to_string(),
    );
    relay.send_scan_chunk(&chunk).unwrap();
    relay.finalize_scan(&finalize).unwrap();
    server.join().unwrap();

    let requests = captured.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].starts_with(&format!(
        "POST /api/v1/telemetry/devices/{INSTALLATION_ID}/relay-token HTTP/1.1"
    )));
    let chunk_path = format!("/api/v1/cloud-sessions/scans/{}/chunks", chunk.scan_id);
    let finalize_path = format!("/api/v1/cloud-sessions/scans/{}/finalize", finalize.scan_id);
    for request in [&requests[1], &requests[3]] {
        assert!(request.starts_with(&format!("POST {chunk_path} HTTP/1.1")));
        let body = request.split_once("\r\n\r\n").unwrap().1;
        let payload: Value = serde_json::from_str(body).unwrap();
        assert_eq!(payload["scan_id"], chunk.scan_id);
        assert!(!body.contains("raw-provider-private-id"));
        assert!(!body.contains("cursor"));
    }
    assert!(requests[1].contains("Authorization: Bearer relay-v2-old"));
    assert!(requests[3].contains("Authorization: Bearer relay-v2-new"));
    assert_eq!(
        requests[1].split_once("\r\n\r\n").unwrap().1,
        requests[3].split_once("\r\n\r\n").unwrap().1
    );
    assert!(requests[4].starts_with(&format!("POST {finalize_path} HTTP/1.1")));
    let finalize_body = requests[4].split_once("\r\n\r\n").unwrap().1;
    let finalize_payload: Value = serde_json::from_str(finalize_body).unwrap();
    assert_eq!(finalize_payload["scan_id"], finalize.scan_id);
    assert!(!finalize_body.contains("raw-provider-private-id"));
    assert!(!finalize_body.contains("cursor"));
}

#[test]
fn v2_receipts_must_exactly_acknowledge_before_progress_or_completion() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    struct RevalidatingRelay {
        relay: RelayCloudSessionTransport,
        grant: CloudSessionBackendGrantResponseV1,
    }
    impl CloudSessionTransport for RevalidatingRelay {
        fn supports_grant_revalidation(&self) -> bool {
            true
        }
        fn revalidate_grant(
            &self,
            _grant: &CloudSessionGrant,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            Ok(self.grant.clone())
        }
        fn revalidate_grant_bounded(
            &self,
            grant: &CloudSessionGrant,
            _timeout: Duration,
        ) -> Result<CloudSessionBackendGrantResponseV1> {
            self.revalidate_grant(grant)
        }
        fn send_scan_chunk(&self, chunk: &CloudSessionObservationChunkV2) -> Result<()> {
            self.relay.send_scan_chunk(chunk)
        }
        fn send_scan_chunk_bounded(
            &self,
            chunk: &CloudSessionObservationChunkV2,
            timeout: Duration,
        ) -> Result<()> {
            self.relay.send_scan_chunk_bounded(chunk, timeout)
        }
        fn finalize_scan(&self, finalize: &CloudSessionScanFinalizeV2) -> Result<()> {
            self.relay.finalize_scan(finalize)
        }
        fn finalize_scan_bounded(
            &self,
            finalize: &CloudSessionScanFinalizeV2,
            timeout: Duration,
        ) -> Result<()> {
            self.relay.finalize_scan_bounded(finalize, timeout)
        }
        fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.relay.send(batch)
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for index in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(header_end) = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|offset| offset + 4)
                {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    });
                    if request.len() >= header_end + content_length.unwrap_or(0) {
                        break;
                    }
                }
            }
            let request = String::from_utf8_lossy(&request).to_string();
            let body = if index == 0 {
                r#"{"token":"relay-v2"}"#.to_string()
            } else {
                let mut ack: Value = serde_json::from_str(&exact_scan_ack(&request)).unwrap();
                if index == 1 {
                    ack["accepted"] = json!(false);
                } else if index == 3 {
                    ack["epoch_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
                }
                ack.to_string()
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });

    let (grants, checkpoints) = stores("v2-strict-receipts");
    enabled(&grants);
    let current = grants.load().unwrap().unwrap();
    let transport = RevalidatingRelay {
        grant: backend_grant(&current, "enabled", 1),
        relay: RelayCloudSessionTransport::new(
            format!("http://{address}"),
            LocalDeviceBinding {
                device_id: INSTALLATION_ID.to_string(),
                machine_id: None,
                sources: vec!["codex".to_string()],
            },
            "device-secret".to_string(),
        ),
    };
    let runner = CursorRecordingPages::new(vec![page("strict-receipt", None)]);

    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Failed
    );
    {
        let runtime = checkpoints.runtime.lock().unwrap();
        assert_eq!(
            runtime
                .active
                .as_ref()
                .unwrap()
                .prepared
                .as_ref()
                .unwrap()
                .next_chunk,
            0
        );
    }
    assert!(checkpoints.load().last_complete_snapshot_at.is_none());

    let unused_runner = CursorRecordingPages::new(Vec::new());
    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &checkpoints,
            &unused_runner,
            &transport,
            now() + TimeDuration::minutes(3),
        ),
        CloudSessionCycleOutcome::Failed
    );
    {
        let runtime = checkpoints.runtime.lock().unwrap();
        let prepared = runtime.active.as_ref().unwrap().prepared.as_ref().unwrap();
        assert_eq!(prepared.next_chunk, 1);
        assert!(prepared.finalize.is_some());
    }
    assert!(checkpoints.load().last_complete_snapshot_at.is_none());

    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &checkpoints,
            &unused_runner,
            &transport,
            now() + TimeDuration::minutes(8),
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    assert!(checkpoints.load().last_complete_snapshot_at.is_some());
    assert!(checkpoints.runtime.lock().unwrap().active.is_none());
    assert!(unused_runner.cursors.borrow().is_empty());
    server.join().unwrap();
}

#[test]
fn collector_supervisor_has_one_process_owner_under_concurrency() {
    let started = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let attempts = (0..8)
        .map(|_| {
            let started = Arc::clone(&started);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                reserve_collector_supervisor(&started)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    assert_eq!(
        attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .filter(|won| *won)
            .count(),
        1
    );
}

#[test]
fn no_grant_is_zero_touch_beyond_the_local_grant_read() {
    let root = temp_dir("runtime-no-grant-zero-touch");
    let grants = CloudSessionGrantStore::new(root.join("grant.json"));
    let checkpoints = CloudSessionCheckpointStore::new(root.join("checkpoint.json"));
    let unreadable_account = root.join("unreadable-account");
    let unreadable_device = root.join("unreadable-device");
    let unreadable_connection = root.join("unreadable-connection");
    fs::create_dir(&unreadable_account).unwrap();
    fs::create_dir(&unreadable_device).unwrap();
    fs::create_dir(&unreadable_connection).unwrap();
    let accounts = FileAccountStore::new(unreadable_account);
    let devices = FileDeviceStore::new(unreadable_device);
    let connections = FileConnectionStore::new(unreadable_connection);
    let runner = Pages {
        pages: RefCell::new(vec![page("must-not-run", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    let mut active_transport: ActiveCloudSessionTransport = None;

    assert_eq!(
        collect_composed_cloud_sessions_once_with(
            &grants,
            &checkpoints,
            &runner,
            &mut active_transport,
            &accounts,
            &devices,
            &connections,
            || panic!("no grant must not read relay credentials"),
            |_, _, _| panic!("no grant must not compose or contact the relay"),
            now(),
        ),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!(runner.calls.get(), 0);
    assert!(active_transport.is_none());
    assert!(!grants.path().exists());
    assert!(!checkpoints.path.exists());
    assert!(checkpoints.runtime.lock().unwrap().active.is_none());
}

#[test]
fn later_consent_activates_the_existing_supervisor_without_restart() {
    let root = temp_dir("runtime-later-consent");
    let grants = CloudSessionGrantStore::new(root.join("grant.json"));
    let checkpoints = CloudSessionCheckpointStore::new(root.join("checkpoint.json"));
    let (accounts, devices, connections) =
        runtime_identity_stores(&root, "user_fixture", "org_fixture", DEFAULT_API_BASE_URL);
    let runner = Pages {
        pages: RefCell::new(vec![page("after-consent", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    let credential_reads = Cell::new(0);
    let transport_compositions = Cell::new(0);
    let mut active_transport: ActiveCloudSessionTransport = None;

    assert_eq!(
        collect_composed_cloud_sessions_once_with(
            &grants,
            &checkpoints,
            &runner,
            &mut active_transport,
            &accounts,
            &devices,
            &connections,
            || panic!("dormant supervisor must not read relay credentials"),
            |_, _, _| panic!("dormant supervisor must not compose a relay"),
            now(),
        ),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!(runner.calls.get(), 0);
    assert!(active_transport.is_none());
    assert!(!checkpoints.path.exists());

    // A previous consent epoch's relay/provider failure may have left a
    // long backoff. New consent must not inherit that stale circuit.
    checkpoints
        .save(&CloudSessionCheckpoint {
            schema_version: CHECKPOINT_SCHEMA_VERSION.to_string(),
            circuit_grant_epoch_digest: Some(sha256(b"previous-grant-epoch")),
            consecutive_failures: 6,
            circuit_open_until: Some(timestamp(now() + TimeDuration::hours(1))),
            last_error_category: Some("provider_error".to_string()),
            ..Default::default()
        })
        .unwrap();

    enabled(&grants);
    assert_eq!(
        collect_composed_cloud_sessions_once_with(
            &grants,
            &checkpoints,
            &runner,
            &mut active_transport,
            &accounts,
            &devices,
            &connections,
            || {
                credential_reads.set(credential_reads.get() + 1);
                Ok((
                    devices.load().unwrap().unwrap(),
                    "device-secret".to_string(),
                ))
            },
            |_, _, _| {
                transport_compositions.set(transport_compositions.get() + 1);
                Box::new(V2RecordingTransport::new())
            },
            now() + TimeDuration::minutes(5),
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(credential_reads.get(), 1);
    assert_eq!(transport_compositions.get(), 1);
    assert_eq!(runner.calls.get(), 1);
    assert!(active_transport.is_some());
    let checkpoint = checkpoints.load();
    assert!(checkpoint.circuit_open_until.is_none());
    assert!(checkpoint.circuit_grant_epoch_digest.is_none());
}

#[test]
fn runtime_rejects_untrusted_destination_without_mutating_grant() {
    let root = temp_dir("runtime-untrusted-destination");
    let grants = CloudSessionGrantStore::new(root.join("grant.json"));
    enabled(&grants);
    let (accounts, devices, connections) = runtime_identity_stores(
        &root,
        "user_fixture",
        "org_fixture",
        "https://attacker.example",
    );
    let before_grant = fs::read(grants.path()).unwrap();

    assert!(
        load_cloud_session_runtime_binding(&grants, &accounts, &devices, &connections,).is_err()
    );
    assert_eq!(fs::read(grants.path()).unwrap(), before_grant);
    assert!(validated_cloud_session_api_base_url("http://localhost.evil").is_err());
    assert!(validated_cloud_session_api_base_url("https://api.ottto.net@evil").is_err());
}

#[test]
fn disabled_and_revoked_grants_never_call_provider_or_transport() {
    let (grants, checkpoints) = stores("revoke");
    let runner = Pages {
        pages: RefCell::new(vec![page("one", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    let transport = RecordingTransport {
        calls: Cell::new(0),
        batches: RefCell::new(Vec::new()),
        fail: false,
    };
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Disabled
    );
    enabled(&grants);
    grants.revoke(now()).unwrap();
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!(runner.calls.get(), 0);
    assert_eq!(transport.calls.get(), 0);
}

#[test]
fn revocation_between_page_and_send_stops_upload() {
    let (grants, checkpoints) = stores("race");
    enabled(&grants);
    let runner = Pages {
        pages: RefCell::new(vec![
            page("one", Some("cursor-after-revoke")),
            page("two", None),
        ]),
        calls: Cell::new(0),
        revoke: Some(grants.clone()),
    };
    let transport = RecordingTransport {
        calls: Cell::new(0),
        batches: RefCell::new(Vec::new()),
        fail: false,
    };
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(runner.calls.get(), 1);
    assert_eq!(transport.calls.get(), 0);
}

#[test]
fn revocation_after_finalize_revalidation_closes_relay_admission() {
    let root = temp_dir("finalize-post-revalidation-race");
    let grants = CloudSessionGrantStore::new(root.join("grant.json"));
    enabled(&grants);
    let checkpoints = Arc::new(CloudSessionCheckpointStore::new(
        root.join("checkpoint.json"),
    ));
    let transport = Arc::new(ThreadRecordingTransport::default());
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    // Skip the chunk boundary and stop exactly after finalization's
    // backend authority response but before finalization admission.
    checkpoints.set_relay_admission_barrier_for_test(1, Arc::clone(&entered), Arc::clone(&release));

    let collector_grants = grants.clone();
    let collector_checkpoints = Arc::clone(&checkpoints);
    let collector_transport = Arc::clone(&transport);
    let collector = thread::spawn(move || {
        collect_cloud_sessions_once(
            &collector_grants,
            &collector_checkpoints,
            &CursorRecordingPages::new(vec![page("finalize-race", None)]),
            collector_transport.as_ref(),
            now(),
        )
    });
    entered.wait();
    grants.revoke(now()).unwrap();
    release.wait();

    assert_eq!(collector.join().unwrap(), CloudSessionCycleOutcome::Noop);
    assert_eq!(transport.chunks.load(Ordering::SeqCst), 1);
    assert_eq!(transport.finalizes.load(Ordering::SeqCst), 0);
}

#[test]
fn health_update_cannot_restore_a_revoked_grant() {
    let (grants, _checkpoints) = stores("grant-lock");
    enabled(&grants);
    grants.revoke(now()).unwrap();
    grants.record_health("ok", "fresh", None).unwrap();
    let grant = grants.load().unwrap().unwrap();
    assert_eq!(grant.status, CloudSessionGrantStatus::Revoked);
    assert_eq!(grant.last_collector_health.as_deref(), Some("revoked"));
}

#[test]
fn transport_failures_open_a_bounded_circuit() {
    let (grants, checkpoints) = stores("circuit");
    enabled(&grants);
    let runner = Pages {
        pages: RefCell::new(vec![page("one", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    let transport = RecordingTransport {
        calls: Cell::new(0),
        batches: RefCell::new(Vec::new()),
        fail: true,
    };
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Failed
    );
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::CircuitOpen
    );
    assert_eq!(runner.calls.get(), 1);
}

#[test]
fn deferred_transport_does_not_call_the_provider() {
    let (grants, checkpoints) = stores("deferred");
    enabled(&grants);
    let runner = Pages {
        pages: RefCell::new(vec![page("one", None)]),
        calls: Cell::new(0),
        revoke: None,
    };
    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &checkpoints,
            &runner,
            &DeferredCloudSessionTransport,
            now(),
        ),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(runner.calls.get(), 0);
}

#[test]
fn hundred_full_pages_emit_ten_ordered_chunks_with_reproducible_digests() {
    let (grants, checkpoints) = stores("v2-two-thousand");
    enabled(&grants);
    let pages = (0..MAX_SCAN_PAGES)
        .map(|index| {
            let cursor =
                (index + 1 < MAX_SCAN_PAGES).then(|| format!("private-cursor-{}", index + 1));
            full_page(index * PAGE_LIMIT, cursor.as_deref())
        })
        .collect::<Vec<_>>();
    let first_runner = CursorRecordingPages::new(pages.clone());
    let transport = V2RecordingTransport::new();
    assert_eq!(
        run_full_scan_cycles(&grants, &checkpoints, &first_runner, &transport, now()),
        CloudSessionCycleOutcome::Uploaded
    );
    let first_chunks = transport.chunks.borrow().clone();
    let first_finalizes = transport.finalizes.borrow().clone();
    assert_eq!(first_chunks.len(), MAX_SCAN_CHUNKS);
    assert_eq!(first_finalizes.len(), 1);
    assert_eq!(first_runner.cursors.borrow().len(), MAX_SCAN_PAGES);
    for (index, chunk) in first_chunks.iter().enumerate() {
        assert_eq!(usize::from(chunk.chunk_index), index);
        assert_eq!(chunk.observations.len(), MAX_ITEMS);
        assert!(chunk.validate_wire_contract().is_ok());
    }
    let finalize = &first_finalizes[0];
    assert_eq!(finalize.chunk_count, MAX_SCAN_CHUNKS as u8);
    assert_eq!(finalize.unique_entity_count, MAX_SCAN_ITEMS as u32);
    assert_eq!(finalize.provider_page_count, MAX_SCAN_PAGES as u16);
    assert_eq!(
        finalize.enumeration_consistency,
        CloudSessionEnumerationConsistencyV2::UnstableCursor
    );
    assert_eq!(transport.revalidation_calls.get(), 111);

    let second_runner = CursorRecordingPages::new(pages);
    assert_eq!(
        run_full_scan_cycles(
            &grants,
            &checkpoints,
            &second_runner,
            &transport,
            now() + TimeDuration::days(1),
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    let all_chunks = transport.chunks.borrow();
    let all_finalizes = transport.finalizes.borrow();
    assert_eq!(all_chunks.len(), MAX_SCAN_CHUNKS * 2);
    assert_eq!(all_finalizes.len(), 2);
    let first_digests = first_chunks
        .iter()
        .map(|chunk| {
            (
                chunk.chunk_identity_digest.clone(),
                chunk.chunk_semantic_digest.clone(),
            )
        })
        .collect::<Vec<_>>();
    let second_digests = all_chunks[MAX_SCAN_CHUNKS..]
        .iter()
        .map(|chunk| {
            (
                chunk.chunk_identity_digest.clone(),
                chunk.chunk_semantic_digest.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(first_digests, second_digests);
    assert_eq!(
        all_finalizes[0].inventory_digest,
        all_finalizes[1].inventory_digest
    );
    assert_eq!(all_finalizes[0].epoch_digest, all_finalizes[1].epoch_digest);
}

#[test]
fn v2_digest_vectors_are_length_framed_canonical_and_time_independent() {
    let observation = |entity_key: &str, lifecycle: &str, attempt_count: u64, observed_at: &str| {
        CloudSessionObservationEntityV1 {
            entity_key: entity_key.to_string(),
            entity_kind: "task".to_string(),
            lifecycle: lifecycle.to_string(),
            attempt_count: Some(attempt_count),
            environment_kind: "unknown".to_string(),
            measurement_basis: "not_itemized".to_string(),
            coverage: vec![
                "identity".to_string(),
                "status".to_string(),
                "attempts".to_string(),
            ],
            created_at: None,
            started_at: None,
            updated_at: None,
            completed_at: None,
            observed_at: observed_at.to_string(),
        }
    };
    let observations = vec![
        observation("hmac-sha256:bbb", "completed", 2, "2026-07-22T12:00:00Z"),
        observation("hmac-sha256:aaa", "running", 1, "2026-07-21T12:00:00Z"),
    ];
    let identity = identity_digest(&observations);
    let semantic = observation_semantic_digest(&observations).unwrap();
    assert_eq!(
        identity,
        "sha256:0f2a9c1e8c76bc324c48c94f599300459ac7366f20fd55ec694ee3ed6c26acdd"
    );
    assert_eq!(
        semantic,
        "sha256:b2767eb1db14b24806318c50131b712b6ef8fa4a402204e75d462d975fc6112f"
    );
    let mut different_observed_at = observations.clone();
    for row in &mut different_observed_at {
        row.observed_at = "2026-08-01T00:00:00Z".to_string();
    }
    assert_eq!(
        semantic,
        observation_semantic_digest(&different_observed_at).unwrap()
    );
    let chunk = CloudSessionObservationChunkV2 {
        grant_id: GRANT_ID.to_string(),
        grant_version: 1,
        grant_scope_fingerprint: "hmac-sha256:grant".to_string(),
        collector_id: COLLECTOR_ID.to_string(),
        schema_version: CHUNK_SCHEMA_VERSION.to_string(),
        collector_version: compiled_release_version(),
        account_fingerprint: "hmac-sha256:account".to_string(),
        scan_id: "00000000-0000-4000-8000-000000000099".to_string(),
        scan_started_at: "2026-07-21T12:00:00Z".to_string(),
        chunk_index: 0,
        chunk_identity_digest: identity,
        chunk_semantic_digest: semantic,
        observations,
        health: CloudSessionCollectorHealthV1 {
            state: "healthy".to_string(),
            observed_at: "2026-07-21T12:00:00Z".to_string(),
            error_category: None,
        },
    };
    assert_eq!(
        epoch_digest(&[chunk]),
        "sha256:d24b850a0c925663feca0bf99b0e93b1a5ed6a419d5b3096c6693718ddf8a0b9"
    );
}

#[test]
fn restart_drops_cursor_and_uses_a_new_scan_id_from_page_zero() {
    let root = temp_dir("v2-restart");
    let grants = CloudSessionGrantStore::new(root.join("grant.json"));
    enabled(&grants);
    let checkpoint_path = root.join("checkpoint.json");
    let first_checkpoints = CloudSessionCheckpointStore::new(&checkpoint_path);
    let first_pages = (0..MAX_PAGES)
        .map(|index| full_page(index * PAGE_LIMIT, Some(&format!("cursor-{index}"))))
        .collect::<Vec<_>>();
    let first_runner = CursorRecordingPages::new(first_pages);
    let transport = V2RecordingTransport::new();
    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &first_checkpoints,
            &first_runner,
            &transport,
            now(),
        ),
        CloudSessionCycleOutcome::Noop
    );
    let first_scan_id = first_checkpoints
        .runtime
        .lock()
        .unwrap()
        .active
        .as_ref()
        .unwrap()
        .scan_id
        .clone();
    let persisted = String::from_utf8(fs::read(&checkpoint_path).unwrap()).unwrap();
    assert!(!persisted.contains("cursor-"));
    assert!(!persisted.contains(&first_scan_id));

    let restarted = CloudSessionCheckpointStore::new(&checkpoint_path);
    let second_runner = CursorRecordingPages::new(vec![page("after-restart", None)]);
    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &restarted,
            &second_runner,
            &transport,
            now() + TimeDuration::minutes(5),
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(second_runner.cursors.borrow().as_slice(), &[None]);
    let second_scan_id = transport.finalizes.borrow()[0].scan_id.clone();
    assert_ne!(first_scan_id, second_scan_id);
}

#[test]
fn response_loss_retries_the_exact_same_chunk_before_finalize() {
    let (grants, checkpoints) = stores("v2-response-loss");
    enabled(&grants);
    let runner = CursorRecordingPages::new(vec![page("retry-me", None)]);
    let transport = V2RecordingTransport::new();
    transport.fail_next_chunk.set(true);
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Failed
    );
    assert_eq!(transport.chunks.borrow().len(), 1);
    assert!(transport.finalizes.borrow().is_empty());
    assert_eq!(
        collect_cloud_sessions_once(
            &grants,
            &checkpoints,
            &runner,
            &transport,
            now() + TimeDuration::minutes(3),
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    let chunks = transport.chunks.borrow();
    assert_eq!(chunks.len(), 2);
    assert_eq!(
        serde_json::to_vec(&chunks[0]).unwrap(),
        serde_json::to_vec(&chunks[1]).unwrap()
    );
    assert_eq!(runner.cursors.borrow().len(), 1);
    assert_eq!(transport.finalizes.borrow().len(), 1);
}

#[test]
fn ambiguous_legacy_shapes_upload_positive_facts_without_finalize() {
    for (name, raw) in [
        (
            "fieldless",
            json!({"tasks": [{"id": "fieldless-positive", "status": "running"}]}),
        ),
        (
            "alias-null",
            json!({
                "tasks": [{"id": "alias-null-positive", "status": "running"}],
                "next_cursor": null
            }),
        ),
        (
            "array-root",
            json!([{"id": "array-positive", "status": "running"}]),
        ),
    ] {
        let (grants, checkpoints) = stores(&format!("ambiguous-positive-{name}"));
        enabled(&grants);
        let runner = CursorRecordingPages::new(vec![raw.to_string()]);
        let transport = V2RecordingTransport::new();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded,
            "{name}"
        );
        assert_eq!(transport.chunks.borrow().len(), 1, "{name}");
        assert_eq!(transport.chunks.borrow()[0].observations.len(), 1, "{name}");
        assert_eq!(
            transport.chunks.borrow()[0].health.state,
            "degraded",
            "{name}"
        );
        assert!(transport.finalizes.borrow().is_empty(), "{name}");
        assert!(
            checkpoints.load().last_complete_snapshot_at.is_none(),
            "{name}"
        );
    }
}

#[test]
fn v2_wire_and_persisted_checkpoint_never_contain_provider_cursor_or_raw_identity() {
    let (grants, checkpoints) = stores("v2-wire-privacy");
    enabled(&grants);
    let runner = CursorRecordingPages::new(
        (0..MAX_PAGES)
            .map(|index| {
                page(
                    &format!("raw-provider-private-id-{index}"),
                    Some(&format!("raw-private-cursor-{index}")),
                )
            })
            .collect(),
    );
    let transport = V2RecordingTransport::new();
    assert_eq!(
        collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
        CloudSessionCycleOutcome::Noop
    );
    let persisted = String::from_utf8(fs::read(&checkpoints.path).unwrap()).unwrap();
    assert!(!persisted.contains("raw-private-cursor"));
    assert!(!persisted.contains("raw-provider-private-id"));
    let active = checkpoints.runtime.lock().unwrap();
    let scan = active.active.as_ref().unwrap();
    assert_ne!(scan.cursor.as_deref(), None);
    assert!(!scan
        .observations
        .keys()
        .any(|key| key == "raw-provider-private-id"));
}
