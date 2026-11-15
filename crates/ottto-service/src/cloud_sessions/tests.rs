use super::*;
use std::cell::{Cell, RefCell};

// Collection fixtures enter the process-wide identity admission fence. Use
// the default serial_test key shared by control's identity-mutation tests;
// separate temporary stores alone do not isolate that global reservation.

const DEVICE_ID: &str = "00000000-0000-4000-8000-000000000001";
const ORG_ID: &str = "org_fixture";
const USER_ID: &str = "user_fixture";

fn temp_dir(name: &str) -> PathBuf {
    crate::test_scratch::canonical_private_dir(&format!("ottto-cloud-sessions-{name}"))
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
        let body = if mode == "redirect-output" {
            format!(
                "echo $$ > {}\n/bin/sleep 4 >/dev/null 2>&1 &\necho $! > {}\n/bin/cat {}\nexit {exit_code}\n",
                quote(&root.join("direct")),
                quote(&root.join("descendant")),
                quote(&root.join("output")),
            )
        } else if mode == "output" {
            format!(
                "/bin/cat {}\nexit {exit_code}\n",
                quote(&root.join("output"))
            )
        } else if mode == "ignore-term" {
            format!(
                "trap \"echo TERM >> {}\" TERM\necho $$ > {}\nwhile :; do /bin/sleep 0.1; done\n",
                quote(&root.join("signals")),
                quote(&root.join("direct")),
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

    fn wait_stopped(&self, label: &str) {
        let pid = self.pid(label).to_string();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let output = Command::new("/bin/ps")
                .args(["-o", "stat=", "-p", &pid])
                .output()
                .unwrap();
            let state = String::from_utf8_lossy(&output.stdout);
            if state.trim().is_empty() || state.trim().starts_with('Z') {
                break;
            }
            assert!(Instant::now() < deadline, "Cloud group descendant survived");
            thread::sleep(Duration::from_millis(10));
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

/// [regress] An identity change while a `codex cloud list` page lingers past
/// its deadline (it may be refreshing its login) completes within the stop
/// wait: after the page's deadline and the child's drain, with no SIGTERM,
/// never before the child is gone. An account change waits the same way, so
/// its CLI call must not time out first.
#[cfg(unix)]
#[test]
#[serial_test::serial]
fn identity_change_during_a_lingering_cloud_child_completes_within_the_stop_wait() {
    let fixture = CloudCliFixture::new("ignore-term", &[], 0);
    let (_root, checkpoints) = store("lingering-child-stop");
    let checkpoints = Arc::new(checkpoints);
    let collector_checkpoints = Arc::clone(&checkpoints);
    let drain = Duration::from_secs(1);
    let run = thread::spawn(move || {
        crate::agent_status::with_codex_app_server_test_timeouts(drain, drain, drain, drain, || {
            let server = Server::new();
            CloudCollector::default().run_slice(
                &inputs(&collector_checkpoints, &CodexCloudCliRunner, &server),
                Instant::now(),
                midnight(),
            )
        })
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fixture.root.join("direct").exists() {
        assert!(Instant::now() < deadline, "the page's child started");
        thread::sleep(Duration::from_millis(5));
    }
    let waited = Instant::now();
    checkpoints
        .wait_for_collector_io_idle(COLLECTOR_IO_STOP_TIMEOUT)
        .expect("stopped within the stop wait");
    assert!(waited.elapsed() < COLLECTOR_IO_STOP_TIMEOUT);
    fixture.wait_gone("direct");
    assert!(!fixture.root.join("signals").exists(), "no SIGTERM");
    run.join().unwrap();
    // An account change replies only after this same wait, so its CLI call
    // (the long control timeout) outlasts it with room for the change itself;
    // the ordinary timeout would not.
    assert!(COLLECTOR_IO_STOP_TIMEOUT > ottto_core::LOCAL_CONTROL_SOCKET_TIMEOUT);
    assert!(
        COLLECTOR_IO_STOP_TIMEOUT + Duration::from_secs(60)
            <= ottto_core::LOCAL_CONTROL_REFRESH_TIMEOUT
    );
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn cloud_cli_timeout_stops_group_after_leader_exit() {
    let fixture = CloudCliFixture::new("hold-exit", &[], 0);
    let result =
        CodexCloudCliRunner.list_page_bounded(None, PAGE_LIMIT, Duration::from_millis(300));
    assert!(result.unwrap_err().to_string().contains("timed out"));
    fixture.wait_gone("direct");
    fixture.wait_stopped("descendant");
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn cloud_cli_completion_stops_redirected_descendants() {
    for output in [b"{}".as_slice(), &[0xff]] {
        let fixture = CloudCliFixture::new("redirect-output", output, 0);
        let result =
            CodexCloudCliRunner.list_page_bounded(None, PAGE_LIMIT, Duration::from_secs(2));
        fixture.wait_gone("direct");
        fixture.wait_stopped("descendant");
        assert_eq!(result.is_ok(), std::str::from_utf8(output).is_ok());
    }
}

fn store(name: &str) -> (PathBuf, CloudSessionCheckpointStore) {
    let root = temp_dir(name);
    let checkpoints = CloudSessionCheckpointStore::new(&root);
    (root, checkpoints)
}

fn runtime_identity_stores(
    root: &Path,
    api_base_url: &str,
) -> (FileAccountStore, FileDeviceStore, FileConnectionStore) {
    let accounts = FileAccountStore::new(root.join("account.json"));
    accounts
        .save(&ottto_protocol::LocalAccountBinding {
            state: LocalAccountState::Connected,
            user: Some(ottto_protocol::LocalAccountUser {
                id: USER_ID.to_string(),
                email: "runtime@example.com".to_string(),
                display_name: None,
            }),
            organization: Some(ottto_protocol::LocalAccountOrganization {
                id: ORG_ID.to_string(),
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
            device_id: DEVICE_ID.to_string(),
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

/// Sets the kill switch for one test and clears it on drop.
struct KillSwitch;

impl KillSwitch {
    fn on() -> Self {
        // SAFETY: serial tests; no other thread reads the environment here.
        unsafe { std::env::set_var(KILL_SWITCH_ENV, "1") };
        Self
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        // SAFETY: as above.
        unsafe { std::env::remove_var(KILL_SWITCH_ENV) };
    }
}

// ---------------------------------------------------------------------------
// Provider and server fakes.

/// One provider task as the official `codex cloud list --json` prints it,
/// with fields the collector must never upload.
fn task(id: &str, status: &str) -> Value {
    json!({
        "id": id,
        "url": format!("https://chatgpt.com/codex/tasks/{id}"),
        "title": "private title",
        "status": status,
        "created_at": "2026-07-20T11:00:00Z",
        "updated_at": "2026-07-20T11:30:00Z",
        "environment_id": "provider-environment-private",
        "environment_label": "Private environment",
        "summary": "private summary",
        "is_review": false,
        "attempt_total": 2
    })
}

fn page_of(tasks: Vec<Value>, cursor: Option<&str>) -> String {
    json!({"tasks": tasks, "cursor": cursor}).to_string()
}

fn page(id: &str, cursor: Option<&str>) -> String {
    page_of(vec![task(id, "applied")], cursor)
}

/// `count` pages of `per_page` tasks each, linked by `c<n>` cursors.
fn chain(count: usize, per_page: usize, status: &str) -> Vec<(Option<String>, String)> {
    (0..count)
        .map(|index| {
            let tasks = (0..per_page)
                .map(|item| task(&format!("task-{index:04}-{item:02}"), status))
                .collect();
            let next = (index + 1 < count).then(|| format!("c{}", index + 1));
            (
                (index > 0).then(|| format!("c{index}")),
                page_of(tasks, next.as_deref()),
            )
        })
        .collect()
}

/// A fake `codex cloud list`: one fixture page per cursor; records each call.
#[derive(Default)]
struct Cli {
    pages: RefCell<HashMap<Option<String>, String>>,
    calls: RefCell<Vec<Option<String>>>,
}

impl Cli {
    fn new(pages: Vec<(Option<String>, String)>) -> Self {
        Self {
            pages: RefCell::new(pages.into_iter().collect()),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn head(head: String) -> Self {
        Self::new(vec![(None, head)])
    }

    fn set(&self, cursor: Option<&str>, page: String) {
        self.pages
            .borrow_mut()
            .insert(cursor.map(str::to_string), page);
    }

    fn calls(&self) -> usize {
        self.calls.borrow().len()
    }
}

impl CloudSessionRunner for Cli {
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String> {
        assert_eq!(limit, PAGE_LIMIT);
        self.calls.borrow_mut().push(cursor.map(str::to_string));
        self.pages
            .borrow()
            .get(&cursor.map(str::to_string))
            .cloned()
            .ok_or_else(|| anyhow!("no fixture page for this cursor"))
    }
}

const OFF: CloudUploadPolicyV2 = CloudUploadPolicyV2 {
    session_titles_enabled: false,
    workspace_labels_enabled: false,
};

/// The Codex fields of an activity hint. `None` omits a field, as an older
/// server does. `stray_key` sends the retired task-key field, which this
/// build ignores.
#[derive(Debug, Clone)]
struct Hint {
    enabled: Option<bool>,
    stray_key: Option<String>,
    contract: Option<String>,
    policy: CloudUploadPolicyV2,
}

impl Hint {
    fn on() -> Self {
        Self {
            enabled: Some(true),
            stray_key: None,
            contract: Some(CHANGES_SCHEMA_VERSION.to_string()),
            policy: OFF,
        }
    }

    fn decoded(&self) -> ActivityHintResponse {
        let mut value = json!({
            "source": "codex",
            "server_time": "2026-07-21T10:00:00Z",
            "last_data_at": null,
            "record_count_15m": 0,
            "record_count_24h": 0,
            "local_usage_reconciliation_enabled": true,
            "backfill_window_days": 183,
            "session_titles_enabled": self.policy.session_titles_enabled,
            "workspace_labels_enabled": self.policy.workspace_labels_enabled,
            "recommended_scan_after": "2026-07-21T10:05:00Z"
        });
        if let Some(enabled) = self.enabled {
            value["codex_cloud_tasks_enabled"] = json!(enabled);
        }
        if let Some(key) = &self.stray_key {
            value["codex_cloud_task_key"] = json!(key);
        }
        if let Some(contract) = &self.contract {
            value["codex_cloud_tasks_contract"] = json!(contract);
        }
        crate::snapshot_client::decode_activity_hint(value).unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HintFault {
    /// An older server: the route answers 404.
    Missing,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckFault {
    DropOne,
    NoEtag,
    Unsolicited,
    /// Echo the first id in decomposed Unicode (`e` + U+0301 for `é`).
    Decomposed,
}

/// A whole-request refusal as the relay maps it: 410 reads like a missing
/// route, 409 like listing off.
fn refusal(status: u16) -> anyhow::Error {
    if status == 410 {
        anyhow::Error::new(crate::snapshot_client::CloudSessionRouteUnsupported { status })
    } else {
        anyhow::Error::new(crate::snapshot_client::CloudTaskRefused { status })
    }
}

/// A fake server holding one head etag per task for one user. It answers
/// `noop` for the same content, `accepted` when the predecessor etag matches,
/// and `conflict` otherwise: like the live server with a null head etag,
/// unless `conflict_reports_head` is set.
/// Like the real server it refuses a body whose policy stamp differs from
/// the policy its hint currently reports.
struct Server {
    hint: RefCell<Hint>,
    hint_fault: Cell<Option<HintFault>>,
    hint_calls: Cell<usize>,
    refuse: Cell<Option<u16>>,
    requests: RefCell<Vec<CloudSessionChangesV2>>,
    acks: RefCell<Vec<CloudSessionChangesAckV2>>,
    heads: RefCell<HashMap<String, String>>,
    reject: RefCell<Vec<String>>,
    conflict_reports_head: Cell<bool>,
    lose_acks: Cell<usize>,
    fault: Cell<Option<AckFault>>,
}

impl Server {
    fn new() -> Self {
        Self {
            hint: RefCell::new(Hint::on()),
            hint_fault: Cell::new(None),
            hint_calls: Cell::new(0),
            refuse: Cell::new(None),
            requests: RefCell::new(Vec::new()),
            acks: RefCell::new(Vec::new()),
            heads: RefCell::new(HashMap::new()),
            reject: RefCell::new(Vec::new()),
            conflict_reports_head: Cell::new(false),
            lose_acks: Cell::new(0),
            fault: Cell::new(None),
        }
    }

    fn set_hint(&self, change: impl FnOnce(&mut Hint)) {
        change(&mut self.hint.borrow_mut());
    }

    fn offered(&self) -> usize {
        self.requests
            .borrow()
            .iter()
            .map(|request| request.observations.len())
            .sum()
    }

    fn outcomes(&self) -> Vec<CloudSessionChangeOutcome> {
        self.acks
            .borrow()
            .iter()
            .flat_map(|ack| ack.entities.iter().map(|entity| entity.outcome))
            .collect()
    }
}

fn server_etag(change: &CloudSessionChangeV2) -> String {
    let mut content = change.clone();
    content.expected_head_etag = None;
    hex(Sha256::digest(serde_json::to_vec(&content).unwrap()).as_slice())
}

impl CloudSessionTransport for Server {
    fn read_hint(&self, _timeout: Duration) -> Result<ActivityHintResponse> {
        self.hint_calls.set(self.hint_calls.get() + 1);
        match self.hint_fault.get() {
            Some(HintFault::Missing) => Err(anyhow::Error::new(
                crate::snapshot_client::CloudSessionRouteUnsupported { status: 404 },
            )),
            Some(HintFault::Offline) => Err(anyhow!("offline")),
            None => Ok(self.hint.borrow().decoded()),
        }
    }

    fn send_changes(
        &self,
        request: &CloudSessionChangesV2,
        _timeout: Duration,
    ) -> Result<CloudSessionChangesAckV2> {
        request.validate().unwrap();
        self.requests.borrow_mut().push(request.clone());
        if let Some(status) = self.refuse.get() {
            return Err(refusal(status));
        }
        if request.upload_policy != self.hint.borrow().policy {
            return Err(refusal(409));
        }
        let mut heads = self.heads.borrow_mut();
        let mut entities = request
            .observations
            .iter()
            .map(|change| {
                let etag = server_etag(change);
                let current = heads.get(&change.source_session_id).cloned();
                let (outcome, head_etag) =
                    if self.reject.borrow().contains(&change.source_session_id) {
                        (CloudSessionChangeOutcome::Rejected, None)
                    } else if current.as_deref() == Some(etag.as_str()) {
                        (CloudSessionChangeOutcome::Noop, Some(etag))
                    } else if change.expected_head_etag == current {
                        heads.insert(change.source_session_id.clone(), etag.clone());
                        (CloudSessionChangeOutcome::Accepted, Some(etag))
                    } else if self.conflict_reports_head.get() {
                        (CloudSessionChangeOutcome::Conflict, current)
                    } else {
                        (CloudSessionChangeOutcome::Conflict, None)
                    };
                CloudSessionChangeAckV2 {
                    source_session_id: change.source_session_id.clone(),
                    outcome,
                    head_etag,
                    accepted_seq: None,
                    reason: None,
                }
            })
            .collect::<Vec<_>>();
        if self.lose_acks.get() > 0 {
            self.lose_acks.set(self.lose_acks.get() - 1);
            return Err(anyhow!("response lost after the server committed"));
        }
        match self.fault.take() {
            Some(AckFault::DropOne) => {
                entities.pop();
            }
            Some(AckFault::NoEtag) => entities[0].head_etag = None,
            Some(AckFault::Unsolicited) => {
                entities[0].source_session_id = "unsolicited-task".to_string()
            }
            Some(AckFault::Decomposed) => {
                entities[0].source_session_id =
                    entities[0].source_session_id.replace('é', "e\u{301}")
            }
            None => {}
        }
        let ack = CloudSessionChangesAckV2 {
            schema_version: wire::CHANGES_ACK_SCHEMA_VERSION.to_string(),
            entities,
        };
        self.acks.borrow_mut().push(ack.clone());
        Ok(ack)
    }
}

fn inputs<'a>(
    checkpoints: &'a CloudSessionCheckpointStore,
    cli: &'a dyn CloudSessionRunner,
    server: &'a dyn CloudSessionTransport,
) -> SliceInputs<'a> {
    SliceInputs {
        checkpoints,
        runner: cli,
        transport: server,
        destination: DEFAULT_API_BASE_URL,
        organization_id: ORG_ID,
        user_id: USER_ID,
    }
}

fn midnight() -> OffsetDateTime {
    OffsetDateTime::parse("2026-07-21T00:00:00Z", &Rfc3339).unwrap()
}

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(60 * 60);

/// Drive the collector the way the supervisor does, on a fake clock from
/// `wall0`, for `horizon`: run a slice, then sleep until `next_wake`.
fn drive(
    collector: &mut CloudCollector,
    inputs: &SliceInputs<'_>,
    t0: Instant,
    wall0: OffsetDateTime,
    horizon: Duration,
) -> Vec<(Duration, CloudSessionCycleOutcome)> {
    let mut offset = Duration::ZERO;
    let mut outcomes = Vec::new();
    while offset < horizon {
        let now = t0 + offset;
        let wall = wall0 + offset;
        outcomes.push((offset, collector.run_slice(inputs, now, wall)));
        let Some(next) = collector.next_wake(now, wall) else {
            break;
        };
        offset = next
            .saturating_duration_since(t0)
            .max(offset + Duration::from_secs(1));
    }
    outcomes
}

fn slice(
    collector: &mut CloudCollector,
    inputs: &SliceInputs<'_>,
    t0: Instant,
    offset: Duration,
) -> CloudSessionCycleOutcome {
    collector.run_slice(inputs, t0 + offset, midnight() + offset)
}

// ---------------------------------------------------------------------------
// Schedule: provider and backend calls per day. [behaviour]

/// [behaviour] 24 hours from 00:00 UTC on a fake clock. Listing off, an
/// older server's hint or a missing route make no provider call; an
/// unchanged account's head slows from five minutes towards a day (nine
/// heads, one upload); a deep task adds one crawl page.
#[test]
#[serial_test::serial]
fn a_day_of_provider_calls_follows_the_schedule() {
    let day = 24 * HOUR;
    let run = |name: &str, prepare: &dyn Fn(&Server), pages: Vec<(Option<String>, String)>| {
        let (_root, checkpoints) = store(name);
        let server = Server::new();
        prepare(&server);
        let cli = Cli::new(pages);
        let mut collector = CloudCollector::default();
        drive(
            &mut collector,
            &inputs(&checkpoints, &cli, &server),
            Instant::now(),
            midnight(),
            day,
        );
        (
            cli.calls(),
            server.hint_calls.get(),
            server.requests.borrow().len(),
        )
    };
    let one = || vec![(None, page("idle-task", None))];

    assert_eq!(
        run(
            "day-off",
            &|server| server.set_hint(|hint| {
                hint.enabled = Some(false);
            }),
            one()
        ),
        (0, 48, 0)
    );
    assert_eq!(
        run(
            "day-older-hint",
            &|server| server.set_hint(|hint| {
                hint.enabled = None;
                hint.contract = None;
            }),
            one()
        ),
        (0, 48, 0)
    );
    assert_eq!(
        run(
            "day-route-missing",
            &|server| server.hint_fault.set(Some(HintFault::Missing)),
            one()
        ),
        (0, 4, 0)
    );
    assert_eq!(run("day-unchanged", &|_| {}, one()), (9, 9, 1));
    assert_eq!(
        run(
            "day-deep",
            &|_| {},
            vec![
                (None, page("head-task", Some("c1"))),
                (
                    Some("c1".to_string()),
                    page_of(vec![task("deep-task", "pending")], None)
                ),
            ]
        ),
        (10, 9, 2)
    );
}

/// [behaviour] The head interval doubles after each successful head listing
/// that the server accepted nothing new from, up to a day. Only an accepted
/// task resets it to five minutes: a second Mac whose upload the server
/// answers `noop` keeps slowing down.
#[test]
#[serial_test::serial]
fn head_interval_doubles_to_a_day_and_resets_only_on_accepted() {
    assert_eq!(head_interval(0), 5 * MINUTE);
    assert_eq!(head_interval(1), 10 * MINUTE);
    assert_eq!(head_interval(8), 1280 * MINUTE);
    for unchanged in [9, 31, 32, 40, u32::MAX] {
        assert_eq!(head_interval(unchanged), 24 * HOUR, "{unchanged}");
    }

    let cli = Cli::head(page("steady", None));
    let server = Server::new();
    let (_root, mac_a) = store("interval-mac-a");
    let a_inputs = inputs(&mac_a, &cli, &server);
    let t0 = Instant::now();
    let mut a = CloudCollector::default();
    assert_eq!(
        slice(&mut a, &a_inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(a.next_wake(t0, midnight()), Some(t0 + 5 * MINUTE));
    let mut at = 5 * MINUTE;
    let mut wait = 10 * MINUTE;
    for _ in 0..8 {
        assert_eq!(
            slice(&mut a, &a_inputs, t0, at),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(a.next_wake(t0 + at, midnight() + at), Some(t0 + at + wait));
        at += wait;
        wait *= 2;
    }
    assert_eq!(server.requests.borrow().len(), 1);

    // A second Mac of the same user lists the same task: one head at the
    // server, a noop, and no reset.
    let (_root, mac_b) = store("interval-mac-b");
    let b_inputs = inputs(&mac_b, &cli, &server);
    let mut b = CloudCollector::default();
    assert_eq!(
        slice(&mut b, &b_inputs, t0, HOUR),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(
        server.outcomes().last(),
        Some(&CloudSessionChangeOutcome::Noop)
    );
    assert_eq!(server.heads.borrow().len(), 1);
    assert_eq!(
        b.next_wake(t0 + HOUR, midnight() + HOUR),
        Some(t0 + HOUR + 10 * MINUTE)
    );

    // A changed task is accepted and the head is fast again.
    cli.set(None, page_of(vec![task("steady", "error")], None));
    assert_eq!(
        slice(&mut a, &a_inputs, t0, at),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(
        server.outcomes().last(),
        Some(&CloudSessionChangeOutcome::Accepted)
    );
    assert_eq!(
        a.next_wake(t0 + at, midnight() + at),
        Some(t0 + at + 5 * MINUTE)
    );
}

/// [behaviour] A deep crawl is paced, not truncated: ten pages per slice,
/// continuing five minutes later where it stopped (with the due head).
#[test]
#[serial_test::serial]
fn daily_crawl_takes_ten_pages_then_continues_five_minutes_later() {
    let (_root, checkpoints) = store("crawl-paced");
    let cli = Cli::new(chain(18, 1, "applied"));
    let server = Server::new();
    let inputs = inputs(&checkpoints, &cli, &server);
    let mut collector = CloudCollector::default();
    let t0 = Instant::now();

    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(cli.calls(), 10);
    assert_eq!(collector.next_wake(t0, midnight()), Some(t0 + 5 * MINUTE));
    assert_eq!(
        slice(&mut collector, &inputs, t0, 5 * MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );
    let expected = std::iter::once(None)
        .chain((1..10).map(|index| Some(format!("c{index}"))))
        .chain(std::iter::once(None))
        .chain((10..18).map(|index| Some(format!("c{index}"))))
        .collect::<Vec<_>>();
    assert_eq!(*cli.calls.borrow(), expected);
    assert_eq!(server.offered(), 18);
    assert_eq!(server.hint_calls.get(), 2);
    assert_eq!(collector.schedule.crawl_completed, Some(midnight().date()));
    // The crawl is done for the day; only the head remains.
    assert_eq!(
        collector.next_wake(t0 + 5 * MINUTE, midnight() + 5 * MINUTE),
        Some(t0 + 10 * MINUTE)
    );
}

/// [regress] More than 100 pages and 2,000 tasks: the crawl reaches the
/// tail and every task is offered exactly once.
#[test]
#[serial_test::serial]
fn crawl_beyond_one_hundred_pages_and_two_thousand_tasks_reaches_the_tail() {
    let (_root, checkpoints) = store("crawl-deep");
    let cli = Cli::new(chain(120, PAGE_LIMIT, "applied"));
    let server = Server::new();
    let mut collector = CloudCollector::default();
    let outcomes = drive(
        &mut collector,
        &inputs(&checkpoints, &cli, &server),
        Instant::now(),
        midnight(),
        2 * HOUR,
    );
    let crawled = cli
        .calls
        .borrow()
        .iter()
        .filter(|cursor| cursor.is_some())
        .count();
    assert_eq!(crawled, 119, "slice outcomes: {outcomes:?}");
    let keys = server
        .requests
        .borrow()
        .iter()
        .flat_map(|request| {
            request
                .observations
                .iter()
                .map(|change| change.source_session_id.clone())
        })
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(keys.len(), 120 * PAGE_LIMIT);
    assert_eq!(server.offered(), 120 * PAGE_LIMIT);
    assert_eq!(collector.schedule.crawl_completed, Some(midnight().date()));
}

/// [behaviour] A crawl that spans UTC midnight continues from its cursor; a
/// restart starts over from the head and the cache suppresses every task the
/// first run already settled.
#[test]
#[serial_test::serial]
fn crawl_survives_midnight_and_a_restart_reoffers_nothing_settled() {
    let (_root, checkpoints) = store("crawl-midnight");
    let cli = Cli::new(chain(18, 1, "applied"));
    let server = Server::new();
    let inputs = inputs(&checkpoints, &cli, &server);
    let late = OffsetDateTime::parse("2026-07-21T23:55:00Z", &Rfc3339).unwrap();
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    collector.run_slice(&inputs, t0, late);
    assert_eq!(cli.calls(), 10);
    collector.run_slice(&inputs, t0 + 5 * MINUTE, late + 5 * MINUTE);
    assert_eq!(cli.calls(), 19);
    assert_eq!(cli.calls.borrow()[11].as_deref(), Some("c10"));
    let next_day = (late + 5 * MINUTE).date();
    assert_eq!(collector.schedule.crawl_completed, Some(next_day));

    // Restart: the persisted completion day holds; only a head runs.
    let mut restarted = CloudCollector::default();
    assert_eq!(
        restarted.run_slice(&inputs, t0 + 10 * MINUTE, late + 10 * MINUTE),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(cli.calls(), 20);
    assert_eq!(server.offered(), 18);

    // A restart mid-crawl starts a new crawl from the head; settled pages
    // are listed again but nothing settled is offered again.
    let (_root, checkpoints) = store("crawl-restart");
    let cli = Cli::new(chain(18, 1, "applied"));
    let server = Server::new();
    let inputs = SliceInputs {
        checkpoints: &checkpoints,
        runner: &cli,
        transport: &server,
        ..inputs
    };
    let mut collector = CloudCollector::default();
    slice(&mut collector, &inputs, t0, Duration::ZERO);
    let mut restarted = CloudCollector::default();
    drive(
        &mut restarted,
        &inputs,
        t0 + MINUTE,
        midnight() + MINUTE,
        HOUR,
    );
    assert_eq!(server.offered(), 18);
    assert!(server
        .outcomes()
        .iter()
        .all(|outcome| *outcome == CloudSessionChangeOutcome::Accepted));
    assert_eq!(restarted.schedule.crawl_completed, Some(midnight().date()));
}

/// [regress] A cursor chain that loops ends the day's traversal without
/// claiming completion and without repeating it.
#[test]
#[serial_test::serial]
fn cycling_cursor_chain_ends_the_day_without_completion() {
    let (_root, checkpoints) = store("crawl-cycle");
    let cli = Cli::new(vec![
        (None, page("cycle-0", Some("c1"))),
        (Some("c1".to_string()), page("cycle-1", Some("c2"))),
        (Some("c2".to_string()), page("cycle-2", Some("c3"))),
        (Some("c3".to_string()), page("cycle-3", Some("c1"))),
    ]);
    let server = Server::new();
    let mut collector = CloudCollector::default();
    drive(
        &mut collector,
        &inputs(&checkpoints, &cli, &server),
        Instant::now(),
        midnight(),
        24 * HOUR,
    );
    // One bounded traversal; every later call is a head.
    let crawled = cli
        .calls
        .borrow()
        .iter()
        .filter(|cursor| cursor.is_some())
        .count();
    assert!(crawled < MAX_SLICE_PAGES * 2, "{crawled}");
    assert_eq!(collector.schedule.crawl_completed, None);
    assert_eq!(collector.schedule.crawl_ended, Some(midnight().date()));
    assert_eq!(server.offered(), 4);
}

/// [behaviour] Brent's detector finds loops of any length in constant space.
#[test]
fn cursor_cycle_detector_finds_every_loop_length() {
    for length in 1..40_u8 {
        let mut cycle = schedule::CursorCycle::default();
        let mut found = None;
        for step in 0..1_000_u32 {
            let cursor = [((step % u32::from(length)) as u8); 32];
            if cycle.repeats(cursor) {
                found = Some(step);
                break;
            }
        }
        let step = found.unwrap_or_else(|| panic!("loop of {length} not found"));
        assert!(step <= 4 * u32::from(length) + 2, "{length}: {step}");
    }
    let mut cycle = schedule::CursorCycle::default();
    assert!((0..500_u32).all(|step| {
        let mut cursor = [0_u8; 32];
        cursor[..4].copy_from_slice(&step.to_be_bytes());
        !cycle.repeats(cursor)
    }));
}
// ---------------------------------------------------------------------------
// Listing on/off and server refusals. [behaviour]

/// One way to change the server's hint.
type HintChange<'a> = &'a dyn Fn(&mut Hint);

/// [behaviour] Only a hint that turns listing on and names exactly this
/// contract lets a slice call the provider; no key is needed, and a stray
/// retired key field changes nothing. Anything else (a v2 server included)
/// is off: no provider call, no upload, a hint recheck in 30 minutes.
/// Turning listing on later starts collection without a restart.
#[test]
#[serial_test::serial]
fn listing_runs_only_on_an_exact_hint() {
    let cases: [(&str, HintChange); 6] = [
        ("off", &|hint: &mut Hint| hint.enabled = Some(false)),
        ("older-server", &|hint: &mut Hint| {
            hint.enabled = None;
            hint.contract = None;
        }),
        ("no-contract", &|hint: &mut Hint| hint.contract = None),
        ("old-contract", &|hint: &mut Hint| {
            hint.contract = Some("cloud_session_changes.v1".to_string())
        }),
        ("v2-server", &|hint: &mut Hint| {
            hint.stray_key = Some("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".to_string());
            hint.contract = Some("cloud_session_changes.v2".to_string())
        }),
        ("off-with-stray-key", &|hint: &mut Hint| {
            hint.enabled = Some(false);
            hint.stray_key = Some("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".to_string());
        }),
    ];
    for (name, change) in cases {
        let (_root, checkpoints) = store(&format!("hint-{name}"));
        let cli = Cli::head(page("never-listed", None));
        let server = Server::new();
        server.set_hint(change);
        let inputs = inputs(&checkpoints, &cli, &server);
        let t0 = Instant::now();
        let mut collector = CloudCollector::default();
        assert_eq!(
            slice(&mut collector, &inputs, t0, Duration::ZERO),
            CloudSessionCycleOutcome::Unsupported,
            "{name}"
        );
        assert_eq!(cli.calls(), 0, "{name}");
        assert!(server.requests.borrow().is_empty(), "{name}");
        assert_eq!(
            collector.next_wake(t0, midnight()),
            Some(t0 + 30 * MINUTE),
            "{name}"
        );
        assert_eq!(collector.reported, Some("listing_off"), "{name}");

        *server.hint.borrow_mut() = Hint::on();
        assert_eq!(
            slice(&mut collector, &inputs, t0, 30 * MINUTE),
            CloudSessionCycleOutcome::Uploaded,
            "{name}"
        );
        assert_eq!(cli.calls(), 1, "{name}");
    }
    let mut stray = Hint::on();
    stray.stray_key = Some("short".to_string());
    assert_eq!(codex_cloud_listing(&stray.decoded()), Some(OFF));
    assert_eq!(codex_cloud_listing(&Hint::on().decoded()), Some(OFF));
}

/// [behaviour] The kill switch stops everything before the hint read; an
/// unconfigured transport does too.
#[test]
#[serial_test::serial]
fn kill_switch_and_unconfigured_transport_make_no_call() {
    struct Unconfigured(Server);
    impl CloudSessionTransport for Unconfigured {
        fn is_configured(&self) -> bool {
            false
        }
        fn read_hint(&self, timeout: Duration) -> Result<ActivityHintResponse> {
            self.0.read_hint(timeout)
        }
        fn send_changes(
            &self,
            request: &CloudSessionChangesV2,
            timeout: Duration,
        ) -> Result<CloudSessionChangesAckV2> {
            self.0.send_changes(request, timeout)
        }
    }
    let (_root, checkpoints) = store("kill-switch");
    let cli = Cli::head(page("never-listed", None));
    let server = Server::new();
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    {
        let _kill = KillSwitch::on();
        assert_eq!(
            slice(
                &mut collector,
                &inputs(&checkpoints, &cli, &server),
                t0,
                Duration::ZERO
            ),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(collector.next_wake(t0, midnight()), None);
    }
    assert_eq!((cli.calls(), server.hint_calls.get()), (0, 0));

    let unconfigured = Unconfigured(Server::new());
    assert_eq!(
        slice(
            &mut collector,
            &inputs(&checkpoints, &cli, &unconfigured),
            t0,
            Duration::ZERO
        ),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!((cli.calls(), unconfigured.0.hint_calls.get()), (0, 0));
}

/// [behaviour] An older server without the hint route: the collector is
/// idle and quiet and reads the hint again in six hours.
#[test]
#[serial_test::serial]
fn missing_hint_route_rechecks_in_six_hours() {
    let (_root, checkpoints) = store("route-missing");
    let cli = Cli::head(page("never-listed", None));
    let server = Server::new();
    server.hint_fault.set(Some(HintFault::Missing));
    let inputs = inputs(&checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Unsupported
    );
    assert_eq!(cli.calls(), 0);
    assert_eq!(collector.next_wake(t0, midnight()), Some(t0 + 6 * HOUR));
    server.hint_fault.set(None);
    assert_eq!(
        slice(&mut collector, &inputs, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Uploaded
    );
}

/// [behaviour] A whole-request refusal settles nothing and rechecks: any 409
/// (listing turned off since the hint, or a policy mismatch) in 30 minutes,
/// a 410 (contract retired) in six hours like a missing route. The recheck
/// reads the hint again and offers the task again under its policy. A long
/// head interval cannot postpone the 30-minute recheck.
#[test]
#[serial_test::serial]
fn request_refusals_recheck_and_settle_nothing() {
    /// Turns titles on at the server between the hint and the upload.
    struct FlipOnList<'a> {
        cli: Cli,
        server: &'a Server,
        flip: Cell<bool>,
    }
    impl CloudSessionRunner for FlipOnList<'_> {
        fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String> {
            if self.flip.replace(false) {
                self.server
                    .set_hint(|hint| hint.policy.session_titles_enabled = true);
            }
            self.cli.list_page(cursor, limit)
        }
    }
    let t0 = Instant::now();
    for (name, refuse, flip, recheck, state) in [
        (
            "listing-off",
            Some(409),
            false,
            30 * MINUTE,
            "server_refused",
        ),
        ("policy-mismatch", None, true, 30 * MINUTE, "server_refused"),
        ("retired", Some(410), false, 6 * HOUR, "server_unsupported"),
    ] {
        let (_root, checkpoints) = store(&format!("refused-{name}"));
        let server = Server::new();
        server.refuse.set(refuse);
        let runner = FlipOnList {
            cli: Cli::head(page("refused", None)),
            server: &server,
            flip: Cell::new(flip),
        };
        let inputs = inputs(&checkpoints, &runner, &server);
        let mut collector = CloudCollector::default();
        assert_eq!(
            slice(&mut collector, &inputs, t0, Duration::ZERO),
            CloudSessionCycleOutcome::Unsupported,
            "{name}"
        );
        assert_eq!(
            collector.next_wake(t0, midnight()),
            Some(t0 + recheck),
            "{name}"
        );
        assert_eq!(collector.reported, Some(state), "{name}");
        assert!(
            checkpoints
                .read_acks(
                    &cache_scope(&inputs),
                    &["refused"],
                    midnight().unix_timestamp()
                )
                .unwrap()
                .is_empty(),
            "{name}"
        );
        server.refuse.set(None);
        assert_eq!(
            slice(&mut collector, &inputs, t0, recheck),
            CloudSessionCycleOutcome::Uploaded,
            "{name}"
        );
        assert_eq!(server.hint_calls.get(), 2, "{name}");
        let requests = server.requests.borrow();
        assert_eq!(requests.len(), 2, "{name}");
        let (first, second) = (&requests[0].observations[0], &requests[1].observations[0]);
        assert_eq!(first.source_session_id, second.source_session_id, "{name}");
        assert_eq!(second.expected_head_etag, None, "{name}");
        assert_eq!(requests[1].upload_policy.session_titles_enabled, flip);
        assert_eq!(second.title.is_some(), flip, "{name}");
        assert_eq!(server.outcomes(), [CloudSessionChangeOutcome::Accepted]);
    }

    // After five unchanged heads (next head 160 minutes away) and a
    // completed crawl, a refusal still reads the hint again 30 minutes later.
    let (_root, checkpoints) = store("refused-mature");
    let cli = Cli::head(page("mature", None));
    let server = Server::new();
    let inputs = inputs(&checkpoints, &cli, &server);
    let mut collector = CloudCollector::default();
    for at in [0, 5, 15, 35, 75, 155] {
        slice(&mut collector, &inputs, t0, at * MINUTE);
    }
    assert_eq!(
        collector.next_wake(t0 + 155 * MINUTE, midnight() + 155 * MINUTE),
        Some(t0 + 315 * MINUTE)
    );
    cli.set(None, page_of(vec![task("mature", "error")], None));
    server.refuse.set(Some(409));
    assert_eq!(
        slice(&mut collector, &inputs, t0, 315 * MINUTE),
        CloudSessionCycleOutcome::Unsupported
    );
    assert_eq!(
        collector.next_wake(t0 + 315 * MINUTE, midnight() + 315 * MINUTE),
        Some(t0 + 345 * MINUTE)
    );
    server.refuse.set(None);
    let hint_calls = server.hint_calls.get();
    assert_eq!(
        slice(&mut collector, &inputs, t0, 345 * MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(server.hint_calls.get(), hint_calls + 1);
    assert_eq!(
        server.outcomes().last(),
        Some(&CloudSessionChangeOutcome::Accepted)
    );
}

/// [behaviour] Turning titles or workspace labels on or off offers every
/// listed task again under the new policy, with its last head as the
/// predecessor; the unchanged next head offers nothing.
#[test]
#[serial_test::serial]
fn policy_flip_reoffers_under_the_new_policy() {
    let (_root, checkpoints) = store("policy-flip");
    let cli = Cli::head(page("flip", None));
    let server = Server::new();
    let inputs = inputs(&checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    slice(&mut collector, &inputs, t0, Duration::ZERO);
    let first = server.requests.borrow()[0].observations[0].clone();
    server.set_hint(|hint| {
        hint.policy = CloudUploadPolicyV2 {
            session_titles_enabled: true,
            workspace_labels_enabled: true,
        }
    });
    assert_eq!(
        slice(&mut collector, &inputs, t0, 5 * MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );
    {
        let requests = server.requests.borrow();
        assert_eq!(requests.len(), 2);
        let second = &requests[1].observations[0];
        assert_eq!(second.source_session_id, first.source_session_id);
        assert_eq!(second.title.as_deref(), Some("private title"));
        assert_eq!(
            second.environment_label.as_deref(),
            Some("Private environment")
        );
        assert_eq!(
            second.expected_head_etag.as_deref(),
            Some(server_etag(&first).as_str())
        );
    }
    assert_eq!(
        server.outcomes(),
        [
            CloudSessionChangeOutcome::Accepted,
            CloudSessionChangeOutcome::Accepted
        ]
    );
    assert_eq!(
        slice(&mut collector, &inputs, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(server.requests.borrow().len(), 2);
}

// ---------------------------------------------------------------------------
// ACK cache. [behaviour]

/// [behaviour] An unchanged task is never uploaded again, and an unchanged
/// poll never rewrites its entry: the 30-day expiry still counts from the
/// exact ACK, after which the task is offered once and answered noop.
#[test]
#[serial_test::serial]
fn unchanged_tasks_are_not_uploaded_or_rewritten() {
    let (_root, checkpoints) = store("cache-noop");
    let cli = Cli::head(page_of(
        vec![
            task("a", "applied"),
            task("b", "error"),
            task("c", "applied"),
        ],
        None,
    ));
    let server = Server::new();
    let inputs = inputs(&checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    let day = 24 * HOUR;
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Uploaded
    );
    let scope = cache_scope(&inputs);
    assert_eq!(
        checkpoints
            .read_acks(&scope, &["a", "b", "c"], midnight().unix_timestamp())
            .unwrap()
            .len(),
        3
    );
    for offset in [6 * HOUR, 20 * day] {
        assert_eq!(
            slice(&mut collector, &inputs, t0, offset),
            CloudSessionCycleOutcome::Noop
        );
    }
    assert_eq!(server.requests.borrow().len(), 1);
    assert_eq!(
        slice(&mut collector, &inputs, t0, 31 * day),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(server.requests.borrow().len(), 2);
    assert_eq!(server.outcomes()[3..], [CloudSessionChangeOutcome::Noop; 3]);
}

/// [behaviour] One changed task in a page of three is the only one offered,
/// with the head etag of its last exact ACK as the predecessor.
#[test]
#[serial_test::serial]
fn one_changed_sibling_is_the_only_task_offered() {
    let (_root, checkpoints) = store("cache-sibling");
    let cli = Cli::head(page_of(
        vec![
            task("a", "applied"),
            task("b", "running"),
            task("c", "applied"),
        ],
        None,
    ));
    let server = Server::new();
    let inputs = inputs(&checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    slice(&mut collector, &inputs, t0, Duration::ZERO);
    let first = server.requests.borrow()[0].clone();
    assert_eq!(first.observations.len(), 3);
    assert!(first
        .observations
        .iter()
        .all(|change| change.expected_head_etag.is_none()));

    cli.set(
        None,
        page_of(
            vec![
                task("a", "applied"),
                task("b", "applied"),
                task("c", "applied"),
            ],
            None,
        ),
    );
    assert_eq!(
        slice(&mut collector, &inputs, t0, 5 * MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );
    let second = server.requests.borrow()[1].clone();
    assert_eq!(second.observations.len(), 1);
    assert_eq!(second.observations[0].source_session_id, "b");
    assert_eq!(second.observations[0].lifecycle, "completed");
    assert_eq!(
        second.observations[0].expected_head_etag.as_deref(),
        Some(server_etag(&first.observations[1]).as_str())
    );
    assert_eq!(server.outcomes()[3], CloudSessionChangeOutcome::Accepted);
}

/// [behaviour] A lost response is resent and settles as noop; nothing is
/// double-counted and the cache then holds.
#[test]
#[serial_test::serial]
fn lost_ack_is_resent_and_settles_noop() {
    let (_root, checkpoints) = store("cache-lost-ack");
    let cli = Cli::head(page("lost-ack", None));
    let server = Server::new();
    server.lose_acks.set(1);
    let inputs = inputs(&checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Failed
    );
    assert_eq!(collector.reported, Some("transport_unavailable"));
    // The backoff, not the head interval, decides the retry.
    let retry = collector.next_wake(t0, midnight()).unwrap();
    assert!(retry < t0 + HOUR);
    let offset = retry.saturating_duration_since(t0);
    assert_eq!(
        slice(&mut collector, &inputs, t0, offset),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(server.outcomes(), [CloudSessionChangeOutcome::Noop]);
    assert_eq!(
        slice(&mut collector, &inputs, t0, offset + 6 * HOUR),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(server.requests.borrow().len(), 2);
    assert_eq!(server.heads.borrow().len(), 1);
}

/// [regress] An ACK that misses, invents or under-specifies a task settles
/// nothing; the next attempt offers the same tasks again.
#[test]
#[serial_test::serial]
fn partial_or_malformed_ack_settles_nothing() {
    for fault in [AckFault::DropOne, AckFault::NoEtag, AckFault::Unsolicited] {
        let (_root, checkpoints) = store("cache-bad-ack");
        let cli = Cli::head(page_of(
            vec![task("a", "applied"), task("b", "applied")],
            None,
        ));
        let server = Server::new();
        server.fault.set(Some(fault));
        let inputs = inputs(&checkpoints, &cli, &server);
        let t0 = Instant::now();
        let mut collector = CloudCollector::default();
        assert_eq!(
            slice(&mut collector, &inputs, t0, Duration::ZERO),
            CloudSessionCycleOutcome::Failed,
            "{fault:?}"
        );
        let offset = collector
            .next_wake(t0, midnight())
            .unwrap()
            .saturating_duration_since(t0);
        slice(&mut collector, &inputs, t0, offset);
        let requests = server.requests.borrow();
        assert_eq!(requests.len(), 2, "{fault:?}");
        assert_eq!(requests[1].observations.len(), 2, "{fault:?}");
    }
}

/// [regress] A provider task id is the raw official `id`, sent byte for
/// byte; the legacy `task_id` alias is never read, not even as a fallback.
#[test]
#[serial_test::serial]
fn raw_task_id_is_sent_and_task_id_alias_is_not_read() {
    let (_root, checkpoints) = store("raw-task-id");
    let mut both = task("task_e_official id é", "applied");
    both["task_id"] = json!("alias-for-official");
    let mut alias_only = task("unused", "applied");
    alias_only.as_object_mut().unwrap().remove("id");
    alias_only["task_id"] = json!("alias-only");
    let cli = Cli::head(page_of(vec![both, alias_only], None));
    let server = Server::new();
    assert_eq!(
        slice(
            &mut CloudCollector::default(),
            &inputs(&checkpoints, &cli, &server),
            Instant::now(),
            Duration::ZERO,
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    let requests = server.requests.borrow();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .observations
            .iter()
            .map(|change| change.source_session_id.as_str())
            .collect::<Vec<_>>(),
        ["task_e_official id é"]
    );
    let text = serde_json::to_string(&requests[0]).unwrap();
    assert!(!text.contains("alias"));
}

/// [behaviour] A structurally valid page whose rows all carry invalid task
/// ids is skipped row by row, counted, and its official cursor still leads
/// to the next page's valid task.
#[test]
#[serial_test::serial]
fn invalid_only_page_continues_to_a_valid_page() {
    let (_root, checkpoints) = store("invalid-only-page");
    let cli = Cli::new(vec![
        (
            None,
            page_of(
                vec![
                    task("", "applied"),
                    task(" padded", "applied"),
                    task(&"x".repeat(256), "applied"),
                ],
                Some("c1"),
            ),
        ),
        (Some("c1".to_string()), page("valid-after-invalid", None)),
    ]);
    let server = Server::new();
    let inputs = inputs(&checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(cli.calls(), 2);
    assert_eq!(
        server.requests.borrow()[0]
            .observations
            .iter()
            .map(|change| change.source_session_id.as_str())
            .collect::<Vec<_>>(),
        ["valid-after-invalid"]
    );
    assert_eq!(collector.schedule.crawl_completed, Some(midnight().date()));
    assert_eq!(collector.reported, Some("ok"));
    assert_eq!(collector.reported_invalid_ids, Some(3));
    // The head alone still lists the invalid rows; the same count logs no
    // second line and nothing is offered again.
    assert_eq!(
        slice(&mut collector, &inputs, t0, 5 * MINUTE),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(collector.reported_invalid_ids, Some(3));
    assert_eq!(server.requests.borrow().len(), 1);
}

/// [behaviour] The ACK cache keys each task by a local digest of its id: a
/// 255-code-point non-ASCII id settles, the upload-history files never hold
/// its bytes, and after the file is reopened the unchanged task is not
/// offered again while changed facts reuse its head etag.
#[test]
#[serial_test::serial]
fn ack_cache_never_stores_the_raw_id() {
    let id = "é".repeat(255);
    let (root, checkpoints) = store("ack-raw-id");
    let cli = Cli::head(page(&id, None));
    let server = Server::new();
    let t0 = Instant::now();
    {
        let inputs = inputs(&checkpoints, &cli, &server);
        assert_eq!(
            slice(&mut CloudCollector::default(), &inputs, t0, Duration::ZERO),
            CloudSessionCycleOutcome::Uploaded
        );
    }
    assert_eq!(server.outcomes(), [CloudSessionChangeOutcome::Accepted]);
    // Touching another support directory closes this history file.
    let (_other_root, other) = store("ack-raw-id-other");
    other
        .read_acks(&[0; 32], &["other"], midnight().unix_timestamp())
        .unwrap();
    let mut files = 0;
    // Not even a 10-character prefix of the id is stored.
    let prefix = &id.as_bytes()[..20];
    for entry in fs::read_dir(root.join("snapshots")).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        files += 1;
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.windows(prefix.len()).any(|window| window == prefix));
    }
    assert!(files > 0);

    let reopened = CloudSessionCheckpointStore::new(&root);
    let inputs = inputs(&reopened, &cli, &server);
    let scope = cache_scope(&inputs);
    let cached = checkpoints_ack(&reopened, &scope, &id).unwrap();
    let first = server.requests.borrow()[0].observations[0].clone();
    assert_eq!(cached.head_etag, Some(server_etag(&first)));
    let mut restarted = CloudCollector::default();
    assert_eq!(
        slice(&mut restarted, &inputs, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(
        server.requests.borrow().len(),
        1,
        "no POST for the unchanged task"
    );

    cli.set(None, page_of(vec![task(&id, "error")], None));
    assert_eq!(
        slice(&mut restarted, &inputs, t0, 12 * HOUR),
        CloudSessionCycleOutcome::Uploaded
    );
    let requests = server.requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].observations[0].source_session_id, id);
    assert_eq!(
        requests[1].observations[0].expected_head_etag,
        Some(server_etag(&first))
    );
    assert_eq!(
        server.outcomes(),
        [
            CloudSessionChangeOutcome::Accepted,
            CloudSessionChangeOutcome::Accepted
        ]
    );
}

/// [behaviour] A non-ASCII id with inner spaces settles on the server's
/// byte-identical echo; an echo in another Unicode normalization names an
/// unsolicited task and settles nothing.
#[test]
#[serial_test::serial]
fn non_ascii_id_settles_only_on_an_exact_echo() {
    let id = "tâche é 1";
    for decomposed in [false, true] {
        let (_root, checkpoints) = store(&format!("echo-{decomposed}"));
        let cli = Cli::head(page(id, None));
        let server = Server::new();
        if decomposed {
            server.fault.set(Some(AckFault::Decomposed));
        }
        let inputs = inputs(&checkpoints, &cli, &server);
        let mut collector = CloudCollector::default();
        let outcome = slice(&mut collector, &inputs, Instant::now(), Duration::ZERO);
        assert_eq!(
            server.requests.borrow()[0].observations[0].source_session_id,
            id
        );
        let cached = checkpoints_ack(&checkpoints, &cache_scope(&inputs), id);
        if decomposed {
            assert_eq!(outcome, CloudSessionCycleOutcome::Failed);
            assert_eq!(collector.reported, Some("ack_invalid"));
            assert!(cached.is_none());
        } else {
            assert_eq!(outcome, CloudSessionCycleOutcome::Uploaded);
            assert!(cached.unwrap().head_etag.is_some());
        }
    }
}

/// [behaviour] A per-task refusal is remembered for exactly that content,
/// with no credit, so it is not offered again until the task changes.
#[test]
#[serial_test::serial]
fn rejected_task_is_not_reoffered_until_it_changes() {
    let (_root, checkpoints) = store("cache-rejected");
    let cli = Cli::head(page("refused", None));
    let server = Server::new();
    let inputs = inputs(&checkpoints, &cli, &server);
    let t0 = Instant::now();
    server.reject.borrow_mut().push("refused".to_string());
    let mut collector = CloudCollector::default();
    slice(&mut collector, &inputs, t0, Duration::ZERO);
    slice(&mut collector, &inputs, t0, 6 * HOUR);
    assert_eq!(server.requests.borrow().len(), 1);
    server.reject.borrow_mut().clear();
    cli.set(None, page_of(vec![task("refused", "error")], None));
    slice(&mut collector, &inputs, t0, 12 * HOUR);
    let requests = server.requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].observations[0].expected_head_etag, None);
}

/// [behaviour] Two Macs list one task in different states. A conflict that
/// names the server head re-lists the page once and retries with that head
/// as the predecessor; the next head offers nothing.
#[test]
#[serial_test::serial]
fn conflict_with_a_head_relists_once_and_retries_with_it() {
    let server = Server::new();
    server.conflict_reports_head.set(true);
    let (_root, mac_a) = store("conflict-mac-a");
    let cli_a = Cli::head(page_of(vec![task("conflict", "running")], None));
    let t0 = Instant::now();
    slice(
        &mut CloudCollector::default(),
        &inputs(&mac_a, &cli_a, &server),
        t0,
        Duration::ZERO,
    );
    let head = server.heads.borrow().values().next().unwrap().clone();

    let (_root, mac_b) = store("conflict-mac-b");
    let cli_b = Cli::head(page_of(vec![task("conflict", "applied")], None));
    let b_inputs = inputs(&mac_b, &cli_b, &server);
    let mut b = CloudCollector::default();
    assert_eq!(
        slice(&mut b, &b_inputs, t0, MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(cli_b.calls(), 2);
    {
        let requests = server.requests.borrow();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].observations[0].expected_head_etag, None);
        assert_eq!(
            requests[2].observations[0].expected_head_etag.as_deref(),
            Some(head.as_str())
        );
    }
    assert_eq!(
        server.outcomes(),
        [
            CloudSessionChangeOutcome::Accepted,
            CloudSessionChangeOutcome::Conflict,
            CloudSessionChangeOutcome::Accepted
        ]
    );
    assert_eq!(
        slice(&mut b, &b_inputs, t0, 7 * HOUR),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(server.requests.borrow().len(), 3);
}

/// [behaviour] A conflict without a server head settles nothing and earns
/// no credit, but the same content is not sent again; changed content is
/// offered again with no predecessor.
#[test]
#[serial_test::serial]
fn conflict_without_a_head_settles_nothing_and_is_not_resent() {
    let server = Server::new();
    let (_root, mac_a) = store("conflict-null-mac-a");
    let cli_a = Cli::head(page_of(vec![task("contended", "running")], None));
    let t0 = Instant::now();
    slice(
        &mut CloudCollector::default(),
        &inputs(&mac_a, &cli_a, &server),
        t0,
        Duration::ZERO,
    );

    let (_root, mac_b) = store("conflict-null-mac-b");
    let cli_b = Cli::head(page_of(vec![task("contended", "applied")], None));
    let b_inputs = inputs(&mac_b, &cli_b, &server);
    let mut b = CloudCollector::default();
    assert_eq!(
        slice(&mut b, &b_inputs, t0, MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(cli_b.calls(), 1, "no re-list without a head");
    assert_eq!(b.unchanged_heads, 1, "a conflict earns no credit");
    let scope = cache_scope(&b_inputs);
    let cached = checkpoints_ack(&mac_b, &scope, "contended");
    assert_eq!(cached.map(|ack| ack.head_etag), Some(None));

    assert_eq!(
        slice(&mut b, &b_inputs, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(server.requests.borrow().len(), 2);

    cli_b.set(None, page_of(vec![task("contended", "error")], None));
    slice(&mut b, &b_inputs, t0, 12 * HOUR);
    let requests = server.requests.borrow();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].observations[0].expected_head_etag, None);
    assert_eq!(server.heads.borrow().len(), 1);
}

fn checkpoints_ack(
    checkpoints: &CloudSessionCheckpointStore,
    scope: &[u8; 32],
    id: &str,
) -> Option<CloudAck> {
    checkpoints
        .read_acks(scope, &[id], midnight().unix_timestamp())
        .unwrap()
        .remove(id)
}

/// [behaviour] One ACK with accepted, noop, rejected and conflicting (no
/// head) entries settles each exactly: only accepted and noop carry a head;
/// the refusal and the conflict are remembered with none and earn no credit.
/// After a restart the same page offers nothing.
#[test]
#[serial_test::serial]
fn mixed_ack_settles_each_task_and_survives_a_restart() {
    let (_root, checkpoints) = store("mixed-ack");
    let cli = Cli::head(page_of(
        vec![
            task("new", "applied"),
            task("known", "applied"),
            task("refused", "applied"),
            task("diverged", "applied"),
        ],
        None,
    ));
    let server = Server::new();
    let known = parse_cloud_page(&page("known", None), OFF, now())
        .unwrap()
        .changes
        .remove(0);
    server
        .heads
        .borrow_mut()
        .insert(known.source_session_id.clone(), server_etag(&known));
    server.reject.borrow_mut().push("refused".to_string());
    server
        .heads
        .borrow_mut()
        .insert("diverged".to_string(), "f".repeat(64));
    let inputs = inputs(&checkpoints, &cli, &server);
    let t0 = Instant::now();
    assert_eq!(
        slice(&mut CloudCollector::default(), &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(
        server.outcomes(),
        [
            CloudSessionChangeOutcome::Accepted,
            CloudSessionChangeOutcome::Noop,
            CloudSessionChangeOutcome::Rejected,
            CloudSessionChangeOutcome::Conflict
        ]
    );
    assert_eq!(cli.calls(), 1, "a conflict without a head is not re-listed");
    let scope = cache_scope(&inputs);
    for (id, etag) in [
        ("new", true),
        ("known", true),
        ("refused", false),
        ("diverged", false),
    ] {
        let ack = checkpoints_ack(&checkpoints, &scope, id).unwrap();
        assert_eq!(ack.head_etag.is_some(), etag, "{id}");
    }

    let mut restarted = CloudCollector::default();
    assert_eq!(
        slice(&mut restarted, &inputs, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(server.requests.borrow().len(), 1);
    assert_eq!(restarted.unchanged_heads, 1);
}

/// [behaviour] Requests are packed by count and bytes, keeping every task
/// once and in order: 450 small tasks become 200, 200 and 50; tasks with
/// full-length labels split under the server's body ceiling.
#[test]
fn pack_splits_by_count_and_bytes_keeping_every_task_in_order() {
    let labelled = CloudUploadPolicyV2 {
        session_titles_enabled: true,
        workspace_labels_enabled: true,
    };
    let changes = |count: usize, policy| {
        let long = "é".repeat(MAX_LABEL_CHARS);
        let tasks = (0..count)
            .map(|index| {
                let mut task = task(&format!("task-{index:03}"), "applied");
                task["title"] = json!(long);
                task["environment_label"] = json!(long);
                task
            })
            .collect();
        parse_cloud_page(&page_of(tasks, None), policy, now())
            .unwrap()
            .changes
    };
    let small = wire::pack(changes(450, OFF));
    assert_eq!(
        small.iter().map(Vec::len).collect::<Vec<_>>(),
        [200, 200, 50]
    );
    let long = changes(100, labelled);
    let requests = wire::pack(long.clone());
    assert!(requests.len() >= 2, "{}", requests.len());
    for request in &requests {
        // The tasks plus a 3 KiB envelope still fit the server's ceiling.
        assert!(serde_json::to_vec(request).unwrap().len() + 3 * 1024 <= wire::MAX_REQUEST_BYTES);
    }
    assert_eq!(requests.concat(), long);
}

/// [behaviour] Cloud failures back off on their own clock; nothing of the
/// local delivery path (receipts, local backoff) is touched.
#[test]
#[serial_test::serial]
fn cloud_collection_is_isolated_from_local_delivery() {
    let (root, checkpoints) = store("isolation");
    let cli = Cli::head(page("isolated", None));
    let server = Server::new();
    server.hint_fault.set(Some(HintFault::Offline));
    let inputs = inputs(&checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Failed
    );
    assert_eq!(cli.calls(), 0);
    assert!(collector.schedule.retry_not_before.is_some());
    server.hint_fault.set(None);
    let offset = collector
        .next_wake(t0, midnight())
        .unwrap()
        .saturating_duration_since(t0);
    assert_eq!(
        slice(&mut collector, &inputs, t0, offset),
        CloudSessionCycleOutcome::Uploaded
    );
    assert!(crate::upload_receipts::read(&root, 500, None, None)
        .unwrap()
        .receipts
        .is_empty());
}

/// [behaviour] A nonempty provider page with no valid task is a provider
/// failure, never an empty healthy page or a completed crawl, even when its
/// malformed rows carry an invalid id.
#[test]
#[serial_test::serial]
fn nonempty_page_without_a_valid_task_is_a_provider_failure() {
    for (name, tasks) in [
        ("no-id", json!([{"status": "running"}, 42])),
        (
            "invalid-id-no-status",
            json!([{"id": ""}, {"id": " padded"}]),
        ),
    ] {
        let (_root, checkpoints) = store(&format!("invalid-page-{name}"));
        let cli = Cli::head(json!({"tasks": tasks, "cursor": null}).to_string());
        let server = Server::new();
        let mut collector = CloudCollector::default();
        assert_eq!(
            slice(
                &mut collector,
                &inputs(&checkpoints, &cli, &server),
                Instant::now(),
                Duration::ZERO
            ),
            CloudSessionCycleOutcome::Failed,
            "{name}"
        );
        assert!(server.requests.borrow().is_empty(), "{name}");
        assert_eq!(
            collector.reported,
            Some("provider_payload_invalid"),
            "{name}"
        );
        assert_eq!(collector.reported_invalid_ids, None, "{name}");
        assert_eq!(collector.schedule.crawl_completed, None, "{name}");
    }
}

/// [regress] A delayed refusal anchors Retry-After to response receipt,
/// even when the injected slice clock is older than the real test clock.
#[test]
#[serial_test::serial]
fn cloud_retry_after_starts_when_the_hint_request_finishes() {
    struct Shed;
    impl CloudSessionTransport for Shed {
        fn read_hint(&self, _: Duration) -> Result<ActivityHintResponse> {
            Err(crate::snapshot_client::UploadShed {
                status: 503,
                retry_after: Some(Duration::ZERO),
                code: None,
            }
            .into())
        }
        fn send_changes(
            &self,
            _: &CloudSessionChangesV2,
            _: Duration,
        ) -> Result<CloudSessionChangesAckV2> {
            unreachable!()
        }
    }
    let (_root, checkpoints) = store("retry-after-receipt");
    let cli = Cli::head(page("must-not-collect", None));
    let mut collector = CloudCollector::default();
    let inputs = inputs(&checkpoints, &cli, &Shed);
    let now = Instant::now();
    // An explicitly old deadline models time spent composing credentials.
    let slice_start = now - Duration::from_secs(5);
    let outcome = collector.run_slice(&inputs, slice_start, midnight());
    assert_eq!(outcome, CloudSessionCycleOutcome::Failed);
    let retry = collector.schedule.retry_not_before.unwrap();
    assert!(retry > slice_start);
    assert_eq!(cli.calls(), 0);
}

/// [behaviour] Backoff defers planned work; it never accelerates head
/// polling. A failed first crawl page is owed at the continuation cadence.
#[test]
#[serial_test::serial]
fn failed_provider_pages_keep_their_planned_work_opportunity() {
    struct Offline;
    impl CloudSessionRunner for Offline {
        fn list_page(&self, _: Option<&str>, _: usize) -> Result<String> {
            Err(anyhow!("offline"))
        }
    }
    let (_root, checkpoints) = store("failure-cadence");
    let server = Server::new();
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    let cli = Cli::head(page("terminal", None));
    assert_eq!(
        slice(
            &mut collector,
            &inputs(&checkpoints, &cli, &server),
            t0,
            Duration::ZERO
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    let offline = inputs(&checkpoints, &Offline, &server);
    assert_eq!(
        slice(&mut collector, &offline, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Failed
    );
    assert!(
        collector
            .next_wake(t0 + 6 * HOUR, midnight() + 6 * HOUR)
            .unwrap()
            >= t0 + 6 * HOUR + 5 * MINUTE
    );
    let mut startup = CloudCollector::default();
    assert_eq!(
        slice(&mut startup, &offline, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Failed
    );
    assert!(startup.next_wake(t0, midnight()).unwrap() >= t0 + 5 * MINUTE);
}

// ---------------------------------------------------------------------------
// Identity fence. [regress]

/// A transport whose local binding can stop being current mid-slice.
struct Fenced {
    server: Server,
    current: Arc<AtomicBool>,
    stop_after_send: bool,
}

impl Fenced {
    fn new(current: Arc<AtomicBool>) -> Self {
        Self {
            server: Server::new(),
            current,
            stop_after_send: false,
        }
    }
}

impl CloudSessionTransport for Fenced {
    fn local_binding_current(&self) -> bool {
        self.current.load(AtomicOrdering::SeqCst)
    }
    fn read_hint(&self, timeout: Duration) -> Result<ActivityHintResponse> {
        self.server.read_hint(timeout)
    }
    fn send_changes(
        &self,
        request: &CloudSessionChangesV2,
        timeout: Duration,
    ) -> Result<CloudSessionChangesAckV2> {
        let ack = self.server.send_changes(request, timeout);
        if self.stop_after_send {
            self.current.store(false, AtomicOrdering::SeqCst);
        }
        ack
    }
}

/// [regress] An identity change stops the hint, page, send and cache paths;
/// an ACK admitted before a change cannot repopulate its cache afterwards.
#[test]
#[serial_test::serial]
fn current_binding_fences_every_io_boundary() {
    struct ChangingCli {
        cli: Cli,
        current: Arc<AtomicBool>,
        stop_after_list: bool,
    }
    impl CloudSessionRunner for ChangingCli {
        fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String> {
            let page = self.cli.list_page(cursor, limit);
            if self.stop_after_list {
                self.current.store(false, AtomicOrdering::SeqCst);
            }
            page
        }
    }
    for stop in ["before-slice", "after-provider", "after-send"] {
        let (_root, checkpoints) = store(&format!("binding-fence-{stop}"));
        let current = Arc::new(AtomicBool::new(stop != "before-slice"));
        let cli = ChangingCli {
            cli: Cli::head(page("identity-fence", None)),
            current: Arc::clone(&current),
            stop_after_list: stop == "after-provider",
        };
        let mut server = Fenced::new(Arc::clone(&current));
        server.stop_after_send = stop == "after-send";
        let inputs = inputs(&checkpoints, &cli, &server);
        let outcome = CloudCollector::default().run_slice(&inputs, Instant::now(), midnight());
        // A send already admitted completes; only its cache write is refused.
        let expected = if stop == "after-send" {
            CloudSessionCycleOutcome::Uploaded
        } else {
            CloudSessionCycleOutcome::Disabled
        };
        assert_eq!(outcome, expected, "{stop}");
        assert_eq!(
            server.server.hint_calls.get(),
            usize::from(stop != "before-slice"),
            "{stop}"
        );
        assert_eq!(
            cli.cli.calls(),
            usize::from(stop != "before-slice"),
            "{stop}"
        );
        assert_eq!(
            server.server.offered(),
            usize::from(stop == "after-send"),
            "{stop}"
        );
        let scope = cache_scope(&inputs);
        assert!(
            checkpoints_ack(&checkpoints, &scope, "identity-fence").is_none(),
            "{stop}"
        );
    }
}

/// [regress] An identity change while a provider call runs: no new I/O is
/// admitted, the change's drain waits for the call, and the page it returned
/// is never uploaded.
#[test]
#[serial_test::serial]
fn identity_change_waits_for_an_inflight_provider_call_and_uploads_nothing() {
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

    let (_root, checkpoints) = store("provider-call-fence");
    let checkpoints = Arc::new(checkpoints);
    let current = Arc::new(AtomicBool::new(true));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let collector_checkpoints = Arc::clone(&checkpoints);
    let collector_current = Arc::clone(&current);
    let run = thread::spawn(move || {
        let server = Fenced::new(collector_current);
        let runner = BlockingRunner {
            entered: entered_tx,
            release: release_rx,
        };
        let outcome = CloudCollector::default().run_slice(
            &inputs(&collector_checkpoints, &runner, &server),
            Instant::now(),
            midnight(),
        );
        (outcome, server.server.requests.borrow().len())
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    current.store(false, AtomicOrdering::SeqCst);
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
    assert_eq!(run.join().unwrap(), (CloudSessionCycleOutcome::Disabled, 0));
}

/// [regress] An identity change at relay admission stops the upload.
#[test]
#[serial_test::serial]
fn identity_change_at_relay_admission_stops_the_upload() {
    let (_root, checkpoints) = store("relay-admission-race");
    let checkpoints = Arc::new(checkpoints);
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    checkpoints.set_relay_admission_barrier_for_test(0, Arc::clone(&entered), Arc::clone(&release));
    let current = Arc::new(AtomicBool::new(true));
    let collector_checkpoints = Arc::clone(&checkpoints);
    let collector_current = Arc::clone(&current);
    let run = thread::spawn(move || {
        let server = Fenced::new(collector_current);
        let cli = Cli::head(page("admission-race", None));
        let outcome = CloudCollector::default().run_slice(
            &inputs(&collector_checkpoints, &cli, &server),
            Instant::now(),
            midnight(),
        );
        (outcome, server.server.requests.borrow().len())
    });
    entered.wait();
    current.store(false, AtomicOrdering::SeqCst);
    release.wait();
    assert_eq!(run.join().unwrap(), (CloudSessionCycleOutcome::Disabled, 0));
}

/// [regress] An identity reservation drains admitted collector I/O; the test
/// hook models one lease still held.
#[test]
#[serial_test::serial]
fn collector_io_drain_times_out_while_a_lease_is_held() {
    let (_root, checkpoints) = store("io-drain");
    checkpoints.set_collector_io_active_for_test(1);
    assert!(checkpoints
        .wait_for_collector_io_idle(Duration::from_millis(20))
        .is_err());
    checkpoints.set_collector_io_active_for_test(0);
    checkpoints
        .wait_for_collector_io_idle(Duration::from_millis(20))
        .unwrap();
}

// ---------------------------------------------------------------------------
// Wire format. [format]

fn fixture_change(id: char) -> CloudSessionChangeV2 {
    CloudSessionChangeV2 {
        source_session_id: format!("task-{id}"),
        expected_head_etag: None,
        entity_kind: "task".to_string(),
        lifecycle: "completed".to_string(),
        attempt_count: None,
        environment_kind: "unknown".to_string(),
        measurement_basis: "not_itemized".to_string(),
        coverage: vec!["identity".to_string(), "status".to_string()],
        created_at: None,
        started_at: None,
        updated_at: None,
        completed_at: None,
        title: None,
        environment_label: None,
    }
}

/// Shared session-id vectors (the server applies the same rule): code-point
/// bounds, multibyte text, C0/DEL/C1 controls, boundary whitespace (U+2028
/// included), and the characters the rule allows (U+200B included).
fn session_id_vectors() -> Vec<(String, bool)> {
    let mut vectors = vec![
        (String::new(), false),
        ("a".to_string(), true),
        ("é".repeat(128), true),
        ("é".repeat(129), true),
        ("é".repeat(255), true),
        ("界".repeat(255), true),
        ("é".repeat(256), false),
        ("x".repeat(256), false),
        ("task id with inner spaces".to_string(), true),
        ("a|b".to_string(), true),
        ("a\\b".to_string(), true),
        (format!("hmac-sha256:{}", "a".repeat(64)), true),
        ("task_e_😀".to_string(), true),
        // U+2028 LINE SEPARATOR is White_Space but not Cc: allowed inside.
        ("task_e_1\u{2028}2".to_string(), true),
        // U+200B ZERO WIDTH SPACE is neither White_Space nor Cc: allowed
        // anywhere, kept as is.
        ("task_e_\u{200b}".to_string(), true),
        ("\u{200b}task_e_1".to_string(), true),
        ("task_e_\u{200b}1".to_string(), true),
    ];
    for bad in [
        " task",
        "task ",
        "\u{3000}task",
        "task\u{a0}",
        "\ttask",
        "task\n",
        "task_e_1\u{2028}",
        "\u{2028}task_e_1",
    ] {
        vectors.push((bad.to_string(), false));
    }
    for control in [
        '\u{0}', '\u{1f}', '\u{7f}', '\u{80}', '\u{85}', '\u{9f}', '\t',
    ] {
        vectors.push((format!("ta{control}sk"), false));
    }
    vectors
}

/// [format] The digest vector: SHA-256 over the domain, a zero byte and
/// sorted compact JSON of the task (its raw id included) and the applied
/// policy. The predecessor etag is not part of it; the policy, a title or a
/// label are.
#[test]
fn semantic_digest_vector_is_stable_and_covers_policy_and_labels() {
    let mut change = CloudSessionChangeV2 {
        source_session_id: "task_e_6830f1c2 é".to_string(),
        attempt_count: Some(2),
        coverage: ["attempts", "identity", "status", "timing"]
            .map(str::to_string)
            .to_vec(),
        created_at: Some("2026-07-20T11:00:00Z".to_string()),
        updated_at: Some("2026-07-20T11:30:00Z".to_string()),
        ..fixture_change('a')
    };
    assert_eq!(
        hex(&change.semantic_digest(OFF)),
        "affcbe83bdbb1bc63eb94c51a4169bf849ae86aaf6599c2e0732daea01ebf771"
    );
    let base = change.semantic_digest(OFF);
    let mut other = change.clone();
    other.source_session_id = "task_e_6830f1c2 e\u{301}".to_string();
    assert_ne!(other.semantic_digest(OFF), base);
    change.expected_head_etag = Some("0".repeat(64));
    assert_eq!(change.semantic_digest(OFF), base);
    let titles = CloudUploadPolicyV2 {
        session_titles_enabled: true,
        ..OFF
    };
    let labels = CloudUploadPolicyV2 {
        workspace_labels_enabled: true,
        ..OFF
    };
    assert_ne!(change.semantic_digest(titles), base);
    assert_ne!(change.semantic_digest(labels), base);
    assert_ne!(
        change.semantic_digest(titles),
        change.semantic_digest(labels)
    );
    change.title = Some("A title".to_string());
    assert_ne!(change.semantic_digest(titles), base);
    change.title = None;
    change.lifecycle = "failed".to_string();
    assert_ne!(change.semantic_digest(OFF), base);
    // The predecessor is always serialized, as null when unknown; absent
    // labels are omitted.
    change.expected_head_etag = None;
    let encoded = serde_json::to_string(&change).unwrap();
    assert!(encoded.contains("\"expected_head_etag\":null"));
    assert!(!encoded.contains("title"));
    assert!(!encoded.contains("environment_label"));
}

/// [format] The body names its source, carries the raw task id as the
/// session id and no grant, and stamps the policy it applied: a title and an
/// environment name appear exactly when their setting is on; URLs,
/// summaries, environment ids and cursors never do.
#[test]
#[serial_test::serial]
fn v3_body_sends_the_raw_task_id_and_stamps_the_policy() {
    for (titles, labels) in [(false, false), (true, false), (false, true), (true, true)] {
        let policy = CloudUploadPolicyV2 {
            session_titles_enabled: titles,
            workspace_labels_enabled: labels,
        };
        let (_root, checkpoints) = store(&format!("wire-policy-{titles}-{labels}"));
        let cli = Cli::head(page("raw-provider-id", Some("private-cursor")));
        cli.set(Some("private-cursor"), page_of(Vec::new(), None));
        let server = Server::new();
        server.set_hint(|hint| hint.policy = policy);
        slice(
            &mut CloudCollector::default(),
            &inputs(&checkpoints, &cli, &server),
            Instant::now(),
            Duration::ZERO,
        );
        let request = server.requests.borrow()[0].clone();
        assert!(request.validate().is_ok());
        assert_eq!(request.schema_version, "cloud_session_changes.v3");
        assert_eq!(request.source, "codex");
        assert_eq!(request.upload_policy, policy);
        let change = &request.observations[0];
        assert_eq!(change.source_session_id, "raw-provider-id");
        assert_eq!(change.title.as_deref(), titles.then_some("private title"));
        assert_eq!(
            change.environment_label.as_deref(),
            labels.then_some("Private environment")
        );
        let wire = serde_json::to_value(&request).unwrap();
        let mut fields = wire
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "collected_at",
                "collector_version",
                "observations",
                "schema_version",
                "source",
                "upload_policy"
            ]
        );
        assert_eq!(
            wire["observations"][0]["source_session_id"],
            json!("raw-provider-id")
        );
        assert!(wire["observations"][0].get("entity_key").is_none());
        let text = wire.to_string();
        for private in [
            "grant",
            "hmac",
            "chatgpt.com",
            "private-cursor",
            "provider-environment-private",
            "private summary",
            "semantic_digest",
        ] {
            assert!(!text.contains(private), "{private}");
        }
        assert_eq!(text.contains("private title"), titles);
        assert_eq!(text.contains("Private environment"), labels);
    }
}

/// [format] Requests validate strictly; another source, an invalid session
/// id, an open lifecycle, unsorted coverage, a label the policy forbids or
/// too long, or an oversize batch is refused before I/O.
#[test]
fn changes_request_rejects_bad_ids_open_values_labels_and_oversize_batches() {
    let titles = CloudUploadPolicyV2 {
        session_titles_enabled: true,
        ..OFF
    };
    let request = CloudSessionChangesV2 {
        schema_version: CHANGES_SCHEMA_VERSION.to_string(),
        source: "codex".to_string(),
        collector_version: "0.0.0".to_string(),
        collected_at: "2026-07-21T00:00:00Z".to_string(),
        upload_policy: titles,
        observations: vec![CloudSessionChangeV2 {
            title: Some("t".repeat(MAX_LABEL_CHARS)),
            ..fixture_change('a')
        }],
    };
    assert!(request.validate().is_ok());
    let mutate = |change: &dyn Fn(&mut CloudSessionChangesV2)| {
        let mut bad = request.clone();
        change(&mut bad);
        bad.validate().is_err()
    };
    for schema in ["cloud_session_changes.v1", "cloud_session_changes.v2"] {
        assert!(mutate(&|bad| bad.schema_version = schema.to_string()));
    }
    assert!(mutate(&|bad| bad.source = "claude".to_string()));
    assert!(mutate(&|bad| bad.collector_version = "9".repeat(33)));
    for (id, valid) in session_id_vectors() {
        assert_eq!(
            mutate(&|bad| bad.observations[0].source_session_id = id.clone()),
            !valid,
            "{:?}",
            id.chars().count()
        );
    }
    assert!(mutate(
        &|bad| bad.observations[0].lifecycle = "future_state".to_string()
    ));
    assert!(mutate(&|bad| bad.observations[0].coverage.reverse()));
    assert!(mutate(
        &|bad| bad.observations[0].expected_head_etag = Some("x".to_string())
    ));
    assert!(mutate(&|bad| bad.upload_policy = OFF));
    assert!(mutate(
        &|bad| bad.observations[0].title = Some("t".repeat(MAX_LABEL_CHARS + 1))
    ));
    assert!(mutate(
        &|bad| bad.observations[0].environment_label = Some("label".to_string())
    ));
    assert!(mutate(&|bad| bad.observations.clear()));
    assert!(mutate(&|bad| {
        let first = bad.observations[0].clone();
        bad.observations.push(first);
    }));
    assert!(mutate(&|bad| {
        bad.observations = (0..=wire::MAX_CHANGES_PER_REQUEST)
            .map(|index| CloudSessionChangeV2 {
                source_session_id: format!("task-{index}"),
                ..fixture_change('a')
            })
            .collect();
    }));
}

/// [format] ACK matching: accepted, refused and conflicting entries are
/// distinct; a conflict without a head is a refusal; a wrong schema,
/// duplicate, unsolicited, missing or etag-less entry settles nothing.
#[test]
fn ack_matching_is_exact() {
    let request = CloudSessionChangesV2 {
        schema_version: CHANGES_SCHEMA_VERSION.to_string(),
        source: "codex".to_string(),
        collector_version: "0.0.0".to_string(),
        collected_at: "2026-07-21T00:00:00Z".to_string(),
        upload_policy: OFF,
        observations: vec![
            fixture_change('a'),
            fixture_change('b'),
            fixture_change('c'),
            fixture_change('d'),
            fixture_change('e'),
        ],
    };
    assert!(request.validate().is_ok());
    let entry = |id: char, outcome, etag: Option<char>| CloudSessionChangeAckV2 {
        source_session_id: format!("task-{id}"),
        outcome,
        head_etag: etag.map(|etag| etag.to_string().repeat(64)),
        accepted_seq: None,
        reason: None,
    };
    let ack = |entities| CloudSessionChangesAckV2 {
        schema_version: "cloud_session_changes_ack.v3".to_string(),
        entities,
    };
    let settled = request
        .settle(&ack(vec![
            entry('c', CloudSessionChangeOutcome::Conflict, Some('e')),
            entry('a', CloudSessionChangeOutcome::Accepted, Some('d')),
            entry('b', CloudSessionChangeOutcome::Rejected, None),
            entry('d', CloudSessionChangeOutcome::Conflict, None),
            entry('e', CloudSessionChangeOutcome::Noop, Some('f')),
        ]))
        .unwrap();
    assert_eq!(
        settled.values().cloned().collect::<Vec<_>>(),
        [
            Settled::Acked {
                head_etag: "d".repeat(64),
                accepted: true
            },
            Settled::Refused,
            Settled::Conflict {
                head_etag: "e".repeat(64)
            },
            Settled::Refused,
            Settled::Acked {
                head_etag: "f".repeat(64),
                accepted: false
            },
        ]
    );
    let good = || {
        ['a', 'b', 'c', 'd', 'e']
            .map(|key| entry(key, CloudSessionChangeOutcome::Noop, Some('d')))
            .to_vec()
    };
    for schema in [
        "cloud_session_changes_ack.v1",
        "cloud_session_changes_ack.v2",
    ] {
        let mut wrong_schema = ack(good());
        wrong_schema.schema_version = schema.to_string();
        assert!(request.settle(&wrong_schema).is_err());
    }
    let mut duplicate = good();
    duplicate[2] = entry('a', CloudSessionChangeOutcome::Noop, Some('d'));
    assert!(request.settle(&ack(duplicate)).is_err());
    let mut unsolicited = good();
    unsolicited[2] = entry('9', CloudSessionChangeOutcome::Noop, Some('d'));
    assert!(request.settle(&ack(unsolicited)).is_err());
    let mut short = good();
    short.pop();
    assert!(request.settle(&ack(short)).is_err());
    let mut no_etag = good();
    no_etag[0].head_etag = None;
    assert!(request.settle(&ack(no_etag)).is_err());
    let mut bad_etag = good();
    bad_etag[0].head_etag = Some("D".repeat(64));
    assert!(request.settle(&ack(bad_etag)).is_err());
}

// ---------------------------------------------------------------------------
// Provider parsing. [behaviour]

/// [format] The field names are those the official `codex cloud list --json`
/// prints (`id`, `title`, `status`, `updated_at`, `environment_id`,
/// `environment_label`, `summary`, `is_review`, `attempt_total`, and a
/// top-level `tasks` and `cursor`); only the title and environment name may
/// leave, under policy, cut to the wire bound.
#[test]
fn parser_takes_title_and_environment_name_only_under_policy() {
    let mut long = task("long", "applied");
    long["title"] = json!("x".repeat(MAX_LABEL_CHARS + 5));
    let raw = page_of(vec![task("plain", "applied"), long], None);
    let both = CloudUploadPolicyV2 {
        session_titles_enabled: true,
        workspace_labels_enabled: true,
    };
    let parsed = parse_cloud_page(&raw, both, now()).unwrap();
    assert_eq!(parsed.changes[0].title.as_deref(), Some("private title"));
    assert_eq!(
        parsed.changes[0].environment_label.as_deref(),
        Some("Private environment")
    );
    assert_eq!(
        parsed.changes[1]
            .title
            .as_deref()
            .map(|title| title.chars().count()),
        Some(MAX_LABEL_CHARS)
    );
    let parsed = parse_cloud_page(&raw, OFF, now()).unwrap();
    assert!(parsed
        .changes
        .iter()
        .all(|change| change.title.is_none() && change.environment_label.is_none()));
    let encoded = serde_json::to_string(&parsed.changes).unwrap();
    for private in [
        "private title",
        "chatgpt.com",
        "provider-environment-private",
        "Private environment",
        "private summary",
    ] {
        assert!(!encoded.contains(private), "{private}");
    }
    assert_eq!(parsed.changes[0].source_session_id, "plain");
}

#[test]
fn official_cloud_task_statuses_and_attempt_total_are_normalized_truthfully() {
    let tasks = [
        ("official-pending", "pending", 3),
        ("official-ready", "ready", 4),
        ("official-applied", "applied", 5),
        ("official-error", "error", 6),
    ]
    .map(|(id, status, attempts)| {
        let mut task = task(id, status);
        task["attempt_total"] = json!(attempts);
        task
    })
    .to_vec();
    let parsed = parse_cloud_page(&page_of(tasks, None), OFF, now()).unwrap();
    assert_eq!(
        parsed
            .changes
            .iter()
            .map(|row| row.lifecycle.as_str())
            .collect::<Vec<_>>(),
        ["unknown", "completed", "completed", "failed"]
    );
    assert_eq!(
        parsed
            .changes
            .iter()
            .map(|row| row.attempt_count)
            .collect::<Vec<_>>(),
        [Some(3), Some(4), Some(5), Some(6)]
    );
    assert!(parsed
        .changes
        .iter()
        .all(|row| row.coverage == ["attempts", "identity", "status", "timing"]));
}

/// [behaviour] Every returned row is processed, beyond the requested limit;
/// a malformed row is skipped alone; provider times become canonical UTC and
/// future times are dropped.
#[test]
fn parser_keeps_every_valid_row_and_canonicalizes_times() {
    let mut offset = task("offset-time", "applied");
    offset["updated_at"] = json!("2026-07-20T13:30:00+02:00");
    let mut future = task("future-time", "applied");
    future["created_at"] = json!("2099-01-01T00:00:00Z");
    let mut rows = (0..PAGE_LIMIT + 5)
        .map(|index| task(&format!("row-{index}"), "applied"))
        .collect::<Vec<_>>();
    rows.push(json!({"status": "running"}));
    rows.push(offset);
    rows.push(future);
    let parsed = parse_cloud_page(&page_of(rows, None), OFF, now()).unwrap();
    assert_eq!(parsed.source_item_count, PAGE_LIMIT + 8);
    assert_eq!(parsed.changes.len(), PAGE_LIMIT + 7);
    let offset = &parsed.changes[PAGE_LIMIT + 5];
    assert_eq!(offset.updated_at.as_deref(), Some("2026-07-20T11:30:00Z"));
    let future = &parsed.changes[PAGE_LIMIT + 6];
    assert_eq!(future.created_at, None);
}

/// [format] Only the official `id` is read, as is: valid ids pass byte for
/// byte, invalid ones are skipped and counted; a conflicting `task_id`, an
/// alias-only row and a non-string id are not task ids.
#[test]
fn parser_reads_only_the_raw_id_and_counts_invalid_ids() {
    for (id, valid) in session_id_vectors() {
        let parsed = parse_cloud_page(&page(&id, None), OFF, now()).unwrap();
        let label = id.chars().count();
        assert_eq!(parsed.source_item_count, 1, "{label}");
        if valid {
            assert_eq!(parsed.changes.len(), 1, "{label}");
            assert_eq!(parsed.changes[0].source_session_id, id, "{label}");
            assert_eq!(parsed.invalid_ids, 0, "{label}");
        } else {
            assert!(parsed.changes.is_empty(), "{label}");
            assert_eq!(parsed.invalid_ids, 1, "{label}");
        }
    }
    let mut both = task("official", "applied");
    both["task_id"] = json!("conflicting-alias");
    let mut alias_only = task("unused", "applied");
    alias_only.as_object_mut().unwrap().remove("id");
    alias_only["task_id"] = json!("alias-only");
    let mut number = task("unused", "applied");
    number["id"] = json!(42);
    let parsed = parse_cloud_page(
        &page_of(
            vec![task("id-only", "applied"), both, alias_only, number],
            None,
        ),
        OFF,
        now(),
    )
    .unwrap();
    assert_eq!(parsed.source_item_count, 4);
    assert_eq!(parsed.invalid_ids, 0);
    assert_eq!(
        parsed
            .changes
            .iter()
            .map(|change| change.source_session_id.as_str())
            .collect::<Vec<_>>(),
        ["id-only", "official"]
    );
}

#[test]
fn cursor_contract_separates_official_terminal_pagination_and_ambiguity() {
    let cursor = |raw: Value| parse_cloud_page(&raw.to_string(), OFF, now());
    assert_eq!(
        cursor(json!({"tasks": [], "cursor": "official-next-page"}))
            .unwrap()
            .cursor,
        CloudPageCursor::Next("official-next-page".to_string())
    );
    assert_eq!(
        cursor(json!({"tasks": [], "cursor": null})).unwrap().cursor,
        CloudPageCursor::OfficialTerminal
    );
    assert_eq!(
        cursor(json!({
            "tasks": [{"id": "legacy-next", "status": "running"}],
            "next_cursor": "legacy-next-page"
        }))
        .unwrap()
        .cursor,
        CloudPageCursor::Next("legacy-next-page".to_string())
    );
    for ambiguous in [
        json!({"tasks": [{"id": "fieldless", "status": "running"}]}),
        json!({"tasks": [{"id": "alias-null", "status": "running"}], "next_cursor": null}),
        json!([{"id": "array-root", "status": "running"}]),
    ] {
        assert_eq!(
            cursor(ambiguous).unwrap().cursor,
            CloudPageCursor::Ambiguous
        );
    }
    for conflicting in [
        json!({"tasks": [], "cursor": "official", "next_cursor": "legacy"}),
        json!({"tasks": [], "cursor": "official", "nextCursor": null}),
        json!({"tasks": [], "next_cursor": null, "nextCursor": "legacy"}),
        json!({"tasks": []}),
    ] {
        assert!(cursor(conflicting).is_err());
    }
    assert!(cursor(json!({
        "tasks": [],
        "cursor": "same",
        "next_cursor": "same",
        "nextCursor": "same"
    }))
    .is_ok());
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

    let restarted = CloudSessionControlTokenUseStore::new(&path);
    assert!(restarted.consume(token_id, now + 120, now).is_err());
    assert!(!fs::read_to_string(&path).unwrap().contains(token_id));
    for index in 0..(MAX_CONTROL_TOKEN_USES - 1) {
        restarted
            .consume(&format!("token-{index}"), now + 121 + index as u64, now)
            .unwrap();
    }
    let ledger: CloudSessionControlTokenUseLedger =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(ledger.entries.len(), MAX_CONTROL_TOKEN_USES);
    assert!(restarted.consume("over-cap", now + 240, now).is_err());
    restarted
        .consume("post-expiry", now + 500, now + 400)
        .unwrap();
    let pruned: CloudSessionControlTokenUseLedger =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(pruned.entries.len(), 1);
}

// ---------------------------------------------------------------------------
// Runtime composition and relay.

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

/// [behaviour] A Mac with no connected Codex account touches nothing: no
/// credential, relay, provider call or cache file. Connecting it activates
/// collection on the next slice, without a restart.
#[test]
#[serial_test::serial]
fn not_connected_is_zero_touch_and_connecting_activates_without_restart() {
    let (root, checkpoints) = store("runtime-connect");
    let accounts = FileAccountStore::new(root.join("account.json"));
    let devices = FileDeviceStore::new(root.join("device.json"));
    let connections = FileConnectionStore::new(root.join("connection.json"));
    let cli = Cli::head(page("after-connect", None));
    let mut collector = CloudCollector::default();
    let mut active_transport: ActiveCloudSessionTransport = None;
    let t0 = Instant::now();
    assert_eq!(
        collect_composed_cloud_sessions_once_with(
            &mut collector,
            &mut active_transport,
            ComposedSliceInputs {
                checkpoints: &checkpoints,
                runner: &cli,
                accounts: &accounts,
                devices: &devices,
                connections: &connections,
                load_credentials: || panic!("not connected must not read relay credentials"),
                compose_transport: |_, _| panic!("not connected must not compose a relay"),
            },
            t0,
            midnight(),
        ),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!(cli.calls(), 0);
    assert!(active_transport.is_none());
    assert!(!root.join("snapshots").exists());
    assert_eq!(collector.next_wake(t0, midnight()), None);

    let (accounts, devices, connections) = runtime_identity_stores(&root, DEFAULT_API_BASE_URL);
    let compositions = Cell::new(0);
    assert_eq!(
        collect_composed_cloud_sessions_once_with(
            &mut collector,
            &mut active_transport,
            ComposedSliceInputs {
                checkpoints: &checkpoints,
                runner: &cli,
                accounts: &accounts,
                devices: &devices,
                connections: &connections,
                load_credentials: || {
                    Ok((
                        devices.load().unwrap().unwrap(),
                        "device-secret".to_string(),
                    ))
                },
                compose_transport: |binding: CloudSessionRuntimeBinding, _: String| {
                    assert_eq!(
                        (binding.organization_id.as_str(), binding.user_id.as_str()),
                        (ORG_ID, USER_ID)
                    );
                    compositions.set(compositions.get() + 1);
                    Box::new(Server::new()) as Box<dyn CloudSessionTransport + Send>
                },
            },
            t0 + MINUTE,
            midnight() + MINUTE,
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(compositions.get(), 1);
    assert_eq!(cli.calls(), 1);
    assert!(active_transport.is_some());
}

/// [behaviour] The binding is refused, before any secret is read, for an
/// untrusted destination or a connection that does not match the device.
#[test]
#[serial_test::serial]
fn runtime_rejects_untrusted_destination_and_mismatched_connection() {
    let root = temp_dir("runtime-untrusted-destination");
    let (accounts, devices, connections) =
        runtime_identity_stores(&root, "https://attacker.example");
    assert!(load_cloud_session_runtime_binding(&accounts, &devices, &connections).is_err());
    assert!(validated_cloud_session_api_base_url("http://localhost.evil").is_err());
    assert!(validated_cloud_session_api_base_url("https://api.ottto.net@evil").is_err());

    let root = temp_dir("runtime-mismatched-connection");
    let (accounts, devices, connections) = runtime_identity_stores(&root, DEFAULT_API_BASE_URL);
    let binding = load_cloud_session_runtime_binding(&accounts, &devices, &connections)
        .unwrap()
        .unwrap();
    assert_eq!(binding.api_base_url, DEFAULT_API_BASE_URL);
    let mut connection = connections.load().unwrap().unwrap();
    connection.machine_id = Some("another-machine".to_string());
    connections.save(&connection).unwrap();
    assert!(load_cloud_session_runtime_binding(&accounts, &devices, &connections).is_err());

    // A device without the Codex source is not a Codex Mac: idle, no error.
    devices
        .save(&LocalDeviceBinding {
            device_id: DEVICE_ID.to_string(),
            machine_id: Some("machine-runtime".to_string()),
            sources: vec!["claude_code".to_string()],
        })
        .unwrap();
    assert!(
        load_cloud_session_runtime_binding(&accounts, &devices, &connections)
            .unwrap()
            .is_none()
    );
}

/// [behaviour] Startup removes the retired per-Mac consent files and nothing
/// else; a missing file is fine.
#[test]
fn startup_removes_only_the_retired_consent_files() {
    let root = temp_dir("retired-consent-files");
    let directory = root.join("cloud_sessions");
    fs::create_dir_all(&directory).unwrap();
    for name in RETIRED_STATE_FILES {
        fs::write(directory.join(name), b"{}").unwrap();
    }
    fs::write(directory.join("unrelated.json"), b"{}").unwrap();
    let daily_reference = root.join("codex-daily-aggregates");
    fs::create_dir_all(&daily_reference).unwrap();
    fs::write(daily_reference.join("control-token-uses.json"), b"{}").unwrap();

    remove_retired_consent_state(&root);
    for name in RETIRED_STATE_FILES {
        assert!(!directory.join(name).exists(), "{name}");
    }
    assert!(directory.join("unrelated.json").exists());
    assert!(daily_reference.join("control-token-uses.json").exists());
    remove_retired_consent_state(&root);
    remove_retired_consent_state(&root.join("absent"));
    assert_eq!(
        RETIRED_STATE_FILES,
        [
            "grant.json",
            "grant.lock",
            "control-token-uses.json",
            "control-token-uses.lock",
            "checkpoint.json"
        ]
    );
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
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    if headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("Content-Encoding: gzip"))
    {
        let mut decoded = String::new();
        flate2::read::GzDecoder::new(&request[header_end..])
            .read_to_string(&mut decoded)
            .unwrap();
        format!("{headers}{decoded}")
    } else {
        String::from_utf8_lossy(&request).to_string()
    }
}

fn relay_binding(api_base_url: String) -> CloudSessionRuntimeBinding {
    CloudSessionRuntimeBinding {
        api_base_url,
        device: LocalDeviceBinding {
            device_id: DEVICE_ID.to_string(),
            machine_id: None,
            sources: vec!["codex".to_string()],
        },
        organization_id: ORG_ID.to_string(),
        user_id: USER_ID.to_string(),
    }
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
        relay_binding(format!("http://{relay_address}")),
        "redirect-guard-secret".to_string(),
    );
    let error = transport
        .token(Instant::now() + Duration::from_secs(2))
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

/// [format] The relay reads the Codex activity hint and posts the exact v3
/// body, raw task id included, to the changes route, each retried once after a 401 with a fresh
/// relay token. A 409 is a refusal and a 410 reads like a missing route,
/// without reading either body; a 404 on the hint reads as an older server.
#[test]
#[serial_test::serial]
fn relay_reads_the_hint_and_maps_refusals_on_the_exact_routes() {
    use std::io::Write;
    use std::net::TcpListener;

    let (_root, checkpoints) = store("relay-http");
    let cli = Cli::head(page("task_e_raw id é|\\", None));
    let fixture = Server::new();
    slice(
        &mut CloudCollector::default(),
        &inputs(&checkpoints, &cli, &fixture),
        Instant::now(),
        Duration::ZERO,
    );
    let request = fixture.requests.borrow()[0].clone();
    let hint = Hint::on().decoded();
    let hint_body = json!({
        "source": "codex",
        "server_time": "2026-07-21T10:00:00Z",
        "last_data_at": null,
        "record_count_15m": 0,
        "record_count_24h": 0,
        "local_usage_reconciliation_enabled": true,
        "backfill_window_days": 183,
        "session_titles_enabled": false,
        "workspace_labels_enabled": false,
        "recommended_scan_after": "2026-07-21T10:05:00Z",
        "codex_cloud_tasks_enabled": true,
        "codex_cloud_tasks_contract": "cloud_session_changes.v3"
    })
    .to_string();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let server_captured = Arc::clone(&captured);
    let server = thread::spawn(move || {
        let mut tokens = 0;
        let mut hints = 0;
        let mut changes = 0;
        while hints < 3 || changes < 4 {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            server_captured.lock().unwrap().push(request.clone());
            let (status, body) = if request.contains("/relay-token HTTP/1.1") {
                tokens += 1;
                (
                    "200 OK",
                    format!(
                        r#"{{"token":"relay-token-{tokens}","expires_at":"2099-01-01T00:00:00Z"}}"#
                    ),
                )
            } else if request.contains("/activity-hints") {
                hints += 1;
                match hints {
                    1 => ("401 Unauthorized", r#"{"detail":"expired"}"#.to_string()),
                    2 => ("200 OK", hint_body.clone()),
                    _ => ("404 Not Found", r#"{"detail":"not found"}"#.to_string()),
                }
            } else {
                changes += 1;
                match changes {
                    1 => ("401 Unauthorized", r#"{"detail":"expired"}"#.to_string()),
                    2 => {
                        let body: Value =
                            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1)
                                .unwrap();
                        let entities = body["observations"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|change| {
                                json!({
                                    "source_session_id": change["source_session_id"],
                                    "outcome": "accepted",
                                    "head_etag": "c".repeat(64),
                                    "accepted_seq": 7,
                                    "reason": null
                                })
                            })
                            .collect::<Vec<_>>();
                        (
                            "200 OK",
                            json!({
                                "schema_version": "cloud_session_changes_ack.v3",
                                "entities": entities
                            })
                            .to_string(),
                        )
                    }
                    3 => (
                        "409 Conflict",
                        json!({"detail": {
                            "message": "The upload policy changed; read it again.",
                            "code": "cloud_upload_policy_mismatch",
                            "retryable": true
                        }})
                        .to_string(),
                    ),
                    _ => (
                        "410 Gone",
                        json!({"detail": {
                            "message": "This contract is retired.",
                            "code": "cloud_sessions_contract_retired"
                        }})
                        .to_string(),
                    ),
                }
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
        relay_binding(format!("http://{address}")),
        "device-secret".to_string(),
    );
    let read = relay.read_hint(Duration::from_secs(5)).unwrap();
    assert_eq!(codex_cloud_listing(&read), Some(OFF));
    assert_eq!(codex_cloud_listing(&hint), codex_cloud_listing(&read));
    let ack = relay
        .send_changes(&request, Duration::from_secs(5))
        .unwrap();
    assert!(request.settle(&ack).is_ok());
    let Err(conflict) = relay.send_changes(&request, Duration::from_secs(5)) else {
        panic!("a 409 must fail");
    };
    assert_eq!(
        conflict.downcast_ref::<crate::snapshot_client::CloudTaskRefused>(),
        Some(&crate::snapshot_client::CloudTaskRefused { status: 409 })
    );
    let Err(gone) = relay.send_changes(&request, Duration::from_secs(5)) else {
        panic!("a 410 must fail");
    };
    assert_eq!(
        gone.downcast_ref::<crate::snapshot_client::CloudSessionRouteUnsupported>(),
        Some(&crate::snapshot_client::CloudSessionRouteUnsupported { status: 410 })
    );
    let Err(missing) = relay.read_hint(Duration::from_secs(5)) else {
        panic!("a missing hint route must fail");
    };
    assert!(missing
        .downcast_ref::<crate::snapshot_client::CloudSessionRouteUnsupported>()
        .is_some());
    server.join().unwrap();

    let requests = captured.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request
                .starts_with("GET /api/v1/agent-session-snapshots/activity-hints HTTP/1.1"))
            .count(),
        3
    );
    let changes = requests
        .iter()
        .filter(|request| {
            request.starts_with("POST /api/v1/cloud-session-observations/changes HTTP/1.1")
        })
        .collect::<Vec<_>>();
    assert_eq!(changes.len(), 4);
    let bodies = changes
        .iter()
        .map(|request| request.split_once("\r\n\r\n").unwrap().1)
        .collect::<Vec<_>>();
    assert!(bodies.iter().all(|body| *body == bodies[0]));
    assert_eq!(
        serde_json::from_str::<CloudSessionChangesV2>(bodies[0]).unwrap(),
        request
    );
    let sent: Value = serde_json::from_str(bodies[0]).unwrap();
    assert_eq!(sent["source"], json!("codex"));
    assert_eq!(
        sent["observations"][0]["source_session_id"].as_str(),
        Some("task_e_raw id é|\\")
    );
    for body in &bodies {
        assert!(!body.contains("cursor"));
        assert!(!body.contains("grant"));
        assert!(!body.contains("entity_key"));
    }
    let bearer = |request: &str| {
        request
            .lines()
            .find(|line| line.starts_with("Authorization: Bearer "))
            .map(str::to_string)
    };
    assert_ne!(bearer(changes[0]), bearer(changes[1]));
    assert!(requests
        .iter()
        .all(|request| !request.contains("device-secret") || request.contains("/relay-token")));
}
