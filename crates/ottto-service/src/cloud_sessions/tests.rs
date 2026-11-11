use super::*;
use std::cell::{Cell, RefCell};

const INSTALLATION_ID: &str = "00000000-0000-4000-8000-000000000001";
const GRANT_ID: &str = "00000000-0000-4000-8000-000000000002";
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

fn stores(name: &str) -> (PathBuf, CloudSessionGrantStore, CloudSessionCheckpointStore) {
    let root = temp_dir(name);
    (
        root.clone(),
        CloudSessionGrantStore::new(root.join("grant.json")),
        CloudSessionCheckpointStore::new(&root),
    )
}

fn authority(grant: &CloudSessionGrant, status: &str) -> CloudSessionGrantAuthorityV1 {
    let binding = grant.backend_binding.as_ref().unwrap();
    CloudSessionGrantAuthorityV1 {
        schema_version: "cloud_collector_grant_authority.v1".to_string(),
        grant_id: binding.grant_id.clone(),
        grant_version: binding.grant_version,
        status: status.to_string(),
        can_collect: status == "enabled",
        can_read_cloud_sessions: status != "revoked",
        paused_at: None,
        collect_not_before: None,
        contract_version: "cloud_session_changes.v1".to_string(),
        disclosure_version: "cloud_sessions_disclosure.v1".to_string(),
    }
}

fn setup() -> CloudSessionGrantSetup {
    CloudSessionGrantSetup {
        installation_id: INSTALLATION_ID.to_string(),
        organization_scope: "org_fixture".to_string(),
        effective_user_scope: "user_fixture".to_string(),
    }
}

fn enabled(store: &CloudSessionGrantStore) {
    let local = store.enable(&setup(), now()).unwrap();
    store.grant_create_request(INSTALLATION_ID).unwrap();
    store
        .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
        .unwrap();
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
        schema_version: CHANGES_SCHEMA_VERSION.to_string(),
        disclosure_version: DISCLOSURE_VERSION.to_string(),
        grant_scope_fingerprint: local.grant_scope_id.clone(),
        account_fingerprint: local.account_fingerprint.clone(),
        status: status.to_string(),
        grant_version,
        can_collect: Some(status == "enabled"),
        ..Default::default()
    }
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

// ---------------------------------------------------------------------------
// Provider and server fakes.

/// One provider task as the official `codex cloud list --json` prints it,
/// with private fields the collector must never upload.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Authority {
    Enabled,
    Paused,
    Revoked,
    /// An older server: the authority route does not exist.
    Missing,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckFault {
    DropOne,
    NoEtag,
    Unsolicited,
}

/// A fake server holding one head etag per task. It answers `noop` for the
/// same content, `accepted` when the predecessor etag matches, and `conflict`
/// with its head as the hint otherwise.
struct Server {
    authority: Cell<Authority>,
    collect_not_before: RefCell<Option<String>>,
    authority_calls: Cell<usize>,
    requests: RefCell<Vec<CloudSessionChangesV1>>,
    acks: RefCell<Vec<CloudSessionChangesAckV1>>,
    heads: RefCell<HashMap<String, String>>,
    reject: RefCell<Vec<String>>,
    lose_acks: Cell<usize>,
    fault: Cell<Option<AckFault>>,
}

impl Server {
    fn new() -> Self {
        Self {
            authority: Cell::new(Authority::Enabled),
            collect_not_before: RefCell::new(None),
            authority_calls: Cell::new(0),
            requests: RefCell::new(Vec::new()),
            acks: RefCell::new(Vec::new()),
            heads: RefCell::new(HashMap::new()),
            reject: RefCell::new(Vec::new()),
            lose_acks: Cell::new(0),
            fault: Cell::new(None),
        }
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

fn server_etag(change: &CloudSessionChangeV1) -> String {
    let mut content = change.clone();
    content.expected_head_etag = None;
    hex(Sha256::digest(serde_json::to_vec(&content).unwrap()).as_slice())
}

impl CloudSessionTransport for Server {
    fn read_authority(
        &self,
        grant: &CloudSessionGrant,
        _timeout: Duration,
    ) -> Result<CloudSessionGrantAuthorityV1> {
        self.authority_calls.set(self.authority_calls.get() + 1);
        let status = match self.authority.get() {
            Authority::Enabled => "enabled",
            Authority::Paused => "paused",
            Authority::Revoked => "revoked",
            Authority::Missing => {
                return Err(anyhow::Error::new(
                    crate::snapshot_client::CloudSessionRouteUnsupported { status: 404 },
                ))
            }
            Authority::Offline => return Err(anyhow!("offline")),
        };
        let mut response = authority(grant, status);
        response.collect_not_before = self.collect_not_before.borrow().clone();
        Ok(response)
    }

    fn send_changes(
        &self,
        request: &CloudSessionChangesV1,
        _timeout: Duration,
    ) -> Result<CloudSessionChangesAckV1> {
        request.validate().unwrap();
        self.requests.borrow_mut().push(request.clone());
        let mut heads = self.heads.borrow_mut();
        let mut entities = request
            .observations
            .iter()
            .map(|change| {
                let etag = server_etag(change);
                let current = heads.get(&change.entity_key).cloned();
                let (outcome, head_etag) = if self.reject.borrow().contains(&change.entity_key) {
                    (CloudSessionChangeOutcome::Rejected, None)
                } else if current.as_deref() == Some(etag.as_str()) {
                    (CloudSessionChangeOutcome::Noop, Some(etag))
                } else if change.expected_head_etag == current {
                    heads.insert(change.entity_key.clone(), etag.clone());
                    (CloudSessionChangeOutcome::Accepted, Some(etag))
                } else {
                    (CloudSessionChangeOutcome::Conflict, current)
                };
                CloudSessionChangeAckV1 {
                    entity_key: change.entity_key.clone(),
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
                entities[0].entity_key = format!("hmac-sha256:{}", "f".repeat(64))
            }
            None => {}
        }
        let ack = CloudSessionChangesAckV1 {
            schema_version: "cloud_session_changes_ack.v1".to_string(),
            grant_id: request.grant_id.clone(),
            grant_version: request.grant_version,
            entities,
        };
        self.acks.borrow_mut().push(ack.clone());
        Ok(ack)
    }
}

fn inputs<'a>(
    grants: &'a CloudSessionGrantStore,
    checkpoints: &'a CloudSessionCheckpointStore,
    cli: &'a dyn CloudSessionRunner,
    server: &'a dyn CloudSessionTransport,
) -> SliceInputs<'a> {
    SliceInputs {
        grants,
        checkpoints,
        runner: cli,
        transport: server,
        destination: DEFAULT_API_BASE_URL,
        last_activity: None,
    }
}

fn midnight() -> OffsetDateTime {
    OffsetDateTime::parse("2026-07-21T00:00:00Z", &Rfc3339).unwrap()
}

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(60 * 60);

/// Drive the collector the way the supervisor does, on a fake clock from
/// `wall0`, for `horizon`: run a slice, then sleep until `next_wake`. With
/// `warm`, local Codex is active throughout.
fn drive(
    collector: &mut CloudCollector,
    inputs: &SliceInputs<'_>,
    t0: Instant,
    wall0: OffsetDateTime,
    horizon: Duration,
    warm: bool,
) -> Vec<(Duration, CloudSessionCycleOutcome)> {
    let mut offset = Duration::ZERO;
    let mut outcomes = Vec::new();
    while offset < horizon {
        let now = t0 + offset;
        let wall = wall0 + offset;
        let last_activity = warm.then_some(now);
        let slice = SliceInputs {
            last_activity,
            ..*inputs
        };
        outcomes.push((offset, collector.run_slice(&slice, now, wall)));
        let Some(next) = collector.next_wake(now, wall, last_activity) else {
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

/// [behaviour] 24 hours from 00:00 UTC on a fake clock: no consent, a pause
/// or an older server make no provider call; an idle account costs four
/// heads, active local Codex 48, a running head task 288. A deep unfinished
/// task does not speed up the head.
#[test]
fn a_day_of_provider_calls_follows_the_schedule() {
    let day = 24 * HOUR;
    let run = |name: &str,
               prepare: &dyn Fn(&CloudSessionGrantStore, &Server),
               pages: Vec<(Option<String>, String)>,
               warm: bool| {
        let (_root, grants, checkpoints) = stores(name);
        let server = Server::new();
        prepare(&grants, &server);
        let cli = Cli::new(pages);
        let mut collector = CloudCollector::default();
        drive(
            &mut collector,
            &inputs(&grants, &checkpoints, &cli, &server),
            Instant::now(),
            midnight(),
            day,
            warm,
        );
        (
            cli.calls(),
            server.authority_calls.get(),
            server.requests.borrow().len(),
        )
    };
    let one = || vec![(None, page("idle-task", None))];

    assert_eq!(run("day-no-consent", &|_, _| {}, one(), true), (0, 0, 0));
    assert_eq!(
        run(
            "day-paused",
            &|grants, _| {
                enabled(grants);
                grants.pause(now()).unwrap();
            },
            one(),
            true
        ),
        (0, 0, 0)
    );
    assert_eq!(
        run(
            "day-older-server",
            &|grants, server| {
                enabled(grants);
                server.authority.set(Authority::Missing);
            },
            one(),
            true
        ),
        (0, 4, 0)
    );
    assert_eq!(
        run(
            "day-remote-pause",
            &|grants, server| {
                enabled(grants);
                server.authority.set(Authority::Paused);
            },
            one(),
            false
        ),
        (0, 4, 0)
    );
    assert_eq!(
        run("day-idle", &|grants, _| enabled(grants), one(), false),
        (4, 4, 1)
    );
    assert_eq!(
        run("day-active", &|grants, _| enabled(grants), one(), true),
        (48, 48, 1)
    );
    assert_eq!(
        run(
            "day-running",
            &|grants, _| enabled(grants),
            vec![(None, page_of(vec![task("running-task", "running")], None))],
            false
        ),
        (288, 288, 1)
    );
    assert_eq!(
        run(
            "day-deep-unknown",
            &|grants, _| enabled(grants),
            vec![
                (None, page("head-task", Some("c1"))),
                (
                    Some("c1".to_string()),
                    page_of(vec![task("deep-task", "pending")], None)
                ),
            ],
            false
        ),
        (5, 4, 2)
    );
}

/// [behaviour] A deep crawl is paced, not truncated: ten pages per slice,
/// continuing five minutes later where it stopped.
#[test]
fn daily_crawl_takes_ten_pages_then_continues_five_minutes_later() {
    let (_root, grants, checkpoints) = stores("crawl-paced");
    enabled(&grants);
    let cli = Cli::new(chain(18, 1, "applied"));
    let server = Server::new();
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let mut collector = CloudCollector::default();
    let t0 = Instant::now();

    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(cli.calls(), 10);
    assert_eq!(
        collector.next_wake(t0, midnight(), None),
        Some(t0 + 5 * MINUTE)
    );
    assert_eq!(
        slice(&mut collector, &inputs, t0, 5 * MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );
    let expected = std::iter::once(None)
        .chain((1..18).map(|index| Some(format!("c{index}"))))
        .collect::<Vec<_>>();
    assert_eq!(*cli.calls.borrow(), expected);
    assert_eq!(server.offered(), 18);
    assert_eq!(server.authority_calls.get(), 2);
    assert_eq!(collector.schedule.crawl_completed, Some(midnight().date()));
    // The crawl is done for the day; only the idle head remains.
    assert_eq!(
        collector.next_wake(t0 + 5 * MINUTE, midnight() + 5 * MINUTE, None),
        Some(t0 + 6 * HOUR)
    );
}

/// [regress] More than 100 pages and 2,000 tasks: the crawl reaches the
/// tail and every task is offered exactly once.
#[test]
fn crawl_beyond_one_hundred_pages_and_two_thousand_tasks_reaches_the_tail() {
    let (_root, grants, checkpoints) = stores("crawl-deep");
    enabled(&grants);
    let cli = Cli::new(chain(120, PAGE_LIMIT, "applied"));
    let server = Server::new();
    let mut collector = CloudCollector::default();
    drive(
        &mut collector,
        &inputs(&grants, &checkpoints, &cli, &server),
        Instant::now(),
        midnight(),
        2 * HOUR,
        false,
    );
    assert_eq!(cli.calls(), 120);
    let keys = server
        .requests
        .borrow()
        .iter()
        .flat_map(|request| {
            request
                .observations
                .iter()
                .map(|change| change.entity_key.clone())
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
fn crawl_survives_midnight_and_a_restart_reoffers_nothing_settled() {
    let (_root, grants, checkpoints) = stores("crawl-midnight");
    enabled(&grants);
    let cli = Cli::new(chain(18, 1, "applied"));
    let server = Server::new();
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let late = OffsetDateTime::parse("2026-07-21T23:55:00Z", &Rfc3339).unwrap();
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    collector.run_slice(&inputs, t0, late);
    assert_eq!(cli.calls(), 10);
    collector.run_slice(&inputs, t0 + 5 * MINUTE, late + 5 * MINUTE);
    assert_eq!(cli.calls(), 18);
    assert_eq!(cli.calls.borrow()[10].as_deref(), Some("c10"));
    let next_day = (late + 5 * MINUTE).date();
    assert_eq!(collector.schedule.crawl_completed, Some(next_day));

    // Restart: the persisted completion day holds; only a head runs.
    let mut restarted = CloudCollector::default();
    assert_eq!(
        restarted.run_slice(&inputs, t0 + 10 * MINUTE, late + 10 * MINUTE),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(cli.calls(), 19);
    assert_eq!(server.offered(), 18);

    // A restart mid-crawl starts a new crawl from the head; settled pages
    // are listed again but nothing settled is offered again.
    let (_root, grants, checkpoints) = stores("crawl-restart");
    enabled(&grants);
    let cli = Cli::new(chain(18, 1, "applied"));
    let server = Server::new();
    let inputs = SliceInputs {
        grants: &grants,
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
        false,
    );
    assert_eq!(cli.calls(), 10 + 18);
    assert_eq!(server.offered(), 18);
    assert!(server
        .outcomes()
        .iter()
        .all(|outcome| *outcome == CloudSessionChangeOutcome::Accepted));
}

/// [regress] A cursor chain that loops ends the day's traversal without
/// claiming completion and without repeating it.
#[test]
fn cycling_cursor_chain_ends_the_day_without_completion() {
    let (_root, grants, checkpoints) = stores("crawl-cycle");
    enabled(&grants);
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
        &inputs(&grants, &checkpoints, &cli, &server),
        Instant::now(),
        midnight(),
        24 * HOUR,
        false,
    );
    // One bounded traversal, then the three remaining idle heads.
    assert!(cli.calls() <= MAX_SLICE_PAGES + 3, "{}", cli.calls());
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
// ACK cache. [behaviour]

/// [behaviour] An unchanged task is never uploaded again, and an unchanged
/// poll never rewrites its entry: the 30-day expiry still counts from the
/// exact ACK, after which the task is offered once and answered noop.
#[test]
fn unchanged_tasks_are_not_uploaded_or_rewritten() {
    let (_root, grants, checkpoints) = stores("cache-noop");
    enabled(&grants);
    let cli = Cli::head(page_of(
        vec![
            task("a", "applied"),
            task("b", "error"),
            task("c", "applied"),
        ],
        None,
    ));
    let server = Server::new();
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    let day = 24 * HOUR;
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Uploaded
    );
    let grant = grants.load().unwrap().unwrap();
    let scope = cache_scope(
        DEFAULT_API_BASE_URL,
        &grant,
        grant.backend_binding.as_ref().unwrap(),
    );
    let keys = server.requests.borrow()[0]
        .observations
        .iter()
        .map(|item| item.entity_key.clone())
        .collect::<Vec<_>>();
    let lookup = keys.iter().map(String::as_str).collect::<Vec<_>>();
    assert_eq!(
        checkpoints
            .read_acks(&scope, &lookup, midnight().unix_timestamp())
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
fn one_changed_sibling_is_the_only_task_offered() {
    let (_root, grants, checkpoints) = stores("cache-sibling");
    enabled(&grants);
    let cli = Cli::head(page_of(
        vec![
            task("a", "applied"),
            task("b", "running"),
            task("c", "applied"),
        ],
        None,
    ));
    let server = Server::new();
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
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
    assert_eq!(
        second.observations[0].entity_key,
        first.observations[1].entity_key
    );
    assert_eq!(second.observations[0].lifecycle, "completed");
    assert_eq!(
        second.observations[0].expected_head_etag.as_deref(),
        Some(server_etag(&first.observations[1]).as_str())
    );
    assert_eq!(server.outcomes()[3], CloudSessionChangeOutcome::Accepted);
}

/// [behaviour] A lost response or a lost cache commit is resent and settles
/// as noop; nothing is double-counted and the cache then holds.
#[test]
fn lost_ack_or_lost_commit_is_resent_and_settles_noop() {
    let (_root, grants, checkpoints) = stores("cache-lost-ack");
    enabled(&grants);
    let cli = Cli::head(page("lost-ack", None));
    let server = Server::new();
    server.lose_acks.set(1);
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Failed
    );
    assert_eq!(
        grants
            .load()
            .unwrap()
            .unwrap()
            .last_error_category
            .as_deref(),
        Some("transport_unavailable")
    );
    // The backoff, not the idle cadence, decides the retry.
    let retry = collector.next_wake(t0, midnight(), None).unwrap();
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

    // A cache that lost its commit forgets; the server answers noop again.
    checkpoints.erase_cache().unwrap();
    assert_eq!(
        slice(&mut collector, &inputs, t0, offset + 12 * HOUR),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(
        server.outcomes(),
        [
            CloudSessionChangeOutcome::Noop,
            CloudSessionChangeOutcome::Noop
        ]
    );
    assert_eq!(server.heads.borrow().len(), 1);
}

/// [regress] An ACK that misses, invents or under-specifies a task settles
/// nothing; the next attempt offers the same tasks again.
#[test]
fn partial_or_malformed_ack_settles_nothing() {
    for fault in [AckFault::DropOne, AckFault::NoEtag, AckFault::Unsolicited] {
        let (_root, grants, checkpoints) = stores("cache-bad-ack");
        enabled(&grants);
        let cli = Cli::head(page_of(
            vec![task("a", "applied"), task("b", "applied")],
            None,
        ));
        let server = Server::new();
        server.fault.set(Some(fault));
        let inputs = inputs(&grants, &checkpoints, &cli, &server);
        let t0 = Instant::now();
        let mut collector = CloudCollector::default();
        assert_eq!(
            slice(&mut collector, &inputs, t0, Duration::ZERO),
            CloudSessionCycleOutcome::Failed,
            "{fault:?}"
        );
        let offset = collector
            .next_wake(t0, midnight(), None)
            .unwrap()
            .saturating_duration_since(t0);
        slice(&mut collector, &inputs, t0, offset);
        let requests = server.requests.borrow();
        assert_eq!(requests.len(), 2, "{fault:?}");
        assert_eq!(requests[1].observations.len(), 2, "{fault:?}");
    }
}

/// [behaviour] A per-task refusal is remembered for exactly that content, so
/// it is not offered again until the task changes.
#[test]
fn rejected_task_is_not_reoffered_until_it_changes() {
    let (_root, grants, checkpoints) = stores("cache-rejected");
    enabled(&grants);
    let cli = Cli::head(page("refused", None));
    let server = Server::new();
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let parsed = parse_cloud_page(&page("refused", None), &grant_key(&grants), midnight()).unwrap();
    server
        .reject
        .borrow_mut()
        .push(parsed.changes[0].entity_key.clone());
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

fn grant_key(grants: &CloudSessionGrantStore) -> Vec<u8> {
    decode_hex(&grants.read().unwrap().unwrap().hmac_key_hex).unwrap()
}

/// [behaviour] A conflict re-lists the same page once and retries with the
/// server's head as the predecessor.
#[test]
fn conflict_relists_once_and_retries_with_the_server_head() {
    let (_root, grants, checkpoints) = stores("conflict");
    enabled(&grants);
    let cli = Cli::head(page_of(vec![task("conflict", "running")], None));
    let server = Server::new();
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    slice(&mut collector, &inputs, t0, Duration::ZERO);
    let head = server.heads.borrow().values().next().unwrap().clone();
    // The cache is lost and the task moved on: the offer has no predecessor.
    checkpoints.erase_cache().unwrap();
    cli.set(None, page_of(vec![task("conflict", "applied")], None));
    assert_eq!(
        slice(&mut collector, &inputs, t0, 5 * MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(cli.calls(), 3);
    let requests = server.requests.borrow();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].observations[0].expected_head_etag, None);
    assert_eq!(
        requests[2].observations[0].expected_head_etag.as_deref(),
        Some(head.as_str())
    );
    assert_eq!(
        server.outcomes()[1..],
        [
            CloudSessionChangeOutcome::Conflict,
            CloudSessionChangeOutcome::Accepted
        ]
    );
    // Settled: the next head offers nothing.
    drop(requests);
    assert_eq!(
        slice(&mut collector, &inputs, t0, 7 * HOUR),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(server.requests.borrow().len(), 3);
}

/// [behaviour] After an erasure the server's cutoff applies: only tasks the
/// provider created after it are offered.
#[test]
fn erasure_cutoff_filters_older_and_undated_tasks() {
    let (_root, grants, checkpoints) = stores("cutoff");
    enabled(&grants);
    let mut newer = task("newer", "applied");
    newer["created_at"] = json!("2026-07-20T13:00:00Z");
    let mut undated = task("undated", "applied");
    undated.as_object_mut().unwrap().remove("created_at");
    let cli = Cli::head(page_of(
        vec![task("older", "applied"), newer, undated],
        None,
    ));
    let server = Server::new();
    *server.collect_not_before.borrow_mut() = Some("2026-07-20T12:00:00Z".to_string());
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let mut collector = CloudCollector::default();
    slice(&mut collector, &inputs, Instant::now(), Duration::ZERO);
    let requests = server.requests.borrow();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].observations.len(), 1);
    assert_eq!(
        requests[0].observations[0].created_at.as_deref(),
        Some("2026-07-20T13:00:00Z")
    );
}

// ---------------------------------------------------------------------------
// Consent, authority and older servers. [behaviour]

/// [behaviour] A remote revoke revokes locally, erases the cache and stops
/// all provider calls; a local revoke stops them before any call.
#[test]
fn revoke_erases_the_cache_and_stops_collection() {
    let (_root, grants, checkpoints) = stores("revoke-remote");
    enabled(&grants);
    let cli = Cli::head(page("revoked", None));
    let server = Server::new();
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    slice(&mut collector, &inputs, t0, Duration::ZERO);
    let scope = collector.schedule.scope.unwrap();
    let key = server.requests.borrow()[0].observations[0]
        .entity_key
        .clone();
    assert_eq!(
        checkpoints
            .read_acks(&scope, &[key.as_str()], midnight().unix_timestamp())
            .unwrap()
            .len(),
        1
    );
    server.authority.set(Authority::Revoked);
    assert_eq!(
        slice(&mut collector, &inputs, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!(cli.calls(), 1);
    assert_eq!(
        grants.load().unwrap().unwrap().status,
        CloudSessionGrantStatus::Revoked
    );
    assert!(checkpoints
        .read_acks(&scope, &[key.as_str()], midnight().unix_timestamp())
        .unwrap()
        .is_empty());
    assert_eq!(collector.next_wake(t0 + 6 * HOUR, midnight(), None), None);
    assert_eq!(
        slice(&mut collector, &inputs, t0, 12 * HOUR),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!(server.authority_calls.get(), 2);

    let (_root, grants, checkpoints) = stores("revoke-local");
    enabled(&grants);
    grants.revoke(now()).unwrap();
    checkpoints.erase_cache().unwrap();
    let cli = Cli::head(page("revoked", None));
    let server = Server::new();
    let mut collector = CloudCollector::default();
    assert_eq!(
        collector.run_slice(
            &SliceInputs {
                grants: &grants,
                checkpoints: &checkpoints,
                runner: &cli,
                transport: &server,
                destination: DEFAULT_API_BASE_URL,
                last_activity: None,
            },
            t0,
            midnight()
        ),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!((cli.calls(), server.authority_calls.get()), (0, 0));
}

/// [behaviour] An older server without this contract: the feature is absent,
/// the collector is idle and quiet, and a local consent change rechecks now.
#[test]
fn older_server_leaves_the_collector_idle_without_errors() {
    let (_root, grants, checkpoints) = stores("older-server");
    enabled(&grants);
    let cli = Cli::head(page("never-listed", None));
    let server = Server::new();
    server.authority.set(Authority::Missing);
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Unsupported
    );
    assert_eq!(cli.calls(), 0);
    assert!(server.requests.borrow().is_empty());
    assert_eq!(
        collector.next_wake(t0, midnight(), None),
        Some(t0 + 6 * HOUR)
    );
    let grant = grants.load().unwrap().unwrap();
    assert_eq!(grant.status, CloudSessionGrantStatus::Enabled);
    assert_ne!(grant.last_collector_health.as_deref(), Some("failing"));
    collector.reset();
    assert_eq!(collector.next_wake(t0, midnight(), None), None);
    server.authority.set(Authority::Enabled);
    assert_eq!(
        slice(&mut collector, &inputs, t0, MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );

    // A grant response on another contract is equally unsupported.
    let (_root, grants, checkpoints) = stores("older-contract");
    enabled(&grants);
    struct OldContract(Server);
    impl CloudSessionTransport for OldContract {
        fn read_authority(
            &self,
            grant: &CloudSessionGrant,
            timeout: Duration,
        ) -> Result<CloudSessionGrantAuthorityV1> {
            let mut response = self.0.read_authority(grant, timeout)?;
            response.contract_version = "cloud_session_observations.v1".to_string();
            Ok(response)
        }
        fn send_changes(
            &self,
            request: &CloudSessionChangesV1,
            timeout: Duration,
        ) -> Result<CloudSessionChangesAckV1> {
            self.0.send_changes(request, timeout)
        }
    }
    let old = OldContract(Server::new());
    let cli = Cli::head(page("never-listed", None));
    let mut collector = CloudCollector::default();
    assert_eq!(
        collector.run_slice(
            &SliceInputs {
                grants: &grants,
                checkpoints: &checkpoints,
                runner: &cli,
                transport: &old,
                destination: DEFAULT_API_BASE_URL,
                last_activity: None,
            },
            t0,
            midnight()
        ),
        CloudSessionCycleOutcome::Unsupported
    );
    assert_eq!(cli.calls(), 0);
}

/// [behaviour] A remote pause or policy-disabled answer stops provider calls
/// without touching local consent; an enabled answer resumes collection.
#[test]
fn remote_pause_gates_collection_until_enabled_again() {
    let (_root, grants, checkpoints) = stores("remote-pause");
    enabled(&grants);
    let cli = Cli::head(page("paused", None));
    let server = Server::new();
    server.authority.set(Authority::Paused);
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Unsupported
    );
    assert_eq!(cli.calls(), 0);
    assert_eq!(
        grants.load().unwrap().unwrap().status,
        CloudSessionGrantStatus::PolicyDisabled
    );
    server.authority.set(Authority::Enabled);
    assert_eq!(
        slice(&mut collector, &inputs, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(
        grants.load().unwrap().unwrap().status,
        CloudSessionGrantStatus::Enabled
    );
}

/// [behaviour] Cloud failures back off on their own clock; nothing of the
/// local delivery path (receipts, local backoff) is touched.
#[test]
fn cloud_collection_is_isolated_from_local_delivery() {
    let (root, grants, checkpoints) = stores("isolation");
    enabled(&grants);
    let cli = Cli::head(page("isolated", None));
    let server = Server::new();
    server.authority.set(Authority::Offline);
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Failed
    );
    assert_eq!(cli.calls(), 0);
    assert!(collector.schedule.retry_not_before.is_some());
    server.authority.set(Authority::Enabled);
    let offset = collector
        .next_wake(t0, midnight(), None)
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
/// failure, never an empty healthy page.
#[test]
fn nonempty_page_without_a_valid_task_is_a_provider_failure() {
    let (_root, grants, checkpoints) = stores("invalid-page");
    enabled(&grants);
    let cli = Cli::head(json!({"tasks": [{"status": "running"}, 42], "cursor": null}).to_string());
    let server = Server::new();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(
            &mut collector,
            &inputs(&grants, &checkpoints, &cli, &server),
            Instant::now(),
            Duration::ZERO
        ),
        CloudSessionCycleOutcome::Failed
    );
    assert!(server.requests.borrow().is_empty());
    let grant = grants.load().unwrap().unwrap();
    assert_eq!(grant.last_collector_health.as_deref(), Some("failing"));
    assert_eq!(
        grant.last_error_category.as_deref(),
        Some("provider_payload_invalid")
    );
}

#[test]
fn deferred_transport_never_calls_the_provider() {
    let (_root, grants, checkpoints) = stores("deferred");
    enabled(&grants);
    let cli = Cli::head(page("deferred", None));
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(
            &mut collector,
            &inputs(&grants, &checkpoints, &cli, &DeferredCloudSessionTransport),
            Instant::now(),
            Duration::ZERO
        ),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!(cli.calls(), 0);
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

    let (_root, grants, checkpoints) = stores("provider-call-fence");
    enabled(&grants);
    let checkpoints = Arc::new(checkpoints);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let collector_grants = grants.clone();
    let collector_checkpoints = Arc::clone(&checkpoints);
    let run = thread::spawn(move || {
        let server = Server::new();
        let runner = BlockingRunner {
            entered: entered_tx,
            release: release_rx,
        };
        let outcome = CloudCollector::default().run_slice(
            &inputs(&collector_grants, &collector_checkpoints, &runner, &server),
            Instant::now(),
            midnight(),
        );
        (outcome, server.requests.borrow().len())
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
    // The page that was in flight is never uploaded.
    assert_eq!(run.join().unwrap(), (CloudSessionCycleOutcome::Disabled, 0));
}

#[test]
fn revocation_at_relay_admission_stops_the_upload() {
    let (_root, grants, checkpoints) = stores("relay-admission-race");
    enabled(&grants);
    let checkpoints = Arc::new(checkpoints);
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    checkpoints.set_relay_admission_barrier_for_test(0, Arc::clone(&entered), Arc::clone(&release));
    let collector_grants = grants.clone();
    let collector_checkpoints = Arc::clone(&checkpoints);
    let run = thread::spawn(move || {
        let server = Server::new();
        let cli = Cli::head(page("admission-race", None));
        let outcome = CloudCollector::default().run_slice(
            &inputs(&collector_grants, &collector_checkpoints, &cli, &server),
            Instant::now(),
            midnight(),
        );
        (outcome, server.requests.borrow().len())
    });
    entered.wait();
    grants.revoke(now()).unwrap();
    release.wait();
    assert_eq!(run.join().unwrap(), (CloudSessionCycleOutcome::Disabled, 0));
}

// ---------------------------------------------------------------------------
// Wire format. [format]

/// [format] The digest vector the server and other clients can reproduce:
/// SHA-256 over the domain, a zero byte and sorted compact JSON. The
/// predecessor etag is not part of it.
#[test]
fn semantic_digest_vector_is_stable_and_excludes_the_predecessor() {
    let mut change = CloudSessionChangeV1 {
        entity_key: format!("hmac-sha256:{}", "ab".repeat(32)),
        expected_head_etag: None,
        entity_kind: "task".to_string(),
        lifecycle: "completed".to_string(),
        attempt_count: Some(2),
        environment_kind: "unknown".to_string(),
        measurement_basis: "not_itemized".to_string(),
        coverage: ["attempts", "identity", "status", "timing"]
            .map(str::to_string)
            .to_vec(),
        created_at: Some("2026-07-20T11:00:00Z".to_string()),
        started_at: None,
        updated_at: Some("2026-07-20T11:30:00Z".to_string()),
        completed_at: None,
    };
    assert_eq!(
        hex(&change.semantic_digest()),
        "2118614c9f001c46ad16b9be2426e59f2121a4e65332c9fde3fb58877d2311e8"
    );
    let base = change.semantic_digest();
    change.expected_head_etag = Some("0".repeat(64));
    assert_eq!(change.semantic_digest(), base);
    change.lifecycle = "failed".to_string();
    assert_ne!(change.semantic_digest(), base);
    // The predecessor is always serialized, as null when unknown.
    change.expected_head_etag = None;
    assert!(serde_json::to_string(&change)
        .unwrap()
        .contains("\"expected_head_etag\":null"));
}

#[test]
fn emitted_wire_is_content_free_and_opaque() {
    let parsed = parse_cloud_page(
        &page("provider-task-123", Some("private-cursor")),
        b"fixture-key",
        now(),
    )
    .unwrap();
    let encoded = serde_json::to_string(&parsed.changes).unwrap();
    for private in [
        "provider-task-123",
        "private title",
        "chatgpt.com",
        "private-cursor",
        "provider-environment-private",
        "Private environment",
        "private summary",
    ] {
        assert!(!encoded.contains(private), "{private}");
    }
    assert!(encoded.contains("hmac-sha256:"));
}

/// [format] Requests validate strictly; a raw or uppercase key, an open
/// lifecycle, unsorted coverage or an oversize batch is refused before I/O.
#[test]
fn changes_request_rejects_raw_keys_open_values_and_oversize_batches() {
    let (_root, grants, checkpoints) = stores("wire-validate");
    enabled(&grants);
    let cli = Cli::head(page("raw-provider-id", None));
    let server = Server::new();
    let mut collector = CloudCollector::default();
    slice(
        &mut collector,
        &inputs(&grants, &checkpoints, &cli, &server),
        Instant::now(),
        Duration::ZERO,
    );
    let request = server.requests.borrow()[0].clone();
    assert!(request.validate().is_ok());
    assert_eq!(request.schema_version, "cloud_session_changes.v1");
    assert_eq!(request.collector_id, "cloud_sessions");
    let wire = serde_json::to_string(&request).unwrap();
    assert!(!wire.contains("raw-provider-id"));
    assert!(!wire.contains("semantic_digest"));

    let mutate = |change: &dyn Fn(&mut CloudSessionChangesV1)| {
        let mut bad = request.clone();
        change(&mut bad);
        bad.validate().is_err()
    };
    assert!(mutate(
        &|bad| bad.observations[0].entity_key = "raw-provider-id".to_string()
    ));
    assert!(mutate(&|bad| {
        bad.observations[0].entity_key = format!("hmac-sha256:{}", "A".repeat(64))
    }));
    assert!(mutate(
        &|bad| bad.observations[0].lifecycle = "future_state".to_string()
    ));
    assert!(mutate(&|bad| bad.observations[0].coverage.reverse()));
    assert!(mutate(
        &|bad| bad.observations[0].expected_head_etag = Some("x".to_string())
    ));
    assert!(mutate(&|bad| bad.observations.clear()));
    assert!(mutate(&|bad| {
        let first = bad.observations[0].clone();
        bad.observations.push(first);
    }));
    assert!(mutate(&|bad| {
        bad.observations = (0..=MAX_CHANGES_PER_REQUEST)
            .map(|index| {
                let mut change = request.observations[0].clone();
                change.entity_key = format!("hmac-sha256:{index:064x}");
                change
            })
            .collect();
    }));
}

/// [format] ACK matching: refused and conflicting entries are distinct, and
/// a wrong epoch, duplicate or unsolicited entry settles nothing.
#[test]
fn ack_matching_is_exact() {
    let change = |key: char| CloudSessionChangeV1 {
        entity_key: format!("hmac-sha256:{}", key.to_string().repeat(64)),
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
    };
    let request = CloudSessionChangesV1 {
        schema_version: CHANGES_SCHEMA_VERSION.to_string(),
        grant_id: GRANT_ID.to_string(),
        grant_version: 3,
        grant_scope_fingerprint: format!("hmac-sha256:{}", "1".repeat(64)),
        account_fingerprint: format!("hmac-sha256:{}", "2".repeat(64)),
        collector_id: COLLECTOR_ID.to_string(),
        collector_version: "0.0.0".to_string(),
        collected_at: "2026-07-21T00:00:00Z".to_string(),
        observations: vec![change('a'), change('b'), change('c')],
    };
    assert!(request.validate().is_ok());
    let entry = |key: char, outcome, etag: Option<char>| CloudSessionChangeAckV1 {
        entity_key: format!("hmac-sha256:{}", key.to_string().repeat(64)),
        outcome,
        head_etag: etag.map(|etag| etag.to_string().repeat(64)),
        accepted_seq: None,
        reason: None,
    };
    let ack = |entities| CloudSessionChangesAckV1 {
        schema_version: "cloud_session_changes_ack.v1".to_string(),
        grant_id: GRANT_ID.to_uppercase(),
        grant_version: 3,
        entities,
    };
    let settled = request
        .settle(&ack(vec![
            entry('c', CloudSessionChangeOutcome::Conflict, Some('e')),
            entry('a', CloudSessionChangeOutcome::Accepted, Some('d')),
            entry('b', CloudSessionChangeOutcome::Rejected, None),
        ]))
        .unwrap();
    assert_eq!(
        settled.values().cloned().collect::<Vec<_>>(),
        [
            Settled::Acked {
                head_etag: "d".repeat(64)
            },
            Settled::Refused,
            Settled::Conflict {
                head_etag: Some("e".repeat(64))
            },
        ]
    );
    let good = || {
        vec![
            entry('a', CloudSessionChangeOutcome::Noop, Some('d')),
            entry('b', CloudSessionChangeOutcome::Noop, Some('d')),
            entry('c', CloudSessionChangeOutcome::Noop, Some('d')),
        ]
    };
    let mut wrong_epoch = ack(good());
    wrong_epoch.grant_version = 2;
    assert!(request.settle(&wrong_epoch).is_err());
    let mut wrong_schema = ack(good());
    wrong_schema.schema_version = "cloud_session_changes_ack.v2".to_string();
    assert!(request.settle(&wrong_schema).is_err());
    let mut duplicate = good();
    duplicate[2] = entry('a', CloudSessionChangeOutcome::Noop, Some('d'));
    assert!(request.settle(&ack(duplicate)).is_err());
    let mut unsolicited = good();
    unsolicited[2] = entry('f', CloudSessionChangeOutcome::Noop, Some('d'));
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
    let parsed = parse_cloud_page(&page_of(tasks, None), b"fixture-key", now()).unwrap();
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
    let parsed = parse_cloud_page(&page_of(rows, None), b"fixture-key", now()).unwrap();
    assert_eq!(parsed.source_item_count, PAGE_LIMIT + 8);
    assert_eq!(parsed.changes.len(), PAGE_LIMIT + 7);
    let offset = &parsed.changes[PAGE_LIMIT + 5];
    assert_eq!(offset.updated_at.as_deref(), Some("2026-07-20T11:30:00Z"));
    let future = &parsed.changes[PAGE_LIMIT + 6];
    assert_eq!(future.created_at, None);
}

#[test]
fn cursor_contract_separates_official_terminal_pagination_and_ambiguity() {
    let cursor = |raw: Value| parse_cloud_page(&raw.to_string(), b"fixture-key", now());
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

// ---------------------------------------------------------------------------
// Grants.

#[test]
fn persisted_grant_discards_raw_scope_and_uses_private_atomic_state() {
    let (_root, grants, _checkpoints) = stores("private-grant-state");
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
    }
}

#[test]
fn legacy_v1_grant_is_privately_migrated_and_remains_revocable() {
    let (_root, grants, _checkpoints) = stores("legacy-grant-migration");
    fs::create_dir_all(grants.path().parent().unwrap()).unwrap();
    let legacy = json!({
        "schema_version": GRANT_SCHEMA_VERSION,
        "hmac_key_hex": "11".repeat(32),
        "grant": {
            "schema_version": GRANT_SCHEMA_VERSION,
            "collector_id": COLLECTOR_ID,
            "collector_version": "cloud_session_observations.v1",
            "release_lane": "supported",
            "disclosure_version": DISCLOSURE_VERSION,
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

/// [regress] A grant bound before this contract does not collect; consent
/// on the new grants API re-binds the same epoch onto it.
#[test]
fn grant_bound_on_the_previous_contract_needs_fresh_consent() {
    let (_root, grants, checkpoints) = stores("contract-upgrade");
    enabled(&grants);
    let mut state = grants.read().unwrap().unwrap();
    state
        .grant
        .backend_binding
        .as_mut()
        .unwrap()
        .collection_contract = None;
    grants.write(&state).unwrap();
    assert_eq!(
        cloud_session_collector_status(&grants, &RuntimeAvailabilityTransport(true)).grant_status,
        CloudSessionGrantStatus::ConsentRequired
    );
    let cli = Cli::head(page("upgrade", None));
    let server = Server::new();
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    slice(&mut collector, &inputs, t0, Duration::ZERO);
    assert_eq!(cli.calls(), 0);

    let local = grants.enable(&setup(), now()).unwrap();
    assert_eq!(local.status, CloudSessionGrantStatus::ConsentRequired);
    let create = grants.grant_create_request(INSTALLATION_ID).unwrap();
    assert_eq!(create.schema_version, "cloud_session_changes.v1");
    let bound = grants
        .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
        .unwrap();
    assert_eq!(bound.status, CloudSessionGrantStatus::Enabled);
    assert!(binding_contract_current(&bound));
    collector.reset();
    assert_eq!(
        slice(&mut collector, &inputs, t0, MINUTE),
        CloudSessionCycleOutcome::Uploaded
    );
}

#[test]
fn backend_binding_requires_exact_scope_and_monotonic_reconsent_epoch() {
    let (_root, grants, checkpoints) = stores("grant-epoch");
    let local = grants.enable(&setup(), now()).unwrap();
    assert_eq!(local.status, CloudSessionGrantStatus::ConsentRequired);
    assert_eq!(local.granted_at, None);
    assert!(grants
        .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
        .is_err());
    let request = grants.grant_create_request(INSTALLATION_ID).unwrap();
    assert_eq!(request.grant_scope_fingerprint, local.grant_scope_id);
    assert_eq!(request.schema_version, CHANGES_SCHEMA_VERSION);
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
        .bind_backend_grant(&wrong_installation, "00000000-0000-4000-8000-000000000099")
        .is_err());
    let mut wrong_contract = backend_grant(&local, "enabled", 1);
    wrong_contract.schema_version = "cloud_session_observations.v1".to_string();
    assert!(grants
        .bind_backend_grant(&wrong_contract, INSTALLATION_ID)
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
    different_policy.can_collect = Some(false);
    assert_eq!(
        grants
            .bind_backend_grant(&different_policy, INSTALLATION_ID)
            .unwrap(),
        first_bound
    );
    assert_eq!(fs::read(grants.path()).unwrap(), bound_bytes);

    let cli = Cli::head(page("one", None));
    let server = Server::new();
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    slice(
        &mut collector,
        &inputs(&grants, &checkpoints, &cli, &server),
        t0,
        Duration::ZERO,
    );
    grants.revoke(now()).unwrap();
    grants
        .apply_backend_revocation(&backend_grant(&local, "revoked", 2), INSTALLATION_ID)
        .unwrap();
    let pending = grants.enable(&setup(), now()).unwrap();
    assert_eq!(pending.status, CloudSessionGrantStatus::ConsentRequired);
    grants.grant_create_request(INSTALLATION_ID).unwrap();
    assert!(grants
        .bind_backend_grant(&backend_grant(&local, "enabled", 1), INSTALLATION_ID)
        .is_err());
    grants
        .bind_backend_grant(&backend_grant(&local, "enabled", 3), INSTALLATION_ID)
        .unwrap();
    collector.reset();
    slice(
        &mut collector,
        &inputs(&grants, &checkpoints, &cli, &server),
        t0,
        MINUTE,
    );
    let requests = server.requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].grant_version, 1);
    // A new epoch is a new cache scope: the same task is offered again.
    assert_eq!(requests[1].grant_version, 3);
    assert_eq!(requests[1].observations.len(), 1);
}

#[test]
fn ambiguous_backend_create_retries_exact_request_until_late_grant_is_deleted() {
    let (_root, grants, _checkpoints) = stores("bind-create-reconcile");
    let local = grants.enable(&setup(), now()).unwrap();
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
fn health_update_cannot_restore_a_revoked_grant() {
    let (_root, grants, _checkpoints) = stores("grant-lock");
    enabled(&grants);
    grants.revoke(now()).unwrap();
    grants.record_health("ok", "fresh", None).unwrap();
    let grant = grants.load().unwrap().unwrap();
    assert_eq!(grant.status, CloudSessionGrantStatus::Revoked);
    assert_eq!(grant.last_collector_health.as_deref(), Some("revoked"));
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

/// [behaviour] No consent touches nothing beyond the local grant read: no
/// credentials, relay, provider call or cache file.
#[test]
fn no_grant_is_zero_touch_and_later_consent_activates_without_restart() {
    let (root, grants, checkpoints) = stores("runtime-consent");
    let (accounts, devices, connections) =
        runtime_identity_stores(&root, "user_fixture", "org_fixture", DEFAULT_API_BASE_URL);
    let cli = Cli::head(page("after-consent", None));
    let mut collector = CloudCollector::default();
    let mut active_transport: ActiveCloudSessionTransport = None;
    let t0 = Instant::now();
    assert_eq!(
        collect_composed_cloud_sessions_once_with(
            &mut collector,
            &mut active_transport,
            ComposedSliceInputs {
                grants: &grants,
                checkpoints: &checkpoints,
                runner: &cli,
                accounts: &accounts,
                devices: &devices,
                connections: &connections,
                load_credentials: || panic!("no grant must not read relay credentials"),
                compose_transport: |_, _, _| panic!("no grant must not compose a relay"),
                last_activity: None,
            },
            t0,
            midnight(),
        ),
        CloudSessionCycleOutcome::Disabled
    );
    assert_eq!(cli.calls(), 0);
    assert!(active_transport.is_none());
    assert!(!grants.path().exists());
    assert!(!root.join("snapshots").exists());
    assert_eq!(collector.next_wake(t0, midnight(), None), None);

    enabled(&grants);
    let compositions = Cell::new(0);
    assert_eq!(
        collect_composed_cloud_sessions_once_with(
            &mut collector,
            &mut active_transport,
            ComposedSliceInputs {
                grants: &grants,
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
                compose_transport: |_, _, _| {
                    compositions.set(compositions.get() + 1);
                    Box::new(Server::new()) as Box<dyn CloudSessionTransport + Send>
                },
                last_activity: None,
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

#[test]
fn runtime_rejects_untrusted_destination_without_mutating_grant() {
    let (root, grants, _checkpoints) = stores("runtime-untrusted-destination");
    enabled(&grants);
    let (accounts, devices, connections) = runtime_identity_stores(
        &root,
        "user_fixture",
        "org_fixture",
        "https://attacker.example",
    );
    let before_grant = fs::read(grants.path()).unwrap();
    assert!(
        load_cloud_session_runtime_binding(&grants, &accounts, &devices, &connections).is_err()
    );
    assert_eq!(fs::read(grants.path()).unwrap(), before_grant);
    assert!(validated_cloud_session_api_base_url("http://localhost.evil").is_err());
    assert!(validated_cloud_session_api_base_url("https://api.ottto.net@evil").is_err());
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

/// [format] The relay uses the exact authority and changes routes, sends
/// the exact validated body, and retries it once after a 401 with a fresh
/// relay token. A 404 on the authority route reads as an older server.
#[test]
fn relay_uses_exact_routes_and_retries_the_exact_body_after_auth_refresh() {
    use std::io::Write;
    use std::net::TcpListener;

    let (_root, grants, checkpoints) = stores("relay-http");
    enabled(&grants);
    let cli = Cli::head(page("raw-provider-private-id", None));
    let fixture = Server::new();
    let mut collector = CloudCollector::default();
    slice(
        &mut collector,
        &inputs(&grants, &checkpoints, &cli, &fixture),
        Instant::now(),
        Duration::ZERO,
    );
    let request = fixture.requests.borrow()[0].clone();
    let grant = grants.load().unwrap().unwrap();
    let authority = serde_json::to_string(&authority(&grant, "enabled")).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let server_captured = Arc::clone(&captured);
    let server = thread::spawn(move || {
        let mut tokens = 0;
        let mut changes = 0;
        let mut authorities = 0;
        while changes < 2 || authorities < 2 {
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
            } else if request.contains("/authority?") {
                authorities += 1;
                if authorities == 1 {
                    ("200 OK", authority.clone())
                } else {
                    ("404 Not Found", r#"{"detail":"not found"}"#.to_string())
                }
            } else {
                changes += 1;
                if changes == 1 {
                    ("401 Unauthorized", r#"{"detail":"expired"}"#.to_string())
                } else {
                    let body: Value =
                        serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
                    let entities = body["observations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|change| {
                            json!({
                                "entity_key": change["entity_key"],
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
                            "schema_version": "cloud_session_changes_ack.v1",
                            "grant_id": body["grant_id"],
                            "grant_version": body["grant_version"],
                            "entities": entities
                        })
                        .to_string(),
                    )
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
        format!("http://{address}"),
        LocalDeviceBinding {
            device_id: INSTALLATION_ID.to_string(),
            machine_id: None,
            sources: vec!["codex".to_string()],
        },
        "device-secret".to_string(),
    );
    let response = relay
        .read_authority(&grant, Duration::from_secs(5))
        .unwrap();
    assert!(response.can_collect);
    assert_eq!(grants.apply_backend_authority(&response).unwrap(), grant);
    let ack = relay
        .send_changes(&request, Duration::from_secs(5))
        .unwrap();
    assert!(request.settle(&ack).is_ok());
    let missing = relay
        .read_authority(&grant, Duration::from_secs(5))
        .unwrap_err();
    assert!(missing
        .downcast_ref::<crate::snapshot_client::CloudSessionRouteUnsupported>()
        .is_some());
    server.join().unwrap();

    let requests = captured.lock().unwrap();
    let authority_line =
        format!("GET /api/v1/cloud-sessions/grants/{GRANT_ID}/authority?grant_version=1 HTTP/1.1");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with(&authority_line))
            .count(),
        2
    );
    let changes = requests
        .iter()
        .filter(|request| {
            request.starts_with("POST /api/v1/cloud-session-observations/changes HTTP/1.1")
        })
        .collect::<Vec<_>>();
    assert_eq!(changes.len(), 2);
    let bodies = changes
        .iter()
        .map(|request| request.split_once("\r\n\r\n").unwrap().1)
        .collect::<Vec<_>>();
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(
        serde_json::from_str::<CloudSessionChangesV1>(bodies[0]).unwrap(),
        request
    );
    for body in &bodies {
        assert!(!body.contains("raw-provider-private-id"));
        assert!(!body.contains("cursor"));
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

/// [regress] Upgrade preserves exact old pending creates, with or without
/// an explicit descriptor, and permits compensation without legacy collection.
#[test]
fn legacy_pending_create_survives_upgrade_until_compensating_revoke() {
    for descriptor in [true, false] {
        let (_root, grants, checkpoints) = stores("legacy-pending-create");
        let local = grants.enable(&setup(), now()).unwrap();
        grants.grant_create_request(INSTALLATION_ID).unwrap();
        let mut saved = grants.read().unwrap().unwrap();
        saved
            .grant
            .pending_backend_create
            .as_mut()
            .unwrap()
            .schema_version = LEGACY_COLLECTION_SCHEMA_VERSION.to_string();
        let old = saved.grant.pending_backend_create.clone().unwrap();
        if !descriptor {
            saved.grant.pending_backend_create = None;
        }
        grants.write(&saved).unwrap();
        let restarted = CloudSessionGrantStore::new(grants.path());
        assert!(restarted.enable(&setup(), now()).is_ok());
        let original = backend_create_request(INSTALLATION_ID, &old);
        assert_eq!(
            restarted.grant_create_request(INSTALLATION_ID).unwrap(),
            original
        );
        restarted.revoke(now()).unwrap();
        assert_eq!(
            restarted.grant_create_request(INSTALLATION_ID).unwrap(),
            original
        );
        let mut response = backend_grant(&local, "enabled", 1);
        response.schema_version = LEGACY_COLLECTION_SCHEMA_VERSION.to_string();
        response.can_collect = None;
        assert_eq!(
            restarted
                .bind_backend_grant(&response, INSTALLATION_ID)
                .unwrap()
                .status,
            CloudSessionGrantStatus::Revoked
        );
        let cli = Cli::head(page("must-not-collect", None));
        let server = Server::new();
        assert_eq!(
            slice(
                &mut CloudCollector::default(),
                &inputs(&restarted, &checkpoints, &cli, &server),
                Instant::now(),
                Duration::ZERO
            ),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(cli.calls(), 0);
        assert_eq!(server.authority_calls.get(), 0);
        response.status = "revoked".to_string();
        response.grant_version = 2;
        restarted
            .apply_backend_revocation(&response, INSTALLATION_ID)
            .unwrap();
        restarted.enable(&setup(), now()).unwrap();
        assert_eq!(
            restarted
                .grant_create_request(INSTALLATION_ID)
                .unwrap()
                .schema_version,
            CHANGES_SCHEMA_VERSION
        );
    }
}

/// [regress] A delayed refusal anchors Retry-After to response receipt,
/// even when the injected slice clock is older than the real test clock.
#[test]
fn cloud_retry_after_starts_when_the_authority_request_finishes() {
    struct Shed;
    impl CloudSessionTransport for Shed {
        fn read_authority(
            &self,
            _: &CloudSessionGrant,
            _: Duration,
        ) -> Result<CloudSessionGrantAuthorityV1> {
            Err(crate::snapshot_client::UploadShed {
                status: 503,
                retry_after: Some(Duration::ZERO),
                code: None,
            }
            .into())
        }
        fn send_changes(
            &self,
            _: &CloudSessionChangesV1,
            _: Duration,
        ) -> Result<CloudSessionChangesAckV1> {
            unreachable!()
        }
    }
    let (_root, grants, checkpoints) = stores("retry-after-receipt");
    enabled(&grants);
    let cli = Cli::head(page("must-not-collect", None));
    let mut collector = CloudCollector::default();
    let inputs = inputs(&grants, &checkpoints, &cli, &Shed);
    let now = Instant::now();
    // An explicitly old deadline models time spent composing credentials.
    let slice_start = now - Duration::from_secs(5);
    let outcome = collector.run_slice(&inputs, slice_start, midnight());
    assert_eq!(outcome, CloudSessionCycleOutcome::Failed);
    let retry = collector.schedule.retry_not_before.unwrap();
    // A zero server delay still begins at receipt, after request execution.
    // The old code anchored it to slice_start, before that execution.
    assert!(retry > slice_start);
    assert_eq!(cli.calls(), 0);
}

/// [behaviour] Backoff defers planned work; it never accelerates head
/// polling. A failed first crawl page is owed at the continuation cadence.
#[test]
fn failed_provider_pages_keep_their_planned_work_opportunity() {
    struct Offline;
    impl CloudSessionRunner for Offline {
        fn list_page(&self, _: Option<&str>, _: usize) -> Result<String> {
            Err(anyhow!("offline"))
        }
    }
    let (_root, grants, checkpoints) = stores("failure-cadence");
    enabled(&grants);
    let server = Server::new();
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    let cli = Cli::head(page("terminal", None));
    assert_eq!(
        slice(
            &mut collector,
            &inputs(&grants, &checkpoints, &cli, &server),
            t0,
            Duration::ZERO
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    let offline = inputs(&grants, &checkpoints, &Offline, &server);
    assert_eq!(
        slice(&mut collector, &offline, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Failed
    );
    assert!(
        collector
            .next_wake(t0 + 6 * HOUR, midnight() + 6 * HOUR, None)
            .unwrap()
            >= t0 + 12 * HOUR
    );
    let mut startup = CloudCollector::default();
    assert_eq!(
        slice(&mut startup, &offline, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Failed
    );
    assert!(startup.next_wake(t0, midnight(), None).unwrap() >= t0 + 5 * MINUTE);
}

/// [behaviour] A successfully listed running head keeps fast polling even
/// when its upload loses an ACK. Delivery failure cannot erase provider facts.
#[test]
fn head_status_controls_cadence_independently_of_delivery() {
    let (_root, grants, checkpoints) = stores("head-delivery-isolation");
    enabled(&grants);
    let cli = Cli::head(page("changing", None));
    let server = Server::new();
    let inputs = inputs(&grants, &checkpoints, &cli, &server);
    let t0 = Instant::now();
    let mut collector = CloudCollector::default();
    assert_eq!(
        slice(&mut collector, &inputs, t0, Duration::ZERO),
        CloudSessionCycleOutcome::Uploaded
    );
    cli.set(None, page_of(vec![task("changing", "running")], None));
    server.lose_acks.set(1);
    assert_eq!(
        slice(&mut collector, &inputs, t0, 6 * HOUR),
        CloudSessionCycleOutcome::Failed
    );
    assert!(collector.schedule.head_nonterminal);
    assert_eq!(
        collector.next_wake(t0 + 6 * HOUR, midnight() + 6 * HOUR, None),
        Some(t0 + 6 * HOUR + 5 * MINUTE)
    );
    // A later valid terminal head slows the schedule even if its ACK is lost.
    cli.set(None, page_of(vec![task("changing", "error")], None));
    server.lose_acks.set(1);
    assert_eq!(
        slice(&mut collector, &inputs, t0, 6 * HOUR + 5 * MINUTE),
        CloudSessionCycleOutcome::Failed
    );
    assert!(!collector.schedule.head_nonterminal);
}

/// [behaviour] Idempotent create may return a paused row. It binds without
/// collecting and remains compensatable if local revoke raced the response.
#[test]
fn paused_create_responses_reconcile_without_resurrecting_collection() {
    for revoked in [false, true] {
        let (_root, grants, checkpoints) = stores("paused-create");
        let local = grants.enable(&setup(), now()).unwrap();
        grants.grant_create_request(INSTALLATION_ID).unwrap();
        if revoked {
            grants.revoke(now()).unwrap();
        }
        let paused = backend_grant(&local, "paused", 1);
        let bound = grants.bind_backend_grant(&paused, INSTALLATION_ID).unwrap();
        assert_eq!(
            bound.status,
            if revoked {
                CloudSessionGrantStatus::Revoked
            } else {
                CloudSessionGrantStatus::PolicyDisabled
            }
        );
        assert_eq!(
            grants.bind_backend_grant(&paused, INSTALLATION_ID).unwrap(),
            bound
        );
        let cli = Cli::head(page("must-not-collect", None));
        let server = Server::new();
        server.authority.set(Authority::Paused);
        slice(
            &mut CloudCollector::default(),
            &inputs(&grants, &checkpoints, &cli, &server),
            Instant::now(),
            Duration::ZERO,
        );
        assert_eq!(cli.calls(), 0);
        if revoked {
            assert_eq!(grants.grant_revoke_target().unwrap().grant_id, GRANT_ID);
        } else {
            let current = grants
                .apply_backend_authority(&authority(&bound, "enabled"))
                .unwrap();
            assert_eq!(current.status, CloudSessionGrantStatus::Enabled);
            // An old bind response never overwrites fresher authority state.
            assert_eq!(
                grants.bind_backend_grant(&paused, INSTALLATION_ID).unwrap(),
                current
            );
        }
    }
}

/// [format] A sign-in rebind repeats safely after server commit and before local save.
#[test]
fn sign_in_rebind_recovers_without_a_new_epoch() {
    let (_root, store, checkpoints) = stores("rebind-crash");
    enabled(&store);
    store.record_health("healthy", "current", None).unwrap();
    let local = store.load().unwrap().unwrap();
    let mut proof = authority(&local, "enabled");
    proof.collect_not_before = Some("2026-01-01T00:00:00Z".to_owned());
    store.apply_backend_authority(&proof).unwrap();
    let cli = Cli::head(page("cached-before-rebind", None));
    let server = Server::new();
    server
        .collect_not_before
        .replace(proof.collect_not_before.clone());
    slice(
        &mut CloudCollector::default(),
        &inputs(&store, &checkpoints, &cli, &server),
        Instant::now(),
        Duration::ZERO,
    );
    let original = store.read().unwrap().unwrap();
    let scope = cache_scope(
        DEFAULT_API_BASE_URL,
        &original.grant,
        original.grant.backend_binding.as_ref().unwrap(),
    );
    let entity = server.requests.borrow()[0].observations[0]
        .entity_key
        .clone();
    let saved_ack = checkpoints
        .read_acks(&scope, &[&entity], midnight().unix_timestamp())
        .unwrap();
    assert_eq!(saved_ack.len(), 1);
    let target = CloudSessionGrantSetup {
        installation_id: "00000000-0000-4000-8000-000000000084".to_owned(),
        organization_scope: "org_fixture".to_owned(),
        effective_user_scope: "user_fixture".to_owned(),
    };
    let proposal = store
        .prepare_rebind(&target, "hardware-fixture".to_owned())
        .unwrap()
        .unwrap();
    let mut response = backend_grant(&original.grant, "enabled", 1);
    response.installation_id = target.installation_id.clone();
    response.grant_scope_fingerprint = proposal.request.grant_scope_fingerprint.clone();
    let value = serde_json::to_value(&response).unwrap();
    let mut value = value.as_object().unwrap().clone();
    for key in ["server_policy_state", "release_lane"] {
        value.remove(key);
    }
    value.insert("can_read_cloud_sessions".into(), json!(true));
    let response =
        serde_json::from_value::<CloudSessionBackendGrantResponseV1>(Value::Object(value)).unwrap();
    let reopened = CloudSessionGrantStore::new(store.path());
    let recovered = reopened
        .prepare_rebind(&target, "hardware-fixture".to_owned())
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(&proposal.request).unwrap(),
        serde_json::to_value(&recovered.request).unwrap()
    );
    let before = fs::read(reopened.path()).unwrap();
    let mut legacy = response.clone();
    legacy.schema_version = LEGACY_COLLECTION_SCHEMA_VERSION.to_owned();
    assert!(reopened
        .bind_backend_grant_with_rebind(&legacy, &target.installation_id, Some(&recovered))
        .is_err());
    assert_eq!(fs::read(reopened.path()).unwrap(), before);
    let rebound = reopened
        .bind_backend_grant_with_rebind(&response, &target.installation_id, Some(&recovered))
        .unwrap();
    let mut expected_binding = original.grant.backend_binding.clone().unwrap();
    expected_binding.cache_origin = Some(CloudSessionCacheOrigin {
        installation_fingerprint: original.grant.installation_fingerprint.clone(),
        grant_scope_id: original.grant.grant_scope_id.clone(),
    });
    assert_eq!(rebound.backend_binding.as_ref(), Some(&expected_binding));
    assert_eq!(
        cache_scope(DEFAULT_API_BASE_URL, &rebound, &expected_binding),
        scope
    );
    assert_eq!(
        checkpoints
            .read_acks(&scope, &[&entity], midnight().unix_timestamp())
            .unwrap()
            .len(),
        1
    );
    assert!(store
        .prepare_rebind(
            &CloudSessionGrantSetup {
                effective_user_scope: "foreign-owner".to_owned(),
                ..target.clone()
            },
            "fixture".to_owned()
        )
        .is_err());
    assert_eq!(
        rebound.account_fingerprint,
        original.grant.account_fingerprint
    );
    assert_eq!(rebound.granted_at, original.grant.granted_at);
    assert_eq!(
        rebound.last_collector_health,
        original.grant.last_collector_health
    );
    assert_eq!(
        reopened.read().unwrap().unwrap().hmac_key_hex,
        original.hmac_key_hex
    );
    let bytes = fs::read(reopened.path()).unwrap();
    reopened
        .bind_backend_grant(&response, &target.installation_id)
        .unwrap();
    assert_eq!(fs::read(reopened.path()).unwrap(), bytes);
    assert!(reopened.runtime_candidate_for(&target).unwrap().is_some());
    // Reopen with the rebound identity and poll unchanged facts: the accepted
    // cache remains accessible, so no second upload is sent.
    assert_eq!(
        slice(
            &mut CloudCollector::default(),
            &inputs(&reopened, &checkpoints, &cli, &server),
            Instant::now(),
            Duration::ZERO
        ),
        CloudSessionCycleOutcome::Noop
    );
    assert_eq!(server.offered(), 1);
    let mut next_target = target.clone();
    next_target.installation_id = "00000000-0000-4000-8000-000000000094".to_owned();
    let next = reopened
        .prepare_rebind(&next_target, "fixture".to_owned())
        .unwrap()
        .unwrap();
    let mut next_response = response.clone();
    next_response.installation_id = next_target.installation_id.clone();
    next_response.grant_scope_fingerprint = next.request.grant_scope_fingerprint.clone();
    let twice = reopened
        .bind_backend_grant_with_rebind(&next_response, &next_target.installation_id, Some(&next))
        .unwrap();
    assert_eq!(
        cache_scope(
            DEFAULT_API_BASE_URL,
            &twice,
            twice.backend_binding.as_ref().unwrap()
        ),
        scope
    );
    reopened.revoke(now()).unwrap();
    assert!(reopened
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .is_none());
    assert!(reopened
        .bind_backend_grant_with_rebind(&response, &target.installation_id, Some(&recovered))
        .is_err());
}

/// [regress] Updating the producer preserves approval and reports the current build.
#[test]
fn update_preserves_consent_time_build_and_uses_current_payload_build() {
    let (_root, store, checkpoints) = stores("update-approval");
    enabled(&store);
    let mut state = store.read().unwrap().unwrap();
    state.grant.collector_version = "0.0.1".to_owned();
    store.write(&state).unwrap();
    assert!(cloud_grant_runtime_ready(&state.grant));
    assert!(cloud_grant_preflight_eligible(&state.grant));
    let cli = Cli::head(page("current-build", None));
    let server = Server::new();
    assert_eq!(
        slice(
            &mut CloudCollector::default(),
            &inputs(&store, &checkpoints, &cli, &server),
            Instant::now(),
            Duration::ZERO
        ),
        CloudSessionCycleOutcome::Uploaded
    );
    assert_eq!(
        server.requests.borrow()[0].collector_version,
        compiled_release_version()
    );
    assert_eq!(store.load().unwrap().unwrap().collector_version, "0.0.1");
}

/// [behaviour] The shared HTTP client dispatches both grant kinds and omits predecessor UUIDs.
#[test]
fn collector_rebind_http_and_authority_send_exact_current_identity() {
    use std::io::Write;
    use std::net::TcpListener;
    for kind in [GrantKind::DailyReference, GrantKind::CloudSessions] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut captured = Vec::new();
            for (status, body) in [
                ("200 OK", "{}"),
                (
                    "409 Conflict",
                    r#"{"detail":{"code":"hardware_changed","message":"refused","retryable":false}}"#,
                ),
                ("200 OK", "{}"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                captured.push(read_http_request(&mut stream));
                write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            captured
        });
        let client = crate::snapshot_client::SnapshotApiClient::new(format!("http://{address}"));
        let request = RebindRequest {
            installation_id: INSTALLATION_ID.to_owned(),
            grant_version: 1,
            grant_scope_fingerprint: format!("hmac-sha256:{}", "a".repeat(64)),
            hardware_id: Some(format!("oth_{}", "a".repeat(32))),
            disclosure_version: match kind {
                GrantKind::DailyReference => "provider_daily_reference_disclosure.v2",
                GrantKind::CloudSessions => "cloud_sessions_disclosure.v1",
            }
            .to_owned(),
        };
        assert_eq!(
            client
                .rebind_collector_grant(
                    kind,
                    GRANT_ID,
                    "fixture-relay-token",
                    &request,
                    Duration::from_secs(2)
                )
                .unwrap(),
            json!({})
        );
        let refusal = client
            .rebind_collector_grant(
                kind,
                GRANT_ID,
                "fixture-relay-token",
                &request,
                Duration::from_secs(2),
            )
            .unwrap_err();
        assert_eq!(refusal.code, "hardware_changed");
        assert!(!refusal.retryable);
        client
            .get_cloud_session_authority_with_timeout(
                "fixture-relay-token",
                GRANT_ID,
                1,
                Duration::from_secs(2),
            )
            .unwrap();
        let captured = server.join().unwrap();
        for raw in &captured[..2] {
            assert!(raw.starts_with(&format!(
                "POST /api/v1/{}/grants/{GRANT_ID}/rebind ",
                kind.route()
            )));
            assert!(raw
                .to_ascii_lowercase()
                .contains("authorization: bearer fixture-relay-token"));
            let (_, body) = raw.split_once("\r\n\r\n").unwrap();
            let body: Value = serde_json::from_str(body).unwrap();
            assert_eq!(body, serde_json::to_value(&request).unwrap());
            assert!(body.get("previous_installation_id").is_none());
        }
        assert!(captured[2].starts_with(&format!(
            "GET /api/v1/cloud-sessions/grants/{GRANT_ID}/authority?grant_version=1 HTTP/1.1"
        )));
    }
}

/// [behaviour] A valid same-epoch rebind can deny collection without enabling it.
#[test]
fn successful_rebind_retains_a_disabled_server_policy() {
    let (_root, store, _) = stores("rebind-disabled-policy");
    enabled(&store);
    let original = store.load().unwrap().unwrap();
    let target = CloudSessionGrantSetup {
        installation_id: "00000000-0000-4000-8000-000000000085".to_owned(),
        organization_scope: "org_fixture".to_owned(),
        effective_user_scope: "user_fixture".to_owned(),
    };
    let proposal = store
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .unwrap();
    let mut response = backend_grant(&original, "enabled", 1);
    response.installation_id = target.installation_id.clone();
    response.grant_scope_fingerprint = proposal.request.grant_scope_fingerprint.clone();
    response.can_collect = Some(false);
    let rebound = store
        .bind_backend_grant_with_rebind(&response, &target.installation_id, Some(&proposal))
        .unwrap();
    assert_eq!(rebound.status, CloudSessionGrantStatus::PolicyDisabled);
    assert!(!cloud_grant_runtime_ready(&rebound));
    assert!(store
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .is_none());
    assert_eq!(rebound.backend_binding.as_ref().unwrap().grant_version, 1);
}

/// [regress] Paused same-owner consent resumes after sign-in without a new browser approval.
#[test]
fn paused_approval_resumes_via_rebind_and_account_switch_requires_new_consent() {
    let (_root, store, _) = stores("rebind-resume-account-switch");
    enabled(&store);
    let original = store.read().unwrap().unwrap();
    store.pause(now()).unwrap();
    let mut target = CloudSessionGrantSetup {
        installation_id: "00000000-0000-4000-8000-000000000086".to_owned(),
        organization_scope: "org_fixture".to_owned(),
        effective_user_scope: "user_fixture".to_owned(),
    };
    let resumed = store.enable(&target, now()).unwrap();
    assert_eq!(resumed.status, CloudSessionGrantStatus::Enabled);
    assert_eq!(resumed.backend_binding, original.grant.backend_binding);
    assert!(!resumed.backend_create_pending);
    let proposal = store
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .unwrap();
    let mut response = backend_grant(&original.grant, "enabled", 1);
    response.installation_id = target.installation_id.clone();
    response.grant_scope_fingerprint = proposal.request.grant_scope_fingerprint.clone();
    store
        .bind_backend_grant_with_rebind(&response, &target.installation_id, Some(&proposal))
        .unwrap();
    assert_eq!(
        store.read().unwrap().unwrap().hmac_key_hex,
        original.hmac_key_hex
    );
    target.installation_id = "00000000-0000-4000-8000-000000000087".to_owned();
    target.effective_user_scope = "another-user".to_owned();
    let new_owner = store.enable(&target, now()).unwrap();
    assert_eq!(new_owner.status, CloudSessionGrantStatus::ConsentRequired);
    assert!(new_owner.backend_binding.is_none());
    assert!(!cloud_grant_runtime_ready(&new_owner));
    assert_ne!(
        new_owner.account_fingerprint,
        original.grant.account_fingerprint
    );
    store.grant_create_request(&target.installation_id).unwrap();
    let mut approved = backend_grant(&new_owner, "enabled", 1);
    approved.installation_id = target.installation_id.clone();
    store
        .bind_backend_grant(&approved, &target.installation_id)
        .unwrap();
    target.effective_user_scope = "user_fixture".to_owned();
    let returned = store.enable(&target, now()).unwrap();
    assert_eq!(returned.status, CloudSessionGrantStatus::ConsentRequired);
    assert!(
        returned.backend_binding.is_none(),
        "returning to the former owner requires approval"
    );
}

/// [regress] A terminal rebind refusal permits explicit replacement; a raced revoke still reconciles exactly.
#[test]
fn refused_approval_can_be_replaced_and_old_device_revocation_can_be_confirmed() {
    let (_root, store, _) = stores("rebind-refusal-new-consent");
    enabled(&store);
    let mut target = CloudSessionGrantSetup {
        installation_id: "00000000-0000-4000-8000-000000000088".to_owned(),
        organization_scope: "org_fixture".to_owned(),
        effective_user_scope: "user_fixture".to_owned(),
    };
    store
        .record_health("unavailable", "unavailable", Some("installation_reset"))
        .unwrap();
    let pending = store.enable(&target, now()).unwrap();
    assert_eq!(pending.status, CloudSessionGrantStatus::ConsentRequired);
    assert!(pending.backend_binding.is_none());
    store.grant_create_request(&target.installation_id).unwrap();
    let mut response = backend_grant(&pending, "enabled", 1);
    response.installation_id = target.installation_id.clone();
    store
        .bind_backend_grant(&response, &target.installation_id)
        .unwrap();
    store.revoke(now()).unwrap();
    let mut revoked = response;
    revoked.status = "revoked".to_owned();
    revoked.grant_version = 2;
    target.installation_id = "00000000-0000-4000-8000-000000000089".to_owned();
    assert!(
        store.enable(&target, now()).is_err(),
        "unconfirmed revoke remains protected"
    );
    store
        .apply_backend_revocation(&revoked, &target.installation_id)
        .unwrap();
    assert_eq!(
        store.load().unwrap().unwrap().status,
        CloudSessionGrantStatus::Revoked
    );
    assert_eq!(
        store.enable(&target, now()).unwrap().status,
        CloudSessionGrantStatus::ConsentRequired
    );
}

/// [regress] A committed in-flight rebind updates cleanup identity while a local stop remains final.
#[test]
fn a_stop_racing_rebind_completion_preserves_cleanup_without_resurrection() {
    for stop in [
        CloudSessionGrantStatus::Paused,
        CloudSessionGrantStatus::Revoked,
    ] {
        let (_root, store, _) = stores("rebind-raced-stop");
        enabled(&store);
        let original = store.load().unwrap().unwrap();
        let target = CloudSessionGrantSetup {
            installation_id: "00000000-0000-4000-8000-000000000090".to_owned(),
            organization_scope: "org_fixture".to_owned(),
            effective_user_scope: "user_fixture".to_owned(),
        };
        let proposal = store
            .prepare_rebind(&target, "fixture".to_owned())
            .unwrap()
            .unwrap();
        let mut response = backend_grant(&original, "enabled", 1);
        response.installation_id = target.installation_id.clone();
        response.grant_scope_fingerprint = proposal.request.grant_scope_fingerprint.clone();
        store.change_status(stop.clone(), now()).unwrap();
        assert!(store
            .prepare_rebind(&target, "fixture".to_owned())
            .unwrap()
            .is_none());
        let retained = store
            .bind_backend_grant_with_rebind(&response, &target.installation_id, Some(&proposal))
            .unwrap();
        assert_eq!(retained.status, stop);
        assert!(!cloud_grant_runtime_ready(&retained));
        assert!(store
            .prepare_rebind(&target, "fixture".to_owned())
            .unwrap()
            .is_none());
        if stop == CloudSessionGrantStatus::Revoked {
            assert_eq!(retained.revoked_at, Some(timestamp(now())));
            response.status = "revoked".to_owned();
            response.grant_version = 2;
            store
                .apply_backend_revocation(&response, &target.installation_id)
                .unwrap();
            assert!(
                store
                    .load()
                    .unwrap()
                    .unwrap()
                    .backend_binding
                    .unwrap()
                    .backend_revoked
            );
        } else {
            assert_eq!(
                store.enable(&target, now()).unwrap().status,
                CloudSessionGrantStatus::Enabled
            );
        }
    }
}

/// [regress] Identity changes stop the new authority/page/send/cache paths;
/// an ACK admitted before a change cannot repopulate its cache afterwards.
#[test]
fn current_binding_fences_every_results_io_boundary() {
    struct Fenced<'a> {
        server: Server,
        current: &'a Cell<bool>,
        stop_after_send: bool,
    }
    impl CloudSessionTransport for Fenced<'_> {
        fn local_binding_current(&self, _grant: &CloudSessionGrant) -> bool {
            self.current.get()
        }
        fn read_authority(
            &self,
            grant: &CloudSessionGrant,
            timeout: Duration,
        ) -> Result<CloudSessionGrantAuthorityV1> {
            self.server.read_authority(grant, timeout)
        }
        fn send_changes(
            &self,
            request: &CloudSessionChangesV1,
            timeout: Duration,
        ) -> Result<CloudSessionChangesAckV1> {
            let ack = self.server.send_changes(request, timeout);
            if self.stop_after_send {
                self.current.set(false);
            }
            ack
        }
    }
    struct ChangingCli<'a> {
        cli: Cli,
        current: &'a Cell<bool>,
        stop_after_list: bool,
    }
    impl CloudSessionRunner for ChangingCli<'_> {
        fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String> {
            let page = self.cli.list_page(cursor, limit);
            if self.stop_after_list {
                self.current.set(false);
            }
            page
        }
    }
    for stop in ["before-slice", "after-provider", "after-send"] {
        let (_root, grants, checkpoints) = stores("binding-fence");
        enabled(&grants);
        let current = Cell::new(stop != "before-slice");
        let cli = ChangingCli {
            cli: Cli::head(page("identity-fence", None)),
            current: &current,
            stop_after_list: stop == "after-provider",
        };
        let server = Fenced {
            server: Server::new(),
            current: &current,
            stop_after_send: stop == "after-send",
        };
        let grant = grants.load().unwrap().unwrap();
        let scope = cache_scope(
            DEFAULT_API_BASE_URL,
            &grant,
            grant.backend_binding.as_ref().unwrap(),
        );
        let key = parse_cloud_page(
            &page("identity-fence", None),
            &decode_hex(&grants.read().unwrap().unwrap().hmac_key_hex).unwrap(),
            now(),
        )
        .unwrap()
        .changes[0]
            .entity_key
            .clone();
        CloudCollector::default().run_slice(
            &SliceInputs {
                grants: &grants,
                checkpoints: &checkpoints,
                runner: &cli,
                transport: &server,
                destination: DEFAULT_API_BASE_URL,
                last_activity: None,
            },
            Instant::now(),
            midnight(),
        );
        assert_eq!(
            server.server.authority_calls.get(),
            usize::from(stop != "before-slice")
        );
        assert_eq!(cli.cli.calls(), usize::from(stop != "before-slice"));
        assert_eq!(server.server.offered(), usize::from(stop == "after-send"));
        assert!(checkpoints
            .read_acks(&scope, &[&key], midnight().unix_timestamp())
            .unwrap()
            .is_empty());
        assert_eq!(
            grants.load().unwrap().unwrap().status,
            CloudSessionGrantStatus::Enabled
        );
    }
}

/// [regress] A lost rebind reply followed by local revoke reconciles the exact
/// DELETE response, without re-enabling consent or retrying a revoked rebind.
#[test]
fn lost_rebind_reply_can_be_revoked_using_the_current_owner_proof() {
    let (_root, grants, _) = stores("lost-rebind-revoke");
    enabled(&grants);
    let original = grants.load().unwrap().unwrap();
    let target = CloudSessionGrantSetup {
        installation_id: "00000000-0000-4000-8000-000000000095".to_owned(),
        ..setup()
    };
    let proposal = grants
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .unwrap();
    // Server commits target binding; its response never reaches local bind.
    let mut deleted = backend_grant(&original, "revoked", 2);
    deleted.installation_id = target.installation_id.clone();
    deleted.grant_scope_fingerprint = proposal.request.grant_scope_fingerprint.clone();
    grants.revoke(now()).unwrap();
    assert!(grants
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .is_none());
    let bytes = fs::read(grants.path()).unwrap();
    let foreign = CloudSessionGrantSetup {
        effective_user_scope: "foreign".to_owned(),
        ..target.clone()
    };
    assert!(grants
        .reconcile_backend_revocation(&deleted, &foreign)
        .is_err());
    for field in ["id", "scope", "status", "epoch"] {
        let mut invalid = deleted.clone();
        match field {
            "id" => invalid.id = "00000000-0000-4000-8000-000000000096".to_owned(),
            "scope" => invalid.grant_scope_fingerprint = original.grant_scope_id.clone(),
            "status" => invalid.status = "enabled".to_owned(),
            "epoch" => invalid.grant_version = 0,
            _ => unreachable!(),
        }
        assert!(grants
            .reconcile_backend_revocation(&invalid, &target)
            .is_err());
        assert_eq!(fs::read(grants.path()).unwrap(), bytes);
    }
    // Another sign-in can replace the relay device again before cleanup.
    // Prove the DELETE target using its returned UUID and the current owner.
    let current = CloudSessionGrantSetup {
        installation_id: "00000000-0000-4000-8000-000000000097".to_owned(),
        ..target.clone()
    };
    let stopped = grants
        .reconcile_backend_revocation(&deleted, &current)
        .unwrap();
    assert_eq!(stopped.status, CloudSessionGrantStatus::Revoked);
    assert_eq!(stopped.revoked_at, Some(timestamp(now())));
    assert!(stopped.backend_binding.as_ref().unwrap().backend_revoked);
    assert!(!cloud_grant_runtime_ready(&stopped));
    assert!(grants
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .is_none());
    assert_eq!(
        grants.enable(&target, now()).unwrap().status,
        CloudSessionGrantStatus::ConsentRequired
    );
}
