use base64::Engine as _;

#[test]
fn session_exec_commands_require_cli_kind_and_authorized_token() {
    let daemon = daemon();
    for report in [false, true] {
        let command = || {
            if report {
                LocalControlCommand::SessionLaunchReport {
                    schema_version: 1,
                    launch_id: "synthetic".into(),
                    attempt_id: SecretString::new("synthetic"),
                    reason: ottto_protocol::SessionLaunchBlockReasonV1::ExecFailed,
                }
            } else {
                LocalControlCommand::SessionLaunchConsume {
                    schema_version: 1,
                    launch_id: "synthetic".into(),
                    secret: SecretString::new("synthetic"),
                }
            }
        };
        for (kind, token, expected) in [
            (
                Some(LocalClientKind::CompanionApp),
                Some("token"),
                CliErrorCode::LocalAuthFailed,
            ),
            (None, Some("token"), CliErrorCode::LocalAuthFailed),
            // Without a token or trusted peer, the common authorization
            // boundary refuses before the CLI-only command check.
            (
                Some(LocalClientKind::Cli),
                None,
                CliErrorCode::LocalClientNotTrusted,
            ),
            (
                Some(LocalClientKind::Cli),
                Some("wrong-token"),
                CliErrorCode::LocalAuthFailed,
            ),
        ] {
            let response = handle_request(
                &daemon,
                LocalControlRequest {
                    request_id: "launch-auth".into(),
                    protocol_version: 28,
                    token: token.map(str::to_owned),
                    client_kind: kind,
                    client_install_owner: None,
                    command: command(),
                },
            );
            assert!(!response.ok);
            assert_eq!(response.error.unwrap().code, expected);
        }
        let response = handle_request(
            &daemon,
            LocalControlRequest {
                request_id: "launch-auth".into(),
                protocol_version: 28,
                token: Some("token".into()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: command(),
            },
        );
        assert!(response.ok);
        assert_eq!(
            response.payload.unwrap()["block"]["reason"],
            "launch_unknown"
        );
    }
}

#[test]
fn codex_prepare_target_resolves_only_daemon_authored_exact_composite() {
    let account_hash = "a".repeat(64);
    let workspace_hash = "b".repeat(64);
    let status = ottto_protocol::CodexAccountsStatusV1 {
        schema_version: ottto_protocol::CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
        setup_operation: Default::default(),
        default_slot: ottto_protocol::CodexAccountSlotDescriptorV1 {
            slot_id: "default".to_string(),
            ownership: ottto_protocol::CodexAccountSlotOwnershipV1::Default,
            collection: Default::default(),
        },
        managed_slots: Vec::new(),
        target_coverage: ottto_protocol::CodexAccountTargetCoverageV1 {
            targets: vec![ottto_protocol::CodexAccountTargetDescriptorV1 {
                target_id: "codex_account_target_exact".to_string(),
                account_identifier_hash: Some(account_hash.clone()),
                workspace_identifier_hash: Some(workspace_hash.clone()),
                account_label: "Codex account".to_string(),
                workspace_label: Some("Acme".to_string()),
                subscription_product: None,
                durability: ottto_protocol::CodexAccountTargetDurabilityV1::ObservedOnly,
                is_current: false,
                connectable: true,
                health: None,
                setup_blockers: Vec::new(),
                observed_at: Some("2026-08-27T00:00:00Z".to_string()),
            }],
            observed_targets: 1,
            durable_targets: 0,
            current_targets: 0,
            connectable_targets: 1,
            blocked_targets: 0,
        },
        capacity: ottto_protocol::CodexAccountCapacityV1 {
            max_slots: 10,
            used_slots: 1,
            remaining_slots: 9,
        },
        daemon_sign_in_supported: None,
        background_quota_refresh: None,
    };

    assert_eq!(
        super::codex_account_target_binding(&status, "codex_account_target_exact")
            .expect("exact target binding"),
        (account_hash, workspace_hash)
    );
    assert!(super::codex_account_target_binding(&status, "codex_account_target_forged").is_err());
}

#[test]
fn backend_body_excerpt_redacts_compact_json_secret_fields() {
    let prior = format!("prior-{}", "value".repeat(4));
    let install = format!("install-{}", "value".repeat(4));
    let candidate = format!("candidate-{}", "value".repeat(4));
    let body = serde_json::json!({
        "detail": "registration rejected",
        "prior_device_secret": prior,
        "candidate_secret": candidate,
        "nested": {"install_session_token": install},
    })
    .to_string();

    let excerpt = super::safe_backend_body_excerpt(&body).expect("non-empty excerpt");
    let parsed: serde_json::Value = serde_json::from_str(&excerpt).expect("valid JSON excerpt");
    assert_eq!(parsed["detail"], "registration rejected");
    assert_eq!(parsed["prior_device_secret"], "[REDACTED]");
    assert_eq!(parsed["candidate_secret"], "[REDACTED]");
    assert_eq!(parsed["nested"]["install_session_token"], "[REDACTED]");
    assert!(!excerpt.contains(&prior));
    assert!(!excerpt.contains(&install));
    assert!(!excerpt.contains(&candidate));
}

#[test]
fn backend_endpoint_redacts_device_credential_preparation_id() {
    assert_eq!(
        super::safe_backend_endpoint(
            "https://api.ottto.net/api/v1/telemetry/device-credential-preparations/private-preparation-id/confirm?x=1"
        ),
        "https://api.ottto.net/api/v1/telemetry/device-credential-preparations/[preparation]/confirm"
    );
    assert_eq!(
        super::safe_backend_endpoint(
            "https://api.ottto.net/api/v1/telemetry/devices/private-device-id/relay-token"
        ),
        "https://api.ottto.net/api/v1/telemetry/devices/[device]/relay-token"
    );
    assert_eq!(
        super::safe_backend_endpoint(
            "https://api.ottto.net/api/v1/telemetry/devices/registration-preparations"
        ),
        "https://api.ottto.net/api/v1/telemetry/devices/registration-preparations"
    );
}

#[test]
fn managed_config_preview_extracts_and_redacts_fence_region() {
    // Assembled at runtime so no token-shaped literal lands in the
    // public source tree (the public-surface scanner rejects those).
    let fake_secret = format!("sk-{}", "abcde12345".repeat(4));
    let body = format!(
        concat!(
            "top_level = true\n",
            "# ottto:start\n",
            "[otel]\n",
            "environment = \"prod\"\n",
            "log_user_prompt = false\n",
            "exporter_otlp_endpoint = \"http://127.0.0.1:4319\"\n",
            "exporter_otlp_headers = \"Bearer {}\"\n",
            "# ottto:end\n",
            "trailing = true\n",
        ),
        fake_secret,
    );
    let preview = super::managed_config_preview("~/.codex/config.toml", Some(&body))
        .expect("fenced body yields a preview");
    assert_eq!(preview["path"], "~/.codex/config.toml");
    assert_eq!(preview["exists"], true);
    let lines: Vec<String> = preview["lines"]
        .as_array()
        .expect("lines array")
        .iter()
        .map(|line| line.as_str().expect("line string").to_string())
        .collect();
    assert_eq!(lines.first().map(String::as_str), Some("# ottto:start"));
    assert_eq!(lines.last().map(String::as_str), Some("# ottto:end"));
    assert!(lines.iter().any(|line| line == "[otel]"));
    assert!(lines
        .iter()
        .any(|line| line == "exporter_otlp_endpoint = \"http://127.0.0.1:4319\""));
    let joined = lines.join("\n");
    assert!(!joined.contains(&fake_secret));
    assert!(!joined.contains("top_level"));
    assert!(!joined.contains("trailing"));
    assert!(joined.contains("…redacted…"));
}

#[test]
fn claude_managed_config_preview_renders_managed_env_keys() {
    let fake_secret = format!("otel_{}", "k1v2x3y4z5".repeat(4));
    let body = format!(
        concat!(
            "{{\n",
            "  \"env\": {{\n",
            "    \"CLAUDE_CODE_ENABLE_TELEMETRY\": \"1\",\n",
            "    \"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT\": \"http://127.0.0.1:43119/v1/logs\",\n",
            "    \"OTEL_EXPORTER_OTLP_HEADERS\": \"X-Ottto-Key {}\",\n",
            "    \"UNRELATED_KEY\": \"kept-private\"\n",
            "  }},\n",
            "  \"statusLine\": {{\"type\": \"command\"}}\n",
            "}}\n",
        ),
        fake_secret,
    );
    let preview = super::claude_managed_config_preview(Some(&body))
        .expect("managed env keys yield a preview");
    assert_eq!(preview["path"], "~/.claude/settings.json");
    let lines: Vec<String> = preview["lines"]
        .as_array()
        .expect("lines array")
        .iter()
        .map(|line| line.as_str().expect("line string").to_string())
        .collect();
    let joined = lines.join("\n");
    assert!(joined.contains("CLAUDE_CODE_ENABLE_TELEMETRY = \"1\""));
    assert!(
        joined.contains("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT = \"http://127.0.0.1:43119/v1/logs\"")
    );
    // Secret-bearing header values are masked; unmanaged keys never leak.
    assert!(!joined.contains(&fake_secret));
    assert!(!joined.contains("UNRELATED_KEY"));
    assert!(!joined.contains("kept-private"));
}

use super::*;

#[test]
#[serial]
fn codex_check_keeps_provider_login_pending_nonterminal() {
    let _guard = lock_backend_test_env();
    // Hosted macOS runners may expose TMPDIR through a symlinked path.
    // Managed credential homes deliberately reject symlinked ancestors,
    // so exercise the production path against the canonical test root.
    let root = control_test_root("codex-check-pending")
        .canonicalize()
        .expect("canonical Codex account test root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let operation_id = "codex_setup_0123456789abcdef0123456789abcdef";

    let prepared = prepare_open_codex_account(1, operation_id.to_string())
        .expect("prepare open Codex connection");
    assert_eq!(
        prepared.setup_operation.state,
        CodexAccountSetupOperationStateV1::WaitingForUserLogin
    );

    // The home has no credential yet, so the setup gate answers without
    // starting the CLI; the provider-pending path itself is covered by
    // `codex_waiting_check_storm_stays_under_the_setup_backoff`.
    let checked = check_codex_account(1, operation_id, false)
        .expect("pending provider login remains a successful status read");
    assert_eq!(
        checked.setup_operation.state,
        CodexAccountSetupOperationStateV1::WaitingForUserLogin
    );
    assert!(checked.setup_operation.launch_command.is_some());

    let _ = fs::remove_dir_all(root);
}

/// A fake `codex` whose app-server answers like a home nobody signed in to:
/// `account/read` succeeds without an account, and the quota read fails.
/// Each app-server start appends one line to `runs`. With `rewrites`,
/// `account/read` also appends to that credential file, as the real CLI
/// rewrites `auth.json` when it refreshes the token.
#[cfg(unix)]
fn write_signed_out_fake_codex(bin: &Path, runs: &Path, rewrites: Option<&Path>) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(bin).expect("fake Codex bin dir");
    let executable = bin.join("codex");
    let rewrite = rewrites.map_or_else(String::new, |auth| {
        format!(
            "        with open({auth:?}, \"a\") as auth:\n            auth.write(\"\\n\")\n",
            auth = auth.display().to_string()
        )
    });
    fs::write(
        &executable,
        format!(
            r#"#!/usr/bin/python3
import sys

if sys.argv[-2:] != ["app-server", "--stdio"]:
    sys.exit(1)
with open({runs:?}, "a") as runs:
    runs.write("run\n")
for line in sys.stdin:
    if '"id":1' in line:
        print('{{"id":1,"result":{{"userAgent":"synthetic"}}}}', flush=True)
    elif '"id":"ottto_account"' in line:
{rewrite}        print('{{"id":"ottto_account","result":{{"account":null,"requiresOpenaiAuth":true}}}}', flush=True)
    elif "account/rateLimits/read" in line:
        print('{{"id":"ottto_rate_limits","error":{{"code":-32600,"message":"codex account authentication required to read rate limits"}}}}', flush=True)
"#,
            runs = runs.display().to_string()
        ),
    )
    .expect("fake Codex executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("fake Codex mode");
}

#[cfg(unix)]
fn counted_lines(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|body| body.lines().count())
        .unwrap_or(0)
}

/// `codex_app_server_quota` lines with trigger `setup` and result `rpc_error`.
#[cfg(unix)]
fn setup_rpc_error_call_lines(support: &Path) -> usize {
    let dir = ottto_core::provider_call_log::provider_call_log_dir(support);
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| fs::read_to_string(entry.path()).unwrap_or_default())
        .flat_map(|body| {
            body.lines()
                .filter_map(|line| {
                    serde_json::from_str::<ottto_core::provider_call_log::ProviderCallLine>(line)
                        .ok()
                })
                .collect::<Vec<_>>()
        })
        .filter(|line| {
            line.kind == "codex_app_server_quota"
                && line.trigger == "setup"
                && line.result == "rpc_error"
        })
        .count()
}

/// Writes a synthetic credential file with the mode managed homes use.
#[cfg(unix)]
fn write_synthetic_codex_auth(home: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let auth = home.join("auth.json");
    fs::write(&auth, body).expect("synthetic credential");
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).expect("credential mode");
}

/// Opens a Codex setup that waits for sign-in and returns its managed home.
#[cfg(unix)]
fn open_waiting_codex_setup(operation_id: &str) -> PathBuf {
    let prepared = prepare_open_codex_account(1, operation_id.to_string()).expect("prepare open");
    let slot_id = prepared
        .setup_operation
        .slot_id
        .expect("the open setup reserves a home");
    FileCodexAccountSlotSettingsStore::default()
        .slot_home(&slot_id)
        .expect("reserved Codex home")
}

/// Runs the waiting check `times` times and asserts the setup still waits.
#[cfg(unix)]
fn check_waiting_codex_setup(operation_id: &str, times: usize, explicit: bool) {
    for _ in 0..times {
        let checked = check_codex_account(1, operation_id, explicit).expect("waiting check");
        assert_eq!(
            checked.setup_operation.state,
            CodexAccountSetupOperationStateV1::WaitingForUserLogin
        );
    }
}

/// The companion checks a setup that waits for sign-in every few seconds.
/// Before the fix each check started one `codex app-server` (20 checks, 20
/// runs). Now a home without a credential is never read, a failing read
/// is spaced, a person's check reads at most once per few seconds, and a
/// new sign-in is read at once. The gate's clock is frozen, so the counts
/// do not depend on how long the checks take.
#[cfg(unix)]
#[test]
#[serial]
fn codex_waiting_check_storm_stays_under_the_setup_backoff() {
    let _guard = lock_backend_test_env();
    let root = control_test_root("codex-check-storm")
        .canonicalize()
        .expect("canonical Codex account test root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let runs = root.join("app-server-runs");
    write_signed_out_fake_codex(&root.join("bin"), &runs, None);
    let _commands = EnvVarGuard::set_path("OTTTO_COMMAND_SEARCH_PATH", &root.join("bin"));
    let clock = crate::agent_status::SetupGateTestClock::frozen_at(std::time::Instant::now());
    let operation_id = "codex_setup_0123456789abcdef0123456789abcdef";
    let home = open_waiting_codex_setup(operation_id);

    // Before the sign-in writes a credential, no check starts the CLI.
    check_waiting_codex_setup(operation_id, 3, false);
    assert_eq!(counted_lines(&runs), 0);

    // A credential whose quota read fails: the first check reads at once
    // and the following polls wait, and so does a person's check made
    // right after the failure.
    write_synthetic_codex_auth(&home, "{}");
    check_waiting_codex_setup(operation_id, 20, false);
    check_waiting_codex_setup(operation_id, 1, true);
    assert_eq!(counted_lines(&runs), 1);
    clock.set(4);
    check_waiting_codex_setup(operation_id, 1, true);
    assert_eq!(counted_lines(&runs), 1);
    // The person's check reads once the short gap passed.
    clock.set(5);
    check_waiting_codex_setup(operation_id, 1, true);
    check_waiting_codex_setup(operation_id, 3, false);
    assert_eq!(counted_lines(&runs), 2);

    // A new sign-in is read at once, then spaced again.
    clock.set(6);
    write_synthetic_codex_auth(&home, "{\"tokens\":null}");
    check_waiting_codex_setup(operation_id, 3, false);
    assert_eq!(counted_lines(&runs), 3);

    // Each failed read still counts as a sent call.
    assert_eq!(setup_rpc_error_call_lines(&root), 3);

    drop(clock);
    let _ = fs::remove_dir_all(root);
}

/// A synthetic `auth.json` whose live tokens claim `user` in `workspace`.
/// A new `expires_at` is a new token for the same sign-in.
#[cfg(unix)]
fn synthetic_codex_auth_with_claims(user: &str, workspace: &str, expires_at: i64) -> String {
    let jwt = |kind: &str| {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "https://auth.openai.com",
                "aud": "synthetic-client",
                "exp": expires_at,
                "email": "synthetic-account",
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": user,
                    "chatgpt_account_id": workspace,
                    "chatgpt_plan_type": "pro"
                }
            })
            .to_string(),
        );
        format!("{header}.{payload}.synthetic-{kind}-signature")
    };
    serde_json::json!({
        "tokens": {"access_token": jwt("access"), "id_token": jwt("id")},
        "account_id": workspace,
    })
    .to_string()
}

/// A fake `codex` for the daemon-run sign-in. `login` first deletes
/// `$CODEX_HOME/auth.json`, as the real CLI revokes and deletes the
/// home's login before the browser opens, then follows the mode in
/// `<bin>/login-mode`:
/// - `success`: prints the sign-in address, writes `<bin>/auth-body` to
///   `$CODEX_HOME/auth.json`, prints the success line and exits 0;
/// - `wait`: prints the address and waits; SIGTERM makes it exit 0, as
///   the real CLI does;
/// - `early`: exits 0 without saving anything;
/// - `fail`: exits 1;
/// - `hold`: prints the address and waits for `<bin>/release-login`,
///   then exits with the status written there, saving nothing;
/// - `fork`: as the real wrapper, starts a child that listens on the
///   port in `<bin>/listen-port` (its pid in `<bin>/listener-pid`); both
///   ignore SIGTERM.
///
/// `app-server` answers with a signed-in account and a fresh quota
/// window; the runs listed in `<bin>/failing-reads` (1-based) fail the
/// quota read instead. Its run number N for one `CODEX_HOME`, written to
/// `<bin>/replace-on-home-run`, first replaces that home's `auth.json`
/// with `<bin>/replacement-body`, as another sign-in there would. Every
/// login appends its pid to `<bin>/login-runs`, every app-server start one
/// line to `<bin>/app-server-runs` and its `CODEX_HOME` to
/// `<bin>/app-server-homes`.
#[cfg(unix)]
fn write_sign_in_fake_codex(bin: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(bin).expect("fake Codex bin dir");
    let script = format!(
        r#"#!/usr/bin/python3
import json, os, signal, sys, time
BIN = {bin:?}

def read(name, default=""):
    try:
        with open(os.path.join(BIN, name)) as f:
            return f.read()
    except OSError:
        return default

args = sys.argv[1:]
if args == ["login"]:
    with open(os.path.join(BIN, "login-runs"), "a") as f:
        f.write("%d\n" % os.getpid())
    try:
        os.remove(os.path.join(os.environ["CODEX_HOME"], "auth.json"))
    except FileNotFoundError:
        pass
    mode = read("login-mode").strip()
    if mode == "fail":
        sys.exit(1)
    if mode == "early":
        sys.exit(0)
    if mode == "fork":
        import socket
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if os.fork() == 0:
            listener.bind(("127.0.0.1", int(read("listen-port"))))
            listener.listen(1)
            with open(os.path.join(BIN, "listener-pid"), "w") as f:
                f.write("%d" % os.getpid())
            while True:
                time.sleep(1)
        sys.stderr.write("If your browser did not open, navigate to this URL to authenticate:\n\n")
        sys.stderr.write("https://auth.example.test/oauth/authorize?state=SYNTHETIC-SIGN-IN-URL-MARKER\n\n")
        sys.stderr.flush()
        while True:
            time.sleep(1)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    sys.stderr.write("Starting local login server on http://localhost:1455.\n")
    sys.stderr.write("If your browser did not open, navigate to this URL to authenticate:\n\n")
    sys.stderr.write("https://auth.example.test/oauth/authorize?state=SYNTHETIC-SIGN-IN-URL-MARKER\n\n")
    sys.stderr.flush()
    if mode == "wait":
        while True:
            time.sleep(1)
    if mode == "hold":
        while not os.path.exists(os.path.join(BIN, "release-login")):
            time.sleep(0.05)
        sys.exit(int(read("release-login").strip() or "0"))
    time.sleep(0.3)
    path = os.path.join(os.environ["CODEX_HOME"], "auth.json")
    with open(path + ".tmp", "w") as f:
        f.write(read("auth-body"))
    os.chmod(path + ".tmp", 0o600)
    os.rename(path + ".tmp", path)
    sys.stderr.write("Successfully logged in\n")
    sys.exit(0)
if args[-2:] != ["app-server", "--stdio"]:
    sys.exit(1)
with open(os.path.join(BIN, "app-server-runs"), "a") as f:
    f.write("run\n")
with open(os.path.join(BIN, "app-server-homes"), "a") as f:
    f.write(os.environ.get("CODEX_HOME", "") + "\n")
home_runs = read("app-server-homes").splitlines().count(os.environ.get("CODEX_HOME", ""))
if read("replace-on-home-run").strip() == str(home_runs):
    path = os.path.join(os.environ["CODEX_HOME"], "auth.json")
    with open(path + ".tmp", "w") as f:
        f.write(read("replacement-body"))
    os.chmod(path + ".tmp", 0o600)
    os.rename(path + ".tmp", path)
run = len(read("app-server-runs").splitlines())
failing = [int(n) for n in read("failing-reads").split()]
for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    request_id = request.get("id")
    if method == "initialize":
        print(json.dumps({{"id": request_id, "result": {{"userAgent": "synthetic"}}}}), flush=True)
    elif method == "account/read":
        print(json.dumps({{"id": request_id, "result": {{"account": {{"type": "chatgpt", "email": "synthetic-account", "planType": "pro"}}, "requiresOpenaiAuth": True}}}}), flush=True)
    elif method == "account/rateLimits/read":
        if run in failing:
            print(json.dumps({{"id": request_id, "error": {{"code": -32603, "message": "synthetic failure"}}}}), flush=True)
        else:
            print(json.dumps({{"id": request_id, "result": {{"rateLimits": {{"primary": {{"usedPercent": 25, "windowDurationMins": 300}}}}}}}}), flush=True)
"#,
        bin = bin.display().to_string()
    );
    let executable = bin.join("codex");
    fs::write(&executable, script).expect("fake Codex executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("fake Codex mode");
}

/// One test's daemon-run sign-in setup: a support dir, the fake `codex`,
/// short timings and a free stand-in for the sign-in port.
#[cfg(unix)]
struct SignInFixture {
    root: PathBuf,
    bin: PathBuf,
    port: u16,
    _timings: crate::codex_sign_in::TestTimingsGuard,
    _commands: EnvVarGuard,
    _support: EnvVarGuard,
    _home: EnvVarGuard,
    _guard: std::sync::MutexGuard<'static, ()>,
}

#[cfg(unix)]
impl SignInFixture {
    fn new(name: &str, sign_in_timeout: Duration) -> Self {
        let guard = lock_backend_test_env();
        let root = control_test_root(name)
            .canonicalize()
            .expect("canonical Codex sign-in test root");
        let support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
        let bin = root.join("bin");
        write_sign_in_fake_codex(&bin);
        let commands = EnvVarGuard::set_path("OTTTO_COMMAND_SEARCH_PATH", &bin);
        // The schedule's default home is `$HOME/.codex`: none here.
        let home = EnvVarGuard::set_path("HOME", &root);
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("free port")
            .local_addr()
            .expect("port")
            .port();
        let timings = crate::codex_sign_in::TestTimingsGuard::set(
            sign_in_timeout,
            Duration::from_millis(300),
            port,
        );
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs() as i64
            + 24 * 60 * 60;
        fs::write(
            bin.join("auth-body"),
            synthetic_codex_auth_with_claims("synthetic-user", "synthetic-workspace", expires_at),
        )
        .expect("auth body");
        Self {
            root,
            bin,
            port,
            _timings: timings,
            _commands: commands,
            _support: support,
            _home: home,
            _guard: guard,
        }
    }

    fn set(&self, name: &str, body: &str) {
        fs::write(self.bin.join(name), body).expect("fake Codex setting");
    }

    fn app_server_runs(&self) -> usize {
        counted_lines(&self.bin.join("app-server-runs"))
    }

    /// App-server runs that read `home`.
    fn app_server_runs_for(&self, home: &Path) -> usize {
        fs::read_to_string(self.bin.join("app-server-homes"))
            .unwrap_or_default()
            .lines()
            .filter(|line| Path::new(line) == home)
            .count()
    }

    /// The status once the sign-in waits for the browser with an address.
    fn waiting_for_browser(&self) -> ottto_protocol::CodexAccountsStatusV1 {
        let status = self.status_until(|status| {
            status
                .setup_operation
                .sign_in
                .as_ref()
                .is_some_and(|sign_in| sign_in.sign_in_url.is_some())
        });
        assert!(status
            .setup_operation
            .sign_in
            .as_ref()
            .is_some_and(|sign_in| sign_in.sign_in_url.is_some()));
        status
    }

    /// A connected account from a daemon sign-in: its slot, home and
    /// binding hashes.
    fn connected_account(&self, operation_id: &str) -> (String, PathBuf, String, String) {
        self.set("login-mode", "success");
        let home = open_waiting_codex_setup(operation_id);
        start_codex_sign_in(1, operation_id).expect("start sign-in");
        let ended = self.ended();
        assert_eq!(
            sign_in_outcome(&ended),
            Some(ottto_protocol::CodexAccountSignInOutcomeV1::Complete)
        );
        let operation = ended.setup_operation;
        (
            operation.slot_id.expect("slot"),
            home,
            operation.account_identifier_hash.expect("account hash"),
            operation.workspace_identifier_hash.expect("workspace hash"),
        )
    }

    fn login_pids(&self) -> Vec<i32> {
        fs::read_to_string(self.bin.join("login-runs"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.parse().ok())
            .collect()
    }

    /// The status a client reads, until `done` holds or 20 s pass.
    fn status_until(
        &self,
        done: impl Fn(&ottto_protocol::CodexAccountsStatusV1) -> bool,
    ) -> ottto_protocol::CodexAccountsStatusV1 {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let status = crate::codex_sign_in::present(
                FileCodexAccountSlotSettingsStore::default()
                    .load()
                    .expect("status"),
            );
            if done(&status) || Instant::now() >= deadline {
                return status;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn ended(&self) -> ottto_protocol::CodexAccountsStatusV1 {
        let status = self.status_until(|status| {
            status
                .setup_operation
                .sign_in
                .as_ref()
                .is_some_and(|sign_in| {
                    sign_in.phase == ottto_protocol::CodexAccountSignInPhaseV1::Done
                })
        });
        assert!(crate::codex_sign_in::wait_until_idle(Duration::from_secs(
            20
        )));
        status
    }

    /// No file under the support dir holds the sign-in address.
    fn assert_url_never_written(&self) {
        fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, found);
                } else if fs::read(&path).is_ok_and(|body| {
                    String::from_utf8_lossy(&body).contains("SYNTHETIC-SIGN-IN-URL-MARKER")
                }) {
                    found.push(path);
                }
            }
        }
        let mut found = Vec::new();
        walk(&self.root, &mut found);
        // The fake CLI itself holds it.
        found.retain(|path| !path.starts_with(&self.bin));
        assert!(found.is_empty(), "sign-in address written to {found:?}");
    }
}

#[cfg(unix)]
impl Drop for SignInFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn sign_in_outcome(
    status: &ottto_protocol::CodexAccountsStatusV1,
) -> Option<ottto_protocol::CodexAccountSignInOutcomeV1> {
    status
        .setup_operation
        .sign_in
        .as_ref()
        .and_then(|sign_in| sign_in.outcome)
}

#[cfg(unix)]
fn process_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

const SIGN_IN_OPERATION: &str = "codex_setup_5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// The daemon runs `codex login`: the address it prints is offered to the
/// client while the browser is open and never written anywhere; the
/// saved credential is checked once (the identity read plus the fresh
/// pinned-workspace read) and the account is connected.
#[cfg(unix)]
#[test]
#[serial]
fn codex_daemon_sign_in_connects_the_account_and_never_writes_the_url() {
    let fixture = SignInFixture::new("codex-sign-in-success", Duration::from_secs(60));
    fixture.set("login-mode", "wait");
    open_waiting_codex_setup(SIGN_IN_OPERATION);

    let started = crate::codex_sign_in::present(
        start_codex_sign_in(1, SIGN_IN_OPERATION).expect("start sign-in"),
    );
    assert_eq!(started.daemon_sign_in_supported, Some(true));
    assert_eq!(started.setup_operation.launch_command, None);
    let waiting = fixture.status_until(|status| {
        status
            .setup_operation
            .sign_in
            .as_ref()
            .is_some_and(|sign_in| sign_in.sign_in_url.is_some())
    });
    let sign_in = waiting.setup_operation.sign_in.clone().expect("sign-in");
    assert_eq!(
        sign_in.phase,
        ottto_protocol::CodexAccountSignInPhaseV1::WaitingForBrowser
    );
    assert_eq!(
        sign_in.sign_in_url.as_ref().map(|url| url.expose_secret()),
        Some("https://auth.example.test/oauth/authorize?state=SYNTHETIC-SIGN-IN-URL-MARKER")
    );
    assert!(!format!("{waiting:?}").contains("SYNTHETIC-SIGN-IN-URL-MARKER"));
    // A replay only reports status; a check while it runs reads nothing.
    start_codex_sign_in(1, SIGN_IN_OPERATION).expect("replay");
    for _ in 0..5 {
        check_codex_account(1, SIGN_IN_OPERATION, false).expect("check while running");
    }
    assert_eq!(fixture.login_pids().len(), 1);
    assert_eq!(fixture.app_server_runs(), 0);
    fixture.assert_url_never_written();

    // Cancel that one, then sign in for real on a new operation.
    stop_waiting_for_codex_account(1, SIGN_IN_OPERATION).expect("stop");
    let operation = "codex_setup_6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
    fixture.set("login-mode", "success");
    open_waiting_codex_setup(operation);
    start_codex_sign_in(1, operation).expect("start sign-in");
    let ended = fixture.ended();
    assert_eq!(
        sign_in_outcome(&ended),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::Complete)
    );
    assert_eq!(
        ended.setup_operation.state,
        CodexAccountSetupOperationStateV1::Complete
    );
    assert_eq!(ended.managed_slots.len(), 1);
    assert_eq!(fixture.app_server_runs(), 2);
    let sign_in = ended.setup_operation.sign_in.expect("sign-in");
    assert_eq!(sign_in.sign_in_url, None);
    // The account reads are logged as setup reads; the browser sign-in is not.
    let lines = setup_call_lines(&fixture.root);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines
        .iter()
        .all(|line| line.kind == "codex_app_server_quota" && line.result == "ok"));
    fixture.assert_url_never_written();
}

/// Call-log lines with trigger `setup`.
#[cfg(unix)]
fn setup_call_lines(support: &Path) -> Vec<ottto_core::provider_call_log::ProviderCallLine> {
    let dir = ottto_core::provider_call_log::provider_call_log_dir(support);
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| fs::read_to_string(entry.path()).unwrap_or_default())
        .flat_map(|body| {
            body.lines()
                .filter_map(|line| {
                    serde_json::from_str::<ottto_core::provider_call_log::ProviderCallLine>(line)
                        .ok()
                })
                .collect::<Vec<_>>()
        })
        .filter(|line| line.trigger == "setup")
        .collect()
}

/// Stop ends `codex login` before the unadopted home is removed, and
/// the sign-in ends `cancelled`.
#[cfg(unix)]
#[test]
#[serial]
fn codex_daemon_sign_in_cancel_ends_the_cli_before_removing_the_home() {
    let fixture = SignInFixture::new("codex-sign-in-cancel", Duration::from_secs(60));
    fixture.set("login-mode", "wait");
    let home = open_waiting_codex_setup(SIGN_IN_OPERATION);
    start_codex_sign_in(1, SIGN_IN_OPERATION).expect("start sign-in");
    fixture.status_until(|status| {
        status
            .setup_operation
            .sign_in
            .as_ref()
            .is_some_and(|sign_in| sign_in.sign_in_url.is_some())
    });
    let pid = fixture.login_pids()[0];
    assert!(process_alive(pid));

    let stopped = crate::codex_sign_in::present(
        stop_waiting_for_codex_account(1, SIGN_IN_OPERATION).expect("stop"),
    );
    assert_eq!(
        sign_in_outcome(&stopped),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::Cancelled)
    );
    assert_eq!(
        stopped.setup_operation.state,
        CodexAccountSetupOperationStateV1::SetupStopped
    );
    assert!(!process_alive(pid), "codex login still runs");
    assert!(!home.exists(), "the unadopted home is removed");
    assert_eq!(
        stopped
            .setup_operation
            .sign_in
            .expect("sign-in")
            .sign_in_url,
        None
    );
    assert_eq!(fixture.app_server_runs(), 0);
    assert!(crate::codex_sign_in::wait_until_idle(Duration::from_secs(
        5
    )));
}

/// `codex login` exits 0 when stopped too: without a new credential the
/// sign-in failed, whatever the exit status. A busy sign-in port starts
/// nothing.
#[cfg(unix)]
#[test]
#[serial]
fn codex_daemon_sign_in_without_a_credential_or_with_a_busy_port_fails_plainly() {
    let fixture = SignInFixture::new("codex-sign-in-early", Duration::from_secs(60));
    for (index, mode) in ["early", "fail"].into_iter().enumerate() {
        fixture.set("login-mode", mode);
        let operation = format!("codex_setup_{index:032}");
        open_waiting_codex_setup(&operation);
        start_codex_sign_in(1, &operation).expect("start sign-in");
        let ended = fixture.ended();
        assert_eq!(
            sign_in_outcome(&ended),
            Some(ottto_protocol::CodexAccountSignInOutcomeV1::LoginFailed),
            "{mode}"
        );
        assert_eq!(
            ended.setup_operation.state,
            CodexAccountSetupOperationStateV1::SetupFailed
        );
    }
    assert_eq!(fixture.login_pids().len(), 2);

    let _held = std::net::TcpListener::bind(("127.0.0.1", fixture.port)).expect("hold port");
    let operation = "codex_setup_7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c";
    open_waiting_codex_setup(operation);
    start_codex_sign_in(1, operation).expect("start sign-in");
    let ended = fixture.ended();
    assert_eq!(
        sign_in_outcome(&ended),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::PortBusy)
    );
    assert_eq!(fixture.login_pids().len(), 2, "no login started");
    assert_eq!(fixture.app_server_runs(), 0);
}

/// The pinned-workspace read fails: `workspace_not_kept`.
#[cfg(unix)]
#[test]
#[serial]
fn codex_daemon_sign_in_reports_a_workspace_restriction_that_did_not_hold() {
    let fixture = SignInFixture::new("codex-sign-in-pinned", Duration::from_secs(60));
    fixture.set("login-mode", "success");
    fixture.set("failing-reads", "2");
    open_waiting_codex_setup(SIGN_IN_OPERATION);
    start_codex_sign_in(1, SIGN_IN_OPERATION).expect("start sign-in");
    let ended = fixture.ended();
    assert_eq!(
        sign_in_outcome(&ended),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::WorkspaceNotKept)
    );
    assert_eq!(fixture.app_server_runs(), 2);
}

/// A target setup signed into another account: `identity_mismatch`, and
/// the same operation may sign in again.
#[cfg(unix)]
#[test]
#[serial]
fn codex_daemon_sign_in_after_a_mismatch_runs_again_on_the_same_operation() {
    let fixture = SignInFixture::new("codex-sign-in-mismatch", Duration::from_secs(60));
    fixture.set("login-mode", "success");
    prepare_codex_account(
        1,
        SIGN_IN_OPERATION.to_string(),
        "a".repeat(64),
        "b".repeat(64),
    )
    .expect("prepare target");
    start_codex_sign_in(1, SIGN_IN_OPERATION).expect("start sign-in");
    let ended = fixture.ended();
    assert_eq!(
        sign_in_outcome(&ended),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::IdentityMismatch)
    );
    assert_eq!(
        ended.setup_operation.state,
        CodexAccountSetupOperationStateV1::IdentityMismatch
    );
    assert_eq!(ended.setup_operation.launch_command, None);
    assert_eq!(fixture.app_server_runs(), 1);

    start_codex_sign_in(1, SIGN_IN_OPERATION).expect("sign in again");
    let ended = fixture.ended();
    assert_eq!(fixture.login_pids().len(), 2);
    assert_eq!(
        sign_in_outcome(&ended),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::IdentityMismatch)
    );
}

/// After a daemon restart a sign-in is never started again: a credential
/// saved meanwhile is checked once, otherwise it ends `interrupted`.
#[cfg(unix)]
#[test]
#[serial]
fn codex_daemon_sign_in_recovery_checks_a_saved_credential_once_or_interrupts() {
    let fixture = SignInFixture::new("codex-sign-in-recovery", Duration::from_secs(60));
    let store = FileCodexAccountSlotSettingsStore::default();
    // The run as a daemon that stopped mid-sign-in left it.
    open_waiting_codex_setup(SIGN_IN_OPERATION);
    store
        .begin_sign_in(
            1,
            SIGN_IN_OPERATION,
            "2026-10-15T12:00:00Z".to_string(),
            "2026-10-15T12:10:00Z".to_string(),
        )
        .expect("record run")
        .expect("new run");
    crate::codex_sign_in::recover_at_startup();
    let ended = fixture.ended();
    assert_eq!(
        sign_in_outcome(&ended),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::Interrupted)
    );
    assert_eq!(
        ended.setup_operation.state,
        CodexAccountSetupOperationStateV1::SetupStopped
    );

    let operation = "codex_setup_9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e";
    let home = open_waiting_codex_setup(operation);
    store
        .begin_sign_in(
            1,
            operation,
            "2026-10-15T12:00:00Z".to_string(),
            "2026-10-15T12:10:00Z".to_string(),
        )
        .expect("record run")
        .expect("new run");
    write_synthetic_codex_auth(
        &home,
        &fs::read_to_string(fixture.bin.join("auth-body")).expect("auth body"),
    );
    crate::codex_sign_in::recover_at_startup();
    let ended = fixture.ended();
    assert_eq!(
        sign_in_outcome(&ended),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::Complete)
    );
    assert_eq!(fixture.app_server_runs(), 2);
    assert!(fixture.login_pids().is_empty(), "no sign-in restarted");
}

/// A reconnect signs in in a staging home while the slot's own home keeps
/// its credential, which the person's own Codex sessions may rewrite
/// meanwhile. Scheduled and explicit quota reads leave the slot's home
/// alone while the sign-in runs, and a rewrite there is no sign-in: a CLI
/// that ends early (exit 0 or 1) is `login_failed`, with no account read.
#[cfg(unix)]
#[test]
#[serial]
fn codex_daemon_sign_in_reconnect_counts_only_the_clis_own_sign_in() {
    let fixture = SignInFixture::new("codex-sign-in-reconnect", Duration::from_secs(60));
    let (slot_id, home, account, workspace) = fixture.connected_account(SIGN_IN_OPERATION);
    assert_eq!(fixture.app_server_runs_for(&home), 2);
    let auth_body = fs::read_to_string(home.join("auth.json")).expect("credential");
    let later = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs()
            + 24 * 60 * 60
    };

    fixture.set("login-mode", "hold");
    for (index, exit) in ["0", "1"].into_iter().enumerate() {
        let _ = fs::remove_file(fixture.bin.join("release-login"));
        let operation = format!("codex_setup_{:032}", index + 1);
        reconnect_codex_account(
            1,
            operation.clone(),
            &slot_id,
            account.clone(),
            workspace.clone(),
        )
        .expect("reconnect");
        start_codex_sign_in(1, &operation).expect("start sign-in");
        fixture.waiting_for_browser();

        // A scheduled round and an explicit refresh during the run.
        crate::agent_status::codex_scheduled_round_now(later());
        crate::agent_status::refresh_codex_quota_now();
        assert_eq!(fixture.app_server_runs_for(&home), 2, "exit {exit}");
        // The person's own Codex session refreshes the credential.
        write_synthetic_codex_auth(&home, &format!("{auth_body}\n"));

        fixture.set("release-login", exit);
        let ended = fixture.ended();
        assert_eq!(
            sign_in_outcome(&ended),
            Some(ottto_protocol::CodexAccountSignInOutcomeV1::LoginFailed),
            "exit {exit}"
        );
        assert_eq!(
            ended.setup_operation.state,
            CodexAccountSetupOperationStateV1::SetupFailed
        );
        assert_eq!(fixture.app_server_runs_for(&home), 2, "no account read");
    }

    // Once the sign-in has ended, the schedule reads the home again.
    crate::agent_status::codex_scheduled_round_now(later() + 24 * 60 * 60);
    assert_eq!(fixture.app_server_runs_for(&home), 3);

    // A reconnect the CLI completes still connects.
    let operation = "codex_setup_afafafafafafafafafafafafafafafaf";
    reconnect_codex_account(1, operation.to_string(), &slot_id, account, workspace)
        .expect("reconnect");
    fixture.set("login-mode", "success");
    start_codex_sign_in(1, operation).expect("start sign-in");
    let ended = fixture.ended();
    assert_eq!(
        sign_in_outcome(&ended),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::Complete)
    );

    // Connecting another workspace after the finished reconnect starts a
    // new setup and leaves the reconnected slot alone.
    let opened = prepare_open_codex_account(
        1,
        "codex_setup_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_string(),
    )
    .expect("open prepare after a finished reconnect");
    assert_eq!(
        opened.setup_operation.state,
        CodexAccountSetupOperationStateV1::WaitingForUserLogin
    );
    assert_ne!(
        opened.setup_operation.slot_id.as_deref(),
        Some(slot_id.as_str())
    );
    assert!(home.join("auth.json").is_file());
}

/// Sign-ins for a named account and workspace run in a staging home; only
/// the verified login is published into the slot.
#[cfg(unix)]
mod codex_staging_sign_in {
    use super::*;
    use serial_test::serial;

    fn staging_home(slot_home: &Path) -> PathBuf {
        slot_home.parent().expect("slot root").join("sign-in")
    }

    fn synthetic_auth(user: &str, workspace: &str, later_secs: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs() as i64;
        synthetic_codex_auth_with_claims(user, workspace, now + later_secs)
    }

    fn assert_slot_kept(slot_id: &str, account: &str, workspace: &str) {
        let bindings = FileCodexAccountSlotSettingsStore::default()
            .registered_bindings()
            .expect("bindings");
        assert!(bindings.iter().any(|binding| binding.slot_id == slot_id
            && binding.accepted
            && binding.account_identifier_hash == account
            && binding.workspace_identifier_hash == workspace));
    }

    /// [regress] `codex login` revokes and deletes the login of its home
    /// before the browser opens. A reconnect that is stopped, times out or
    /// signs into another account leaves the slot's login byte for byte
    /// and its identity, and removes the staging home. A new account ("+")
    /// still signs in in its own new home.
    #[test]
    #[serial]
    fn codex_reconnect_that_does_not_complete_keeps_the_slots_login() {
        use ottto_protocol::CodexAccountSignInOutcomeV1 as Outcome;
        let fixture = SignInFixture::new("codex-staging-kept", Duration::from_secs(4));
        let (slot_id, home, account, workspace) = fixture.connected_account(SIGN_IN_OPERATION);
        let staging = staging_home(&home);
        assert!(!staging.exists(), "a new account signs in in its own home");
        assert_eq!(fixture.app_server_runs_for(&home), 2);
        let credential = fs::read(home.join("auth.json")).expect("synthetic credential");
        let other = synthetic_auth("synthetic-other-user", "synthetic-other", 24 * 60 * 60);

        for (index, (mode, stop, outcome)) in [
            ("wait", true, Outcome::Cancelled),
            ("wait", false, Outcome::TimedOut),
            ("success", false, Outcome::IdentityMismatch),
        ]
        .into_iter()
        .enumerate()
        {
            fixture.set("login-mode", mode);
            fixture.set("auth-body", &other);
            let operation = format!("codex_setup_{:032}", index + 1);
            reconnect_codex_account(
                1,
                operation.clone(),
                &slot_id,
                account.clone(),
                workspace.clone(),
            )
            .expect("reconnect");
            start_codex_sign_in(1, &operation).expect("start sign-in");
            if stop {
                fixture.waiting_for_browser();
                stop_waiting_for_codex_account(1, &operation).expect("stop");
            }
            assert_eq!(
                sign_in_outcome(&fixture.ended()),
                Some(outcome),
                "{outcome:?}"
            );
            if outcome == Outcome::IdentityMismatch {
                // The wrong login is deleted; a sign-in again starts afresh.
                assert!(!staging.join("auth.json").exists());
                stop_waiting_for_codex_account(1, &operation).expect("stop");
            }
            assert_eq!(
                fs::read(home.join("auth.json")).ok().as_ref(),
                Some(&credential),
                "{outcome:?}: the slot's login is unchanged"
            );
            assert!(!staging.exists(), "{outcome:?}: staging home removed");
            assert_slot_kept(&slot_id, &account, &workspace);
        }
        assert_eq!(fixture.login_pids().len(), 4);
    }

    /// [behaviour] An accepted reconnect publishes the verified login into
    /// the slot's home only under that home's read lock, with its workspace
    /// restriction; the account reads checked the staging home, which is
    /// then removed.
    #[test]
    #[serial]
    fn codex_reconnect_publishes_the_verified_login_under_the_slots_lock() {
        let fixture = SignInFixture::new("codex-staging-publish", Duration::from_secs(60));
        let (slot_id, home, account, workspace) = fixture.connected_account(SIGN_IN_OPERATION);
        let staging = staging_home(&home);
        let before = fs::read(home.join("auth.json")).expect("credential");
        let renewed = synthetic_auth("synthetic-user", "synthetic-workspace", 2 * 24 * 60 * 60);
        fixture.set("auth-body", &renewed);

        let operation = "codex_setup_2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b";
        reconnect_codex_account(
            1,
            operation.to_string(),
            &slot_id,
            account.clone(),
            workspace.clone(),
        )
        .expect("reconnect");
        // Hold the slot's read lock from before the sign-in starts. The
        // final check cannot publish while it is held, so the slot keeps
        // its login; once it is released, the link and rename that publish
        // set the file's change time.
        let released_at = crate::agent_status::with_codex_home_read_lock(&home, || {
            start_codex_sign_in(1, operation).expect("start sign-in");
            let deadline = Instant::now() + Duration::from_secs(20);
            while fixture.app_server_runs_for(&staging) < 2 {
                assert!(Instant::now() < deadline, "the final check never ran");
                std::thread::sleep(Duration::from_millis(20));
            }
            std::thread::sleep(Duration::from_millis(1500));
            assert_eq!(
                fs::read(home.join("auth.json")).expect("credential"),
                before
            );
            assert_ne!(
                FileCodexAccountSlotSettingsStore::default()
                    .setup_operation(operation)
                    .expect("setup")
                    .state,
                CodexAccountSetupOperationStateV1::Complete,
                "published while the slot's home was locked"
            );
            SystemTime::now()
        });
        let ended = fixture.ended();
        assert_eq!(
            sign_in_outcome(&ended),
            Some(ottto_protocol::CodexAccountSignInOutcomeV1::Complete)
        );
        assert_eq!(
            fs::read_to_string(home.join("auth.json")).expect("new credential"),
            renewed
        );
        let changed = {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(home.join("auth.json")).expect("credential");
            UNIX_EPOCH + Duration::new(metadata.ctime() as u64, metadata.ctime_nsec() as u32)
        };
        // The kernel's change-time clock is coarse: allow 100 ms.
        assert!(
            changed + Duration::from_millis(100) >= released_at,
            "published before the slot's lock was released"
        );
        let config = fs::read_to_string(home.join("config.toml")).expect("config");
        assert!(config.contains("forced_chatgpt_workspace_id = \"synthetic-workspace\""));
        assert_eq!(fixture.app_server_runs_for(&staging), 2);
        assert!(!staging.exists(), "staging home removed");
        assert_slot_kept(&slot_id, &account, &workspace);
    }

    /// [behaviour] A login replaced while the final check reads it (another
    /// sign-in into the staging home) is not published: the check fails,
    /// the slot keeps its login and the staging home is removed.
    #[test]
    #[serial]
    fn codex_reconnect_refuses_a_login_replaced_during_its_check() {
        let fixture = SignInFixture::new("codex-staging-replaced", Duration::from_secs(60));
        let (slot_id, home, account, workspace) = fixture.connected_account(SIGN_IN_OPERATION);
        let staging = staging_home(&home);
        let before = fs::read(home.join("auth.json")).expect("credential");
        let later =
            |days: i64| synthetic_auth("synthetic-user", "synthetic-workspace", days * 86_400);
        fixture.set("auth-body", &later(2));
        fixture.set("replacement-body", &later(3));
        // The second read of the staging home is the final check.
        fixture.set("replace-on-home-run", "2");

        let operation = "codex_setup_2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";
        reconnect_codex_account(
            1,
            operation.to_string(),
            &slot_id,
            account.clone(),
            workspace.clone(),
        )
        .expect("reconnect");
        start_codex_sign_in(1, operation).expect("start sign-in");
        assert_eq!(
            sign_in_outcome(&fixture.ended()),
            Some(ottto_protocol::CodexAccountSignInOutcomeV1::CheckFailed)
        );
        assert_eq!(fixture.app_server_runs_for(&staging), 2);
        assert_eq!(fs::read(home.join("auth.json")).expect("kept"), before);
        assert!(!staging.exists(), "staging home removed");
        assert_slot_kept(&slot_id, &account, &workspace);
    }
}

/// The real `codex` is a wrapper whose child listens on the port. A
/// stop ends both, even when they ignore SIGTERM, so the port is free.
#[cfg(target_os = "macos")]
#[test]
#[serial]
fn codex_daemon_sign_in_stop_ends_the_clis_listener_and_frees_the_port() {
    let fixture = SignInFixture::new("codex-sign-in-listener", Duration::from_secs(60));
    fixture.set("login-mode", "fork");
    fixture.set("listen-port", &fixture.port.to_string());
    open_waiting_codex_setup(SIGN_IN_OPERATION);
    start_codex_sign_in(1, SIGN_IN_OPERATION).expect("start sign-in");
    fixture.waiting_for_browser();
    let deadline = Instant::now() + Duration::from_secs(10);
    let listener = loop {
        if let Some(pid) = fs::read_to_string(fixture.bin.join("listener-pid"))
            .ok()
            .and_then(|pid| pid.trim().parse::<i32>().ok())
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "listener never started");
        std::thread::sleep(Duration::from_millis(20));
    };
    let wrapper = fixture.login_pids()[0];
    assert!(std::net::TcpStream::connect(("127.0.0.1", fixture.port)).is_ok());

    let stopped = crate::codex_sign_in::present(
        stop_waiting_for_codex_account(1, SIGN_IN_OPERATION).expect("stop"),
    );
    assert_eq!(
        sign_in_outcome(&stopped),
        Some(ottto_protocol::CodexAccountSignInOutcomeV1::Cancelled)
    );
    assert!(!process_alive(wrapper), "the wrapper still runs");
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_alive(listener) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!process_alive(listener), "the listener still runs");
    assert!(std::net::TcpListener::bind(("127.0.0.1", fixture.port)).is_ok());
}

#[test]
fn cloud_status_accepts_only_known_sources() {
    assert!(validate_cloud_status_source(None).is_ok());
    assert!(validate_cloud_status_source(Some("bedrock")).is_ok());
    assert!(validate_cloud_status_source(Some("vertex")).is_ok());
    assert!(matches!(
        validate_cloud_status_source(Some("../register/vertex")),
        Err(LocalApiError::InvalidRequest(message)) if message.contains("bedrock or vertex")
    ));
}
use crate::agent_status::PiRouteClassification;

fn subscription_oauth_route() -> PiModelRoute {
    PiModelRoute {
        provider: "openai-codex".to_string(),
        model: "gpt-5.5".to_string(),
        thinking_level: None,
        classification: PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("chatgpt".to_string()),
            source_category: Some("chatgpt_openai_subscription".to_string()),
        },
    }
}

fn live_pi_route() -> PiModelRoute {
    let mut route = subscription_oauth_route();
    route.classification.auth_mode = Some("api_key".to_string());
    route.classification.billing_channel = Some("usage".to_string());
    route.classification.subscription_product = None;
    route
}

#[test]
fn subscription_oauth_local_evidence_accepts_recent_session_or_identity() {
    let empty_identity = BillingIdentityHints::default();
    assert!(!pi_route_has_local_verification_evidence(
        &empty_identity,
        false
    ));
    assert!(pi_route_has_local_verification_evidence(
        &empty_identity,
        true
    ));

    let identity = BillingIdentityHints {
        account_identifier_hash: Some("acct_hash".to_string()),
        ..BillingIdentityHints::default()
    };
    assert!(pi_route_has_local_verification_evidence(&identity, false));
}

#[test]
#[serial]
fn pi_default_model_not_found_names_the_model() {
    let _lock = lock_backend_test_env();
    // The route builder reads Pi's auth file; keep both lookups empty.
    let root = control_test_root("pi-default-model-not-found");
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _pi_dir_guard = EnvVarGuard::set_path("PI_CODING_AGENT_DIR", &root.join("pi-agent"));
    let failed_smoke = |diagnostic: &str| SmokeResult {
        command_found: true,
        succeeded: false,
        exit_status: Some(1),
        duration_ms: 9_000,
        message: "Pi smoke session failed.".to_string(),
        diagnostic: Some(diagnostic.to_string()),
        error_code: None,
        local_session_observed: None,
    };
    let route = live_pi_route();
    let label = format!("{} / {}", route.provider, route.model);
    let failed =
        |diagnostic: &str| pi_route_result_from_smoke(&route, &failed_smoke(diagnostic), None);
    let generic = "No Pi model routes passed smoke verification.";

    let not_found = pi_route_aggregate_result(vec![failed(
        r#"Error: 404 {"error":{"code":404,"message":"Publisher Model was not found or your project does not have access to it."}}"#,
    )]);
    assert_eq!(not_found.status, SourceVerificationStatus::Failed);
    assert_eq!(not_found.message.code, "pi_route_smoke_failed");
    assert_eq!(
        not_found.message.text,
        format!(
            "The provider couldn't find Pi's default model, {label}. Choose another default model in Pi, or ignore this; usage collection is not affected."
        )
    );

    for other in [
        "connection reset by peer",
        "Error: 404 page not found",
        "404 /v1/models endpoint not found",
        "model is overloaded",
    ] {
        let result = pi_route_aggregate_result(vec![failed(other)]);
        assert_eq!(result.status, SourceVerificationStatus::Failed, "{other}");
        assert_eq!(result.message.code, "pi_route_smoke_failed", "{other}");
        assert_eq!(result.message.text, generic, "{other}");
    }
    let not_found_404 = r#"404 model not found"#;
    let two_routes = pi_route_aggregate_result(vec![failed(not_found_404), failed(not_found_404)]);
    assert_eq!(two_routes.message.text, generic);

    // A failed Pi check shows as failed until real usage or a Verify clears it.
    let daemon = daemon().with_account(connected_account());
    daemon.record_verification_result(&not_found).unwrap();
    let status = daemon.status("token").unwrap();
    let health = status
        .sources
        .iter()
        .find(|health| health.source == SourceKind::Pi)
        .unwrap();
    assert_eq!(health.state, ottto_protocol::SourceState::Failed);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn pi_reauth_pending_route_aggregates_to_warning_not_failed() {
    let route = subscription_oauth_route();
    let reauth = pi_route_passive_result(
        &route,
        SourceVerificationStatus::Warning,
        false,
        0,
        None,
        None,
        Some("2026-06-04T00:00:00Z".to_string()),
        Some(PI_OAUTH_REAUTH_CODE.to_string()),
        "needs provider re-auth".to_string(),
        Some(true),
    );

    let aggregate = pi_route_aggregate_result(vec![reauth]);

    // The old behavior aggregated a single non-verified route to Failed /
    // pi_route_smoke_failed; an awaiting-re-auth route must be a soft Warning.
    assert_eq!(aggregate.status, SourceVerificationStatus::Warning);
    assert_eq!(aggregate.message.code, PI_OAUTH_REAUTH_CODE);
    assert!(!aggregate.verified);
}

#[test]
fn pi_admin_disabled_import_rejection_stays_typed_and_non_blocking() {
    let error = LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: "/api/v1/pi/sessions/import".to_string(),
        status: Some(403),
        body_excerpt: Some(r#"{"detail":"telemetry_disabled_by_admin"}"#.to_string()),
        reason_code: None,
    });
    assert!(is_telemetry_disabled_by_admin_error(&error));
    let smoke = SmokeResult {
        command_found: true,
        succeeded: true,
        exit_status: Some(0),
        duration_ms: 12_000,
        message: "Pi smoke session completed.".to_string(),
        diagnostic: None,
        error_code: None,
        local_session_observed: Some(true),
    };

    let route = pi_route_result_from_backend_error(
        &live_pi_route(),
        &smoke,
        Some("2026-09-11T06:55:00Z".to_string()),
        &error,
    );
    assert_eq!(route.status, SourceVerificationStatus::NoFreshTelemetry);
    assert_eq!(
        route.error_code.as_deref(),
        Some("telemetry_disabled_by_admin")
    );
    assert!(!route.message.text.contains("Sign in"));

    let aggregate = pi_route_aggregate_result(vec![route]);
    assert_eq!(aggregate.status, SourceVerificationStatus::NoFreshTelemetry);
    assert_eq!(aggregate.message.code, "telemetry_disabled_by_admin");
    assert!(aggregate
        .message
        .text
        .contains("turned off in this workspace"));
    assert!(!verification_result_should_refresh_agent_status(&aggregate));

    let daemon = daemon().with_account(connected_account());
    daemon
        .record_verification_result(&aggregate)
        .expect("record typed admin-disabled result");
    let status = daemon.status("token").expect("read projected health");
    let source = status.sources.first().expect("Pi source health");
    assert_eq!(source.grade, ottto_protocol::HealthGrade::Warning);
    assert_eq!(
        source.problems.first().map(|problem| &problem.code),
        Some(&ottto_protocol::StableProblemCode::TelemetryDisabledByAdmin)
    );
    assert!(source.recommended_actions.is_empty());
    let canonical_source = status
        .canonical_health
        .expect("canonical health")
        .sources
        .into_iter()
        .find(|source| source.app == SourceKind::Pi)
        .expect("canonical Pi source");
    assert_eq!(
        canonical_source.blocking_reason.as_deref(),
        Some("telemetry_disabled_by_admin")
    );
}

use crate::keychain::{TelemetryKeyStore, TelemetryKeychainError, TELEMETRY_KEY_FILE_STORE_ENV};
use crate::{ControlToken, LocalDaemon};
use ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV;
use ottto_protocol::{LocalClientKind, MachineIdentity, OperatingSystem, SecretString};
use serial_test::serial;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// The per-file Mutex below serializes tests within control.rs that mutate
// shared process env vars (HOME, OTTTO_*). The #[serial] markers on each
// such test extend that boundary across the entire ottto-service test
// binary so that other modules whose tests merely *read* HOME (snapshot_sync,
// agent_status, agent_configs::detection, etc.) cannot observe HOME
// mid-swap. Two named tests — verify_repair_repairs_codex_config_before_account_check
// and verify_without_local_account_points_to_app_sign_in — failed at full
// --test-threads, pass at 4; #[serial] on all env-mutating tests is the
// robust fix, since the per-file Mutex only protects against intra-file
// contention.
static TELEMETRY_CONTROL_BACKEND_TEST_LOCK: Mutex<()> = Mutex::new(());
static TELEMETRY_KEY_STORE_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Acquire the backend/env test lock, tolerating a poisoned mutex.
///
/// The guarded value is `()` and every caller restores the process env it
/// mutated via `EnvVarGuard` on scope exit, so a panic inside one critical
/// section leaves no shared state for the next test to observe. Recovering
/// the guard with `into_inner()` keeps a single legitimate test failure from
/// cascading into a wall of spurious `PoisonError` panics in every later
/// test that takes this lock — which is exactly what masked the real
/// failure when these tests raced at full `--test-threads`.
fn lock_backend_test_env() -> std::sync::MutexGuard<'static, ()> {
    TELEMETRY_CONTROL_BACKEND_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn manual_agent_status_upload_dispatch_returns_without_network_wait() {
    let started = Instant::now();

    upload_agent_status_snapshots_in_background(Vec::new());

    assert!(
        started.elapsed() < Duration::from_secs(1),
        "manual upload dispatch blocked for {:?}",
        started.elapsed()
    );
}

pub(crate) struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn set_path(key: &'static str, value: &Path) -> Self {
        Self::set_os(key, value.as_os_str().to_os_string())
    }

    pub(crate) fn set_str(key: &'static str, value: &str) -> Self {
        Self::set_os(key, OsString::from(value))
    }

    fn set_os(key: &'static str, value: OsString) -> Self {
        let previous = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }

    /// Temporarily unset an env var, restoring it (or its absence) on drop.
    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        unsafe { std::env::remove_var(key) };
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            unsafe { std::env::set_var(self.key, previous) };
        } else {
            unsafe { std::env::remove_var(self.key) };
        }
    }
}

pub(crate) struct ControlFilesFixture {
    root: PathBuf,
    _guards: [EnvVarGuard; 3],
}

impl ControlFilesFixture {
    pub(crate) fn new() -> Self {
        let root = control_test_root("local-control-files");
        fs::create_dir_all(root.join(".codex")).unwrap();
        fs::write(
            root.join(".codex/config.toml"),
            render_codex_relay_toml_block_for_base("http://127.0.0.1:43119"),
        )
        .unwrap();
        let keys = root.join("keys");
        TelemetryKeyStore::file_only(&keys)
            .save(&SourceKind::Codex, "key_local", "synthetic-key")
            .unwrap();
        let guards = [
            EnvVarGuard::set_path("HOME", &root),
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support")),
            EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &keys),
        ];
        Self {
            root,
            _guards: guards,
        }
    }

    pub(crate) fn assert_unchanged<T>(&self, run: impl FnOnce() -> T) -> T {
        fn files(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
            let mut result = std::collections::BTreeMap::new();
            for entry in fs::read_dir(root).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    result.extend(files(&path));
                } else {
                    result.insert(path.clone(), fs::read(path).unwrap());
                }
            }
            result
        }
        let before = files(&self.root);
        let result = run();
        assert_eq!(files(&self.root), before, "local files changed");
        result
    }
}

impl Drop for ControlFilesFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn bind_telemetry_control_account() -> ControlFilesFixture {
    let files = ControlFilesFixture::new();
    let mut account = connected_account();
    account.user.as_mut().unwrap().id = "user_123".into();
    account.organization.as_mut().unwrap().id = "org_123".into();
    FileAccountStore::default().save(&account).unwrap();
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_local".into(),
            machine_id: Some("machine_test".into()),
            sources: vec![],
        })
        .unwrap();
    files
}

fn telemetry_key_store_root(name: &str) -> PathBuf {
    let counter = TELEMETRY_KEY_STORE_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ottto-telemetry-control-{name}-{}-{counter}",
        std::process::id(),
    ))
}

fn control_test_root(name: &str) -> PathBuf {
    let counter = TELEMETRY_KEY_STORE_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = fs::canonicalize(std::env::temp_dir())
        .expect("canonical scratch parent")
        .join(format!(
            "ottto-control-{name}-{}-{}-{counter}",
            std::process::id(),
            current_millis()
        ));
    let _ = fs::remove_dir_all(&root);
    create_control_test_dir(&root);
    root
}

fn open_pi_test_root(path: &Path) -> OpenPiSessionRoot {
    open_pi_session_root_direct(path)
        .expect("open Pi test root")
        .expect("Pi test root exists")
}

fn test_pending_device_credential(
    preparation_id: &str,
    confirmation_authorized: bool,
) -> PendingDeviceCredentialPreparation {
    let candidate_secret = format!("candidate-{}", "value".repeat(4));
    PendingDeviceCredentialPreparation {
        schema_version: PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION,
        capability: DEVICE_CREDENTIAL_PREPARATION_CAPABILITY.to_string(),
        preparation_id: preparation_id.to_string(),
        api_base_url: DEFAULT_API_BASE_URL.to_string(),
        expires_at: "2026-08-01T00:00:00Z".to_string(),
        credential_generation: 4,
        secret_commitment_sha256: secret_sha256(&candidate_secret),
        request_authority: None,
        device: LocalDeviceBinding {
            device_id: "device-prepared".to_string(),
            machine_id: Some("machine-one".to_string()),
            sources: vec!["codex".to_string()],
        },
        confirmation_authorized,
        preconfirm_guards_passed: confirmation_authorized,
        claim_commit: None,
        confirmed_at: None,
    }
}

fn test_setup_claim_request_authority(
    prior_secret: &str,
) -> PendingDeviceCredentialRequestAuthority {
    let machine = MachineIdentity {
        hardware_uuid: Some("hardware-test".to_string()),
        ..test_machine()
    };
    let prior = PriorDeviceCredential {
        machine_id: Some("machine_test".to_string()),
        device_id: "device-prior".to_string(),
        device_sources: vec!["codex".to_string(), "pi".to_string()],
        device_secret: prior_secret.to_string(),
        owner: None,
        snapshot_namespace: "a".repeat(64),
    };
    device_credential_request_authority(
        "setup_claim",
        "claim-immutable",
        &machine,
        Some(&prior),
        Some(IDENTITY_CONTINUITY_CAPABILITY),
    )
}

#[test]
fn credential_preparation_idempotency_is_stable_and_server_operation_bounded() {
    let first = device_credential_preparation_idempotency_key(
        "setup_claim",
        "claim-one",
        "installation-one",
    );
    let replay = device_credential_preparation_idempotency_key(
        "setup_claim",
        "claim-one",
        "installation-one",
    );
    let new_claim_after_expiry = device_credential_preparation_idempotency_key(
        "setup_claim",
        "claim-two",
        "installation-one",
    );

    assert_eq!(first, replay);
    assert_ne!(first, new_claim_after_expiry);
    assert!(first.starts_with("sha256:"));
}

#[test]
fn confirmation_receipt_must_match_journaled_prior_device() {
    let mut pending = test_pending_device_credential("preparation-confirm-prior", true);
    pending.request_authority = Some(test_setup_claim_request_authority("prior-confirm-proof"));
    let exact: DeviceCredentialConfirmationApiResponse = serde_json::from_value(json!({
        "preparation_id": pending.preparation_id,
        "status": "confirmed",
        "confirmed_at": "2026-07-31T20:00:00Z",
        "credential_generation": pending.credential_generation,
        "device": {
            "id": pending.device.device_id,
            "machine_id": pending.device.machine_id,
            "sources": pending.device.sources,
        },
        "identity_continuity_capability": IDENTITY_CONTINUITY_CAPABILITY,
        "credential_rotation_performed": true,
        "rotated_prior_device_id": "device-prior",
    }))
    .expect("parse exact confirmation");
    validate_device_credential_confirmation("https://api.test/confirm", &pending, &exact)
        .expect("exact prior confirmation");

    let mismatched: DeviceCredentialConfirmationApiResponse = serde_json::from_value(json!({
        "preparation_id": pending.preparation_id,
        "status": "confirmed",
        "confirmed_at": "2026-07-31T20:00:00Z",
        "credential_generation": pending.credential_generation,
        "device": {
            "id": pending.device.device_id,
            "machine_id": pending.device.machine_id,
            "sources": pending.device.sources,
        },
        "identity_continuity_capability": IDENTITY_CONTINUITY_CAPABILITY,
        "credential_rotation_performed": true,
        "rotated_prior_device_id": "device-other",
    }))
    .expect("parse mismatched confirmation");
    assert!(validate_device_credential_confirmation(
        "https://api.test/confirm",
        &pending,
        &mismatched,
    )
    .is_err());

    let wrong_generation: DeviceCredentialConfirmationApiResponse = serde_json::from_value(json!({
        "preparation_id": pending.preparation_id,
        "status": "confirmed",
        "confirmed_at": "2026-07-31T20:00:00Z",
        "credential_generation": pending.credential_generation + 1,
        "device": {
            "id": pending.device.device_id,
            "machine_id": pending.device.machine_id,
            "sources": pending.device.sources,
        },
        "identity_continuity_capability": IDENTITY_CONTINUITY_CAPABILITY,
        "credential_rotation_performed": true,
        "rotated_prior_device_id": "device-prior",
    }))
    .expect("parse wrong-generation confirmation");
    assert!(validate_device_credential_confirmation(
        "https://api.test/confirm",
        &pending,
        &wrong_generation,
    )
    .is_err());
}

#[test]
fn prepared_candidate_stages_without_changing_active_authority() {
    use ottto_core::token_store::MemoryTokenStore;

    let root = control_test_root("credential-stage-old-authority");
    let pending_store = FilePendingDeviceCredentialStore::new(root.join("pending.json"));
    let pending_secret = MemoryTokenStore::new();
    let active_secret = MemoryTokenStore::new();
    let device_store = FileDeviceStore::new(root.join("device.json"));
    let old_device = LocalDeviceBinding {
        device_id: "device-old".to_string(),
        machine_id: Some("machine-one".to_string()),
        sources: vec!["codex".to_string()],
    };
    let old_secret = format!("old-{}", "value".repeat(4));
    let candidate = format!("candidate-{}", "value".repeat(4));
    device_store.save(&old_device).expect("save old device");
    active_secret.save(&old_secret).expect("save old secret");
    let pending = test_pending_device_credential("preparation-one", true);

    stage_pending_device_credential_with_stores(
        &pending,
        &candidate,
        &pending_store,
        &pending_secret,
    )
    .expect("stage candidate");

    assert_eq!(
        device_store.load().expect("load old device"),
        Some(old_device)
    );
    assert_eq!(active_secret.load().expect("load old secret"), old_secret);
    assert_eq!(pending_secret.load().expect("load candidate"), candidate);
    assert_eq!(pending_store.load().expect("load pending"), Some(pending));
}

#[test]
fn same_preparation_id_cannot_replace_the_staged_candidate_or_binding() {
    use ottto_core::token_store::MemoryTokenStore;

    let root = control_test_root("credential-same-id-immutable");
    let pending_store = FilePendingDeviceCredentialStore::new(root.join("pending.json"));
    let pending_secret = MemoryTokenStore::new();
    let first_candidate = format!("candidate-{}", "first".repeat(4));
    let prior_secret = format!("prior-{}", "authority".repeat(3));
    let mut pending = test_pending_device_credential("preparation-immutable", true);
    pending.secret_commitment_sha256 = secret_sha256(&first_candidate);
    pending.request_authority = Some(test_setup_claim_request_authority(&prior_secret));
    stage_pending_device_credential_with_stores(
        &pending,
        &first_candidate,
        &pending_store,
        &pending_secret,
    )
    .expect("stage first candidate");

    let replacement_candidate = format!("candidate-{}", "second".repeat(4));
    assert_eq!(
        stage_pending_device_credential_with_stores(
            &pending,
            &replacement_candidate,
            &pending_store,
            &pending_secret,
        ),
        Err(LocalApiError::StatePoisoned)
    );
    let assert_rebound = |rebound: PendingDeviceCredentialPreparation| {
        assert_eq!(
            stage_pending_device_credential_with_stores(
                &rebound,
                &first_candidate,
                &pending_store,
                &pending_secret,
            ),
            Err(LocalApiError::IdentityMutationInProgress)
        );
    };
    let mut rebound = pending.clone();
    rebound.device.device_id = "device-rebound".to_string();
    assert_rebound(rebound);

    let mut mutations = Vec::new();
    for field in [
        "prior_device_id",
        "prior_secret_commitment",
        "prior_sources",
        "continuity_capability",
        "account_scope",
        "installation_id",
        "machine_id",
        "hardware_uuid",
    ] {
        let mut rebound = pending.clone();
        let authority = rebound
            .request_authority
            .as_mut()
            .expect("request authority");
        match field {
            "prior_device_id" => authority.prior_device_id = Some("device-other".to_string()),
            "prior_secret_commitment" => {
                authority.prior_secret_commitment_sha256 = Some(secret_sha256("prior-other"));
            }
            "prior_sources" => {
                authority.prior_device_sources = Some(vec!["claude_code".to_string()]);
            }
            "continuity_capability" => {
                authority.identity_continuity_capability = Some("other-capability".to_string());
            }
            "account_scope" => authority.account_scope = Some("account-other".to_string()),
            "installation_id" => authority.installation_id = "install-other".to_string(),
            "machine_id" => authority.machine_id = "machine-other".to_string(),
            "hardware_uuid" => authority.hardware_uuid = Some("hardware-other".to_string()),
            _ => unreachable!(),
        }
        mutations.push((field, rebound));
    }
    for (field, rebound) in mutations {
        let result = stage_pending_device_credential_with_stores(
            &rebound,
            &first_candidate,
            &pending_store,
            &pending_secret,
        );
        if field == "continuity_capability" {
            assert_eq!(result, Err(LocalApiError::StatePoisoned));
        } else {
            assert_eq!(
                result,
                Err(LocalApiError::IdentityMutationInProgress),
                "same-ID request authority rebound for {field}"
            );
        }
    }
    assert_eq!(
        pending_secret.load().expect("original candidate retained"),
        first_candidate
    );
    assert_eq!(
        pending_store.load().expect("original binding retained"),
        Some(pending)
    );
}

#[test]
fn pending_setup_token_repairs_an_unreadable_orphan_with_exact_journal_value() {
    struct FailFirstLoadStore {
        loads: AtomicUsize,
        value: Mutex<Option<String>>,
    }

    impl ControlTokenStore for FailFirstLoadStore {
        fn load(&self) -> Result<String, TokenStoreError> {
            if self.loads.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(TokenStoreError::Store(
                    "simulated transient read failure".to_string(),
                ));
            }
            self.value
                .lock()
                .expect("token value lock")
                .clone()
                .ok_or(TokenStoreError::Missing)
        }

        fn save(&self, token: &str) -> Result<(), TokenStoreError> {
            *self.value.lock().expect("token value lock") = Some(token.to_string());
            Ok(())
        }

        fn delete(&self) -> Result<(), TokenStoreError> {
            *self.value.lock().expect("token value lock") = None;
            Ok(())
        }
    }

    let setup_token = format!("setup-{}", "recovery".repeat(3));
    let mut pending = test_pending_device_credential("preparation-token-recovery", true);
    pending.claim_commit = Some(PendingClaimCredentialCommit {
        account: connected_account(),
        connection: LocalConnectionBinding {
            setup_run_id: "setup-token-recovery".to_string(),
            setup_run_token_expires_at: "2099-01-01T00:00:00Z".to_string(),
            machine_id: Some("machine-one".to_string()),
            claim_code: Some("claim-token-recovery".to_string()),
            api_base_url: DEFAULT_API_BASE_URL.to_string(),
        },
        target_user_id: "user_test".to_string(),
        setup_run_token_sha256: secret_sha256(&setup_token),
        backfill_policy: None,
        backfill_cutoff_at: None,
    });
    let store = FailFirstLoadStore {
        loads: AtomicUsize::new(0),
        value: Mutex::new(Some("unreadable-orphan".to_string())),
    };

    stage_pending_setup_run_token_with_store(&pending, &setup_token, &store)
        .expect("replace unreadable orphan with exact journal token");

    assert_eq!(
        store.value.lock().expect("token value lock").as_deref(),
        Some(setup_token.as_str())
    );
}

#[test]
#[serial]
fn post_confirm_device_file_failure_keeps_candidate_restart_recoverable() {
    use ottto_core::token_store::MemoryTokenStore;

    let root = control_test_root("credential-promote-file-failure");
    // Promotion cleanup also touches the default pending setup-token store,
    // even when the device stores below are explicit in-memory fixtures.
    let secret_root = root.join("secrets");
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let setup_token_store = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT);
    setup_token_store
        .save("setup-file-failure")
        .expect("stage setup token");
    let pending_store = FilePendingDeviceCredentialStore::new(root.join("pending.json"));
    let pending_secret = MemoryTokenStore::new();
    let active_secret = MemoryTokenStore::new();
    let blocked_parent = root.join("blocked-parent");
    fs::write(&blocked_parent, b"not-a-directory").expect("create blocker");
    let device_store = FileDeviceStore::new(blocked_parent.join("device.json"));
    let candidate = format!("candidate-{}", "value".repeat(4));
    let pending = test_pending_device_credential("preparation-two", true);
    stage_pending_device_credential_with_stores(
        &pending,
        &candidate,
        &pending_store,
        &pending_secret,
    )
    .expect("stage candidate");
    let confirmed =
        mark_pending_device_credential_confirmed(&pending, "2026-07-31T20:00:00Z", &pending_store)
            .expect("mark confirmed");

    assert_eq!(
        promote_pending_device_credential_with_stores(
            &confirmed,
            &candidate,
            &pending_store,
            &pending_secret,
            &device_store,
            &active_secret,
        ),
        Err(LocalApiError::StatePoisoned)
    );
    assert_eq!(
        pending_store.load().expect("pending survives"),
        Some(confirmed.clone())
    );
    assert_eq!(
        pending_secret.load().expect("candidate survives"),
        candidate
    );
    assert_eq!(
        active_secret.load().expect("active candidate write"),
        candidate
    );

    assert_eq!(
        setup_token_store.load().expect("setup token survives"),
        "setup-file-failure"
    );
    fs::remove_file(&blocked_parent).expect("remove blocker");
    fs::create_dir(&blocked_parent).expect("create device parent");
    promote_pending_device_credential_with_stores(
        &confirmed,
        &candidate,
        &pending_store,
        &pending_secret,
        &device_store,
        &active_secret,
    )
    .expect("retry promotion");

    assert!(pending_store.load().expect("pending cleared").is_none());
    assert!(matches!(
        setup_token_store.load(),
        Err(TokenStoreError::Missing)
    ));
    assert!(matches!(
        pending_secret.load(),
        Err(TokenStoreError::Missing)
    ));
    assert_eq!(
        device_store
            .load_with_credential_generation()
            .expect("load active binding")
            .expect("active binding")
            .credential_generation,
        4
    );
}

#[test]
fn confirmed_journal_rejects_a_replaced_candidate_secret_before_promotion() {
    use ottto_core::token_store::MemoryTokenStore;

    let root = control_test_root("credential-confirmed-secret-binding");
    let pending_store = FilePendingDeviceCredentialStore::new(root.join("pending.json"));
    let pending_secret = MemoryTokenStore::new();
    let active_secret = MemoryTokenStore::new();
    let device_store = FileDeviceStore::new(root.join("device.json"));
    let candidate = format!("candidate-{}", "value".repeat(4));
    let replacement = format!("candidate-{}", "replaced".repeat(4));
    let old_secret = format!("old-{}", "authority".repeat(3));
    active_secret.save(&old_secret).expect("save old authority");
    let pending = test_pending_device_credential("preparation-secret-binding", true);
    stage_pending_device_credential_with_stores(
        &pending,
        &candidate,
        &pending_store,
        &pending_secret,
    )
    .expect("stage candidate");
    let confirmed =
        mark_pending_device_credential_confirmed(&pending, "2026-07-31T20:00:00Z", &pending_store)
            .expect("mark confirmed");

    // Mutation oracle: simulate a stale/corrupted Keychain value after the
    // server confirmation receipt became durable.
    pending_secret
        .save(&replacement)
        .expect("replace staged secret");
    assert_eq!(
        promote_pending_device_credential_with_stores(
            &confirmed,
            &replacement,
            &pending_store,
            &pending_secret,
            &device_store,
            &active_secret,
        ),
        Err(LocalApiError::StatePoisoned)
    );
    assert_eq!(
        active_secret.load().expect("old authority retained"),
        old_secret
    );
    assert_eq!(
        pending_store.load().expect("journal retained"),
        Some(confirmed)
    );
    assert!(device_store
        .load()
        .expect("device remains absent")
        .is_none());
}

#[test]
#[serial]
fn confirmed_regular_rotation_fences_old_authority_until_restart_promotion() {
    let support_root = telemetry_key_store_root("credential-rotation-recovery");
    let secret_root = telemetry_key_store_root("credential-rotation-recovery-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);

    let old_device = LocalDeviceBinding {
        device_id: "device-old".to_string(),
        machine_id: Some("machine-one".to_string()),
        sources: vec!["codex".to_string()],
    };
    let old_secret = format!("old-{}", "authority".repeat(3));
    FileDeviceStore::default()
        .save(&old_device)
        .expect("save old device");
    fs::write(
        secret_root.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        &old_secret,
    )
    .expect("save old secret fallback");

    let pending_store = FilePendingDeviceCredentialStore::default();
    let pending_secret = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT);
    let active_secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT);
    let candidate = format!("candidate-{}", "rotation".repeat(3));
    let mut pending = test_pending_device_credential("preparation-regular-rotation", true);
    pending.preconfirm_guards_passed = false;
    pending.secret_commitment_sha256 = secret_sha256(&candidate);
    pending.request_authority = Some(device_credential_request_authority(
        "register",
        "install-regular-rotation",
        &test_machine(),
        Some(&PriorDeviceCredential {
            machine_id: Some("machine_test".to_string()),
            device_id: old_device.device_id.clone(),
            device_sources: old_device.sources.clone(),
            device_secret: old_secret.clone(),
            owner: None,
            snapshot_namespace: "a".repeat(64),
        }),
        Some(IDENTITY_CONTINUITY_CAPABILITY),
    ));
    stage_pending_device_credential(&pending, &candidate).expect("stage rotation candidate");

    // Preparing alone never invalidates the old authority.
    assert_eq!(
        crate::snapshot_client::load_snapshot_device_credentials()
            .expect("old authority remains admissible before confirmation"),
        (old_device.clone(), old_secret)
    );
    assert!(crate::snapshot_client::ensure_no_incomplete_device_credential_promotion().is_ok());

    let pending = mark_pending_device_credential_guards_passed(&pending, &pending_store)
        .expect("persist pre-confirm crash boundary");
    // Once the confirm request can be sent, a lost response is ambiguous:
    // the server may already have revoked the prior generation.
    assert!(crate::snapshot_client::load_snapshot_device_credentials().is_err());
    assert!(crate::snapshot_client::ensure_no_incomplete_device_credential_promotion().is_err());

    let confirmed =
        mark_pending_device_credential_confirmed(&pending, "2026-07-31T20:00:00Z", &pending_store)
            .expect("mark rotation confirmed");
    let blocked_parent = support_root.join("blocked-rotation-parent");
    fs::write(&blocked_parent, b"not-a-directory").expect("create promotion blocker");
    let blocked_device_store = FileDeviceStore::new(blocked_parent.join("device.json"));
    assert_eq!(
        promote_pending_device_credential_with_stores(
            &confirmed,
            &candidate,
            &pending_store,
            &pending_secret,
            &blocked_device_store,
            &active_secret,
        ),
        Err(LocalApiError::StatePoisoned)
    );
    assert_eq!(
        FileDeviceStore::default()
            .load()
            .expect("old device remains"),
        Some(old_device)
    );

    // Server confirmation can revoke the old generation. Even though its
    // local files still exist, neither snapshots nor cached OTLP admission
    // may use it across this crash cut.
    assert!(crate::snapshot_client::load_snapshot_device_credentials().is_err());
    assert!(crate::snapshot_client::ensure_no_incomplete_device_credential_promotion().is_err());

    assert_eq!(recover_pending_device_credential_at_startup(), Ok(true));
    assert!(pending_store.load().expect("pending cleared").is_none());
    assert_eq!(
        crate::snapshot_client::load_snapshot_device_credentials()
            .expect("promoted authority admitted"),
        (confirmed.device, candidate)
    );
    assert!(crate::snapshot_client::ensure_no_incomplete_device_credential_promotion().is_ok());
}

#[test]
#[serial]
fn post_confirm_claim_commit_failure_fences_live_admission_then_rolls_forward() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let support_root = telemetry_key_store_root("credential-claim-commit-recovery");
    let secret_root = telemetry_key_store_root("credential-claim-commit-recovery-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let account = connected_account();
    let connection = LocalConnectionBinding {
        setup_run_id: "setup-recover".to_string(),
        setup_run_token_expires_at: "2099-01-01T00:00:00Z".to_string(),
        machine_id: Some("machine-one".to_string()),
        claim_code: Some("claim-recover".to_string()),
        api_base_url: DEFAULT_API_BASE_URL.to_string(),
    };
    let setup_token = format!("setup-{}", "claim".repeat(4));
    let mut pending = test_pending_device_credential("preparation-claim-recover", true);
    pending.claim_commit = Some(PendingClaimCredentialCommit {
        target_user_id: account.user.as_ref().expect("connected user").id.clone(),
        account: account.clone(),
        connection: connection.clone(),
        setup_run_token_sha256: secret_sha256(&setup_token),
        backfill_policy: None,
        backfill_cutoff_at: None,
    });
    let candidate = format!("candidate-{}", "claim".repeat(4));
    pending.secret_commitment_sha256 = secret_sha256(&candidate);
    stage_pending_device_credential(&pending, &candidate).expect("stage claim candidate");
    stage_pending_setup_run_token(&pending, &setup_token).expect("stage claim setup token");
    pending = mark_pending_device_credential_confirmed(
        &pending,
        "2026-07-31T20:00:00Z",
        &FilePendingDeviceCredentialStore::default(),
    )
    .expect("mark claim confirmed");

    let blocked_connection = support_root.join("connection.json");
    fs::create_dir(&blocked_connection).expect("block connection file");
    assert_eq!(
        recover_pending_device_credential_at_startup(),
        Err(LocalApiError::StatePoisoned)
    );
    assert_eq!(
        FilePendingDeviceCredentialStore::default()
            .load()
            .expect("claim journal retained"),
        Some(pending.clone())
    );
    assert!(crate::snapshot_client::load_snapshot_device_credentials().is_err());
    assert!(crate::snapshot_client::ensure_no_incomplete_device_credential_promotion().is_err());
    assert!(matches!(
        setup_run_token_for_connection(DEFAULT_API_BASE_URL, &connection),
        Err(LocalApiError::IdentityMutationInProgress)
    ));
    fs::remove_dir(&blocked_connection).expect("unblock connection file");

    assert_eq!(recover_pending_device_credential_at_startup(), Ok(true));
    assert_eq!(
        FileAccountStore::default().load().expect("active account"),
        account
    );
    assert_eq!(
        FileConnectionStore::default()
            .load()
            .expect("active connection"),
        Some(connection)
    );
    assert_eq!(
        KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .load()
            .expect("active setup token"),
        setup_token
    );
    assert_eq!(
        KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .expect("active device candidate"),
        candidate
    );
    assert!(FilePendingDeviceCredentialStore::default()
        .load()
        .expect("claim journal cleared")
        .is_none());
    // Pending-secret deletion is deliberately best-effort after the
    // verified active commit. A Keychain cleanup failure may leave an
    // inert orphan, but without the journal it is neither discoverable nor
    // authority and the next exact journal-bound stage replaces it.
    assert!(crate::snapshot_client::load_snapshot_device_credentials().is_ok());
    assert!(crate::snapshot_client::ensure_no_incomplete_device_credential_promotion().is_ok());
}

#[test]
fn unconfirmed_or_unauthorized_candidate_cannot_promote() {
    use ottto_core::token_store::MemoryTokenStore;

    let root = control_test_root("credential-promote-unauthorized");
    let pending_store = FilePendingDeviceCredentialStore::new(root.join("pending.json"));
    let pending_secret = MemoryTokenStore::new();
    let active_secret = MemoryTokenStore::new();
    let device_store = FileDeviceStore::new(root.join("device.json"));
    let pending = test_pending_device_credential("preparation-three", false);
    let candidate = format!("candidate-{}", "value".repeat(4));
    stage_pending_device_credential_with_stores(
        &pending,
        &candidate,
        &pending_store,
        &pending_secret,
    )
    .expect("stage candidate");

    assert_eq!(
        promote_pending_device_credential_with_stores(
            &pending,
            &candidate,
            &pending_store,
            &pending_secret,
            &device_store,
            &active_secret,
        ),
        Err(LocalApiError::StatePoisoned)
    );
    assert!(matches!(
        active_secret.load(),
        Err(TokenStoreError::Missing)
    ));
    assert_eq!(
        pending_store.load().expect("pending remains"),
        Some(pending)
    );
}

fn seed_pending_recovery_fixture(
    api_base_url: String,
    confirmation_authorized: bool,
    expires_at: &str,
    secret_root: &Path,
) -> (PendingDeviceCredentialPreparation, String) {
    use ottto_core::token_store::FileControlTokenStore;

    let mut pending =
        test_pending_device_credential("preparation-recovery", confirmation_authorized);
    pending.api_base_url = api_base_url;
    pending.expires_at = expires_at.to_string();
    let candidate = format!("candidate-{}", "recovery".repeat(4));
    pending.secret_commitment_sha256 = secret_sha256(&candidate);
    FilePendingDeviceCredentialStore::default()
        .save(&pending)
        .expect("save pending recovery fixture");
    FileControlTokenStore::new(secret_root.join(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT))
        .save(&candidate)
        .expect("save pending candidate fallback");
    (pending, candidate)
}

#[test]
#[serial]
fn confirmed_pruned_preparation_recovers_via_normal_device_auth() {
    let support_root = telemetry_key_store_root("credential-pruned-confirmed");
    let secret_root = telemetry_key_store_root("credential-pruned-confirmed-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind recovery backend");
    let address = listener.local_addr().expect("recovery backend address");
    let api_base_url = format!("http://{address}");
    let (mut pending, _) =
        seed_pending_recovery_fixture(api_base_url, true, "2026-08-01T00:00:00Z", &secret_root);
    pending.request_authority = Some(test_setup_claim_request_authority("prior-pruned-proof"));
    FilePendingDeviceCredentialStore::default()
        .save(&pending)
        .expect("save authority-bound pruned journal");
    thread::spawn(move || {
        let (mut confirm, _) = listener.accept().expect("accept pruned confirm");
        let _ = read_complete_http_request(&mut confirm);
        write_json_response(&mut confirm, 404, "Not Found", r#"{"detail":"pruned"}"#);
        let (mut probe, _) = listener.accept().expect("accept relay probe");
        let _ = read_complete_http_request(&mut probe);
        write_json_response(&mut probe, 200, "OK", r#"{"relay_token":"issued"}"#);
    });

    assert_eq!(recover_pending_device_credential_at_startup(), Ok(true));
    assert!(FilePendingDeviceCredentialStore::default()
        .load()
        .expect("load pending")
        .is_none());
    let active = FileDeviceStore::default()
        .load_with_credential_generation()
        .expect("load active")
        .expect("active generation");
    assert_eq!(active.device, pending.device);
    assert_eq!(active.credential_generation, pending.credential_generation);
}

#[test]
#[serial]
fn expired_pruned_preparation_clears_only_after_normal_auth_rejection() {
    let support_root = telemetry_key_store_root("credential-pruned-expired");
    let secret_root = telemetry_key_store_root("credential-pruned-expired-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind recovery backend");
    let address = listener.local_addr().expect("recovery backend address");
    seed_pending_recovery_fixture(
        format!("http://{address}"),
        false,
        "2020-01-01T00:00:00Z",
        &secret_root,
    );
    thread::spawn(move || {
        let (mut status, _) = listener.accept().expect("accept pruned status");
        let _ = read_complete_http_request(&mut status);
        write_json_response(&mut status, 404, "Not Found", r#"{"detail":"pruned"}"#);
        let (mut probe, _) = listener.accept().expect("accept rejected relay probe");
        let _ = read_complete_http_request(&mut probe);
        write_json_response(&mut probe, 401, "Unauthorized", r#"{"detail":"invalid"}"#);
    });

    assert_eq!(recover_pending_device_credential_at_startup(), Ok(false));
    assert!(FilePendingDeviceCredentialStore::default()
        .load()
        .expect("load pending")
        .is_none());
}

fn create_control_test_dir(path: &Path) {
    fs::create_dir_all(path).expect("create control test dir");
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("set control test dir permissions");
    }
}

fn fake_binary_path(root: &Path, name: &str) -> PathBuf {
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).expect("fake bin dir");
    let binary = bin_dir.join(name);
    fs::write(&binary, "#!/bin/sh\n").expect("fake binary");
    if name == "claude" {
        // The quiet window reads the keychain before a Claude smoke and
        // fails closed without `security`. This fake reports "item not
        // found" (exit 44): no stored login.
        let security = bin_dir.join("security");
        fs::write(&security, "#!/bin/sh\nexit 44\n").expect("fake security");
        #[cfg(unix)]
        fs::set_permissions(&security, fs::Permissions::from_mode(0o755))
            .expect("fake security mode");
    }
    binary
}

fn count_backup_files(path: &Path) -> usize {
    fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .metadata()
                        .map(|metadata| metadata.is_file())
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn handles_authenticated_status_request() {
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_test".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Status {
                refresh_agent_status: false,
                retry_relay_authorization: false,
            },
        },
    );

    assert!(response.ok, "{response:?}");
    assert_eq!(response.error, None);
    assert_eq!(
        response.payload.expect("payload").get("daemon"),
        Some(&serde_json::Value::String("running".to_string()))
    );
}

#[test]
#[serial]
fn handles_authenticated_receipts_request_from_private_ring() {
    let support_root = control_test_root("receipts-control");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    crate::upload_receipts::append_transport_error(&support_root, SourceKind::Codex, 3).unwrap();
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_receipts".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Receipts {
                limit: 10,
                since: None,
                source: Some(SourceKind::Codex),
                before: None,
            },
        },
    );
    assert!(response.ok, "{response:?}");
    let payload = response.payload.unwrap();
    assert_eq!(payload["schema"], "ottto.upload_receipts.v1");
    assert_eq!(payload["receipts"][0]["outcome"], "transport_error");
    assert_eq!(payload["receipts"][0]["batch_item_count"], 3);
    let _ = fs::remove_dir_all(support_root);
}

#[test]
#[serial]
fn claude_accounts_require_auth_and_apply_operation_specific_mutations() {
    let root = control_test_root("claude-config-slots");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let test_daemon = daemon();

    for command in [
        LocalControlCommand::ClaudeAccountsStatus,
        LocalControlCommand::ClaudeAccountSetUpkeepConsent {
            schema_version: 1,
            consent: true,
        },
        LocalControlCommand::ClaudeAccountRemove {
            schema_version: 1,
            slot_id: "claude_slot_0123456789abcdef0123456789abcdef".to_string(),
        },
        LocalControlCommand::ClaudeAccountRegisterPath {
            schema_version: 1,
            config_dir: "/tmp/claude-work/".to_string(),
        },
        LocalControlCommand::ClaudeAccountPrepare {
            schema_version: 1,
            operation_id: "claude_setup_0123456789abcdef0123456789abcdef".to_string(),
            expected_account_identifier_hash: None,
        },
        LocalControlCommand::ClaudeAccountReconnect {
            schema_version: 1,
            operation_id: "claude_setup_0123456789abcdef0123456789abcdef".to_string(),
            slot_id: "claude_slot_0123456789abcdef0123456789abcdef".to_string(),
            expected_account_identifier_hash: "a".repeat(64),
        },
        LocalControlCommand::ClaudeAccountCheck {
            schema_version: 1,
            operation_id: "claude_setup_0123456789abcdef0123456789abcdef".to_string(),
            expected_account_identifier_hash: None,
        },
        LocalControlCommand::ClaudeAccountStopWaiting {
            schema_version: 1,
            operation_id: "claude_setup_0123456789abcdef0123456789abcdef".to_string(),
        },
    ] {
        let response = handle_request(
            &test_daemon,
            LocalControlRequest {
                request_id: "req_slots_unauthorized".to_string(),
                protocol_version: ottto_protocol::CLAUDE_ACCOUNTS_CONTROL_PROTOCOL_VERSION,
                token: Some("bad-token".to_string()),
                client_kind: Some(LocalClientKind::CompanionApp),
                client_install_owner: None,
                command,
            },
        );
        assert!(!response.ok);
        assert_eq!(
            response.error.expect("auth error").code,
            CliErrorCode::LocalAuthFailed
        );
    }

    let registered = handle_request(
        &test_daemon,
        LocalControlRequest {
            request_id: "req_account_register".to_string(),
            protocol_version: ottto_protocol::CLAUDE_ACCOUNTS_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::CompanionApp),
            client_install_owner: None,
            command: LocalControlCommand::ClaudeAccountRegisterPath {
                schema_version: 1,
                config_dir: "/tmp/claude-work/".to_string(),
            },
        },
    );
    assert!(registered.ok, "{registered:?}");
    let register_payload = registered.payload.expect("register payload");
    // "Keep my Claude accounts signed in" is on until the user chooses.
    assert_eq!(register_payload["consent"], "granted");
    assert_eq!(
        register_payload["default_slot"]["service_name"],
        "Claude Code-credentials"
    );
    assert_eq!(
        register_payload["external_slots"][0]["config_dir"],
        "/tmp/claude-work/"
    );
    assert_eq!(
        register_payload["external_slots"][0]["ownership"],
        "external"
    );
    assert!(register_payload["managed_slots"]
        .as_array()
        .expect("managed slots")
        .is_empty());
    assert_eq!(register_payload["setup_operation"]["state"], "idle");
    assert_eq!(register_payload["capacity"]["max_slots"], 10);
    assert_eq!(register_payload["capacity"]["used_slots"], 2);

    let consented = handle_request(
        &test_daemon,
        LocalControlRequest {
            request_id: "req_account_consent".to_string(),
            protocol_version: ottto_protocol::CLAUDE_ACCOUNTS_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::CompanionApp),
            client_install_owner: None,
            command: LocalControlCommand::ClaudeAccountSetUpkeepConsent {
                schema_version: 1,
                consent: true,
            },
        },
    );
    assert!(consented.ok, "{consented:?}");
    let consent_payload = consented.payload.expect("consent payload");
    assert_eq!(consent_payload["consent"], "granted");

    let loaded = handle_request(
        &test_daemon,
        LocalControlRequest {
            request_id: "req_accounts_status".to_string(),
            protocol_version: ottto_protocol::CLAUDE_ACCOUNTS_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::CompanionApp),
            client_install_owner: None,
            command: LocalControlCommand::ClaudeAccountsStatus,
        },
    );
    assert!(loaded.ok, "{loaded:?}");
    assert_eq!(loaded.payload.expect("status payload"), consent_payload);

    let slot_id = register_payload["external_slots"][0]["slot_id"]
        .as_str()
        .expect("slot id")
        .to_string();
    let removed = handle_request(
        &test_daemon,
        LocalControlRequest {
            request_id: "req_account_remove".to_string(),
            protocol_version: ottto_protocol::CLAUDE_ACCOUNTS_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::CompanionApp),
            client_install_owner: None,
            command: LocalControlCommand::ClaudeAccountRemove {
                schema_version: 1,
                slot_id,
            },
        },
    );
    assert!(removed.ok, "{removed:?}");
    assert_eq!(
        removed.payload.expect("remove payload")["capacity"]["used_slots"],
        1
    );
    assert!(root.join("claude-config-slots.json").is_file());

    let operation_id = "claude_setup_abcdefabcdefabcdefabcdefabcdefab";
    let lifecycle_request = |request_id: &str, command| LocalControlRequest {
        request_id: request_id.to_string(),
        protocol_version: ottto_protocol::CLAUDE_ACCOUNTS_CONTROL_PROTOCOL_VERSION,
        token: Some("token".to_string()),
        client_kind: Some(LocalClientKind::CompanionApp),
        client_install_owner: None,
        command,
    };
    let prepared = handle_request(
        &test_daemon,
        lifecycle_request(
            "req_account_prepare",
            LocalControlCommand::ClaudeAccountPrepare {
                schema_version: 1,
                operation_id: operation_id.to_string(),
                expected_account_identifier_hash: None,
            },
        ),
    );
    assert!(prepared.ok, "{prepared:?}");
    let prepared_payload = prepared.payload.expect("prepare payload");
    assert_eq!(
        prepared_payload["setup_operation"]["state"],
        "waiting_for_user_login"
    );
    assert!(prepared_payload["setup_operation"]["launch_command"]
        .as_str()
        .is_some_and(
            |command| command.starts_with("CLAUDE_CONFIG_DIR='") && command.ends_with("' claude")
        ));

    let stopped = handle_request(
        &test_daemon,
        lifecycle_request(
            "req_account_stop",
            LocalControlCommand::ClaudeAccountStopWaiting {
                schema_version: 1,
                operation_id: operation_id.to_string(),
            },
        ),
    );
    assert!(stopped.ok, "{stopped:?}");
    assert_eq!(
        stopped.payload.as_ref().expect("stop payload")["setup_operation"]["state"],
        "setup_stopped"
    );

    let queued_check = handle_request(
        &test_daemon,
        lifecycle_request(
            "req_account_stopped_check",
            LocalControlCommand::ClaudeAccountCheck {
                schema_version: 1,
                operation_id: operation_id.to_string(),
                expected_account_identifier_hash: None,
            },
        ),
    );
    assert!(queued_check.ok, "{queued_check:?}");
    assert_eq!(
        queued_check.payload.expect("stopped check payload")["setup_operation"]["state"],
        "setup_stopped"
    );

    // A new daemon instance reads the same persisted stopped operation;
    // only explicit prepare replay resumes the same slot/path.
    let restarted_daemon = daemon();
    let resumed = handle_request(
        &restarted_daemon,
        lifecycle_request(
            "req_account_resume",
            LocalControlCommand::ClaudeAccountPrepare {
                schema_version: 1,
                operation_id: operation_id.to_string(),
                expected_account_identifier_hash: None,
            },
        ),
    );
    assert!(resumed.ok, "{resumed:?}");
    assert_eq!(
        resumed.payload.expect("resume payload")["setup_operation"]["state"],
        "waiting_for_user_login"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn forget_installation_fails_closed_when_prior_selector_cannot_be_removed() {
    let root = telemetry_key_store_root("forget-installation-prior-selector-failure");
    let support_root = root.join("support");
    let secret_root = root.join("secrets");
    fs::create_dir_all(&support_root).unwrap();
    fs::create_dir_all(&secret_root).unwrap();
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileMachineStore::default()
        .save(&LocalMachineBinding {
            machine_id: "otm_must_survive".to_string(),
            installation_id: "oti_must_survive".to_string(),
            hardware_uuid: None,
        })
        .unwrap();
    fs::create_dir_all(default_prior_device_path()).unwrap();

    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_forget_prior_failure".to_string(),
            protocol_version: ottto_protocol::INSTALLATION_RESET_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::AuthReset {
                local_only: true,
                forget_installation: true,
            },
        },
    );

    assert!(!response.ok, "selector removal failure must abort reset");
    assert!(FileMachineStore::default().load().unwrap().is_some());
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn claude_reconnect_binds_existing_slot_identity_and_final_check_fails_closed() {
    let root = control_test_root("claude-account-reconnect");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let exact_dir = format!("{}/existing account/", root.display());
    let registered = store
        .register_path(1, exact_dir.clone())
        .expect("register existing slot");
    let slot_id = registered.external_slots[0].slot_id.clone();
    let account_hash = "a".repeat(64);
    let organization_hash = "b".repeat(64);
    crate::agent_status::persist_one_claude_slot_collection_state(
        &slot_id,
        &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::NeedsLogin,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2026-08-05T00:00:00Z".to_string()),
            ..Default::default()
        },
    )
    .expect("persist last strong identity");
    let operation_id = "claude_setup_99999999999999999999999999999999";
    let begun = reconnect_claude_account(
        1,
        operation_id.to_string(),
        &slot_id,
        None,
        account_hash.clone(),
        None,
    )
    .expect("begin reconnect");
    assert_eq!(
        begun.setup_operation.kind,
        ottto_protocol::ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
    );
    assert_eq!(begun.external_slots.len(), 1);
    assert_eq!(
        begun.external_slots[0].config_dir.as_deref(),
        Some(exact_dir.as_str())
    );
    assert_eq!(
        begun.setup_operation.slot_id.as_deref(),
        Some(slot_id.as_str())
    );
    assert!(begun
        .setup_operation
        .launch_command
        .as_deref()
        .is_some_and(
            |command| command.contains("existing account/") && !command.contains("/login")
        ));
    assert!(matches!(
        reconnect_claude_account(
            1,
            "claude_setup_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            &slot_id,
            None,
            "c".repeat(64),
            None,
        ),
        Err(LocalApiError::InvalidRequest(_))
    ));

    let mismatched = check_claude_account_with_collector(
        1,
        operation_id,
        Some(&account_hash),
        |observed_slot_id, _, _| {
            assert_eq!(observed_slot_id, slot_id);
            ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(account_hash.clone()),
                organization_identifier_hash: Some("e".repeat(64)),
                observed_at: Some("2026-08-05T00:01:00Z".to_string()),
                last_full_quota_read_at: Some("2026-08-05T00:01:00Z".to_string()),
                has_account_windows: true,
                has_scoped_limits: true,
                ..Default::default()
            }
        },
    )
    .expect("identity mismatch is typed");
    assert_eq!(
        mismatched.setup_operation.state,
        ClaudeAccountSetupOperationState::IdentityMismatch
    );

    store.remove(1, &slot_id).expect("remove registered slot");
    assert!(matches!(
        check_claude_account_with_collector(1, operation_id, Some(&account_hash), |_, _, _| {
            unreachable!("removed slot cannot be collected")
        }),
        Err(LocalApiError::InvalidRequest(_))
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn legacy_prepare_requires_one_unambiguous_organization_for_expected_account() {
    let root = control_test_root("claude-legacy-prepare-composite");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let account_hash = "a".repeat(64);
    let organization_a = "b".repeat(64);
    let organization_b = "c".repeat(64);
    let first = store
        .register_path(1, root.join("first").display().to_string())
        .expect("register first legacy witness");
    let first_slot = first.external_slots[0].slot_id.clone();
    let second = store
        .register_path(1, root.join("second").display().to_string())
        .expect("register second legacy witness");
    let second_slot = second
        .external_slots
        .iter()
        .find(|slot| slot.slot_id != first_slot)
        .expect("second slot")
        .slot_id
        .clone();
    for (slot_id, organization_hash) in [
        (&first_slot, &organization_a),
        (&second_slot, &organization_b),
    ] {
        crate::agent_status::persist_one_claude_slot_collection_state(
            slot_id,
            &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::NeedsLogin,
                account_identifier_hash: Some(account_hash.clone()),
                organization_identifier_hash: Some(organization_hash.clone()),
                ..Default::default()
            },
        )
        .expect("persist composite legacy witness");
    }

    assert!(matches!(
        prepare_claude_account_legacy(
            1,
            "claude_setup_11111111111111111111111111111111".to_string(),
            Some(account_hash.clone()),
        ),
        Err(LocalApiError::InvalidRequest(_))
    ));
    assert!(matches!(
        prepare_claude_account_legacy(
            1,
            "claude_setup_22222222222222222222222222222222".to_string(),
            Some("d".repeat(64)),
        ),
        Err(LocalApiError::InvalidRequest(_))
    ));

    store.remove(1, &second_slot).expect("remove ambiguity");
    crate::agent_status::prune_claude_slot_collection_state(&second_slot)
        .expect("prune removed witness");
    let prepared = prepare_claude_account_legacy(
        1,
        "claude_setup_33333333333333333333333333333333".to_string(),
        Some(account_hash.clone()),
    )
    .expect("unique legacy binding prepares");
    assert_eq!(
        prepared.setup_operation.expected_account_identifier_hash,
        Some(account_hash.clone())
    );
    assert_eq!(
        prepared
            .setup_operation
            .expected_organization_identifier_hash,
        Some(organization_a)
    );
    let replayed = prepare_claude_account_legacy(
        1,
        "claude_setup_33333333333333333333333333333333".to_string(),
        Some(account_hash),
    )
    .expect("legacy replay remains idempotent");
    assert_eq!(
        replayed.setup_operation.slot_id,
        prepared.setup_operation.slot_id
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn legacy_v18_and_v19_terminal_replay_release_their_ceremony_claim() {
    let root = control_test_root("claude-legacy-terminal-replay-claim");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let store = FileClaudeConfigSlotSettingsStore::default();

    let v18 = "claude_setup_44444444444444444444444444444444";
    store
        .prepare_managed_account(1, v18.to_string(), None)
        .expect("v18 prepare");
    assert!(crate::claude_browser_auth::claim_ceremony(v18).expect("v18 claim"));
    store
        .transition_setup_operation_with_binding(
            1,
            v18,
            None,
            None,
            ClaudeAccountSetupOperationState::SetupFailed,
            None,
            None,
            Some("terminal v18 fixture"),
        )
        .expect("v18 terminal");
    let replayed =
        prepare_claude_account_legacy(1, v18.to_string(), None).expect("v18 terminal replay");
    assert_eq!(
        replayed.setup_operation.state,
        ClaudeAccountSetupOperationState::SetupFailed
    );
    let after_v18 = "claude_setup_45454545454545454545454545454545";
    assert!(crate::claude_browser_auth::claim_ceremony(after_v18).expect("v18 claim released"));
    crate::claude_browser_auth::release_ceremony(after_v18);

    let v19 = "claude_setup_46464646464646464646464646464646";
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    store
        .prepare_managed_account_target(
            1,
            v19.to_string(),
            Some("claude_anchor_target_46464646464646464646464646464646".to_string()),
            Some(account.clone()),
            Some(organization.clone()),
        )
        .expect("v19 prepare");
    assert!(crate::claude_browser_auth::claim_ceremony(v19).expect("v19 claim"));
    store
        .transition_setup_operation_with_binding(
            1,
            v19,
            Some(&account),
            Some(&organization),
            ClaudeAccountSetupOperationState::IdentityMismatch,
            None,
            None,
            Some("terminal v19 fixture"),
        )
        .expect("v19 terminal");
    let replayed = prepare_claude_account(
        1,
        v19.to_string(),
        Some("claude_anchor_target_46464646464646464646464646464646".to_string()),
        Some(account),
        Some(organization),
        None,
    )
    .expect("v19 terminal replay");
    assert_eq!(
        replayed.setup_operation.state,
        ClaudeAccountSetupOperationState::IdentityMismatch
    );
    let after_v19 = "claude_setup_47474747474747474747474747474747";
    assert!(crate::claude_browser_auth::claim_ceremony(after_v19).expect("v19 claim released"));
    crate::claude_browser_auth::release_ceremony(after_v19);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn active_v23_reconnect_same_id_replay_is_idempotent() {
    use std::os::unix::fs::PermissionsExt;

    let root = control_test_root("claude-browser-reconnect-active-replay");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let managed_parent = root.join(ottto_core::CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    let managed = managed_parent.join("claude_slot_48484848484848484848484848484848");
    fs::create_dir_all(&managed).expect("managed root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("support mode");
    fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
        .expect("managed parent mode");
    fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("managed mode");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_managed_path(1, managed.to_string_lossy().into_owned())
        .expect("register");
    let slot_id = registered.managed_slots[0].slot_id.clone();
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    crate::agent_status::persist_one_claude_slot_collection_state(
        &slot_id,
        &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            ..Default::default()
        },
    )
    .expect("strong binding");
    let operation_id = "claude_setup_48484848484848484848484848484848";
    let target_id = "claude_anchor_target_48484848484848484848484848484848";
    store
        .begin_registered_slot_reconnect_target(
            1,
            operation_id.to_string(),
            &slot_id,
            Some(target_id.to_string()),
            account.clone(),
            Some(organization.clone()),
        )
        .expect("core reconnect");
    fs::write(
        root.join("claude-browser-auth-state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "active_operation_id": operation_id,
            "operations": [{
                "operation_id": operation_id,
                "slot_id": slot_id.clone(),
                "config_dir": managed.to_string_lossy(),
                "ceremony_baseline": "baseline",
                "mode": "reconnect",
                "target_id": target_id,
                "expected_account_identifier_hash": account,
                "expected_organization_identifier_hash": organization,
                "phase": "waiting_for_provider",
                "cancel_requested": false,
                "started_unix_seconds": 1,
                "deadline_unix_seconds": u64::MAX,
                "fallback_completed": false
            }],
            "quarantined_roots": []
        }))
        .expect("sidecar json"),
    )
    .expect("active sidecar");

    let state_path = root.join("claude-browser-auth-state.json");
    let core_path = root.join(ottto_core::CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME);
    let core_before = fs::read(&core_path).expect("core before replay");
    let sidecar_before = fs::read(&state_path).expect("sidecar before replay");
    let worker_lock = crate::claude_browser_auth::registry_mutation_guard(operation_id)
        .expect("worker operation lock");

    let replayed = start_claude_browser_reconnect(
        1,
        operation_id.to_string(),
        &slot_id,
        target_id.to_string(),
    )
    .expect("active replay");
    assert_eq!(
        replayed.setup_operation.state,
        ClaudeAccountSetupOperationState::WaitingForUserLogin
    );
    assert_eq!(
        replayed
            .setup_operation
            .browser_auth
            .as_ref()
            .map(|browser| browser.phase),
        Some(ottto_protocol::ClaudeBrowserAuthPhaseV1::WaitingForProvider)
    );
    assert_eq!(
        fs::read(&core_path).expect("core after replay"),
        core_before
    );
    assert_eq!(
        fs::read(&state_path).expect("sidecar after replay"),
        sidecar_before
    );
    assert!(crate::claude_browser_auth::claim_ceremony(
        "claude_setup_49494949494949494949494949494949"
    )
    .is_err());
    drop(worker_lock);
    crate::claude_browser_auth::release_ceremony(operation_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn claude_account_check_orchestrates_full_partial_pause_and_rotation_without_fanout() {
    let root = control_test_root("claude-account-check-orchestration");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let account_a = "a".repeat(64);
    let account_b = "b".repeat(64);
    let organization_a = "f".repeat(64);
    let operation_a = "claude_setup_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let store = FileClaudeConfigSlotSettingsStore::default();
    store
        .prepare_managed_account(1, operation_a.to_string(), Some(account_a.clone()))
        .expect("prepare exact account");

    let full = check_claude_account_with_collector(1, operation_a, Some(&account_a), |_, _, _| {
        ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_a.clone()),
            organization_identifier_hash: Some(organization_a.clone()),
            observed_at: Some("2026-08-04T10:00:00Z".to_string()),
            last_full_quota_read_at: Some("2026-08-04T10:00:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            has_credit_balances: false,
            ..Default::default()
        }
    })
    .expect("one synchronous full check");
    assert_eq!(
        full.setup_operation.state,
        ClaudeAccountSetupOperationState::Complete
    );

    for temporary in [
        ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
    ] {
        let retained =
            check_claude_account_with_collector(1, operation_a, Some(&account_a), |_, _, _| {
                ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                    state: temporary,
                    observed_at: Some("2026-08-04T10:00:30Z".to_string()),
                    ..Default::default()
                }
            })
            .expect("temporary evidence loss preserves complete");
        assert_eq!(
            retained.setup_operation.state,
            ClaudeAccountSetupOperationState::Complete
        );
    }

    let rotated =
        check_claude_account_with_collector(1, operation_a, Some(&account_a), |_, _, _| {
            ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(account_b),
                organization_identifier_hash: Some(organization_a.clone()),
                observed_at: Some("2026-08-04T10:01:00Z".to_string()),
                last_full_quota_read_at: Some("2026-08-04T10:01:00Z".to_string()),
                has_account_windows: true,
                has_scoped_limits: true,
                ..Default::default()
            }
        })
        .expect("rotation is typed, not an API failure");
    assert_eq!(
        rotated.setup_operation.state,
        ClaudeAccountSetupOperationState::IdentityMismatch
    );

    let operation_partial = "claude_setup_cccccccccccccccccccccccccccccccc";
    let account_c = "c".repeat(64);
    let organization_c = "d".repeat(64);
    store
        .prepare_managed_account(1, operation_partial.to_string(), Some(account_c.clone()))
        .expect("prepare partial account");
    let partial =
        check_claude_account_with_collector(1, operation_partial, Some(&account_c), |_, _, _| {
            ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(account_c.clone()),
                organization_identifier_hash: Some(organization_c.clone()),
                observed_at: Some("2026-08-04T10:02:00Z".to_string()),
                has_account_windows: true,
                has_scoped_limits: false,
                ..Default::default()
            }
        })
        .expect("partial check");
    assert_eq!(
        partial.setup_operation.state,
        ClaudeAccountSetupOperationState::Reading
    );

    let paused =
        check_claude_account_with_collector(1, operation_partial, Some(&account_c), |_, _, _| {
            ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::CollectionPaused,
                account_identifier_hash: Some(account_c.clone()),
                organization_identifier_hash: Some(organization_c.clone()),
                observed_at: Some("2026-08-04T10:03:00Z".to_string()),
                ..Default::default()
            }
        })
        .expect("paused check remains active");
    assert_eq!(
        paused.setup_operation.state,
        ClaudeAccountSetupOperationState::Reading
    );
    store
        .stop_waiting(1, operation_partial)
        .expect("stop partial operation before next setup");

    let cases = [
        (
            "claude_setup_11111111111111111111111111111111",
            ClaudeConfigSlotCollectionStateV1::CredentialUnavailable,
            None,
            ClaudeAccountSetupOperationState::WaitingForUserLogin,
        ),
        (
            "claude_setup_22222222222222222222222222222222",
            ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
            None,
            ClaudeAccountSetupOperationState::WaitingForUserLogin,
        ),
        (
            "claude_setup_33333333333333333333333333333333",
            ClaudeConfigSlotCollectionStateV1::Unverified,
            None,
            ClaudeAccountSetupOperationState::WaitingForUserLogin,
        ),
        (
            "claude_setup_44444444444444444444444444444444",
            ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            Some("d".repeat(64)),
            ClaudeAccountSetupOperationState::Reading,
        ),
        (
            "claude_setup_55555555555555555555555555555555",
            ClaudeConfigSlotCollectionStateV1::CollectionInProgress,
            Some("e".repeat(64)),
            ClaudeAccountSetupOperationState::Reading,
        ),
        // A same-owner race is never "wrong account": without a verified
        // account it keeps waiting, and with the expected one it keeps
        // reading. A race that switched owners arrives as
        // `IdentityMismatch`; see
        // `claude_account_check_sees_a_race_to_another_account_as_mismatch`.
        (
            "claude_setup_66666666666666666666666666666666",
            ClaudeConfigSlotCollectionStateV1::ConcurrentMutation,
            None,
            ClaudeAccountSetupOperationState::WaitingForUserLogin,
        ),
        (
            "claude_setup_77777777777777777777777777777777",
            ClaudeConfigSlotCollectionStateV1::ConcurrentMutation,
            Some("7".repeat(64)),
            ClaudeAccountSetupOperationState::Reading,
        ),
    ];
    for (operation_id, collection_state, account_hash, expected_state) in cases {
        store
            .prepare_managed_account(1, operation_id.to_string(), account_hash.clone())
            .expect("prepare matrix case");
        let result = check_claude_account_with_collector(
            1,
            operation_id,
            account_hash.as_deref(),
            |_, _, _| ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: collection_state.clone(),
                account_identifier_hash: account_hash.clone(),
                organization_identifier_hash: account_hash.as_ref().map(|_| "9".repeat(64)),
                observed_at: Some("2026-08-04T10:04:00Z".to_string()),
                ..Default::default()
            },
        )
        .expect("matrix check");
        assert_eq!(result.setup_operation.state, expected_state);
        let slot_id = result.setup_operation.slot_id.as_deref().expect("slot id");
        let slot = result
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .expect("managed slot");
        assert_eq!(slot.collection.state, collection_state);
        if matches!(
            result.setup_operation.state,
            ClaudeAccountSetupOperationState::WaitingForUserLogin
                | ClaudeAccountSetupOperationState::Reading
        ) {
            store
                .stop_waiting(1, operation_id)
                .expect("stop matrix operation before next setup");
        }
    }
    let _ = fs::remove_dir_all(root);
}

/// [regress] The real race status at the setup boundary: verified A, a
/// race ending on A keeps the setup complete; ending on B is a mismatch.
#[test]
#[serial]
fn claude_account_check_sees_a_race_to_another_account_as_mismatch() {
    let root = control_test_root("claude-account-check-race-switch");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let hash = |kind: &str, value: &str| {
        ottto_core::billing_identity_hash("anthropic", kind, value).expect("hash")
    };
    let account_a = hash("account", "account-a");
    let operation = "claude_setup_5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    let prepared = FileClaudeConfigSlotSettingsStore::default()
        .prepare_managed_account(1, operation.to_string(), Some(account_a.clone()))
        .expect("prepare exact account");
    let slot = prepared.managed_slots.last().expect("managed slot");
    let config_dir = slot.config_dir.clone().expect("managed config dir");
    fs::create_dir_all(&config_dir).expect("managed config dir exists");
    let write_identity = |account: &str| {
        let identity = serde_json::json!({"oauthAccount": {
            "accountUuid": account, "organizationUuid": "organization-race"}});
        fs::write(
            Path::new(&config_dir).join(".claude.json"),
            identity.to_string(),
        )
        .expect("identity");
    };
    let race = |slot_id: &str, captured_at: String, _: String| {
        crate::agent_status::registered_claude_race_status_for_test(
            slot_id,
            &config_dir,
            &captured_at,
        )
    };
    // [regress] A race with no verified account (approval lookup failed,
    // no prior binding) keeps setup waiting without a /login prompt.
    let unbound = check_claude_account_with_collector(1, operation, Some(&account_a), |_, _, _| {
        ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::ConcurrentMutation,
            observed_at: Some("2026-08-04T09:59:00Z".to_string()),
            ..Default::default()
        }
    })
    .expect("unbound race");
    assert_eq!(
        unbound.setup_operation.state,
        ClaudeAccountSetupOperationState::WaitingForUserLogin
    );
    assert!(!unbound
        .setup_operation
        .message
        .as_deref()
        .unwrap_or_default()
        .contains("/login"));

    write_identity("account-a");
    let full = check_claude_account_with_collector(1, operation, Some(&account_a), |_, _, _| {
        ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_a.clone()),
            organization_identifier_hash: Some(hash("organization", "organization-race")),
            observed_at: Some("2026-08-04T10:00:00Z".to_string()),
            last_full_quota_read_at: Some("2026-08-04T10:00:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            ..Default::default()
        }
    })
    .expect("verified full check");
    assert_eq!(
        full.setup_operation.state,
        ClaudeAccountSetupOperationState::Complete
    );

    let same = check_claude_account_with_collector(1, operation, Some(&account_a), race)
        .expect("same-owner race");
    assert_eq!(
        same.setup_operation.state,
        ClaudeAccountSetupOperationState::Complete
    );

    write_identity("account-b");
    let switched = check_claude_account_with_collector(1, operation, Some(&account_a), race)
        .expect("switched race is typed");
    assert_eq!(
        switched.setup_operation.state,
        ClaudeAccountSetupOperationState::IdentityMismatch
    );
    assert_ne!(
        switched.setup_operation.account_identifier_hash,
        Some(hash("account", "account-b"))
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn target_prepare_anchors_default_only_binding_and_replays_after_it_is_anchored() {
    let root = control_test_root("claude-target-prepare-default-only");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let account_hash = "a".repeat(64);
    let organization_hash = "b".repeat(64);
    crate::agent_status::persist_one_claude_slot_collection_state(
        "default",
        &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2026-08-23T00:00:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            ..Default::default()
        },
    )
    .expect("persist default-only binding");
    let discovered = load_claude_config_slot_settings().expect("discover target");
    let target = discovered
        .anchor_coverage
        .accounts
        .iter()
        .find(|account| {
            account.durability == ottto_protocol::ClaudeAccountAnchorDurabilityV1::DefaultOnly
        })
        .and_then(|account| account.target_id.clone())
        .expect("daemon-authored target");
    let operation_id = "claude_setup_12121212121212121212121212121212";
    let prepared = prepare_claude_account_target(1, operation_id.to_string(), target.clone())
        .expect("prepare exact default-only target");
    assert_eq!(
        prepared.setup_operation.expected_account_identifier_hash,
        Some(account_hash.clone())
    );
    assert_eq!(
        prepared
            .setup_operation
            .expected_organization_identifier_hash,
        Some(organization_hash.clone())
    );
    let slot_id = prepared
        .setup_operation
        .slot_id
        .clone()
        .expect("managed slot");
    crate::agent_status::persist_one_claude_slot_collection_state(
        &slot_id,
        &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash),
            organization_identifier_hash: Some(organization_hash),
            observed_at: Some("2026-08-23T00:01:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            ..Default::default()
        },
    )
    .expect("persist new anchor");
    let replay = prepare_claude_account_target(1, operation_id.to_string(), target)
        .expect("replay remains idempotent after target becomes anchored");
    assert_eq!(
        replay.setup_operation.slot_id.as_deref(),
        Some(slot_id.as_str())
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn transient_core_lookup_failure_preserves_exact_reusable_claim_for_recovery() {
    let root = control_test_root("claude-target-transient-core-failure");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let seed_id = "claude_setup_17171717171717171717171717171717";
    crate::claude_browser_auth::prepare_generic(store.load().expect("registry"), seed_id)
        .expect("seed reusable root");
    assert!(crate::claude_browser_auth::request_cancel(seed_id).expect("cancel seed"));

    let operation_id = "claude_setup_18181818181818181818181818181818";
    assert!(crate::claude_browser_auth::claim_ceremony(operation_id).expect("claim ceremony"));
    let reusable = crate::claude_browser_auth::claim_reusable_root(operation_id)
        .expect("claim reusable")
        .expect("one reusable root");
    crate::claude_browser_auth::persist_registry_mutation_fence(
        operation_id,
        crate::claude_browser_auth::BrowserLoginMode::Target,
        None,
        Some(&reusable),
        Some("claude_anchor_target_18181818181818181818181818181818"),
        Some(&"a".repeat(64)),
        Some(&"b".repeat(64)),
    )
    .expect("target fence");
    let status_before_failure = store.load().expect("pre-failure registry");
    let settings_path = root.join(ottto_core::CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME);
    fs::create_dir(&settings_path).expect("inject core read/write failure");

    recover_failed_claude_browser_registry_mutation(
        &store,
        operation_id,
        Some(crate::claude_browser_auth::BrowserLoginMode::Target),
        true,
    );
    assert!(crate::claude_browser_auth::has_browser_operation(
        operation_id
    ));
    let sidecar_only = crate::claude_browser_auth::annotate_status(status_before_failure);
    assert_eq!(sidecar_only.retained_provisional_login_count, None);
    assert!(crate::claude_browser_auth::claim_ceremony(
        "claude_setup_19191919191919191919191919191919"
    )
    .is_err());

    fs::remove_dir(&settings_path).expect("restore core store");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    while std::time::Instant::now() < deadline
        && crate::claude_browser_auth::has_browser_operation(operation_id)
    {
        thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(!crate::claude_browser_auth::has_browser_operation(
        operation_id
    ));
    let retry_id = "claude_setup_19191919191919191919191919191919";
    assert!(crate::claude_browser_auth::claim_ceremony(retry_id).expect("retry ceremony"));
    assert_eq!(
        crate::claude_browser_auth::claim_reusable_root(retry_id)
            .expect("retry root")
            .as_deref(),
        Some(reusable.as_str())
    );
    crate::claude_browser_auth::release_reusable_root_claim(retry_id);
    crate::claude_browser_auth::release_ceremony(retry_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn concurrent_same_id_target_replay_uses_one_exact_root_without_ledger_leak() {
    for reusable_count in [1usize, 2] {
        let root = control_test_root(&format!("claude-target-concurrent-replay-{reusable_count}"));
        let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
        let store = FileClaudeConfigSlotSettingsStore::default();
        for index in 0..reusable_count {
            let blocker_id = format!("claude_setup_{:032x}", 0x280usize + index);
            if index > 0 {
                assert!(crate::claude_browser_auth::claim_reusable_root(&blocker_id)
                    .expect("temporarily claim earlier root")
                    .is_some());
            }
            let seed_id = format!("claude_setup_{:032x}", 0x200usize + index);
            crate::claude_browser_auth::prepare_generic(store.load().expect("registry"), &seed_id)
                .expect("seed reusable root");
            assert!(crate::claude_browser_auth::request_cancel(&seed_id).expect("cancel seed"));
            if index > 0 {
                crate::claude_browser_auth::release_reusable_root_claim(&blocker_id);
            }
        }
        let account_hash = "a".repeat(64);
        let organization_hash = "b".repeat(64);
        crate::agent_status::persist_one_claude_slot_collection_state(
            "default",
            &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(account_hash),
                organization_identifier_hash: Some(organization_hash),
                observed_at: Some("2026-08-31T00:00:00Z".to_string()),
                has_account_windows: true,
                has_scoped_limits: true,
                ..Default::default()
            },
        )
        .expect("default identity");
        let discovered = load_claude_config_slot_settings().expect("discover target");
        let target_id = discovered
            .anchor_coverage
            .accounts
            .iter()
            .find(|account| {
                account.durability == ottto_protocol::ClaudeAccountAnchorDurabilityV1::DefaultOnly
            })
            .and_then(|account| account.target_id.clone())
            .expect("target");
        let operation_id = format!("claude_setup_{:032x}", 0x300usize + reusable_count);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let operation_id = operation_id.clone();
            let target_id = target_id.clone();
            workers.push(thread::spawn(move || {
                barrier.wait();
                prepare_claude_account_target_mode(1, operation_id, target_id, true)
                    .expect("concurrent target replay")
            }));
        }
        barrier.wait();
        let first = workers.remove(0).join().expect("first replay");
        let second = workers.remove(0).join().expect("second replay");
        assert_eq!(
            first.setup_operation.slot_id,
            second.setup_operation.slot_id
        );
        let slot_id = first.setup_operation.slot_id.clone().expect("slot");
        let first_root = first
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .expect("first root");
        let second_root = second
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .expect("second root");
        assert_eq!(first_root, second_root);
        assert_eq!(
            crate::claude_browser_auth::collection_suppression(&slot_id),
            Some(crate::claude_browser_auth::ClaudeCollectionSuppression::HideProvisionalTarget)
        );
        let during = crate::claude_browser_auth::annotate_status(
            store.load().expect("status during target"),
        );
        assert_eq!(
            during.retained_provisional_login_count.unwrap_or(0) as usize,
            reusable_count - 1
        );
        assert!(crate::claude_browser_auth::request_cancel(&operation_id).expect("cancel target"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline
            && crate::claude_browser_auth::has_browser_operation(&operation_id)
            && crate::claude_browser_auth::annotate_status(
                store.load().expect("poll target cancellation"),
            )
            .retained_provisional_login_count
            .unwrap_or(0) as usize
                != reusable_count
        {
            thread::sleep(std::time::Duration::from_millis(25));
        }
        let after =
            crate::claude_browser_auth::annotate_status(store.load().expect("status after target"));
        assert_eq!(
            after.retained_provisional_login_count.unwrap_or(0) as usize,
            reusable_count
        );
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
#[serial]
fn claude_account_check_is_singleflight_and_stop_wins_inflight_finalization() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let root = control_test_root("claude-account-check-singleflight");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let operation_id = "claude_setup_77777777777777777777777777777777";
    let account_hash = "7".repeat(64);
    let organization_hash = "6".repeat(64);
    let store = FileClaudeConfigSlotSettingsStore::default();
    store
        .prepare_managed_account(1, operation_id.to_string(), Some(account_hash.clone()))
        .expect("prepare");
    let probes = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let first_hash = account_hash.clone();
    let first_organization_hash = organization_hash.clone();
    let first_probes = Arc::clone(&probes);
    let first = thread::spawn(move || {
        check_claude_account_with_collector(1, operation_id, Some(&first_hash), |_, _, _| {
            first_probes.fetch_add(1, Ordering::SeqCst);
            entered_tx.send(()).expect("entered");
            release_rx.recv().expect("release");
            ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(first_hash.clone()),
                organization_identifier_hash: Some(first_organization_hash.clone()),
                observed_at: Some("2026-08-04T11:00:00Z".to_string()),
                last_full_quota_read_at: Some("2026-08-04T11:00:00Z".to_string()),
                has_account_windows: true,
                has_scoped_limits: true,
                ..Default::default()
            }
        })
    });
    entered_rx.recv().expect("first probe entered");
    let loser_probes = Arc::clone(&probes);
    let loser =
        check_claude_account_with_collector(1, operation_id, Some(&account_hash), |_, _, _| {
            loser_probes.fetch_add(1, Ordering::SeqCst);
            unreachable!("single-flight loser must not collect")
        })
        .expect("loser returns persisted progress");
    assert_eq!(
        loser.setup_operation.state,
        ClaudeAccountSetupOperationState::Validating
    );
    let stopped = store.stop_waiting(1, operation_id).expect("stop in flight");
    assert_eq!(
        stopped.setup_operation.state,
        ClaudeAccountSetupOperationState::SetupStopped
    );
    release_tx.send(()).expect("release first");
    let first_result = first.join().expect("join first").expect("first result");
    assert_eq!(
        first_result.setup_operation.state,
        ClaudeAccountSetupOperationState::SetupStopped
    );
    assert_eq!(probes.load(Ordering::SeqCst), 1);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn browser_claim_commands_accept_cli_token_authorization_boundary() {
    for command in [
        LocalControlCommand::AuthStart,
        LocalControlCommand::AuthComplete {
            claim_code: "claim_test".to_string(),
            nonce: "nonce_test".to_string(),
        },
        LocalControlCommand::AuthCompletePending {
            claim_code: "claim_test".to_string(),
        },
        LocalControlCommand::Status {
            refresh_agent_status: false,
            retry_relay_authorization: false,
        },
        LocalControlCommand::AuthSwitchAccount {
            claim_code: "claim_test".into(),
        },
        LocalControlCommand::ClaudeAccountStartBrowserLogin {
            schema_version: ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            operation_id: "claude_setup_a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0".into(),
            target_id: None,
        },
        LocalControlCommand::ClaudeAccountStartBrowserReconnect {
            schema_version: ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            operation_id: "claude_setup_b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0".into(),
            slot_id: "claude_slot_b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0".into(),
            target_id: "claude_target_b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0".into(),
        },
    ] {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_cli_browser_claim".to_string(),
                protocol_version: ottto_protocol::expected_local_control_protocol_version(&command),
                token: Some("bad-token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command,
            },
        );

        assert!(!response.ok);
        assert_eq!(
            response.error.expect("error").code,
            CliErrorCode::LocalAuthFailed
        );
    }
}

#[test]
#[serial]
fn retired_claude_auth_code_command_rejects_without_side_effects_or_echo() {
    let _guard = lock_backend_test_env();
    let root = control_test_root("retired-claude-auth-code");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let submitted = "fixture-code-must-not-echo";
    let operation_id = "claude_setup_c0dec0dec0dec0dec0dec0dec0dec0de";
    let request = |request_id: &str, token: Option<&str>| {
        serde_json::json!({
            "request_id": request_id,
            "protocol_version": ottto_protocol::CLAUDE_AUTH_CODE_CONTROL_PROTOCOL_VERSION,
            "token": token,
            "client_kind": "companion_app",
            "command": "claude_account_submit_auth_code",
            "schema_version": ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            "operation_id": operation_id,
            "code": submitted,
        })
        .to_string()
    };
    let trusted_peer = || Some(LocalClientPeer::trusted_for_tests());
    for (request_id, token, peer, expected) in [
        (
            "req_retired_token",
            Some("token"),
            None,
            CliErrorCode::InvalidRequest,
        ),
        (
            "req_retired_peer",
            None,
            trusted_peer(),
            CliErrorCode::InvalidRequest,
        ),
        (
            "req_retired_bad_token",
            Some("bad-token"),
            trusted_peer(),
            CliErrorCode::LocalAuthFailed,
        ),
        (
            "req_retired_untrusted",
            None,
            None,
            CliErrorCode::LocalClientNotTrusted,
        ),
    ] {
        let _ = crate::local_resource_diagnostics::take_control();
        let raw = handle_request_json_with_peer(&daemon(), &request(request_id, token), peer);
        assert!(!raw.contains(submitted), "{request_id} echoed the code");
        assert!(
            !raw.contains(operation_id),
            "{request_id} echoed the operation"
        );
        assert_eq!(
            crate::local_resource_diagnostics::take_control(),
            BTreeMap::from([("other", 1)]),
            "{request_id} diagnostics class"
        );
        let response: LocalControlResponse =
            serde_json::from_str(&raw).expect("local control response");
        assert_eq!(response.request_id, request_id);
        assert!(!response.ok);
        assert!(response.payload.is_none());
        let error = response.error.expect("error");
        assert_eq!(error.code, expected, "{request_id}");
        if expected == CliErrorCode::InvalidRequest {
            assert_eq!(
                error.message,
                crate::claude_browser_auth::RETIRED_CODE_SUBMISSION_MESSAGE
            );
            // Approved user-facing copy; older apps display it verbatim.
            assert_eq!(
                error.message,
                "Finish signing in to Claude in your browser. \
                     Nothing happening? Cancel and try again."
            );
            assert!(!error.retryable);
            assert!(error.details.is_empty());
            let message = error.message.to_lowercase();
            for forbidden in [
                "unknown variant",
                "unknown command",
                "protocol_version",
                "schema_version",
                "code",
                "terminal",
            ] {
                assert!(!message.contains(forbidden), "{forbidden}");
            }
        }
        assert!(
            !root.join("claude-browser-auth-state.json").exists(),
            "{request_id} touched browser-auth state"
        );
    }
}

#[test]
fn setup_claim_completion_parses_backfill_policy_fields() {
    let completed: SetupClaimCompleteResponse = serde_json::from_value(serde_json::json!({
        "setup_run_id": "setup_1",
        "setup_run_token": "otsr_test",
        "setup_run_token_expires_at": "2026-07-06T11:00:00Z",
        "machine_id": "machine_test",
        "relay_device": null,
        "relay_device_secret": null,
        "connected_at": "2026-07-06T10:00:00Z",
        "user": {"id": "user_2", "email": "other@example.com", "display_name": null},
        "organization": {"id": "org_1", "name": "Org"},
        "backfill_policy": "from",
        "backfill_cutoff_at": "2026-07-06T10:00:00Z"
    }))
    .expect("new-backend completion parses");
    assert_eq!(completed.backfill_policy.as_deref(), Some("from"));
    assert_eq!(
        completed.backfill_cutoff_at.as_deref(),
        Some("2026-07-06T10:00:00Z")
    );
}

#[test]
fn switch_candidate_error_keeps_reset_required_code_with_additive_details() {
    let error = cli_error(LocalApiError::AccountSwitchCandidate {
        current_user_email: "old@example.com".to_string(),
        new_user_email: "new@example.com".to_string(),
        new_organization_name: "New Workspace".to_string(),
        claim_code: "claim_123".to_string(),
    });

    // Old clients: unchanged code + message shape.
    assert_eq!(error.code, CliErrorCode::AccountResetRequired);
    assert!(!error.retryable);
    // New clients: additive structured details.
    assert_eq!(
        error.details.get("switch_candidate"),
        Some(&RedactedValue::Bool(true))
    );
    assert_eq!(
        error.details.get("current_user_email"),
        Some(&RedactedValue::String("old@example.com".to_string()))
    );
    assert_eq!(
        error.details.get("new_user_email"),
        Some(&RedactedValue::String("new@example.com".to_string()))
    );
    assert_eq!(
        error.details.get("new_organization_name"),
        Some(&RedactedValue::String("New Workspace".to_string()))
    );
    assert_eq!(
        error.details.get("claim_code"),
        Some(&RedactedValue::String("claim_123".to_string()))
    );
}

#[test]
#[serial]
fn repeated_auth_start_reuses_unexpired_pending_claim() {
    // Daemon with an in-flight, far-future claim: auth_start must return
    // the SAME claim (idempotent re-trigger) without minting a new one —
    // no backend call happens because the reuse path short-circuits.
    let daemon = daemon();
    daemon
        .begin_auth_with_claim(crate::PendingAuthClaim {
            claim_code: "claim_reuse".to_string(),
            claim_token: "token_reuse".to_string(),
            nonce: "nonce_reuse".to_string(),
            claim_url: "https://ottto.net/setup/claim?code=claim_reuse".to_string(),
            expires_at: "2100-01-01T00:00:00Z".to_string(),
        })
        .expect("begin claim");

    let device = LocalDeviceBinding {
        device_id: "pending-claim-retry-fixture".into(),
        machine_id: None,
        sources: vec!["codex".into()],
    };
    let base = "http://127.0.0.1:1/pending-claim-retry-fixture";
    let mut rejected = crate::relay_auth::Probe::begin(base, &device, "same", "codex").unwrap();
    rejected.reject(401);
    let response = auth_start(&daemon, &RequestAuthorization::Token("token".to_string()))
        .expect("auth start reuses pending claim");
    assert_eq!(response.claim_code, "claim_reuse");
    assert_eq!(response.nonce, "nonce_reuse");
    assert_eq!(
        response.account.state,
        ottto_protocol::LocalAccountState::ClaimPending
    );
    assert!(
        crate::relay_auth::Probe::begin(base, &device, "same", "codex").is_err(),
        "reusing an in-flight claim does not start another sign-in or reset backoff"
    );
    crate::relay_auth::clear(crate::relay_auth::binding_key(
        base, &device, "same", "codex",
    ));
}

#[test]
#[serial]
fn auth_start_on_connected_daemon_does_not_create_competing_claim() {
    let daemon = daemon();
    daemon
        .begin_auth_with_claim(crate::PendingAuthClaim {
            claim_code: "claim_connected".to_string(),
            claim_token: "token_connected".to_string(),
            nonce: "nonce_connected".to_string(),
            claim_url: "https://ottto.net/setup/claim?code=claim_connected".to_string(),
            expires_at: "2100-01-01T00:00:00Z".to_string(),
        })
        .expect("begin claim");
    daemon
        .complete_auth_with_account(
            "claim_connected",
            "nonce_connected",
            connected_account(),
            "run_connected".to_string(),
            "2100-01-01T00:00:00Z".to_string(),
            Some("machine_test".to_string()),
        )
        .expect("connect account");

    let device = LocalDeviceBinding {
        device_id: "connect-retry-fixture".into(),
        machine_id: None,
        sources: vec!["codex".into()],
    };
    let base = "http://127.0.0.1:1/connect-retry-fixture";
    let mut rejected = crate::relay_auth::Probe::begin(base, &device, "same", "codex").unwrap();
    rejected.reject(401);
    let error = auth_start(&daemon, &RequestAuthorization::Token("token".to_string()))
        .expect_err("connected auth start must be explicit");
    assert!(matches!(
        error,
        LocalApiError::InvalidRequest(message)
            if message.contains("already connected") && message.contains("ottto logout")
    ));
    assert!(daemon.pending_auth_claim_snapshot().unwrap().is_none());
    assert!(
        crate::relay_auth::Probe::begin(base, &device, "same", "codex").is_err(),
        "an already-connected refusal must retain relay authorization backoff"
    );
    crate::relay_auth::clear(crate::relay_auth::binding_key(
        base, &device, "same", "codex",
    ));
}

#[test]
#[serial]
fn verify_of_ended_setup_run_lets_sign_in_reconnect_the_connected_mac() {
    const EXPIRED: &str = r#"{"detail":"Setup run expired"}"#;
    let _guard = lock_backend_test_env();
    let root = control_test_root("verify-ended-setup-run");
    let secret_root = telemetry_key_store_root("verify-ended-setup-run-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard =
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["claude_code".to_string()],
        })
        .expect("persist relay device binding");
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("device_secret_test")
        .expect("persist relay device secret");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(SetupRunReadScript {
        read: (401, EXPIRED),
        refresh: (401, EXPIRED),
    }));
    let api_base_url = expired_setup_run_read_server(calls.clone(), script);
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_expired".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url,
    };
    FileConnectionStore::default()
        .save(&connection)
        .expect("persist connection binding");
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(connection));
    let authorization = RequestAuthorization::Token("token".to_string());

    // While Ottto has said nothing terminal, a connected Mac refuses a
    // competing claim.
    let error =
        auth_start(&daemon, &authorization).expect_err("healthy connected Mac refuses a new claim");
    assert!(matches!(
        error,
        LocalApiError::InvalidRequest(message) if message.contains("already connected")
    ));

    // Verify meets the ended run on the device-secret refresh and records it.
    let result =
        verify_source(&daemon, &authorization, SourceKind::ClaudeCode, false).expect("verify");
    assert_eq!(result.status, SourceVerificationStatus::ReconnectRequired);
    assert!(calls
        .lock()
        .expect("calls lock")
        .iter()
        .any(|path| path.contains("/local-client/refresh")));
    let health = daemon
        .status("token")
        .expect("status")
        .canonical_health
        .expect("canonical health");
    assert_eq!(
        health.account.setup_run_state,
        ottto_protocol::LocalSetupRunState::Rejected
    );

    // Sign-in, which Verify told the user to use, may now claim over the
    // bound account instead of dead-ending on "already connected".
    daemon
        .begin_auth_with_claim(crate::PendingAuthClaim {
            claim_code: "claim_reconnect".to_string(),
            claim_token: "token_reconnect".to_string(),
            nonce: "nonce_reconnect".to_string(),
            claim_url: "https://ottto.net/setup/claim?code=claim_reconnect".to_string(),
            expires_at: "2100-01-01T00:00:00Z".to_string(),
        })
        .expect("begin claim");
    let response = auth_start(&daemon, &authorization).expect("reconnect claim is allowed");
    assert_eq!(response.claim_code, "claim_reconnect");
    assert_eq!(
        response.account.user.as_ref().map(|user| user.id.as_str()),
        connected_account()
            .user
            .as_ref()
            .map(|user| user.id.as_str()),
        "the reconnect claim keeps the bound user"
    );
}

/// A connected Mac with a device credential and a setup run bound to
/// `api_base_url`, inside hermetic support/secret directories.
fn connected_binding_fixture(
    name: &str,
    api_base_url: String,
) -> (PathBuf, Vec<EnvVarGuard>, LocalDaemon, LocalDeviceBinding) {
    let root = telemetry_key_store_root(name);
    let secret_root = root.join("secrets");
    fs::create_dir_all(&secret_root).expect("secret root");
    let guards = vec![
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support")),
        EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root),
    ];
    let account = connected_account();
    let device = LocalDeviceBinding {
        device_id: "device-connected".to_string(),
        machine_id: Some("machine_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    let connection = LocalConnectionBinding {
        setup_run_id: "run_connected_setup".to_string(),
        setup_run_token_expires_at: "2100-01-01T00:00:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url,
    };
    FileAccountStore::default().save(&account).unwrap();
    FileDeviceStore::default().save(&device).unwrap();
    FileConnectionStore::default().save(&connection).unwrap();
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("connected-secret")
        .unwrap();
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save("otsr_connected")
        .unwrap();
    let daemon = daemon()
        .with_account(account)
        .with_connection(Some(connection));
    (root, guards, daemon, device)
}

#[test]
#[serial]
fn explicit_login_claim_repairs_unreadable_binding_and_clears_doctor_finding() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let _lock = lock_backend_test_env();
    for bytes in [b"invalid-json".to_vec(), vec![b' '; 64 * 1024 + 1]] {
        let attach = r#"{"setup_run_id":"run_repaired","setup_run_token":"synthetic-fresh-token","expires_at":"2100-01-01T00:00:00Z","run":{"id":"run_repaired","status":"completed","machine_id":"machine_test"}}"#;
        let detail = r#"{"run":{"id":"run_repaired","status":"completed","machine_id":"machine_test"},"sources":[],"next_action":null,"next_question":null}"#;
        let (api_base_url, server) = scripted_json_backend(vec![
            (200, attach),
            (200, detail),
            (200, "{}"),
            (200, r#"{"action":null}"#),
        ]);
        let (root, _guards, daemon, _) =
            connected_binding_fixture("repair-binding-claim", api_base_url.clone());
        let home = root.join("synthetic-home");
        fs::create_dir_all(&home).unwrap();
        let _home = EnvVarGuard::set_path("HOME", &home);
        fs::write(FileConnectionStore::default().path(), bytes).unwrap();
        let has_finding = |daemon: &LocalDaemon| {
            daemon
                .status("token")
                .unwrap()
                .canonical_health
                .unwrap()
                .blockers
                .iter()
                .any(|b| b.code == "connection_binding_unreadable")
        };
        assert!(has_finding(&daemon));
        let payload = setup_run(
            &daemon,
            &RequestAuthorization::Token("token".into()),
            vec![SourceKind::Pi],
            Some("synthetic-fresh-claim".into()),
            None,
            None,
        )
        .unwrap();
        assert_eq!(payload["status"], "completed");
        assert_eq!(payload["claim_code_provided"], true);
        assert_ne!(payload["already_connected"], true);
        let binding = FileConnectionStore::default().load().unwrap().unwrap();
        assert_eq!(binding.setup_run_id, "run_repaired");
        assert_eq!(binding.api_base_url, api_base_url);
        assert_eq!(
            crate::snapshot_sync::snapshot_api_base_url().unwrap(),
            api_base_url
        );
        assert!(!has_finding(&daemon));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests[0].starts_with("POST /api/v1/setup-claims/synthetic-fresh-claim/attach "));
        assert!(requests[1].contains("/run_repaired/local-client/scan-result "));
        assert!(requests[2].contains("/run_repaired/local-client/heartbeat "));
        assert!(requests[3].contains("/run_repaired/local-client/next-action "));
        fs::remove_dir_all(root).unwrap();
    }
}

fn scan_refresh(status: &str) -> &'static str {
    Box::leak(json!({
        "setup_run_id":"run_connected_setup", "setup_run_token":"synthetic-token", "expires_at":"2100-01-01T00:00:00Z",
        "run":{"id":"run_connected_setup", "status":status, "machine_id":null}
    }).to_string().into_boxed_str())
}
const SCAN_DETAIL: &str = r#"{"run":{"id":"run_connected_setup","status":"completed","machine_id":null},"sources":[],"next_action":null,"next_question":null}"#;
fn scan_fixture(base: String) -> (PathBuf, Vec<EnvVarGuard>, LocalDaemon, LocalDeviceBinding) {
    *SETUP_SCAN.lock().unwrap() = SetupScanReconcile::default();
    let (root, mut guards, daemon, device) = connected_binding_fixture("setup-scan", base);
    guards.push(EnvVarGuard::set_path("HOME", &root));
    guards.push(EnvVarGuard::set_path(
        "OTTTO_COMMAND_SEARCH_PATH",
        &root.join("bin"),
    ));
    (root, guards, daemon, device)
}

/// [regress] Missing initial scans recover after connectivity returns, without the app.
#[test]
#[serial]
fn background_setup_scan_repairs_offline_debt_once_without_app() {
    let _lock = lock_backend_test_env();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(SetupRunReadScript {
        refresh: (0, ""),
        read: (200, SCAN_DETAIL),
    }));
    let base = expired_setup_run_read_server(calls.clone(), script.clone());
    let (_root, _guards, daemon, _) = scan_fixture(base);
    reconcile_setup_scan_in_background(&daemon);
    assert!(FileConnectionStore::default()
        .setup_scan_settled_run_id()
        .unwrap()
        .is_none());
    assert_eq!(SETUP_SCAN.lock().unwrap().failures, 1);
    script.lock().unwrap().refresh = (200, scan_refresh("scanning"));
    SETUP_SCAN.lock().unwrap().next_due = None;
    reconcile_setup_scan_in_background(&daemon);
    reconcile_setup_scan_in_background(&daemon);
    assert_eq!(SETUP_SCAN.lock().unwrap().failures, 0);
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.ends_with("/scan-result"))
            .count(),
        1
    );
}

/// [behaviour] Scan debt posts, action debt polls without scanning, and other statuses settle.
#[test]
#[serial]
fn background_setup_scan_status_decisions() {
    let _lock = lock_backend_test_env();
    for status in [
        "scanning",
        "completed",
        "waiting_for_companion",
        "running_action",
    ] {
        let actions = matches!(status, "waiting_for_companion" | "running_action");
        let mut answers = vec![(200, scan_refresh(status))];
        if status == "scanning" {
            answers.push((200, SCAN_DETAIL));
        }
        if status == "scanning" || actions {
            answers.extend([(200, "{}"), (200, r#"{"action":null}"#)]);
        }
        let (base, server) = scripted_json_backend(answers);
        let (_root, _guards, daemon, _) = scan_fixture(base);
        reconcile_setup_scan_in_background(&daemon);
        let requests = server.join().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.contains("/scan-result"))
                .count(),
            usize::from(status == "scanning")
        );
        assert_eq!(
            FileConnectionStore::default()
                .setup_scan_settled_run_id()
                .unwrap()
                .is_some(),
            !actions
        );
        if actions {
            assert!(SETUP_SCAN.lock().unwrap().next_due.is_some());
        }
    }
}

/// [regress] The idle poll's status settles action debt without another refresh.
#[test]
#[serial]
fn background_setup_scan_uses_idle_poll_status() {
    let _lock = lock_backend_test_env();
    for status in [
        Some("completed"),
        Some("waiting_for_user"),
        Some("waiting_for_companion"),
        Some("future_status"),
        None,
    ] {
        let response = match status {
            Some(status) => json!({"action":null,"run_status":status}),
            None => json!({"action":null}),
        };
        let body = Box::leak(response.to_string().into_boxed_str());
        let (base, server) = scripted_json_backend(vec![
            (200, scan_refresh("waiting_for_companion")),
            (200, "{}"),
            (200, body),
        ]);
        let (_root, _guards, daemon, _) = scan_fixture(base);
        reconcile_setup_scan_in_background(&daemon);
        assert_eq!(server.join().unwrap().len(), 3);
        let settled = matches!(status, Some("completed" | "waiting_for_user"));
        assert_eq!(
            FileConnectionStore::default()
                .setup_scan_settled_run_id()
                .unwrap()
                .as_deref(),
            settled.then_some("run_connected_setup"),
        );
        let state = SETUP_SCAN.lock().unwrap();
        assert_eq!(state.failures, u32::from(!settled));
        assert_eq!(state.next_due.is_some(), !settled);
    }
}

/// [behaviour] A scan-result 400 waits a day; other refusals and transient failures keep jitter.
#[test]
#[serial]
fn background_setup_scan_refusal_backs_off_a_day() {
    let _lock = lock_backend_test_env();
    let jitter_ceiling = Duration::from_secs(60);
    let scanning = (200, scan_refresh("scanning"));
    for (answers, day) in [
        (
            vec![scanning, (400, r#"{"detail":"scan_payload_invalid"}"#)],
            true,
        ),
        (vec![scanning, (422, "{}")], false),
        (vec![scanning, (503, "{}")], false),
        (vec![(400, "{}")], false),
    ] {
        let route = if answers.len() == 2 {
            "/scan-result "
        } else {
            "/refresh "
        };
        let (base, server) = scripted_json_backend(answers);
        let (_root, _guards, daemon, _) = scan_fixture(base);
        let before = Instant::now();
        reconcile_setup_scan_in_background(&daemon);
        let requests = server.join().unwrap();
        assert!(requests.last().unwrap().contains(route));
        assert!(FileConnectionStore::default()
            .setup_scan_settled_run_id()
            .unwrap()
            .is_none());
        let state = SETUP_SCAN.lock().unwrap();
        assert_eq!(state.failures, 1);
        let wait = state.next_due.unwrap() - before;
        if day {
            assert!(wait >= SETUP_RECONCILE_REFUSED_RETRY, "{route}: {wait:?}");
            assert!(wait < SETUP_RECONCILE_REFUSED_RETRY + jitter_ceiling);
        } else {
            assert!(wait <= jitter_ceiling, "{route}: {wait:?}");
        }
    }

    // A network failure keeps the jittered backoff.
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (_root, _guards, daemon, _) = scan_fixture(format!("http://{closed}"));
    let before = Instant::now();
    reconcile_setup_scan_in_background(&daemon);
    let state = SETUP_SCAN.lock().unwrap();
    assert_eq!(state.failures, 1);
    assert!(state.next_due.unwrap() - before <= jitter_ceiling);
}

/// [behaviour] A new setup run is not held behind the old run's refusal backoff.
#[test]
#[serial]
fn background_setup_scan_refusal_resets_on_new_setup_run() {
    let _lock = lock_backend_test_env();
    let (base, server) = scripted_json_backend(vec![
        (200, scan_refresh("scanning")),
        (400, "{}"),
        (503, "{}"),
    ]);
    let (_root, _guards, daemon, _) = scan_fixture(base);
    reconcile_setup_scan_in_background(&daemon);
    // Still inside the refusal window: no request.
    reconcile_setup_scan_in_background(&daemon);
    let store = FileConnectionStore::default();
    let mut replacement = store.load().unwrap().unwrap();
    replacement.setup_run_id = "replacement-run".into();
    store.save(&replacement).unwrap();
    let before = Instant::now();
    reconcile_setup_scan_in_background(&daemon);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].contains("/replacement-run/local-client/refresh "));
    let state = SETUP_SCAN.lock().unwrap();
    assert_eq!(
        state.binding,
        Some((replacement.api_base_url, "replacement-run".to_string()))
    );
    assert_eq!(state.failures, 1);
    assert!(state.next_due.unwrap() - before <= Duration::from_secs(60));
}

/// [privacy] The reconcile log names a route label, status and code; only a scan-result 400 is a refusal.
#[test]
fn setup_reconcile_refusal_class_and_log_fields() {
    let error = |endpoint: &str, status, reason_code: Option<&str>| {
        LocalApiError::Backend(BackendErrorDetails {
            kind: BackendErrorKind::Rejected,
            endpoint: safe_backend_endpoint(endpoint),
            status,
            body_excerpt: Some("synthetic body text".to_string()),
            reason_code: reason_code.map(str::to_string),
        })
    };
    assert_eq!(
        setup_reconcile_backend_fields(&error(
            "https://api.example.test/api/v1/setup-runs/run_ab12/local-client/scan-result?x=1",
            Some(400),
            Some("scan_payload_invalid"),
        )),
        " endpoint=scan-result status=400 code=scan_payload_invalid"
    );
    assert_eq!(
        setup_reconcile_backend_fields(&error("/api/v1/setup-runs/run_ab12", None, None)),
        " endpoint=other"
    );
    assert_eq!(
        setup_reconcile_backend_fields(&LocalApiError::NetworkUnavailable),
        ""
    );
    let scan_result = "/api/v1/setup-runs/run_ab12/local-client/scan-result";
    assert!(setup_reconcile_refused(&error(
        scan_result,
        Some(400),
        None
    )));
    for status in [
        None,
        Some(401),
        Some(404),
        Some(409),
        Some(410),
        Some(422),
        Some(503),
    ] {
        assert!(!setup_reconcile_refused(&error(scan_result, status, None)));
    }
    let complete = "/api/v1/setup-runs/run_ab12/local-client/actions/act_9/complete";
    assert!(!setup_reconcile_refused(&error(complete, Some(400), None)));
    assert!(!setup_reconcile_refused(&LocalApiError::NetworkUnavailable));
}

/// [behaviour] One completed action and its final idle poll settle in one attempt.
#[test]
#[serial]
fn background_setup_scan_settles_after_one_action() {
    let _lock = lock_backend_test_env();
    let (base, server) = scripted_json_backend(vec![
        (200, scan_refresh("waiting_for_companion")),
        (200, "{}"),
        (
            200,
            r#"{"run_status":"running_action","action":{"id":"synthetic-action","action_type":"unsupported","source":null}}"#,
        ),
        (200, "{}"),
        (200, SCAN_DETAIL),
        (200, "{}"),
        (200, r#"{"run_status":"completed","action":null}"#),
    ]);
    let (_root, _guards, daemon, _) = scan_fixture(base);
    reconcile_setup_scan_in_background(&daemon);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 7);
    assert_eq!(
        requests.iter().filter(|r| r.contains("/complete ")).count(),
        1
    );
    assert_eq!(
        FileConnectionStore::default()
            .setup_scan_settled_run_id()
            .unwrap()
            .as_deref(),
        Some("run_connected_setup"),
    );
    let state = SETUP_SCAN.lock().unwrap();
    assert_eq!(state.failures, 0);
    assert!(state.next_due.is_none());
}

/// [behaviour] Rejected background authority parks; only the existing health hold owns logout.
#[test]
#[serial]
fn terminal_setup_refresh_parks_without_resetting_identity() {
    let _lock = lock_backend_test_env();
    for detail in ["Setup run expired", "Telemetry device secret is invalid"] {
        let body = Box::leak(json!({"detail":detail}).to_string().into_boxed_str());
        let (base, server) = scripted_json_backend(vec![(401, body)]);
        let (_root, _guards, daemon, device) = scan_fixture(base);
        let store = FileConnectionStore::default();
        let binding = store.load().unwrap();
        let account = FileAccountStore::default().load().unwrap();
        let setup_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .load()
            .unwrap();
        let device_secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .unwrap();
        reconcile_setup_scan_in_background(&daemon);
        assert!(store.setup_scan_settled_run_id().unwrap().is_some());
        assert_eq!(store.load().unwrap(), binding);
        assert_eq!(FileAccountStore::default().load().unwrap(), account);
        assert_eq!(FileDeviceStore::default().load().unwrap(), Some(device));
        assert_eq!(
            KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
                .load()
                .unwrap(),
            setup_token
        );
        assert_eq!(
            KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
                .load()
                .unwrap(),
            device_secret
        );
        reconcile_setup_scan_in_background(&daemon);
        assert_eq!(server.join().unwrap().len(), 1);
    }
}

/// [format] Settlement survives restart, remains readable by the old binding type, and clears on save.
#[test]
#[serial]
fn persisted_setup_settlement_skips_restart_refresh_and_is_backward_compatible() {
    let _lock = lock_backend_test_env();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(SetupRunReadScript {
        refresh: (200, scan_refresh("completed")),
        read: (200, "{}"),
    }));
    let base = expired_setup_run_read_server(calls.clone(), script);
    let (_root, _guards, daemon, _) = scan_fixture(base);
    let store = FileConnectionStore::default();
    assert!(store.setup_scan_settled_run_id().unwrap().is_none());
    reconcile_setup_scan_in_background(&daemon);
    let binding = store.load().unwrap().unwrap();
    let legacy: LocalConnectionBinding =
        serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();
    assert_eq!(legacy, binding);
    assert_eq!(
        store.setup_scan_settled_run_id().unwrap().as_deref(),
        Some(binding.setup_run_id.as_str())
    );
    *SETUP_SCAN.lock().unwrap() = SetupScanReconcile::default();
    reconcile_setup_scan_in_background(&daemon);
    assert_eq!(calls.lock().unwrap().len(), 1);
    let mut replacement = binding.clone();
    replacement.setup_run_id = "replacement-run".into();
    store.save(&replacement).unwrap();
    assert!(store.setup_scan_settled_run_id().unwrap().is_none());
    store.settle_setup_scan(&binding).unwrap();
    assert!(store.setup_scan_settled_run_id().unwrap().is_none());
}

#[test]
#[serial]
fn setup_on_connected_daemon_is_noop_until_ottto_ends_the_run() {
    let _lock = lock_backend_test_env();
    assert_setup_denies_unauthorized_callers_before_scan_lock();
    let (api_base_url, server) = scripted_json_backend(vec![
        (401, r#"{"detail":"Setup run not found for this device"}"#),
        (401, r#"{"detail":"Setup run expired"}"#),
    ]);
    let (root, _guards, daemon, device) =
        connected_binding_fixture("connected-setup", api_base_url);
    let authorization = RequestAuthorization::Token("token".to_string());

    // A rejection that is not an authoritative terminal answer proves nothing.
    let payload = setup_run(&daemon, &authorization, Vec::new(), None, None, None)
        .expect("connected setup no-op");
    assert_eq!(payload["status"], "completed");
    assert_eq!(payload["already_connected"], true);
    assert_eq!(payload["setup_run_id"], "run_connected_setup");
    assert_eq!(
        daemon.status("token").unwrap().account.state,
        LocalAccountState::Connected
    );

    // An ended run is not revived: local-only cleanup keeps the prior
    // device proof and the caller is sent to a fresh browser claim.
    let error = setup_run(&daemon, &authorization, Vec::new(), None, None, None)
        .expect_err("an ended setup run is not connected");
    assert_eq!(cli_error(error).code, CliErrorCode::NeedsUserAction);
    let requests = server.join().expect("scripted backend");
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request
        .starts_with("POST /api/v1/setup-runs/run_connected_setup/local-client/refresh")));
    assert_eq!(
        daemon.status("token").unwrap().account.state,
        LocalAccountState::NotConnected
    );
    assert!(FileDeviceStore::default().load().unwrap().is_none());
    assert_eq!(
        FileDeviceStore::new(default_prior_device_path())
            .load()
            .unwrap(),
        Some(device)
    );
    assert!(daemon.pending_auth_claim_snapshot().unwrap().is_none());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn account_gone_detection_matches_terminal_backend_failures() {
    let gone_404 = LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: "/api/v1/setup-runs/run_1/local-client/refresh".to_string(),
        status: Some(404),
        body_excerpt: None,
        reason_code: None,
    });
    assert!(backend_error_indicates_account_gone(&gone_404));

    let gone_401 = LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: "/api/v1/setup-runs/run_1/local-client/refresh".to_string(),
        status: Some(401),
        body_excerpt: Some(r#"{"detail":"account_not_found"}"#.to_string()),
        reason_code: None,
    });
    assert!(backend_error_indicates_account_gone(&gone_401));

    // A plain expired-token 401 must NOT count as account-gone.
    let expired_401 = LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: "/api/v1/setup-runs/run_1/local-client/refresh".to_string(),
        status: Some(401),
        body_excerpt: Some(r#"{"detail":"setup run companion token expired"}"#.to_string()),
        reason_code: None,
    });
    assert!(!backend_error_indicates_account_gone(&expired_401));

    // Unrelated 404s (not a setup-run/local-client endpoint) don't count.
    let unrelated_404 = LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: "/api/v1/releases/latest".to_string(),
        status: Some(404),
        body_excerpt: None,
        reason_code: None,
    });
    assert!(!backend_error_indicates_account_gone(&unrelated_404));

    assert!(!backend_error_indicates_account_gone(
        &LocalApiError::NetworkUnavailable
    ));
}

#[test]
#[serial]
fn logout_fails_before_active_reset_when_recovery_journal_cannot_be_invalidated() {
    let support_root = telemetry_key_store_root("logout-pending-invalidation");
    let secret_root = telemetry_key_store_root("logout-pending-invalidation-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let account = connected_account();
    let device = LocalDeviceBinding {
        device_id: "device-logout-preserved".to_string(),
        machine_id: Some("machine_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    FileAccountStore::default()
        .save(&account)
        .expect("save active account");
    FileDeviceStore::default()
        .save(&device)
        .expect("save active device");
    fs::create_dir_all(ottto_core::default_pending_device_credential_path())
        .expect("make pending journal unreadable as a file");
    let daemon = daemon().with_account(account.clone());

    let response = handle_request(
        &daemon,
        LocalControlRequest {
            request_id: "req_logout_pending_invalidation".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::AuthReset {
                local_only: true,
                forget_installation: false,
            },
        },
    );

    assert!(!response.ok);
    assert_eq!(
        FileAccountStore::default().load().expect("active account"),
        account
    );
    assert_eq!(
        FileDeviceStore::default().load().expect("active device"),
        Some(device)
    );
    assert_eq!(
        daemon.status("token").expect("daemon status").account.state,
        LocalAccountState::Connected
    );
    let _ = fs::remove_dir_all(support_root);
    let _ = fs::remove_dir_all(secret_root);
}

#[test]
#[serial]
fn local_only_logout_retains_prior_proof_and_rejection_becomes_reattach_required() {
    let _lock = lock_backend_test_env();
    let root = telemetry_key_store_root("logout-prior-credential");
    let support_root = root.join("support");
    let secret_root = root.join("secrets");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let account = connected_account();
    let device = LocalDeviceBinding {
        device_id: "device-prior-proof".to_string(),
        machine_id: Some("machine_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    FileAccountStore::default().save(&account).unwrap();
    FileDeviceStore::default().save(&device).unwrap();
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("prior-secret-test")
        .unwrap();
    let daemon = daemon().with_account(account);

    let reset = handle_request(
        &daemon,
        LocalControlRequest {
            request_id: "req_local_only_prior".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::AuthReset {
                local_only: true,
                forget_installation: false,
            },
        },
    );
    assert!(reset.ok, "{reset:?}");
    assert!(FileDeviceStore::default().load().unwrap().is_none());
    assert!(KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .is_err());
    assert_eq!(
        FileDeviceStore::new(default_prior_device_path())
            .load()
            .unwrap(),
        Some(device)
    );
    assert_eq!(
        KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .unwrap(),
        "prior-secret-test"
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind reattach backend");
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept reattach request");
        let request = read_complete_http_request(&mut stream);
        let body: serde_json::Value =
            serde_json::from_str(http_request_body(&request)).expect("completion body");
        assert_eq!(body["relay_device_id"], "device-prior-proof");
        assert_eq!(body["prior_device_secret"], "prior-secret-test");
        write_json_response(
            &mut stream,
            409,
            "Conflict",
            r#"{"detail":{"code":"reattach_required","message":"Existing installation authority requires an explicit relay device","reason":"existing_authority","device_name":"Example Mac","last_seen_at":"2026-09-07T12:30:00Z","can_reconnect":true,"can_replace":true,"replacement_approved":false}}"#,
        );
    });
    let _api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &format!("http://{address}"));
    let pending = PendingAuthClaim {
        claim_code: "claim_reattach".to_string(),
        claim_token: "claim_token_reattach".to_string(),
        nonce: "nonce_reattach_1234567890".to_string(),
        claim_url: "https://ottto.net/setup/claim?code=claim_reattach".to_string(),
        expires_at: "2026-09-08T12:30:00Z".to_string(),
    };
    daemon.begin_auth_with_claim(pending.clone()).unwrap();
    let result = complete_pending_auth_claim(&daemon, &test_machine(), pending);
    server.join().unwrap();

    assert!(matches!(result, Err(LocalApiError::Backend(_))));
    let status = daemon.status("token").unwrap();
    assert_eq!(status.account.state, LocalAccountState::ReattachRequired);
    assert!(status.account.user.is_none());
    assert_eq!(status.account.can_reconnect, Some(true));
    let message = status.account.message.unwrap();
    assert_eq!(message.code, "reattach_required:existing_authority");
    assert!(message.text.contains("Example Mac"));
    assert!(message.text.contains("2026-09-07T12:30:00Z"));
    assert!(message.text.contains("Reconnect it"));
}

#[test]
#[serial]
/// [format] Forget-installation clears identity and credentials only: every
/// collected store, cache, composition state, backfill state and receipt
/// stays, so a re-pair reads this Mac's Claude history as moved.
fn forget_installation_clears_identity_and_credentials_and_keeps_collected_state() {
    let root = telemetry_key_store_root("forget-installation");
    let support_root = root.join("support");
    let secret_root = root.join("secrets");
    fs::create_dir_all(support_root.join("snapshots/destinations/old")).unwrap();
    seed_private_literal_canary(&support_root.join("snapshots"));
    for destination in ["old", "other"] {
        for source in crate::snapshots::durable_sources::SOURCES {
            let index = support_root
                .join("snapshots/destinations")
                .join(destination)
                .join(format!("{}-scan-index.json", source.snapshot.api_slug()));
            let dir = crate::snapshots::state_v2::retired_record_dir(&index);
            fs::create_dir_all(&dir).unwrap();
            // Whole-tree forget cannot depend on inventory or body decoding.
            fs::write(
                dir.join(format!("{}.rec", "f".repeat(64))),
                b"opaque record",
            )
            .unwrap();
            fs::write(dir.join("torn.tmp"), b"unfinished write").unwrap();
            fs::create_dir_all(dir.join("temp/child")).unwrap();
            fs::write(dir.join("temp/child/pending"), b"unfinished child").unwrap();
            fs::write(dir.with_extension("private-labels"), b"opaque marker").unwrap();
            assert!(dir.exists());
        }
    }
    fs::create_dir_all(&secret_root).unwrap();
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileMachineStore::default()
        .save(&LocalMachineBinding {
            machine_id: "otm_original".to_string(),
            installation_id: "oti_original".to_string(),
            hardware_uuid: None,
        })
        .unwrap();
    FileAccountStore::default()
        .save(&connected_account())
        .unwrap();
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_forget".to_string(),
            machine_id: Some("otm_original".to_string()),
            sources: vec!["codex".to_string()],
        })
        .unwrap();
    FileDeviceStore::new(default_prior_device_path())
        .save(&LocalDeviceBinding {
            device_id: "device_prior_forget".to_string(),
            machine_id: Some("otm_original".to_string()),
            sources: vec!["codex".to_string()],
        })
        .unwrap();
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: "run_forget".to_string(),
            setup_run_token_expires_at: "2026-09-08T12:00:00Z".to_string(),
            machine_id: Some("otm_original".to_string()),
            claim_code: None,
            api_base_url: "https://api.ottto.net".to_string(),
        })
        .unwrap();
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("device-secret-forget")
        .unwrap();
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save("setup-token-forget")
        .unwrap();
    KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("prior-device-secret-forget")
        .unwrap();
    fs::write(
        support_root.join("snapshots/destinations/old/codex-scan-index.json"),
        b"receipt",
    )
    .unwrap();
    crate::backfill::update_backfill_state(&support_root, |state| {
        crate::backfill::mark_backfill_complete_for_destination(
            state,
            crate::snapshots::SnapshotSource::ClaudeCode,
            "old",
        );
    })
    .unwrap();
    fs::write(
        support_root.join("snapshot_upload_receipts.json"),
        b"upload receipt",
    )
    .unwrap();
    let mut kept = vec![
        support_root.join("snapshots/destinations/old/codex-scan-index.json"),
        crate::backfill::backfill_state_path(&support_root),
        support_root.join("snapshot_upload_receipts.json"),
        support_root.join("context_composition/v2/scopes/codex-scope.json"),
        support_root.join("context_composition/v2/scopes/codex-scope.upload.json"),
        support_root.join("context_footprint/workspace.json"),
        support_root.join("mcp_inventory/disabled"),
        support_root.join("context_composition/disabled"),
    ];
    for source in crate::snapshots::durable_sources::SOURCES {
        let source = source.snapshot;
        kept.push(crate::active_sessions::active_session_cache_path(
            &support_root,
            source,
        ));
        kept.push(crate::mcp_inventory::cache_path(&support_root, source));
        kept.push(crate::snapshot_sync::detected_uses_cache_path(
            &support_root,
            source,
        ));
    }
    for path in &kept {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        if !path.exists() {
            fs::write(path, b"synthetic-forget-canary").unwrap();
        }
    }
    kept.push(crate::snapshots::state_v2::retired_record_dir(
        &support_root.join("snapshots/destinations/other/claude_code-scan-index.json"),
    ));
    let source_data = root.join("codex-source.jsonl");
    fs::write(&source_data, b"source data").unwrap();

    let response = handle_request(
        &daemon().with_account(connected_account()),
        LocalControlRequest {
            request_id: "req_forget_installation".to_string(),
            protocol_version: ottto_protocol::INSTALLATION_RESET_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::AuthReset {
                local_only: true,
                forget_installation: true,
            },
        },
    );
    assert!(response.ok, "{response:?}");
    assert!(FileMachineStore::default().load().unwrap().is_none());
    assert!(FileDeviceStore::default().load().unwrap().is_none());
    assert!(FileConnectionStore::default().load().unwrap().is_none());
    assert!(FileDeviceStore::new(default_prior_device_path())
        .load()
        .unwrap()
        .is_none());
    assert!(KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .is_err());
    assert!(
        KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .is_err()
    );
    assert!(KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .is_err());
    for path in &kept {
        assert!(path.exists(), "{path:?}: collected state stays");
    }
    assert_eq!(
        crate::snapshot_sync::withheld_support::claude_prior_history_for_new_destination(
            &support_root,
            "new"
        ),
        crate::snapshots::PriorHistory::Moved,
        "a re-pair after forget reads this Mac's Claude history as moved"
    );
    assert_eq!(fs::read(source_data).unwrap(), b"source data");
    assert_eq!(
        response.payload.unwrap()["message"]["code"],
        "installation_forgotten"
    );
    let _ = fs::remove_dir_all(root);
}
#[test]
#[serial]
fn local_reset_file_cleanup_clears_relay_device_binding() {
    let support_root = telemetry_key_store_root("local-reset-device-binding");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    FileAccountStore::default()
        .save(&connected_account())
        .expect("save account");
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: "setup_test".to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("machine_test".to_string()),
            claim_code: None,
            api_base_url: "https://api.ottto.net".to_string(),
        })
        .expect("save connection");
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string()],
        })
        .expect("save device");

    reset_local_account_files().expect("reset local files");

    assert_eq!(
        FileAccountStore::default()
            .load()
            .expect("load reset account")
            .state,
        LocalAccountState::NotConnected
    );
    assert_eq!(
        FileConnectionStore::default()
            .load()
            .expect("load reset connection"),
        None
    );
    assert_eq!(
        FileDeviceStore::default()
            .load()
            .expect("load reset device"),
        None
    );
}

#[test]
#[serial]
fn claim_completion_persists_rotated_relay_device_credentials() {
    let support_root = telemetry_key_store_root("claim-complete-relay-device");
    let secret_root = telemetry_key_store_root("claim-complete-relay-device-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);

    let credentials = relay_device_credentials_from_claim_completion(
        &SetupClaimCompleteResponse {
            setup_run_id: "setup_claim".to_string(),
            setup_run_token: "otsr_claim".to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("machine_claim".to_string()),
            relay_device: Some(SetupClaimCompleteRelayDevice {
                id: "device_claim".to_string(),
                machine_id: None,
                sources: vec![
                    "claude_code".to_string(),
                    "codex".to_string(),
                    "pi".to_string(),
                ],
            }),
            relay_device_secret: Some("otdev_rotated_claim".to_string()),
            relay_device_credential_preparation: None,
            connected_at: "2026-05-05T09:20:00Z".to_string(),
            user: SetupClaimCompleteUser {
                id: "user_claim".to_string(),
                email: "claim@example.com".to_string(),
                display_name: None,
            },
            organization: SetupClaimCompleteOrganization {
                id: "org_claim".to_string(),
                name: "Claim Org".to_string(),
            },
            backfill_policy: None,
            backfill_cutoff_at: None,
        },
        None,
    )
    .expect("materialize claim relay device");
    let ClaimRelayDeviceCredential::Legacy(device, secret) = credentials else {
        panic!("legacy relay device credentials present");
    };
    persist_relay_device_credentials(&device, &secret).expect("persist claim relay device");
    assert_eq!(
        FileDeviceStore::default()
            .load()
            .expect("load device")
            .expect("device saved"),
        LocalDeviceBinding {
            device_id: "device_claim".to_string(),
            machine_id: Some("machine_claim".to_string()),
            sources: vec![
                "claude_code".to_string(),
                "codex".to_string(),
                "pi".to_string(),
            ],
        }
    );
    assert_eq!(
        KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .expect("relay device secret saved"),
        "otdev_rotated_claim"
    );
}

#[test]
#[serial]
fn claim_completion_accepts_only_the_modern_prepared_credential_shape() {
    let support_root = telemetry_key_store_root("claim-complete-prepared-device");
    let secret_root = telemetry_key_store_root("claim-complete-prepared-device-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let candidate = format!("candidate-{}", "value".repeat(4));
    let completed: SetupClaimCompleteResponse = serde_json::from_value(json!({
        "setup_run_id": "setup_claim",
        "setup_run_token": "setup-token",
        "setup_run_token_expires_at": "2026-08-01T00:00:00Z",
        "machine_id": "machine-one",
        "relay_device_credential_preparation": {
            "preparation_id": "preparation-modern",
            "capability": DEVICE_CREDENTIAL_PREPARATION_CAPABILITY,
            "expires_at": "2026-08-01T00:00:00Z",
            "credential_generation": 2,
            "device": {"id": "device-modern", "machine_id": "machine-one", "sources": ["codex"]},
            "candidate_secret": candidate.clone(),
            "credential_rotation_planned": false
        },
        "connected_at": "2026-07-31T20:00:00Z",
        "user": {"id": "user-one", "email": "user@example.com", "display_name": null},
        "organization": {"id": "org-one", "name": "Org"}
    }))
    .expect("parse modern completion");

    let credentials = relay_device_credentials_from_claim_completion(&completed, None)
        .expect("validate modern completion");
    let ClaimRelayDeviceCredential::Prepared(prepared) = credentials else {
        panic!("modern preparation expected");
    };
    let debug = format!("{prepared:?}");
    assert!(!debug.contains(&candidate));
    assert!(!debug.contains("preparation-modern"));

    let mut mixed: serde_json::Value = serde_json::to_value(json!({
        "setup_run_id": "setup_claim",
        "setup_run_token": "setup-token",
        "setup_run_token_expires_at": "2026-08-01T00:00:00Z",
        "machine_id": "machine-one",
        "relay_device": {"id": "device-active", "machine_id": "machine-one", "sources": ["codex"]},
        "relay_device_secret": "legacy-secret",
        "relay_device_credential_preparation": {
            "preparation_id": "preparation-modern",
            "capability": DEVICE_CREDENTIAL_PREPARATION_CAPABILITY,
            "expires_at": "2026-08-01T00:00:00Z",
            "credential_generation": 2,
            "device": {"id": "device-modern", "machine_id": "machine-one", "sources": ["codex"]},
            "candidate_secret": "candidate-secret",
            "credential_rotation_planned": false
        },
        "connected_at": "2026-07-31T20:00:00Z",
        "user": {"id": "user-one", "email": "user@example.com", "display_name": null},
        "organization": {"id": "org-one", "name": "Org"}
    }))
    .expect("serialize mixed completion");
    // Keep the value mutable to make it explicit this is a wire-shape
    // rejection test, not a typed constructor accidentally omitting data.
    mixed["backfill_policy"] = serde_json::Value::Null;
    let mixed: SetupClaimCompleteResponse =
        serde_json::from_value(mixed).expect("parse mixed completion");
    assert!(relay_device_credentials_from_claim_completion(&mixed, None).is_err());
}

#[test]
#[serial]
fn account_binding_payloads_include_persistent_installation_identity() {
    let machine = test_machine();
    let claim = PendingAuthClaim {
        claim_code: "claim_installation".to_string(),
        claim_token: "token_installation".to_string(),
        nonce: "nonce_installation_identity".to_string(),
        claim_url: "https://ottto.net/setup/claim?code=claim_installation".to_string(),
        expires_at: "2026-05-05T09:30:00Z".to_string(),
    };
    let install_session = InstallSessionApiResponse {
        install_session_id: "install_session_identity".to_string(),
        install_session_token: "install_token_identity".to_string(),
    };

    let body = setup_claim_complete_body(&claim, &machine);
    assert!(body["machine_identity_capability"] == MACHINE_IDENTITY_CAPABILITY);
    for payload in [
        setup_claim_create_body(&machine, &claim.nonce),
        setup_claim_complete_body(&claim, &machine),
        setup_run_attach_body(&machine),
        telemetry_device_register_body(&install_session, &machine),
    ] {
        assert_eq!(
            payload
                .get("installation_id")
                .and_then(serde_json::Value::as_str),
            Some("install_test")
        );
    }
}

#[test]
fn telemetry_registration_declares_continuity_and_sends_proof_only_as_a_pair() {
    let machine = test_machine();
    let install_session = InstallSessionApiResponse {
        install_session_id: "install_session_continuity".to_string(),
        install_session_token: "install_token_continuity".to_string(),
    };
    let first = telemetry_device_register_body(&install_session, &machine);
    assert_eq!(
        first["identity_continuity_capability"],
        IDENTITY_CONTINUITY_CAPABILITY
    );
    assert!(first["machine_identity_capability"] == MACHINE_IDENTITY_CAPABILITY);
    assert!(first.get("prior_device_id").is_none());
    assert!(first.get("prior_device_secret").is_none());

    let prior = PriorDeviceCredential {
        machine_id: Some("machine_test".to_string()),
        device_id: "device_prior".to_string(),
        device_sources: vec!["codex".to_string()],
        device_secret: "secret_prior".to_string(),
        owner: None,
        snapshot_namespace: "a".repeat(64),
    };
    let repeat =
        telemetry_device_register_body_with_prior(&install_session, &machine, Some(&prior));
    assert!(repeat["machine_identity_capability"] == MACHINE_IDENTITY_CAPABILITY);
    assert_eq!(repeat["prior_device_id"], "device_prior");
    assert_eq!(repeat["prior_device_secret"], "secret_prior");
}

#[test]
#[serial]
fn modern_registration_prepare_and_confirm_use_the_additive_contract() {
    let support_root = telemetry_key_store_root("device-prepare-wire");
    let secret_root = telemetry_key_store_root("device-prepare-wire-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind prepare backend");
    let address = listener.local_addr().expect("prepare backend address");
    let candidate = format!("candidate-{}", "value".repeat(4));
    let candidate_for_server = candidate.clone();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_for_server = captured.clone();
    thread::spawn(move || {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept credential request");
            let request = read_complete_http_request(&mut stream);
            captured_for_server
                .lock()
                .expect("captured request lock")
                .push(request);
            let body = if index == 0 {
                json!({
                    "preparation_id": "preparation-wire",
                    "capability": DEVICE_CREDENTIAL_PREPARATION_CAPABILITY,
                    "expires_at": "2026-08-01T00:00:00Z",
                    "credential_generation": 3,
                    "device": {"id": "device-wire", "machine_id": "machine_test", "sources": ["codex"]},
                    "candidate_secret": candidate_for_server.clone(),
                    "credential_rotation_planned": false
                })
            } else {
                json!({
                    "preparation_id": "preparation-wire",
                    "status": "confirmed",
                    "confirmed_at": "2026-07-31T20:00:00Z",
                    "credential_generation": 3,
                    "device": {"id": "device-wire", "machine_id": "machine_test", "sources": ["codex"]},
                    "credential_rotation_performed": false
                })
            };
            write_json_response(&mut stream, 200, "OK", &body.to_string());
        }
    });
    let api_base_url = format!("http://{address}");
    let install_session = InstallSessionApiResponse {
        install_session_id: "install-session-wire".to_string(),
        install_session_token: "install-token-wire".to_string(),
    };
    let (prepared, _prior, request_authority) =
        prepare_telemetry_device_registration(&api_base_url, &install_session, &test_machine())
            .expect("prepare registration");
    let mut pending = pending_device_credential_from_preparation(
        &api_base_url,
        &prepared,
        true,
        None,
        request_authority,
    )
    .expect("materialize pending");
    pending.preconfirm_guards_passed = true;
    confirm_device_credential_preparation(&pending, &candidate).expect("confirm registration");

    let requests = captured.lock().expect("captured requests");
    let prepare_request = &requests[0];
    assert!(prepare_request
        .starts_with("POST /api/v1/telemetry/devices/registration-preparations HTTP/1.1"));
    let prepare_body: serde_json::Value =
        serde_json::from_str(http_request_body(prepare_request)).expect("prepare body");
    assert_eq!(
        prepare_body["credential_preparation_capability"],
        DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
    );
    assert_eq!(
        prepare_body["credential_preparation_idempotency_key"],
        device_credential_preparation_idempotency_key(
            "register",
            "install-session-wire",
            "install_test"
        )
    );
    assert!(prepare_body["machine_identity_capability"] == MACHINE_IDENTITY_CAPABILITY);
    let confirm_request = &requests[1];
    assert!(confirm_request.starts_with(
        "POST /api/v1/telemetry/device-credential-preparations/preparation-wire/confirm HTTP/1.1"
    ));
    assert!(confirm_request.contains(&format!(
        "{DEVICE_CREDENTIAL_PREPARATION_SECRET_HEADER}: {candidate}"
    )));
    assert!(!confirm_request.contains("/telemetry/devices/register "));
}

/// Every backend payload that already carries install-scoped identity must
/// also carry `account_scope`, or the product cannot tell two installs on
/// one Mac apart (each macOS user account has its own agent config).
#[test]
#[serial]
fn account_binding_payloads_include_the_account_scope_discriminator() {
    let machine = test_machine();
    let claim = PendingAuthClaim {
        claim_code: "claim_account_scope".to_string(),
        claim_token: "token_account_scope".to_string(),
        nonce: "nonce_account_scope".to_string(),
        claim_url: "https://ottto.net/setup/claim?code=claim_account_scope".to_string(),
        expires_at: "2026-05-05T09:30:00Z".to_string(),
    };
    let install_session = InstallSessionApiResponse {
        install_session_id: "install_session_account_scope".to_string(),
        install_session_token: "install_token_account_scope".to_string(),
    };

    for payload in [
        setup_claim_create_body(&machine, &claim.nonce),
        setup_claim_complete_body(&claim, &machine),
        setup_run_attach_body(&machine),
        telemetry_device_register_body(&install_session, &machine),
    ] {
        assert_eq!(
            payload
                .get("account_scope")
                .and_then(serde_json::Value::as_str),
            Some(TEST_ACCOUNT_SCOPE)
        );
    }
}

#[test]
#[serial]
fn claim_completion_request_sends_existing_keychain_proof_stably_across_retries() {
    let support_root = telemetry_key_store_root("claim-complete-request-device");
    let secret_root = telemetry_key_store_root("claim-complete-request-device-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_existing_claim".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string(), "pi".to_string()],
        })
        .expect("persist existing relay device");
    let prior_secret = format!("prior-{}", "claim-proof".repeat(3));
    fs::write(
        secret_root.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        &prior_secret,
    )
    .expect("persist existing relay secret fallback");
    let candidate_secret = format!("candidate-{}", "claim".repeat(4));

    let captured_requests = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind claim backend");
    let address = listener.local_addr().expect("claim backend address");
    let captured_requests_for_thread = captured_requests.clone();
    let candidate_for_server = candidate_secret.clone();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept claim complete");
            let request = read_complete_http_request(&mut stream);
            captured_requests_for_thread
                .lock()
                .expect("captured request lock")
                .push(request);
            let response = json!({
                "setup_run_id": "setup_claim",
                "setup_run_token": "otsr_claim",
                "setup_run_token_expires_at": "2026-05-05T10:30:00Z",
                "machine_id": "machine_test",
                "relay_device_credential_preparation": {
                    "preparation_id": "preparation-claim-existing",
                    "capability": DEVICE_CREDENTIAL_PREPARATION_CAPABILITY,
                    "expires_at": "2099-01-01T00:00:00Z",
                    "credential_generation": 7,
                    "device": {
                        "id": "device_claim_next",
                        "machine_id": "machine_test",
                        "sources": ["codex", "pi"],
                    },
                    "candidate_secret": candidate_for_server.clone(),
                    "identity_continuity_capability": IDENTITY_CONTINUITY_CAPABILITY,
                    "credential_rotation_planned": true,
                    "prior_device_id": "device_existing_claim",
                },
                "connected_at": "2026-05-05T09:20:00Z",
                "user": {
                    "id": "user_claim",
                    "email": "claim@example.com",
                    "display_name": null,
                },
                "organization": {"id": "org_claim", "name": "Claim Org"},
            });
            write_json_response(&mut stream, 200, "OK", &response.to_string());
        }
    });
    let _api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &format!("http://{address}"));

    let claim = PendingAuthClaim {
        claim_code: "claim_existing".to_string(),
        claim_token: "token_existing".to_string(),
        nonce: "nonce_existing".to_string(),
        claim_url: "https://ottto.net/setup/claim?code=claim_existing".to_string(),
        expires_at: "2026-05-05T09:30:00Z".to_string(),
    };
    let mut completions = Vec::new();
    for _ in 0..2 {
        completions.push(
            complete_setup_claim(&claim, &test_machine(), None).expect("complete setup claim"),
        );
    }
    server.join().expect("claim server");

    let requests = captured_requests.lock().expect("captured request lock");
    assert_eq!(requests.len(), 2);
    let request = &requests[0];
    let body: serde_json::Value =
        serde_json::from_str(http_request_body(request)).expect("claim request json");
    let retry_body: serde_json::Value =
        serde_json::from_str(http_request_body(&requests[1])).expect("retry request json");
    assert!(body["machine_identity_capability"] == MACHINE_IDENTITY_CAPABILITY);
    assert_eq!(
        retry_body, body,
        "retry must reproduce the exact proof body"
    );
    assert_eq!(
        body.get("relay_device_id")
            .and_then(serde_json::Value::as_str),
        Some("device_existing_claim")
    );
    assert_eq!(
        body.get("relay_device_sources")
            .and_then(serde_json::Value::as_array)
            .map(|sources| sources
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()),
        Some(vec!["codex", "pi"])
    );
    assert_eq!(
        body.get("identity_continuity_capability")
            .and_then(serde_json::Value::as_str),
        Some(IDENTITY_CONTINUITY_CAPABILITY)
    );
    assert_eq!(
        body.get("prior_device_secret")
            .and_then(serde_json::Value::as_str),
        Some(prior_secret.as_str())
    );
    assert_eq!(
        body.get("installation_id")
            .and_then(serde_json::Value::as_str),
        Some("install_test"),
        "claim completion must send the persistent installation identity"
    );
    assert_eq!(
        body.get("hardware_uuid"),
        Some(&serde_json::Value::Null),
        "claim completion must send hardware_uuid when known and null otherwise"
    );
    assert_eq!(
        body.get("credential_preparation_capability")
            .and_then(serde_json::Value::as_str),
        Some(DEVICE_CREDENTIAL_PREPARATION_CAPABILITY)
    );
    let expected_idempotency_key = device_credential_preparation_idempotency_key(
        "setup_claim",
        "claim_existing",
        "install_test",
    );
    assert_eq!(
        body.get("credential_preparation_idempotency_key")
            .and_then(serde_json::Value::as_str),
        Some(expected_idempotency_key.as_str())
    );

    let completion = completions.pop().expect("claim completion");
    let credentials = relay_device_credentials_from_claim_completion(
        &completion.response,
        completion.prior_device_credential.as_ref(),
    )
    .expect("validate prepared claim credential");
    let ClaimRelayDeviceCredential::Prepared(prepared) = credentials else {
        panic!("prepared claim credential");
    };
    let pending = pending_device_credential_from_preparation(
        &format!("http://{address}"),
        &prepared,
        false,
        None,
        completion.request_authority,
    )
    .expect("materialize exact pending claim credential");
    let authority = pending
        .request_authority
        .as_ref()
        .expect("request authority journal");
    assert_eq!(authority.flow, "setup_claim");
    assert_eq!(
        authority.prior_device_id.as_deref(),
        Some("device_existing_claim")
    );
    assert_eq!(
        authority.prior_device_sources.as_deref(),
        Some(["codex".to_string(), "pi".to_string()].as_slice())
    );
    let prior_secret_commitment = secret_sha256(&prior_secret);
    assert_eq!(
        authority.prior_secret_commitment_sha256.as_deref(),
        Some(prior_secret_commitment.as_str())
    );
    assert_eq!(
        pending.secret_commitment_sha256,
        secret_sha256(&candidate_secret)
    );
    let raw_journal = serde_json::to_string(&pending).expect("serialize pending journal");
    assert!(!raw_journal.contains(&prior_secret));
    assert!(!raw_journal.contains(&candidate_secret));
    stage_pending_device_credential(&pending, &candidate_secret)
        .expect("stage exact pending candidate");
    assert_eq!(
        FilePendingDeviceCredentialStore::default()
            .load()
            .expect("load exact pending candidate"),
        Some(pending)
    );
}

#[test]
fn existing_device_with_missing_secret_fails_closed() {
    use ottto_core::token_store::MemoryTokenStore;

    let root = control_test_root("claim-prior-secret-missing");
    let device_store = FileDeviceStore::new(root.join("device.json"));
    device_store
        .save(&LocalDeviceBinding {
            device_id: "device-existing".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string()],
        })
        .expect("save existing device");
    let missing_secret = MemoryTokenStore::new();

    assert!(matches!(
        prior_device_credential_with_stores(&device_store, &missing_secret, None),
        Err(LocalApiError::StatePoisoned)
    ));
    assert!(device_store
        .load()
        .expect("existing binding remains readable")
        .is_some());
}

#[test]
#[serial]
fn rejected_prior_proof_preserves_active_authority_and_no_pending_candidate() {
    let support_root = telemetry_key_store_root("claim-prior-proof-rejected");
    let secret_root = telemetry_key_store_root("claim-prior-proof-rejected-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let active_device = LocalDeviceBinding {
        device_id: "device-rejected-proof".to_string(),
        machine_id: Some("machine_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    let rejected_secret = format!("rejected-{}", "proof".repeat(4));
    FileDeviceStore::default()
        .save(&active_device)
        .expect("save active binding");
    fs::write(
        secret_root.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        &rejected_secret,
    )
    .expect("save rejected proof fallback");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind rejecting backend");
    let address = listener.local_addr().expect("rejecting backend address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept rejected proof");
        let _ = read_complete_http_request(&mut stream);
        write_json_response(
            &mut stream,
            401,
            "Unauthorized",
            r#"{"detail":"invalid prior device credential"}"#,
        );
    });
    let _api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &format!("http://{address}"));

    let result = complete_setup_claim(
        &PendingAuthClaim {
            claim_code: "claim_rejected".to_string(),
            claim_token: "token_rejected".to_string(),
            nonce: "nonce_rejected".to_string(),
            claim_url: "https://ottto.net/setup/claim?code=claim_rejected".to_string(),
            expires_at: "2026-05-05T09:30:00Z".to_string(),
        },
        &test_machine(),
        None,
    );
    server.join().expect("rejecting backend");

    assert!(matches!(
        result,
        Err(LocalApiError::Backend(details)) if details.status == Some(401)
    ));
    assert_eq!(
        FileDeviceStore::default().load().expect("active binding"),
        Some(active_device)
    );
    assert_eq!(
        KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .expect("active proof"),
        rejected_secret
    );
    assert!(FilePendingDeviceCredentialStore::default()
        .load()
        .expect("pending journal")
        .is_none());
}

#[test]
#[serial]
fn prior_secret_rotation_during_claim_http_is_detected_before_journaling() {
    let support_root = telemetry_key_store_root("claim-prior-proof-race");
    let secret_root = telemetry_key_store_root("claim-prior-proof-race-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device-proof-race".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string()],
        })
        .expect("save active binding");
    let secret_path = secret_root.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT);
    fs::write(&secret_path, "prior-proof-before").expect("save initial proof");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proof race backend");
    let address = listener.local_addr().expect("proof race address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept proof race");
        let request = read_complete_http_request(&mut stream);
        let body: serde_json::Value =
            serde_json::from_str(http_request_body(&request)).expect("proof race body");
        assert_eq!(body["prior_device_secret"], "prior-proof-before");
        fs::write(secret_path, "prior-proof-after").expect("rotate proof out of band");
        write_json_response(
            &mut stream,
            200,
            "OK",
            r#"{"setup_run_id":"setup_race","setup_run_token":"otsr_race","setup_run_token_expires_at":"2026-05-05T10:30:00Z","machine_id":"machine_test","connected_at":"2026-05-05T09:20:00Z","user":{"id":"user_race","email":"race@example.com","display_name":null},"organization":{"id":"org_race","name":"Race Org"}}"#,
        );
    });
    let _api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &format!("http://{address}"));

    let result = complete_setup_claim(
        &PendingAuthClaim {
            claim_code: "claim_race".to_string(),
            claim_token: "token_race".to_string(),
            nonce: "nonce_race".to_string(),
            claim_url: "https://ottto.net/setup/claim?code=claim_race".to_string(),
            expires_at: "2026-05-05T09:30:00Z".to_string(),
        },
        &test_machine(),
        None,
    );
    server.join().expect("proof race server");

    assert!(matches!(result, Err(LocalApiError::StatePoisoned)));
    assert!(FilePendingDeviceCredentialStore::default()
        .load()
        .expect("pending journal")
        .is_none());
}

#[test]
#[serial]
fn logout_backend_unavailable_preserves_local_state() {
    let secret_root = telemetry_key_store_root("logout-unavailable");
    fs::create_dir_all(&secret_root).expect("secret root");
    fs::write(secret_root.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT), "otsr_test")
        .expect("setup-run token");
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let api_base_url = unused_loopback_base_url();
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(LocalConnectionBinding {
            setup_run_id: "setup_unavailable".to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("machine_test".to_string()),
            claim_code: None,
            api_base_url,
        }));

    let response = handle_request(
        &daemon,
        LocalControlRequest {
            request_id: "req_logout_backend_unavailable".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::AuthReset {
                local_only: false,
                forget_installation: false,
            },
        },
    );

    assert!(!response.ok);
    let error = response.error.expect("error");
    assert_eq!(error.code, CliErrorCode::BackendUnreachable);
    assert!(error
        .message
        .contains("logout did not clear local credentials"));
    assert!(error
        .details
        .get("endpoint")
        .and_then(|value| match value {
            RedactedValue::String(endpoint) => Some(endpoint.as_str()),
            _ => None,
        })
        .is_some_and(|endpoint| endpoint
            .ends_with("/api/v1/setup-runs/setup_unavailable/local-client/disconnect")));
    assert_eq!(
        daemon
            .status("token")
            .expect("local state remains")
            .account
            .state,
        LocalAccountState::Connected
    );
    assert!(daemon
        .connection_for_authorized_client()
        .expect("connection lookup")
        .is_some());
}

fn auth_reset_request(
    request_id: &str,
    local_only: bool,
    forget_installation: bool,
) -> LocalControlRequest {
    LocalControlRequest {
        request_id: request_id.to_string(),
        protocol_version: if forget_installation {
            ottto_protocol::INSTALLATION_RESET_CONTROL_PROTOCOL_VERSION
        } else {
            PROTOCOL_VERSION
        },
        token: Some("token".to_string()),
        client_kind: Some(LocalClientKind::Cli),
        client_install_owner: None,
        command: LocalControlCommand::AuthReset {
            local_only,
            forget_installation,
        },
    }
}

const ENDED_RUN_RELEASED: &str = r#"{"device_released":true}"#;

#[test]
#[serial]
fn logout_after_ottto_ended_the_run_releases_this_mac_with_its_device_secret() {
    let _lock = lock_backend_test_env();
    let expired = r#"{"detail":"Setup run expired"}"#;
    let (api_base_url, server) = scripted_json_backend(vec![
        (401, expired),
        (401, expired),
        (200, ENDED_RUN_RELEASED),
    ]);
    let (root, _guards, daemon, _device) =
        connected_binding_fixture("logout-ended-run-release", api_base_url);

    let response = handle_request(
        &daemon,
        auth_reset_request("req_logout_ended_run_release", false, false),
    );
    let requests = server.join().expect("scripted backend");

    assert!(response.ok, "{response:?}");
    let payload = response.payload.expect("payload");
    assert_eq!(payload["local_only"], false);
    assert_eq!(payload["cloud_disconnected"], false);
    assert_eq!(payload["device_released"], true);
    assert!(payload["setup_run_id"].is_null());
    assert_eq!(
        payload["message"]["code"],
        "device_released_after_run_ended"
    );
    assert!(payload["message"]["text"]
        .as_str()
        .is_some_and(|text| text.contains("connection had expired")));
    assert!(!payload.to_string().contains("connected-secret"));
    assert_eq!(
        daemon.status("token").unwrap().account.state,
        LocalAccountState::NotConnected
    );
    // Same local cleanup as a successful cloud logout: no prior proof kept.
    assert!(FileDeviceStore::default().load().unwrap().is_none());
    assert!(FileDeviceStore::new(default_prior_device_path())
        .load()
        .unwrap()
        .is_none());
    assert!(KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .is_err());
    assert!(
        KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .is_err()
    );

    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("/local-client/disconnect"));
    assert!(requests[1].contains("/local-client/refresh"));
    let release = &requests[2];
    assert!(release.starts_with("POST /api/v1/telemetry/devices/device-connected/release "));
    assert!(release
        .lines()
        .any(|line| line.eq_ignore_ascii_case("x-ottto-device-secret: connected-secret")));
    assert!(!release
        .to_ascii_lowercase()
        .contains("x-ottto-setup-run-token"));
    assert_eq!(http_request_body(release), "");
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn credential_backend_calls_never_follow_redirects_or_reach_a_host_logger() {
    use crate::retry_tls::credential_test_support::{
        assert_never_logged, install_host_logger, RedirectingBackend,
    };
    let _lock = lock_backend_test_env();
    install_host_logger();
    for status in ["302 Found", "307 Temporary Redirect"] {
        let code = &status[..3];

        // Setup-run token on a POST (disconnect, events, scan results).
        let secret = format!("synthetic-run-token-post-{code}");
        let backend = RedirectingBackend::start(status);
        let url = format!(
            "{}/api/v1/setup-runs/run/local-client/disconnect",
            backend.base_url
        );
        let result: Result<serde_json::Value, LocalApiError> = backend_post_json(
            &url,
            &json!({"reason": "logout"}),
            &[("X-Ottto-Setup-Run-Token", secret.as_str())],
        );
        assert!(
            matches!(
                result,
                Err(LocalApiError::Backend(BackendErrorDetails {
                    kind: BackendErrorKind::ResponseUnexpected,
                    status: Some(returned),
                    ..
                })) if returned.to_string() == code
            ),
            "{status}: an unfollowed 3xx is not a success"
        );
        let request = backend.finish();
        assert!(request.contains(&format!("X-Ottto-Setup-Run-Token: {secret}")));
        assert_never_logged(&secret);

        // Setup-run token on a GET (agent reads, next action polling).
        let secret = format!("synthetic-run-token-get-{code}");
        let backend = RedirectingBackend::start(status);
        let url = format!("{}/api/v1/setup-runs/run/agent/costs", backend.base_url);
        let result: Result<serde_json::Value, LocalApiError> =
            backend_get_json(&url, &[("X-Ottto-Setup-Run-Token", secret.as_str())]);
        assert!(
            matches!(
                result,
                Err(LocalApiError::Backend(BackendErrorDetails {
                    kind: BackendErrorKind::ResponseUnexpected,
                    status: Some(returned),
                    ..
                })) if returned.to_string() == code
            ),
            "{status}: an unfollowed 3xx is not a success"
        );
        let request = backend.finish();
        assert!(request.starts_with("GET /api/v1/setup-runs/run/agent/costs "));
        assert!(request.contains(&format!("X-Ottto-Setup-Run-Token: {secret}")));
        assert_never_logged(&secret);

        // Device secret on the ended-run release.
        let secret = format!("synthetic-device-secret-release-{code}");
        let backend = RedirectingBackend::start(status);
        let proof = device_release_proof("device-synthetic".to_string(), secret.clone())
            .expect("complete proof");
        assert!(!release_device_without_setup_run(&backend.base_url, &proof));
        let request = backend.finish();
        assert!(request.contains(&format!("X-Ottto-Device-Secret: {secret}")));
        assert_never_logged(&secret);
    }
}

#[test]
#[serial]
fn ended_run_release_refuses_a_device_id_that_is_not_a_plain_path_segment() {
    let _lock = lock_backend_test_env();
    let proof = device_release_proof("../setup-runs/x".to_string(), "secret".to_string())
        .expect("complete proof");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    listener.set_nonblocking(true).expect("nonblocking");
    let api_base_url = format!("http://{}", listener.local_addr().unwrap());

    assert!(!release_device_without_setup_run(&api_base_url, &proof));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn disconnect_body_carries_release_proof_only_when_both_halves_exist() {
    let proof = device_release_proof("device_release".to_string(), "secret-release".to_string())
        .expect("complete proof");
    assert_eq!(
        setup_run_disconnect_body(Some(&proof)),
        json!({
            "reason": "logout",
            "release_device_id": "device_release",
            "release_device_secret": "secret-release",
        })
    );
    assert_eq!(
        setup_run_disconnect_body(None),
        json!({ "reason": "logout" })
    );
    assert!(device_release_proof(String::new(), "secret-release".to_string()).is_none());
    assert!(device_release_proof("device_release".to_string(), String::new()).is_none());
    assert!(!format!("{proof:?}").contains("secret-release"));
}

#[test]
fn account_switch_never_releases_the_incoming_device() {
    let proof = device_release_proof("device_old".to_string(), "secret-old".to_string())
        .expect("complete proof");
    assert!(releasable_on_switch(&proof, None));
    assert!(releasable_on_switch(&proof, Some("device_new")));
    assert!(!releasable_on_switch(&proof, Some("device_old")));
}

#[test]
fn revocation_receipt_release_responses_are_optional_and_debug_redacted() {
    let secret = "otrr_synthetic_response_receipt";
    for receipt in [None, Some(serde_json::Value::Null), Some(json!(secret))] {
        let mut body = json!({"setup_run_id":"run", "run_status":"disconnected",
            "client_disconnected":true, "disconnected_at":"2026-10-25T10:00:00Z",
            "device_released":true});
        if let Some(receipt) = receipt {
            body["revocation_receipt"] = receipt;
        }
        let disconnect: SetupRunDisconnectResponse = serde_json::from_value(body.clone()).unwrap();
        let release: DeviceSelfReleaseResponse = serde_json::from_value(body).unwrap();
        assert_eq!(
            disconnect
                .revocation_receipt
                .as_ref()
                .map(SecretString::expose_secret),
            release
                .revocation_receipt
                .as_ref()
                .map(SecretString::expose_secret)
        );
        assert!(!format!("{disconnect:?} {release:?}").contains(secret));
    }
}

struct HistoryChoiceTestEnv {
    root: PathBuf,
    _support: EnvVarGuard,
}
impl Drop for HistoryChoiceTestEnv {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn history_choice_test_env() -> HistoryChoiceTestEnv {
    let root = control_test_root("history-recovery");
    let guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    HistoryChoiceTestEnv {
        root,
        _support: guard,
    }
}

fn history_choice_test_stores() -> HistoryStores {
    use ottto_core::token_store::MemoryTokenStore;
    HistoryStores {
        receipt: Box::new(MemoryTokenStore::new()),
        marker: Box::new(MemoryTokenStore::new()),
        proof: Box::new(MemoryTokenStore::new()),
        browser: Box::new(MemoryTokenStore::new()),
    }
}

fn history_choice_stage_test_release(stores: &HistoryStores, base: &str, now: i64) {
    stage_local_release(
        base,
        &DeviceReleaseProof {
            device_id: "released-device".into(),
            device_secret: "synthetic-own-secret".into(),
        },
        stores,
        now,
    )
    .unwrap();
}

fn history_choice_store_test_receipt(stores: &HistoryStores, now: i64) {
    history_save(
        stores.receipt.as_ref(),
        &StoredRevocationReceipt {
            revocation_receipt: SecretString::new("otrr_synthetic_history_receipt"),
            received_at: now,
        },
    )
    .unwrap();
}

fn history_choice_create(
    base: &str,
    stores: &HistoryStores,
    now: i64,
) -> Result<SetupClaimCreateResponse, LocalApiError> {
    create_setup_claim_with_history(
        &api_url_with_base(base, "/api/v1/setup-claims"),
        &test_machine(),
        "synthetic-original-nonce",
        stores,
        now,
    )
}

fn history_choice_request_body(request: &str) -> serde_json::Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}

const RECEIPT_CLAIM_SUCCESS: &str = r#"{"claim_code":"claim","claim_token":"token","client_nonce":"synthetic-original-nonce","claim_url":"https://ottto.net/setup/claim?code=claim","expires_at":"2030-01-01T00:00:00Z"}"#;

#[test]
#[serial]
fn history_choice_receipt_malformed_2xx_and_5xx_retry_keep_one_ceremony() {
    use crate::retry_tls::credential_test_support::{assert_never_logged, install_host_logger};
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    install_host_logger();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let ceremonies = Arc::new(AtomicUsize::new(0));
    let server_count = ceremonies.clone();
    let server = thread::spawn(move || {
        let mut seen = BTreeSet::new();
        let mut requests = Vec::new();
        for (status, body) in [
            (429, "{}"),
            (503, "{}"),
            (200, "{"),
            (200, RECEIPT_CLAIM_SUCCESS),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_complete_http_request(&mut stream);
            let body_receipt = history_choice_request_body(&request)["revocation_receipt"]
                .as_str()
                .unwrap()
                .to_string();
            if seen.insert(body_receipt) {
                server_count.fetch_add(1, Ordering::SeqCst);
            }
            requests.push(request);
            write_json_response(&mut stream, status, "Fixture", body);
        }
        requests
    });
    let stores = history_choice_test_stores();
    history_choice_stage_test_release(&stores, &base, 100);
    history_choice_store_test_receipt(&stores, 100);
    let encoded = stores.receipt.load().unwrap();
    for now in [101, 102, 103] {
        assert!(history_choice_create(&base, &stores, now).is_err());
        assert_eq!(stores.receipt.load().unwrap(), encoded);
        assert!(stores.marker.load().is_ok());
    }
    let claim = history_choice_create(&base, &stores, 104).unwrap();
    assert_eq!(claim.claim_code, "claim");
    assert_eq!(
        ceremonies.load(Ordering::SeqCst),
        1,
        "retries must not create a second ceremony"
    );
    assert!(matches!(
        stores.receipt.load(),
        Err(TokenStoreError::Missing)
    ));
    // The question is still unanswered; marker/proof survive until actual
    // completion, so an expired or lost local claim can be recovered too.
    assert!(stores.marker.load().is_ok());
    assert!(stores.proof.load().is_ok());
    assert!(!format!("{claim:?}").contains("token"));
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 4);
    for request in requests {
        assert_eq!(
            history_choice_request_body(&request)["revocation_receipt"],
            "otrr_synthetic_history_receipt"
        );
    }
    finish_history_browser_claim_with_stores("claim", &stores).unwrap();
    for store in [
        &stores.receipt,
        &stores.marker,
        &stores.proof,
        &stores.browser,
    ] {
        assert!(matches!(store.load(), Err(TokenStoreError::Missing)));
    }
    assert_never_logged("otrr_synthetic_history_receipt");
    assert_never_logged("synthetic-own-secret");
}

#[test]
#[serial]
fn history_choice_receipt_transport_failure_keeps_proof_and_marker() {
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let stores = history_choice_test_stores();
    history_choice_stage_test_release(&stores, &base, 100);
    history_choice_store_test_receipt(&stores, 100);
    let before = stores.receipt.load().unwrap();
    assert!(history_choice_create(&base, &stores, 101).is_err());
    assert_eq!(stores.receipt.load().unwrap(), before);
    assert!(stores.marker.load().is_ok());
    assert!(stores.proof.load().is_ok());
}

struct HistoryChoiceFaultStore {
    inner: ottto_core::token_store::MemoryTokenStore,
    fail_load: std::sync::atomic::AtomicBool,
    fail_delete: std::sync::atomic::AtomicBool,
}
impl ControlTokenStore for HistoryChoiceFaultStore {
    fn load(&self) -> Result<String, TokenStoreError> {
        if self.fail_load.swap(false, Ordering::SeqCst) {
            return Err(TokenStoreError::Store("synthetic read failure".into()));
        }
        self.inner.load()
    }
    fn save(&self, value: &str) -> Result<(), TokenStoreError> {
        self.inner.save(value)
    }
    fn delete(&self) -> Result<(), TokenStoreError> {
        if self.fail_delete.swap(false, Ordering::SeqCst) {
            return Err(TokenStoreError::Store("synthetic delete failure".into()));
        }
        self.inner.delete()
    }
}

struct HistoryChoiceUnavailableStore;
impl ControlTokenStore for HistoryChoiceUnavailableStore {
    fn load(&self) -> Result<String, TokenStoreError> {
        Err(TokenStoreError::Store("synthetic unavailable store".into()))
    }
    fn save(&self, _: &str) -> Result<(), TokenStoreError> {
        Err(TokenStoreError::Store("synthetic unavailable store".into()))
    }
    fn delete(&self) -> Result<(), TokenStoreError> {
        Err(TokenStoreError::Store("synthetic unavailable store".into()))
    }
}
fn history_choice_unavailable_stores() -> HistoryStores {
    HistoryStores {
        receipt: Box::new(HistoryChoiceUnavailableStore),
        marker: Box::new(HistoryChoiceUnavailableStore),
        proof: Box::new(HistoryChoiceUnavailableStore),
        browser: Box::new(HistoryChoiceUnavailableStore),
    }
}

#[test]
#[serial]
fn history_choice_ordinary_sign_in_works_without_optional_keychain() {
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    let (base, server) = scripted_json_backend(vec![(200, RECEIPT_CLAIM_SUCCESS)]);
    let stores = history_choice_unavailable_stores();
    assert!(
        resume_history_browser_claim_with_stores(&test_machine(), &base, &stores)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        history_choice_create(&base, &stores, 101)
            .unwrap()
            .claim_code,
        "claim"
    );
    assert!(retire_refused_registration_after_browser_answer_with_stores("claim", &stores).is_ok());
    assert!(history_choice_request_body(&server.join().unwrap()[0])
        .get("revocation_receipt")
        .is_none());
    persist_local_release_expected().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let blocked_base = format!("http://{}", listener.local_addr().unwrap());
    assert!(
        history_choice_create(&blocked_base, &stores, 102).is_err(),
        "known release must not silently downgrade when Keychain is locked"
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
#[serial]
fn history_choice_forget_installation_invalidates_old_browser_credentials() {
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    let base = DEFAULT_API_BASE_URL;
    let stores = history_stores();
    history_choice_stage_test_release(&stores, base, history_now());
    let claim: SetupClaimCreateResponse = serde_json::from_str(RECEIPT_CLAIM_SUCCESS).unwrap();
    persist_history_browser_claim(
        &claim,
        "synthetic-original-nonce",
        &test_machine(),
        base,
        &stores,
    )
    .unwrap();
    {
        let _identity_lock = lock_setup_run_binding();
        forget_installation_state_locked().unwrap();
    }
    let mut machine = test_machine();
    machine.installation_id = "new-installation-after-forget".into();
    assert!(resume_history_browser_claim(&machine, base)
        .unwrap()
        .is_none());
    assert!(!local_history_recovery_expected().unwrap());
    for store in [
        &stores.receipt,
        &stores.marker,
        &stores.proof,
        &stores.browser,
    ] {
        assert!(matches!(store.load(), Err(TokenStoreError::Missing)));
    }
}

#[test]
#[serial]
fn history_choice_release_recovery_preserves_identity_reservation_witness() {
    let _lock = lock_backend_test_env();
    let (root, _guards, daemon, _) =
        connected_binding_fixture("history-reservation", DEFAULT_API_BASE_URL.into());
    let account = FileAccountStore::default().load().unwrap();
    let reservation = reserve_identity_mutation().unwrap();
    let stores = history_stores();
    history_choice_stage_test_release(&stores, DEFAULT_API_BASE_URL, history_now());
    {
        let _identity_lock = lock_setup_run_binding();
        assert_eq!(reservation.validate_locked(), Ok(()));
    }
    let pending = PendingAuthClaim {
        claim_code: "claim".into(),
        claim_token: "token".into(),
        nonce: "nonce".into(),
        claim_url: "https://ottto.net/setup/claim?code=claim".into(),
        expires_at: "2030-01-01T00:00:00Z".into(),
    };
    assert!(matches!(
        begin_durable_browser_claim(&daemon, pending),
        Err(LocalApiError::IdentityMutationInProgress)
    ));
    clear_local_release(&stores).unwrap();
    assert_eq!(FileAccountStore::default().load().unwrap(), account);
    {
        let _identity_lock = lock_setup_run_binding();
        assert_eq!(reservation.validate_locked(), Ok(()));
        let mut changed = account;
        changed.message = Some(StableMessage {
            code: "unrelated-authority-change".into(),
            text: "synthetic".into(),
        });
        FileAccountStore::default().save(&changed).unwrap();
        assert_eq!(
            reservation.validate_locked(),
            Err(LocalApiError::IdentityMutationInProgress)
        );
    }
    drop(reservation);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn history_choice_interrupted_closed_cleanup_needs_no_deleted_proof() {
    use ottto_core::token_store::MemoryTokenStore;
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    let (base, server) = scripted_json_backend(vec![(200, RECEIPT_CLAIM_SUCCESS)]);
    let mut stores = history_choice_test_stores();
    history_choice_stage_test_release(&stores, &base, 100);
    history_choice_store_test_receipt(&stores, 100);
    let marker = MemoryTokenStore::new();
    marker.save(&stores.marker.load().unwrap()).unwrap();
    stores.marker = Box::new(HistoryChoiceFaultStore {
        inner: marker,
        fail_load: false.into(),
        fail_delete: true.into(),
    });
    assert!(clear_local_release(&stores).is_err());
    assert!(matches!(stores.proof.load(), Err(TokenStoreError::Missing)));
    assert!(
        history_load::<LocalReleaseMarker>(stores.marker.as_ref())
            .unwrap()
            .unwrap()
            .ceremony_closed
    );
    assert!(history_choice_create(&base, &stores, 101).is_ok());
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /api/v1/setup-claims "));
    assert!(matches!(
        stores.marker.load(),
        Err(TokenStoreError::Missing)
    ));
}

#[test]
#[serial]
fn history_choice_receipt_missing_read_or_parse_failure_reissues_before_claim() {
    use ottto_core::token_store::MemoryTokenStore;
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    for fault in ["missing", "read", "parse"] {
        let (base, server) = scripted_json_backend(vec![
            (
                200,
                r#"{"outcome":"receipt_issued","revocation_receipt":"otrr_reissued"}"#,
            ),
            (200, RECEIPT_CLAIM_SUCCESS),
        ]);
        let inner = MemoryTokenStore::new();
        if fault == "parse" {
            inner.save("{").unwrap();
        }
        let mut stores = history_choice_test_stores();
        history_choice_stage_test_release(&stores, &base, 100);
        stores.browser.save("{").unwrap();
        assert!(
            resume_history_browser_claim_with_stores(&test_machine(), &base, &stores)
                .unwrap()
                .is_none()
        );
        stores.receipt = Box::new(HistoryChoiceFaultStore {
            inner,
            fail_load: (fault == "read").into(),
            fail_delete: false.into(),
        });
        assert_eq!(
            history_choice_create(&base, &stores, 101)
                .unwrap()
                .claim_code,
            "claim"
        );
        let requests = server.join().unwrap();
        assert!(requests[0]
            .starts_with("POST /api/v1/telemetry/devices/released-device/revocation-receipt "));
        assert!(requests[0].contains("X-Ottto-Device-Secret: synthetic-own-secret"));
        assert!(requests[1].starts_with("POST /api/v1/setup-claims "));
        assert_eq!(
            history_choice_request_body(&requests[1])["revocation_receipt"],
            "otrr_reissued"
        );
    }
}

#[test]
#[serial]
fn history_choice_receipt_failed_delete_recovers_same_claim_and_original_nonce() {
    use ottto_core::token_store::MemoryTokenStore;
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    let (base, server) = scripted_json_backend(vec![
        (200, RECEIPT_CLAIM_SUCCESS),
        (
            200,
            r#"{"outcome":"claim_recovered","claim_code":"claim","claim_token":"token","client_nonce":"synthetic-original-nonce"}"#,
        ),
        (
            200,
            r#"{"claim_url":"https://ottto.net/setup/claim?code=claim","expires_at":"2030-01-01T00:00:00Z"}"#,
        ),
    ]);
    let mut stores = history_choice_test_stores();
    let inner = MemoryTokenStore::new();
    inner
        .save(
            &serde_json::to_string(&StoredRevocationReceipt {
                revocation_receipt: SecretString::new("otrr_original"),
                received_at: 100,
            })
            .unwrap(),
        )
        .unwrap();
    history_choice_stage_test_release(&stores, &base, 100);
    stores.receipt = Box::new(HistoryChoiceFaultStore {
        inner,
        fail_load: false.into(),
        fail_delete: true.into(),
    });
    let first = history_choice_create(&base, &stores, 101).unwrap();
    let marker: LocalReleaseMarker = history_load(stores.marker.as_ref()).unwrap().unwrap();
    assert!(marker.cleanup_required);
    let second = create_setup_claim_with_history(
        &api_url_with_base(&base, "/api/v1/setup-claims"),
        &test_machine(),
        "a-new-nonce-must-not-rebind",
        &stores,
        102,
    )
    .unwrap();
    assert_eq!(first.claim_code, second.claim_code);
    assert_eq!(
        second.client_nonce.as_deref(),
        Some("synthetic-original-nonce")
    );
    let requests = server.join().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST /api/v1/setup-claims "))
            .count(),
        1
    );
    assert!(requests[1].contains("/revocation-receipt "));
    assert!(requests[2].starts_with("GET /api/v1/setup-claims/claim "));
}

#[test]
#[serial]
fn history_choice_receipt_reissue_unavailable_or_rate_limited_never_silently_creates() {
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    for (status, body) in [
        (503, "{}"),
        (429, r#"{"detail":"rate limited"}"#),
        (200, "{"),
    ] {
        let (base, server) = scripted_json_backend(vec![(status, body)]);
        let stores = history_choice_test_stores();
        history_choice_stage_test_release(&stores, &base, 100);
        assert!(history_choice_create(&base, &stores, 101).is_err());
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("/revocation-receipt "));
        assert!(stores.marker.load().is_ok());
    }
}

#[test]
#[serial]
fn history_choice_receipt_definitive_reissue_refusal_allows_unconfirmed_claim() {
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    for (status, body) in [
        (401, r#"{"detail":{"code":"device_secret_invalid"}}"#),
        (409, r#"{"detail":{"code":"ceremony_closed"}}"#),
        (404, r#"{"detail":"Not Found"}"#),
    ] {
        let (base, server) =
            scripted_json_backend(vec![(status, body), (200, RECEIPT_CLAIM_SUCCESS)]);
        let stores = history_choice_test_stores();
        history_choice_stage_test_release(&stores, &base, 100);
        assert!(history_choice_create(&base, &stores, 101).is_ok());
        let requests = server.join().unwrap();
        assert!(requests[0].contains("/revocation-receipt "));
        assert!(history_choice_request_body(&requests[1])
            .get("revocation_receipt")
            .is_none());
    }
}

#[test]
#[serial]
fn history_choice_receipt_marker_survives_reload_and_expires_at_24h() {
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    let root = control_test_root("history-marker-reload");
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let (base, server) = scripted_json_backend(vec![(200, RECEIPT_CLAIM_SUCCESS)]);
    {
        let stores = history_stores();
        history_choice_stage_test_release(&stores, &base, 100);
        history_choice_store_test_receipt(&stores, 100);
    }
    let reloaded = history_stores();
    let marker: LocalReleaseMarker = history_load(reloaded.marker.as_ref()).unwrap().unwrap();
    assert_eq!(marker.device_id, "released-device");
    assert_eq!(marker.released_at, 100);
    assert!(
        history_choice_create(&base, &reloaded, 100 + REVOCATION_RECEIPT_MAX_AGE_SECONDS).is_ok()
    );
    assert!(history_choice_request_body(&server.join().unwrap()[0])
        .get("revocation_receipt")
        .is_none());
    for store in [&reloaded.receipt, &reloaded.marker, &reloaded.proof] {
        assert!(matches!(store.load(), Err(TokenStoreError::Missing)));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn history_choice_receipt_definitive_4xx_closes_local_marker() {
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    for status in [400, 401, 404, 422] {
        let (base, server) = scripted_json_backend(vec![(status, "{}")]);
        let stores = history_choice_test_stores();
        history_choice_stage_test_release(&stores, &base, 100);
        history_choice_store_test_receipt(&stores, 100);
        assert!(history_choice_create(&base, &stores, 101).is_err());
        assert_eq!(server.join().unwrap().len(), 1);
        for store in [&stores.receipt, &stores.marker, &stores.proof] {
            assert!(matches!(store.load(), Err(TokenStoreError::Missing)));
        }
    }
}

#[test]
#[serial]
fn history_choice_registration_prepare_400_preserves_old_binding() {
    let _lock = lock_backend_test_env();
    let (base, server) = scripted_json_backend(vec![(
        400,
        r#"{"code":"history_choice_required","detail":"Setup claim session is pending: answer in the browser"}"#,
    )]);
    let (root, _guards, _, old_device) =
        connected_binding_fixture("history-prepare-refusal", base.clone());
    let session = InstallSessionApiResponse {
        install_session_id: "install-existing".into(),
        install_session_token: "synthetic-install-token".into(),
    };
    let error = prepare_telemetry_device_registration(&base, &session, &test_machine())
        .err()
        .expect("history refusal");
    assert!(registration_history_choice_required(&error));
    assert!(registration_history_choice_account(
        &FileAccountStore::default().load().unwrap()
    ));
    assert_eq!(FileDeviceStore::default().load().unwrap(), Some(old_device));
    assert!(FilePendingDeviceCredentialStore::default()
        .load()
        .unwrap()
        .is_none());
    assert_eq!(server.join().unwrap().len(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn history_choice_registration_action_reoffers_browser_without_failed_completion() {
    let _lock = lock_backend_test_env();
    let (base, server) = scripted_json_backend(vec![
        (200, "{}"), // heartbeat before polling the next setup action
        (
            200,
            r#"{"action":{"id":"action-history","action_type":"install_source","source":"codex"}}"#,
        ),
        (200, "{}"),
        (
            200,
            r#"{"install_session_id":"install-history","install_session_token":"synthetic-install"}"#,
        ),
        (200, "{}"),
        (
            400,
            r#"{"code":"history_choice_required","detail":"Setup claim session is pending: answer in the browser"}"#,
        ),
        (200, RECEIPT_CLAIM_SUCCESS),
    ]);
    let (root, _guards, daemon, old_device) =
        connected_binding_fixture("history-action", base.clone());
    let connection = FileConnectionStore::default().load().unwrap().unwrap();
    let candidate = format!("candidate-{}", "value".repeat(4));
    let mut pending = test_pending_device_credential("old-running-candidate", true);
    pending.api_base_url = base.clone();
    pending.expires_at = "2099-01-01T00:00:00Z".into();
    stage_pending_device_credential(&pending, &candidate).unwrap();
    let mut credentials = SetupRunCredentials {
        setup_run_token: "synthetic-setup-token".into(),
        connection: connection.clone(),
    };
    let results = process_setup_actions(&daemon, &base, &mut credentials, &test_machine()).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, "running");
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 7);
    assert!(requests.iter().all(|r| !r.contains("/complete ")));
    assert_eq!(
        daemon
            .pending_auth_claim_snapshot()
            .unwrap()
            .unwrap()
            .0
            .claim_code,
        "claim"
    );
    assert_eq!(
        FilePendingDeviceCredentialStore::default().load().unwrap(),
        Some(pending)
    );
    assert_eq!(FileDeviceStore::default().load().unwrap(), Some(old_device));
    assert_eq!(
        FileConnectionStore::default().load().unwrap(),
        Some(connection)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn history_choice_receipt_lost_own_proof_blocks_ordinary_claim() {
    let _lock = lock_backend_test_env();
    let _env = history_choice_test_env();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let stores = history_choice_test_stores();
    history_choice_stage_test_release(&stores, &base, 100);
    stores.proof.delete().unwrap();
    assert!(history_choice_create(&base, &stores, 101).is_err());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert!(stores.marker.load().is_ok());
}

#[test]
#[serial]
fn history_choice_registration_old_candidate_reoffers_browser_after_reload() {
    let _lock = lock_backend_test_env();
    let (api, server) = scripted_json_backend(vec![(
        400,
        r#"{"code":"history_choice_required","detail":"Setup claim session is pending: answer in the browser"}"#,
    )]);
    let (root, _guards, _, old_device) =
        connected_binding_fixture("history-choice-old-candidate", api.clone());
    let candidate = format!("candidate-{}", "value".repeat(4));
    let mut pending = test_pending_device_credential("prepared-by-shipped-daemon", true);
    pending.api_base_url = api;
    pending.expires_at = "2099-01-01T00:00:00Z".to_string();
    stage_pending_device_credential(&pending, &candidate).unwrap();
    let before = FilePendingDeviceCredentialStore::default().load().unwrap();
    let old_secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .unwrap();
    let old_connection = FileConnectionStore::default().load().unwrap();
    let recovered = recover_pending_device_credential_at_startup();
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        recovered,
        Ok(false),
        "history refusal must become a durable browser re-offer"
    );
    let saved = FileAccountStore::default().load().unwrap();
    assert_eq!(
        saved.message.as_ref().unwrap().code,
        "history_choice_required"
    );
    assert_eq!(
        FilePendingDeviceCredentialStore::default().load().unwrap(),
        before
    );
    assert_eq!(FileDeviceStore::default().load().unwrap(), Some(old_device));
    assert_eq!(
        KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .unwrap(),
        old_secret
    );
    assert_eq!(
        KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .unwrap(),
        candidate
    );

    let (claim_api, claim_server) = scripted_json_backend(vec![(200, RECEIPT_CLAIM_SUCCESS)]);
    let _api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &claim_api);
    let daemon = daemon()
        .with_account(saved)
        .with_connection(old_connection.clone());
    let authorization = RequestAuthorization::Token("token".to_string());
    let first = auth_start(&daemon, &authorization).expect("browser claim offered");
    assert_eq!(first.claim_code, "claim");
    assert_eq!(claim_server.join().unwrap().len(), 1);
    assert_eq!(
        auth_start(&daemon, &authorization).unwrap().claim_code,
        first.claim_code
    );
    let restarted = self::daemon()
        .with_account(FileAccountStore::default().load().unwrap())
        .with_connection(old_connection.clone());
    assert_eq!(
        auth_start(&restarted, &authorization).unwrap().claim_code,
        first.claim_code
    );
    assert_eq!(
        FileConnectionStore::default().load().unwrap(),
        old_connection
    );
    assert_eq!(
        FilePendingDeviceCredentialStore::default().load().unwrap(),
        before
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn cloud_forget_installation_releases_device_before_forgetting() {
    let root = telemetry_key_store_root("cloud-forget-installation");
    let support_root = root.join("support");
    let secret_root = root.join("secrets");
    fs::create_dir_all(support_root.join("snapshots/destinations/old")).unwrap();
    fs::create_dir_all(&secret_root).unwrap();
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileMachineStore::default()
        .save(&LocalMachineBinding {
            machine_id: "otm_original".to_string(),
            installation_id: "oti_original".to_string(),
            hardware_uuid: None,
        })
        .unwrap();
    FileAccountStore::default()
        .save(&connected_account())
        .unwrap();
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_cloud_forget".to_string(),
            machine_id: Some("otm_original".to_string()),
            sources: vec!["codex".to_string()],
        })
        .unwrap();
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("device-secret-cloud-forget")
        .unwrap();
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save("setup-token-cloud-forget")
        .unwrap();
    fs::write(
        support_root.join("snapshots/destinations/old/codex-scan-index.json"),
        b"receipt",
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind release backend");
    let address = listener.local_addr().expect("release backend address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept release");
        let request = read_complete_http_request(&mut stream);
        write_json_response(
            &mut stream,
            200,
            "OK",
            r#"{"setup_run_id":"run_cloud_forget","run_status":"disconnected","client_disconnected":true,"disconnected_at":"2026-10-18T12:00:00Z","device_released":true}"#,
        );
        request
    });
    let api_base_url = format!("http://{address}");
    let _api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);
    let connection = LocalConnectionBinding {
        setup_run_id: "run_cloud_forget".to_string(),
        setup_run_token_expires_at: "2026-10-18T13:00:00Z".to_string(),
        machine_id: Some("otm_original".to_string()),
        claim_code: None,
        api_base_url,
    };
    FileConnectionStore::default().save(&connection).unwrap();

    let response = handle_request(
        &daemon()
            .with_account(connected_account())
            .with_connection(Some(connection)),
        LocalControlRequest {
            request_id: "req_cloud_forget_installation".to_string(),
            protocol_version: ottto_protocol::INSTALLATION_RESET_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::AuthReset {
                local_only: false,
                forget_installation: true,
            },
        },
    );
    let request = server.join().expect("release backend");

    assert!(response.ok, "{response:?}");
    assert!(
        request.starts_with("POST /api/v1/setup-runs/run_cloud_forget/local-client/disconnect ")
    );
    let body: serde_json::Value =
        serde_json::from_str(http_request_body(&request)).expect("disconnect body");
    assert_eq!(
        body,
        json!({
            "reason": "logout",
            "release_device_id": "device_cloud_forget",
            "release_device_secret": "device-secret-cloud-forget",
        })
    );
    let payload = response.payload.expect("payload");
    assert_eq!(payload["cloud_disconnected"], true);
    assert_eq!(payload["device_released"], true);
    assert_eq!(payload["message"]["code"], "installation_forgotten");
    assert!(!payload.to_string().contains("device-secret-cloud-forget"));
    assert!(FileMachineStore::default().load().unwrap().is_none());
    assert!(FileDeviceStore::default().load().unwrap().is_none());
    assert!(KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .is_err());
    assert!(support_root
        .join("snapshots/destinations/old/codex-scan-index.json")
        .exists());
    let _ = fs::remove_dir_all(root);
}

/// [behaviour] Each decoded XPC command counts once under its class.
#[test]
fn raw_local_control_json_counts_command_class() {
    let status = LocalControlCommand::Status {
        refresh_agent_status: false,
        retry_relay_authorization: false,
    };
    let refresh = LocalControlCommand::AgentStatusRefresh {
        source: None,
        quota_refresh: false,
    };
    for (command, class) in [
        (status, "status"),
        (
            LocalControlCommand::ClaudeAccountsStatus,
            "claude_accounts_status",
        ),
        (
            LocalControlCommand::CodexAccountsStatus,
            "codex_accounts_status",
        ),
        (refresh, "agent_status_refresh"),
        (LocalControlCommand::AuthStatus, "other"),
    ] {
        let request = LocalControlRequest {
            request_id: "r".to_string(),
            protocol_version: ottto_protocol::expected_local_control_protocol_version(&command),
            token: Some("wrong".to_string()),
            client_kind: None,
            client_install_owner: None,
            command,
        };
        let json = serde_json::to_string(&request).unwrap();
        handle_request_json_with_peer(&daemon(), &json, None);
        let counts = crate::local_resource_diagnostics::take_control();
        assert_eq!(counts, BTreeMap::from([(class, 1)]), "{class}");
    }
}

#[test]
fn raw_local_control_json_rejects_stale_protocol_version() {
    let response = handle_request_json_with_peer(
        &daemon(),
        r#"{"request_id":"req_stale","protocol_version":10,"token":"token","client_kind":"cli","command":"status"}"#,
        None,
    );
    let response: LocalControlResponse =
        serde_json::from_str(&response).expect("local control response");

    assert!(!response.ok);
    let error = response.error.expect("error");
    assert_eq!(error.code, CliErrorCode::InvalidRequest);
    assert!(error
        .message
        .contains("unsupported local control protocol_version 10"));
}

#[test]
fn validated_api_base_url_rejects_untrusted_https_origin() {
    assert!(validated_api_base_url(Some("https://attacker.example")).is_err());
}

#[test]
fn validated_api_base_url_accepts_default_origin() {
    assert_eq!(
        validated_api_base_url(Some(DEFAULT_API_BASE_URL)).expect("valid"),
        DEFAULT_API_BASE_URL.to_string()
    );
}

#[test]
fn agent_costs_url_encodes_local_client_query() {
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_costs".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: DIRECT_API_BASE_URL.to_string(),
    };
    let url = agent_costs_url(
        DIRECT_API_BASE_URL,
        &connection,
        &AgentCostsQuery {
            days: Some(14),
            range: Some("last 7 days".to_string()),
            start_date: Some("2026-06-01".to_string()),
            end_date: Some("2026-06-05".to_string()),
            timezone: Some("America/Los_Angeles".to_string()),
            source: Some("vertex".to_string()),
            machine_id: Some("otm_test".to_string()),
            source_plan_profile_id: Some("profile_123".to_string()),
            bucket: Some("day".to_string()),
            mode: Some("full".to_string()),
            all_machines: false,
            dimensions: Some("machine,model".to_string()),
            daily: true,
        },
    );

    assert_eq!(
        url,
        "https://api.ottto.net/api/v1/setup-runs/setup_costs/local-client/costs?days=14&range=last+7+days&start_date=2026-06-01&end_date=2026-06-05&source=vertex&machine_id=otm_test&source_plan_profile_id=profile_123&bucket=day&mode=full&dimensions=machine%2Cmodel&daily=true"
    );
}

#[test]
fn refresh_setup_run_token_refuses_untrusted_api_base() {
    // SECURITY (Codex High: "Verify refresh can leak device secret to
    // untrusted API base"): the device-secret refresh must fail closed when
    // connection.api_base_url is untrusted, BEFORE the relay device_secret is
    // loaded or POSTed anywhere. Validation runs first, so an attacker base
    // never reaches the secret-bearing request.
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_untrusted".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: "https://attacker.example".to_string(),
    };
    let result = refresh_setup_run_token_via_device_secret("https://attacker.example", &connection);
    assert!(matches!(result, Err(LocalApiError::NetworkUnavailable)));
}

#[test]
#[serial]
fn control_token_validation_base_ignores_request_loopback_without_env() {
    let _guard = lock_backend_test_env();
    let _env_guard = EnvVarGuard::remove("OTTTO_API_BASE_URL");
    // The attack: a request-supplied loopback validation URL must NOT be
    // honored; validation falls back to the trusted production default.
    assert_eq!(
        control_token_validation_base_url(Some("http://127.0.0.1:1")).expect("fallback"),
        DEFAULT_API_BASE_URL.to_string()
    );
    assert_eq!(
        control_token_validation_base_url(Some("http://localhost:8787")).expect("fallback"),
        DEFAULT_API_BASE_URL.to_string()
    );
}

#[test]
#[serial]
fn control_token_validation_base_rejects_untrusted_env_origin() {
    let _guard = lock_backend_test_env();
    let _env_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", "https://attacker.example");
    assert!(control_token_validation_base_url(None).is_err());
}

#[test]
#[serial]
fn telemetry_control_ignores_request_supplied_localhost_base() {
    // SECURITY regression guard for the control-token authorization bypass:
    // a request whose `api_base_url` points at an attacker loopback server
    // must NOT cause the control token to be validated against that server.
    //
    // The trusted env-resolved backend is wired to a mock that REJECTS the
    // token (HTTP 401), while the request `api_base_url` points at an
    // attacker mock that would APPROVE it (HTTP 200). If the request field
    // were still honored the forged token would be approved; the fix routes
    // validation to the env backend, so the request is correctly rejected.
    let _guard = lock_backend_test_env();
    let trusted_rejecting_backend = control_token_validation_server(401);
    let _env_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &trusted_rejecting_backend);
    let attacker_approving_backend = control_token_validation_server(200);
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_telemetry_attacker_base".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: None,
            client_kind: Some(LocalClientKind::WebUi),
            client_install_owner: None,
            command: LocalControlCommand::TelemetryControl {
                action: TelemetryControlAction::Status,
                source: SourceKind::Codex,
                control_token: test_control_token("status", "codex", 300),
                api_base_url: Some(attacker_approving_backend),
                key_id: None,
                organization_id: None,
                otlp_endpoint: None,
                ingest_key: None,
            },
        },
    );

    // Validation hit the trusted (rejecting) backend, not the attacker's
    // approving one, so the forged token is denied.
    assert!(!response.ok, "{response:?}");
    assert_eq!(
        response.error.expect("error").code,
        CliErrorCode::LocalClientNotTrusted
    );
}

#[test]
fn commits_equivalent_handles_short_and_long_hashes() {
    assert!(commits_equivalent("436d0f2a", "436d0f2a2352"));
    assert!(commits_equivalent("436d0f2a2352", "436D0F2A"));
    assert!(!commits_equivalent("436d0f2a", "deadbeef"));
    assert!(!commits_equivalent("436", "436d0f2a"));
    assert!(commits_equivalent("", ""));
}

#[test]
fn app_bundle_client_can_report_supported_service_owner_health() {
    assert!(!client_owner_conflict(
        InstallOwner::AppBundle,
        InstallOwner::HostedInstaller
    ));
    assert!(!client_owner_conflict(
        InstallOwner::AppBundle,
        InstallOwner::AppBundle
    ));
    assert!(!client_owner_conflict(
        InstallOwner::AppBundle,
        InstallOwner::Unknown
    ));
    assert!(!client_owner_conflict(
        InstallOwner::AppBundle,
        InstallOwner::Homebrew
    ));
    assert!(client_owner_conflict(
        InstallOwner::AppBundle,
        InstallOwner::Dev
    ));
}

#[test]
fn version_tuple_collapses_dev_suffixes() {
    // Documents the prior false-current bug: dev builds with different
    // commits collapse to the same semver tuple, so commit comparison must
    // be the disambiguator.
    assert_eq!(
        version_tuple("0.1.0-dev-436d0f2a"),
        version_tuple("0.1.0-dev-deadbeef")
    );
}

fn release_manifest_for_update(
    version: &str,
    min_supported_version: Option<&str>,
    min_protocol_version: Option<u16>,
) -> ReleaseManifest {
    ReleaseManifest {
        schema_version: 1,
        product: "ottto-local-platform".to_string(),
        version: version.to_string(),
        channel: ReleaseChannel::Dev,
        commit: "deadbeef".to_string(),
        min_supported_version: min_supported_version.unwrap_or("0.1.0").to_string(),
        min_protocol_version: min_protocol_version.unwrap_or(PROTOCOL_VERSION),
        supported_install_owners: vec![
            InstallOwner::Homebrew,
            InstallOwner::HostedInstaller,
            InstallOwner::AppBundle,
        ],
        release_notes: Some(
            "- Fixes sign-in completion.\n- Improves local usage sync reliability.".to_string(),
        ),
        rollback: ReleaseRollback {
            strategy: "channel_latest_pointer".to_string(),
            immutable_prefix:
                "https://install.ottto.net/ottto-local-platform/releases/dev/latest"
                    .to_string(),
            latest_manifest_url:
                "https://install.ottto.net/ottto-local-platform/releases/dev/latest/release-manifest.json"
                    .to_string(),
            preserve_failed_version: true,
        },
        artifacts: vec![ReleaseArtifact {
            kind: "macos_app".to_string(),
            platform: "macos".to_string(),
            arch: "universal".to_string(),
            url: "https://install.ottto.net/ottto-local-platform/releases/dev/latest/Ottto-macos-universal.dmg".to_string(),
        }],
    }
}

#[test]
fn release_manifest_deserialization_requires_update_and_rollback_metadata() {
    let mut manifest = json!({
        "schema_version": 1,
        "product": "ottto-local-platform",
        "version": "0.2.0",
        "channel": "dev",
        "commit": "deadbeef",
        "min_supported_version": "0.1.0",
        "min_protocol_version": PROTOCOL_VERSION,
        "supported_install_owners": ["homebrew", "hosted_installer", "app_bundle"],
        "rollback": {
            "strategy": "channel_latest_pointer",
            "immutable_prefix": "https://install.ottto.net/ottto-local-platform/releases/dev/latest",
            "latest_manifest_url": "https://install.ottto.net/ottto-local-platform/releases/dev/latest/release-manifest.json",
            "preserve_failed_version": true
        },
        "artifacts": [{
            "kind": "macos_app",
            "platform": "macos",
            "arch": "universal",
            "url": "https://install.ottto.net/ottto-local-platform/releases/dev/latest/Ottto-macos-universal.dmg"
        }]
    });

    serde_json::from_value::<ReleaseManifest>(manifest.clone()).expect("valid manifest");

    manifest
        .as_object_mut()
        .expect("manifest object")
        .remove("rollback");
    assert!(serde_json::from_value::<ReleaseManifest>(manifest).is_err());
}

#[test]
fn update_state_soft_warns_for_supported_outdated_homebrew_install() {
    let state = update_state_from_manifest(
        release_manifest_for_update("0.2.0", Some("0.1.0"), None),
        "0.1.0".to_string(),
        ReleaseChannel::Dev,
        Some("2026-05-20T00:00:00Z".to_string()),
        Some("deadbeef".to_string()),
        InstallOwner::Homebrew,
    );

    assert_eq!(state.status, UpdateStatus::UpdateAvailable);
    assert_eq!(state.gate, UpdateGate::SoftWarn);
    assert_eq!(state.install_owner, InstallOwner::Homebrew);
    assert_eq!(
        state.release_notes.as_deref(),
        Some("- Fixes sign-in completion.\n- Improves local usage sync reliability.")
    );
    assert_eq!(
        state.update_command.as_deref(),
        Some("brew update && brew upgrade ottto")
    );
    assert!(state
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("newer Ottto app"));
}

#[test]
fn update_state_hard_blocks_below_min_supported_version() {
    let state = update_state_from_manifest(
        release_manifest_for_update("0.2.0", Some("0.1.0"), None),
        "0.0.9".to_string(),
        ReleaseChannel::Dev,
        Some("2026-05-20T00:00:00Z".to_string()),
        Some("deadbeef".to_string()),
        InstallOwner::HostedInstaller,
    );

    assert_eq!(state.status, UpdateStatus::UpdateAvailable);
    assert_eq!(state.gate, UpdateGate::HardBlock);
    assert_eq!(state.install_owner, InstallOwner::HostedInstaller);
    assert_eq!(
        state.update_command.as_deref(),
        Some("curl -fsSL https://ottto.net/install.sh | bash")
    );
    assert!(state
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("minimum supported version"));
}

#[test]
fn install_owner_detection_routes_known_install_paths() {
    assert_eq!(
        install_owner_for_path(Path::new(
            "/opt/homebrew/Cellar/ottto/0.1.0/bin/ottto-service"
        )),
        InstallOwner::Homebrew
    );
    assert_eq!(
        install_owner_for_path(Path::new("/Users/example/.ottto/bin/ottto-service")),
        InstallOwner::HostedInstaller
    );
    assert_eq!(
        install_owner_for_path(Path::new(
            "/Users/example/Applications/Ottto.app/Contents/Helpers/ottto-service"
        )),
        InstallOwner::AppBundle
    );
}

#[test]
fn trusted_companion_can_read_status_without_keychain_token() {
    let response = handle_request_with_peer(
        &daemon(),
        LocalControlRequest {
            request_id: "req_app_status".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: None,
            client_kind: Some(LocalClientKind::CompanionApp),
            client_install_owner: None,
            command: LocalControlCommand::Status {
                refresh_agent_status: false,
                retry_relay_authorization: false,
            },
        },
        Some(LocalClientPeer::trusted_for_tests()),
    );

    assert!(response.ok, "{response:?}");
    assert_eq!(response.error, None);
}

#[test]
fn companion_without_trusted_peer_is_rejected() {
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_app_status".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: None,
            client_kind: Some(LocalClientKind::CompanionApp),
            client_install_owner: None,
            command: LocalControlCommand::Status {
                refresh_agent_status: false,
                retry_relay_authorization: false,
            },
        },
    );

    assert!(!response.ok);
    assert_eq!(
        response.error.expect("error").code,
        CliErrorCode::LocalClientNotTrusted
    );
}

#[test]
fn companion_peer_with_mismatched_euid_is_not_trusted() {
    // The euid gate runs before the PID-based code-signing check, so a peer
    // running as a different uid is rejected regardless of its PID.
    let other = daemon_effective_uid().wrapping_add(1);
    let peer = LocalClientPeer::from_pid_and_euid(Some(std::process::id()), Some(other));
    assert!(!companion_peer_is_trusted(Some(&peer)));
}

#[test]
fn auth_only_command_keeps_trust_and_poisoned_state_refusals() {
    let daemon = daemon();
    let command = || LocalControlCommand::SessionLaunchStatus {
        schema_version: 1,
        launch_id: "synthetic".into(),
    };
    let request = |peer| {
        let request = LocalControlRequest {
            request_id: "auth-only".into(),
            protocol_version: ottto_protocol::SESSION_LAUNCH_CONTROL_PROTOCOL_VERSION,
            token: None,
            client_kind: Some(LocalClientKind::CompanionApp),
            client_install_owner: None,
            command: command(),
        };
        handle_request_with_peer(&daemon, request, peer)
    };
    assert!(request(Some(LocalClientPeer::trusted_for_tests())).ok);
    assert_eq!(
        request(None).error.expect("error").code,
        CliErrorCode::LocalClientNotTrusted
    );

    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _state = daemon.inner.lock().expect("daemon state");
        panic!("poison the daemon state");
    }));
    assert!(poison.is_err());
    let run = |authorization| {
        handle_command(
            &daemon,
            authorization,
            command(),
            InstallOwner::Unknown,
            false,
        )
    };
    // The token check still runs before the poisoned-state refusal.
    assert!(matches!(
        run(RequestAuthorization::Token("wrong-token".into())),
        Err(LocalApiError::Unauthorized)
    ));
    for authorization in [
        RequestAuthorization::Token("token".into()),
        RequestAuthorization::TrustedCompanionApp,
    ] {
        assert!(matches!(
            run(authorization),
            Err(LocalApiError::StatePoisoned)
        ));
    }
}

/// The requirement an internal build resolves to, and the one QA writes
/// into a dev LaunchAgent when pointing a *release* daemon at a locally
/// built Companion. An ad-hoc signature carries no team OU, so only the
/// identifier can be asserted.
#[cfg(target_os = "macos")]
const DEV_ADHOC_COMPANION_REQUIREMENT: &str = "identifier \"net.ottto.Companion\"";

#[cfg(target_os = "macos")]
const TEST_TEAM_ID: &str = "YRNP9UD7WY";

#[cfg(target_os = "macos")]
const RELEASE_SIGNED: bool = true;
#[cfg(target_os = "macos")]
const INTERNAL_BUILD: bool = false;

#[cfg(target_os = "macos")]
#[test]
fn a_release_daemon_requires_a_developer_id_companion() {
    // The production configuration: a signed daemon, no env overrides.
    // Before the requirement was baked in, that combination meant "no
    // requirement at all", and any binary at a trusted path — including the
    // user-writable ~/Applications/Ottto.app — was trusted.
    assert_eq!(
        resolve_companion_code_requirement(None, None, TEST_TEAM_ID, RELEASE_SIGNED),
        CompanionCodeRequirement::Enforced(
            "identifier \"net.ottto.Companion\" and anchor apple generic \
                 and certificate leaf[field.1.2.840.113635.100.6.1.13] \
                 and certificate leaf[subject.OU] = \"YRNP9UD7WY\""
                .to_string()
        )
    );
}

#[cfg(target_os = "macos")]
#[test]
fn every_team_requirement_pins_the_apple_anchor() {
    // `certificate leaf[subject.OU] = "TEAM"` on its own is satisfied by any
    // certificate carrying that OU, self-signed included, and the team id is
    // public. Without the anchor and the Developer ID leaf marker, a
    // same-uid attacker mints a cert with OU=<team>, signs a bundle as
    // net.ottto.Companion, drops it at ~/Applications/Ottto.app, and the
    // "Developer ID" rule passes — the exact hole this change exists to
    // close. Both requirements the daemon can build must carry both clauses.
    for text in [
        companion_team_code_requirement(TEST_TEAM_ID),
        daemon_release_code_requirement(TEST_TEAM_ID),
    ] {
        assert!(
            text.contains("anchor apple generic"),
            "requirement must chain to Apple: {text}"
        );
        assert!(
            text.contains("certificate leaf[field.1.2.840.113635.100.6.1.13]"),
            "requirement must demand a Developer ID leaf: {text}"
        );
        assert!(
            text.contains(&format!(
                "certificate leaf[subject.OU] = \"{TEST_TEAM_ID}\""
            )),
            "requirement must demand our team: {text}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
#[serial]
fn shipped_build_bakes_in_a_companion_team_id() {
    // Guards the actual shipped constant, not just the resolver: a build
    // that loses its baked-in team id would fail closed and grant no
    // token-less companion trust at all.
    //
    // #[serial] because it reads the real process env: it must not observe
    // the override that
    // `companion_code_requirement_reads_its_overrides_from_the_environment`
    // sets mid-test.
    assert!(
        !OTTTO_COMPANION_DEFAULT_TEAM_ID.trim().is_empty(),
        "the default build must bake in the Companion Developer ID team"
    );
    let _requirement = EnvVarGuard::remove("OTTTO_COMPANION_CODE_REQUIREMENT");
    let _team_id = EnvVarGuard::remove("OTTTO_COMPANION_TEAM_ID");
    let expected = if daemon_is_release_signed() {
        companion_team_code_requirement(OTTTO_COMPANION_DEFAULT_TEAM_ID)
    } else {
        companion_identity_code_requirement()
    };
    assert_eq!(
        companion_code_requirement(),
        CompanionCodeRequirement::Enforced(expected),
        "an unconfigured process must enforce a requirement matching its own build kind"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn path_only_companion_trust_is_never_resolved() {
    // There is no input combination that yields "trust the path, skip the
    // signature". Every resolution is either an enforced requirement or a
    // refusal to grant token-less trust.
    let inputs = [
        (None, None, TEST_TEAM_ID, RELEASE_SIGNED),
        (None, None, TEST_TEAM_ID, INTERNAL_BUILD),
        (None, Some("ABCDE12345"), TEST_TEAM_ID, INTERNAL_BUILD),
        (
            Some(DEV_ADHOC_COMPANION_REQUIREMENT),
            None,
            TEST_TEAM_ID,
            RELEASE_SIGNED,
        ),
        (Some("   "), Some("  "), TEST_TEAM_ID, RELEASE_SIGNED),
        (None, Some("ABCDE12345"), "", INTERNAL_BUILD),
    ];
    for (requirement, team_id, default_team_id, release_signed) in inputs {
        assert!(
            matches!(
                resolve_companion_code_requirement(
                    requirement,
                    team_id,
                    default_team_id,
                    release_signed
                ),
                CompanionCodeRequirement::Enforced(_)
            ),
            "expected an enforced requirement for \
                 {requirement:?}/{team_id:?}/{default_team_id:?}/{release_signed}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn companion_trust_is_disabled_when_a_fork_bakes_in_no_team() {
    // `OTTTO_COMPANION_DEFAULT_TEAM_ID=` is an explicit opt-out: fail
    // closed rather than fall back to path-only trust, on either build kind.
    for release_signed in [RELEASE_SIGNED, INTERNAL_BUILD] {
        for (requirement, team_id) in [(None, None), (Some(""), Some("   "))] {
            assert_eq!(
                resolve_companion_code_requirement(requirement, team_id, "", release_signed),
                CompanionCodeRequirement::Disabled
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn requirement_override_wins_on_a_release_daemon() {
    for (requirement, team, release, expected) in [
        (
            Some(DEV_ADHOC_COMPANION_REQUIREMENT),
            Some("ABCDE12345"),
            RELEASE_SIGNED,
            DEV_ADHOC_COMPANION_REQUIREMENT.to_string(),
        ),
        (
            None,
            Some(" ABCDE12345 "),
            RELEASE_SIGNED,
            companion_team_code_requirement("ABCDE12345"),
        ),
        (
            None,
            Some("ABCDE12345"),
            INTERNAL_BUILD,
            companion_team_code_requirement("ABCDE12345"),
        ),
        (
            Some(""),
            Some("\t\n"),
            RELEASE_SIGNED,
            companion_team_code_requirement(TEST_TEAM_ID),
        ),
    ] {
        assert_eq!(
            resolve_companion_code_requirement(requirement, team, TEST_TEAM_ID, release),
            CompanionCodeRequirement::Enforced(expected)
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn companion_requirement_strings_parse_as_code_requirements() {
    // A requirement string that does not parse makes `trusted_companion_pid`
    // reject every peer, so every requirement this daemon can produce must
    // be valid csreq syntax.
    use security_framework::os::macos::code_signing::SecRequirement;

    for text in [
        companion_team_code_requirement(OTTTO_COMPANION_DEFAULT_TEAM_ID),
        companion_identity_code_requirement(),
        daemon_release_code_requirement(OTTTO_COMPANION_DEFAULT_TEAM_ID),
        DEV_ADHOC_COMPANION_REQUIREMENT.to_string(),
    ] {
        assert!(
            text.parse::<SecRequirement>().is_ok(),
            "requirement should parse: {text}"
        );
    }
}

#[test]
fn uninstall_plan_is_typed_and_cloud_safe() {
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_uninstall_plan".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::UninstallPlan,
        },
    );

    assert!(response.ok, "{response:?}");
    let payload = response.payload.expect("payload");
    assert_eq!(
        payload.get("cloud_credentials_untouched"),
        Some(&serde_json::Value::Bool(true))
    );
    assert_eq!(
        payload.get("requires_confirmation"),
        Some(&serde_json::Value::Bool(true))
    );
}

#[test]
fn uninstall_execute_requires_confirmation() {
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_uninstall_execute".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::UninstallExecute { confirm: false },
        },
    );

    assert!(!response.ok);
    assert_eq!(
        response.error.expect("error").code,
        CliErrorCode::InvalidRequest
    );
}

/// Seed the private record directory with codec bytes, so both diagnostic
/// paths must exclude stored literals rather than merely redact a Debug.
fn seed_private_literal_canary(support: &Path) -> &'static str {
    const CANARY: &str = "PRIVATE_LITERAL_DIAGNOSTICS_CANARY_20261030";
    let dir =
        crate::snapshots::state_v2::retired_record_dir(&support.join("claude-scan-index.json"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let record = dir.join(format!("{}.rec", "0".repeat(64)));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(record)
        .unwrap();
    file.write_all(CANARY.as_bytes()).unwrap();
    // The support collector must also omit transient replay input,
    // including raw-value magic keys and malformed-selector material.
    std::fs::write(support.join("bounded-replay-private.jsonl"), format!(
        "{{\"$serde_json::private::RawValue\":\"{CANARY}\"}}\n{{\"selector\":{{\"model\":[\"{CANARY}\"]}},\"content\":\"{CANARY}\"}}\n"
    )).unwrap();
    CANARY
}

#[test]
#[serial]
fn diagnostics_collect_is_local_only_without_upload() {
    let _env_lock = lock_backend_test_env();
    let support = crate::test_scratch::ScratchDir::new("pl-diagnostics-export");
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &support.join("secrets"));
    let _keys = EnvVarGuard::set_path(
        TELEMETRY_KEY_FILE_STORE_ENV,
        &support.join("telemetry-keys"),
    );
    let canary = seed_private_literal_canary(&support);
    let _tail_literals = crate::snapshots::seed_tail_literals_for_test(&support, canary);
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_diagnostics_local_only".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::DiagnosticsCollect {
                upload: false,
                upload_approval: None,
                api_base_url: None,
            },
        },
    );

    assert!(response.ok, "{response:?}");
    let payload = response.payload.expect("payload");
    assert!(!serde_json::to_string(&payload).unwrap().contains(canary));
    // The bundle excludes stored session facts.
    for fact in crate::snapshots::TAIL_FACT_LITERALS {
        let literal = format!("{canary}-{fact}");
        assert!(!serde_json::to_string(&payload).unwrap().contains(&literal));
    }
    for private in [
        "PRIVATE_REPLAY_HEAD_CANARY_20261030",
        "PRIVATE_REPLAY_PROMPT_CANARY_20261030",
        "PRIVATE_REPLAY_LABEL_CANARY_20261030",
    ] {
        assert!(!serde_json::to_string(&payload).unwrap().contains(private));
    }
    assert!(payload
        .get("bundle_id")
        .and_then(|value| value.as_str())
        .is_some_and(|bundle_id| bundle_id.starts_with("diag_")));
    let upload = payload.get("upload").expect("upload report");
    assert_eq!(
        upload.get("status").and_then(|value| value.as_str()),
        Some("local_only")
    );
    assert_eq!(
        upload.get("requested").and_then(|value| value.as_bool()),
        Some(false)
    );
}

#[test]
fn diagnostics_upload_requires_explicit_approval() {
    for (upload_approval, message) in [
        (None, "--approve-upload"),
        (
            Some(DiagnosticsUploadApproval {
                approved: true,
                retention_disclosure_accepted: false,
                support_claim: Some("support_123".into()),
            }),
            "--accept-retention-disclosure",
        ),
        (
            Some(DiagnosticsUploadApproval {
                approved: true,
                retention_disclosure_accepted: true,
                support_claim: None,
            }),
            "Ottto login or --support-claim",
        ),
    ] {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_diagnostics_refusal".into(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".into()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::DiagnosticsCollect {
                    upload: true,
                    upload_approval,
                    api_base_url: None,
                },
            },
        );
        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert!(error.message.contains(message));
    }
}

#[test]
#[serial]
fn diagnostics_upload_with_support_claim_posts_redacted_bundle() {
    let _env_lock = lock_backend_test_env();
    let support = crate::test_scratch::ScratchDir::new("pl-support-bundle");
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &support.join("secrets"));
    let _keys = EnvVarGuard::set_path(
        TELEMETRY_KEY_FILE_STORE_ENV,
        &support.join("telemetry-keys"),
    );
    let canary = seed_private_literal_canary(&support);
    let _tail_literals = crate::snapshots::seed_tail_literals_for_test(&support, canary);
    let captured = Arc::new(Mutex::new(None));
    let api_base_url = diagnostics_upload_server(captured.clone());
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_diagnostics_support_upload".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::DiagnosticsCollect {
                upload: true,
                upload_approval: Some(DiagnosticsUploadApproval {
                    approved: true,
                    retention_disclosure_accepted: true,
                    support_claim: Some("support_123".to_string()),
                }),
                api_base_url: Some(api_base_url),
            },
        },
    );

    assert!(response.ok, "{response:?}");
    let payload = response.payload.expect("payload");
    let upload = payload.get("upload").expect("upload report");
    assert_eq!(
        upload.get("status").and_then(|value| value.as_str()),
        Some("uploaded")
    );
    assert_eq!(
        upload.get("authorization").and_then(|value| value.as_str()),
        Some("support_claim")
    );
    assert_eq!(
        upload
            .get("support_claim_provided")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        upload.get("upload_id").and_then(|value| value.as_str()),
        Some("diag_upload_123")
    );
    let payload_json = serde_json::to_string(&payload).expect("payload serializes");
    assert!(!payload_json.contains("support_123"));
    assert!(!payload_json
        .to_ascii_lowercase()
        .contains("x-ottto-support-claim"));

    let request = captured
        .lock()
        .expect("captured request lock")
        .clone()
        .expect("request captured");
    assert!(request.starts_with("POST /api/v1/diagnostics/support-bundles HTTP/1.1"));
    assert!(request
        .to_ascii_lowercase()
        .contains("x-ottto-support-claim: support_123"));
    let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert!(body.contains("\"retention_disclosure_accepted\":true"));
    assert!(body.contains("\"support_claim_provided\":true"));
    assert!(!body.contains("support_123"));
    assert!(!body.contains(canary));
    // The uploaded bundle excludes stored session facts.
    for fact in crate::snapshots::TAIL_FACT_LITERALS {
        let literal = format!("{canary}-{fact}");
        assert!(!body.contains(&literal));
        assert!(!payload_json.contains(&literal));
    }
    for private in [
        "PRIVATE_REPLAY_HEAD_CANARY_20261030",
        "PRIVATE_REPLAY_PROMPT_CANARY_20261030",
        "PRIVATE_REPLAY_LABEL_CANARY_20261030",
    ] {
        assert!(!body.contains(private));
        assert!(!payload_json.contains(private));
    }
    assert!(!payload_json.contains(canary));
}

#[test]
fn diagnostics_upload_no_backend_returns_retryable_backend_error() {
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_diagnostics_no_backend".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::DiagnosticsCollect {
                upload: true,
                upload_approval: Some(DiagnosticsUploadApproval {
                    approved: true,
                    retention_disclosure_accepted: true,
                    support_claim: Some("support_123".to_string()),
                }),
                api_base_url: Some(unused_loopback_base_url()),
            },
        },
    );

    assert!(!response.ok);
    let error = response.error.expect("error");
    assert_eq!(error.code, CliErrorCode::BackendUnreachable);
    assert!(error.retryable);
    match error.details.get("endpoint") {
        Some(RedactedValue::String(endpoint)) => {
            assert!(endpoint.ends_with("/api/v1/diagnostics/support-bundles"))
        }
        other => panic!("expected endpoint detail, got {other:?}"),
    }
}

#[test]
#[serial]
fn telemetry_control_accepts_fresh_enable_request_without_leaking_key() {
    let _guard = lock_backend_test_env();
    let _binding = bind_telemetry_control_account();
    let store_root = telemetry_key_store_root("enable");
    let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
    let install_root = telemetry_key_store_root("enable-install");
    let fake_claude = fake_binary_path(&install_root, "claude");
    let _home_guard = EnvVarGuard::set_path("HOME", &install_root);
    let _path_guard = EnvVarGuard::set_os(
        "OTTTO_COMMAND_SEARCH_PATH",
        fake_claude
            .parent()
            .expect("fake binary parent")
            .as_os_str()
            .to_os_string(),
    );
    // The mock backend serves both the control-token validation (resolved
    // via the trusted OTTTO_API_BASE_URL env) and the OTLP verification
    // marker (via otlp_endpoint). The request `api_base_url` carries a dead
    // loopback URL: if it were still honored for token validation the
    // request would fail, proving the resolver ignores it.
    let api_base_url = control_token_validation_server_with_marker(200);
    let _api_base_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_telemetry_enable".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: None,
            client_kind: Some(LocalClientKind::WebUi),
            client_install_owner: None,
            command: LocalControlCommand::TelemetryControl {
                action: TelemetryControlAction::EnableTelemetry,
                source: SourceKind::ClaudeCode,
                control_token: test_control_token("enable_telemetry", "claude_code", 300),
                api_base_url: Some(ATTACKER_LOOPBACK_API_BASE_URL.to_string()),
                key_id: Some("key_123".to_string()),
                organization_id: Some("org_123".to_string()),
                otlp_endpoint: Some(api_base_url),
                ingest_key: Some(SecretString::new("transit_secret_for_tests")),
            },
        },
    );

    assert!(response.ok, "{response:?}");
    let payload = response.payload.expect("payload");
    assert_eq!(
        payload.get("status").and_then(|value| value.as_str()),
        Some("accepted")
    );
    assert_eq!(
        payload
            .get("requires_restart")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(!payload.to_string().contains("transit_secret_for_tests"));
    assert_eq!(
        payload
            .get("installation")
            .and_then(|value| value.get("installed"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        TelemetryKeyStore::file_only(&store_root)
            .load(&SourceKind::ClaudeCode, "key_123")
            .expect("stored key"),
        "transit_secret_for_tests"
    );
    let config =
        fs::read_to_string(install_root.join(".claude/settings.json")).expect("Claude settings");
    assert!(config.contains("CLAUDE_CODE_ENABLE_TELEMETRY"));
    assert!(config.contains("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"));
    assert!(!config.contains("transit_secret_for_tests"));
    // Telemetry lives in settings.json only: no shell env file or line.
    assert!(!install_root.join(".ottto/claude-telemetry.env").exists());
    assert!(!install_root.join(".zshrc").exists());
}

#[test]
#[serial]
fn claim_completion_reservation_blocks_identity_writers_until_install() {
    let _guard = lock_backend_test_env();
    let files = ControlFilesFixture::new();
    let root = files.root.clone();
    let secret_root = telemetry_key_store_root("claim-reservation-clean-race-secret");
    fs::create_dir_all(&secret_root).unwrap();
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let account = connected_account();
    let old_device = LocalDeviceBinding {
        device_id: "00000000-0000-4000-8000-000000000001".to_string(),
        machine_id: Some("machine_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    FileAccountStore::default().save(&account).unwrap();
    FileDeviceStore::default().save(&old_device).unwrap();
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("otdev_old_claim")
        .unwrap();
    let pending = PendingAuthClaim {
        claim_code: "claim_reserved".to_string(),
        claim_token: "claim_token_reserved".to_string(),
        nonce: "nonce_reserved".to_string(),
        claim_url: "https://ottto.net/setup/claim?code=claim_reserved".to_string(),
        expires_at: "2030-01-01T00:00:00Z".to_string(),
    };
    let daemon = Arc::new(daemon().with_account(account.clone()));
    daemon.begin_auth_with_claim(pending.clone()).unwrap();
    let (claim_api, request_seen, allow_response) = controlled_claim_completion_server();
    let _claim_api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &claim_api);
    let worker_daemon = Arc::clone(&daemon);
    let worker_pending = pending.clone();
    let worker = thread::spawn(move || {
        complete_pending_auth_claim(worker_daemon.as_ref(), &test_machine(), worker_pending)
    });
    request_seen
        .recv_timeout(Duration::from_secs(2))
        .expect("claim completion reached controlled backend");
    assert_ne!(IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire), 0);
    assert!(matches!(
        reset_local_account_files(),
        Err(LocalApiError::IdentityMutationInProgress)
    ));
    assert!(matches!(
        save_relay_device_binding(&LocalDeviceBinding {
            device_id: "device_competing_writer".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string()],
        }),
        Err(LocalApiError::IdentityMutationInProgress)
    ));
    assert!(matches!(
        reserve_identity_mutation(),
        Err(LocalApiError::IdentityMutationInProgress)
    ));
    assert_eq!(
        FileDeviceStore::default().load().unwrap(),
        Some(old_device.clone())
    );
    {
        let base = control_token_validation_server_with_claims(
            200,
            json!({"user_id":"user_test", "organization_id":"org_test"}).to_string(),
        );
        let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &base);
        let result = files.assert_unchanged(|| {
            telemetry_control(
                daemon.as_ref(),
                TelemetryControlAction::DisableTelemetry,
                SourceKind::Codex,
                test_control_token("disable_telemetry", "codex", 300),
                None,
                Some("key_local".into()),
                None,
                None,
                None,
            )
        });
        assert!(matches!(
            result,
            Err(LocalApiError::IdentityMutationInProgress)
        ));
    }

    allow_response.send(()).unwrap();
    let completed = worker
        .join()
        .unwrap()
        .expect("claim installs after release");
    assert_eq!(completed.account.user.unwrap().id, "user_test");
    assert_eq!(
        FileDeviceStore::default()
            .load()
            .unwrap()
            .unwrap()
            .device_id,
        "device_reserved_claim"
    );
    assert_eq!(IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire), 0);
}

#[test]
#[serial]
fn identity_mutation_reservation_clears_after_panic() {
    let _guard = lock_backend_test_env();
    let root = telemetry_key_store_root("identity-reservation-panic");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);

    let panic_result = std::panic::catch_unwind(|| {
        let _reservation = reserve_identity_mutation().unwrap();
        panic!("exercise reservation RAII cleanup");
    });
    assert!(panic_result.is_err());
    assert_eq!(IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire), 0);

    let reservation = reserve_identity_mutation().unwrap();
    assert_ne!(IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire), 0);
    drop(reservation);
    assert_eq!(IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire), 0);
}

fn provider_daily_reference_backend_grant(
    local: &crate::provider_daily_reference::DailyReferenceGrant,
    device_id: &str,
    status: &str,
    grant_version: u64,
) -> ProviderDailyReferenceBackendGrantResponseV1 {
    ProviderDailyReferenceBackendGrantResponseV1 {
        id: "00000000-0000-4000-8000-000000000002".to_string(),
        installation_id: device_id.to_string(),
        source: crate::provider_daily_reference::SOURCE.to_string(),
        collector_id: crate::provider_daily_reference::COLLECTOR_ID.to_string(),
        schema_version: crate::provider_daily_reference::SCHEMA_VERSION.to_string(),
        collector_version: compiled_release_version(),
        release_lane: crate::provider_daily_reference::RELEASE_LANE.to_string(),
        disclosure_version: crate::provider_daily_reference::DISCLOSURE_VERSION.to_string(),
        grant_scope_fingerprint: local.grant_scope_fingerprint.clone(),
        account_fingerprint: local.account_fingerprint.clone(),
        status: status.to_string(),
        grant_version,
        server_policy_state: ottto_protocol::ProviderDailyReferenceServerPolicyState::Approved,
    }
}

thread_local! {
    static DAILY_REFERENCE_STATUS_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn before_daily_reference_status() {
    let hook = DAILY_REFERENCE_STATUS_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

fn assert_daily_reference_status_keeps_binding(
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
    grants: &crate::provider_daily_reference::GrantStore,
    token_uses: &crate::cloud_sessions::CloudSessionControlTokenUseStore,
    device_id: &str,
) {
    struct ResetStatusHook;
    impl Drop for ResetStatusHook {
        fn drop(&mut self) {
            DAILY_REFERENCE_STATUS_HOOK.with(|slot| {
                let _ = slot.borrow_mut().take();
            });
        }
    }
    let _hook_reset = ResetStatusHook;
    let expected = crate::provider_daily_reference::status_with_live_binding(
        grants,
        crate::provider_daily_reference::collector_status(grants, false),
        Some(device_id),
    );
    assert_eq!(
        expected.runtime_state,
        crate::provider_daily_reference::RuntimeState::Enabled
    );
    let writer = Arc::new(Mutex::new(None));
    let blocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_slot = Arc::clone(&writer);
    let observed_block = Arc::clone(&blocked);
    let switched_accounts = accounts.clone();
    let switched_devices = devices.clone();
    let switched_grants = grants.clone();
    DAILY_REFERENCE_STATUS_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            let (send, receive) = mpsc::channel();
            let worker = thread::spawn(move || {
                let immediate = try_lock_setup_run_binding();
                send.send(immediate.is_none()).unwrap();
                let _binding_lock = immediate.unwrap_or_else(lock_setup_run_binding);
                let mut account = connected_account();
                account.user.as_mut().unwrap().id = "user_next".into();
                account.organization.as_mut().unwrap().id = "org_next".into();
                switched_accounts.save(&account).unwrap();
                switched_devices
                    .save(&LocalDeviceBinding {
                        device_id: "device_next".into(),
                        machine_id: None,
                        sources: vec!["codex".into()],
                    })
                    .unwrap();
                switched_grants
                    .revoke(time::OffsetDateTime::now_utc())
                    .unwrap();
            });
            let waited = receive
                .recv_timeout(Duration::from_secs(5))
                .expect("binding writer reached status boundary");
            observed_block.store(waited, Ordering::SeqCst);
            if waited {
                *writer_slot.lock().unwrap() = Some(worker);
            } else {
                worker.join().unwrap();
            }
        }));
    });
    let action = ProviderDailyReferenceControlAction::Status;
    let slug = provider_daily_reference_action_slug(&action);
    let base = cloud_control_validation_server(slug, "pdr-status-binding", device_id);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &base);
    let response = provider_daily_reference_control_with_stores(
        action,
        SecretString::new(test_control_token(slug, "codex", 240)),
        None,
        None,
        None,
        accounts,
        devices,
        grants,
        token_uses,
        &|_| panic!("status must not read a login"),
        false,
    );
    if let Some(worker) = writer.lock().unwrap().take() {
        worker.join().unwrap();
    }
    assert!(
        blocked.load(Ordering::SeqCst),
        "status released the binding before its reads"
    );
    assert_eq!(response.unwrap().status, expected);
    assert_eq!(accounts.load().unwrap().user.unwrap().id, "user_next");
    assert_eq!(devices.load().unwrap().unwrap().device_id, "device_next");
    assert_eq!(
        crate::provider_daily_reference::collector_status(grants, false).runtime_state,
        crate::provider_daily_reference::RuntimeState::Revoked
    );
}

#[test]
#[serial]
fn provider_daily_reference_control_composes_prepare_bind_revoke_and_confirm() {
    let _guard = lock_backend_test_env();
    let root = telemetry_key_store_root("provider-daily-reference-control");
    let accounts = FileAccountStore::new(root.join("account.json"));
    let devices = FileDeviceStore::new(root.join("device.json"));
    let grants = crate::provider_daily_reference::GrantStore::new(root.join("grant.json"));
    let token_path = root.join("control-token-uses.json");
    let token_uses = crate::cloud_sessions::CloudSessionControlTokenUseStore::new(&token_path);
    accounts.save(&connected_account()).unwrap();
    let device_id = "00000000-0000-4000-8000-000000000001";
    devices
        .save(&LocalDeviceBinding {
            device_id: device_id.to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string()],
        })
        .unwrap();

    let run = |action: ProviderDailyReferenceControlAction,
               token_id: &str,
               backend_grant: Option<ProviderDailyReferenceBackendGrantResponseV1>,
               network_disabled: bool| {
        let action_slug = provider_daily_reference_action_slug(&action);
        let api_base = cloud_control_validation_server(action_slug, token_id, device_id);
        let _api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base);
        let expected_account_fingerprint = matches!(
            action,
            ProviderDailyReferenceControlAction::ExcludeCurrentAccount
                | ProviderDailyReferenceControlAction::IncludeCurrentAccount
        )
        .then(|| {
            grants
                .account_fingerprint_for("provider-account-scope")
                .unwrap()
                .unwrap()
        });
        // Only Prepare and the account privacy controls may read a login.
        let reads_login = matches!(
            action,
            ProviderDailyReferenceControlAction::Prepare
                | ProviderDailyReferenceControlAction::ExcludeCurrentAccount
                | ProviderDailyReferenceControlAction::IncludeCurrentAccount
        );
        let account_scope = move |prepare_fallback: bool| {
            assert!(reads_login, "this action must not read a Codex login");
            assert_eq!(
                prepare_fallback,
                matches!(action_slug, "prepare_provider_daily_reference")
            );
            Some("provider-account-scope".to_string())
        };
        provider_daily_reference_control_with_stores(
            action,
            SecretString::new(test_control_token(action_slug, "codex", 240)),
            // An attacker-supplied base url never wins over the trusted one.
            Some(ATTACKER_LOOPBACK_API_BASE_URL.to_string()),
            backend_grant,
            expected_account_fingerprint,
            &accounts,
            &devices,
            &grants,
            &token_uses,
            &account_scope,
            network_disabled,
        )
    };

    let prepared = run(
        ProviderDailyReferenceControlAction::Prepare,
        "pdr-control-prepare",
        None,
        false,
    )
    .unwrap();
    let create = prepared.backend_create_request.clone().unwrap();
    assert_eq!(create.installation_id, device_id);
    assert_eq!(create.source, crate::provider_daily_reference::SOURCE);
    assert_eq!(
        create.collector_id,
        crate::provider_daily_reference::COLLECTOR_ID
    );
    assert_eq!(
        create.schema_version,
        crate::provider_daily_reference::SCHEMA_VERSION
    );
    assert_eq!(
        create.disclosure_version,
        crate::provider_daily_reference::DISCLOSURE_VERSION
    );
    assert_eq!(create.collector_version, compiled_release_version());
    assert!(create.consent);
    assert_eq!(
        prepared.status.runtime_state,
        crate::provider_daily_reference::RuntimeState::ConsentRequired
    );
    assert_eq!(
        prepared.status.reason_code,
        "backend_grant_reconciliation_required"
    );
    assert!(!prepared.status.provider_read_permitted);

    // A lost Prepare response: authenticated Status hands the same create
    // request back so the browser retries the idempotent POST.
    let recovered = run(
        ProviderDailyReferenceControlAction::Status,
        "pdr-control-status-pending",
        None,
        false,
    )
    .unwrap();
    assert_eq!(recovered.backend_create_request, Some(create));

    let local = grants.load().unwrap().unwrap();
    let bound = run(
        ProviderDailyReferenceControlAction::Bind,
        "pdr-control-bind",
        Some(provider_daily_reference_backend_grant(
            &local, device_id, "enabled", 1,
        )),
        false,
    )
    .unwrap();
    assert_eq!(
        bound.status.runtime_state,
        crate::provider_daily_reference::RuntimeState::Enabled
    );
    // No tick has discovered logins under the new binding yet.
    assert_eq!(bound.status.reason_code, "discovery_pending");
    assert!(bound.status.provider_read_permitted);
    assert!(bound.status.accounts.is_empty());
    assert!(bound.backend_create_request.is_none());

    // Browser status and the privacy mutation must name the same opaque
    // account. If the provider login changes between them, refuse before
    // mutating the newly-current account.
    let live_fingerprint = grants
        .account_fingerprint_for("provider-account-scope")
        .unwrap()
        .unwrap();
    // The collector's latest discovery under this binding: one default
    // home login. Status reads only this file, never a credential.
    fs::write(
        root.join("state.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 2,
            "discovery": {
                "binding": {
                    "grant_id": "00000000-0000-4000-8000-000000000002",
                    "grant_version": 1
                },
                "complete": true,
                "accounts": ["entry-default"],
                "skipped": {},
                "default_home": { "state": "ok", "fingerprint": live_fingerprint }
            },
            "entries": {
                "entry-default": {
                    "schema_version": 2,
                    "identity": "entry-default",
                    "account_fingerprint": live_fingerprint,
                    "home_kind": "default",
                    "binding": {
                        "grant_id": "00000000-0000-4000-8000-000000000002",
                        "grant_version": 1
                    },
                    "last_seen_day": "2026-07-27",
                    "last_reason": "ok"
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let mismatch_action = ProviderDailyReferenceControlAction::ExcludeCurrentAccount;
    let mismatch_slug = provider_daily_reference_action_slug(&mismatch_action);
    let mismatch_api = cloud_control_validation_server(
        mismatch_slug,
        "pdr-control-exclude-account-mismatch",
        device_id,
    );
    let _mismatch_api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &mismatch_api);
    assert!(matches!(
        provider_daily_reference_control_with_stores(
            mismatch_action,
            SecretString::new(test_control_token(mismatch_slug, "codex", 240)),
            None,
            None,
            Some(format!("hmac-sha256:{}", "f".repeat(64))),
            &accounts,
            &devices,
            &grants,
            &token_uses,
            &|_| Some("provider-account-scope".to_string()),
            false,
        ),
        Err(LocalApiError::InvalidRequest(_))
    ));
    assert!(!grants.account_is_excluded(&live_fingerprint).unwrap());

    let excluded = run(
        ProviderDailyReferenceControlAction::ExcludeCurrentAccount,
        "pdr-control-exclude-current",
        None,
        false,
    )
    .unwrap();
    assert_eq!(
        excluded.status.runtime_state,
        crate::provider_daily_reference::RuntimeState::AccountExcluded
    );
    assert_eq!(excluded.status.reason_code, "account_excluded");
    assert!(excluded.status.current_account_excluded);
    assert!(!excluded.status.provider_read_permitted);

    let included = run(
        ProviderDailyReferenceControlAction::IncludeCurrentAccount,
        "pdr-control-include-current",
        None,
        false,
    )
    .unwrap();
    assert_eq!(
        included.status.runtime_state,
        crate::provider_daily_reference::RuntimeState::Enabled
    );
    assert_eq!(included.status.reason_code, "enabled");
    assert!(!included.status.current_account_excluded);
    assert!(included.status.provider_read_permitted);
    assert_eq!(
        included.status.accounts,
        vec![crate::provider_daily_reference::CollectorAccountStatusV1 {
            ordinal: 1,
            home_kind: "default".to_string(),
            reason: "ok".to_string(),
            last_success_at: None,
        }]
    );

    // The local off-switch outranks a live grant in the served status.
    let switched_off = run(
        ProviderDailyReferenceControlAction::Status,
        "pdr-control-status-off",
        None,
        true,
    )
    .unwrap();
    assert_eq!(
        switched_off.status.runtime_state,
        crate::provider_daily_reference::RuntimeState::NetworkDisabled
    );
    assert!(!switched_off.status.provider_read_permitted);

    let revoked = run(
        ProviderDailyReferenceControlAction::Revoke,
        "pdr-control-revoke",
        None,
        false,
    )
    .unwrap();
    assert_eq!(
        revoked.backend_revoke_target.unwrap().grant_id,
        "00000000-0000-4000-8000-000000000002"
    );
    assert_eq!(
        revoked.status.runtime_state,
        crate::provider_daily_reference::RuntimeState::Revoked
    );

    let confirmed = run(
        ProviderDailyReferenceControlAction::ConfirmRevoked,
        "pdr-control-confirm",
        Some(provider_daily_reference_backend_grant(
            &grants.load().unwrap().unwrap(),
            device_id,
            "revoked",
            2,
        )),
        false,
    )
    .unwrap();
    assert_eq!(
        confirmed.status.runtime_state,
        crate::provider_daily_reference::RuntimeState::Revoked
    );
    assert_eq!(confirmed.status.reason_code, "revoked");
    assert!(
        grants
            .load()
            .unwrap()
            .unwrap()
            .backend_binding
            .unwrap()
            .backend_revoked
    );

    // The replay ledger persists digests only.
    let persisted = fs::read_to_string(token_path).unwrap();
    for raw_id in [
        "pdr-control-prepare",
        "pdr-control-status-pending",
        "pdr-control-bind",
        "pdr-control-exclude-current",
        "pdr-control-include-current",
        "pdr-control-status-off",
        "pdr-control-revoke",
        "pdr-control-confirm",
    ] {
        assert!(!persisted.contains(raw_id));
    }
    assert!(!persisted.contains("header."));
    run(
        ProviderDailyReferenceControlAction::Prepare,
        "pdr-status-prepare",
        None,
        false,
    )
    .unwrap();
    let local = grants.load().unwrap().unwrap();
    run(
        ProviderDailyReferenceControlAction::Bind,
        "pdr-status-bind",
        Some(provider_daily_reference_backend_grant(
            &local, device_id, "enabled", 3,
        )),
        false,
    )
    .unwrap();
    assert_daily_reference_status_keeps_binding(
        &accounts,
        &devices,
        &grants,
        &token_uses,
        device_id,
    );
}

#[test]
#[serial]
fn provider_daily_reference_control_refuses_to_create_consent_without_authority() {
    let _guard = lock_backend_test_env();
    let root = telemetry_key_store_root("provider-daily-reference-control-authority");
    let accounts = FileAccountStore::new(root.join("account.json"));
    let devices = FileDeviceStore::new(root.join("device.json"));
    let grants = crate::provider_daily_reference::GrantStore::new(root.join("grant.json"));
    let token_uses = crate::cloud_sessions::CloudSessionControlTokenUseStore::new(
        root.join("control-token-uses.json"),
    );
    accounts.save(&connected_account()).unwrap();
    let device_id = "00000000-0000-4000-8000-000000000001";
    devices
        .save(&LocalDeviceBinding {
            device_id: device_id.to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string()],
        })
        .unwrap();

    let run = |action: ProviderDailyReferenceControlAction,
               token_id: &str,
               backend_grant: Option<ProviderDailyReferenceBackendGrantResponseV1>,
               provider_account_scope: Option<String>| {
        let action_slug = provider_daily_reference_action_slug(&action);
        let api_base = cloud_control_validation_server(action_slug, token_id, device_id);
        let _api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base);
        provider_daily_reference_control_with_stores(
            action,
            SecretString::new(test_control_token(action_slug, "codex", 240)),
            None,
            backend_grant,
            None,
            &accounts,
            &devices,
            &grants,
            &token_uses,
            &move |_| provider_account_scope.clone(),
            false,
        )
    };

    // Consent is taken over a provider account. Without a signed-in Codex
    // account there is nothing to consent about, and none is invented.
    assert!(matches!(
        run(
            ProviderDailyReferenceControlAction::Prepare,
            "pdr-authority-no-provider-account",
            None,
            Some("   ".to_string()),
        ),
        Err(LocalApiError::LocalOperationFailed(_))
    ));
    assert!(grants.load().unwrap().is_none());

    // A backend grant on an action that must not carry one is refused
    // before any local mutation.
    assert!(matches!(
        run(
            ProviderDailyReferenceControlAction::Prepare,
            "pdr-authority-unexpected-grant",
            Some(ProviderDailyReferenceBackendGrantResponseV1 {
                id: "00000000-0000-4000-8000-000000000002".to_string(),
                installation_id: device_id.to_string(),
                source: crate::provider_daily_reference::SOURCE.to_string(),
                collector_id: crate::provider_daily_reference::COLLECTOR_ID.to_string(),
                schema_version: crate::provider_daily_reference::SCHEMA_VERSION.to_string(),
                collector_version: compiled_release_version(),
                release_lane: crate::provider_daily_reference::RELEASE_LANE.to_string(),
                disclosure_version: crate::provider_daily_reference::DISCLOSURE_VERSION.to_string(),
                grant_scope_fingerprint: format!("hmac-sha256:{}", "a".repeat(64)),
                account_fingerprint: format!("hmac-sha256:{}", "b".repeat(64)),
                status: "enabled".to_string(),
                grant_version: 1,
                server_policy_state:
                    ottto_protocol::ProviderDailyReferenceServerPolicyState::Approved,
            }),
            Some("provider-account-scope".to_string()),
        ),
        Err(LocalApiError::InvalidRequest(_))
    ));
    assert!(grants.load().unwrap().is_none());

    // Bind requires one.
    assert!(matches!(
        run(
            ProviderDailyReferenceControlAction::Bind,
            "pdr-authority-missing-grant",
            None,
            Some("provider-account-scope".to_string()),
        ),
        Err(LocalApiError::InvalidRequest(_))
    ));

    // A control token minted for a different action is not this action's.
    let api_base = cloud_control_validation_server(
        "prepare_provider_daily_reference",
        "pdr-authority-wrong-action",
        device_id,
    );
    let _api_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base);
    assert!(matches!(
        provider_daily_reference_control_with_stores(
            ProviderDailyReferenceControlAction::Prepare,
            SecretString::new(test_control_token("prepare_cloud_sessions", "codex", 240)),
            None,
            None,
            None,
            &accounts,
            &devices,
            &grants,
            &token_uses,
            &|_| Some("provider-account-scope".to_string()),
            false,
        ),
        Err(LocalApiError::LocalClientNotTrusted)
    ));
    assert!(grants.load().unwrap().is_none());
}

#[test]
fn verification_marker_body_has_single_magic_metric() {
    let marker = verification_marker_body(
        &SourceKind::Codex,
        Some("77f0dbdf-3b05-47e2-a9cc-23f8d94ffdc4"),
        None,
        "marker_test",
        None,
        None,
    );
    let metrics = marker["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        .as_array()
        .expect("metrics array");
    assert_eq!(metrics.len(), 1);
    assert_eq!(
        metrics[0]["name"].as_str(),
        Some(VERIFICATION_MARKER_METRIC_NAME)
    );
    let data_points = metrics[0]["sum"]["dataPoints"]
        .as_array()
        .expect("data points array");
    assert_eq!(data_points.len(), 1);
    let attrs = data_points[0]["attributes"]
        .as_array()
        .expect("attributes array");
    assert!(attrs.iter().any(|attr| {
        attr["key"].as_str() == Some(VERIFICATION_MARKER_ATTRIBUTE)
            && attr["value"]["boolValue"].as_bool() == Some(true)
    }));
    assert!(!marker.to_string().contains("input_tokens"));
    assert!(!marker.to_string().contains("output_tokens"));
}

#[test]
fn otlp_metrics_url_normalizes_base_or_signal_endpoint() {
    assert_eq!(
        otlp_metrics_url("https://api.ottto.net").expect("base url"),
        "https://api.ottto.net/v1/metrics"
    );
    assert_eq!(
        otlp_metrics_url("https://api.ottto.net/v1").expect("v1 url"),
        "https://api.ottto.net/v1/metrics"
    );
    assert_eq!(
        otlp_metrics_url("https://api.ottto.net/v1/metrics").expect("metrics url"),
        "https://api.ottto.net/v1/metrics"
    );
    assert!(otlp_metrics_url("https://api.ottto.net.evil").is_err());
    assert!(otlp_metrics_url("http://127.0.0.1.evil/v1/metrics").is_err());
    assert!(otlp_metrics_url("https://api.ottto.net@evil.example/v1/metrics").is_err());
}

#[test]
#[serial]
fn telemetry_control_disable_removes_stored_key() {
    let _guard = lock_backend_test_env();
    assert_telemetry_control_requires_local_binding();
    assert_telemetry_control_requires_matching_device_and_key();
    let _binding = bind_telemetry_control_account();
    let store_root = telemetry_key_store_root("disable");
    let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
    let install_root = telemetry_key_store_root("disable-install");
    let _home_guard = EnvVarGuard::set_path("HOME", &install_root);
    let config_path = install_root.join(".codex/config.toml");
    patch_codex_config_at(&config_path, &install_root.join("backups")).expect("seed config");
    let store = TelemetryKeyStore::file_only(&store_root);
    store
        .save(
            &SourceKind::Codex,
            "key_disable",
            "transit_secret_for_tests",
        )
        .expect("seed key");

    // SECURITY: the control token must be validated against the trusted
    // env-resolved backend, not the request-supplied `api_base_url`. The
    // working mock backend is wired through OTTTO_API_BASE_URL, while the
    // request carries a dead loopback URL that would fail validation if it
    // were (insecurely) honored.
    let api_base_url = control_token_validation_server_with_claims(
        200,
        json!({"user_id":"user_123", "organization_id":"org_123",
            "device_id":"device_local", "key_id":"key_disable"})
        .to_string(),
    );
    let _api_base_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_telemetry_disable".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: None,
            client_kind: Some(LocalClientKind::WebUi),
            client_install_owner: None,
            command: LocalControlCommand::TelemetryControl {
                action: TelemetryControlAction::DisableTelemetry,
                source: SourceKind::Codex,
                control_token: test_control_token("disable_telemetry", "codex", 300),
                api_base_url: Some(ATTACKER_LOOPBACK_API_BASE_URL.to_string()),
                key_id: Some("key_disable".to_string()),
                organization_id: None,
                otlp_endpoint: None,
                ingest_key: None,
            },
        },
    );

    assert!(response.ok, "{response:?}");
    let payload = response.payload.expect("payload");
    assert_eq!(
        payload
            .get("requires_restart")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(matches!(
        store.load(&SourceKind::Codex, "key_disable"),
        Err(TelemetryKeychainError::Missing)
    ));
    let config = fs::read_to_string(config_path).expect("read config");
    assert!(!config.contains("# ottto:start"));
    assert!(!config.contains("# ottto:end"));
    assert!(!codex_config_has_relay_otel(&config));
}

fn assert_telemetry_control_requires_local_binding() {
    for (user, organization, bound, matches_binding) in [
        (Some("user_123"), Some("org_other"), true, false),
        (Some("user_other"), Some("org_123"), true, false),
        (Some("user_123"), Some("org_123"), false, false),
        (None, Some("org_123"), true, false),
        (Some("user_123"), None, true, false),
        (Some(""), Some("org_123"), true, false),
        (Some(" \t"), Some("org_123"), true, false),
        (Some("user_123"), Some(""), true, false),
        (Some("user_123"), Some(" \t"), true, false),
        (Some("user_123"), Some("org_123"), true, true),
    ] {
        for (source, action) in [
            (SourceKind::Codex, TelemetryControlAction::DisableTelemetry),
            (SourceKind::Codex, TelemetryControlAction::Status),
            (
                SourceKind::ClaudeCode,
                TelemetryControlAction::EnableTelemetry,
            ),
            (
                SourceKind::ClaudeCode,
                TelemetryControlAction::DisableTelemetry,
            ),
            (SourceKind::ClaudeCode, TelemetryControlAction::Status),
        ] {
            for reserved in [false, true] {
                let files = ControlFilesFixture::new();
                TelemetryKeyStore::production()
                    .save(&SourceKind::ClaudeCode, "key_local", "synthetic-key")
                    .unwrap();
                let mut account = connected_account();
                account.user.as_mut().unwrap().id = "user_123".into();
                account.organization.as_mut().unwrap().id = "org_123".into();
                if bound {
                    FileAccountStore::default().save(&account).unwrap();
                }
                FileDeviceStore::default()
                    .save(&LocalDeviceBinding {
                        device_id: "device_local".into(),
                        machine_id: Some("machine_test".into()),
                        sources: vec![],
                    })
                    .unwrap();
                let _reservation = reserved.then(|| reserve_identity_mutation().unwrap());
                let allowed = matches_binding && !reserved;
                let enable = action == TelemetryControlAction::EnableTelemetry;
                let base = if allowed && enable {
                    control_token_validation_server_with_marker(200)
                } else {
                    control_token_validation_server_with_claims(
                        200,
                        json!({"user_id":user,"organization_id":organization,
                            "device_id":"device_local","key_id":"key_local"})
                        .to_string(),
                    )
                };
                let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &base);
                let detections = std::cell::Cell::new(0);
                let detector = |source: &SourceKind| {
                    assert!(allowed, "refused control reached installation detection");
                    detections.set(detections.get() + 1);
                    AgentInstallationDetection {
                        source: source.clone(),
                        installed: true,
                        version: None,
                        config_path: None,
                        binary_path: None,
                        install_docs_url: None,
                    }
                };
                let daemon = daemon();
                let run = || {
                    telemetry_control_with_detector(
                        &daemon,
                        action.clone(),
                        source.clone(),
                        test_control_token(action_slug(&action), source_slug(&source), 300),
                        None,
                        Some("key_local".into()),
                        enable.then(|| "org_123".into()),
                        enable.then(|| base.clone()),
                        enable.then(|| SecretString::new("synthetic-key")),
                        &detector,
                    )
                };
                if allowed {
                    run().expect("matching unreserved local binding");
                    assert_eq!(
                        detections.get(),
                        usize::from(action != TelemetryControlAction::DisableTelemetry)
                    );
                    if action == TelemetryControlAction::DisableTelemetry {
                        assert!(matches!(
                            TelemetryKeyStore::production().load(&source, "key_local"),
                            Err(TelemetryKeychainError::Missing)
                        ));
                    }
                } else {
                    let result = files.assert_unchanged(run);
                    assert_eq!(detections.get(), 0);
                    if reserved {
                        assert!(matches!(
                            result,
                            Err(LocalApiError::IdentityMutationInProgress)
                        ));
                    } else {
                        assert!(matches!(result, Err(LocalApiError::LocalClientNotTrusted)));
                    }
                    let state = daemon.inner.lock().unwrap();
                    assert!(state.sources.is_empty());
                    assert!(state.local_health_events.is_empty());
                    assert!(state.command_ledger.is_empty());
                }
            }
        }
    }
}

fn assert_telemetry_control_requires_matching_device_and_key() {
    const UNREADABLE_DEVICE: &str = "<unreadable device file>";
    let device = Some("device_local");
    let key = Some("key_local");
    for (claim_device, local_device, request_key, claim_key, allowed) in [
        (device, device, key, key, true),
        (device, device, None, None, true),
        (Some("device_other"), device, key, key, false),
        (None, device, key, key, false),
        (Some(""), device, key, key, false),
        (Some(" \t"), device, key, key, false),
        (device, None, key, key, false),
        (None, None, None, None, false),
        (device, Some(""), key, key, false),
        (device, device, key, Some("key_other"), false),
        (device, device, key, None, false),
        (device, device, None, key, false),
        (device, device, None, Some(""), false),
        (device, device, None, Some(" \t"), false),
        (device, device, key, Some(" key_local "), false),
        (device, Some(UNREADABLE_DEVICE), key, key, false),
    ] {
        for source in [SourceKind::Codex, SourceKind::ClaudeCode] {
            for action in [
                TelemetryControlAction::Status,
                TelemetryControlAction::DisableTelemetry,
            ] {
                let files = bind_telemetry_control_account();
                let devices = FileDeviceStore::default();
                devices.reset().unwrap();
                if local_device == Some(UNREADABLE_DEVICE) {
                    fs::create_dir_all(devices.path().parent().unwrap()).unwrap();
                    fs::write(devices.path(), b"{not json").unwrap();
                } else if let Some(device_id) = local_device {
                    devices
                        .save(&LocalDeviceBinding {
                            device_id: device_id.into(),
                            machine_id: Some("machine_test".into()),
                            sources: vec![],
                        })
                        .unwrap();
                }
                TelemetryKeyStore::production()
                    .save(&SourceKind::ClaudeCode, "key_local", "synthetic-key")
                    .unwrap();
                patch_claude_code_settings_at(
                    &files.root.join(".claude/settings.json"),
                    &test_machine(),
                    &files.root.join("backups"),
                )
                .unwrap();
                let base = control_token_validation_server_with_claims(
                    200,
                    json!({"user_id":"user_123", "organization_id":"org_123",
                        "device_id":claim_device, "key_id":claim_key})
                    .to_string(),
                );
                let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &base);
                let daemon = daemon();
                let detections = std::cell::Cell::new(0);
                let detector = |source: &SourceKind| {
                    assert!(allowed, "refused control reached installation detection");
                    detections.set(detections.get() + 1);
                    AgentInstallationDetection {
                        source: source.clone(),
                        installed: true,
                        version: None,
                        config_path: None,
                        binary_path: None,
                        install_docs_url: None,
                    }
                };
                let run = || {
                    telemetry_control_with_detector(
                        &daemon,
                        action.clone(),
                        source.clone(),
                        test_control_token(action_slug(&action), source_slug(&source), 300),
                        None,
                        request_key.map(str::to_string),
                        None,
                        None,
                        None,
                        &detector,
                    )
                };
                if allowed {
                    let result = run().expect("matching device and key");
                    assert_eq!(result.status, ControlResultStatus::Accepted);
                    assert_eq!(
                        detections.get(),
                        usize::from(action == TelemetryControlAction::Status)
                    );
                    let key = TelemetryKeyStore::production().load(&source, "key_local");
                    if action == TelemetryControlAction::DisableTelemetry && request_key.is_some() {
                        assert!(matches!(key, Err(TelemetryKeychainError::Missing)));
                    } else {
                        assert_eq!(key.unwrap(), "synthetic-key");
                    }
                } else {
                    let result = files.assert_unchanged(run);
                    assert!(matches!(result, Err(LocalApiError::LocalClientNotTrusted)));
                    assert_eq!(detections.get(), 0);
                    let state = daemon.inner.lock().unwrap();
                    assert!(state.sources.is_empty());
                    assert!(state.local_health_events.is_empty());
                    assert!(state.command_ledger.is_empty());
                }
            }
        }
    }
}

#[test]
#[serial]
fn telemetry_control_disable_preserves_key_when_fence_needs_review() {
    let _guard = lock_backend_test_env();
    let _binding = bind_telemetry_control_account();
    let store_root = telemetry_key_store_root("disable-manual-fence");
    let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
    let install_root = telemetry_key_store_root("disable-manual-fence-install");
    let _home_guard = EnvVarGuard::set_path("HOME", &install_root);
    let config_path = install_root.join(".codex/config.toml");
    patch_codex_config_at(&config_path, &install_root.join("backups")).expect("seed config");
    let config = fs::read_to_string(&config_path).expect("read seeded config");
    fs::write(&config_path, config.replace("# ottto:end", "")).expect("mangle managed fence");
    let store = TelemetryKeyStore::file_only(&store_root);
    store
        .save(
            &SourceKind::Codex,
            "key_manual_fence",
            "transit_secret_for_tests",
        )
        .expect("seed key");

    let api_base_url = control_token_validation_server_with_claims(
        200,
        json!({"user_id":"user_123", "organization_id":"org_123",
            "device_id":"device_local", "key_id":"key_manual_fence"})
        .to_string(),
    );
    let _api_base_guard = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_telemetry_disable_manual_fence".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: None,
            client_kind: Some(LocalClientKind::WebUi),
            client_install_owner: None,
            command: LocalControlCommand::TelemetryControl {
                action: TelemetryControlAction::DisableTelemetry,
                source: SourceKind::Codex,
                control_token: test_control_token("disable_telemetry", "codex", 300),
                api_base_url: Some(ATTACKER_LOOPBACK_API_BASE_URL.to_string()),
                key_id: Some("key_manual_fence".to_string()),
                organization_id: None,
                otlp_endpoint: None,
                ingest_key: None,
            },
        },
    );

    assert!(!response.ok, "{response:?}");
    let error = response.error.expect("error");
    assert_eq!(error.code, CliErrorCode::ManualFenceReviewRequired);
    assert_eq!(
        error.message,
        "Ottto left the configuration unchanged. Review the Ottto telemetry entries and fence markers in the source config, then retry."
    );
    assert!(!error.retryable);
    assert!(store.load(&SourceKind::Codex, "key_manual_fence").is_ok());
    let config = fs::read_to_string(config_path).expect("read config");
    assert!(config.contains("# ottto:start"));
    assert!(!config.contains("# ottto:end"));
}

#[test]
#[serial]
fn uninstall_sweep_removes_indexed_telemetry_keys() {
    let _guard = lock_backend_test_env();
    let store_root = telemetry_key_store_root("uninstall");
    let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
    let store = TelemetryKeyStore::file_only(&store_root);
    store
        .save(
            &SourceKind::ClaudeCode,
            "key_uninstall",
            "transit_secret_for_tests",
        )
        .expect("seed key");
    let mut result = UninstallExecutionResult {
        status: "uninstalled".to_string(),
        plan: plan_local_uninstall(Path::new("/Users/test")),
        credential_status: "removed_or_absent".to_string(),
        removed_paths: Vec::new(),
        missing_paths: Vec::new(),
        warnings: Vec::new(),
        failed_operations: Vec::new(),
        cloud_credentials_untouched: true,
    };

    sweep_telemetry_keys_for_uninstall(&mut result);

    assert_eq!(result.status, "uninstalled");
    assert!(result.failed_operations.is_empty());
    assert!(result
        .removed_paths
        .contains(&"keychain://ottto-telemetry-key-claude_code/key_uninstall".to_string()));
    assert!(matches!(
        store.load(&SourceKind::ClaudeCode, "key_uninstall"),
        Err(TelemetryKeychainError::Missing)
    ));
}

#[test]
fn telemetry_control_rejects_stale_token() {
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_telemetry_stale".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: None,
            client_kind: Some(LocalClientKind::WebUi),
            client_install_owner: None,
            command: LocalControlCommand::TelemetryControl {
                action: TelemetryControlAction::Status,
                source: SourceKind::Codex,
                control_token: test_control_token("status", "codex", -30),
                api_base_url: None,
                key_id: None,
                organization_id: None,
                otlp_endpoint: None,
                ingest_key: None,
            },
        },
    );

    assert!(!response.ok);
    assert_eq!(
        response.error.expect("error").code,
        CliErrorCode::LocalClientNotTrusted
    );
}

#[test]
fn telemetry_control_rejects_mismatched_action_token() {
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_telemetry_mismatch".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: None,
            client_kind: Some(LocalClientKind::WebUi),
            client_install_owner: None,
            command: LocalControlCommand::TelemetryControl {
                action: TelemetryControlAction::DisableTelemetry,
                source: SourceKind::Codex,
                control_token: test_control_token("enable_telemetry", "codex", 300),
                api_base_url: None,
                key_id: Some("key_123".to_string()),
                organization_id: None,
                otlp_endpoint: None,
                ingest_key: None,
            },
        },
    );

    assert!(!response.ok);
    assert_eq!(
        response.error.expect("error").code,
        CliErrorCode::LocalClientNotTrusted
    );
}

#[test]
#[serial]
fn smoke_commands_keep_source_specific_flags_and_provider_environment() {
    for (command, persists) in [
        (claude_smoke_command(), false),
        (pi_smoke_command_with_version(None, None), true),
    ] {
        assert_eq!(
            command
                .args
                .iter()
                .any(|arg| arg == "--no-session-persistence"),
            !persists,
            "{} smoke persistence flag",
            command.program
        );
    }

    let root = control_test_root("pi-smoke-provider-env");
    let fake_pi = fake_binary_path(&root, "pi");
    fs::write(
        &fake_pi,
        "#!/bin/sh\n[ \"$GEMINI_API_KEY\" = ottto-test-key ] || { echo missing provider env >&2; exit 42; }\necho ok\n",
    )
    .expect("write fake pi");
    #[cfg(unix)]
    fs::set_permissions(&fake_pi, fs::Permissions::from_mode(0o755))
        .expect("mark fake pi executable");
    let _search_guard = EnvVarGuard::set_os(
        "OTTTO_COMMAND_SEARCH_PATH",
        fake_pi
            .parent()
            .expect("fake pi parent")
            .as_os_str()
            .to_os_string(),
    );
    let _provider_guard = EnvVarGuard::set_str("GEMINI_API_KEY", "ottto-test-key");

    let result = run_bounded_command("pi", &[], Duration::from_secs(5), "Pi");

    assert!(
        result.succeeded,
        "message={} diagnostic={:?} exit={:?}",
        result.message, result.diagnostic, result.exit_status
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn pi_smoke_session_ids_are_version_gated_for_default_and_route_commands() {
    // The user's own default thinking level never reaches the check.
    let mut live_route = live_pi_route();
    live_route.thinking_level = Some("xhigh".to_string());
    for route in [None, Some(&live_route)] {
        let mut expected = [
            "--no-builtin-tools",
            "--no-context-files",
            "--print",
            "--thinking",
            "off",
        ]
        .map(str::to_string)
        .to_vec();
        if let Some(route) = route {
            expected.extend([
                "--provider".to_string(),
                route.provider.clone(),
                "--model".to_string(),
                route.model.clone(),
            ]);
        }
        expected.push(SMOKE_PROMPT.to_string());
        for version in [
            None,
            Some("0.75.9"),
            Some("unknown"),
            Some("0.76.bad"),
            Some("0.76.0.1"),
            Some("0.76.0-beta"),
            Some("0.76.0-beta.1"),
            Some("0.76"),
            Some("pi 0.76.0"),
        ] {
            assert_eq!(pi_smoke_command_with_version(route, version).args, expected);
        }
        for version in ["0.76.0", "0.86.0", "1.0.0"] {
            let mut previous = String::new();
            for _ in 0..2 {
                let mut args = pi_smoke_command_with_version(route, Some(version)).args;
                let flag = args.iter().position(|arg| arg == "--session-id").unwrap();
                assert_eq!(flag, args.len() - 3);
                let id = args.remove(flag + 1);
                args.remove(flag);
                assert_eq!(args, expected);
                assert!(crate::internal_session::is_internal_session_id(&id));
                assert_ne!(id, previous);
                previous = id;
            }
        }
    }
}

#[test]
#[serial]
fn pi_verification_refreshes_and_repopulates_shell_cache() {
    let root = control_test_root("pi-verify-shell-cache");
    let fake_pi = fake_binary_path(&root, "pi");
    fs::write(
        &fake_pi,
        "#!/bin/sh\n[ \"$GOOGLE_CLOUD_PROJECT\" = refreshed ]\n",
    )
    .expect("fake pi");
    fs::set_permissions(&fake_pi, fs::Permissions::from_mode(0o755)).unwrap();
    let _search = EnvVarGuard::set_path("OTTTO_COMMAND_SEARCH_PATH", fake_pi.parent().unwrap());
    let _project = EnvVarGuard::remove("GOOGLE_CLOUD_PROJECT");
    let (_, imports) = crate::command_env::test_shell_env::with_output(
        Some(b"GOOGLE_CLOUD_PROJECT=old\n"),
        || {
            let start = Instant::now();
            crate::command_env::test_shell_env::set_now(start);
            assert_eq!(
                crate::command_env::provider_env()["GOOGLE_CLOUD_PROJECT"],
                "old"
            );
            crate::command_env::test_shell_env::set_now(start + Duration::from_secs(1));
            crate::command_env::test_shell_env::set_output(Some(
                b"GOOGLE_CLOUD_PROJECT=refreshed\n",
            ));
            assert!(run_bounded_command("pi", &[], Duration::from_secs(5), "Pi").succeeded);
            crate::command_env::test_shell_env::set_output(None);
            assert_eq!(
                crate::command_env::provider_env()["GOOGLE_CLOUD_PROJECT"],
                "refreshed"
            );
        },
    );
    assert_eq!(imports, 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn pi_smoke_timeout_does_not_wait_on_inherited_pipe() {
    let root = control_test_root("pi-smoke-held-pipe");
    let fake_pi = fake_binary_path(&root, "pi");
    fs::write(&fake_pi, "#!/bin/sh\n(sh -c 'sleep 2') &\nsleep 30\n").expect("write fake pi");
    #[cfg(unix)]
    fs::set_permissions(&fake_pi, fs::Permissions::from_mode(0o755))
        .expect("mark fake pi executable");
    let _search_guard = EnvVarGuard::set_os(
        "OTTTO_COMMAND_SEARCH_PATH",
        fake_pi
            .parent()
            .expect("fake pi parent")
            .as_os_str()
            .to_os_string(),
    );

    let started = Instant::now();
    let result = run_bounded_command("pi", &[], Duration::from_millis(200), "Pi");

    assert!(
        !result.succeeded,
        "message={} diagnostic={:?} exit={:?}",
        result.message, result.diagnostic, result.exit_status
    );
    assert!(
        matches!(
            result.error_code.as_deref(),
            Some("smoke_timeout") | Some("smoke_command_failed")
        ),
        "unexpected error_code={:?}",
        result.error_code
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "timeout path must not block on a descendant-held stdout pipe"
    );
    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
#[serial]
fn live_pi_first_use_establishes_held_empty_census_before_smoke() {
    let root = control_test_root("pi-live-first-use");
    let home = root.join("home");
    create_control_test_dir(&home);
    let fake_pi = fake_binary_path(&root, "pi");
    fs::write(
        &fake_pi,
        "#!/bin/sh\nprintf '{}\\n' > \"$HOME/.pi/agent/sessions/first.jsonl\"\n",
    )
    .expect("write first-use Pi smoke");
    fs::set_permissions(&fake_pi, fs::Permissions::from_mode(0o755))
        .expect("mark fake Pi executable");
    let _home_guard = EnvVarGuard::set_path("HOME", &home);
    let _search_guard = EnvVarGuard::set_os(
        "OTTTO_COMMAND_SEARCH_PATH",
        fake_pi
            .parent()
            .expect("fake Pi parent")
            .as_os_str()
            .to_os_string(),
    );

    let (before, _, smoke) = match run_pi_route_pre_smoke(&live_pi_route()) {
        Ok(ready) => ready,
        Err(failed) => panic!("first-use pre-smoke failed: {}", failed.message.text),
    };

    assert!(before.files.is_empty(), "baseline must precede the smoke");
    assert!(smoke.succeeded, "fake Pi smoke failed: {}", smoke.message);
    let selected = new_pi_route_session_files(&before).expect("select first-use transcript");
    assert_eq!(selected, vec![home.join(".pi/agent/sessions/first.jsonl")]);
    for path in [
        home.join(".pi"),
        home.join(".pi/agent"),
        home.join(".pi/agent/sessions"),
    ] {
        let mode = fs::metadata(path)
            .expect("created Pi directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "new Pi directories must be owner-only");
    }
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
#[serial]
fn live_pi_verify_makes_no_retired_import_request_and_settles_local_only() {
    let root = control_test_root("pi-live-no-retired-import");
    let home = root.join("home");
    create_control_test_dir(&home);
    let fake_pi = fake_binary_path(&root, "pi");
    fs::write(
        &fake_pi,
        "#!/bin/sh\nprintf '{}\\n' > \"$HOME/.pi/agent/sessions/smoke.jsonl\"\n",
    )
    .expect("write Pi smoke");
    fs::set_permissions(&fake_pi, fs::Permissions::from_mode(0o755))
        .expect("mark fake Pi executable");
    let _home_guard = EnvVarGuard::set_path("HOME", &home);
    let _search_guard = EnvVarGuard::set_os(
        "OTTTO_COMMAND_SEARCH_PATH",
        fake_pi
            .parent()
            .expect("fake Pi parent")
            .as_os_str()
            .to_os_string(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind Pi verify backend");
    let api_base_url = format!("http://{}", listener.local_addr().expect("local address"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let request = read_complete_http_request(&mut stream);
            let request_line = request.lines().next().unwrap_or_default().to_string();
            recorded.lock().expect("record request").push(request_line);
            write_json_response(
                &mut stream,
                200,
                "OK",
                r#"{"verified":false,"records_seen":0,"last_record_id":null,"last_received_at":null,"smoke_after":"2026-10-18T00:00:00Z"}"#,
            );
        }
    });
    let mut credentials = SetupRunCredentials {
        setup_run_token: "otsr_test".to_string(),
        connection: LocalConnectionBinding {
            setup_run_id: "setup_pi_verify".to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("machine_test".to_string()),
            claim_code: None,
            api_base_url: api_base_url.clone(),
        },
    };

    let route =
        run_one_pi_route_verification(&api_base_url, &mut credentials, &live_pi_route(), None);

    let requests = requests.lock().expect("read requests").clone();
    assert!(
        !requests.is_empty(),
        "Verify still polls setup verification"
    );
    for request in &requests {
        assert!(
            request.starts_with("GET ")
                && request.contains("/api/v1/setup-runs/setup_pi_verify/local-client/verification"),
            "Verify must only poll setup verification, saw {request}"
        );
        assert!(!request.contains("/api/v1/pi/"));
        assert!(!request.contains("relay-token"));
    }
    assert_eq!(route.status, SourceVerificationStatus::Warning);
    assert!(route.verified);
    assert_eq!(route.records_seen, 0);
    assert_eq!(route.error_code.as_deref(), Some(PI_LOCAL_ONLY_CODE));
    assert_eq!(route.local_session_observed, Some(true));
    assert!(!route.message.text.contains("Sign in"));
    let aggregate = pi_route_aggregate_result(vec![route]);
    assert_eq!(aggregate.message.code, PI_LOCAL_ONLY_CODE);
    assert!(!aggregate.message.text.contains("Sign in"));
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
#[serial]
fn live_pi_root_replacement_during_smoke_cannot_verify_from_reopened_count() {
    let root = control_test_root("pi-live-root-replaced-during-smoke");
    let home = root.join("home");
    create_control_test_dir(&home);
    let sessions = home.join(".pi/agent/sessions");
    let original = home.join(".pi/agent/sessions-original");
    let _home_guard = EnvVarGuard::set_path("HOME", &home);

    let result =
        run_pi_route_pre_smoke_with(&live_pi_route(), prepare_pi_live_session_census, |_| {
            fs::rename(&sessions, &original).expect("move held pre-smoke root");
            fs::create_dir(&sessions).expect("create replacement session root");
            fs::write(sessions.join("preexisting-a.jsonl"), b"{}\n")
                .expect("write first replacement transcript");
            fs::write(sessions.join("preexisting-b.jsonl"), b"{}\n")
                .expect("write second replacement transcript");
            SmokeResult {
                command_found: true,
                succeeded: true,
                exit_status: Some(0),
                duration_ms: 1,
                message: "fake Pi smoke completed".to_string(),
                diagnostic: None,
                error_code: None,
                local_session_observed: Some(true),
            }
        });
    let failed = match result {
        Ok(_) => panic!("a replaced root must fail before route evidence is accepted"),
        Err(failed) => *failed,
    };

    assert_eq!(failed.status, SourceVerificationStatus::Failed);
    assert!(!failed.verified);
    assert!(failed.command_found);
    assert!(failed.command_succeeded);
    assert_eq!(failed.exit_status, Some(0));
    assert_eq!(failed.duration_ms, 1);
    assert!(failed.smoke_after.is_some());
    assert_eq!(
        failed.error_code.as_deref(),
        Some(PI_SESSION_CENSUS_FAILED_CODE)
    );
    assert_eq!(failed.local_session_observed, None);
    assert!(failed.message.text.contains("completed smoke"));
    assert!(!failed.message.text.contains("could not run a smoke"));
    let aggregate = pi_route_aggregate_result(vec![failed]);
    assert_eq!(aggregate.status, SourceVerificationStatus::Failed);
    assert!(!aggregate.verified);
    assert_eq!(aggregate.message.code, PI_SESSION_CENSUS_FAILED_CODE);
    assert!(!aggregate.message.text.contains("stopped before smoke"));
    assert!(aggregate.message.text.contains("before or after smoke"));
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn live_pi_root_establishment_refuses_symlink_without_creating_beyond_it() {
    use std::os::unix::fs::symlink;

    let home = control_test_root("pi-live-root-symlink");
    let outside = control_test_root("pi-live-root-symlink-outside");
    symlink(&outside, home.join(".pi")).expect("symlink .pi outside HOME");

    assert!(
        open_or_create_pi_session_root_from_home_io(&home, &home.join(".pi/agent/sessions"))
            .is_err()
    );
    assert!(!outside.join("agent").exists());
    let _ = fs::remove_dir_all(home);
    let _ = fs::remove_dir_all(outside);
}

#[cfg(unix)]
#[test]
fn live_pi_root_establishment_refuses_a_symlink_eexist_race_winner() {
    use std::os::unix::fs::symlink;

    let home = control_test_root("pi-live-root-eexist-symlink");
    let outside = control_test_root("pi-live-root-eexist-symlink-outside");
    let held_home = open_pi_session_root_direct_io(&home).expect("hold test HOME");

    let result =
        open_or_create_pi_directory_component_with(&held_home.directory, ".pi".as_ref(), |_, _| {
            symlink(&outside, home.join(".pi")).expect("race winner creates symlink");
            Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
        });

    assert!(result.is_err());
    assert!(!outside.join("agent").exists());
    let _ = fs::remove_dir_all(home);
    let _ = fs::remove_dir_all(outside);
}

#[cfg(unix)]
#[test]
fn pi_session_files_include_nested_workspace_sessions() {
    let root = std::env::temp_dir().join(format!(
        "ottto-pi-session-files-{}-{}",
        std::process::id(),
        current_millis()
    ));
    let nested = root.join("----");
    fs::create_dir_all(&nested).expect("create nested session dir");
    fs::write(nested.join("session.jsonl"), "{}\n").expect("write nested session");
    fs::write(root.join("ignore.txt"), "ignored").expect("write ignored file");

    let files = pi_session_files_in(&root).expect("discover nested Pi session");

    assert_eq!(files.len(), 1);
    assert!(files.contains(&nested.join("session.jsonl")));
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn pi_session_discovery_skips_symlink_files_and_directories() {
    use std::os::unix::fs::symlink;

    let root = control_test_root("pi-session-symlinks");
    let outside = control_test_root("pi-session-symlinks-outside");
    let real = root.join("real.jsonl");
    fs::write(&real, b"inside\n").expect("write real session");
    fs::write(outside.join("outside.jsonl"), b"outside\n").expect("write outside session");
    symlink(outside.join("outside.jsonl"), root.join("file-link.jsonl"))
        .expect("create file symlink");
    symlink(&outside, root.join("directory-link")).expect("create directory symlink");

    let files = pi_session_files_in(&root).expect("bounded symlink-safe discovery");

    assert_eq!(files, BTreeSet::from([real]));
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(outside);
}

#[cfg(unix)]
#[test]
fn pi_session_root_walk_rejects_pi_and_agent_symlinks() {
    use std::os::unix::fs::symlink;

    let home = control_test_root("pi-session-root-symlink-home");
    let outside = control_test_root("pi-session-root-symlink-outside");
    fs::create_dir_all(outside.join("agent/sessions")).expect("create outside session tree");
    fs::write(
        outside.join("agent/sessions/outside.jsonl"),
        b"outside-secret\n",
    )
    .expect("write outside session");

    symlink(&outside, home.join(".pi")).expect("symlink .pi outside home");
    assert!(matches!(
        open_pi_session_root_from_home(&home, &home.join(".pi/agent/sessions")),
        Err(LocalApiError::LocalOperationFailed(_))
    ));

    fs::remove_file(home.join(".pi")).expect("remove .pi symlink");
    fs::create_dir(home.join(".pi")).expect("create real .pi");
    symlink(outside.join("agent"), home.join(".pi/agent")).expect("symlink agent outside .pi");
    assert!(matches!(
        open_pi_session_root_from_home(&home, &home.join(".pi/agent/sessions")),
        Err(LocalApiError::LocalOperationFailed(_))
    ));

    let _ = fs::remove_dir_all(home);
    let _ = fs::remove_dir_all(outside);
}

/// [behaviour] An overridden Pi agent directory below home is walked from
/// the trusted home; one outside home, relative or with `..` is refused,
/// never reported as no root, and nothing is created.
#[cfg(unix)]
#[test]
fn pi_session_root_follows_an_override_below_home_and_refuses_others() {
    let home = control_test_root("pi-session-root-override");
    let sessions = home.join("alt/agent/sessions");
    let opened = open_or_create_pi_session_root_from_home_io(&home, &sessions)
        .expect("an override below home is created and walked");
    assert_eq!(opened.path, sessions);
    assert!(matches!(
        open_pi_session_root_from_home(&home, &sessions),
        Ok(Some(_))
    ));
    let outside = control_test_root("pi-session-root-override-outside");
    for refused in [
        outside.join("agent/sessions"),
        PathBuf::from("agent/sessions"),
        home.join("alt/../escape/sessions"),
    ] {
        assert!(matches!(
            open_pi_session_root_from_home(&home, &refused),
            Err(LocalApiError::LocalOperationFailed(_))
        ));
        assert!(open_or_create_pi_session_root_from_home_io(&home, &refused).is_err());
    }
    assert!(!outside.join("agent").exists());
    assert!(!home.join("escape").exists());
    let _ = fs::remove_dir_all(home);
    let _ = fs::remove_dir_all(outside);
}

#[cfg(unix)]
#[test]
fn pi_session_discovery_refuses_root_replacement_after_open() {
    let parent = control_test_root("pi-session-root-replacement");
    let root = parent.join("sessions");
    let original = parent.join("sessions-original");
    fs::create_dir(&root).expect("create session root");
    fs::write(root.join("inside.jsonl"), b"inside\n").expect("write inside session");
    let opened_root = open_pi_test_root(&root);

    fs::rename(&root, &original).expect("move opened session root");
    fs::create_dir(&root).expect("create replacement session root");
    fs::write(root.join("outside.jsonl"), b"outside-secret\n").expect("write replacement session");

    let error = pi_session_files_for_root(&opened_root)
        .expect_err("count/selection must refuse a replaced root");
    assert!(error.to_string().contains("session root changed"));
    let _ = fs::remove_dir_all(parent);
}

#[cfg(unix)]
#[test]
fn pi_session_open_rejects_file_and_directory_symlink_swaps() {
    use std::os::unix::fs::symlink;

    let root = control_test_root("pi-session-swap");
    let outside = control_test_root("pi-session-swap-outside");
    let nested = root.join("nested");
    fs::create_dir_all(&nested).expect("create nested session directory");
    let nested_session = nested.join("session.jsonl");
    let outside_session = outside.join("session.jsonl");
    fs::write(&nested_session, b"inside\n").expect("write nested session");
    fs::write(&outside_session, b"outside-secret\n").expect("write outside session");
    let opened_root = open_pi_test_root(&root);
    let discovered = pi_session_files_for_root(&opened_root).expect("discover nested session");

    fs::rename(&nested, root.join("nested-original")).expect("move discovered directory");
    symlink(&outside, &nested).expect("swap directory for symlink");
    for path in &discovered {
        let error = open_pi_session_file_beneath_root(&opened_root, path)
            .expect_err("component-wise no-follow open must reject directory swap");
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
    }

    fs::remove_file(&nested).expect("remove directory symlink");
    let final_session = root.join("final.jsonl");
    fs::write(&final_session, b"inside-final\n").expect("write final session");
    let discovered = pi_session_files_for_root(&opened_root).expect("discover final session");
    fs::remove_file(&final_session).expect("remove discovered final session");
    symlink(&outside_session, &final_session).expect("swap file for symlink");
    assert!(discovered.contains(&final_session));
    let error = open_pi_session_file_beneath_root(&opened_root, &final_session)
        .expect_err("no-follow open must reject final-component swap");
    assert_ne!(error.kind(), std::io::ErrorKind::NotFound);

    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(outside);
}

/// [behaviour] The census lists a whole tree, however deep or wide; there
/// is no size cap.
#[cfg(unix)]
#[test]
fn pi_session_traversal_lists_deep_and_wide_trees() {
    let root = control_test_root("pi-session-traversal-uncapped");
    let deep = (0..40).fold(root.clone(), |path, level| path.join(format!("d{level}")));
    fs::create_dir_all(&deep).expect("create deep tree");
    fs::write(deep.join("session.jsonl"), b"{}\n").expect("write deep session");
    for index in 0..3 {
        fs::write(root.join(format!("{index}.jsonl")), b"{}\n").expect("write wide session");
    }
    let files = pi_session_files_in(&root).expect("an uncapped census lists the tree");
    assert_eq!(files.len(), 4);
    assert!(files.contains(&deep.join("session.jsonl")));
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn pi_session_files_modified_since_filters_on_mtime() {
    let root = std::env::temp_dir().join(format!(
        "ottto-pi-recent-{}-{}",
        std::process::id(),
        current_millis()
    ));
    fs::create_dir_all(&root).expect("create session dir");
    let session = root.join("session.jsonl");
    fs::write(&session, "{}\n").expect("write session");
    let modified = fs::metadata(&session)
        .and_then(|metadata| metadata.modified())
        .expect("read session mtime");
    let opened_root = open_pi_test_root(&root);

    // A boundary just after the file's mtime excludes it...
    let after = modified + Duration::from_secs(60);
    assert!(
        pi_session_files_modified_since(&opened_root, [session.clone()], after)
            .expect("filter old Pi session")
            .is_empty(),
        "file older than `since` must be filtered out"
    );

    // ...and a boundary before (or equal to) the mtime includes it.
    let before = modified - Duration::from_secs(60);
    let included = pi_session_files_modified_since(&opened_root, [session.clone()], before)
        .expect("include recent Pi session");
    assert_eq!(included, vec![session.clone()]);
    let at = pi_session_files_modified_since(&opened_root, [session.clone()], modified)
        .expect("include Pi session at boundary");
    assert_eq!(
        at,
        vec![session.clone()],
        "mtime == since must be inclusive"
    );

    // Unreadable / missing paths are dropped, not panicked on.
    let missing = root.join("does-not-exist.jsonl");
    assert!(
        pi_session_files_modified_since(&opened_root, [missing], before)
            .expect("drop missing Pi session")
            .is_empty()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn pi_route_aggregate_allows_partial_success_as_warning() {
    let route_results = vec![
        SourceRouteVerificationResult {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.4-mini".to_string()),
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("direct_api".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("openai_api_key".to_string()),
            account_identifier_hash: None,
            organization_identifier_hash: None,
            credential_fingerprint_hash: Some("credential_hash".to_string()),
            billing_identity_evidence: Some("credential_fingerprint".to_string()),
            billing_identity_confidence: ottto_protocol::AgentStatusConfidence::High,
            status: SourceVerificationStatus::Verified,
            verified: true,
            records_seen: 1,
            last_record_id: Some("record_1".to_string()),
            last_received_at: Some("2026-05-11T10:00:00Z".to_string()),
            smoke_after: Some("2026-05-11T09:59:00Z".to_string()),
            command_found: true,
            command_succeeded: true,
            exit_status: Some(0),
            duration_ms: 12,
            diagnostic: None,
            error_code: None,
            local_session_observed: Some(true),
            message: StableMessage {
                code: "verified".to_string(),
                text: "ok".to_string(),
            },
            check: None,
        },
        SourceRouteVerificationResult {
            provider: Some("google-vertex".to_string()),
            model: Some("gemini-2.5-flash-lite".to_string()),
            model_provider: Some("google".to_string()),
            billing_provider: Some("google".to_string()),
            billing_channel: Some("google_vertex".to_string()),
            auth_mode: Some("service_account".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("google_cloud_vertex".to_string()),
            account_identifier_hash: None,
            organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: None,
            billing_identity_confidence: ottto_protocol::AgentStatusConfidence::Unknown,
            status: SourceVerificationStatus::NoFreshTelemetry,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-05-11T10:01:00Z".to_string()),
            command_found: true,
            command_succeeded: true,
            exit_status: Some(0),
            duration_ms: 10,
            diagnostic: None,
            error_code: Some("no_fresh_telemetry".to_string()),
            local_session_observed: Some(false),
            message: StableMessage {
                code: "no_fresh_telemetry".to_string(),
                text: "missing".to_string(),
            },
            check: None,
        },
    ];

    let result = pi_route_aggregate_result(route_results);

    assert_eq!(result.status, SourceVerificationStatus::Warning);
    assert!(result.verified);
    assert_eq!(result.records_seen, 1);
    assert_eq!(result.message.code, "pi_route_warnings");
}

#[test]
fn verification_check_states_what_each_completed_check_established() {
    fn checked(mut result: SourceVerificationResult) -> SourceVerificationResult {
        attach_verification_check(&mut result);
        result
    }
    let check = |method, scope| Some(SourceVerificationCheck { method, scope });
    use SourceVerificationMethod::{ConfigurationCheck, LivePrompt, Mixed, PassiveRecentUsage};
    use SourceVerificationScope::{
        Configuration, LocalEvidence, NotEstablished, Partial, UsageReceived,
    };

    // Codex: configuration only. The legacy fields stay unchanged.
    let codex = checked(codex_local_import_verification(empty_source_config(
        &SourceKind::Codex,
    )));
    assert_eq!(codex.check, check(Some(ConfigurationCheck), Configuration));
    assert_eq!(codex.status, SourceVerificationStatus::Warning);
    assert!(!codex.verified);
    let mut drifted = empty_source_config(&SourceKind::Codex);
    drifted
        .drift
        .push(config_drift("otel", "managed", "missing"));
    let codex_drift = checked(codex_local_import_verification(drifted));
    assert_eq!(
        codex_drift.check,
        check(Some(ConfigurationCheck), NotEstablished)
    );

    // Claude: only fresh usage after the prompt establishes anything;
    // warnings (not installed, quiet window) do not.
    let claude = |status: SourceVerificationStatus, verified: bool, code: &str| {
        checked(verification_result(
            SourceKind::ClaudeCode,
            status,
            verified,
            u64::from(verified),
            None,
            None,
            None,
            code,
            "text",
        ))
    };
    assert_eq!(
        claude(SourceVerificationStatus::Verified, true, "verified").check,
        check(Some(LivePrompt), UsageReceived)
    );
    for (status, code) in [
        (
            SourceVerificationStatus::Warning,
            CLAUDE_LOGIN_REFRESH_PENDING_CODE,
        ),
        (
            SourceVerificationStatus::Warning,
            crate::agent_status::CLAUDE_OTTTO_SIGNED_IN,
        ),
        (SourceVerificationStatus::Warning, SOURCE_NOT_INSTALLED_CODE),
        (
            SourceVerificationStatus::NoFreshTelemetry,
            "no_fresh_telemetry",
        ),
    ] {
        assert_eq!(
            claude(status, false, code).check,
            check(Some(LivePrompt), NotEstablished)
        );
    }

    // Pi: per-route method and scope; partial keeps the legacy verified bit.
    let smoke = SmokeResult {
        command_found: true,
        succeeded: true,
        exit_status: Some(0),
        duration_ms: 1,
        message: "ok".to_string(),
        diagnostic: None,
        error_code: None,
        local_session_observed: Some(false),
    };
    let live_verified = pi_route_result_from_verification(
        &live_pi_route(),
        &smoke,
        SetupRunVerificationResponse {
            verified: true,
            records_seen: 1,
            last_record_id: Some("record_1".to_string()),
            last_received_at: Some("2026-10-19T10:00:00Z".to_string()),
            smoke_after: "2026-10-19T09:59:00Z".to_string(),
            error_code: None,
            clear_condition: None,
        },
    );
    let passive = |status, verified, code: Option<&str>| {
        pi_route_passive_result(
            &subscription_oauth_route(),
            status,
            verified,
            0,
            None,
            None,
            Some("2026-10-19T04:00:00Z".to_string()),
            code.map(str::to_string),
            "text".to_string(),
            Some(true),
        )
    };
    let reauth = passive(
        SourceVerificationStatus::Warning,
        false,
        Some(PI_OAUTH_REAUTH_CODE),
    );
    let local_only = passive(
        SourceVerificationStatus::Warning,
        true,
        Some(PI_LOCAL_ONLY_CODE),
    );

    let partial = checked(pi_route_aggregate_result(vec![
        live_verified.clone(),
        reauth.clone(),
    ]));
    assert_eq!(partial.status, SourceVerificationStatus::Warning);
    assert!(partial.verified);
    assert_eq!(partial.message.code, "pi_route_warnings");
    assert_eq!(partial.check, check(Some(Mixed), Partial));
    assert_eq!(
        partial.route_results[0].check,
        check(Some(LivePrompt), UsageReceived)
    );
    assert_eq!(
        partial.route_results[1].check,
        check(Some(PassiveRecentUsage), NotEstablished)
    );

    let local = checked(pi_route_aggregate_result(vec![local_only]));
    assert_eq!(local.message.code, PI_LOCAL_ONLY_CODE);
    assert_eq!(local.check, check(Some(PassiveRecentUsage), LocalEvidence));

    let reauth_only = checked(pi_route_aggregate_result(vec![reauth]));
    assert_eq!(
        reauth_only.check,
        check(Some(PassiveRecentUsage), NotEstablished)
    );
    let live_only = checked(pi_route_aggregate_result(vec![live_verified]));
    assert_eq!(live_only.check, check(Some(LivePrompt), UsageReceived));

    // Pi stopped before any route ran: the kind is not determined.
    let unrouted = checked(verification_result(
        SourceKind::Pi,
        SourceVerificationStatus::ReconnectRequired,
        false,
        0,
        None,
        None,
        None,
        "reconnect_required",
        "text",
    ));
    assert_eq!(unrouted.check, check(None, NotEstablished));
}

/// Inside the quiet window the Verify smoke does not start Claude Code
/// and returns a typed, non-blocking warning; outside it, it runs.
#[test]
#[serial]
fn claude_smoke_waits_inside_the_quiet_window() {
    use crate::provider_calls::CallKind;
    let fake = crate::claude_spawn_gate::test_support::FakeClaudeEnv::new("smoke");
    let account = fake.default_account("smoke-account-uuid");
    fake.default_login_expires_in(time::Duration::minutes(10));
    let smoke = run_claude_smoke_prompt();
    assert!(!smoke.succeeded);
    assert_eq!(
        smoke.error_code.as_deref(),
        Some(CLAUDE_LOGIN_REFRESH_PENDING_CODE)
    );
    assert!(fake.spawns().is_empty(), "Claude Code was not started");
    let result = smoke_failure_verification_result(SourceKind::ClaudeCode, &smoke, None);
    assert_eq!(result.status, SourceVerificationStatus::Warning);

    assert!(crate::provider_calls::test_lines(CallKind::ClaudeSmokePrompt, &account).is_empty());

    fake.default_login_expires_in(time::Duration::hours(2));
    let smoke = run_claude_smoke_prompt();
    assert!(smoke.succeeded, "{}", smoke.message);
    assert_eq!(fake.spawns().len(), 1);
    // Only the run that started is a provider call: a prompt sent to
    // Anthropic, from a person's Verify unless a caller says otherwise.
    let lines = crate::provider_calls::test_lines(CallKind::ClaudeSmokePrompt, &account);
    assert_eq!(lines.len(), 1);
    assert_eq!(
        (
            lines[0].provider.as_str(),
            lines[0].trigger.as_str(),
            lines[0].result.as_str(),
            lines[0].basis.as_str(),
            lines[0].requests_at_least
        ),
        ("anthropic", "other", "ok", "subprocess_lower_bound", 1)
    );
    assert!(!crate::provider_calls::test_raw_log().contains("fixture-access"));
}

/// Only Claude Code has a live prompt check: any other source gets an explicit
/// result and no command runs.
#[test]
fn verification_smoke_runs_no_prompt_for_codex_or_pi() {
    let daemon = daemon().with_account(connected_account());
    for source in [SourceKind::Codex, SourceKind::Pi] {
        let smoke = run_verification_smoke_prompt(&daemon, &source).unwrap();
        assert!(!smoke.succeeded);
        assert_eq!(smoke.duration_ms, 0);
        assert_eq!(smoke.error_code.as_deref(), Some(NO_LIVE_CHECK_CODE));
    }
}

/// A Pi route whose provider is neither OpenAI nor Anthropic is still a real
/// model request: one line with provider `unknown`.
#[cfg(unix)]
#[test]
#[serial]
fn pi_route_smoke_with_other_provider_is_one_unknown_provider_line() {
    use crate::provider_calls::CallKind;
    use std::os::unix::fs::PermissionsExt;
    let root = control_test_root("pi-route-smoke-unknown");
    let bin = root.join("bin");
    create_control_test_dir(&bin);
    let pi = bin.join("pi");
    fs::write(&pi, "#!/bin/sh\necho ok\n").expect("fake pi");
    fs::set_permissions(&pi, fs::Permissions::from_mode(0o755)).expect("executable");
    let _home = EnvVarGuard::set_path("HOME", &root);
    let _pi_dir = EnvVarGuard::set_path("PI_CODING_AGENT_DIR", &root.join("pi-agent"));
    let _search = EnvVarGuard::set_path("OTTTO_COMMAND_SEARCH_PATH", &bin);
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let mut route = live_pi_route();
    route.classification.model_provider = Some("zai".to_string());

    let smoke = run_pi_route_smoke_prompt(&route);
    assert!(smoke.succeeded, "{}", smoke.message);

    let lines = crate::provider_calls::test_lines(CallKind::PiSmokePrompt, "unknown");
    assert_eq!(
        lines
            .iter()
            .map(|line| (
                line.provider.as_str(),
                line.basis.as_str(),
                line.requests_at_least
            ))
            .collect::<Vec<_>>(),
        [("unknown", "subprocess_lower_bound", 1)]
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn command_diagnostics_are_redacted_before_display() {
    let diagnostic = redact_command_diagnostic(
        "Token sk-secret123 is expired at /Users/example/.aws/sso/cache/file.json account_id=org_123 raw_prompt=show private repo",
    )
    .expect("diagnostic");

    assert!(diagnostic.contains("[REDACTED]"));
    assert!(diagnostic.contains("[path]"));
    assert!(diagnostic.contains("[account_id]"));
    assert!(diagnostic.contains("[prompt]"));
    assert!(!diagnostic.contains("/Users/example"));
    assert!(!diagnostic.contains("org_123"));
    assert!(!diagnostic.contains("sk-secret123"));
    assert!(!diagnostic.contains("show private repo"));

    let login =
        redact_command_diagnostic("Token is expired. Run /login.").expect("login diagnostic");
    assert!(login.contains("/login"));
    assert!(command_diagnostic_requires_claude_reauth(Some(&login)));
}

#[test]
fn codex_config_rejects_legacy_direct_ottto_endpoint() {
    let body = r#"
[otel]
log_user_prompt = false

[otel.exporter.otlp-http]
endpoint = "https://api.ottto.net/v1/logs"
protocol = "binary"

[otel.exporter.otlp-http.headers]
X-API-Key = "otel_redacted"
"#;

    assert!(!codex_config_has_relay_otel(body));
}

#[test]
fn codex_source_off_removes_all_owned_exporters_and_preserves_user_fields() {
    let root = control_test_root("codex-source-off");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("config.toml");
    let original = "model = \"test-model\"\n";
    fs::write(&path, original).unwrap();
    patch_codex_config_at(&path, &root.join("backups")).unwrap();
    let result = reconcile_codex_source_off_at(&path, &root.join("backups")).unwrap();
    assert!(result.changed);
    assert!(result.backup_created);
    let body = fs::read_to_string(&path).unwrap();
    assert!(!body.contains("/v1/logs"));
    assert!(!body.contains("/v1/traces"));
    assert!(!body.contains("/v1/metrics"));
    assert_eq!(
        body.parse::<DocumentMut>().unwrap()["model"].as_str(),
        Some("test-model")
    );
    assert!(
        !reconcile_codex_source_off_at(&path, &root.join("backups"))
            .unwrap()
            .changed
    );
    assert!(codex_config_state_at(&path, "config", "", false)
        .drift
        .is_empty());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn codex_source_off_compare_before_replace_refuses_concurrent_edits() {
    let root = control_test_root("codex-source-off-edit-conflict");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("config.toml");
    fs::write(&path, "model = \"new\"\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(write_codex_source_off_body(&path, "model = \"old\"\n", "").is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "model = \"new\"\n");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    write_codex_source_off_body(&path, "model = \"new\"\n", "model = \"kept\"\n").unwrap();
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn codex_source_off_refuses_ambiguous_or_invalid_config_without_writes() {
    let root = control_test_root("codex-source-off-invalid");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("config.toml");
    for body in ["# ottto:start\n[otel]\n", "[otel\n"] {
        fs::write(&path, body).unwrap();
        assert!(reconcile_codex_source_off_at(&path, &root.join("backups")).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), body);
    }
    let missing = root.join("missing.toml");
    assert!(
        !reconcile_codex_source_off_at(&missing, &root.join("backups"))
            .unwrap()
            .changed
    );
    assert!(!missing.exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn codex_source_off_recovers_orphan_end_with_exact_byte_preservation() {
    let generated = render_codex_relay_toml_block_for_base("http://127.0.0.1:44621");
    let external = generated.lines().nth(3).unwrap().replace(
        "http://127.0.0.1:44621/v1/traces",
        "https://collector.example/v1/traces",
    );
    for (body, expected) in [
        (format!("{} # retain annotation\n{external}\n# ottto:end\n", generated.lines().nth(2).unwrap()), format!(" # retain annotation\n{external}\n")),
        ("[otel]\nenvironment='custom'\nexporter = { otlp-http = { endpoint='http://localhost:44621/v1/logs', headers={ X-Ottto-Local-Relay='codex' } } }\n# ottto:end\ncustom_setting=true\n".into(), "[otel]\nenvironment='custom'\n\ncustom_setting=true\n".into()),
    ] {
        let next = codex_source_off_body(&body).unwrap();
        assert_eq!(next, expected);
        assert_eq!(codex_source_off_body(&next).unwrap(), next);
    }
    for eol in ["\n", "\r\n"] {
        let prefix = format!("# user formatting{eol}model='kept'{eol}");
        let suffix = format!("[profiles.work]{eol}model = 'also kept' # user comment{eol}");
        let owned = generated.replace('\n', eol);
        let body = format!("{prefix}{owned}{eol}# ottto:end{eol}{suffix}");
        let expected = format!("{prefix}otel.environment = \"prod\"{eol}otel.log_user_prompt = false{eol}{eol}{eol}{eol}{suffix}");
        let next = codex_source_off_body(&body).unwrap();
        assert_eq!(next.as_bytes(), expected.as_bytes());
        assert_eq!(codex_source_off_body(&next).unwrap(), next);
        assert!(!next.contains("/v1/"));
    }
}

#[test]
fn codex_source_off_orphan_refuses_unknown_ownership_without_backup_or_write() {
    let root = control_test_root("codex-orphan-fence-refusals");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("config.toml");
    let owned = render_codex_relay_toml_block_for_base("http://127.0.0.1:44621");
    let orphan = format!("{owned}\n# ottto:end\n");
    let cases = vec![
        orphan.replace("# ottto:end", "# ottto:end\n# ottto:end"),
        format!("# ottto:end\n{owned}\n"),
        orphan.replace("X-Ottto-Local-Relay", "Looks-Like-Ottto"),
        orphan.replace("http://127.0.0.1:44621", "https://collector.example"),
        orphan.replace("http://127.0.0.1:44621", "http://127.0.0.1:44621/extra"),
        orphan.replace("protocol = \"binary\"", "protocol = \"json\""),
        orphan.replace("headers = {", "timeout=5, headers = {"),
        orphan.replace("headers = {", "headers = { User-Header='keep',"),
        orphan.replace("44621/v1/traces", "44622/v1/traces"),
        format!("{orphan}[broken\n"),
        format!("{orphan}[otel]\nenvironment='duplicate'\n"),
        "[otel.exporter.otlp-http]\nendpoint='http://localhost:44621/v1/logs'\nheaders={X-Ottto-Local-Relay='codex'}\n# ottto:end\n".into(),
        "otel={environment='user',exporter={otlp-http={endpoint='http://localhost:44621/v1/logs',headers={X-Ottto-Local-Relay='codex'}}}}\n# ottto:end\n".into(),
    ];
    for body in cases {
        fs::write(&path, &body).unwrap();
        assert!(
            matches!(
                reconcile_codex_source_off_at(&path, &root.join("backups")),
                Err(LocalApiError::ManualFenceReviewRequired)
            ),
            "{body}"
        );
        assert_eq!(fs::read(&path).unwrap(), body.as_bytes());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn remove_claude_code_env_clears_old_shell_line_and_env_file_and_keeps_user_lines() {
    let root = std::env::temp_dir().join(format!("ottto-claude-env-test-{}", std::process::id()));
    let env_path = root.join(".ottto/claude-telemetry.env");
    let shell_path = root.join(".zshrc");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".ottto")).expect("create temp dir");
    let original_shell = "alias ll='ls -la'\n";
    fs::write(&shell_path, original_shell).expect("write shell rc");
    // The state an older daemon left behind.
    let relay_exports = |logs_endpoint: Option<&str>| {
        claude_code_relay_env_for_machine_id(
            "machine_test",
            &crate::otlp_relay::default_local_relay_base_url(),
        )
        .into_iter()
        .map(|(key, value)| {
            let value = match (key, logs_endpoint) {
                ("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", Some(endpoint)) => endpoint.to_string(),
                _ => value,
            };
            format!("export {key}='{value}'\n")
        })
        .collect::<String>()
    };
    let legacy_env = format!("# ottto:start\n{}# ottto:end\n", relay_exports(None));
    let legacy_env = legacy_env.as_str();
    let legacy_line =
        r#"[ -f "$HOME/.ottto/claude-telemetry.env" ] && . "$HOME/.ottto/claude-telemetry.env""#;
    let legacy_shell = format!("# ottto:start\n{legacy_line}\n# ottto:end\n{original_shell}");
    fs::write(&env_path, legacy_env).expect("seed env file");
    fs::write(&shell_path, &legacy_shell).expect("seed shell line");

    // Anything Ottto did not write inside the fence, or a linked file, leaves
    // both files untouched.
    let edited = format!("# ottto:start\n{legacy_line}\nalias gs='git status'\n# ottto:end\n");
    fs::write(&shell_path, &edited).unwrap();
    assert_eq!(
        remove_claude_code_env_at(&env_path, &shell_path),
        Err(LocalApiError::ManualFenceReviewRequired)
    );
    assert_eq!(fs::read_to_string(&shell_path).unwrap(), edited);
    assert_eq!(fs::read_to_string(&env_path).unwrap(), legacy_env);
    let broken = format!("# ottto:start\n{legacy_line}\n");
    fs::write(&shell_path, &broken).unwrap();
    assert_eq!(
        remove_claude_code_env_at(&env_path, &shell_path),
        Err(LocalApiError::ManualFenceReviewRequired)
    );
    assert_eq!(fs::read_to_string(&env_path).unwrap(), legacy_env);
    #[cfg(unix)]
    {
        let target = root.join("dotfiles-zshrc");
        fs::write(&target, &legacy_shell).unwrap();
        fs::remove_file(&shell_path).unwrap();
        std::os::unix::fs::symlink(&target, &shell_path).unwrap();
        assert_eq!(
            remove_claude_code_env_at(&env_path, &shell_path),
            Err(LocalApiError::ManualFenceReviewRequired)
        );
        assert!(fs::symlink_metadata(&shell_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&target).unwrap(), legacy_shell);
        fs::remove_file(&shell_path).unwrap();
    }
    // An indented start marker is not Ottto's fence: nothing changes.
    let indented = format!("  # ottto:start\n{legacy_line}\n# ottto:end\n");
    fs::write(&shell_path, &indented).unwrap();
    assert_eq!(
        remove_claude_code_env_at(&env_path, &shell_path),
        Err(LocalApiError::ManualFenceReviewRequired)
    );
    assert_eq!(fs::read_to_string(&env_path).unwrap(), legacy_env);
    // A user's own export inside the env fence is not Ottto's.
    fs::write(&shell_path, &legacy_shell).unwrap();
    let user_env =
        "# ottto:start\nexport CLAUDE_CODE_ENABLE_TELEMETRY='1'\nexport OTEL_SERVICE_NAME='mine'\n# ottto:end\n";
    fs::write(&env_path, user_env).unwrap();
    assert_eq!(
        remove_claude_code_env_at(&env_path, &shell_path),
        Err(LocalApiError::ManualFenceReviewRequired)
    );
    assert_eq!(fs::read_to_string(&env_path).unwrap(), user_env);
    assert_eq!(fs::read_to_string(&shell_path).unwrap(), legacy_shell);
    // An Ottto key the user pointed at their own collector is not Ottto's.
    // All three endpoints moved to the user's own local collector port.
    let own_collector = format!(
        "# ottto:start\n{}# ottto:end\n",
        relay_exports(None).replace(
            &format!(":{}/", crate::otlp_relay::LOCAL_RELAY_DEFAULT_PORT),
            ":4318/"
        )
    );
    fs::write(&env_path, &own_collector).unwrap();
    assert_eq!(
        remove_claude_code_env_at(&env_path, &shell_path),
        Err(LocalApiError::ManualFenceReviewRequired)
    );
    assert_eq!(fs::read_to_string(&env_path).unwrap(), own_collector);
    for collector in [
        "https://collector.example/v1/logs",
        "http://localhost:4318/v1/logs",
    ] {
        let user_value = format!(
            "# ottto:start\n{}# ottto:end\n",
            relay_exports(Some(collector))
        );
        fs::write(&env_path, &user_value).unwrap();
        assert_eq!(
            remove_claude_code_env_at(&env_path, &shell_path),
            Err(LocalApiError::ManualFenceReviewRequired),
            "{collector}"
        );
        assert_eq!(fs::read_to_string(&env_path).unwrap(), user_value);
        assert_eq!(fs::read_to_string(&shell_path).unwrap(), legacy_shell);
    }
    // A second source line outside the fence keeps both files.
    fs::write(&env_path, legacy_env).unwrap();
    let doubled = format!("{legacy_shell}{legacy_line}\n");
    fs::write(&shell_path, &doubled).unwrap();
    assert_eq!(
        remove_claude_code_env_at(&env_path, &shell_path),
        Err(LocalApiError::ManualFenceReviewRequired)
    );
    assert_eq!(fs::read_to_string(&shell_path).unwrap(), doubled);
    fs::write(&shell_path, &legacy_shell).unwrap();
    // A source line outside a recognized fence keeps the env file it points at.
    let stray = format!("  # ottto:start\n{legacy_line}\n  # ottto:end\n");
    fs::write(&shell_path, &stray).unwrap();
    fs::write(&env_path, legacy_env).unwrap();
    assert_eq!(
        remove_claude_code_env_at(&env_path, &shell_path),
        Err(LocalApiError::ManualFenceReviewRequired)
    );
    assert_eq!(fs::read_to_string(&env_path).unwrap(), legacy_env);
    fs::write(&shell_path, &legacy_shell).unwrap();
    fs::write(&env_path, legacy_env).unwrap();
    // A linked env folder is never followed.
    #[cfg(unix)]
    {
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("claude-telemetry.env"), legacy_env).unwrap();
        let linked_env = root.join("linked-ottto").join("claude-telemetry.env");
        std::os::unix::fs::symlink(&elsewhere, root.join("linked-ottto")).unwrap();
        assert_eq!(
            remove_claude_code_env_at(&linked_env, &shell_path),
            Err(LocalApiError::ManualFenceReviewRequired)
        );
        assert_eq!(
            fs::read_to_string(elsewhere.join("claude-telemetry.env")).unwrap(),
            legacy_env
        );
        assert_eq!(fs::read_to_string(&shell_path).unwrap(), legacy_shell);
    }
    fs::write(&shell_path, &legacy_shell).unwrap();

    let removed = remove_claude_code_env_at(&env_path, &shell_path).expect("remove env");
    assert!(removed.changed);
    assert!(!env_path.exists());
    assert_eq!(
        fs::read_to_string(&shell_path).expect("read restored shell rc"),
        original_shell
    );
    // Nothing left: the next pass changes nothing.
    let again = remove_claude_code_env_at(&env_path, &shell_path).expect("remove again");
    assert!(!again.changed);
    assert_eq!(fs::read_to_string(&shell_path).unwrap(), original_shell);
    let _ = fs::remove_dir_all(&root);
}

fn managed_claude_relay_fixture() -> (PathBuf, Vec<EnvVarGuard>) {
    let root = fs::canonicalize(control_test_root("managed-relay")).unwrap();
    let guards = vec![
        EnvVarGuard::set_path("HOME", &root),
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support")),
        EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &root.join("secrets")),
        EnvVarGuard::remove("OTTTO_PATCH_CLAUDE_CODE_DISABLED"),
    ];
    fs::create_dir_all(root.join(".claude")).unwrap();
    fs::create_dir_all(root.join("secrets")).unwrap();
    let env: serde_json::Map<String, serde_json::Value> =
        claude_code_relay_env_for_machine_id("machine_test", "http://127.0.0.1:48123")
            .into_iter()
            .map(|(key, value)| (key.to_owned(), json!(value)))
            .collect();
    fs::write(
        root.join(".claude/settings.json"),
        serde_json::to_vec(&json!({"env":env})).unwrap(),
    )
    .unwrap();
    FileMachineStore::default()
        .save(&ottto_core::LocalMachineBinding {
            machine_id: "machine_test".into(),
            installation_id: "install_test".into(),
            hardware_uuid: None,
        })
        .unwrap();
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".into(),
            machine_id: Some("machine_test".into()),
            sources: vec!["claude_code".into()],
        })
        .unwrap();
    (root, guards)
}

#[cfg(unix)]
fn startup_relay_candidates() -> Vec<u16> {
    // SAFETY: getuid has no preconditions.
    crate::otlp_relay::candidate_relay_ports(unsafe { libc::getuid() })
}

#[test]
#[serial]
#[cfg(unix)]
fn settings_port_follows_only_a_bound_relay() {
    let (root, _guards) = managed_claude_relay_fixture();
    let settings = root.join(".claude/settings.json");
    let daemon = daemon().with_account(connected_account());
    let relay = |state, port: u16| ottto_protocol::RelayState {
        state,
        endpoint: Some(crate::otlp_relay::local_relay_base_url_for_port(port)),
        last_connected_at: None,
        last_error: None,
    };
    use ottto_protocol::RelayRuntimeState::{Connected, Failed, Unknown};
    // Not bound, or a rebind in flight: the approved 48123 stays.
    for state in [Unknown, Failed] {
        daemon
            .set_relay_state_for_trusted_client(relay(state, 43119))
            .unwrap();
        assert_eq!(local_relay_port_for_daemon(&daemon), 48123);
    }
    // Bound on the approved port: writing it changes nothing.
    daemon
        .set_relay_state_for_trusted_client(relay(Connected, 48123))
        .unwrap();
    assert_eq!(local_relay_port_for_daemon(&daemon), 48123);
    // Bound on a fallback: it is written, and the mismatch then clears.
    daemon
        .set_relay_state_for_trusted_client(relay(Connected, 43119))
        .unwrap();
    for _ in 0..2 {
        daemon.status_for_trusted_client().unwrap();
    }
    assert!(daemon
        .status_for_trusted_client()
        .unwrap()
        .relay
        .last_error
        .is_some());
    assert_eq!(local_relay_port_for_daemon(&daemon), 43119);
    write_startup_relay_settings(&root, &local_relay_base_url_for_daemon(&daemon));
    let status = daemon.status_for_trusted_client().unwrap();
    assert!(status.relay.last_error.is_none());
    assert!(status
        .canonical_health
        .unwrap()
        .blockers
        .iter()
        .all(|blocker| blocker.code != "claude_relay_endpoint_mismatch"));
    assert!(fs::read_to_string(&settings)
        .unwrap()
        .contains("127.0.0.1:43119"));
    fs::remove_dir_all(root).unwrap();
}

fn write_startup_relay_settings(root: &Path, base: &str) {
    let env: serde_json::Map<String, serde_json::Value> =
        claude_code_relay_env_for_machine_id("machine_test", base)
            .into_iter()
            .map(|(key, value)| (key.to_owned(), json!(value)))
            .collect();
    fs::write(
        root.join(".claude/settings.json"),
        serde_json::to_vec(&json!({"env": env})).unwrap(),
    )
    .unwrap();
}

#[test]
#[serial]
#[cfg(unix)]
fn startup_relay_busy_preferred_port_uses_default_then_fallbacks() {
    use crate::otlp_relay::tests::with_bind_plan;

    let (root, _guards) = managed_claude_relay_fixture();
    let ports = startup_relay_candidates();
    write_startup_relay_settings(
        &root,
        &crate::otlp_relay::local_relay_base_url_for_port(ports[1]),
    );
    // Plan the candidate binds: any real candidate number can be held by a
    // parallel test's ephemeral port, so the free one is a held listener.
    let busy =
        || -> std::io::Result<std::net::TcpListener> { Err(std::io::ErrorKind::AddrInUse.into()) };
    let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = held.local_addr().unwrap();
    let default_listener = with_bind_plan([(ports[1], busy()), (ports[0], Ok(held))], || {
        crate::otlp_relay::bind_startup_local_relay_listener().unwrap()
    });
    assert_eq!(default_listener.local_addr().unwrap(), addr);
    // Default busy too: the preferred port is not retried as a fallback,
    // so the next candidate is selected.
    let fallback_listener = with_bind_plan(
        [
            (ports[1], busy()),
            (ports[0], busy()),
            (ports[2], Ok(default_listener)),
        ],
        || crate::otlp_relay::bind_startup_local_relay_listener().unwrap(),
    );
    assert_eq!(fallback_listener.local_addr().unwrap(), addr);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
#[cfg(unix)]
fn startup_relay_ignores_unapproved_hosts_ports_and_settings() {
    let (root, _guards) = managed_claude_relay_fixture();
    let port = startup_relay_candidates()[1];
    // The default port is the first bind attempted; a held listener stands
    // in for it, since a parallel test's ephemeral port can hold 43119.
    let binds_default_first = || {
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = held.local_addr().unwrap();
        let default = crate::otlp_relay::LOCAL_RELAY_DEFAULT_PORT;
        let listener = crate::otlp_relay::tests::with_bind_plan([(default, Ok(held))], || {
            crate::otlp_relay::bind_startup_local_relay_listener().unwrap()
        });
        assert_eq!(listener.local_addr().unwrap(), addr);
    };
    for base in [
        format!("http://192.0.2.1:{port}"),
        format!("http://localhost:{port}"),
        "http://127.0.0.1:48123".to_string(),
    ] {
        write_startup_relay_settings(&root, &base);
        binds_default_first();
    }
    write_startup_relay_settings(
        &root,
        &crate::otlp_relay::local_relay_base_url_for_port(port),
    );
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "test".into(),
            machine_id: None,
            sources: vec!["codex".into()],
        })
        .unwrap();
    binds_default_first();
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
#[cfg(unix)]
fn rebind_busy_approved_port_falls_back_after_three_attempts_and_serves() {
    use std::io::{Read, Write};

    let (root, _guards) = managed_claude_relay_fixture();
    let ports = startup_relay_candidates();
    let approved = ports[1];
    let old = ports[2];
    write_startup_relay_settings(
        &root,
        &crate::otlp_relay::local_relay_base_url_for_port(approved),
    );
    let settings = root.join(".claude/settings.json");
    let before = fs::read(&settings).unwrap();
    let _busy = std::net::TcpListener::bind(("127.0.0.1", approved)).unwrap();
    // The approved binds hit the held busy listener. The old port is
    // planned: a parallel test's ephemeral port can hold that number.
    let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = held.local_addr().unwrap();
    let mut attempts = 0;
    let listener = crate::otlp_relay::tests::with_bind_plan([(old, Ok(held))], || {
        crate::otlp_relay::rebind_relay_listener(old, &mut |port, attempt| {
            attempts += 1;
            assert!(attempt <= 3, "approved retry must be bounded");
            let result = crate::otlp_relay::bind_replacement_local_relay_listener(port, attempt);
            if attempt < 3 {
                assert!(result.is_err(), "approved port gets its retry budget first");
            }
            result
        })
    });
    assert_eq!(attempts, 3);
    assert_eq!(
        listener.local_addr().unwrap(),
        addr,
        "old port precedes the free default port"
    );
    let daemon = daemon().with_account(connected_account());
    let endpoint = format!("http://127.0.0.1:{old}");
    let connected = ottto_protocol::RelayState {
        state: ottto_protocol::RelayRuntimeState::Connected,
        endpoint: Some(endpoint.clone()),
        last_connected_at: None,
        last_error: None,
    };
    daemon
        .set_relay_state_for_trusted_client(connected.clone())
        .unwrap();
    // A listener failure between sightings ends the streak: recovery to the
    // same mismatch needs two fresh sightings again.
    assert!(daemon
        .status_for_trusted_client()
        .unwrap()
        .relay
        .last_error
        .is_none());
    daemon
        .set_relay_state_for_trusted_client(ottto_protocol::RelayState {
            state: ottto_protocol::RelayRuntimeState::Failed,
            endpoint: Some(endpoint),
            last_connected_at: None,
            last_error: Some(StableMessage {
                code: "relay_listener_failed".into(),
                text: "listener failed".into(),
            }),
        })
        .unwrap();
    let failed = daemon.status_for_trusted_client().unwrap().relay;
    assert_eq!(failed.last_error.unwrap().code, "relay_listener_failed");
    daemon
        .set_relay_state_for_trusted_client(connected)
        .unwrap();
    let first = daemon.status_for_trusted_client().unwrap().relay;
    assert!(first.last_error.is_none(), "one sighting is not reported");
    let relay = daemon.status_for_trusted_client().unwrap().relay;
    assert_eq!(relay.state, ottto_protocol::RelayRuntimeState::Connected);
    let finding = relay.last_error.unwrap();
    assert_eq!(finding.code, "claude_relay_endpoint_mismatch");
    assert!(finding.text.contains(&format!("127.0.0.1:{approved}")));
    assert!(finding.text.contains(&format!("127.0.0.1:{old}")));

    // Serve a real health request on the recovered listener, not just bind it.
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        crate::otlp_relay::serve_test_connection(stream, daemon);
    });
    let mut client = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    server.join().unwrap();
    assert_eq!(fs::read(settings).unwrap(), before);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn relay_runtime_failure_health_survives_control_and_config_intents() {
    use ottto_protocol::{LocalHealthSeverity, RelayRuntimeState, RelayState};

    let (root, _guards) = managed_claude_relay_fixture();
    let daemon = daemon(); // Unconnected synthetic account keeps Verify local.
    let connected = RelayState {
        state: RelayRuntimeState::Connected,
        endpoint: Some("http://127.0.0.1:48123".into()),
        last_connected_at: None,
        last_error: None,
    };
    let failure_blockers = |status: &ottto_protocol::DaemonStatus| {
        status
            .canonical_health
            .as_ref()
            .unwrap()
            .blockers
            .iter()
            .filter(|b| {
                matches!(
                    b.code.as_str(),
                    "relay_bind_failed" | "relay_listener_failed"
                )
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    daemon
        .set_relay_state_for_trusted_client(connected.clone())
        .unwrap();
    for _ in 0..2 {
        assert!(failure_blockers(&daemon.status_for_trusted_client().unwrap()).is_empty());
    }
    for (code, guidance) in [
        (
            "relay_bind_failed",
            "Claude telemetry listener unavailable; restart Ottto, then Verify",
        ),
        (
            "relay_listener_failed",
            "Ottto is rebinding the Claude telemetry listener; if this persists, restart Ottto",
        ),
    ] {
        let failed = RelayState {
            state: RelayRuntimeState::Failed,
            last_error: Some(StableMessage {
                code: code.into(),
                text: "synthetic listener failure".into(),
            }),
            ..connected.clone()
        };
        daemon
            .set_relay_state_for_trusted_client(failed.clone())
            .unwrap();
        let mut status = daemon.status_for_trusted_client().unwrap();
        assert_eq!(status.relay, failed);
        if code == "relay_listener_failed" {
            assert!(failure_blockers(&status).is_empty());
            crate::refresh_canonical_local_health(&mut status);
            assert!(
                failure_blockers(&status).is_empty(),
                "upload reprojection respects grace"
            );
            daemon.relay_mismatch.age_for_test(Duration::from_secs(59));
            assert!(failure_blockers(&daemon.status_for_trusted_client().unwrap()).is_empty());
            daemon.relay_mismatch.age_for_test(Duration::from_secs(60));
        }
        status = daemon.status_for_trusted_client().unwrap();
        let blockers = failure_blockers(&status);
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].code, code);
        assert_eq!(blockers[0].severity, LocalHealthSeverity::Warning);
        assert_eq!(blockers[0].owner, "source");
        assert_eq!(blockers[0].source, "runtime");
        assert_eq!(blockers[0].clear_condition, guidance);
        let since = blockers[0].since.clone();
        status.generated_at = "2099-01-01T00:00:00Z".into();
        crate::refresh_canonical_local_health(&mut status);
        assert_eq!(failure_blockers(&status)[0].since, since);
        for command in [
            LocalControlCommand::RelayStart,
            LocalControlCommand::RelayStop,
        ] {
            let response = handle_command(
                &daemon,
                RequestAuthorization::Token("token".into()),
                command,
                InstallOwner::Unknown,
                false,
            )
            .unwrap();
            assert_eq!(
                serde_json::from_value::<RelayState>(response).unwrap(),
                failed
            );
            let current = daemon.status_for_trusted_client().unwrap();
            assert_eq!(failure_blockers(&current)[0].since, since);
        }
        verify_source(
            &daemon,
            &RequestAuthorization::Token("token".into()),
            SourceKind::ClaudeCode,
            false,
        )
        .unwrap();
        fs::write(root.join(".claude/settings.json"), "{}").unwrap();
        let patch = repair_source_config(&daemon, &SourceKind::ClaudeCode).unwrap();
        assert!(patch.changed);
        let current = daemon.status_for_trusted_client().unwrap();
        assert_eq!(current.relay, failed);
        assert_eq!(failure_blockers(&current)[0].since, since);
        daemon
            .set_relay_state_for_trusted_client(connected.clone())
            .unwrap();
        let recovered = daemon.status_for_trusted_client().unwrap();
        assert!(recovered.relay.last_error.is_none());
        assert!(failure_blockers(&recovered).is_empty());

        // Recovery and a new failure between reads must start a fresh grace.
        if code == "relay_listener_failed" {
            daemon
                .set_relay_state_for_trusted_client(failed.clone())
                .unwrap();
            daemon.relay_mismatch.age_for_test(Duration::from_secs(60));
            daemon
                .set_relay_state_for_trusted_client(connected.clone())
                .unwrap();
            daemon.set_relay_state_for_trusted_client(failed).unwrap();
            assert!(failure_blockers(&daemon.status_for_trusted_client().unwrap()).is_empty());
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
#[cfg(unix)]
fn relay_endpoint_mismatch_is_response_only_and_clears_with_settings_or_consent() {
    let (root, _guards) = managed_claude_relay_fixture();
    let daemon = daemon().with_account(connected_account());
    let saved_account = daemon.account_for_trusted_client().unwrap();
    let live = ottto_protocol::RelayState {
        state: ottto_protocol::RelayRuntimeState::Connected,
        endpoint: Some("http://127.0.0.1:43119".into()),
        last_connected_at: None,
        last_error: None,
    };
    daemon
        .set_relay_state_for_trusted_client(live.clone())
        .unwrap();
    let settings = root.join(".claude/settings.json");
    let before = fs::read(&settings).unwrap();
    // No flapping: the first sighting raises neither finding nor blocker.
    let first = daemon.status_for_trusted_client().unwrap();
    assert!(first.relay.last_error.is_none());
    assert!(first
        .canonical_health
        .as_ref()
        .unwrap()
        .blockers
        .iter()
        .all(|blocker| blocker.code != "claude_relay_endpoint_mismatch"));
    let finding = daemon
        .status_for_trusted_client()
        .unwrap()
        .relay
        .last_error
        .unwrap();
    assert_eq!(finding.code, "claude_relay_endpoint_mismatch");
    assert_eq!(
        finding.text,
        "Relay connected (127.0.0.1:43119) but Claude settings point at 127.0.0.1:48123."
    );
    let mismatch_blockers = |status: &ottto_protocol::DaemonStatus| {
        let health = status.canonical_health.as_ref().unwrap();
        let codes = health
            .blockers
            .iter()
            .filter(|blocker| blocker.code == finding.code)
            .map(|blocker| (blocker.severity.clone(), blocker.owner.clone()))
            .collect::<Vec<_>>();
        (codes, health.overall.state.clone())
    };
    // The uploaded projection re-reads status, then re-projects it.
    let mut uploaded = daemon.status_for_trusted_client().unwrap();
    crate::refresh_canonical_local_health(&mut uploaded);
    // One projection per status: a raised blocker never takes a revision
    // above the cleared status that follows it.
    let revision =
        |status: &ottto_protocol::DaemonStatus| status.canonical_health.as_ref().unwrap().revision;
    let raised_revision = revision(&daemon.status_for_trusted_client().unwrap());
    for status in [daemon.status_for_trusted_client().unwrap(), uploaded] {
        let (codes, overall) = mismatch_blockers(&status);
        assert_eq!(
            codes,
            vec![(
                ottto_protocol::LocalHealthSeverity::Warning,
                "source".to_string()
            )]
        );
        assert_ne!(overall, ottto_protocol::LocalHealthOverallState::Healthy);
    }
    let diagnostics =
        crate::claude_local_otel::support_health::diagnostics_items(&root.join("support"), &live);
    assert_eq!(
        diagnostics[&finding.code],
        ottto_protocol::RedactedValue::String(finding.text.clone())
    );
    // Doctor and status share this command. Both retry postures expose it.
    for retry in [false, true] {
        let response = handle_request(
            &daemon,
            LocalControlRequest {
                request_id: "relay-health".into(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".into()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                    retry_relay_authorization: retry,
                },
            },
        );
        assert!(response.ok, "{response:?}");
        let payload = response.payload.unwrap();
        assert_eq!(payload["relay"]["state"], "connected");
        assert_eq!(payload["relay"]["last_error"]["text"], finding.text);
    }
    assert_eq!(daemon.account_for_trusted_client().unwrap(), saved_account);
    assert_eq!(fs::read(&settings).unwrap(), before);
    assert_eq!(daemon.state().unwrap().relay, live);

    write_startup_relay_settings(&root, "http://127.0.0.1:43119");
    let cleared = daemon.status_for_trusted_client().unwrap();
    assert!(cleared.relay.last_error.is_none());
    assert_eq!(revision(&cleared), raised_revision);
    assert!(
        mismatch_blockers(&cleared).0.is_empty(),
        "blocker clears on match"
    );
    assert!(
        !crate::claude_local_otel::support_health::diagnostics_items(&root.join("support"), &live)
            .contains_key(&finding.code)
    );
    write_startup_relay_settings(&root, "http://127.0.0.1:48123");
    assert!(
        daemon
            .status_for_trusted_client()
            .unwrap()
            .relay
            .last_error
            .is_none(),
        "an agreeing check resets the streak"
    );
    let disabled = EnvVarGuard::set_str("OTTTO_PATCH_CLAUDE_CODE_DISABLED", "1");
    assert!(daemon
        .status_for_trusted_client()
        .unwrap()
        .relay
        .last_error
        .is_none());
    drop(disabled);
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "test".into(),
            machine_id: None,
            sources: vec!["codex".into()],
        })
        .unwrap();
    assert!(daemon
        .status_for_trusted_client()
        .unwrap()
        .relay
        .last_error
        .is_none());
    assert!(
        !crate::claude_local_otel::support_health::diagnostics_items(&root.join("support"), &live)
            .contains_key(&finding.code)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn managed_claude_relay_requires_existing_approval_and_preserves_optout() {
    let (root, _guards) = managed_claude_relay_fixture();
    let dir = ottto_core::prepare_managed_claude_provisional_root(
        "claude_setup_33333333333333333333333333333333",
    )
    .unwrap()
    .1;
    FileClaudeConfigSlotSettingsStore::default()
        .register_managed_path(1, dir.clone())
        .unwrap();
    let settings = Path::new(&dir).join("settings.json");
    {
        let _disabled = EnvVarGuard::set_str("OTTTO_PATCH_CLAUDE_CODE_DISABLED", "true");
        assert!(!provision_managed_claude_relay_settings(&dir).unwrap());
        assert!(!settings.exists());
    }
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "test".into(),
            machine_id: None,
            sources: vec!["codex".into()],
        })
        .unwrap();
    assert!(!provision_managed_claude_relay_settings(&dir).unwrap());
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "test".into(),
            machine_id: None,
            sources: vec!["claude_code".into()],
        })
        .unwrap();
    let default_settings = root.join(".claude/settings.json");
    let approved = fs::read(&default_settings).unwrap();
    fs::write(
        &default_settings,
        r#"{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"0"}}"#,
    )
    .unwrap();
    assert!(!provision_managed_claude_relay_settings(&dir).unwrap());
    assert!(!settings.exists());
    let canonical_default: serde_json::Value = serde_json::from_slice(&approved).unwrap();
    for (key, value) in [
        (
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            "http://127.0.0.1:48123/collector/v1/logs",
        ),
        (
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
            "http://localhost:48123/collector/v1/metrics",
        ),
        (
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "http://127.0.0.1:48123/collector/v1/traces",
        ),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example"),
        ("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "grpc"),
        ("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "grpc"),
        ("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=user"),
    ] {
        let mut customized = canonical_default.clone();
        customized["env"][key] = json!(value);
        let bytes = serde_json::to_vec(&customized).unwrap();
        fs::write(&default_settings, &bytes).unwrap();
        assert!(!provision_managed_claude_relay_settings(&dir).unwrap());
        assert!(!settings.exists());
        assert_eq!(fs::read(&default_settings).unwrap(), bytes);
    }
    fs::write(&default_settings, &approved).unwrap();
    let opted_out =
        r#"{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"0"},"statusLine":{"command":"keep"}}"#;
    fs::write(&settings, opted_out).unwrap();
    assert!(!provision_managed_claude_relay_settings(&dir).unwrap());
    assert_eq!(fs::read_to_string(&settings).unwrap(), opted_out);
    fs::remove_file(&settings).unwrap();
    assert!(provision_managed_claude_relay_settings(&dir).unwrap());
    let canonical: serde_json::Value =
        serde_json::from_slice(&fs::read(&settings).unwrap()).unwrap();
    for (key, value) in [
        ("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "grpc"),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        ("OTEL_LOGS_EXPORTER", "console"),
        ("CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS", "25000"),
        ("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=user"),
    ] {
        let mut customized = canonical.clone();
        customized["env"][key] = json!(value);
        let bytes = serde_json::to_vec(&customized).unwrap();
        fs::write(&settings, &bytes).unwrap();
        assert!(!provision_managed_claude_relay_settings(&dir).unwrap());
        assert_eq!(fs::read(&settings).unwrap(), bytes);
    }
    fs::write(&settings, "{malformed").unwrap();
    assert!(provision_managed_claude_relay_settings(&dir).is_err());
    assert_eq!(fs::read_to_string(&settings).unwrap(), "{malformed");
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn managed_claude_relay_disable_survives_automatic_repair_and_preserves_root_optout() {
    let (root, _guards) = managed_claude_relay_fixture();
    let store = FileClaudeConfigSlotSettingsStore::default();
    let prepared = store
        .prepare_managed_account_target(
            1,
            "claude_setup_44444444444444444444444444444444".into(),
            None,
            None,
            None,
        )
        .unwrap();
    let dir = prepared.managed_slots[0].config_dir.clone().unwrap();
    provision_managed_claude_relay_settings(&dir).unwrap();
    let path = Path::new(&dir).join("settings.json");
    let mut settings: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    settings["env"]["USER_FLAG"] = json!("keep");
    fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();
    assert!(disable_managed_claude_relay_settings().unwrap());
    let disabled: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(disabled["env"], json!({"USER_FLAG":"keep"}));
    let default = root.join(".claude/settings.json");
    let default_body = fs::read(&default).unwrap();
    assert!(!claude_statusline_refresh_repair_needed(
        &default,
        &root.join("support")
    ));
    assert!(!provision_managed_claude_relay_settings(&dir).unwrap());
    assert!(!repair_registered_managed_claude_relay_settings().unwrap());
    assert_eq!(fs::read(&default).unwrap(), default_body);
    assert!(!disable_managed_claude_relay_settings().unwrap());
    // Explicit source enable restores approval; root-specific off remains.
    patch_claude_code_settings_with_relay_base(&test_machine(), "http://127.0.0.1:48123", true)
        .unwrap();
    assert!(!repair_registered_managed_claude_relay_settings().unwrap());
    let mut settings: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    settings["env"]["CLAUDE_CODE_ENABLE_TELEMETRY"] = json!("0");
    fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();
    disable_managed_claude_relay_settings().unwrap();
    patch_claude_code_settings_with_relay_base(&test_machine(), "http://127.0.0.1:48123", true)
        .unwrap();
    assert!(!repair_registered_managed_claude_relay_settings().unwrap());
    let settings: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(settings["env"]["CLAUDE_CODE_ENABLE_TELEMETRY"], "0");
    assert_eq!(settings["env"]["USER_FLAG"], "keep");
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn managed_claude_relay_refresh_authorizes_before_any_config_write() {
    let (root, _guards) = managed_claude_relay_fixture();
    let prepared = FileClaudeConfigSlotSettingsStore::default()
        .prepare_managed_account_target(
            1,
            "claude_setup_55555555555555555555555555555555".into(),
            None,
            None,
            None,
        )
        .unwrap();
    let dir = prepared.managed_slots[0].config_dir.as_ref().unwrap();
    let default = root.join(".claude/settings.json");
    let original = fs::read(&default).unwrap();
    assert!(matches!(
        refresh_agent_status_for(
            &daemon(),
            &RequestAuthorization::Untrusted,
            Some(SourceKind::ClaudeCode)
        ),
        Err(LocalApiError::LocalClientNotTrusted)
    ));
    assert_eq!(fs::read(&default).unwrap(), original);
    assert!(!Path::new(dir).join("settings.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
#[serial]
fn secondary_claude_removal_preserves_legacy_listeners_but_disable_retires_them() {
    let (root, _guards) = managed_claude_relay_fixture();
    let store = FileClaudeConfigSlotSettingsStore::default();
    let prepared = store
        .prepare_managed_account_target(
            1,
            "claude_setup_99999999999999999999999999999999".into(),
            None,
            None,
            None,
        )
        .unwrap();
    let slot = &prepared.managed_slots[0];
    provision_managed_claude_relay_settings(slot.config_dir.as_ref().unwrap()).unwrap();
    let default_settings = root.join(".claude/settings.json");
    let approval = fs::read(&default_settings).unwrap();
    let (open, retired) = crate::otlp_relay::legacy::with_running_listener_for_test(|| {
        remove_claude_registration_with_relay_cleanup(1, &slot.slot_id).unwrap();
    });
    assert_eq!((open, retired), (1, 0));
    assert_eq!(fs::read(&default_settings).unwrap(), approval);
    let (open, retired) = crate::otlp_relay::legacy::with_running_listener_for_test(|| {
        assert!(disable_managed_claude_relay_settings().unwrap());
    });
    assert_eq!((open, retired), (0, 1));
    assert_ne!(fs::read(&default_settings).unwrap(), approval);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[serial]
fn managed_claude_relay_remove_clears_settings_before_forgetting_ownership() {
    let (root, _guards) = managed_claude_relay_fixture();
    let store = FileClaudeConfigSlotSettingsStore::default();
    let prepared = store
        .prepare_managed_account_target(
            1,
            "claude_setup_77777777777777777777777777777777".into(),
            None,
            None,
            None,
        )
        .unwrap();
    let slot = &prepared.managed_slots[0];
    let dir = slot.config_dir.as_ref().unwrap();
    provision_managed_claude_relay_settings(dir).unwrap();
    let path = Path::new(dir).join("settings.json");
    let original = fs::read(&path).unwrap();
    let (failed, requested) = crate::agent_status_refresh::with_test_requests_now(|| {
        remove_claude_account(999, &slot.slot_id)
    });
    assert!(failed.is_err());
    assert!(requested.is_empty());
    assert_eq!(fs::read(&path).unwrap(), original);
    let (removed, requested) = crate::agent_status_refresh::with_test_requests_now(|| {
        remove_claude_account(1, &slot.slot_id)
    });
    removed.unwrap();
    assert_eq!(requested, vec![SourceKind::ClaudeCode]);
    assert!(Path::new(dir).is_dir());
    let removed: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(removed["env"], json!({}));
    assert!(!provision_managed_claude_relay_settings(dir).unwrap());
    let removed_bytes = fs::read(&path).unwrap();
    disable_managed_claude_relay_settings().unwrap();
    assert_eq!(fs::read(&path).unwrap(), removed_bytes);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn patch_claude_code_settings_writes_loopback_relay_without_dropping_env() {
    let root = control_test_root("claude-settings-loopback");
    let path = root.join("settings.json");
    fs::create_dir_all(&root).expect("create temp dir");
    fs::write(
        &path,
        r#"{"env":{"EXISTING":"keep"},"theme":"dark","statusLine":{"type":"command","command":"jq -r '.model.display_name'","padding":1}}"#,
    )
    .expect("write settings");

    let backup_root = root.join("backups");
    let result = patch_claude_code_settings_at(&path, &test_machine(), &backup_root)
        .expect("patch settings");
    let body = fs::read_to_string(&path).expect("read settings");
    let value: serde_json::Value = serde_json::from_str(&body).expect("json settings");
    let env = value
        .get("env")
        .and_then(|value| value.as_object())
        .expect("env object");

    assert!(result.changed);
    assert!(!result.created);
    assert!(result.backup_created);
    let backup_dir = backup_root.join("config-backups/claude_code");
    assert!(backup_dir.exists());
    assert_eq!(count_backup_files(&backup_dir), 1);
    assert_eq!(
        env.get("EXISTING").and_then(|value| value.as_str()),
        Some("keep")
    );
    assert_eq!(
        env.get("CLAUDE_CODE_ENABLE_TELEMETRY")
            .and_then(|value| value.as_str()),
        Some("1")
    );
    assert_eq!(
        env.get("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA")
            .and_then(|value| value.as_str()),
        Some("1")
    );
    assert_eq!(
        env.get("OTEL_TRACES_EXPORTER")
            .and_then(|value| value.as_str()),
        Some("otlp")
    );
    assert_eq!(
        env.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
            .and_then(|value| value.as_str()),
        Some("http://127.0.0.1:43119/v1/logs")
    );
    assert_eq!(
        env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
            .and_then(|value| value.as_str()),
        Some("http://127.0.0.1:43119/v1/traces")
    );
    assert!(env
        .get("OTEL_RESOURCE_ATTRIBUTES")
        .and_then(|value| value.as_str())
        .expect("resource attributes")
        .contains("ottto.machine_id=machine_test"));
    assert!(claude_code_settings_has_relay_env(&body));
    assert!(claude_code_settings_has_statusline_helper(&body));
    let statusline = value
        .get("statusLine")
        .and_then(|value| value.as_object())
        .expect("statusLine object");
    assert_eq!(
        statusline.get("type").and_then(|value| value.as_str()),
        Some("command")
    );
    assert_eq!(
        statusline.get("padding").and_then(|value| value.as_i64()),
        Some(1)
    );
    let statusline_command = statusline
        .get("command")
        .and_then(|value| value.as_str())
        .expect("statusLine command");
    assert!(statusline_command.contains("claude-code-statusline.sh"));
    let wrapper = fs::read_to_string(backup_root.join("claude-code-statusline.sh"))
        .expect("read statusLine wrapper");
    assert!(wrapper.contains("claude-code-statusline"));
    assert!(wrapper.contains("ORIGINAL_STATUSLINE="));
    assert!(wrapper.contains("model.display_name"));
    assert_eq!(
        value.get("theme").and_then(|value| value.as_str()),
        Some("dark")
    );

    let second = patch_claude_code_settings_at(&path, &test_machine(), &backup_root)
        .expect("patch settings again");
    assert!(!second.changed);
    assert!(!second.created);
    assert!(!second.backup_created);
    assert_eq!(
        fs::read_to_string(&path).expect("read second settings"),
        body
    );
    assert_eq!(
        fs::read_to_string(backup_root.join("claude-code-statusline.sh"))
            .expect("read second statusLine wrapper"),
        wrapper
    );
    assert_eq!(count_backup_files(&backup_dir), 1);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn refresh_repair_preserves_user_claude_statusline_command() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-refresh-user-statusline-test-{}-{}",
        std::process::id(),
        current_millis()
    ));
    let path = root.join("settings.json");
    let support_dir = root.join("support");
    fs::create_dir_all(&root).expect("create temp dir");
    fs::write(
        &path,
        r#"{"statusLine":{"type":"command","command":"jq -r '.model.display_name'"}}"#,
    )
    .expect("write user settings");
    let body = fs::read_to_string(&path).expect("read user settings");

    let repaired = repair_claude_statusline_for_refresh_at(
        &path,
        &test_machine(),
        &support_dir,
        &crate::otlp_relay::default_local_relay_base_url(),
    )
    .expect("refresh repair");

    assert!(!repaired.changed);
    assert!(!repaired.created);
    assert!(!repaired.backup_created);
    assert_eq!(
        fs::read_to_string(&path).expect("read settings again"),
        body
    );
    assert!(!claude_statusline_wrapper_path(&support_dir).exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[serial]
fn backup_retention_keeps_newest_n_and_invalid_env_uses_default() {
    let root = std::env::temp_dir().join(format!(
        "ottto-backup-retention-test-{}-{}",
        std::process::id(),
        current_millis()
    ));
    let backup_dir = root.join("config-backups/codex");
    fs::create_dir_all(&backup_dir).expect("create backup dir");
    for timestamp in 1..=5 {
        fs::write(
            backup_dir.join(format!("codex_config_{timestamp}.toml")),
            format!("model = \"gpt-5.{timestamp}\"\n"),
        )
        .expect("write backup");
    }
    fs::write(backup_dir.join("codex_config_bad.toml"), "bad").expect("write bad backup");

    let _retention_guard = EnvVarGuard::set_str(OTTTO_CONFIG_BACKUP_RETENTION_ENV, "3");
    prune_config_backups(&backup_dir, config_backup_retention_limit()).expect("prune backups");
    let files = fs::read_dir(&backup_dir)
        .expect("read backups")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(files.len(), 3);
    assert!(files.contains(&"codex_config_3.toml".to_string()));
    assert!(files.contains(&"codex_config_4.toml".to_string()));
    assert!(files.contains(&"codex_config_5.toml".to_string()));

    drop(_retention_guard);
    let _invalid_guard = EnvVarGuard::set_str(OTTTO_CONFIG_BACKUP_RETENTION_ENV, "nope");
    assert_eq!(
        config_backup_retention_limit(),
        MAX_CONFIG_BACKUPS_PER_SOURCE
    );
    let _ = fs::remove_dir_all(&root);
}

thread_local! {
    pub(super) static SETUP_SCAN_PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[test]
#[serial]
fn setup_pause_filters_probes_and_cancels_claimed_actions_for_all_sources() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("setup-paused-sources");
    let support = root.join("support");
    fs::create_dir_all(support.join("snapshots")).unwrap();
    let _home = EnvVarGuard::set_path("HOME", &root);
    let _commands = EnvVarGuard::set_path("OTTTO_COMMAND_SEARCH_PATH", &root.join("bin"));
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    for source in [SourceKind::ClaudeCode, SourceKind::Codex, SourceKind::Pi] {
        let slug = source_slug(&source);
        let marker = support.join(format!("snapshots/{slug}.source-disabled"));
        fs::write(&marker, "pending").unwrap();
        SETUP_SCAN_PROBES.with(|count| count.set(0));
        assert!(build_local_scan(&test_machine(), vec![source.clone()])
            .sources
            .is_empty());
        fs::remove_file(&marker).unwrap();
        fs::create_dir(&marker).unwrap();
        assert!(build_local_scan(&test_machine(), vec![source])
            .sources
            .is_empty());
        assert_eq!(SETUP_SCAN_PROBES.with(|count| count.get()), 0);
        fs::remove_dir(&marker).unwrap();
        fs::write(&marker, "pending").unwrap();
    }
    assert!(build_local_scan(&test_machine(), vec![]).sources.is_empty());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        for i in 0..11 {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_complete_http_request(&mut stream);
            if request.contains("/complete") {
                assert!(request.contains("cancelled") && request.contains("source_paused"));
            }
            let source = ["claude_code", "codex", "pi"].get(i / 3).copied();
            let body = json!({
                "action": source.map(|source| json!({"id":"action", "action_type":"verify_source", "source":source})),
                "run": {"id":"run", "status":"completed", "machine_id":null},
                "sources":[], "next_action":null, "next_question":null,
            });
            write_json_response(&mut stream, 200, "OK", &body.to_string());
        }
    });
    let mut credentials = SetupRunCredentials {
        setup_run_token: "synthetic".into(),
        connection: LocalConnectionBinding {
            setup_run_id: "run".into(),
            api_base_url: base.clone(),
            setup_run_token_expires_at: "".into(),
            machine_id: None,
            claim_code: None,
        },
    };
    let results =
        process_setup_actions(&daemon(), &base, &mut credentials, &test_machine()).unwrap();
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|action| action.status == "cancelled"));
    server.join().unwrap();
    fs::remove_dir_all(support.join("snapshots")).unwrap();
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::write(root.join(".codex/config.toml"), "model = \"synthetic\"\n").unwrap();
    let scan = build_local_scan(&test_machine(), vec![SourceKind::Codex]);
    assert!(scan.sources[0].detected);
    let _admin = EnvVarGuard::set_str("OTTTO_PATCH_CODEX_DISABLED", "1");
    assert!(build_local_scan(&test_machine(), vec![SourceKind::Codex])
        .sources
        .is_empty());
}

/// Each scan source carries the scan's own time beside the selected
/// status row, whose own (cached) captured_at is left as it was.
#[test]
#[serial]
fn setup_scan_sources_carry_scan_time_and_the_selected_status_row() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("setup-scan-selected-status");
    let _home = EnvVarGuard::set_path("HOME", &root);
    let _commands = EnvVarGuard::set_path("OTTTO_COMMAND_SEARCH_PATH", &root.join("bin"));
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let _secret = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &root.join("secrets"));
    let cached: AgentStatusSnapshot = serde_json::from_value(json!({
        "source": "pi", "status": "available", "collection_method": "config_file",
        "captured_at": "2026-11-13T00:00:00Z", "expires_at": "2026-11-13T00:15:00Z",
    }))
    .unwrap();
    let collection = crate::agent_status::AgentStatusCollection {
        snapshots: vec![cached.clone()],
        source_health_snapshot: cached.clone(),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
        setup_snapshot_index: Some(0),
    };
    let scan = crate::agent_status_refresh::with_collection(collection, || {
        build_local_scan(&test_machine(), vec![])
    });
    let scan = serde_json::to_value(&scan).unwrap();
    let sources = scan["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 3);
    for source in sources {
        let captured_at = source["captured_at"].as_str().expect("scan time");
        assert!(time::OffsetDateTime::parse(
            captured_at,
            &time::format_description::well_known::Rfc3339
        )
        .is_ok());
        assert_ne!(captured_at, "2026-11-13T00:00:00Z");
        assert_eq!(
            source["agent_status"],
            serde_json::to_value(cached.clone().redacted_for_backend()).unwrap()
        );
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[serial]
fn source_patch_disabled_parses_per_source_truthy_values() {
    let _lock = lock_backend_test_env();
    assert_eq!(source_patch_env_token(&SourceKind::Codex), Some("CODEX"));
    assert_eq!(
        source_patch_env_token(&SourceKind::ClaudeCode),
        Some("CLAUDE_CODE")
    );
    assert_eq!(source_patch_env_token(&SourceKind::Pi), None);
    assert!(!source_patch_disabled(&SourceKind::Codex));

    let _guard = EnvVarGuard::set_str("OTTTO_PATCH_CODEX_DISABLED", " yes ");
    assert!(source_patch_disabled(&SourceKind::Codex));
    assert!(!source_patch_disabled(&SourceKind::ClaudeCode));
    assert!(!source_patch_disabled(&SourceKind::Pi));
}

#[test]
#[serial]
fn codex_source_off_setup_and_manual_verification_do_not_probe_provider_or_backend() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("codex-source-off-verify");
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::write(root.join(".codex/config.toml"), "model = \"test-model\"\n").unwrap();
    let _commands = EnvVarGuard::set_path("OTTTO_COMMAND_SEARCH_PATH", &root.join("empty-bin"));
    let _home = EnvVarGuard::set_path("HOME", &root);
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let secret_root = root.join("secrets");
    fs::create_dir_all(&secret_root).unwrap();
    let _secret = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".into(),
            machine_id: None,
            sources: vec!["codex".into()],
        })
        .unwrap();
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("device_secret_test")
        .unwrap();
    let connection = LocalConnectionBinding {
        setup_run_id: "test".into(),
        setup_run_token_expires_at: "2000-01-01T00:00:00Z".into(),
        machine_id: None,
        claim_code: None,
        api_base_url: "http://127.0.0.1:1".into(),
    };
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(connection.clone()));
    let registered = scan_source(&SourceKind::Codex);
    assert_eq!(registered.live_telemetry_required, Some(false));
    assert_eq!(registered.local_import_ready, Some(true));
    assert!(!registered.telemetry_installed);
    let result = verify_source(
        &daemon,
        &RequestAuthorization::TrustedCompanionApp,
        SourceKind::Codex,
        false,
    )
    .unwrap();
    assert_eq!(result.message.code, "codex_local_import");
    assert!(!result.verified);
    assert_eq!(result.records_seen, 0);
    assert!(!verification_result_should_refresh_agent_status(&result));
    let mut credentials = SetupRunCredentials {
        connection,
        setup_run_token: "test".into(),
    };
    let action = SetupRunActionApiResponse {
        id: "test".into(),
        action_type: "verify_source".into(),
        source: Some("codex".into()),
    };
    let (status, _, payload, verification) = run_verify_source_action(
        &daemon,
        "http://127.0.0.1:1",
        &mut credentials,
        &action,
        SourceKind::Codex,
    )
    .unwrap();
    assert_eq!(status, "succeeded");
    assert_eq!(payload["verified"], false);
    assert_eq!(payload["records_seen"], 0);
    assert_eq!(payload["live_telemetry_required"], false);
    assert!(payload["smoke_after"].is_null());
    assert!(payload.get("check").is_none());
    // The setup completion says configuration only, never usage or an account.
    assert_eq!(
        verification.and_then(|result| result.check),
        Some(SourceVerificationCheck {
            method: Some(SourceVerificationMethod::ConfigurationCheck),
            scope: SourceVerificationScope::Configuration,
        })
    );
    let disconnected = self::daemon().with_connection(Some(credentials.connection.clone()));
    let (status, _, payload, verification) = run_verify_source_action(
        &disconnected,
        "http://127.0.0.1:1",
        &mut credentials,
        &action,
        SourceKind::Codex,
    )
    .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(payload["local_import_ready"], false);
    assert_eq!(payload["error_code"], "account_not_connected");
    assert_eq!(
        verification
            .and_then(|result| result.check)
            .map(|check| check.scope),
        Some(SourceVerificationScope::NotEstablished)
    );
    {
        let _disabled = EnvVarGuard::set_str("OTTTO_PATCH_CODEX_DISABLED", "1");
        let (status, _, payload, _) = run_verify_source_action(
            &daemon,
            "http://127.0.0.1:1",
            &mut credentials,
            &action,
            SourceKind::Codex,
        )
        .unwrap();
        assert_eq!(status, "failed");
        assert_eq!(payload["local_import_ready"], false);
        assert_eq!(payload["error_code"], "patch_disabled");
    }
    FileDeviceStore::default().reset().unwrap();
    assert_eq!(
        scan_source(&SourceKind::Codex).local_import_ready,
        Some(false)
    );
    let result = verify_source(
        &daemon,
        &RequestAuthorization::TrustedCompanionApp,
        SourceKind::Codex,
        false,
    )
    .unwrap();
    assert_eq!(result.message.code, "relay_device_not_provisioned");
    assert!(!result.verified);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn codex_source_off_respects_no_touch_override_at_startup() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("codex-source-off-no-touch");
    fs::create_dir_all(root.join(".codex")).unwrap();
    let _home = EnvVarGuard::set_path("HOME", &root);
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let _disabled = EnvVarGuard::set_str("OTTTO_PATCH_CODEX_DISABLED", "1");
    let path = root.join(".codex/config.toml");
    let body = render_codex_relay_toml_block_for_base("http://127.0.0.1:44621");
    fs::write(&path, &body).unwrap();
    assert!(!reconcile_codex_source_off_at_startup().unwrap());
    assert_eq!(fs::read_to_string(path).unwrap(), body);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn codex_source_off_rejects_enable_without_touching_control_token_or_key_store() {
    let result = telemetry_control(
        &daemon(),
        TelemetryControlAction::EnableTelemetry,
        SourceKind::Codex,
        "not-a-token".into(),
        None,
        None,
        None,
        None,
        None,
    );
    assert!(matches!(result, Err(LocalApiError::InvalidRequest(_))));
}

#[test]
fn claude_code_config_state_detects_settings_shape_without_env_fence_dependency() {
    let root = control_test_root("claude-config-state");
    fs::create_dir_all(&root).expect("create root");
    let missing = root.join("settings-missing.json");
    let default_base = crate::otlp_relay::default_local_relay_base_url();
    let support_dir = root.join("backups");

    let missing_state = claude_code_settings_config_state_at(
        &missing,
        "~/.claude/settings.json",
        &test_machine(),
        &default_base,
        &support_dir,
        false,
    );
    assert!(!missing_state.discovered);
    assert!(missing_state
        .drift
        .iter()
        .any(|drift| drift.key == "claude_code.settings_file"));

    let clean = root.join("settings.json");
    patch_claude_code_settings_at_with_relay_base(
        &clean,
        &test_machine(),
        &support_dir,
        &default_base,
        false,
    )
    .expect("seed clean settings");
    let clean_body = fs::read_to_string(&clean).expect("read clean settings");
    let clean_state = claude_code_settings_config_state_at(
        &clean,
        "~/.claude/settings.json",
        &test_machine(),
        &default_base,
        &support_dir,
        false,
    );
    assert!(clean_state.discovered);
    assert!(clean_state.drift.is_empty());
    assert!(!root.join(".ottto/claude-telemetry.env").exists());
    assert!(!root.join(".zshrc").exists());
    assert_eq!(
        fs::read_to_string(&clean).expect("read clean again"),
        clean_body
    );

    fs::remove_file(claude_statusline_wrapper_path(&support_dir))
        .expect("remove statusLine wrapper");
    let missing_wrapper_state = claude_code_settings_config_state_at(
        &clean,
        "~/.claude/settings.json",
        &test_machine(),
        &default_base,
        &support_dir,
        false,
    );
    assert!(missing_wrapper_state
        .drift
        .iter()
        .any(|drift| drift.key == "statusLine.wrapper"));
    patch_claude_code_settings_at_with_relay_base(
        &clean,
        &test_machine(),
        &support_dir,
        &default_base,
        false,
    )
    .expect("restore clean wrapper");

    let fallback_base = "http://127.0.0.1:44621";
    let wrong_relay_state = claude_code_settings_config_state_at(
        &clean,
        "~/.claude/settings.json",
        &test_machine(),
        fallback_base,
        &support_dir,
        false,
    );
    assert!(wrong_relay_state
        .drift
        .iter()
        .any(|drift| drift.key == "env.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"));

    let value: serde_json::Value = serde_json::from_str(&clean_body).expect("settings json");
    let env = value.get("env").expect("env");
    fs::write(&clean, serde_json::json!({ "env": env }).to_string())
        .expect("write env-only settings");
    let missing_statusline = claude_code_settings_config_state_at(
        &clean,
        "~/.claude/settings.json",
        &test_machine(),
        &default_base,
        &support_dir,
        false,
    );
    assert!(missing_statusline
        .drift
        .iter()
        .any(|drift| drift.key == "statusLine.command"));

    fs::write(&clean, "{").expect("write invalid json");
    let invalid_state = claude_code_settings_config_state_at(
        &clean,
        "~/.claude/settings.json",
        &test_machine(),
        &default_base,
        &support_dir,
        false,
    );
    assert!(invalid_state
        .drift
        .iter()
        .any(|drift| drift.key == "claude_code.settings_json"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn patch_disabled_config_state_reports_no_drift_for_codex_and_claude() {
    let root = control_test_root("patch-disabled-config-state");
    fs::create_dir_all(&root).expect("create root");
    let codex_path = root.join("config.toml");
    let claude_path = root.join("settings.json");
    fs::write(&codex_path, "[otel\n").expect("write invalid codex");
    fs::write(&claude_path, "{").expect("write invalid claude");
    let default_base = crate::otlp_relay::default_local_relay_base_url();

    let codex = codex_config_state_at(&codex_path, "~/.codex/config.toml", &default_base, true);
    let claude = claude_code_settings_config_state_at(
        &claude_path,
        "~/.claude/settings.json",
        &test_machine(),
        &default_base,
        &root.join("support"),
        true,
    );

    assert!(codex.discovered);
    assert!(codex.drift.is_empty());
    assert!(claude.discovered);
    assert!(claude.drift.is_empty());
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[serial]
fn verify_repair_repairs_codex_config_before_account_check() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("verify-repair-codex");
    create_control_test_dir(&root.join(".codex"));
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard =
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let config_path = root.join(".codex/config.toml");
    fs::write(
        &config_path,
        render_codex_relay_toml_block_for_base("http://127.0.0.1:44621"),
    )
    .expect("legacy config");

    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_verify_repair_codex".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Verify {
                source: SourceKind::Codex,
                repair: true,
            },
        },
    );

    assert!(response.ok, "{response:?}");
    let result: SourceVerificationResult =
        serde_json::from_value(response.payload.expect("payload")).expect("verification result");
    assert_eq!(result.message.code, "account_not_connected");
    assert!(result.config.drift.is_empty());
    let body = fs::read_to_string(&config_path).expect("read repaired config");
    assert!(!body.contains("/v1/logs"));
    assert!(!body.contains("/v1/traces"));
    assert!(!body.contains("/v1/metrics"));
    let _ = fs::remove_dir_all(&root);
}

fn assert_setup_denies_unauthorized_callers_before_scan_lock() {
    let files = ControlFilesFixture::new();
    let daemon = daemon();
    for (authorization, expected) in [
        (
            RequestAuthorization::Untrusted,
            CliErrorCode::LocalClientNotTrusted,
        ),
        (
            RequestAuthorization::Token("wrong-token".into()),
            CliErrorCode::LocalAuthFailed,
        ),
    ] {
        thread::scope(|scope| {
            let held = SETUP_SCAN.lock().unwrap();
            let (send, receive) = std::sync::mpsc::channel();
            let daemon = &daemon;
            let files = &files;
            scope.spawn(move || {
                let result = files
                    .assert_unchanged(|| {
                        setup_run(daemon, &authorization, vec![], None, None, None)
                    })
                    .map_err(|error| cli_error(error).code);
                send.send(result).unwrap();
            });
            // The caller must be refused while another setup still owns the lock.
            let result = receive.recv_timeout(Duration::from_secs(5));
            drop(held); // Release before asserting so a regression cannot deadlock the test.
            assert_eq!(
                result.expect("authorization waited for setup scan"),
                Err(expected)
            );
        });
        assert!(SETUP_SCAN.try_lock().is_ok(), "refused setup kept the lock");
    }
    let state = daemon.inner.lock().unwrap();
    assert!(state.sources.is_empty());
    assert!(state.local_health_events.is_empty());
    assert!(state.command_ledger.is_empty());
}

fn assert_verification_denies_unauthorized_callers() {
    let files = ControlFilesFixture::new();
    let daemon = daemon();
    for (authorization, expected) in [
        (
            RequestAuthorization::Untrusted,
            CliErrorCode::LocalClientNotTrusted,
        ),
        (
            RequestAuthorization::Token("wrong-token".into()),
            CliErrorCode::LocalAuthFailed,
        ),
    ] {
        for repair in [false, true] {
            let error = files
                .assert_unchanged(|| {
                    verify_source(&daemon, &authorization, SourceKind::Codex, repair)
                })
                .expect_err("verification must authorize before any result write");
            assert_eq!(cli_error(error).code, expected);
            let state = daemon.inner.lock().unwrap();
            assert!(
                !state.repair_locked,
                "refused verification kept the repair lock"
            );
            assert!(
                state.sources.is_empty(),
                "refused verification changed health"
            );
            assert!(state.local_health_events.is_empty());
            assert!(
                state.command_ledger.is_empty(),
                "refused verification recorded a result"
            );
        }
    }
}

#[test]
#[serial]
fn verify_json_exposes_canonical_health_failure() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("verify-canonical-health");
    create_control_test_dir(&root.join(".codex"));
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard =
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let config_path = root.join(".codex/config.toml");
    let original = render_codex_relay_toml_block_for_base("http://127.0.0.1:44621");
    fs::write(&config_path, &original).expect("legacy config");
    assert_verification_denies_unauthorized_callers();
    assert_eq!(fs::read_to_string(&config_path).unwrap(), original);

    let response = handle_request(
        &daemon().with_account(connected_account()),
        LocalControlRequest {
            request_id: "req_verify_canonical".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Verify {
                source: SourceKind::Codex,
                repair: false,
            },
        },
    );

    assert!(response.ok, "{response:?}");
    let payload = response.payload.expect("payload");
    assert_eq!(
        payload.get("status").and_then(serde_json::Value::as_str),
        Some("failed")
    );
    assert_eq!(
        payload
            .get("canonical_health")
            .and_then(|health| health.get("overall"))
            .and_then(|overall| overall.get("state"))
            .and_then(serde_json::Value::as_str),
        Some("blocked")
    );
    assert!(payload
        .get("canonical_health")
        .and_then(|health| health.get("blockers"))
        .and_then(serde_json::Value::as_array)
        .expect("blockers array")
        .iter()
        .any(
            |blocker| blocker.get("code").and_then(serde_json::Value::as_str)
                == Some("config_drift")
        ));
    assert!(payload
        .get("local_health_events")
        .and_then(serde_json::Value::as_array)
        .expect("events array")
        .iter()
        .any(
            |event| event.get("event_type").and_then(serde_json::Value::as_str)
                == Some("VerifyFailed")
        ));
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[serial]
fn verify_patch_disabled_skips_repair_writes() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("verify-patch-disabled");
    create_control_test_dir(&root.join(".codex"));
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard =
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let _disabled_guard = EnvVarGuard::set_str("OTTTO_PATCH_CODEX_DISABLED", "1");
    let config_path = root.join(".codex/config.toml");
    let original = "[otel\n";
    fs::write(&config_path, original).expect("write invalid config");
    assert_verification_denies_unauthorized_callers();

    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_verify_patch_disabled".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Verify {
                source: SourceKind::Codex,
                repair: true,
            },
        },
    );

    assert!(response.ok);
    let result: SourceVerificationResult =
        serde_json::from_value(response.payload.expect("payload")).expect("verification result");
    assert_eq!(result.message.code, "patch_disabled");
    assert!(result.config.drift.is_empty());
    assert_eq!(
        fs::read_to_string(&config_path).expect("read config"),
        original
    );
    let _ = fs::remove_dir_all(&root);
}

mod tracking_confirmation_tests {
    use super::*;

    #[test]
    #[serial]
    fn repair_confirmation_arms_only_final_eligible_non_dry_run_plans() {
        let _lock = lock_backend_test_env();
        let root = control_test_root("repair-confirmation-arm");
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
        let daemon = daemon();
        let authorization = RequestAuthorization::TrustedCompanionApp;
        let mut plan = propose_repair_plan(&daemon, &authorization, SourceKind::Pi, true).unwrap();
        FileDeviceStore::default()
            .save(&LocalDeviceBinding {
                device_id: "device_test".into(),
                machine_id: None,
                sources: vec!["claude_code".into(), "codex".into(), "pi".into()],
            })
            .unwrap();
        for source in [SourceKind::ClaudeCode, SourceKind::Codex, SourceKind::Pi] {
            for status in [
                RepairPlanStatus::Succeeded,
                RepairPlanStatus::Running,
                RepairPlanStatus::Proposed,
            ] {
                plan.status = status;
                plan.dry_run = true;
                daemon.arm_tracking_confirmation(&source, &plan).unwrap();
                assert!(daemon.tracking_episode(&source).is_none());
                plan.dry_run = false;
                daemon.arm_tracking_confirmation(&source, &plan).unwrap();
                assert!(daemon.tracking_episode(&source).is_some());
                daemon.clear_tracking_confirmation(&source).unwrap();
            }
            for status in [RepairPlanStatus::Failed, RepairPlanStatus::Blocked] {
                plan.status = status;
                daemon.arm_tracking_confirmation(&source, &plan).unwrap();
                assert!(daemon.tracking_episode(&source).is_none());
            }
        }
        plan.status = RepairPlanStatus::Proposed;
        crate::snapshot_sync::disable_snapshot_source(&root, crate::snapshots::SnapshotSource::Pi)
            .unwrap();
        daemon
            .arm_tracking_confirmation(&SourceKind::Pi, &plan)
            .unwrap();
        assert!(daemon.tracking_episode(&SourceKind::Pi).is_none());
        FileDeviceStore::default().reset().unwrap();
        daemon
            .arm_tracking_confirmation(&SourceKind::Codex, &plan)
            .unwrap();
        assert!(daemon.tracking_episode(&SourceKind::Codex).is_none());
        fs::write(ottto_core::default_device_path(), b"{").unwrap();
        daemon
            .arm_tracking_confirmation(&SourceKind::Codex, &plan)
            .expect("observation cannot fail a completed Repair");
        assert!(daemon.tracking_episode(&SourceKind::Codex).is_none());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
#[serial]
fn fix_non_dry_run_executes_claude_write_config_repair() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("fix-claude-config");
    create_control_test_dir(&root.join(".claude"));
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard =
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let settings_path = root.join(".claude/settings.json");
    fs::write(&settings_path, r#"{"env":{"EXISTING":"keep"}}"#).expect("write drifted settings");

    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_fix_claude".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Repair {
                source: SourceKind::ClaudeCode,
                dry_run: false,
            },
        },
    );

    assert!(response.ok);
    let plan: RepairPlan =
        serde_json::from_value(response.payload.expect("payload")).expect("repair plan");
    assert_eq!(plan.status, RepairPlanStatus::Succeeded);
    assert_eq!(plan.actions.len(), 1);
    assert_eq!(plan.actions[0].action, RepairActionKind::WriteConfig);
    let state = claude_code_settings_config_state_at(
        &settings_path,
        "~/.claude/settings.json",
        &test_machine(),
        &crate::otlp_relay::default_local_relay_base_url(),
        &root.join("support"),
        false,
    );
    assert!(state.drift.is_empty());

    fs::remove_file(claude_statusline_wrapper_path(&root.join("support")))
        .expect("remove statusLine wrapper");
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_fix_claude_missing_wrapper".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Repair {
                source: SourceKind::ClaudeCode,
                dry_run: false,
            },
        },
    );
    assert!(response.ok);
    let plan: RepairPlan =
        serde_json::from_value(response.payload.expect("payload")).expect("repair plan");
    assert_eq!(plan.status, RepairPlanStatus::Succeeded);
    assert!(claude_statusline_wrapper_path(&root.join("support")).is_file());
    let state = claude_code_settings_config_state_at(
        &settings_path,
        "~/.claude/settings.json",
        &test_machine(),
        &crate::otlp_relay::default_local_relay_base_url(),
        &root.join("support"),
        false,
    );
    assert!(state.drift.is_empty());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn install_source_action_result_uses_setup_safe_metadata_keys() {
    let result = install_source_action_result(
        "install_session_test",
        "device_test",
        "codex",
        true,
        43119,
        "Codex telemetry setup installed",
        true,
    );
    let object = result.as_object().expect("result object");
    for key in object.keys() {
        let lower = key.to_ascii_lowercase();
        for forbidden in [
            "authorization",
            "bearer",
            "cookie",
            "device_secret",
            "header",
            "key",
            "password",
            "secret",
            "token",
        ] {
            assert!(
                !lower.contains(forbidden),
                "install action result key should be backend-safe: {key}"
            );
        }
    }
    assert_eq!(
        object
            .get("relay_source")
            .and_then(serde_json::Value::as_str),
        Some("codex")
    );
    assert!(!object.contains_key("relay_source_header"));
    assert!(!object.contains_key("error_code"));
    assert!(!object.contains_key("error_message"));

    let failed = install_source_action_result(
        "install_session_test",
        "device_test",
        "codex",
        false,
        43119,
        "Codex relay unavailable",
        true,
    );
    assert_eq!(
        failed.get("error_code").and_then(serde_json::Value::as_str),
        Some("relay_unavailable")
    );
}

#[test]
fn pi_install_source_registers_device_without_config_patch() {
    assert!(source_requires_device_registration(&SourceKind::Pi));
    assert!(!source_requires_config_patch(&SourceKind::Pi));

    let result = install_source_registration_result(
        "install_session_test",
        "device_test",
        "pi",
        "Pi local session import prepared",
    );
    let object = result.as_object().expect("result object");
    for key in object.keys() {
        let lower = key.to_ascii_lowercase();
        for forbidden in [
            "authorization",
            "bearer",
            "cookie",
            "device_secret",
            "header",
            "key",
            "password",
            "secret",
            "token",
        ] {
            assert!(
                !lower.contains(forbidden),
                "install action result key should be backend-safe: {key}"
            );
        }
    }
    assert_eq!(
        object.get("source").and_then(serde_json::Value::as_str),
        Some("pi")
    );
    assert_eq!(
        object
            .get("local_changes")
            .and_then(serde_json::Value::as_str),
        Some("registered")
    );
    assert_eq!(
        object
            .get("config_patched")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        object
            .get("relay_required")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
}

#[test]
fn smoke_command_failure_maps_to_failed_verification_result() {
    let smoke = SmokeResult {
        command_found: true,
        succeeded: false,
        exit_status: Some(1),
        duration_ms: 12,
        message: "Pi smoke session failed before verification could complete.".to_string(),
        diagnostic: Some("Token is expired.".to_string()),
        error_code: Some("smoke_command_failed".to_string()),
        local_session_observed: Some(false),
    };

    let result = smoke_failure_verification_result(
        SourceKind::Pi,
        &smoke,
        Some("2026-05-06T12:00:00Z".to_string()),
    );

    assert_eq!(result.status, SourceVerificationStatus::Failed);
    assert!(!result.verified);
    assert_eq!(result.message.code, "smoke_command_failed");
    assert_eq!(result.records_seen, 0);
}

#[test]
fn claude_expired_oauth_maps_to_source_reconnect_required() {
    assert!(command_diagnostic_requires_claude_reauth(Some(
        "Failed to authenticate: OAuth session expired and could not be refreshed"
    )));
    assert!(command_diagnostic_requires_claude_reauth(Some(
        "Token is expired. Run /login to sign in again."
    )));
    assert!(!command_diagnostic_requires_claude_reauth(Some(
        "Unable to fetch usage credits due to network error"
    )));

    let mut smoke = SmokeResult {
        command_found: true,
        succeeded: false,
        exit_status: Some(1),
        duration_ms: 12,
        message: "The Claude Code test run failed before Ottto could check it.".to_string(),
        diagnostic: Some(
            "Failed to authenticate: OAuth session expired and could not be refreshed".to_string(),
        ),
        error_code: Some("smoke_command_failed".to_string()),
        local_session_observed: None,
    };
    classify_source_smoke_failure(&SourceKind::ClaudeCode, &mut smoke);

    let result = smoke_failure_verification_result(
        SourceKind::ClaudeCode,
        &smoke,
        Some("2026-09-14T12:00:00Z".to_string()),
    );

    assert_eq!(result.status, SourceVerificationStatus::ReconnectRequired);
    assert!(!result.verified);
    assert_eq!(result.message.code, CLAUDE_OAUTH_REAUTH_REQUIRED_CODE);
    assert_eq!(result.message.text, "Claude Code sign-in expired. Open Claude Code, sign in again, then retry Verify. Ottto itself is still connected.");
}

#[test]
#[serial]
fn claude_signed_out_smoke_requires_provider_sign_in() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("claude-ottto-connected-smoke");
    let fake_claude = fake_binary_path(&root, "claude");
    fs::write(
        &fake_claude,
        "#!/bin/sh\n: > \"$HOME/spawned\"\necho 'Not logged in · Please run /login' >&2\nexit 1\n",
    )
    .unwrap();
    let fake_security = fake_binary_path(&root, "security");
    fs::write(&fake_security, "#!/bin/sh\nexit 44\n").unwrap();
    for path in [&fake_claude, &fake_security] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let _home = EnvVarGuard::set_path("HOME", &root);
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let _search = EnvVarGuard::set_path("OTTTO_COMMAND_SEARCH_PATH", fake_claude.parent().unwrap());
    for diagnostic in [
        "Not logged in · Please run /login",
        "not signed in",
        "NOT SIGNED IN. Please run /login",
        "Not logged in\nPlease run /login",
    ] {
        let mut smoke = SmokeResult {
            command_found: true,
            succeeded: false,
            exit_status: Some(1),
            duration_ms: 12,
            message: "Claude Code smoke session failed.".into(),
            diagnostic: Some(diagnostic.into()),
            error_code: Some("smoke_command_failed".into()),
            local_session_observed: None,
        };
        classify_source_smoke_failure(&SourceKind::ClaudeCode, &mut smoke);
        let result = smoke_failure_verification_result(SourceKind::ClaudeCode, &smoke, None);
        assert_eq!(
            result.status,
            SourceVerificationStatus::ReconnectRequired,
            "{diagnostic}"
        );
        assert_eq!(result.message.code, CLAUDE_OAUTH_REAUTH_REQUIRED_CODE);
        assert_eq!(result.message.text, "Claude Code is not signed in. Open Claude Code, sign in, then retry Verify. Ottto itself is still connected.");
        let daemon = daemon().with_account(connected_account());
        daemon.record_verification_result(&result).unwrap();
        let status = daemon.status("token").unwrap();
        let health = status
            .sources
            .iter()
            .find(|health| health.source == SourceKind::ClaudeCode)
            .unwrap();
        assert_eq!(
            health.recommended_actions[0].action,
            RepairActionKind::ReauthProvider
        );
        assert_eq!(health.state, ottto_protocol::SourceState::Failed);
    }
    let daemon = daemon().with_account(connected_account());
    let snapshot: AgentStatusSnapshot = serde_json::from_value(json!({
        "source": "claude_code", "status": "available", "collection_method": "command_probe",
        "captured_at": "2026-11-13T00:00:00Z", "expires_at": "2026-11-13T00:15:00Z",
        "account": {"login_state": "signed_out", "confidence": "low"},
        "diagnostics": [{"code": crate::agent_status::CLAUDE_OTTTO_SIGNED_IN,
            "severity": "info", "message": "1 Claude account signed in through Ottto"}]
    }))
    .unwrap();
    let mut initial = verification_result(
        SourceKind::ClaudeCode,
        SourceVerificationStatus::Failed,
        false,
        0,
        None,
        None,
        None,
        "smoke_command_failed",
        "old failed check",
    );
    for (code, clears) in [
        ("smoke_command_failed", false),
        (CLAUDE_OAUTH_REAUTH_REQUIRED_CODE, true),
    ] {
        initial.message.code = code.into();
        daemon.record_verification_result(&initial).unwrap();
        daemon.record_agent_status_health(snapshot.clone()).unwrap();
        let status = daemon.status("token").unwrap();
        assert_eq!(
            status.sources[0].state,
            if clears {
                ottto_protocol::SourceState::NeedsConfirmation
            } else {
                ottto_protocol::SourceState::Failed
            }
        );
        if clears {
            let canonical = status.canonical_health.unwrap();
            assert_ne!(
                canonical.overall.next_action.as_deref(),
                Some("finish_source_setup")
            );
        }
    }
    assert!(!root.join("spawned").exists());
    let smoke = run_verification_smoke_prompt(&daemon, &SourceKind::ClaudeCode).unwrap();
    assert_eq!(smoke.duration_ms, 0);
    assert_eq!(smoke.exit_status, None);
    assert!(!root.join("spawned").exists());
    initial = smoke_failure_verification_result(SourceKind::ClaudeCode, &smoke, None);
    attach_verification_check(&mut initial);
    assert_eq!(initial.status, SourceVerificationStatus::Warning);
    assert!(!initial.verified);
    assert_eq!(
        initial.message.code,
        crate::agent_status::CLAUDE_OTTTO_SIGNED_IN
    );
    assert_eq!(
        initial.check.as_ref().unwrap().scope,
        SourceVerificationScope::NotEstablished
    );
    daemon.record_verification_result(&initial).unwrap();
    let status = daemon.status("token").unwrap();
    let health = &status.sources[0];
    assert_eq!(health.state, ottto_protocol::SourceState::NeedsConfirmation);
    assert_eq!(health.grade, ottto_protocol::HealthGrade::Warning);
    assert_eq!(health.problems.len(), 1);
    assert_eq!(
        health.problems[0].code,
        ottto_protocol::StableProblemCode::AgentCliUnavailable
    );
    assert!(health.recommended_actions.is_empty());
    let canonical_health = status.canonical_health.unwrap();
    assert_ne!(
        canonical_health.overall.severity,
        ottto_protocol::LocalHealthSeverity::Blocking
    );
    assert_ne!(
        canonical_health.overall.next_action.as_deref(),
        Some("finish_source_setup")
    );
    let canonical = &canonical_health.sources[0];
    assert_eq!(
        canonical.state,
        ottto_protocol::LocalHealthSourceState::PendingSetup
    );
    assert!(canonical.next_action.is_none());
    for (has_slot, login) in [(false, "signed_out"), (true, "unsupported")] {
        let mut saved = serde_json::to_value(&snapshot).unwrap();
        saved["account"]["login_state"] = json!(login);
        if !has_slot {
            saved["diagnostics"] = json!([]);
        }
        daemon.state().unwrap().sources[0].agent_status =
            Some(serde_json::from_value(saved).unwrap());
        let smoke = run_verification_smoke_prompt(&daemon, &SourceKind::ClaudeCode).unwrap();
        assert!(root.join("spawned").exists());
        assert_eq!(
            smoke.error_code.as_deref(),
            Some(CLAUDE_OAUTH_REAUTH_REQUIRED_CODE)
        );
        fs::remove_file(root.join("spawned")).unwrap();
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn smoke_sign_in_classifier_preserves_other_failures_and_success() {
    for (source, succeeded, diagnostic, code) in [
        (
            SourceKind::ClaudeCode,
            false,
            "Network connection failed",
            "smoke_command_failed",
        ),
        (
            SourceKind::ClaudeCode,
            false,
            "You've hit your usage limit",
            SMOKE_USAGE_LIMIT_ERROR_CODE,
        ),
        (
            SourceKind::ClaudeCode,
            false,
            "Help: run /login to manage your account",
            "smoke_command_failed",
        ),
        (
            SourceKind::ClaudeCode,
            true,
            "stdout: Not logged in · Please run /login",
            "smoke_command_failed",
        ),
        (
            SourceKind::Codex,
            false,
            "Not logged in · Please run /login",
            "smoke_command_failed",
        ),
        (
            SourceKind::Pi,
            false,
            "Not signed in",
            "smoke_command_failed",
        ),
    ] {
        let mut smoke = SmokeResult {
            command_found: true,
            succeeded,
            exit_status: Some(if succeeded { 0 } else { 1 }),
            duration_ms: 12,
            message: "Original smoke result".into(),
            diagnostic: Some(diagnostic.into()),
            error_code: Some(code.into()),
            local_session_observed: None,
        };
        classify_source_smoke_failure(&source, &mut smoke);
        assert_eq!(
            smoke.error_code.as_deref(),
            Some(code),
            "{source:?}: {diagnostic}"
        );
        assert_eq!(smoke.message, "Original smoke result");
    }
}

#[test]
fn usage_limited_smoke_failure_maps_to_warning_verification_result() {
    let smoke = SmokeResult {
        command_found: true,
        succeeded: false,
        exit_status: None,
        duration_ms: 45_000,
        message: usage_limited_smoke_message("Codex"),
        diagnostic: Some(
            "ERROR: You've hit your usage limit. Visit settings to purchase more credits."
                .to_string(),
        ),
        error_code: Some(SMOKE_USAGE_LIMIT_ERROR_CODE.to_string()),
        local_session_observed: None,
    };

    assert!(command_diagnostic_is_usage_limited(
        smoke.diagnostic.as_deref()
    ));
    assert!(command_diagnostic_is_usage_limited(Some(&format!(
        "{} ERROR: You've hit your usage limit. Visit settings to purchase more credits.",
        "OpenAI Codex startup noise ".repeat(80)
    ))));
    assert!(command_diagnostic_is_usage_limited(Some(
        "Claude Code smoke session failed: You've hit your weekly limit · resets 8am (Asia/Jerusalem)"
    )));
    // Anthropic org spend-cap wording (2026): quota exhaustion, not setup
    // breakage — it must classify as usage-limited so it never renders as
    // a blocking Critical failure in the companion app.
    assert!(command_diagnostic_is_usage_limited(Some(
        "You've hit your org's monthly spend limit · run [path] to raise it, or visit claude.ai/admin-settings/usage"
    )));
    assert!(command_diagnostic_is_usage_limited(Some(
        "Your credit balance is too low to access the Anthropic API."
    )));
    assert!(command_diagnostic_is_usage_limited(Some(
        "You're out of extra usage credits."
    )));
    assert!(!command_diagnostic_is_usage_limited(Some(
        "Token is expired. Run /login to sign in again."
    )));
    // Mentioning balances/credits/limits in a transient fetch or auth
    // error is NOT quota exhaustion and must stay a real failure.
    assert!(!command_diagnostic_is_usage_limited(Some(
        "Failed to fetch credit balance: authentication expired"
    )));
    assert!(!command_diagnostic_is_usage_limited(Some(
        "Unable to read usage credits due to network error"
    )));
    assert!(!command_diagnostic_is_usage_limited(Some(
        "Unable to fetch spend limit: authentication expired"
    )));

    let result = smoke_failure_verification_result(
        SourceKind::Codex,
        &smoke,
        Some("2026-05-06T12:00:00Z".to_string()),
    );

    assert_eq!(result.status, SourceVerificationStatus::Warning);
    assert!(!result.verified);
    assert_eq!(result.message.code, SMOKE_USAGE_LIMIT_ERROR_CODE);
    assert_eq!(
        result.message.text,
        "Codex is signed in, but its usage limit is reached. Wait for quota to reset or update usage, then retry Verify."
    );
}

#[test]
fn expired_setup_run_token_maps_to_reconnect_required_verification() {
    let error = LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: "/api/v1/setup-runs/[id]/local-client/verification".to_string(),
        status: Some(401),
        body_excerpt: Some("Setup run companion token expired".to_string()),
        reason_code: None,
    });

    let result = verification_result_for_backend_error(
        SourceKind::Codex,
        Some("2026-05-08T20:00:00Z".to_string()),
        &error,
    );

    assert_eq!(result.status, SourceVerificationStatus::ReconnectRequired);
    assert!(!result.verified);
    assert_eq!(result.message.code, "setup_run_token_expired");
}

#[test]
#[serial]
fn only_the_companion_repair_press_overrides_a_rebuild_loop_pause() {
    use crate::snapshots::{ScanIndex, ScanIndexLoadOrigin, SnapshotSource};
    let _lock = lock_backend_test_env();
    let root = control_test_root("repair-rebuild-loop-override");
    create_control_test_dir(&root.join(".codex"));
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    fs::write(root.join(".codex/config.toml"), "model = \"gpt-6.1-sol\"\n")
        .expect("seed clean config");
    // Hold-budget damage: valid JSON whose session-identity fields an
    // override can strictly recover; syntax damage cannot.
    let mut damage = serde_json::to_value(ScanIndex::default()).expect("index value");
    damage["files"]["excess-held"] = serde_json::json!({"unknown": "x".repeat(2 * 1024 * 1024)});
    let damage = serde_json::to_vec(&damage).expect("damaged index bytes");
    // A second whole-index incident inside 24 hours pauses the source.
    let pause = |source: SnapshotSource| {
        let path = root.join(format!("{}-scan-index.json", source.api_slug()));
        crate::snapshots::e2_pipeline_scan_fixture::bind_source_for_test(&path, source);
        crate::snapshots::e2_pipeline_scan_fixture::legacy_input_for_test(&path, b"{");
        let (_, origin) =
            crate::snapshots::e2_pipeline_scan_fixture::load_source_for_test(&path, source, &root)
                .expect("first incident publishes and then adopts fresh native custody");
        assert_eq!(origin, ScanIndexLoadOrigin::Loaded);
        crate::snapshots::e2_pipeline_scan_fixture::legacy_input_for_test(&path, &damage);
        path
    };
    let refused = |path: &Path, source: SnapshotSource| {
        let error = ScanIndex::load_for_snapshot_source_with_origin(path, source, &root)
            .expect_err("the guard refuses");
        assert!(format!("{error:#}").contains("scan_index_rebuild_loop"));
        assert!(crate::snapshots::scan_index_rebuild_paused(source));
        assert_eq!(fs::read(path).expect("index kept"), damage);
    };
    let daemon = daemon();
    let repair = |token: Option<&str>,
                  client_kind: LocalClientKind,
                  dry_run: bool,
                  peer: Option<LocalClientPeer>| {
        let response = handle_request_with_peer(
            &daemon,
            LocalControlRequest {
                request_id: "req_repair_rebuild_loop".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: token.map(str::to_string),
                client_kind: Some(client_kind),
                client_install_owner: None,
                command: LocalControlCommand::Repair {
                    source: SourceKind::Pi,
                    dry_run,
                },
            },
            peer,
        );
        assert!(response.ok, "{response:?}");
        serde_json::from_value::<RepairPlan>(response.payload.expect("payload"))
            .expect("repair plan")
    };

    // Verify, even with repair, is not the Repair press.
    let codex = pause(SnapshotSource::Codex);
    refused(&codex, SnapshotSource::Codex);
    let result = verify_source(
        &daemon,
        &RequestAuthorization::TrustedCompanionApp,
        SourceKind::Codex,
        true,
    )
    .expect("verification returns account state");
    assert_eq!(result.status, SourceVerificationStatus::AccountNotConnected);
    refused(&codex, SnapshotSource::Codex);

    let pi = pause(SnapshotSource::Pi);
    refused(&pi, SnapshotSource::Pi);
    // The token-authorized CLI or agent Repair keeps its ordinary path.
    let cli = repair(Some("token"), LocalClientKind::Cli, false, None);
    assert_eq!(cli.authority.message.code, "pi_provider_reauth_required");
    refused(&pi, SnapshotSource::Pi);
    // A companion dry run proposes only.
    let proposed = repair(
        None,
        LocalClientKind::CompanionApp,
        true,
        Some(LocalClientPeer::trusted_for_tests()),
    );
    assert_eq!(proposed.status, RepairPlanStatus::Proposed);
    refused(&pi, SnapshotSource::Pi);
    assert_eq!(
        crate::snapshots::scan_index_rebuild_manual_override_count(),
        0
    );

    // The interactive press arms exactly one gated rebuild.
    let armed = repair(
        None,
        LocalClientKind::CompanionApp,
        false,
        Some(LocalClientPeer::trusted_for_tests()),
    );
    assert_eq!(armed.status, RepairPlanStatus::Running);
    assert_eq!(
        armed.authority.message.code,
        "scan_index_rebuild_override_armed"
    );
    assert!(armed.actions.is_empty());
    let again = repair(
        None,
        LocalClientKind::CompanionApp,
        false,
        Some(LocalClientPeer::trusted_for_tests()),
    );
    assert_eq!(again.status, RepairPlanStatus::Blocked);
    assert_eq!(
        again.authority.message.code,
        "scan_index_rebuild_override_cooldown"
    );
    let (index, origin) = crate::snapshots::e2_pipeline_scan_fixture::load_source_for_test(
        &pi,
        SnapshotSource::Pi,
        &root,
    )
    .expect("the armed press publishes and the next pass adopts the carried rebuild");
    assert_eq!(origin, ScanIndexLoadOrigin::Loaded);
    assert!(index.files.is_empty());
    assert!(!crate::snapshots::scan_index_rebuild_paused(
        SnapshotSource::Pi
    ));
    assert_eq!(
        crate::snapshots::scan_index_rebuild_manual_override_count(),
        1
    );
    // Codex was never armed: Verify spent nothing.
    refused(&codex, SnapshotSource::Codex);

    // A fresh failure inside 24 hours of the override refuses again,
    // and a press inside 24 hours names the cooldown and the retry time.
    crate::snapshots::e2_pipeline_scan_fixture::legacy_input_for_test(&pi, &damage);
    refused(&pi, SnapshotSource::Pi);
    let cooling = repair(
        None,
        LocalClientKind::CompanionApp,
        false,
        Some(LocalClientPeer::trusted_for_tests()),
    );
    assert_eq!(cooling.status, RepairPlanStatus::Blocked);
    assert_eq!(
        cooling.authority.message.code,
        "scan_index_rebuild_override_cooldown"
    );
    assert!(cooling
        .authority
        .message
        .text
        .contains("retries by itself at"));
    refused(&pi, SnapshotSource::Pi);
    assert_eq!(
        crate::snapshots::scan_index_rebuild_manual_override_count(),
        1
    );
    // Another source's syntax refusal returns its actual reason again on
    // the next companion press; it never claims Repair was already used.
    fs::write(&codex, b"{ ").expect("unrecoverable identity");
    assert_eq!(
        crate::snapshots::arm_scan_index_rebuild_manual_override(
            SnapshotSource::Codex,
            SystemTime::now()
        ),
        crate::snapshots::ScanIndexRebuildOverride::Armed
    );
    assert!(
        ScanIndex::load_for_snapshot_source_with_origin(&codex, SnapshotSource::Codex, &root)
            .is_err()
    );
    let plan = propose_repair_plan(
        &daemon,
        &RequestAuthorization::TrustedCompanionApp,
        SourceKind::Codex,
        false,
    )
    .expect("ordinary repair plan");
    // Reuse the ordinary plan's authority; the override only changes its
    // result and message after the signed-companion origin check.
    let plan = scan_index_rebuild_override_repair(
        &daemon,
        &RequestAuthorization::TrustedCompanionApp,
        &SourceKind::Codex,
        &plan,
    );
    let plan = plan.expect("paused source has an override result");
    assert_eq!(plan.status, RepairPlanStatus::Blocked);
    assert_eq!(
        plan.authority.message.code,
        "scan_index_rebuild_override_identity_unrecoverable"
    );
    assert!(!plan.authority.message.text.contains("already used"));
    assert!(!plan.authority.message.text.contains("will be rebuilt"));
    assert!(!plan.authority.message.text.contains("Armed"));
    assert!(plan.authority.message.text.contains("too damaged"));
    assert!(plan.authority.message.text.contains("retries by itself at"));
    let _ = fs::remove_dir_all(&root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
#[serial]
fn daemon_internal_verification_leaves_a_paused_index_for_the_companion() {
    use crate::snapshots::{ScanIndex, ScanIndexLoadOrigin, SnapshotSource};
    let _lock = lock_backend_test_env();
    let root = control_test_root("internal-rebuild-override");
    create_control_test_dir(&root.join(".codex"));
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    fs::write(root.join(".codex/config.toml"), "model = \"gpt-6.1-sol\"\n")
        .expect("seed clean config");
    // Syntax damage quarantines once; recoverable hold-budget damage inside
    // 24 hours then pauses the source.
    let path = root.join("codex-scan-index.json");
    crate::snapshots::e2_pipeline_scan_fixture::bind_source_for_test(&path, SnapshotSource::Codex);
    crate::snapshots::e2_pipeline_scan_fixture::legacy_input_for_test(&path, b"{");
    let (_, origin) = crate::snapshots::e2_pipeline_scan_fixture::load_source_for_test(
        &path,
        SnapshotSource::Codex,
        &root,
    )
    .expect("first incident publishes and then adopts fresh native custody");
    assert_eq!(origin, ScanIndexLoadOrigin::Loaded);
    let mut damage = serde_json::to_value(ScanIndex::default()).expect("index value");
    damage["files"]["excess-held"] = serde_json::json!({"unknown": "x".repeat(2 * 1024 * 1024)});
    let damage = serde_json::to_vec(&damage).expect("damaged index bytes");
    crate::snapshots::e2_pipeline_scan_fixture::legacy_input_for_test(&path, &damage);
    let error =
        ScanIndex::load_for_snapshot_source_with_origin(&path, SnapshotSource::Codex, &root)
            .expect_err("the guard refuses");
    assert!(format!("{error:#}").contains("scan_index_rebuild_loop"));

    let daemon = daemon();
    let guard = || {
        (
            crate::snapshots::scan_index_rebuild_paused(SnapshotSource::Codex),
            crate::snapshots::scan_index_rebuild_manual_override_count(),
            crate::snapshots::scan_index_rebuild_override_identity_unrecoverable_count(),
        )
    };
    let before = guard();
    assert!(before.0, "the source is paused");
    let internal = RequestAuthorization::DaemonInternal;
    // The internal caller first: verification reaches its account check and
    // gets no override result, and the pause, counters and bytes stay.
    let result = verify_source(&daemon, &internal, SourceKind::Codex, false)
        .expect("internal verification reaches the account check");
    assert_eq!(result.status, SourceVerificationStatus::AccountNotConnected);
    let plan = propose_repair_plan(
        &daemon,
        &RequestAuthorization::TrustedCompanionApp,
        SourceKind::Codex,
        false,
    )
    .expect("ordinary repair plan");
    assert!(
        scan_index_rebuild_override_repair(&daemon, &internal, &SourceKind::Codex, &plan).is_none()
    );
    assert_eq!(guard(), before);
    assert_eq!(fs::read(&path).expect("index kept"), damage);
    // The same pause still gives the Companion its first arm; an earlier arm
    // would answer with the cooldown instead.
    let companion = scan_index_rebuild_override_repair(
        &daemon,
        &RequestAuthorization::TrustedCompanionApp,
        &SourceKind::Codex,
        &plan,
    )
    .expect("paused source gives the Companion an override result");
    assert_eq!(companion.status, RepairPlanStatus::Running);
    assert_eq!(
        companion.authority.message.code,
        "scan_index_rebuild_override_armed"
    );
    assert!(companion.actions.is_empty());
    let _ = fs::remove_dir_all(&root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
#[serial]
fn daemon_internal_is_never_a_request_caller_and_is_refused_beyond_verification() {
    let _lock = lock_backend_test_env();
    let foreign = LocalClientPeer::from_pid_and_euid(
        Some(std::process::id()),
        Some(daemon_effective_uid().wrapping_add(1)),
    );
    for token in [None, Some("wrong-token"), Some("token")] {
        for kind in [
            None,
            Some(LocalClientKind::Cli),
            Some(LocalClientKind::CompanionApp),
            Some(LocalClientKind::WebUi),
        ] {
            for peer in [
                None,
                Some(LocalClientPeer::default()),
                Some(foreign.clone()),
                Some(LocalClientPeer::trusted_for_tests()),
            ] {
                let request = LocalControlRequest {
                    request_id: "internal-origin".into(),
                    protocol_version: PROTOCOL_VERSION,
                    token: token.map(str::to_owned),
                    client_kind: kind.clone(),
                    client_install_owner: None,
                    command: LocalControlCommand::AuthStatus,
                };
                let expected = if let Some(token) = token {
                    RequestAuthorization::Token(token.into())
                } else if kind == Some(LocalClientKind::CompanionApp)
                    && peer.as_ref().is_some_and(|peer| peer.trusted_for_tests)
                {
                    RequestAuthorization::TrustedCompanionApp
                } else {
                    RequestAuthorization::Untrusted
                };
                assert_eq!(request_authorization(&request, peer.as_ref()), expected);
            }
        }
    }

    // Verification passes repair=false and reaches none of these checks.
    let files = ControlFilesFixture::new();
    let _patch = EnvVarGuard::remove("OTTTO_PATCH_CODEX_DISABLED");
    let daemon = daemon();
    let relay = daemon.inner.lock().unwrap().relay.clone();
    let internal = RequestAuthorization::DaemonInternal;
    let refused = Err(LocalApiError::LocalClientNotTrusted);
    files.assert_unchanged(|| {
        assert_eq!(
            diagnostics_collect(&daemon, &internal, false, None, None),
            refused
        );
        assert!(matches!(
            propose_repair_plan(&daemon, &internal, SourceKind::Codex, true),
            Err(LocalApiError::LocalClientNotTrusted)
        ));
        assert!(matches!(
            execute_write_config_repair(&daemon, &internal, &SourceKind::Codex),
            Err(LocalApiError::LocalClientNotTrusted)
        ));
        // UninstallExecute refuses before its confirm guard, which precedes
        // all of its work: a later refusal would answer InvalidRequest here.
        // confirm=false because a regressed confirm=true would reach the
        // host's launch agents and keychain.
        for command in [
            LocalControlCommand::AgentStatusCached { source: None },
            LocalControlCommand::RelayStart,
            LocalControlCommand::RelayStop,
            LocalControlCommand::UninstallExecute { confirm: false },
        ] {
            let result = handle_command(
                &daemon,
                internal.clone(),
                command,
                InstallOwner::Unknown,
                false,
            );
            assert_eq!(result, refused);
        }
    });
    let state = daemon.inner.lock().unwrap();
    assert_eq!(state.relay, relay);
    assert!(!state.repair_locked);
    assert!(state.sources.is_empty());
    assert!(state.local_health_events.is_empty());
    assert!(state.command_ledger.is_empty());
}

#[test]
fn backend_cli_error_message_omits_endpoint_details() {
    let error = cli_error(LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: "/api/v1/setup-runs/[id]/local-client/scan-result".to_string(),
        status: Some(401),
        body_excerpt: Some(
            r#"{"error":"AuthenticationError","detail":"Setup run expired","request_id":"req_private"}"#
                .to_string(),
        ),
        reason_code: None,
    }));

    assert_eq!(
        error.message,
        "Setup run expired. Run `ottto login` to reconnect this Mac."
    );
    assert!(!error.message.contains("/api/v1"));
    assert!(!error.message.contains("req_private"));
}

fn backend_rejection(endpoint: &str, status: u16, body: &str) -> LocalApiError {
    LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: endpoint.to_string(),
        status: Some(status),
        body_excerpt: Some(body.to_string()),
        reason_code: None,
    })
}

#[test]
fn revoked_or_deleted_mac_gets_plain_sign_in_guidance() {
    // Observed 2026-11-04: a Mac whose account was deleted showed "Ottto
    // rejected the local setup request. Open the Ottto app from Ottto to
    // attach an active setup run. (HTTP 401)".
    for (endpoint, body) in [
        (
            "/api/v1/setup-runs/[id]/local-client/scan-result",
            r#"{"detail":"Telemetry device is not active"}"#,
        ),
        (
            "/api/v1/setup-runs/[id]/local-client/refresh",
            r#"{"detail":"Telemetry device not found"}"#,
        ),
        (
            "/api/v1/agent-status/snapshots",
            r#"{"detail":"Telemetry device is revoked"}"#,
        ),
        (
            "/api/v1/setup-runs/[id]/local-client/scan-result",
            r#"{"detail":"Setup run owner not found"}"#,
        ),
        (
            "/api/v1/setup-runs/[id]/local-client/scan-result",
            r#"{"detail":{"code":"account_not_found"}}"#,
        ),
    ] {
        let error = cli_error(backend_rejection(endpoint, 401, body));
        assert_eq!(error.message, MAC_DISCONNECTED_MESSAGE, "{endpoint} {body}");
        assert_eq!(
            error.details.get("reason_code"),
            Some(&RedactedValue::String("mac_disconnected".to_string())),
            "{endpoint} {body}"
        );
    }
}

#[test]
fn other_rejections_keep_their_guidance_and_no_disconnected_reason() {
    let expired = cli_error(backend_rejection(
        "/api/v1/setup-runs/[id]/local-client/scan-result",
        401,
        r#"{"detail":"Setup run expired"}"#,
    ));
    assert_eq!(
        expired.message,
        "Setup run expired. Run `ottto login` to reconnect this Mac."
    );
    assert!(!expired.details.contains_key("reason_code"));

    let unknown = cli_error(backend_rejection(
        "/api/v1/setup-runs/[id]/local-client/scan-result",
        401,
        r#"{"detail":"Setup run companion token expired"}"#,
    ));
    assert!(unknown.message.contains("attach an active setup run"));
    assert!(!unknown.details.contains_key("reason_code"));

    let diagnostics = cli_error(backend_rejection(
        "/api/v1/diagnostics/bundles",
        401,
        r#"{"detail":"Telemetry device is not active"}"#,
    ));
    assert!(diagnostics.message.contains("diagnostics upload"));
    assert!(!diagnostics.details.contains_key("reason_code"));

    let logout = cli_error(backend_rejection(
        "/api/v1/setup-runs/[id]/local-client/disconnect",
        401,
        r#"{"detail":"Telemetry device is not active"}"#,
    ));
    assert!(logout.message.contains("cloud logout"));
    assert!(!logout.details.contains_key("reason_code"));
}

#[test]
fn revoked_cross_account_predecessor_gets_plain_replace_it_guidance() {
    let body = r#"{"detail":{"code":"reattach_required","reason":"revoked_cross_account_predecessor","device_name":"Test Mac","can_reconnect":false}}"#;
    let endpoint = "/api/v1/setup-claims/[claim]/local-client/complete";
    let message = cli_error(backend_rejection(endpoint, 409, body)).message;
    assert_eq!(message, MAC_DISCONNECTED_FROM_EARLIER_ACCOUNT_MESSAGE);
    assert!(message.contains("Replace it"));
    assert!(!message.contains("predecessor"));

    let state =
        reattach_required_state(&backend_rejection(endpoint, 409, body)).expect("reattach state");
    assert_eq!(
        state.message.code,
        "reattach_required:revoked_cross_account_predecessor"
    );
    assert_eq!(
        state.message.text,
        MAC_DISCONNECTED_FROM_EARLIER_ACCOUNT_MESSAGE
    );
    assert!(!state.can_reconnect);
}

#[test]
fn auth_complete_log_endpoint_redacts_claim_code() {
    assert_eq!(
        auth_complete_log_endpoint(
            "https://api.ottto.net/api/v1/setup-claims/claim_private/local-client/complete"
        ),
        "https://api.ottto.net/api/v1/setup-claims/[claim]/local-client/complete"
    );
    assert_eq!(
        auth_complete_log_endpoint("/api/v1/setup-claims/claim_private/local-client/complete"),
        "/api/v1/setup-claims/[claim]/local-client/complete"
    );
    assert_eq!(
        auth_complete_log_endpoint("/api/v1/setup-claims/claim_private/status"),
        "/api/v1/setup-claims/claim_private/status"
    );
}

#[test]
#[serial]
fn setup_clears_cancelled_binding_before_requiring_fresh_claim() {
    let _lock = lock_backend_test_env();
    let support_root = control_test_root("setup-cancelled-binding");
    let secret_root = telemetry_key_store_root("setup-cancelled-binding-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    fs::write(
        secret_root.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT),
        "otsr_stale",
    )
    .expect("setup-run token");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_cancelled".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: setup_run_cancelled_scan_server(),
    };
    FileConnectionStore::default()
        .save(&connection)
        .expect("persist connection binding");
    let mut stale_overlay = connected_account();
    stale_overlay.state = LocalAccountState::ClaimPending;
    stale_overlay.user = None;
    stale_overlay.organization = None;
    let daemon = daemon()
        .with_account(stale_overlay)
        .with_connection(Some(connection));

    let response = handle_request(
        &daemon,
        LocalControlRequest {
            request_id: "req_setup_cancelled".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Setup {
                sources: vec![SourceKind::Codex],
                claim_code: None,
                setup_run_id: None,
                api_base_url: None,
            },
        },
    );

    assert!(!response.ok);
    let error = response.error.expect("error");
    assert_eq!(error.code, CliErrorCode::NeedsUserAction);
    assert!(error.message.contains("Setup needs browser approval"));
    assert_eq!(
        daemon
            .connection_for_authorized_client()
            .expect("load connection"),
        None
    );
    assert_eq!(
        FileConnectionStore::default()
            .load()
            .expect("load persisted connection"),
        None
    );
    assert!(KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .is_err());
    assert!(!secret_root.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).exists());
}

#[test]
#[serial]
fn setup_cancelled_cleanup_preserves_newer_binding_and_token() {
    let _lock = lock_backend_test_env();
    let support_root = control_test_root("setup-cancelled-race");
    let secret_root = telemetry_key_store_root("setup-cancelled-race-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let stale = LocalConnectionBinding {
        setup_run_id: "setup_cancelled".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: "https://api.ottto.net".to_string(),
    };
    let fresh = LocalConnectionBinding {
        setup_run_id: "setup_fresh".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:35:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: Some("claim_fresh".to_string()),
        api_base_url: "https://api.ottto.net".to_string(),
    };
    FileConnectionStore::default()
        .save(&fresh)
        .expect("persist fresh binding");
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save("otsr_fresh")
        .expect("persist fresh token");
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(fresh.clone()));

    clear_setup_run_connection_if_current(&daemon, &stale, "otsr_stale")
        .expect("conditional clear");

    assert_eq!(
        daemon
            .connection_for_authorized_client()
            .expect("load daemon connection"),
        Some(fresh.clone())
    );
    assert_eq!(
        FileConnectionStore::default()
            .load()
            .expect("load persisted connection"),
        Some(fresh)
    );
    assert_eq!(
        KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .load()
            .expect("load setup token"),
        "otsr_fresh"
    );
}

#[test]
fn setup_timeout_maps_to_timed_out_exit_code() {
    let error = cli_error(LocalApiError::TimedOut(
        "setup wait reached timeout".to_string(),
    ));

    assert_eq!(error.code, CliErrorCode::TimedOut);
    assert_eq!(error.code.exit_code(), 61);
    assert!(error.retryable);
    assert!(error.message.contains("Timed out waiting for setup"));
}

/// What the scripted setup-run backend answers: `read` for every agent
/// read, `refresh` for the device-secret refresh. Status 0 closes the
/// connection without an answer (a transport failure).
#[derive(Clone, Copy)]
struct SetupRunReadScript {
    read: (u16, &'static str),
    refresh: (u16, &'static str),
}

fn expired_setup_run_read_server(
    calls: Arc<Mutex<Vec<String>>>,
    script: Arc<Mutex<SetupRunReadScript>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind expired run backend");
    let address = listener.local_addr().expect("local address");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                return;
            };
            let request = read_complete_http_request(&mut stream);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            calls.lock().expect("calls lock").push(path.clone());
            let script = *script.lock().expect("script lock");
            let (status, body) = if path.contains("/local-client/refresh") {
                script.refresh
            } else {
                script.read
            };
            match status {
                0 => drop(stream),
                200 => write_json_response(&mut stream, 200, "OK", body),
                401 => write_json_response(&mut stream, 401, "Unauthorized", body),
                _ => write_json_response(&mut stream, status, "Error", body),
            }
        }
    });
    format!("http://{address}")
}

/// One backend request held open until the test thread answers it.
struct HeldSetupRunRequest {
    path: String,
    request: String,
    respond: mpsc::Sender<(u16, &'static str)>,
}

impl HeldSetupRunRequest {
    fn answer(self, status: u16, body: &'static str) {
        self.respond
            .send((status, body))
            .expect("backend connection waits for its answer");
    }
}

/// A backend whose every response is released by the test thread, so read
/// and rebind interleavings are fixed by message order rather than timing.
fn held_setup_run_backend() -> (String, mpsc::Receiver<HeldSetupRunRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind held backend");
    let address = listener.local_addr().expect("local address");
    let (requests_tx, requests_rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                return;
            };
            let requests_tx = requests_tx.clone();
            thread::spawn(move || {
                let request = read_complete_http_request(&mut stream);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or_default()
                    .to_string();
                let (respond, answer) = mpsc::channel();
                if requests_tx
                    .send(HeldSetupRunRequest {
                        path,
                        request,
                        respond,
                    })
                    .is_err()
                {
                    return;
                }
                if let Ok((status, body)) = answer.recv() {
                    let reason = if status == 200 { "OK" } else { "Unauthorized" };
                    write_json_response(&mut stream, status, reason, body);
                }
            });
        }
    });
    (format!("http://{address}"), requests_rx)
}

#[test]
#[serial]
fn setup_run_read_outcome_never_crosses_a_concurrent_rebind() {
    const EXPIRED: &str = r#"{"detail":"Setup run expired"}"#;
    const COSTS: &str = r#"{"results_state":"current"}"#;
    let _guard = lock_backend_test_env();
    let root = control_test_root("setup-run-read-concurrent-rebind");
    let secret_root = telemetry_key_store_root("setup-run-read-concurrent-rebind-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard =
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string()],
        })
        .expect("persist relay device binding");
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("device_secret_test")
        .expect("persist relay device secret");
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save("otsr_current")
        .expect("persist setup token");
    let (api_base_url, requests) = held_setup_run_backend();
    let binding = |setup_run_id: &str| LocalConnectionBinding {
        setup_run_id: setup_run_id.to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: api_base_url.clone(),
    };
    let (run_a, run_b) = (binding("run_a"), binding("run_b"));
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(run_a.clone()));
    let authorization = RequestAuthorization::Token("token".to_string());
    let next = || {
        requests
            .recv_timeout(Duration::from_secs(30))
            .expect("the read reaches the backend")
    };
    let held = |run: &str, endpoint: &str| {
        let request = next();
        assert!(
            request
                .path
                .starts_with(&format!("/api/v1/setup-runs/{run}/local-client/{endpoint}")),
            "expected {run} {endpoint}, got {}",
            request.path
        );
        request
    };
    let no_more_requests = || {
        assert!(
            matches!(requests.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "one read makes one request and at most one refresh"
        );
    };
    let run_state = || {
        daemon
            .status("token")
            .expect("status")
            .canonical_health
            .expect("canonical health")
            .account
            .setup_run_state
    };
    let read = || agent_costs(&daemon, &authorization, AgentCostsQuery::default());

    thread::scope(|scope| {
        // A read of run A is in flight when this Mac reconnects to run B.
        // Its refresh still targets A: the read keeps the binding the
        // observer captured instead of looking it up again.
        let stale_read = scope.spawn(read);
        let stale_costs = held("run_a", "costs");
        daemon
            .bind_setup_run_for_authorized_client(run_b.clone())
            .expect("reconnect to run B");
        stale_costs.answer(401, EXPIRED);
        held("run_a", "refresh").answer(401, EXPIRED);
        assert!(stale_read.join().expect("read thread").is_err());
        no_more_requests();
        assert_eq!(
            run_state(),
            ottto_protocol::LocalSetupRunState::Complete,
            "a rejection of replaced run A must not mark run B rejected"
        );

        // Same binding: a rejected read of B (one refresh) marks B rejected.
        let b_read = scope.spawn(read);
        held("run_b", "costs").answer(401, EXPIRED);
        held("run_b", "refresh").answer(401, EXPIRED);
        assert!(b_read.join().expect("read thread").is_err());
        no_more_requests();
        assert_eq!(run_state(), ottto_protocol::LocalSetupRunState::Rejected);

        // A read of run A is in flight when this Mac reconnects to run B
        // and a read of B is rejected; A's late success cannot clear it.
        daemon
            .bind_setup_run_for_authorized_client(run_a.clone())
            .expect("bind run A for the stale read");
        let stale_read = scope.spawn(read);
        let stale_costs = held("run_a", "costs");
        daemon
            .bind_setup_run_for_authorized_client(run_b.clone())
            .expect("reconnect to run B");
        let b_read = scope.spawn(read);
        held("run_b", "costs").answer(401, EXPIRED);
        held("run_b", "refresh").answer(401, EXPIRED);
        assert!(b_read.join().expect("read thread").is_err());
        assert_eq!(run_state(), ottto_protocol::LocalSetupRunState::Rejected);
        stale_costs.answer(200, COSTS);
        stale_read
            .join()
            .expect("read thread")
            .expect("run A answered");
        no_more_requests();
        assert_eq!(
            run_state(),
            ottto_protocol::LocalSetupRunState::Rejected,
            "a success of replaced run A must not clear run B's rejection"
        );

        // Same binding: a successful read of B clears B's rejection.
        let b_read = scope.spawn(read);
        held("run_b", "costs").answer(200, COSTS);
        b_read.join().expect("read thread").expect("run B answered");
        no_more_requests();
        assert_eq!(run_state(), ottto_protocol::LocalSetupRunState::Complete);

        // Same binding, out of order: a slow read of B is in flight when a
        // later read of B is told the run ended. The slow read's success
        // arrives last but predates that answer, so it cannot clear it.
        let slow_read = scope.spawn(read);
        let slow_costs = held("run_b", "costs");
        let later_read = scope.spawn(read);
        held("run_b", "costs").answer(401, EXPIRED);
        held("run_b", "refresh").answer(401, EXPIRED);
        assert!(later_read.join().expect("read thread").is_err());
        assert_eq!(run_state(), ottto_protocol::LocalSetupRunState::Rejected);
        slow_costs.answer(200, COSTS);
        slow_read
            .join()
            .expect("read thread")
            .expect("run B answered");
        no_more_requests();
        assert_eq!(
            run_state(),
            ottto_protocol::LocalSetupRunState::Rejected,
            "an older success of run B must not clear its newer rejection"
        );

        // A read of B that starts after the rejection and succeeds clears it.
        let b_read = scope.spawn(read);
        held("run_b", "costs").answer(200, COSTS);
        b_read.join().expect("read thread").expect("run B answered");
        no_more_requests();
        assert_eq!(run_state(), ottto_protocol::LocalSetupRunState::Complete);

        // Logout while a rejected read is in flight records nothing.
        let stale_read = scope.spawn(read);
        let stale_costs = held("run_b", "costs");
        daemon
            .reset_account_for_authorized_client()
            .expect("logout");
        stale_costs.answer(401, EXPIRED);
        held("run_b", "refresh").answer(401, EXPIRED);
        assert!(stale_read.join().expect("read thread").is_err());
        no_more_requests();
        let status = daemon.status("token").expect("status");
        assert_ne!(
            status
                .local_health_events
                .iter()
                .rfind(|event| event.event_type.starts_with("SetupRunRead"))
                .map(|event| event.event_type.as_str()),
            Some("SetupRunReadRejected"),
            "a rejection that finishes after logout must not be recorded"
        );
    });
}

#[derive(Default)]
struct FakeSetupRunConnectionStore {
    value: std::cell::RefCell<Option<LocalConnectionBinding>>,
    fail_save: bool,
}

impl SetupRunConnectionStore for FakeSetupRunConnectionStore {
    fn load_connection(&self) -> anyhow::Result<Option<LocalConnectionBinding>> {
        Ok(self.value.borrow().clone())
    }

    fn save_connection(&self, connection: &LocalConnectionBinding) -> anyhow::Result<()> {
        if self.fail_save {
            return Err(anyhow::anyhow!("synthetic connection write failure"));
        }
        *self.value.borrow_mut() = Some(connection.clone());
        Ok(())
    }
}

#[derive(Default)]
struct FakeSetupRunTokenStore {
    value: std::cell::RefCell<Option<String>>,
    fail_save: bool,
}

impl ControlTokenStore for FakeSetupRunTokenStore {
    fn load(&self) -> Result<String, TokenStoreError> {
        self.value.borrow().clone().ok_or(TokenStoreError::Missing)
    }

    fn save(&self, token: &str) -> Result<(), TokenStoreError> {
        if self.fail_save {
            return Err(TokenStoreError::Store(
                "synthetic token write failure".to_string(),
            ));
        }
        *self.value.borrow_mut() = Some(token.to_string());
        Ok(())
    }

    fn delete(&self) -> Result<(), TokenStoreError> {
        *self.value.borrow_mut() = None;
        Ok(())
    }
}

fn refresh_binding(setup_run_id: &str, expires_at: &str) -> LocalConnectionBinding {
    LocalConnectionBinding {
        setup_run_id: setup_run_id.to_string(),
        setup_run_token_expires_at: expires_at.to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: "https://api.ottto.net".to_string(),
    }
}

#[test]
fn refresh_commit_storage_failure_never_leaves_a_mixed_pair() {
    let run_a = refresh_binding("run_a", "2026-05-05T10:00:00Z");
    let run_c_refreshed = refresh_binding("run_c", "2026-05-05T10:15:00Z");

    // Token write fails: both stores keep the prior pair.
    let connections = FakeSetupRunConnectionStore {
        value: std::cell::RefCell::new(Some(run_a.clone())),
        ..Default::default()
    };
    let tokens = FakeSetupRunTokenStore {
        value: std::cell::RefCell::new(Some("otsr_a".to_string())),
        fail_save: true,
    };
    let result = commit_refreshed_setup_run_binding_locked(
        &run_a,
        &run_c_refreshed,
        "otsr_minted",
        &connections,
        &tokens,
    );
    assert!(matches!(result, Err(LocalApiError::StatePoisoned)));
    assert_eq!(connections.value.take(), Some(run_a.clone()));
    assert_eq!(tokens.value.take().as_deref(), Some("otsr_a"));

    // Connection write fails after the token write: the prior token is
    // put back, so the stores keep the prior binding rather than the new
    // token beside the old connection.
    let connections = FakeSetupRunConnectionStore {
        value: std::cell::RefCell::new(Some(run_a.clone())),
        fail_save: true,
    };
    let tokens = FakeSetupRunTokenStore {
        value: std::cell::RefCell::new(Some("otsr_a".to_string())),
        ..Default::default()
    };
    let result = commit_refreshed_setup_run_binding_locked(
        &run_a,
        &run_c_refreshed,
        "otsr_minted",
        &connections,
        &tokens,
    );
    assert!(matches!(result, Err(LocalApiError::StatePoisoned)));
    assert_eq!(connections.value.take(), Some(run_a.clone()));
    assert_eq!(tokens.value.take().as_deref(), Some("otsr_a"));

    // No prior token: the new one is removed, and the next read refreshes
    // again with the device credential.
    let connections = FakeSetupRunConnectionStore {
        value: std::cell::RefCell::new(Some(run_a.clone())),
        fail_save: true,
    };
    let tokens = FakeSetupRunTokenStore::default();
    let result = commit_refreshed_setup_run_binding_locked(
        &run_a,
        &run_c_refreshed,
        "otsr_minted",
        &connections,
        &tokens,
    );
    assert!(matches!(result, Err(LocalApiError::StatePoisoned)));
    assert_eq!(connections.value.take(), Some(run_a));
    assert_eq!(tokens.value.take(), None);
}

#[test]
#[serial]
fn stale_refresh_never_overwrites_a_reconnected_or_logged_out_binding() {
    const INVALID: &str = r#"{"detail":"Setup run companion token is invalid"}"#;
    const COSTS: &str = r#"{"results_state":"current"}"#;
    let _guard = lock_backend_test_env();
    let root = control_test_root("stale-refresh-binding-cas");
    let secret_root = telemetry_key_store_root("stale-refresh-binding-cas-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard =
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string()],
        })
        .expect("persist relay device binding");
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("device_secret_test")
        .expect("persist relay device secret");
    let (api_base_url, requests) = held_setup_run_backend();
    let binding = |setup_run_id: &str, expires_at: &str| LocalConnectionBinding {
        setup_run_id: setup_run_id.to_string(),
        setup_run_token_expires_at: expires_at.to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: api_base_url.clone(),
    };
    let run_a = binding("run_a", "2026-05-05T10:00:00Z");
    let run_b = binding("run_b", "2026-05-05T10:05:00Z");
    let tokens = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT);
    // Model a binding writer (claim, switch, setup attach): it replaces
    // both stores under the same lock the refresh commit takes.
    let install = |connection: &LocalConnectionBinding, token: &str| {
        let _binding_lock = lock_setup_run_binding();
        tokens.save(token).expect("persist setup token");
        FileConnectionStore::default()
            .save(connection)
            .expect("persist connection binding");
    };
    let persisted = || {
        (
            FileConnectionStore::default()
                .load()
                .expect("load connection binding"),
            tokens.load().ok(),
        )
    };
    install(&run_a, "otsr_a");
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(run_a.clone()));
    let authorization = RequestAuthorization::Token("token".to_string());
    let held = |run: &str, endpoint: &str| {
        let request = requests
            .recv_timeout(Duration::from_secs(30))
            .expect("the read reaches the backend");
        assert!(
            request
                .path
                .starts_with(&format!("/api/v1/setup-runs/{run}/local-client/{endpoint}")),
            "expected {run} {endpoint}, got {}",
            request.path
        );
        request
    };
    let no_more_requests = || {
        assert!(
            matches!(requests.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "one read makes one request, at most one refresh and one retry"
        );
    };
    let read = || agent_costs(&daemon, &authorization, AgentCostsQuery::default());

    thread::scope(|scope| {
        // Same binding: a successful refresh persists the new pair and
        // the retry uses the new token.
        let a_read = scope.spawn(read);
        held("run_a", "costs").answer(401, INVALID);
        held("run_a", "refresh").answer(
            200,
            r#"{"setup_run_id":"run_a","setup_run_token":"otsr_a_refreshed","expires_at":"2026-05-05T10:30:00Z"}"#,
        );
        let retry = held("run_a", "costs");
        assert!(retry
            .request
            .contains("X-Ottto-Setup-Run-Token: otsr_a_refreshed"));
        retry.answer(200, COSTS);
        a_read.join().expect("read thread").expect("run A answered");
        no_more_requests();
        assert_eq!(
            persisted(),
            (
                Some(binding("run_a", "2026-05-05T10:30:00Z")),
                Some("otsr_a_refreshed".to_string())
            )
        );

        // A successful refresh of run A finishes after this Mac
        // reconnected to run B: B's connection and token stay intact and
        // the stale read does not retry with A's new token.
        let stale_read = scope.spawn(read);
        held("run_a", "costs").answer(401, INVALID);
        let stale_refresh = held("run_a", "refresh");
        install(&run_b, "otsr_b");
        daemon
            .bind_setup_run_for_authorized_client(run_b.clone())
            .expect("reconnect to run B");
        stale_refresh.answer(
            200,
            r#"{"setup_run_id":"run_a","setup_run_token":"otsr_stale_a","expires_at":"2026-05-05T10:45:00Z"}"#,
        );
        assert!(matches!(
            stale_read.join().expect("read thread"),
            Err(LocalApiError::SetupRunConnectionMismatch)
        ));
        no_more_requests();
        assert_eq!(
            persisted(),
            (Some(run_b.clone()), Some("otsr_b".to_string()))
        );

        // A successful refresh of run B finishes after logout: nothing
        // is restored.
        let stale_read = scope.spawn(read);
        held("run_b", "costs").answer(401, INVALID);
        let stale_refresh = held("run_b", "refresh");
        {
            let _binding_lock = lock_setup_run_binding();
            FileConnectionStore::default()
                .reset()
                .expect("logout removes the connection binding");
        }
        let _ = tokens.delete();
        daemon
            .reset_account_for_authorized_client()
            .expect("logout");
        stale_refresh.answer(
            200,
            r#"{"setup_run_id":"run_b","setup_run_token":"otsr_stale_b","expires_at":"2026-05-05T10:45:00Z"}"#,
        );
        assert!(matches!(
            stale_read.join().expect("read thread"),
            Err(LocalApiError::SetupRunConnectionMissing)
        ));
        no_more_requests();
        assert_eq!(persisted(), (None, None));
    });
}

#[test]
#[serial]
fn expired_setup_run_read_refreshes_once_and_reports_reconnect_required() {
    const EXPIRED: &str = r#"{"detail":"Setup run expired"}"#;
    const INVALID: &str = r#"{"detail":"Setup run companion token is invalid"}"#;
    const DEVICE_INACTIVE: &str = r#"{"detail":"Telemetry device is not active"}"#;
    const REFRESHED: &str =
        r#"{"setup_run_token":"otsr_recovered","expires_at":"2026-05-05T10:45:00Z"}"#;
    const COSTS: &str = r#"{"results_state":"current"}"#;
    let _guard = lock_backend_test_env();
    let root = control_test_root("expired-setup-run-read");
    let secret_root = telemetry_key_store_root("expired-setup-run-read-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard =
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string()],
        })
        .expect("persist relay device binding");
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("device_secret_test")
        .expect("persist relay device secret");
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save("otsr_expired_run")
        .expect("persist setup token");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(SetupRunReadScript {
        read: (401, INVALID),
        refresh: (401, INVALID),
    }));
    let api_base_url = expired_setup_run_read_server(calls.clone(), script.clone());
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_expired".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url,
    };
    FileConnectionStore::default()
        .save(&connection)
        .expect("persist connection binding");
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(connection));
    let authorization = RequestAuthorization::Token("token".to_string());
    let answer = |read: (u16, &'static str), refresh: (u16, &'static str)| {
        *script.lock().expect("script lock") = SetupRunReadScript { read, refresh };
    };
    // Runs one read; returns its result and how many reads and refreshes
    // it sent.
    let read = || {
        let result = agent_costs(&daemon, &authorization, AgentCostsQuery::default());
        let paths = std::mem::take(&mut *calls.lock().expect("calls lock"));
        let count = |endpoint: &str| paths.iter().filter(|path| path.contains(endpoint)).count();
        (
            result,
            count("/local-client/costs"),
            count("/local-client/refresh"),
        )
    };
    let account = || {
        daemon
            .status("token")
            .expect("status")
            .canonical_health
            .expect("canonical health")
            .account
    };
    let assert_no_terminal_proof = |row: &str| {
        let account = account();
        assert_eq!(
            (account.setup_run_state, account.setup_token_state),
            (
                ottto_protocol::LocalSetupRunState::Complete,
                ottto_protocol::LocalSetupTokenState::Valid
            ),
            "{row} is not terminal proof"
        );
        assert!(
            !daemon
                .status("token")
                .expect("status")
                .local_health_events
                .iter()
                .any(|event| event.event_type == "SetupRunReadRejected"),
            "{row} records nothing"
        );
    };

    // A generic 401 from the refresh (a detail Ottto does not list as
    // terminal) proves nothing about the run.
    answer((401, EXPIRED), (401, INVALID));
    let (result, reads, refreshes) = read();
    assert!(result.is_err());
    assert_eq!((reads, refreshes), (1, 1));
    assert_no_terminal_proof("an unrecognized refresh 401");

    // The refresh succeeds but the retried read is refused again: the
    // final 401 is the read's, not an authoritative refresh answer.
    answer((401, EXPIRED), (200, REFRESHED));
    let (result, reads, refreshes) = read();
    assert!(result.is_err());
    assert_eq!((reads, refreshes), (2, 1));
    assert_no_terminal_proof("a 401 retried after a successful refresh");

    // The refresh never reaches Ottto.
    answer((401, INVALID), (0, ""));
    let (result, reads, refreshes) = read();
    assert!(result.is_err());
    assert_eq!((reads, refreshes), (1, 1));
    assert_no_terminal_proof("a refresh transport failure");

    // Ottto ended the run: one read and one refresh per command.
    answer((401, EXPIRED), (401, EXPIRED));
    for _ in 1..=2 {
        let (result, reads, refreshes) = read();
        let error = cli_error(result.expect_err("an expired setup run cannot serve reads"));
        assert!(
            error.message.contains("Run `ottto login`"),
            "{}",
            error.message
        );
        assert!(!error.retryable);
        assert_eq!((reads, refreshes), (1, 1), "one read and one refresh");
    }
    let health = daemon
        .status("token")
        .expect("status")
        .canonical_health
        .expect("canonical health");
    assert_eq!(
        health.account.setup_run_state,
        ottto_protocol::LocalSetupRunState::Rejected
    );
    assert_eq!(
        health.account.setup_token_state,
        ottto_protocol::LocalSetupTokenState::Expired
    );
    assert!(health
        .blockers
        .iter()
        .any(|blocker| blocker.code == "setup_run_rejected"));

    // A later transport failure proves nothing either way.
    answer((401, INVALID), (0, ""));
    assert!(read().0.is_err());
    assert_eq!(
        account().setup_run_state,
        ottto_protocol::LocalSetupRunState::Rejected
    );

    // Ottto refuses the device credential: not an ended run.
    answer((401, INVALID), (401, DEVICE_INACTIVE));
    let (result, reads, refreshes) = read();
    assert!(result.is_err());
    assert_eq!((reads, refreshes), (1, 1));
    let health = daemon
        .status("token")
        .expect("status")
        .canonical_health
        .expect("canonical health");
    assert_eq!(
        health.account.setup_token_state,
        ottto_protocol::LocalSetupTokenState::RefreshRequired
    );
    assert_eq!(
        health.account.device_state,
        ottto_protocol::LocalDeviceState::Inactive
    );
    assert!(health
        .blockers
        .iter()
        .any(|blocker| blocker.code == "device_credential_rejected"));
    assert!(!health
        .blockers
        .iter()
        .any(|blocker| blocker.code == "setup_run_rejected"));

    // A successful read clears the current binding's rejection.
    answer((200, COSTS), (200, REFRESHED));
    let (result, reads, refreshes) = read();
    result.expect("an accepted read restores reads");
    assert_eq!((reads, refreshes), (1, 0));
    let recovered = account();
    assert_eq!(
        recovered.setup_run_state,
        ottto_protocol::LocalSetupRunState::Complete
    );
    assert_eq!(
        recovered.setup_token_state,
        ottto_protocol::LocalSetupTokenState::Valid
    );
}

#[test]
#[serial]
fn agent_read_refreshes_the_setup_run_token_only_on_401() {
    const INVALID: &str = r#"{"detail":"Setup run companion token is invalid"}"#;
    // A token-invalid body under 403 would refresh a setup-run request,
    // but an agent read returns it after one request, without refreshing.
    let _guard = lock_backend_test_env();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(SetupRunReadScript {
        read: (403, INVALID),
        refresh: (0, ""),
    }));
    let api_base_url = expired_setup_run_read_server(calls.clone(), script);
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_agent_read".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: api_base_url.clone(),
    };
    let error = agent_read_with_refresh(
        &api_base_url,
        &connection,
        "otsr_agent_read",
        |api_base_url, connection| {
            agent_costs_url(api_base_url, connection, &AgentCostsQuery::default())
        },
    )
    .expect_err("a refused read fails");
    assert!(
        matches!(&error, LocalApiError::Backend(details) if details.status == Some(403)),
        "{error:?}"
    );
    let paths = calls.lock().expect("calls lock").clone();
    assert_eq!(paths.len(), 1, "{paths:?}");
    assert!(paths[0].contains("/local-client/costs"), "{paths:?}");
}

#[test]
fn backend_reason_code_drives_the_message_and_incidental_expiry_text_does_not() {
    let backend = |status: u16, body: &str| BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: "/api/v1/setup-runs/[id]/local-client/costs".to_string(),
        status: Some(status),
        body_excerpt: Some(body.to_string()),
        reason_code: backend_reason_code(body),
    };

    let machine = cli_error(LocalApiError::Backend(backend(
        422,
        r#"{"error":"ResultsUnavailableError","detail":"Filtering by machine isn't available yet","request_id":"req_1","code":"machine_filter_unsupported"}"#,
    )));
    assert_eq!(machine.code, CliErrorCode::BackendRejected);
    assert_eq!(machine.code.exit_code(), 15);
    assert!(!machine.retryable);
    assert_eq!(
        machine.details.get("reason_code"),
        Some(&RedactedValue::String(
            "machine_filter_unsupported".to_string()
        ))
    );
    // --all-machines is the no-op default; the explicit filter is what to drop.
    assert!(machine.message.contains("--machine-id"));
    assert!(!machine.message.contains("--all-machines"));

    let unavailable = cli_error(LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Unavailable,
        ..backend(
            503,
            r#"{"error":"ResultsUnavailable","code":"no_committed_answer","detail":"Ottto has no cost numbers for this window yet.","results_state":"pending"}"#,
        )
    }));
    assert_eq!(unavailable.code.exit_code(), 16);
    assert!(unavailable.message.contains("unavailable, not zero"));

    let retired = cli_error(LocalApiError::Backend(backend(
        422,
        r#"{"error":"PreviousPipelineRetiredError","detail":"Retired","request_id":"req_4","code":"previous_pipeline_retired"}"#,
    )));
    assert_eq!(retired.code.exit_code(), 15);
    assert_eq!(retired.message, "Ottto can't answer this read yet.");

    // A short-lived companion token that merely expired is not a dead run.
    let token = cli_error(LocalApiError::Backend(backend(
        401,
        r#"{"error":"AuthenticationError","detail":"Setup run companion token expired","request_id":"req_2"}"#,
    )));
    assert_eq!(token.code, CliErrorCode::BackendRejected);
    assert!(!token.details.contains_key("reason_code"));
    assert!(!token.message.contains("Setup run expired"));

    let expired = cli_error(LocalApiError::Backend(backend(
        401,
        r#"{"error":"AuthenticationError","detail":"Setup run expired","request_id":"req_3"}"#,
    )));
    assert!(expired.message.starts_with("Setup run expired."));

    // Terminal only for the exact detail from the refresh endpoint.
    let refresh = |detail: &str| {
        LocalApiError::Backend(BackendErrorDetails {
            endpoint: "https://api.ottto.net/api/v1/setup-runs/run_1/local-client/refresh"
                .to_string(),
            ..backend(401, &format!(r#"{{"detail":"{detail}"}}"#))
        })
    };
    for (detail, expected) in [
        (
            "Setup run expired",
            Some(TerminalRefreshRejection::SetupRunEnded),
        ),
        (
            "Setup run cancelled",
            Some(TerminalRefreshRejection::SetupRunEnded),
        ),
        (
            "Telemetry device is not active",
            Some(TerminalRefreshRejection::DeviceRejected),
        ),
        ("Setup run not found for this device", None),
        ("Setup run companion token expired", None),
    ] {
        assert_eq!(
            terminal_refresh_rejection(&refresh(detail)),
            expected,
            "{detail}"
        );
    }
    assert_eq!(
        terminal_refresh_rejection(&LocalApiError::Backend(backend(
            401,
            r#"{"detail":"Setup run expired"}"#
        ))),
        None,
        "a read endpoint's 401 is not a refresh answer"
    );
    assert_eq!(
        terminal_refresh_rejection(&LocalApiError::NetworkUnavailable),
        None
    );
}

const SC_DEVICE: &str = "6f1c0e52-0000-4000-8000-00000000a001";

/// A support dir bound to `SC_DEVICE` with every source granted.
fn source_collection_support(name: &str) -> (PathBuf, [EnvVarGuard; 2]) {
    let root = control_test_root(name);
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support root");
    let env = [
        EnvVarGuard::set_path("HOME", &root),
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
    ];
    ottto_core::FileDeviceStore::default()
        .save(&ottto_core::LocalDeviceBinding {
            device_id: SC_DEVICE.into(),
            machine_id: Some("machine_test".into()),
            sources: vec!["codex".into(), "claude_code".into(), "pi".into()],
        })
        .expect("bind device");
    (support, env)
}

/// The server's reply for Codex: the heartbeat's `source_control` block.
fn sc_reply(revision: u64, state: &str) -> serde_json::Value {
    json!({"source_control": {"contract": "source_control:v1", "device_id": SC_DEVICE,
        "sources": [{"source": "codex", "revision": revision, "desired_state": state,
            "changed_at": "2026-11-05T00:00:00Z",
            "action_id": "00000000-0000-4000-8000-000000000001"}]}})
}

fn sc_files(support: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(support.join("snapshots"))
        .into_iter()
        .flatten()
        .map(|entry| entry.unwrap().path())
        .map(|path| (path.clone(), fs::read(&path).unwrap_or_default()))
        .collect()
}

/// [behaviour] Pause writes its marker before the POST; a failed POST
/// keeps the source paused and reports it unsaved.
#[test]
#[serial]
fn companion_pause_marks_before_post_and_stays_paused_on_post_failure() {
    use crate::snapshot_sync::source_marker;
    use crate::snapshots::SnapshotSource;
    let _guard = lock_backend_test_env();
    let (support, _env) = source_collection_support("source-pause");
    let reply = save_source_collection(&SourceKind::Codex, false, |body| {
        assert_eq!(body, &json!({"source": "codex", "enabled": false}));
        assert_eq!(
            source_marker(&support, SnapshotSource::Codex).as_deref(),
            Some("pending"),
            "marked before the POST"
        );
        Err(anyhow::anyhow!("offline"))
    })
    .expect("an unsaved pause still pauses");
    assert_eq!(
        reply,
        json!({"source": "codex", "source_paused": true, "server_saved": false})
    );
    assert_eq!(
        source_marker(&support, SnapshotSource::Codex).as_deref(),
        Some("pending")
    );
}

/// [behaviour] Resume writes nothing before the POST, then applies the
/// server's serialized reply as a heartbeat would: the marker turns
/// `reconnect` and the record moves to N+1 before the handler returns.
#[test]
#[serial]
fn companion_resume_through_handler_applies_serialized_server_reply() {
    use crate::snapshot_sync::{apply_source_control, source_marker};
    use crate::snapshots::SnapshotSource;
    let _guard = lock_backend_test_env();
    let (support, _env) = source_collection_support("source-resume");
    apply_source_control(&support, &sc_reply(4, "disabled"));
    let body: &'static str = Box::leak(sc_reply(5, "enabled").to_string().into_boxed_str());
    let (url, server) = scripted_json_backend(vec![(200, body)]);
    let reply = save_source_collection(&SourceKind::Codex, true, |body| {
        assert_eq!(
            source_marker(&support, SnapshotSource::Codex).as_deref(),
            Some("pending"),
            "nothing written before the POST"
        );
        crate::snapshot_client::SnapshotApiClient::new(url.clone())
            .upload_source_control("relay-token", body)
    })
    .expect("resume saved");
    let requests = server.join().expect("backend");
    assert!(requests[0].starts_with("POST /api/v1/apps/health/source-control "));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(http_request_body(&requests[0])).unwrap(),
        json!({"source": "codex", "enabled": true})
    );
    assert_eq!(
        reply,
        json!({"source": "codex", "source_paused": false, "server_saved": true})
    );
    assert_eq!(
        source_marker(&support, SnapshotSource::Codex).as_deref(),
        Some("reconnect")
    );
    let record = fs::read(support.join("snapshots/codex.source-control")).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&record).unwrap();
    assert_eq!(record["revision"], json!(5));
}

/// [behaviour] A Resume the server did not save fails and writes nothing.
#[test]
#[serial]
fn resume_post_failure_writes_nothing() {
    use crate::snapshot_sync::disable_snapshot_source;
    use crate::snapshots::SnapshotSource;
    let _guard = lock_backend_test_env();
    let (support, _env) = source_collection_support("source-resume-fail");
    disable_snapshot_source(&support, SnapshotSource::Codex).unwrap();
    let before = sc_files(&support);
    let error = save_source_collection(&SourceKind::Codex, true, |_| {
        Err(anyhow::anyhow!("offline"))
    })
    .expect_err("an unsaved resume fails");
    assert!(matches!(error, LocalApiError::LocalOperationFailed(_)));
    assert_eq!(sc_files(&support), before);
}

/// [format] Status always carries `source_paused`, read at status time:
/// true for a paused source, false for a running or resuming one.
#[test]
#[serial]
fn status_reports_source_paused() {
    use crate::snapshot_sync::{disable_snapshot_source, reconnect_snapshot_source};
    use crate::snapshots::SnapshotSource;
    let _guard = lock_backend_test_env();
    let (support, _env) = source_collection_support("source-paused-status");
    let device = ottto_core::FileDeviceStore::default().load().unwrap();
    let daemon = daemon()
        .with_account(connected_account())
        .with_registered_device_sources_presence(device, |_| true);
    disable_snapshot_source(&support, SnapshotSource::Codex).unwrap();
    disable_snapshot_source(&support, SnapshotSource::Pi).unwrap();
    reconnect_snapshot_source(&support, SnapshotSource::Pi).unwrap();
    let status = serde_json::to_value(daemon.status_for_trusted_client().unwrap()).unwrap();
    let rows = status["sources"].as_array().unwrap().iter();
    let paused: BTreeMap<_, _> = rows
        .map(|row| {
            (
                row["source"].as_str().unwrap(),
                row["source_paused"].as_bool(),
            )
        })
        .collect();
    let expected = [("claude_code", false), ("codex", true), ("pi", false)];
    assert_eq!(paused, BTreeMap::from(expected.map(|(s, p)| (s, Some(p)))));
}

/// [behaviour] Claude's legacy relay is revoked once per local answer.
/// A disable revokes with its pause marker before the POST, so a refused
/// POST stays paused; a skip revokes after its POST and pauses nothing.
#[test]
#[serial]
fn setup_answer_revokes_claude_once_and_disable_stays_paused_on_failed_post() {
    use crate::otlp_relay::legacy::count_revokes;
    use crate::snapshots::SnapshotSource;
    let _guard = lock_backend_test_env();
    let root = control_test_root("setup-answer-revoke");
    let support_root = root.join("support");
    let secret_root = telemetry_key_store_root("setup-answer-revoke-secret");
    fs::create_dir_all(&support_root).expect("support root");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save("otsr_answer")
        .expect("persist setup token");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind setup answer backend");
    let api_base_url = format!("http://{}", listener.local_addr().expect("address"));
    thread::spawn(move || {
        for (status, reason, body) in [
            (400, "Bad Request", r#"{"detail":"refused"}"#),
            (
                200,
                "OK",
                r#"{"run":{"id":"setup_answer","status":"waiting_for_user","machine_id":"machine_test"},"sources":[],"next_action":null,"next_question":null}"#,
            ),
        ] {
            let (mut stream, _) = listener.accept().expect("accept setup answer");
            let request = read_complete_http_request(&mut stream);
            assert!(request.contains("/api/v1/setup-runs/setup_answer/local-client/answers"));
            write_json_response(&mut stream, status, reason, body);
        }
    });
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_answer".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: api_base_url.clone(),
    };
    FileConnectionStore::default()
        .save(&connection)
        .expect("persist connection binding");
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(connection));
    let answer = |answer_type: &str| {
        setup_answer(
            &daemon,
            &RequestAuthorization::Token("token".to_string()),
            SourceKind::ClaudeCode,
            answer_type.to_string(),
            Some(api_base_url.clone()),
        )
    };
    let marker = || crate::snapshot_sync::source_marker(&support_root, SnapshotSource::ClaudeCode);

    let revokes = count_revokes(|| {
        answer("disable_source").expect_err("the backend refuses the disable");
    });
    assert_eq!(revokes, 1);
    assert_eq!(marker().as_deref(), Some("pending"), "fail-closed");

    fs::remove_file(support_root.join("snapshots/claude_code.source-disabled"))
        .expect("clear the pause marker");
    let revokes = count_revokes(|| {
        answer("skip_source").expect("skip is saved");
    });
    assert_eq!(revokes, 1);
    assert_eq!(marker(), None, "a skip pauses nothing");
}

#[test]
#[serial]
fn setup_action_refreshes_token_across_queue_and_verification() {
    let _guard = lock_backend_test_env();
    let root = control_test_root("setup-action-token-refresh");
    let support_root = root.join("support");
    let secret_root = telemetry_key_store_root("setup-action-token-refresh-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let fake_claude = fake_binary_path(&root, "claude");
    fs::write(&fake_claude, "#!/bin/sh\nexit 0\n").expect("write fake claude smoke");
    #[cfg(unix)]
    fs::set_permissions(&fake_claude, fs::Permissions::from_mode(0o755))
        .expect("mark fake claude executable");
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    let _path_guard = EnvVarGuard::set_os(
        "OTTTO_COMMAND_SEARCH_PATH",
        fake_claude
            .parent()
            .expect("fake binary parent")
            .as_os_str()
            .to_os_string(),
    );
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["claude_code".to_string()],
        })
        .expect("persist relay device binding");
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("device_secret_test")
        .expect("persist relay device secret");
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save("otsr_stale")
        .expect("persist stale setup token");
    let completed_body = Arc::new(Mutex::new(None));
    let api_base_url = setup_verify_action_token_refresh_server(completed_body.clone());
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_token_refresh".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: api_base_url.clone(),
    };
    FileConnectionStore::default()
        .save(&connection)
        .expect("persist connection binding");
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(connection.clone()));

    let response = setup_action(
        &daemon,
        &RequestAuthorization::Token("token".to_string()),
        SourceKind::ClaudeCode,
        "verify_source".to_string(),
        Some(api_base_url.clone()),
    )
    .expect("setup action should refresh stale token and complete");

    assert_eq!(
        response.get("status").and_then(serde_json::Value::as_str),
        Some("complete")
    );
    assert_eq!(
        response
            .pointer("/actions/0/action_type")
            .and_then(serde_json::Value::as_str),
        Some("verify_source")
    );
    assert_eq!(
        response
            .pointer("/actions/0/source")
            .and_then(serde_json::Value::as_str),
        Some("claude_code")
    );
    assert_eq!(
        response
            .pointer("/actions/0/status")
            .and_then(serde_json::Value::as_str),
        Some("succeeded")
    );
    // The completion is bound to the queued action and carries what the
    // check established, with no account.
    assert_eq!(
        response.get("queued_action_id"),
        response.pointer("/actions/0/action_id")
    );
    assert_eq!(
        response.pointer("/actions/0/action_id"),
        Some(&json!("action_verify_claude"))
    );
    assert_eq!(
        response.pointer("/actions/0/verification/check"),
        Some(&json!({"method": "live_prompt", "scope": "usage_received"}))
    );
    let body_guard = completed_body.lock().expect("completed body lock");
    let body = body_guard.as_ref().expect("complete body observed");
    assert_eq!(
        body.get("status").and_then(serde_json::Value::as_str),
        Some("succeeded")
    );
    let result = body.get("result").expect("completion result");
    assert_eq!(
        result.get("verified").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(result.get("check").is_none());
    assert_eq!(
        KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .load()
            .expect("load refreshed setup token"),
        "otsr_fresh_complete"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn setup_verification_request_honors_custom_timeout() {
    let api_base_url =
        delayed_setup_verification_server("setup_slow_verification", Duration::from_millis(250));
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_slow_verification".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: api_base_url.clone(),
    };

    let started = Instant::now();
    let result = get_setup_run_verification_with_base_timeout(
        &api_base_url,
        &connection,
        "token_test",
        &SourceKind::Pi,
        "2026-05-05T10:00:00Z",
        None,
        Duration::from_millis(50),
    );

    assert!(matches!(result, Err(LocalApiError::TimedOut(_))));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
#[serial]
fn install_source_action_uses_rebound_credentials_for_install_session_and_completion() {
    let _guard = lock_backend_test_env();
    let root = control_test_root("install-source-rebound-credentials");
    let support_root = root.join("support");
    let secret_root = telemetry_key_store_root("install-source-rebound-secret");
    fs::create_dir_all(&secret_root).expect("secret root");
    let _home_guard = EnvVarGuard::set_path("HOME", &root);
    let _support_guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
    let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_existing".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["pi".to_string()],
        })
        .expect("persist existing relay device binding");
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("device_secret_existing")
        .expect("persist relay device secret");
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save("otsr_install_stale")
        .expect("persist stale setup token");
    let install_session_request = Arc::new(Mutex::new(None));
    let completed_body = Arc::new(Mutex::new(None));
    let api_base_url =
        setup_install_source_rebind_server(install_session_request.clone(), completed_body.clone());
    let connection = LocalConnectionBinding {
        setup_run_id: "setup_install_stale".to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: None,
        api_base_url: api_base_url.clone(),
    };
    FileConnectionStore::default()
        .save(&connection)
        .expect("persist stale connection binding");
    let mut credentials = SetupRunCredentials {
        setup_run_token: "otsr_install_stale".to_string(),
        connection: connection.clone(),
    };
    let daemon = daemon()
        .with_account(connected_account())
        .with_connection(Some(connection));

    let results = process_setup_actions(&daemon, &api_base_url, &mut credentials, &test_machine())
        .expect("install_source should refresh, rebind, and complete");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].action_type, "install_source");
    assert_eq!(results[0].source.as_deref(), Some("pi"));
    assert_eq!(results[0].status, "succeeded");
    assert_eq!(credentials.connection.setup_run_id, "setup_install_fresh");
    assert_eq!(credentials.setup_run_token, "otsr_install_fresh");
    assert_eq!(
        FileConnectionStore::default()
            .load()
            .expect("load rebound connection")
            .expect("connection saved")
            .setup_run_id,
        "setup_install_fresh"
    );
    assert_eq!(
        KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .load()
            .expect("load refreshed setup token"),
        "otsr_install_fresh"
    );
    let install_request = install_session_request
        .lock()
        .expect("install request lock")
        .clone()
        .expect("install session request observed");
    assert!(install_request
        .contains("/api/v1/setup-runs/setup_install_fresh/local-client/install-sessions"));
    assert!(install_request.contains("X-Ottto-Setup-Run-Token: otsr_install_fresh"));
    assert!(!install_request.contains("setup_install_stale"));
    assert!(!install_request.contains("otsr_install_stale"));
    let body_guard = completed_body.lock().expect("completed body lock");
    let body = body_guard.as_ref().expect("complete body observed");
    assert_eq!(
        body.get("status").and_then(serde_json::Value::as_str),
        Some("succeeded")
    );
    let result = body.get("result").expect("completion result");
    assert_eq!(
        result
            .get("install_session_id")
            .and_then(serde_json::Value::as_str),
        Some("install_session_fresh")
    );
    let _ = fs::remove_dir_all(&root);
}

fn setup_install_source_rebind_server(
    install_session_request: Arc<Mutex<Option<String>>>,
    completed_body: Arc<Mutex<Option<serde_json::Value>>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind install source backend");
    let address = listener.local_addr().expect("local address");
    thread::spawn(move || {
        let mut next_action_calls = 0_u8;
        for _ in 0..24 {
            let (mut stream, _) = listener.accept().expect("accept setup install request");
            let request = read_complete_http_request(&mut stream);
            if request.contains("/api/v1/setup-runs/setup_install_stale/local-client/heartbeat")
                && request.contains("X-Ottto-Setup-Run-Token: otsr_install_stale")
            {
                write_json_response(
                    &mut stream,
                    401,
                    "Unauthorized",
                    r#"{"detail":"Setup run companion token expired"}"#,
                );
            } else if request
                .contains("/api/v1/setup-runs/setup_install_stale/local-client/refresh")
            {
                write_json_response(
                    &mut stream,
                    200,
                    "OK",
                    r#"{"setup_run_id":"setup_install_fresh","setup_run_token":"otsr_install_fresh","expires_at":"2026-06-11T18:30:00Z"}"#,
                );
            } else if request
                .contains("/api/v1/setup-runs/setup_install_fresh/local-client/heartbeat")
                && request.contains("X-Ottto-Setup-Run-Token: otsr_install_fresh")
            {
                write_json_response(&mut stream, 200, "OK", "{}");
            } else if request
                .contains("/api/v1/setup-runs/setup_install_fresh/local-client/next-action")
                && request.contains("X-Ottto-Setup-Run-Token: otsr_install_fresh")
            {
                let body = if next_action_calls == 0 {
                    r#"{"action":{"id":"action_install_pi","action_type":"install_source","source":"pi"}}"#
                } else {
                    r#"{"action":null}"#
                };
                next_action_calls += 1;
                write_json_response(&mut stream, 200, "OK", body);
                if next_action_calls > 1 {
                    break;
                }
            } else if request
                .contains("/api/v1/setup-runs/setup_install_fresh/local-client/actions/action_install_pi/events")
                && request.contains("X-Ottto-Setup-Run-Token: otsr_install_fresh")
            {
                write_json_response(&mut stream, 200, "OK", "{}");
            } else if request
                .contains("/api/v1/setup-runs/setup_install_fresh/local-client/install-sessions")
                && request.contains("X-Ottto-Setup-Run-Token: otsr_install_fresh")
            {
                *install_session_request
                    .lock()
                    .expect("install request lock") = Some(request);
                write_json_response(
                    &mut stream,
                    200,
                    "OK",
                    r#"{"install_session_id":"install_session_fresh","install_session_token":"install_token_fresh"}"#,
                );
            } else if request.contains(
                "/api/v1/telemetry/devices/install-sessions/install_session_fresh/events",
            ) && request.contains("X-Ottto-Install-Session-Token: install_token_fresh")
            {
                write_json_response(&mut stream, 200, "OK", "{}");
            } else if request.contains(
                "/api/v1/telemetry/devices/registration-preparations",
            ) {
                write_json_response(
                    &mut stream,
                    200,
                    "OK",
                    r#"{"preparation_id":"preparation_install_fresh","capability":"device_credential_prepare_confirm_v1","expires_at":"2099-01-01T00:00:00Z","credential_generation":2,"device":{"id":"device_install_fresh","machine_id":"machine_test","sources":["pi"]},"candidate_secret":"relay_secret_install","identity_continuity_capability":"prior_device_credential_v1","credential_rotation_planned":true,"prior_device_id":"device_existing"}"#,
                );
            } else if request.contains(
                "/api/v1/telemetry/device-credential-preparations/preparation_install_fresh/confirm",
            ) {
                write_json_response(
                    &mut stream,
                    200,
                    "OK",
                    r#"{"preparation_id":"preparation_install_fresh","status":"confirmed","confirmed_at":"2026-07-31T20:00:00Z","credential_generation":2,"device":{"id":"device_install_fresh","machine_id":"machine_test","sources":["pi"]},"identity_continuity_capability":"prior_device_credential_v1","credential_rotation_performed":true,"rotated_prior_device_id":"device_existing"}"#,
                );
            } else if request
                .contains("/api/v1/setup-runs/setup_install_fresh/local-client/actions/action_install_pi/complete")
                && request.contains("X-Ottto-Setup-Run-Token: otsr_install_fresh")
            {
                let body: serde_json::Value =
                    serde_json::from_str(http_request_body(&request)).expect("complete json");
                *completed_body.lock().expect("completed body lock") = Some(body);
                write_json_response(
                    &mut stream,
                    200,
                    "OK",
                    r#"{"run":{"id":"setup_install_fresh","status":"complete","machine_id":"machine_test"},"sources":[{"source":"pi","detected":true,"readiness_percent":100,"state":"verified","missing_fields":[]}],"next_action":null,"next_question":null}"#,
                );
            } else {
                write_json_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    r#"{"detail":"stale or unexpected setup install request"}"#,
                );
            }
        }
    });
    format!("http://{address}")
}

fn setup_verify_action_token_refresh_server(
    completed_body: Arc<Mutex<Option<serde_json::Value>>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind setup action backend");
    let address = listener.local_addr().expect("local address");
    thread::spawn(move || {
        let mut queue_calls = 0_u8;
        let mut heartbeat_calls = 0_u8;
        let mut next_action_calls = 0_u8;
        let mut event_calls = 0_u8;
        let mut marker_calls = 0_u8;
        let mut refresh_calls = 0_u8;
        let mut complete_calls = 0_u8;
        for _ in 0..20 {
            let (mut stream, _) = listener.accept().expect("accept setup action request");
            let request = read_complete_http_request(&mut stream);
            if request.contains("/local-client/actions HTTP/") {
                if queue_calls == 0 {
                    queue_calls += 1;
                    write_json_response(
                        &mut stream,
                        401,
                        "Unauthorized",
                        r#"{"detail":"Setup run companion token expired"}"#,
                    );
                } else if request.contains("X-Ottto-Setup-Run-Token: otsr_fresh_queue") {
                    queue_calls += 1;
                    write_json_response(
                        &mut stream,
                        200,
                        "OK",
                        r#"{"id":"action_verify_claude","action_type":"verify_source","source":"claude_code"}"#,
                    );
                } else {
                    write_json_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        r#"{"detail":"queue used stale setup token"}"#,
                    );
                }
            } else if request.contains("/local-client/heartbeat") {
                if heartbeat_calls == 0 {
                    heartbeat_calls += 1;
                    write_json_response(
                        &mut stream,
                        401,
                        "Unauthorized",
                        r#"{"detail":"Setup run companion token expired"}"#,
                    );
                } else {
                    heartbeat_calls += 1;
                    write_json_response(&mut stream, 200, "OK", "{}");
                }
            } else if request.contains("/local-client/next-action") {
                if next_action_calls == 0
                    && !request.contains("X-Ottto-Setup-Run-Token: otsr_fresh_poll")
                {
                    write_json_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        r#"{"detail":"next-action used stale setup token"}"#,
                    );
                    continue;
                }
                let body = if next_action_calls == 0 {
                    r#"{"action":{"id":"action_verify_claude","action_type":"verify_source","source":"claude_code"}}"#
                } else {
                    r#"{"action":null}"#
                };
                next_action_calls += 1;
                write_json_response(&mut stream, 200, "OK", body);
                if next_action_calls > 1 {
                    break;
                }
            } else if request.contains("/actions/action_verify_claude/events") {
                if event_calls == 0 {
                    event_calls += 1;
                    write_json_response(
                        &mut stream,
                        401,
                        "Unauthorized",
                        r#"{"detail":"Setup run companion token expired"}"#,
                    );
                } else if request.contains("X-Ottto-Setup-Run-Token: otsr_fresh_event")
                    || event_calls > 1
                {
                    event_calls += 1;
                    write_json_response(&mut stream, 200, "OK", "{}");
                } else {
                    write_json_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        r#"{"detail":"event used stale setup token"}"#,
                    );
                }
            } else if request.contains("/local-client/verification-marker") {
                if marker_calls == 0 {
                    marker_calls += 1;
                    write_json_response(
                        &mut stream,
                        401,
                        "Unauthorized",
                        r#"{"detail":"Setup run companion token expired"}"#,
                    );
                } else if request.contains("X-Ottto-Setup-Run-Token: otsr_fresh_verify") {
                    marker_calls += 1;
                    write_json_response(
                        &mut stream,
                        200,
                        "OK",
                        r#"{"source":"claude_code","marker_id":"marker_test","received_at":"2026-06-11T18:00:00Z","last_record_id":"verification_marker:1"}"#,
                    );
                } else {
                    write_json_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        r#"{"detail":"marker used stale setup token"}"#,
                    );
                }
            } else if request.contains("/local-client/verification") {
                if request.contains("X-Ottto-Setup-Run-Token: otsr_fresh_verify")
                    && marker_calls > 1
                {
                    write_json_response(
                        &mut stream,
                        200,
                        "OK",
                        r#"{"verified":true,"records_seen":1,"last_record_id":"rec_test","last_received_at":"2026-06-11T18:00:00Z","smoke_after":"2026-06-11T17:59:00Z"}"#,
                    );
                } else {
                    write_json_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        r#"{"detail":"verification used stale setup token"}"#,
                    );
                }
            } else if request.contains("/local-client/refresh") {
                let token = match refresh_calls {
                    0 => "otsr_fresh_queue",
                    1 => "otsr_fresh_poll",
                    2 => "otsr_fresh_event",
                    3 => "otsr_fresh_verify",
                    _ => "otsr_fresh_complete",
                };
                refresh_calls += 1;
                let body = format!(
                    r#"{{"setup_run_token":"{token}","expires_at":"2026-06-11T18:30:00Z"}}"#
                );
                write_json_response(&mut stream, 200, "OK", &body);
            } else if request.contains("/actions/action_verify_claude/complete") {
                if complete_calls == 0 {
                    complete_calls += 1;
                    write_json_response(
                        &mut stream,
                        401,
                        "Unauthorized",
                        r#"{"detail":"Setup run companion token expired"}"#,
                    );
                } else if request.contains("X-Ottto-Setup-Run-Token: otsr_fresh_complete") {
                    complete_calls += 1;
                    let body: serde_json::Value =
                        serde_json::from_str(http_request_body(&request)).expect("complete json");
                    *completed_body.lock().expect("completed body lock") = Some(body);
                    write_json_response(
                        &mut stream,
                        200,
                        "OK",
                        r#"{"run":{"id":"setup_token_refresh","status":"complete","machine_id":"machine_test"},"sources":[{"source":"claude_code","detected":true,"readiness_percent":100,"state":"verified","missing_fields":[]}],"next_action":null,"next_question":null}"#,
                    );
                } else {
                    write_json_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        r#"{"detail":"completion used stale setup token"}"#,
                    );
                }
            } else {
                write_json_response(
                    &mut stream,
                    404,
                    "Not Found",
                    r#"{"detail":"unexpected setup action request"}"#,
                );
            }
        }
    });
    format!("http://{address}")
}

fn setup_run_cancelled_scan_server() -> String {
    setup_run_terminal_scan_server("setup_cancelled", "Setup run cancelled")
}

fn delayed_setup_verification_server(setup_run_id: &'static str, delay: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind setup backend");
    let address = listener.local_addr().expect("local address");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept setup verification");
        let request = read_complete_http_request(&mut stream);
        assert!(request.contains(&format!(
            "/api/v1/setup-runs/{setup_run_id}/local-client/verification"
        )));
        thread::sleep(delay);
        let body = r#"{"verified":false,"records_seen":0,"last_record_id":null,"last_received_at":null,"smoke_after":"2026-05-05T10:00:00Z"}"#;
        write_json_response(&mut stream, 200, "OK", body);
    });
    format!("http://{address}")
}

fn setup_run_terminal_scan_server(setup_run_id: &'static str, detail: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind setup backend");
    let address = listener.local_addr().expect("local address");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept setup scan");
        let request = read_complete_http_request(&mut stream);
        assert!(request.contains(&format!(
            "/api/v1/setup-runs/{setup_run_id}/local-client/scan-result"
        )));
        let body =
            format!(r#"{{"error":"HTTPException","detail":"{detail}","request_id":"req_test"}}"#);
        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write setup cancellation");
    });
    format!("http://{address}")
}

fn control_token_validation_server(status: u16) -> String {
    control_token_validation_server_with_claims(status, r#"{"source":"codex","action":"enable_telemetry","organization_id":"org_123","user_id":"user_123","expires_at":"2026-05-17T00:00:00Z"}"#.into())
}

fn control_token_validation_server_with_claims(status: u16, claims: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test backend");
    let address = listener.local_addr().expect("local address");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept validation request");
        read_complete_http_request(&mut stream);
        let (reason, body) = if status == 200 {
            ("OK", claims)
        } else {
            (
                "Unauthorized",
                r#"{"detail":"Invalid app control token"}"#.to_string(),
            )
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write validation response");
    });
    format!("http://{address}")
}

fn cloud_control_validation_server(action: &str, token_id: &str, device_id: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind cloud control backend");
    let address = listener.local_addr().expect("local address");
    let action = action.to_string();
    let token_id = token_id.to_string();
    let device_id = device_id.to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept cloud control validation");
        let request = read_complete_http_request(&mut stream);
        let body: serde_json::Value =
            serde_json::from_str(http_request_body(&request)).expect("validation body");
        assert_eq!(body["source"], "codex");
        assert_eq!(body["action"], action);
        // Consent requests have no telemetry key selector to compare.
        let response = serde_json::json!({
            "valid": true,
            "source": "codex",
            "action": action,
            "organization_id": "org_test",
            "user_id": "user_test",
            "device_id": device_id,
            "key_id": "key_consent",
            "token_id": token_id,
            "expires_at": "2030-01-01T00:00:00Z"
        });
        write_json_response(&mut stream, 200, "OK", &response.to_string());
    });
    format!("http://{address}")
}

fn controlled_claim_completion_server() -> (String, mpsc::Receiver<()>, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind claim backend");
    let address = listener.local_addr().expect("claim backend address");
    let (request_seen_tx, request_seen_rx) = mpsc::channel();
    let (allow_response_tx, allow_response_rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept claim completion");
        read_complete_http_request(&mut stream);
        request_seen_tx.send(()).unwrap();
        allow_response_rx.recv().unwrap();
        write_json_response(
            &mut stream,
            200,
            "OK",
            r#"{"setup_run_id":"setup_reserved_claim","setup_run_token":"otsr_reserved_claim","setup_run_token_expires_at":"2030-01-01T00:00:00Z","machine_id":"machine_test","relay_device":{"id":"device_reserved_claim","machine_id":"machine_test","sources":["codex"]},"relay_device_secret":"relay_reserved_claim","connected_at":"2026-05-05T09:20:00Z","user":{"id":"user_test","email":"user@example.com","display_name":null},"organization":{"id":"org_test","name":"Test Org"}}"#,
        );
    });
    (
        format!("http://{address}"),
        request_seen_rx,
        allow_response_tx,
    )
}

fn observed_install_registration_server() -> (String, mpsc::Receiver<bool>, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind install backend");
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().expect("install backend address");
    let (observed_tx, observed_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Only accept polling is nonblocking. On macOS an accepted
                    // socket inherits that mode; drain the body before replying
                    // so a split header/body write cannot race a closed socket.
                    stream
                        .set_nonblocking(false)
                        .expect("blocking install observer connection");
                    let request = read_complete_http_request(&mut stream);
                    assert!(
                        http_request_complete(request.as_bytes()),
                        "complete install observer request"
                    );
                    if request.contains("/local-client/install-sessions") {
                        write_json_response(
                            &mut stream,
                            200,
                            "OK",
                            r#"{"install_session_id":"install_blocked","install_session_token":"install_token_blocked"}"#,
                        );
                    } else if request
                        .contains("/api/v1/telemetry/devices/registration-preparations")
                    {
                        write_json_response(
                            &mut stream,
                            200,
                            "OK",
                            r#"{"preparation_id":"preparation_should_not_rotate","capability":"device_credential_prepare_confirm_v1","expires_at":"2099-01-01T00:00:00Z","credential_generation":2,"device":{"id":"device_should_not_rotate","machine_id":"machine_test","sources":["pi"]},"candidate_secret":"relay_should_not_rotate","identity_continuity_capability":"prior_device_credential_v1","credential_rotation_planned":true,"prior_device_id":"00000000-0000-4000-8000-000000000001"}"#,
                        );
                        observed_tx.send(true).unwrap();
                        return;
                    } else {
                        write_json_response(&mut stream, 200, "OK", "{}");
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    match finished_rx.try_recv() {
                        Ok(()) => {
                            observed_tx.send(false).unwrap();
                            return;
                        }
                        Err(mpsc::TryRecvError::Disconnected) => return,
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                    // A watchdog failure must not certify that no request
                    // occurred while the operation was still in progress.
                    assert!(
                        Instant::now() < deadline,
                        "install operation did not finish"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept install registration: {error}"),
            }
        }
    });
    (format!("http://{address}"), observed_rx, finished_tx)
}

#[test]
fn observed_install_registration_remains_live_until_operation_finishes() {
    let (api_base, observed, operation_finished) = observed_install_registration_server();
    // Deliberately exceed the former 750ms mock lifetime. Slow setup must
    // not turn an unobserved registration into a false cleanup success.
    thread::sleep(Duration::from_secs(1));
    assert!(matches!(
        observed.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let response: serde_json::Value = backend_post_json(
        &format!("{api_base}/api/v1/telemetry/devices/registration-preparations"),
        &json!({}),
        &[],
    )
    .expect("late synthetic registration reaches observer");
    assert_eq!(response["preparation_id"], "preparation_should_not_rotate");
    assert!(observed.recv_timeout(Duration::from_secs(2)).unwrap());
    let _ = operation_finished.send(());
}

fn control_token_validation_server_with_marker(status: u16) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test backend");
    let address = listener.local_addr().expect("local address");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept validation request");
        read_complete_http_request(&mut stream);
        let (reason, body) = if status == 200 {
            (
                "OK",
                r#"{"source":"codex","action":"enable_telemetry","organization_id":"org_123","user_id":"user_123","expires_at":"2026-05-17T00:00:00Z"}"#,
            )
        } else {
            ("Unauthorized", r#"{"detail":"Invalid app control token"}"#)
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write validation response");
        if status != 200 {
            return;
        }

        let (mut marker_stream, _) = listener.accept().expect("accept marker request");
        read_complete_http_request(&mut marker_stream);
        let body = "{}";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        marker_stream
            .write_all(response.as_bytes())
            .expect("write marker response");
    });
    format!("http://{address}")
}

fn diagnostics_upload_server(captured: Arc<Mutex<Option<String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind diagnostics backend");
    let address = listener.local_addr().expect("local address");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept diagnostics upload");
        let request = read_complete_http_request(&mut stream);
        *captured.lock().expect("capture diagnostics request") = Some(request);
        let body = r#"{"upload_id":"diag_upload_123","uploaded_at":"2026-05-05T09:30:00Z"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write diagnostics response");
    });
    format!("http://{address}")
}

fn unused_loopback_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused port");
    let address = listener.local_addr().expect("local address");
    drop(listener);
    format!("http://{address}")
}

/// A trusted-format loopback URL on a port nothing listens on. Telemetry
/// control tests pass this as the *request* `api_base_url` to prove the
/// control-token resolver ignores it: if validation were (insecurely)
/// routed here it would fail with connection-refused, but the resolver
/// instead uses the mock backend wired through OTTTO_API_BASE_URL.
const ATTACKER_LOOPBACK_API_BASE_URL: &str = "http://127.0.0.1:1";

/// Fixed stand-in for `MachineIdentity::account_scope`. Shaped like the real
/// derivation (`otu_` + 32 hex) but not derived from any real uid.
const TEST_ACCOUNT_SCOPE: &str = "otu_00112233445566778899aabbccddeeff";

fn read_complete_http_request(stream: &mut std::net::TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                request.extend_from_slice(&buffer[..bytes_read]);
                if http_request_complete(&request) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&request).to_string()
}

fn http_request_complete(request: &[u8]) -> bool {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    request.len() >= body_start + content_length
}

fn http_request_body(request: &str) -> &str {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

/// Loopback backend answering each request in order with `(status, body)`;
/// joining it returns the raw requests.
fn scripted_json_backend(
    answers: Vec<(u16, &'static str)>,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted backend");
    let address = listener.local_addr().expect("scripted backend address");
    let server = thread::spawn(move || {
        answers
            .into_iter()
            .map(|(status, body)| {
                let (mut stream, _) = listener.accept().expect("accept scripted request");
                let request = read_complete_http_request(&mut stream);
                write_json_response(&mut stream, status, "Scripted", body);
                request
            })
            .collect()
    });
    (format!("http://{address}"), server)
}

fn write_json_response(stream: &mut std::net::TcpStream, status: u16, reason: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write response");
}

fn test_control_token(action: &str, source: &str, expires_in_seconds: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64;
    let payload = serde_json::json!({
        "type": "apps_control",
        "source": source,
        "action": action,
        "organization_id": "org_123",
        "exp": now + expires_in_seconds,
    });
    format!(
        "header.{}.signature",
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes())
    )
}

fn daemon() -> LocalDaemon {
    LocalDaemon::new(
        test_machine(),
        ControlToken::new("token").expect("token"),
        "2026-05-05T09:20:00Z",
    )
}

const RELOGIN_CUTOFF: &str = "2026-10-01T00:00:00Z";

fn relogin_env(name: &str) -> [EnvVarGuard; 2] {
    let secrets = telemetry_key_store_root(&format!("{name}-secret"));
    fs::create_dir_all(&secrets).expect("secret root");
    [
        EnvVarGuard::set_path(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            &telemetry_key_store_root(name),
        ),
        EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets),
    ]
}

fn relogin_device(device_id: &str, sources: &[&str]) -> LocalDeviceBinding {
    LocalDeviceBinding {
        device_id: device_id.to_string(),
        machine_id: Some("machine_test".to_string()),
        sources: sources.iter().map(|source| source.to_string()).collect(),
    }
}

fn relogin_account(user: &str, org: &str) -> (LocalAccountBinding, LocalConnectionBinding) {
    let mut account = connected_account();
    account.user.as_mut().unwrap().id = user.to_string();
    account.organization.as_mut().unwrap().id = org.to_string();
    let connection = LocalConnectionBinding {
        setup_run_id: format!("setup-{user}"),
        setup_run_token_expires_at: "2099-01-01T00:00:00Z".to_string(),
        machine_id: Some("machine_test".to_string()),
        claim_code: Some(format!("claim-{user}")),
        api_base_url: DEFAULT_API_BASE_URL.to_string(),
    };
    (account, connection)
}

/// A legacy (owner-less) active device of connected `user`; its first claim
/// set a dated cutoff and completed Codex backfill on the returned namespace.
fn install_legacy_active(device_id: &str, sources: &[&str], user: &str) -> String {
    let (account, connection) = relogin_account(user, "org_test");
    FileAccountStore::default().save(&account).unwrap();
    FileConnectionStore::default().save(&connection).unwrap();
    let device = relogin_device(device_id, sources);
    FileDeviceStore::default().save(&device).unwrap();
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("secret-0")
        .unwrap();
    let namespace = raw_namespace(device_id, "secret-0");
    let support = default_support_dir();
    crate::backfill::apply_claim_backfill_policy_for_destination(
        &support,
        Some("from"),
        Some(RELOGIN_CUTOFF),
        user,
        Some(&namespace),
    )
    .unwrap();
    let codex = crate::snapshots::SnapshotSource::Codex;
    crate::backfill::update_backfill_state(&support, |state| {
        crate::backfill::mark_backfill_complete_for_destination(state, codex, &namespace)
    })
    .unwrap();
    namespace
}

/// The local-only logout steps that matter here: retain, then reset.
fn relogin_local_logout() {
    retain_prior_device_credential_for_logout().unwrap();
    FileAccountStore::default().reset().unwrap();
    FileConnectionStore::default().reset().unwrap();
    FileDeviceStore::default().reset().unwrap();
    let secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT);
    secret.delete().unwrap();
}

/// A setup claim by `user`/`org` rotating `prior` to `next` (dated
/// backfill at the first cutoff), decided as at stage time.
fn relogin_claim(
    prior: &PriorDeviceCredential,
    user: &str,
    org: &str,
    next: LocalDeviceBinding,
) -> (PendingDeviceCredentialPreparation, String, String) {
    let candidate = format!("candidate-{}-{}", next.device_id, "secret".repeat(3));
    let setup_token = format!("setup-{}-{}", next.device_id, "token".repeat(3));
    let (account, connection) = relogin_account(user, org);
    let mut pending = test_pending_device_credential(&next.device_id, true);
    pending.request_authority = Some(device_credential_request_authority(
        "setup_claim",
        &next.device_id,
        &test_machine(),
        Some(prior),
        Some(IDENTITY_CONTINUITY_CAPABILITY),
    ));
    pending.device = next;
    pending.secret_commitment_sha256 = secret_sha256(&candidate);
    pending.claim_commit = Some(PendingClaimCredentialCommit {
        target_user_id: user.to_string(),
        account,
        connection,
        setup_run_token_sha256: secret_sha256(&setup_token),
        backfill_policy: Some("from".to_string()),
        backfill_cutoff_at: Some(RELOGIN_CUTOFF.to_string()),
    });
    select_owner_snapshot_namespace(
        &mut pending,
        &candidate,
        Some(prior),
        &FileOwnerSnapshotNamespaceStore::default(),
        &default_support_dir(),
    )
    .unwrap();
    (pending, candidate, setup_token)
}

/// Synthetic direct-switch driver through current selection and recovery.
pub(crate) fn account_return_claim_for_test(
    user: &str,
    org: &str,
    device_id: &str,
    record_initial: bool,
) -> (LocalDeviceBinding, String) {
    let machine = test_machine();
    FileMachineStore::default()
        .save(&LocalMachineBinding {
            machine_id: machine.machine_id.clone(),
            installation_id: machine.installation_id.clone(),
            hardware_uuid: machine.hardware_uuid.clone(),
        })
        .unwrap();
    let device = relogin_device(device_id, &["claude_code", "codex", "pi"]);
    let api = std::env::var("OTTTO_API_BASE_URL").expect("synthetic receiver URL");
    if let Some(prior) = prior_device_credential_for_registration().unwrap() {
        assert_ne!(prior.owner.as_ref().unwrap().user_id, user);
        // Direct switching retains predecessor proof without a logout seed.
        relogin_local_logout();
    } else if !record_initial {
        // Pre-existing owners without a row are not adopted by this fix.
        let (account, mut connection) = relogin_account(user, org);
        connection.api_base_url = api;
        FileAccountStore::default().save(&account).unwrap();
        FileConnectionStore::default().save(&connection).unwrap();
        FileDeviceStore::default().save(&device).unwrap();
        KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
            .save("synthetic-return-secret-a")
            .unwrap();
        return crate::snapshot_client::load_snapshot_device_credentials().unwrap();
    }
    let prior = prior_device_credential_for_registration().unwrap();
    let (mut pending, secret) = owner_return_pending(user, org, device_id);
    pending.api_base_url = api.clone();
    pending
        .claim_commit
        .as_mut()
        .unwrap()
        .connection
        .api_base_url = api;
    pending.request_authority = Some(device_credential_request_authority(
        "setup_claim",
        device_id,
        &machine,
        prior.as_ref(),
        Some(IDENTITY_CONTINUITY_CAPABILITY),
    ));
    select_owner_snapshot_namespace(
        &mut pending,
        &secret,
        prior.as_ref(),
        &FileOwnerSnapshotNamespaceStore::default(),
        &default_support_dir(),
    )
    .unwrap();
    promote_relogin(&pending, &secret, "setup");
    clear_prior_device_credential().unwrap();
    let active = crate::snapshot_client::load_snapshot_device_credentials().unwrap();
    assert_eq!(active, (device, secret));
    active
}

fn journaled_namespace(pending: &PendingDeviceCredentialPreparation) -> Option<String> {
    let authority = pending.request_authority.as_ref()?;
    authority.canonical_snapshot_namespace.clone()
}

fn stored_journal_namespace() -> Option<String> {
    let pending = FilePendingDeviceCredentialStore::default().load().unwrap();
    journaled_namespace(&pending?)
}

/// Stage, confirm and promote through startup recovery.
fn promote_relogin(pending: &PendingDeviceCredentialPreparation, candidate: &str, token: &str) {
    stage_pending_device_credential(pending, candidate).unwrap();
    stage_pending_setup_run_token(pending, token).unwrap();
    let store = FilePendingDeviceCredentialStore::default();
    mark_pending_device_credential_confirmed(pending, "2026-11-05T00:00:00Z", &store).unwrap();
    assert_eq!(recover_pending_device_credential_at_startup(), Ok(true));
}

/// What the snapshot loader and resolver use for the active credential.
fn active_namespace() -> String {
    let (device, secret) = crate::snapshot_client::load_snapshot_device_credentials().unwrap();
    crate::snapshot_sync::snapshot_upload_destination_namespace(&device, &secret)
}

fn raw_namespace(device_id: &str, secret: &str) -> String {
    let device = relogin_device(device_id, &[]);
    crate::snapshot_sync::snapshot_destination_namespace(&device, secret, None)
}

fn cutoff_destination() -> Option<String> {
    let state = crate::backfill::load_backfill_state(&default_support_dir());
    assert_eq!(state.backfill_cutoff_at.as_deref(), Some(RELOGIN_CUTOFF));
    state.backfill_cutoff_destination_namespace
}

fn owner_return_pending(
    user: &str,
    org: &str,
    id: &str,
) -> (PendingDeviceCredentialPreparation, String) {
    OWNER_SNAPSHOT_MACHINE_FOR_TEST.with(|v| v.set(Some(true)));
    let mut pending = test_pending_device_credential(id, true);
    let candidate = format!("candidate-{id}");
    pending.secret_commitment_sha256 = secret_sha256(&candidate);
    pending.device = relogin_device(id, &["claude_code", "codex", "pi"]);
    pending.request_authority = Some(device_credential_request_authority(
        "setup_claim",
        id,
        &test_machine(),
        None,
        None,
    ));
    let (account, connection) = relogin_account(user, org);
    pending.claim_commit = Some(PendingClaimCredentialCommit {
        account,
        connection,
        target_user_id: user.into(),
        setup_run_token_sha256: secret_sha256("setup"),
        backfill_policy: Some("from".into()),
        backfill_cutoff_at: Some(RELOGIN_CUTOFF.into()),
    });
    (pending, candidate)
}

pub(crate) fn owner_return_seed_for_test(namespace: &str, user: &str) {
    let (mut pending, _) = owner_return_pending(user, "org", "initial");
    pending.api_base_url = validated_api_base_url(None).unwrap();
    pending
        .claim_commit
        .as_mut()
        .unwrap()
        .connection
        .api_base_url = pending.api_base_url.clone();
    let row = OwnerSnapshotNamespace {
        key: pending_owner_snapshot_key(&pending).unwrap(),
        namespace: namespace.into(),
    };
    FileOwnerSnapshotNamespaceStore::default()
        .upsert(&[row])
        .unwrap();
}

/// Synthetic driver of the production selection, validation, publication and
/// active-envelope seams. Only physical hardware observation is injected.
pub(crate) fn owner_return_credential_for_test(
    device: &LocalDeviceBinding,
    candidate: &str,
    user: &str,
) -> String {
    let (mut pending, _) = owner_return_pending(user, "org", &device.device_id);
    pending.device = device.clone();
    pending.secret_commitment_sha256 = secret_sha256(candidate);
    pending.api_base_url = validated_api_base_url(None).unwrap();
    let commit = pending.claim_commit.as_mut().unwrap();
    let second = i64::from(Sha256::digest(device.device_id.as_bytes())[0]);
    commit.account.connected_at = Some(
        time::OffsetDateTime::from_unix_timestamp(1_700_000_000 + second)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    );
    commit.connection.api_base_url = pending.api_base_url.clone();
    commit.backfill_cutoff_at = Some("2026-08-01T00:00:00Z".into());
    commit.connection.machine_id = device.machine_id.clone();
    let prior = prior_device_credential_for_registration().unwrap();
    pending.request_authority = Some(device_credential_request_authority(
        "setup_claim",
        &device.device_id,
        &test_machine(),
        prior.as_ref(),
        Some(IDENTITY_CONTINUITY_CAPABILITY),
    ));
    pending.request_authority.as_mut().unwrap().machine_id = device.machine_id.clone().unwrap();
    let store = FileOwnerSnapshotNamespaceStore::default();
    select_owner_snapshot_namespace(
        &mut pending,
        candidate,
        prior.as_ref(),
        &store,
        &default_support_dir(),
    )
    .unwrap();
    let pending_store = FilePendingDeviceCredentialStore::default();
    let pending_secret = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT);
    stage_pending_device_credential_with_stores(
        &pending,
        candidate,
        &pending_store,
        &pending_secret,
    )
    .unwrap();
    stage_pending_setup_run_token(&pending, "setup").unwrap();
    let confirmed =
        mark_pending_device_credential_confirmed(&pending, "2026-11-16T08:00:00Z", &pending_store)
            .unwrap();
    // Restart boundary: reload the staged journal and candidate through
    // the real startup recovery owner, including account/connection/cutoff.
    assert_eq!(pending_store.load().unwrap().as_ref(), Some(&confirmed));
    assert_eq!(recover_pending_device_credential_at_startup(), Ok(true));
    assert!(pending_store.load().unwrap().is_none());
    let claim = confirmed.claim_commit.as_ref().unwrap();
    assert_eq!(FileAccountStore::default().load().unwrap(), claim.account);
    assert_eq!(
        FileConnectionStore::default().load().unwrap().as_ref(),
        Some(&claim.connection)
    );
    let backfill = crate::backfill::load_backfill_state(&default_support_dir());
    assert_eq!(backfill.backfill_cutoff_at, claim.backfill_cutoff_at);
    clear_prior_device_credential().unwrap();
    crate::snapshot_sync::snapshot_destination_namespace(
        device,
        candidate,
        pending_snapshot_alias(&pending).as_ref(),
    )
}

#[test]
/// [regress] Logout after either active write cannot publish a mixed
/// namespace or alter already-recorded forward history before pending clear.
fn owner_return_logout_preserves_history_at_promotion_failure_cuts() {
    for existing_history in [false, true] {
        for cut in ["candidate-secret", "device-envelope", "account-binding"] {
            let root = crate::test_scratch::ScratchDir::canonical("owner-return-logout-cut");
            let store = FileOwnerSnapshotNamespaceStore::new(root.join("history.json"));
            let (mut pending, candidate) = owner_return_pending("b", "org", cut);
            let mut seed = OwnerSnapshotNamespace {
                key: pending_owner_snapshot_key(&pending).unwrap(),
                namespace: "a".repeat(64),
            };
            seed.key.owner.user_id = "a".into();
            if existing_history {
                store.upsert(std::slice::from_ref(&seed)).unwrap();
            }
            let namespace = crate::snapshot_sync::snapshot_destination_namespace(
                &pending.device,
                &candidate,
                None,
            );
            let key = pending_owner_snapshot_key(&pending).unwrap();
            let authority = pending.request_authority.as_mut().unwrap();
            authority.incoming_snapshot_namespace = Some(OwnerSnapshotNamespace { key, namespace });
            pending.schema_version = OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION;
            pending.confirmed_at = Some("confirmed".into());
            assert!(
                !owner_snapshot_logout_can_retain_active(&pending).unwrap(),
                "never retain mixed active authority at {cut}"
            );
            assert_eq!(
                store.load().unwrap(),
                if existing_history {
                    vec![seed.clone()]
                } else {
                    Vec::new()
                },
                "logout preserves only already-recorded A at {cut}"
            );
            assert!(!owner_snapshot_logout_can_retain_active(&pending).unwrap());
            assert_eq!(
                store.load().unwrap(),
                if existing_history {
                    vec![seed]
                } else {
                    Vec::new()
                }
            );
        }
    }
}

#[test]
#[serial]
/// [regress] Before the confirm guard the active pair is intact: ordinary
/// logout still seeds it even when a pending unconfirmed switch exists.
fn owner_return_pre_guard_logout_seeds_the_intact_active_owner() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let _env = relogin_env("return-logout-intact-seed");
    let machine = test_machine();
    FileMachineStore::default()
        .save(&ottto_core::LocalMachineBinding {
            machine_id: machine.machine_id,
            installation_id: machine.installation_id,
            hardware_uuid: machine.hardware_uuid,
        })
        .unwrap();
    let device = relogin_device("logout-owner-a", &["codex"]);
    let namespace = owner_return_credential_for_test(&device, "logout-a-secret", "a");
    let history = FileOwnerSnapshotNamespaceStore::default();
    fs::remove_file(history.path()).unwrap();
    let (mut pending, _) = owner_return_pending("b", "org", "logout-b-pending");
    pending.preconfirm_guards_passed = false;
    FilePendingDeviceCredentialStore::default()
        .save(&pending)
        .unwrap();
    assert!(seed_owner_snapshot_history_for_logout().unwrap());
    let rows = history.load().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key.owner.user_id, "a");
    assert_eq!(rows[0].namespace, namespace);
    assert_eq!(
        FilePendingDeviceCredentialStore::default()
            .load()
            .unwrap()
            .as_ref(),
        Some(&pending)
    );
}

#[test]
#[serial]
/// [regress] History retention failures never block local/cloud logout or
/// installation reset; the existing Unknown-history claim fence survives.
fn owner_return_logout_skips_unreadable_history_and_counts_the_diagnostic() {
    if !crate::test_isolation::run_here() {
        return;
    }
    for local_only in [true, false] {
        for forget_installation in [false, true] {
            for unreadable in [true, false] {
                let _env = relogin_env(&format!(
                    "return-logout-history-{local_only}-{forget_installation}-{unreadable}"
                ));
                let machine = test_machine();
                FileMachineStore::default()
                    .save(&LocalMachineBinding {
                        machine_id: machine.machine_id,
                        installation_id: machine.installation_id,
                        hardware_uuid: machine.hardware_uuid,
                    })
                    .unwrap();
                let device = relogin_device("history-error-device", &["codex"]);
                owner_return_credential_for_test(&device, "history-error-secret", "a");
                let history = FileOwnerSnapshotNamespaceStore::default();
                fs::remove_file(history.path()).unwrap();
                if unreadable {
                    // Nonregular input fails deterministically, even as root.
                    fs::create_dir(history.path()).unwrap();
                } else {
                    fs::write(history.path(), b"invalid history").unwrap();
                }
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let mut connection = FileConnectionStore::default().load().unwrap().unwrap();
                connection.api_base_url = format!("http://{address}");
                FileConnectionStore::default().save(&connection).unwrap();
                let server = (!local_only).then(|| {
                    thread::spawn(move || {
                        let (mut stream, _) = listener.accept().unwrap();
                        let request = read_complete_http_request(&mut stream);
                        assert!(request.starts_with("POST /api/v1/setup-runs/"));
                        write_json_response(
                            &mut stream,
                            200,
                            "OK",
                            r#"{"setup_run_id":"setup-a","run_status":"disconnected","client_disconnected":true,"disconnected_at":"2026-10-18T12:00:00Z","device_released":true}"#,
                        );
                    })
                });
                let daemon = daemon()
                    .with_account(FileAccountStore::default().load().unwrap())
                    .with_connection(Some(connection));
                let (response, diagnostics) = crate::local_resource_diagnostics::capture(|| {
                    handle_request(
                        &daemon,
                        auth_reset_request("logout-history-error", local_only, forget_installation),
                    )
                });
                if let Some(server) = server {
                    server.join().unwrap();
                }
                assert!(response.ok, "{response:?}");
                assert_eq!(
                    daemon.status("token").unwrap().account.state,
                    LocalAccountState::NotConnected
                );
                assert!(FileDeviceStore::default().load().unwrap().is_none());
                assert_eq!(
                    FileMachineStore::default().load().unwrap().is_none(),
                    forget_installation
                );
                assert!(
                    history.load().is_err(),
                    "Unknown was not replaced with a seed"
                );
                if unreadable {
                    assert_eq!(fs::read_dir(history.path()).unwrap().count(), 0);
                } else {
                    assert_eq!(fs::read(history.path()).unwrap(), b"invalid history");
                }
                let skipped: Vec<_> = diagnostics
                    .iter()
                    .filter(|row| row["stage"] == "owner_history_seed_skipped")
                    .collect();
                assert_eq!(skipped.len(), 1, "one counted skip per logout");
                assert_eq!(skipped[0]["counts"], json!({"skipped_seeds": 1}));
                let encoded = serde_json::to_string(&skipped).unwrap();
                for private in [
                    "history-error-device",
                    "history-error-secret",
                    "invalid history",
                    history.path().to_str().unwrap(),
                ] {
                    assert!(!encoded.contains(private));
                }
            }
        }
    }
}

#[test]
/// [regress] Canceling an unconfirmed switch during local logout retains
/// the intact predecessor pair; the candidate grants no incoming history.
fn owner_return_logout_with_unconfirmed_switch_retains_the_active_pair() {
    use ottto_core::token_store::MemoryTokenStore;
    for authorized in [false, true] {
        let root = crate::test_scratch::ScratchDir::canonical("owner-return-unconfirmed-logout");
        let store = FileOwnerSnapshotNamespaceStore::new(root.join("history.json"));
        let (mut pending, _) = owner_return_pending("b", "org", "unconfirmed");
        let key = pending_owner_snapshot_key(&pending).unwrap();
        let mut seed = OwnerSnapshotNamespace {
            key: key.clone(),
            namespace: "a".repeat(64),
        };
        seed.key.owner.user_id = "a".into();
        store.upsert(std::slice::from_ref(&seed)).unwrap();
        let authority = pending.request_authority.as_mut().unwrap();
        authority.incoming_snapshot_namespace = Some(OwnerSnapshotNamespace {
            key,
            namespace: "b".repeat(64),
        });
        pending.schema_version = OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION;
        pending.confirmation_authorized = authorized;
        pending.preconfirm_guards_passed = false;
        let active = FileDeviceStore::new(root.join("active.json"));
        let device = relogin_device("original-a", &["codex"]);
        active.save(&device).unwrap();
        let secret = MemoryTokenStore::new();
        secret.save("original-a-secret").unwrap();
        let prior = FileDeviceStore::new(root.join("prior.json"));
        let prior_secret = MemoryTokenStore::new();
        assert!(owner_snapshot_logout_can_retain_active(&pending).unwrap());
        retain_prior_device_credential_with_stores(
            &active,
            &secret,
            &prior,
            &prior_secret,
            Some(LocalCredentialOwner {
                user_id: "a".into(),
                organization_id: "org".into(),
                api_base_url: DEFAULT_API_BASE_URL.into(),
            }),
        )
        .unwrap();
        assert_eq!(prior.load().unwrap(), Some(device));
        assert_eq!(prior_secret.load().unwrap(), "original-a-secret");
        let journal = FilePendingDeviceCredentialStore::new(root.join("pending.json"));
        journal.save(&pending).unwrap();
        journal.reset().unwrap();
        assert!(journal.load().unwrap().is_none());
        assert_eq!(
            store.load().unwrap(),
            vec![seed],
            "incoming B is never published by logout"
        );
    }
}

pub(super) fn owner_return_test_machine(key: &OwnerSnapshotKey) -> Result<bool, LocalApiError> {
    Ok(key.machine_id == "machine_test"
        && key.installation_id == "install_test"
        && (key.account_scope == TEST_ACCOUNT_SCOPE
            || crate::local_account_scope("machine_test").as_deref()
                == Some(key.account_scope.as_str())))
}

#[test]
/// [behaviour] Exact matching, long owner chains, rotation, frozen selection,
/// positive deletion and idempotent confirmed-history publication.
fn owner_return_claims_reuse_only_their_exact_recorded_destination() {
    let root = crate::test_scratch::ScratchDir::canonical("owner-return-claims");
    let store = FileOwnerSnapshotNamespaceStore::new(root.join("history.json"));
    let mut first = None;
    for (i, user) in ["a", "b", "c", "a", "a"].iter().enumerate() {
        let (mut pending, candidate) = owner_return_pending(user, "org", &format!("claim-{i}"));
        select_owner_snapshot_namespace(&mut pending, &candidate, None, &store, &root).unwrap();
        let incoming = pending
            .request_authority
            .as_ref()
            .unwrap()
            .incoming_snapshot_namespace
            .as_ref()
            .unwrap()
            .clone();
        if i == 0 {
            first = Some(incoming.clone());
        }
        if i >= 3 {
            assert_eq!(incoming, first.clone().unwrap());
        } else if i > 0 {
            assert_ne!(incoming.namespace, first.as_ref().unwrap().namespace);
        }
        assert_eq!(
            pending.schema_version,
            OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION
        );
        assert_eq!(
            publish_owner_snapshot_history(&pending, &store),
            Err(LocalApiError::StatePoisoned),
            "unconfirmed cannot publish"
        );
        pending.confirmed_at = Some("confirmed".into());
        publish_owner_snapshot_history(&pending, &store).unwrap();
        publish_owner_snapshot_history(&pending, &store).unwrap();
        validate_owner_snapshot_selection(&pending, &candidate, &store).unwrap();
        let dir = root
            .join("snapshots/destinations")
            .join(&incoming.namespace);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("codex-scan-index-v3.json"), b"{}").unwrap();
    }
    assert_eq!(store.load().unwrap().len(), 3, "rotation replaces the row");
    let a = first.unwrap();
    // Organization and endpoint are independent destinations. A changed
    // installation/OS account/physical machine has no authority to reuse.
    for changed in ["org", "api", "install", "scope", "machine", "hardware"] {
        let (mut pending, candidate) = owner_return_pending("a", "org", changed);
        match changed {
            "org" => {
                pending
                    .claim_commit
                    .as_mut()
                    .unwrap()
                    .account
                    .organization
                    .as_mut()
                    .unwrap()
                    .id += "-other"
            }
            "api" => {
                let base = format!("{DEFAULT_API_BASE_URL}/other");
                pending.api_base_url = base.clone();
                pending
                    .claim_commit
                    .as_mut()
                    .unwrap()
                    .connection
                    .api_base_url = base;
            }
            "install" => pending.request_authority.as_mut().unwrap().installation_id += "-new",
            "scope" => {
                pending.request_authority.as_mut().unwrap().account_scope = Some("other".into())
            }
            "machine" => pending.device.machine_id = Some("second-mac".into()),
            _ => {}
        }
        OWNER_SNAPSHOT_MACHINE_FOR_TEST.with(|v| v.set(Some(changed != "hardware")));
        select_owner_snapshot_namespace(&mut pending, &candidate, None, &store, &root).unwrap();
        assert!(pending_snapshot_alias(&pending).is_none(), "{changed}");
    }
    let (mut pending, candidate) = owner_return_pending("a", "org", "frozen");
    select_owner_snapshot_namespace(&mut pending, &candidate, None, &store, &root).unwrap();
    let journal =
        FilePendingDeviceCredentialStore::new(root.join("pending-device-credential.json"));
    journal.save(&pending).unwrap();
    fs::remove_dir_all(root.join("snapshots/destinations").join(&a.namespace)).unwrap();
    let (mut retry, _) = owner_return_pending("a", "org", "frozen");
    select_owner_snapshot_namespace(&mut retry, &candidate, None, &store, &root).unwrap();
    assert_eq!(
        retry, pending,
        "independent deletion cannot mutate a frozen choice"
    );
    journal.reset().unwrap();
    let (mut deleted, secret) = owner_return_pending("a", "org", "deleted");
    select_owner_snapshot_namespace(&mut deleted, &secret, None, &store, &root).unwrap();
    assert!(pending_snapshot_alias(&deleted).is_none());
    assert_ne!(
        deleted
            .request_authority
            .as_ref()
            .unwrap()
            .incoming_snapshot_namespace
            .as_ref()
            .unwrap()
            .namespace,
        a.namespace
    );
    deleted.confirmed_at = Some("confirmed".into());
    publish_owner_snapshot_history(&deleted, &store).unwrap();
    assert_eq!(store.load().unwrap().len(), 3);
}

#[test]
/// [behaviour] Recorded return history survives v3 decode before/after
/// confirmation, with/without another owner's prior rotation tuple.
fn owner_return_history_and_downgrade_journal_rows() {
    for has_prior in [false, true] {
        for confirmed in [false, true] {
            let root = crate::test_scratch::ScratchDir::canonical("owner-return-journal");
            let store = FileOwnerSnapshotNamespaceStore::new(root.join("history.json"));
            let (mut pending, candidate) = owner_return_pending("a", "org", "seed");
            let key = pending_owner_snapshot_key(&pending).unwrap();
            let seed = OwnerSnapshotNamespace {
                key,
                namespace: "a".repeat(64),
            };
            let dir = root.join("snapshots/destinations").join(&seed.namespace);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("pi-scan-index-v3.json"), b"{}").unwrap();
            let prior = PriorDeviceCredential {
                machine_id: Some("machine_test".into()),
                device_id: "prior".into(),
                device_sources: vec!["pi".into()],
                device_secret: "old-secret".into(),
                owner: Some(LocalCredentialOwner {
                    user_id: "b".into(),
                    organization_id: "org".into(),
                    api_base_url: DEFAULT_API_BASE_URL.into(),
                }),
                snapshot_namespace: seed.namespace.clone(),
            };
            if has_prior {
                pending.request_authority = Some(device_credential_request_authority(
                    "setup_claim",
                    "seed",
                    &test_machine(),
                    Some(&prior),
                    Some(IDENTITY_CONTINUITY_CAPABILITY),
                ));
            }
            store.upsert(&[seed]).unwrap();
            select_owner_snapshot_namespace(
                &mut pending,
                &candidate,
                has_prior.then_some(&prior),
                &store,
                &root,
            )
            .unwrap();
            pending.confirmed_at = confirmed.then(|| "confirmed".into());
            let decoded: PendingDeviceCredentialPreparation =
                serde_json::from_slice(&serde_json::to_vec(&pending).unwrap()).unwrap();
            validate_owner_snapshot_selection(&decoded, &candidate, &store).unwrap();
            assert_ne!(
                decoded.schema_version, PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION,
                "old reader rejects before promotion, with or without rotation tuple"
            );
            assert_eq!(
                pending_snapshot_alias(&decoded)
                    .unwrap()
                    .secret_commitment_sha256,
                secret_sha256(&candidate)
            );
            let mut downgraded = decoded.clone();
            downgraded.schema_version = PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION;
            assert_eq!(
                validate_pending_prior_credential_binding(&downgraded),
                Err(LocalApiError::StatePoisoned)
            );
            if confirmed {
                publish_owner_snapshot_history(&decoded, &store).unwrap();
            } else {
                assert_eq!(
                    publish_owner_snapshot_history(&decoded, &store),
                    Err(LocalApiError::StatePoisoned)
                );
            }
            let mut corrupt = decoded;
            corrupt
                .request_authority
                .as_mut()
                .unwrap()
                .incoming_snapshot_namespace
                .as_mut()
                .unwrap()
                .key
                .owner
                .organization_id += "-changed";
            assert_eq!(
                validate_owner_snapshot_selection(&corrupt, &candidate, &store),
                Err(LocalApiError::StatePoisoned)
            );
        }
    }
}

#[test]
#[serial]
/// [regress] Rotation keeps main's floor with no history, source custody,
/// installation/OS scope or live hardware proof available.
fn owner_return_rotation_matches_main_without_return_proof() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let _env = relogin_env("rotation-main-floor");
    let canonical = install_legacy_active("rotation-old", &["codex"], "user_test");
    let prior = prior_device_credential_for_registration().unwrap().unwrap();
    let (mut pending, candidate, token) = relogin_claim(
        &prior,
        "user_test",
        "org_test",
        relogin_device("rotation-next", &["codex"]),
    );
    pending.request_authority.as_mut().unwrap().account_scope = None;
    pending.request_authority.as_mut().unwrap().hardware_uuid = None;
    OWNER_SNAPSHOT_MACHINE_FOR_TEST.with(|v| v.set(Some(false)));
    let store = FileOwnerSnapshotNamespaceStore::default();
    fs::write(store.path(), b"unreadable history").unwrap();
    assert!(!default_support_dir()
        .join("snapshots/destinations")
        .join(&canonical)
        .exists());
    select_owner_snapshot_namespace(
        &mut pending,
        &candidate,
        Some(&prior),
        &store,
        &default_support_dir(),
    )
    .unwrap();
    assert_eq!(
        pending.schema_version,
        PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION
    );
    assert_eq!(journaled_namespace(&pending), Some(canonical.clone()));
    promote_relogin(&pending, &candidate, &token);
    assert_eq!(active_namespace(), canonical);
    assert_eq!(fs::read(store.path()).unwrap(), b"unreadable history");
}

#[test]
#[serial]
/// [behaviour] A mid-claim restart reloads released v2 and history-bearing
/// v3 journals before/after server confirmation and commits cutoff/account.
fn owner_return_claim_restart_recovers_v2_and_v3_boundaries() {
    if !crate::test_isolation::run_here() {
        return;
    }
    for version in [
        PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION,
        OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION,
    ] {
        for confirmed in [false, true] {
            let _env = relogin_env(&format!("return-restart-{version}-{confirmed}"));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let (mut pending, candidate) = owner_return_pending("a", "org", "restart");
            pending.api_base_url = base.clone();
            pending
                .claim_commit
                .as_mut()
                .unwrap()
                .connection
                .api_base_url = base;
            let cutoff = "2026-11-15T08:00:00Z";
            pending.claim_commit.as_mut().unwrap().backfill_cutoff_at = Some(cutoff.into());
            let store = FileOwnerSnapshotNamespaceStore::default();
            if version == OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION {
                select_owner_snapshot_namespace(
                    &mut pending,
                    &candidate,
                    None,
                    &store,
                    &default_support_dir(),
                )
                .unwrap();
            }
            assert_eq!(pending.schema_version, version);
            stage_pending_device_credential(&pending, &candidate).unwrap();
            stage_pending_setup_run_token(&pending, "setup").unwrap();
            let journal = FilePendingDeviceCredentialStore::default();
            if confirmed {
                mark_pending_device_credential_confirmed(
                    &pending,
                    "2026-11-16T08:00:00Z",
                    &journal,
                )
                .unwrap();
            }
            let receipt = json!({"preparation_id": pending.preparation_id, "status":"confirmed", "confirmed_at":"2026-11-16T08:00:00Z",
                "credential_generation":pending.credential_generation,
                "device":{"id":pending.device.device_id,"machine_id":pending.device.machine_id,"sources":pending.device.sources},
                "credential_rotation_performed":false});
            let server = (!confirmed).then(|| {
                thread::spawn(move || {
                    let (mut request, _) = listener.accept().unwrap();
                    let bytes = read_complete_http_request(&mut request);
                    assert!(bytes.contains("/device-credential-preparations/"));
                    write_json_response(&mut request, 200, "OK", &receipt.to_string());
                })
            });
            if confirmed {
                // Actual partial promotion: active halves/account are written,
                // connection publication fails, and incoming history stays owed.
                let connection = FileConnectionStore::default();
                fs::create_dir_all(connection.path()).unwrap();
                assert_eq!(
                    recover_pending_device_credential_at_startup(),
                    Err(LocalApiError::StatePoisoned)
                );
                assert!(journal.load().unwrap().is_some());
                assert!(store.load().unwrap().is_empty());
                fs::remove_dir(connection.path()).unwrap();
            }
            assert_eq!(recover_pending_device_credential_at_startup(), Ok(true));
            if let Some(server) = server {
                server.join().unwrap();
            }
            assert!(journal.load().unwrap().is_none());
            let claim = pending.claim_commit.as_ref().unwrap();
            assert_eq!(FileAccountStore::default().load().unwrap(), claim.account);
            assert_eq!(
                FileConnectionStore::default().load().unwrap().as_ref(),
                Some(&claim.connection)
            );
            let backfill = crate::backfill::load_backfill_state(&default_support_dir());
            assert_eq!(backfill.backfill_cutoff_at.as_deref(), Some(cutoff));
            assert_eq!(
                backfill.backfill_cutoff_destination_namespace.as_deref(),
                Some(active_namespace().as_str())
            );
            assert_eq!(
                store.load().unwrap().len(),
                usize::from(version == OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION)
            );
        }
    }
}

#[test]
#[serial]
/// [regress] A same-account claim re-login keeps the local
/// namespace for each source, re-claimed while bound or after a local
/// logout of a legacy (owner-less) device, along A→B and A→B→C. A grant
/// added by the successor, or dropped by the next, changes nothing; the
/// first claim's dated cutoff stays bound to the namespace.
fn same_account_relogin_keeps_snapshot_namespace() {
    if !crate::test_isolation::run_here() {
        return;
    }
    for source in ["claude_code", "codex", "pi"] {
        let grants: [&[&str]; 2] = [&["claude_code", "codex", "pi"], &[source]];
        for (logout, links) in [(false, 1), (false, 2), (true, 1), (true, 2)] {
            let row = format!("{source}, logout={logout}, links={links}");
            let _env = relogin_env(&format!("relogin-keep-{source}-{logout}-{links}"));
            let id = |link: usize| format!("device-{source}-{link}");
            let canonical = install_legacy_active(&id(0), &[source], "user_test");
            for link in 1..=links {
                if logout {
                    relogin_local_logout();
                }
                let prior = prior_device_credential_for_registration().unwrap().unwrap();
                assert_eq!(prior.snapshot_namespace, canonical, "{row}");
                let next = relogin_device(&id(link), grants[link - 1]);
                let (pending, candidate, token) =
                    relogin_claim(&prior, "user_test", "org_test", next);
                assert_eq!(journaled_namespace(&pending), Some(canonical.clone()));
                promote_relogin(&pending, &candidate, &token);
                assert_eq!(active_namespace(), canonical, "{row}");
                assert_ne!(raw_namespace(&id(link), &candidate), canonical);
                let binding = FileDeviceStore::default().load_envelope().unwrap().unwrap();
                let owner = binding.continuity.owner.unwrap();
                assert_eq!(
                    [owner.user_id, owner.organization_id],
                    ["user_test", "org_test"]
                );
                let alias = binding.continuity.snapshot_namespace.unwrap();
                assert_eq!(alias.namespace, canonical, "{row}: copied, never chained");
                assert_eq!(cutoff_destination(), Some(canonical.clone()), "{row}");
            }
        }
    }
}

#[test]
#[serial]
/// R5: a claim that does not prove the same account on the same API and
/// machine journals no namespace; the promoted credential resolves raw
/// and inherits none of the predecessor's backfill completion. "0-case"
/// rows are defensive checks no current caller reaches.
fn relogin_refusals_start_a_fresh_namespace() {
    if !crate::test_isolation::run_here() {
        return;
    }
    type Pending = PendingDeviceCredentialPreparation;
    fn claim(pending: &mut Pending) -> &mut PendingClaimCredentialCommit {
        pending.claim_commit.as_mut().unwrap()
    }
    fn authority(pending: &mut Pending) -> &mut PendingDeviceCredentialRequestAuthority {
        pending.request_authority.as_mut().unwrap()
    }
    let promoted = |row: &str, edit: &dyn Fn(&mut Pending, &mut PriorDeviceCredential)| {
        let _env = relogin_env(&format!("relogin-refuse-{row}"));
        let canonical = install_legacy_active("device-refuse-a", &["codex"], "user_test");
        let mut prior = prior_device_credential_for_registration().unwrap().unwrap();
        let next = relogin_device("device-refuse-b", &["codex"]);
        let (mut pending, candidate, token) = relogin_claim(&prior, "user_test", "org_test", next);
        let original = pending.claim_commit.clone().unwrap();
        authority(&mut pending).canonical_snapshot_namespace = None;
        edit(&mut pending, &mut prior);
        let prior = (row != "no prior").then_some(&prior);
        select_owner_snapshot_namespace(
            &mut pending,
            &candidate,
            prior,
            &FileOwnerSnapshotNamespaceStore::default(),
            &default_support_dir(),
        )
        .unwrap();
        // A claim the commit validator refuses cannot promote at all.
        let commit = pending.claim_commit.get_or_insert_with(|| original.clone());
        if commit.account.user.is_none() {
            commit.account.user = original.account.user;
        }
        promote_relogin(&pending, &candidate, &token);
        let namespace = active_namespace();
        let owed = |namespace: &str| {
            let state = crate::backfill::load_backfill_state(&default_support_dir());
            crate::backfill::pending_backfill_sources_for_destination(&state, namespace)
        };
        let codex = crate::snapshots::SnapshotSource::Codex;
        assert!(!owed(&canonical).contains(&codex), "{row}");
        let inherited = !owed(&namespace).contains(&codex);
        (pending, namespace, candidate, inherited)
    };
    let fresh = |row: &str, edit: &dyn Fn(&mut Pending, &mut PriorDeviceCredential)| {
        let (pending, namespace, candidate, inherited) = promoted(row, edit);
        assert_eq!(journaled_namespace(&pending), None, "{row}");
        assert!(!inherited, "{row}: no predecessor completion");
        let raw = raw_namespace("device-refuse-b", &candidate);
        assert_eq!(namespace, raw, "{row}");
    };
    let (control, namespace, _, inherited) = promoted("control", &|_, _| {});
    assert!(inherited, "control keeps its completion");
    assert_eq!(journaled_namespace(&control), Some(namespace), "kept");
    fresh("different user", &|p, _| {
        claim(p).target_user_id += "x";
        claim(p).account.user.as_mut().unwrap().id += "x";
    });
    fresh("other org", &|p, _| {
        claim(p).account.organization.as_mut().unwrap().id += "x"
    });
    fresh("None user", &|p, _| claim(p).account.user = None);
    fresh("None org", &|p, _| claim(p).account.organization = None);
    fresh("None machine", &|p, _| p.device.machine_id = None);
    fresh("other machine", &|p, _| {
        p.device.machine_id = Some("other".into())
    });
    fresh("no prior", &|_, _| {});
    fresh("no owner", &|_, prior| prior.owner = None);
    fresh("api differs", &|_, prior| {
        prior.owner.as_mut().unwrap().api_base_url = "https://api.other.example".into()
    });
    fresh("register route", &|p, _| {
        authority(p).flow = "register".into()
    });
    fresh("0-case: foreign prior", &|_, prior| prior.device_id += "x");
    fresh("0-case: no claim commit", &|p, _| p.claim_commit = None);

    // No journal carries a namespace on the register route or malformed.
    for (flow, namespace) in [("register", "a".repeat(64)), ("setup_claim", "zz".into())] {
        let mut pending = control.clone();
        authority(&mut pending).flow = flow.into();
        authority(&mut pending).canonical_snapshot_namespace = Some(namespace);
        let refused = validate_pending_prior_credential_binding(&pending);
        assert_eq!(refused, Err(LocalApiError::StatePoisoned), "{flow}");
    }

    // The loader takes an alias only with this secret's commitment, even
    // when its namespace is another credential's raw hash, and a reload
    // after a legacy save stripped it resolves raw in the same process.
    let _env = relogin_env("relogin-carry");
    let device = relogin_device("device-carry", &["codex"]);
    let install = |namespace: String, commitment: &str| {
        let snapshot_namespace = Some(SnapshotNamespaceAlias {
            namespace,
            secret_commitment_sha256: secret_sha256(commitment),
        });
        let continuity = DeviceCredentialContinuity {
            owner: None,
            snapshot_namespace,
        };
        let envelope = LocalDeviceEnvelope {
            device: device.clone(),
            continuity,
        };
        FileDeviceStore::default().save_envelope(&envelope).unwrap();
    };
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save("secret-1")
        .unwrap();
    let s1_raw = raw_namespace("device-carry", "secret-1");
    install(s1_raw.clone(), "secret-2");
    assert_eq!(active_namespace(), s1_raw);
    let s2 = crate::snapshot_sync::snapshot_upload_destination_namespace(&device, "secret-2");
    assert_eq!(s2, raw_namespace("device-carry", "secret-2"), "foreign");
    install("Z".repeat(64), "secret-1");
    assert_eq!(active_namespace(), s1_raw, "malformed alias");
    install("c".repeat(64), "secret-1");
    assert_eq!(active_namespace(), "c".repeat(64));
    FileDeviceStore::default().save(&device).unwrap();
    assert_eq!(active_namespace(), s1_raw, "legacy save, then reload");
    drop(_env);

    // Different user, owner retained after a local logout of user A.
    let _env = relogin_env("relogin-cross-account");
    install_legacy_active("device-cross-a", &["codex"], "user_a");
    relogin_local_logout();
    let prior = prior_device_credential_for_registration().unwrap().unwrap();
    let next = relogin_device("device-cross-b", &["codex"]);
    let (pending, candidate, token) = relogin_claim(&prior, "user_b", "org_test", next);
    assert_eq!(journaled_namespace(&pending), None);
    promote_relogin(&pending, &candidate, &token);
    let fresh = raw_namespace("device-cross-b", &candidate);
    assert_eq!(active_namespace(), fresh, "owner retained, different user");
    assert_eq!(
        cutoff_destination(),
        Some(fresh),
        "the new account's cutoff"
    );
}

#[test]
#[serial]
/// R2: a crash at each journal step keeps the namespace decided before
/// staging; it comes only from the immutable journal, never from hashing
/// the old device with the new secret. Unconfirmed cuts recover through
/// the server (the existing recovery tests), so they assert the journal.
fn relogin_crash_cuts_keep_the_journaled_namespace() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let restart = recover_pending_device_credential_at_startup;
    let fenced = || crate::snapshot_client::load_snapshot_device_credentials().is_err();
    for (cut, row) in [
        "staged",
        "guards passed",
        "confirmed",
        "candidate secret written",
        "envelope written and read back",
        "claim commit blocked",
    ]
    .into_iter()
    .enumerate()
    {
        let _env = relogin_env(&format!("relogin-cut-{cut}"));
        let canonical = install_legacy_active("device-cut-a", &["codex"], "user_test");
        let prior = prior_device_credential_for_registration().unwrap().unwrap();
        let next = relogin_device("device-cut-b", &["codex"]);
        let (mut pending, candidate, token) = relogin_claim(&prior, "user_test", "org_test", next);
        pending.preconfirm_guards_passed = false;
        stage_pending_device_credential(&pending, &candidate).unwrap();
        stage_pending_setup_run_token(&pending, &token).unwrap();
        assert_eq!(stored_journal_namespace(), Some(canonical.clone()), "{row}");
        if cut == 0 {
            assert_eq!(
                active_namespace(),
                canonical,
                "{row}: old credential usable"
            );
            continue;
        }
        let store = FilePendingDeviceCredentialStore::default();
        let pending = mark_pending_device_credential_guards_passed(&pending, &store).unwrap();
        let confirmed = (cut >= 2).then(|| {
            let at = "2026-11-05T00:00:00Z";
            mark_pending_device_credential_confirmed(&pending, at, &store).unwrap()
        });
        let active_secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT);
        if cut >= 3 {
            active_secret.save(&candidate).unwrap();
        }
        if let Some(confirmed) = confirmed.as_ref().filter(|_| cut >= 4) {
            let devices = FileDeviceStore::default();
            write_and_verify_active_device_credential(
                confirmed,
                &candidate,
                &devices,
                &active_secret,
            )
            .unwrap();
        }
        if cut == 5 {
            let connection = ottto_core::default_connection_path();
            fs::remove_file(&connection).unwrap();
            fs::create_dir(&connection).unwrap();
            assert_eq!(restart(), Err(LocalApiError::StatePoisoned), "{row}");
            fs::remove_dir(&connection).unwrap();
        }
        assert!(fenced(), "{row}");
        assert_eq!(stored_journal_namespace(), Some(canonical.clone()), "{row}");
        if cut >= 2 {
            assert_eq!(restart(), Ok(true), "{row}");
            assert_eq!(active_namespace(), canonical, "{row}: restart");
            assert_eq!(restart(), Ok(false), "{row}");
            assert_eq!(active_namespace(), canonical, "{row}: second restart");
        }
    }
}

fn connected_account() -> LocalAccountBinding {
    LocalAccountBinding {
        state: LocalAccountState::Connected,
        user: Some(LocalAccountUser {
            id: "user_test".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
        }),
        organization: Some(LocalAccountOrganization {
            id: "org_test".to_string(),
            name: "Test Org".to_string(),
        }),
        connected_at: Some("2026-05-05T09:00:00Z".to_string()),
        last_refreshed_at: Some("2026-05-05T09:20:00Z".to_string()),
        message: None,
        can_reconnect: None,
    }
}

fn test_machine() -> MachineIdentity {
    MachineIdentity {
        machine_id: "machine_test".to_string(),
        installation_id: "install_test".to_string(),
        display_name: "Test Mac".to_string(),
        hostname: "test-mac.local".to_string(),
        os: OperatingSystem::Macos,
        arch: "arm64".to_string(),
        local_platform_version: "0.1.0".to_string(),
        hardware_uuid: None,
        account_scope: Some(TEST_ACCOUNT_SCOPE.to_string()),
    }
}

mod claude_settings;

mod admission_matrix;

/// Doctor names a second install variant: a formula next to an app-owned
/// daemon (each keg version once), a Homebrew-owned daemon with an app bundle
/// installed, or a root LaunchDaemon. It lists folders and reads no file.
#[test]
fn doctor_names_a_second_install_variant() {
    let root = control_test_root("doctor-install-variants");
    let arm = root.join("opt-homebrew-Cellar-ottto");
    let intel = root.join("usr-local-Cellar-ottto");
    for keg in [
        arm.join("0.1.258"),
        intel.join("0.1.258"),
        intel.join("0.1.255"),
    ] {
        create_control_test_dir(&keg);
    }
    fs::write(arm.join("not-a-keg"), b"").unwrap();
    create_control_test_dir(&arm.join("bad name"));
    let cellars = [arm.as_path(), intel.as_path()];
    let app = root.join("Applications").join("Ottto.app");
    let helpers = app.join("Contents").join("Helpers");
    create_control_test_dir(&helpers);
    let apps = [root.join("missing").join("Ottto.app"), app.clone()];
    let no_apps = [root.join("missing").join("Ottto.app")];
    let system_plist = root.join("net.ottto.service.plist");
    let empty = root.join("empty-cellar");
    create_control_test_dir(&empty);
    let missing = root.join("missing");
    let no_cellars = [empty.as_path(), missing.as_path()];

    let conflict =
        install_variant_conflict_in(InstallOwner::AppBundle, &cellars, &apps, &system_plist)
            .unwrap();
    assert_eq!(conflict["kind"], json!("formula_next_to_app"));
    assert_eq!(conflict["versions"], json!(["0.1.255", "0.1.258"]));
    assert_eq!(
        conflict["daemon_version"],
        json!(crate::compiled_release_version())
    );
    assert_eq!(conflict["system_service"], json!(false));
    assert!(install_variant_conflict_in(
        InstallOwner::AppBundle,
        &no_cellars,
        &apps,
        &system_plist
    )
    .is_none());

    // The app bundle counts only with its bundled service.
    assert!(
        install_variant_conflict_in(InstallOwner::Homebrew, &cellars, &no_apps, &system_plist)
            .is_none()
    );
    fs::write(helpers.join("ottto-service"), b"").unwrap();
    let conflict =
        install_variant_conflict_in(InstallOwner::Homebrew, &cellars, &apps, &system_plist)
            .unwrap();
    assert_eq!(conflict["kind"], json!("homebrew_service_with_app"));
    assert_eq!(conflict["app_installed"], json!(true));

    for owner in [
        InstallOwner::HostedInstaller,
        InstallOwner::Dev,
        InstallOwner::Unknown,
    ] {
        assert!(install_variant_conflict_in(owner, &cellars, &apps, &system_plist).is_none());
    }

    fs::write(&system_plist, b"").unwrap();
    let conflict =
        install_variant_conflict_in(InstallOwner::Dev, &no_cellars, &no_apps, &system_plist)
            .unwrap();
    assert_eq!(conflict["kind"], json!("system_service"));
    let conflict =
        install_variant_conflict_in(InstallOwner::AppBundle, &cellars, &apps, &system_plist)
            .unwrap();
    assert_eq!(conflict["kind"], json!("formula_next_to_app"));
    assert_eq!(conflict["system_service"], json!(true));
    let _ = fs::remove_dir_all(&root);
}
