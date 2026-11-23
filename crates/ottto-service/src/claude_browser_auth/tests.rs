use super::*;
use serial_test::serial;
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

struct EnvGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let previous = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        unsafe { std::env::remove_var(key) };
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

fn temp_dir(label: &str) -> PathBuf {
    fs::canonicalize(std::env::temp_dir())
        .expect("canonical scratch parent")
        .join(crate::test_scratch::unique_name(&format!(
            "ottto-claude-browser-auth-{label}"
        )))
}

fn with_support(label: &str) -> (PathBuf, PathBuf, EnvGuard) {
    let root = temp_dir(label);
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    #[cfg(unix)]
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    let guard = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    (root, support, guard)
}

/// Finalize `operation_id` with a proof for the a/b pair and return the
/// Claude status passes it asked for immediately.
fn finalize_requests_now(operation_id: &str) -> Vec<ottto_protocol::SourceKind> {
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    let ((), requested) = crate::agent_status_refresh::with_test_requests_now(|| {
        finalize_identity(
            operation_id,
            crate::agent_status::ClaudeLocalIdentityProof {
                account_identifier_hash: account.clone(),
                organization_identifier_hash: organization.clone(),
                collection: ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                    state: ottto_protocol::ClaudeConfigSlotCollectionStateV1::Fresh,
                    account_identifier_hash: Some(account.clone()),
                    organization_identifier_hash: Some(organization.clone()),
                    ..Default::default()
                },
            },
        )
        .expect("finalize");
    });
    requested
}

/// Only a completed sign-in asks for one immediate Claude status pass; a
/// replay of the same finalization asks for none.
fn assert_one_completed_request(operation_id: &str) {
    assert_eq!(
        finalize_requests_now(operation_id),
        vec![ottto_protocol::SourceKind::ClaudeCode]
    );
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::Complete)
    );
    assert!(
        finalize_requests_now(operation_id).is_empty(),
        "a replayed finalization asks for no second pass"
    );
}

/// A journal written before code entry was retired may hold a code phase and
/// an invalid-code marker. Status shows the passive browser wait with no code
/// error, the legacy capability bit stays for older apps, projection never
/// rewrites the journal, and the next save drops the marker.
#[test]
#[serial]
fn legacy_code_phases_project_as_browser_wait_and_marker_is_dropped_on_save() {
    let (root, _support_dir, _support) = with_support("legacy-code-projection");
    let operation_id = "claude_setup_c0dec0dec0dec0dec0dec0dec0dec0de";
    let store = FileClaudeConfigSlotSettingsStore::default();
    let status =
        prepare_generic(store.load().expect("registry"), operation_id).expect("prepare generic");
    for phase in [
        ClaudeBrowserAuthPhaseV1::WaitingForCode,
        ClaudeBrowserAuthPhaseV1::SubmittingCode,
    ] {
        set_phase(operation_id, phase);
        let mut journal: serde_json::Value =
            serde_json::from_slice(&fs::read(state_path()).expect("journal")).expect("json");
        journal["invalid_code_operation_id"] = serde_json::json!(operation_id);
        fs::write(
            state_path(),
            serde_json::to_vec_pretty(&journal).expect("legacy journal"),
        )
        .expect("write legacy journal");

        let annotated = annotate_status(status.clone());
        assert_eq!(annotated.browser_auth_supported, Some(true));
        assert_eq!(annotated.auth_code_entry_supported, Some(cfg!(unix)));
        let auth = annotated
            .setup_operation
            .browser_auth
            .expect("browser auth");
        assert_eq!(auth.phase, ClaudeBrowserAuthPhaseV1::WaitingForProvider);
        assert_eq!(auth.code_error, None);
        assert!(!auth.terminal_fallback_available);
        let persisted = read_operation(operation_id).expect("operation");
        assert_eq!(
            persisted.phase, phase,
            "projection never rewrites the journal"
        );
        assert_eq!(
            synthetic_operation(&persisted).state,
            ClaudeAccountSetupOperationState::WaitingForUserLogin
        );

        set_phase(operation_id, phase);
        let saved = fs::read_to_string(state_path()).expect("saved journal");
        assert!(!saved.contains("invalid_code_operation_id"));
    }
    finish(operation_id, ClaudeBrowserAuthOutcomeV1::Cancelled, None);
    let _ = fs::remove_dir_all(root);
}

/// After a restart, a nonterminal legacy `submitting_code` operation takes the
/// ordinary recovery path: nothing is relaunched, it moves to Validating with
/// its original deadline and root, and an identity proof finalizes it.
#[test]
#[serial]
fn restart_with_legacy_submitting_code_recovers_through_validating_to_complete() {
    let (root, _support_dir, _support) = with_support("legacy-submitting-code-restart");
    let empty_bin = root.join("empty-bin");
    fs::create_dir_all(&empty_bin).expect("empty command dir");
    // No CLI or keychain tool is reachable: recovery can never prove the
    // identity on its own or spawn anything real.
    let _commands = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &empty_bin);
    let operation_id = "claude_setup_c1dec1dec1dec1dec1dec1dec1dec1de";
    let store = FileClaudeConfigSlotSettingsStore::default();
    prepare_generic(store.load().expect("registry"), operation_id).expect("prepare generic");
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::SubmittingCode);
    let before = read_operation(operation_id).expect("legacy operation");

    let operation = operation_id.to_string();
    let recovery = thread::spawn(move || recover_operation(&operation));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let current = read_operation(operation_id).expect("operation");
        if current.phase == ClaudeBrowserAuthPhaseV1::Validating {
            assert!(current.outcome.is_none());
            assert_eq!(current.deadline_unix_seconds, before.deadline_unix_seconds);
            assert_eq!(current.config_dir, before.config_dir);
            assert_eq!(current.slot_id, before.slot_id);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the legacy phase never entered recovery validation"
        );
        thread::sleep(Duration::from_millis(25));
    }
    assert!(!provider_process_active(operation_id).expect("lock state"));

    assert_one_completed_request(operation_id);
    recovery.join().expect("recovery");
    assert!(read_state().active_operation_id.is_none());
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn production_supervisor_environment_keeps_the_resolved_operation_journal() {
    let root = temp_dir("production-supervisor-environment");
    let home = root.join("home");
    fs::create_dir_all(&home).expect("home");
    let _support = EnvGuard::remove("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR");
    let _home = EnvGuard::set("HOME", &home);
    let mut command = std::process::Command::new("/usr/bin/true");

    configure_auth_supervisor_environment(&mut command);

    let support_dir = command
        .get_envs()
        .find(|(key, _)| *key == OsStr::new("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR"))
        .and_then(|(_, value)| value)
        .map(PathBuf::from)
        .expect("explicit supervisor support directory");
    assert_eq!(
        support_dir,
        home.join("Library")
            .join("Application Support")
            .join("Ottto")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[cfg(unix)]
fn private_provider_pty_is_interactive_and_does_not_echo_secrets() {
    use std::os::fd::AsRawFd;

    let (provider_io, provider_tty) = private_provider_pty().expect("private provider PTY");
    assert_eq!(unsafe { libc::isatty(provider_tty.as_raw_fd()) }, 1);
    for fd in [provider_io.as_raw_fd(), provider_tty.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
    let mut attributes = std::mem::MaybeUninit::<libc::termios>::uninit();
    assert_eq!(
        unsafe { libc::tcgetattr(provider_tty.as_raw_fd(), attributes.as_mut_ptr()) },
        0
    );
    // SAFETY: tcgetattr initialized the structure on success.
    let attributes = unsafe { attributes.assume_init() };
    assert_eq!(attributes.c_lflag & (libc::ECHO | libc::ECHONL), 0);
}

static SUPERVISOR_TEST_ENTRY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
const SUPERVISOR_TEST_ARGS_ENV: &str = "OTTTO_TEST_AUTH_SUPERVISOR_ARGS";
const SUPERVISOR_TEST_ENTRY_NAME: &str = "claude_browser_auth::tests::auth_supervisor_test_entry";

/// Opts one test into launching the real supervisor; every other test keeps
/// the unrouted launch, which the test binary rejects before any provider runs.
struct SupervisorTestEntry;

impl SupervisorTestEntry {
    fn enable() -> Self {
        SUPERVISOR_TEST_ENTRY.store(true, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

impl Drop for SupervisorTestEntry {
    fn drop(&mut self) {
        SUPERVISOR_TEST_ENTRY.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Rebuilds the worker's supervisor launch as this test binary running only
/// [`auth_supervisor_test_entry`], with the unchanged supervisor arguments,
/// environment and inherited pipe descriptors.
#[cfg(unix)]
pub(super) fn route_supervisor_to_test_entry(command: &mut std::process::Command) {
    if !SUPERVISOR_TEST_ENTRY.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let args = command
        .get_args()
        .map(|arg| arg.to_str().expect("utf8 supervisor argument"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut routed = std::process::Command::new(command.get_program());
    routed.env_clear();
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            routed.env(key, value);
        }
    }
    routed.env(SUPERVISOR_TEST_ARGS_ENV, args).args([
        "--exact",
        SUPERVISOR_TEST_ENTRY_NAME,
        "--nocapture",
        "--test-threads=1",
        "--quiet",
    ]);
    *command = routed;
}

/// The supervisor half of a routed launch. In an ordinary test run the
/// variable is absent and this returns at once.
#[test]
#[cfg(unix)]
fn auth_supervisor_test_entry() {
    let Ok(args) = std::env::var(SUPERVISOR_TEST_ARGS_ENV) else {
        return;
    };
    let args = args.split('\n').collect::<Vec<_>>();
    assert_eq!(args.first(), Some(&"claude-auth-supervisor"));
    let value = |flag: &str| {
        args.iter()
            .position(|arg| *arg == flag)
            .and_then(|index| args.get(index + 1))
            .copied()
            .expect("supervisor flag")
    };
    let code = run_auth_supervisor(
        value("--operation-id"),
        value("--config-dir"),
        value("--control-fd").parse().expect("control fd"),
        value("--ready-fd").parse().expect("ready fd"),
    )
    .unwrap_or(1);
    std::process::exit(code);
}

/// Passive browser completion across the whole boundary: the worker launches
/// the real supervisor, the provider shows its paste prompt, nothing answers
/// it, and the provider then finishes the way a browser callback does (it
/// writes the login and identity) and exits 0. The worker sees the witness
/// change, proves the identity and admits it: one completed sign-in.
#[test]
#[serial]
#[cfg(unix)]
fn passive_browser_completion_reaches_witness_identity_and_admission() {
    let (root, _support_dir, _support) = with_support("passive-browser-completion");
    let bin = root.join("bin");
    let home = root.join("home");
    fs::create_dir_all(&bin).expect("bin");
    fs::create_dir_all(&home).expect("home");
    let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &bin);
    let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home);
    // No keychain item: the stored login is read from the slot's own
    // credentials file on every platform.
    let security = bin.join("security");
    fs::write(&security, "#!/bin/sh\nexit 44\n").expect("fake security");
    fs::set_permissions(&security, fs::Permissions::from_mode(0o755)).expect("security mode");

    let operation_id = "claude_setup_b0b1b0b1b0b1b0b1b0b1b0b1b0b1b0b1";
    let store = FileClaudeConfigSlotSettingsStore::default();
    let prepared =
        prepare_generic(store.load().expect("registry"), operation_id).expect("prepare generic");
    let config_dir = read_operation(operation_id).expect("operation").config_dir;
    let prompted = root.join("prompted");
    let identity = serde_json::json!({
        "oauthAccount": {
            "accountUuid": "passive-account",
            "organizationUuid": "passive-organization",
            "emailAddress": "passive@example.invalid",
            "organizationType": "claude_max"
        }
    });
    let expires_at = (unix_seconds() + 3 * 60 * 60) * 1_000;
    let credential = serde_json::json!({
        "claudeAiOauth": {
            "accessToken": "fixture-passive-access",
            "refreshToken": "fixture-passive-refresh",
            "expiresAt": expires_at,
            "refreshTokenExpiresAt": expires_at + 25 * 24 * 60 * 60 * 1_000,
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max"
        }
    });
    let claude = bin.join("claude");
    fs::write(
        &claude,
        format!(
            "#!/bin/sh\nfor fd in 0 1 2; do test -t \"$fd\" || exit 42; done\nprintf 'Paste code here if prompted >' >&2\n: > '{prompted}'\numask 077\nprintf '%s' '{identity}' > '{config}/.claude.json'\nprintf '%s' '{credential}' > '{config}/.credentials.json'\nexit 0\n",
            prompted = prompted.display(),
            config = config_dir,
        ),
    )
    .expect("fake claude");
    fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).expect("claude mode");

    let _entry = SupervisorTestEntry::enable();
    start(prepared, BrowserLoginMode::Generic).expect("start browser sign-in");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut phases = Vec::new();
    let completed = loop {
        let operation = read_operation(operation_id).expect("operation");
        if phases.last() != Some(&operation.phase) {
            phases.push(operation.phase);
        }
        if operation.outcome.is_some() && read_state().active_operation_id.is_none() {
            break operation;
        }
        assert!(
            Instant::now() < deadline,
            "passive completion did not finish: {phases:?}"
        );
        thread::sleep(Duration::from_millis(25));
    };

    assert!(prompted.exists(), "the provider showed its paste prompt");
    assert_eq!(
        completed.outcome,
        Some(ClaudeBrowserAuthOutcomeV1::Complete),
        "{phases:?}"
    );
    assert!(phases.iter().all(|phase| !matches!(
        phase,
        ClaudeBrowserAuthPhaseV1::WaitingForCode | ClaudeBrowserAuthPhaseV1::SubmittingCode
    )));
    let canonical = completed.canonical_slot_id.expect("admitted slot");
    assert!(store
        .load()
        .expect("registry after admission")
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == canonical));
    assert!(!provider_process_active(operation_id).expect("provider lock released"));
    let account = ottto_core::claude_cli_account_identifier_hash_at(
        &Path::new(&config_dir).join(".claude.json"),
    );
    let lines =
        crate::provider_calls::test_lines(crate::provider_calls::CallKind::ClaudeSignIn, &account);
    assert_eq!(
        lines
            .iter()
            .map(|line| (line.result.as_str(), line.requests_at_least))
            .collect::<Vec<_>>(),
        [("ok", 1)]
    );
    let _ = fs::remove_dir_all(root);
}

/// A legacy `--code-fd` is closed without being read, and only when it is a
/// live read-only pipe: a write end or a standard stream is left alone.
#[test]
#[cfg(unix)]
fn legacy_code_fd_closes_only_a_read_only_pipe() {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let [read_fd, write_fd] = fds;
    let write_byte = || unsafe { libc::write(write_fd, b"x".as_ptr().cast(), 1) };

    close_legacy_code_fd(-1);
    close_legacy_code_fd(libc::STDIN_FILENO);
    close_legacy_code_fd(write_fd);
    assert_eq!(write_byte(), 1, "the write end and its reader stay open");

    close_legacy_code_fd(read_fd);
    // With the only reader closed, a write fails with EPIPE even if another
    // thread has since reused the closed descriptor number.
    assert_eq!(write_byte(), -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPIPE)
    );
    unsafe { libc::close(write_fd) };
}

#[test]
#[cfg(unix)]
fn provider_output_drain_consumes_unbounded_output_until_eof() {
    use std::sync::mpsc;

    let (provider_io, provider_tty) = private_provider_pty().expect("private provider PTY");
    let (drained_tx, drained_rx) = mpsc::channel();
    let drain = thread::spawn(move || {
        drain_provider_output(provider_io);
        let _ = drained_tx.send(());
    });
    let (written_tx, written_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        let mut provider_tty = provider_tty;
        // Far more than any PTY buffer: a stalled drain blocks this writer.
        let chunk = [b'x'; 4096];
        for _ in 0..64 {
            provider_tty.write_all(&chunk).expect("provider write");
        }
        let _ = written_tx.send(());
    });
    written_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("256 KiB of provider output drained without a consumer");
    writer.join().expect("writer thread");
    drained_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("drain ends once the provider side closes");
    drain.join().expect("drain thread");
}

#[test]
fn public_metadata_contains_no_path_or_identity() {
    let operation = PersistedOperation {
        operation_id: "claude_setup_0123456789abcdef0123456789abcdef".to_string(),
        slot_id: "claude_slot_0123456789abcdef0123456789abcdef".to_string(),
        config_dir: "/private/provisional".to_string(),
        ceremony_baseline: None,
        mode: PersistedMode::Generic,
        target_id: None,
        expected_account_identifier_hash: None,
        expected_organization_identifier_hash: None,
        phase: ClaudeBrowserAuthPhaseV1::Complete,
        outcome: Some(ClaudeBrowserAuthOutcomeV1::AlreadyConnected),
        canonical_slot_id: Some("claude_slot_fedcba9876543210fedcba9876543210".to_string()),
        admission_slot_id: None,
        identity_mismatch: None,
        cancel_requested: false,
        started_unix_seconds: 1,
        deadline_unix_seconds: 2,
        completed_unix_seconds: Some(2),
        fallback_completed: false,
    };
    let wire = serde_json::to_string(&public_operation(&operation)).expect("serialize");
    for forbidden in [
        "config_dir",
        "/Users/",
        "account_identifier",
        "organization_identifier",
    ] {
        assert!(!wire.contains(forbidden));
    }
}

#[test]
#[serial]
fn active_replay_shortcut_requires_exact_sealed_core_sidecar_binding() {
    let (root, _support_dir, _support) = with_support("active-replay-sealed-binding");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let operation_id = "claude_setup_03030303030303030303030303030303";
    let target_id = "claude_anchor_target_03030303030303030303030303030303";
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    let core = store
        .prepare_managed_account_target(
            1,
            operation_id.to_string(),
            Some(target_id.to_string()),
            Some(account.clone()),
            Some(organization.clone()),
        )
        .expect("target core");
    let slot_id = core.setup_operation.slot_id.clone().expect("slot");
    let config_dir = core
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == slot_id)
        .and_then(|slot| slot.config_dir.clone())
        .expect("config root");
    let base = PersistedOperation {
        operation_id: operation_id.to_string(),
        slot_id: slot_id.clone(),
        config_dir: config_dir.clone(),
        ceremony_baseline: Some("baseline".to_string()),
        mode: PersistedMode::Target,
        target_id: Some(target_id.to_string()),
        expected_account_identifier_hash: Some(account),
        expected_organization_identifier_hash: Some(organization),
        phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
        outcome: None,
        canonical_slot_id: None,
        admission_slot_id: None,
        identity_mismatch: None,
        cancel_requested: false,
        started_unix_seconds: 1,
        deadline_unix_seconds: u64::MAX,
        completed_unix_seconds: None,
        fallback_completed: false,
    };
    let install = |operations: Vec<PersistedOperation>, active: Option<&str>| {
        transact(|state| {
            state.operations = operations;
            state.active_operation_id = active.map(str::to_string);
        })
        .expect("install replay case");
    };
    install(vec![base.clone()], Some(operation_id));
    assert!(active_replay_is_sealed(
        &core,
        operation_id,
        BrowserLoginMode::Target
    ));
    for phase in [
        ClaudeBrowserAuthPhaseV1::WaitingForCode,
        ClaudeBrowserAuthPhaseV1::SubmittingCode,
    ] {
        let mut target = base.clone();
        target.phase = phase;
        install(vec![target.clone()], Some(operation_id));
        assert!(
            active_replay_is_sealed(&core, operation_id, BrowserLoginMode::Target),
            "targeted {phase:?} replay must remain sealed"
        );

        target.mode = PersistedMode::Reconnect;
        let mut reconnect_core = core.clone();
        reconnect_core.setup_operation.kind =
            ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot;
        install(vec![target], Some(operation_id));
        assert!(
            active_replay_is_sealed(&reconnect_core, operation_id, BrowserLoginMode::Reconnect),
            "reconnect {phase:?} replay must remain sealed"
        );
    }
    install(vec![base.clone()], Some(operation_id));

    let mut cases = Vec::new();
    let mut changed = base.clone();
    changed.mode = PersistedMode::Reconnect;
    cases.push(("sidecar kind", core.clone(), changed, Some(operation_id)));
    let mut changed_core = core.clone();
    changed_core.setup_operation.kind = ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot;
    cases.push(("core kind", changed_core, base.clone(), Some(operation_id)));
    let mut changed = base.clone();
    changed.target_id = Some("claude_anchor_target_ffffffffffffffffffffffffffffffff".to_string());
    cases.push(("target", core.clone(), changed, Some(operation_id)));
    let mut changed = base.clone();
    changed.expected_account_identifier_hash = Some("c".repeat(64));
    cases.push(("account hash", core.clone(), changed, Some(operation_id)));
    let mut changed = base.clone();
    changed.expected_organization_identifier_hash = Some("d".repeat(64));
    cases.push((
        "organization hash",
        core.clone(),
        changed,
        Some(operation_id),
    ));
    let mut changed = base.clone();
    changed.slot_id = "claude_slot_ffffffffffffffffffffffffffffffff".to_string();
    cases.push(("slot", core.clone(), changed, Some(operation_id)));
    let mut changed = base.clone();
    changed.config_dir = format!("{config_dir}-changed");
    cases.push(("raw config root", core.clone(), changed, Some(operation_id)));
    let mut changed = base.clone();
    changed.ceremony_baseline = None;
    cases.push(("unsealed", core.clone(), changed, Some(operation_id)));
    let mut changed = base.clone();
    changed.cancel_requested = true;
    cases.push(("cancel pending", core.clone(), changed, Some(operation_id)));
    let mut changed = base.clone();
    changed.deadline_unix_seconds = 0;
    cases.push(("expired", core.clone(), changed, Some(operation_id)));
    let mut placeholder = base.clone();
    placeholder.slot_id.clear();
    placeholder.config_dir.clear();
    placeholder.ceremony_baseline = None;
    placeholder.phase = ClaudeBrowserAuthPhaseV1::Prepared;
    cases.push((
        "pre-core placeholder",
        core.clone(),
        placeholder,
        Some(operation_id),
    ));
    let mut terminal = base.clone();
    terminal.phase = ClaudeBrowserAuthPhaseV1::Complete;
    terminal.outcome = Some(ClaudeBrowserAuthOutcomeV1::LoginFailed);
    terminal.completed_unix_seconds = Some(unix_seconds());
    cases.push((
        "terminal sidecar",
        core.clone(),
        terminal,
        Some(operation_id),
    ));
    let mut terminal_core = core.clone();
    terminal_core.setup_operation.state = ClaudeAccountSetupOperationState::SetupFailed;
    cases.push((
        "terminal core",
        terminal_core,
        base.clone(),
        Some(operation_id),
    ));
    let mut wrong_operation = core.clone();
    wrong_operation.setup_operation.operation_id =
        Some("claude_setup_ffffffffffffffffffffffffffffffff".to_string());
    cases.push((
        "core operation id",
        wrong_operation,
        base.clone(),
        Some(operation_id),
    ));
    cases.push(("inactive ceremony", core.clone(), base.clone(), None));
    cases.push((
        "wrong ceremony owner",
        core.clone(),
        base.clone(),
        Some("claude_setup_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    ));

    for (label, status, operation, active) in cases {
        install(vec![operation], active);
        assert!(
            !active_replay_is_sealed(&status, operation_id, BrowserLoginMode::Target),
            "{label} must not use the active replay shortcut"
        );
    }
    install(vec![base.clone(), base], Some(operation_id));
    assert!(!active_replay_is_sealed(
        &core,
        operation_id,
        BrowserLoginMode::Target
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn fallback_is_not_advertised_without_a_resolved_claude_executable() {
    let root = temp_dir("fallback-missing-executable");
    let support = root.join("support");
    let empty_bin = root.join("empty-bin");
    let home = root.join("home");
    fs::create_dir_all(&support).expect("support");
    fs::create_dir_all(&empty_bin).expect("empty bin");
    fs::create_dir_all(&home).expect("home");
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &empty_bin);
    let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home);
    let operation_id = "claude_setup_02020202020202020202020202020202";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    let prepared = prepare_generic(status, operation_id).expect("prepare");
    start(prepared, BrowserLoginMode::Generic).expect("start worker");
    let deadline = Instant::now() + Duration::from_secs(2);
    let operation = loop {
        let operation = read_operation(operation_id).expect("operation");
        if operation.outcome.is_some() || Instant::now() >= deadline {
            break operation;
        }
        thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(
        operation.outcome,
        Some(ClaudeBrowserAuthOutcomeV1::LoginFailed)
    );
    let public = public_operation(&operation);
    assert!(public.retryable);
    assert!(public.retry_requires_new_operation_id);
    assert!(!public.terminal_fallback_available);
    assert!(synthetic_operation(&operation).launch_command.is_none());
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn retained_provisional_count_is_identifier_free_and_omitted_at_zero() {
    let root = temp_dir("retained-count-privacy");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let empty = annotate_status(
        FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry"),
    );
    assert_eq!(empty.retained_provisional_login_count, None);
    assert!(!serde_json::to_string(&empty)
        .expect("empty wire")
        .contains("retained_provisional_login_count"));

    transact(|state| {
        state.quarantined_roots.push(QuarantinedRoot {
            root_id: "claude_slot_deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            config_dir: "/private/secret/customer-root".to_string(),
            service_alias: "Claude Code-credentials-deadbeef".to_string(),
            pending_registry_removal: false,
            claimed_by: None,
        });
    })
    .expect("retained root");
    let annotated = annotate_status(
        FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry"),
    );
    assert_eq!(annotated.retained_provisional_login_count, Some(1));
    let wire = serde_json::to_string(&annotated).expect("wire");
    assert!(wire.contains("\"retained_provisional_login_count\":1"));
    for forbidden in [
        "deadbeef",
        "customer-root",
        "Claude Code-credentials-deadbeef",
    ] {
        assert!(!wire.contains(forbidden));
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn active_browser_operation_overrides_unrelated_historical_core_status() {
    let (root, _support_dir, _support) = with_support("active-sidecar-over-historical-core");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let historical_id = "claude_setup_03030303030303030303030303030303";
    let historical = store
        .prepare_managed_account_target(
            1,
            historical_id.to_string(),
            Some("claude_anchor_target_03030303030303030303030303030303".to_string()),
            Some("a".repeat(64)),
            Some("b".repeat(64)),
        )
        .expect("historical core");
    store
        .transition_setup_operation_with_binding(
            1,
            historical_id,
            historical
                .setup_operation
                .expected_account_identifier_hash
                .as_deref(),
            historical
                .setup_operation
                .expected_organization_identifier_hash
                .as_deref(),
            ClaudeAccountSetupOperationState::SetupFailed,
            None,
            None,
            Some("historical"),
        )
        .expect("terminal historical core");
    let historical_slot = historical
        .setup_operation
        .slot_id
        .clone()
        .expect("historical slot");
    let historical_root = historical
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == historical_slot)
        .and_then(|slot| slot.config_dir.clone())
        .expect("historical root");
    transact(|state| {
        state.operations.push(PersistedOperation {
            operation_id: historical_id.to_string(),
            slot_id: historical_slot,
            config_dir: historical_root,
            ceremony_baseline: None,
            mode: PersistedMode::Target,
            target_id: historical.setup_operation.target_id.clone(),
            expected_account_identifier_hash: historical
                .setup_operation
                .expected_account_identifier_hash
                .clone(),
            expected_organization_identifier_hash: historical
                .setup_operation
                .expected_organization_identifier_hash
                .clone(),
            phase: ClaudeBrowserAuthPhaseV1::Complete,
            outcome: Some(ClaudeBrowserAuthOutcomeV1::LoginFailed),
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: unix_seconds(),
            deadline_unix_seconds: unix_seconds(),
            completed_unix_seconds: Some(unix_seconds()),
            fallback_completed: false,
        });
    })
    .expect("matching terminal browser sidecar");
    let active_id = "claude_setup_04040404040404040404040404040404";
    prepare_generic(store.load().expect("registry"), active_id).expect("active generic");

    let annotated = annotate_status(store.load().expect("status"));
    assert_eq!(
        annotated.setup_operation.operation_id.as_deref(),
        Some(active_id)
    );
    assert!(annotated.setup_operation.browser_auth.is_some());
    assert!(request_cancel(active_id).expect("cancel request"));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn pre_core_target_placeholder_with_matching_core_seals_exact_root() {
    let (root, _support_dir, _support) = with_support("pre-core-target-seal");
    let operation_id = "claude_setup_05050505050505050505050505050505";
    let target_id = "claude_anchor_target_05050505050505050505050505050505";
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    assert!(claim_ceremony(operation_id).expect("claim ceremony"));
    persist_registry_mutation_fence(
        operation_id,
        BrowserLoginMode::Target,
        None,
        None,
        Some(target_id),
        Some(&account),
        Some(&organization),
    )
    .expect("placeholder fence");
    let core = FileClaudeConfigSlotSettingsStore::default()
        .prepare_managed_account_target(
            1,
            operation_id.to_string(),
            Some(target_id.to_string()),
            Some(account),
            Some(organization),
        )
        .expect("core target");
    let placeholder = read_operation(operation_id).expect("placeholder");
    assert!(placeholder.slot_id.is_empty());
    assert!(placeholder.config_dir.is_empty());

    assert_eq!(
        reconcile_pre_core_fence(&placeholder).expect("reconcile"),
        PreCoreFenceRecovery::Sealed
    );
    let sealed = read_operation(operation_id).expect("sealed fence");
    let expected_slot = core.setup_operation.slot_id.expect("core slot");
    let expected_root = core
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == expected_slot)
        .and_then(|slot| slot.config_dir.clone())
        .expect("core root");
    assert_eq!(sealed.slot_id, expected_slot);
    assert_eq!(sealed.config_dir, expected_root);
    assert!(fail_operation(
        operation_id,
        ClaudeBrowserAuthOutcomeV1::LoginFailed
    ));
    release_ceremony(operation_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn pre_core_target_placeholder_releases_exact_reusable_claim_without_quarantining_parent() {
    let root = temp_dir("pre-core-target-abort");
    let support = root.join("support");
    let reusable = support
        .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
        .join("claude_slot_06060606060606060606060606060606");
    fs::create_dir_all(&reusable).expect("reusable root");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(
            support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME),
            fs::Permissions::from_mode(0o700),
        )
        .expect("managed mode");
        fs::set_permissions(&reusable, fs::Permissions::from_mode(0o700)).expect("root mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let operation_id = "claude_setup_06060606060606060606060606060606";
    assert!(claim_ceremony(operation_id).expect("claim ceremony"));
    transact(|state| {
        state.quarantined_roots.push(QuarantinedRoot {
            root_id: "claude_slot_06060606060606060606060606060606".to_string(),
            config_dir: reusable.to_string_lossy().into_owned(),
            service_alias: ClaudeConfigDirSlot::registered(reusable.to_string_lossy().into_owned())
                .expect("slot")
                .service_name(),
            pending_registry_removal: false,
            claimed_by: Some(operation_id.to_string()),
        });
    })
    .expect("reusable journal");
    persist_registry_mutation_fence(
        operation_id,
        BrowserLoginMode::Target,
        None,
        Some(reusable.to_string_lossy().as_ref()),
        Some("claude_anchor_target_06060606060606060606060606060606"),
        Some(&"a".repeat(64)),
        Some(&"b".repeat(64)),
    )
    .expect("pre-core target fence");

    recover_operation(operation_id);
    let state = read_state_strict().expect("recovered state");
    assert!(state
        .operations
        .iter()
        .all(|operation| operation.operation_id != operation_id));
    assert!(state.active_operation_id.is_none());
    assert_eq!(state.quarantined_roots.len(), 1);
    assert_eq!(
        state.quarantined_roots[0].config_dir,
        reusable.to_string_lossy()
    );
    assert!(state.quarantined_roots[0].claimed_by.is_none());
    assert!(state
        .quarantined_roots
        .iter()
        .all(|candidate| { candidate.config_dir != managed_root().to_string_lossy() }));
    let retry_id = "claude_setup_07070707070707070707070707070707";
    assert!(claim_ceremony(retry_id).expect("retry claim"));
    release_ceremony(retry_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn pre_core_reconnect_without_core_operation_aborts_fence_and_preserves_slot() {
    let root = temp_dir("pre-core-reconnect-abort");
    let support = root.join("support");
    let managed = support
        .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
        .join("claude_slot_08080808080808080808080808080808");
    fs::create_dir_all(&managed).expect("managed root");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(
            support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME),
            fs::Permissions::from_mode(0o700),
        )
        .expect("managed mode");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("root mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_managed_path(1, managed.to_string_lossy().into_owned())
        .expect("registered slot");
    let slot_id = registered.managed_slots[0].slot_id.clone();
    let operation_id = "claude_setup_08080808080808080808080808080808";
    assert!(claim_ceremony(operation_id).expect("claim ceremony"));
    persist_registry_mutation_fence(
        operation_id,
        BrowserLoginMode::Reconnect,
        Some(&slot_id),
        Some(managed.to_string_lossy().as_ref()),
        None,
        Some(&"a".repeat(64)),
        Some(&"b".repeat(64)),
    )
    .expect("pre-core reconnect fence");

    recover_operation(operation_id);
    assert!(read_operation(operation_id).is_none());
    assert!(read_state().active_operation_id.is_none());
    let after = store.load().expect("registry after recovery");
    assert!(after
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id
            && slot.config_dir.as_deref() == Some(managed.to_string_lossy().as_ref())));
    let retry_id = "claude_setup_09090909090909090909090909090909";
    assert!(claim_ceremony(retry_id).expect("retry claim"));
    release_ceremony(retry_id);
    let _ = fs::remove_dir_all(root);
}

/// A sign-in run is one provider-call line for setup: one that completed
/// sent at least the token exchange; one that timed out, was cancelled or was
/// given up on claims no request but is still logged.
#[test]
#[serial]
fn each_sign_in_run_is_one_provider_call_line() {
    use crate::provider_calls::{CallKind, CallResult};
    let root = temp_dir("sign-in-call-log");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", root.join("support"));
    let config_dir = root.join("slot");
    fs::create_dir_all(&config_dir).expect("slot");
    fs::write(
        config_dir.join(".claude.json"),
        serde_json::json!({"oauthAccount": {"accountUuid": "sign-in-account-uuid"}}).to_string(),
    )
    .expect("account");
    let account =
        ottto_core::claude_account_identifier_hash(Some("sign-in-account-uuid"), None, None);
    let config = config_dir.to_str().expect("utf8");
    SignInCall::started(config).finish(CallResult::Ok);
    let mut cancelled = SignInCall::started(config);
    cancelled.finish(CallResult::Error("cancelled"));
    cancelled.finish(CallResult::Ok);
    drop(SignInCall::started(config));
    SignInCall::started(config).finish(CallResult::Timeout);
    let lines = crate::provider_calls::test_lines(CallKind::ClaudeSignIn, &account);
    assert_eq!(
        lines
            .iter()
            .map(|line| (
                line.provider.as_str(),
                line.trigger.as_str(),
                line.result.as_str(),
                line.requests_at_least
            ))
            .collect::<Vec<_>>(),
        [
            ("anthropic", "setup", "ok", 1),
            ("anthropic", "setup", "cancelled", 0),
            ("anthropic", "setup", "abandoned", 0),
            ("anthropic", "setup", "timeout", 0),
        ]
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn login_command_uses_exact_argv_cleared_env_closed_streams_and_managed_cwd() {
    let root = temp_dir("process-contract");
    let support = root.join("support");
    let managed = support
        .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
        .join("claude_slot_0123456789abcdef0123456789abcdef");
    let bin = root.join("bin");
    let effective_home = root.join("home");
    fs::create_dir_all(&managed).expect("managed root");
    fs::create_dir_all(&bin).expect("bin");
    fs::create_dir_all(&effective_home).expect("home");
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    fs::set_permissions(
        support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME),
        fs::Permissions::from_mode(0o700),
    )
    .expect("managed parent mode");
    fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("slot mode");
    let capture = root.join("capture.txt");
    let script = format!(
        "#!/bin/sh\n{{\nprintf 'argc=%s\\n' \"$#\"\nprintf 'argv=%s\\n' \"$*\"\nprintf 'config=%s\\n' \"$CLAUDE_CONFIG_DIR\"\nprintf 'home=%s\\n' \"$HOME\"\nprintf 'cwd=%s\\n' \"$PWD\"\nprintf 'provider=%s\\n' \"${{ANTHROPIC_API_KEY-unset}}\"\nprintf 'poison=%s\\n' \"${{OTTTO_SECRET_PROBE-unset}}\"\nif IFS= read -r ignored; then printf 'stdin=open\\n'; else printf 'stdin=closed\\n'; fi\n}} >> \"{}\"\n",
        capture.display()
    );
    let executable = bin.join("claude");
    fs::write(&executable, script).expect("fake claude");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("executable");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &bin);
    let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &effective_home);
    let _provider = EnvGuard::set("ANTHROPIC_API_KEY", "must-not-survive");
    let _poison = EnvGuard::set("OTTTO_SECRET_PROBE", "must-not-survive");

    let mut child = login_command(managed.to_str().expect("utf8"))
        .expect("hardened login command")
        .spawn()
        .expect("spawn");
    assert!(child.wait().expect("wait").success());
    let observed = fs::read_to_string(&capture).expect("capture");
    assert!(observed.contains("argc=3\n"));
    assert!(observed.contains("argv=auth login --claudeai\n"));
    assert!(observed.contains(&format!("config={}\n", managed.display())));
    assert!(observed.contains(&format!("home={}\n", effective_home.display())));
    let canonical_managed = fs::canonicalize(&managed).expect("canonical managed root");
    assert!(observed.contains(&format!("cwd={}\n", canonical_managed.display())));
    assert!(observed.contains("provider=unset\n"));
    assert!(observed.contains("poison=unset\n"));
    assert!(observed.contains("stdin=closed\n"));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn duplicate_quarantine_never_registers_candidate_and_reuses_exact_root() {
    let root = temp_dir("duplicate-quarantine");
    let support = root.join("support");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    fs::create_dir_all(&managed_parent).expect("managed parent");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("managed mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let canonical_root = managed_parent.join("canonical");
    fs::create_dir_all(&canonical_root).expect("canonical root");
    #[cfg(unix)]
    fs::set_permissions(&canonical_root, fs::Permissions::from_mode(0o700))
        .expect("canonical mode");
    let canonical = store
        .register_managed_path(1, canonical_root.to_string_lossy().into_owned())
        .expect("canonical registration");
    let canonical_slot = canonical.managed_slots[0].slot_id.clone();
    let operation_id = "claude_setup_30303030303030303030303030303030";
    let (candidate_slot, candidate_root) =
        prepare_managed_claude_provisional_root(operation_id).expect("candidate");
    let before = store.load().expect("registry before duplicate");
    assert_eq!(before.capacity.used_slots, 2);
    assert!(!before
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == candidate_slot));
    let now = unix_seconds();
    transact(|state| {
        state.operations.push(PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: candidate_slot.clone(),
            config_dir: candidate_root.clone(),
            ceremony_baseline: None,
            mode: PersistedMode::Generic,
            target_id: None,
            expected_account_identifier_hash: None,
            expected_organization_identifier_hash: None,
            phase: ClaudeBrowserAuthPhaseV1::Validating,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: now,
            deadline_unix_seconds: now + 60,
            completed_unix_seconds: None,
            fallback_completed: false,
        });
    })
    .expect("browser state");

    let operation = read_operation(operation_id).expect("operation");
    quarantine_generic_root(&operation).expect("quarantine duplicate");
    finish(
        operation_id,
        ClaudeBrowserAuthOutcomeV1::AlreadyConnected,
        Some(canonical_slot),
    );
    let after = store.load().expect("registry after duplicate");
    assert_eq!(after.capacity.used_slots, 2);
    assert!(!after
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == candidate_slot));
    assert!(Path::new(&candidate_root).is_dir());
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::AlreadyConnected)
    );
    let reused = claim_reusable_root("claude_setup_40404040404040404040404040404040")
        .expect("claim succeeds")
        .expect("quarantined root is reusable");
    assert_eq!(reused, candidate_root);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn generic_prepare_skips_stale_unclaimed_root_and_allocates_current_root() {
    let (root, support, _support) = with_support("stale-unclaimed-root");
    let stale_root = root
        .join("retired-installation")
        .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
        .join("claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    transact(|state| {
        state.quarantined_roots.push(QuarantinedRoot {
            root_id: "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            config_dir: stale_root.to_string_lossy().into_owned(),
            service_alias: String::new(),
            pending_registry_removal: false,
            claimed_by: None,
        });
    })
    .expect("stale state");

    let operation_id = "claude_setup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare current root");

    let operation = read_operation(operation_id).expect("operation");
    let current_managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    assert_eq!(
        Path::new(&operation.config_dir).parent(),
        Some(current_managed_parent.as_path())
    );
    assert!(Path::new(&operation.config_dir).is_dir());
    let state = read_state();
    assert!(state.quarantined_roots.iter().any(|candidate| {
        candidate.config_dir == stale_root.to_string_lossy() && candidate.claimed_by.is_none()
    }));
    assert!(state.quarantined_roots.iter().any(|candidate| {
        candidate.config_dir == operation.config_dir
            && candidate.claimed_by.as_deref() == Some(operation_id)
    }));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn same_operation_stale_root_remains_a_strict_replay_error() {
    let (root, _support_dir, _support) = with_support("stale-replay-root");
    let operation_id = "claude_setup_cccccccccccccccccccccccccccccccc";
    let stale_root = root
        .join("retired-installation")
        .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
        .join("claude_slot_cccccccccccccccccccccccccccccccc");
    transact(|state| {
        state.quarantined_roots.push(QuarantinedRoot {
            root_id: "claude_slot_cccccccccccccccccccccccccccccccc".to_string(),
            config_dir: stale_root.to_string_lossy().into_owned(),
            service_alias: String::new(),
            pending_registry_removal: false,
            claimed_by: Some(operation_id.to_string()),
        });
    })
    .expect("stale replay state");

    let error = claim_reusable_root(operation_id).expect_err("strict replay failure");
    assert!(error.contains("not a direct managed child"));
    assert_eq!(
        read_state().quarantined_roots[0].claimed_by.as_deref(),
        Some(operation_id)
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn duplicate_requires_the_same_account_and_organization() {
    let mut status = ClaudeAccountsStatusV1 {
        schema_version: 1,
        consent: ottto_protocol::ClaudeAccountUpkeepConsentState::ConsentRequired,
        setup_operation: synthetic_operation(&PersistedOperation {
            operation_id: "claude_setup_50505050505050505050505050505050".to_string(),
            slot_id: "claude_slot_50505050505050505050505050505050".to_string(),
            config_dir: "/tmp/candidate".to_string(),
            ceremony_baseline: None,
            mode: PersistedMode::Generic,
            target_id: None,
            expected_account_identifier_hash: None,
            expected_organization_identifier_hash: None,
            phase: ClaudeBrowserAuthPhaseV1::Validating,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: 2,
            completed_unix_seconds: None,
            fallback_completed: false,
        }),
        default_slot: ClaudeConfigDirSlot::Default.descriptor(
            "default",
            ottto_protocol::ClaudeConfigSlotOwnership::External,
        ),
        managed_slots: Vec::new(),
        external_slots: Vec::new(),
        unresolved_accounts: Vec::new(),
        anchor_coverage: Default::default(),
        anchor_transitions: Vec::new(),
        capacity: ottto_protocol::ClaudeAccountCapacityV1 {
            max_slots: 10,
            used_slots: 1,
            remaining_slots: 9,
        },
        browser_auth_supported: Some(true),
        auth_code_entry_supported: Some(true),
        retained_provisional_login_count: None,
        consent_covers_limit_reads: None,
    };
    let mut existing = ClaudeConfigDirSlot::registered("/tmp/existing".to_string())
        .expect("descriptor")
        .descriptor(
            "claude_slot_60606060606060606060606060606060",
            ottto_protocol::ClaudeConfigSlotOwnership::Managed,
        );
    existing.collection.account_identifier_hash = Some("a".repeat(64));
    existing.collection.organization_identifier_hash = Some("b".repeat(64));
    existing.collection.access_expires_at = Some(
        (time::OffsetDateTime::now_utc() + time::Duration::hours(8))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    );
    status.managed_slots.push(existing);
    assert!(serving_slot_for_binding(
        &status,
        "claude_slot_50505050505050505050505050505050",
        &"a".repeat(64),
        &"b".repeat(64)
    )
    .is_some());
    assert!(serving_slot_for_binding(
        &status,
        "claude_slot_50505050505050505050505050505050",
        &"a".repeat(64),
        &"c".repeat(64)
    )
    .is_none());
}

#[test]
#[serial]
fn cancelled_outcome_wins_late_worker_completion() {
    let root = temp_dir("cancel-wins");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let operation_id = "claude_setup_70707070707070707070707070707070";
    let now = unix_seconds();
    transact(|state| {
        state.operations.push(PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: "claude_slot_70707070707070707070707070707070".to_string(),
            config_dir: support
                .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
                .join("claude_slot_70707070707070707070707070707070")
                .to_string_lossy()
                .into_owned(),
            ceremony_baseline: None,
            mode: PersistedMode::Generic,
            target_id: None,
            expected_account_identifier_hash: None,
            expected_organization_identifier_hash: None,
            phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: now,
            deadline_unix_seconds: now + 60,
            completed_unix_seconds: None,
            fallback_completed: false,
        });
    })
    .expect("state");
    request_cancel(operation_id).expect("cancel request");
    let ((), requested) = crate::agent_status_refresh::with_test_requests_now(|| {
        finalize_identity(
            operation_id,
            crate::agent_status::ClaudeLocalIdentityProof {
                account_identifier_hash: "a".repeat(64),
                organization_identifier_hash: "b".repeat(64),
                collection: Default::default(),
            },
        )
        .expect("cancelled finalize is a no-op");
        finish(operation_id, ClaudeBrowserAuthOutcomeV1::Complete, None);
    });
    assert!(requested.is_empty(), "a cancelled sign-in asks for no pass");
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline
        && read_operation(operation_id).is_some_and(|operation| operation.outcome.is_none())
    {
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::Cancelled)
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn generic_prepare_is_provisional_and_does_not_consume_registry_capacity() {
    let (root, _support_dir, _support) = with_support("generic-provisional");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let before = store.load().expect("before");
    let operation_id = "claude_setup_80808080808080808080808080808080";
    let prepared = prepare_generic(before.clone(), operation_id).expect("prepare generic");
    let after = store.load().expect("after");
    assert_eq!(after.capacity.used_slots, before.capacity.used_slots);
    assert!(after.managed_slots.is_empty());
    assert!(after.external_slots.is_empty());
    assert_eq!(
        prepared
            .setup_operation
            .browser_auth
            .expect("browser")
            .phase,
        ClaudeBrowserAuthPhaseV1::Prepared
    );
    let operation = read_operation(operation_id).expect("operation");
    assert_eq!(
        Path::new(&operation.config_dir)
            .file_name()
            .and_then(|name| name.to_str()),
        Some(operation.slot_id.as_str())
    );
    assert!(Path::new(&operation.config_dir).is_dir());
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn generic_registry_exposure_already_has_strong_composite_identity() {
    let (root, _support_dir, _support) = with_support("generic-admission-order");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let operation_id = "claude_setup_c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
    prepare_generic(store.load().expect("registry"), operation_id).expect("prepare");
    assert!(store
        .load()
        .expect("still provisional")
        .managed_slots
        .is_empty());
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    // Generic admission of a new root is a completed sign-in.
    assert_one_completed_request(operation_id);
    let exposed = crate::agent_status::annotate_claude_accounts_status(
        store.load().expect("registered status"),
    );
    assert_eq!(exposed.managed_slots.len(), 1);
    assert_eq!(
        exposed.managed_slots[0]
            .collection
            .account_identifier_hash
            .as_deref(),
        Some(account.as_str())
    );
    assert_eq!(
        exposed.managed_slots[0]
            .collection
            .organization_identifier_hash
            .as_deref(),
        Some(organization.as_str())
    );
    assert_eq!(
        store
            .expected_slot_binding(&exposed.managed_slots[0].slot_id)
            .expect("approval"),
        ottto_core::ClaudeSlotAccountBinding::new(&account, &organization),
        "admission records the verified pair as the slot's approval atomically"
    );
    let _ = fs::remove_dir_all(root);
}

/// A generic root that is already registered completes on the existing-slot
/// route and asks for one immediate status pass.
#[test]
#[serial]
fn generic_already_registered_root_completes_with_one_status_request() {
    let (root, _support_dir, _support) = with_support("generic-existing-complete");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let operation_id = "claude_setup_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    prepare_generic(store.load().expect("registry"), operation_id).expect("prepare");
    let operation = read_operation(operation_id).expect("operation");
    store
        .register_managed_path_with_slot_id_and_binding(
            1,
            operation.slot_id.clone(),
            operation_config_dir(&operation),
            ottto_core::ClaudeSlotAccountBinding::new(&"a".repeat(64), &"b".repeat(64)),
        )
        .expect("root already registered");
    assert_one_completed_request(operation_id);
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.canonical_slot_id),
        Some(operation.slot_id)
    );
    let _ = fs::remove_dir_all(root);
}

/// Observed live, 2026-10-02: "Add Claude account" for an account whose only
/// saved connection was signed out ended "already connected", quarantined
/// the fresh login and left the account on the dead connection. A slot
/// that cannot serve the pair must not swallow the login; a healthy one
/// still does.
#[test]
#[serial]
fn generic_login_for_pair_whose_saved_connection_is_dead_is_admitted() {
    use ottto_protocol::ClaudeConfigSlotCollectionStateV1 as State;
    use ottto_protocol::ClaudeConfigSlotUpkeepResultV1 as Upkeep;
    let at = |offset: time::Duration| {
        (time::OffsetDateTime::now_utc() + offset)
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let valid = Some(at(time::Duration::hours(8)));
    let expired = Some("2026-09-24T12:27:25Z".to_string());
    for (existing_state, access, upkeep, admitted) in [
        (State::NeedsLogin, expired.clone(), None, true),
        (State::RefreshDue, expired.clone(), None, true),
        (State::StaleAccessToken, expired.clone(), None, true),
        (State::CredentialUnavailable, None, None, true),
        // A failed refresh on an expired credential is presented as
        // `probe_failed`; it is dead and must not swallow the login.
        (
            State::ProbeFailed,
            expired.clone(),
            Some(Upkeep::TimedOut),
            true,
        ),
        (
            State::ProbeFailed,
            expired.clone(),
            Some(Upkeep::ExpiryUnchanged),
            true,
        ),
        (
            State::ProbeFailed,
            expired.clone(),
            Some(Upkeep::MissingBinary),
            true,
        ),
        (State::ProviderUnavailable, expired.clone(), None, true),
        (State::Fresh, valid.clone(), None, false),
        (State::ProviderUnavailable, valid.clone(), None, false),
        (State::ProbeFailed, valid.clone(), None, false),
    ] {
        let root = temp_dir("generic-dead-pair");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let existing_root = root.join("existing");
        fs::create_dir_all(&existing_root).expect("existing root");
        let existing_slot = store
            .register_path(1, existing_root.to_string_lossy().into_owned())
            .expect("existing registration")
            .external_slots[0]
            .slot_id
            .clone();
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        crate::agent_status::persist_one_claude_slot_collection_state(
            &existing_slot,
            &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: existing_state.clone(),
                account_identifier_hash: Some(account.clone()),
                organization_identifier_hash: Some(organization.clone()),
                observed_at: Some("2026-09-24T12:21:06Z".to_string()),
                access_expires_at: access.clone(),
                upkeep: upkeep.map(|result| ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
                    result,
                    due_access_expires_at: access.clone(),
                    refresh_token_expires_at: None,
                    attempted_at: None,
                    next_allowed_attempt_at: None,
                    consecutive_failures: 3,
                }),
                ..Default::default()
            },
        )
        .expect("existing saved state");
        let operation_id = "claude_setup_c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
        prepare_generic(store.load().expect("registry"), operation_id).expect("prepare");
        let candidate_slot = read_operation(operation_id).expect("operation").slot_id;
        // Only the admitted (completed) login asks for an immediate pass;
        // a duplicate and any replay ask for none.
        assert_eq!(
            finalize_requests_now(operation_id).len(),
            usize::from(admitted),
            "{existing_state:?} {access:?} {upkeep:?}"
        );
        assert!(finalize_requests_now(operation_id).is_empty());
        let operation = read_operation(operation_id).expect("finished operation");
        let registry = store.load().expect("registry after");
        let candidate_registered = registry
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == candidate_slot);
        if admitted {
            assert_eq!(
                operation.outcome,
                Some(ClaudeBrowserAuthOutcomeV1::Complete),
                "{existing_state:?} {access:?} {upkeep:?}"
            );
            assert!(
                candidate_registered,
                "{existing_state:?} {access:?} {upkeep:?}"
            );
        } else {
            assert_eq!(
                operation.outcome,
                Some(ClaudeBrowserAuthOutcomeV1::AlreadyConnected),
                "{existing_state:?} {access:?} {upkeep:?}"
            );
            assert_eq!(
                operation.canonical_slot_id.as_deref(),
                Some(existing_slot.as_str())
            );
            assert!(
                !candidate_registered,
                "{existing_state:?} {access:?} {upkeep:?}"
            );
        }
        // The existing connection is never removed or rewritten here.
        assert!(registry
            .external_slots
            .iter()
            .any(|slot| slot.slot_id == existing_slot));
        drop(_support);
        let _ = fs::remove_dir_all(root);
    }
}

/// With upkeep consent granted, admission runs the real one-slot quota
/// collection. When that first read is
/// unavailable, the admitted login must still own the canonical anchor in
/// persisted coverage over a dead slot with complete historical limits.
#[test]
#[serial]
fn admitted_login_with_unavailable_first_quota_read_becomes_canonical() {
    let (root, support, _support) = with_support("generic-dead-pair-canonical");
    let store = FileClaudeConfigSlotSettingsStore::default();
    store
        .set_upkeep_consent(1, true)
        .expect("grant upkeep consent");
    // Quota reads are unavailable on this machine for the whole test: no
    // provider request can be made, and the collector reports that state.
    fs::write(
        support.join(crate::agent_status::CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE),
        b"off",
    )
    .expect("quota network off");
    let existing_root = root.join("existing");
    fs::create_dir_all(&existing_root).expect("existing root");
    let existing_slot = store
        .register_path(1, existing_root.to_string_lossy().into_owned())
        .expect("existing registration")
        .external_slots[0]
        .slot_id
        .clone();
    let account = ottto_core::billing_identity_hash("anthropic", "account", "account-uuid-gmail")
        .expect("account hash");
    let organization =
        ottto_core::billing_identity_hash("anthropic", "organization", "org-uuid-gmail")
            .expect("organization hash");
    crate::agent_status::persist_one_claude_slot_collection_state(
        &existing_slot,
        &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ottto_protocol::ClaudeConfigSlotCollectionStateV1::NeedsLogin,
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            observed_at: Some("2026-09-24T12:21:06Z".to_string()),
            access_expires_at: Some("2026-09-24T12:27:25Z".to_string()),
            last_full_quota_read_at: Some("2026-09-24T12:21:06Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            ..Default::default()
        },
    )
    .expect("dead slot with complete history");
    let operation_id = "claude_setup_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    prepare_generic(store.load().expect("registry"), operation_id).expect("prepare");
    let candidate = read_operation(operation_id).expect("operation");
    let candidate_slot = candidate.slot_id.clone();
    // The fresh login's own identity file, as Claude Code writes it.
    fs::write(
        Path::new(&operation_config_dir(&candidate)).join(".claude.json"),
        br#"{"oauthAccount":{"accountUuid":"account-uuid-gmail","organizationUuid":"org-uuid-gmail"}}"#,
    )
    .expect("identity file");
    finalize_identity(
        operation_id,
        crate::agent_status::ClaudeLocalIdentityProof {
            account_identifier_hash: account.clone(),
            organization_identifier_hash: organization.clone(),
            collection: ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: ottto_protocol::ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(account.clone()),
                organization_identifier_hash: Some(organization.clone()),
                observed_at: Some(observed_at()),
                access_expires_at: Some(
                    (time::OffsetDateTime::now_utc() + time::Duration::hours(8))
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap(),
                ),
                ..Default::default()
            },
        },
    )
    .expect("finalize");
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::Complete)
    );
    let status =
        crate::agent_status::annotate_claude_accounts_status(store.load().expect("registry after"));
    let admitted = status
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == candidate_slot)
        .expect("admitted slot");
    assert!(!admitted.collection.has_account_windows);
    assert_ne!(
        admitted.collection.state,
        ottto_protocol::ClaudeConfigSlotCollectionStateV1::Fresh,
        "first quota read must be unavailable in this fixture"
    );
    let anchor_health = |status: &ClaudeAccountsStatusV1| {
        let anchors = status
            .anchor_coverage
            .accounts
            .iter()
            .filter(|anchor| anchor.account_identifier_hash == account)
            .collect::<Vec<_>>();
        assert_eq!(anchors.len(), 1);
        anchors[0].health
    };
    // The admitted login owns the anchor (its own paused state), not the
    // dead slot's reconnect requirement.
    assert_eq!(
        anchor_health(&status),
        Some(ottto_protocol::ClaudeAccountAnchorHealthV1::Paused)
    );

    // A later collection: the old slot's refresh fails on its expired
    // credential, which is presented as `probe_failed` with complete
    // historical limits. It must stay below the working login.
    crate::agent_status::persist_one_claude_slot_collection_state(
        &existing_slot,
        &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ottto_protocol::ClaudeConfigSlotCollectionStateV1::ProbeFailed,
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            observed_at: Some(observed_at()),
            access_expires_at: Some("2026-09-24T12:27:25Z".to_string()),
            relogin_required_at: Some("2026-10-09T23:27:42Z".to_string()),
            last_full_quota_read_at: Some("2026-09-24T12:21:06Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            upkeep: Some(ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
                result: ottto_protocol::ClaudeConfigSlotUpkeepResultV1::TimedOut,
                due_access_expires_at: Some("2026-09-24T12:27:25Z".to_string()),
                refresh_token_expires_at: Some("2026-10-09T23:27:42Z".to_string()),
                attempted_at: Some(observed_at()),
                next_allowed_attempt_at: None,
                consecutive_failures: 3,
            }),
            ..Default::default()
        },
    )
    .expect("old slot refresh failed");
    let later =
        crate::agent_status::annotate_claude_accounts_status(store.load().expect("registry later"));
    assert_eq!(
        later
            .external_slots
            .iter()
            .find(|slot| slot.slot_id == existing_slot)
            .map(|slot| slot.collection.state.clone()),
        Some(ottto_protocol::ClaudeConfigSlotCollectionStateV1::ProbeFailed)
    );
    assert_eq!(
        anchor_health(&later),
        Some(ottto_protocol::ClaudeAccountAnchorHealthV1::Paused),
        "a failed refresh on an expired credential must not reclaim the anchor"
    );
    drop(_support);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn corrupt_state_prevents_provisional_root_creation() {
    let root = temp_dir("corrupt-before-root");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    fs::write(state_path(), b"{not-json").expect("corrupt state");
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    assert!(prepare_generic(status, "claude_setup_c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0").is_err());
    assert!(!managed_root().exists());
    assert_eq!(fs::read(state_path()).expect("preserved"), b"{not-json");
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn ceremony_singleflight_is_idempotent_and_releases_only_owner() {
    let root = temp_dir("singleflight");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let first = "claude_setup_d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
    let second = "claude_setup_e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0";
    assert!(claim_ceremony(first).expect("first claim"));
    assert!(!claim_ceremony(first).expect("same-operation replay"));
    assert!(claim_ceremony(second).is_err());
    release_ceremony(second);
    assert!(claim_ceremony(second).is_err());
    release_ceremony(first);
    claim_ceremony(second).expect("released claim");
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn same_id_cross_mode_replay_never_mutates_or_releases_original_claim() {
    let root = temp_dir("cross-mode-replay");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let operation_id = "claude_setup_25252525252525252525252525252525";
    let other_id = "claude_setup_26262626262626262626262626262626";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("generic prepare");
    assert!(preflight_browser_binding(
        operation_id,
        BrowserLoginMode::Target,
        Some("claude_slot_other"),
        Some("claude_anchor_target_other")
    )
    .is_err());
    assert!(claim_ceremony(other_id).is_err());
    let state = read_state();
    assert_eq!(state.active_operation_id.as_deref(), Some(operation_id));
    assert_eq!(
        state
            .operations
            .iter()
            .filter(|operation| operation.operation_id == operation_id)
            .count(),
        1
    );
    assert_eq!(
        read_operation(operation_id).map(|operation| operation.mode),
        Some(PersistedMode::Generic)
    );
    release_ceremony(operation_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn terminal_same_id_replay_is_read_only() {
    let root = temp_dir("terminal-replay-read-only");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let operation_id = "claude_setup_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    let prepared = prepare_generic(status, operation_id).expect("prepare");
    finish(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed, None);
    let before = fs::read(state_path()).expect("before replay");
    assert!(terminal_replay(prepared, operation_id).is_some());
    assert_eq!(fs::read(state_path()).expect("after replay"), before);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn quarantine_capacity_rejects_generic_before_launch_without_leaking_claim() {
    let root = temp_dir("generic-capacity-prelaunch");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    transact(|state| {
        for index in 0..MAX_QUARANTINED_ROOTS {
            state.quarantined_roots.push(QuarantinedRoot {
                root_id: format!("claude_slot_{index:032x}"),
                config_dir: format!("/private/provisional/{index}"),
                service_alias: format!("service-{index}"),
                pending_registry_removal: false,
                claimed_by: None,
            });
        }
    })
    .expect("full quarantine");
    let operation_id = "claude_setup_a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    assert!(prepare_generic(status, operation_id).is_err());
    assert!(read_operation(operation_id).is_none());
    assert!(claim_ceremony("claude_setup_a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3").is_ok());
    assert!(!managed_root()
        .join("claude_slot_a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2")
        .exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn generic_derived_root_collision_with_canonical_registry_fails_before_creation() {
    let root = temp_dir("generic-canonical-collision");
    let support = root.join("support");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    fs::create_dir_all(&managed_parent).expect("managed parent");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("managed parent mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let operation_id = "claude_setup_27272727272727272727272727272727";
    let slot_id = "claude_slot_27272727272727272727272727272727";
    let exact = managed_parent.join(slot_id);
    fs::create_dir(&exact).expect("canonical root");
    #[cfg(unix)]
    fs::set_permissions(&exact, fs::Permissions::from_mode(0o700)).expect("canonical mode");
    FileClaudeConfigSlotSettingsStore::default()
        .register_managed_path_with_slot_id(
            1,
            slot_id.to_string(),
            exact.to_string_lossy().into_owned(),
        )
        .expect("canonical registration");
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    assert!(prepare_generic(status, operation_id).is_err());
    assert!(read_operation(operation_id).is_none());
    assert!(read_state().quarantined_roots.is_empty());
    assert!(
        claim_ceremony("claude_setup_28282828282828282828282828282828")
            .expect("collision released ceremony")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn recovery_retains_ceremony_while_orphan_supervisor_lock_is_held() {
    let root = temp_dir("orphan-supervisor-lock");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let operation_id = "claude_setup_a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4";
    let retry_id = "claude_setup_a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare");
    transact(|state| {
        let operation = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
            .expect("operation");
        operation.phase = ClaudeBrowserAuthPhaseV1::WaitingForProvider;
        operation.deadline_unix_seconds = 0;
    })
    .expect("expire operation");
    let provider = provider_process_guard(operation_id, false)
        .expect("provider lock")
        .expect("provider ownership");
    let operation = operation_id.to_string();
    let recovery = thread::spawn(move || recover_operation(&operation));
    thread::sleep(Duration::from_millis(250));
    assert!(claim_ceremony(retry_id).is_err());
    let retained = read_operation(operation_id).expect("operation retained");
    assert!(retained.outcome.is_none());
    assert_eq!(retained.phase, ClaudeBrowserAuthPhaseV1::WaitingForProvider);
    drop(provider);
    recovery.join().expect("recovery");
    claim_ceremony(retry_id).expect("released only after provider teardown");
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn failed_provider_reap_keeps_operation_and_ceremony_nonterminal() {
    use std::os::unix::process::CommandExt;

    let root = temp_dir("failed-provider-reap");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let operation_id = "claude_setup_a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    let retry_id = "claude_setup_afafafafafafafafafafafafafafafaf";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare");
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::WaitingForProvider);
    let provider = provider_process_guard(operation_id, false)
        .expect("provider lock")
        .expect("provider ownership");
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("exit 0")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command.spawn().expect("exited supervisor fixture");
    let process_group_id = child.id() as libc::pid_t;
    let mut supervised = SupervisedChild {
        child,
        control: None,
        process_group_id,
    };

    assert!(!supervised.cancel_and_wait(operation_id));
    assert!(read_operation(operation_id)
        .expect("operation")
        .outcome
        .is_none());
    assert!(claim_ceremony(retry_id).is_err());
    drop(provider);
    assert!(request_cancel(operation_id).expect("cancel request"));
    release_ceremony(operation_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn supervisor_entry_rejects_unbound_or_terminal_requests_before_fd_use() {
    use std::os::fd::{AsRawFd, FromRawFd};

    let root = temp_dir("supervisor-binding");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    assert!(run_auth_supervisor("../escape", "/tmp/arbitrary", -1, -1).is_err());
    assert!(run_auth_supervisor(
        "claude_setup_a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6",
        "/tmp/arbitrary",
        -1,
        -1,
    )
    .is_err());

    let operation_id = "claude_setup_a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare");
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::Launching);
    let exact = read_operation(operation_id).expect("operation").config_dir;
    assert!(run_auth_supervisor(operation_id, "/tmp/wrong", -1, -1).is_err());
    assert!(run_auth_supervisor(operation_id, &exact, -1, -1).is_err());
    let mut pipe_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    // SAFETY: successful pipe returned newly-owned descriptors.
    let pipe_read = unsafe { File::from_raw_fd(pipe_fds[0]) };
    let pipe_write = unsafe { File::from_raw_fd(pipe_fds[1]) };
    assert!(run_auth_supervisor(
        operation_id,
        &exact,
        pipe_read.as_raw_fd(),
        pipe_read.as_raw_fd(),
    )
    .is_err());
    assert!(run_auth_supervisor(
        operation_id,
        &exact,
        pipe_write.as_raw_fd(),
        pipe_read.as_raw_fd(),
    )
    .is_err());
    let unrelated = File::open(&exact).expect("unrelated directory descriptor");
    assert!(run_auth_supervisor(
        operation_id,
        &exact,
        unrelated.as_raw_fd(),
        pipe_write.as_raw_fd(),
    )
    .is_err());
    finish(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed, None);
    assert!(run_auth_supervisor(operation_id, &exact, -1, -1).is_err());
    let _ = fs::remove_dir_all(root);
}

/// The provider prints far more than a PTY buffer holds and then shows its
/// paste prompt. The supervisor drains without a consumer, never answers the
/// prompt, and parent-pipe EOF still kills the provider before the lifetime
/// lock is released.
#[test]
#[serial]
#[cfg(unix)]
fn supervisor_parent_eof_kills_provider_before_releasing_lifetime_lock() {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

    let root = temp_dir("supervisor-parent-eof");
    let support = root.join("support");
    let bin = root.join("bin");
    let home = root.join("home");
    let prompted = root.join("prompted");
    let answered = root.join("answered");
    fs::create_dir_all(&support).expect("support");
    fs::create_dir_all(&bin).expect("bin");
    fs::create_dir_all(&home).expect("home");
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    let executable = bin.join("claude");
    fs::write(
        &executable,
        format!(
            "#!/bin/sh\nfor fd in 0 1 2; do test -t \"$fd\" || exit 42; done\ns=xxxxxxxxxxxxxxxx; i=0; while [ $i -lt 14 ]; do s=\"$s$s\"; i=$((i + 1)); done; printf '%s' \"$s\" >&2\nprintf 'Paste code here if prompted >' >&2\n: > '{}'\nIFS= read -r code\n: > '{}'\nexec sleep 30\n",
            prompted.display(),
            answered.display()
        ),
    )
    .expect("fake claude");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
        .expect("fake executable mode");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &bin);
    let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home);
    let operation_id = "claude_setup_a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare");
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::Launching);
    let config_dir = read_operation(operation_id).expect("operation").config_dir;

    let mut control_fds = [-1; 2];
    let mut ready_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(control_fds.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::pipe(ready_fds.as_mut_ptr()) }, 0);
    // SAFETY: successful pipe calls returned newly-owned descriptors.
    let control_read = unsafe { File::from_raw_fd(control_fds[0]) };
    let control_write = unsafe { File::from_raw_fd(control_fds[1]) };
    let mut ready_read = unsafe { File::from_raw_fd(ready_fds[0]) };
    let ready_write = unsafe { File::from_raw_fd(ready_fds[1]) };
    // Like the daemon, keep this side's ends out of every exec'd child. The
    // provider is spawned inside this process; an inherited control write end
    // would keep the pipe open so parent EOF could never be observed.
    for fd in [control_write.as_raw_fd(), ready_read.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
            0
        );
    }
    let operation = operation_id.to_string();
    let supervisor_root = config_dir.clone();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let supervisor = thread::spawn(move || {
        let result = run_auth_supervisor(
            &operation,
            &supervisor_root,
            control_read.into_raw_fd(),
            ready_write.into_raw_fd(),
        );
        let _ = finished_tx.send(());
        result
    });
    let mut ready = [0_u8; 1];
    ready_read.read_exact(&mut ready).expect("ready");
    assert_eq!(ready, [PROVIDER_EVENT_READY]);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !prompted.exists() {
        assert!(
            Instant::now() < deadline,
            "provider output was not drained without a consumer"
        );
        thread::sleep(Duration::from_millis(25));
    }
    thread::sleep(Duration::from_millis(200));
    assert!(
        !answered.exists(),
        "the paste prompt must never be answered"
    );
    // Readiness is the only event: the prompt produces nothing on the pipe.
    let flags = unsafe { libc::fcntl(ready_read.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe {
            libc::fcntl(
                ready_read.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        },
        0
    );
    let mut extra = [0_u8; 1];
    assert!(
        !matches!(ready_read.read(&mut extra), Ok(count) if count > 0),
        "no event follows readiness"
    );
    assert!(provider_process_active(operation_id).expect("lock state"));
    drop(control_write);
    finished_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("parent EOF must kill the provider and end the supervisor");
    let result = supervisor.join().expect("supervisor thread");
    assert!(result.is_ok(), "supervisor result: {result:?}");
    assert!(!provider_process_active(operation_id).expect("released lock"));
    assert!(
        !answered.exists(),
        "the paste prompt must never be answered"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn provider_child_retains_lifetime_lock_after_supervisor_guard_is_gone() {
    use std::os::unix::process::CommandExt;

    let root = temp_dir("provider-inherited-lock");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let operation_id = "claude_setup_a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9";
    let mut provider = provider_process_guard(operation_id, false)
        .expect("provider lock")
        .expect("available");
    provider
        .set_inherited_by_exec(true)
        .expect("make lock inheritable");
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("exec sleep 30")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("provider child");
    provider
        .set_inherited_by_exec(false)
        .expect("restore supervisor fd");
    provider.preserve_inherited_lock_on_drop();
    drop(provider);
    assert!(provider_process_active(operation_id).expect("child retains lock"));
    kill_owned_process(&mut child);
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline && provider_process_active(operation_id).expect("lock state") {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(!provider_process_active(operation_id).expect("released with provider exit"));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn pinned_root_detects_child_and_ancestor_swaps() {
    use std::os::unix::fs::symlink;

    let root = temp_dir("root-swap");
    let support = root.join("support");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    let managed = managed_parent.join("claude_slot_f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0");
    fs::create_dir_all(&managed).expect("root");
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700)).expect("parent mode");
    fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("root mode");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let pinned = pin_managed_root(managed.to_str().expect("utf8")).expect("pinned root");
    let parked_support = root.join("parked-support-root");
    fs::rename(&support, &parked_support).expect("park support root");
    symlink(&parked_support, &support)
        .expect("symlink original support name to pinned ancestor inode");
    assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
    fs::remove_file(&support).expect("remove support symlink");
    fs::rename(&parked_support, &support).expect("restore support root");
    let parked = managed_parent.join("parked");
    fs::rename(&managed, &parked).expect("park old root");
    symlink(&parked, &managed).expect("symlink original child name to pinned inode");
    assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
    fs::remove_file(&managed).expect("remove child symlink");
    fs::create_dir(&managed).expect("replacement");
    fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("replacement mode");
    assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
    let parked_parent = support.join("parked-managed-parent");
    fs::rename(&managed_parent, &parked_parent).expect("park ancestor");
    symlink(&parked_parent, &managed_parent)
        .expect("symlink original parent name to pinned ancestor inode");
    assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
    fs::remove_file(&managed_parent).expect("remove parent symlink");
    fs::create_dir(&managed_parent).expect("replacement ancestor");
    fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
        .expect("replacement ancestor mode");
    fs::create_dir(&managed).expect("replacement child under swapped ancestor");
    fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
        .expect("replacement child mode");
    assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn unchanged_witness_cannot_finalize_recovery() {
    let root = temp_dir("witness-change");
    let support = root.join("support");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    let managed = managed_parent.join("claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    fs::create_dir_all(&managed).expect("root");
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700)).expect("parent mode");
    fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("root mode");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let baseline =
        crate::agent_status::claude_auth_ceremony_witness(managed.to_str().expect("utf8"))
            .expect("baseline");
    let operation = PersistedOperation {
        operation_id: "claude_setup_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        slot_id: "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        config_dir: managed.to_string_lossy().into_owned(),
        ceremony_baseline: Some(baseline),
        mode: PersistedMode::Reconnect,
        target_id: None,
        expected_account_identifier_hash: None,
        expected_organization_identifier_hash: None,
        phase: ClaudeBrowserAuthPhaseV1::Validating,
        outcome: None,
        canonical_slot_id: None,
        admission_slot_id: None,
        identity_mismatch: None,
        cancel_requested: false,
        started_unix_seconds: 1,
        deadline_unix_seconds: u64::MAX,
        completed_unix_seconds: None,
        fallback_completed: false,
    };
    assert!(!ceremony_witness_changed(
        &operation,
        managed.to_str().expect("utf8")
    ));
    fs::write(managed.join(".claude.json"), br#"{"oauthAccount":{}}"#)
        .expect("provider identity write");
    assert!(ceremony_witness_changed(
        &operation,
        managed.to_str().expect("utf8")
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn active_cancel_reserves_root_until_worker_teardown() {
    let (root, _support_dir, _support) = with_support("cancel-retry-overlap");
    let operation_id = "claude_setup_12121212121212121212121212121212";
    let retry_id = "claude_setup_13131313131313131313131313131313";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare");
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::WaitingForProvider);
    let exact = operation_config_dir(&read_operation(operation_id).expect("operation"));
    // The phase alone is not evidence of a live worker. Hold the same
    // lifetime lock as its supervisor so recovery cannot finish early.
    let provider = provider_process_guard(operation_id, false)
        .expect("provider guard")
        .expect("provider ownership");
    assert!(request_cancel(operation_id).expect("cancel request"));
    assert!(claim_ceremony(retry_id).is_err());
    assert!(claim_reusable_root(retry_id)
        .expect("claim check")
        .is_none());
    let stopping = read_operation(operation_id).expect("stopping operation");
    assert!(stopping.cancel_requested);
    assert!(stopping.outcome.is_none());

    drop(provider);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match claim_ceremony(retry_id) {
            Ok(true) => break,
            Ok(false) => panic!("retry unexpectedly owned the ceremony before teardown"),
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "recovery did not release: {error}"
                );
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
    assert_eq!(
        read_operation(operation_id)
            .expect("cancelled operation")
            .outcome,
        Some(ClaudeBrowserAuthOutcomeV1::Cancelled)
    );
    let reused = claim_reusable_root(retry_id)
        .expect("claim")
        .expect("released after teardown");
    assert_eq!(reused, exact);
    release_ceremony(retry_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn cancel_intent_survives_provider_and_quarantine_cleanup_failure_until_recovery() {
    let (root, _support_dir, _support) = with_support("cancel-intent-cleanup-recovery");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let operation_id = "claude_setup_15151515151515151515151515151515";
    let prepared = store
        .prepare_managed_account_target(
            1,
            operation_id.to_string(),
            Some("claude_anchor_target_15151515151515151515151515151515".to_string()),
            Some("a".repeat(64)),
            Some("b".repeat(64)),
        )
        .expect("target");
    let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
    let config_dir = prepared
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == slot_id)
        .and_then(|slot| slot.config_dir.clone())
        .expect("root");
    assert!(claim_ceremony(operation_id).expect("claim ceremony"));
    transact(|state| {
        state.operations.push(PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir: config_dir.clone(),
            ceremony_baseline: Some("baseline".to_string()),
            mode: PersistedMode::Target,
            target_id: prepared.setup_operation.target_id.clone(),
            expected_account_identifier_hash: prepared
                .setup_operation
                .expected_account_identifier_hash
                .clone(),
            expected_organization_identifier_hash: prepared
                .setup_operation
                .expected_organization_identifier_hash
                .clone(),
            phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: None,
            fallback_completed: false,
        });
        for index in 0..MAX_QUARANTINED_ROOTS {
            state.quarantined_roots.push(QuarantinedRoot {
                root_id: format!("claude_slot_{index:032x}"),
                config_dir: managed_root()
                    .join(format!("claude_slot_{index:032x}"))
                    .to_string_lossy()
                    .into_owned(),
                service_alias: format!("Claude Code-credentials-{index:032x}"),
                pending_registry_removal: false,
                claimed_by: None,
            });
        }
    })
    .expect("active sidecar and full quarantine");
    let provider = provider_process_guard(operation_id, false)
        .expect("provider guard")
        .expect("provider lock");

    assert!(request_cancel(operation_id).expect("cancel intent"));
    let stopping = read_operation(operation_id).expect("stopping operation");
    assert!(stopping.cancel_requested);
    assert!(stopping.outcome.is_none());
    assert!(synthetic_operation(&stopping)
        .message
        .as_deref()
        .is_some_and(|message| message.contains("Stopping Claude authentication")));
    let retry_id = "claude_setup_16161616161616161616161616161616";
    assert!(claim_ceremony(retry_id).is_err());

    drop(provider);
    thread::sleep(Duration::from_millis(300));
    let failed_cleanup = read_operation(operation_id).expect("retained cancel intent");
    assert!(failed_cleanup.cancel_requested);
    assert!(failed_cleanup.outcome.is_none());
    transact(|state| {
        state.quarantined_roots.pop();
    })
    .expect("free quarantine capacity");
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline
        && read_operation(operation_id).is_some_and(|operation| operation.outcome.is_none())
    {
        thread::sleep(Duration::from_millis(25));
    }
    let cancelled = read_operation(operation_id).expect("cancelled operation");
    assert_eq!(
        cancelled.outcome,
        Some(ClaudeBrowserAuthOutcomeV1::Cancelled)
    );
    assert!(!store
        .load()
        .expect("registry")
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id));
    assert!(claim_ceremony(retry_id).expect("fresh retry after cleanup"));
    release_ceremony(retry_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn browser_reconnect_cancel_never_falls_through_and_releases_after_teardown() {
    let root = temp_dir("reconnect-cancel-browser-owned");
    let support = root.join("support");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    let managed = managed_parent.join("claude_slot_b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1");
    fs::create_dir_all(&managed).expect("managed root");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("managed parent mode");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
            .expect("managed root mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_managed_path(1, managed.to_string_lossy().into_owned())
        .expect("register");
    let slot_id = registered.managed_slots[0].slot_id.clone();
    let operation_id = "claude_setup_b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    let retry_id = "claude_setup_b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3";
    let account = "a".repeat(64);
    claim_ceremony(operation_id).expect("claim");
    store
        .begin_registered_slot_reconnect(1, operation_id.to_string(), &slot_id, account.clone())
        .expect("core reconnect");
    transact(|state| {
        state.operations.push(PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir: managed.to_string_lossy().into_owned(),
            ceremony_baseline: None,
            mode: PersistedMode::Reconnect,
            target_id: None,
            expected_account_identifier_hash: Some(account.clone()),
            expected_organization_identifier_hash: None,
            phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: None,
            fallback_completed: false,
        });
    })
    .expect("sidecar reconnect");
    let provider = provider_process_guard(operation_id, false)
        .expect("provider guard")
        .expect("provider lock");
    assert!(request_cancel(operation_id).expect("cancel request"));
    assert!(claim_ceremony(retry_id).is_err());
    assert_eq!(
        store
            .setup_operation(operation_id)
            .expect("terminal core op")
            .setup_operation
            .state,
        ClaudeAccountSetupOperationState::WaitingForUserLogin
    );
    assert!(read_operation(operation_id)
        .is_some_and(|operation| { operation.cancel_requested && operation.outcome.is_none() }));
    drop(provider);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline
        && read_operation(operation_id).is_some_and(|operation| operation.outcome.is_none())
    {
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        store
            .setup_operation(operation_id)
            .expect("terminal core op")
            .setup_operation
            .state,
        ClaudeAccountSetupOperationState::SetupStopped
    );
    claim_ceremony(retry_id).expect("released after provider teardown");
    store
        .begin_registered_slot_reconnect(1, retry_id.to_string(), &slot_id, account)
        .expect("fresh reconnect after terminal old op");
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn reconnect_collection_preserves_prior_binding_while_active_and_after_mismatch() {
    let root = temp_dir("reconnect-collection-fence");
    let support = root.join("support");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    let managed = managed_parent.join("claude_slot_c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1");
    fs::create_dir_all(&managed).expect("managed root");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("managed parent mode");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
            .expect("managed root mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_managed_path(1, managed.to_string_lossy().into_owned())
        .expect("register");
    let slot_id = registered.managed_slots[0].slot_id.clone();
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    let prior = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
        account_identifier_hash: Some(account.clone()),
        organization_identifier_hash: Some(organization.clone()),
        ..Default::default()
    };
    crate::agent_status::persist_one_claude_slot_collection_state(&slot_id, &prior)
        .expect("prior canonical evidence");

    let operation_id = "claude_setup_c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
    store
        .begin_registered_slot_reconnect(1, operation_id.to_string(), &slot_id, account.clone())
        .expect("core reconnect");
    transact(|state| {
        state.operations.push(PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir: managed.to_string_lossy().into_owned(),
            ceremony_baseline: None,
            mode: PersistedMode::Reconnect,
            target_id: None,
            expected_account_identifier_hash: Some(account.clone()),
            expected_organization_identifier_hash: Some(organization.clone()),
            phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: None,
            fallback_completed: false,
        });
    })
    .expect("sidecar reconnect");
    assert_eq!(
        collection_suppression(&slot_id),
        Some(ClaudeCollectionSuppression::PreserveCanonicalReconnect)
    );
    let active = crate::agent_status::collect_registered_claude_slot_status(
        &slot_id,
        "active".to_string(),
        "active-expiry".to_string(),
    );
    assert_eq!(active.account_identifier_hash, Some(account.clone()));
    assert_eq!(
        active.organization_identifier_hash,
        Some(organization.clone())
    );

    finish_mismatch(
        operation_id,
        ClaudeBrowserAuthIdentityMismatchV1::Organization,
        false,
    )
    .expect("terminal mismatch");
    assert_eq!(
        collection_suppression(&slot_id),
        Some(ClaudeCollectionSuppression::PreserveCanonicalReconnect)
    );
    let terminal = crate::agent_status::collect_registered_claude_slot_status(
        &slot_id,
        "terminal".to_string(),
        "terminal-expiry".to_string(),
    );
    assert_eq!(terminal.account_identifier_hash, Some(account));
    assert_eq!(terminal.organization_identifier_hash, Some(organization));
    let durable = crate::agent_status::annotate_claude_accounts_status(
        store.load().expect("durable prior evidence"),
    );
    let durable = durable
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == slot_id)
        .expect("canonical reconnect slot");
    assert_eq!(durable.collection, prior);
    let _ = fs::remove_dir_all(root);
}

/// Browser reconnect of `slot_id` expecting `expected`, finalized with a
/// local identity proof for `proven`.
fn finalize_browser_reconnect(
    store: &FileClaudeConfigSlotSettingsStore,
    operation_id: &str,
    slot_id: &str,
    config_dir: &Path,
    expected: &ottto_core::ClaudeSlotAccountBinding,
    proven: &ottto_core::ClaudeSlotAccountBinding,
) {
    store
        .begin_registered_slot_reconnect_target(
            1,
            operation_id.to_string(),
            slot_id,
            None,
            expected.account_identifier_hash.clone(),
            Some(expected.organization_identifier_hash.clone()),
        )
        .expect("core reconnect");
    transact(|state| {
        state.operations.push(PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.to_string(),
            config_dir: config_dir.to_string_lossy().into_owned(),
            ceremony_baseline: None,
            mode: PersistedMode::Reconnect,
            target_id: None,
            expected_account_identifier_hash: Some(expected.account_identifier_hash.clone()),
            expected_organization_identifier_hash: Some(
                expected.organization_identifier_hash.clone(),
            ),
            phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: None,
            fallback_completed: false,
        });
    })
    .expect("sidecar reconnect");
    finalize_identity(
        operation_id,
        crate::agent_status::ClaudeLocalIdentityProof {
            account_identifier_hash: proven.account_identifier_hash.clone(),
            organization_identifier_hash: proven.organization_identifier_hash.clone(),
            collection: ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                state: ottto_protocol::ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(proven.account_identifier_hash.clone()),
                organization_identifier_hash: Some(proven.organization_identifier_hash.clone()),
                ..Default::default()
            },
        },
    )
    .expect("finalize reconnect");
}

#[test]
#[serial]
fn verified_reconnect_replaces_only_an_observed_approval_with_another_account() {
    let root = temp_dir("reconnect-replaces-observed");
    let support = root.join("support");
    let external = root.join("external-slot");
    fs::create_dir_all(&support).expect("support");
    fs::create_dir_all(&external).expect("external slot");
    #[cfg(unix)]
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let slot_id = store
        .register_path(1, external.to_string_lossy().into_owned())
        .expect("register external")
        .external_slots[0]
        .slot_id
        .clone();
    let pair = |account: char, organization: char| {
        ottto_core::ClaudeSlotAccountBinding::new(
            &account.to_string().repeat(64),
            &organization.to_string().repeat(64),
        )
        .expect("binding")
    };
    let observed = pair('a', 'b');
    let chosen = pair('c', 'd');
    store
        .ensure_approved_slot_binding(1, &slot_id, Some(&observed))
        .expect("trust on first use");

    // Reconnect started for the observed account, signed in as another:
    // the user's explicit choice replaces an observed approval.
    let first = "claude_setup_e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1";
    let ((), requested) = crate::agent_status_refresh::with_test_requests_now(|| {
        finalize_browser_reconnect(&store, first, &slot_id, &external, &observed, &chosen)
    });
    // A completed sign-in asks for one immediate Claude status pass.
    assert_eq!(requested, vec![ottto_protocol::SourceKind::ClaudeCode]);
    assert_eq!(
        read_operation(first).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::Complete)
    );
    assert_eq!(
        store.slot_approvals().expect("approvals").remove(&slot_id),
        Some(ottto_core::ClaudeSlotApproval {
            binding: chosen.clone(),
            source: ottto_core::ClaudeSlotApprovalSource::Reconnect
        })
    );

    // Now verified: another account through a reconnect is refused.
    let second = "claude_setup_e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2";
    let ((), requested) = crate::agent_status_refresh::with_test_requests_now(|| {
        finalize_browser_reconnect(&store, second, &slot_id, &external, &chosen, &observed)
    });
    assert!(
        requested.is_empty(),
        "a mismatch asks for no immediate pass"
    );
    assert_eq!(
        read_operation(second).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch)
    );
    assert_eq!(
        store.expected_slot_binding(&slot_id).expect("approval"),
        Some(chosen)
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn mismatched_reconnect_of_an_approved_slot_reports_truthfully_and_recovers_by_any_path() {
    let root = temp_dir("reconnect-mismatch-approved");
    let support = root.join("support");
    let empty_bin = root.join("empty-bin");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    let managed = managed_parent.join("claude_slot_d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1");
    fs::create_dir_all(&managed).expect("managed root");
    fs::create_dir_all(&empty_bin).expect("empty command dir");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("managed parent mode");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
            .expect("managed root mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    // No CLI or keychain tool is reachable: nothing real is ever spawned.
    let _commands = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &empty_bin);
    let hash = |kind: &str, value: &str| {
        ottto_core::billing_identity_hash("anthropic", kind, value).expect("hash")
    };
    let account = hash("account", "account-approved");
    let organization = hash("organization", "organization-approved");
    let sign_in = |account_uuid: &str, organization_uuid: &str| {
        fs::write(
            managed.join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "oauthAccount": {
                    "accountUuid": account_uuid,
                    "organizationUuid": organization_uuid,
                    "emailAddress": "someone@example.invalid",
                    "organizationType": "claude_max",
                    "organizationRateLimitTier": "default_claude_max_20x"
                }
            }))
            .expect("identity json"),
        )
        .expect("write identity");
    };
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_managed_path(1, managed.to_string_lossy().into_owned())
        .expect("register");
    let slot_id = registered.managed_slots[0].slot_id.clone();
    let approved =
        ottto_core::ClaudeSlotAccountBinding::new(&account, &organization).expect("binding");
    let verified = "claude_setup_d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
    store
        .begin_registered_slot_reconnect_target(
            1,
            verified.to_string(),
            &slot_id,
            None,
            account.clone(),
            Some(organization.clone()),
        )
        .expect("verified reconnect");
    store
        .transition_setup_operation_with_binding(
            1,
            verified,
            Some(&account),
            Some(&organization),
            ClaudeAccountSetupOperationState::Complete,
            Some(&account),
            Some(&organization),
            Some("verified"),
        )
        .expect("verified approval");
    let prior = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
        account_identifier_hash: Some(account.clone()),
        organization_identifier_hash: Some(organization.clone()),
        ..Default::default()
    };
    crate::agent_status::persist_one_claude_slot_collection_state(&slot_id, &prior)
        .expect("prior canonical evidence");

    let operation_id = "claude_setup_d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
    store
        .begin_registered_slot_reconnect_target(
            1,
            operation_id.to_string(),
            &slot_id,
            None,
            account.clone(),
            Some(organization.clone()),
        )
        .expect("core reconnect");
    transact(|state| {
        state.operations.push(PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir: managed.to_string_lossy().into_owned(),
            ceremony_baseline: None,
            mode: PersistedMode::Reconnect,
            target_id: None,
            expected_account_identifier_hash: Some(account.clone()),
            expected_organization_identifier_hash: Some(organization.clone()),
            phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: None,
            fallback_completed: false,
        });
    })
    .expect("sidecar reconnect");
    assert_eq!(
        collection_suppression(&slot_id),
        Some(ClaudeCollectionSuppression::PreserveCanonicalReconnect),
        "an active reconnect still preserves the slot"
    );

    // Claude's sign-in ran in the slot directory with another account.
    sign_in("account-other", "organization-other");
    finish_mismatch(
        operation_id,
        ClaudeBrowserAuthIdentityMismatchV1::Account,
        false,
    )
    .expect("terminal mismatch");
    let operation = store
        .setup_operation(operation_id)
        .expect("terminal core op")
        .setup_operation;
    assert_eq!(
        operation.state,
        ClaudeAccountSetupOperationState::IdentityMismatch
    );
    let message = operation.message.expect("mismatch detail");
    assert!(
        message.contains("replaced the Claude login saved in this connection"),
        "{message}"
    );
    assert!(!message.contains("not changed"), "{message}");
    assert_eq!(
        store.expected_slot_binding(&slot_id).expect("approval"),
        Some(approved),
        "a mismatch never changes the approval"
    );
    assert_eq!(
        collection_suppression(&slot_id),
        None,
        "the approved-binding gate owns the slot after a mismatched reconnect"
    );
    let mismatched = crate::agent_status::collect_registered_claude_slot_status(
        &slot_id,
        "2026-10-03T20:00:00Z".to_string(),
        "2026-10-03T20:15:00Z".to_string(),
    );
    // This fixture stores no Claude login, so the other account's
    // `.claude.json` has no token whose owner can be proven: owner
    // unproven, never a mismatch for an unknown owner.
    assert_eq!(
        mismatched.state,
        ottto_protocol::ClaudeConfigSlotCollectionStateV1::IdentityUnknown
    );
    assert!(mismatched.diagnostics[0]
        .message
        .contains("could not yet confirm"));
    assert_eq!(mismatched.account_identifier_hash, Some(account.clone()));
    assert_eq!(
        mismatched.organization_identifier_hash,
        Some(organization.clone())
    );

    // The approved account signs in again from Terminal: the gate passes
    // and ordinary collection resumes (no CLI here, so it stops at the
    // credential check instead of reporting a mismatch).
    sign_in("account-approved", "organization-approved");
    let resumed = crate::agent_status::collect_registered_claude_slot_status(
        &slot_id,
        "2026-10-03T20:05:00Z".to_string(),
        "2026-10-03T20:20:00Z".to_string(),
    );
    assert_ne!(
        resumed.state,
        ottto_protocol::ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn target_registry_exposure_is_fenced_before_sidecar_binding_is_sealed() {
    let root = temp_dir("target-pre-sidecar-fence");
    let support = root.join("support");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    let reusable = managed_parent.join("claude_slot_81818181818181818181818181818181");
    fs::create_dir_all(&reusable).expect("reusable root");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("managed parent mode");
        fs::set_permissions(&reusable, fs::Permissions::from_mode(0o700)).expect("reusable mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let operation_id = "claude_setup_81818181818181818181818181818181";
    let target_id = "claude_anchor_target_81818181818181818181818181818181";
    let expected_account = "a".repeat(64);
    let expected_organization = "b".repeat(64);
    claim_ceremony(operation_id).expect("claim");
    transact(|state| {
        state.quarantined_roots.push(QuarantinedRoot {
            root_id: "claude_slot_81818181818181818181818181818181".to_string(),
            config_dir: reusable.to_string_lossy().into_owned(),
            service_alias: ClaudeConfigDirSlot::registered(reusable.to_string_lossy().into_owned())
                .expect("slot")
                .service_name(),
            pending_registry_removal: false,
            claimed_by: Some(operation_id.to_string()),
        });
    })
    .expect("quarantine");
    persist_registry_mutation_fence(
        operation_id,
        BrowserLoginMode::Target,
        None,
        reusable.to_str(),
        Some(target_id),
        Some(&expected_account),
        Some(&expected_organization),
    )
    .expect("pre-registry fence");
    fs::write(
        reusable.join(".claude.json"),
        br#"{"oauthAccount":{"accountUuid":"wrong-account","organizationUuid":"wrong-org","emailAddress":"wrong@example.invalid"}}"#,
    )
    .expect("wrong identity");
    crate::test_scratch::write_private_file(
        reusable.join(".credentials.json"),
        br#"{"claudeAiOauth":{"accessToken":"fixture-wrong-token","refreshToken":"fixture-wrong-token-refresh","expiresAt":4102444800000,"scopes":["user:inference"]}}"#,
    );
    let store = FileClaudeConfigSlotSettingsStore::default();
    let prepared = store
        .prepare_managed_account_target_in_reusable_root(
            1,
            operation_id.to_string(),
            Some(target_id.to_string()),
            Some(expected_account),
            Some(expected_organization),
            reusable.to_string_lossy().into_owned(),
        )
        .expect("core exposure");
    let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
    assert!(read_operation(operation_id)
        .expect("placeholder")
        .slot_id
        .is_empty());
    assert_eq!(
        collection_suppression(&slot_id),
        Some(ClaudeCollectionSuppression::HideProvisionalTarget)
    );
    let direct = crate::agent_status::collect_registered_claude_slot_status(
        &slot_id,
        "2026-08-31T00:00:00Z".to_string(),
        "2026-08-31T00:05:00Z".to_string(),
    );
    assert!(direct.account_identifier_hash.is_none());
    assert!(direct.organization_identifier_hash.is_none());
    let _ = crate::agent_status::collect_agent_status_collection(
        &ottto_protocol::SourceKind::ClaudeCode,
        "2026-08-31T00:00:00Z".to_string(),
        "2026-08-31T00:05:00Z".to_string(),
    );
    let durable = crate::agent_status::annotate_claude_accounts_status(
        store.load().expect("post-scheduled registry"),
    );
    let collection = &durable
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == slot_id)
        .expect("target slot")
        .collection;
    assert!(collection.account_identifier_hash.is_none());
    assert!(collection.organization_identifier_hash.is_none());
    fs::remove_dir_all(&reusable).expect("remove root before start");
    assert!(start(prepared, BrowserLoginMode::Target).is_err());
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::LoginFailed)
    );
    assert_eq!(read_state().active_operation_id, None);
    assert!(!store
        .load()
        .expect("retired target")
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn reconnect_core_refresh_is_fenced_before_sidecar_start() {
    let root = temp_dir("reconnect-pre-sidecar-fence");
    let support = root.join("support");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    let managed = managed_parent.join("claude_slot_82828282828282828282828282828282");
    fs::create_dir_all(&managed).expect("managed root");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("managed parent mode");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("managed mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_managed_path(1, managed.to_string_lossy().into_owned())
        .expect("register");
    let slot_id = registered.managed_slots[0].slot_id.clone();
    let account = "c".repeat(64);
    let organization = "d".repeat(64);
    let prior = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
        account_identifier_hash: Some(account.clone()),
        organization_identifier_hash: Some(organization.clone()),
        ..Default::default()
    };
    crate::agent_status::persist_one_claude_slot_collection_state(&slot_id, &prior)
        .expect("prior canonical evidence");
    fs::write(
        managed.join(".claude.json"),
        br#"{"oauthAccount":{"accountUuid":"wrong-account","organizationUuid":"wrong-org","emailAddress":"wrong@example.invalid"}}"#,
    )
    .expect("wrong identity");
    crate::test_scratch::write_private_file(
        managed.join(".credentials.json"),
        br#"{"claudeAiOauth":{"accessToken":"fixture-wrong-token","refreshToken":"fixture-wrong-token-refresh","expiresAt":4102444800000,"scopes":["user:inference"]}}"#,
    );
    let operation_id = "claude_setup_82828282828282828282828282828282";
    let target_id = "claude_anchor_target_82828282828282828282828282828282";
    claim_ceremony(operation_id).expect("claim");
    persist_registry_mutation_fence(
        operation_id,
        BrowserLoginMode::Reconnect,
        Some(&slot_id),
        managed.to_str(),
        Some(target_id),
        Some(&account),
        Some(&organization),
    )
    .expect("pre-core reconnect fence");
    let reconnecting = store
        .begin_registered_slot_reconnect_target(
            1,
            operation_id.to_string(),
            &slot_id,
            Some(target_id.to_string()),
            account.clone(),
            Some(organization.clone()),
        )
        .expect("core reconnect");
    let direct = crate::agent_status::collect_registered_claude_slot_status(
        &slot_id,
        "2026-08-31T00:00:00Z".to_string(),
        "2026-08-31T00:05:00Z".to_string(),
    );
    assert_eq!(direct, prior);
    let _ = crate::agent_status::collect_agent_status_collection(
        &ottto_protocol::SourceKind::ClaudeCode,
        "2026-08-31T00:00:00Z".to_string(),
        "2026-08-31T00:05:00Z".to_string(),
    );
    let durable = crate::agent_status::annotate_claude_accounts_status(
        store.load().expect("post-scheduled registry"),
    );
    let durable_collection = &durable
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == slot_id)
        .expect("reconnect slot")
        .collection;
    assert_eq!(
        durable_collection.account_identifier_hash,
        prior.account_identifier_hash
    );
    assert_eq!(
        durable_collection.organization_identifier_hash,
        prior.organization_identifier_hash
    );
    assert!(durable_collection.quota_snapshot.is_none());
    fs::remove_dir_all(&managed).expect("remove root before reconnect start");
    assert!(start(reconnecting, BrowserLoginMode::Reconnect).is_err());
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::LoginFailed)
    );
    assert_eq!(read_state().active_operation_id, None);
    assert!(store
        .load()
        .expect("canonical reconnect retained")
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn corrupt_or_unreadable_sidecar_preserves_registered_collection_without_probe() {
    let root = temp_dir("collection-fence-corrupt-sidecar");
    let support = root.join("support");
    let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    let managed = managed_parent.join("claude_slot_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3");
    fs::create_dir_all(&managed).expect("managed root");
    #[cfg(unix)]
    {
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("managed parent mode");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
            .expect("managed root mode");
    }
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store
        .register_managed_path(1, managed.to_string_lossy().into_owned())
        .expect("register");
    let slot_id = registered.managed_slots[0].slot_id.clone();
    let account = "d".repeat(64);
    let organization = "e".repeat(64);
    let prior = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
        account_identifier_hash: Some(account.clone()),
        organization_identifier_hash: Some(organization.clone()),
        ..Default::default()
    };
    crate::agent_status::persist_one_claude_slot_collection_state(&slot_id, &prior)
        .expect("prior collection");

    fs::write(state_path(), b"{corrupt").expect("corrupt sidecar");
    assert_eq!(
        collection_suppression(&slot_id),
        Some(ClaudeCollectionSuppression::PreserveWhileStateUnavailable)
    );
    let corrupt = crate::agent_status::collect_registered_claude_slot_status(
        &slot_id,
        "corrupt".to_string(),
        "corrupt-expiry".to_string(),
    );
    assert_eq!(corrupt.account_identifier_hash, Some(account.clone()));
    assert_eq!(
        corrupt.organization_identifier_hash,
        Some(organization.clone())
    );

    fs::remove_file(state_path()).expect("remove corrupt sidecar");
    fs::create_dir(state_path()).expect("make sidecar unreadable as a file");
    assert_eq!(
        collection_suppression(&slot_id),
        Some(ClaudeCollectionSuppression::PreserveWhileStateUnavailable)
    );
    let unreadable = crate::agent_status::collect_registered_claude_slot_status(
        &slot_id,
        "unreadable".to_string(),
        "unreadable-expiry".to_string(),
    );
    assert_eq!(unreadable.account_identifier_hash, Some(account));
    assert_eq!(unreadable.organization_identifier_hash, Some(organization));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn failed_reconnect_fence_survives_trim_and_successful_reconnect_clears_it() {
    let root = temp_dir("reconnect-fence-retention");
    let support = root.join("support");
    fs::create_dir_all(&support).expect("support");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let slot_id = "claude_slot_c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4".to_string();
    let failed_id = "claude_setup_c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
    let failed = PersistedOperation {
        operation_id: failed_id.to_string(),
        slot_id: slot_id.clone(),
        config_dir: "/private/reconnect".to_string(),
        ceremony_baseline: None,
        mode: PersistedMode::Reconnect,
        target_id: None,
        expected_account_identifier_hash: Some("a".repeat(64)),
        expected_organization_identifier_hash: Some("b".repeat(64)),
        phase: ClaudeBrowserAuthPhaseV1::Complete,
        outcome: Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch),
        canonical_slot_id: None,
        admission_slot_id: None,
        identity_mismatch: Some(ClaudeBrowserAuthIdentityMismatchV1::Organization),
        cancel_requested: false,
        started_unix_seconds: 1,
        deadline_unix_seconds: 2,
        completed_unix_seconds: Some(2),
        fallback_completed: false,
    };
    transact(|state| {
        state.operations.push(failed.clone());
        for index in 0..(MAX_RETAINED_OPERATIONS + 8) {
            let mut later = failed.clone();
            later.operation_id = format!("claude_setup_{:032x}", index + 1);
            later.slot_id = format!("claude_slot_{:032x}", index + 1);
            later.mode = PersistedMode::Generic;
            later.outcome = Some(ClaudeBrowserAuthOutcomeV1::LoginFailed);
            later.identity_mismatch = None;
            later.started_unix_seconds = 3 + index as u64;
            later.completed_unix_seconds = Some(3 + index as u64);
            state.operations.push(later);
        }
        trim_operations(state);
    })
    .expect("trim fixture");
    assert!(read_operation(failed_id).is_some());
    assert_eq!(
        collection_suppression(&slot_id),
        Some(ClaudeCollectionSuppression::PreserveCanonicalReconnect)
    );

    let mut successful = failed;
    successful.operation_id = "claude_setup_c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5".to_string();
    successful.outcome = Some(ClaudeBrowserAuthOutcomeV1::Complete);
    successful.identity_mismatch = None;
    successful.started_unix_seconds = 100;
    successful.completed_unix_seconds = Some(101);
    transact(|state| {
        state.operations.push(successful);
        trim_operations(state);
    })
    .expect("successful successor");
    assert_eq!(collection_suppression(&slot_id), None);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn target_success_consumes_prelaunch_quarantine_claim() {
    let (root, _support_dir, _support) = with_support("target-success-consumes-claim");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let operation_id = "claude_setup_d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    let prepared = store
        .prepare_managed_account_target(
            1,
            operation_id.to_string(),
            Some("claude_anchor_target_d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1".to_string()),
            Some(account.clone()),
            Some(organization.clone()),
        )
        .expect("target");
    let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
    let config_dir = prepared
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == slot_id)
        .and_then(|slot| slot.config_dir.clone())
        .expect("config root");
    let operation = PersistedOperation {
        operation_id: operation_id.to_string(),
        slot_id: slot_id.clone(),
        config_dir,
        ceremony_baseline: None,
        mode: PersistedMode::Target,
        target_id: prepared.setup_operation.target_id.clone(),
        expected_account_identifier_hash: Some(account.clone()),
        expected_organization_identifier_hash: Some(organization.clone()),
        phase: ClaudeBrowserAuthPhaseV1::Validating,
        outcome: None,
        canonical_slot_id: None,
        admission_slot_id: None,
        identity_mismatch: None,
        cancel_requested: false,
        started_unix_seconds: 1,
        deadline_unix_seconds: u64::MAX,
        completed_unix_seconds: None,
        fallback_completed: false,
    };
    transact(|state| state.operations.push(operation.clone())).expect("sidecar");
    reserve_quarantine_root(&operation, false).expect("prelaunch reservation");
    assert_eq!(
        collection_suppression(&slot_id),
        Some(ClaudeCollectionSuppression::HideProvisionalTarget)
    );
    assert_one_completed_request(operation_id);
    assert_eq!(collection_suppression(&slot_id), None);
    let state = read_state();
    assert!(!state
        .quarantined_roots
        .iter()
        .any(|root| root.claimed_by.as_deref() == Some(operation_id)));
    assert!(store
        .load()
        .expect("registry")
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id));
    let _ = fs::remove_dir_all(root);
}

/// A target sign-in for a pair another healthy slot already serves ends
/// AlreadyConnected and asks for no immediate status pass, even on replay.
#[test]
#[serial]
fn target_duplicate_of_a_serving_slot_requests_no_immediate_status() {
    let (root, _support_dir, _support) = with_support("target-duplicate-no-request");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let operation_id = "claude_setup_d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    let prepared = store
        .prepare_managed_account_target(
            1,
            operation_id.to_string(),
            Some("claude_anchor_target_d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4".to_string()),
            Some(account.clone()),
            Some(organization.clone()),
        )
        .expect("target");
    let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
    let config_dir = prepared
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == slot_id)
        .and_then(|slot| slot.config_dir.clone())
        .expect("config root");
    let operation = PersistedOperation {
        operation_id: operation_id.to_string(),
        slot_id: slot_id.clone(),
        config_dir,
        ceremony_baseline: None,
        mode: PersistedMode::Target,
        target_id: prepared.setup_operation.target_id.clone(),
        expected_account_identifier_hash: Some(account.clone()),
        expected_organization_identifier_hash: Some(organization.clone()),
        phase: ClaudeBrowserAuthPhaseV1::Validating,
        outcome: None,
        canonical_slot_id: None,
        admission_slot_id: None,
        identity_mismatch: None,
        cancel_requested: false,
        started_unix_seconds: 1,
        deadline_unix_seconds: u64::MAX,
        completed_unix_seconds: None,
        fallback_completed: false,
    };
    transact(|state| state.operations.push(operation.clone())).expect("sidecar");
    reserve_quarantine_root(&operation, false).expect("prelaunch reservation");
    // Another slot that already serves the same pair with a valid credential.
    let existing_root = root.join("existing");
    fs::create_dir_all(&existing_root).expect("existing root");
    let existing_slot = store
        .register_path(1, existing_root.to_string_lossy().into_owned())
        .expect("existing registration")
        .external_slots[0]
        .slot_id
        .clone();
    let valid = (time::OffsetDateTime::now_utc() + time::Duration::hours(8))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("expiry");
    crate::agent_status::persist_one_claude_slot_collection_state(
        &existing_slot,
        &ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ottto_protocol::ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account),
            organization_identifier_hash: Some(organization),
            observed_at: Some("2026-09-24T12:21:06Z".to_string()),
            access_expires_at: Some(valid),
            ..Default::default()
        },
    )
    .expect("existing saved state");

    assert!(finalize_requests_now(operation_id).is_empty());
    let finished = read_operation(operation_id).expect("finished operation");
    assert_eq!(
        finished.outcome,
        Some(ClaudeBrowserAuthOutcomeV1::AlreadyConnected)
    );
    assert_eq!(
        finished.canonical_slot_id.as_deref(),
        Some(existing_slot.as_str())
    );
    assert!(finalize_requests_now(operation_id).is_empty());
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn target_mismatch_retires_candidate_and_preserves_exact_root_for_reuse() {
    let (root, _support_dir, _support) = with_support("target-mismatch-retire");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let operation_id = "claude_setup_d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
    let account = "a".repeat(64);
    let organization = "b".repeat(64);
    let prepared = store
        .prepare_managed_account_target(
            1,
            operation_id.to_string(),
            Some("claude_anchor_target_d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2".to_string()),
            Some(account.clone()),
            Some(organization.clone()),
        )
        .expect("target");
    let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
    let config_dir = prepared
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == slot_id)
        .and_then(|slot| slot.config_dir.clone())
        .expect("config root");
    let operation = PersistedOperation {
        operation_id: operation_id.to_string(),
        slot_id: slot_id.clone(),
        config_dir: config_dir.clone(),
        ceremony_baseline: None,
        mode: PersistedMode::Target,
        target_id: prepared.setup_operation.target_id.clone(),
        expected_account_identifier_hash: Some(account),
        expected_organization_identifier_hash: Some(organization.clone()),
        phase: ClaudeBrowserAuthPhaseV1::Validating,
        outcome: None,
        canonical_slot_id: None,
        admission_slot_id: None,
        identity_mismatch: None,
        cancel_requested: false,
        started_unix_seconds: 1,
        deadline_unix_seconds: u64::MAX,
        completed_unix_seconds: None,
        fallback_completed: false,
    };
    transact(|state| state.operations.push(operation.clone())).expect("sidecar");
    reserve_quarantine_root(&operation, false).expect("prelaunch reservation");
    let settings = Path::new(&config_dir).join("settings.json");
    fs::write(&settings, "{broken").expect("unsafe settings fixture");
    assert!(retire_target_candidate(&operation, true).is_err());
    assert!(store
        .load()
        .unwrap()
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id));
    assert_eq!(fs::read_to_string(&settings).unwrap(), "{broken");
    fs::write(&settings, r#"{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_EXPORTER_OTLP_HEADERS":"X-Ottto-Local-Relay=claude_code","OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"http://127.0.0.1:48123/v1/logs","USER_FLAG":"keep"}}"#).unwrap();
    let wrong_account = "c".repeat(64);
    let collection = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
        account_identifier_hash: Some(wrong_account.clone()),
        organization_identifier_hash: Some(organization.clone()),
        ..Default::default()
    };
    finalize_identity(
        operation_id,
        crate::agent_status::ClaudeLocalIdentityProof {
            account_identifier_hash: wrong_account,
            organization_identifier_hash: organization,
            collection,
        },
    )
    .expect("typed mismatch");
    let registry = store.load().expect("registry");
    assert!(!registry
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id));
    assert_eq!(registry.capacity.used_slots, 1);
    let current = read_operation(operation_id).expect("operation");
    assert_eq!(
        current.outcome,
        Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch)
    );
    assert_eq!(
        current.identity_mismatch,
        Some(ClaudeBrowserAuthIdentityMismatchV1::Account)
    );
    assert!(Path::new(&config_dir).is_dir());
    let cleared: serde_json::Value = serde_json::from_slice(&fs::read(&settings).unwrap()).unwrap();
    assert_eq!(cleared["env"], serde_json::json!({"USER_FLAG":"keep"}));
    let retry_id = "claude_setup_d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3";
    let reused = claim_reusable_root(retry_id)
        .expect("claim reusable")
        .expect("retained exact root");
    assert_eq!(reused, config_dir);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn full_quarantine_keeps_target_candidate_registered_and_tracked() {
    let (root, _support_dir, _support) = with_support("target-quarantine-full");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let operation_id = "claude_setup_17171717171717171717171717171717";
    let retry_id = "claude_setup_16161616161616161616161616161616";
    let prepared = store
        .prepare_managed_account_target(
            1,
            operation_id.to_string(),
            Some("claude_anchor_target_17171717171717171717171717171717".to_string()),
            Some("a".repeat(64)),
            Some("b".repeat(64)),
        )
        .expect("target");
    let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
    let config_dir = prepared
        .managed_slots
        .iter()
        .find(|slot| slot.slot_id == slot_id)
        .and_then(|slot| slot.config_dir.clone())
        .expect("root");
    let now = unix_seconds();
    let operation = PersistedOperation {
        operation_id: operation_id.to_string(),
        slot_id: slot_id.clone(),
        config_dir,
        ceremony_baseline: None,
        mode: PersistedMode::Target,
        target_id: None,
        expected_account_identifier_hash: Some("a".repeat(64)),
        expected_organization_identifier_hash: Some("b".repeat(64)),
        phase: ClaudeBrowserAuthPhaseV1::Validating,
        outcome: None,
        canonical_slot_id: None,
        admission_slot_id: None,
        identity_mismatch: None,
        cancel_requested: false,
        started_unix_seconds: now,
        deadline_unix_seconds: now + 60,
        completed_unix_seconds: None,
        fallback_completed: false,
    };
    transact(|state| {
        state.operations.push(operation.clone());
        for index in 0..MAX_QUARANTINED_ROOTS {
            state.quarantined_roots.push(QuarantinedRoot {
                root_id: format!("claude_slot_{index:032x}"),
                config_dir: format!("/private/quarantine/{index}"),
                service_alias: format!("Claude Code-{index:08x}"),
                pending_registry_removal: false,
                claimed_by: None,
            });
        }
    })
    .expect("state");
    assert!(retire_target_candidate(&operation, true).is_err());
    assert!(store
        .load()
        .expect("registry")
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id));
    assert!(Path::new(&operation.config_dir).is_dir());
    assert!(claim_ceremony(operation_id).expect("fallback claim"));
    transact(|state| {
        let persisted = state
            .operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation_id)
            .expect("persisted target");
        persisted.phase = ClaudeBrowserAuthPhaseV1::Complete;
        persisted.outcome = Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired);
    })
    .expect("fallback state");
    assert!(terminalize_fallback_operation(
        &read_operation(operation_id).expect("fallback target"),
        ClaudeBrowserAuthOutcomeV1::TimedOut,
    )
    .is_err());
    assert_eq!(
        read_operation(operation_id).and_then(|candidate| candidate.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
    );
    assert!(claim_ceremony(retry_id).is_err());
    assert!(store
        .load()
        .expect("failed terminalization registry")
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id));
    release_ceremony(operation_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn full_quarantine_rejects_target_before_provider_launch_with_terminal_truth() {
    let (root, _support_dir, _support) = with_support("target-prelaunch-quarantine-full");
    let store = FileClaudeConfigSlotSettingsStore::default();
    let operation_id = "claude_setup_18181818181818181818181818181818";
    let target_id = "claude_anchor_target_18181818181818181818181818181818";
    claim_ceremony(operation_id).expect("claim");
    let prepared = store
        .prepare_managed_account_target(
            1,
            operation_id.to_string(),
            Some(target_id.to_string()),
            Some("a".repeat(64)),
            Some("b".repeat(64)),
        )
        .expect("target");
    let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
    transact(|state| {
        for index in 0..MAX_QUARANTINED_ROOTS {
            state.quarantined_roots.push(QuarantinedRoot {
                root_id: format!("claude_slot_{index:032x}"),
                config_dir: format!("/private/quarantine/{index}"),
                service_alias: format!("Claude Code-{index:08x}"),
                pending_registry_removal: false,
                claimed_by: None,
            });
        }
    })
    .expect("full quarantine");
    let error = start(prepared, BrowserLoginMode::Target).expect_err("capacity rejection");
    assert!(error.contains("capacity"));
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::LoginFailed)
    );
    assert_eq!(read_state().active_operation_id, None);
    let status = store
        .setup_operation(operation_id)
        .expect("terminal core op");
    assert_eq!(
        status.setup_operation.state,
        ClaudeAccountSetupOperationState::SetupFailed
    );
    assert!(status
        .managed_slots
        .iter()
        .any(|slot| slot.slot_id == slot_id));
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn initial_fallback_transition_observer_auto_completes_after_legacy_login() {
    let root = temp_dir("fallback-observer");
    let support = root.join("support");
    let bin = root.join("bin");
    let home = root.join("home");
    for directory in [&support, &bin, &home] {
        fs::create_dir_all(directory).expect("directory");
    }
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    let claude = bin.join("claude");
    fs::write(
        &claude,
        r#"#!/bin/sh
if [ "$1" = "auth" ] && [ "$2" = "status" ] && [ "$3" = "--json" ]; then
  printf '%s\n' '{"status":"authenticated","email":"fallback@example.invalid","organizationId":"organization-fallback","subscriptionType":"max"}'
  exit 0
fi
exit 1
"#,
    )
    .expect("fake claude");
    fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).expect("claude mode");
    // Keychain item not found: the credentials file is the store.
    let security = bin.join("security");
    fs::write(&security, "#!/bin/sh\nexit 44\n").expect("fake security");
    fs::set_permissions(&security, fs::Permissions::from_mode(0o755)).expect("security mode");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &bin);
    let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home);
    let operation_id = "claude_setup_18181818181818181818181818181818";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare");
    let operation = read_operation(operation_id).expect("operation");
    let baseline =
        crate::agent_status::claude_auth_ceremony_witness(&operation.config_dir).expect("baseline");
    transact(|state| {
        let persisted = state
            .operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation_id)
            .expect("persisted");
        persisted.ceremony_baseline = Some(baseline);
        persisted.phase = ClaudeBrowserAuthPhaseV1::WaitingForProvider;
    })
    .expect("baseline state");
    reserve_quarantine_root(&read_operation(operation_id).expect("operation"), false)
        .expect("reserve fallback root");
    finish(
        operation_id,
        ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired,
        None,
    );
    fs::write(
        Path::new(&operation.config_dir).join(".claude.json"),
        serde_json::to_vec(&serde_json::json!({
            "oauthAccount": {
                "accountUuid": "account-fallback",
                "organizationUuid": "organization-fallback",
                "emailAddress": "fallback@example.invalid"
            }
        }))
        .expect("identity"),
    )
    .expect("identity write");
    crate::test_scratch::write_private_file(
        Path::new(&operation.config_dir).join(".credentials.json"),
        br#"{"claudeAiOauth":{"accessToken":"fixture-fallback-token","refreshToken":"fixture-fallback-token-refresh","expiresAt":4102444800000,"scopes":["user:inference"]}}"#,
    );
    for _ in 0..80 {
        if read_operation(operation_id).is_some_and(|current| current.fallback_completed) {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let completed = read_operation(operation_id).expect("completed operation");
    assert!(completed.fallback_completed);
    assert_eq!(
        public_operation(&completed).outcome,
        Some(ClaudeBrowserAuthOutcomeV1::Complete)
    );
    assert_eq!(
        FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("admitted registry")
            .capacity
            .used_slots,
        2
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
#[cfg(unix)]
fn legacy_fallback_replay_is_not_advertised_and_releases_at_deadline() {
    let root = temp_dir("fallback-replay-deadline");
    let support = root.join("support");
    let bin = root.join("bin");
    let home = root.join("home");
    fs::create_dir_all(&support).expect("support");
    fs::create_dir_all(&bin).expect("bin");
    fs::create_dir_all(&home).expect("home");
    #[cfg(unix)]
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
    let executable = bin.join("claude");
    fs::write(&executable, "#!/bin/sh\nexit 1\n").expect("fake claude");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
        .expect("fake executable mode");
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &bin);
    let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home);
    let operation_id = "claude_setup_e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1";
    let retry_id = "claude_setup_e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    let prepared = prepare_generic(status, operation_id).expect("prepare");
    transact(|state| {
        let operation = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
            .expect("operation");
        operation.phase = ClaudeBrowserAuthPhaseV1::Complete;
        operation.outcome = Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired);
        operation.completed_unix_seconds = Some(0);
    })
    .expect("fallback transition fixture");
    let replay = terminal_replay(prepared, operation_id).expect("terminal replay");
    assert!(!replay
        .setup_operation
        .browser_auth
        .as_ref()
        .is_some_and(|browser| browser.terminal_fallback_available));
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline
        && read_operation(operation_id).is_some_and(|operation| {
            operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
        })
    {
        thread::sleep(Duration::from_millis(25));
    }
    let terminal = read_operation(operation_id).expect("terminal operation");
    assert_eq!(terminal.outcome, Some(ClaudeBrowserAuthOutcomeV1::TimedOut));
    assert!(!public_operation(&terminal).terminal_fallback_available);
    assert!(claim_ceremony(retry_id).expect("fallback deadline released ceremony"));
    release_ceremony(retry_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn fallback_stop_waiting_terminalizes_before_fresh_retry() {
    let (root, _support_dir, _support) = with_support("fallback-stop-waiting");
    let operation_id = "claude_setup_d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
    let retry_id = "claude_setup_d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare");
    let ((), requested) = crate::agent_status_refresh::with_test_requests_now(|| {
        finish(
            operation_id,
            ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired,
            None,
        );
        assert!(request_cancel(operation_id).expect("cancel request"));
    });
    assert!(requested.is_empty(), "fallback and cancel ask for no pass");
    let cancelled = read_operation(operation_id).expect("cancelled fallback");
    assert_eq!(
        cancelled.outcome,
        Some(ClaudeBrowserAuthOutcomeV1::Cancelled)
    );
    assert!(read_state().quarantined_roots.iter().any(|candidate| {
        candidate.root_id == cancelled.slot_id && candidate.claimed_by.is_none()
    }));
    assert!(claim_ceremony(retry_id).expect("fresh retry claim"));
    release_ceremony(retry_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn terminal_fallback_recovery_retains_ceremony_for_observer() {
    let (root, _support_dir, _support) = with_support("fallback-recovery-retains-claim");
    let operation_id = "claude_setup_d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3";
    let retry_id = "claude_setup_d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare");
    transact(|state| {
        let operation = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
            .expect("operation");
        operation.phase = ClaudeBrowserAuthPhaseV1::Complete;
        operation.outcome = Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired);
        operation.completed_unix_seconds = Some(unix_seconds());
    })
    .expect("fallback fixture");

    recover_operation(operation_id);
    assert!(claim_ceremony(retry_id).is_err());
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
    );
    assert!(request_cancel(operation_id).expect("cancel request"));
    assert!(claim_ceremony(retry_id).expect("fresh claim after fallback cancel"));
    release_ceremony(retry_id);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[serial]
fn fallback_state_write_failure_preserves_nonterminal_claim() {
    let (root, _support_dir, _support) = with_support("fallback-state-write-failure");
    let operation_id = "claude_setup_c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
    let retry_id = "claude_setup_c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .expect("registry");
    prepare_generic(status, operation_id).expect("prepare");
    finish(
        operation_id,
        ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired,
        None,
    );
    let operation = read_operation(operation_id).expect("fallback operation");
    let state = fs::read(state_path()).expect("saved state");
    fs::remove_file(state_path()).expect("remove state");
    fs::create_dir(state_path()).expect("block state write");

    assert!(
        terminalize_fallback_operation(&operation, ClaudeBrowserAuthOutcomeV1::TimedOut).is_err()
    );
    fs::remove_dir(state_path()).expect("remove blocker");
    fs::write(state_path(), state).expect("restore state");
    assert_eq!(
        read_operation(operation_id).and_then(|operation| operation.outcome),
        Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
    );
    assert!(claim_ceremony(retry_id).is_err());

    assert!(request_cancel(operation_id).expect("cancel request"));
    assert!(claim_ceremony(retry_id).expect("claim after ordered cancel"));
    release_ceremony(retry_id);
    let _ = fs::remove_dir_all(root);
}
