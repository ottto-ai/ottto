//! A Codex sign-in the daemon runs itself (control protocol v26).
//!
//! After a setup operation reserved a managed home (prepare, prepare-open,
//! prepare-target or reconnect), `codex_account_start_sign_in` runs
//! `codex login` for that home: no terminal, stdin closed, the home's own
//! `CODEX_HOME`, and the same binary, PATH and clean environment as the
//! home's quota reads. The CLI opens the sign-in page in the default browser
//! and waits on a local callback port. The daemon:
//! - starts at most one sign-in at a time. Every `codex login` on the Mac
//!   listens on the same local port, and a new one takes it over from the
//!   last, so none starts while the port is taken (`port_busy`);
//! - keeps the sign-in page address the CLI prints, in memory only, so a
//!   client can open it again or copy it. It is never logged or stored;
//! - stops the CLI (SIGTERM, then SIGKILL) on cancel or after
//!   [`SIGN_IN_TIMEOUT`], and waits for the port to be free again;
//! - decides by the home's `auth.json`, not the exit status: `codex login`
//!   exits 0 both when it saved a credential and when it was stopped. A
//!   credential that appeared or changed during the run is the result; then
//!   the account is read through the setup's validation, and that read is
//!   retried once after [`CHECK_RETRY_DELAY`] when it fails;
//! - never restarts a sign-in after a daemon restart: a run whose credential
//!   changed is checked once, any other ends `interrupted`.
//!
//! The browser sign-in is the person's, not a provider call of ours; the call
//! log records the account reads only (trigger `setup`). Never used for the
//! person's own `~/.codex`: setup operations only name managed homes.
//!
//! The CLI stays in the daemon's process group, so the service manager ends
//! it with the daemon.

use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use ottto_core::{CodexAccountSlotSettingsError, FileCodexAccountSlotSettingsStore};
use ottto_protocol::{
    CodexAccountSetupOperationStateV1, CodexAccountSetupOperationV1, CodexAccountSignInOutcomeV1,
    CodexAccountSignInPhaseV1, CodexAccountsStatusV1, SecretString,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::control::CodexSetupValidationEnd;

/// How long a sign-in may wait for the person, as for Claude.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Wait before the one retry of a failed account read after a sign-in.
const CHECK_RETRY_DELAY: Duration = Duration::from_secs(15);
/// The local callback port of every `codex login` browser sign-in.
const CODEX_LOGIN_PORT: u16 = 1455;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Time the CLI gets to exit after SIGTERM before SIGKILL.
const TERMINATE_GRACE: Duration = Duration::from_secs(5);
/// Time to wait for the callback port to be free after the CLI exited.
const PORT_RELEASE_WAIT: Duration = Duration::from_secs(3);
/// How long a stop request waits for a running sign-in to end.
const CANCEL_WAIT: Duration = Duration::from_secs(10);
/// Bounds on the CLI output scanned for the sign-in page address; the rest
/// is drained unread.
const MAX_SCANNED_LINE_BYTES: u64 = 16 * 1024;
const MAX_SCANNED_BYTES: u64 = 256 * 1024;
const MAX_SIGN_IN_URL_BYTES: usize = 8 * 1024;

const PORT_BUSY_MESSAGE: &str =
    "Another Codex sign-in is open on this Mac. Finish or close it, then try again.";
const CODEX_UNAVAILABLE_MESSAGE: &str =
    "Codex could not be started. Check that the Codex CLI is installed, then try again.";
const CANCELLED_MESSAGE: &str =
    "Stopped the Codex sign-in; the Codex home and provider credential were left untouched.";
const TIMED_OUT_MESSAGE: &str =
    "The Codex sign-in did not finish within 10 minutes and was stopped. Try again.";
const INTERRUPTED_MESSAGE: &str =
    "Ottto restarted during the Codex sign-in, so it was stopped. Try again.";
const ENDED_EARLY_MESSAGE: &str = "The Codex sign-in ended before it finished. If another Codex sign-in was started on this Mac, finish or close it, then try again.";
const FAILED_MESSAGE: &str = "The Codex sign-in failed. Try again.";
const NOT_SAVED_MESSAGE: &str =
    "Codex reported a sign-in, but no sign-in was saved for this account. Try again.";
const STOPPED_UNEXPECTEDLY_MESSAGE: &str = "The Codex sign-in stopped unexpectedly. Try again.";

/// The sign-in running in this daemon, if any.
static ACTIVE: Mutex<Option<Arc<Run>>> = Mutex::new(None);

struct Run {
    operation_id: String,
    cancel: AtomicBool,
    /// The sign-in page address, while the CLI waits for the browser.
    url: Mutex<Option<String>>,
    ended: Mutex<bool>,
    ended_changed: Condvar,
}

impl Run {
    fn new(operation_id: &str) -> Arc<Self> {
        Arc::new(Self {
            operation_id: operation_id.to_string(),
            cancel: AtomicBool::new(false),
            url: Mutex::new(None),
            ended: Mutex::new(false),
            ended_changed: Condvar::new(),
        })
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    fn set_url(&self, url: Option<String>) {
        *self.url.lock().unwrap_or_else(PoisonError::into_inner) = url;
    }

    /// Wait up to `timeout` for the cancel flag. True when it was set.
    fn wait_for_cancel(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.cancelled() {
                return true;
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
        self.cancelled()
    }
}

/// Ends a run however its worker leaves: a run that recorded no outcome
/// (a store error, a panic) is ended as failed, so it cannot stay "running"
/// in the persisted setup.
struct RunGuard {
    run: Arc<Run>,
    finished: bool,
}

impl RunGuard {
    fn finish(&mut self, outcome: CodexAccountSignInOutcomeV1, message: &str) {
        self.finished = true;
        // An operation stopped or replaced meanwhile has nothing to record.
        let _ = store().finish_sign_in(&self.run.operation_id, outcome, message);
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = store().finish_sign_in(
                &self.run.operation_id,
                CodexAccountSignInOutcomeV1::LoginFailed,
                STOPPED_UNEXPECTEDLY_MESSAGE,
            );
        }
        self.run.set_url(None);
        {
            let mut active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
            if active
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &self.run))
            {
                *active = None;
            }
        }
        *self
            .run
            .ended
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        self.run.ended_changed.notify_all();
    }
}

fn store() -> FileCodexAccountSlotSettingsStore {
    FileCodexAccountSlotSettingsStore::default()
}

/// Start the daemon-run sign-in of `operation_id`. A replay while that run is
/// active changes nothing.
pub(crate) fn start(
    schema_version: u16,
    operation_id: &str,
) -> Result<(), CodexAccountSlotSettingsError> {
    let mut active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(run) = active.as_ref() {
        if run.operation_id == operation_id {
            return Ok(());
        }
        return Err(CodexAccountSlotSettingsError::Invalid(
            "Another Codex sign-in is already running.".to_string(),
        ));
    }
    let timeout = timings().sign_in_timeout;
    let started = OffsetDateTime::now_utc();
    let deadline = Deadline {
        monotonic: Instant::now() + timeout,
        wall: started + timeout,
    };
    let Some(home) = store().begin_sign_in(
        schema_version,
        operation_id,
        rfc3339(started),
        rfc3339(deadline.wall),
    )?
    else {
        return Ok(());
    };
    let run = Run::new(operation_id);
    *active = Some(run.clone());
    drop(active);
    let worker_run = run.clone();
    let spawned = thread::Builder::new()
        .name("ottto-codex-sign-in".to_string())
        .spawn(move || run_sign_in(worker_run, home, deadline));
    if spawned.is_err() {
        // The guard was never built: end the run here.
        RunGuard {
            run,
            finished: false,
        }
        .finish(
            CodexAccountSignInOutcomeV1::LoginFailed,
            STOPPED_UNEXPECTEDLY_MESSAGE,
        );
    }
    Ok(())
}

/// Stop the running sign-in of `operation_id`, if this daemon runs one: end
/// `codex login` and record `cancelled`. Waits a bounded time for the run to
/// end. False when this daemon runs no sign-in for the operation.
pub(crate) fn cancel(operation_id: &str) -> bool {
    let run = {
        let active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
        match active.as_ref() {
            Some(run) if run.operation_id == operation_id => run.clone(),
            _ => return false,
        }
    };
    run.cancel.store(true, Ordering::SeqCst);
    let ended = run.ended.lock().unwrap_or_else(PoisonError::into_inner);
    let _ = run
        .ended_changed
        .wait_timeout_while(ended, CANCEL_WAIT, |ended| !*ended);
    true
}

/// Whether the operation has a daemon-run sign-in that has not ended.
pub(crate) fn is_running(operation: &CodexAccountSetupOperationV1) -> bool {
    operation
        .sign_in
        .as_ref()
        .is_some_and(|sign_in| sign_in.phase != CodexAccountSignInPhaseV1::Done)
}

/// The status as a client sees it: the capability bit, and the sign-in page
/// address of the running sign-in while it waits for the browser.
pub(crate) fn present(mut status: CodexAccountsStatusV1) -> CodexAccountsStatusV1 {
    status.daemon_sign_in_supported = Some(true);
    let operation_id = status.setup_operation.operation_id.clone();
    if let Some(sign_in) = status.setup_operation.sign_in.as_mut() {
        sign_in.sign_in_url = None;
        if sign_in.phase == CodexAccountSignInPhaseV1::WaitingForBrowser {
            let active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(run) = active
                .as_ref()
                .filter(|run| operation_id.as_deref() == Some(run.operation_id.as_str()))
            {
                sign_in.sign_in_url = run
                    .url
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
                    .map(SecretString::new);
            }
        }
    }
    status
}

/// After a daemon restart: a sign-in that was running is never started
/// again. If its home's credential appeared or changed, the sign-in finished
/// just before the restart, so the account is checked once; otherwise the
/// run ends `interrupted`.
pub fn recover_at_startup() {
    let store = store();
    let Ok(Some(active)) = store.active_sign_in() else {
        return;
    };
    let operation_id = active.operation_id.clone();
    let settled = store
        .setup_operation(&operation_id)
        .ok()
        .and_then(|operation| settled_outcome(operation.state));
    let run = Run::new(&operation_id);
    {
        let mut slot = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_some() {
            return;
        }
        *slot = Some(run.clone());
    }
    let mut guard = RunGuard {
        run,
        finished: false,
    };
    if let Some(outcome) = settled {
        // The validation finished before the restart; only its outcome was
        // not recorded.
        let message = if outcome == CodexAccountSignInOutcomeV1::Cancelled {
            CANCELLED_MESSAGE
        } else {
            ""
        };
        guard.finish(outcome, message);
        return;
    }
    if !active.credential_changed() {
        guard.finish(
            CodexAccountSignInOutcomeV1::Interrupted,
            INTERRUPTED_MESSAGE,
        );
        return;
    }
    let spawned = thread::Builder::new()
        .name("ottto-codex-sign-in-recovery".to_string())
        .spawn(move || {
            let mut guard = guard;
            check_account(&mut guard);
        });
    // On a failed spawn the moved guard is dropped and ends the run.
    let _ = spawned;
}

/// The sign-in outcome of a setup whose validation already settled it.
fn settled_outcome(
    state: CodexAccountSetupOperationStateV1,
) -> Option<CodexAccountSignInOutcomeV1> {
    match state {
        CodexAccountSetupOperationStateV1::Complete => Some(CodexAccountSignInOutcomeV1::Complete),
        CodexAccountSetupOperationStateV1::IdentityMismatch => {
            Some(CodexAccountSignInOutcomeV1::IdentityMismatch)
        }
        CodexAccountSetupOperationStateV1::DuplicateAccount => {
            Some(CodexAccountSignInOutcomeV1::DuplicateAccount)
        }
        CodexAccountSetupOperationStateV1::SetupFailed => {
            Some(CodexAccountSignInOutcomeV1::CheckFailed)
        }
        CodexAccountSetupOperationStateV1::SetupStopped => {
            Some(CodexAccountSignInOutcomeV1::Cancelled)
        }
        CodexAccountSetupOperationStateV1::Idle
        | CodexAccountSetupOperationStateV1::WaitingForUserLogin
        | CodexAccountSetupOperationStateV1::Validating => None,
    }
}

/// When a sign-in is stopped: whichever comes first, so a Mac that slept
/// (the monotonic clock pauses) still stops it at the stated time.
#[derive(Debug, Clone, Copy)]
struct Deadline {
    monotonic: Instant,
    wall: OffsetDateTime,
}

impl Deadline {
    fn passed(&self) -> bool {
        Instant::now() >= self.monotonic || OffsetDateTime::now_utc() >= self.wall
    }
}

fn run_sign_in(run: Arc<Run>, home: PathBuf, deadline: Deadline) {
    let mut guard = RunGuard {
        run: run.clone(),
        finished: false,
    };
    match supervise_login(&run, &home, deadline) {
        LoginEnd::SignedIn => check_account(&mut guard),
        LoginEnd::Ended(outcome, message) => guard.finish(outcome, message),
        // The setup was stopped or replaced while the CLI started; it has
        // nothing to record.
        LoginEnd::OperationGone => guard.finished = true,
    }
}

enum LoginEnd {
    /// The home's credential appeared or changed.
    SignedIn,
    Ended(CodexAccountSignInOutcomeV1, &'static str),
    OperationGone,
}

fn supervise_login(run: &Arc<Run>, home: &Path, deadline: Deadline) -> LoginEnd {
    let port = timings().login_port;
    if port_in_use(port) {
        return LoginEnd::Ended(CodexAccountSignInOutcomeV1::PortBusy, PORT_BUSY_MESSAGE);
    }
    let Some(mut command) = crate::agent_status::codex_login_command(home) else {
        return LoginEnd::Ended(
            CodexAccountSignInOutcomeV1::CodexUnavailable,
            CODEX_UNAVAILABLE_MESSAGE,
        );
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let Ok(mut child) = command.spawn() else {
        return LoginEnd::Ended(
            CodexAccountSignInOutcomeV1::CodexUnavailable,
            CODEX_UNAVAILABLE_MESSAGE,
        );
    };
    let reported_success = Arc::new(AtomicBool::new(false));
    if let Some(stderr) = child.stderr.take() {
        let scan_run = Arc::clone(run);
        let reported = reported_success.clone();
        let _ = thread::Builder::new()
            .name("ottto-codex-sign-in-output".to_string())
            .spawn(move || scan_login_output(stderr, &scan_run, &reported));
    }
    if store()
        .set_sign_in_phase(
            &run.operation_id,
            CodexAccountSignInPhaseV1::WaitingForBrowser,
        )
        .is_err()
    {
        stop_login(&mut child, port);
        return LoginEnd::OperationGone;
    }
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => break None,
        }
        if run.cancelled() {
            stop_login(&mut child, port);
            run.set_url(None);
            return LoginEnd::Ended(CodexAccountSignInOutcomeV1::Cancelled, CANCELLED_MESSAGE);
        }
        if deadline.passed() {
            stop_login(&mut child, port);
            run.set_url(None);
            return LoginEnd::Ended(CodexAccountSignInOutcomeV1::TimedOut, TIMED_OUT_MESSAGE);
        }
        thread::sleep(POLL_INTERVAL);
    };
    run.set_url(None);
    if run.cancelled() {
        return LoginEnd::Ended(CodexAccountSignInOutcomeV1::Cancelled, CANCELLED_MESSAGE);
    }
    let credential_changed = store()
        .active_sign_in()
        .ok()
        .flatten()
        .filter(|active| active.operation_id == run.operation_id)
        .is_some_and(|active| active.credential_changed());
    if credential_changed {
        return LoginEnd::SignedIn;
    }
    LoginEnd::Ended(
        CodexAccountSignInOutcomeV1::LoginFailed,
        ended_without_credential_message(exit, reported_success.load(Ordering::SeqCst)),
    )
}

fn ended_without_credential_message(
    exit: Option<ExitStatus>,
    reported_success: bool,
) -> &'static str {
    if reported_success {
        NOT_SAVED_MESSAGE
    } else if exit.is_some_and(|status| status.success()) {
        ENDED_EARLY_MESSAGE
    } else {
        FAILED_MESSAGE
    }
}

/// The account read after a sign-in saved a credential: one read through
/// the setup's validation (which also verifies a pinned workspace in a fresh
/// session), and one retry after [`CHECK_RETRY_DELAY`] when the read fails.
/// A stop request is honored while waiting for the retry.
fn check_account(guard: &mut RunGuard) {
    let run = guard.run.clone();
    let store = store();
    let schema_version = ottto_protocol::CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION;
    let operation_id = run.operation_id.as_str();
    if store
        .set_sign_in_phase(operation_id, CodexAccountSignInPhaseV1::CheckingAccount)
        .is_err()
    {
        guard.finished = true;
        return;
    }
    let ended = (|| {
        store
            .begin_validation(schema_version, operation_id)
            .map_err(|_| ())?;
        let slot_id = crate::control::codex_setup_slot_id(&store, operation_id).map_err(|_| ())?;
        if store
            .is_verifying_pinned_workspace(operation_id)
            .map_err(|_| ())?
        {
            return crate::control::verify_pinned_codex_setup(
                &store,
                schema_version,
                operation_id,
                &slot_id,
            )
            .map(|(_, end)| Some(end))
            .map_err(|_| ());
        }
        let read = || {
            crate::agent_status::collect_registered_codex_slot_for_setup(
                &slot_id,
                crate::agent_status::CodexSetupRead::Validation,
            )
        };
        let mut collection = read();
        if matches!(
            collection,
            Err(crate::agent_status::CodexSlotSetupCollectionError::ProviderLoginPending(_))
        ) {
            if run.wait_for_cancel(timings().check_retry_delay) {
                return Ok(None);
            }
            collection = read();
        }
        crate::control::finish_codex_setup_validation(
            &store,
            schema_version,
            operation_id,
            &slot_id,
            collection,
        )
        .map(|(_, end)| Some(end))
        .map_err(|_| ())
    })();
    match ended {
        Ok(Some(end)) => guard.finish(validation_outcome(end), ""),
        Ok(None) => guard.finish(CodexAccountSignInOutcomeV1::Cancelled, CANCELLED_MESSAGE),
        Err(()) => {
            let _ = store.fail_validation(
                schema_version,
                operation_id,
                "The Codex account could not be checked. Try again.",
            );
            guard.finish(CodexAccountSignInOutcomeV1::CheckFailed, "");
        }
    }
}

fn validation_outcome(end: CodexSetupValidationEnd) -> CodexAccountSignInOutcomeV1 {
    match end {
        CodexSetupValidationEnd::Accepted => CodexAccountSignInOutcomeV1::Complete,
        CodexSetupValidationEnd::IdentityMismatch => CodexAccountSignInOutcomeV1::IdentityMismatch,
        CodexSetupValidationEnd::DuplicateAccount => CodexAccountSignInOutcomeV1::DuplicateAccount,
        CodexSetupValidationEnd::WorkspaceNotKept => CodexAccountSignInOutcomeV1::WorkspaceNotKept,
        CodexSetupValidationEnd::ReadFailed => CodexAccountSignInOutcomeV1::CheckFailed,
    }
}

/// End `codex login`: SIGTERM (the CLI then stops its callback server), then
/// SIGKILL after [`TERMINATE_GRACE`]; then wait a short time for the port to
/// be free.
fn stop_login(child: &mut Child, port: u16) {
    if matches!(child.try_wait(), Ok(None)) {
        #[cfg(unix)]
        if let Ok(pid) = libc::pid_t::try_from(child.id()) {
            // SAFETY: `pid` is our own child, not yet reaped.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
        let deadline = Instant::now() + TERMINATE_GRACE;
        while Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
            thread::sleep(POLL_INTERVAL);
        }
        if matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
        }
    }
    let _ = child.wait();
    let deadline = Instant::now() + PORT_RELEASE_WAIT;
    while Instant::now() < deadline && port_in_use(port) {
        thread::sleep(POLL_INTERVAL);
    }
}

/// Whether something holds the local sign-in port: a server answers on it,
/// or it cannot be bound.
fn port_in_use(port: u16) -> bool {
    let loopbacks = [
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
    ];
    if loopbacks
        .iter()
        .any(|address| TcpStream::connect_timeout(address, Duration::from_millis(300)).is_ok())
    {
        return true;
    }
    matches!(
        TcpListener::bind(loopbacks[0]),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse
    )
}

/// Read the CLI's stderr for the sign-in page address and its success line,
/// within byte bounds, then drain the rest unread so the CLI never blocks on
/// a full pipe. Nothing read here is logged or kept beyond the address.
fn scan_login_output(output: impl Read, run: &Run, reported_success: &AtomicBool) {
    let mut reader = BufReader::new(output);
    let mut scanned = 0_u64;
    let mut after_marker = false;
    let mut captured = false;
    let mut line = Vec::new();
    while scanned < MAX_SCANNED_BYTES {
        line.clear();
        match (&mut reader)
            .take(MAX_SCANNED_LINE_BYTES)
            .read_until(b'\n', &mut line)
        {
            Ok(0) | Err(_) => return,
            Ok(read) => scanned += read as u64,
        }
        let text = String::from_utf8_lossy(&line);
        if text.contains("Successfully logged in") {
            reported_success.store(true, Ordering::SeqCst);
        }
        if text.contains("navigate to this URL") {
            after_marker = true;
        }
        if !captured {
            if let Some(url) = sign_in_url(&text, after_marker) {
                run.set_url(Some(url));
                captured = true;
            }
        }
    }
    let _ = std::io::copy(&mut reader, &mut std::io::sink());
}

/// The sign-in page address on one output line: the first `https://` word
/// after the CLI's "navigate to this URL" line, or an authorize address
/// anywhere.
fn sign_in_url(line: &str, after_marker: bool) -> Option<String> {
    line.split_whitespace()
        .map(|word| word.trim_matches(|c: char| matches!(c, '<' | '>' | '"' | '\'' | '`')))
        .find(|word| {
            word.starts_with("https://")
                && (after_marker || word.contains("/oauth/authorize"))
                && word.len() <= MAX_SIGN_IN_URL_BYTES
                && word.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .map(str::to_string)
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[derive(Debug, Clone, Copy)]
struct Timings {
    sign_in_timeout: Duration,
    check_retry_delay: Duration,
    login_port: u16,
}

const TIMINGS: Timings = Timings {
    sign_in_timeout: SIGN_IN_TIMEOUT,
    check_retry_delay: CHECK_RETRY_DELAY,
    login_port: CODEX_LOGIN_PORT,
};

#[cfg(not(test))]
fn timings() -> Timings {
    TIMINGS
}

#[cfg(test)]
static TEST_TIMINGS: Mutex<Option<Timings>> = Mutex::new(None);

#[cfg(test)]
fn timings() -> Timings {
    TEST_TIMINGS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .unwrap_or(TIMINGS)
}

/// Short timings for tests, restored on drop.
#[cfg(test)]
pub(crate) struct TestTimingsGuard;

#[cfg(test)]
impl TestTimingsGuard {
    pub(crate) fn set(
        sign_in_timeout: Duration,
        check_retry_delay: Duration,
        login_port: u16,
    ) -> Self {
        *TEST_TIMINGS.lock().unwrap_or_else(PoisonError::into_inner) = Some(Timings {
            sign_in_timeout,
            check_retry_delay,
            login_port,
        });
        Self
    }
}

#[cfg(test)]
impl Drop for TestTimingsGuard {
    fn drop(&mut self) {
        *TEST_TIMINGS.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

/// Wait until no sign-in runs in this process.
#[cfg(test)]
pub(crate) fn wait_until_idle(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if ACTIVE
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
        {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sign_in_url_is_the_address_after_the_cli_prompt() {
        assert_eq!(
            sign_in_url(
                "Starting local login server on http://localhost:1455.",
                false
            ),
            None
        );
        assert_eq!(sign_in_url("https://example.test/docs", false), None);
        assert_eq!(
            sign_in_url("  https://auth.example.test/x?state=s  ", true).as_deref(),
            Some("https://auth.example.test/x?state=s")
        );
        assert_eq!(
            sign_in_url("go to https://auth.example.test/oauth/authorize?a=b", false).as_deref(),
            Some("https://auth.example.test/oauth/authorize?a=b")
        );
        let long = format!(
            "https://auth.example.test/{}",
            "a".repeat(MAX_SIGN_IN_URL_BYTES)
        );
        assert_eq!(sign_in_url(&long, true), None);
    }

    #[test]
    fn output_scan_keeps_the_first_address_and_the_success_line() {
        let run = Run::new("codex_setup_0123456789abcdef0123456789abcdef");
        let reported = AtomicBool::new(false);
        let output = "Starting local login server on http://localhost:1455.\n\
            If your browser did not open, navigate to this URL to authenticate:\n\
            \n\
            https://auth.example.test/oauth/authorize?state=first\n\
            https://auth.example.test/oauth/authorize?state=second\n\
            Successfully logged in\n";
        scan_login_output(output.as_bytes(), &run, &reported);
        assert_eq!(
            run.url.lock().expect("url").as_deref(),
            Some("https://auth.example.test/oauth/authorize?state=first")
        );
        assert!(reported.load(Ordering::SeqCst));

        // Output past the scan bound is drained, not scanned.
        let run = Run::new("codex_setup_0123456789abcdef0123456789abcdef");
        let reported = AtomicBool::new(false);
        let mut flood = "x\n".repeat(MAX_SCANNED_BYTES as usize);
        flood.push_str(
            "https://auth.example.test/oauth/authorize?state=late\nSuccessfully logged in\n",
        );
        scan_login_output(flood.as_bytes(), &run, &reported);
        assert_eq!(*run.url.lock().expect("url"), None);
        assert!(!reported.load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    fn a_login_without_a_new_credential_says_why_plainly() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            ended_without_credential_message(Some(ExitStatus::from_raw(0)), false),
            ENDED_EARLY_MESSAGE
        );
        assert_eq!(
            ended_without_credential_message(Some(ExitStatus::from_raw(1 << 8)), false),
            FAILED_MESSAGE
        );
        assert_eq!(
            ended_without_credential_message(Some(ExitStatus::from_raw(0)), true),
            NOT_SAVED_MESSAGE
        );
    }

    #[test]
    fn a_held_port_is_busy() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let port = listener.local_addr().expect("address").port();
        assert!(port_in_use(port));
        drop(listener);
        assert!(!port_in_use(port));
    }
}
