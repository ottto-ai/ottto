//! Quiet window for short Claude Code runs.
//!
//! Claude Code refreshes an OAuth login inside any command that starts within
//! five minutes of the access token's expiry (or after it). A short command
//! that exits, or is killed, before the rotated token is saved leaves the
//! refresh token spent, and Claude Code then signs the login out
//! (anthropics/claude-code#95822).
//!
//! The daemon's own short Claude runs (the `-p /context` footprint read, the
//! Verify smoke, and an MCP inventory probe of a server that is Claude Code
//! itself) therefore never start from 15 minutes before the access
//! token's expiry until the background refresher (`claude_refresher`) has
//! confirmed a new expiry, nor while the token is expired. `claude auth
//! status` and `claude doctor` are not run at all.

use ottto_core::ClaudeConfigDirSlot;
use std::path::Path;
use std::time::{Duration, SystemTime};
use time::{Duration as TimeDuration, OffsetDateTime};

/// No short Claude run starts this close to the access token's expiry: the
/// CLI's 5-minute refresh window, plus 10 minutes for start-up and the run.
pub(crate) const QUIET_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Another Claude Code process holding its refresh lock this recently is
/// refreshing now.
pub(crate) const REFRESH_LOCK_FRESHNESS: Duration = Duration::from_secs(60);
/// Claude Code's advisory refresh lock inside the config directory.
pub(crate) const REFRESH_LOCK_FILE: &str = ".oauth_refresh.lock";

/// Secret-free view of a stored credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeGateCredential {
    /// No stored OAuth login: nothing can be refreshed.
    Absent,
    /// The read failed or the item is malformed: fail closed.
    ReadFailed,
    Present {
        has_refresh_token: bool,
        access_expires_at: Option<OffsetDateTime>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeSpawnRefusal {
    CredentialReadFailed,
    AccessExpiryUnknown,
    QuietWindow,
    RefreshInProgress,
    #[cfg(unix)]
    CleanupPending,
}

impl ClaudeSpawnRefusal {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::CredentialReadFailed => "credential_read_failed",
            Self::AccessExpiryUnknown => "access_expiry_unknown",
            Self::QuietWindow => "quiet_window",
            Self::RefreshInProgress => "refresh_in_progress",
            #[cfg(unix)]
            Self::CleanupPending => "cleanup_pending",
        }
    }

    /// This login must refresh or its admitted probe must settle first;
    /// a later attempt can succeed without user action.
    pub(crate) fn waits_for_claude_refresh(self) -> bool {
        match self {
            Self::QuietWindow | Self::RefreshInProgress => true,
            #[cfg(unix)]
            Self::CleanupPending => true,
            _ => false,
        }
    }
}

/// The rule. Pure: every input is passed in, so it is tested with a fake
/// clock.
pub(crate) fn evaluate_short_run(
    credential: ClaudeGateCredential,
    refresh_lock_modified: Option<SystemTime>,
    now: OffsetDateTime,
) -> Result<(), ClaudeSpawnRefusal> {
    match credential {
        ClaudeGateCredential::ReadFailed => return Err(ClaudeSpawnRefusal::CredentialReadFailed),
        // No refresh token: no refresh is possible, so none can be lost.
        ClaudeGateCredential::Absent
        | ClaudeGateCredential::Present {
            has_refresh_token: false,
            ..
        } => return Ok(()),
        ClaudeGateCredential::Present {
            access_expires_at: None,
            ..
        } => return Err(ClaudeSpawnRefusal::AccessExpiryUnknown),
        ClaudeGateCredential::Present {
            access_expires_at: Some(expires_at),
            ..
        } => {
            if expires_at - now < TimeDuration::try_from(QUIET_WINDOW).expect("window") {
                return Err(ClaudeSpawnRefusal::QuietWindow);
            }
        }
    }
    if let Some(modified) = refresh_lock_modified {
        // A lock stamped in the future (clock jump) counts as fresh.
        if now - OffsetDateTime::from(modified)
            < TimeDuration::try_from(REFRESH_LOCK_FRESHNESS).expect("freshness")
        {
            return Err(ClaudeSpawnRefusal::RefreshInProgress);
        }
    }
    Ok(())
}

/// The single gate every short Claude run asks immediately before it starts:
/// a fresh read of that login's stored credential (keychain, then the
/// credentials file) and of Claude Code's refresh lock.
pub(crate) fn check_short_claude_run(slot: &ClaudeConfigDirSlot) -> Result<(), ClaudeSpawnRefusal> {
    let credential = gate_credential(slot);
    let lock_modified = refresh_lock_dir(slot)
        .as_deref()
        .and_then(refresh_lock_modified);
    let decision = evaluate_short_run(credential, lock_modified, OffsetDateTime::now_utc());
    if let Err(refusal) = decision {
        eprintln!(
            "claude_short_run decision=refused reason={} target={}",
            refusal.code(),
            if slot.config_dir().is_some() {
                "slot"
            } else {
                "default"
            }
        );
    }
    decision
}

/// Claude Code's own refresh window: it refreshes when the access token
/// expires within 5 minutes.
pub(crate) const CLI_REFRESH_WINDOW: Duration = Duration::from_secs(5 * 60);
/// How often a Claude process left running near a refresh is re-checked.
const LEFT_RUNNING_POLL: Duration = Duration::from_millis(500);

/// Whether killing a Claude Code process of this login could cut a token
/// refresh short: the access token is within the CLI's 5-minute window or
/// expired (or its expiry is unknown, or the read failed), or the CLI's
/// refresh lock exists at any age. Pure.
pub(crate) fn kill_could_cut_a_refresh(
    credential: ClaudeGateCredential,
    refresh_lock_exists: bool,
    now: OffsetDateTime,
) -> bool {
    if refresh_lock_exists {
        return true;
    }
    match credential {
        ClaudeGateCredential::Absent
        | ClaudeGateCredential::Present {
            has_refresh_token: false,
            ..
        } => false,
        ClaudeGateCredential::ReadFailed
        | ClaudeGateCredential::Present {
            access_expires_at: None,
            ..
        } => true,
        ClaudeGateCredential::Present {
            access_expires_at: Some(expires_at),
            ..
        } => expires_at - now <= TimeDuration::try_from(CLI_REFRESH_WINDOW).expect("window"),
    }
}

fn kill_could_cut_a_refresh_now(slot: &ClaudeConfigDirSlot) -> bool {
    kill_could_cut_a_refresh(
        gate_credential(slot),
        refresh_lock_dir(slot).is_some_and(|dir| dir.join(REFRESH_LOCK_FILE).exists()),
        OffsetDateTime::now_utc(),
    )
}

fn gate_credential(slot: &ClaudeConfigDirSlot) -> ClaudeGateCredential {
    #[cfg(test)]
    if let Some(policy) = test_support::probe_policy(slot) {
        return *policy.credential.lock().unwrap();
    }
    crate::agent_status::read_claude_spawn_gate_credential(slot)
}

/// The one way a timed-out Claude Code process of `slot` is stopped. It is
/// killed only when that cannot cut a token refresh short; otherwise it is
/// left to finish (its output drained) and killed only once the login is out
/// of the refresh window and the lock is gone. Returns whether it was left
/// running.
pub(crate) fn stop_claude_child(
    mut child: std::process::Child,
    slot: &ClaudeConfigDirSlot,
    label: &'static str,
) -> bool {
    if !kill_could_cut_a_refresh_now(slot) {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    eprintln!("claude_short_run decision=left_running reason=refresh_window label={label}");
    for pipe in [
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let mut pipe = pipe;
        let _ = std::thread::Builder::new()
            .name("ottto-claude-left-running-drain".to_string())
            .spawn(move || {
                let _ = std::io::copy(&mut pipe, &mut std::io::sink());
            });
    }
    let slot = slot.clone();
    let _ = std::thread::Builder::new()
        .name("ottto-claude-left-running".to_string())
        .spawn(move || loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            if !kill_could_cut_a_refresh_now(&slot) {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            std::thread::sleep(LEFT_RUNNING_POLL);
        });
    true
}

/// Pin a short Claude run to the login the gate evaluated: `CLAUDE_CONFIG_DIR`
/// set to that login's config dir (unset for the default login), and no
/// `CLAUDE_SECURESTORAGE_CONFIG_DIR`, which would select another keychain
/// item.
pub(crate) fn pin_claude_login(command: &mut std::process::Command, slot: &ClaudeConfigDirSlot) {
    match slot.config_dir() {
        Some(config_dir) => command.env("CLAUDE_CONFIG_DIR", config_dir),
        None => command.env_remove("CLAUDE_CONFIG_DIR"),
    };
    command.env_remove("CLAUDE_SECURESTORAGE_CONFIG_DIR");
}

/// The directory holding this login's refresh lock (its config dir;
/// `~/.claude` for the default login).
pub(crate) fn refresh_lock_dir(slot: &ClaudeConfigDirSlot) -> Option<std::path::PathBuf> {
    #[cfg(test)]
    if let Some(policy) = test_support::probe_policy(slot) {
        return Some(policy.lock_dir.clone());
    }
    slot.credentials_path(&crate::agent_status::home_dir())
        .parent()
        .map(Path::to_path_buf)
}

/// Modification time of Claude Code's refresh lock. Read-only: the lock
/// belongs to Claude Code and is never created or removed here.
pub(crate) fn refresh_lock_modified(config_dir: &Path) -> Option<SystemTime> {
    std::fs::metadata(config_dir.join(REFRESH_LOCK_FILE))
        .and_then(|metadata| metadata.modified())
        .ok()
}

/// A fresh, empty, owner-only working directory for a Claude run that must not
/// pick up any project settings. Removed on drop.
pub(crate) struct EmptyWorkingDir {
    path: std::path::PathBuf,
}

impl EmptyWorkingDir {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EmptyWorkingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn empty_working_dir() -> std::io::Result<EmptyWorkingDir> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "ottto-claude-empty-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    std::fs::create_dir(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(EmptyWorkingDir { path })
}

/// Ownership for the Unix MCP/context probes only. Verify retains its existing
/// stop API above. No response-size policy or process-group kill is introduced.
#[cfg(unix)]
pub(crate) mod probe {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Origin {
        McpInventory,
        Context,
    }

    static ADMITTED: OnceLock<Mutex<BTreeMap<String, Origin>>> = OnceLock::new();

    fn admitted() -> &'static Mutex<BTreeMap<String, Origin>> {
        ADMITTED.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    pub(crate) fn login_key(slot: &ClaudeConfigDirSlot) -> String {
        // Coordinate the exact credential selected by the child, without
        // changing its raw config-dir string or credential lookup paths.
        #[cfg(target_os = "macos")]
        return slot.service_name();
        #[cfg(not(target_os = "macos"))]
        slot.credentials_path(&crate::agent_status::home_dir())
            .to_string_lossy()
            .into_owned()
    }

    struct Permit(String);

    impl Drop for Permit {
        fn drop(&mut self) {
            admitted()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.0);
        }
    }

    pub(crate) enum StartError {
        Refused(ClaudeSpawnRefusal),
        Io(io::Error),
    }

    impl From<io::Error> for StartError {
        fn from(error: io::Error) -> Self {
            Self::Io(error)
        }
    }

    struct Packet {
        child: Child,
        stdin: Option<File>,
        stdout: Option<File>,
    }

    enum Event {
        Protected,
        Done,
    }

    struct Reservation {
        sender: Option<mpsc::SyncSender<Packet>>,
        events: mpsc::Receiver<Event>,
        worker: Option<JoinHandle<()>>,
        login: ClaudeConfigDirSlot,
        _permit: Arc<Permit>,
    }

    impl Reservation {
        fn start(slot: &ClaudeConfigDirSlot, origin: Origin) -> Result<Self, StartError> {
            let key = login_key(slot);
            {
                let mut active = admitted()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let capacity = match origin {
                    Origin::McpInventory => crate::mcp_inventory::MCP_HARVEST_MAX_CONCURRENCY,
                    Origin::Context => 1, // Existing serial context capture.
                };
                if active.contains_key(&key)
                    || active.values().filter(|value| **value == origin).count() >= capacity
                {
                    return Err(StartError::Refused(ClaudeSpawnRefusal::CleanupPending));
                }
                active.insert(key.clone(), origin);
            }
            let permit = Arc::new(Permit(key));
            let (sender, receiver) = mpsc::sync_channel::<Packet>(1);
            let (events_tx, events) = mpsc::sync_channel(2);
            let login = slot.clone();
            #[cfg(test)]
            if test_support::take_probe_fault(test_support::ProbeFault::WorkerStart) {
                return Err(io::Error::other("injected cleanup-worker failure").into());
            }
            // Start before command.spawn: no fallible post-launch thread start
            // may drop the pipes of a protected Claude child.
            let worker_permit = Arc::clone(&permit);
            let worker = thread::Builder::new()
                .name("ottto-claude-left-running".to_string())
                .spawn(move || {
                    if let Ok(packet) = receiver.recv() {
                        drain_and_stop(packet, &login, &events_tx);
                    }
                    drop(worker_permit); // Release only after pipe/reap settlement.
                    let _ = events_tx.send(Event::Done);
                })?;
            Ok(Self {
                sender: Some(sender),
                events,
                worker: Some(worker),
                login: slot.clone(),
                _permit: permit,
            })
        }

        fn transfer(&mut self, packet: Packet, deadline: Instant) {
            if let Some(sender) = self.sender.take() {
                if let Err(error) = sender.send(packet) {
                    // The waiter unexpectedly ended. Preserve ownership and
                    // refresh safety even if this exceptional fallback cannot
                    // preserve the caller's deadline; never launch another owner.
                    let (tx, _rx) = mpsc::sync_channel(2);
                    drain_and_stop(error.0, &self.login, &tx);
                }
            }
            if matches!(
                self.events
                    .recv_timeout(deadline.saturating_duration_since(Instant::now())),
                Ok(Event::Done)
            ) {
                if let Some(worker) = self.worker.take() {
                    let _ = worker.join();
                }
            } else {
                // Registered deferred owner retains its permit and packet.
                self.worker.take();
            }
        }
    }

    impl Drop for Reservation {
        fn drop(&mut self) {
            self.sender.take(); // Cancel an unused pre-launch waiter.
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn drain_and_stop(
        mut packet: Packet,
        login: &ClaudeConfigDirSlot,
        events: &mpsc::SyncSender<Event>,
    ) {
        let mut buffer = [0_u8; 8192];
        let mut exited = false;
        let mut status_uncertain = false;
        let mut next_check = Instant::now();
        let mut notified = false;
        loop {
            if !exited {
                match packet.child.try_wait() {
                    Ok(Some(_)) => exited = true,
                    Ok(None) => status_uncertain = false,
                    Err(error) if error.raw_os_error() == Some(libc::ECHILD) => exited = true,
                    Err(_) => status_uncertain = true,
                }
            }
            let mut progressed = false;
            if let Some(stdout) = packet.stdout.as_mut() {
                match stdout.read(&mut buffer) {
                    Ok(0) => packet.stdout = None,
                    Ok(_) => progressed = true,
                    Err(_) => {} // Keep the FD until safe settlement.
                }
            }
            if exited && packet.stdout.is_none() {
                return; // Natural completion: no writer is left to interrupt.
            }
            if Instant::now() >= next_check {
                next_check = Instant::now() + LEFT_RUNNING_POLL;
                if !kill_could_cut_a_refresh_now(login) {
                    if exited {
                        return; // A retained descendant cannot block FD closure.
                    }
                    if !status_uncertain {
                        let _ = packet.child.kill();
                        match packet.child.wait() {
                            Ok(_) => return,
                            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
                            Err(_) => {} // Keep owning the child after wait failure.
                        }
                    }
                } else if !notified {
                    let _ = events.send(Event::Protected);
                    notified = true;
                }
            }
            if !progressed {
                let wait = next_check.saturating_duration_since(Instant::now());
                if let Some(stdout) = packet.stdout.as_ref() {
                    if poll_pipe(stdout, libc::POLLIN, wait).is_err() {
                        thread::sleep(wait.min(Duration::from_millis(50)));
                    }
                } else {
                    thread::sleep(wait.min(Duration::from_millis(50)));
                }
            }
        }
    }

    fn parent_pipe(parent_reads: bool) -> io::Result<(File, File)> {
        let mut fds = [-1; 2];
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let created = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let created = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if created < 0 {
            return Err(io::Error::last_os_error());
        }
        let read = unsafe { File::from_raw_fd(fds[0]) };
        let write = unsafe { File::from_raw_fd(fds[1]) };
        for fd in fds {
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let fd = if parent_reads { fds[0] } else { fds[1] };
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(if parent_reads {
            (read, write)
        } else {
            (write, read)
        })
    }

    /// Child and pipe ownership never leaves this guard during active I/O.
    pub(crate) struct ChildProbe {
        packet: Option<Packet>,
        reservation: Option<Reservation>,
    }

    impl ChildProbe {
        pub(crate) fn spawn(
            mut command: Command,
            login: Option<&ClaudeConfigDirSlot>,
            origin: Origin,
            deadline: Instant,
        ) -> Result<Self, StartError> {
            check_deadline(deadline)?;
            #[cfg(test)]
            if test_support::take_probe_fault(test_support::ProbeFault::Prepare) {
                return Err(io::Error::other("injected pipe preparation failure").into());
            }
            let (stdout, output) = parent_pipe(true)?;
            command.stdout(Stdio::from(output)).stderr(Stdio::null());
            let stdin = if origin == Origin::McpInventory {
                let (stdin, input) = parent_pipe(false)?;
                command.stdin(Stdio::from(input));
                Some(stdin)
            } else {
                None
            };
            let reservation = login
                .map(|slot| Reservation::start(slot, origin))
                .transpose()?;
            if let Some(slot) = login {
                check_short_claude_run(slot).map_err(StartError::Refused)?;
                pin_claude_login(&mut command, slot);
            }
            check_deadline(deadline)?;
            let child = command.spawn()?;
            drop(command); // Close parent copies of child ends before drain/EOF.
            #[cfg(test)]
            let mut stdin = stdin;
            #[cfg(test)]
            if test_support::take_probe_fault(test_support::ProbeFault::FillStdin) {
                if let Some(stdin) = stdin.as_mut() {
                    while stdin.write(&[b'x'; 8192]).is_ok() {}
                    while stdin.write(b"x").is_ok() {}
                }
            }
            Ok(Self {
                packet: Some(Packet {
                    child,
                    stdin,
                    stdout: Some(stdout),
                }),
                reservation,
            })
        }

        pub(crate) fn stdin_stdout(&mut self) -> (&mut File, &mut File) {
            let packet = self.packet.as_mut().expect("owned probe");
            (
                packet.stdin.as_mut().expect("MCP input"),
                packet.stdout.as_mut().expect("probe output"),
            )
        }

        pub(crate) fn stdout(&mut self) -> &mut File {
            self.packet
                .as_mut()
                .expect("owned probe")
                .stdout
                .as_mut()
                .expect("probe output")
        }

        pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            #[cfg(test)]
            if test_support::take_probe_fault(test_support::ProbeFault::Status) {
                return Err(io::Error::other("injected status failure"));
            }
            self.packet.as_mut().expect("owned probe").child.try_wait()
        }

        pub(crate) fn finish(mut self, deadline: Instant) {
            self.settle(deadline);
        }

        fn settle(&mut self, deadline: Instant) {
            if let Some(mut packet) = self.packet.take() {
                if let Some(reservation) = self.reservation.as_mut() {
                    reservation.transfer(packet, deadline);
                } else {
                    let _ = packet.child.kill();
                    let _ = packet.child.wait();
                }
            }
        }
    }

    impl Drop for ChildProbe {
        fn drop(&mut self) {
            self.settle(Instant::now());
        }
    }

    pub(crate) fn check_deadline(deadline: Instant) -> io::Result<()> {
        if Instant::now() >= deadline {
            Err(io::Error::new(io::ErrorKind::TimedOut, "probe timed out"))
        } else {
            Ok(())
        }
    }

    fn poll_pipe(pipe: &File, events: libc::c_short, remaining: Duration) -> io::Result<()> {
        let mut ready = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events,
            revents: 0,
        };
        let timeout = remaining.as_millis().min(50) as libc::c_int;
        if unsafe { libc::poll(&mut ready, 1, timeout) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) struct Reader<'a>(pub(crate) &'a mut File, pub(crate) Instant);

    impl Read for Reader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            loop {
                check_deadline(self.1)?;
                #[cfg(test)]
                if test_support::take_probe_fault(test_support::ProbeFault::Read) {
                    return Err(io::Error::other("injected read failure"));
                }
                match self.0.read(buffer) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if let Err(error) = poll_pipe(
                            self.0,
                            libc::POLLIN,
                            self.1.saturating_duration_since(Instant::now()),
                        ) {
                            if error.kind() != io::ErrorKind::Interrupted {
                                return Err(error);
                            }
                        }
                    }
                    result => return result,
                }
            }
        }
    }

    pub(crate) struct Writer<'a>(pub(crate) &'a mut File, pub(crate) Instant);

    impl Write for Writer<'_> {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            loop {
                check_deadline(self.1)?;
                #[cfg(test)]
                if test_support::take_probe_fault(test_support::ProbeFault::Write) {
                    return Err(io::Error::other("injected write failure"));
                }
                match self.0.write(buffer) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        #[cfg(test)]
                        test_support::record_probe_write_wait();
                        if let Err(error) = poll_pipe(
                            self.0,
                            libc::POLLOUT,
                            self.1.saturating_duration_since(Instant::now()),
                        ) {
                            if error.kind() != io::ErrorKind::Interrupted {
                                return Err(error);
                            }
                        }
                    }
                    result => return result,
                }
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            check_deadline(self.1)
        }
    }

    #[cfg(test)]
    pub(crate) fn active_count() -> usize {
        admitted().lock().unwrap().len()
    }

    #[cfg(test)]
    pub(crate) fn is_active(slot: &ClaudeConfigDirSlot) -> bool {
        admitted().lock().unwrap().contains_key(&login_key(slot))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[serial_test::serial]
        fn probe_reservations_keep_existing_lane_capacity_across_cycles() {
            assert_eq!(active_count(), 0);
            let mut owners = Vec::new();
            for index in 0..crate::mcp_inventory::MCP_HARVEST_MAX_CONCURRENCY {
                let slot = ClaudeConfigDirSlot::registered(format!("/tmp/ottto-probe-mcp-{index}"))
                    .unwrap();
                owners.push(
                    Reservation::start(&slot, Origin::McpInventory)
                        .ok()
                        .unwrap(),
                );
            }
            let context = ClaudeConfigDirSlot::Default;
            owners.push(Reservation::start(&context, Origin::Context).ok().unwrap());
            for index in 0..20 {
                let next =
                    ClaudeConfigDirSlot::registered(format!("/tmp/ottto-probe-next-{index}"))
                        .unwrap();
                for origin in [Origin::McpInventory, Origin::Context] {
                    assert!(matches!(
                        Reservation::start(&next, origin),
                        Err(StartError::Refused(ClaudeSpawnRefusal::CleanupPending))
                    ));
                }
                assert_eq!(active_count(), 5);
            }
            drop(owners); // All unused waiters are joined before slot reuse.
            assert_eq!(active_count(), 0);
            drop(Reservation::start(&context, Origin::Context).ok().unwrap());
            assert_eq!(active_count(), 0);
        }

        #[cfg(target_os = "macos")]
        #[test]
        #[serial_test::serial]
        fn probe_admission_uses_keychain_nfc_identity_without_rewriting_slot() {
            let composed = ClaudeConfigDirSlot::registered("/tmp/ottto-probe-é").unwrap();
            let decomposed = ClaudeConfigDirSlot::registered("/tmp/ottto-probe-e\u{301}").unwrap();
            assert_ne!(composed.config_dir(), decomposed.config_dir());
            let owner = Reservation::start(&composed, Origin::McpInventory)
                .ok()
                .unwrap();
            assert!(matches!(
                Reservation::start(&decomposed, Origin::Context),
                Err(StartError::Refused(ClaudeSpawnRefusal::CleanupPending))
            ));
            assert_eq!(composed.config_dir(), Some("/tmp/ottto-probe-é"));
            assert_eq!(decomposed.config_dir(), Some("/tmp/ottto-probe-e\u{301}"));
            drop(owner);
            assert_eq!(active_count(), 0);
        }
    }
}

/// Shared fixture for spawn-site tests in other modules: throwaway HOME and
/// support dirs, a fake `claude` that logs every spawn as
/// `<CLAUDE_CONFIG_DIR>|<args>`, and a fake `security` that serves only the
/// default login item this fixture writes. Never the real CLI or keychain.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{ClaudeConfigDirSlot, ClaudeGateCredential};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use time::{Duration as TimeDuration, OffsetDateTime};

    pub(crate) struct ProbePolicy {
        pub(crate) credential: Mutex<ClaudeGateCredential>,
        pub(crate) lock_dir: PathBuf,
    }

    static PROBE_POLICIES: OnceLock<Mutex<BTreeMap<String, Arc<ProbePolicy>>>> = OnceLock::new();
    static PROBE_FAULT: AtomicU8 = AtomicU8::new(0);
    static PROBE_WRITE_WAITS: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Copy)]
    #[repr(u8)]
    pub(crate) enum ProbeFault {
        WorkerStart = 1,
        Prepare,
        Read,
        Write,
        Status,
        FillStdin,
    }

    pub(crate) fn set_probe_fault(fault: ProbeFault) {
        PROBE_WRITE_WAITS.store(0, Ordering::SeqCst);
        PROBE_FAULT.store(fault as u8, Ordering::SeqCst);
    }

    pub(crate) fn record_probe_write_wait() {
        PROBE_WRITE_WAITS.fetch_add(1, Ordering::SeqCst);
    }
    pub(crate) fn probe_write_waits() -> usize {
        PROBE_WRITE_WAITS.load(Ordering::SeqCst)
    }

    pub(crate) fn take_probe_fault(fault: ProbeFault) -> bool {
        let taken = PROBE_FAULT
            .compare_exchange(fault as u8, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if taken
            && matches!(
                fault,
                ProbeFault::Read | ProbeFault::Write | ProbeFault::Status
            )
        {
            // Inject an error after admission while retaining a synthetic
            // protected credential; no real keychain may resolve the test.
            for policy in PROBE_POLICIES
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .unwrap()
                .values()
            {
                *policy.credential.lock().unwrap() = ClaudeGateCredential::ReadFailed;
            }
        }
        taken
    }

    pub(crate) fn probe_policy(slot: &ClaudeConfigDirSlot) -> Option<Arc<ProbePolicy>> {
        PROBE_POLICIES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap()
            .get(&slot.service_name())
            .cloned()
    }

    pub(crate) struct ProbePolicyGuard {
        key: String,
        slot: ClaudeConfigDirSlot,
        pub(crate) policy: Arc<ProbePolicy>,
    }

    impl ProbePolicyGuard {
        pub(crate) fn new(slot: &ClaudeConfigDirSlot, lock_dir: &Path) -> Self {
            let key = slot.service_name();
            let policy = Arc::new(ProbePolicy {
                credential: Mutex::new(ClaudeGateCredential::Present {
                    has_refresh_token: true,
                    access_expires_at: Some(OffsetDateTime::now_utc() + TimeDuration::hours(2)),
                }),
                lock_dir: lock_dir.to_path_buf(),
            });
            let old = PROBE_POLICIES
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .unwrap()
                .insert(key.clone(), Arc::clone(&policy));
            assert!(old.is_none(), "synthetic policy already installed");
            Self {
                key,
                slot: slot.clone(),
                policy,
            }
        }
    }

    impl Drop for ProbePolicyGuard {
        fn drop(&mut self) {
            // A failing oracle must not let a deferred test worker fall through
            // to a real credential reader after its fake policy is removed.
            *self
                .policy
                .credential
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = ClaudeGateCredential::Absent;
            let _ = std::fs::remove_file(self.policy.lock_dir.join(super::REFRESH_LOCK_FILE));
            #[cfg(unix)]
            {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while super::probe::is_active(&self.slot) && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                if super::probe::is_active(&self.slot) {
                    return; // Retain the synthetic override, never read a live login.
                }
            }
            PROBE_POLICIES
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .remove(&self.key);
            PROBE_FAULT.store(0, Ordering::SeqCst);
        }
    }

    struct Guard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn guard(key: &'static str, value: &Path) -> Guard {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Guard { key, previous }
    }

    pub(crate) struct FakeClaudeEnv {
        pub(crate) root: PathBuf,
        spawn_log: PathBuf,
        item: PathBuf,
        _guards: Vec<Guard>,
    }

    impl FakeClaudeEnv {
        pub(crate) fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "ottto-fake-claude-{label}-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            let bin = root.join("bin");
            let home = root.join("home");
            let support = root.join("support");
            for dir in [&bin, &home, &support] {
                std::fs::create_dir_all(dir).expect("fixture dir");
            }
            let spawn_log = root.join("claude-spawns.log");
            let item = root.join("default-item.json");
            let claude = bin.join("claude");
            std::fs::write(
                &claude,
                format!(
                    "#!/bin/sh\necho \"$CLAUDE_CONFIG_DIR|$*\" >> '{}'\necho '{{}}'\nexit 0\n",
                    spawn_log.display()
                ),
            )
            .expect("fake claude");
            let security = bin.join("security");
            std::fs::write(
                &security,
                format!(
                    "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = 'Claude Code-credentials' ] && [ -f '{item}' ]; then /bin/cat '{item}'; exit 0; fi\ndone\nexit 44\n",
                    item = item.display()
                ),
            )
            .expect("fake security");
            for executable in [&claude, &security] {
                let mut permissions = std::fs::metadata(executable).expect("meta").permissions();
                permissions.set_mode(0o755);
                std::fs::set_permissions(executable, permissions).expect("chmod");
            }
            let guards = vec![
                guard("HOME", &home),
                guard("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home),
                guard("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
                guard("OTTTO_COMMAND_SEARCH_PATH", &bin),
            ];
            Self {
                root,
                spawn_log,
                item,
                _guards: guards,
            }
        }

        /// The default login as Claude Code stores it, expiring `expires_in`
        /// from now.
        pub(crate) fn default_login_expires_in(&self, expires_in: TimeDuration) {
            let now = OffsetDateTime::now_utc();
            let item = serde_json::json!({
                "claudeAiOauth": {
                    "accessToken": "fixture-access",
                    "refreshToken": "fixture-refresh",
                    "expiresAt": (now + expires_in).unix_timestamp() * 1_000,
                    "refreshTokenExpiresAt": (now + TimeDuration::days(25)).unix_timestamp() * 1_000,
                    "scopes": ["user:inference"],
                    "subscriptionType": "max"
                }
            });
            std::fs::write(&self.item, item.to_string()).expect("write item");
        }

        /// Every logged spawn except `--version` probes, which a detached
        /// status refresh from another test may run under this fixture's
        /// search path (they never touch a login).
        pub(crate) fn spawns(&self) -> Vec<String> {
            std::fs::read_to_string(&self.spawn_log)
                .unwrap_or_default()
                .lines()
                .filter(|line| *line != "|--version")
                .map(str::to_string)
                .collect()
        }
    }

    impl Drop for FakeClaudeEnv {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    pub(crate) struct ProbeFixture {
        // Drop the synthetic policy after worker settlement, before HOME/bin.
        pub(crate) policy: ProbePolicyGuard,
        pub(crate) fake: FakeClaudeEnv,
        pub(crate) script: PathBuf,
    }

    #[cfg(unix)]
    impl ProbeFixture {
        pub(crate) fn new(label: &str, mode: &str, output: &[u8], exit: u8) -> Self {
            let fake = FakeClaudeEnv::new(label);
            let root = &fake.root;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(root.join("output"), output).unwrap();
            let policy = ProbePolicyGuard::new(&ClaudeConfigDirSlot::Default, root);
            let quote =
                |path: &Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
            let initialize_pause = if mode == "mcp-delayed" {
                "/bin/sleep 0.1;"
            } else {
                ""
            };
            let body = match mode {
                "output" => format!("/bin/cat {}\nexit {exit}\n", quote(&root.join("output"))),
                "mcp" | "mcp-delayed" => format!(
                    "while IFS= read -r line; do\nprintf '%s\\n' \"$line\" >> {}\ncase \"$line\" in\n*'\"method\":\"initialize\"'*) {initialize_pause} /bin/cat {} ;;\n*'\"method\":\"tools/list\"'*) /bin/cat {}; exit {exit} ;;\nesac\ndone\n",
                    quote(&root.join("requests")), quote(&root.join("initialize")), quote(&root.join("output")),
                ),
                "hold-exit" => format!("/bin/sleep 4 &\necho $! > {}\nexit 0\n", quote(&root.join("descendant"))),
                "protected" => format!(": > {}\nexec /bin/sleep 4\n", quote(&root.join(super::REFRESH_LOCK_FILE))),
                "escaped" => format!(
                    ": > {}\nexport OTTTO_PROBE_FIXTURE_DIR={}\n{} --ignored --exact claude_spawn_gate::tests::probe_escape_fixture --nocapture --test-threads=1 &\nwhile [ ! -s {} ]; do /bin/sleep 0.01; done\nexit 0\n",
                    quote(&root.join(super::REFRESH_LOCK_FILE)), quote(root), quote(&std::env::current_exe().unwrap()), quote(&root.join("descendant")),
                ),
                _ => "exec /bin/sleep 4\n".to_string(),
            };
            let script = root.join("bin/claude");
            std::fs::write(&script, format!(
                "#!/bin/sh\nif [ \"$1\" = '--version' ]; then echo 'fixture'; exit 0; fi\necho $$ > {}\nprintf '%s\\n' \"$CLAUDE_CONFIG_DIR\" \"$@\" > {}\n{body}",
                quote(&root.join("direct")), quote(&root.join("arguments")),
            )).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                policy,
                fake,
                script,
            }
        }

        pub(crate) fn pid(&self, label: &str) -> i32 {
            std::fs::read_to_string(self.fake.root.join(label))
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        }

        pub(crate) fn alive(pid: i32) -> bool {
            unsafe { libc::kill(pid, 0) == 0 }
        }

        #[track_caller]
        pub(crate) fn wait_started(&self) {
            self.wait_until(|| {
                std::fs::read_to_string(self.fake.root.join("direct"))
                    .ok()
                    .and_then(|pid| pid.trim().parse::<i32>().ok())
                    .is_some()
            });
        }

        #[track_caller]
        pub(crate) fn wait_until(&self, mut predicate: impl FnMut() -> bool) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !predicate() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "fake probe did not settle"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        pub(crate) fn release(&self) {
            *self.policy.policy.credential.lock().unwrap() = ClaudeGateCredential::Absent;
            let _ = std::fs::remove_file(self.fake.root.join(super::REFRESH_LOCK_FILE));
        }

        #[track_caller]
        pub(crate) fn wait_settled(&self) {
            self.wait_until(|| !super::probe::is_active(&ClaudeConfigDirSlot::Default));
            if self.fake.root.join("direct").exists() {
                self.wait_until(|| !Self::alive(self.pid("direct")));
            }
        }

        pub(crate) fn command(&self) -> std::process::Command {
            let mut command = std::process::Command::new(&self.script);
            command.env_clear();
            command
        }
    }

    #[cfg(unix)]
    impl Drop for ProbeFixture {
        fn drop(&mut self) {
            self.release();
            let _ = std::fs::write(self.fake.root.join("release"), []);
            for label in ["direct", "descendant"] {
                if let Some(pid) = std::fs::read_to_string(self.fake.root.join(label))
                    .ok()
                    .and_then(|pid| pid.trim().parse::<i32>().ok())
                {
                    let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
                    while Self::alive(pid) && std::time::Instant::now() < end {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn probe_resources() -> (usize, i32) {
        let fds = (0..4096)
            .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
            .count();
        let mut task = unsafe { std::mem::zeroed::<libc::proc_taskinfo>() };
        let size = std::mem::size_of_val(&task) as libc::c_int;
        assert_eq!(
            unsafe {
                libc::proc_pidinfo(
                    libc::getpid(),
                    libc::PROC_PIDTASKINFO,
                    0,
                    &mut task as *mut _ as *mut libc::c_void,
                    size,
                )
            },
            size
        );
        (fds, task.pti_threadnum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[cfg(unix)]
    #[test]
    #[ignore = "finite escaped fake invoked only by probe lifecycle tests"]
    fn probe_escape_fixture() {
        let Some(root) = std::env::var_os("OTTTO_PROBE_FIXTURE_DIR").map(PathBuf::from) else {
            return;
        };
        assert!(unsafe { libc::setsid() } >= 0);
        std::fs::write(root.join("descendant"), std::process::id().to_string()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        while std::time::Instant::now() < deadline && !root.join("release").exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::process::exit(0);
    }

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_900_000_000 + seconds).expect("timestamp")
    }

    fn present(expires_in: TimeDuration) -> ClaudeGateCredential {
        ClaudeGateCredential::Present {
            has_refresh_token: true,
            access_expires_at: Some(at(0) + expires_in),
        }
    }

    #[test]
    fn a_kill_never_lands_near_a_refresh() {
        let now = at(0);
        // Inside the CLI's 5-minute window, expired, unknown or unreadable:
        // never killed. Outside it with no lock: killed.
        for (credential, lock, expected) in [
            (present(TimeDuration::minutes(5)), false, true),
            (present(-TimeDuration::hours(2)), false, true),
            (
                ClaudeGateCredential::Present {
                    has_refresh_token: true,
                    access_expires_at: None,
                },
                false,
                true,
            ),
            (ClaudeGateCredential::ReadFailed, false, true),
            (present(TimeDuration::hours(3)), true, true),
            (ClaudeGateCredential::Absent, true, true),
            (present(TimeDuration::minutes(6)), false, false),
            (ClaudeGateCredential::Absent, false, false),
            (
                ClaudeGateCredential::Present {
                    has_refresh_token: false,
                    access_expires_at: None,
                },
                false,
                false,
            ),
        ] {
            assert_eq!(
                kill_could_cut_a_refresh(credential, lock, now),
                expected,
                "{credential:?} lock={lock}"
            );
        }
    }

    #[test]
    fn short_runs_are_pinned_to_the_evaluated_login() {
        let run = |slot: &ClaudeConfigDirSlot| {
            let mut command = std::process::Command::new("/usr/bin/env");
            command
                .env("CLAUDE_CONFIG_DIR", "/tmp/ottto-ambient-slot")
                .env(
                    "CLAUDE_SECURESTORAGE_CONFIG_DIR",
                    "/tmp/ottto-ambient-store",
                );
            pin_claude_login(&mut command, slot);
            String::from_utf8(command.output().expect("env").stdout).expect("utf8")
        };
        let default = run(&ClaudeConfigDirSlot::Default);
        assert!(!default.contains("CLAUDE_CONFIG_DIR="), "{default}");
        assert!(!default.contains("CLAUDE_SECURESTORAGE_CONFIG_DIR="));
        let slot = ClaudeConfigDirSlot::registered("/tmp/ottto-evaluated-slot").expect("slot");
        let registered = run(&slot);
        assert!(registered
            .lines()
            .any(|line| line == "CLAUDE_CONFIG_DIR=/tmp/ottto-evaluated-slot"));
        assert!(!registered.contains("CLAUDE_SECURESTORAGE_CONFIG_DIR="));
    }

    #[test]
    fn short_runs_wait_from_15_minutes_before_expiry_until_a_new_expiry() {
        for offset in [
            TimeDuration::minutes(15) - TimeDuration::seconds(1),
            TimeDuration::minutes(5),
            TimeDuration::seconds(1),
            -TimeDuration::seconds(1),
            -TimeDuration::hours(8),
        ] {
            assert_eq!(
                evaluate_short_run(present(offset), None, at(0)),
                Err(ClaudeSpawnRefusal::QuietWindow),
                "{offset}"
            );
        }
        assert_eq!(
            evaluate_short_run(present(TimeDuration::minutes(15)), None, at(0)),
            Ok(())
        );
        // After the refresher confirmed a new expiry, runs resume.
        assert_eq!(
            evaluate_short_run(present(TimeDuration::hours(8)), None, at(0)),
            Ok(())
        );
    }

    #[test]
    fn short_runs_fail_closed_and_respect_a_running_refresh() {
        assert_eq!(
            evaluate_short_run(ClaudeGateCredential::ReadFailed, None, at(0)),
            Err(ClaudeSpawnRefusal::CredentialReadFailed)
        );
        assert_eq!(
            evaluate_short_run(
                ClaudeGateCredential::Present {
                    has_refresh_token: true,
                    access_expires_at: None,
                },
                None,
                at(0)
            ),
            Err(ClaudeSpawnRefusal::AccessExpiryUnknown)
        );
        assert_eq!(
            evaluate_short_run(ClaudeGateCredential::Absent, None, at(0)),
            Ok(())
        );
        assert_eq!(
            evaluate_short_run(
                present(TimeDuration::hours(2)),
                Some(SystemTime::from(at(-10))),
                at(0)
            ),
            Err(ClaudeSpawnRefusal::RefreshInProgress)
        );
        assert_eq!(
            evaluate_short_run(
                present(TimeDuration::hours(2)),
                Some(SystemTime::from(at(-61))),
                at(0)
            ),
            Ok(())
        );
    }

    /// `claude auth status` and `claude doctor` are never spawned again.
    #[test]
    fn no_auth_status_or_doctor_spawn_in_daemon_code() {
        const FORBIDDEN: &[&str] = &["\"auth\", \"status\"", "\"doctor\"]"];
        let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .to_path_buf();
        let mut files = Vec::new();
        for krate in ["ottto-service", "ottto-core", "ottto-cli"] {
            collect_rust_files(&crates.join(krate).join("src"), &mut files);
        }
        let mut violations = Vec::new();
        for file in &files {
            let body = std::fs::read_to_string(file).expect("read source");
            let production = body.split("#[cfg(test)]\nmod tests").next().unwrap_or("");
            for (number, line) in production.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") || code.starts_with("const FORBIDDEN") {
                    continue;
                }
                for pattern in FORBIDDEN {
                    if code.contains(pattern) {
                        violations.push(format!("{}:{}: {pattern}", file.display(), number + 1));
                    }
                }
            }
        }
        assert!(violations.is_empty(), "{violations:#?}");
    }

    fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
}
