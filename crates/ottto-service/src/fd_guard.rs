//! Opt-in kernel guard on the daemon's listening sockets, and descriptor
//! diagnostics for when a listener fails.
//!
//! Both the local OTLP relay listener and the unix control listener have been
//! "drained" in production: a blocking `accept` woke with `ECONNABORTED` and
//! the listener never served again. Only a `close` (or a `dup2` over the
//! number) of the listener's descriptor from inside this process, while a
//! thread is blocked on it, does that; a child process closing its inherited
//! copy does not. So some code in the daemon closes a descriptor number it no
//! longer owns, and the number belongs to a listener by then. Which code is not
//! known.
//!
//! [`ListenerFdGuard`] finds it. With the guard armed, the kernel refuses any
//! `close`, `dup` or `dup2` of the listener's descriptor that does not present
//! the guard, kills the process with `EXC_GUARD`, and writes a crash report
//! whose crashing thread is the culprit's stack
//! (`~/Library/Logs/DiagnosticReports/ottto-service-*.ips`). launchd then
//! restarts the daemon, which costs seconds instead of a dead listener.
//!
//! Off by default. Arm it with `OTTTO_FD_GUARD=1` in the service environment,
//! or by creating `<support dir>/diagnostics/fd-guard`. The file survives the
//! LaunchAgent plist being rewritten by an upgrade or by the Companion.

use std::os::fd::RawFd;
use std::path::PathBuf;

pub const FD_GUARD_ENV: &str = "OTTTO_FD_GUARD";

/// Marker file that arms the guard, relative to the support directory.
pub fn fd_guard_marker_path() -> PathBuf {
    ottto_core::default_support_dir()
        .join("diagnostics")
        .join("fd-guard")
}

fn fd_guard_enabled() -> bool {
    if cfg!(test) {
        // Tests dup and close listeners on purpose; never arm from a test
        // environment that happens to see the operator's marker file.
        return false;
    }
    std::env::var_os(FD_GUARD_ENV).is_some_and(|value| value == "1")
        || fd_guard_marker_path().exists()
}

/// A kernel guard on one listener descriptor. Drop it BEFORE the listener:
/// closing a guarded descriptor, even from its owner, is a guard violation.
#[must_use = "the guard is removed when this value drops"]
pub(crate) struct ListenerFdGuard {
    #[cfg(target_os = "macos")]
    fd: RawFd,
}

impl ListenerFdGuard {
    /// Arms the guard when it is enabled, logging either way it goes. `label`
    /// names the listener in the log.
    pub(crate) fn arm_if_enabled(fd: RawFd, label: &str) -> Option<Self> {
        if !fd_guard_enabled() {
            return None;
        }
        match Self::arm(fd) {
            Ok(guard) => {
                eprintln!("fd guard armed on the {label} listener (fd {fd})");
                Some(guard)
            }
            Err(error) => {
                eprintln!("fd guard unavailable on the {label} listener (fd {fd}): {error}");
                None
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn arm(fd: RawFd) -> std::io::Result<Self> {
        let mut fd_flags = libc::FD_CLOEXEC;
        // SAFETY: `fd` is an open descriptor owned by the caller; the guard
        // and flag pointers point at live locals of the declared types.
        let rc = unsafe {
            change_fdguard_np(
                fd,
                std::ptr::null(),
                0,
                &LISTENER_GUARD_ID,
                LISTENER_GUARD_FLAGS,
                &mut fd_flags,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    #[cfg(not(target_os = "macos"))]
    fn arm(_fd: RawFd) -> std::io::Result<Self> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

impl Drop for ListenerFdGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            let mut fd_flags = libc::FD_CLOEXEC;
            // SAFETY: removes the guard this value installed on its own
            // descriptor; the pointers point at live values.
            let rc = unsafe {
                change_fdguard_np(
                    self.fd,
                    &LISTENER_GUARD_ID,
                    LISTENER_GUARD_FLAGS,
                    std::ptr::null(),
                    0,
                    &mut fd_flags,
                )
            };
            if rc != 0 {
                eprintln!(
                    "fd guard could not be removed from fd {}: {}",
                    self.fd,
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

/// Arbitrary nonzero guard value ("ottto").
#[cfg(target_os = "macos")]
const LISTENER_GUARD_ID: u64 = 0x006f_7474_746f;
/// `GUARD_CLOSE | GUARD_DUP` from `<sys/guarded.h>`. The dup guard is what
/// also catches a `dup2` onto the listener's number; spawned children still
/// start normally (a guarded descriptor is close-on-exec).
#[cfg(target_os = "macos")]
const LISTENER_GUARD_FLAGS: libc::c_uint = (1 << 0) | (1 << 1);

#[cfg(target_os = "macos")]
extern "C" {
    /// Exported by libsystem_kernel; declared in the private
    /// `<sys/guarded.h>`.
    fn change_fdguard_np(
        fd: libc::c_int,
        guard: *const u64,
        guardflags: libc::c_uint,
        nguard: *const u64,
        nguardflags: libc::c_uint,
        fdflagsp: *mut libc::c_int,
    ) -> libc::c_int;
}

/// What `fd` names right now, for the log line written when a listener
/// fails: closed, still the listener (and whether it is draining), or reused
/// by some other kind of file.
pub(crate) fn describe_descriptor(fd: RawFd) -> String {
    // SAFETY: F_GETFD only reads the descriptor table.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return format!("fd {fd} is closed ({})", std::io::Error::last_os_error());
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes one stat into the live buffer.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return format!(
            "fd {fd} is open but fstat failed ({})",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: fstat succeeded, so the buffer is initialized.
    let mode = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
    if mode != libc::S_IFSOCK {
        return format!("fd {fd} now names a {}", descriptor_kind(mode));
    }
    if !cfg!(target_os = "macos") {
        return format!("fd {fd} is a socket");
    }
    if let Some(draining) = crate::control_plane_health::tcp_listener_draining(fd) {
        return format!("fd {fd} is a TCP listener (draining: {draining})");
    }
    if let Some(draining) = crate::control_plane_health::listener_draining(fd) {
        return format!("fd {fd} is a unix listener (draining: {draining})");
    }
    format!("fd {fd} is a socket that is not listening")
}

/// A one-line count of this process's open descriptors by kind. A steadily
/// growing count alongside a listener failure points at a descriptor leak.
pub(crate) fn descriptor_census() -> String {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit into the live struct.
    let scan_to = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
        limit.rlim_cur.min(65_536) as RawFd
    } else {
        4_096
    };
    let mut counts = std::collections::BTreeMap::<&'static str, usize>::new();
    let mut total = 0_usize;
    for fd in 0..scan_to {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat writes one stat into the live buffer; a closed
        // descriptor just fails.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            continue;
        }
        // SAFETY: fstat succeeded, so the buffer is initialized.
        let mode = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
        *counts.entry(descriptor_kind(mode)).or_default() += 1;
        total += 1;
    }
    let kinds = counts
        .iter()
        .map(|(kind, count)| format!("{count} {kind}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{total} open descriptors ({kinds})")
}

fn descriptor_kind(mode: libc::mode_t) -> &'static str {
    match mode {
        libc::S_IFSOCK => "socket",
        libc::S_IFREG => "file",
        libc::S_IFIFO => "pipe",
        libc::S_IFDIR => "directory",
        libc::S_IFCHR => "character device",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::fd::AsRawFd;

    #[test]
    fn describe_descriptor_tells_a_live_listener_from_a_closed_number() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let fd = listener.as_raw_fd();
        let live = describe_descriptor(fd);
        if cfg!(target_os = "macos") {
            assert_eq!(live, format!("fd {fd} is a TCP listener (draining: false)"));
        } else {
            assert!(live.starts_with(&format!("fd {fd} is a socket")), "{live}");
        }
        // Far above any descriptor a test process opens.
        let unused = 65_000;
        assert!(
            describe_descriptor(unused).starts_with(&format!("fd {unused} is closed")),
            "{}",
            describe_descriptor(unused)
        );
    }

    #[test]
    fn descriptor_census_counts_open_sockets() {
        let _listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let census = descriptor_census();
        assert!(census.contains(" socket"), "{census}");
        assert!(census.ends_with(')'), "{census}");
    }

    #[test]
    fn fd_guard_never_arms_under_test() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        assert!(ListenerFdGuard::arm_if_enabled(listener.as_raw_fd(), "test").is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_dropped_guard_lets_the_owner_close_its_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let guard = ListenerFdGuard::arm(listener.as_raw_fd()).expect("arm guard");
        drop(guard);
        // Would be a fatal guard violation if the guard were still in place.
        drop(listener);
    }

    /// Env var that turns [`guarded_listener_stale_close_child`] from a no-op
    /// into the child half of [`a_stale_close_of_a_guarded_listener_kills_the_process`].
    #[cfg(target_os = "macos")]
    const STALE_CLOSE_CHILD_ENV: &str = "OTTTO_FD_GUARD_STALE_CLOSE_CHILD";

    #[cfg(target_os = "macos")]
    #[test]
    fn guarded_listener_stale_close_child() {
        if std::env::var_os(STALE_CLOSE_CHILD_ENV).is_none() {
            return;
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let _guard = ListenerFdGuard::arm(listener.as_raw_fd()).expect("arm guard");
        // The bug this guard exists to catch: someone else closes the number.
        // SAFETY: deliberately closes a descriptor this code does not own.
        unsafe { libc::close(listener.as_raw_fd()) };
        std::process::exit(0);
    }

    /// Runs [`guarded_listener_stale_close_child`] in a child test process and
    /// proves the kernel killed it at the stale close instead of letting the
    /// close through.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_stale_close_of_a_guarded_listener_kills_the_process() {
        use std::os::unix::process::ExitStatusExt;

        let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "fd_guard::tests::guarded_listener_stale_close_child",
                "--test-threads=1",
            ])
            .env(STALE_CLOSE_CHILD_ENV, "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run child test");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "a guarded stale close must be fatal, got {status:?}"
        );
    }
}
