//! Local control-plane health, reported on every collector check-in.
//!
//! The check-in heartbeat proves that uploads are alive. It says nothing about
//! the LOCAL control plane that Setup, Repair, Verify, account flows and the
//! Companion depend on: the unix socket (the only transport for Homebrew
//! installs, which run `serve`) or XPC plus its debug socket (`serve-xpc`).
//! This module keeps a few process-wide counters for that plane, and
//! [`snapshot`] turns them into the optional `control_plane` block of the
//! check-in body (public ottto#440).
//!
//! `listener_draining` reads XNU's `SOI_S_DRAINING` bit off the unix listener.
//! A descriptor for the listener closed while another thread is blocked on it
//! sets that bit for good. Before 0.1.136 it broke every large response (see
//! `unix_socket::serve_listener`). Since then a drained listener keeps serving,
//! so `true` is a marker of a latent descriptor-lifetime bug, not an outage.
//! The point of reporting it is to learn how often the drain happens, and what
//! it correlates with, now that the daemon no longer fails because of it.
//!
//! `describe_descriptor` and `descriptor_census` write the descriptor state
//! into the log line of a listener that failed.

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU64, Ordering};
use std::sync::OnceLock;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// How the daemon serves local control requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlTransport {
    /// `serve`: the unix socket is the only control transport.
    UnixSocket,
    /// `serve-xpc`: the XPC Mach service, plus a debug unix socket.
    Xpc,
}

impl ControlTransport {
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::UnixSocket => "unix_socket",
            Self::Xpc => "xpc",
        }
    }
}

/// The `control_plane` block of a collector check-in.
///
/// Everything is additive and optional on the backend. No field carries a
/// socket path, because a path contains the user's home directory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlPlaneHealth {
    /// [`ControlTransport::wire_name`].
    pub transport: String,
    /// Whether a unix control listener is bound right now. Under `serve-xpc`
    /// this is the debug socket; XPC itself has no listener descriptor.
    pub listener_bound: bool,
    /// `SOI_S_DRAINING` on the bound unix listener. `None` when it cannot be
    /// measured: not macOS, no bound listener, or the probe was refused.
    pub listener_draining: Option<bool>,
    /// Control requests answered since the daemon started, on every transport.
    pub requests_served: u64,
    /// Control requests whose read or response write failed, or whose worker
    /// could not produce a response, since the daemon started.
    pub request_errors: u64,
    /// RFC 3339 time of the most recent answered request.
    pub last_request_served_at: Option<String>,
    /// RFC 3339 time the control plane started serving.
    pub started_at: String,
}

struct ControlPlaneStart {
    transport: ControlTransport,
    started_at: String,
}

const NO_LISTENER: i32 = -1;
const NEVER: i64 = i64::MIN;

static START: OnceLock<ControlPlaneStart> = OnceLock::new();
static REQUESTS_SERVED: AtomicU64 = AtomicU64::new(0);
static REQUEST_ERRORS: AtomicU64 = AtomicU64::new(0);
static LAST_REQUEST_SERVED_UNIX_SECONDS: AtomicI64 = AtomicI64::new(NEVER);
static LISTENER_FD: AtomicI32 = AtomicI32::new(NO_LISTENER);

/// Records which transport this daemon process serves. Only the first call
/// counts. Until it is made, [`snapshot`] returns `None`, so a process that
/// is not a serving daemon never reports control-plane health.
pub fn mark_serving(transport: ControlTransport) {
    let _ = START.set(ControlPlaneStart {
        transport,
        started_at: format_unix_seconds(now_unix_seconds()).unwrap_or_default(),
    });
}

/// Counts one control request that was answered in full.
pub fn record_request_served() {
    REQUESTS_SERVED.fetch_add(1, Ordering::Relaxed);
    LAST_REQUEST_SERVED_UNIX_SECONDS.store(now_unix_seconds(), Ordering::Relaxed);
}

/// Counts one control request that could not be read or answered.
pub fn record_request_error() {
    REQUEST_ERRORS.fetch_add(1, Ordering::Relaxed);
}

/// Publishes the bound unix listener's descriptor for the drain probe while
/// this guard lives.
///
/// Drop the guard BEFORE the listener. A descriptor number outlives its socket
/// the moment the socket closes: the kernel can hand it to the next `open`, and
/// the probe would then read someone else's descriptor. Clearing uses a
/// compare-and-swap, so a guard never clears a newer listener's descriptor.
#[must_use = "the listener is unpublished when the guard drops"]
pub(crate) struct PublishedListener {
    fd: i32,
}

impl PublishedListener {
    pub(crate) fn publish(fd: i32) -> Self {
        LISTENER_FD.store(fd, Ordering::SeqCst);
        Self { fd }
    }
}

impl Drop for PublishedListener {
    fn drop(&mut self) {
        let _ =
            LISTENER_FD.compare_exchange(self.fd, NO_LISTENER, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// The current health block, or `None` when this process is not serving.
pub fn snapshot() -> Option<ControlPlaneHealth> {
    let start = START.get()?;
    let fd = LISTENER_FD.load(Ordering::SeqCst);
    let listener_bound = fd != NO_LISTENER;
    let listener_draining = if listener_bound {
        listener_draining(fd)
    } else {
        None
    };
    let last_served = LAST_REQUEST_SERVED_UNIX_SECONDS.load(Ordering::Relaxed);
    Some(ControlPlaneHealth {
        transport: start.transport.wire_name().to_string(),
        listener_bound,
        listener_draining,
        requests_served: REQUESTS_SERVED.load(Ordering::Relaxed),
        request_errors: REQUEST_ERRORS.load(Ordering::Relaxed),
        last_request_served_at: if last_served == NEVER {
            None
        } else {
            format_unix_seconds(last_served)
        },
        started_at: start.started_at.clone(),
    })
}

/// Whether the published unix listener is draining, if one is bound.
#[cfg(all(test, target_os = "macos"))]
pub(crate) fn published_listener_draining() -> Option<bool> {
    match LISTENER_FD.load(Ordering::SeqCst) {
        NO_LISTENER => None,
        fd => listener_draining(fd),
    }
}

fn now_unix_seconds() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn format_unix_seconds(seconds: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// Reads `SOI_S_DRAINING` for `fd` with `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`.
///
/// This is a read of kernel bookkeeping. It has no side effects on the socket,
/// so it never races the accept loop. A non-blocking `accept` hides the state,
/// and no `getsockopt` exposes it, which is why the probe goes through
/// `libproc`.
///
/// `libc` binds `proc_pidfdinfo` but not `struct socket_fdinfo`, so the result
/// is read at fixed offsets out of an 8-byte-aligned buffer. The offsets come
/// from `<sys/proc_info.h>` and are the same on arm64 and x86_64. The kernel
/// fills exactly `sizeof(struct socket_fdinfo)` bytes. A different return
/// size, or a descriptor that is not an AF_UNIX listening socket (layout
/// drift, or the descriptor was reused), yields `None` instead of a guess.
pub(crate) fn listener_draining(fd: i32) -> Option<bool> {
    socket_listener_draining(fd, ListenerFamily::Unix)
}

/// [`listener_draining`] for a loopback TCP listener, such as the local OTLP
/// relay. The drain works the same way on TCP: once it is set, a blocking
/// `accept` fails with `ECONNABORTED` for every incoming connection.
pub(crate) fn tcp_listener_draining(fd: i32) -> Option<bool> {
    socket_listener_draining(fd, ListenerFamily::Tcp)
}

#[derive(Debug, Clone, Copy)]
enum ListenerFamily {
    Unix,
    Tcp,
}

#[cfg(target_os = "macos")]
fn socket_listener_draining(fd: i32, family: ListenerFamily) -> Option<bool> {
    /// `sizeof(struct socket_fdinfo)`.
    const SOCKET_FDINFO_SIZE: usize = 792;
    /// `offsetof(struct socket_fdinfo, psi.soi_family)`.
    const SOI_FAMILY_OFFSET: usize = 184;
    /// `offsetof(struct socket_fdinfo, psi.soi_options)`.
    const SOI_OPTIONS_OFFSET: usize = 188;
    /// `offsetof(struct socket_fdinfo, psi.soi_state)`.
    const SOI_STATE_OFFSET: usize = 192;
    /// `offsetof(struct socket_fdinfo, psi.soi_kind)`.
    const SOI_KIND_OFFSET: usize = 256;
    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    const SOCKINFO_TCP: i32 = 2;
    const SOCKINFO_UN: i32 = 3;
    const SOI_S_DRAINING: i16 = 0x4000;

    let mut buffer = [0_u64; SOCKET_FDINFO_SIZE / 8];
    // SAFETY: the buffer is SOCKET_FDINFO_SIZE bytes, 8-byte aligned, and
    // writable. The kernel writes at most `buffersize` bytes into it.
    let written = unsafe {
        libc::proc_pidfdinfo(
            libc::getpid(),
            fd,
            PROC_PIDFDSOCKETINFO,
            buffer.as_mut_ptr().cast(),
            SOCKET_FDINFO_SIZE as libc::c_int,
        )
    };
    if written != SOCKET_FDINFO_SIZE as libc::c_int {
        return None;
    }
    // SAFETY: reinterpreting fully initialized u64s as bytes of the same size.
    let bytes: &[u8; SOCKET_FDINFO_SIZE] = unsafe { &*buffer.as_ptr().cast() };
    let read_i32 =
        |offset: usize| i32::from_ne_bytes(bytes[offset..offset + 4].try_into().expect("4 bytes"));
    let read_i16 =
        |offset: usize| i16::from_ne_bytes(bytes[offset..offset + 2].try_into().expect("2 bytes"));
    let (families, kind): (&[i32], i32) = match family {
        ListenerFamily::Unix => (&[libc::AF_UNIX], SOCKINFO_UN),
        ListenerFamily::Tcp => (&[libc::AF_INET, libc::AF_INET6], SOCKINFO_TCP),
    };
    let is_listener = families.contains(&read_i32(SOI_FAMILY_OFFSET))
        && read_i32(SOI_KIND_OFFSET) == kind
        && read_i16(SOI_OPTIONS_OFFSET) & libc::SO_ACCEPTCONN as i16 != 0;
    if !is_listener {
        return None;
    }
    Some(read_i16(SOI_STATE_OFFSET) & SOI_S_DRAINING != 0)
}

#[cfg(not(target_os = "macos"))]
fn socket_listener_draining(_fd: i32, _family: ListenerFamily) -> Option<bool> {
    None
}

/// What `fd` names right now, for the log line written when a listener
/// fails: closed, still the listener (and whether it is draining), or reused
/// by some other kind of file.
#[cfg(unix)]
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
    if let Some(draining) = tcp_listener_draining(fd) {
        return format!("fd {fd} is a TCP listener (draining: {draining})");
    }
    if let Some(draining) = listener_draining(fd) {
        return format!("fd {fd} is a unix listener (draining: {draining})");
    }
    format!("fd {fd} is a socket that is not listening")
}

/// Process soft descriptor limit; failure supplies no admission authority.
#[cfg(unix)]
pub(crate) fn descriptor_limit() -> Option<usize> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit into the live struct.
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0)
        .then(|| usize::try_from(limit.rlim_cur).unwrap_or(usize::MAX))
}

/// A one-line count of this process's open descriptors by kind.
#[cfg(unix)]
pub(crate) fn descriptor_census() -> String {
    let scan_to = descriptor_limit().unwrap_or(4_096).min(65_536) as RawFd;
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

#[cfg(unix)]
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
    #[cfg(unix)]
    use std::net::{Ipv4Addr, TcpListener};
    #[cfg(unix)]
    use std::os::fd::AsRawFd;

    #[test]
    fn counters_only_move_forward_and_stamp_the_last_served_time() {
        let before_served = REQUESTS_SERVED.load(Ordering::Relaxed);
        let before_errors = REQUEST_ERRORS.load(Ordering::Relaxed);

        record_request_served();
        record_request_served();
        record_request_error();

        assert!(REQUESTS_SERVED.load(Ordering::Relaxed) >= before_served + 2);
        assert!(REQUEST_ERRORS.load(Ordering::Relaxed) > before_errors);
        let stamped = LAST_REQUEST_SERVED_UNIX_SECONDS.load(Ordering::Relaxed);
        assert_ne!(stamped, NEVER);
        let formatted = format_unix_seconds(stamped).expect("rfc3339");
        assert!(formatted.ends_with('Z'), "{formatted}");
        OffsetDateTime::parse(&formatted, &Rfc3339).expect("parses back");
    }

    #[test]
    fn a_serving_process_reports_its_transport_and_start_once() {
        mark_serving(ControlTransport::UnixSocket);
        let first = snapshot().expect("serving process reports health");
        // A second mark never rewrites the transport or the start clock.
        mark_serving(ControlTransport::Xpc);
        let second = snapshot().expect("serving process reports health");

        assert_eq!(first.transport, second.transport);
        assert_eq!(first.started_at, second.started_at);
        assert!(!second.started_at.is_empty());
        assert!(second.requests_served >= first.requests_served);
    }

    #[test]
    fn the_wire_block_names_no_path_and_serializes_an_unmeasured_drain_as_null() {
        let health = ControlPlaneHealth {
            transport: ControlTransport::Xpc.wire_name().to_string(),
            listener_bound: false,
            listener_draining: None,
            requests_served: 3,
            request_errors: 0,
            last_request_served_at: None,
            started_at: "2026-09-25T08:00:00Z".to_string(),
        };

        let value = serde_json::to_value(&health).expect("serialize");

        assert_eq!(
            value,
            serde_json::json!({
                "transport": "xpc",
                "listener_bound": false,
                "listener_draining": null,
                "requests_served": 3,
                "request_errors": 0,
                "last_request_served_at": null,
                "started_at": "2026-09-25T08:00:00Z",
            })
        );
        // A journal entry written by a later daemon with more members, or by
        // this one with fewer, still reloads.
        let reloaded: ControlPlaneHealth =
            serde_json::from_value(serde_json::json!({"transport": "xpc", "future": 1}))
                .expect("forward-tolerant reload");
        assert_eq!(reloaded.transport, "xpc");
    }

    #[test]
    #[serial_test::serial]
    fn a_guard_never_clears_a_newer_listener() {
        // Descriptor numbers far above anything this test process opens, so
        // the socket tests that publish real listeners are not disturbed for
        // longer than these two statements.
        let older = PublishedListener::publish(1_000_001);
        let newer = PublishedListener::publish(1_000_002);
        drop(older);
        assert_eq!(LISTENER_FD.load(Ordering::SeqCst), 1_000_002);
        drop(newer);
        assert_ne!(LISTENER_FD.load(Ordering::SeqCst), 1_000_002);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_drain_probe_refuses_descriptors_that_are_not_unix_listeners() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (connected, _peer) = UnixStream::pair().expect("socket pair");
        assert_eq!(listener_draining(connected.as_raw_fd()), None);
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        assert_eq!(listener_draining(file.as_raw_fd()), None);
        assert_eq!(listener_draining(-1), None);
    }

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn descriptor_census_counts_open_sockets() {
        let _listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let census = descriptor_census();
        assert!(census.contains(" socket"), "{census}");
        assert!(census.ends_with(')'), "{census}");
    }
}
