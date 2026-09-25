use crate::control::{handle_request_with_peer, LocalClientPeer};
use crate::control_plane_health::{self, PublishedListener};
use crate::LocalDaemon;
use anyhow::{Context, Result};
use ottto_protocol::{CliError, CliErrorCode, LocalControlRequest, LocalControlResponse};
use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// How long a worker waits for the client to finish sending its request.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a worker keeps a response in flight for a client that stopped
/// reading. Clients wait at least `LOCAL_CONTROL_SOCKET_TIMEOUT` (45s) for the
/// whole exchange, so this only reaps workers whose client is gone.
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

type RequestHandler =
    Arc<dyn Fn(LocalControlRequest, Option<LocalClientPeer>) -> LocalControlResponse + Send + Sync>;

pub fn serve_unix_socket_once(path: &Path, daemon: LocalDaemon) -> Result<()> {
    serve_unix_socket_with_limit(path, daemon, Some(1))
}

pub fn serve_unix_socket(path: &Path, daemon: LocalDaemon) -> Result<()> {
    serve_unix_socket_with_limit(path, daemon, None)
}

pub fn serve_unix_socket_with_limit(
    path: &Path,
    daemon: LocalDaemon,
    max_requests: Option<usize>,
) -> Result<()> {
    let handler = Arc::new(move |request, peer| handle_request_with_peer(&daemon, request, peer));
    serve_unix_socket_with_limit_and_handler(path, max_requests, handler)
}

fn serve_unix_socket_with_limit_and_handler(
    path: &Path,
    max_requests: Option<usize>,
    handler: RequestHandler,
) -> Result<()> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("remove stale socket {}", path.display()))?;
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create socket parent {}", parent.display()))?;
    }

    let listener = bind_user_only_socket(path)?;
    serve_listener(listener, path, max_requests, handler)
}

/// Accepts control connections on `listener` and serves each on its own worker.
///
/// No thread ever sleeps inside a socket syscall here. The listener and every
/// accepted stream are non-blocking, and all waiting happens in `poll(2)`
/// ([`wait_for_fd`]). On macOS this is load-bearing, not a style choice.
///
/// XNU marks a socket `SS_DRAINING` when a descriptor for it is closed while
/// another thread is blocked on it. The flag never clears, and each connection
/// accepted afterwards copies it from the listener (`sonewconn` copies
/// `so_state`). From then on every *sleeping* socket wait fails. A blocking
/// `accept` returns `ECONNABORTED` once per incoming connection. `sbwait`
/// returns `EBADF`, so a read that has to wait for the request fails, and so
/// does a write that has to wait for buffer space. That second case cuts every
/// response larger than one unix-socket send buffer (8 KiB,
/// `net.local.stream.sendspace`) off at exactly 8192 bytes while `write_all`
/// reports `EBADF`. A daemon that reached this state kept failing every large
/// `status` until it restarted.
///
/// Non-blocking calls never enter `sbwait`, and `poll` does not look at
/// `SS_DRAINING`, so the same poisoned listener keeps serving complete
/// responses in either direction.
fn serve_listener(
    listener: UnixListener,
    path: &Path,
    max_requests: Option<usize>,
    handler: RequestHandler,
) -> Result<()> {
    listener
        .set_nonblocking(true)
        .with_context(|| format!("set socket nonblocking {}", path.display()))?;
    // Lets the check-in report whether this listener is draining. `listener`
    // is a parameter, so this local drops (and unpublishes the descriptor)
    // before it on every return path, before the descriptor can be closed and
    // reused.
    let published = PublishedListener::publish(listener.as_raw_fd());

    let mut served = 0_usize;
    let mut workers = Vec::new();
    loop {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                wait_for_fd(listener.as_raw_fd(), libc::POLLIN, None)
                    .with_context(|| format!("wait for socket {}", path.display()))?;
                continue;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => {
                eprintln!("socket listener {} accept failed: {error}", path.display());
                continue;
            }
        };
        let path = path.to_path_buf();
        let handler = Arc::clone(&handler);
        let worker = thread::Builder::new()
            .name("ottto-unix-control".to_string())
            .spawn(move || handle_stream(path, stream, handler))
            .context("spawn unix control worker")?;
        if max_requests.is_some() {
            workers.push(worker);
        }
        served += 1;
        if max_requests.is_some_and(|limit| served >= limit) {
            break;
        }
    }
    for worker in workers {
        if worker.join().is_err() {
            eprintln!("socket listener {} worker panicked", path.display());
        }
    }
    drop(published);
    Ok(())
}

fn handle_stream(path: PathBuf, mut stream: UnixStream, handler: RequestHandler) {
    // Whether an accepted socket inherits the listener's O_NONBLOCK differs by
    // platform; the poll-driven I/O below requires it, so set it explicitly.
    if let Err(error) = stream.set_nonblocking(true) {
        eprintln!(
            "socket listener {} set stream nonblocking failed: {error}",
            path.display()
        );
        control_plane_health::record_request_error();
        return;
    }
    let peer = local_client_peer(&stream);
    let (response, read_failed) = match read_request(&mut stream) {
        Ok(request) => (handler(request, peer), false),
        Err(error) => (invalid_request_response(&error.to_string()), true),
    };
    match write_response(&mut stream, &response) {
        Ok(()) if !read_failed => control_plane_health::record_request_served(),
        Ok(()) => control_plane_health::record_request_error(),
        Err(error) => {
            eprintln!(
                "socket listener {} response write failed: {error}",
                path.display()
            );
            control_plane_health::record_request_error();
        }
    }
}

fn invalid_request_response(message: &str) -> LocalControlResponse {
    LocalControlResponse {
        request_id: "req_socket_invalid".to_string(),
        ok: false,
        payload: None,
        error: Some(CliError {
            code: CliErrorCode::InvalidRequest,
            message: format!("invalid local control request: {message}"),
            retryable: false,
            details: BTreeMap::new(),
        }),
    }
}

/// Binds an owner-only control socket without touching the process umask.
///
/// A unix domain socket inherits its permissions from the umask in effect at
/// bind time, so the obvious hardening is a scoped `umask(0o177)`. umask is
/// process-global rather than per-thread, and the daemon binds this socket while
/// its relay threads are already running, so such a window also narrows every
/// file and directory those threads happen to create. A directory created under
/// `0o177` lands at `0o600`: it keeps its read bit but loses its execute bit, so
/// it can never be traversed again and every write inside it fails with EACCES.
///
/// Bind inside a private staging directory instead, tighten the socket there,
/// then rename it into place. Renaming keeps the listening socket's inode, so
/// clients connect through the published path as before, and that path only ever
/// appears with owner-only permissions.
fn bind_user_only_socket(path: &Path) -> Result<UnixListener> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staging = PrivateStagingDir::create_in(parent)?;
    // Socket paths are capped at `sockaddr_un::sun_path`, so keep the staged
    // name short: it replaces the final file name, it does not extend it.
    let staged = staging.path().join("s");
    let listener =
        UnixListener::bind(&staged).with_context(|| format!("bind socket {}", path.display()))?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod socket {}", path.display()))?;
    fs::rename(&staged, path).with_context(|| format!("publish socket {}", path.display()))?;
    Ok(listener)
}

/// Owner-only directory that is removed when it goes out of scope, including
/// when the bind it was staging fails.
struct PrivateStagingDir {
    path: PathBuf,
}

impl PrivateStagingDir {
    fn create_in(parent: &Path) -> Result<Self> {
        for _ in 0..16 {
            let mut suffix = [0_u8; 4];
            getrandom::fill(&mut suffix)
                .map_err(|error| anyhow::anyhow!("random socket staging name: {error}"))?;
            let path = parent.join(format!(".s{:08x}", u32::from_ne_bytes(suffix)));
            match fs::create_dir(&path) {
                Ok(()) => {
                    // `mkdir` masks its requested mode with the umask, which
                    // another thread can move underneath us, so pin the mode
                    // explicitly instead of inheriting whatever is in effect.
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .with_context(|| format!("chmod socket staging {}", path.display()))?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(anyhow::Error::new(error)
                        .context(format!("create socket staging {}", path.display())))
                }
            }
        }
        anyhow::bail!(
            "could not create a unique socket staging directory in {}",
            parent.display()
        )
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateStagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn local_client_peer(stream: &UnixStream) -> Option<LocalClientPeer> {
    let pid = peer_pid(stream);
    let euid = peer_euid(stream);
    if pid.is_none() && euid.is_none() {
        return None;
    }
    Some(LocalClientPeer::from_pid_and_euid(pid, euid))
}

#[cfg(unix)]
fn peer_euid(stream: &UnixStream) -> Option<u32> {
    // getpeereid is a supported, non-spoofable way to read the connecting
    // peer's effective uid (and gid). It is captured here at accept time and
    // threaded into LocalClientPeer so the control layer can enforce that the
    // peer runs as the daemon's own uid before granting token-less trust.
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    // `libc::uid_t` is `u32` on every supported unix target.
    if rc == 0 {
        Some(uid)
    } else {
        None
    }
}

#[cfg(not(unix))]
fn peer_euid(_stream: &UnixStream) -> Option<u32> {
    None
}

#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Option<u32> {
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;

    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 && pid > 0 {
        Some(pid as u32)
    } else {
        None
    }
}

#[cfg(not(target_os = "macos"))]
fn peer_pid(_stream: &UnixStream) -> Option<u32> {
    None
}

fn read_request(stream: &mut UnixStream) -> Result<LocalControlRequest> {
    let deadline = Instant::now() + REQUEST_READ_TIMEOUT;
    let mut body = Vec::new();
    let mut chunk = [0_u8; 4096];

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                body.extend_from_slice(&chunk[..read]);
                if let Ok(request) = serde_json::from_slice(&body) {
                    return Ok(request);
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                match wait_for_fd(stream.as_raw_fd(), libc::POLLIN, Some(deadline)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == ErrorKind::TimedOut => break,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(serde_json::from_slice(&body)?)
}

fn write_response(stream: &mut UnixStream, response: &LocalControlResponse) -> Result<()> {
    let response = serde_json::to_vec(response)?;
    let deadline = Instant::now() + RESPONSE_WRITE_TIMEOUT;
    let mut written = 0;
    while written < response.len() {
        match stream.write(&response[written..]) {
            Ok(0) => return Err(std::io::Error::from(ErrorKind::WriteZero).into()),
            Ok(count) => written += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                wait_for_fd(stream.as_raw_fd(), libc::POLLOUT, Some(deadline))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Blocks in `poll(2)` until `fd` reports `events` (or an error/hang-up, which
/// the caller's next read or write surfaces), or until `deadline` passes.
///
/// Every wait on the control socket goes through here instead of blocking
/// inside `accept`/`read`/`write`; see [`serve_listener`] for why.
fn wait_for_fd(
    fd: libc::c_int,
    events: libc::c_short,
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    loop {
        let timeout_ms = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(ErrorKind::TimedOut.into());
                }
                // Round up so a sub-millisecond remainder still waits.
                remaining
                    .as_millis()
                    .saturating_add(1)
                    .min(libc::c_int::MAX as u128) as libc::c_int
            }
            None => -1,
        };
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: one valid pollfd on the stack, and nfds matches.
        let rc = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok(());
        }
        if rc == 0 {
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlToken, LocalDaemon};
    use ottto_core::{request_unix_socket, request_unix_socket_with_timeout};
    use ottto_protocol::{
        LocalClientKind, LocalControlCommand, LocalControlRequest, MachineIdentity,
        OperatingSystem, LOCAL_CONTROL_PROTOCOL_VERSION,
    };
    use serial_test::serial;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::{mpsc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn peer_euid_reports_connecting_process_euid() {
        // A connected socket pair lives in this process, so the captured peer
        // euid must equal our own effective uid.
        let (a, _b) = UnixStream::pair().expect("socket pair");
        let euid = peer_euid(&a).expect("peer euid available on connected socket");
        assert_eq!(euid, unsafe { libc::geteuid() });
    }

    #[test]
    fn local_client_peer_captures_euid() {
        let (a, _b) = UnixStream::pair().expect("socket pair");
        let peer = local_client_peer(&a).expect("peer attributes");
        assert_eq!(peer.euid, Some(unsafe { libc::geteuid() }));
    }

    #[test]
    #[serial]
    fn unix_socket_serves_authenticated_status() {
        let path = std::env::temp_dir().join(format!(
            "ottto-service-test-{}-{}.sock",
            std::process::id(),
            "status"
        ));
        let daemon = daemon();
        let server_path = path.clone();
        let server = thread::spawn(move || serve_unix_socket_once(&server_path, daemon));

        wait_for_socket(&path);
        let response = request_unix_socket(
            &path,
            &LocalControlRequest {
                request_id: "req_socket".to_string(),
                protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        )
        .expect("socket request should succeed");

        assert!(response.ok);
        assert_eq!(
            response.payload.expect("payload").get("daemon"),
            Some(&serde_json::Value::String("running".to_string()))
        );
        server.join().expect("server thread should join").unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    #[serial]
    fn unix_socket_permissions_are_user_only() {
        let path = std::env::temp_dir().join(format!(
            "ottto-service-test-{}-{}.sock",
            std::process::id(),
            "permissions"
        ));
        let daemon = daemon();
        let server_path = path.clone();
        let server = thread::spawn(move || serve_unix_socket_once(&server_path, daemon));

        wait_for_socket(&path);
        let mode = fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = request_unix_socket(
            &path,
            &LocalControlRequest {
                request_id: "req_socket_permissions".to_string(),
                protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        )
        .expect("socket request should succeed");

        server.join().expect("server thread should join").unwrap();
        let _ = fs::remove_file(path);
    }

    /// A bound AF_UNIX socket takes its mode from the process umask, so it is
    /// tempting to tighten the umask around `bind`. umask is process-global:
    /// every other thread that creates a file or directory inside that window
    /// inherits the restriction. A directory created at `0o600` keeps its read
    /// bit but loses its execute bit, so it can no longer be traversed and every
    /// write inside it fails with `EACCES` - which is how a daemon relay (or a
    /// sibling test) ends up with a state directory it can never write to again.
    /// Bind repeatedly while another thread creates directories and require
    /// every one of them to stay traversable.
    #[test]
    #[serial]
    fn socket_bind_never_narrows_directories_created_by_other_threads() {
        // Socket paths are capped at SUN_LEN (104 bytes on macOS) and $TMPDIR is
        // already long here, so keep every component short.
        let root = std::env::temp_dir().join(format!(
            "ottto-um-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.subsec_nanos())
                .unwrap_or_default()
        ));
        let dirs = root.join("d");
        for path in [&root, &dirs] {
            fs::create_dir_all(path).expect("probe directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("probe directory mode");
        }

        let stop = Arc::new(AtomicBool::new(false));
        let creator_stop = Arc::clone(&stop);
        let creator_dirs = dirs.clone();
        let creator = thread::spawn(move || {
            let mut narrowed: Vec<String> = Vec::new();
            let mut created = 0_u64;
            while !creator_stop.load(AtomicOrdering::Relaxed) {
                let child = creator_dirs.join(format!("{created}"));
                created += 1;
                if fs::create_dir(&child).is_err() {
                    continue;
                }
                if let Ok(metadata) = fs::metadata(&child) {
                    let mode = metadata.permissions().mode() & 0o777;
                    if mode & 0o100 == 0 {
                        narrowed.push(format!("{mode:o}"));
                        let _ = fs::set_permissions(&child, fs::Permissions::from_mode(0o700));
                    }
                }
                let _ = fs::remove_dir(&child);
                // Throttle: this probe runs inside a parallel suite and must
                // detect the leak, not become a load generator for its
                // neighbours.
                thread::sleep(Duration::from_micros(50));
            }
            narrowed
        });

        for attempt in 0..400 {
            let socket_path = root.join(format!("s{attempt}.sock"));
            let listener = bind_user_only_socket(&socket_path).expect("bind probe socket");
            drop(listener);
            let _ = fs::remove_file(&socket_path);
        }

        stop.store(true, AtomicOrdering::Relaxed);
        let mut narrowed = creator.join().expect("probe creator thread");
        let _ = fs::remove_dir_all(&root);

        let observed = narrowed.len();
        narrowed.sort();
        narrowed.dedup();
        assert!(
            narrowed.is_empty(),
            "binding the control socket narrowed {observed} directories created by \
             another thread (modes {narrowed:?}); a directory without the owner \
             execute bit cannot be traversed, so every write inside it fails"
        );
    }

    #[test]
    #[serial]
    fn unix_socket_does_not_require_client_write_shutdown() {
        let path = std::env::temp_dir().join(format!(
            "ottto-service-test-{}-{}.sock",
            std::process::id(),
            "no-shutdown"
        ));
        let daemon = daemon();
        let server_path = path.clone();
        let server = thread::spawn(move || serve_unix_socket_once(&server_path, daemon));

        wait_for_socket(&path);
        let request = LocalControlRequest {
            request_id: "req_no_shutdown".to_string(),
            protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Status {
                refresh_agent_status: false,
            },
        };
        let mut stream = UnixStream::connect(&path).expect("connect socket");
        stream
            .write_all(&serde_json::to_vec(&request).expect("serialize request"))
            .expect("write request");

        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        let response: LocalControlResponse =
            serde_json::from_str(&response).expect("parse response");
        assert!(response.ok);

        server.join().expect("server thread should join").unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    #[serial]
    fn unix_socket_rejects_stale_protocol_request_with_local_control_error() {
        let path = std::env::temp_dir().join(format!(
            "ottto-service-test-{}-{}.sock",
            std::process::id(),
            "stale-protocol"
        ));
        let daemon = daemon();
        let server_path = path.clone();
        let server = thread::spawn(move || serve_unix_socket_once(&server_path, daemon));

        wait_for_socket(&path);
        let mut stream = UnixStream::connect(&path).expect("connect socket");
        stream
            .write_all(
                br#"{"request_id":"req_stale","protocol_version":10,"token":"token","client_kind":"cli","command":"status"}"#,
            )
            .expect("write request");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");

        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        let response: LocalControlResponse =
            serde_json::from_str(&response).expect("parse response");

        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, ottto_protocol::CliErrorCode::InvalidRequest);
        assert!(error
            .message
            .contains("unsupported local control protocol_version 10"));

        server.join().expect("server thread should join").unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    #[serial]
    fn unix_socket_keeps_serving_after_client_disconnects_before_response() {
        let path = std::env::temp_dir().join(format!(
            "ottto-service-test-{}-{}.sock",
            std::process::id(),
            "disconnect"
        ));
        let daemon = daemon();
        let server_path = path.clone();
        let server =
            thread::spawn(move || serve_unix_socket_with_limit(&server_path, daemon, Some(2)));

        wait_for_socket(&path);
        {
            let mut stream = UnixStream::connect(&path).expect("connect socket");
            stream.write_all(b"{").expect("write malformed request");
        }

        let response = request_unix_socket(
            &path,
            &LocalControlRequest {
                request_id: "req_socket_after_disconnect".to_string(),
                protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        )
        .expect("socket request after disconnect should succeed");

        assert!(response.ok);
        server.join().expect("server thread should join").unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    #[serial]
    fn unix_socket_serves_fast_request_while_slow_request_is_in_flight() {
        let path = std::env::temp_dir().join(format!(
            "ottto-service-test-{}-{}.sock",
            std::process::id(),
            "concurrent"
        ));
        let _ = fs::remove_file(&path);
        let (slow_started_tx, slow_started_rx) = mpsc::channel();
        let (release_slow_tx, release_slow_rx) = mpsc::channel();
        let release_slow_rx = Arc::new(Mutex::new(release_slow_rx));

        let handler: RequestHandler = Arc::new(move |request, _peer| {
            if request.request_id == "req_slow" {
                let _ = slow_started_tx.send(());
                let _ = release_slow_rx
                    .lock()
                    .expect("release receiver lock")
                    .recv_timeout(Duration::from_secs(2));
            }
            LocalControlResponse {
                request_id: request.request_id,
                ok: true,
                payload: Some(serde_json::json!({"daemon": "running"})),
                error: None,
            }
        });

        let server_path = path.clone();
        let server = thread::spawn(move || {
            serve_unix_socket_with_limit_and_handler(&server_path, Some(2), handler)
        });

        wait_for_socket(&path);
        let slow_path = path.clone();
        let slow = thread::spawn(move || {
            request_unix_socket_with_timeout(
                &slow_path,
                &LocalControlRequest {
                    request_id: "req_slow".to_string(),
                    protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
                    token: Some("token".to_string()),
                    client_kind: Some(LocalClientKind::Cli),
                    client_install_owner: None,
                    command: LocalControlCommand::Verify {
                        source: ottto_protocol::SourceKind::Pi,
                        repair: false,
                    },
                },
                Duration::from_secs(3),
            )
        });
        slow_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("slow request reached handler");

        let fast = request_unix_socket_with_timeout(
            &path,
            &LocalControlRequest {
                request_id: "req_fast".to_string(),
                protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
            Duration::from_millis(500),
        )
        .expect("fast request should not wait for slow request to complete");
        assert_eq!(fast.request_id, "req_fast");
        assert!(fast.ok);

        release_slow_tx.send(()).expect("release slow handler");
        slow.join()
            .expect("slow client joins")
            .expect("slow request completes");
        server.join().expect("server thread should join").unwrap();
        let _ = fs::remove_file(path);
    }

    /// A unix stream socket on macOS only buffers `net.local.stream.sendspace`
    /// bytes (8 KiB by default), so a large `status` payload can only reach the
    /// client if the daemon keeps writing while the client drains it. Every
    /// other socket test here uses a payload that fits in one buffer.
    #[test]
    #[serial]
    fn unix_socket_round_trips_response_larger_than_socket_buffer() {
        let path = std::env::temp_dir().join(format!(
            "ottto-service-test-{}-{}.sock",
            std::process::id(),
            "large-response"
        ));
        let _ = fs::remove_file(&path);
        let filler = "x".repeat(256 * 1024);
        let expected = filler.clone();
        let handler: RequestHandler = Arc::new(move |request, _peer| LocalControlResponse {
            request_id: request.request_id,
            ok: true,
            payload: Some(serde_json::json!({"daemon": "running", "filler": filler})),
            error: None,
        });

        let server_path = path.clone();
        let server = thread::spawn(move || {
            serve_unix_socket_with_limit_and_handler(&server_path, Some(1), handler)
        });

        wait_for_socket(&path);
        let response = request_unix_socket(
            &path,
            &LocalControlRequest {
                request_id: "req_large".to_string(),
                protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        )
        .expect("large socket response should round-trip");

        assert_eq!(response.request_id, "req_large");
        let payload = response.payload.expect("payload");
        assert_eq!(
            payload.get("filler").and_then(serde_json::Value::as_str),
            Some(expected.as_str())
        );
        server.join().expect("server thread should join").unwrap();
        let _ = fs::remove_file(path);
    }

    /// Reproduces the listener state a long-running macOS daemon was found in:
    /// closing a descriptor for the listener while another thread is blocked in
    /// `accept` on it leaves the socket permanently `SS_DRAINING`, and every
    /// connection accepted afterwards inherits that. A blocking server then
    /// cannot wait for a late request (`EBADF`) and cuts responses off at one
    /// socket buffer, exactly 8192 bytes. Serving must stay complete in both
    /// directions on such a listener.
    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn unix_socket_serves_complete_responses_on_a_drained_listener() {
        let path = std::env::temp_dir().join(format!(
            "ottto-service-test-{}-{}.sock",
            std::process::id(),
            "drained"
        ));
        let _ = fs::remove_file(&path);
        let listener = bind_user_only_socket(&path).expect("bind listener");
        assert_eq!(
            control_plane_health::listener_draining(listener.as_raw_fd()),
            Some(false),
            "a freshly bound listener must probe as not draining"
        );
        drain_listener(&listener);
        assert_eq!(
            control_plane_health::listener_draining(listener.as_raw_fd()),
            Some(true),
            "the drain probe must see SOI_S_DRAINING after drain_listener"
        );

        let filler = "y".repeat(256 * 1024);
        let expected = filler.clone();
        let handler: RequestHandler = Arc::new(move |request, _peer| LocalControlResponse {
            request_id: request.request_id,
            ok: true,
            payload: Some(serde_json::json!({"daemon": "running", "filler": filler})),
            error: None,
        });
        let server_path = path.clone();
        let server =
            thread::spawn(move || serve_listener(listener, &server_path, Some(2), handler));

        // The CLI's own client sends its request immediately, so the worker's
        // read finds it buffered and only the response write has to wait. This
        // is the reported `ottto status --json` failure: "EOF while parsing a
        // string at line 1 column 8192".
        let response = request_unix_socket(
            &path,
            &LocalControlRequest {
                request_id: "req_drained_immediate".to_string(),
                protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        )
        .expect("large response round-trips on a drained listener");
        // The serving listener is published for the check-in, and the
        // check-in sees it as the drained listener it is.
        assert_eq!(
            control_plane_health::published_listener_draining(),
            Some(true)
        );
        assert!(
            response.ok,
            "drained listener failed the request: {:?}",
            response.error
        );
        assert_eq!(
            response
                .payload
                .expect("payload")
                .get("filler")
                .and_then(serde_json::Value::as_str),
            Some(expected.as_str())
        );

        let request = LocalControlRequest {
            request_id: "req_drained".to_string(),
            protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Status {
                refresh_agent_status: false,
            },
        };
        let mut stream = UnixStream::connect(&path).expect("connect socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("client read timeout");
        // Let the worker reach its read before the request exists, so it has to
        // wait for it rather than finding it already buffered.
        thread::sleep(Duration::from_millis(200));
        stream
            .write_all(&serde_json::to_vec(&request).expect("serialize request"))
            .expect("write request");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");

        let mut body = Vec::new();
        stream.read_to_end(&mut body).expect("read response");
        let response: LocalControlResponse =
            serde_json::from_slice(&body).unwrap_or_else(|error| {
                panic!(
                    "response of {} bytes did not parse on a drained listener: {error}",
                    body.len()
                )
            });
        assert_eq!(response.request_id, "req_drained");
        assert_eq!(
            response
                .payload
                .expect("payload")
                .get("filler")
                .and_then(serde_json::Value::as_str),
            Some(expected.as_str())
        );
        server.join().expect("server thread should join").unwrap();
        // The listener is gone, so its descriptor is no longer published.
        assert_eq!(control_plane_health::published_listener_draining(), None);
        let _ = fs::remove_file(path);
    }

    /// Serving counts answered requests for the check-in, and a request that
    /// could not be read counts as an error.
    #[test]
    #[serial]
    fn unix_socket_counts_served_requests_and_read_failures() {
        let path = std::env::temp_dir().join(format!(
            "ottto-service-test-{}-{}.sock",
            std::process::id(),
            "health-counters"
        ));
        let _ = fs::remove_file(&path);
        let handler: RequestHandler = Arc::new(move |request, _peer| LocalControlResponse {
            request_id: request.request_id,
            ok: true,
            payload: Some(serde_json::json!({"daemon": "running"})),
            error: None,
        });
        let server_path = path.clone();
        let server = thread::spawn(move || {
            serve_unix_socket_with_limit_and_handler(&server_path, Some(2), handler)
        });
        wait_for_socket(&path);
        control_plane_health::mark_serving(control_plane_health::ControlTransport::UnixSocket);
        let before = control_plane_health::snapshot().expect("serving health");

        let response = request_unix_socket(
            &path,
            &LocalControlRequest {
                request_id: "req_health_counters".to_string(),
                protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        )
        .expect("socket request should succeed");
        assert!(response.ok);
        {
            let mut stream = UnixStream::connect(&path).expect("connect socket");
            stream
                .write_all(b"not json")
                .expect("write malformed request");
            stream
                .shutdown(std::net::Shutdown::Write)
                .expect("shutdown write");
            let mut body = Vec::new();
            stream
                .read_to_end(&mut body)
                .expect("read invalid-request reply");
        }
        server.join().expect("server thread should join").unwrap();

        let after = control_plane_health::snapshot().expect("serving health");
        assert!(after.requests_served > before.requests_served);
        assert!(after.request_errors > before.request_errors);
        assert!(after.last_request_served_at.is_some());
        let _ = fs::remove_file(path);
    }

    /// Puts `listener` into XNU's `SS_DRAINING` state: block a thread in
    /// `accept` on a duplicate descriptor, then close that duplicate. The close
    /// drains the shared socket, waking the blocked `accept` with
    /// `ECONNABORTED`, and the original descriptor stays open but poisoned.
    #[cfg(target_os = "macos")]
    fn drain_listener(listener: &UnixListener) {
        // SAFETY: dup of a descriptor we own; the copy is closed below.
        let duplicate = unsafe { libc::dup(listener.as_raw_fd()) };
        assert!(duplicate >= 0, "dup listener");
        let (done_tx, done_rx) = mpsc::channel();
        let blocked = thread::spawn(move || {
            // SAFETY: accept on an open listening descriptor; the peer address
            // is not requested.
            let rc = unsafe { libc::accept(duplicate, std::ptr::null_mut(), std::ptr::null_mut()) };
            let error = std::io::Error::last_os_error();
            let _ = done_tx.send((rc, error.raw_os_error()));
        });
        thread::sleep(Duration::from_millis(200));
        // SAFETY: closes only the duplicate, while the thread above is blocked
        // in accept on it.
        unsafe { libc::close(duplicate) };
        let (rc, errno) = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("closing the descriptor wakes the blocked accept");
        blocked.join().expect("blocked accept thread joins");
        assert_eq!(
            (rc, errno),
            (-1, Some(libc::ECONNABORTED)),
            "the listener must now be draining for this test to mean anything"
        );
    }

    fn wait_for_socket(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("socket was not created");
    }

    fn daemon() -> LocalDaemon {
        LocalDaemon::new(
            MachineIdentity {
                machine_id: "machine_test".to_string(),
                installation_id: "install_test".to_string(),
                display_name: "Test Mac".to_string(),
                hostname: "test-mac.local".to_string(),
                os: OperatingSystem::Macos,
                arch: "arm64".to_string(),
                local_platform_version: "0.1.0".to_string(),
                hardware_uuid: None,
                account_scope: None,
            },
            ControlToken::new("token").expect("token"),
            "2026-05-05T09:30:00Z",
        )
    }
}
