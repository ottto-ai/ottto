use crate::{OTTTO_SERVICE_SOCKET_NAME, OTTTO_SOCKET_ENV};
use anyhow::{Context, Result};
use ottto_protocol::{LocalControlRequest, LocalControlResponse};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::path::PathBuf;
use std::time::Duration;

/// Read/write bound for ordinary control-socket commands. These reply quickly,
/// so a tight bound surfaces a wedged daemon fast.
pub const LOCAL_CONTROL_SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// Read/write bound for agent-status refresh commands. The daemon refreshes
/// agent status by collecting and uploading telemetry for every connected
/// source **serially** (Codex, Claude Code, Pi), and each source's
/// collect+upload round-trip can take ~18s in the worst case — far over the 10s
/// ordinary bound. Too short a bound here makes a slow-but-alive refresh look
/// like a dead daemon, so refresh commands get a budget well above the summed
/// server-side worst case.
pub const LOCAL_CONTROL_REFRESH_TIMEOUT: Duration = Duration::from_secs(180);

/// Why a control-socket round-trip failed, so the caller can decide whether an
/// autostart kickstart is warranted.
#[derive(Debug)]
pub enum LocalRequestError {
    /// The control socket could not be connected: the daemon is not accepting
    /// connections (not running, wrong socket path). Autostarting it is the
    /// right recovery.
    Connect(anyhow::Error),
    /// The connection succeeded but the request/response round-trip failed
    /// (write, read timeout, or parse). A read timeout here means the daemon is
    /// alive but busy; kickstarting it would needlessly restart healthy work.
    Transport(anyhow::Error),
}

impl LocalRequestError {
    /// True when the failure happened before a connection was established, i.e.
    /// the daemon is not accepting connections and an autostart is warranted.
    pub fn is_connect_failure(&self) -> bool {
        matches!(self, LocalRequestError::Connect(_))
    }

    /// Unwrap to the underlying error for callers that only need the message.
    pub fn into_anyhow(self) -> anyhow::Error {
        match self {
            LocalRequestError::Connect(error) | LocalRequestError::Transport(error) => error,
        }
    }
}

impl std::fmt::Display for LocalRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalRequestError::Connect(error) | LocalRequestError::Transport(error) => {
                write!(f, "{error:#}")
            }
        }
    }
}

impl std::error::Error for LocalRequestError {}

pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var(OTTTO_SOCKET_ENV) {
        return PathBuf::from(path);
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Ottto")
            .join(OTTTO_SERVICE_SOCKET_NAME);
    }

    std::env::temp_dir().join(OTTTO_SERVICE_SOCKET_NAME)
}

#[cfg(unix)]
pub fn request_unix_socket(
    path: &std::path::Path,
    request: &LocalControlRequest,
) -> Result<LocalControlResponse> {
    request_unix_socket_with_timeout(path, request, LOCAL_CONTROL_SOCKET_TIMEOUT)
        .map_err(LocalRequestError::into_anyhow)
}

/// Like [`request_unix_socket`] but with a caller-chosen read/write timeout, and
/// a typed error that distinguishes a pre-connect failure (the daemon is not
/// accepting connections) from a post-connect transport failure (the daemon is
/// alive but the round-trip stalled or failed). Callers use that distinction to
/// avoid kickstarting a daemon that is merely busy.
#[cfg(unix)]
pub fn request_unix_socket_with_timeout(
    path: &std::path::Path,
    request: &LocalControlRequest,
    timeout: Duration,
) -> std::result::Result<LocalControlResponse, LocalRequestError> {
    use std::os::unix::net::UnixStream;

    // A failure to connect means the daemon is not accepting connections; an
    // autostart is the right recovery for it.
    let mut stream = UnixStream::connect(path)
        .with_context(|| format!("connect socket {}", path.display()))
        .map_err(LocalRequestError::Connect)?;

    // Once connected, every remaining step (timeout setup, write, read, parse)
    // is a transport failure: the daemon is alive, so a read timeout means it is
    // busy, not absent.
    let mut exchange = || -> Result<LocalControlResponse> {
        stream
            .set_write_timeout(Some(timeout))
            .with_context(|| format!("set socket write timeout {}", path.display()))?;
        stream
            .set_read_timeout(Some(timeout))
            .with_context(|| format!("set socket read timeout {}", path.display()))?;
        let request = serde_json::to_vec(request)?;
        stream
            .write_all(&request)
            .with_context(|| format!("write socket request {}", path.display()))?;
        stream
            .shutdown(Shutdown::Write)
            .with_context(|| format!("finish socket request {}", path.display()))?;

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .with_context(|| format!("read socket response {}", path.display()))?;
        serde_json::from_str(&response)
            .with_context(|| format!("parse socket response {}", path.display()))
    };

    exchange().map_err(LocalRequestError::Transport)
}

#[cfg(not(unix))]
pub fn request_unix_socket(
    path: &std::path::Path,
    _request: &LocalControlRequest,
) -> Result<LocalControlResponse> {
    anyhow::bail!("unix socket transport is not supported: {}", path.display())
}

#[cfg(not(unix))]
pub fn request_unix_socket_with_timeout(
    path: &std::path::Path,
    _request: &LocalControlRequest,
    _timeout: Duration,
) -> std::result::Result<LocalControlResponse, LocalRequestError> {
    Err(LocalRequestError::Connect(anyhow::anyhow!(
        "unix socket transport is not supported: {}",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{LocalClientKind, LocalControlCommand, LOCAL_CONTROL_PROTOCOL_VERSION};

    fn status_request() -> LocalControlRequest {
        LocalControlRequest {
            request_id: "req_local_client_status".to_string(),
            protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Status {
                refresh_agent_status: false,
            },
        }
    }

    #[test]
    fn default_socket_path_uses_env_override() {
        let old = std::env::var(OTTTO_SOCKET_ENV).ok();
        std::env::set_var(OTTTO_SOCKET_ENV, "/tmp/ottto-test.sock");
        assert_eq!(default_socket_path(), PathBuf::from("/tmp/ottto-test.sock"));
        match old {
            Some(value) => std::env::set_var(OTTTO_SOCKET_ENV, value),
            None => std::env::remove_var(OTTTO_SOCKET_ENV),
        }
    }

    #[cfg(unix)]
    #[test]
    fn request_unix_socket_times_out_when_daemon_accepts_without_reply() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let path = std::env::temp_dir().join(format!(
            "ottto-local-client-timeout-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind timeout test socket");
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept timeout client");
            thread::sleep(Duration::from_millis(250));
        });

        let error =
            request_unix_socket_with_timeout(&path, &status_request(), Duration::from_millis(50))
                .expect_err("stalled daemon response should time out");
        assert!(
            matches!(error, LocalRequestError::Transport(_)),
            "a stalled reply after a successful connect is a transport failure, not a connect failure: {error:#}"
        );
        assert!(
            error.to_string().contains("read socket response"),
            "{error:#}"
        );
        let _ = std::fs::remove_file(&path);
        server.join().expect("timeout test server joins");
    }

    #[cfg(unix)]
    #[test]
    fn request_unix_socket_classifies_missing_daemon_as_connect_failure() {
        // No listener is bound, so the connect itself fails. That must be a
        // Connect error (autostart is the right recovery), never a Transport
        // error (which would imply an alive-but-busy daemon).
        let path = std::env::temp_dir().join(format!(
            "ottto-local-client-missing-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let error =
            request_unix_socket_with_timeout(&path, &status_request(), Duration::from_millis(50))
                .expect_err("connecting to a missing socket must fail");
        assert!(
            error.is_connect_failure(),
            "a missing daemon socket must classify as a connect failure: {error:#}"
        );
    }
}
