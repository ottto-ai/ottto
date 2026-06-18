use crate::{OTTTO_SERVICE_SOCKET_NAME, OTTTO_SOCKET_ENV};
use anyhow::{Context, Result};
use ottto_protocol::{LocalControlRequest, LocalControlResponse};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::path::PathBuf;
use std::time::Duration;

const LOCAL_CONTROL_SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

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
}

#[cfg(unix)]
fn request_unix_socket_with_timeout(
    path: &std::path::Path,
    request: &LocalControlRequest,
    timeout: Duration,
) -> Result<LocalControlResponse> {
    use std::os::unix::net::UnixStream;

    let mut stream =
        UnixStream::connect(path).with_context(|| format!("connect socket {}", path.display()))?;
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
    Ok(serde_json::from_str(&response)
        .with_context(|| format!("parse socket response {}", path.display()))?)
}

#[cfg(not(unix))]
pub fn request_unix_socket(
    path: &std::path::Path,
    _request: &LocalControlRequest,
) -> Result<LocalControlResponse> {
    anyhow::bail!("unix socket transport is not supported: {}", path.display())
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
            error.to_string().contains("read socket response"),
            "{error:#}"
        );
        let _ = std::fs::remove_file(&path);
        server.join().expect("timeout test server joins");
    }
}
