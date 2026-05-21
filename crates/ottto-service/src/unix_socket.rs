use crate::control::{handle_request_with_peer, LocalClientPeer};
use crate::LocalDaemon;
use anyhow::{Context, Result};
use ottto_protocol::{CliError, CliErrorCode, LocalControlRequest, LocalControlResponse};
use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

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
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("remove stale socket {}", path.display()))?;
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create socket parent {}", parent.display()))?;
    }

    let listener = bind_user_only_socket(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod socket {}", path.display()))?;

    for (served, stream) in listener.incoming().enumerate() {
        let mut stream = stream.with_context(|| format!("accept socket {}", path.display()))?;
        let peer = local_client_peer(&stream);
        let response = match read_request(&mut stream) {
            Ok(request) => handle_request_with_peer(&daemon, request, peer),
            Err(error) => invalid_request_response(&error.to_string()),
        };
        write_response(&mut stream, &response)?;
        if max_requests.is_some_and(|limit| served + 1 >= limit) {
            break;
        }
    }
    Ok(())
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

fn bind_user_only_socket(path: &Path) -> Result<UnixListener> {
    let _guard = RestrictiveSocketUmask::new();
    UnixListener::bind(path).with_context(|| format!("bind socket {}", path.display()))
}

struct RestrictiveSocketUmask {
    previous: libc::mode_t,
}

impl RestrictiveSocketUmask {
    fn new() -> Self {
        // Unix domain sockets inherit permissions from the process umask at bind time.
        // Use owner-only permissions before the socket appears, then restore immediately.
        let previous = unsafe { libc::umask(0o177) };
        Self { previous }
    }
}

impl Drop for RestrictiveSocketUmask {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.previous);
        }
    }
}

fn local_client_peer(stream: &UnixStream) -> Option<LocalClientPeer> {
    peer_pid(stream).map(LocalClientPeer::from_pid)
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
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
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
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(serde_json::from_slice(&body)?)
}

fn write_response(stream: &mut UnixStream, response: &LocalControlResponse) -> Result<()> {
    let response = serde_json::to_vec(response)?;
    stream.write_all(&response)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlToken, LocalDaemon};
    use ottto_core::request_unix_socket;
    use ottto_protocol::{
        LocalClientKind, LocalControlCommand, LocalControlRequest, MachineIdentity,
        OperatingSystem, LOCAL_CONTROL_PROTOCOL_VERSION,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
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
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        )
        .expect("socket request should succeed");

        server.join().expect("server thread should join").unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
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
            },
            ControlToken::new("token").expect("token"),
            "2026-05-05T09:30:00Z",
        )
    }
}
