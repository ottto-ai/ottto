#[cfg(target_os = "macos")]
use crate::control::{handle_request_json_with_peer, LocalClientPeer};
use crate::LocalDaemon;
#[cfg(target_os = "macos")]
use anyhow::Context;
use anyhow::Result;
#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "macos")]
use std::os::raw::{c_char, c_int, c_void};
#[cfg(target_os = "macos")]
use std::thread;

#[cfg(target_os = "macos")]
const XPC_CONTROL_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn ottto_xpc_serve(
        mach_service: *const c_char,
        handler: extern "C" fn(*const c_char, libc::pid_t, libc::uid_t, *mut c_void) -> *mut c_char,
        context: *mut c_void,
    ) -> c_int;
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn ottto_xpc_start_signer(
        mach_service: *const c_char,
        peer_requirement: *const c_char,
        handler: extern "C" fn(*const c_char, u64, *mut c_void) -> *mut c_char,
        closed: extern "C" fn(u64, *mut c_void),
        context: *mut c_void,
    ) -> c_int;
}

/// Opens the Mac app's signer channel on `mach_service`, beside the control listener, when this
/// service may serve it (`control::cloud_connect::signer_peer_requirement`). Any failure is logged
/// and leaves the signer unavailable; it never stops the service. Call it before
/// [`serve_xpc_mach_service`], whose `dispatch_main()` also serves this listener.
#[cfg(target_os = "macos")]
pub fn start_signer_listener(mach_service: &str, daemon: LocalDaemon) {
    use crate::control::cloud_connect;

    let requirement = match cloud_connect::signer_peer_requirement() {
        Ok(requirement) => requirement,
        Err(off) => {
            eprintln!("signer channel off: {}", off.reason());
            return;
        }
    };
    let (Ok(name), Ok(peer_requirement)) = (
        CString::new(mach_service),
        CString::new(requirement.as_str()),
    ) else {
        eprintln!("signer channel off: its name or requirement contains NUL");
        return;
    };
    // Owned by the listener for the life of the process once it starts.
    let context = Box::into_raw(Box::new(daemon)) as *mut c_void;
    let rc = unsafe {
        ottto_xpc_start_signer(
            name.as_ptr(),
            peer_requirement.as_ptr(),
            handle_signer_request,
            signer_connection_closed,
            context,
        )
    };
    if rc != 0 {
        unsafe {
            drop(Box::from_raw(context as *mut LocalDaemon));
        }
        eprintln!("signer channel off: its listener failed to start with status {rc}");
        return;
    }
    cloud_connect::signer_listening(requirement);
    eprintln!("serving the signer channel on {mach_service}");
}

#[cfg(target_os = "macos")]
extern "C" fn handle_signer_request(
    request_json: *const c_char,
    connection_id: u64,
    context: *mut c_void,
) -> *mut c_char {
    const SIGNER_INTERNAL: &str =
        r#"{"signer_protocol":1,"id":"","ok":false,"error":{"code":"internal"}}"#;
    if request_json.is_null() || context.is_null() {
        return c_string_or_null(SIGNER_INTERNAL);
    }
    let daemon = unsafe { &*(context as *const LocalDaemon) }.clone();
    let request = unsafe { CStr::from_ptr(request_json) }
        .to_string_lossy()
        .into_owned();
    let response = join_worker("ottto-xpc-signer", move || {
        crate::control::cloud_connect::handle_signer_request_json(&daemon, connection_id, &request)
    })
    .unwrap_or_else(|| SIGNER_INTERNAL.to_string());
    c_string_or_null(&response)
}

#[cfg(target_os = "macos")]
extern "C" fn signer_connection_closed(connection_id: u64, _context: *mut c_void) {
    // A panic must not unwind into libxpc.
    let _ = std::panic::catch_unwind(|| {
        crate::control::cloud_connect::signer_connection_closed(connection_id);
    });
}

#[cfg(target_os = "macos")]
pub fn serve_xpc_mach_service(mach_service: &str, daemon: LocalDaemon) -> Result<()> {
    let mach_service = CString::new(mach_service).context("Mach service name contains NUL")?;
    let context = Box::into_raw(Box::new(daemon)) as *mut c_void;
    let rc = unsafe { ottto_xpc_serve(mach_service.as_ptr(), handle_xpc_request, context) };

    // dispatch_main() never returns during normal service operation. If the C shim
    // does return, reclaim the daemon context and report the failure.
    unsafe {
        drop(Box::from_raw(context as *mut LocalDaemon));
    }
    if rc == 0 {
        Ok(())
    } else {
        anyhow::bail!("XPC listener failed to start with status {rc}")
    }
}

#[cfg(not(target_os = "macos"))]
pub fn serve_xpc_mach_service(_mach_service: &str, _daemon: LocalDaemon) -> Result<()> {
    anyhow::bail!("XPC Mach services are supported only on macOS")
}

#[cfg(target_os = "macos")]
extern "C" fn handle_xpc_request(
    request_json: *const c_char,
    peer_pid: libc::pid_t,
    peer_euid: libc::uid_t,
    context: *mut c_void,
) -> *mut c_char {
    let mut stage =
        crate::local_resource_diagnostics::StageWindow::begin("unknown", "offpass_control_xpc");
    if request_json.is_null() || context.is_null() {
        crate::control_plane_health::record_request_error();
        return null_response();
    }

    let daemon = unsafe { &*(context as *const LocalDaemon) }.clone();
    let request = unsafe { CStr::from_ptr(request_json) }
        .to_string_lossy()
        .into_owned();
    let pid = if peer_pid > 0 {
        Some(peer_pid as u32)
    } else {
        None
    };
    // The shim already rejected peers whose euid != the daemon euid at the
    // connection level; capturing the euid here lets the control layer re-assert
    // the match as defense in depth. On macOS `libc::uid_t` is `u32`.
    let peer = Some(LocalClientPeer::from_pid_and_euid(pid, Some(peer_euid)));
    let (response, control) = run_control_on_xpc_worker(daemon, request, peer);
    stage.control = control;
    c_string_or_null(&response)
}

#[cfg(target_os = "macos")]
fn run_control_on_xpc_worker(
    daemon: LocalDaemon,
    request: String,
    peer: Option<LocalClientPeer>,
) -> (String, std::collections::BTreeMap<&'static str, u64>) {
    // The worker hands back its request's counts; none (a panic) counts as other.
    let (sent, counts) = std::sync::mpsc::channel();
    let response = run_xpc_worker(move || {
        let response = handle_request_json_with_peer(&daemon, &request, peer);
        let _ = sent.send(crate::local_resource_diagnostics::take_control());
        response
    });
    let other = || std::collections::BTreeMap::from([("other", 1)]);
    (response, counts.try_recv().unwrap_or_else(|_| other()))
}

#[cfg(target_os = "macos")]
fn run_xpc_worker<F>(operation: F) -> String
where
    F: FnOnce() -> String + Send + 'static,
{
    match join_worker("ottto-xpc-control", operation) {
        Some(response) => {
            crate::control_plane_health::record_request_served();
            response
        }
        None => {
            crate::control_plane_health::record_request_error();
            internal_error_response()
        }
    }
}

/// Runs `operation` on its own thread with the control stack size and waits for it. `None` when
/// the thread could not start or panicked.
#[cfg(target_os = "macos")]
fn join_worker<F>(name: &str, operation: F) -> Option<String>
where
    F: FnOnce() -> String + Send + 'static,
{
    let worker = thread::Builder::new()
        .name(name.to_string())
        .stack_size(XPC_CONTROL_THREAD_STACK_BYTES)
        .spawn(operation);
    match worker {
        Ok(handle) => handle.join().ok(),
        Err(error) => {
            eprintln!("failed to spawn {name} worker: {error}");
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn c_string_or_null(value: &str) -> *mut c_char {
    match CString::new(value) {
        Ok(value) => unsafe { libc::strdup(value.as_ptr()) },
        Err(_) => null_response(),
    }
}

#[cfg(target_os = "macos")]
fn null_response() -> *mut c_char {
    c_string_or_null(
        r#"{"request_id":"req_xpc_invalid","ok":false,"payload":null,"error":{"code":"internal","message":"XPC request failed","retryable":false,"details":{}}}"#,
    )
}

#[cfg(target_os = "macos")]
fn internal_error_response() -> String {
    r#"{"request_id":"req_xpc_internal","ok":false,"payload":null,"error":{"code":"internal","message":"XPC request failed","retryable":false,"details":{}}}"#.to_string()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::ControlToken;
    use ottto_protocol::{
        LocalControlResponse, MachineIdentity, OperatingSystem, PROTOCOL_VERSION,
    };

    #[test]
    fn xpc_worker_returns_local_control_response() {
        let request = format!(
            r#"{{"request_id":"req_xpc_worker","protocol_version":{PROTOCOL_VERSION},"token":"token","client_kind":"cli","command":"status"}}"#
        );

        let (response, control) = run_control_on_xpc_worker(daemon(), request, None);
        let response: LocalControlResponse =
            serde_json::from_str(&response).expect("local control response");

        assert_eq!(response.request_id, "req_xpc_worker");
        assert!(response.ok);
        assert_eq!(control, std::collections::BTreeMap::from([("status", 1)]));
    }

    #[test]
    fn xpc_worker_converts_panic_to_internal_error() {
        let response = run_xpc_worker(|| panic!("worker panic"));
        let response: LocalControlResponse =
            serde_json::from_str(&response).expect("local control response");

        assert_eq!(response.request_id, "req_xpc_internal");
        assert!(!response.ok);
        assert_eq!(response.error.expect("error").message, "XPC request failed");
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
            "2026-05-05T09:20:00Z",
        )
    }
}
