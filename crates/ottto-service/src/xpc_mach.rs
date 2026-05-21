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
extern "C" {
    fn ottto_xpc_serve(
        mach_service: *const c_char,
        handler: extern "C" fn(*const c_char, libc::pid_t, *mut c_void) -> *mut c_char,
        context: *mut c_void,
    ) -> c_int;
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
    context: *mut c_void,
) -> *mut c_char {
    if request_json.is_null() || context.is_null() {
        return null_response();
    }

    let daemon = unsafe { &*(context as *const LocalDaemon) };
    let request = unsafe { CStr::from_ptr(request_json) }
        .to_string_lossy()
        .into_owned();
    let peer = if peer_pid > 0 {
        Some(LocalClientPeer::from_pid(peer_pid as u32))
    } else {
        None
    };
    let response = handle_request_json_with_peer(daemon, &request, peer);
    c_string_or_null(&response)
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
