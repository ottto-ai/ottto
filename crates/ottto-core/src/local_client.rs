use crate::{OTTTO_SERVICE_SOCKET_NAME, OTTTO_SOCKET_ENV};
use anyhow::{Context, Result};
use ottto_protocol::{LocalControlRequest, LocalControlResponse};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::path::PathBuf;

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
    use std::os::unix::net::UnixStream;

    let mut stream =
        UnixStream::connect(path).with_context(|| format!("connect socket {}", path.display()))?;
    let request = serde_json::to_vec(request)?;
    stream.write_all(&request)?;
    stream.shutdown(Shutdown::Write)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(serde_json::from_str(&response)?)
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
}
