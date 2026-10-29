//! Reusable synthetic entity-ACK sink. Binds only IPv4 loopback; no outbound I/O.
#![cfg(any(test, feature = "replay-harness"))]
use super::current_rfc3339;
use ottto_core::{
    FileDeviceStore, LocalDeviceBinding, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
    OTTTO_SECRET_FALLBACK_DIR_ENV,
};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

pub(super) type BatchObserver =
    Arc<dyn Fn(&serde_json::Value) -> std::io::Result<()> + Send + Sync>;

type RequestObserver = Arc<dyn Fn(&str, &serde_json::Value) -> std::io::Result<()> + Send + Sync>;

pub(super) fn thread_cpu_us() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime fills `now`.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) },
        0
    );
    now.tv_sec as u64 * 1_000_000 + now.tv_nsec as u64 / 1_000
}

#[derive(Default)]
pub(super) struct BackendStats {
    /// CPU of the backend thread, which shares this process; subtracted from
    /// every page's process CPU.
    pub(super) cpu_us: AtomicU64,
    pub(super) batches: AtomicU64,
    pub(super) items: AtomicU64,
    #[cfg(test)]
    pub(super) literal_items: AtomicU64,
    pub(super) body_bytes: AtomicU64,
    #[cfg(test)]
    pub(super) fingerprints: Mutex<Vec<String>>,
}

/// In-process backend that accepts everything with entity ACKs (the routes
/// of the reason re-offer pipeline's accept path).
pub(super) struct Backend {
    pub(super) url: String,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    pub(super) stats: Arc<BackendStats>,
}

fn entity_ack(item: &serde_json::Value) -> serde_json::Value {
    let mut payload = serde_json::Map::new();
    for key in [
        "session_account_evidence",
        "tool_usage",
        "tool_usage_truncated",
    ] {
        if let Some(value) = item.get(key) {
            payload.insert(key.into(), value.clone());
        }
    }
    let exclusive = item
        .get("usage_accounting_contract")
        .and_then(|v| v.as_str())
        == Some("session_exclusive_reported_usage:v1");
    let version = item
        .get("session_account_evidence")
        .is_some()
        .then_some(if exclusive { 8u64 } else { 7u64 });
    let digest = format!(
        "{:x}",
        Sha256::digest(
            crate::canonical_json::canonicalize(&serde_json::Value::Object(payload)).unwrap()
        )
    );
    serde_json::json!({"source_session_id": item["source_session_id"],
        "snapshot_fingerprint": item["snapshot_fingerprint"], "occurrence_count": 1,
        "body_witness_version": version, "body_witness_digest": version.map(|_| digest)})
}

impl Backend {
    #[cfg(test)]
    pub(super) fn start() -> Self {
        Self::with_listener(
            std::net::TcpListener::bind("127.0.0.1:0").expect("loopback listener"),
            None,
        )
        .expect("bind isolated loopback backend")
    }

    pub(super) fn with_listener(
        listener: std::net::TcpListener,
        observer: Option<BatchObserver>,
    ) -> std::io::Result<Self> {
        Self::with_observers(listener, observer, None)
    }

    #[cfg(test)]
    pub(super) fn with_request_observer(
        listener: std::net::TcpListener,
        observer: Option<BatchObserver>,
        request_observer: RequestObserver,
    ) -> std::io::Result<Self> {
        Self::with_observers(listener, observer, Some(request_observer))
    }

    fn with_observers(
        listener: std::net::TcpListener,
        observer: Option<BatchObserver>,
        request_observer: Option<RequestObserver>,
    ) -> std::io::Result<Self> {
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(BackendStats::default());
        let (done, seen) = (stop.clone(), stats.clone());
        let worker = std::thread::spawn(move || -> std::io::Result<()> {
            let mut source = "claude_code".to_string();
            while !done.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let started = thread_cpu_us();
                stream.set_nonblocking(false)?;
                let request = read_complete_http_request(&mut stream)?;
                let head = request.lines().next().unwrap_or_default().to_string();
                let raw = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
                let value: serde_json::Value = if raw.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_str(raw)?
                };
                if let Some(observer) = &request_observer {
                    observer(&head, &value)?;
                }
                if head.contains("/relay-token") {
                    if let Some(selected @ ("claude_code" | "codex" | "pi")) =
                        value["source"].as_str()
                    {
                        source = selected.to_string();
                    }
                }
                let response = if head.contains("/relay-token") {
                    serde_json::json!({"token": "synthetic-e2-bench-token", "expires_at": "2099-01-01T00:00:00Z"})
                } else if head.contains("/activity-hints") {
                    serde_json::json!({"source": source, "server_time": current_rfc3339(),
                        "last_data_at": null, "record_count_15m": 0, "record_count_24h": 0,
                        "local_usage_reconciliation_enabled": true, "backfill_window_days": 183,
                        "recommended_scan_after": "2099-01-01T00:00:00Z"})
                } else if head.contains("/agent-status/snapshots") {
                    serde_json::json!({"accepted": 1, "machine_id": "otm_test", "sources": [source]})
                } else if let Some(items) = value.get("snapshots").and_then(|v| v.as_array()) {
                    if let Some(observer) = &observer {
                        observer(&value)?;
                    }
                    seen.batches.fetch_add(1, Ordering::Relaxed);
                    seen.items.fetch_add(items.len() as u64, Ordering::Relaxed);
                    seen.body_bytes
                        .fetch_add(raw.len() as u64, Ordering::Relaxed);
                    #[cfg(test)]
                    {
                        let literal = items
                            .iter()
                            .filter(|item| {
                                item["usage_accounting_contract"].as_str()
                                    == Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT)
                            })
                            .count();
                        seen.literal_items
                            .fetch_add(literal as u64, Ordering::Relaxed);
                    }
                    #[cfg(test)]
                    seen.fingerprints
                        .lock()
                        .unwrap()
                        .extend(items.iter().filter_map(|item| {
                            item["snapshot_fingerprint"].as_str().map(str::to_string)
                        }));
                    serde_json::json!({"accepted": items.len(), "sessions_reconciled": items.len(),
                        "session_ids": [], "disabled": false, "disabled_reason": null,
                        "entity_ack_contract": crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
                        "accepted_entities": items.iter().map(entity_ack).collect::<Vec<_>>(),
                        "unchanged_entities": [], "rejected_entities": [], "conflict_entities": []})
                } else {
                    serde_json::json!({"accepted": true, "source": source, "machine_id": "otm_test", "disabled": false})
                };
                bounded_native_response(&mut stream, "200 OK", &response.to_string())?;
                seen.cpu_us
                    .fetch_add(thread_cpu_us().saturating_sub(started), Ordering::Relaxed);
            }
            Ok(())
        });
        Ok(Self {
            url,
            stop,
            worker: Some(worker),
            stats,
        })
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            #[cfg(test)]
            if !std::thread::panicking() {
                result.expect("loopback worker").expect("loopback I/O");
            }
            #[cfg(not(test))]
            let _ = result; // A failed request never ACKs; the client reports failure.
        }
    }
}

// Requests are already capped by the production batch builder. Reject malformed
// local clients rather than retaining an unbounded request in this helper.
fn read_complete_http_request(stream: &mut std::net::TcpStream) -> std::io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut request = Vec::new();
    let mut buffer = [0; 8192];
    while !http_request_complete(&request) {
        if request.len() >= 64 * 1024 * 1024 {
            return Err(std::io::Error::other("loopback request bound"));
        }
        let n = stream.read(&mut buffer)?;
        if n == 0 {
            return Err(std::io::Error::other("incomplete loopback request"));
        }
        request.extend_from_slice(&buffer[..n]);
    }
    String::from_utf8(request).map_err(std::io::Error::other)
}
fn http_request_complete(request: &[u8]) -> bool {
    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let header = String::from_utf8_lossy(&request[..end]);
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    request.len().saturating_sub(end + 4) >= length
}
fn bounded_native_response(
    stream: &mut std::net::TcpStream,
    status: &str,
    body: &str,
) -> std::io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

/// Process environment is changed only by an isolated harness process or a
/// serialized synthetic bench. Restore it on all normal/unwind exits.
pub(super) struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}
impl EnvVarGuard {
    #[cfg(feature = "replay-harness")]
    pub(super) fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, previous }
    }
    pub(super) fn set_path(key: &'static str, value: &Path) -> Self {
        Self::set_str(key, value.as_os_str())
    }
    pub(super) fn set_str(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

pub(super) fn synthetic_device(
    support: &Path,
    secrets: &Path,
    url: &str,
    sources: Vec<String>,
) -> anyhow::Result<(LocalDeviceBinding, Vec<EnvVarGuard>)> {
    let guards = vec![
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support),
        EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, secrets),
        EnvVarGuard::set_str("OTTTO_API_BASE_URL", url),
    ];
    let device = LocalDeviceBinding {
        device_id: "e2-bench-device".into(),
        machine_id: Some("otm_test".into()),
        sources,
    };
    FileDeviceStore::default().save(&device)?;
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )?;
    Ok((device, guards))
}
