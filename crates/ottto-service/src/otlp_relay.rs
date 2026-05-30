use crate::control::handle_request;
use crate::snapshot_client::load_snapshot_device_credentials;
use crate::snapshots::SnapshotSource;
use crate::LocalDaemon;
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ottto_core::FileConnectionStore;
use ottto_protocol::{
    LocalControlCommand, LocalControlRequest, RelayRuntimeState, RelayState, StableMessage,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const LOCAL_RELAY_DEFAULT_PORT: u16 = 43119;
pub const CLAUDE_CODE_RELAY_PORT: u16 = LOCAL_RELAY_DEFAULT_PORT;
pub const LOCAL_RELAY_HEADER: &str = "X-Ottto-Local-Relay";
pub const CODEX_RELAY_SOURCE: &str = "codex";
pub const CLAUDE_CODE_RELAY_SOURCE: &str = "claude_code";

const DEFAULT_API_BASE_URL: &str = "https://ottto.net/backend";
const LOCAL_RELAY_FALLBACK_BASE_PORT: u16 = 44120;
const LOCAL_RELAY_FALLBACK_SPAN: u16 = 2000;
const LOCAL_RELAY_FALLBACK_ATTEMPTS: u16 = 24;
const MAX_OTLP_BODY_BYTES: usize = 25 * 1024 * 1024;
const RELAY_TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(30);
/// Per-connection read/write timeout. A local client that never finishes
/// sending its request line + headers (classic slowloris) — or that stops
/// reading our response — trips this and is dropped instead of pinning a
/// worker thread forever.
const RELAY_IO_TIMEOUT: Duration = Duration::from_secs(20);
/// Maximum bytes accepted for a single request line or header line. Caps the
/// per-line heap allocation a client can force with one unterminated line.
const MAX_HEADER_LINE_BYTES: usize = 16 * 1024;
/// Maximum cumulative bytes accepted across all header lines (request line
/// excluded). Caps total head allocation independent of per-line size.
const MAX_HEADER_TOTAL_BYTES: usize = 64 * 1024;
/// Maximum number of header lines accepted before the terminating blank line.
const MAX_HEADER_COUNT: usize = 100;
/// Maximum number of relay connections handled at once. Bounds the blast
/// radius of a local flood: connections over the cap are rejected with 503
/// without spawning an unbounded worker.
const MAX_CONCURRENT_RELAY_CONNECTIONS: usize = 128;

/// Live count of in-flight relay connections, released via [`ConnectionGuard`].
static ACTIVE_RELAY_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// RAII guard that reserves one in-flight connection slot on construction and
/// releases it on drop, so the count is always restored on handler exit even
/// across early returns, errors, or panics.
struct ConnectionGuard;

impl ConnectionGuard {
    /// Reserves a connection slot. Returns `None` (and reserves nothing) when
    /// the cap is already reached, so the caller can reject without spawning.
    fn acquire() -> Option<Self> {
        // Reserve optimistically, then roll back if we exceeded the cap. This
        // keeps acquisition lock-free; the brief over-count is bounded by the
        // number of concurrent acquirers and never leaks a slot.
        if ACTIVE_RELAY_CONNECTIONS.fetch_add(1, Ordering::SeqCst)
            >= MAX_CONCURRENT_RELAY_CONNECTIONS
        {
            ACTIVE_RELAY_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ConnectionGuard)
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_RELAY_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct RelayTokenResponse {
    token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RelayTokenCacheKey {
    api_base_url: String,
    source: &'static str,
}

#[derive(Debug, Clone)]
struct CachedRelayToken {
    token: String,
    refresh_after: SystemTime,
}

static RELAY_TOKEN_CACHE: OnceLock<Mutex<BTreeMap<RelayTokenCacheKey, CachedRelayToken>>> =
    OnceLock::new();
static UPSTREAM_HTTP_AGENT: OnceLock<ureq::Agent> = OnceLock::new();

pub fn spawn_local_otlp_relay(daemon: LocalDaemon) -> Result<SocketAddr> {
    spawn_source_relay(daemon, SnapshotSource::ClaudeCode)
}

pub fn spawn_claude_code_relay(daemon: LocalDaemon) -> Result<SocketAddr> {
    spawn_local_otlp_relay(daemon)
}

fn spawn_source_relay(daemon: LocalDaemon, source: SnapshotSource) -> Result<SocketAddr> {
    let (listener, _port) = match bind_local_relay_listener() {
        Ok(bound) => bound,
        Err(error) => {
            let _ = daemon.set_relay_state_for_trusted_client(RelayState {
                state: RelayRuntimeState::Failed,
                endpoint: Some(default_local_relay_base_url()),
                last_connected_at: None,
                last_error: Some(StableMessage {
                    code: "relay_bind_failed".to_string(),
                    text: format!(
                        "Could not bind local OTLP relay on 127.0.0.1:{LOCAL_RELAY_DEFAULT_PORT} or a per-user fallback port."
                    ),
                }),
            });
            return Err(error);
        }
    };
    let local_addr = listener.local_addr()?;
    let endpoint = format!("http://{local_addr}");
    let _ = daemon.set_relay_state_for_trusted_client(RelayState {
        state: RelayRuntimeState::Connected,
        endpoint: Some(endpoint.clone()),
        last_connected_at: Some(current_rfc3339()),
        last_error: None,
    });

    thread::spawn(move || {
        for incoming in listener.incoming() {
            match incoming {
                Ok(mut stream) => {
                    // Bound per-connection I/O time before doing anything else
                    // so a slow or stalled client trips the timeout instead of
                    // blocking a worker thread forever.
                    apply_relay_io_timeouts(&stream);

                    // Cap simultaneously-handled connections. Over the cap we
                    // reject with 503 on the accept thread without spawning an
                    // unbounded worker, so a local flood can't exhaust threads
                    // or memory. The guard releases the slot on handler exit.
                    let Some(guard) = ConnectionGuard::acquire() else {
                        let _ = write_json_response(
                            &mut stream,
                            503,
                            json!({"error":"relay_busy","message":"Too many concurrent local relay connections"}),
                        );
                        continue;
                    };

                    let client_daemon = daemon.clone();
                    thread::spawn(move || {
                        let _guard = guard;
                        if let Err(error) = handle_client(stream, source, client_daemon) {
                            // BrokenPipe / ConnectionReset are routine when the
                            // upstream agent (Codex / Claude Code) times out
                            // before we finish writing the response — drop
                            // those silently so we don't fill the daemon log
                            // with one line per disconnected client. Slow-client
                            // I/O timeouts are likewise routine. Everything else
                            // still surfaces.
                            if !client_disconnect_during_write(&error) {
                                eprintln!("local OTLP relay request failed: {error}");
                            }
                        }
                    });
                }
                Err(error) => {
                    eprintln!("local OTLP relay listener failed: {error}");
                    break;
                }
            }
        }
    });

    Ok(local_addr)
}

fn bind_local_relay_listener() -> Result<(TcpListener, u16)> {
    let mut last_error = None;
    for port in candidate_relay_ports(current_uid()) {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        match TcpListener::bind(bind_addr) {
            Ok(listener) => {
                if port != LOCAL_RELAY_DEFAULT_PORT {
                    eprintln!(
                        "local OTLP relay default port {LOCAL_RELAY_DEFAULT_PORT} is unavailable; using fallback port {port}"
                    );
                }
                return Ok((listener, port));
            }
            Err(error) => {
                last_error = Some(error);
            }
        }
    }

    let error = last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("no local OTLP relay ports were available"));
    Err(error).context("bind local OTLP relay")
}

/// Apply the read and write timeout to an accepted relay stream. A best-effort
/// operation: if the platform rejects the timeout we proceed without it rather
/// than dropping an otherwise-valid connection.
fn apply_relay_io_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(RELAY_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(RELAY_IO_TIMEOUT));
}

pub fn default_local_relay_base_url() -> String {
    local_relay_base_url_for_port(LOCAL_RELAY_DEFAULT_PORT)
}

pub fn local_relay_base_url_for_port(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

pub fn local_relay_port_from_endpoint(endpoint: &str) -> Option<u16> {
    let without_scheme = endpoint
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| endpoint.strip_prefix("http://localhost:"))?;
    let port = without_scheme
        .split('/')
        .next()
        .and_then(|value| value.parse::<u16>().ok())?;
    Some(port)
}

pub fn local_relay_base_url_from_state(relay: &RelayState) -> String {
    relay
        .endpoint
        .as_deref()
        .and_then(local_relay_port_from_endpoint)
        .map(local_relay_base_url_for_port)
        .unwrap_or_else(default_local_relay_base_url)
}

pub fn local_relay_port_from_state(relay: &RelayState) -> u16 {
    relay
        .endpoint
        .as_deref()
        .and_then(local_relay_port_from_endpoint)
        .unwrap_or(LOCAL_RELAY_DEFAULT_PORT)
}

fn candidate_relay_ports(uid: u32) -> Vec<u16> {
    let mut ports = Vec::with_capacity(usize::from(LOCAL_RELAY_FALLBACK_ATTEMPTS) + 1);
    push_unique_port(&mut ports, LOCAL_RELAY_DEFAULT_PORT);
    let start = fallback_relay_port_for_uid(uid);
    for offset in 0..LOCAL_RELAY_FALLBACK_ATTEMPTS {
        let relative =
            ((start - LOCAL_RELAY_FALLBACK_BASE_PORT) + offset) % LOCAL_RELAY_FALLBACK_SPAN;
        push_unique_port(&mut ports, LOCAL_RELAY_FALLBACK_BASE_PORT + relative);
    }
    ports
}

fn push_unique_port(ports: &mut Vec<u16>, port: u16) {
    if !ports.contains(&port) {
        ports.push(port);
    }
}

fn fallback_relay_port_for_uid(uid: u32) -> u16 {
    LOCAL_RELAY_FALLBACK_BASE_PORT + (uid % u32::from(LOCAL_RELAY_FALLBACK_SPAN)) as u16
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getuid has no preconditions and does not mutate Rust-managed memory.
        unsafe { libc::getuid() as u32 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn handle_client(mut stream: TcpStream, source: SnapshotSource, daemon: LocalDaemon) -> Result<()> {
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            write_json_response(
                &mut stream,
                400,
                json!({"error":"bad_request","message": error.to_string()}),
            )?;
            return Ok(());
        }
    };

    if request.path == "/control" {
        return handle_control_request(&mut stream, &daemon, request);
    }

    if request.method == "GET" && request.path == "/healthz" {
        return write_json_response(&mut stream, 200, relay_health_payload(source));
    }

    if request.method != "POST"
        || !matches!(
            request.path.as_str(),
            "/v1/logs" | "/v1/metrics" | "/v1/traces"
        )
    {
        return write_json_response(
            &mut stream,
            404,
            json!({"error":"not_found","message":"Unsupported local relay endpoint"}),
        );
    }

    let request_source = source_from_request(&request).unwrap_or(source);
    match forward_otlp_request(request_source, &request) {
        Ok(response) => write_raw_response(
            &mut stream,
            response.status,
            &response.content_type,
            &response.body,
        ),
        Err(error) => write_json_response(
            &mut stream,
            502,
            json!({"error":"relay_forward_failed","message": error.to_string()}),
        ),
    }
}

fn handle_control_request(
    stream: &mut TcpStream,
    daemon: &LocalDaemon,
    request: HttpRequest,
) -> Result<()> {
    let origin = request.headers.get("origin").map(String::as_str);
    if let Some(origin) = origin {
        if !is_allowed_control_origin(origin) {
            return write_json_response(
                stream,
                403,
                json!({"error":"origin_forbidden","message":"Origin is not allowed for local Ottto control"}),
            );
        }
    }
    let cors_headers = control_cors_headers(origin);

    if request.method == "OPTIONS" {
        return write_raw_response_with_headers(
            stream,
            204,
            "application/json",
            b"",
            &cors_headers,
        );
    }

    if request.method != "POST" {
        return write_json_response_with_headers(
            stream,
            404,
            json!({"error":"not_found","message":"Unsupported local control endpoint"}),
            &cors_headers,
        );
    }

    let control_request = match serde_json::from_slice::<LocalControlRequest>(&request.body) {
        Ok(request) => request,
        Err(error) => {
            return write_json_response_with_headers(
                stream,
                400,
                json!({"error":"bad_request","message": format!("Invalid local control request: {error}")}),
                &cors_headers,
            )
        }
    };
    if !matches!(
        &control_request.command,
        LocalControlCommand::TelemetryControl { .. }
    ) {
        return write_json_response_with_headers(
            stream,
            400,
            json!({"error":"unsupported_command","message":"Browser local control only accepts telemetry_control"}),
            &cors_headers,
        );
    }

    let response = handle_request(daemon, control_request);
    write_json_response_with_headers(stream, 200, serde_json::to_value(response)?, &cors_headers)
}

fn control_cors_headers(origin: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "Access-Control-Allow-Methods".to_string(),
            "POST, OPTIONS".to_string(),
        ),
        (
            "Access-Control-Allow-Headers".to_string(),
            "Content-Type".to_string(),
        ),
        (
            "Access-Control-Allow-Private-Network".to_string(),
            "true".to_string(),
        ),
        ("Access-Control-Max-Age".to_string(), "300".to_string()),
        (
            "Vary".to_string(),
            "Origin, Access-Control-Request-Private-Network".to_string(),
        ),
    ];
    if let Some(origin) = origin {
        headers.push((
            "Access-Control-Allow-Origin".to_string(),
            origin.to_string(),
        ));
    }
    headers
}

fn is_allowed_control_origin(origin: &str) -> bool {
    matches!(origin, "https://ottto.net" | "https://www.ottto.net")
        || is_loopback_origin(origin, "http", "localhost")
        || is_loopback_origin(origin, "http", "127.0.0.1")
        || is_loopback_origin(origin, "https", "localhost")
        || is_loopback_origin(origin, "https", "127.0.0.1")
}

fn is_loopback_origin(origin: &str, scheme: &str, host: &str) -> bool {
    let prefix = format!("{scheme}://{host}");
    let Some(suffix) = origin.strip_prefix(&prefix) else {
        return false;
    };
    suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()))
}

fn source_from_request(request: &HttpRequest) -> Option<SnapshotSource> {
    request
        .headers
        .get(&LOCAL_RELAY_HEADER.to_ascii_lowercase())
        .and_then(|value| source_from_relay_header(value))
}

fn source_from_relay_header(value: &str) -> Option<SnapshotSource> {
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        CODEX_RELAY_SOURCE => Some(SnapshotSource::Codex),
        CLAUDE_CODE_RELAY_SOURCE => Some(SnapshotSource::ClaudeCode),
        _ => None,
    }
}

struct ForwardResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

fn forward_otlp_request(source: SnapshotSource, request: &HttpRequest) -> Result<ForwardResponse> {
    let api_base_url = current_api_base_url();
    let relay_token = cached_relay_token(&api_base_url, source)?;
    let response = send_otlp_request(&api_base_url, &relay_token, request)?;
    if response.status != 401 {
        return Ok(response);
    }

    evict_cached_relay_token(&api_base_url, source)?;
    let relay_token = cached_relay_token(&api_base_url, source)?;
    send_otlp_request(&api_base_url, &relay_token, request)
}

fn send_otlp_request(
    api_base_url: &str,
    relay_token: &str,
    request: &HttpRequest,
) -> Result<ForwardResponse> {
    let url = format!("{}{}", api_base_url.trim_end_matches('/'), request.path);
    let content_type = request
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or("application/x-protobuf");
    let mut upstream = upstream_http_agent()
        .post(&url)
        .set("Accept", "application/json")
        .set("Authorization", &format!("Bearer {relay_token}"))
        .set("Content-Type", content_type);
    if let Some(encoding) = request.headers.get("content-encoding") {
        upstream = upstream.set("Content-Encoding", encoding);
    }

    match upstream.send_bytes(&request.body) {
        Ok(response) => response_from_ureq(response),
        Err(ureq::Error::Status(_, response)) => response_from_ureq(response),
        Err(ureq::Error::Transport(error)) => Err(anyhow!("upstream transport failed: {error}")),
    }
}

fn cached_relay_token(api_base_url: &str, source: SnapshotSource) -> Result<String> {
    let key = RelayTokenCacheKey {
        api_base_url: api_base_url.trim_end_matches('/').to_string(),
        source: source.api_slug(),
    };
    let now = SystemTime::now();
    if let Some(token) = {
        let cache = relay_token_cache()
            .lock()
            .map_err(|_| anyhow!("relay token cache lock poisoned"))?;
        cache
            .get(&key)
            .filter(|entry| entry.refresh_after > now)
            .map(|entry| entry.token.clone())
    } {
        return Ok(token);
    }

    let token = issue_relay_token(api_base_url, source)?;
    let refresh_after = relay_token_refresh_after(&token, now);
    let mut cache = relay_token_cache()
        .lock()
        .map_err(|_| anyhow!("relay token cache lock poisoned"))?;
    cache.insert(
        key,
        CachedRelayToken {
            token: token.clone(),
            refresh_after,
        },
    );
    Ok(token)
}

fn evict_cached_relay_token(api_base_url: &str, source: SnapshotSource) -> Result<()> {
    let key = RelayTokenCacheKey {
        api_base_url: api_base_url.trim_end_matches('/').to_string(),
        source: source.api_slug(),
    };
    let mut cache = relay_token_cache()
        .lock()
        .map_err(|_| anyhow!("relay token cache lock poisoned"))?;
    cache.remove(&key);
    Ok(())
}

fn relay_token_cache() -> &'static Mutex<BTreeMap<RelayTokenCacheKey, CachedRelayToken>> {
    RELAY_TOKEN_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn upstream_http_agent() -> &'static ureq::Agent {
    UPSTREAM_HTTP_AGENT.get_or_init(|| ureq::AgentBuilder::new().build())
}

fn relay_token_refresh_after(token: &str, now: SystemTime) -> SystemTime {
    relay_token_expires_at(token)
        .and_then(|expires_at| expires_at.checked_sub(RELAY_TOKEN_REFRESH_SKEW))
        .filter(|refresh_after| *refresh_after > now)
        .unwrap_or(now)
}

fn relay_token_expires_at(token: &str) -> Option<SystemTime> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let exp = value.get("exp")?.as_u64()?;
    Some(UNIX_EPOCH + Duration::from_secs(exp))
}

fn response_from_ureq(response: ureq::Response) -> Result<ForwardResponse> {
    let status = response.status();
    let content_type = response
        .header("content-type")
        .unwrap_or("application/json")
        .to_string();
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .context("read upstream response")?;
    Ok(ForwardResponse {
        status,
        content_type,
        body,
    })
}

fn issue_relay_token(api_base_url: &str, source: SnapshotSource) -> Result<String> {
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let url = format!(
        "{}/api/v1/telemetry/devices/{}/relay-token",
        api_base_url.trim_end_matches('/'),
        device.device_id
    );
    let response: RelayTokenResponse = upstream_http_agent()
        .post(&url)
        .set("Accept", "application/json")
        .set("X-Ottto-Device-Secret", &device_secret)
        .send_json(json!({ "source": source.api_slug() }))
        .map_err(|error| anyhow!("issue relay token failed: {error}"))?
        .into_json()
        .map_err(|error| anyhow!("parse relay token response failed: {error}"))?;
    Ok(response.token)
}

fn current_api_base_url() -> String {
    FileConnectionStore::default()
        .load()
        .ok()
        .flatten()
        .map(|binding| binding.api_base_url)
        .or_else(|| std::env::var("OTTTO_API_BASE_URL").ok())
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

fn relay_health_payload(source: SnapshotSource) -> serde_json::Value {
    let api_base_url = current_api_base_url();
    let device_id = load_snapshot_device_credentials()
        .ok()
        .map(|(device, _)| device.device_id)
        .unwrap_or_else(|| "missing".to_string());
    json!({
        "ok": device_id != "missing",
        "source": source.api_slug(),
        "state_fingerprint": state_fingerprint(source, &api_base_url, &device_id),
    })
}

fn state_fingerprint(source: SnapshotSource, api_base_url: &str, device_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.api_slug().as_bytes());
    hasher.update(b"\0");
    hasher.update(api_base_url.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_id.as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    read_http_request_from(&mut reader)
}

/// Parse an HTTP request from any buffered reader. Split out from
/// [`read_http_request`] so the bounded request-line/header parsing can be
/// unit-tested without a socket. The request line and every header line are
/// read with [`read_line_limited`] (per-line cap), the header section is
/// bounded by cumulative byte and count caps, and the body keeps the existing
/// [`MAX_OTLP_BODY_BYTES`] cap.
fn read_http_request_from<R: BufRead>(reader: &mut R) -> Result<HttpRequest> {
    let mut request_line = String::new();
    let read = read_line_limited(reader, &mut request_line, MAX_HEADER_LINE_BYTES)
        .context("read request line")?;
    if read == 0 {
        return Err(anyhow!("empty request"));
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("missing method"))?;
    let path = parts.next().ok_or_else(|| anyhow!("missing path"))?;
    if !path.starts_with('/') {
        return Err(anyhow!("invalid path"));
    }
    let method = method.to_ascii_uppercase();
    let path = path.to_string();

    let mut headers = BTreeMap::new();
    let mut header_bytes_total: usize = 0;
    let mut header_count: usize = 0;
    loop {
        let mut line = String::new();
        let read =
            read_line_limited(reader, &mut line, MAX_HEADER_LINE_BYTES).context("read header")?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            // A zero-length read means EOF before the terminating blank line;
            // an empty trimmed line is the blank line itself. Either way the
            // header section ends here.
            break;
        }
        header_count += 1;
        if header_count > MAX_HEADER_COUNT {
            return Err(anyhow!("too many request headers"));
        }
        header_bytes_total = header_bytes_total.saturating_add(read);
        if header_bytes_total > MAX_HEADER_TOTAL_BYTES {
            return Err(anyhow!("request headers too large"));
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .context("parse content-length")?
        .unwrap_or(0);
    if content_length > MAX_OTLP_BODY_BYTES {
        return Err(anyhow!("request body too large"));
    }
    let mut body = vec![0; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).context("read body")?;
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

/// Read a single line (up to and including the terminating `\n`) into `buf`,
/// but fail once more than `max` bytes have been consumed without reaching the
/// newline. This bounds the per-line heap allocation an unbounded
/// `BufRead::read_line` would otherwise allow, closing the "stream one giant
/// header line" memory-exhaustion path. Returns the number of bytes appended;
/// `0` means EOF was reached with no bytes read.
fn read_line_limited<R: BufRead>(
    reader: &mut R,
    buf: &mut String,
    max: usize,
) -> io::Result<usize> {
    let start_len = buf.len();
    // Cap the reader at `max` bytes for this line. A well-formed line of at
    // most `max` bytes (including its trailing `\n`) is read in full; a longer
    // line is truncated before its newline, so the missing terminator below
    // signals "over-long" without ever allocating past the cap.
    let mut limited = reader.take(max as u64);
    let read = limited.read_line(buf)?;
    if read == 0 {
        return Ok(0);
    }
    let line = &buf[start_len..];
    if !line.ends_with('\n') {
        // We pulled at least one byte but never reached a newline within the
        // cap. Either the line is over-long or the stream ended mid-line;
        // either way the request head is malformed/oversized — reject it.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request line exceeds maximum length",
        ));
    }
    Ok(read)
}

fn write_json_response(stream: &mut TcpStream, status: u16, body: serde_json::Value) -> Result<()> {
    write_json_response_with_headers(stream, status, body, &[])
}

fn write_json_response_with_headers(
    stream: &mut TcpStream,
    status: u16,
    body: serde_json::Value,
    headers: &[(String, String)],
) -> Result<()> {
    let body = serde_json::to_vec(&body)?;
    write_raw_response_with_headers(stream, status, "application/json", &body, headers)
}

fn write_raw_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    write_raw_response_with_headers(stream, status, content_type, body, &[])
}

fn write_raw_response_with_headers(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    headers: &[(String, String)],
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        status,
        reason_phrase(status),
        content_type,
        body.len()
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

fn current_rfc3339() -> String {
    Command::new("/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// Walk the anyhow chain looking for an `io::Error` that's a routine
/// "client went away or stalled" pattern. Used to decide whether to bother
/// logging a relay failure — these happen any time an OTLP client closes the
/// socket before we finish writing the response, or trickles/stalls its
/// request until the per-connection [`RELAY_IO_TIMEOUT`] fires. A socket
/// read/write timeout surfaces as `WouldBlock` on Unix and `TimedOut` on
/// Windows, so both are treated as routine.
fn client_disconnect_during_write(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io_error| {
            matches!(
                io_error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_fingerprint_is_short_and_stable() {
        let first = state_fingerprint(
            SnapshotSource::ClaudeCode,
            "https://ottto.test/backend",
            "device_1",
        );
        let second = state_fingerprint(
            SnapshotSource::ClaudeCode,
            "https://ottto.test/backend",
            "device_1",
        );

        assert_eq!(first, second);
        assert_eq!(first.len(), 16);
    }

    #[test]
    fn client_disconnect_during_write_recognises_routine_io_errors() {
        let broken_pipe: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Broken pipe (os error 32)").into();
        let connection_reset: anyhow::Error = std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "Connection reset by peer (os error 54)",
        )
        .into();
        // Wrap to mimic the way anyhow nests errors when callers add context.
        let wrapped: anyhow::Error = anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ))
        .context("write response");

        assert!(client_disconnect_during_write(&broken_pipe));
        assert!(client_disconnect_during_write(&connection_reset));
        assert!(client_disconnect_during_write(&wrapped));

        // Slow-client socket timeouts are routine too: a read/write timeout
        // surfaces as TimedOut (Windows) or WouldBlock (Unix), and both mean
        // the per-connection RELAY_IO_TIMEOUT fired rather than a real fault.
        let timed_out: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out").into();
        let would_block: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block").into();
        assert!(client_disconnect_during_write(&timed_out));
        assert!(client_disconnect_during_write(&would_block));

        // Non-I/O errors and unrelated I/O errors must still surface.
        let not_found: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::NotFound, "not found").into();
        let plain = anyhow::anyhow!("relay device binding is missing");
        assert!(!client_disconnect_during_write(&not_found));
        assert!(!client_disconnect_during_write(&plain));
    }

    #[test]
    fn relay_source_header_routes_codex_separately_from_claude_code() {
        assert_eq!(
            source_from_relay_header("codex"),
            Some(SnapshotSource::Codex)
        );
        assert_eq!(
            source_from_relay_header("claude_code"),
            Some(SnapshotSource::ClaudeCode)
        );
        assert_eq!(
            source_from_relay_header("CLAUDE-CODE"),
            Some(SnapshotSource::ClaudeCode)
        );
        assert_eq!(source_from_relay_header("unknown"), None);
    }

    #[test]
    fn relay_candidates_try_default_before_user_fallbacks() {
        let ports = candidate_relay_ports(501);

        assert_eq!(ports.first().copied(), Some(LOCAL_RELAY_DEFAULT_PORT));
        assert_eq!(
            ports.get(1).copied(),
            Some(LOCAL_RELAY_FALLBACK_BASE_PORT + 501)
        );
        assert_eq!(ports.len(), usize::from(LOCAL_RELAY_FALLBACK_ATTEMPTS) + 1);
    }

    #[test]
    fn relay_endpoint_helpers_accept_loopback_only() {
        assert_eq!(
            local_relay_port_from_endpoint("http://127.0.0.1:44121/v1/logs"),
            Some(44121)
        );
        assert_eq!(
            local_relay_port_from_endpoint("http://localhost:44122"),
            Some(44122)
        );
        assert_eq!(local_relay_port_from_endpoint("https://ottto.net"), None);

        let relay = RelayState {
            state: RelayRuntimeState::Connected,
            endpoint: Some("http://127.0.0.1:44121".to_string()),
            last_connected_at: Some("2026-05-25T00:00:00Z".to_string()),
            last_error: None,
        };
        assert_eq!(local_relay_port_from_state(&relay), 44121);
        assert_eq!(
            local_relay_base_url_from_state(&relay),
            "http://127.0.0.1:44121"
        );
    }

    #[test]
    fn control_origin_allowlist_accepts_production_and_loopback_only() {
        assert!(is_allowed_control_origin("https://ottto.net"));
        assert!(is_allowed_control_origin("http://localhost:3000"));
        assert!(is_allowed_control_origin("http://127.0.0.1:3001"));
        assert!(!is_allowed_control_origin("https://ottto.net.evil"));
        assert!(!is_allowed_control_origin("http://127.0.0.1.evil:3000"));
    }

    #[test]
    fn control_cors_headers_allow_private_network_preflight() {
        let headers = control_cors_headers(Some("https://ottto.net"))
            .into_iter()
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("https://ottto.net")
        );
        assert_eq!(
            headers
                .get("Access-Control-Allow-Private-Network")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            headers.get("Vary").map(String::as_str),
            Some("Origin, Access-Control-Request-Private-Network")
        );
    }

    #[test]
    fn relay_token_expiry_is_read_from_jwt_payload_without_verification() {
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
        let token = format!("header.{payload}.signature");

        assert_eq!(
            relay_token_expires_at(&token),
            Some(UNIX_EPOCH + Duration::from_secs(4_102_444_800))
        );
    }

    #[test]
    fn relay_token_refreshes_before_expiry() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":1090}"#);
        let token = format!("header.{payload}.signature");

        assert_eq!(
            relay_token_refresh_after(&token, now),
            UNIX_EPOCH + Duration::from_secs(1_060)
        );
    }

    #[test]
    fn relay_token_with_near_expiry_refreshes_immediately() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":1020}"#);
        let token = format!("header.{payload}.signature");

        assert_eq!(relay_token_refresh_after(&token, now), now);
    }

    #[test]
    fn read_http_request_parses_well_formed_post() {
        let body = b"hello-otlp";
        let raw = format!(
            "POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut bytes = raw.into_bytes();
        bytes.extend_from_slice(body);
        let mut reader = BufReader::new(bytes.as_slice());

        let request = read_http_request_from(&mut reader).expect("request parses");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/logs");
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/x-protobuf")
        );
        assert_eq!(request.body, body);
    }

    #[test]
    fn read_http_request_parses_bodyless_get() {
        let raw = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        let mut reader = BufReader::new(raw.as_bytes());

        let request = read_http_request_from(&mut reader).expect("request parses");
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/healthz");
        assert!(request.body.is_empty());
    }

    #[test]
    fn read_http_request_rejects_over_long_header_line() {
        let mut raw = String::from("POST /v1/logs HTTP/1.1\r\nX-Big: ");
        raw.push_str(&"a".repeat(MAX_HEADER_LINE_BYTES + 64));
        raw.push_str("\r\n\r\n");
        let mut reader = BufReader::new(raw.as_bytes());

        let error = read_http_request_from(&mut reader).expect_err("over-long line rejected");
        assert!(
            error.to_string().contains("read header")
                || error.to_string().contains("exceeds maximum length"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn read_http_request_rejects_cumulative_header_bytes() {
        // Each header line stays under the per-line cap, but together they
        // exceed the cumulative byte cap.
        let mut raw = String::from("POST /v1/logs HTTP/1.1\r\n");
        let value = "b".repeat(MAX_HEADER_LINE_BYTES / 2);
        let lines_needed = (MAX_HEADER_TOTAL_BYTES / value.len()) + 2;
        for index in 0..lines_needed {
            raw.push_str(&format!("X-Pad-{index}: {value}\r\n"));
        }
        raw.push_str("\r\n");
        let mut reader = BufReader::new(raw.as_bytes());

        let error =
            read_http_request_from(&mut reader).expect_err("cumulative header bytes rejected");
        assert!(
            error.to_string().contains("headers too large"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn read_http_request_rejects_excess_header_count() {
        let mut raw = String::from("POST /v1/logs HTTP/1.1\r\n");
        for index in 0..(MAX_HEADER_COUNT + 5) {
            raw.push_str(&format!("X-H-{index}: v\r\n"));
        }
        raw.push_str("\r\n");
        let mut reader = BufReader::new(raw.as_bytes());

        let error = read_http_request_from(&mut reader).expect_err("excess header count rejected");
        assert!(
            error.to_string().contains("too many request headers"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn read_http_request_rejects_oversized_body_via_content_length() {
        let raw = format!(
            "POST /v1/logs HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_OTLP_BODY_BYTES + 1
        );
        let mut reader = BufReader::new(raw.as_bytes());

        let error = read_http_request_from(&mut reader).expect_err("oversized body rejected");
        assert!(
            error.to_string().contains("request body too large"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn read_line_limited_accepts_line_at_cap_and_rejects_beyond() {
        // A line whose bytes (including the newline) total exactly the cap is
        // accepted.
        let at_cap = format!("{}\n", "x".repeat(15));
        assert_eq!(at_cap.len(), 16);
        let mut reader = BufReader::new(at_cap.as_bytes());
        let mut buf = String::new();
        let read = read_line_limited(&mut reader, &mut buf, 16).expect("at-cap line accepted");
        assert_eq!(read, 16);
        assert_eq!(buf, at_cap);

        // One byte over the cap is rejected before the newline is reached.
        let over_cap = format!("{}\n", "x".repeat(16));
        let mut reader = BufReader::new(over_cap.as_bytes());
        let mut buf = String::new();
        let error =
            read_line_limited(&mut reader, &mut buf, 16).expect_err("over-cap line rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_line_limited_reports_eof_as_zero() {
        let mut reader = BufReader::new(&b""[..]);
        let mut buf = String::new();
        let read = read_line_limited(&mut reader, &mut buf, 16).expect("eof is not an error");
        assert_eq!(read, 0);
        assert!(buf.is_empty());
    }

    // The two ConnectionGuard tests both mutate the shared
    // ACTIVE_RELAY_CONNECTIONS static, so serialize them against each other to
    // keep their counter assertions deterministic under the parallel test
    // runner.
    static CONNECTION_GUARD_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn connection_guard_increments_and_releases_on_drop() {
        let _serial = CONNECTION_GUARD_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let baseline = ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst);
        {
            let _guard = ConnectionGuard::acquire().expect("slot available");
            assert_eq!(
                ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst),
                baseline + 1
            );
        }
        assert_eq!(ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst), baseline);
    }

    #[test]
    fn connection_guard_rejects_over_the_cap_without_leaking_slots() {
        let _serial = CONNECTION_GUARD_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let baseline = ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst);
        // Saturate the remaining slots up to the cap.
        let mut guards = Vec::new();
        while ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst) < MAX_CONCURRENT_RELAY_CONNECTIONS {
            guards.push(ConnectionGuard::acquire().expect("slot available below cap"));
        }
        assert_eq!(
            ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst),
            MAX_CONCURRENT_RELAY_CONNECTIONS
        );

        // At the cap, acquisition is refused and the rejected attempt must not
        // leave the counter inflated.
        assert!(ConnectionGuard::acquire().is_none());
        assert_eq!(
            ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst),
            MAX_CONCURRENT_RELAY_CONNECTIONS
        );

        drop(guards);
        assert_eq!(ACTIVE_RELAY_CONNECTIONS.load(Ordering::SeqCst), baseline);
    }
}
