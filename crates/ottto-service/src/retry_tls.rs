//! The one rustls connector behind every ureq agent, and the absolute TLS I/O
//! deadline for optional snapshot turns. ureq's own `tls` feature stays off so
//! its webpki-roots 0.26 shim (RUSTSEC-2026-0381) never enters the build; the
//! connector below keeps ureq 2.12.1's built-in ring/TLS1.2+1.3/WebPKI client.
//! No thread or socket clone: pinned ureq performs its normal handshake over
//! the bounded deadline stream.
use std::io::{self, Read, Write};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use ureq::{ReadWrite, TlsConnector};

/// ureq 2.12.1's built-in client policy (src/rtls.rs `default_tls_config`):
/// ring, TLS 1.2 and 1.3, the patched WebPKI roots, no client auth, no ALPN.
fn webpki_client_config() -> Arc<rustls::ClientConfig> {
    client_config(rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    })
}
/// The policy above over `roots`. Only tests pass synthetic roots.
fn client_config(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    Arc::new(
        rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .expect("ring supports TLS 1.2 and TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

/// The connector ureq's `tls` feature installed on every agent. One
/// process-wide config, like ureq's lazy default, keeps session resumption
/// in its previous scope.
struct WebPkiTls {
    config: Arc<rustls::ClientConfig>,
}
fn default_connector() -> Arc<WebPkiTls> {
    static DEFAULT: OnceLock<Arc<WebPkiTls>> = OnceLock::new();
    DEFAULT
        .get_or_init(|| {
            Arc::new(WebPkiTls {
                config: webpki_client_config(),
            })
        })
        .clone()
}
/// Every ureq agent starts here: without ureq's `tls` feature a bare
/// `ureq::get` or `AgentBuilder::new()` refuses HTTPS. The inventory test
/// below keeps production code off those.
pub(crate) fn agent_builder() -> ureq::AgentBuilder {
    let builder = ureq::AgentBuilder::new().tls_connector(default_connector());
    guard_unit_test_egress(builder)
}

/// Also applied to the bounded agent, which installs a deadline TLS connector.
/// Production builds preserve their existing routing policy.
pub(crate) fn guard_unit_test_egress(builder: ureq::AgentBuilder) -> ureq::AgentBuilder {
    #[cfg(test)]
    let builder = builder.redirects(0).middleware(unit_test_loopback_only);
    builder
}
/// Test binaries have no external HTTP egress, even from background threads
/// after an environment fixture has dropped. Redirects are disabled above in
/// tests too: ureq invokes middleware only for the initial request.
#[cfg(test)]
#[allow(clippy::result_large_err)] // ureq middleware requires this unboxed Error type
fn unit_test_loopback_only(
    request: ureq::Request,
    next: ureq::MiddlewareNext<'_>,
) -> Result<ureq::Response, ureq::Error> {
    let url = request.request_url()?;
    let host = url.host().trim_start_matches('[').trim_end_matches(']');
    let local = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !local {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unit tests may only send HTTP requests to loopback fixtures",
        )
        .into());
    }
    next.handle(request)
}

/// A fresh agent per call, like the `ureq::get` shortcuts it replaces.
pub(crate) fn agent() -> ureq::Agent {
    agent_builder().build()
}
/// Every request that carries an Ottto credential in a header or its body
/// (relay device secret, setup-run, setup-claim and install-session tokens,
/// support claims, ingest keys) starts here. Pinned ureq follows 301/302/303
/// (and 307/308 for bodiless methods) and replays every header except
/// `Authorization` and `Cookie` to the `Location` target, so a misconfigured
/// or compromised server could collect the credential on another host. These
/// requests never follow a redirect; a 3xx comes back as an ordinary
/// unexpected response. Header values stay out of logs because the `log`
/// dependency compiles out ureq's debug-level request prelude (see the
/// workspace `Cargo.toml`).
pub(crate) fn credential_agent_builder() -> ureq::AgentBuilder {
    agent_builder().redirects(0)
}
pub(crate) fn credential_agent() -> ureq::Agent {
    credential_agent_builder().build()
}
impl TlsConnector for WebPkiTls {
    fn connect(
        &self,
        dns_name: &str,
        io: Box<dyn ReadWrite>,
    ) -> Result<Box<dyn ReadWrite>, ureq::Error> {
        rustls_connect(&self.config, dns_name, io)
    }
}

pub(crate) struct DeadlineTls {
    config: Arc<rustls::ClientConfig>,
    deadline: Instant,
}
pub(crate) fn connector(deadline: Instant) -> Arc<DeadlineTls> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(webpki_client_config);
    #[cfg(test)]
    let config = TEST_CONFIG
        .with(|c| c.borrow().clone())
        .unwrap_or_else(|| config.clone());
    Arc::new(DeadlineTls {
        config: config.clone(),
        deadline,
    })
}
impl TlsConnector for DeadlineTls {
    fn connect(
        &self,
        dns_name: &str,
        io: Box<dyn ReadWrite>,
    ) -> Result<Box<dyn ReadWrite>, ureq::Error> {
        if io.socket().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "bounded TLS requires a native socket",
            )
            .into());
        }
        let io = DeadlineIo {
            inner: io,
            deadline: self.deadline,
        };
        let tls = rustls_connect(&self.config, dns_name, Box::new(io))?;
        Ok(Box::new(ResponseHeaders {
            inner: tls,
            bytes: 0,
            wire_bytes: 0,
            line_bytes: 0,
            line_last_cr: false,
            complete: false,
        }))
    }
}

// The client config above, the connect step and the stream below are adapted
// from ureq 2.12.1 src/rtls.rs
// (https://github.com/algesten/ureq), Copyright (c) 2019 Martin Algesten,
// licensed MIT OR Apache-2.0; see NOTICE. Only error construction differs:
// ureq's `ErrorKind::msg` and `Error::src` are crate-private, so each failure
// is an `io::Error` that keeps the underlying I/O kind and carries a typed
// `TlsSetupError` naming the step.
#[allow(clippy::result_large_err)] // ureq's own `TlsConnector::connect` result
fn rustls_connect(
    config: &Arc<rustls::ClientConfig>,
    dns_name: &str,
    mut io: Box<dyn ReadWrite>,
) -> Result<Box<dyn ReadWrite>, ureq::Error> {
    #[cfg(test)]
    CONNECTS.with(|count| count.set(count.get() + 1));
    // rustls doesn't like ipv6 addresses with brackets
    let dns_name = dns_name
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
        .unwrap_or(dns_name);
    let sni = rustls::pki_types::ServerName::try_from(dns_name)
        .map_err(|e| {
            TlsSetupError::io(
                TlsSetupStep::ServerName(dns_name.to_string()),
                io::ErrorKind::InvalidInput,
                e,
            )
        })?
        .to_owned();
    let mut sess = rustls::ClientConnection::new(config.clone(), sni)
        .map_err(|e| TlsSetupError::io(TlsSetupStep::Session, io::ErrorKind::Other, e))?;
    sess.complete_io(&mut io)
        .map_err(|e| TlsSetupError::io(TlsSetupStep::Handshake, e.kind(), e))?;
    Ok(Box::new(RustlsStream(rustls::StreamOwned::new(sess, io))))
}

#[allow(deprecated)]
fn is_close_notify(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ConnectionAborted
        && e.get_ref()
            .is_some_and(|msg| msg.description().contains("CloseNotify"))
}

struct RustlsStream(rustls::StreamOwned<rustls::ClientConnection, Box<dyn ReadWrite>>);
impl ReadWrite for RustlsStream {
    // ureq applies its connect/read/write deadlines through this socket.
    fn socket(&self) -> Option<&std::net::TcpStream> {
        self.0.get_ref().socket()
    }
}
impl Read for RustlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.read(buf) {
            Ok(size) => Ok(size),
            Err(ref e) if is_close_notify(e) => Ok(0),
            Err(e) => Err(e),
        }
    }
}
impl Write for RustlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl std::fmt::Debug for RustlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RustlsStream").finish()
    }
}

/// The connect step that failed, with ureq's former messages.
#[derive(Debug)]
enum TlsSetupStep {
    ServerName(String),
    Session,
    Handshake,
}
/// A typed connector failure, so diagnostics keep the DNS / connect / I/O
/// categories ureq's built-in connector reported for each step.
#[derive(Debug)]
struct TlsSetupError {
    step: TlsSetupStep,
    source: Box<dyn std::error::Error + Send + Sync>,
}
impl TlsSetupError {
    fn io(
        step: TlsSetupStep,
        kind: io::ErrorKind,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> io::Error {
        io::Error::new(
            kind,
            Self {
                step,
                source: Box::new(source),
            },
        )
    }
    fn transport_kind(&self) -> ureq::ErrorKind {
        match self.step {
            TlsSetupStep::ServerName(_) => ureq::ErrorKind::Dns,
            TlsSetupStep::Session => ureq::ErrorKind::Io,
            TlsSetupStep::Handshake => ureq::ErrorKind::ConnectionFailed,
        }
    }
}
impl std::fmt::Display for TlsSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.step {
            TlsSetupStep::ServerName(name) => write!(f, "parsing '{name}'")?,
            TlsSetupStep::Session => f.write_str("tls connection creation failed")?,
            TlsSetupStep::Handshake => f.write_str("tls connection init failed")?,
        }
        write!(f, ": {}", self.source)
    }
}
impl std::error::Error for TlsSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}
/// A transport failure's ureq category. A failure from `rustls_connect`
/// reports the category ureq's built-in connector gave the same step.
pub(crate) fn transport_kind(transport: &ureq::Transport) -> ureq::ErrorKind {
    std::error::Error::source(transport)
        .and_then(|source| source.downcast_ref::<io::Error>())
        .and_then(io::Error::get_ref)
        .and_then(|inner| inner.downcast_ref::<TlsSetupError>())
        .map_or_else(|| transport.kind(), TlsSetupError::transport_kind)
}

/// ureq bounds individual header lines, not their aggregate. Limit plaintext
/// headers after the normal authenticated TLS handshake, before its parser can
/// retain many large lines. Each optional request uses a fresh, nonpooled agent.
const RESPONSE_HEADER_BYTES: usize = 16 * 1024;
// Bound encoded HTTP framing and compressed bytes before ureq's chunk-size
// decoder or gzip reader can allocate. Decoded bodies keep their smaller cap.
const RESPONSE_WIRE_BYTES: usize =
    crate::snapshot_retry::RESPONSE_BYTES * 2 + RESPONSE_HEADER_BYTES;
#[derive(Debug)]
struct ResponseHeaders {
    inner: Box<dyn ReadWrite>,
    bytes: usize,
    wire_bytes: usize,
    line_bytes: usize,
    line_last_cr: bool,
    complete: bool,
}
impl Read for ResponseHeaders {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let header_limit = if self.complete {
            bytes.len()
        } else {
            bytes
                .len()
                .min(RESPONSE_HEADER_BYTES.saturating_sub(self.bytes) + 1)
        };
        let limit = header_limit.min(RESPONSE_WIRE_BYTES.saturating_sub(self.wire_bytes) + 1);
        let read = self.inner.read(&mut bytes[..limit])?;
        self.wire_bytes += read;
        if self.wire_bytes > RESPONSE_WIRE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "optional snapshot encoded response exceeds admission limit",
            ));
        }
        for byte in &bytes[..read] {
            if self.complete {
                break;
            }
            self.bytes += 1;
            if self.bytes > RESPONSE_HEADER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "optional snapshot response headers exceed admission limit",
                ));
            }
            if *byte == b'\n' {
                // Pinned ureq strips exactly one trailing CR. Multiple CRs
                // are a malformed nonempty header, not the header terminator.
                self.complete = self.line_bytes == 0 || (self.line_bytes == 1 && self.line_last_cr);
                self.line_bytes = 0;
                self.line_last_cr = false;
            } else {
                self.line_bytes += 1;
                self.line_last_cr = *byte == b'\r';
            }
        }
        Ok(read)
    }
}
impl Write for ResponseHeaders {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl ReadWrite for ResponseHeaders {
    fn socket(&self) -> Option<&std::net::TcpStream> {
        self.inner.socket()
    }
}

// Synthetic native TLS fixtures change only their own thread's trust roots.
// Production still uses the unchanged pinned WebPKI/ring policy above.
#[cfg(test)]
thread_local! {
    static TEST_CONFIG: std::cell::RefCell<Option<Arc<rustls::ClientConfig>>> = const {
        std::cell::RefCell::new(None)
    };
    // Connector handshakes started on this thread, for path coverage tests.
    static CONNECTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(crate) fn with_test_config<T>(config: Arc<rustls::ClientConfig>, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Arc<rustls::ClientConfig>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_CONFIG.with(|c| {
                c.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(TEST_CONFIG.with(|c| c.replace(Some(config))));
    f()
}
#[derive(Debug)]
struct DeadlineIo {
    inner: Box<dyn ReadWrite>,
    deadline: Instant,
}
impl DeadlineIo {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "optional snapshot TLS deadline expired",
                )
            })
    }
    fn before_io(&self, read: bool) -> io::Result<()> {
        let remaining = self.remaining()?;
        let socket = self.inner.socket().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "bounded TLS socket disappeared")
        })?;
        // Preserve any shorter ureq connect/request/write timeout. Refresh the
        // absolute remainder before every handshake and post-handshake I/O;
        // partial records and repeated small reads cannot replenish it.
        if read {
            socket.set_read_timeout(Some(
                socket
                    .read_timeout()?
                    .map_or(remaining, |t| t.min(remaining)),
            ))
        } else {
            socket.set_write_timeout(Some(
                socket
                    .write_timeout()?
                    .map_or(remaining, |t| t.min(remaining)),
            ))
        }
    }
}
impl Read for DeadlineIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.before_io(true)?;
        self.inner.read(bytes)
    }
}
impl Write for DeadlineIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.before_io(false)?;
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.before_io(false)?;
        self.inner.flush()
    }
}
impl ReadWrite for DeadlineIo {
    fn socket(&self) -> Option<&std::net::TcpStream> {
        self.inner.socket()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_agent_keeps_custom_secret_headers_out_of_logs_and_redirects() {
        use super::credential_test_support::{
            assert_never_logged, install_host_logger, RedirectingBackend,
        };
        install_host_logger();
        for header in ["X-Ottto-Device-Secret"] {
            for status in ["302 Found", "307 Temporary Redirect"] {
                for method in ["GET", "POST"] {
                    let secret = format!("synthetic-{method}-{}", &status[..3]);
                    let backend = RedirectingBackend::start(status);
                    let url = format!("{}/api/v1/probe", backend.base_url);
                    let result = credential_agent()
                        .request(method, &url)
                        .set(header, &secret)
                        .timeout(Duration::from_secs(5))
                        .call();
                    let response = result.expect("an unfollowed 3xx is a response");
                    assert_eq!(response.status(), status[..3].parse::<u16>().unwrap());
                    let request = backend.finish();
                    assert!(request.contains(&format!("{header}: {secret}")));
                    assert_never_logged(&secret);
                }
            }
        }
    }
    #[derive(Debug)]
    struct Bytes(std::io::Cursor<Vec<u8>>);
    impl Read for Bytes {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            // Exercise header boundaries split over many native reads.
            let limit = bytes.len().min(31);
            self.0.read(&mut bytes[..limit])
        }
    }
    impl Write for Bytes {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl ReadWrite for Bytes {
        fn socket(&self) -> Option<&std::net::TcpStream> {
            None
        }
    }
    fn headers(bytes: Vec<u8>) -> ResponseHeaders {
        ResponseHeaders {
            inner: Box::new(Bytes(std::io::Cursor::new(bytes))),
            bytes: 0,
            wire_bytes: 0,
            line_bytes: 0,
            line_last_cr: false,
            complete: false,
        }
    }
    #[test]
    fn aggregate_header_cap_refuses_many_individually_legal_lines() {
        let mut stream = headers(
            format!(
                "HTTP/1.1 200 OK\r\nX: {}\r\nY: {}\r\n\r\n",
                "x".repeat(9000),
                "y".repeat(9000)
            )
            .into_bytes(),
        );
        assert_eq!(
            stream.read_to_end(&mut Vec::new()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn malformed_cr_header_does_not_disable_aggregate_limit() {
        let mut stream = headers(
            format!("HTTP/1.1 200 OK\r\n\r\r\nX: {}\r\n\r\n", "x".repeat(18_000)).into_bytes(),
        );
        assert_eq!(
            stream.read_to_end(&mut Vec::new()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn encoded_body_framing_is_capped_before_decode() {
        let mut stream = headers(
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}1\r\nx\r\n0\r\n\r\n",
                "0".repeat(RESPONSE_WIRE_BYTES)
            )
            .into_bytes(),
        );
        assert_eq!(
            stream.read_to_end(&mut Vec::new()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    // Synthetic trust only: each fixture mints throwaway loopback certificates.
    // No test contacts a live host or trusts anything outside its own fixture.
    struct Certificates(std::path::PathBuf);
    impl Certificates {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ottto-retry-tls-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn mint(
            &self,
            name: &str,
            subject_alt_names: &str,
        ) -> (
            rustls::pki_types::CertificateDer<'static>,
            rustls::pki_types::PrivateKeyDer<'static>,
        ) {
            use rustls::pki_types::pem::PemObject;
            std::fs::write(
                self.0.join(format!("{name}.cnf")),
                format!(
                    "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN={name}\n[ext]\nsubjectAltName={subject_alt_names}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                ),
            )
            .unwrap();
            let output = std::process::Command::new("/usr/bin/openssl")
                .args([
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                ])
                .arg("-config")
                .arg(format!("{name}.cnf"))
                .arg("-keyout")
                .arg(format!("{name}.key"))
                .arg("-out")
                .arg(format!("{name}.pem"))
                .current_dir(&self.0)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "synthetic certificate generation failed"
            );
            let certificate = rustls::pki_types::CertificateDer::from_pem_slice(
                &std::fs::read(self.0.join(format!("{name}.pem"))).unwrap(),
            )
            .unwrap();
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
                &std::fs::read(self.0.join(format!("{name}.key"))).unwrap(),
            )
            .unwrap();
            (certificate, key)
        }
    }
    impl Drop for Certificates {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn trusting(
        certificate: &rustls::pki_types::CertificateDer<'static>,
    ) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        client_config(roots)
    }
    fn serve(
        certificate: rustls::pki_types::CertificateDer<'static>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
        connections: usize,
    ) -> (u16, std::thread::JoinHandle<Vec<bool>>) {
        serve_on("127.0.0.1:0", certificate, key, connections)
    }
    /// Serve `connections` loopback TLS connections with one tiny response
    /// each; report whether each connection completed a request.
    fn serve_on(
        address: &str,
        certificate: rustls::pki_types::CertificateDer<'static>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
        connections: usize,
    ) -> (u16, std::thread::JoinHandle<Vec<bool>>) {
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap(),
        );
        let listener = std::net::TcpListener::bind(address).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut served = Vec::new();
            for _ in 0..connections {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, socket);
                let mut request = Vec::new();
                let mut bytes = [0; 1024];
                let complete = loop {
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break true;
                    }
                    match stream.read(&mut bytes) {
                        Ok(0) | Err(_) => break false,
                        Ok(count) => request.extend_from_slice(&bytes[..count]),
                    }
                };
                if complete {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    let _ = stream.flush();
                }
                served.push(complete);
            }
            served
        });
        (port, server)
    }
    fn connects() -> usize {
        CONNECTS.with(|count| count.get())
    }
    /// The rustls error behind a connector failure, through the typed chain.
    fn rustls_cause(error: &ureq::Error) -> Option<&rustls::Error> {
        let ureq::Error::Transport(transport) = error else {
            return None;
        };
        let setup = std::error::Error::source(transport)?
            .downcast_ref::<io::Error>()?
            .get_ref()?
            .downcast_ref::<TlsSetupError>()?;
        setup
            .source
            .downcast_ref::<io::Error>()?
            .get_ref()?
            .downcast_ref::<rustls::Error>()
    }
    fn kind_of(error: &ureq::Error) -> Option<ureq::ErrorKind> {
        match error {
            ureq::Error::Transport(transport) => Some(transport_kind(transport)),
            ureq::Error::Status(..) => None,
        }
    }
    fn result_class(error: ureq::Error) -> crate::provider_calls::CallResult {
        crate::provider_calls::http_result(&Err::<(), _>(error))
    }

    #[test]
    fn default_agent_uses_the_shared_webpki_connector() {
        assert!(Arc::ptr_eq(&default_connector(), &default_connector()));
        let certificates = Certificates::new("default");
        let (certificate, key) = certificates.mint("localhost", "DNS:localhost,IP:127.0.0.1");
        let (port, server) = serve(certificate, key, 1);
        let before = connects();
        // Production trust is the patched WebPKI root set: a synthetic
        // loopback certificate is an unknown issuer, never a missing backend.
        let error = agent()
            .get(&format!("https://localhost:{port}/"))
            .call()
            .unwrap_err();
        assert_eq!(connects(), before + 1);
        assert!(
            matches!(
                rustls_cause(&error),
                Some(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ),
            "{error}"
        );
        assert_eq!(kind_of(&error), Some(ureq::ErrorKind::ConnectionFailed));
        assert!(error.to_string().contains("tls connection init failed"));
        assert_eq!(
            result_class(error),
            crate::provider_calls::CallResult::Error("connect_error")
        );
        assert_eq!(server.join().unwrap(), vec![false]);
    }

    #[test]
    fn wrong_host_certificate_is_refused() {
        let certificates = Certificates::new("refused");
        let (certificate, key) = certificates.mint("wrong", "DNS:wrong.example");
        let tls = Arc::new(WebPkiTls {
            config: trusting(&certificate),
        });
        let agent = ureq::AgentBuilder::new().tls_connector(tls).build();
        let (port, server) = serve(certificate, key, 1);
        let error = agent
            .get(&format!("https://localhost:{port}/"))
            .call()
            .unwrap_err();
        assert!(
            matches!(
                rustls_cause(&error),
                Some(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForName
                        | rustls::CertificateError::NotValidForNameContext { .. }
                ))
            ),
            "{error}"
        );
        assert_eq!(kind_of(&error), Some(ureq::ErrorKind::ConnectionFailed));
        assert_eq!(server.join().unwrap(), vec![false]);
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn deadline_agent_shares_the_connector_and_bounds_a_stalled_handshake() {
        let certificates = Certificates::new("deadline");
        let (certificate, key) = certificates.mint("localhost", "DNS:localhost,IP:127.0.0.1");
        let config = trusting(&certificate);
        let (port, server) = serve(certificate, key, 1);
        let before = connects();
        let response = with_test_config(config.clone(), || {
            ureq::AgentBuilder::new()
                .tls_connector(connector(Instant::now() + Duration::from_secs(10)))
                .build()
                .get(&format!("https://localhost:{port}/"))
                .call()
        })
        .unwrap();
        assert_eq!(connects(), before + 1);
        assert_eq!(response.into_string().unwrap(), "ok");
        assert_eq!(server.join().unwrap(), vec![true]);

        // A peer that accepts TCP and never answers the ClientHello.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let (_socket, _) = listener.accept().unwrap();
            let _ = released.recv_timeout(Duration::from_secs(10));
        });
        let started = Instant::now();
        let error = with_test_config(config, || {
            ureq::AgentBuilder::new()
                .timeout_read(Duration::from_secs(30))
                .tls_connector(connector(Instant::now() + Duration::from_millis(300)))
                .build()
                .get(&format!("https://127.0.0.1:{port}/"))
                .call()
        })
        .unwrap_err();
        let elapsed = started.elapsed();
        release.send(()).unwrap();
        holder.join().unwrap();
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(connects(), before + 2);
        // The underlying I/O timeout survives the typed connector cause.
        assert_eq!(
            result_class(error),
            crate::provider_calls::CallResult::Timeout
        );
    }

    #[derive(Clone, Copy)]
    enum Scope {
        Production,
        TestModule,
        // A file compiled only inside a test module through `include!`.
        IncludedTestFile,
    }
    /// One permitted line holding a guarded token: exact file, exact trimmed
    /// line, scope and occurrence count. `{u}` stands for `ureq::` and `{x}`
    /// for nothing, so these lists never match themselves.
    struct Allowed {
        file: &'static str,
        line: &'static str,
        scope: Scope,
        count: usize,
        // Text the same builder chain must hold before `.build()`.
        chain: Option<&'static str>,
    }
    const ALLOWED: &[Allowed] = &[
        // Production: the shared connector, its config, and the bounded
        // snapshot agent's deadline connector.
        Allowed {
            file: "src/retry_tls.rs",
            line: "let builder = {u}AgentBuilder::new().tls_connector(default_connector());",
            scope: Scope::Production,
            count: 1,
            chain: None,
        },
        Allowed {
            file: "src/retry_tls.rs",
            line: ".with_root_{x}certificates(roots)",
            scope: Scope::Production,
            count: 1,
            chain: None,
        },
        Allowed {
            file: "src/snapshot_client.rs",
            line: "let agent = {u}AgentBuilder::new()",
            scope: Scope::Production,
            count: 1,
            chain: Some(".tls_connector(connector)"),
        },
        // Tests: plain-HTTP agents and synthetic-trust fixtures.
        Allowed {
            file: "src/net_resilience.rs",
            line: "let agent = {u}AgentBuilder::new().resolver(resolver).build();",
            scope: Scope::TestModule,
            count: 1,
            chain: None,
        },
        Allowed {
            file: "src/net_resilience.rs",
            line: "let error = {u}agent()",
            scope: Scope::TestModule,
            count: 1,
            chain: None,
        },
        Allowed {
            file: "src/snapshot_client.rs",
            line: "let agent = {u}AgentBuilder::new().resolver(resolver).build();",
            scope: Scope::TestModule,
            count: 1,
            chain: None,
        },
        Allowed {
            file: "src/provider_calls.rs",
            line: "let refused = {u}get(\"http://127.0.0.1:9/\")",
            scope: Scope::TestModule,
            count: 1,
            chain: None,
        },
        Allowed {
            file: "src/retry_tls.rs",
            line: "let agent = {u}AgentBuilder::new().tls_connector(tls).build();",
            scope: Scope::TestModule,
            count: 1,
            chain: None,
        },
        Allowed {
            file: "src/retry_tls.rs",
            line: "{u}AgentBuilder::new()",
            scope: Scope::TestModule,
            count: 2,
            chain: Some(".tls_connector(connector(Instant::now() + Duration::from_"),
        },
        Allowed {
            file: "src/retry_allocation_native_tests.rs",
            line: ".with_root_{x}certificates(roots)",
            scope: Scope::IncludedTestFile,
            count: 1,
            chain: None,
        },
    ];
    // Constructors and shortcuts that would install ureq's own TLS default.
    const BYPASSES: &[&str] = &[
        "{u}get(",
        "{u}post(",
        "{u}put(",
        "{u}patch(",
        "{u}delete(",
        "{u}head(",
        "{u}request(",
        "{u}request_url(",
        "{u}agent(",
        "{u}builder(",
        "{u}Agent::new(",
        "{u}Agent::default(",
        "{u}AgentBuilder::default(",
        "{u}AgentBuilder::new(",
    ];
    // rustls policy overrides: verifiers, root sources, ALPN, SNI,
    // resumption, early data, client certificates and key logs.
    const OVERRIDES: &[&str] = &[
        ".danger{x}ous()",
        "ServerCert{x}Verifier",
        "certificate_{x}verifier",
        "native_{x}certs",
        "native_{x}tls::",
        "platform_{x}verifier",
        "alpn_{x}protocols",
        "enable_{x}sni",
        "key_{x}log",
        ".resump{x}tion",
        "early_{x}data",
        "client_auth_{x}cert",
        "with_root_{x}certificates(",
    ];
    fn expand(text: &str) -> String {
        text.replace("{u}", "ureq::").replace("{x}", "")
    }
    /// A builder chain from its first line through `.build()`, at most 12 lines.
    fn builder_chain(rest: &str) -> &str {
        let lines = rest
            .match_indices('\n')
            .nth(11)
            .map_or(rest.len(), |(at, _)| at);
        let end = rest[..lines]
            .find(".build()")
            .map_or(lines, |at| at + ".build()".len());
        &rest[..end]
    }
    /// Whether a trimmed line imports ureq items, at any visibility, or
    /// declares the crate.
    fn imports_ureq(trimmed: &str) -> bool {
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        words.windows(2).any(|pair| {
            matches!(pair[0], "use" | "crate")
                && pair[1].trim_start_matches("::").starts_with("ureq")
        })
    }

    #[test]
    fn every_production_ureq_agent_uses_the_configured_connector() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = vec![root.join("build.rs")];
        let mut pending = vec![root.join("src"), root.join("tests")];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    files.push(path);
                }
            }
        }
        assert!(files.len() > 50, "source inventory looks truncated");
        let mut seen = vec![0; ALLOWED.len()];
        let tokens: Vec<String> = BYPASSES
            .iter()
            .chain(OVERRIDES)
            .map(|token| expand(token))
            .collect();
        for path in files {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let file = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let tests_start = text.find("\n#[cfg(test)]\nmod tests {");
            let mut offset = 0;
            for (index, line) in text.split_inclusive('\n').enumerate() {
                let start = offset;
                offset += line.len();
                let trimmed = line.trim();
                if imports_ureq(trimmed)
                    && !(file == "src/retry_tls.rs"
                        && trimmed == "use ureq::{ReadWrite, TlsConnector};")
                {
                    panic!("{file}:{}: import ureq items by path: {trimmed}", index + 1);
                }
                if !tokens.iter().any(|token| line.contains(token.as_str())) {
                    continue;
                }
                let in_tests = tests_start.is_some_and(|tests| start > tests);
                let allowed = ALLOWED.iter().position(|allowed| {
                    allowed.file == file
                        && expand(allowed.line) == trimmed
                        && match allowed.scope {
                            Scope::Production => !in_tests,
                            Scope::TestModule => in_tests,
                            Scope::IncludedTestFile => true,
                        }
                        && match allowed.chain {
                            None => true,
                            Some(chain) => builder_chain(&text[start..]).contains(chain),
                        }
                });
                match allowed {
                    Some(allowed) => seen[allowed] += 1,
                    None => panic!(
                        "{file}:{}: ureq agent or rustls policy bypasses retry_tls: {trimmed}",
                        index + 1
                    ),
                }
            }
        }
        for (allowed, seen) in ALLOWED.iter().zip(seen) {
            assert_eq!(
                seen,
                allowed.count,
                "{}: {}",
                allowed.file,
                expand(allowed.line)
            );
        }
        let read = |file: &str| std::fs::read_to_string(root.join(file)).unwrap();
        // The bounded snapshot agent's `connector` is the deadline connector.
        let snapshot = read("src/snapshot_client.rs");
        assert_eq!(snapshot.matches("let connector =").count(), 1);
        assert_eq!(
            snapshot
                .matches("let connector = crate::retry_tls::connector(deadline);")
                .count(),
            1
        );
        // The included fixture file compiles only inside a test module.
        let sync = read("src/snapshot_sync.rs");
        let include = sync
            .find("include!(\"retry_live_native_tests.rs\");")
            .unwrap();
        assert!(sync
            .find("\n#[cfg(test)]\nmod tests {")
            .is_some_and(|tests| tests < include));
        assert!(read("src/retry_live_native_tests.rs")
            .contains("include!(\"retry_allocation_native_tests.rs\");"));
    }

    type LockedPackage = (String, String, Vec<String>);
    /// Name, version and dependency list of every package in a lockfile.
    fn locked_packages(relative: &str) -> Vec<LockedPackage> {
        let lock = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative),
        )
        .unwrap();
        lock.split("[[package]]")
            .skip(1)
            .map(|block| {
                let field = |key: &str| {
                    block
                        .lines()
                        .find_map(|line| line.strip_prefix(&format!("{key} = \"")))
                        .and_then(|rest| rest.strip_suffix('"'))
                        .unwrap_or_default()
                        .to_string()
                };
                let dependencies = block
                    .lines()
                    .skip_while(|line| *line != "dependencies = [")
                    .skip(1)
                    .take_while(|line| *line != "]")
                    .map(|line| {
                        line.trim()
                            .trim_end_matches(',')
                            .trim_matches('"')
                            .to_string()
                    })
                    .collect();
                (field("name"), field("version"), dependencies)
            })
            .collect()
    }

    #[test]
    fn locked_graph_carries_only_patched_tls_roots() {
        // CI builds both workspaces with --locked, so these lockfiles are the
        // resolved graphs.
        let packages = locked_packages("../../Cargo.lock");
        let versions = |name: &str| -> Vec<Vec<u64>> {
            packages
                .iter()
                .filter(|(package, _, _)| package == name)
                .map(|(_, version, _)| {
                    version
                        .split('.')
                        .map(|part| part.parse().unwrap())
                        .collect()
                })
                .collect()
        };
        let roots = versions("webpki-roots");
        assert_eq!(roots.len(), 1, "one webpki-roots, never the 0.26 shim");
        assert!(roots[0] >= vec![1, 0, 10], "{roots:?}");
        let webpki = versions("rustls-webpki");
        assert_eq!(webpki.len(), 1);
        assert!(
            webpki[0] >= vec![0, 103, 16] && webpki[0] < vec![0, 104],
            "{webpki:?}"
        );
        assert_eq!(versions("rustls").len(), 1);
        for absent in [
            "aws-lc-rs",
            "aws-lc-sys",
            "native-tls",
            "rustls-native-certs",
            "webpki-root-certs",
        ] {
            assert!(versions(absent).is_empty(), "{absent} entered the graph");
        }
        let ureq = packages.iter().find(|(name, _, _)| name == "ureq").unwrap();
        assert!(
            ureq.2
                .iter()
                .all(|dependency| !dependency.starts_with("rustls")
                    && !dependency.starts_with("webpki")),
            "ureq's own TLS stack is enabled: {:?}",
            ureq.2
        );
        let dependents: Vec<&str> = packages
            .iter()
            .filter(|(_, _, dependencies)| dependencies.iter().any(|d| d == "ureq"))
            .map(|(name, _, _)| name.as_str())
            .collect();
        assert_eq!(dependents, ["ottto-service"]);
        // The connector workspace carries no TLS stack at all.
        let connector_tls: Vec<String> = locked_packages("../Cargo.lock")
            .into_iter()
            .map(|(name, _, _)| name)
            .filter(|name| {
                name == "ureq"
                    || name.starts_with("rustls")
                    || name.starts_with("webpki")
                    || name.starts_with("aws-lc")
                    || name.starts_with("native-tls")
                    || name.starts_with("openssl")
                    || name == "ring"
            })
            .collect();
        assert!(connector_tls.is_empty(), "{connector_tls:?}");
    }
}

/// Fixtures for credential-transport regressions: a logger that accepts every
/// record, as a host program enabling ureq debug output would install, and a
/// one-shot backend that redirects to a second loopback host.
#[cfg(test)]
pub(crate) mod credential_test_support {
    use std::io::{ErrorKind, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Mutex, Once};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    struct HostLogger;

    static HOST_LOGGER: HostLogger = HostLogger;

    impl log::Log for HostLogger {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            let line = format!("{} {}", record.target(), record.args());
            RECORDS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(line);
        }

        fn flush(&self) {}
    }

    fn captured() -> Vec<String> {
        RECORDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Install the accept-everything logger at the most verbose runtime level
    /// and prove it receives records for ureq's own target.
    pub(crate) fn install_host_logger() {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            log::set_logger(&HOST_LOGGER).expect("no other logger in the test binary");
        });
        log::set_max_level(log::LevelFilter::Trace);
        log::info!(target: "ureq::unit", "host-logger-canary");
        assert!(captured()
            .iter()
            .any(|line| line == "ureq::unit host-logger-canary"));
    }

    /// No record the host logger received holds `secret`. Call after the
    /// request under test returned and after `install_host_logger`.
    pub(crate) fn assert_never_logged(secret: &str) {
        assert!(!log::log_enabled!(target: "ureq::unit", log::Level::Debug));
        let leaked = captured()
            .iter()
            .filter(|line| line.contains(secret))
            .count();
        assert_eq!(leaked, 0, "a credential reached the host logger");
    }

    /// A backend that answers its first request with `status`, a `Location`
    /// on a second loopback host nobody serves, and a success-shaped body.
    pub(crate) struct RedirectingBackend {
        pub(crate) base_url: String,
        target: TcpListener,
        server: JoinHandle<String>,
    }

    impl RedirectingBackend {
        pub(crate) fn start(status: &str) -> Self {
            let target = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
            target.set_nonblocking(true).expect("nonblocking target");
            let location = format!("http://{}/captured", target.local_addr().unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let status = status.to_string();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept request");
                let request = read_request(&mut stream);
                // A body every caller would decode as success: a client
                // must reject the 3xx itself, not fail on an empty body.
                let body = r#"{"token":"redirected","device_released":true}"#;
                let response = format!(
                    "HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write redirect");
                request
            });
            Self {
                base_url,
                target,
                server,
            }
        }

        /// The request the redirecting backend saw. Panics if the client
        /// contacted the redirect target at all.
        pub(crate) fn finish(self) -> String {
            let request = self.server.join().expect("redirecting backend");
            assert!(
                matches!(self.target.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
                "the client followed the redirect to a second host"
            );
            request
        }
    }

    pub(crate) fn read_request(stream: &mut TcpStream) -> String {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let body_len = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= end + 4 + body_len {
                    break;
                }
            }
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => request.extend_from_slice(&buffer[..read]),
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }
}

#[cfg(test)]
mod unit_test_egress_tests {
    use super::*;

    #[test]
    fn unit_tests_refuse_external_base_urls_before_any_resolution() {
        for base in [
            "https://api.ottto.net",
            "http://localhost.attacker.invalid",
            "http://localhost@api.ottto.net",
        ] {
            std::thread::spawn(move || {
                let error = agent().get(base).call().unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("unit tests may only send HTTP requests to loopback fixtures"),
                    "{error}"
                );
            })
            .join()
            .unwrap();
        }
    }
}
