//! Absolute TLS I/O deadline for optional snapshot turns. No thread or socket
//! clone: pinned ureq performs its normal handshake over this bounded stream.
use std::io::{self, Read, Write};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use ureq::{ReadWrite, TlsConnector};

pub(crate) struct DeadlineTls {
    config: Arc<ureq::rustls::ClientConfig>,
    deadline: Instant,
}
pub(crate) fn connector(deadline: Instant) -> Arc<DeadlineTls> {
    static CONFIG: OnceLock<Arc<ureq::rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        // Match pinned ureq's default ring/TLS1.2+1.3/WebPKI trust policy.
        // Use its rustls re-export so connector types stay version compatible.
        let roots = ureq::rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Arc::new(
            ureq::rustls::ClientConfig::builder_with_provider(
                ureq::rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&ureq::rustls::version::TLS12, &ureq::rustls::version::TLS13])
            .expect("ring supports TLS 1.2 and TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    });
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
        TlsConnector::connect(&self.config, dns_name, Box::new(io))
    }
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
