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
        let tls = TlsConnector::connect(&self.config, dns_name, Box::new(io))?;
        Ok(Box::new(ResponseHeaders {
            inner: tls,
            bytes: 0,
            line_has_content: false,
            complete: false,
        }))
    }
}

/// ureq bounds individual header lines, not their aggregate. Limit plaintext
/// headers after the normal authenticated TLS handshake, before its parser can
/// retain many large lines. Each optional request uses a fresh, nonpooled agent.
const RESPONSE_HEADER_BYTES: usize = 16 * 1024;
#[derive(Debug)]
struct ResponseHeaders {
    inner: Box<dyn ReadWrite>,
    bytes: usize,
    line_has_content: bool,
    complete: bool,
}
impl Read for ResponseHeaders {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let limit = if self.complete {
            bytes.len()
        } else {
            bytes
                .len()
                .min(RESPONSE_HEADER_BYTES.saturating_sub(self.bytes) + 1)
        };
        let read = self.inner.read(&mut bytes[..limit])?;
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
                self.complete = !self.line_has_content;
                self.line_has_content = false;
            } else if *byte != b'\r' {
                self.line_has_content = true;
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
    static TEST_CONFIG: std::cell::RefCell<Option<Arc<ureq::rustls::ClientConfig>>> = const {
        std::cell::RefCell::new(None)
    };
}
#[cfg(test)]
pub(crate) fn with_test_config<T>(
    config: Arc<ureq::rustls::ClientConfig>,
    f: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Arc<ureq::rustls::ClientConfig>>);
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
            line_has_content: false,
            complete: false,
        }
    }
    #[test]
    fn aggregate_header_cap_accepts_boundary_and_does_not_charge_body() {
        let prefix = "HTTP/1.1 200 OK\r\nX: ";
        let mut input = format!(
            "{prefix}{}\r\n\r\n",
            "x".repeat(RESPONSE_HEADER_BYTES - prefix.len() - 4)
        )
        .into_bytes();
        input.extend_from_slice(&vec![b'b'; RESPONSE_HEADER_BYTES * 3]);
        let mut stream = headers(input.clone());
        let mut output = Vec::new();
        stream.read_to_end(&mut output).unwrap();
        assert_eq!(output, input);
        assert_eq!(stream.bytes, RESPONSE_HEADER_BYTES);
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
}
