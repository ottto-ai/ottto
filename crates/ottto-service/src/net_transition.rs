//! Proactive macOS network-transition observer.
//!
//! The reactive recovery ladders in `net_resilience` classify upload errors
//! after the fact, which leaves irreducible gaps (plain-anyhow error paths,
//! classification ordering) and a latency floor (10 min to a pool rebuild,
//! 1 h to a self-restart). The 2026-07-17 stall showed the actual trigger is
//! always the same event: a network transition (VPN up/down, sleep/wake
//! MAGICWAKE, interface reconfiguration) that leaves pooled keep-alive
//! sockets bound to a dead local IP. So watch for the transition itself: a
//! `PF_ROUTE` routing socket receives a kernel message on every interface
//! and address change, with no polling and no framework dependencies. On a
//! debounced transition, force-rebuild BOTH upstream HTTP pools immediately —
//! independent of error families, streaks, and rate-limit windows — so the
//! next upload cycle starts from fresh connections.

#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

/// Rebuild only after the routing table has been quiet this long: transitions
/// arrive as message flurries, and rebuilding mid-flurry could pool a socket
/// on a network state that is still changing.
#[cfg(target_os = "macos")]
const TRANSITION_QUIET_PERIOD: Duration = Duration::from_secs(3);
/// Never force-rebuild more often than this; dropping idle pools is cheap but
/// a flapping interface must not thrash them continuously.
#[cfg(target_os = "macos")]
const TRANSITION_REBUILD_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// Blocking-read timeout on the routing socket, doubling as the debounce
/// tick so a quiet period is noticed without further route messages.
#[cfg(target_os = "macos")]
const ROUTE_SOCKET_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// Spawn the observer thread. Non-macOS builds are a no-op (the trigger —
/// macOS network-transition handling of long-running processes — does not
/// exist elsewhere, and `PF_ROUTE` is BSD-specific).
pub fn spawn_network_transition_observer() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let socket = RouteSocket::open()?;
        std::thread::Builder::new()
            .name("ottto-net-transition".to_string())
            .spawn(move || observe_route_socket(socket))
            .map_err(|error| anyhow::anyhow!("spawn network transition observer: {error}"))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
struct RouteSocket {
    fd: libc::c_int,
}

#[cfg(target_os = "macos")]
impl RouteSocket {
    fn open() -> anyhow::Result<Self> {
        // SAFETY: plain socket(2); the fd is owned by RouteSocket and closed
        // on drop.
        let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "open PF_ROUTE socket failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let timeout = libc::timeval {
            tv_sec: ROUTE_SOCKET_READ_TIMEOUT.as_secs() as libc::time_t,
            tv_usec: 0,
        };
        // SAFETY: fd is a valid socket we just opened; timeval is a plain
        // stack value of the documented size.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: fd is open and owned here.
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "configure PF_ROUTE socket read timeout failed: {error}"
            ));
        }
        Ok(Self { fd })
    }

    /// One routing message, `Ok(None)` on the read-timeout tick.
    fn read_message(&self, buffer: &mut [u8]) -> std::io::Result<Option<usize>> {
        // SAFETY: fd is a valid open socket; the buffer pointer/length come
        // from a live mutable slice.
        let read = unsafe {
            libc::read(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };
        if read > 0 {
            return Ok(Some(read as usize));
        }
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "PF_ROUTE socket closed",
            ));
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) | Some(libc::EAGAIN) => Ok(None),
            _ => Err(error),
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for RouteSocket {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this struct and still open.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(target_os = "macos")]
fn observe_route_socket(socket: RouteSocket) {
    // Route messages are bounded well below this (rt_msghdr + a few
    // sockaddrs); a short read of an oversized message just truncates
    // payload we never parse.
    let mut buffer = [0_u8; 2048];
    let mut pending_since: Option<Instant> = None;
    let mut last_rebuild_at: Option<Instant> = None;
    loop {
        let message = match socket.read_message(&mut buffer) {
            Ok(message) => message,
            Err(error) => {
                // Without the socket the proactive layer is gone, but the
                // reactive ladders still cover recovery; say so once and stop.
                eprintln!(
                    "OTTTO-NET-TRANSITION: routing socket read failed ({error}); network \
                     transitions will be handled by the reactive recovery ladders only."
                );
                return;
            }
        };
        let now = Instant::now();
        if let Some(length) = message {
            if is_transition_message(&buffer[..length]) {
                // Quiet-period debounce: each new message re-arms the timer so
                // the rebuild lands after the flurry settles.
                pending_since = Some(now);
            }
        }
        let Some(since) = pending_since else {
            continue;
        };
        if now.saturating_duration_since(since) < TRANSITION_QUIET_PERIOD {
            continue;
        }
        pending_since = None;
        let rebuilt_recently = last_rebuild_at
            .is_some_and(|at| now.saturating_duration_since(at) < TRANSITION_REBUILD_MIN_INTERVAL);
        if rebuilt_recently {
            continue;
        }
        last_rebuild_at = Some(now);
        crate::net_resilience::force_rebuild_upstream_agents(
            "a macOS network transition (interface/address change)",
        );
    }
}

/// Whether one raw `PF_ROUTE` message signals a network transition worth a
/// pool rebuild: an address was added/removed or an interface changed state.
/// Plain route add/delete chatter (`RTM_ADD`/`RTM_DELETE`/...) is ignored —
/// those fire for individual host routes without the network changing.
#[cfg(target_os = "macos")]
fn is_transition_message(message: &[u8]) -> bool {
    // struct rt_msghdr: u_short rtm_msglen; u_char rtm_version; u_char rtm_type;
    let Some(&message_type) = message.get(3) else {
        return false;
    };
    matches!(
        message_type as i32,
        libc::RTM_NEWADDR | libc::RTM_DELADDR | libc::RTM_IFINFO
    )
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn route_message(message_type: u8) -> Vec<u8> {
        // Minimal rt_msghdr prefix: msglen (little-endian u16), version, type.
        let mut message = vec![0_u8; 16];
        message[0] = 16;
        message[2] = 5; // RTM_VERSION
        message[3] = message_type;
        message
    }

    #[test]
    fn address_and_interface_messages_are_transitions() {
        assert!(is_transition_message(&route_message(
            libc::RTM_NEWADDR as u8
        )));
        assert!(is_transition_message(&route_message(
            libc::RTM_DELADDR as u8
        )));
        assert!(is_transition_message(&route_message(
            libc::RTM_IFINFO as u8
        )));
    }

    #[test]
    fn plain_route_chatter_and_short_reads_are_ignored() {
        assert!(!is_transition_message(&route_message(libc::RTM_ADD as u8)));
        assert!(!is_transition_message(&route_message(
            libc::RTM_DELETE as u8
        )));
        assert!(!is_transition_message(&[0, 0]));
        assert!(!is_transition_message(&[]));
    }

    #[test]
    fn route_socket_opens_on_macos() {
        // The observer must actually be able to open the kernel routing
        // socket on the platform it targets.
        let socket = RouteSocket::open().expect("PF_ROUTE socket opens");
        assert!(socket.fd >= 0);
    }
}
