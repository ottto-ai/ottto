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
use crate::local_resource_diagnostics::StageWindow;
#[cfg(any(target_os = "macos", all(test, unix)))]
use std::time::{Duration, Instant};

/// Rebuild only after the routing table has been quiet this long: transitions
/// arrive as message flurries, and rebuilding mid-flurry could pool a socket
/// on a network state that is still changing.
#[cfg(any(target_os = "macos", all(test, unix)))]
const TRANSITION_QUIET_PERIOD: Duration = Duration::from_secs(3);
/// Never force-rebuild more often than this; dropping idle pools is cheap but
/// a flapping interface must not thrash them continuously.
#[cfg(any(target_os = "macos", all(test, unix)))]
const TRANSITION_REBUILD_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// Wake coalescing bound: at most one readiness wait per second, matching the
/// 1 s legacy relay health deadline.
#[cfg(any(target_os = "macos", all(test, unix)))]
const ROUTE_WAKE_COALESCE_INTERVAL: Duration = Duration::from_secs(1);
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

#[cfg(any(target_os = "macos", all(test, unix)))]
struct RouteSocket {
    fd: libc::c_int,
}

#[cfg(any(target_os = "macos", all(test, unix)))]
impl RouteSocket {
    #[cfg(target_os = "macos")]
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
        // SAFETY: fd is the socket just opened here, initially with no status flags.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: fd is open and owned here.
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "configure nonblocking PF_ROUTE socket failed: {error}"
            ));
        }
        Ok(Self { fd })
    }

    fn wait_readable(&self, deadline: Option<Instant>) -> std::io::Result<()> {
        let timeout = deadline.map_or(-1, |at| {
            at.saturating_duration_since(Instant::now())
                .as_nanos()
                .div_ceil(1_000_000) as libc::c_int
        });
        let mut pollfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd is live and nfds matches its single entry.
        let rc = unsafe { libc::poll(&mut pollfd, 1, timeout) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                return Err(error);
            }
        }
        // Timeout/EINTR/EAGAIN return to the observer's absolute-deadline check.
        Ok(())
    }

    /// One routing message, `Ok(None)` when interrupted or fully drained.
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

#[cfg(any(target_os = "macos", all(test, unix)))]
impl Drop for RouteSocket {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this struct and still open.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(target_os = "macos")]
fn observe_route_socket(socket: RouteSocket) {
    observe_route_messages(socket, is_transition_message, std::thread::sleep, || {
        crate::net_resilience::force_rebuild_upstream_agents(
            "a macOS network transition (interface/address change)",
        );
        // Sleep/wake and restored network state are a lazy catch-up
        // opportunity. The coalesced collection worker is independent of the transcript
        // sync lock; consent/off-switch and the durable per-slot claim remain
        // the final command boundaries.
        crate::agent_status_refresh::request_all();
    });
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn observe_route_messages(
    socket: RouteSocket,
    is_transition: impl Fn(&[u8]) -> bool,
    mut pause: impl FnMut(Duration),
    mut rebuild: impl FnMut(),
) {
    // Route messages are bounded well below this (rt_msghdr + a few
    // sockaddrs); a short read of an oversized message just truncates
    // payload we never parse.
    let mut buffer = [0_u8; 2048];
    let mut pending_since: Option<Instant> = None;
    let mut last_rebuild_at: Option<Instant> = None;
    let mut readable = false;
    let mut next_wait_at = Instant::now();
    loop {
        let deadline = pending_since.map(|since| since + TRANSITION_QUIET_PERIOD);
        let result = if readable {
            Ok(())
        } else {
            // The queue is drained. Coalesce the next wake: messages queue
            // unread until a second after the last wake, so a deadline inside
            // the pause fires at its end (at most 1 s late).
            pause(next_wait_at.saturating_duration_since(Instant::now()));
            let result = socket.wait_readable(deadline);
            next_wait_at = Instant::now() + ROUTE_WAKE_COALESCE_INTERVAL;
            result
        };

        let message = match result.and_then(|()| socket.read_message(&mut buffer)) {
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
        readable = message.is_some();
        let relevant = message.is_some_and(|length| is_transition(&buffer[..length]));
        // Measure transitions and rebuilds, never route chatter or readiness waits.
        #[cfg(target_os = "macos")]
        let _stage = relevant.then(|| StageWindow::begin("unknown", "offpass_network_transition"));
        if relevant {
            // Quiet-period debounce: each transition re-arms the timer so
            // the rebuild lands after the flurry settles.
            pending_since = Some(Instant::now());
        }
        if transition_ready(&mut pending_since, &mut last_rebuild_at, Instant::now()) {
            #[cfg(target_os = "macos")]
            let _rebuild_stage =
                (!relevant).then(|| StageWindow::begin("unknown", "offpass_network_transition"));
            rebuild();
        }
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn transition_ready(
    pending_since: &mut Option<Instant>,
    last_rebuild_at: &mut Option<Instant>,
    now: Instant,
) -> bool {
    let Some(since) = *pending_since else {
        return false;
    };
    if now.saturating_duration_since(since) < TRANSITION_QUIET_PERIOD {
        return false;
    }
    *pending_since = None;
    let rebuilt_recently = last_rebuild_at
        .is_some_and(|at| now.saturating_duration_since(at) < TRANSITION_REBUILD_MIN_INTERVAL);
    if rebuilt_recently {
        return false;
    }
    *last_rebuild_at = Some(now);
    true
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

#[cfg(all(test, unix))]
mod readiness_tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::sync::{atomic::AtomicBool, atomic::Ordering, mpsc, Arc};

    /// [behaviour] An idle indefinite wait wakes on fd readiness.
    #[test]
    fn idle_wait_wakes_on_readiness() {
        let (mut peer, reader) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let socket = RouteSocket {
            fd: reader.into_raw_fd(),
        };
        let (started_tx, started_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            socket.wait_readable(None).unwrap();
            let mut byte = [0];
            ready_tx
                .send(socket.read_message(&mut byte).unwrap())
                .unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            ready_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        peer.write_all(&[1]).unwrap();
        let ready = ready_rx.recv_timeout(Duration::from_millis(500));
        // Unblocks the waiter if the read never arrived. On macOS this fails
        // with ENOTCONN once the waiter has already closed its end.
        let _ = peer.shutdown(std::net::Shutdown::Both);
        waiter.join().unwrap();
        assert_eq!(ready.unwrap(), Some(1));
    }

    /// [regress] Ignored route chatter creates no diagnostic stage work.
    #[cfg(target_os = "macos")]
    #[test]
    fn route_chatter_begins_no_stage() {
        let (mut peer, reader) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let socket = RouteSocket {
            fd: reader.into_raw_fd(),
        };
        peer.write_all(&[0; 8]).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            observe_route_messages(socket, |_| false, |_| (), || panic!("unexpected rebuild"));
            crate::local_resource_diagnostics::source_prepare("unknown", || (), |_| false);
        });
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["stage"], "source_prepare");
    }

    /// [behaviour] A burst queued during the coalescing pause drains in one
    /// wake, every message reaches the transition decision, and a quiet
    /// deadline that passes inside the pause rebuilds once when it ends.
    #[test]
    fn route_burst_coalesces_into_one_wake() {
        let (peer, reader) = UnixDatagram::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let control = reader.try_clone().unwrap();
        let socket = RouteSocket {
            fd: reader.into_raw_fd(),
        };
        let (seen_tx, seen_rx) = mpsc::channel();
        let (paused_tx, paused_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel::<()>();
        let (rebuilt_tx, rebuilt_rx) = mpsc::channel();
        let observer = std::thread::spawn(move || {
            observe_route_messages(
                socket,
                |message| {
                    let relevant = message[0] == 1;
                    seen_tx.send((relevant, Instant::now())).unwrap();
                    relevant
                },
                // The test owns time inside the pause: it ends on resume.
                |pause| {
                    let _ = paused_tx.send(pause);
                    let _ = resume_rx.recv();
                },
                || rebuilt_tx.send(Instant::now()).unwrap(),
            );
        });
        let next_pause = || paused_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        // No earlier wake, so the first wait starts at once.
        assert_eq!(next_pause(), Duration::ZERO);
        resume_tx.send(()).unwrap();
        peer.send(&[0; 16]).unwrap();
        let pause = next_pause();
        assert!(pause > Duration::from_millis(500) && pause <= ROUTE_WAKE_COALESCE_INTERVAL);
        assert_eq!(seen_rx.try_iter().count(), 1);
        for index in 0..10 {
            peer.send(&[u8::from(index == 4); 16]).unwrap();
        }
        resume_tx.send(()).unwrap();
        // One wake drained the whole burst before the next pause.
        assert!(next_pause() > Duration::from_millis(500));
        let seen: Vec<_> = seen_rx.try_iter().collect();
        assert_eq!(seen.len(), 10);
        let transitions: Vec<_> = seen.iter().filter(|(relevant, _)| *relevant).collect();
        assert_eq!(transitions.len(), 1);
        let transition_at = transitions[0].1;
        // Hold the pause past the quiet deadline; the rebuild waits for its end.
        std::thread::sleep(
            (transition_at + TRANSITION_QUIET_PERIOD + Duration::from_millis(100))
                .saturating_duration_since(Instant::now()),
        );
        assert!(rebuilt_rx.try_recv().is_err());
        let resumed = Instant::now();
        resume_tx.send(()).unwrap();
        let rebuilt = rebuilt_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(rebuilt >= transition_at + TRANSITION_QUIET_PERIOD);
        assert!(rebuilt < resumed + Duration::from_millis(500));
        next_pause();
        control.shutdown(std::net::Shutdown::Read).unwrap();
        drop(resume_tx);
        observer.join().unwrap();
        assert_eq!(rebuilt_rx.try_iter().count(), 0);
    }

    /// [behaviour] Quiet fires without another message, re-arms only for relevant
    /// messages, survives continuous chatter and discards suppressed transitions.
    #[test]
    fn quiet_deadline_and_rebuild_suppression() {
        for chatter in [false, true] {
            let (mut peer, reader) = UnixStream::pair().unwrap();
            reader.set_nonblocking(true).unwrap();
            let socket = RouteSocket {
                fd: reader.into_raw_fd(),
            };
            let (seen_tx, seen_rx) = mpsc::channel();
            let (rebuilt_tx, rebuilt_rx) = mpsc::channel();
            let observer = std::thread::spawn(move || {
                observe_route_messages(
                    socket,
                    |message| {
                        let relevant = message.contains(&1);
                        if relevant {
                            seen_tx.send(Instant::now()).unwrap();
                        }
                        relevant
                    },
                    |_| (),
                    || {
                        rebuilt_tx.send(Instant::now()).unwrap();
                    },
                );
            });
            peer.write_all(&[1]).unwrap();
            let first = seen_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            let initial = rebuilt_rx.recv_timeout(Duration::from_secs(1));
            peer.write_all(&[1]).unwrap();
            let rearmed = seen_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let writer = chatter.then(|| {
                let mut writer = peer.try_clone().unwrap();
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        if writer.write_all(&[0; 2048]).is_err() {
                            break;
                        }
                    }
                })
            });
            let old_deadline = rebuilt_rx.recv_timeout(
                (first + TRANSITION_QUIET_PERIOD).saturating_duration_since(Instant::now()),
            );
            let rebuilt = rebuilt_rx.recv_timeout(Duration::from_secs(3));
            stop.store(true, Ordering::Relaxed);
            peer.shutdown(std::net::Shutdown::Both).unwrap();
            if let Some(writer) = writer {
                writer.join().unwrap();
            }
            observer.join().unwrap();
            assert!(matches!(initial, Err(mpsc::RecvTimeoutError::Timeout)));
            assert!(matches!(old_deadline, Err(mpsc::RecvTimeoutError::Timeout)));
            let rebuilt = rebuilt.unwrap();
            assert!(rebuilt >= rearmed + TRANSITION_QUIET_PERIOD);
            assert!(rebuilt < rearmed + Duration::from_secs(5));
        }

        let start = Instant::now();
        let mut pending = Some(start);
        let mut last = None;
        assert!(!transition_ready(
            &mut pending,
            &mut last,
            start + Duration::from_secs(2)
        ));
        assert!(transition_ready(
            &mut pending,
            &mut last,
            start + Duration::from_secs(3)
        ));
        pending = Some(start + Duration::from_secs(4));
        assert!(!transition_ready(
            &mut pending,
            &mut last,
            start + Duration::from_secs(7)
        ));
        assert!(pending.is_none());
        // Suppressed work is discarded, not queued at the 30-second boundary.
        assert!(!transition_ready(
            &mut pending,
            &mut last,
            start + Duration::from_secs(33)
        ));
        pending = Some(start + Duration::from_secs(30));
        assert!(transition_ready(
            &mut pending,
            &mut last,
            start + Duration::from_secs(33)
        ));
    }
}
