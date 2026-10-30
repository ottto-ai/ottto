//! Probe wildcard holders before the loopback bind: reuse lets our own
//! connected sockets/TIME_WAIT survive replacement without sharing a listener.
#[cfg(unix)]
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::{io, net::TcpListener};

#[cfg(unix)]
fn checked(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn new_socket(domain: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: socket has no pointer arguments; ownership transfers once below.
    let raw = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a new, uniquely owned socket descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: fcntl sets flags on our live descriptor.
    checked(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
    let reuse: libc::c_int = 1;
    // SAFETY: setsockopt reads a live c_int of the supplied size.
    checked(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&reuse as *const libc::c_int).cast(),
            std::mem::size_of_val(&reuse) as libc::socklen_t,
        )
    })?;
    Ok(fd)
}

#[cfg(unix)]
pub(super) fn bind_ipv6_wildcard(port: u16) -> io::Result<OwnedFd> {
    let fd = new_socket(libc::AF_INET6)?;
    let dual_stack: libc::c_int = 0;
    // SAFETY: setsockopt reads a live c_int of the supplied size.
    checked(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&dual_stack as *const libc::c_int).cast(),
            std::mem::size_of_val(&dual_stack) as libc::socklen_t,
        )
    })?;
    // SAFETY: zero is valid for all fields, including the wildcard address.
    let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    address.sin6_port = port.to_be();
    let length = std::mem::size_of_val(&address) as libc::socklen_t;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        address.sin6_len = length as u8;
    }
    // SAFETY: bind reads our initialized sockaddr_in6 with its exact size.
    checked(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_in6).cast(),
            length,
        )
    })?;
    Ok(fd)
}

#[cfg(unix)]
pub(super) fn bind(port: u16) -> io::Result<TcpListener> {
    bind_with_probe(port, bind_ipv6_wildcard)
}

#[cfg(unix)]
pub(super) fn bind_with_probe(
    port: u16,
    probe: impl FnOnce(u16) -> io::Result<OwnedFd>,
) -> io::Result<TcpListener> {
    bind_with_probe_and_hook(port, probe, || {})
}

#[cfg(unix)]
pub(super) fn bind_with_probe_and_hook(
    port: u16,
    probe: impl FnOnce(u16) -> io::Result<OwnedFd>,
    after_probe: impl FnOnce(),
) -> io::Result<TcpListener> {
    // Keep both reservations through listen: a same-uid wildcard contender
    // must not enter between our probes and the specific loopback bind.
    let ipv4_guard = bind_ipv4(port, Ipv4Addr::UNSPECIFIED)?;
    let ipv6_guard = match probe(port) {
        Ok(fd) => Some(fd),
        // These mean IPv6 cannot serve here, not that another holder owns the
        // port. Keep IPv4 service available on hosts with IPv6 disabled.
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::EADDRNOTAVAIL)
            ) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    after_probe();
    let fd = bind_ipv4(port, Ipv4Addr::LOCALHOST)?;
    // SAFETY: listen operates on our uniquely owned, bound socket.
    checked(unsafe { libc::listen(fd.as_raw_fd(), 128) })?;
    drop((ipv4_guard, ipv6_guard));
    let listener = TcpListener::from(fd);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(unix)]
fn bind_ipv4(port: u16, ip: Ipv4Addr) -> io::Result<OwnedFd> {
    let fd = new_socket(libc::AF_INET)?;
    // SAFETY: zero is valid for every sockaddr_in field.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_port = port.to_be();
    address.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    let length = std::mem::size_of_val(&address) as libc::socklen_t;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        address.sin_len = length as u8;
    }
    // SAFETY: address is initialized and its exact length is supplied.
    checked(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_in).cast(),
            length,
        )
    })?;
    Ok(fd)
}

#[cfg(not(unix))]
pub(super) fn bind(_port: u16) -> io::Result<TcpListener> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "exclusive legacy relay binds require Unix",
    ))
}
