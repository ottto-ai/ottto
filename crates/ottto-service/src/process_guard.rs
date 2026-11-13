//! Owned process groups: observe exit without releasing the leader's PID.
use std::io;
use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) fn exited(child: &Child) -> io::Result<bool> {
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.si_signo != 0)
}

/// Preserve specialized waiters' accounting and cached exit status.
pub(crate) trait GroupChild {
    fn child_mut(&mut self) -> &mut Child;
    fn reap(&mut self) -> io::Result<ExitStatus>;
}

impl GroupChild for Child {
    fn child_mut(&mut self) -> &mut Child {
        self
    }
    fn reap(&mut self) -> io::Result<ExitStatus> {
        self.wait()
    }
}

impl GroupChild for crate::local_resource_diagnostics::cli_children::MeasuredChild {
    fn child_mut(&mut self) -> &mut Child {
        self
    }
    fn reap(&mut self) -> io::Result<ExitStatus> {
        self.wait()
    }
}

/// Requires a child spawned with process_group(0) and exclusively reaped here.
/// Give the leader up to `drain` to exit, then stop its group before reaping.
pub(crate) fn stop_group_and_reap(
    child: &mut impl GroupChild,
    drain: Duration,
) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + drain;
    loop {
        match exited(child.child_mut()) {
            Ok(done) if done || Instant::now() >= deadline => break,
            Ok(_) => thread::sleep(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            ),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            // An already-reaped child's PID is no longer reserved. Never signal it.
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return child.reap(),
            // A status-read failure must still stop and reap our owned child.
            Err(_) => break,
        }
    }
    let direct = child.child_mut();
    if let Ok(pgid) = libc::pid_t::try_from(direct.id())
        && pgid > 1
        && pgid != unsafe { libc::getpgrp() }
    {
        // Even an exited leader may have live descendants in its group.
        unsafe { libc::killpg(pgid, libc::SIGKILL) };
    }
    let _ = direct.kill();
    child.reap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;

    fn command(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]).env_clear().process_group(0);
        command
    }

    #[test]
    fn drain_observes_exit_without_reaping_and_preserves_cached_status() {
        let mut child = command("exit 7").spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !exited(&child).unwrap() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(exited(&child).unwrap());
        let status = stop_group_and_reap(&mut child, Duration::from_secs(2)).unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!(
            stop_group_and_reap(&mut child, Duration::ZERO).unwrap(),
            status
        );
    }

    #[test]
    fn zero_drain_kills_immediately() {
        let mut child = command("exec /bin/sleep 10").spawn().unwrap();
        assert_eq!(
            stop_group_and_reap(&mut child, Duration::ZERO)
                .unwrap()
                .signal(),
            Some(libc::SIGKILL)
        );
    }

    #[test]
    fn positive_drain_has_a_deadline() {
        let mut child = command("exec /bin/sleep 10").spawn().unwrap();
        let start = Instant::now();
        let status = stop_group_and_reap(&mut child, Duration::from_millis(100)).unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn measured_reaper_keeps_its_exit_status_cache() {
        let mut child =
            crate::local_resource_diagnostics::cli_children::spawn(&mut command("exit 7")).unwrap();
        let status = stop_group_and_reap(&mut child, Duration::from_secs(2)).unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!(child.wait().unwrap(), status);
        assert_eq!(
            stop_group_and_reap(&mut child, Duration::ZERO).unwrap(),
            status
        );
    }
}
