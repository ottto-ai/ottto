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

/// Requires an exclusively owned, unreaped group leader (process_group(0) or setsid()).
/// Observe exit for up to `drain`: reap exited leaders without signalling; only
/// force-stop the group when the leader is still running after the drain.
/// Consume the handle so no group signal can follow a reap.
pub(crate) fn stop_group_and_reap(
    mut child: impl GroupChild,
    drain: Duration,
) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + drain;
    loop {
        match exited(child.child_mut()) {
            Ok(true) => return child.reap(),
            Ok(false) if Instant::now() >= deadline => break,
            Ok(_) => thread::sleep(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            ),
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted && Instant::now() < deadline =>
            {
                continue;
            }
            // An already-reaped child's PID is no longer reserved. Never signal it.
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return child.reap(),
            // A status-read failure must still stop and reap our owned child.
            Err(_) => break,
        }
    }
    kill_group_and_reap(child)
}

/// Force-stop an exclusively owned, unreaped group, even if its leader exited.
/// Used when a failed exchange must release descendants holding inherited pipes.
pub(crate) fn kill_group_and_reap(mut child: impl GroupChild) -> io::Result<ExitStatus> {
    if let Err(error) = exited(child.child_mut())
        && error.raw_os_error() == Some(libc::ECHILD)
    {
        return child.reap();
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
    fn drain_observes_exit_without_reaping() {
        let child = command("exit 7").spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !exited(&child).unwrap() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(exited(&child).unwrap());
        let status = stop_group_and_reap(child, Duration::from_secs(2)).unwrap();
        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn zero_drain_kills_immediately() {
        let child = command("exec /bin/sleep 10").spawn().unwrap();
        assert_eq!(
            stop_group_and_reap(child, Duration::ZERO).unwrap().signal(),
            Some(libc::SIGKILL)
        );
    }

    #[test]
    fn positive_drain_has_a_deadline() {
        let child = command("exec /bin/sleep 10").spawn().unwrap();
        let start = Instant::now();
        let status = stop_group_and_reap(child, Duration::from_millis(100)).unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn measured_reaper_keeps_its_exit_status_cache() {
        struct Probe {
            child: crate::local_resource_diagnostics::cli_children::MeasuredChild,
            reaps: std::rc::Rc<std::cell::Cell<usize>>,
        }
        impl GroupChild for Probe {
            fn child_mut(&mut self) -> &mut Child {
                &mut self.child
            }
            fn reap(&mut self) -> io::Result<ExitStatus> {
                self.reaps.set(self.reaps.get() + 1);
                let status = GroupChild::reap(&mut self.child)?;
                assert_eq!(self.child.wait()?, status);
                Ok(status)
            }
        }
        let child =
            crate::local_resource_diagnostics::cli_children::spawn(&mut command("exit 7")).unwrap();
        let reaps = std::rc::Rc::new(std::cell::Cell::new(0));
        let status = stop_group_and_reap(
            Probe {
                child,
                reaps: reaps.clone(),
            },
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!(reaps.get(), 1);
    }
}
