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

/// Requires an exclusively owned group leader (process_group(0) or setsid()).
/// The owner is the sole reaper: peek only with waitid(WNOWAIT) for up to `drain`.
/// Then, whether the leader exited or is running, kill its checked group with
/// SIGKILL before reaping; an exited zombie still reserves its pid/pgid. Kill
/// the direct child only if it is still running, then reap. Group checks require
/// pgid > 1 and pgid != getpgrp(), using only this owned child's pid.
/// ECHILD means already reaped elsewhere: send no signal. Consume ownership;
/// never send a group signal after a reap. No SIGTERM step.
pub(crate) fn stop_group_and_reap(
    mut child: impl GroupChild,
    drain: Duration,
) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + drain;
    loop {
        match exited(child.child_mut()) {
            Ok(true) => break,
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
    let direct = child.child_mut();
    if let Ok(pgid) = libc::pid_t::try_from(direct.id())
        && pgid > 1
        && pgid != unsafe { libc::getpgrp() }
    {
        // Even an exited leader may have live descendants in its group.
        unsafe { libc::killpg(pgid, libc::SIGKILL) };
    }
    match exited(direct) {
        Ok(true) => {}
        Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
        _ => {
            let _ = direct.kill();
        }
    }
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

    fn exited_leader_with_descendant() -> (Child, libc::pid_t) {
        use std::io::Read;
        let mut child = command("/bin/sleep 10 >/dev/null 2>&1 & echo $!; exit 7")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        let descendant = output.trim().parse().unwrap();
        assert!(descendant > 1);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !exited(&child).unwrap() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        (child, descendant)
    }

    fn running(pid: libc::pid_t) -> bool {
        let output = Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&output.stdout);
        !state.trim().is_empty() && !state.trim().starts_with('Z')
    }

    #[test]
    fn exited_leader_stops_descendant_before_reaping() {
        struct Owner {
            child: Child,
            descendant: libc::pid_t,
            reaped: bool,
        }
        impl GroupChild for Owner {
            fn child_mut(&mut self) -> &mut Child {
                assert!(!self.reaped, "accessed child after reap");
                &mut self.child
            }
            fn reap(&mut self) -> io::Result<ExitStatus> {
                assert!(!self.reaped, "reaped twice");
                let deadline = Instant::now() + Duration::from_secs(2);
                while running(self.descendant) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(10));
                }
                let stopped_before_reap = !running(self.descendant);
                let status = self.child.wait()?;
                self.reaped = true;
                if !stopped_before_reap {
                    unsafe { libc::kill(self.descendant, libc::SIGKILL) };
                }
                assert!(stopped_before_reap, "descendant survived until leader reap");
                Ok(status)
            }
        }
        let (child, descendant) = exited_leader_with_descendant();
        let status = stop_group_and_reap(
            Owner {
                child,
                descendant,
                reaped: false,
            },
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(status.code(), Some(7));
        assert!(!running(descendant));
    }

    #[test]
    fn echild_does_not_signal_the_remaining_group() {
        let (child, descendant) = exited_leader_with_descendant();
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child.id() as libc::pid_t, &mut status, 0) },
            child.id() as libc::pid_t
        );
        // Bypass Child's cached status so the helper's peek really returns ECHILD.
        let result = stop_group_and_reap(child, Duration::from_secs(2));
        let survived = running(descendant);
        unsafe { libc::kill(descendant, libc::SIGKILL) };
        assert!(survived, "ECHILD path signalled the remaining group");
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ECHILD));
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
