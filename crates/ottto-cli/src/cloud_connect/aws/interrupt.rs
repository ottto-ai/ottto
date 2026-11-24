//! Keep the isolated AWS process group under Ottto's supervision on interruption.

use crate::cloud_connect::Failure;
use std::io;

#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(unix)]
static SIGNAL: AtomicI32 = AtomicI32::new(0);

pub(super) struct InterruptGuard {
    #[cfg(unix)]
    _interrupt: ScopedSignal,
    #[cfg(unix)]
    _terminate: ScopedSignal,
}

impl InterruptGuard {
    pub(super) fn install() -> io::Result<Self> {
        #[cfg(unix)]
        SIGNAL.store(0, Ordering::Relaxed);
        Ok(Self {
            #[cfg(unix)]
            _interrupt: ScopedSignal::install(libc::SIGINT)?,
            #[cfg(unix)]
            _terminate: ScopedSignal::install(libc::SIGTERM)?,
        })
    }
}

pub(super) fn check() -> Result<(), Failure> {
    #[cfg(unix)]
    match SIGNAL.load(Ordering::Relaxed) {
        signal @ (libc::SIGINT | libc::SIGTERM) => {
            let mut failure = Failure::new(
                "interrupted",
                "Cloud setup was interrupted. Run the command again to resume.",
                "run_again",
            );
            failure.reason = Some(
                if signal == libc::SIGTERM {
                    "sigterm"
                } else {
                    "sigint"
                }
                .into(),
            );
            return Err(failure);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(unix)]
extern "C" fn record_signal(signal: libc::c_int) {
    SIGNAL.store(signal, Ordering::Relaxed);
}

#[cfg(unix)]
struct ScopedSignal {
    signal: libc::c_int,
    previous: libc::sigaction,
}

#[cfg(unix)]
impl ScopedSignal {
    fn install(signal: libc::c_int) -> io::Result<Self> {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = record_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        let mut previous = std::mem::MaybeUninit::uninit();
        // The handler only stores the signal number. The supervising thread
        // can then stop the child group and restore the original disposition.
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, previous.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                signal,
                previous: previous.assume_init(),
            })
        }
    }
}

#[cfg(unix)]
impl Drop for ScopedSignal {
    fn drop(&mut self) {
        unsafe { libc::sigaction(self.signal, &self.previous, std::ptr::null_mut()) };
    }
}
