//! Machine-local opt-in, using the existing support-directory sentinel pattern.
//! No ScanIndex field, upload field, remote setting or agent-writable API.

/// Declares a module's `enabled()` and `enabled_at(support)`: one owner-set
/// marker in the support directory, sampled once per process.
macro_rules! local_switch {
    ($marker:expr, marker_enables = $enables:literal, test_default = $default:literal) => {
        pub(super) fn enabled() -> bool {
            #[cfg(test)]
            {
                // A test must opt in on its own thread, never read the host setting.
                ENABLED.with(std::cell::Cell::get)
            }
            #[cfg(not(test))]
            {
                // Pin policy for this process, including worker threads and yields.
                // Ron changes the marker himself and restarts the daemon to apply it.
                static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
                *ENABLED.get_or_init(|| enabled_at(&ottto_core::default_support_dir()))
            }
        }
        fn enabled_at(support: &std::path::Path) -> bool {
            // As with mcp_inventory/disabled and context_footprint/disabled, the
            // owner's local marker is the setting. Refuse symlinks and non-files.
            let marker = std::fs::symlink_metadata(support.join($marker))
                .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink());
            marker == $enables
        }
        #[cfg(test)]
        thread_local! {
            static ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new($default) };
        }
    };
}
pub(super) use local_switch;

pub(super) const NAME: &str = "claude_terminal_off_enabled";
local_switch!(NAME, marker_enables = true, test_default = false);

/// Sets a test switch for this thread until dropped; unwind restores the
/// previous value. Rc makes the guard !Send/!Sync, so moving it cannot
/// silently change another fixture's policy.
#[cfg(test)]
pub(crate) struct ThreadSwitchForTest {
    slot: &'static std::thread::LocalKey<std::cell::Cell<bool>>,
    previous: bool,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(test)]
impl ThreadSwitchForTest {
    pub(crate) fn set(
        slot: &'static std::thread::LocalKey<std::cell::Cell<bool>>,
        value: bool,
    ) -> Self {
        Self {
            slot,
            previous: slot.with(|switch| switch.replace(value)),
            _thread: std::marker::PhantomData,
        }
    }
}
#[cfg(test)]
impl Drop for ThreadSwitchForTest {
    fn drop(&mut self) {
        self.slot.with(|switch| switch.set(self.previous));
    }
}

#[cfg(test)]
pub(crate) struct ClaudeTerminalOffForTest {
    _switch: ThreadSwitchForTest,
}
#[cfg(test)]
impl ClaudeTerminalOffForTest {
    pub(crate) fn enabled() -> Self {
        Self {
            _switch: ThreadSwitchForTest::set(&ENABLED, true),
        }
    }
    /// The thread's test policy, ignoring any completion-path override.
    /// Retained feature fixtures use it to select their containment setup;
    /// main tests keep the original helper at the default OFF.
    pub(crate) fn active() -> bool {
        ENABLED.with(std::cell::Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// [off=main] Default OFF preserves the main policy and checkpoint contract.
    #[test]
    fn machine_switch_defaults_off_and_only_local_regular_marker_enables() {
        let scratch = crate::test_scratch::ScratchDir::new("terminal-off-policy");
        assert!(!enabled_at(&scratch));
        std::fs::write(scratch.join(NAME), b"").unwrap();
        assert!(enabled_at(&scratch));
        std::fs::remove_file(scratch.join(NAME)).unwrap();
        assert!(!enabled_at(&scratch));
        std::fs::create_dir(scratch.join(NAME)).unwrap();
        assert!(!enabled_at(&scratch));
        assert!(!enabled(), "fixture process never consults host marker");
        let guard = ClaudeTerminalOffForTest::enabled();
        assert!(enabled());
        assert!(!std::thread::spawn(enabled).join().unwrap());
        drop(guard);
        assert!(!enabled());
    }
}
