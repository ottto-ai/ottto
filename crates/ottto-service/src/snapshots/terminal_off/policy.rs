//! Machine-local opt-in, using the existing support-directory sentinel pattern.
//! No ScanIndex field, upload field, remote setting or agent-writable API.
use std::path::Path;

pub(super) const NAME: &str = "claude_terminal_off_enabled";
fn enabled_at(support: &Path) -> bool {
    marker_at(support, NAME)
}
pub(in crate::snapshots) fn marker_at(support: &Path, name: &str) -> bool {
    // As with mcp_inventory/disabled and context_footprint/disabled, the
    // owner's local marker is the setting. Refuse symlinks and non-files.
    std::fs::symlink_metadata(support.join(name))
        .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
}

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

/// Q-D3: hash the child's consumed root evidence instead of sidecar stats.
pub(in crate::snapshots) fn child_evidence_digest() -> bool {
    #[cfg(test)]
    { false }
    #[cfg(not(test))]
    {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| marker_at(
            &ottto_core::default_support_dir(), "claude_child_evidence_digest_enabled",
        ))
    }
}

#[cfg(test)]
thread_local! {
    static ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) struct ClaudeTerminalOffForTest {
    previous: bool,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(test)]
impl ClaudeTerminalOffForTest {
    pub(crate) fn enabled() -> Self {
        Self::set(true)
    }
    /// The thread's test policy, ignoring any completion-path override.
    /// Retained feature fixtures use it to select their containment setup;
    /// main tests keep the original helper at the default OFF.
    pub(crate) fn active() -> bool {
        ENABLED.with(std::cell::Cell::get)
    }
    fn set(enabled: bool) -> Self {
        Self {
            previous: ENABLED.with(|slot| slot.replace(enabled)),
            _thread: std::marker::PhantomData,
        }
    }
}
#[cfg(test)]
impl Drop for ClaudeTerminalOffForTest {
    fn drop(&mut self) {
        ENABLED.with(|slot| slot.set(self.previous));
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
