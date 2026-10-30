//! Machine-local M3 opt-in. Policy is fixed for the lifetime of the process.
use std::path::Path;

const NAME: &str = "restart_restore_enabled";
// #876 + F4 must flip this marker only when held grown files remain discoverable.
// The sentinel alone can never bypass this release dependency.
const DISCOVERY_DEPENDENCY_READY: bool = false;

#[derive(Clone, Copy, Default)]
struct Policy {
    effective: bool,
    on_refused: u64,
}
impl Policy {
    fn resolve(requested: bool, discovery_ready: bool) -> Self {
        Self {
            effective: requested && discovery_ready,
            on_refused: u64::from(requested && !discovery_ready),
        }
    }
}
fn requested_at(support: &Path) -> bool {
    std::fs::symlink_metadata(support.join(NAME))
        .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
}
fn policy() -> Policy {
    #[cfg(test)]
    {
        // Fixtures never consult the host sentinel. Guards are thread-local.
        POLICY.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        static POLICY: std::sync::OnceLock<Policy> = std::sync::OnceLock::new();
        *POLICY.get_or_init(|| {
            Policy::resolve(
                requested_at(&ottto_core::default_support_dir()),
                DISCOVERY_DEPENDENCY_READY,
            )
        })
    }
}
pub(super) fn enabled() -> bool {
    policy().effective
}
pub(super) fn on_refused_discovery_dependency() -> u64 {
    policy().on_refused
}

#[cfg(test)]
thread_local! {
    static POLICY: std::cell::Cell<Policy> = const { std::cell::Cell::new(Policy { effective: false, on_refused: 0 }) };
}
#[cfg(test)]
pub(crate) struct RestartRestoreForTest {
    previous: Policy,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(test)]
impl RestartRestoreForTest {
    pub(crate) fn enabled() -> Self {
        Self::set(true, true)
    }
    pub(crate) fn disabled() -> Self {
        Self::set(false, false)
    }
    pub(crate) fn requested_without_dependency() -> Self {
        Self::set(true, DISCOVERY_DEPENDENCY_READY)
    }
    fn set(requested: bool, discovery_ready: bool) -> Self {
        Self {
            previous: POLICY.with(|slot| slot.replace(Policy::resolve(requested, discovery_ready))),
            _thread: std::marker::PhantomData,
        }
    }
}
#[cfg(test)]
impl Drop for RestartRestoreForTest {
    fn drop(&mut self) {
        POLICY.with(|slot| slot.set(self.previous));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// [behaviour] sentinel requires regular file and defaults off.
    #[test]
    fn sentinel_requires_regular_file_and_defaults_off() {
        let scratch = crate::test_scratch::ScratchDir::new("restart-restore-policy");
        assert!(!requested_at(&scratch));
        std::fs::write(scratch.join(NAME), b"").unwrap();
        assert!(requested_at(&scratch));
        std::fs::remove_file(scratch.join(NAME)).unwrap();
        std::fs::create_dir(scratch.join(NAME)).unwrap();
        assert!(!requested_at(&scratch));
        std::fs::remove_dir(scratch.join(NAME)).unwrap();
        #[cfg(unix)]
        {
            std::fs::write(scratch.join("target"), b"").unwrap();
            std::os::unix::fs::symlink(scratch.join("target"), scratch.join(NAME)).unwrap();
            assert!(!requested_at(&scratch));
        }
    }
    /// [behaviour] dependency is hard and thread guards never read host or propagate.
    #[test]
    fn dependency_is_hard_and_thread_guards_never_read_host_or_propagate() {
        assert!(!enabled());
        let refused = RestartRestoreForTest::requested_without_dependency();
        assert!(!enabled());
        assert_eq!(on_refused_discovery_dependency(), 1);
        let enabled_guard = RestartRestoreForTest::enabled();
        assert!(enabled());
        assert_eq!(on_refused_discovery_dependency(), 0);
        assert!(!std::thread::spawn(enabled).join().unwrap());
        drop(enabled_guard);
        assert!(!enabled());
        assert_eq!(on_refused_discovery_dependency(), 1);
        drop(refused);
        assert_eq!(on_refused_discovery_dependency(), 0);
    }
}
