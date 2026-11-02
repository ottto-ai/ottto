//! Restart-restore policy: ON in production, opt-in per thread in test fixtures.

// Held grown files remain discoverable.
const DISCOVERY_DEPENDENCY_READY: bool = true;

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
fn production() -> Policy {
    Policy::resolve(true, DISCOVERY_DEPENDENCY_READY)
}
fn policy() -> Policy {
    #[cfg(test)]
    {
        // Guards are thread-local.
        POLICY.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        production()
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
        Self::set(true, false)
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
    /// [behaviour] production policy is on with nothing refused.
    #[test]
    fn production_policy_is_on() {
        let policy = production();
        assert!(policy.effective);
        assert_eq!(policy.on_refused, 0);
    }
    /// [behaviour] dependency is hard and thread guards never propagate.
    #[test]
    fn dependency_is_hard_and_thread_guards_never_propagate() {
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
