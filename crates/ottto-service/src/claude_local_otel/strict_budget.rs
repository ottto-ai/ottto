//! A pass-local allowance shared by ordinary strict API and trace readers.
//! Exhaustion is failed evidence, never EOF/absence authority.
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
thread_local! {
    static REMAINING: Cell<Option<u64>> = const { Cell::new(None) };
    // Roots whose strict API read this pass refused only for the allowance.
    static DEFERRED: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}
pub(crate) struct StrictReadBudget {
    allowance: u64,
}
impl StrictReadBudget {
    pub(crate) fn new(allowance: u64) -> Self {
        REMAINING.with(|remaining| {
            assert!(
                remaining.replace(Some(allowance)).is_none(),
                "nested strict allowance"
            );
        });
        Self { allowance }
    }
    pub(crate) fn consumed(&self) -> u64 {
        self.allowance - REMAINING.with(|remaining| remaining.get().unwrap_or(0))
    }
    /// The root's strict API read fit its per-file cap but not this pass's
    /// allowance: it waits for a later pass (#932 hold), it is not unhealthy.
    pub(crate) fn deferred(&self, root: &str) -> bool {
        DEFERRED.with(|deferred| deferred.borrow().contains(root))
    }
}
impl Drop for StrictReadBudget {
    fn drop(&mut self) {
        REMAINING.with(|remaining| remaining.set(None));
        DEFERRED.with(|deferred| deferred.borrow_mut().clear());
    }
}
pub(super) fn allowance() -> u64 {
    REMAINING.with(|remaining| remaining.get().unwrap_or(super::MAX_EVIDENCE_FILE_BYTES))
}
pub(super) fn defer(root: &str) {
    DEFERRED.with(|deferred| deferred.borrow_mut().insert(root.to_owned()));
}
pub(super) fn consumed(bytes: u64) {
    REMAINING.with(|remaining| {
        if let Some(left) = remaining.get() {
            remaining.set(Some(left.saturating_sub(bytes)));
        }
    });
}
