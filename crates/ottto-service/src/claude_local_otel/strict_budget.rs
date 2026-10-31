//! A scoped allowance shared by a strict API/trace pair.
//! Exhaustion is failed evidence, never EOF/absence authority.
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
thread_local! {
    static REMAINING: Cell<Option<u64>> = const { Cell::new(None) };
    // Roots whose strict API or trace read refused only for the allowance.
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
    /// The root's strict API or trace read fit its per-file cap but not this pair's
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
    let remaining =
        REMAINING.with(|remaining| remaining.get().unwrap_or(super::MAX_EVIDENCE_FILE_BYTES));
    if crate::snapshots::claude_terminal_off() {
        remaining.min(super::MAX_EVIDENCE_FILE_BYTES)
    } else {
        remaining
    }
}
pub(super) fn defer(root: &str) {
    if DEFERRED.with(|deferred| deferred.borrow_mut().insert(root.to_owned())) {
        crate::local_resource_diagnostics::line_delivery_unselected(
            "claude_code",
            crate::local_resource_diagnostics::UnselectedReason::StrictBudgetDeferred,
        );
    }
}
pub(super) fn consumed(bytes: u64) {
    REMAINING.with(|remaining| {
        if let Some(left) = remaining.get() {
            remaining.set(Some(left.saturating_sub(bytes)));
        }
    });
}
