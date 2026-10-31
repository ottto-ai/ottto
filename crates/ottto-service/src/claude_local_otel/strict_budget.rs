//! A pass-local allowance shared by ordinary strict API and trace readers.
//! Exhaustion is failed evidence, never EOF/absence authority.
use std::cell::Cell;
thread_local! {
    static BYTES_READ: Cell<u64> = const { Cell::new(0) };
    static REMAINING: Cell<Option<u64>> = const { Cell::new(None) };
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
}
impl Drop for StrictReadBudget {
    fn drop(&mut self) {
        REMAINING.with(|remaining| remaining.set(None));
    }
}
pub(super) fn allowance() -> u64 {
    REMAINING.with(|remaining| remaining.get().unwrap_or(super::MAX_EVIDENCE_FILE_BYTES))
}
/// Monotone per-thread loader receipt; observation never installs an allowance.
pub(crate) fn bytes_read() -> u64 {
    BYTES_READ.with(Cell::get)
}
pub(super) fn consumed(bytes: u64) {
    BYTES_READ.with(|total| total.set(total.get().saturating_add(bytes)));
    REMAINING.with(|remaining| {
        if let Some(left) = remaining.get() {
            remaining.set(Some(left.saturating_sub(bytes)));
        }
    });
}
