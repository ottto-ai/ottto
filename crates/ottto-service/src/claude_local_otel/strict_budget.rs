//! A pass-local allowance shared by ordinary strict API and trace readers.
//! Exhaustion is failed evidence, never EOF/absence authority.
use std::cell::Cell;
thread_local! {
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
/// Without a pass budget, one streaming root is its own read turn. A larger
/// pair gets a protected allowance rather than being permanently refused.
pub(super) fn allowance(pair_bytes: u64) -> u64 {
    REMAINING.with(|remaining| {
        remaining
            .get()
            .unwrap_or_else(|| protected_allowance(super::MAX_EVIDENCE_FILE_BYTES, pair_bytes))
    })
}
pub(crate) fn protected_allowance(quantum: u64, pair_bytes: u64) -> u64 {
    if pair_bytes > quantum {
        crate::local_resource_diagnostics::traversal_point(
            "claude_sidecar_read",
            "claude_code",
            &std::collections::BTreeMap::from([
                ("oversized_root_alone", 1),
                ("allowance_bytes", pair_bytes),
            ]),
        );
    }
    quantum.max(pair_bytes)
}
pub(super) fn consumed(bytes: u64) {
    REMAINING.with(|remaining| {
        if let Some(left) = remaining.get() {
            remaining.set(Some(left.saturating_sub(bytes)));
        }
    });
}
