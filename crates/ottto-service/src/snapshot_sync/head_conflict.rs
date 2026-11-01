//! Optional, bounded recovery metadata; never authority for money or receipts.
use std::sync::atomic::{AtomicU64, Ordering};

static REFUSED: AtomicU64 = AtomicU64::new(0);

pub(super) fn note(reason: &str) {
    let total = REFUSED.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    eprintln!(
        "local snapshot head-CAS recovery metadata refused: reason={reason} count=1 process_total={total}; usage remains held"
    );
    #[cfg(test)]
    REFUSALS.with(|counts| counts.borrow_mut().push(reason.to_string()));
}

#[cfg(test)]
thread_local! {
    pub(super) static REFUSALS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}
