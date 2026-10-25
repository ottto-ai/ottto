//! One paced reassessment of an unchanged rejected body after reconstruction changes.
use super::{SnapshotQuarantineDisposition, SnapshotQuarantineRecord, SnapshotQuarantineWitness};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Bump only in PRs that change reconstruction logic or its contract. A bump
/// grants each retained unproven terminal record one paced attempt, not a
/// history replay. Adding this field does not itself change reconstruction.
const RECONSTRUCTION_CONTRACT: u16 = 1;

pub(super) const fn legacy_contract() -> u16 {
    1
}

pub(crate) fn current_contract() -> u16 {
    #[cfg(test)]
    if let Some(version) = CONTRACT_FOR_TEST.with(std::cell::Cell::get) {
        return version;
    }
    RECONSTRUCTION_CONTRACT
}

// Counts local record transitions (index and disposable upload ledger), never
// identities or upload fields. Existing terminal-census lines expose the total.
static TERMINAL_CONTRACT_RETRY: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn local_count() -> usize {
    TERMINAL_CONTRACT_RETRY.load(Ordering::Relaxed)
}

pub(crate) fn rearm<'a>(
    records: impl IntoIterator<Item = (&'a String, &'a mut SnapshotQuarantineRecord)>,
    active_witness: Option<&SnapshotQuarantineWitness>,
) -> usize {
    let current = current_contract();
    let mut count = 0;
    for (fingerprint, record) in records {
        if record.disposition != SnapshotQuarantineDisposition::UnprovenTerminal
            || record.reconstruction_contract >= current
        {
            continue;
        }
        record.disposition = SnapshotQuarantineDisposition::RetryPending;
        record.failed_reconstruction_count = super::MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1;
        record.retry_after_unix_seconds = crate::snapshot_sync::quarantine_retry_after(fingerprint);
        record.reconstruction_contract = current;
        // A simultaneous collector/witness upgrade must not bypass pacing.
        if let Some(active) = active_witness {
            record.witness = active.clone();
        }
        count += 1;
    }
    TERMINAL_CONTRACT_RETRY.fetch_add(count, Ordering::Relaxed);
    count
}

#[cfg(test)]
thread_local! {
    static CONTRACT_FOR_TEST: std::cell::Cell<Option<u16>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_contract<T>(version: u16, run: impl FnOnce() -> T) -> T {
    struct Guard(Option<u16>);
    impl Drop for Guard {
        fn drop(&mut self) {
            CONTRACT_FOR_TEST.with(|value| value.set(self.0));
        }
    }
    let _guard = Guard(CONTRACT_FOR_TEST.with(|value| value.replace(Some(version))));
    run()
}
