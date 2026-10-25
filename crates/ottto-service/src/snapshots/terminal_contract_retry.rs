//! One paced reassessment of an unchanged rejected body after reconstruction changes.
use super::{SnapshotQuarantineDisposition, SnapshotQuarantineRecord, SnapshotQuarantineWitness};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Bump only in PRs that change reconstruction logic or its contract. A bump
/// grants each retained unproven terminal record one paced attempt, not a
/// history replay. Adding this field does not itself change reconstruction.
const RECONSTRUCTION_CONTRACT: u16 = 1;
/// No known reconstruction assessment. This sentinel must receive one paced
/// attempt rather than resetting unrelated state or becoming opaque debt.
const UNKNOWN_CONTRACT: u16 = 0;

pub(super) const fn legacy_contract() -> u16 {
    1
}

/// Decode non-identity bookkeeping without failing its enclosing record.
/// Consume malformed containers too, without allocating their contents. Missing
/// fields still use `legacy_contract`; only malformed-present values are unknown.
pub(super) fn decode_contract<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u16, D::Error> {
    struct Contract;
    impl<'de> serde::de::Visitor<'de> for Contract {
        type Value = u16;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a reconstruction contract version or unknown bookkeeping")
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<u16, E> {
            Ok(u16::try_from(value).unwrap_or(UNKNOWN_CONTRACT))
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<u16, E> {
            Ok(u16::try_from(value).unwrap_or(UNKNOWN_CONTRACT))
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<u16, E> {
            Ok(UNKNOWN_CONTRACT)
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<u16, E> {
            Ok(UNKNOWN_CONTRACT)
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<u16, E> {
            Ok(UNKNOWN_CONTRACT)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<u16, E> {
            Ok(UNKNOWN_CONTRACT)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut values: A) -> Result<u16, A::Error> {
            while values.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(UNKNOWN_CONTRACT)
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut values: A) -> Result<u16, A::Error> {
            while values
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {}
            Ok(UNKNOWN_CONTRACT)
        }
    }
    deserializer.deserialize_any(Contract)
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
        let unassessed_pending = record.reconstruction_contract == UNKNOWN_CONTRACT
            && record.disposition == SnapshotQuarantineDisposition::RetryPending;
        if (record.disposition != SnapshotQuarantineDisposition::UnprovenTerminal
            && !unassessed_pending)
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
