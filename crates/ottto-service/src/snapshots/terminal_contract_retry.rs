//! Bounded paced reassessment of an unchanged rejected body after reconstruction changes.
use super::{SnapshotQuarantineDisposition, SnapshotQuarantineRecord, SnapshotQuarantineWitness};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Bump only in PRs that change reconstruction logic or its contract. A bump
/// grants each retained unproven terminal record at most two claimed reads, not a
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
    decode_u16(deserializer, UNKNOWN_CONTRACT)
}

/// A malformed-present claim is exhausted, never a fresh budget. Absence means
/// an ordinary pre-existing retry; a contract migration explicitly sets Some(0).
pub(super) fn decode_claims<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<u16>, D::Error> {
    decode_u16(d, MAX_CLAIMS).map(Some)
}

fn decode_u16<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
    invalid: u16,
) -> Result<u16, D::Error> {
    struct Contract(u16);
    impl<'de> serde::de::Visitor<'de> for Contract {
        type Value = u16;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a reconstruction contract version or unknown bookkeeping")
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<u16, E> {
            Ok(u16::try_from(value).unwrap_or(self.0))
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<u16, E> {
            Ok(u16::try_from(value).unwrap_or(self.0))
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<u16, E> {
            Ok(self.0)
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<u16, E> {
            Ok(self.0)
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<u16, E> {
            Ok(self.0)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<u16, E> {
            Ok(self.0)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut values: A) -> Result<u16, A::Error> {
            while values.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(self.0)
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut values: A) -> Result<u16, A::Error> {
            while values
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {}
            Ok(self.0)
        }
    }
    deserializer.deserialize_any(Contract(invalid))
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
pub(crate) const MAX_CLAIMS: u16 = 2;
static TERMINAL_CONTRACT_RETRY_EXHAUSTED: AtomicUsize = AtomicUsize::new(0);
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
        record.contract_retry_claims = Some(0);
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

/// A claim is spent at selection, before its durable save and source acquisition.
/// Failed saves abort acquisition; failed outcomes cannot undo a saved claim.
pub(crate) fn claim(record: &mut SnapshotQuarantineRecord) {
    if let Some(claims) = &mut record.contract_retry_claims {
        *claims = claims.saturating_add(1);
    }
}

pub(crate) fn exhausted_count() -> usize {
    TERMINAL_CONTRACT_RETRY_EXHAUSTED.load(Ordering::Relaxed)
}

pub(crate) fn exhaust(record: &mut SnapshotQuarantineRecord) -> bool {
    if record
        .contract_retry_claims
        .is_some_and(|n| n >= MAX_CLAIMS)
        && record.disposition == SnapshotQuarantineDisposition::RetryPending
    {
        record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
        record.failed_reconstruction_count = super::MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
        record.retry_after_unix_seconds = 0;
        TERMINAL_CONTRACT_RETRY_EXHAUSTED.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

/// Merge only like-version, exact-body budgets. A newer claim also owns its
/// cooldown; an older timer or copy cannot revive it. Other retry policy stays
/// with the caller. Contract bumps create a distinct budget.
pub(crate) fn merge_claims(
    record: &mut SnapshotQuarantineRecord,
    other: &SnapshotQuarantineRecord,
) -> bool {
    let before = record.clone();
    if record.reconstruction_contract == other.reconstruction_contract
        && record.upload_body_witness == other.upload_body_witness
    {
        if let Some(claims) = other.contract_retry_claims {
            let previous = record.contract_retry_claims;
            record.contract_retry_claims = Some(previous.unwrap_or(0).max(claims));
            if previous.is_none_or(|n| n < claims)
                && record.disposition == SnapshotQuarantineDisposition::RetryPending
            {
                record.retry_after_unix_seconds = record
                    .retry_after_unix_seconds
                    .max(other.retry_after_unix_seconds);
            }
            if previous.is_none_or(|n| n <= claims)
                && other.disposition == SnapshotQuarantineDisposition::UnprovenTerminal
            {
                record.disposition = other.disposition;
                record.failed_reconstruction_count = other.failed_reconstruction_count;
                record.retry_after_unix_seconds = 0;
            }
        }
    }
    *record != before
}

pub(crate) fn merge_maps(
    records: &mut std::collections::BTreeMap<String, SnapshotQuarantineRecord>,
    other: &std::collections::BTreeMap<String, SnapshotQuarantineRecord>,
) -> bool {
    let mut changed = false;
    for (fingerprint, record) in records {
        if let Some(other) = other.get(fingerprint) {
            changed |= merge_claims(record, other);
        }
    }
    changed
}

#[cfg(test)]
thread_local! {
    static SOURCE_ACQUISITIONS: std::cell::RefCell<Option<std::collections::BTreeMap<std::path::PathBuf, usize>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn record_source_acquisition(path: &std::path::Path) {
    SOURCE_ACQUISITIONS.with(|reads| {
        if let Some(reads) = reads.borrow_mut().as_mut() {
            *reads.entry(path.to_owned()).or_default() += 1;
        }
    });
}
#[cfg(test)]
pub(crate) fn source_acquisitions<T>(
    run: impl FnOnce() -> T,
) -> (T, std::collections::BTreeMap<std::path::PathBuf, usize>) {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            SOURCE_ACQUISITIONS.with(|reads| {
                reads.replace(None);
            });
        }
    }
    let _guard = Guard;
    SOURCE_ACQUISITIONS.with(|reads| {
        assert!(reads.replace(Some(Default::default())).is_none());
    });
    let result = run();
    let reads = SOURCE_ACQUISITIONS.with(|reads| reads.replace(None).unwrap());
    (result, reads)
}
