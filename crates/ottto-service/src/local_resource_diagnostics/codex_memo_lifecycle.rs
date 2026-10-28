//! Cumulative process-global Codex memo transitions (L-2), separate from
//! `CodexCursorCounts` and its 4096 B record. Counters and one gauge only:
//! no identifiers, paths, namespaces or retained history. Memo records and
//! hits are counted once, in `CodexCursorCounts`. Later slices add their
//! counters together with their writers.
//!
//! Semantics: every `Counts` field is a lifetime counter (monotone since
//! process start, saturating, summed over every namespace and overlapping
//! scan). `memo_resident_bytes` is a gauge: the last measured size of the
//! resident memo, overwritten on each memo change. Neither is money, a dedup
//! or coverage figure, nor wire data. Independent relaxed loads are not a
//! transactional snapshot.
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($($field:ident: $event:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
        pub(crate) struct Counts { $(pub(crate) $field: u64),+ }
        #[derive(Clone, Copy)]
        pub(crate) enum Event { $($event),+ }
        const COUNT: usize = [$(stringify!($field)),+].len();
        // Fixed static instrumentation only: no owner/cache graph fields,
        // allocations, additional locks, identifiers or retained history.
        static TOTALS: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
        impl Counts {
            fn from_array(values: [u64; COUNT]) -> Self {
                Self { $($field: values[Event::$event as usize]),+ }
            }
            #[cfg(test)]
            fn maximum() -> Self { Self { $($field: u64::MAX),+ } }
        }
    };
}
counters! {
    // An estimate of parser input bytes a memo hit did not read again (the
    // held file's extent at the hit). Neither physical I/O nor measured CPU.
    memo_hit_estimated_avoided_parser_bytes: HitEstimatedAvoidedParserBytes,
    // A lookup that missed only because an exact-stamp entry's file grew.
    memo_miss_exact_stamp: MissExactStamp,
    // The grown extent of those misses (the bytes then re-read).
    memo_miss_exact_stamp_bytes: MissExactStampBytes,
    // Every other miss of a lookup that found an entry, plus an owed-parent
    // bypass. A lookup that finds no entry is not counted, so thrashing past
    // the memo's 256-entry cap (entries evicted before their next lookup) is
    // invisible here; `memo_entries` at the cap is its only signal.
    memo_miss_other: MissOther,
}
/// Last stored resident memo bytes (gauge, `set_resident` only). The entry
/// count is already `CodexCursorRetained.memo_entries`.
static RESIDENT_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Record {
    #[serde(flatten)]
    pub(crate) counts: Counts,
    pub(crate) memo_resident_bytes: u64,
}
impl Record {
    #[cfg(test)]
    pub(super) fn maximum() -> Self {
        Self {
            counts: Counts::maximum(),
            memo_resident_bytes: u64::MAX,
        }
    }
}

pub(crate) fn add(event: Event, amount: u64) {
    let _ = TOTALS[event as usize].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(amount))
    });
    #[cfg(test)]
    TEST_EVENTS.with(|events| {
        if let Some(mut values) = events.get() {
            values[event as usize] = values[event as usize].saturating_add(amount);
            events.set(Some(values));
        }
    });
}
pub(crate) fn record(event: Event) {
    add(event, 1);
}
pub(crate) fn set_resident(bytes: u64) {
    RESIDENT_BYTES.store(bytes, Ordering::Relaxed);
}
pub(crate) fn snapshot() -> Record {
    Record {
        counts: Counts::from_array(std::array::from_fn(|i| TOTALS[i].load(Ordering::Relaxed))),
        memo_resident_bytes: RESIDENT_BYTES.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
thread_local! {
    static TEST_EVENTS: std::cell::Cell<Option<[u64; COUNT]>> = const { std::cell::Cell::new(None) };
}
/// Isolates assertions from concurrent fixtures without resetting or
/// changing the production process totals. No production observer or callback.
#[cfg(test)]
pub(crate) fn observe<T>(f: impl FnOnce() -> T) -> (T, Counts) {
    struct Reset(Option<[u64; COUNT]>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_EVENTS.with(|events| events.set(self.0));
        }
    }
    let reset = Reset(TEST_EVENTS.with(|events| events.replace(Some([0; COUNT]))));
    let value = f();
    let counts = TEST_EVENTS.with(|events| Counts::from_array(events.get().unwrap()));
    drop(reset);
    (value, counts)
}
