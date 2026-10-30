//! Cumulative process-global cache transitions, including overlapping scans.
//! Independent relaxed loads are not a transactional snapshot. These counters
//! cannot assign an absent entry's historical cause to a file or namespace.
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($($field:ident: $event:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
        pub(crate) struct Counts { $(pub(crate) $field: u64),+ }
        pub(crate) struct Sparse(pub(crate) Counts);
        impl Serialize for Sparse {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(None)?;
                $(if self.0.$field != 0 { map.serialize_entry(stringify!($field), &self.0.$field)?; })+
                map.end()
            }
        }
        #[derive(Clone, Copy)]
        pub(crate) enum Event { $($event),+ }
        const COUNT: usize = [$(stringify!($field)),+].len();
        // Fixed static instrumentation only: no owner/cache graph fields,
        // allocations, additional locks, identifiers or retained history.
        static TOTALS: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
        impl Counts {
            pub(crate) fn add(&mut self, event: Event, amount: u64) {
                match event { $(Event::$event => self.$field = self.$field.saturating_add(amount)),+ }
            }
            pub(crate) fn merge(&mut self, other: Self) {
                $(self.$field = self.$field.saturating_add(other.$field);)+
            }
            pub(crate) fn is_empty(&self) -> bool { $(self.$field == 0)&&+ }
            fn from_array(values: [u64; COUNT]) -> Self {
                Self { $($field: values[Event::$event as usize]),+ }
            }
            #[cfg(test)]
            pub(super) fn maximum() -> Self { Self { $($field: u64::MAX),+ } }
        }
    };
}
counters! {
    take_hit: TakeHit,
    take_absent: TakeAbsent,
    take_poisoned_lock: TakePoisonedLock,
    insert_admitted: InsertAdmitted,
    insert_live_reservation_refused: InsertLiveReservationRefused,
    insert_clock_reset: InsertClockReset,
    insert_disabled_or_layout_refused: InsertDisabledOrLayoutRefused,
    insert_entry_bound_refused: InsertEntryBoundRefused,
    insert_frozen_charge_refused: InsertFrozenChargeRefused,
    insert_key_bound_refused: InsertKeyBoundRefused,
    insert_self_evicted: InsertSelfEvicted,
    insert_no_victim_refused: InsertNoVictimRefused,
    insert_poisoned_lock: InsertPoisonedLock,
    insert_entries_evicted: InsertEntriesEvicted,
    cache_evicted_by_pi_claude_code: CacheEvictedByPiClaudeCode,
    cache_evicted_by_pi_codex: CacheEvictedByPiCodex,
    cursor_reservation_entries_evicted: CursorReservationEntriesEvicted,
    // M1 copy refusals. `entries_evicted` and `admission_evicted` count
    // entries; `bytes_released` their stored charge, for both causes.
    // `admission_evicted` also counts a shape-F completion's exact
    // lower-ranked release (P1-RETAIN R0, `Release::CopyAdmission`). The
    // others count zero-budget step starts, not files or refusals: a long
    // tail beside a full cache counts once per line it reads.
    copy_refusal_entries_evicted: CopyRefusalEntriesEvicted,
    copy_refusal_bytes_released: CopyRefusalBytesReleased,
    copy_refusal_remeasured: CopyRefusalRemeasured,
    copy_refusal_kept: CopyRefusalKept,
    copy_refusal_walk_visit_limit: CopyRefusalWalkVisitLimit,
    copy_refusal_admission_evicted: CopyRefusalAdmissionEvicted,
    clear_metadata_unsupported: ClearMetadataUnsupported,
    clear_full_resident_bound_unknown: ClearFullResidentBoundUnknown,
    clear_no_active: ClearNoActive,
    clear_other_active: ClearOtherActive,
    clear_entries_released: ClearEntriesReleased,
    clear_poisoned_lock: ClearPoisonedLock,
    retention_incomplete_or_lossy: RetentionIncompleteOrLossy,
    retention_incompatible: RetentionIncompatible,
    retention_bound_refused: RetentionBoundRefused,
    retention_bound_refused_pi: RetentionBoundRefusedPi,
    retention_bound_refused_pi_bytes: RetentionBoundRefusedPiBytes,
    retention_bound_refused_pi_bytes_unavailable: RetentionBoundRefusedPiBytesUnavailable,
    // Transitional Pi Full on change without a RAM record (no durable Pi yet).
    pi: Pi,
    retention_no_plan: RetentionNoPlan,
    retention_unsealed_eof: RetentionUnsealedEof,
    retention_clone_bound_refused: RetentionCloneBoundRefused,
    retention_finalization_bound_refused: RetentionFinalizationBoundRefused,
    retention_produced: RetentionProduced,
    // SOURCE (B): fixed content-free totals, never per-file history.
    prefix_excluded_bodies: PrefixExcludedBody,
    prefix_tag_clears: PrefixTagCleared,
}

pub(crate) fn add(event: Event, amount: u64) {
    super::claude_reread::cache_event(event, amount);
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
pub(crate) fn snapshot() -> Counts {
    Counts::from_array(std::array::from_fn(|i| TOTALS[i].load(Ordering::Relaxed)))
}

#[cfg(test)]
thread_local! {
    static TEST_EVENTS: std::cell::Cell<Option<[u64; COUNT]>> = const { std::cell::Cell::new(None) };
}
/// This thread's counts so far inside `observe`, for a mid-run phase split
/// (tests only); `None` outside `observe`.
#[cfg(test)]
pub(crate) fn observed() -> Option<Counts> {
    TEST_EVENTS.with(|events| events.get().map(Counts::from_array))
}
/// Isolates assertions from concurrent cache fixtures without resetting or
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
