//! Production glue. One process-owned cache is shared by background and manual
//! cycles; provider parsing, durable index/CAS and delivery remain native.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::local_resource_diagnostics::cache_lifecycle::{record, Event};
use crate::transcript_acquisition::{ReadMode, Scope};
use crate::transcript_cache::{Release, TranscriptCache, CACHE_BYTES, CACHE_ENTRIES, ENTRY_BYTES};
use sampled_jsonl::CachedJsonlReduction;

// The existing owner enforces aggregate parked/optional-send overlap. The
// separate 1MiB reserve covers bounded marker strings in existing index copies
// and fixed acquisition/path scratch; it is not a daemon RSS allowance.
const AUDIT_AND_SCRATCH_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const RETAIL_RESERVE_BYTES: usize = 2 * (2 * crate::durable_tail_store::MAX_RECORDS + 1) * 1024;
#[cfg(not(unix))]
const RETAIL_RESERVE_BYTES: usize = 0;
#[cfg(unix)]
const KEY_RESERVE_BYTES: usize = durable_tail::KEY_RESERVE_BYTES;
#[cfg(not(unix))]
const KEY_RESERVE_BYTES: usize = 0;
#[cfg(unix)]
const STALE_PREDECESSOR_RESERVE_BYTES: usize = durable_tail::STALE_PREDECESSOR_RESERVE_BYTES;
#[cfg(not(unix))]
const STALE_PREDECESSOR_RESERVE_BYTES: usize = 0;
const STATE_BYTES: usize = CACHE_BYTES
    - crate::source_rotation::OVERLAP_BUDGET
    - AUDIT_AND_SCRATCH_BYTES
    - RETAIL_RESERVE_BYTES
    - KEY_RESERVE_BYTES
    - STALE_PREDECESSOR_RESERVE_BYTES;

/// M3's custody/pacing reserve cannot reduce main's OFF admission budget.
fn state_bytes() -> usize {
    if restart_restore::enabled() {
        STATE_BYTES
    } else {
        CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - AUDIT_AND_SCRATCH_BYTES
    }
}

pub(super) mod codex_cursor;
#[cfg(unix)]
pub(super) mod durable_tail;
#[cfg(unix)]
pub(crate) use durable_tail::MissClass;
#[cfg(unix)]
pub(crate) use durable_tail::RestoreOutcome;
#[cfg(all(test, unix))]
mod m3_format_tests;
#[cfg(all(test, unix))]
mod m3_write_ahead_tests;
pub(super) mod side_ledger;
#[cfg(all(test, unix))]
pub(crate) mod transition_fixture;

/// The retained-copy cache behind `SharedCache::retained`.
pub(super) type RetainedCache = TranscriptCache<CachedJsonlReduction>;

thread_local! {
    /// This thread holds the retained lock (a `RetainedGuard` is alive).
    /// Lock-order checks read it in debug builds only.
    static RETAINED_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether this thread holds the retained lock.
pub(super) fn retained_held() -> bool {
    RETAINED_HELD.with(std::cell::Cell::get)
}

/// The retained-copy lock, marked held for its scope, so a relock on the same
/// thread panics in debug builds instead of hanging. Reset on drop, unwinds
/// included.
pub(super) struct RetainedGuard<'a> {
    guard: std::sync::MutexGuard<'a, RetainedCache>,
}
impl<'a> RetainedGuard<'a> {
    fn new(guard: std::sync::MutexGuard<'a, RetainedCache>) -> Self {
        RETAINED_HELD.with(|held| held.set(true));
        Self { guard }
    }
}
impl Drop for RetainedGuard<'_> {
    fn drop(&mut self) {
        RETAINED_HELD.with(|held| held.set(false));
    }
}
impl std::ops::Deref for RetainedGuard<'_> {
    type Target = RetainedCache;
    fn deref(&self) -> &RetainedCache {
        &self.guard
    }
}
impl std::ops::DerefMut for RetainedGuard<'_> {
    fn deref_mut(&mut self) -> &mut RetainedCache {
        &mut self.guard
    }
}

thread_local! {
    static BLOCKING_RESIDENT_MEASURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// P1-RETAIN R0: while held, this thread's resident walk waits on the
/// retained and cursor locks, one at a time, instead of reading contention as
/// an unbounded resident. Used only for the measure of a releasing completion
/// (`releases_at_completion`); every other walk keeps `try_lock`. Restored on drop.
pub(super) struct BlockingResidentMeasure(bool);
impl BlockingResidentMeasure {
    pub(super) fn enter() -> Self {
        Self(BLOCKING_RESIDENT_MEASURE.with(|blocking| blocking.replace(true)))
    }
}
impl Drop for BlockingResidentMeasure {
    fn drop(&mut self) {
        BLOCKING_RESIDENT_MEASURE.with(|blocking| blocking.set(self.0));
    }
}

/// Stage 1 K8, tests only: one of [`SharedCache`]'s three locks.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestLock {
    Cursor,
    Retained,
    Side,
}

// RAM-only per-key cap pacing; unify with P2's shared paced_full at integration.
// Fixed slots charge their full inline size through SharedCache, with no path heap.
pub(super) const CAP_PACE_SECONDS: u64 = 6 * 60 * 60;
const CAP_CLOCK_SANITY_SECONDS: u64 = 30 * 24 * 60 * 60;
#[derive(Clone, Copy)]
struct CapStamp {
    key: [u8; 32],
    at: SystemTime,
}
struct CapPace {
    entries: [Option<CapStamp>; CACHE_ENTRIES],
}
impl Default for CapPace {
    fn default() -> Self {
        Self {
            entries: [None; CACHE_ENTRIES],
        }
    }
}
impl CapPace {
    /// (may read Full, evicted). Backwards/implausible clocks expire, never hold.
    fn admit(&mut self, key: &str, now: SystemTime) -> (bool, bool) {
        let key: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|old| old.key == key))
        {
            let old = slot.expect("matched pace");
            if now.duration_since(old.at).is_ok_and(|elapsed| {
                elapsed.as_secs() <= CAP_CLOCK_SANITY_SECONDS
                    && elapsed.as_secs() < CAP_PACE_SECONDS
            }) {
                return (false, false);
            }
            *slot = Some(CapStamp { key, at: now });
            return (true, false);
        }
        let empty = self.entries.iter().position(Option::is_none);
        let slot = empty.unwrap_or_else(|| {
            self.entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.expect("full pace").at)
                .expect("nonempty pace")
                .0
        });
        self.entries[slot] = Some(CapStamp { key, at: now });
        (true, empty.is_none())
    }
}

pub(crate) struct SharedCache {
    pub(crate) withheld_memo: withheld_account::Memo,
    inner: Mutex<RetainedCache>,
    cap_pace: Mutex<CapPace>,
    /// The resumable Codex job slot and held-singleton memo. Charged once,
    /// here; copy budgets and insert admission see it through this cache.
    cursor: Mutex<codex_cursor::CursorState>,
    /// Codex parent side-request pacing (U1a-2a), process lifetime. A leaf
    /// lock (retained, then cursor, then side; nothing is locked under it).
    /// Charged as the fixed `side_ledger::SIDE_LEDGER_BYTES`, never walked.
    side: Mutex<side_ledger::SideLedger>,
    /// M1 durable warm-cache stores and write candidates. A leaf lock, never
    /// held while taking another. Not part of the state budget: bounded by
    /// `durable_tail::STORES_RESIDENT_BOUND` and never walked.
    #[cfg(unix)]
    durable: Mutex<durable_tail::StoreRoot>,
    #[cfg(unix)]
    durable_bytes: std::sync::atomic::AtomicUsize,
}
impl Default for SharedCache {
    fn default() -> Self {
        Self {
            withheld_memo: Default::default(),
            inner: Mutex::new(TranscriptCache::with_byte_limit(state_bytes())),
            cap_pace: Mutex::new(CapPace::default()),
            cursor: Mutex::new(codex_cursor::CursorState::default()),
            side: Mutex::new(side_ledger::SideLedger::default()),
            #[cfg(unix)]
            durable: Mutex::new(durable_tail::StoreRoot::default()),
            #[cfg(unix)]
            durable_bytes: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}
impl std::fmt::Debug for SharedCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedTranscriptCache")
    }
}
impl HeapLayoutBound for SharedCache {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        // The shared cache owns the memo allocation header even when empty.
        // Its optional entries are priced separately by the rotation owner.
        self.withheld_memo.heap_bound(c)?;
        if BLOCKING_RESIDENT_MEASURE.with(std::cell::Cell::get) {
            // P1-RETAIN R0's completion measure: wait for each lock, one at a
            // time and in lock order (`retained` checks this thread holds
            // neither; `with_cursor` marks the cursor lock held, as every
            // cursor critical section does), so contention is never read as
            // an unbounded resident.
            self.retained().ok()?.heap_bound(c)?;
            self.with_cursor(|cursor| cursor.heap_bound(c)).flatten()?;
        } else {
            self.inner.heap_bound(c)?;
            self.cursor.heap_bound(c)?;
        }
        // Never `side`'s lock: a busy lock would read as unbounded and zero
        // every copy budget. The ledger's whole heap is this proved constant;
        // its inline tables are inside `size_of::<SharedCache>()`, which the
        // caller's `bound` (or `Arc`) charges once (D5′ size test).
        c.add(side_ledger::SIDE_LEDGER_BYTES.checked_add(self.durable_root_charge())?)
    }
}
#[cfg(test)]
impl SharedCache {
    pub(super) fn cap_pace_for_test(&self, key: &str, now: SystemTime) -> (bool, bool, usize) {
        let mut pace = self.cap_pace.lock().unwrap();
        let (admitted, evicted) = pace.admit(key, now);
        (admitted, evicted, pace.entries.iter().flatten().count())
    }
}

// Qualified 64-bit main root: Stores 18,272 B, complete SharedCache 40,784 B.
// The memo handle fits the root's existing padding; its owned header is
// charged separately above. The touched-family
// view remains behind the already boxed cursor job.
// Keep its reservation while OFF, even though optional M3 owners now allocate
// only for ON or the approved erasure/invalidation actions.
const OFF_MAIN_SHARED_BYTES: usize = 40_784;
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<SharedCache>() <= OFF_MAIN_SHARED_BYTES);
impl SharedCache {
    // Main's Stores root reservation on the qualified 64-bit toolchains.
    // This is conservative when OFF's optional owner is absent; every real
    // ON/exception allocation is added as well, without taking a leaf lock.
    fn durable_root_charge(&self) -> usize {
        #[cfg(unix)]
        {
            OFF_MAIN_SHARED_BYTES.saturating_sub(size_of::<SharedCache>())
                + self
                    .durable_bytes
                    .load(std::sync::atomic::Ordering::Relaxed)
        }
        #[cfg(not(unix))]
        {
            0
        }
    }
}
impl SharedCache {
    /// Bind before constructor-time discovery/selection, which consults CONTENT.
    pub(crate) fn bind_withheld(&self, index: &mut ScanIndex) {
        index.withheld_memo = self.withheld_memo.clone();
        index
            .withheld_memo
            .retain_held(&index.claude_account_deferred_holds);
    }

    /// The retained-copy lock. Lock order: retained, then cursor, never the
    /// reverse; never twice on one thread (both checked in debug builds).
    pub(super) fn retained(&self) -> std::sync::LockResult<RetainedGuard<'_>> {
        debug_assert!(
            !codex_cursor::cursor_held(),
            "retained lock taken under the cursor lock"
        );
        debug_assert!(
            !retained_held(),
            "retained lock taken while this thread holds it"
        );
        match self.inner.lock() {
            Ok(guard) => Ok(RetainedGuard::new(guard)),
            Err(poisoned) => Err(std::sync::PoisonError::new(RetainedGuard::new(
                poisoned.into_inner(),
            ))),
        }
    }
    /// The resident copy's accepted `(requests, tokens)` for `key`; `None`
    /// without one or under a poisoned lock. Diagnostics only.
    pub(super) fn resident_usage(&self, source: SnapshotSource, key: &str) -> Option<(u64, u64)> {
        self.retained()
            .ok()?
            .peek(key)
            .and_then(|copy| copy.state.accepted_usage(source))
    }
    /// Copy-refusal release: evicts retained copies and optional header facts.
    /// The paused cursor job, held-singleton memo, parked records and rotation
    /// state are charged and bounded in `heap_bound`, and survive (K6).
    pub(super) fn clear(&self) {
        if let Ok(mut cache) = self.retained() {
            cache.clear();
        } else {
            record(Event::ClearPoisonedLock);
        }
        self.with_cursor(|cursor| cursor.headers.clear());
    }
    /// M1: evict retained copies in victim order until they fit the state
    /// budget beside the cursor state and `pinned` bytes, measured under
    /// blocking locks in the one order (retained, then cursor). Usually it
    /// evicts nothing. False, with nothing evicted: the retained lock is
    /// poisoned, the cursor state is unbounded or poisoned, or even an empty
    /// cache would not fit. Evicted copies drop under the retained lock, as
    /// `clear` drops them; no guard or credit drops there, so nothing relocks.
    /// U1a-2a D6(e): the cursor state is main's, without a suspended proof;
    /// where the fit is reachable, that proof is retired first, under these
    /// same locks, if the copies overflow beside it, so its bytes count
    /// toward the fit before any copy is evicted (`release_room_for_main`).
    pub(super) fn release_to_fit(&self, pinned: usize) -> bool {
        let Ok(mut retained) = self.retained() else {
            return false;
        };
        let floor = crate::heap_layout_bound::bound(&RetainedCache::default(), state_bytes());
        let Some(limit) = self.release_room_for_main(&retained, pinned, |limit| {
            floor.is_some_and(|floor| floor <= limit)
        }) else {
            return false;
        };
        retained.release_until_for(limit, Release::CopyRefusal)
    }
    /// M1 Path A: `release_to_fit`, evicting only retained copies ranked
    /// strictly below `rank`, and only where evicting them makes room;
    /// otherwise nothing, the suspended proof included
    /// (`TranscriptCache::release_older_until`, `older_release_fits`).
    pub(super) fn release_older_to_fit(&self, pinned: usize, rank: (i64, i64)) -> bool {
        let Ok(mut retained) = self.retained() else {
            return false;
        };
        let Some(limit) = self.release_room_for_main(&retained, pinned, |limit| {
            retained.older_release_fits(limit, rank)
        }) else {
            return false;
        };
        retained.release_older_until(limit, rank)
    }
    /// M-a: `release_older_to_fit` through the same `release_room_for_main`
    /// (the proof retired first), evicting at most `max_victims` entries
    /// (`TranscriptCache::release_older_until_at_most`), fit-or-nothing.
    pub(super) fn release_older_prefix_to_fit(
        &self,
        pinned: usize,
        rank: (i64, i64),
        max_victims: usize,
    ) -> bool {
        let Ok(mut retained) = self.retained() else {
            return false;
        };
        let Some(limit) = self.release_room_for_main(&retained, pinned, |limit| {
            retained
                .older_prefix_len(limit, rank)
                .is_some_and(|victims| victims <= max_victims)
        }) else {
            return false;
        };
        retained.release_older_until_at_most(limit, rank, max_victims)
    }
    pub(super) fn take(
        &self,
        key: &str,
    ) -> Option<crate::transcript_cache::Taken<CachedJsonlReduction>> {
        match self.retained() {
            Ok(mut cache) => cache.take(key),
            Err(_) => {
                record(Event::TakePoisonedLock);
                None
            }
        }
    }
    /// Capture after E2 finish_page, before identity/policy changes fingerprints.
    /// The committed index is the pre-scan authority: new held keys remain
    /// absent there and in settlement. Each flag shares its reduction's scope
    /// and is useful only after the ordinary checkpoint/scope validation.
    pub(crate) fn record_e2_held_new_files(
        &self,
        committed: &ScanIndex,
        scanned: &ScanIndex,
        items: &[SnapshotItem],
        withheld: &BTreeSet<String>,
    ) {
        if let Ok(mut cache) = self.retained() {
            cache.update_e2_held(|key| {
                if committed.files.contains_key(key) {
                    return Some(false);
                }
                let entry = scanned.files.get(key)?;
                let mut visited = false;
                let mut held = false;
                for item in items {
                    if item.source_file_fingerprint.as_deref()
                        == Some(entry.source_file_fingerprint.as_str())
                    {
                        visited = true;
                        held |= withheld.contains(&item.source_session_id);
                    }
                }
                visited.then_some(held)
            });
        }
    }
    pub(super) fn retained_sealed_offset(&self, key: &str) -> Option<u64> {
        self.retained().ok()?.sealed_offset(key)
    }
    /// Stage 1 K8 (iii), tests only: panic on this thread while holding
    /// `lock`, as a continuation worker would (W9).
    #[cfg(test)]
    pub(crate) fn panic_under_lock_for_test(&self, lock: TestLock) {
        match lock {
            TestLock::Cursor => {
                self.with_cursor(|_| panic!("W9: panic under the cursor lock (test)"));
            }
            TestLock::Retained => {
                let _held = self.retained();
                panic!("W9: panic under the retained lock (test)");
            }
            TestLock::Side => {
                let _held = self.side_ledger();
                panic!("W9: panic under the side-ledger lock (test)");
            }
        }
    }
    /// Stage 1 K8, tests only: whether `lock` is poisoned now.
    #[cfg(test)]
    pub(crate) fn lock_poisoned_for_test(&self, lock: TestLock) -> bool {
        match lock {
            TestLock::Cursor => self.cursor.is_poisoned(),
            TestLock::Retained => self.inner.is_poisoned(),
            TestLock::Side => self.side.is_poisoned(),
        }
    }
    /// Poison the retained lock from another thread (tests only).
    #[cfg(test)]
    pub(super) fn poison_retained(&self) {
        std::thread::scope(|scope| {
            let poisoner = scope.spawn(|| {
                let _guard = self.inner.lock();
                panic!("poisoning the retained lock (test)");
            });
            assert!(poisoner.join().is_err());
        });
    }
    #[cfg(test)]
    pub(super) fn retained_checkpoint(
        &self,
        key: &str,
    ) -> Option<crate::transcript_acquisition::Checkpoint> {
        self.retained().ok()?.checkpoint(key)
    }
    #[cfg(test)]
    pub(super) fn insert(
        &self,
        key: String,
        completed: sampled_jsonl::CompletedNativeAcquisition,
        live_bytes: usize,
    ) {
        self.insert_admitted(key, completed, live_bytes);
    }
    pub(super) fn insert_admitted(
        &self,
        key: String,
        completed: sampled_jsonl::CompletedNativeAcquisition,
        live_bytes: usize,
    ) -> bool {
        self.insert_with_custody(key, completed, live_bytes, false, true, false)
            .is_ok()
    }
    /// A completion whose durable record the M3 native route already
    /// settled. A receipted record keeps its post-save audit-carrier offer;
    /// a no-record disposition must not retry the failed write after effects.
    #[cfg(unix)]
    pub(super) fn insert_settled(
        &self,
        key: String,
        completed: sampled_jsonl::CompletedNativeAcquisition,
        live_bytes: usize,
        write_candidate: bool,
    ) -> bool {
        self.insert_with_custody(key, completed, live_bytes, false, write_candidate, false)
            .is_ok()
    }
    pub(super) fn return_prepared_taken(
        &self,
        key: String,
        taken: Box<crate::transcript_cache::Taken<CachedJsonlReduction>>,
    ) -> Result<(), Box<crate::transcript_cache::Taken<CachedJsonlReduction>>> {
        self.insert_taken(key, taken, false, false).map(|_| ())
    }
    fn insert_taken<I: crate::transcript_cache::Incoming<CachedJsonlReduction>>(
        &self,
        key: String,
        incoming: I,
        _write_candidate: bool,
        take_back: bool,
    ) -> Result<Option<crate::transcript_cache::Taken<CachedJsonlReduction>>, I> {
        let taken: &crate::transcript_cache::Taken<CachedJsonlReduction> = incoming.borrow();
        let custody_bytes = taken.durable.retained_bytes(state_bytes());
        let fits = custody_bytes.is_some();
        #[cfg(test)]
        let fits = fits && !sampled_jsonl::preparation_tests::heap_refused();
        if !fits {
            record(Event::InsertEntryBoundRefused);
            return Err(incoming);
        }
        let Ok(mut cache) = self.retained() else {
            record(Event::InsertPoisonedLock);
            return Err(incoming);
        };
        let live_bytes = taken.finalization_charge;
        let reserved =
            self.retained_reservation(&cache, &key, taken, live_bytes, taken.modified_hint);
        let touched = key.clone();
        let result = cache.insert_taken_reserving(key, incoming, reserved);
        self.drop_suspended_proof_if_over(&cache, live_bytes);
        #[cfg(unix)]
        if result.is_ok() && _write_candidate {
            self.durable_touch(&touched);
        }
        // No cold copy is observable between admission and take: both happen
        // under this retained guard, with ordinary cursor/side reservations.
        result.map(|()| {
            if take_back {
                cache.take(&touched)
            } else {
                None
            }
        })
    }
    // Refusal returns the original inline graph; boxing adds an unfunded allocation.
    #[allow(clippy::result_large_err)]
    fn insert_with_custody(
        &self,
        key: String,
        mut completed: sampled_jsonl::CompletedNativeAcquisition,
        live_bytes: usize,
        held_new: bool,
        write_candidate: bool,
        take_back: bool,
    ) -> Result<
        Option<crate::transcript_cache::Taken<CachedJsonlReduction>>,
        sampled_jsonl::CompletedNativeAcquisition,
    > {
        let Some(state) = completed.reduction.take() else {
            return Err(completed);
        };
        let rank = completed.released.unwrap_or_else(|| {
            crate::transcript_cache::admission_rank(
                completed.checkpoint.modified_hint(),
                crate::transcript_cache::admission_now(),
            )
        });
        let taken = crate::transcript_cache::Taken {
            retained: crate::transcript_cache::Retained {
                checkpoint: completed.checkpoint,
                state,
            },
            durable: completed.durable,
            modified_hint: rank,
            finalization_charge: live_bytes,
            e2_held_new_file: held_new,
        };
        match self.insert_taken(key, taken, write_candidate, take_back) {
            Ok(taken) => Ok(taken),
            Err(taken) => Err(sampled_jsonl::CompletedNativeAcquisition {
                checkpoint: taken.retained.checkpoint,
                reduction: Some(taken.retained.state),
                durable: taken.durable,
                released: completed.released,
                unsealed: completed.unsealed,
            }),
        }
    }
}

pub(super) struct Context {
    pub(super) cache: Arc<SharedCache>,
    pub(super) namespace: Scope,
    pub(super) audit_metadata_supported: bool,
    pub(super) audit_slots: usize,
    pub(super) full_files: usize,
    pub(super) tail_files: usize,
    pub(super) unchanged_files: usize,
    pub(super) native_bytes: u64,
    pub(super) sample_bytes: u64,
    pub(super) full_reasons: [usize; 11],
    pub(super) priority_replays: usize,
    pub(super) audits_started: usize,
    pub(super) audits_completed: usize,
    pub(super) audit_quiet_retired: usize,
    pub(super) audit_cap_full: usize,
    pub(super) audit_cap_delay: usize,
    pub(super) pace_evicted: usize,
    pub(super) start_overdue_seconds: u64,
    pub(super) completion_overdue_seconds: u64,
    pub(super) admission: crate::local_resource_diagnostics::AcquisitionAdmission,
}
crate::heap_layout_bound::fields!(Context; cache, namespace, audit_metadata_supported, audit_slots,
    full_files, tail_files, unchanged_files, native_bytes, sample_bytes, full_reasons,
    priority_replays, audits_started, audits_completed, audit_quiet_retired, audit_cap_full, audit_cap_delay, pace_evicted, start_overdue_seconds,
    completion_overdue_seconds, admission);

pub(super) struct Active {
    /// Structural fallback keeps cursor/scope metadata but retains no graph.
    pub(super) no_record: bool,
    /// Frozen observation only; never participates in admission or settlement.
    pub(super) restored_behind_accepted: bool,
    pub(super) key: String,
    pub(super) scope: Scope,
    pub(super) mode: ReadMode,
    pub(super) audit_due: Option<u64>,
    /// The taken copy's admitted victim-order hint while this read continues
    /// it (Tail or Unchanged); `None` otherwise. Only a continued copy may
    /// release residents for its own copy (P1-RETAIN R0), and it ranks them
    /// by its re-admission rank (`tail_completion_budget`), not by this hint.
    pub(super) retained_hint: Option<(i64, i64)>,
    /// The finalization charge reserved beside the continued copy at its last
    /// admission (Q-PR13(iii) β); 0 without one.
    pub(super) retained_finalization_charge: usize,
    /// The continued copy's usage witness at its take
    /// (`SnapshotAccumulator::usage_witness`); `None` without one. Q-PR15's
    /// guard compares it at completion.
    pub(super) retained_usage: Option<u64>,
    pub(super) reinsertion: crate::local_resource_diagnostics::claude_reread::Reinsertion,
}
crate::heap_layout_bound::fields!(Active; key, scope, mode, audit_due, retained_hint,
    retained_finalization_charge, retained_usage, reinsertion; inline no_record, restored_behind_accepted);

impl Context {
    #[inline(never)]
    pub(super) fn cap_candidate(&mut self, key: &str) -> bool {
        let now = cap_wall_time();
        let (admit, evicted) = self
            .cache
            .cap_pace
            .lock()
            .map(|mut pace| pace.admit(key, now))
            .unwrap_or((true, false));
        self.pace_evicted += usize::from(evicted);
        if admit {
            self.audit_cap_full += 1;
        } else {
            self.audit_cap_delay += 1;
        }
        admit
    }
}
fn cap_wall_time() -> SystemTime {
    #[cfg(test)]
    if let Some(now) = TEST_NOW.with(std::cell::Cell::get) {
        return UNIX_EPOCH + std::time::Duration::from_secs(now);
    }
    SystemTime::now()
}

impl Context {
    pub(super) fn file_scope(
        &self,
        source: SnapshotSource,
        candidate: &CandidateFile,
        sidecar: &str,
        artifacts: bool,
        index: &ScanIndex,
    ) -> Scope {
        Scope(sha256_hex(&[
            "sampled_native_reduction:v1",
            &self.namespace.0,
            source.api_slug(),
            source.parser_version(),
            source.scan_identity_version(),
            &local_index_key(&candidate.scan_root),
            &local_index_key(&candidate.path),
            sidecar,
            if artifacts {
                "artifacts"
            } else {
                "no_artifacts"
            },
            // Retired full context-curve upload: keeps the scope bytes.
            "no_curve",
            index
                .active_upload_context_fingerprint
                .as_deref()
                .unwrap_or("none"),
            index
                .historical_replay_generation
                .as_deref()
                .unwrap_or("none"),
        ]))
    }
    pub(super) fn record_mode(&mut self, mode: ReadMode, audit_due: Option<u64>) {
        match mode {
            ReadMode::Full(reason) => {
                self.full_files += 1;
                self.full_reasons[reason.slot()] += 1;
                if let Some(due) = audit_due {
                    self.audits_started += 1;
                    self.start_overdue_seconds = self
                        .start_overdue_seconds
                        .max(now_seconds().saturating_sub(due));
                }
            }
            ReadMode::Tail => self.tail_files += 1,
            ReadMode::Unchanged => self.unchanged_files += 1,
        }
    }
    pub(super) fn record_input(&mut self, metrics: crate::transcript_acquisition::ReadMetrics) {
        self.native_bytes = self.native_bytes.saturating_add(metrics.native_bytes);
        self.sample_bytes = self
            .sample_bytes
            .saturating_add(metrics.sample_bytes as u64);
    }
    pub(super) fn complete_audit(&mut self, due: u64) {
        self.audits_completed += 1;
        self.completion_overdue_seconds = self
            .completion_overdue_seconds
            .max(now_seconds().saturating_sub(due));
    }
}

impl OwnedSourceScan {
    pub(crate) fn with_sampled_acquisition(
        mut self,
        cache: Arc<SharedCache>,
        namespace: Scope,
    ) -> Self {
        self.durable_guard = Some(Arc::downgrade(&cache));
        if self.source == SnapshotSource::ClaudeCode {
            cache.bind_withheld(&mut self.index);
            self.resource_probe
                .set_withheld_memo(self.index.withheld_memo.clone());
        }
        #[cfg(unix)]
        let admitted = durable_tail::durable_source(self.source).is_some();
        #[cfg(not(unix))]
        let admitted = self.source != SnapshotSource::Pi;
        if admitted {
            sampled_audit::normalize_marker_storage(&mut self.index);
            if self.source == SnapshotSource::ClaudeCode {
                sampled_audit::restore_held_audit_deadlines(&mut self.index, self.audit_now);
                self.prepare_held_audit_progress(self.audit_now);
            }
            let pending = self
                .index
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .take(CACHE_ENTRIES + 1)
                .count();
            self.sampling = Some(Context {
                cache,
                namespace,
                // Legacy prefix/audit scheduling and diagnostic observations
                // keep these values; ordinary restore never gates on them.
                audit_metadata_supported: pending <= CACHE_ENTRIES,
                audit_slots: CACHE_ENTRIES.saturating_sub(pending),
                full_files: 0,
                tail_files: 0,
                unchanged_files: 0,
                native_bytes: 0,
                sample_bytes: 0,
                full_reasons: [0; 11],
                priority_replays: 0,
                audits_started: 0,
                audits_completed: 0,
                audit_quiet_retired: 0,
                audit_cap_full: 0,
                audit_cap_delay: 0,
                pace_evicted: 0,
                start_overdue_seconds: 0,
                completion_overdue_seconds: 0,
                admission: Default::default(),
            });
        }
        self
    }
    /// The conservative release: no measurement is supplied, so every shape
    /// but a measured full native baseline still clears (L-A1).
    #[cfg(test)]
    pub(crate) fn release_sampled_cache_for_copy_refusal(&self) {
        release_cache_for_copy_refusal(self.sampling.as_ref(), self.active_file.as_deref(), None);
    }
    /// Charge only optimization-owned native state, samples/keys and copies.
    /// The unchanged serial index/metadata is baseline; parked/proof/send
    /// frames still use their existing aggregate 32MiB allocation/lifetime gate.
    #[cfg(test)]
    pub(super) fn sampled_copy_budget(&mut self) -> usize {
        self.sampled_copy_step().0
    }
    /// The copy budget and the resident bound measured by the same walk.
    #[cfg(test)]
    pub(super) fn sampled_copy_parts(&mut self) -> (usize, Option<usize>) {
        let (budget, step) = self.sampled_copy_step();
        (budget, step.resident)
    }
    /// The copy budget and what the same walk measured (`StepMeasure`).
    pub(super) fn sampled_copy_step(&mut self) -> (usize, StepMeasure) {
        copy_budget_step(
            self.sampling.as_ref(),
            self.active_file.as_deref_mut(),
            false,
        )
    }
}

/// L-A1: an unsampled synchronous native read. Its retained entry, if any,
/// was dropped before the active was built; it owns no acquisition, cursor
/// job, group proof or tee, alias or receipt. Each conjunct is checked even
/// where another implies it today.
fn owns_no_optimization_state(active: &OwnedActiveFile) -> bool {
    active.sampling.is_none()
        && !active.parser.return_pending()
        && active.cursor.is_none()
        && active.group.is_none()
        && active.aliases.is_empty()
        && active.applied_receipts.is_empty()
        && active.parser.reader.acquisition.is_none()
        && active
            .parser
            .accumulator
            .codex_tier_replay
            .as_ref()
            .map_or(true, |replay| replay.join.is_none())
}

/// P1-RETAIN R0, shape F: a sampled Tail/Unchanged singleton that borrows
/// only its own retained reduction (moved into the parser at prepare) and its
/// plan. Each conjunct is checked even where another implies it today.
pub(super) fn borrows_only_retained_reduction(active: &OwnedActiveFile) -> bool {
    active
        .sampling
        .as_ref()
        .is_some_and(|sampling| matches!(sampling.mode, ReadMode::Tail | ReadMode::Unchanged))
        && sampled_singleton(active)
}

/// A completion that may release lower-ranked residents for its copy
/// (`tail_completion_budget`): shape F, or a sampled Full singleton whose file
/// grew since its last read. The index still holds the pre-read size here;
/// a first read, shrink or same-size re-read releases nothing at completion.
pub(super) fn releases_at_completion(active: &OwnedActiveFile, index: &ScanIndex) -> bool {
    borrows_only_retained_reduction(active)
        || (active.sampling.as_ref().is_some_and(|sampling| {
            matches!(sampling.mode, ReadMode::Full(_))
                && index
                    .files
                    .get(&sampling.key)
                    .is_some_and(|entry| active.candidate.size_bytes > entry.size_bytes)
        }) && active.side_origin.is_none()
            && sampled_singleton(active))
}

/// One file on its own plan: no comparison, cursor job, group, alias, receipt
/// or tier join. Each conjunct is checked even where another implies it today.
fn sampled_singleton(active: &OwnedActiveFile) -> bool {
    !active.comparison_target
        && active.cursor.is_none()
        && active.group.is_none()
        && active.aliases.is_empty()
        && active.applied_receipts.is_empty()
        && active.parser.reader.acquisition.is_some()
        && active
            .parser
            .accumulator
            .codex_tier_replay
            .as_ref()
            .map_or(true, |replay| replay.join.is_none())
}

/// Whether a refusal beside `active` fits the residents to the active's
/// optional charge: not a full native read and not an unsampled one, whose
/// refusal treats their native state as baseline and never uses the charge.
fn refusal_charges_active(active: &OwnedActiveFile) -> bool {
    !active
        .sampling
        .as_ref()
        .is_some_and(|sampling| matches!(sampling.mode, ReadMode::Full(_)))
        && !owns_no_optimization_state(active)
}

/// What one step's budget walk measured, for that step's refusal decision
/// only; never carried to another step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct StepMeasure {
    /// The resident bound (`None`: not measured, e.g. a contended
    /// `try_lock`, the visit cap, or over the state budget).
    pub(super) resident: Option<usize>,
    /// The active file's optional charge (`None`: unknown, e.g. it exceeds
    /// the state budget). The walk less the reader's line buffer: a full read
    /// of the same line holds that buffer too, so it is native baseline
    /// (#641, #654), not optional memory. Where the per-step walk hit the
    /// visit cap, the byte walk's (`completed_bound`) charge instead.
    pub(super) active: Option<usize>,
    /// The active's charge in this step's copy budget: its whole walk, line
    /// buffer included (`None`: none, so the budget is zero).
    pub(super) used: Option<usize>,
}
impl StepMeasure {
    /// The active's per-step walk hit the visit cap, so its optional charge
    /// came from the byte walk and the copy budget stays zero (M1 F1).
    fn visit_limited(&self) -> bool {
        self.active.is_some() && self.used.is_none()
    }

    /// U1a-2a (fix round 2, DB1): the room this walk left in main's view
    /// (`bound_for_main`) for the copy budget's two equal shares, a retained
    /// copy and finish/output: `state_bytes() - resident - used`, or
    /// `state_bytes() - resident` with no active. The same arithmetic
    /// `copy_budget_step` halves, on this walk's own fields (no second
    /// walk; a field would edit M1's unedited test literals). `None`:
    /// unknown. Read only beside this walk's own non-zero budget, which
    /// implies a known room, where that budget is allocated against
    /// (`retire_proof_beside_copy`).
    pub(super) fn room(&self) -> Option<usize> {
        let remaining = state_bytes().checked_sub(self.resident?)?;
        match (self.active, self.used) {
            (_, Some(used)) => remaining.checked_sub(used),
            (None, None) => Some(remaining),
            (Some(_), None) => None,
        }
    }
}

/// The conservative copy-refusal release, given at most a resident bound and
/// no active charge (L-A1): any active other than a measured native baseline
/// read still clears. `None` supplies no measurement: nothing is re-measured.
/// Production never reaches either branch this way: its step start always
/// supplies a `StepMeasure` with the active's charge (`release_cache_to_fit`).
/// Rows that pass `None`, or a non-exempt active, pin a non-production branch.
#[cfg(test)]
pub(super) fn release_cache_for_copy_refusal(
    sampling: Option<&Context>,
    active: Option<&OwnedActiveFile>,
    measured_resident: Option<usize>,
) {
    release_for_copy_refusal(
        sampling,
        active,
        measured_resident.map(|resident| StepMeasure {
            resident: Some(resident),
            active: None,
            used: None,
        }),
    );
}

/// M1: the copy-refusal release for `sampling` beside `active`, decided on
/// this step's own walk (`step`).
pub(super) fn release_cache_to_fit(
    sampling: Option<&Context>,
    active: Option<&OwnedActiveFile>,
    step: StepMeasure,
) {
    release_for_copy_refusal(sampling, active, Some(step));
}

/// A zero copy budget forbids an optional copy beside the active. It does
/// not by itself mean the residents overflow: the budget is half of what is
/// left, so it is zero whenever the cache is merely full. M1 releases
/// retained copies only where optional memory (residents, cursor state and
/// the active's optional charge) really exceeds the state budget, and then
/// only as many as the overflow needs, in victim order. The whole cache is
/// cleared only where the charge to fit is unknown or cannot fit beside an
/// empty cache; each such clear is counted by its cause. A sampled tail then
/// makes room for its own copy from older entries only (`admit_tail_copy`),
/// except a shape-F singleton (`borrows_only_retained_reduction`), which is
/// released for only at its completion (P1-RETAIN R0, Q-PR14). `step` `None`
/// is a caller with no step measurement: the conservative release.
fn release_for_copy_refusal(
    sampling: Option<&Context>,
    active: Option<&OwnedActiveFile>,
    step: Option<StepMeasure>,
) {
    let Some(context) = sampling else {
        return;
    };
    // A full parser's native accumulator is the unchanged synchronous
    // baseline. Its local layout refusal forbids optional copies, but
    // does not invalidate other already bounded resident reductions.
    // Acquisition/path scratch still uses the separate 1MiB reserve.
    // Borrowed tail state keeps its existing release accounting; audit
    // population is not a cache or restore admission bound.
    let native_full_baseline = active.is_some_and(|active| {
        active
            .sampling
            .as_ref()
            .is_some_and(|sampling| matches!(sampling.mode, ReadMode::Full(_)))
    });
    // The optional charge the residents must fit beside, and the clear's
    // cause where it cannot be fitted (no charge: clear).
    let (charge, cause) = if native_full_baseline {
        if crate::heap_layout_bound::bound(context, state_bytes()).is_some() {
            return;
        }
        (step.map(|_| 0), Event::ClearFullResidentBoundUnknown)
    } else if active.is_none() {
        (step.map(|_| 0), Event::ClearNoActive)
    } else if active.is_some_and(owns_no_optimization_state) {
        // Like a full parser, an unsampled native read is the unchanged
        // synchronous baseline and retains nothing, so its refusal does
        // not invalidate residents this step measured as bounded. This
        // is not a combined native-plus-cache bound.
        if step
            .and_then(|step| step.resident)
            .is_some_and(|resident| resident <= state_bytes())
        {
            return;
        }
        (step.map(|_| 0), Event::ClearFullResidentBoundUnknown)
    } else {
        if step.is_some_and(|step| step.visit_limited()) {
            record(Event::CopyRefusalWalkVisitLimit);
        }
        if active.is_some_and(borrows_only_retained_reduction) {
            // P1-RETAIN R0 (Q-PR14): a sampled Tail/Unchanged singleton
            // (shape F) gets neither `fit_residents` nor Path A here. Its
            // retained reduction was moved into the parser by the destructive
            // take; its copy's only release is at completion, sized exactly,
            // of residents ranked strictly below its copy's re-admission
            // rank, after every non-budget, entry and stamp gate
            // (`tail_completion_budget`). Until then its
            // optional-copy allowance stays zero, and an unknown or
            // unsupported measure there refuses its copy. Nothing is evicted
            // or cleared here, whether or not the residents and its charge
            // already overflow the state budget (disclosed residual (i)).
            return;
        }
        (step.and_then(|step| step.active), Event::ClearOtherActive)
    };
    if let Some(charge) = charge {
        if fit_residents(context, step.and_then(|step| step.resident), charge) {
            if let (Some(active), Some(step), Event::ClearOtherActive) = (active, step, cause) {
                admit_tail_copy(context, active, step, charge);
            }
            return;
        }
    }
    record(cause);
    context.cache.clear();
}

/// Fit the residents beside `charge` within the state budget, evicting only
/// what a real overflow needs. False where they cannot fit even emptied.
fn fit_residents(context: &Context, resident: Option<usize>, charge: usize) -> bool {
    // This step's walk already shows the residents fit beside the charge: a
    // merely full cache. Nothing is released.
    if resident
        .and_then(|resident| resident.checked_add(charge))
        .is_some_and(|total| total <= state_bytes())
    {
        record(Event::CopyRefusalKept);
        return true;
    }
    // An unknown resident (contention, the visit cap, a real overflow) is
    // measured again under blocking locks before anything is evicted.
    if resident.is_none() {
        record(Event::CopyRefusalRemeasured);
    }
    context_overhead(context)
        .and_then(|overhead| overhead.checked_add(charge))
        .is_some_and(|pinned| context.cache.release_to_fit(pinned))
}

/// M1 Path A (review §3c, owner-accepted): at a zero-budget step of a
/// sampled tail, make room for its own copy by evicting, in victim order,
/// only entries ranked strictly older than the tailed file, and only where
/// that makes the copy fit; otherwise nothing. Main's wipe evicted every such
/// entry; a newer entry never yields to an older tail (G3). The room is the
/// next step's copy budget: the active's whole walk plus twice its optional
/// charge, which over-approximates the copy (`retain_reduction` takes half
/// the remainder). The tail's growth after this step is not foreseen, and a
/// zero-budget completion step has already fixed its own budget.
fn admit_tail_copy(context: &Context, active: &OwnedActiveFile, step: StepMeasure, charge: usize) {
    let tail = active
        .sampling
        .as_ref()
        .is_some_and(|sampling| sampling.mode == ReadMode::Tail);
    if !tail || codex_cursor::byte_charged(active) || charge > ENTRY_BYTES {
        return;
    }
    let pinned = step
        .used
        .zip(context_overhead(context))
        .and_then(|(used, overhead)| {
            overhead
                .checked_add(used)?
                .checked_add(charge.checked_mul(2)?)
        });
    if let Some(pinned) = pinned {
        context
            .cache
            .release_older_to_fit(pinned, tail_rank(&active.candidate));
    }
}

/// The tailed file's eviction rank as its re-admission records it: its
/// modification time, clipped to now (`TranscriptCache` clips at admission).
fn tail_rank(candidate: &CandidateFile) -> (i64, i64) {
    let nanos = candidate.modified_unix_nanos;
    let modified = (
        i64::try_from(nanos / 1_000_000_000).unwrap_or(i64::MAX),
        i64::try_from(nanos % 1_000_000_000).unwrap_or_default(),
    );
    crate::transcript_cache::admission_rank(modified, crate::transcript_cache::admission_now())
}

/// `context`'s charge outside its shared cache's two locked states, as
/// `bound(context)` counts it, plus those states' inline layouts, which their
/// own bounds count again: a few hundred bytes over, never under. The inline
/// pace table (Stage 1, ~6 KiB) is the exception: left out here, it is
/// counted only by the cursor state's own bound.
fn context_overhead(context: &Context) -> Option<usize> {
    use crate::heap_layout_bound::bound;
    use std::mem::{align_of, size_of};
    // Exhaustive destructuring: a new owned field must be charged here too.
    let Context {
        cache: _,
        namespace,
        audit_metadata_supported: _,
        audit_slots: _,
        full_files: _,
        tail_files: _,
        unchanged_files: _,
        native_bytes: _,
        sample_bytes: _,
        full_reasons: _,
        priority_replays: _,
        audits_started: _,
        audits_completed: _,
        audit_quiet_retired: _,
        audit_cap_full: _,
        audit_cap_delay: _,
        pace_evicted: _,
        start_overdue_seconds: _,
        completion_overdue_seconds: _,
        admission,
    } = context;
    // The shared cache's `Arc` payload charge, and the side ledger's fixed
    // charge, which `heap_bound` adds lock-free outside the two locked states
    // (U1a-2a ss-4, F4b). Stage 1: less the inline pace table, which every
    // caller adds again through the cursor state (`state_for_main` or
    // `cursor_resident`), so it is counted once (condition 4).
    let shared = size_of::<SharedCache>()
        .checked_sub(size_of::<codex_cursor::PaceTable>())?
        .checked_add(align_of::<SharedCache>())?
        .checked_add(2 * size_of::<usize>())?
        .checked_add(side_ledger::SIDE_LEDGER_BYTES)?
        .checked_add(context.cache.durable_root_charge())?;
    size_of::<Context>()
        .checked_add(shared)?
        .checked_add(bound(namespace, state_bytes())?)?
        .checked_add(bound(admission, state_bytes())?)
}

/// Whether `context_overhead` plus the two locked states covers
/// `bound(context)` (tests only).
#[cfg(test)]
pub(super) fn context_overhead_covers(context: &Context) -> bool {
    use crate::heap_layout_bound::bound;
    let Some(whole) = bound(context, state_bytes()) else {
        return false;
    };
    let Ok(retained) = context.cache.retained() else {
        return false;
    };
    bound(&*retained, state_bytes())
        .zip(context_overhead(context))
        .and_then(|(retained, overhead)| {
            retained
                .checked_add(overhead)?
                .checked_add(context.cache.cursor_resident())
        })
        .is_some_and(|parts| parts >= whole)
}

/// A completing cursor job's exact copy budget (E3), with the same
/// refusal release the step start applies to an ordinary file, and the
/// walk it came from (for `retire_proof_beside_copy`).
pub(super) fn completion_copy_budget(
    sampling: Option<&Context>,
    active: &mut OwnedActiveFile,
) -> (usize, StepMeasure) {
    let (budget, step) = copy_budget_step(sampling, Some(&mut *active), true);
    if budget == 0 {
        release_cache_to_fit(sampling, Some(&*active), step);
    }
    (budget, step)
}

/// U1a-2a (R2-B3, fix round 2 DB1, c22 ruling (b); fix round 3 DM3): main's
/// copy budget funds two shares at once, a retained copy and finish/output
/// (`ClaudeResponses::finish_copy_budget`), so before main allocates
/// against `budget` (its completion's clone and finish), a suspended proof
/// larger than what both shares leave of `step`'s room is retired:
/// `proof + copy + finish/output <= room`, the room main's view
/// (`bound_for_main`) measured without the proof. Both clones admit a copy
/// only within `min(budget, ENTRY_BYTES)` before they allocate it
/// (`retain_reduction`'s `retention_bound`, `retain_sealed_prefix`'s
/// `admitted`), so the copy's share is `min(budget, ENTRY_BYTES)`. The
/// caller passes 0 where its completion cannot retain a copy. Where no copy
/// can be allocated (`budget == 0`, which an unknown room always gives)
/// nothing is retired: no proof drops on unavailable inputs. Non-allocating
/// steps never call this, and M1 Path A (`admit_tail_copy`) clones nothing
/// at its zero-budget step.
pub(super) fn retire_proof_beside_copy(
    sampling: Option<&Context>,
    budget: usize,
    step: StepMeasure,
) {
    if budget == 0 {
        return;
    }
    let Some((context, room)) = sampling.zip(step.room()) else {
        return;
    };
    context
        .cache
        .retire_proof_over_room(room.saturating_sub(copy_shares(budget)));
    #[cfg(test)]
    COPY_RETIRE_PROBE.with(|probe| {
        let whole = crate::heap_layout_bound::bound(context, state_bytes());
        let main = codex_cursor::bound_for_main(context, state_bytes());
        probe.set(Some(CopyRetireProbe {
            proof: whole
                .zip(main)
                .and_then(|(whole, main)| whole.checked_sub(main)),
            resident: step.resident,
            used: step.used.unwrap_or(0),
            budget,
        }))
    });
}

/// U1a-2a (fix round 3, DM3): the finish/output share plus the copy's share,
/// which both clones cap at `ENTRY_BYTES` before they allocate.
fn copy_shares(budget: usize) -> usize {
    budget.saturating_add(budget.min(ENTRY_BYTES))
}

/// Tests only: what `retire_proof_beside_copy` saw right after its retire.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) struct CopyRetireProbe {
    /// The suspended proof's charge left beside the copy (`bound(context)`
    /// less main's view, measured together, so main's own growth since the
    /// walk cancels).
    pub(super) proof: Option<usize>,
    /// The walk's main-view resident, its active charge and the budget.
    pub(super) resident: Option<usize>,
    pub(super) used: usize,
    pub(super) budget: usize,
}
#[cfg(test)]
impl CopyRetireProbe {
    /// At the clone: the walk's resident + the proof + the active + both
    /// shares (`copy_shares`) fit `state_bytes()`.
    pub(super) fn fits(&self) -> bool {
        self.resident
            .zip(self.proof)
            .and_then(|(resident, proof)| {
                resident
                    .checked_add(proof)?
                    .checked_add(self.used)?
                    .checked_add(copy_shares(self.budget))
            })
            .is_some_and(|total| total <= state_bytes())
    }
}

#[cfg(test)]
thread_local! {
    /// Tests only: the last `retire_proof_beside_copy` on this thread.
    static COPY_RETIRE_PROBE: std::cell::Cell<Option<CopyRetireProbe>> =
        const { std::cell::Cell::new(None) };
}

/// Tests only: the last `COPY_RETIRE_PROBE` on this thread, taken.
#[cfg(test)]
pub(super) fn copy_retire_probe() -> Option<CopyRetireProbe> {
    COPY_RETIRE_PROBE.with(std::cell::Cell::take)
}

/// The copy budget left beside the active file. A cursor job's state grows
/// past the ordinary walk's visit limit (usage hours, witnesses), so it is
/// charged by bytes like its pause (N3), but never walked per line (E3):
/// mid-job it uses the last walk plus the bytes consumed and the reader
/// buffer growth since (`JobMeta::charge_estimate`, bounded slack corrected
/// at the next walk, at most every `CHARGE_REFRESH_BYTES`); `completing`
/// walks exactly, once, on the step that consumes the budget.
/// This accounting is amortized across the job, not completion-only.
/// Also returns what this walk measured (`StepMeasure`), for the same
/// step's refusal decision only.
pub(super) fn copy_budget_step(
    sampling: Option<&Context>,
    active: Option<&mut OwnedActiveFile>,
    completing: bool,
) -> (usize, StepMeasure) {
    let Some(context) = sampling else {
        return (0, StepMeasure::default());
    };
    // U1a-2a (R2-B3): main's view, any suspended proof charged as none, so
    // optional proof work never shrinks a copy budget. It is no allocation
    // authority either: the walk's `room` goes with the budget, and where
    // main allocates against it the proof is retired first
    // (`retire_proof_beside_copy`, fix round 2 DB1).
    let resident = codex_cursor::bound_for_main(context, state_bytes());
    let remaining = resident.and_then(|resident| state_bytes().checked_sub(resident));
    let Some(active) = active else {
        let budget = remaining.map_or(0, |remaining| remaining / 2);
        return (
            budget,
            StepMeasure {
                resident,
                active: None,
                used: None,
            },
        );
    };
    let consumed = active.parser.reader.consumed_bytes();
    let buffer = active.parser.reader.buf.capacity();
    let estimate = (!completing)
        .then(|| codex_cursor::job_charge_estimate(active, consumed, buffer))
        .flatten();
    let byte_charged = codex_cursor::byte_charged(active);
    // Every active is walked to the whole state budget, a non-byte-charged
    // one past its line buffer, so a refusal knows its real optional charge
    // (M1; F2 for a byte-charged job). The budget below is unchanged: it
    // still charges the walk against the measured remainder.
    let limit = if byte_charged {
        state_bytes()
    } else {
        state_bytes().saturating_add(buffer)
    };
    // (the budget's charge, the refusal's optional charge)
    let (used, optional) = if let Some(estimate) = estimate {
        // The E3 estimate is charged whole, its buffer growth included.
        (Some(estimate), Some(estimate))
    } else {
        // These native source-wide inputs predate the optimization, are
        // refreshed on reuse, and are absent from every retained copy.
        // All active owned parser/acquisition/path/receipt state stays charged.
        let inputs = active.parser.take_live_reduction_inputs();
        // A group's legacy tee holds the same inputs (P2).
        let tee_inputs = active
            .group
            .as_mut()
            .and_then(|group| group.take_tee_inputs());
        // The walk charges the file itself, as before it was boxed.
        let file: &OwnedActiveFile = active;
        let bound = if byte_charged {
            crate::heap_layout_bound::completed_bound(file, limit)
        } else {
            crate::heap_layout_bound::bound(file, limit)
        };
        // F1: a per-step walk over the visit cap (a long Codex tail's usage
        // hours, keep R2 §2.2) takes the visit-robust byte walk for the
        // refusal's charge only; the copy budget stays zero. It runs only on
        // the steps of such an active, never for a shape whose refusal does
        // not use the charge.
        let visit_limited = if !byte_charged && bound.is_none() && refusal_charges_active(file) {
            crate::heap_layout_bound::completed_bound(file, limit)
        } else {
            None
        };
        active.parser.restore_live_reduction_inputs(inputs);
        if let Some(group) = active.group.as_mut() {
            group.restore_tee_inputs(tee_inputs);
        }
        if byte_charged {
            // The real walk, so the E3 estimate stays usable for the next
            // refusal (F2); `usize::MAX` only where the job alone exceeds
            // the state budget.
            codex_cursor::record_job_charge(active, bound.unwrap_or(usize::MAX), consumed, buffer);
            (bound, bound)
        } else {
            (
                bound,
                bound
                    .or(visit_limited)
                    .map(|bound| bound.saturating_sub(buffer)),
            )
        }
    };
    let room = remaining
        .zip(used)
        .and_then(|(remaining, used)| remaining.checked_sub(used));
    if let Some(room) = room {
        context.cache.retire_headers_over_room(room);
    }
    let budget = room.map_or(0, |room| room / 2);
    (
        budget,
        StepMeasure {
            resident,
            active: optional,
            used,
        },
    )
}

/// The copy budget a completion hands to retention (P1-RETAIN R0 and its
/// diagnostic packet). No production counter reads the variant.
pub(super) enum RetainBudget {
    /// Admit against `budget` now. The flags say whether the walk behind it
    /// measured the residents and the active file; only refusal
    /// classification reads them.
    Granted {
        budget: usize,
        resident_measured: bool,
        active_measured: bool,
    },
    /// Aliases or an applied receipt: never retained, and not a budget
    /// refusal. `raw` is this completion's pre-release budget.
    TierOrJoinExcluded { raw: usize },
    /// A cursor job with applied bytes outside its certified prefix.
    Unsealed { raw: usize },
    /// A proven release: admit against `budget_after`, and only after `release` has
    /// run, which happens after every non-budget gate (`retain_reduction`).
    Deferred {
        raw: usize,
        budget_after: usize,
        release: DeferredRelease,
    },
}
impl RetainBudget {
    /// A budget whose refusals are outside the packet's buckets (cursor,
    /// group and unsampled completions).
    pub(super) fn granted_unclassified(budget: usize) -> Self {
        Self::Granted {
            budget,
            resident_measured: true,
            active_measured: true,
        }
    }
    /// This completion's pre-release budget.
    pub(super) fn raw(&self) -> usize {
        match self {
            Self::Granted { budget, .. } => *budget,
            Self::TierOrJoinExcluded { raw }
            | Self::Unsealed { raw }
            | Self::Deferred { raw, .. } => *raw,
        }
    }
    /// #667's decode peak reserved from the budget a copy is admitted
    /// against (`ClaudeResponses::finish_copy_budget`, `finish`): `granted`
    /// is main's already peak-reserved pre-release budget; a deferred
    /// release keeps running only where `finish_copy_budget(budget_after)`
    /// fits too, and is otherwise dropped unrun (granted at `granted`), so a
    /// release never precedes an unfunded peak. Excluded and unsealed budgets
    /// are never admitted and keep their pre-release figure.
    pub(super) fn reserve_peak(
        self,
        granted: usize,
        finish_copy_budget: impl FnOnce(usize) -> Option<usize>,
    ) -> Self {
        match self {
            Self::Granted {
                resident_measured,
                active_measured,
                ..
            } => Self::Granted {
                budget: granted,
                resident_measured,
                active_measured,
            },
            Self::Deferred {
                budget_after,
                release,
                ..
            } => match finish_copy_budget(budget_after) {
                Some(budget_after) => Self::Deferred {
                    raw: granted,
                    budget_after,
                    release,
                },
                None => Self::granted_unclassified(granted),
            },
            other => other,
        }
    }
    /// A deferred release's (peak-reserved) `budget_after`: the finalization
    /// copy's limit once that release has actually run
    /// (`CompletedNativeAcquisition::released`); `None` otherwise.
    pub(super) fn released_budget(&self) -> Option<usize> {
        match self {
            Self::Deferred { budget_after, .. } => Some(*budget_after),
            _ => None,
        }
    }
    /// What a retained copy is admitted against without a deferred release:
    /// excluded and unsealed passes get none.
    pub(super) fn admission_budget(&self) -> usize {
        match self {
            Self::Granted { budget, .. } => *budget,
            Self::TierOrJoinExcluded { .. } | Self::Unsealed { .. } => 0,
            Self::Deferred { budget_after, .. } => *budget_after,
        }
    }
    /// The same budget with any deferred release dropped unrun: `Deferred`
    /// becomes `Granted` at its pre-release budget, so no path that cannot
    /// run the release (a cursor job's sealed prefix) admits against
    /// `budget_after`.
    pub(super) fn without_release(self) -> Self {
        match self {
            Self::Deferred { raw, .. } => Self::granted_unclassified(raw),
            other => other,
        }
    }
    /// The same pre-release budget, excluded from retention.
    pub(super) fn excluded(self) -> Self {
        Self::TierOrJoinExcluded { raw: self.raw() }
    }
    /// The same pre-release budget, unsealed.
    pub(super) fn unsealed(self) -> Self {
        Self::Unsealed { raw: self.raw() }
    }
}
impl From<(usize, StepMeasure)> for RetainBudget {
    fn from((budget, step): (usize, StepMeasure)) -> Self {
        Self::Granted {
            budget,
            resident_measured: step.resident.is_some(),
            active_measured: step.used.is_some(),
        }
    }
}

/// How a deferred release ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseOutcome {
    /// The prefix was released (or the residents already fit): admit.
    Released,
    /// The residents changed so the lower-ranked prefix no longer covers the
    /// need: nothing evicted, no copy.
    Race,
    /// The retained lock was poisoned or the residents could not be measured:
    /// nothing evicted, no copy.
    Unmeasurable,
}

/// A completion's release (`releases_at_completion`) of residents ranked
/// strictly below its copy's re-admission rank, sized at completion for both
/// its clone and its insert (`prove_release`). It runs at most once, inside
/// `retain_reduction`, after every non-budget gate; anything less than the
/// exact prefix evicts nothing.
pub(super) struct DeferredRelease {
    cache: Arc<SharedCache>,
    /// What must fit beside the retained copies after the release, besides
    /// main's cursor state: the context's own charge (the side ledger's
    /// fixed charge once, `context_overhead`), the copy's clone and
    /// finish/output (`2K`) and `max(A, ins_extra)`. With main's cursor
    /// state measured at the release, the retained copies' limit is
    /// `state_bytes() - cursor - pinned`, the completion's `R - need`
    /// (`SharedCache::release_older_to_fit`).
    pinned: usize,
    /// The copy's re-admission rank, computed once
    /// (`transcript_cache::admission_rank` of `modified`): only residents
    /// ranked strictly below it leave, and the copy is admitted at exactly it.
    pub(super) rank: (i64, i64),
    /// The source mtime `rank` was computed from (the read plan's stamp). A
    /// checkpoint carrying any other releases nothing.
    pub(super) modified: (i64, i64),
    /// `ENTRY_BYTES − entry_overhead − bound(key)`: the copy's admission
    /// limit, so the insert's entry and key bounds cannot refuse it (e).
    pub(super) entry_limit: usize,
    /// M-a's churn bound: at most `|P_C|` victims (`prove_release`); `None`
    /// on the legacy path and for a grown Full (`proven_release`).
    max_victims: Option<usize>,
}
impl DeferredRelease {
    /// Release through M1's one mechanism (`SharedCache::release_older_to_fit`,
    /// U1a-2a D6(e)): under the retained and cursor locks, a suspended proof
    /// is retired first where the fit is reachable, then the shortest
    /// victim-order prefix ranked strictly below `rank` is evicted
    /// (`Release::CopyAdmission`), fit-or-nothing. Already fitting evicts
    /// nothing. A poisoned lock or an unmeasurable cache (classified first,
    /// for the packet only) or a fit the lower-ranked entries cannot reach
    /// evicts nothing.
    pub(super) fn execute(self) -> ReleaseOutcome {
        let measured = self
            .cache
            .retained()
            .ok()
            .and_then(|retained| crate::heap_layout_bound::bound(&*retained, usize::MAX))
            .is_some();
        if !measured {
            return ReleaseOutcome::Unmeasurable;
        }
        let released = match self.max_victims {
            None => self.cache.release_older_to_fit(self.pinned, self.rank),
            Some(max_victims) => {
                self.cache
                    .release_older_prefix_to_fit(self.pinned, self.rank, max_victims)
            }
        };
        if released {
            ReleaseOutcome::Released
        } else {
            ReleaseOutcome::Race
        }
    }
}

/// P1-RETAIN R0 at a completion that may release (`releases_at_completion`):
/// one exact measure, the budget this copy is admitted against without a
/// release, and the facts a release proof needs (`ReleaseProof`). Nothing is decided or mutated here: the
/// release is proven only at the retention site, after main's proof
/// retirement and #667's peak reservation (`prove_release`, M-a S-a), and
/// runs only after every non-budget gate. This is the only release of its
/// own copy: the step start makes no room for it (Q-PR14,
/// `release_for_copy_refusal`).
///
/// The rank (Q-PR14 amendment) is the one this copy is admitted at: its read
/// plan's source mtime (the checkpoint the commit carries), clipped to now
/// as every admission clips (`transcript_cache::admission_rank`). It is
/// computed once, here, and carried unchanged through the proof, `execute`
/// and the insert, so no later clock read or mtime change widens which
/// residents may leave; equal or newer ranks never leave.
///
/// The measure is the step walk's (`copy_budget_step`, completing), taken
/// under blocking locks and main's view (`bound_for_main`, so a suspended
/// proof never inflates the need): `A` is the active's whole walk
/// (`StepMeasure::used`) and the room is the state budget less the
/// residents. An unmeasured part (residents, a visit-limited or over-budget
/// active) grants nothing and proves nothing. The insert's own slot
/// (`ins_extra`) and `A` are never held at once (`finish` consumes the
/// parser first), so they combine by `max`. No proof is carried for a copy
/// in the insert's entry/key band or one without a plan. Only a Full that
/// passed the pre-read size-growth gate reaches here; it has no previous
/// finalization charge or taken usage and can displace only older residents.
pub(super) fn tail_completion_budget(
    sampling: Option<&Context>,
    active: &mut OwnedActiveFile,
) -> (RetainBudget, StepMeasure, Option<ReleaseProof>) {
    // 1. Measure, waiting on the locks, in main's view (`copy_budget_step`
    // walks `bound_for_main`): a suspended proof never inflates `need`.
    let (budget, step) = {
        let _blocking = BlockingResidentMeasure::enter();
        copy_budget_step(sampling, Some(&mut *active), true)
    };
    let measured = (RetainBudget::from((budget, step)), step, None);
    let (Some(context), Some(resident), Some(a)) = (sampling, step.resident, step.used) else {
        return measured;
    };
    let Some(remaining) = state_bytes().checked_sub(resident) else {
        return measured;
    };
    let Some(file) = active.sampling.as_ref() else {
        return measured;
    };
    let continued = file.retained_hint.is_some();
    let full = matches!(file.mode, ReadMode::Full(_));
    let finalization_prev = file.retained_finalization_charge;
    let taken_usage = file.retained_usage;
    let key_len = file.key.len();
    let key_bound = crate::heap_layout_bound::bound(&file.key, usize::MAX);
    // 2. The insert-aware budget, computed before the clone charge.
    let Some(slot) = crate::transcript_cache::entry_slot_bytes::<CachedJsonlReduction>(key_len)
    else {
        return (
            RetainBudget::Granted {
                budget: 0,
                resident_measured: true,
                active_measured: true,
            },
            step,
            None,
        );
    };
    let ins_extra = slot.saturating_sub(
        std::mem::size_of::<CachedJsonlReduction>()
            + std::mem::size_of::<crate::transcript_acquisition::ReadPlan>(),
    );
    // Tests only: `ins_extra > A` does not occur on a supported layout, so
    // the rows that need it set this term (`test_hooks::set_ins_extra`).
    #[cfg(test)]
    let ins_extra = test_hooks::ins_extra().unwrap_or(ins_extra);
    let floor = a.max(ins_extra);
    let b_ins = remaining.checked_sub(floor).map_or(0, |room| room / 2);
    let granted = RetainBudget::Granted {
        budget: b_ins,
        resident_measured: true,
        active_measured: true,
    };
    #[cfg(test)]
    test_hooks::probe(|probe| {
        *probe = test_hooks::Probe {
            a,
            remaining,
            ins_extra,
            b_ins,
            ..test_hooks::Probe::default()
        }
    });
    let Some(clone) = active
        .parser
        .retention_bound(crate::transcript_cache::ENTRY_BYTES)
    else {
        return (granted, step, None);
    };
    #[cfg(test)]
    test_hooks::probe(|probe| {
        probe.clone = Some(clone);
        probe.finalization_prev = finalization_prev;
        probe.k = Some(clone.max(finalization_prev));
    });
    let Some(entry_limit) = crate::transcript_cache::ENTRY_BYTES
        .checked_sub(crate::transcript_cache::entry_overhead::<
            CachedJsonlReduction,
        >())
        .zip(key_bound)
        .and_then(|(limit, key)| limit.checked_sub(key))
    else {
        return (granted, step, None);
    };
    // In the entry/key band the insert would refuse it: never release for it.
    if clone > entry_limit {
        return (granted, step, None);
    }
    // 3. The re-admission rank, once; a continued copy or grown Full, with a plan.
    if !continued && !full {
        return (granted, step, None);
    }
    let Some(modified) = active.parser.planned_modified_hint() else {
        return (granted, step, None);
    };
    let rank =
        crate::transcript_cache::admission_rank(modified, crate::transcript_cache::admission_now());
    #[cfg(test)]
    test_hooks::probe(|probe| probe.rank = Some(rank));
    // Q-PR15's facts, owned before `finish`; `prove_release` applies the
    // guard on the legacy path only (S-c).
    let usage_grew =
        taken_usage.is_some_and(|taken| active.parser.accumulator.usage_witness() > taken);
    (
        granted,
        step,
        Some(ReleaseProof {
            cache: Arc::clone(&context.cache),
            remaining,
            floor,
            clone,
            finalization_prev,
            usage_grew,
            full,
            rank,
            modified,
            entry_limit,
        }),
    )
}

/// What a releasing completion owns for its release decision (M-a, S-a):
/// everything `prove_release` needs after main's proof retirement and decode
/// peak reservation, measured once in `tail_completion_budget`. Inline only.
pub(super) struct ReleaseProof {
    cache: Arc<SharedCache>,
    /// The completion walk's room (`state_bytes()` less main's resident view),
    /// before the proof retirement: the legacy path's figure.
    remaining: usize,
    /// `max(A, ins_extra)`: the active charge and the insert's slot are
    /// never held at once.
    floor: usize,
    /// `C`, the clone's bound.
    clone: usize,
    /// `F_prev`, the finalization charge reserved at the last admission.
    finalization_prev: usize,
    /// This read added usage since the take (Q-PR15 (b)).
    usage_grew: bool,
    /// A Full completion that passed the file-growth gate.
    full: bool,
    rank: (i64, i64),
    modified: (i64, i64),
    entry_limit: usize,
}

/// The finish-output bound a release proof may use (B1 ruling 3; X_out
/// hunk map). `Legacy` keeps `K = max(C, F_prev)` and the Q-PR15 guard:
/// Codex's explicit residual (ruling 5). `Refused`: no owned bound, so zero
/// victims. `Bound`: Claude's X_out, without the guard (S-c).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum XOut {
    Legacy,
    Refused,
    Bound(usize),
}

/// The X_out a completion of `source` proves with: Claude's `bound`
/// (`SnapshotAccumulator::finish_output_bound`, `None` refuses), the legacy
/// decision for every other source. `bound` runs only for Claude.
pub(super) fn x_out_for(source: SnapshotSource, bound: impl FnOnce() -> Option<usize>) -> XOut {
    if source != SnapshotSource::ClaudeCode {
        return XOut::Legacy;
    }
    #[cfg(test)]
    if let Some(x_out) = test_hooks::x_out() {
        return x_out;
    }
    bound().map_or(XOut::Refused, XOut::Bound)
}

/// M-a's release proof at the retention site (S-a): after main's proof
/// retirement (`retire_proof_beside_copy`) and #667's peak reservation.
/// `granted` is main's peak-reserved budget, admitted when nothing is
/// released. Without a proof (`proof` absent) this is `reserve_peak`.
///
/// With `XOut::Bound(x)` (Claude): `K' = max(C, x)`, `peak` = #667's decode
/// peak, `remaining'` re-read in main's view after the retirement, and
/// `need' = 2(K' + peak) + max(A, ins_extra) - remaining'`, all checked.
/// The churn bound (c22 amendment 1): `P_C` and `P*` are the shortest
/// victim-order prefixes ranked strictly below the copy's rank covering
/// `need_C = 2C + max(A, ins_extra) - remaining'` and `need'`, computed
/// together under the retained lock; release iff `|P*| <= |P_C|` (as
/// `K' >= C`, exactly when the copy-only prefix suffices), capped at
/// `|P_C|` at execution. Anything unknown, overflowing, infeasible or over
/// the bound releases nothing. A Full on the legacy decision releases nothing:
/// with neither X_out nor `F_prev`, nothing proves its finished output fits.
/// A Full reaches this proof only after file growth against the pre-read index
/// size. With X_out it has no churn bound: the margin over `C` can keep `|P*|`
/// above `|P_C|` among small residents and lock a growing file out of RAM.
/// It stays fit-or-nothing over strictly older residents and stops at the first
/// fit. Same-size re-reads, shrinks and first reads release nothing. Tail and
/// Unchanged reads keep the churn bound.
pub(super) fn prove_release(
    granted: RetainBudget,
    proof: Option<ReleaseProof>,
    sampling: Option<&Context>,
    x_out: XOut,
    finish_copy_budget: impl Fn(usize) -> Option<usize>,
    decode_peak: impl Fn(usize) -> Option<usize>,
) -> RetainBudget {
    let raw = granted.raw();
    // The peak #667 reserved from main's `copy_budget` (`granted`).
    #[cfg(test)]
    test_hooks::probe(|probe| probe.granted_peak = decode_peak(usize::MAX));
    let Some((proof, context)) = proof.zip(sampling) else {
        return granted;
    };
    match x_out {
        XOut::Legacy if proof.full => granted,
        XOut::Legacy => legacy_release(granted, proof, context, finish_copy_budget, decode_peak),
        XOut::Refused => granted,
        XOut::Bound(x_out) => {
            proven_release(proof, context, x_out, raw, finish_copy_budget, decode_peak)
                .unwrap_or(granted)
        }
    }
}

/// The pre-M-a decision: `K = max(C, F_prev)` with the Q-PR15 guard, at the
/// completion walk's `remaining`. #667 funds the decode peak inside the copy
/// share (c22 integ2 ACK, the rule M-a uses): the share is `K + peak`, so
/// `budget_after = finish_copy_budget(K + peak)` still admits the copy.
fn legacy_release(
    granted: RetainBudget,
    proof: ReleaseProof,
    context: &Context,
    finish_copy_budget: impl Fn(usize) -> Option<usize>,
    decode_peak: impl FnOnce(usize) -> Option<usize>,
) -> RetainBudget {
    let raw = granted.raw();
    let k = proof.clone.max(proof.finalization_prev);
    let Some(share) = decode_peak(proof.remaining).and_then(|peak| {
        #[cfg(test)]
        test_hooks::probe(|probe| probe.peak = Some(peak));
        k.checked_add(peak)
    }) else {
        return granted;
    };
    // Overflow-safe; `None` or 0 means `b_ins >= K + peak` (or an
    // unreachable overflow, admitted only against `b_ins` anyway).
    let Some(need) = share
        .checked_mul(2)
        .and_then(|twice| twice.checked_add(proof.floor))
        .and_then(|total| total.checked_sub(proof.remaining))
        .filter(|need| *need > 0)
    else {
        return granted;
    };
    #[cfg(test)]
    test_hooks::probe(|probe| probe.need = Some(need));
    // Q-PR15 (b): the conservative finalization guard.
    if proof.finalization_prev > proof.clone && proof.usage_grew {
        #[cfg(test)]
        test_hooks::probe(|probe| probe.finalization_guard = true);
        return granted;
    }
    // What must fit beside the retained copies after the release:
    // `R - need = state_bytes() - cursor - pinned`, with the context's own
    // charge (the side ledger once) in `pinned` (`DeferredRelease::pinned`).
    let Some(pinned) = context_overhead(context)
        .and_then(|overhead| overhead.checked_add(share.checked_mul(2)?))
        .and_then(|pinned| pinned.checked_add(proof.floor))
    else {
        return granted;
    };
    // Feasibility under the retained lock, without mutating: the
    // lower-ranked entries can make the copies fit `R - need`
    // (`older_release_fits`; the post-gate `release_older_to_fit` repeats
    // it under the same lock it releases under).
    let Ok(retained) = proof.cache.retained() else {
        return granted;
    };
    let Some(target) = crate::heap_layout_bound::bound(&*retained, usize::MAX)
        .and_then(|resident| resident.checked_sub(need))
    else {
        return granted;
    };
    if !retained.older_release_fits(target, proof.rank) {
        return granted;
    }
    drop(retained);
    // #667: the release keeps running only where the decode peak fits
    // `budget_after` too; a release never precedes an unfunded peak.
    let Some(budget_after) = finish_copy_budget(share) else {
        return granted;
    };
    RetainBudget::Deferred {
        raw,
        budget_after,
        release: DeferredRelease {
            cache: proof.cache,
            pinned,
            rank: proof.rank,
            modified: proof.modified,
            entry_limit: proof.entry_limit,
            max_victims: None,
        },
    }
}

/// `prove_release` with an owned X_out: the release, or `None` for zero
/// victims.
fn proven_release(
    proof: ReleaseProof,
    context: &Context,
    x_out: usize,
    raw: usize,
    finish_copy_budget: impl Fn(usize) -> Option<usize>,
    decode_peak: impl FnOnce(usize) -> Option<usize>,
) -> Option<RetainBudget> {
    // `remaining'` after the retirement, in main's view (a suspended proof
    // never inflates the need; the release retires it first).
    let resident = {
        let _blocking = BlockingResidentMeasure::enter();
        codex_cursor::bound_for_main(context, state_bytes())?
    };
    let remaining = state_bytes().checked_sub(resident)?;
    let k = proof.clone.max(x_out);
    let peak = decode_peak(remaining)?;
    #[cfg(test)]
    test_hooks::probe(|probe| probe.peak = Some(peak));
    let share = k.checked_add(peak)?;
    let need = share
        .checked_mul(2)?
        .checked_add(proof.floor)?
        .checked_sub(remaining)
        .filter(|need| *need > 0)?;
    let need_c = proof
        .clone
        .checked_mul(2)?
        .checked_add(proof.floor)?
        .saturating_sub(remaining);
    #[cfg(test)]
    test_hooks::probe(|probe| {
        probe.x_out = Some(x_out);
        probe.need_prime = Some(need);
        probe.need_c = Some(need_c);
    });
    let pinned = context_overhead(context)?
        .checked_add(share.checked_mul(2)?)?
        .checked_add(proof.floor)?;
    // Both prefixes on the same victim order, under one retained lock.
    let (victims, copy_only) = {
        let retained = proof.cache.retained().ok()?;
        let resident = crate::heap_layout_bound::bound(&*retained, usize::MAX)?;
        let victims = retained.older_prefix_len(resident.checked_sub(need)?, proof.rank)?;
        let copy_only = retained.older_prefix_len(resident.saturating_sub(need_c), proof.rank)?;
        (victims, copy_only)
    };
    #[cfg(test)]
    test_hooks::probe(|probe| probe.prefixes = Some((victims, copy_only)));
    if !proof.full && victims > copy_only {
        return None;
    }
    // The copy is admitted against its share, its decode peak reserved
    // (#667); `None` refuses.
    let budget_after = finish_copy_budget(share)?;
    Some(RetainBudget::Deferred {
        raw,
        budget_after,
        release: DeferredRelease {
            cache: proof.cache,
            pinned,
            rank: proof.rank,
            modified: proof.modified,
            entry_limit: proof.entry_limit,
            max_victims: (!proof.full).then_some(copy_only),
        },
    })
}

/// Completion hooks and recorders (tests only). Nothing here runs in a
/// production build.
#[cfg(test)]
pub(super) mod test_hooks {
    use std::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::snapshots) enum Point {
        BeforeRetireWitness,
        /// A bounded restore is decoded, immediately before identity sampling.
        BeforeRestoredIdentity,
        /// The first opened-object identity sample has actually been read.
        AfterIdentityHead,
        /// Content replay succeeded, before its final accepted-floor check.
        AfterRestoredContent,
        /// After revalidation, before `retain_reduction`.
        BeforeRetain,
        /// `retain_reduction`'s deferred path, before the stamp gate.
        BeforeStampGate,
        /// After `retain_reduction` returns, before `finish`.
        AfterRetain,
        /// The prepared native finish returned (any staged temp still
        /// private), before the commit fences or any store decision.
        BeforeNativeSettle,
        /// The completion is settled (receipt, owed hold or degraded
        /// disposition), before cursor publication, birth or any effect.
        BeforeNativeEffects,
        /// Before the retained PRE binding changes on disk; no POST is allowed.
        BeforeFaultBarrier,
        /// The retained PRE rebind is durable; the uploader may now proceed.
        AfterFaultBarrier,
    }

    /// What `tail_completion_budget` measured on its last call.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(in crate::snapshots) struct Probe {
        pub(in crate::snapshots) a: usize,
        pub(in crate::snapshots) remaining: usize,
        pub(in crate::snapshots) ins_extra: usize,
        pub(in crate::snapshots) b_ins: usize,
        pub(in crate::snapshots) clone: Option<usize>,
        pub(in crate::snapshots) finalization_prev: usize,
        pub(in crate::snapshots) k: Option<usize>,
        pub(in crate::snapshots) need: Option<usize>,
        /// Q-PR15's conservative finalization guard refused the release.
        pub(in crate::snapshots) finalization_guard: bool,
        /// The copy's re-admission rank, once computed (step 3).
        pub(in crate::snapshots) rank: Option<(i64, i64)>,
        /// M-a (`proven_release`): the X_out used, `need'`, `need_C`, and
        /// the prefix lengths `(|P*|, |P_C|)`.
        pub(in crate::snapshots) x_out: Option<usize>,
        pub(in crate::snapshots) need_prime: Option<usize>,
        pub(in crate::snapshots) need_c: Option<usize>,
        pub(in crate::snapshots) prefixes: Option<(usize, usize)>,
        /// #667's decode peak: `peak` sized into a release's share,
        /// `granted_peak` reserved from main's `copy_budget` (Claude-tail
        /// retention sites only: set in `prove_release`).
        pub(in crate::snapshots) peak: Option<usize>,
        pub(in crate::snapshots) granted_peak: Option<usize>,
    }

    /// A retention budget as a retention call received it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::snapshots) enum Decision {
        Granted {
            budget: usize,
            resident_measured: bool,
            active_measured: bool,
        },
        TierOrJoinExcluded,
        Unsealed,
        Deferred {
            raw: usize,
            budget_after: usize,
        },
    }

    type Hook = Box<dyn FnMut()>;
    type SelectionHook =
        Box<dyn FnOnce(&mut super::super::ScanIndex, Option<super::super::CandidateParseReason>)>;
    thread_local! {
        static HOOKS: RefCell<Vec<(Point, Hook)>> = RefCell::new(Vec::new());
        static AFTER_SELECTION: RefCell<Option<SelectionHook>> = const { RefCell::new(None) };
        static PROBE: RefCell<Probe> = RefCell::new(Probe::default());
        static DECISIONS: RefCell<Vec<Decision>> = const { RefCell::new(Vec::new()) };
        static BUCKETS: RefCell<Vec<super::sampled_jsonl::Bucket>> = const { RefCell::new(Vec::new()) };
        static UNREADABLE: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        static FINISH_ERRORS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        static INS_EXTRA: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
        static X_OUT: std::cell::Cell<Option<super::XOut>> = const { std::cell::Cell::new(None) };
    }

    /// Run `hook` each time this thread reaches `point`, until `clear`.
    pub(in crate::snapshots) fn set(point: Point, hook: impl FnMut() + 'static) {
        HOOKS.with(|hooks| hooks.borrow_mut().push((point, Box::new(hook))));
    }

    /// Change test inputs after selection, before acquisition; restore nested hooks on unwind.
    /// Its only caller is a native-layout restore test, which is macOS-only.
    #[cfg(target_os = "macos")]
    pub(in crate::snapshots) fn with_after_selection<T>(
        hook: impl FnOnce(&mut super::super::ScanIndex, Option<super::super::CandidateParseReason>)
            + 'static,
        run: impl FnOnce() -> T,
    ) -> T {
        struct Reset(Option<SelectionHook>);
        impl Drop for Reset {
            fn drop(&mut self) {
                AFTER_SELECTION.with(|slot| *slot.borrow_mut() = self.0.take());
            }
        }
        let _reset = Reset(AFTER_SELECTION.with(|slot| slot.replace(Some(Box::new(hook)))));
        run()
    }

    pub(in crate::snapshots) fn after_selection(
        index: &mut super::super::ScanIndex,
        reason: Option<super::super::CandidateParseReason>,
    ) {
        let hook = AFTER_SELECTION.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook(index, reason);
        }
    }

    /// Drop every hook and recorded value on this thread.
    pub(in crate::snapshots) fn clear() {
        HOOKS.with(|hooks| hooks.borrow_mut().clear());
        AFTER_SELECTION.with(|slot| slot.borrow_mut().take());
        PROBE.with(|probe| *probe.borrow_mut() = Probe::default());
        DECISIONS.with(|decisions| decisions.borrow_mut().clear());
        BUCKETS.with(|buckets| buckets.borrow_mut().clear());
        UNREADABLE.with(|causes| causes.borrow_mut().clear());
        FINISH_ERRORS.with(|errors| errors.borrow_mut().clear());
        INS_EXTRA.with(|term| term.set(None));
        X_OUT.with(|x_out| x_out.set(None));
    }

    pub(in crate::snapshots) fn fire(point: Point) {
        // Out of the table while it runs, so a hook may use the cache.
        let mut fired = HOOKS.with(|hooks| {
            let mut hooks = hooks.borrow_mut();
            let (fired, kept) = std::mem::take(&mut *hooks)
                .into_iter()
                .partition::<Vec<_>, _>(|(at, _)| *at == point);
            *hooks = kept;
            fired
        });
        for (_, hook) in &mut fired {
            hook();
        }
        HOOKS.with(|hooks| hooks.borrow_mut().extend(fired));
    }

    pub(in crate::snapshots) fn probe(update: impl FnOnce(&mut Probe)) {
        PROBE.with(|probe| update(&mut probe.borrow_mut()));
    }

    pub(in crate::snapshots) fn last_probe() -> Probe {
        PROBE.with(|probe| *probe.borrow())
    }

    pub(in crate::snapshots) fn record_budget(budget: &super::RetainBudget) {
        let decision = match budget {
            super::RetainBudget::Granted {
                budget,
                resident_measured,
                active_measured,
            } => Decision::Granted {
                budget: *budget,
                resident_measured: *resident_measured,
                active_measured: *active_measured,
            },
            super::RetainBudget::TierOrJoinExcluded { .. } => Decision::TierOrJoinExcluded,
            super::RetainBudget::Unsealed { .. } => Decision::Unsealed,
            super::RetainBudget::Deferred {
                raw, budget_after, ..
            } => Decision::Deferred {
                raw: *raw,
                budget_after: *budget_after,
            },
        };
        DECISIONS.with(|decisions| decisions.borrow_mut().push(decision));
    }

    pub(in crate::snapshots) fn decisions() -> Vec<Decision> {
        DECISIONS.with(|decisions| decisions.borrow().clone())
    }

    pub(in crate::snapshots) fn record_bucket(bucket: super::sampled_jsonl::Bucket) {
        BUCKETS.with(|buckets| buckets.borrow_mut().push(bucket));
    }

    pub(in crate::snapshots) fn buckets() -> Vec<super::sampled_jsonl::Bucket> {
        BUCKETS.with(|buckets| buckets.borrow().clone())
    }

    /// A census unreadable cause, by its `UnreadableCause` ordinal.
    pub(in crate::snapshots) fn record_unreadable(cause: usize) {
        UNREADABLE.with(|causes| causes.borrow_mut().push(cause));
    }

    pub(in crate::snapshots) fn unreadable() -> Vec<usize> {
        UNREADABLE.with(|causes| causes.borrow().clone())
    }

    /// The error chain of a sampled completion's failed `finish`.
    pub(in crate::snapshots) fn record_finish_error(error: &anyhow::Error) {
        FINISH_ERRORS.with(|errors| errors.borrow_mut().push(format!("{error:#}")));
    }

    pub(in crate::snapshots) fn finish_errors() -> Vec<String> {
        FINISH_ERRORS.with(|errors| errors.borrow().clone())
    }

    /// Sets R0's insert term in place of the measured one, until `clear`.
    pub(in crate::snapshots) fn set_ins_extra(term: Option<usize>) {
        INS_EXTRA.with(|ins_extra| ins_extra.set(term));
    }

    pub(in crate::snapshots) fn ins_extra() -> Option<usize> {
        INS_EXTRA.with(std::cell::Cell::get)
    }

    /// Sets a Claude completion's X_out in place of its measured bound
    /// (`x_out_for`), until `clear`: drives M-a's proof at a chosen X_out.
    pub(in crate::snapshots) fn set_x_out(x_out: Option<super::XOut>) {
        X_OUT.with(|cell| cell.set(x_out));
    }

    pub(in crate::snapshots) fn x_out() -> Option<super::XOut> {
        X_OUT.with(std::cell::Cell::get)
    }
}

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Pin this thread's scan clock (tests only); `None` restores real time.
#[cfg(test)]
pub(super) fn set_test_now(now: Option<u64>) {
    TEST_NOW.with(|clock| clock.set(now));
}

pub(super) fn now_seconds() -> u64 {
    #[cfg(test)]
    if let Some(now) = TEST_NOW.with(std::cell::Cell::get) {
        return now;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

pub(super) fn compatible_reduction(accumulator: &SnapshotAccumulator) -> bool {
    accumulator.source != SnapshotSource::Codex
        || (accumulator.codex_observed_priority_turns.is_some()
            && accumulator.codex_usage_accounting_complete()
            && lineage_retainable(accumulator))
}

/// Which ownership lineages a retained copy may continue (P1-RETAIN-3).
fn lineage_retainable(accumulator: &SnapshotAccumulator) -> bool {
    // (1) Today's class, unchanged: no fork, no header parent, no sidecar parent.
    let today = !accumulator.codex_is_fork
        && accumulator.codex_parent_session_ref.is_none()
        && accumulator.codex_sidecar_parent.is_none();
    // (2) A fork whose boundary was decided from in-file header fields only:
    // exact_start → Ordinal, history_base → AllLocal, subagent legacy trigger
    // → AllLocal. Not a created thread or sidecar-ambiguous file (native_only),
    // and no parent ledger was read.
    let in_file_fork = accumulator.codex_is_fork
        && !accumulator.codex_created_thread_native_only
        && !accumulator.codex_parent_ledger_consulted
        && matches!(
            accumulator.codex_ownership_boundary,
            CodexOwnershipBoundary::Ordinal { .. } | CodexOwnershipBoundary::AllLocal
        );
    // NativeCreatedThread: false until step 2 (G-CT). Ledger-resolved
    // AwaitingParentPrefix → AllLocal: false until U1a-2.
    today || in_file_fork
}

#[allow(clippy::too_many_arguments)]
pub(super) fn new_source_parser(
    file: File,
    candidate: &CandidateFile,
    source: SnapshotSource,
    metadata: &CodexTitleMetadata,
    traces: Option<Arc<CodexTurnTraceMap>>,
    parents: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    artifacts: bool,
    identity_capture: bool,
    index: &ScanIndex,
) -> Result<Box<OwnedJsonlParser>> {
    let mut parser = OwnedJsonlParser::new(
        file,
        &candidate.path,
        source,
        match source {
            SnapshotSource::Codex => apply_codex_line,
            SnapshotSource::ClaudeCode => apply_claude_code_line,
            SnapshotSource::Pi => apply_pi_line,
        },
        (source == SnapshotSource::Codex).then_some(metadata),
        traces,
        parents,
        artifacts,
    )?;
    parser.accumulator.claude_request_identity_capture = identity_capture;
    if source == SnapshotSource::Codex {
        configure_tier_replay(&mut parser, candidate, index);
        codex_counting_version::configure_singleton(&mut parser, candidate, index);
    }
    Ok(Box::new(parser))
}
pub(super) fn configure_tier_replay(
    parser: &mut OwnedJsonlParser,
    candidate: &CandidateFile,
    index: &ScanIndex,
) {
    let previous =
        codex_file_join::receipt_state(index.files.get(&local_index_key(&candidate.path)));
    parser.accumulator.codex_tier_replay = Some(codex_file_join::TierReplay::new(
        previous.0,
        previous.1,
        index
            .active_upload_context_fingerprint
            .clone()
            .unwrap_or_default(),
    ));
}

#[cfg(test)]
thread_local! { static TEST_REFUSE_REDUCTION_DEPENDENCIES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

/// Actual path-scoped interpretation dependencies. Decode no provider row here;
/// reuse existing sidecar inventory and bounded owning-header authority.
pub(super) fn reduction_dependencies(
    source: SnapshotSource,
    candidate: &CandidateFile,
    codex: &CodexTitleMetadata,
    claude: &ClaudeTitleMetadata,
    support: Option<&Path>,
) -> Option<String> {
    #[cfg(test)]
    if TEST_REFUSE_REDUCTION_DEPENDENCIES.with(std::cell::Cell::get) {
        return None;
    }
    if source == SnapshotSource::Codex {
        Some(sha256_hex(&[
            "codex_reduction_dependencies:v1",
            &codex.path_reduction_fingerprint(&candidate.path),
            &codex_file_join::header_reduction_witness(candidate).ok()?,
        ]))
    } else {
        let mut scoped = candidate.clone();
        // Claude API/trace evidence is joined freshly after native finish, not
        // retained in the pre-finish transcript accumulator. Keep Desktop and
        // child naming dependencies here; keep usage sidecars in selection.
        let reduction_support = if source == SnapshotSource::ClaudeCode {
            None
        } else {
            support
        };
        prepare_owned_scan_candidate(source, &mut scoped, codex, claude, reduction_support);
        if source == SnapshotSource::ClaudeCode {
            Some(sha256_hex(&[
                "claude_reduction_dependencies:v1",
                &scoped.source_file_fingerprint,
            ]))
        } else {
            Some(scoped.source_file_fingerprint)
        }
    }
}

#[cfg(test)]
#[path = "claude_sidecar_reduction_tests.rs"]
mod claude_sidecar_reduction_tests;

#[cfg(test)]
mod cache_lifecycle_tests {
    use super::*;

    #[test]
    fn cache_lifecycle_poisoned_lock_is_not_reported_as_absent() {
        let cache = SharedCache::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache.inner.lock().unwrap();
            panic!("synthetic cache lock poison");
        }));
        assert!(result.is_err());
        let (_, counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
            assert!(cache.take("synthetic").is_none());
            cache.clear();
        });
        assert_eq!(counts.take_poisoned_lock, 1);
        assert_eq!(counts.take_absent, 0);
        assert_eq!(counts.take_hit, 0);
        assert_eq!(counts.clear_poisoned_lock, 1);
        assert_eq!(counts.clear_entries_released, 0);
    }
}

// The daemon owns this cache; the guard is a non-owning alias beside Context.cache.
impl HeapLayoutBound for std::sync::Weak<SharedCache> {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, _: &mut Counter) -> Option<()> {
        Some(())
    }
}
