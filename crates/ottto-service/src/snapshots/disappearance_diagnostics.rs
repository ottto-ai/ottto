//! Best-effort process/source totals, never traversal authority or persisted state.
//! Independent relaxed loads are non-atomic across counters and overflow. A wrap
//! can be visible before its sticky flag: even false cannot prove exact concurrent
//! conservation. First/reset/gap/missing-field/restored-window attribution is UNKNOWN.
use super::SnapshotSource;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    NotFound,
    RootResolutionUnresolved,
    PreflightFingerprintChanged,
}
impl Cause {
    fn index(self) -> usize {
        match self {
            Self::NotFound => 0,
            Self::RootResolutionUnresolved => 1,
            Self::PreflightFingerprintChanged => 2,
        }
    }
}

/// Where a NotFound was observed. Content-free and process-only: it names a
/// scanner branch, never a path, and is never traversal authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Site {
    /// A queued directory vanished before it was read.
    WalkDirectory,
    /// A directory entry vanished between `readdir` and its `lstat`.
    WalkEntry,
    /// A queued census member (walk, hint or replay) vanished before its stat.
    CandidateWalk,
    /// A forced Claude family member enumerated from the index vanished.
    CandidateForcedIndex,
    /// A selected file vanished before its no-follow open.
    Open,
}
const SITES: usize = 5;
/// Per site: a NotFound that stayed operational loss, then one settled as removal.
const OUTCOMES: usize = 2;
impl Site {
    fn index(self) -> usize {
        match self {
            Self::WalkDirectory => 0,
            Self::WalkEntry => 1,
            Self::CandidateWalk => 2,
            Self::CandidateForcedIndex => 3,
            Self::Open => 4,
        }
    }
}

/// What a vanished Claude census member's retirement dropped with its index
/// entry. Content-free and process-only, like the site split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Vanished {
    /// Its request-census record.
    RequestCensusRemoved,
}
const VANISHED: usize = 1;
impl Vanished {
    fn index(self) -> usize {
        match self {
            Self::RequestCensusRemoved => 0,
        }
    }
}

struct Counters {
    counts: [AtomicU64; 4],
    not_found_sites: [AtomicU64; SITES * OUTCOMES],
    vanished: [AtomicU64; VANISHED],
    overflowed: AtomicBool,
}
impl Counters {
    const fn new() -> Self {
        Self {
            counts: [const { AtomicU64::new(0) }; 4],
            not_found_sites: [const { AtomicU64::new(0) }; SITES * OUTCOMES],
            vanished: [const { AtomicU64::new(0) }; VANISHED],
            overflowed: AtomicBool::new(false),
        }
    }
    fn bump(&self, counter: &AtomicU64) {
        if counter.fetch_add(1, Ordering::Relaxed) == u64::MAX {
            self.overflowed.store(true, Ordering::Relaxed);
        }
    }
    fn record(&self, cause: Cause) {
        self.bump(&self.counts[cause.index()]);
    }
    fn record_not_found_site(&self, site: Site, removal: bool) {
        self.bump(&self.not_found_sites[site.index() * OUTCOMES + usize::from(removal)]);
    }
    fn record_vanished(&self, vanished: Vanished) {
        self.bump(&self.vanished[vanished.index()]);
    }
    fn snapshot(&self) -> Totals {
        Totals {
            version: 1,
            scope: "process_lifetime_not_window",
            counts: std::array::from_fn(|i| self.counts[i].load(Ordering::Relaxed)),
            not_found_sites: std::array::from_fn(|site| {
                std::array::from_fn(|outcome| {
                    self.not_found_sites[site * OUTCOMES + outcome].load(Ordering::Relaxed)
                })
            }),
            vanished_request_census_removed: self.vanished[Vanished::RequestCensusRemoved.index()]
                .load(Ordering::Relaxed),
            overflowed: self.overflowed.load(Ordering::Relaxed),
        }
    }
}

static TOTALS: [Counters; 3] = [const { Counters::new() }; 3];

/// Fixed order: NotFound, unresolved root, changed preflight, changed target.
/// `not_found_sites` splits the walk, candidate and open NotFounds by site in
/// `Site` order, each `[loss, removal]`; NotFound in `counts` includes both,
/// and root NotFounds have no site. `vanished_request_census_removed` counts
/// the request-census records the page merge dropped with a vanished Claude
/// member's retired entry.
/// The sticky flag invalidates exact intervals; false is not a coherence proof.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct Totals {
    version: u8,
    scope: &'static str,
    counts: [u64; 4],
    not_found_sites: [[u64; OUTCOMES]; SITES],
    vanished_request_census_removed: u64,
    overflowed: bool,
}

pub(super) fn increment(count: &mut usize, source: SnapshotSource, cause: Cause) {
    // Preserve the original arithmetic (including overflow behavior) and order.
    *count += 1;
    record(source, cause);
}

fn record(source: SnapshotSource, cause: Cause) {
    TOTALS[source.slot()].record(cause);
    #[cfg(test)]
    TEST_EVENTS.with(|events| {
        if let Some(mut counts) = events.get() {
            counts[source.slot()][cause.index()] += 1;
            events.set(Some(counts));
        }
    });
}

fn record_not_found_site(source: SnapshotSource, site: Site, removal: bool) {
    TOTALS[source.slot()].record_not_found_site(site, removal);
    #[cfg(test)]
    TEST_SITE_EVENTS.with(|events| {
        if let Some(mut counts) = events.get() {
            counts[source.slot()][site.index()][usize::from(removal)] += 1;
            events.set(Some(counts));
        }
    });
}

/// A NotFound at `site` that stays operational loss and turns the traversal red.
pub(super) fn not_found(count: &mut usize, source: SnapshotSource, site: Site) {
    increment(count, source, Cause::NotFound);
    record_not_found_site(source, site, false);
}

/// A NotFound at `site` the scanner settles as a removal. It is recorded in the
/// process totals only and never increments an operational count.
pub(super) fn not_found_removal(source: SnapshotSource, site: Site) {
    record(source, Cause::NotFound);
    record_not_found_site(source, site, true);
}

/// The page merge dropped `vanished` with a vanished Claude member's entry.
pub(super) fn vanished(source: SnapshotSource, vanished: Vanished) {
    TOTALS[source.slot()].record_vanished(vanished);
    #[cfg(test)]
    TEST_VANISHED_EVENTS.with(|events| {
        if let Some(mut counts) = events.get() {
            counts[source.slot()][vanished.index()] += 1;
            events.set(Some(counts));
        }
    });
}

pub(super) fn snapshot(source: SnapshotSource) -> Totals {
    TOTALS[source.slot()].snapshot()
}

#[cfg(test)]
pub(crate) type SiteEvents = [[[u64; OUTCOMES]; SITES]; 3];

#[cfg(test)]
thread_local! {
    static TEST_EVENTS: std::cell::Cell<Option<[[u64; 4]; 3]>> = const { std::cell::Cell::new(None) };
    static TEST_SITE_EVENTS: std::cell::Cell<Option<SiteEvents>> = const { std::cell::Cell::new(None) };
    static TEST_VANISHED_EVENTS: std::cell::Cell<Option<[[u64; VANISHED]; 3]>> = const { std::cell::Cell::new(None) };
}

/// Observe actual caller-thread producers without global resets or decision hooks.
#[cfg(test)]
pub(super) fn observe<T>(f: impl FnOnce() -> T) -> (T, [[u64; 4]; 3]) {
    struct Reset(Option<[[u64; 4]; 3]>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_EVENTS.with(|events| events.set(self.0));
        }
    }
    let reset = Reset(TEST_EVENTS.with(|events| events.replace(Some([[0; 4]; 3]))));
    let result = f();
    let counts = TEST_EVENTS.with(|events| events.get().unwrap());
    drop(reset);
    (result, counts)
}

/// The caller-thread NotFound site split, per source, `Site` order, `[loss, removal]`.
#[cfg(test)]
pub(crate) fn observe_sites<T>(f: impl FnOnce() -> T) -> (T, SiteEvents) {
    struct Reset(Option<SiteEvents>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_SITE_EVENTS.with(|events| events.set(self.0));
        }
    }
    let reset =
        Reset(TEST_SITE_EVENTS.with(|events| events.replace(Some([[[0; OUTCOMES]; SITES]; 3]))));
    let result = f();
    let counts = TEST_SITE_EVENTS.with(|events| events.get().unwrap());
    drop(reset);
    (result, counts)
}

/// The caller-thread vanished-member retirement counts, per source, `Vanished` order.
#[cfg(test)]
pub(super) fn observe_vanished<T>(f: impl FnOnce() -> T) -> (T, [[u64; VANISHED]; 3]) {
    struct Reset(Option<[[u64; VANISHED]; 3]>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_VANISHED_EVENTS.with(|events| events.set(self.0));
        }
    }
    let reset = Reset(TEST_VANISHED_EVENTS.with(|events| events.replace(Some([[0; VANISHED]; 3]))));
    let result = f();
    let counts = TEST_VANISHED_EVENTS.with(|events| events.get().unwrap());
    drop(reset);
    (result, counts)
}

#[cfg(test)]
impl Totals {
    pub(super) fn maximum() -> Self {
        Self {
            version: 1,
            scope: "process_lifetime_not_window",
            counts: [u64::MAX; 4],
            not_found_sites: [[u64::MAX; OUTCOMES]; SITES],
            vanished_request_census_removed: u64::MAX,
            overflowed: true,
        }
    }
}

#[cfg(test)]
#[rustfmt::skip]
pub(super) mod tests;

#[cfg(test)]
type AbsenceParentProbeHook = Box<dyn FnOnce()>;
#[cfg(test)]
thread_local! {
    static ABSENCE_PARENT_PROBE_HOOK: std::cell::RefCell<Option<AbsenceParentProbeHook>> = const { std::cell::RefCell::new(None) };
    static WALK_DIRECTORY_ABSENCE_HOOK: std::cell::RefCell<Option<AbsenceParentProbeHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn before_walk_directory_absence_proof() {
    let hook = WALK_DIRECTORY_ABSENCE_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
#[cfg(test)]
pub(super) fn before_absence_parent_probe() {
    let hook = ABSENCE_PARENT_PROBE_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(all(test, unix))]
#[rustfmt::skip]
mod absence_parent_counts_tests;
