//! What the live Claude finalizer knows about each response that its item
//! does not keep, captured for the P1 money shadow only.
//!
//! The live finalizer runs unchanged when no capture is armed (no allocation,
//! no accounting, no field on `SnapshotItem` or the accumulator). When the
//! shadow is armed for the file, `finish` passes a capture that records, per
//! response: the live bucket row it was added to (hour, model, pricing
//! selectors), its message-id hash when its key has one, and the usage of
//! the responses the occurrence map does not keep (message-only, idless and
//! displaced). Every byte is admitted first against the capture ceiling,
//! which is the shadow's own budget, never a live reservation; a refusal
//! drops the capture and the shadow reports the file unbuilt. Its CPU is
//! bounded apart from its memory: the message ids it hashes are checked
//! (each id's length and the parse's total) before any is hashed, and they
//! are sorted only when they arrive out of order.
//!
//! Captures wait in a process store keyed by index key until the page's
//! shadow takes them (bound to the parse's fingerprint), and expire after a
//! fixed time if no shadow takes them.

use super::super::{rfc3339_unix_seconds, ClaudeTranscriptUsageOccurrence, UsageTotals};
use super::ClaudeMoneyTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// All captures alive at once (in a parse or waiting in the store).
pub(crate) const CAPTURE_CEILING_BYTES: usize = 8 * 1024 * 1024;
/// A capture no shadow took by then is dropped.
const CAPTURE_TTL: Duration = Duration::from_secs(15 * 60);
/// Distinct live rows one file may place responses in.
const MAX_ROWS_PER_FILE: usize = 4096;
/// Admission granularity.
const FUNDS_CHUNK_BYTES: usize = 16 * 1024;
/// Per-node share of a B-tree entry (key, value and node overhead).
pub(super) const MAP_ENTRY_BYTES: usize = 64;
/// A message id longer than this refuses the capture (real ids are ~30 B).
const MAX_MESSAGE_ID_BYTES: usize = 256;
/// Message-id bytes one parse's capture may hash, and how many ids (the
/// hashing and the sort are linear and `n log n` in them).
const MAX_MESSAGE_HASH_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_MESSAGE_IDS: usize = 131_072;

static CAPTURE_RESERVED: AtomicUsize = AtomicUsize::new(0);

/// Cumulative work allowance, independent of resident refunds. Reset once,
/// before the page's native finalizers. Time counts capture work, not parsing:
/// `micros` sums the ended money sections only, `section` is the start of
/// the one running (admission checks count it before it ends), and `first`
/// (the first money finalizer) dates the native time between them for the
/// receipt alone.
#[derive(Default)]
struct Work {
    input: usize,
    comparisons: usize,
    micros: u64,
    section: Option<Instant>,
    first: Option<Instant>,
    exhausted: bool,
}
const PAGE_INPUT_BYTES: usize = 8 * 1024 * 1024;
const PAGE_COMPARISONS: usize = 1_048_576;
const PAGE_CAPTURE_US: u64 = 100_000;
static WORK: Mutex<BTreeMap<PathBuf, Work>> = Mutex::new(BTreeMap::new());

// Production has one capture scope, and SNAPSHOT_SYNC_LOCK serializes its
// pages. Mirror the page latch so later files return before arming takes a
// lock or clones a scope. Tests have independent scopes on parallel threads.
static PAGE_EXHAUSTED: AtomicBool = AtomicBool::new(false);

// Normal tests isolate scopes; one regression opts its thread into the
// actual production latch. Other test threads never read or mutate it.
fn uses_process_latch() -> bool {
    #[cfg(test)]
    {
        PROCESS_LATCH_FOR_TEST.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        true
    }
}

pub(super) fn page_exhausted(scope: &Path) -> bool {
    #[cfg(test)]
    if !uses_process_latch() {
        return WORK.lock().map_or(true, |pages| {
            pages.get(scope).is_some_and(|work| work.exhausted)
        });
    }
    let _ = scope;
    PAGE_EXHAUSTED.load(Ordering::Acquire)
}

/// Check before arming (which locks and, in tests, clones the scope).
/// Arming and plan eligibility stay independent of the current page's work:
/// the next-page finalizer probe selects its inputs before resetting Work.
fn page_exhausted_for_file(path: &Path) -> bool {
    #[cfg(test)]
    if !uses_process_latch() {
        return super::SHADOW_ENABLED_FOR_TEST
            .lock()
            .map_or(true, |scopes| {
                scopes
                    .iter()
                    .find(|dir| dir.parent().is_some_and(|base| path.starts_with(base)))
                    .is_some_and(|scope| page_exhausted(scope))
            });
    }
    let _ = path;
    PAGE_EXHAUSTED.load(Ordering::Acquire)
}

/// After a cold page, focus the next Full parse on the oldest 64 family
/// turns. Gating optional capture leaves native file/finalizer order alone.
/// All members of a chosen family remain eligible, within the original caps.
pub(crate) const NEXT_PAGE_FAMILIES: usize = 64;
/// One plan entry's admission: its key bytes, a map entry, the `String`
/// and the entry. A fallback-set entry is charged the same.
fn plan_key_bytes(key: &str) -> usize {
    key.len() + MAP_ENTRY_BYTES + std::mem::size_of::<String>() + std::mem::size_of::<PlanEntry>()
}

/// A family some page of the scope listed.
struct PlanEntry {
    /// Its scheduling turn, possibly a consumed turn not yet acknowledged.
    turn: u64,
    /// The plan build that last listed it.
    build: u64,
    /// When a page last listed it; once `CAPTURE_TTL` old the entry has
    /// expired, as if no page had listed it.
    listed: Instant,
    /// Among the oldest 64 of the page that last listed it, as of that
    /// page's complete plan, and not consumed since.
    eligible: bool,
}

/// What the scope's pages decided for the next parse's optional captures.
/// It is scope-wide: each page updates the entries of the families it
/// lists in place, and other pages' entries (their turns and exclusions)
/// stay until they expire, so a family built on any page is not eligible
/// again before its turn comes. Once a scope has had a page it always has
/// a plan (MONEY decision: fail closed, never stale).
struct Plan {
    entries: BTreeMap<String, PlanEntry>,
    entry_funds: Funds,
    /// After a page's complete plan failed: only these families (at most
    /// 64) are eligible. Empty: nothing optional is captured.
    fallback: Option<BTreeSet<String>>,
    fallback_funds: Funds,
    /// When entries that had not expired were dropped (ceiling pressure, or
    /// a consumed turn the plan could not fund). Until that is
    /// `CAPTURE_TTL` old, a family without an entry may be one of them and
    /// is not eligible.
    lost: Option<Instant>,
    build: u64,
    created: Instant,
}

impl Plan {
    /// Nothing optional is captured.
    fn closed() -> Self {
        Self {
            entries: BTreeMap::new(),
            entry_funds: Funds::default(),
            fallback: Some(BTreeSet::new()),
            fallback_funds: Funds::default(),
            lost: None,
            build: 0,
            created: Instant::now(),
        }
    }

    fn live(&self, key: &str) -> Option<&PlanEntry> {
        self.entries
            .get(key)
            .filter(|entry| entry.listed.elapsed() < CAPTURE_TTL)
    }

    /// Whether the next parse may capture the family `key` optionally. A
    /// family no live entry lists (another native page's, never planned)
    /// is, unless entries were lost recently.
    fn allows(&self, key: &str) -> bool {
        if self.created.elapsed() >= CAPTURE_TTL {
            return false;
        }
        if let Some(fallback) = &self.fallback {
            return fallback.contains(key);
        }
        match self.live(key) {
            Some(entry) => entry.eligible,
            None => !matches!(self.lost, Some(lost) if lost.elapsed() < CAPTURE_TTL),
        }
    }
}

/// Every holder keeps this lock for one map operation (microseconds:
/// `begin` and `scheduling_turn` do one lookup; installing or forgetting a
/// plan swaps it and drops the replaced one after unlocking), so planning
/// takes it blocking rather than failing on contention.
static PLANS: Mutex<BTreeMap<PathBuf, Plan>> = Mutex::new(BTreeMap::new());

/// Why a page's complete plan was not installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlanFailure {
    /// The close budget ran out during the walk.
    Deadline,
    /// The capture ceiling refused the plan's keys.
    Funds,
    /// The plan lock was poisoned.
    Lock,
}

/// What a page installed for the next parse's optional captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlanInstall {
    Complete,
    /// Only the oldest 64 not consumed this page are eligible; nothing
    /// else is captured.
    Fallback(PlanFailure),
    /// Not even the fallback could be funded or installed: nothing optional
    /// is captured.
    Closed(PlanFailure),
}

impl PlanInstall {
    pub(super) fn failure(self) -> Option<PlanFailure> {
        match self {
            Self::Complete => None,
            Self::Fallback(failure) | Self::Closed(failure) => Some(failure),
        }
    }
}

/// Update the scope's plan for the next parse. `keys` is every page family
/// with its turn after this page's updates; `fallback` lists the oldest 64
/// not consumed this page (eligible) and this page's consumed families
/// (with their new turns, not eligible). The walk over `keys` is bounded
/// by its funds (the capture ceiling) and stops at `deadline`; then only
/// the fallback becomes eligible, which is O(64) work, never the old plan's
/// eligible families.
pub(super) fn plan_next_page<'a>(
    scope: &Path,
    keys: impl Iterator<Item = (&'a str, u64)>,
    fallback: impl Iterator<Item = (&'a str, u64, bool)>,
    deadline: Instant,
) -> PlanInstall {
    plan_next_page_while(scope, keys, fallback, || {
        #[cfg(test)]
        if PLAN_DEADLINE_FOR_TEST.with(std::cell::Cell::get) {
            return false;
        }
        Instant::now() < deadline
    })
}

fn plan_next_page_while<'a>(
    scope: &Path,
    keys: impl Iterator<Item = (&'a str, u64)>,
    fallback: impl Iterator<Item = (&'a str, u64, bool)>,
    within_deadline: impl FnMut() -> bool,
) -> PlanInstall {
    // Take the scope's plan out, leaving it closed: until the update is
    // installed, the next parse captures nothing optional. The update
    // reuses the plan's funds and live entries.
    let Some(taken) = swap_plan(scope, Plan::closed()) else {
        return PlanInstall::Closed(PlanFailure::Lock);
    };
    let mut plan = taken.unwrap_or_else(Plan::closed);
    drop_expired(&mut plan);
    let installed = match complete_plan(&mut plan, keys, within_deadline) {
        Ok(()) => PlanInstall::Complete,
        Err(failure) => {
            if fallback_plan(&mut plan, fallback) {
                PlanInstall::Fallback(failure)
            } else {
                PlanInstall::Closed(failure)
            }
        }
    };
    plan.created = Instant::now();
    match swap_plan(scope, plan) {
        Some(_) => installed,
        None => PlanInstall::Closed(PlanFailure::Lock),
    }
}

/// Drop expired entries, refunding their funds (ceiling-bounded work).
fn drop_expired(plan: &mut Plan) {
    let mut freed = 0;
    plan.entries.retain(|key, entry| {
        let keep = entry.listed.elapsed() < CAPTURE_TTL;
        if !keep {
            freed += plan_key_bytes(key);
        }
        keep
    });
    plan.entry_funds.refund(freed);
}

/// Update every page family's entry in place and make the oldest 64
/// eligible. On failure the page's entries updated so far keep their new
/// turns (each no older than before) and are not eligible; the fallback
/// then decides.
fn complete_plan<'a>(
    plan: &mut Plan,
    keys: impl Iterator<Item = (&'a str, u64)>,
    mut within_deadline: impl FnMut() -> bool,
) -> Result<(), PlanFailure> {
    if !within_deadline() {
        return Err(PlanFailure::Deadline);
    }
    plan.build += 1;
    let build = plan.build;
    let listed = Instant::now();
    // Under ceiling pressure, room comes from families this build has not
    // listed (yet): other pages' entries never outlast a page whose own
    // families fit.
    let oldest_bytes =
        NEXT_PAGE_FAMILIES * (MAP_ENTRY_BYTES + std::mem::size_of::<((u64, &str), &str)>());
    let mut oldest_funds = Funds::default();
    if !oldest_funds.spend(oldest_bytes) {
        prune_unlisted(plan, build);
        if !oldest_funds.spend(oldest_bytes) {
            return Err(PlanFailure::Funds);
        }
    }
    // Oldest-64 selection with the producer's same (turn, family key)
    // total order, without an uninterruptible whole-page sort.
    let mut oldest = BTreeMap::new();
    for (key, turn) in keys {
        if !within_deadline() {
            return Err(PlanFailure::Deadline);
        }
        let entry = PlanEntry {
            turn,
            build,
            listed,
            eligible: false,
        };
        if let Some(old) = plan.entries.get_mut(key) {
            *old = entry;
        } else {
            // A page family still ahead in the walk that the pruning drops
            // comes back with the page's own turn, which already includes
            // the plan's (`scheduling_turn`).
            if !plan.entry_funds.spend(plan_key_bytes(key)) {
                prune_unlisted(plan, build);
                if !plan.entry_funds.spend(plan_key_bytes(key)) {
                    return Err(PlanFailure::Funds);
                }
            }
            plan.entries.insert(key.to_owned(), entry);
        }
        oldest.insert((turn, key), key);
        if oldest.len() > NEXT_PAGE_FAMILIES {
            let _ = oldest.pop_last();
        }
    }
    if !within_deadline() {
        return Err(PlanFailure::Deadline);
    }
    for key in oldest.values() {
        // Pruning drops only entries other builds listed.
        plan.entries
            .get_mut(*key)
            .expect("listed by this build")
            .eligible = true;
    }
    plan.fallback = None;
    plan.fallback_funds = Funds::default();
    Ok(())
}

/// Drop the entries `build` has not listed, refunding their funds; a family
/// without an entry is not eligible until this loss expires.
fn prune_unlisted(plan: &mut Plan, build: u64) {
    let mut freed = 0;
    plan.entries.retain(|key, entry| {
        let keep = entry.build == build;
        if !keep {
            freed += plan_key_bytes(key);
        }
        keep
    });
    if freed > 0 {
        plan.entry_funds.refund(freed);
        plan.lost = Some(Instant::now());
    }
}

/// Make the fallback's families (at most 64) the only eligible ones and
/// record this page's consumed turns, which are never eligible again before
/// a complete plan selects them. The funded selection is also kept in the
/// families' entries, so it outlasts another page's complete plan. False
/// (nothing eligible) when funds refuse the fallback set.
fn fallback_plan<'a>(plan: &mut Plan, entries: impl Iterator<Item = (&'a str, u64, bool)>) -> bool {
    plan.fallback = Some(BTreeSet::new());
    plan.fallback_funds = Funds::default();
    let listed = Instant::now();
    let mut fallback_funds = Funds::default();
    let mut fallback = BTreeSet::new();
    let mut funded = true;
    for (key, turn, allowed) in entries {
        if allowed && (!funded || fallback.len() == NEXT_PAGE_FAMILIES) {
            continue;
        }
        if let Some(entry) = plan.entries.get_mut(key) {
            entry.turn = turn;
            entry.listed = listed;
            entry.eligible &= allowed;
        } else if plan.entry_funds.spend(plan_key_bytes(key)) {
            plan.entries.insert(
                key.to_owned(),
                PlanEntry {
                    turn,
                    build: plan.build,
                    listed,
                    eligible: false,
                },
            );
        } else if !allowed {
            plan.lost = Some(listed);
        }
        if allowed {
            if fallback_funds.spend(plan_key_bytes(key)) {
                fallback.insert(key.to_owned());
            } else {
                funded = false;
            }
        }
    }
    if funded {
        for key in &fallback {
            if let Some(entry) = plan.entries.get_mut(key) {
                entry.eligible = true;
            }
        }
        plan.fallback = Some(fallback);
        plan.fallback_funds = fallback_funds;
    }
    funded
}

/// Install `plan` for `scope`, returning the plan it replaced (to be dropped
/// by the caller, after unlocking); None when the lock is poisoned. Plans of
/// other scopes past their TTL are closed, never removed: a scope that has
/// had a page keeps failing closed.
fn swap_plan(scope: &Path, plan: Plan) -> Option<Option<Plan>> {
    let mut expired = Vec::new();
    let replaced = {
        let mut plans = PLANS.lock().ok()?;
        for (other, old) in plans.iter_mut() {
            if other != scope
                && old.created.elapsed() >= CAPTURE_TTL
                && old.entry_funds.held + old.fallback_funds.held > 0
            {
                let created = old.created;
                expired.push(std::mem::replace(
                    old,
                    Plan {
                        created,
                        ..Plan::closed()
                    },
                ));
            }
        }
        plans.insert(scope.to_path_buf(), plan)
    };
    drop(expired);
    Some(replaced)
}

/// A page of the scope has started: from now on the scope is never treated
/// as before its first page, even when this page refuses before it plans.
/// A plan already installed stays.
pub(super) fn mark_paged(scope: &Path) {
    if let Ok(mut plans) = PLANS.lock() {
        plans
            .entry(scope.to_path_buf())
            .or_insert_with(Plan::closed);
    }
}

/// Selection and finalizers share this scheduling state, including turns
/// consumed while publication is delayed or the JSONL day is sealed. These
/// hints confer no coverage, publication acknowledgement or removal basis.
pub(super) fn scheduling_turn(scope: &Path, key: &str, published: u64) -> u64 {
    PLANS
        .lock()
        .ok()
        .and_then(|plans| {
            plans
                .get(scope)
                .and_then(|plan| plan.live(key))
                .map(|entry| entry.turn)
        })
        .unwrap_or(0)
        .max(published)
}

/// The shadow is off (or a test ends): the scope starts over, as before its
/// first page.
pub(super) fn forget_plan(scope: &Path) {
    let removed = PLANS.lock().ok().and_then(|mut plans| plans.remove(scope));
    drop(removed);
}

/// Whether the parse of `path` may capture optionally: always before the
/// scope's first page; after it only what its live plan allows (a paged
/// scope without a plan, or with an expired one, allows nothing).
fn capture_eligible(scope: &Path, path: &Path) -> bool {
    PLANS.lock().is_ok_and(|plans| {
        let Some(plan) = plans.get(scope) else {
            return true;
        };
        super::super::claude_index_path_member_ref(path)
            .is_some_and(|member| plan.allows(&super::family_key(member.root)))
    })
}

#[cfg(test)]
thread_local! {
    static PLAN_DEADLINE_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Make this thread's next plans run out of their close budget at once.
#[cfg(test)]
pub(crate) fn set_plan_deadline_for_test(expired: bool) {
    PLAN_DEADLINE_FOR_TEST.with(|current| current.set(expired));
}

pub(crate) fn begin_page(scope: &Path) {
    if uses_process_latch() {
        PAGE_EXHAUSTED.store(false, Ordering::Release);
    }
    if let Ok(mut work) = WORK.lock() {
        work.insert(scope.to_path_buf(), Work::default());
    }
}

#[cfg(test)]
fn start_clock(scope: &Path, first: Instant) {
    if let Ok(mut pages) = WORK.lock() {
        start_page_clock(pages.entry(scope.to_path_buf()).or_default(), first);
    }
}

/// The page's money clock starts with its first money finalizer, never at
/// native page start. It counts money sections only (`MoneyTimer`): native
/// time between or after finalizers is never charged (MONEY decision,
/// superseding the one absolute wall deadline).
fn start_page_clock(work: &mut Work, first: Instant) {
    if work.first.is_none() {
        *work = Work {
            first: Some(first),
            ..Default::default()
        };
    }
}

/// One money section. Its time is added when it ends; while it runs, the
/// outermost section's start lets admission checks charge it already.
struct MoneyTimer {
    scope: PathBuf,
    started: Instant,
    owns_section: bool,
}
impl MoneyTimer {
    fn new(scope: &Path, started: Instant) -> Self {
        #[cfg(test)]
        TIMER_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
        let owns_section = WORK.lock().is_ok_and(|mut pages| {
            let work = pages.entry(scope.to_path_buf()).or_default();
            start_page_clock(work, started);
            if work.section.is_some() {
                return false;
            }
            work.section = Some(started);
            true
        });
        Self {
            scope: scope.to_path_buf(),
            started,
            owns_section,
        }
    }
}
impl Drop for MoneyTimer {
    fn drop(&mut self) {
        if let Ok(mut pages) = WORK.lock() {
            let work = pages.entry(self.scope.clone()).or_default();
            work.micros = work
                .micros
                .saturating_add(self.started.elapsed().as_micros() as u64);
            if self.owns_section {
                work.section = None;
            }
        }
    }
}

/// Charge money work that ran outside a capture section since `started`
/// (an off page's kill-switch check, purge and false-row handoff) to the
/// scope's money clock.
pub(super) fn charge_since(scope: &Path, started: Instant) {
    drop(MoneyTimer::new(scope, started));
}

pub(super) struct PageClock {
    /// `shadow_started` plus what is left of the page's money budget after
    /// capture: the shadow and closing are one contiguous wall interval.
    pub(super) deadline: Instant,
    /// Accumulated capture (money) time, charged against the budget.
    pub(super) capture_us: u64,
    /// Native wall time from the first money finalizer to shadow entry,
    /// minus capture time. Receipt only: never charged.
    pub(super) native_us: u64,
}

/// The page's money budget is money-added time only: accumulated capture
/// time plus the shadow measured from its entry, at most
/// `PAGE_MAX_ELAPSED` in total. Taking it ends the page's capture clock, so
/// a page never gets a refreshed budget; a page without captures starts its
/// money clock at shadow entry.
pub(super) fn take_page_clock(scope: &Path, shadow_started: Instant) -> PageClock {
    let (capture_us, native_us) = WORK.lock().map_or((0, 0), |mut pages| {
        let work = pages.entry(scope.to_path_buf()).or_default();
        match work.first.take() {
            Some(first) => {
                let wall = shadow_started.saturating_duration_since(first).as_micros() as u64;
                (work.micros, wall.saturating_sub(work.micros))
            }
            None => (0, 0),
        }
    });
    PageClock {
        deadline: shadow_started
            + super::PAGE_MAX_ELAPSED.saturating_sub(Duration::from_micros(capture_us)),
        capture_us,
        native_us,
    }
}

fn spend_work(scope: &Path, bytes: usize, comparisons: usize) -> bool {
    WORK.lock().is_ok_and(|mut pages| {
        let work = pages.entry(scope.to_path_buf()).or_default();
        let input = work.input.saturating_add(bytes);
        let comparisons = work.comparisons.saturating_add(comparisons);
        let running = work
            .section
            .map_or(0, |section| section.elapsed().as_micros() as u64);
        if work.exhausted
            || input > PAGE_INPUT_BYTES
            || comparisons > PAGE_COMPARISONS
            || work.micros.saturating_add(running) >= PAGE_CAPTURE_US
        {
            work.exhausted = true;
            if uses_process_latch() {
                PAGE_EXHAUSTED.store(true, Ordering::Release);
            }
            return false;
        }
        work.input = input;
        work.comparisons = comparisons;
        true
    })
}

/// Bytes held against the capture ceiling, released on drop.
#[derive(Debug, Default)]
struct Funds {
    held: usize,
    used: usize,
}

impl Funds {
    /// Admit `bytes` more before allocating them.
    fn spend(&mut self, bytes: usize) -> bool {
        let Some(used) = self.used.checked_add(bytes) else {
            return false;
        };
        if used > self.held {
            let grant = (used - self.held).max(FUNDS_CHUNK_BYTES);
            let admitted = CAPTURE_RESERVED
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                    reserved
                        .checked_add(grant)
                        .filter(|total| *total <= CAPTURE_CEILING_BYTES)
                })
                .is_ok();
            if !admitted {
                return false;
            }
            self.held += grant;
        }
        self.used = used;
        true
    }
}

impl Funds {
    /// `bytes` admitted earlier are no longer used: whole chunks no longer
    /// needed go back to the ceiling.
    fn refund(&mut self, bytes: usize) {
        self.used = self.used.saturating_sub(bytes);
        let surplus = (self.held - self.used) / FUNDS_CHUNK_BYTES * FUNDS_CHUNK_BYTES;
        if surplus > 0 {
            CAPTURE_RESERVED.fetch_sub(surplus, Ordering::AcqRel);
            self.held -= surplus;
        }
    }
}

/// Holds the whole capture ceiling until dropped (no capture or plan funds).
#[cfg(test)]
pub(crate) struct CeilingHoldForTest(#[allow(dead_code)] Funds);

#[cfg(test)]
pub(crate) fn hold_capture_ceiling_for_test() -> CeilingHoldForTest {
    let mut funds = Funds::default();
    assert!(funds.spend(CAPTURE_CEILING_BYTES - capture_reserved()));
    CeilingHoldForTest(funds)
}

impl Drop for Funds {
    fn drop(&mut self) {
        CAPTURE_RESERVED.fetch_sub(self.held, Ordering::AcqRel);
    }
}

/// One live bucket row: hour start, model and pricing selectors (the
/// reduced selector context plus the row's billing fields).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CapturedRow {
    pub(crate) bucket_start: String,
    pub(crate) model: String,
    pub(crate) selector: BTreeMap<String, String>,
}

/// How a response the occurrence map does not keep is keyed
/// (`claude_request_counting:v1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapturedKind {
    /// `M`: no request id; the hash of its `message.id`.
    Message(u64),
    /// `L`: neither id.
    Idless,
    /// `R` displaced by a later response under the same request id in this
    /// file (the occurrence map keeps the last); the request hash.
    Displaced(u64),
}

/// One response the occurrence map does not keep.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CapturedUnit {
    pub(crate) kind: CapturedKind,
    pub(crate) sequence: u64,
    pub(crate) tokens: ClaudeMoneyTokens,
    pub(crate) requests: u64,
    pub(crate) clock: Option<u64>,
    /// `claude_model_hash` of its model, for the response fingerprint.
    pub(crate) model: Option<u64>,
}

#[derive(Debug, Default)]
pub(crate) struct ClaudeResponseCapture {
    funds: Funds,
    refused: bool,
    /// The shadow scope that armed it (its store partition).
    scope: PathBuf,
    /// (sequence, message-id hash) of every response keyed by a message id,
    /// sorted by sequence.
    messages: Vec<(u64, u64)>,
    /// (sequence, row) of every response the live path added to a bucket,
    /// in finalize order (ascending sequence).
    placements: Vec<(u64, u32)>,
    rows: Vec<CapturedRow>,
    units: Vec<CapturedUnit>,
}

/// Grow `vec` by one slot, admitting a doubled capacity first.
fn reserve_one<T>(funds: &mut Funds, vec: &mut Vec<T>) -> bool {
    if vec.len() < vec.capacity() {
        return true;
    }
    let next = vec.capacity().max(4).saturating_mul(2);
    if !funds.spend(next.saturating_mul(std::mem::size_of::<T>())) {
        return false;
    }
    vec.reserve_exact(next - vec.len());
    true
}

impl ClaudeResponseCapture {
    /// A capture for the Claude file at `path`, or None when the shadow is
    /// not armed for it.
    pub(crate) fn begin(path: &Path) -> Option<Self> {
        if page_exhausted_for_file(path) {
            return None;
        }
        let started = Instant::now();
        let mut scope = None;
        super::guarded(|| scope = super::capture_armed(path));
        let scope = scope?;
        let _timer = MoneyTimer::new(&scope, started);
        if !spend_work(&scope, 0, 0) {
            return None;
        }
        let eligible = capture_eligible(&scope, path);
        eligible.then(|| Self {
            scope: scope.clone(),
            ..Self::default()
        })
    }

    /// Every entry point the live finalizer calls runs here (StateMissing
    /// r3): a panic in the capture ends in the shadow. It sets the panic
    /// latch (the shadow is off for the process), the capture is refused
    /// and never deposited, and the live parse goes on unchanged.
    fn contained(&mut self, run: impl FnOnce(&mut Self)) {
        if self.refused {
            return;
        }
        if page_exhausted(&self.scope) {
            self.refuse();
            return;
        }
        let _timer = MoneyTimer::new(&self.scope, Instant::now());
        if !spend_work(&self.scope, 0, 1) {
            self.refuse();
            return;
        }
        let mut finished = false;
        super::guarded(|| {
            #[cfg(test)]
            if PANIC_FOR_TEST.with(std::cell::Cell::get) {
                panic!("synthetic capture panic");
            }
            run(self);
            finished = true;
        });
        if !finished {
            self.refuse();
        }
    }

    pub(crate) fn is_refused(&self) -> bool {
        self.refused
    }

    fn refuse(&mut self) {
        self.refused = true;
        self.messages = Vec::new();
        self.placements = Vec::new();
        self.rows = Vec::new();
        self.units = Vec::new();
    }

    /// Record the message-id hash of every message-keyed response.
    pub(crate) fn note_messages<'k>(&mut self, keys: impl Iterator<Item = (u64, &'k str)> + Clone) {
        self.contained(|capture| capture.record_messages(keys));
    }

    /// One pass checks the ids (their count, each length, total bytes) before the
    /// count is funded and any id is hashed; then the hashes are sorted by
    /// sequence only if they came out of order.
    fn record_messages<'k>(&mut self, keys: impl Iterator<Item = (u64, &'k str)> + Clone) {
        if self.refused {
            return;
        }
        let mut count = 0_usize;
        let mut bytes = 0_usize;
        for (_, message_id) in keys.clone() {
            count += 1;
            bytes = bytes.saturating_add(message_id.len());
            if !spend_work(&self.scope, message_id.len(), 1)
                || count > MAX_MESSAGE_IDS
                || message_id.len() > MAX_MESSAGE_ID_BYTES
                || bytes > MAX_MESSAGE_HASH_INPUT_BYTES
            {
                self.refuse();
                return;
            }
        }
        if !self
            .funds
            .spend(count.saturating_mul(std::mem::size_of::<(u64, u64)>()))
        {
            self.refuse();
            return;
        }
        // Prepay comparisons for ordering detection, binary lookups, and
        // worst-case sort work before hashing or sorting.
        if !spend_work(
            &self.scope,
            0,
            count.saturating_mul(2 + count.max(1).ilog2() as usize),
        ) {
            self.refuse();
            return;
        }
        self.messages.reserve_exact(count);
        for (sequence, message_id) in keys.take(count) {
            self.messages
                .push((sequence, super::claude_message_hash(message_id)));
        }
        if self.messages.windows(2).any(|pair| pair[0] > pair[1]) {
            self.messages.sort_unstable();
        }
    }

    pub(crate) fn message(&self, sequence: u64) -> Option<u64> {
        self.messages
            .binary_search_by_key(&sequence, |(at, _)| *at)
            .ok()
            .map(|position| self.messages[position].1)
    }

    /// The live bucket row a response's usage was added to: its hour start,
    /// model, reduced selector context and the row's billing fields (keys
    /// disjoint from the context's). Interned per file; admitted first.
    pub(crate) fn place(
        &mut self,
        sequence: u64,
        bucket_start: &str,
        model: &str,
        context: &BTreeMap<String, String>,
        billing: &[(&'static str, Option<&str>)],
    ) {
        self.contained(|capture| {
            capture.record_place(sequence, bucket_start, model, context, billing)
        });
    }

    fn record_place(
        &mut self,
        sequence: u64,
        bucket_start: &str,
        model: &str,
        context: &BTreeMap<String, String>,
        billing: &[(&'static str, Option<&str>)],
    ) {
        if self.refused {
            return;
        }
        // Bound each input and precharge every possible selector comparison
        // before looking at interned rows (resident admission is separate).
        let mut input = bucket_start.len().saturating_add(model.len());
        for (key, value) in context {
            input = input.saturating_add(key.len()).saturating_add(value.len());
            if !spend_work(&self.scope, key.len().saturating_add(value.len()), 1) {
                self.refuse();
                return;
            }
        }
        for (key, value) in billing {
            input = input.saturating_add(key.len() + value.map_or(0, str::len));
        }
        let comparisons = input
            .saturating_mul(self.rows.len().max(1))
            .saturating_mul(1 + context.len().max(1).ilog2() as usize);
        if input > 16 * 1024 || !spend_work(&self.scope, input, comparisons) {
            self.refuse();
            return;
        }
        let present = || {
            billing
                .iter()
                .filter_map(|(key, value)| Some((*key, (*value)?)))
        };
        let same = |row: &CapturedRow| {
            row.bucket_start == bucket_start
                && row.model == model
                && row.selector.len() == context.len() + present().count()
                && context
                    .iter()
                    .all(|(key, value)| row.selector.get(key) == Some(value))
                && present()
                    .all(|(key, value)| row.selector.get(key).map(String::as_str) == Some(value))
        };
        let row = match self.rows.iter().position(same) {
            Some(position) => position,
            None => {
                let bytes = std::mem::size_of::<CapturedRow>()
                    + bucket_start.len()
                    + model.len()
                    + context
                        .iter()
                        .map(|(key, value)| key.len() + value.len() + MAP_ENTRY_BYTES)
                        .sum::<usize>()
                    + present()
                        .map(|(key, value)| key.len() + value.len() + MAP_ENTRY_BYTES)
                        .sum::<usize>();
                if self.rows.len() >= MAX_ROWS_PER_FILE
                    || !self.funds.spend(bytes)
                    || !reserve_one(&mut self.funds, &mut self.rows)
                {
                    self.refuse();
                    return;
                }
                let mut selector = context.clone();
                selector.extend(present().map(|(key, value)| (key.to_owned(), value.to_owned())));
                self.rows.push(CapturedRow {
                    bucket_start: bucket_start.to_owned(),
                    model: model.to_owned(),
                    selector,
                });
                self.rows.len() - 1
            }
        };
        if !reserve_one(&mut self.funds, &mut self.placements) {
            self.refuse();
            return;
        }
        self.placements.push((sequence, row as u32));
    }

    pub(crate) fn placement(&self, sequence: u64) -> Option<&CapturedRow> {
        let position = self
            .placements
            .binary_search_by_key(&sequence, |(at, _)| *at)
            .ok()?;
        self.rows.get(self.placements[position].1 as usize)
    }

    fn push_unit(&mut self, unit: CapturedUnit) {
        if self.refused {
            return;
        }
        if !reserve_one(&mut self.funds, &mut self.units) {
            self.refuse();
            return;
        }
        self.units.push(unit);
    }

    /// The request hash a displaced response needs. Only an armed capture
    /// hashes the id (the native parse keeps it unhashed), so this is money
    /// work: timed and admitted against the page's capture input first.
    pub(crate) fn request_hash(&mut self, request_id: &str) -> Option<u64> {
        if self.refused {
            return None;
        }
        if page_exhausted(&self.scope) {
            self.refuse();
            return None;
        }
        let _timer = MoneyTimer::new(&self.scope, Instant::now());
        if !spend_work(&self.scope, request_id.len(), 0) {
            self.refuse();
            return None;
        }
        let mut hash = None;
        super::guarded(|| {
            hash = Some(super::super::claude_request_census::claude_request_hash(
                request_id,
            ))
        });
        if hash.is_none() {
            self.refuse();
        }
        hash
    }

    /// A response the occurrence map replaced under the same request id.
    pub(crate) fn displaced(&mut self, request_hash: u64, prior: &ClaudeTranscriptUsageOccurrence) {
        self.contained(|capture| capture.record_displaced(request_hash, prior));
    }

    fn record_displaced(&mut self, request_hash: u64, prior: &ClaudeTranscriptUsageOccurrence) {
        if !self.charge_unit_input(prior.timestamp.as_deref(), prior.model.as_deref()) {
            return;
        }
        self.push_unit(CapturedUnit {
            kind: CapturedKind::Displaced(request_hash),
            sequence: prior.sequence,
            tokens: ClaudeMoneyTokens::from_usage(&prior.usage),
            requests: prior.usage.request_count,
            clock: prior.timestamp.as_deref().and_then(rfc3339_unix_seconds),
            model: prior.model.as_deref().map(super::claude_model_hash),
        });
    }

    /// A response with no request id: message-only when its key had a
    /// message id, else idless.
    pub(in crate::snapshots) fn unkeyed(
        &mut self,
        sequence: u64,
        usage: &UsageTotals,
        timestamp: Option<&str>,
        model: Option<&str>,
    ) {
        self.contained(|capture| capture.record_unkeyed(sequence, usage, timestamp, model));
    }

    fn record_unkeyed(
        &mut self,
        sequence: u64,
        usage: &UsageTotals,
        timestamp: Option<&str>,
        model: Option<&str>,
    ) {
        if !self.charge_unit_input(timestamp, model) {
            return;
        }
        let kind = match self.message(sequence) {
            Some(hash) => CapturedKind::Message(hash),
            None => CapturedKind::Idless,
        };
        self.push_unit(CapturedUnit {
            kind,
            sequence,
            tokens: ClaudeMoneyTokens::from_usage(usage),
            requests: usage.request_count,
            clock: timestamp.and_then(rfc3339_unix_seconds),
            model: model.map(super::claude_model_hash),
        });
    }

    pub(crate) fn units(&self) -> &[CapturedUnit] {
        &self.units
    }

    fn charge_unit_input(&mut self, timestamp: Option<&str>, model: Option<&str>) -> bool {
        let bytes = timestamp
            .map_or(0, str::len)
            .saturating_add(model.map_or(0, str::len));
        if bytes > 16 * 1024 || !spend_work(&self.scope, bytes, 1) {
            self.refuse();
            return false;
        }
        true
    }

    /// Sorted unique message-only hashes (the ledger's `mh:` record).
    pub(crate) fn message_only_hashes(&self) -> Vec<u64> {
        let mut hashes = self
            .units
            .iter()
            .filter_map(|unit| match unit.kind {
                CapturedKind::Message(hash) => Some(hash),
                _ => None,
            })
            .collect::<Vec<_>>();
        hashes.sort_unstable();
        hashes.dedup();
        hashes.shrink_to_fit();
        hashes
    }

    /// Hand the finished capture to the store under the parse's index key
    /// and fingerprint (replacing any earlier one). After the panic latch
    /// the capture is dropped instead (its funds are refunded).
    /// The store key and fingerprint are built here, inside the money timer:
    /// they are money-only work.
    pub(crate) fn deposit(self, path: &Path, fingerprint: &str) {
        if self.refused || page_exhausted(&self.scope) {
            return;
        }
        let _timer = MoneyTimer::new(&self.scope, Instant::now());
        if super::SHADOW_PANICKED.load(Ordering::Acquire) || !spend_work(&self.scope, 0, 0) {
            return;
        }
        super::guarded(move || {
            self.keep(super::super::local_index_key(path), fingerprint.to_owned())
        });
    }

    fn keep(mut self, index_key: String, fingerprint: String) {
        if self.refused {
            return;
        }
        if !self.refused
            && !self.funds.spend(
                index_key.len()
                    + fingerprint.len()
                    + MAP_ENTRY_BYTES
                    + std::mem::size_of::<Entry>(),
            )
        {
            self.refuse();
        }
        if self.refused {
            return;
        }
        let Ok(mut store) = STORE.lock() else {
            return;
        };
        let now = Instant::now();
        store.retain(|_, entry| now.duration_since(entry.deposited) < CAPTURE_TTL);
        store.insert(
            (self.scope.clone(), index_key),
            Entry {
                fingerprint,
                deposited: now,
                capture: self,
            },
        );
    }
}

struct Entry {
    fingerprint: String,
    deposited: Instant,
    capture: ClaudeResponseCapture,
}

/// Waiting captures by (scope, index key).
static STORE: Mutex<BTreeMap<(PathBuf, String), Entry>> = Mutex::new(BTreeMap::new());

/// The index keys `scope` holds captures for: on a Full parse, the files of
/// the planned families. Bounded by the capture funds.
pub(crate) fn captured_index_keys(scope: &Path) -> Vec<String> {
    let Ok(store) = STORE.lock() else {
        return Vec::new();
    };
    store
        .keys()
        .filter(|(entry_scope, _)| entry_scope == scope)
        .map(|(_, key)| key.clone())
        .collect()
}

/// The capture of the parse at `index_key` with `fingerprint`, removed from
/// the store. None when it was never captured, expired or is of another
/// revision (then it stays for its own revision's page); a refused capture
/// is returned refused.
pub(crate) fn take_capture(
    scope: &Path,
    index_key: &str,
    fingerprint: &str,
) -> Option<ClaudeResponseCapture> {
    let mut store = STORE.lock().ok()?;
    let key = (scope.to_path_buf(), index_key.to_owned());
    if store.get(&key)?.fingerprint != fingerprint {
        return None;
    }
    store.remove(&key).map(|entry| entry.capture)
}

/// Drop the scope's captures deposited before `before` (the scope's
/// previous shadow ran after them and did not take them). Returns how many.
pub(crate) fn purge_before(scope: &Path, before: Instant) -> u64 {
    let Ok(mut store) = STORE.lock() else {
        return 0;
    };
    let len = store.len();
    store.retain(|(entry_scope, _), entry| entry_scope != scope || entry.deposited >= before);
    (len - store.len()) as u64
}

#[cfg(test)]
thread_local! {
    static PANIC_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Make every capture entry point on this thread panic (a capture bug).
#[cfg(test)]
pub(crate) fn set_panic_for_test(panic: bool) {
    PANIC_FOR_TEST.with(|current| current.set(panic));
}

#[cfg(test)]
pub(crate) fn purge_scope_for_test(scope: &Path) {
    if let Ok(mut store) = STORE.lock() {
        store.retain(|(entry_scope, _), _| entry_scope != scope);
    }
}

#[cfg(test)]
pub(crate) fn retain_for_test(scope: &Path, keep: impl Fn(&str) -> bool) {
    if let Ok(mut store) = STORE.lock() {
        store.retain(|(entry_scope, key), _| entry_scope != scope || keep(key));
    }
}

/// Current, fingerprint-bound store entries, without consuming any capture.
#[cfg(test)]
pub(crate) fn keys_for_test(scope: &Path) -> Vec<(String, String)> {
    STORE
        .lock()
        .unwrap()
        .iter()
        .filter(|((entry_scope, _), _)| entry_scope == scope)
        .map(|((_, key), entry)| (key.clone(), entry.fingerprint.clone()))
        .collect()
}

pub(crate) fn capture_reserved() -> usize {
    CAPTURE_RESERVED.load(Ordering::Acquire)
}

/// The families the scope's plan makes eligible by name: the fallback's,
/// or every live entry a complete plan selected (any page's).
#[cfg(test)]
pub(crate) fn planned_families_for_test(
    scope: &Path,
) -> Option<std::collections::BTreeSet<String>> {
    PLANS
        .lock()
        .unwrap()
        .get(scope)
        .map(|plan| match &plan.fallback {
            Some(fallback) => fallback.clone(),
            None => plan
                .entries
                .keys()
                .filter(|key| plan.live(key).is_some_and(|entry| entry.eligible))
                .cloned()
                .collect(),
        })
}

/// Whether the scope is armed and its plan allows `path` on the next native
/// page, independent of the current page's spent capture work.
#[cfg(test)]
pub(crate) fn capture_eligible_for_test(path: &Path) -> bool {
    super::capture_armed(path).is_some_and(|scope| capture_eligible(&scope, path))
}

/// None before the scope's first page (never paged); after it, whether its
/// live plan allows any optional capture at all (false: paged without a
/// plan, closed, or expired).
#[cfg(test)]
pub(crate) fn plan_allows_capture_for_test(scope: &Path) -> Option<bool> {
    PLANS.lock().unwrap().get(scope).map(|plan| {
        plan.created.elapsed() < CAPTURE_TTL
            && match &plan.fallback {
                Some(fallback) => !fallback.is_empty(),
                None => {
                    !matches!(plan.lost, Some(lost) if lost.elapsed() < CAPTURE_TTL)
                        || plan
                            .entries
                            .values()
                            .any(|entry| entry.eligible && entry.listed.elapsed() < CAPTURE_TTL)
                }
            }
    })
}

/// Capture funds the scope's plan holds.
#[cfg(test)]
pub(crate) fn plan_funds_for_test(scope: &Path) -> usize {
    PLANS
        .lock()
        .unwrap()
        .get(scope)
        .map_or(0, |plan| plan.entry_funds.held + plan.fallback_funds.held)
}

/// The family's live scheduling turn in the scope's plan.
#[cfg(test)]
pub(crate) fn plan_turn_for_test(scope: &Path, key: &str) -> Option<u64> {
    PLANS
        .lock()
        .unwrap()
        .get(scope)
        .and_then(|plan| plan.live(key))
        .map(|entry| entry.turn)
}

/// Accepted cumulative work, including work whose resident capture was dropped.
#[cfg(test)]
pub(crate) fn work_for_test(scope: &Path) -> (usize, usize, u64) {
    let pages = WORK.lock().unwrap();
    let work = pages.get(scope).expect("page capture budget installed");
    (work.input, work.comparisons, work.micros)
}

#[cfg(test)]
thread_local! {
    static TIMER_CONSTRUCTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PROCESS_LATCH_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod bounded_tests {
    use super::*;

    fn charge_money_for_test(scope: &Path, micros: u64) {
        let mut pages = WORK.lock().unwrap();
        let work = pages.get_mut(scope).expect("page clock started");
        work.micros = work.micros.saturating_add(micros);
    }

    /// MONEY decision (supersedes the one absolute wall deadline): native
    /// gaps between or after finalizers are never charged; capture stops at
    /// 100 ms of accumulated capture time; the shadow gets only what capture
    /// left of 250 ms; and a page never gets a refreshed budget.
    #[test]
    fn native_gaps_are_never_charged_to_the_money_budget() {
        let budget = super::super::PAGE_MAX_ELAPSED;
        let scope = PathBuf::from("money-clock-native-gap");
        begin_page(&scope);
        let first = Instant::now() - Duration::from_millis(110);
        start_clock(&scope, first);
        assert!(
            spend_work(&scope, 1, 1),
            "a 110 ms native gap is not capture time"
        );
        charge_money_for_test(&scope, PAGE_CAPTURE_US - 1);
        assert!(spend_work(&scope, 1, 1), "below 100 ms of capture time");
        charge_money_for_test(&scope, 1);
        assert!(
            !spend_work(&scope, 1, 1),
            "capture refuses at 100 ms of accumulated capture time"
        );
        start_clock(&scope, Instant::now());
        assert_eq!(
            work_for_test(&scope).2,
            PAGE_CAPTURE_US,
            "a later finalizer never refreshes the page's money clock"
        );
        assert!(
            !spend_work(&scope, 1, 1),
            "refusal stays latched for the page"
        );
        let shadow_started = Instant::now();
        let clock = take_page_clock(&scope, shadow_started);
        assert_eq!(clock.capture_us, PAGE_CAPTURE_US);
        assert_eq!(
            clock.deadline,
            shadow_started + budget - Duration::from_micros(PAGE_CAPTURE_US),
            "the shadow gets only what capture left: capture plus shadow is 250 ms"
        );
        assert!(
            clock.native_us >= 10_000,
            "native receipt: {}",
            clock.native_us
        );
        let following = Instant::now();
        assert_eq!(
            take_page_clock(&scope, following).deadline,
            following + budget,
            "a following Skip with no capture has its own money clock from shadow entry"
        );

        begin_page(&scope);
        let first = Instant::now() - Duration::from_millis(260);
        start_clock(&scope, first);
        charge_money_for_test(&scope, 20);
        let shadow_started = Instant::now();
        let clock = take_page_clock(&scope, shadow_started);
        assert_eq!(clock.capture_us, 20);
        assert_eq!(
            clock.deadline,
            shadow_started + budget - Duration::from_micros(20),
            "a 260 ms native gap leaves the money budget intact"
        );
        assert!(clock.deadline > shadow_started);
        assert!(
            clock.native_us >= 259_000,
            "native receipt: {}",
            clock.native_us
        );

        begin_page(&scope);
        start_clock(&scope, Instant::now());
        charge_money_for_test(&scope, budget.as_micros() as u64 + 1);
        let shadow_started = Instant::now();
        assert!(
            take_page_clock(&scope, shadow_started).deadline <= shadow_started,
            "capture time alone exhausting 250 ms keeps the pre-admission refusal"
        );
        println!("MONEY_P1B_CLOCK native_gap_ms=110,260 native_charged_us=0 capture_refused_at_us={PAGE_CAPTURE_US} shadow_budget_after_capture_us={} total_money_us<=250000 deadline_refreshed=0 capture_exhausted_refusal=1", (budget - Duration::from_micros(PAGE_CAPTURE_US)).as_micros());
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn planned_capture_rotates_known_roots_without_gating_a_different_native_page() {
        let scratch = crate::test_scratch::ScratchDir::new("money-capture-turns");
        let support = scratch.join("support");
        let _shadow_cleanup = super::super::ShadowTestCleanup::new(&support);
        super::super::enable_shadow_for_test(&support);
        let keys = (0..NEXT_PAGE_FAMILIES + 1)
            .map(|at| super::super::family_key(&format!("root-{at}")))
            .collect::<Vec<_>>();
        assert_eq!(
            plan_next_page(
                &support,
                keys.iter()
                    .enumerate()
                    .map(|(at, key)| (key.as_str(), at as u64)),
                std::iter::empty(),
                Instant::now() + Duration::from_secs(1),
            ),
            PlanInstall::Complete
        );
        assert!(ClaudeResponseCapture::begin(&scratch.join("root-0.jsonl")).is_some());
        assert!(
            ClaudeResponseCapture::begin(&scratch.join("root-0/subagents/agent-one.jsonl"))
                .is_some()
        );
        assert!(ClaudeResponseCapture::begin(
            &scratch.join(format!("root-{NEXT_PAGE_FAMILIES}.jsonl"))
        )
        .is_none());
        assert!(
            ClaudeResponseCapture::begin(&scratch.join("different-native-page.jsonl")).is_some()
        );
        // Rotate eligibility to the formerly skipped root, without parsing
        // files or changing a native candidate's ordering or identity.
        assert_eq!(
            plan_next_page(
                &support,
                keys.iter()
                    .rev()
                    .enumerate()
                    .map(|(at, key)| (key.as_str(), at as u64)),
                std::iter::empty(),
                Instant::now() + Duration::from_secs(1),
            ),
            PlanInstall::Complete
        );
        assert!(ClaudeResponseCapture::begin(
            &scratch.join(format!("root-{NEXT_PAGE_FAMILIES}.jsonl"))
        )
        .is_some());
        super::super::disable_shadow_for_test(&support);
    }

    fn eligible_families(support: &Path) -> std::collections::BTreeSet<String> {
        planned_families_for_test(support).expect("a page installs a plan")
    }

    /// MONEY decision (fail closed, never stale; supersedes "keep the old
    /// plan until a complete replacement installs"): a page whose complete
    /// plan cannot be built makes only the oldest-64 fallback eligible,
    /// never a partial selection and never the old plan's eligible
    /// families. The update reuses the old plan's funds and keeps earlier
    /// pages' unacknowledged turns.
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn capture_plan_stops_at_expiry_and_installs_only_the_fallback() {
        let scratch = crate::test_scratch::ScratchDir::new("money-capture-plan-deadline");
        let support = scratch.join("support");
        let _shadow_cleanup = super::super::ShadowTestCleanup::new(&support);
        let before = capture_reserved();
        let keys = (0..4096)
            .map(|at| super::super::family_key(&format!("root-{at}")))
            .collect::<Vec<_>>();
        let started = Instant::now();
        let visited = std::cell::Cell::new(0_usize);
        assert_eq!(
            plan_next_page(
                &support,
                keys.iter().map(|key| {
                    visited.set(visited.get() + 1);
                    (key.as_str(), 0)
                }),
                std::iter::empty(),
                started
            ),
            PlanInstall::Fallback(PlanFailure::Deadline)
        );
        // Iteration can fetch the next element before its deadline check,
        // but no walk/sort of the remaining 4095 entries is allowed.
        assert!(visited.get() <= 1);
        assert!(started.elapsed() <= super::super::PAGE_MAX_ELAPSED + Duration::from_millis(25));
        assert_eq!(
            plan_allows_capture_for_test(&support),
            Some(false),
            "an empty fallback allows nothing: never a partial plan"
        );
        assert_eq!(capture_reserved(), before);
        let fallback = |turn: u64| {
            keys[100..100 + NEXT_PAGE_FAMILIES]
                .iter()
                .map(move |key| (key.as_str(), turn, true))
                .chain(std::iter::once((keys[0].as_str(), turn + 1, false)))
        };
        let checks = std::cell::Cell::new(0);
        assert_eq!(
            plan_next_page_while(
                &support,
                keys.iter().map(|key| (key.as_str(), 0)),
                fallback(0),
                || {
                    checks.set(checks.get() + 1);
                    checks.get() <= 7
                }
            ),
            PlanInstall::Fallback(PlanFailure::Deadline)
        );
        assert_eq!(
            capture_reserved(),
            before + plan_funds_for_test(&support),
            "an interrupted plan holds only its installed funds: no admission leaks"
        );
        assert_eq!(
            eligible_families(&support),
            keys[100..100 + NEXT_PAGE_FAMILIES]
                .iter()
                .cloned()
                .collect()
        );
        assert_eq!(
            plan_next_page(
                &support,
                keys.iter()
                    .enumerate()
                    .map(|(at, key)| (key.as_str(), at as u64)),
                std::iter::empty(),
                Instant::now() + Duration::from_secs(1)
            ),
            PlanInstall::Complete
        );
        let complete = eligible_families(&support);
        assert_eq!(complete.len(), NEXT_PAGE_FAMILIES);
        assert!(keys[..NEXT_PAGE_FAMILIES]
            .iter()
            .all(|key| complete.contains(key)));
        let funded = capture_reserved();
        let checks = std::cell::Cell::new(0);
        assert_eq!(
            plan_next_page_while(
                &support,
                keys.iter().map(|key| (key.as_str(), 9000)),
                fallback(9000),
                || {
                    checks.set(checks.get() + 1);
                    checks.get() <= 7
                }
            ),
            PlanInstall::Fallback(PlanFailure::Deadline)
        );
        assert_eq!(
            capture_reserved(),
            funded
                + keys[100..100 + NEXT_PAGE_FAMILIES]
                    .iter()
                    .map(|key| plan_key_bytes(key))
                    .sum::<usize>()
                    .div_ceil(FUNDS_CHUNK_BYTES)
                    * FUNDS_CHUNK_BYTES,
            "the update reuses the old plan's funds; the partial walk adds none, only the fallback's 64 are funded"
        );
        assert_eq!(capture_reserved(), before + plan_funds_for_test(&support));
        assert_eq!(
            scheduling_turn(&support, &keys[300], 0),
            300,
            "mid-walk expiry must preserve unacknowledged consumed turns"
        );
        assert_eq!(
            scheduling_turn(&support, &keys[0], 0),
            9001,
            "this page's consumed turn survives in the fallback"
        );
        assert_eq!(scheduling_turn(&support, &keys[100], 0), 9000);
        let fallback_families = eligible_families(&support);
        assert_eq!(
            fallback_families,
            keys[100..100 + NEXT_PAGE_FAMILIES]
                .iter()
                .cloned()
                .collect(),
            "the fallback lists the oldest 64 not consumed this page"
        );
        assert!(
            fallback_families.is_disjoint(&complete),
            "never the stale plan's eligibility"
        );
        // An assertion must unwind after releasing the shared plan mutex.
        let (first_allowed, other_allowed, unlisted_allowed) = {
            let plans = PLANS.lock().unwrap();
            (
                plans[&support].allows(&keys[0]),
                plans[&support].allows(&keys[200]),
                plans[&support].allows(&super::super::family_key("unlisted")),
            )
        };
        assert!(!first_allowed);
        assert!(
            !other_allowed && !unlisted_allowed,
            "interruption never changes the next Full to all-eligible"
        );
        forget_plan(&support);
        assert_eq!(capture_reserved(), before);
        println!("MONEY_P1B_PLAN entries=4096 expired_visited={} interrupted_checks={} eligible={NEXT_PAGE_FAMILIES} fallback_eligible={} plan_funds={funded} stale_plan_installed=0 carried_turn=300", visited.get(), checks.get(), fallback_families.len());
    }

    /// The next parse's captures follow the fallback: a family the page
    /// consumed (built) and a family the fallback does not list capture
    /// nothing, while the fallback's families do.
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn fallback_plan_captures_only_prior_incomplete_families() {
        let scratch = crate::test_scratch::ScratchDir::new("money-capture-fallback");
        let support = scratch.join("support");
        let _shadow_cleanup = super::super::ShadowTestCleanup::new(&support);
        super::super::enable_shadow_for_test(&support);
        let roots = (0..3 * NEXT_PAGE_FAMILIES)
            .map(|at| format!("root-{at}"))
            .collect::<Vec<_>>();
        let keys = roots
            .iter()
            .map(|root| super::super::family_key(root))
            .collect::<Vec<_>>();
        // The previous page planned roots 0..64 (now consumed and built).
        assert_eq!(
            plan_next_page(
                &support,
                keys.iter()
                    .enumerate()
                    .map(|(at, key)| (key.as_str(), at as u64)),
                std::iter::empty(),
                Instant::now() + Duration::from_secs(1),
            ),
            PlanInstall::Complete
        );
        let consumed = 0..NEXT_PAGE_FAMILIES;
        let pending = NEXT_PAGE_FAMILIES..2 * NEXT_PAGE_FAMILIES;
        set_plan_deadline_for_test(true);
        let installed = plan_next_page(
            &support,
            keys.iter().map(|key| (key.as_str(), 0)),
            pending
                .clone()
                .map(|at| (keys[at].as_str(), at as u64, true))
                .chain(consumed.clone().map(|at| (keys[at].as_str(), 9000, false))),
            Instant::now() + Duration::from_secs(1),
        );
        set_plan_deadline_for_test(false);
        assert_eq!(installed, PlanInstall::Fallback(PlanFailure::Deadline));
        let path = |at: usize| scratch.join(format!("{}.jsonl", roots[at]));
        assert!(consumed
            .clone()
            .all(|at| ClaudeResponseCapture::begin(&path(at)).is_none()));
        assert!(pending
            .clone()
            .all(|at| ClaudeResponseCapture::begin(&path(at)).is_some()));
        assert!(ClaudeResponseCapture::begin(&path(2 * NEXT_PAGE_FAMILIES)).is_none());
        assert!(
            ClaudeResponseCapture::begin(&scratch.join("different-native-page.jsonl")).is_none(),
            "a fallback lists everything it allows"
        );
        super::super::disable_shadow_for_test(&support);
    }

    /// A scope that has had a page and has no live plan captures nothing
    /// optional (MONEY decision); only a scope before its first page (or
    /// after the shadow turned off) captures every file. A page's start
    /// marks the scope paged, so a page refused before it plans leaves the
    /// scope closed, and a page of at most 64 families expires like any
    /// other plan.
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn a_paged_scope_without_a_plan_captures_nothing_optional() {
        let scratch = crate::test_scratch::ScratchDir::new("money-capture-closed");
        let support = scratch.join("support");
        let _shadow_cleanup = super::super::ShadowTestCleanup::new(&support);
        super::super::enable_shadow_for_test(&support);
        let file = scratch.join("root-0.jsonl");
        let other = scratch.join("different-native-page.jsonl");
        assert_eq!(plan_allows_capture_for_test(&support), None);
        assert!(ClaudeResponseCapture::begin(&file).is_some(), "first page");
        assert!(ClaudeResponseCapture::begin(&other).is_some(), "first page");
        let keys = (0..2 * NEXT_PAGE_FAMILIES)
            .map(|at| super::super::family_key(&format!("root-{at}")))
            .collect::<Vec<_>>();
        // Neither the complete plan nor its fallback can be funded.
        let mut full = Funds::default();
        assert!(full.spend(CAPTURE_CEILING_BYTES - capture_reserved()));
        assert_eq!(
            plan_next_page(
                &support,
                keys.iter().map(|key| (key.as_str(), 0)),
                keys[..NEXT_PAGE_FAMILIES]
                    .iter()
                    .map(|key| (key.as_str(), 0, true)),
                Instant::now() + Duration::from_secs(1),
            ),
            PlanInstall::Closed(PlanFailure::Funds)
        );
        drop(full);
        assert_eq!(plan_allows_capture_for_test(&support), Some(false));
        assert!(ClaudeResponseCapture::begin(&file).is_none());
        assert!(ClaudeResponseCapture::begin(&other).is_none());
        assert!(!capture_eligible_for_test(&file));
        // A page of at most 64 families makes them all eligible, and another
        // native page's families too.
        assert_eq!(
            plan_next_page(
                &support,
                keys[..NEXT_PAGE_FAMILIES]
                    .iter()
                    .map(|key| (key.as_str(), 0)),
                std::iter::empty(),
                Instant::now() + Duration::from_secs(1),
            ),
            PlanInstall::Complete
        );
        assert!(
            ClaudeResponseCapture::begin(&file).is_some(),
            "a page of at most 64"
        );
        assert!(
            ClaudeResponseCapture::begin(&other).is_some(),
            "a page of at most 64"
        );
        // An expired plan allows nothing, the small page's included.
        // (A fresh runner's monotonic clock may not reach back 15 minutes.)
        let expired = Instant::now().checked_sub(CAPTURE_TTL);
        if let Some(created) = expired {
            PLANS.lock().unwrap().get_mut(&support).unwrap().created = created;
            assert_eq!(plan_allows_capture_for_test(&support), Some(false));
            assert!(
                ClaudeResponseCapture::begin(&file).is_none(),
                "expired small-page plan"
            );
            assert!(
                ClaudeResponseCapture::begin(&other).is_none(),
                "expired small-page plan"
            );
        }
        assert_eq!(
            plan_next_page(
                &support,
                keys.iter()
                    .enumerate()
                    .map(|(at, key)| (key.as_str(), at as u64)),
                std::iter::empty(),
                Instant::now() + Duration::from_secs(1),
            ),
            PlanInstall::Complete
        );
        assert!(
            ClaudeResponseCapture::begin(&file).is_some(),
            "planned family"
        );
        if let Some(created) = expired {
            PLANS.lock().unwrap().get_mut(&support).unwrap().created = created;
            assert!(
                ClaudeResponseCapture::begin(&file).is_none(),
                "expired plan"
            );
            assert!(
                ClaudeResponseCapture::begin(&other).is_none(),
                "expired plan"
            );
        }
        // The shadow turning off starts the scope over.
        forget_plan(&support);
        assert_eq!(plan_allows_capture_for_test(&support), None);
        assert!(ClaudeResponseCapture::begin(&file).is_some());
        // A page that starts and refuses before planning leaves the scope
        // paged without a plan: nothing optional, never back to all.
        mark_paged(&support);
        assert_eq!(plan_allows_capture_for_test(&support), Some(false));
        assert!(ClaudeResponseCapture::begin(&file).is_none());
        assert!(ClaudeResponseCapture::begin(&other).is_none());
        // A following page start keeps the plan its predecessor installed.
        assert_eq!(
            plan_next_page(
                &support,
                keys.iter()
                    .enumerate()
                    .map(|(at, key)| (key.as_str(), at as u64)),
                std::iter::empty(),
                Instant::now() + Duration::from_secs(1),
            ),
            PlanInstall::Complete
        );
        mark_paged(&support);
        assert!(ClaudeResponseCapture::begin(&file).is_some());
        super::super::disable_shadow_for_test(&support);
        println!("MONEY_P1B_PLAN_CLOSED first_page_eligible=1 closed_eligible=0 refused_first_page_eligible=0 expired_checked={} expired_eligible=0 small_page_expired_eligible=0 funds_refused=1", u8::from(expired.is_some()));
    }

    /// Plan state is scope-wide (MONEY round 2): a page that lists other
    /// families keeps the turns and exclusions of the families an earlier
    /// page listed, so after A -> B the next parse of A captures only A's
    /// planned families, never what A built, and A's unacknowledged
    /// consumed turns still order A.
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn another_pages_plan_keeps_earlier_pages_turns_and_exclusions() {
        let scratch = crate::test_scratch::ScratchDir::new("money-capture-scope-wide");
        let support = scratch.join("support");
        let _shadow_cleanup = super::super::ShadowTestCleanup::new(&support);
        super::super::enable_shadow_for_test(&support);
        let before = capture_reserved();
        let page = |name: &str| {
            (0..3 * NEXT_PAGE_FAMILIES)
                .map(|at| format!("{name}-{at}"))
                .collect::<Vec<_>>()
        };
        let (a, b) = (page("a"), page("b"));
        let key = |root: &str| super::super::family_key(root);
        let begins = |root: &str| {
            ClaudeResponseCapture::begin(&scratch.join(format!("{root}.jsonl"))).is_some()
        };
        let plan = |roots: &[String], turn: &dyn Fn(usize) -> u64| {
            let keys = roots.iter().map(|root| key(root)).collect::<Vec<_>>();
            plan_next_page(
                &support,
                keys.iter()
                    .enumerate()
                    .map(|(at, key)| (key.as_str(), turn(at))),
                std::iter::empty(),
                Instant::now() + Duration::from_secs(1),
            )
        };
        // Page A consumed (built) a-0..64 at turn 9000, acknowledgement not
        // (yet) arrived: its plan selects a-64..128.
        let a_turn = |at: usize| {
            if at < NEXT_PAGE_FAMILIES {
                9000 + at as u64
            } else {
                at as u64
            }
        };
        assert_eq!(plan(&a, &a_turn), PlanInstall::Complete);
        // Page B, a different native page, plans its own families.
        assert_eq!(plan(&b, &|at: usize| at as u64), PlanInstall::Complete);
        for at in 0..3 * NEXT_PAGE_FAMILIES {
            let planned = (NEXT_PAGE_FAMILIES..2 * NEXT_PAGE_FAMILIES).contains(&at);
            assert_eq!(begins(&a[at]), planned, "A's plan survives B's: a-{at}");
            assert_eq!(begins(&b[at]), at < NEXT_PAGE_FAMILIES, "b-{at}");
        }
        assert_eq!(
            scheduling_turn(&support, &key(&a[0]), 0),
            9000,
            "A's unacknowledged consumed turn survives B's plan"
        );
        // A again (A -> B -> A): it builds a-64..128 and plans a-128..192,
        // never a-0..64, which it built first.
        let a_turn = |at: usize| {
            if at < 2 * NEXT_PAGE_FAMILIES {
                9000 + at as u64
            } else {
                at as u64
            }
        };
        assert_eq!(plan(&a, &a_turn), PlanInstall::Complete);
        assert_eq!(plan(&b, &|at: usize| at as u64), PlanInstall::Complete);
        for (at, root) in a.iter().enumerate() {
            assert_eq!(begins(root), at >= 2 * NEXT_PAGE_FAMILIES, "a-{at}");
        }
        // A fallback on B leaves A's selection to A's own next page.
        set_plan_deadline_for_test(true);
        let b_keys = b.iter().map(|root| key(root)).collect::<Vec<_>>();
        assert_eq!(
            plan_next_page(
                &support,
                b_keys.iter().map(|key| (key.as_str(), 0)),
                b_keys[NEXT_PAGE_FAMILIES..2 * NEXT_PAGE_FAMILIES]
                    .iter()
                    .map(|key| (key.as_str(), 0, true))
                    .chain(b_keys[..NEXT_PAGE_FAMILIES].iter().map(|key| (
                        key.as_str(),
                        9100,
                        false
                    ))),
                Instant::now() + Duration::from_secs(1),
            ),
            PlanInstall::Fallback(PlanFailure::Deadline)
        );
        set_plan_deadline_for_test(false);
        assert!(
            !begins(&a[2 * NEXT_PAGE_FAMILIES]),
            "a fallback lists everything it allows"
        );
        assert_eq!(plan(&a, &a_turn), PlanInstall::Complete);
        assert!(
            (0..NEXT_PAGE_FAMILIES).all(|at| !begins(&b[at])),
            "B's consumed families stay excluded after A's complete plan"
        );
        assert!(
            (NEXT_PAGE_FAMILIES..2 * NEXT_PAGE_FAMILIES).all(|at| begins(&b[at])),
            "B's fallback selection outlasts A's complete plan"
        );
        assert_eq!(scheduling_turn(&support, &key(&b[0]), 0), 9100);
        assert_eq!(capture_reserved(), before + plan_funds_for_test(&support));
        forget_plan(&support);
        assert_eq!(capture_reserved(), before);
        super::super::disable_shadow_for_test(&support);
        println!("MONEY_P1B_PLAN_SCOPE_WIDE pages=A,B,A,B,fallback(B),A families_per_page=192 a_rebuilt=0 b_consumed_eligible_after_a=0 b_fallback_eligible_after_a=64");
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn shadow_cleanup_releases_plan_and_disables_scope_on_panic() {
        let scratch = crate::test_scratch::ScratchDir::new("money-plan-panic-cleanup");
        let support = scratch.join("support");
        let before = capture_reserved();
        let failure = std::panic::catch_unwind(|| {
            let _cleanup = super::super::ShadowTestCleanup::new(&support);
            super::super::enable_shadow_for_test(&support);
            assert_eq!(
                plan_next_page(
                    &support,
                    std::iter::once(("root", 0)),
                    std::iter::empty(),
                    Instant::now() + Duration::from_secs(1),
                ),
                PlanInstall::Complete
            );
            assert!(capture_reserved() > before);
            assert!(super::super::shadow_enabled(&support));
            let entries = PLANS.lock().unwrap()[&support].entries.len();
            assert_eq!(entries, 0, "synthetic fixture assertion failure");
        });
        assert!(failure.is_err());
        assert_eq!(capture_reserved(), before);
        assert!(!super::super::shadow_enabled(&support));
        assert!(!PLANS.is_poisoned());
    }

    /// Each page updates the plan in place and reuses its funds, so a family
    /// count whose two plans exceed the capture ceiling still installs every
    /// page. Changing family sets near the ceiling, after an interrupted
    /// build kept the union of two pages, still install: families the page
    /// does not list make room first.
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn replacing_a_large_plan_reuses_the_old_plans_funds() {
        let scratch = crate::test_scratch::ScratchDir::new("money-capture-large-plan");
        let support = scratch.join("support");
        let _shadow_cleanup = super::super::ShadowTestCleanup::new(&support);
        let before = capture_reserved();
        let set = |name: &str| {
            (0..30_000)
                .map(|at| super::super::family_key(&format!("{name}-{at}")))
                .collect::<Vec<_>>()
        };
        let keys = set("root");
        let one_plan = keys.iter().map(|key| plan_key_bytes(key)).sum::<usize>();
        assert!(
            2 * one_plan > CAPTURE_CEILING_BYTES - before
                && one_plan < CAPTURE_CEILING_BYTES - before,
            "two plans exceed the ceiling, one fits: {one_plan}"
        );
        let page = |keys: &[String], offset: u64, checks: usize| {
            let walked = std::cell::Cell::new(0);
            plan_next_page_while(
                &support,
                keys.iter()
                    .enumerate()
                    .map(|(at, key)| (key.as_str(), (at as u64 + offset) % 30_000)),
                keys[..NEXT_PAGE_FAMILIES]
                    .iter()
                    .map(|key| (key.as_str(), 0, true)),
                || {
                    walked.set(walked.get() + 1);
                    walked.get() <= checks
                },
            )
        };
        for offset in 0..3_u64 {
            assert_eq!(
                page(&keys, offset * 7, usize::MAX),
                PlanInstall::Complete,
                "page {offset}"
            );
            assert!(capture_reserved() - before < 2 * one_plan);
        }
        let held = capture_reserved() - before;
        // Another native page's families: an interrupted build keeps the
        // union (with half the room left under the ceiling) ...
        let other = set("other");
        let room = CAPTURE_CEILING_BYTES - capture_reserved();
        let interrupted = room / 2 / plan_key_bytes(&other[0]);
        assert!(
            interrupted >= 1_000,
            "room for an interrupted build: {room}"
        );
        assert_eq!(
            page(&other, 0, interrupted + 1),
            PlanInstall::Fallback(PlanFailure::Deadline)
        );
        let union = capture_reserved() - before;
        assert!(union > held, "{union} {held}");
        // ... and a third page set, whose own 30,000 families fit but the
        // union with them does not, still installs completely.
        let third = set("third");
        assert_eq!(page(&third, 0, usize::MAX), PlanInstall::Complete);
        assert!(capture_reserved() - before < 2 * one_plan);
        let eligible = planned_families_for_test(&support).unwrap();
        assert_eq!(eligible.len(), NEXT_PAGE_FAMILIES);
        assert!(eligible.iter().all(|key| third.contains(key)));
        // Keep the same checks without poisoning shared state on failure.
        let (entry_count, first_allowed, other_allowed) = {
            let plans = PLANS.lock().unwrap();
            (
                plans[&support].entries.len(),
                plans[&support].allows(&keys[0]),
                plans[&support].allows(&other[0]),
            )
        };
        assert_eq!(
            entry_count,
            third.len(),
            "only the page's own families stay"
        );
        assert!(
            !first_allowed && !other_allowed,
            "a family whose entry made room is not eligible again before the loss expires"
        );
        assert_eq!(capture_reserved(), before + plan_funds_for_test(&support));
        forget_plan(&support);
        assert_eq!(capture_reserved(), before);
        println!("MONEY_P1B_PLAN_FUNDS keys=30000 one_plan_bytes={one_plan} held_bytes={held} interrupted_entries={interrupted} interrupted_union_bytes={union} ceiling={CAPTURE_CEILING_BYTES} same_set_pages=3 changed_set_installed=1");
    }

    /// Admission inside a running money section charges its time already;
    /// the section's time is added once when it ends.
    #[test]
    fn a_running_money_section_counts_before_it_ends() {
        let scope = PathBuf::from("money-clock-running-section");
        begin_page(&scope);
        {
            let _section = MoneyTimer::new(&scope, Instant::now());
            assert!(spend_work(&scope, 1, 1), "a fresh section is admitted");
        }
        let short = work_for_test(&scope).2;
        assert!(short < PAGE_CAPTURE_US, "{short}");
        {
            let _section = MoneyTimer::new(
                &scope,
                Instant::now() - Duration::from_micros(PAGE_CAPTURE_US),
            );
            assert!(
                !spend_work(&scope, 1, 1),
                "a section that has run 100 ms refuses before it ends"
            );
        }
        assert!(work_for_test(&scope).2 >= short + PAGE_CAPTURE_US);
        assert!(
            WORK.lock().unwrap()[&scope].section.is_none(),
            "an ended section stops charging"
        );
    }

    /// Refusal is a constant-work fast path, even when a file still has
    /// many finalizers and the native page still has many files to parse.
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn exhausted_capture_constructs_no_timers_and_allocates_nothing() {
        assert_exhausted_capture_fast_path();
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn production_exhaustion_latch_constructs_no_timers_and_allocates_nothing() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                PROCESS_LATCH_FOR_TEST.with(|enabled| enabled.set(false));
            }
        }
        PROCESS_LATCH_FOR_TEST.with(|enabled| assert!(!enabled.replace(true)));
        let _reset = Reset;
        assert_exhausted_capture_fast_path();
    }

    fn assert_exhausted_capture_fast_path() {
        let scratch = crate::test_scratch::ScratchDir::new("money-exhausted-fast-path");
        let scope = scratch.join("support");
        let path = scratch.join("transcript.jsonl");
        let _shadow_cleanup = super::super::ShadowTestCleanup::new(&scope);
        super::super::enable_shadow_for_test(&scope);
        let mut capture = ClaudeResponseCapture::begin(&path).expect("armed capture");
        let pending_deposit = ClaudeResponseCapture::begin(&path).expect("second capture");
        let mut pending_finalizer = ClaudeResponseCapture::begin(&path).expect("third capture");
        WORK.lock().unwrap().get_mut(&scope).unwrap().micros = PAGE_CAPTURE_US;
        assert_eq!(capture.request_hash("exhaust"), None);
        assert!(capture.is_refused());
        assert!(page_exhausted(&scope));
        assert!(
            capture_eligible_for_test(&path),
            "next-page plan eligibility ignores the current page's spent work"
        );
        let timers = TIMER_CONSTRUCTIONS.with(std::cell::Cell::get);
        let work = work_for_test(&scope);
        let (_, allocations) = crate::retry_allocation_probe::measure_caller_thread(|| {
            // Captures created before another capture exhausted the page
            // also refuse before constructing a timer.
            pending_finalizer.contained(|_| panic!("exhausted page ran a finalizer"));
            pending_deposit.deposit(&path, "fingerprint");
            for _ in 0..4096 {
                capture.contained(|_| panic!("refused capture ran a finalizer"));
                capture.note_messages(std::iter::once((0, "message")));
                assert_eq!(capture.request_hash("request"), None);
                assert!(ClaudeResponseCapture::begin(&path).is_none());
            }
            capture.deposit(&path, "fingerprint");
        });
        assert!(pending_finalizer.is_refused());
        assert_eq!(TIMER_CONSTRUCTIONS.with(std::cell::Cell::get), timers);
        assert_eq!(allocations.allocations, 0, "{allocations:?}");
        assert_eq!(
            work_for_test(&scope),
            work,
            "refused callbacks charge no work"
        );
        assert!(take_capture(
            &scope,
            &super::super::super::local_index_key(&path),
            "fingerprint"
        )
        .is_none());
        // Only an explicit new native page clears the refusal.
        begin_page(&scope);
        assert!(ClaudeResponseCapture::begin(&path).is_some());
        super::super::disable_shadow_for_test(&scope);
        println!("MONEY_P1B_EXHAUSTED callbacks=4096 timer_constructions_after_refusal=0 allocations_after_refusal=0 new_page_rearms=1");
    }

    /// Hashing a displaced response's request id is shadow-only work: it is
    /// timed and admitted against the capture input, and refused once the
    /// capture allowance is spent.
    #[test]
    fn displaced_request_hashing_is_timed_and_admitted_capture_work() {
        let scope = PathBuf::from("money-request-hash-work");
        begin_page(&scope);
        let mut capture = ClaudeResponseCapture {
            scope: scope.clone(),
            ..Default::default()
        };
        assert_eq!(
            capture.request_hash("req-1"),
            Some(crate::snapshots::claude_request_census::claude_request_hash("req-1"))
        );
        assert_eq!(work_for_test(&scope).0, "req-1".len());
        WORK.lock().unwrap().get_mut(&scope).unwrap().micros = PAGE_CAPTURE_US;
        assert_eq!(capture.request_hash("req-2"), None);
        assert!(capture.is_refused());
        assert_eq!(capture.request_hash("req-3"), None);
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn cumulative_work_does_not_refund_when_a_capture_drops() {
        let scope = PathBuf::from("cumulative-capture-budget-fixture");
        begin_page(&scope);
        let mut accepted = 0;
        for _ in 0..4096 {
            let mut capture = ClaudeResponseCapture {
                scope: scope.clone(),
                ..Default::default()
            };
            let id = "m".repeat(256);
            capture.note_messages((0..64).map(|sequence| (sequence, id.as_str())));
            accepted += usize::from(!capture.refused);
            // Deliberately drop resident funds: work must stay spent.
        }
        assert!(accepted > 0 && accepted <= PAGE_INPUT_BYTES / (64 * 256));
        let work = WORK.lock().unwrap();
        assert!(work[&scope].exhausted);
        assert!(work[&scope].input <= PAGE_INPUT_BYTES);
        assert!(work[&scope].comparisons <= PAGE_COMPARISONS);
        let spent = work[&scope].micros;
        drop(work);
        assert_eq!(
            take_page_clock(Path::new("unrelated-capture-page"), Instant::now()).capture_us,
            0
        );
        assert_eq!(take_page_clock(&scope, Instant::now()).capture_us, spent);
        assert_eq!(
            work_for_test(&scope).2,
            spent,
            "reporting never refunds work"
        );
        println!("MONEY_P1B_CAPTURE admitted_files={accepted} attempted_files=4096 input_cap={PAGE_INPUT_BYTES} comparisons_cap={PAGE_COMPARISONS} time_cap_us={PAGE_CAPTURE_US}");
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn giant_ids_and_selectors_are_refused_before_comparison_or_hashing() {
        let scope = PathBuf::from("capture-input-fixture");
        begin_page(&scope);
        let mut capture = ClaudeResponseCapture {
            scope: scope.clone(),
            ..Default::default()
        };
        let id = "x".repeat(257);
        capture.note_messages(std::iter::once((0, id.as_str())));
        assert!(capture.refused);
        assert!(capture.messages.is_empty());
        let mut capture = ClaudeResponseCapture {
            scope: scope.clone(),
            ..Default::default()
        };
        let selector = BTreeMap::from([("plan".to_owned(), "x".repeat(PAGE_INPUT_BYTES + 1))]);
        capture.place(0, "hour", "model", &selector, &[]);
        assert!(capture.refused);
        assert!(capture.rows.is_empty());
    }
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn saturated_capture_with_occupied_outbox_stays_in_separate_limits() {
        let scratch = crate::test_scratch::ScratchDir::new("money-occupied-outbox");
        let paused = super::super::store::pause_for_test();
        let now = super::super::now_unix();
        for _ in 0..4 {
            let reservation = super::super::ShadowReservation::admit(8 * 1024 * 1024).unwrap();
            let job = super::super::store::WriteJob {
                support_dir: scratch.to_path_buf(),
                jsonl: super::super::JsonlBatch {
                    now,
                    fault: super::super::PageFault::None,
                    families: Vec::new(),
                    coverage: super::super::CoverageRow::owed(now),
                    buffer_bytes: 0,
                },
                memos: Vec::new(),
                save: None,
                reservations: vec![reservation],
            };
            assert!(super::super::store::submit_unledgered(job).is_ok());
        }
        let baseline = capture_reserved();
        let mut occupied = Funds::default();
        assert!(occupied.spend(CAPTURE_CEILING_BYTES - baseline));
        let scope = scratch.to_path_buf();
        begin_page(&scope);
        let mut capture = ClaudeResponseCapture {
            scope,
            ..Default::default()
        };
        capture.note_messages(std::iter::once((0, "message")));
        assert!(capture.is_refused());
        assert_eq!(capture_reserved(), CAPTURE_CEILING_BYTES);
        assert_eq!(super::super::reserved_for_test(), 32 * 1024 * 1024);
        println!("MONEY_P1B_OUTBOX queued_transient=33554432 capture_resident={} capture_cap={} transient_cap=67108864", capture_reserved(), CAPTURE_CEILING_BYTES);
        drop((capture, occupied, paused));
        super::super::store::flush();
        assert_eq!(super::super::reserved_for_test(), 0);
    }
}
