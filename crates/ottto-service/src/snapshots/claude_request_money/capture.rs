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
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// After a cold page, focus the next Full parse on the oldest 64 family
/// turns. Gating optional capture leaves native file/finalizer order alone.
/// All members of a chosen family remain eligible, within the original caps.
pub(crate) const NEXT_PAGE_FAMILIES: usize = 64;
/// One plan entry's admission: its key bytes, a map entry, the `String`
/// and the (turn, build) value. An eligible-set entry is charged the same.
fn plan_key_bytes(key: &str) -> usize {
    key.len() + MAP_ENTRY_BYTES + std::mem::size_of::<String>() + std::mem::size_of::<(u64, u64)>()
}

/// What the scope's pages decided for the next parse's optional captures.
/// Once a scope has had a page it always has one (MONEY decision: fail
/// closed, never stale). Each page updates the scope's plan in place: its
/// funds and the turns of families consumed on earlier pages (possibly
/// still unacknowledged) carry over; the eligible set is replaced.
struct Plan {
    /// The scheduling turn of each family the scope's pages listed, and the
    /// build that last saw it (a complete build drops the others).
    turns: BTreeMap<String, (u64, u64)>,
    turn_funds: Funds,
    /// The families the next parse may capture: the oldest 64 of a complete
    /// build, or the fallback's.
    eligible: BTreeSet<String>,
    eligible_funds: Funds,
    /// A family the plan does not list is eligible after a complete build
    /// (another native page's family); never after a fallback or a closed
    /// plan.
    unlisted_eligible: bool,
    /// A page of at most 64 families: every file is eligible.
    all: bool,
    build: u64,
    created: Instant,
}

impl Plan {
    /// Nothing optional is captured.
    fn closed() -> Self {
        Self {
            turns: BTreeMap::new(),
            turn_funds: Funds::default(),
            eligible: BTreeSet::new(),
            eligible_funds: Funds::default(),
            unlisted_eligible: false,
            all: false,
            build: 0,
            created: Instant::now(),
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
    // reuses the plan's funds and turns (an expired plan starts empty).
    let Some(taken) = swap_plan(scope, Plan::closed()) else {
        return PlanInstall::Closed(PlanFailure::Lock);
    };
    let mut plan = taken
        .filter(|plan| !plan.all && plan.created.elapsed() < CAPTURE_TTL)
        .unwrap_or_else(Plan::closed);
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

/// Update every page family's turn in place and select the oldest 64. On
/// failure the plan keeps the turns updated so far (each no older than
/// before) and its old eligible set, which the fallback replaces.
fn complete_plan<'a>(
    plan: &mut Plan,
    keys: impl Iterator<Item = (&'a str, u64)>,
    mut within_deadline: impl FnMut() -> bool,
) -> Result<(), PlanFailure> {
    if !within_deadline() {
        return Err(PlanFailure::Deadline);
    }
    let mut oldest_funds = Funds::default();
    if !oldest_funds
        .spend(NEXT_PAGE_FAMILIES * (MAP_ENTRY_BYTES + std::mem::size_of::<((u64, &str), &str)>()))
    {
        return Err(PlanFailure::Funds);
    }
    plan.build += 1;
    let build = plan.build;
    // Oldest-64 selection with the producer's same (turn, family key)
    // total order, without an uninterruptible whole-page sort.
    let mut oldest = BTreeMap::new();
    for (key, turn) in keys {
        if !within_deadline() {
            return Err(PlanFailure::Deadline);
        }
        if let Some(entry) = plan.turns.get_mut(key) {
            *entry = (turn, build);
        } else {
            if !plan.turn_funds.spend(plan_key_bytes(key)) {
                return Err(PlanFailure::Funds);
            }
            plan.turns.insert(key.to_owned(), (turn, build));
        }
        oldest.insert((turn, key), key);
        if oldest.len() > NEXT_PAGE_FAMILIES {
            let _ = oldest.pop_last();
        }
    }
    let mut eligible_funds = Funds::default();
    let mut eligible = BTreeSet::new();
    for key in oldest.values() {
        if !within_deadline() {
            return Err(PlanFailure::Deadline);
        }
        if !eligible_funds.spend(plan_key_bytes(key)) {
            return Err(PlanFailure::Funds);
        }
        eligible.insert((*key).to_owned());
    }
    if !within_deadline() {
        return Err(PlanFailure::Deadline);
    }
    // Families this page does not list leave the plan, with their funds.
    let mut freed = 0;
    plan.turns.retain(|key, (_, seen)| {
        let keep = *seen == build;
        if !keep {
            freed += plan_key_bytes(key);
        }
        keep
    });
    plan.turn_funds.refund(freed);
    plan.eligible = eligible;
    plan.eligible_funds = eligible_funds;
    plan.unlisted_eligible = true;
    Ok(())
}

/// Replace the eligible set with the fallback's (at most 64) and record
/// this page's consumed turns; false (nothing eligible) when funds refuse.
fn fallback_plan<'a>(plan: &mut Plan, entries: impl Iterator<Item = (&'a str, u64, bool)>) -> bool {
    plan.unlisted_eligible = false;
    plan.eligible = BTreeSet::new();
    plan.eligible_funds = Funds::default();
    let mut eligible_funds = Funds::default();
    let mut eligible = BTreeSet::new();
    for (key, turn, allowed) in entries {
        if allowed && eligible.len() == NEXT_PAGE_FAMILIES {
            continue;
        }
        if let Some(entry) = plan.turns.get_mut(key) {
            entry.0 = turn;
        } else {
            if !plan.turn_funds.spend(plan_key_bytes(key)) {
                return false;
            }
            plan.turns.insert(key.to_owned(), (turn, plan.build));
        }
        if allowed {
            if !eligible_funds.spend(plan_key_bytes(key)) {
                return false;
            }
            eligible.insert(key.to_owned());
        }
    }
    plan.eligible = eligible;
    plan.eligible_funds = eligible_funds;
    true
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
            if other != scope && old.created.elapsed() >= CAPTURE_TTL && !old.turns.is_empty() {
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

/// A page of at most 64 families: every file stays eligible (as when such
/// a page kept no plan).
pub(super) fn plan_all_families(scope: &Path) {
    let _ = swap_plan(
        scope,
        Plan {
            all: true,
            ..Plan::closed()
        },
    );
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
                .filter(|plan| plan.created.elapsed() < CAPTURE_TTL)
                .and_then(|plan| plan.turns.get(key))
                .map(|(turn, _)| *turn)
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
/// scope's first page and after a page of at most 64 families; otherwise
/// only a family its live plan allows (an expired plan allows nothing).
fn capture_eligible(scope: &Path, path: &Path) -> bool {
    PLANS.lock().is_ok_and(|plans| {
        let Some(plan) = plans.get(scope) else {
            return true;
        };
        if plan.all {
            return true;
        }
        plan.created.elapsed() < CAPTURE_TTL
            && super::super::claude_index_path_member_ref(path).is_some_and(|member| {
                let key = super::family_key(member.root);
                plan.eligible.contains(&key)
                    || (plan.unlisted_eligible && !plan.turns.contains_key(&key))
            })
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
        let _timer = MoneyTimer::new(&self.scope, Instant::now());
        if self.refused {
            return;
        }
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
        let _timer = MoneyTimer::new(&self.scope, Instant::now());
        if self.refused {
            return None;
        }
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

#[cfg(test)]
pub(crate) fn planned_families_for_test(
    scope: &Path,
) -> Option<std::collections::BTreeSet<String>> {
    PLANS
        .lock()
        .unwrap()
        .get(scope)
        .map(|plan| plan.eligible.clone())
}

/// Whether `begin` would capture `path` now (its scope armed and its plan
/// allowing the family), without spending capture work.
#[cfg(test)]
pub(crate) fn capture_eligible_for_test(path: &Path) -> bool {
    super::capture_armed(path).is_some_and(|scope| capture_eligible(&scope, path))
}

/// None before the scope's first page; after it, whether its live plan
/// allows any optional capture at all.
#[cfg(test)]
pub(crate) fn plan_allows_capture_for_test(scope: &Path) -> Option<bool> {
    PLANS.lock().unwrap().get(scope).map(|plan| {
        plan.all
            || plan.created.elapsed() < CAPTURE_TTL
                && (plan.unlisted_eligible || !plan.eligible.is_empty())
    })
}

/// Capture funds the scope's plan holds.
#[cfg(test)]
pub(crate) fn plan_funds_for_test(scope: &Path) -> usize {
    PLANS
        .lock()
        .unwrap()
        .get(scope)
        .map_or(0, |plan| plan.turn_funds.held + plan.eligible_funds.held)
}

/// Accepted cumulative work, including work whose resident capture was dropped.
#[cfg(test)]
pub(crate) fn work_for_test(scope: &Path) -> (usize, usize, u64) {
    let pages = WORK.lock().unwrap();
    let work = pages.get(scope).expect("page capture budget installed");
    (work.input, work.comparisons, work.micros)
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
            funded,
            "the update reuses the old plan's funds; the partial walk adds none"
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
        let plans = PLANS.lock().unwrap();
        assert!(!plans[&support].eligible.contains(&keys[0]));
        assert!(
            !plans[&support].eligible.contains(&keys[200]) && !plans[&support].unlisted_eligible,
            "interruption never changes the next Full to all-eligible"
        );
        drop(plans);
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
    /// optional (MONEY decision); only a scope's first page, before any
    /// page planned, captures every file.
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn a_paged_scope_without_a_plan_captures_nothing_optional() {
        let scratch = crate::test_scratch::ScratchDir::new("money-capture-closed");
        let support = scratch.join("support");
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
        plan_all_families(&support);
        assert!(
            ClaudeResponseCapture::begin(&file).is_some(),
            "a page of at most 64"
        );
        assert!(
            ClaudeResponseCapture::begin(&other).is_some(),
            "a page of at most 64"
        );
        // An expired plan allows nothing either.
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
        // (A fresh runner's monotonic clock may not reach back 15 minutes.)
        let expired = Instant::now().checked_sub(CAPTURE_TTL);
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
        assert!(ClaudeResponseCapture::begin(&file).is_some());
        super::super::disable_shadow_for_test(&support);
        println!("MONEY_P1B_PLAN_CLOSED first_page_eligible=1 closed_eligible=0 expired_checked={} expired_eligible=0 funds_refused=1", u8::from(expired.is_some()));
    }

    /// Replacing a plan releases the old plan's funds before funding the new
    /// one, so a family count whose two plans exceed the capture ceiling
    /// still installs every page.
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn replacing_a_large_plan_reuses_the_old_plans_funds() {
        let scratch = crate::test_scratch::ScratchDir::new("money-capture-large-plan");
        let support = scratch.join("support");
        let before = capture_reserved();
        let keys = (0..30_000)
            .map(|at| super::super::family_key(&format!("root-{at}")))
            .collect::<Vec<_>>();
        let one_plan = keys.iter().map(|key| plan_key_bytes(key)).sum::<usize>();
        assert!(
            2 * one_plan > CAPTURE_CEILING_BYTES - before
                && one_plan < CAPTURE_CEILING_BYTES - before,
            "two plans exceed the ceiling, one fits: {one_plan}"
        );
        for page in 0..3_u64 {
            assert_eq!(
                plan_next_page_while(
                    &support,
                    keys.iter()
                        .enumerate()
                        .map(|(at, key)| (key.as_str(), (at as u64 + page * 7) % 30_000)),
                    std::iter::empty(),
                    || true,
                ),
                PlanInstall::Complete,
                "page {page}"
            );
            assert!(capture_reserved() - before < 2 * one_plan);
        }
        let held = capture_reserved() - before;
        forget_plan(&support);
        assert_eq!(capture_reserved(), before);
        println!("MONEY_P1B_PLAN_FUNDS keys=30000 one_plan_bytes={one_plan} held_bytes={held} ceiling={CAPTURE_CEILING_BYTES} pages=3 installed=3");
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
