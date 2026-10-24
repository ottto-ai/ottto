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
use std::collections::BTreeMap;
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
struct Plan {
    keys: BTreeMap<String, (u64, bool)>,
    _funds: Funds,
    created: Instant,
}
static PLANS: Mutex<BTreeMap<PathBuf, Plan>> = Mutex::new(BTreeMap::new());

pub(super) fn plan_next_page<'a>(
    scope: &Path,
    keys: impl Iterator<Item = (&'a str, u64)>,
    deadline: Instant,
) -> bool {
    plan_next_page_while(scope, keys, || Instant::now() < deadline)
}

fn plan_next_page_while<'a>(
    scope: &Path,
    keys: impl Iterator<Item = (&'a str, u64)>,
    mut within_deadline: impl FnMut() -> bool,
) -> bool {
    if !within_deadline() {
        return false;
    }
    // Keep the funded old plan, including unacknowledged consumed turns,
    // until the replacement is complete and can be installed atomically.
    let mut funds = Funds::default();
    if !funds
        .spend(NEXT_PAGE_FAMILIES * (MAP_ENTRY_BYTES + std::mem::size_of::<((u64, &str), &str)>()))
    {
        return false;
    }
    let mut selected = BTreeMap::new();
    // Oldest-64 selection with the producer's same (turn, family key)
    // total order, without an uninterruptible whole-page sort.
    let mut oldest = BTreeMap::new();
    for (key, turn) in keys {
        if !within_deadline()
            || !funds.spend(
                key.len()
                    + MAP_ENTRY_BYTES
                    + std::mem::size_of::<String>()
                    + std::mem::size_of::<(u64, bool)>(),
            )
        {
            return false;
        }
        selected.insert(key.to_owned(), (turn, false));
        oldest.insert((turn, key), key);
        if oldest.len() > NEXT_PAGE_FAMILIES {
            let _ = oldest.pop_last();
        }
    }
    for key in oldest.values() {
        if !within_deadline() {
            return false;
        }
        selected.get_mut(*key).expect("admitted plan key").1 = true;
    }
    if !within_deadline() {
        return false;
    }
    if let Ok(mut plans) = PLANS.try_lock() {
        plans.retain(|_, plan| plan.created.elapsed() < CAPTURE_TTL);
        plans.insert(
            scope.to_path_buf(),
            Plan {
                keys: selected,
                _funds: funds,
                created: Instant::now(),
            },
        );
        true
    } else {
        false
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
                .filter(|plan| plan.created.elapsed() < CAPTURE_TTL)
                .and_then(|plan| plan.keys.get(key))
                .map(|(turn, _)| *turn)
        })
        .unwrap_or(0)
        .max(published)
}

pub(super) fn forget_plan(scope: &Path) {
    if let Ok(mut plans) = PLANS.lock() {
        plans.remove(scope);
    }
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
        let eligible = PLANS.lock().is_ok_and(|plans| {
            plans
                .get(&scope)
                .filter(|plan| plan.created.elapsed() < CAPTURE_TTL)
                .map_or(true, |plan| {
                    super::super::claude_index_path_member_ref(path).is_some_and(|member| {
                        plan.keys
                            .get(&super::family_key(member.root))
                            .map(|(_, eligible)| *eligible)
                            .unwrap_or(true)
                    })
                })
        });
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
    pub(crate) fn deposit(self, index_key: String, fingerprint: String) {
        let _timer = MoneyTimer::new(&self.scope, Instant::now());
        if super::SHADOW_PANICKED.load(Ordering::Acquire) || !spend_work(&self.scope, 0, 0) {
            return;
        }
        super::guarded(move || self.keep(index_key, fingerprint));
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
    PLANS.lock().unwrap().get(scope).map(|plan| {
        plan.keys
            .iter()
            .filter(|(_, (_, eligible))| *eligible)
            .map(|(key, _)| key.clone())
            .collect()
    })
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
        plan_next_page(
            &support,
            keys.iter()
                .enumerate()
                .map(|(at, key)| (key.as_str(), at as u64)),
            Instant::now() + Duration::from_secs(1),
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
        plan_next_page(
            &support,
            keys.iter()
                .rev()
                .enumerate()
                .map(|(at, key)| (key.as_str(), at as u64)),
            Instant::now() + Duration::from_secs(1),
        );
        assert!(ClaudeResponseCapture::begin(
            &scratch.join(format!("root-{NEXT_PAGE_FAMILIES}.jsonl"))
        )
        .is_some());
        super::super::disable_shadow_for_test(&support);
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn capture_plan_stops_at_expiry_and_never_installs_a_partial_plan() {
        let scratch = crate::test_scratch::ScratchDir::new("money-capture-plan-deadline");
        let support = scratch.join("support");
        let before = capture_reserved();
        let keys = (0..4096)
            .map(|at| super::super::family_key(&format!("root-{at}")))
            .collect::<Vec<_>>();
        let started = Instant::now();
        let visited = std::cell::Cell::new(0_usize);
        assert!(!plan_next_page(
            &support,
            keys.iter().map(|key| {
                visited.set(visited.get() + 1);
                (key.as_str(), 0)
            }),
            started
        ));
        // Iteration can fetch the next element before its deadline check,
        // but no walk/sort of the remaining 4095 entries is allowed.
        assert!(visited.get() <= 1);
        assert!(started.elapsed() <= super::super::PAGE_MAX_ELAPSED + Duration::from_millis(25));
        assert!(!PLANS.lock().unwrap().contains_key(&support));
        assert_eq!(capture_reserved(), before);
        let checks = std::cell::Cell::new(0);
        assert!(!plan_next_page_while(
            &support,
            keys.iter().map(|key| (key.as_str(), 0)),
            || {
                checks.set(checks.get() + 1);
                checks.get() <= 7
            }
        ));
        assert!(!PLANS.lock().unwrap().contains_key(&support));
        assert_eq!(
            capture_reserved(),
            before,
            "interrupted plan refunds all admitted metadata"
        );
        assert!(plan_next_page(
            &support,
            keys.iter()
                .enumerate()
                .map(|(at, key)| (key.as_str(), at as u64)),
            Instant::now() + Duration::from_secs(1)
        ));
        let plans = PLANS.lock().unwrap();
        let plan = &plans[&support];
        assert_eq!(
            plan.keys.values().filter(|(_, eligible)| *eligible).count(),
            NEXT_PAGE_FAMILIES
        );
        assert!(keys[..NEXT_PAGE_FAMILIES]
            .iter()
            .all(|key| plan.keys[key].1));
        drop(plans);
        let funded = capture_reserved();
        let checks = std::cell::Cell::new(0);
        assert!(!plan_next_page_while(
            &support,
            keys.iter().map(|key| (key.as_str(), 9000)),
            || {
                checks.set(checks.get() + 1);
                checks.get() <= 7
            }
        ));
        assert_eq!(
            capture_reserved(),
            funded,
            "old plan stays funded; partial replacement refunds"
        );
        assert_eq!(
            scheduling_turn(&support, &keys[100], 0),
            100,
            "mid-walk expiry must preserve unacknowledged consumed turns"
        );
        let plans = PLANS.lock().unwrap();
        assert!(plans[&support].keys[&keys[0]].1);
        assert!(
            !plans[&support].keys[&keys[100]].1,
            "interruption never changes the next Full to all-eligible"
        );
        drop(plans);
        forget_plan(&support);
        assert_eq!(capture_reserved(), before);
        println!("MONEY_P1B_PLAN entries=4096 expired_visited={} interrupted_checks={} eligible={NEXT_PAGE_FAMILIES}", visited.get(), checks.get());
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
