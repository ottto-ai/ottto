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
//! drops the capture and the shadow reports the file unbuilt.
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

static CAPTURE_RESERVED: AtomicUsize = AtomicUsize::new(0);

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
    pub(crate) clock_nanos: Option<i128>,
    pub(crate) event_clock_complete: bool,
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
        let mut scope = None;
        super::guarded(|| scope = super::capture_armed(path));
        scope.map(|scope| Self {
            scope,
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
    pub(crate) fn note_messages<'k>(
        &mut self,
        count: usize,
        keys: impl Iterator<Item = (u64, &'k str)>,
    ) {
        self.contained(|capture| capture.record_messages(count, keys));
    }

    fn record_messages<'k>(&mut self, count: usize, keys: impl Iterator<Item = (u64, &'k str)>) {
        if self.refused {
            return;
        }
        if !self
            .funds
            .spend(count.saturating_mul(std::mem::size_of::<(u64, u64)>()))
        {
            self.refuse();
            return;
        }
        self.messages.reserve_exact(count);
        for (sequence, message_id) in keys.take(count) {
            self.messages
                .push((sequence, super::claude_message_hash(message_id)));
        }
        self.messages.sort_unstable();
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

    /// A response the occurrence map replaced under the same request id.
    pub(crate) fn displaced(&mut self, request_hash: u64, prior: &ClaudeTranscriptUsageOccurrence) {
        self.contained(|capture| capture.record_displaced(request_hash, prior));
    }

    fn record_displaced(&mut self, request_hash: u64, prior: &ClaudeTranscriptUsageOccurrence) {
        self.push_unit(CapturedUnit {
            kind: CapturedKind::Displaced(request_hash),
            sequence: prior.sequence,
            tokens: ClaudeMoneyTokens::from_usage(&prior.usage),
            requests: prior.usage.request_count,
            clock: prior.timestamp.as_deref().and_then(rfc3339_unix_seconds),
            clock_nanos: prior
                .timestamp
                .as_deref()
                .and_then(super::super::rfc3339_unix_nanos),
            event_clock_complete: prior.event_clock_complete,
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
            clock_nanos: timestamp.and_then(super::super::rfc3339_unix_nanos),
            event_clock_complete: false,
            model: model.map(super::claude_model_hash),
        });
    }

    /// Full-body copies of placement keys and counted contributions, admitted
    /// before building. A single long selector can be copied by every unit.
    pub(super) fn body_allocation_bound(&self) -> usize {
        let largest = self
            .rows
            .iter()
            .map(|row| {
                row.selector.iter().fold(
                    row.model.len().saturating_add(row.bucket_start.len()),
                    |bytes, (key, value)| {
                        bytes
                            .saturating_add(key.len())
                            .saturating_add(value.len())
                            .saturating_add(128)
                    },
                )
            })
            .max()
            .unwrap_or(0);
        self.placements
            .len()
            .saturating_add(self.units.len())
            .saturating_mul(largest.saturating_add(1024).saturating_mul(8))
    }

    pub(crate) fn units(&self) -> &[CapturedUnit] {
        &self.units
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
        if super::SHADOW_PANICKED.load(Ordering::Acquire) {
            return;
        }
        super::guarded(move || self.keep(index_key, fingerprint));
    }

    fn keep(mut self, index_key: String, fingerprint: String) {
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

pub(crate) fn capture_reserved() -> usize {
    CAPTURE_RESERVED.load(Ordering::Acquire)
}
