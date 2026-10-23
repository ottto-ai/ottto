//! P1 per-request Claude Code money, shadow only (`claude_request_counting:v1`).
//!
//! The live path is unchanged: nothing here changes an upload byte, a hold,
//! an account decision, a live allowance or a return value. The live
//! finalizer runs exactly as before unless the shadow is armed; then a side
//! capture (its own funded budget, never on `SnapshotItem` or any live
//! reservation) records which live bucket row each response went to, its
//! message identity and the responses the occurrence map does not keep.
//!
//! The shadow reads the scan index and never writes it. Its ledger (the
//! telemetry facts, message-only ids, sweeps and family memos) is its own
//! store (`store`), one in-memory copy per support directory: the index's
//! bytes, live allowances, save and validation are the same armed or not.
//! Its file writes (the B1 JSONL and the ledger's changed shards) are handed
//! to one writer thread after the page, outside `SNAPSHOT_SYNC_LOCK`; the
//! JSONL rows are serialized there, from the page's built families.
//!
//! Each authoritative Claude page builds a second body beside the live one
//! (`body::build_claude_request_body`), checks its certificate, and writes
//! the B1 pricing rows of every family of the page: one `grain` row per
//! differing slice (hour, model, pricing selectors, token components, own
//! costs, an explanation category), one `family` row with old/new totals
//! and the removal delta, and the page's `coverage` row, false whenever
//! anything (a refused page, a truncated day, an unbuilt member, a held
//! unit, unread rows, no telemetry certificate) leaves the day unusable for
//! the exit criterion. The reader keeps each family's latest rows by
//! `snapshot` (page sequence); nothing is deduplicated on the writer side. A
//! page whose batch is dropped or not written owes a false coverage row to
//! its day (a marker file keeps the debt across a restart), written with the
//! next batch. All of its memory is admitted before allocation against the
//! shadow's own ceiling and its work runs under a deadline; a refusal skips
//! the page's shadow, writes a false coverage row and is counted.
//!
//! The shadow never fails or stalls the live page: a panic is caught (the
//! shadow is then off for the rest of the process, counted), every phase
//! under the sync lock checks the page deadline, and a local file
//! (`<support>/claude-request-money-shadow.off`) turns it off without a
//! release. Off, it captures nothing either, and the first off page of a
//! day writes one false coverage row.

pub(crate) mod body;
pub(crate) mod capture;
pub(crate) mod coverage;
pub(crate) mod facts;
pub(crate) mod rows;
pub(crate) mod store;

use super::claude_request_census::{
    claude_request_hash, family_key, fingerprint_matches, message_key, telemetry_key,
    ClaudeFamilyMemo, ClaudeFamilyPublication, ClaudeRequestCensusInsert,
    ClaudeRequestCensusRecord, FAMILY_KEY_PREFIX, MESSAGE_KEY_PREFIX,
};
use super::claude_request_ledger::{
    self, ClaudeClassifyContext, ClaudeCountedBy, ClaudeLedgerScope, ClaudeUndecidedBy,
};
use super::{
    claude_index_path_family_member, claude_snapshot_family_root_ref,
    claude_trace_owner_session_id, ScanIndex, SnapshotItem, UsageTotals,
};
use crate::claude_local_otel::telemetry_tail::{
    drop_certificate, tail_fixed_memory, telemetry_certified, telemetry_complete_through,
    ClaudeLedgerWork, ClaudeRootTelemetry, ClaudeTelemetryTail, ClaudeTelemetryTailBudget,
    ClaudeTelemetryTailCounts,
};
use crate::claude_local_otel::{ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipLoadReport};
use body::{
    build_claude_request_body, ClaudeFamilyCategory, ClaudeFamilyInput, ClaudeGrainKey,
    ClaudeGrainSide, ClaudeRequestBody,
};
pub(crate) use capture::ClaudeResponseCapture;
use coverage::{ClaudeHolderView, FamilyCensus, FamilyCoverage};
use rows::{ClaudeRootRows, ClaudeRowCounts};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use store::{ClaudeLedger, ClaudeLedgerAcquire, PendingMemo, WriteJob};

pub(crate) const CLAUDE_REQUEST_COUNTING: &str = "claude_request_counting:v1";
/// Row format of the JSONL (B1 reader `claude_money_shadow_report.py`).
const JSONL_VERSION: u8 = 3;

/// A unit younger than this is immature: deferred, neither counted nor removed.
pub(crate) const MATURITY_SECONDS: u64 = 60;

/// Aggregate transient shadow memory ceiling (all concurrent pages and the
/// batches waiting for the writer).
pub(crate) const SHADOW_MEMORY_CEILING_BYTES: usize = 64 * 1024 * 1024;

/// The shared per-page I/O budget of every shadow reader.
const WORK_MAX_BYTES: u64 = 16 * 1024 * 1024;
const WORK_MAX_STATS: u64 = 1024;
/// Total synchronous allowance under SNAPSHOT_SYNC_LOCK, in every build.
/// Includes closing failure rows and handoff; the writer runs separately.
pub(crate) const PAGE_MAX_ELAPSED: Duration = Duration::from_millis(250);
/// Leave bounded closing work inside the total, rather than after expiry.
const PAGE_CLOSE_RESERVE: Duration = Duration::from_millis(150);
/// A growing structure's admission step.
const GROWTH_STEP_BYTES: usize = 256 * 1024;

/// Daily JSONL: per-day byte cap and days kept. The last bytes of the cap
/// are kept for the seal row (a false coverage row naming the truncation).
const JSONL_DAY_CAP_BYTES: u64 = 8 * 1024 * 1024;
/// The writer streams a batch's rows through one buffer of this size
/// (admitted with the batch): never a second copy of the rows.
const JSONL_WRITE_BUFFER_BYTES: usize = 64 * 1024;
const JSONL_SEAL_RESERVE_BYTES: u64 = 512;
const JSONL_RETENTION_DAYS: i64 = 7;
const JSONL_PREFIX: &str = "claude-request-money-shadow-";
const JSONL_MAX_DIR_ENTRIES: usize = 1024;
/// Family memos older than this (no page rebuilt the family) are dropped.
const FAMILY_MEMO_RETENTION_SECONDS: u64 = 35 * 86_400;
/// `mh:` records checked against their file's record per page.
const MESSAGE_PRUNE_PER_PAGE: usize = 256;
/// The walked part of the ledger state counts is refreshed at most this
/// often (it walks every record).
const STATE_COUNTS_REFRESH: Duration = Duration::from_secs(60);
/// The shadow's local kill switch: this file in the support directory turns
/// it off.
const SHADOW_OFF_FILE: &str = "claude-request-money-shadow.off";

// Per-element admission charges (bytes), generous for the owned strings.
const UNIT_BYTES: usize = 512;
const LIVE_ROW_BYTES: usize = 768;
const GRAIN_BYTES: usize = 2048;
const FAMILY_BYTES: usize = 8192;
const TRACE_ROW_BYTES: usize = 160;
/// One page hash in the page's hash list, claim map and collision map.
const PAGE_HASH_BYTES: usize = 160;

/// What `rows` API rows may grow into downstream: the rows themselves, and
/// for each a page hash, a unit and a grain (a side call is all three).
fn row_charge(rows: usize) -> usize {
    rows::rows_bound(rows)
        .saturating_add(rows.saturating_mul(UNIT_BYTES + GRAIN_BYTES + PAGE_HASH_BYTES))
}

// ---------------------------------------------------------------- normalizer

/// One reading of a Claude cache-creation write: the flat total and its
/// 5m/1h split. Every caller (transcript lines, API sidecar rows, the shadow)
/// uses this; each keeps its own mapping of the three outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheCreation {
    /// A stated split (the total is absent or agrees with it).
    Split { five_m: u64, one_h: u64 },
    /// No split: the total's TTL is unknown.
    Unattributed(u64),
    /// The split disagrees with the total, or overflows.
    Contradictory,
}

pub(crate) fn claude_cache_creation(total: u64, five_m: u64, one_h: u64) -> CacheCreation {
    match five_m.checked_add(one_h) {
        None => CacheCreation::Contradictory,
        Some(0) => CacheCreation::Unattributed(total),
        Some(split) if total == 0 || total == split => CacheCreation::Split { five_m, one_h },
        Some(_) => CacheCreation::Contradictory,
    }
}

// ---------------------------------------------------------------- tokens

/// Token components of one unit or slice. `reasoning` is part of output and
/// never added to the conserved total.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct ClaudeMoneyTokens {
    pub(crate) input: u64,
    pub(crate) output: u64,
    pub(crate) cache_read: u64,
    pub(crate) cache_5m: u64,
    pub(crate) cache_1h: u64,
    pub(crate) unattributed: u64,
    pub(crate) reasoning: u64,
}

impl ClaudeMoneyTokens {
    pub(crate) fn conserved(&self) -> u64 {
        [
            self.input,
            self.output,
            self.cache_read,
            self.cache_5m,
            self.cache_1h,
            self.unattributed,
        ]
        .into_iter()
        .fold(0, u64::saturating_add)
    }

    pub(crate) fn add(&mut self, other: &Self) {
        self.input = self.input.saturating_add(other.input);
        self.output = self.output.saturating_add(other.output);
        self.cache_read = self.cache_read.saturating_add(other.cache_read);
        self.cache_5m = self.cache_5m.saturating_add(other.cache_5m);
        self.cache_1h = self.cache_1h.saturating_add(other.cache_1h);
        self.unattributed = self.unattributed.saturating_add(other.unattributed);
        self.reasoning = self.reasoning.saturating_add(other.reasoning);
    }

    /// `self - other` per component, or None when any would go negative.
    pub(crate) fn checked_sub(&self, other: &Self) -> Option<Self> {
        Some(Self {
            input: self.input.checked_sub(other.input)?,
            output: self.output.checked_sub(other.output)?,
            cache_read: self.cache_read.checked_sub(other.cache_read)?,
            cache_5m: self.cache_5m.checked_sub(other.cache_5m)?,
            cache_1h: self.cache_1h.checked_sub(other.cache_1h)?,
            unattributed: self.unattributed.checked_sub(other.unattributed)?,
            reasoning: self.reasoning.checked_sub(other.reasoning)?,
        })
    }

    pub(in crate::snapshots) fn from_usage(usage: &UsageTotals) -> Self {
        Self {
            input: usage.input_tokens,
            output: usage.output_tokens,
            cache_read: usage.cache_read_tokens,
            cache_5m: usage.cache_creation_5m_tokens,
            cache_1h: usage.cache_creation_1h_tokens,
            unattributed: usage.unattributed_total_tokens,
            reasoning: usage.reasoning_output_tokens,
        }
    }

    pub(crate) fn from_model_usage(row: &super::SnapshotModelUsage) -> Self {
        Self {
            input: row.input_tokens,
            output: row.output_tokens,
            cache_read: row.cache_read_tokens,
            cache_5m: row.cache_creation_5m_tokens,
            cache_1h: row.cache_creation_1h_tokens,
            unattributed: row.unattributed_total_tokens,
            reasoning: row.reasoning_output_tokens,
        }
    }
}

/// Tokens, requests and (where known) money of one slice of a body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeMoneyTotals {
    pub(crate) tokens: u64,
    pub(crate) requests: u64,
    /// Sum of the known costs (USD micros); `unpriced` counts the rest.
    pub(crate) cost_micros: u64,
    pub(crate) unpriced: u64,
}

impl ClaudeMoneyTotals {
    pub(crate) fn add(&mut self, tokens: u64, requests: u64, cost_micros: Option<u64>) {
        self.tokens = self.tokens.saturating_add(tokens);
        self.requests = self.requests.saturating_add(requests);
        match cost_micros {
            Some(cost) => self.cost_micros = self.cost_micros.saturating_add(cost),
            None => self.unpriced = self.unpriced.saturating_add(requests),
        }
    }
}

// ---------------------------------------------------------------- identity

fn digest_u64(domain: &[u8], parts: &[&[u8]]) -> u64 {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    let digest = digest.finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix)
}

/// The `M` ledger hash of a message id (design v2 §1):
/// sha256("m\x1f" + id), first 8 bytes.
pub(crate) fn claude_message_hash(message_id: &str) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"m\x1f");
    digest.update(message_id.as_bytes());
    let digest = digest.finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix)
}

pub(crate) fn claude_model_hash(model: &str) -> u64 {
    digest_u64(b"claude_model:v1\0", &[model.as_bytes()])
}

/// A response's content fingerprint: its usage, model, clock and message
/// identity. Two different responses under one key never share it unless
/// they are the same response.
pub(crate) fn claude_response_fingerprint(
    tokens: &ClaudeMoneyTokens,
    model: Option<u64>,
    clock: u64,
    message: u64,
) -> u64 {
    let mut parts = Vec::with_capacity(11);
    let values = [
        tokens.input,
        tokens.output,
        tokens.cache_read,
        tokens.cache_5m,
        tokens.cache_1h,
        tokens.unattributed,
        tokens.reasoning,
        model.unwrap_or(0),
        u64::from(model.is_some()),
        clock,
        message,
    ]
    .map(u64::to_be_bytes);
    for value in &values {
        parts.push(&value[..]);
    }
    digest_u64(b"claude_response_fingerprint:v1\0", &parts)
}

/// The total order between two different responses under one key (Sol N3):
/// the larger conserved total, then the larger output, then the smaller
/// message-id hash, then the smaller response fingerprint. `Less` = `left`
/// wins. Equal only for the same response.
pub(crate) fn claude_response_conflict_order(
    left: (&ClaudeMoneyTokens, u64, u64),
    right: (&ClaudeMoneyTokens, u64, u64),
) -> std::cmp::Ordering {
    right
        .0
        .conserved()
        .cmp(&left.0.conserved())
        .then_with(|| right.0.output.cmp(&left.0.output))
        .then_with(|| left.1.cmp(&right.1))
        .then_with(|| left.2.cmp(&right.2))
}

pub(crate) fn parse_usd_micros(value: &str) -> Option<u64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty() && fraction.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let whole = if whole.is_empty() {
        0
    } else {
        whole.parse::<u64>().ok()?
    };
    let mut micros = 0_u64;
    for (place, digit) in fraction.bytes().take(6).enumerate() {
        micros += u64::from(digit - b'0') * 10_u64.pow(5 - place as u32);
    }
    whole.checked_mul(1_000_000)?.checked_add(micros)
}

fn usd_string(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

// ---------------------------------------------------------------- arming

#[cfg(test)]
static SHADOW_ENABLED_FOR_TEST: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Tests opt in per support directory (tests run in parallel); production
/// always runs the shadow.
#[cfg(test)]
pub(crate) fn enable_shadow_for_test(support_dir: &Path) {
    capture::begin_page(support_dir);
    SHADOW_ENABLED_FOR_TEST
        .lock()
        .expect("shadow control")
        .push(support_dir.to_path_buf());
}

#[cfg(test)]
pub(crate) fn disable_shadow_for_test(support_dir: &Path) {
    SHADOW_ENABLED_FOR_TEST
        .lock()
        .expect("shadow control")
        .retain(|dir| dir != support_dir);
}

fn shadow_enabled(support_dir: &Path) -> bool {
    #[cfg(test)]
    {
        SHADOW_ENABLED_FOR_TEST
            .lock()
            .expect("shadow control")
            .iter()
            .any(|dir| dir == support_dir)
    }
    #[cfg(not(test))]
    {
        let _ = support_dir;
        true
    }
}

/// The capture scope of a support directory (tests: the directory itself;
/// production: one scope).
fn shadow_scope(support_dir: &Path) -> PathBuf {
    #[cfg(test)]
    {
        support_dir.to_path_buf()
    }
    #[cfg(not(test))]
    {
        let _ = support_dir;
        PathBuf::new()
    }
}

/// The finalizer captures for the money shadow only where it is armed and
/// not off (Sol R4-3): the panic latch, or the scope's last page (or the
/// cycle before its first parse, `seed_shadow_off`) saw the local kill
/// switch. In tests: a transcript under the parent of an enabled
/// support directory (fixtures keep both side by side); in production:
/// always.
pub(crate) fn capture_armed(path: &Path) -> Option<PathBuf> {
    if SHADOW_PANICKED.load(Ordering::Acquire) {
        return None;
    }
    #[cfg(test)]
    let scope = SHADOW_ENABLED_FOR_TEST
        .lock()
        .expect("shadow control")
        .iter()
        .find(|dir| dir.parent().is_some_and(|base| path.starts_with(base)))
        .cloned();
    #[cfg(not(test))]
    let scope = {
        let _ = path;
        Some(PathBuf::new())
    };
    scope.filter(|scope| !SHADOW_OFF.lock().is_ok_and(|off| off.contains_key(scope)))
}

/// Scopes whose last page found the shadow off (the kill switch file), and
/// the last day an off page published its false coverage row.
static SHADOW_OFF: Mutex<BTreeMap<PathBuf, String>> = Mutex::new(BTreeMap::new());
/// Scopes whose kill switch was checked before their first parse.
static SHADOW_SEEDED: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

/// Once per process and scope, before the cycle's first parse: a kill
/// switch present at start turns capture off before any page has seen it
/// (StateMissing r3), so it also stops a capture that fails at startup. The
/// scope's first off page then publishes its false row as usual.
pub(crate) fn seed_shadow_off(support_dir: &Path) {
    let scope = shadow_scope(support_dir);
    capture::begin_page(&scope);
    let first = SHADOW_SEEDED
        .lock()
        .is_ok_and(|mut seeded| seeded.insert(scope.clone()));
    if first && support_dir.join(SHADOW_OFF_FILE).exists() {
        if let Ok(mut off) = SHADOW_OFF.lock() {
            off.entry(scope).or_default();
        }
    }
}

/// The shadow is off for `support_dir` (panic latch or kill switch): the
/// scope stops capturing, its waiting captures are dropped, and the first
/// off page of each day hands the writer one false coverage row
/// (StateMissing B), so a day the shadow skipped part of never reads
/// complete.
fn shadow_off(support_dir: &Path, now: u64) -> bool {
    let scope = shadow_scope(support_dir);
    let off = SHADOW_PANICKED.load(Ordering::Acquire) || support_dir.join(SHADOW_OFF_FILE).exists();
    let day = day_stamp(now).unwrap_or_default();
    let first_today = SHADOW_OFF.lock().is_ok_and(|mut scopes| {
        if off {
            scopes.insert(scope.clone(), day.clone()).as_ref() != Some(&day)
        } else {
            scopes.remove(&scope);
            false
        }
    });
    if off {
        capture::purge_before(&scope, Instant::now());
    }
    if first_today {
        guarded(|| publish_off(support_dir, now));
    }
    off
}

/// An off page's false coverage row, straight to the writer (no page, no
/// ledger). A refused handoff owes the day its row in memory.
fn publish_off(support_dir: &Path, now: u64) {
    let Some(reservation) = ShadowReservation::admit(1024) else {
        owe_coverage(support_dir, now, false);
        return;
    };
    let job = WriteJob {
        support_dir: support_dir.to_path_buf(),
        jsonl: JsonlBatch {
            now,
            fault: PageFault::None,
            families: Vec::new(),
            coverage: CoverageRow {
                row: "page",
                v: JSONL_VERSION,
                observed_unix: now,
                coverage_complete: false,
                families: 0,
                snapshot: 0,
                page_families: 0,
                written: 0,
                unchanged: 0,
                failed: 0,
                holder_view: false,
                families_incomplete: 0,
                refused: true,
                truncated: false,
                telemetry_sweep_complete: false,
                rows_unavailable_roots: 0,
                dropped: false,
            },
            buffer_bytes: 0,
        },
        memos: Vec::new(),
        save: None,
        reservations: vec![reservation],
    };
    if store::submit_unledgered(job).is_err() {
        owe_coverage(support_dir, now, false);
    }
}

/// Faults a test injects at the page's last gates (the caller's thread).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum PageFault {
    None,
    /// The deadline passes just before the families are handed over.
    LateAtHandOff,
    /// The batch's admission is refused.
    BatchRefused,
    WriteFailure,
    SyncFailure,
    SaveFailure,
    LostAck,
}

#[cfg(test)]
thread_local! {
    static PAGE_FAULT: std::cell::Cell<PageFault> = const { std::cell::Cell::new(PageFault::None) };
}

#[cfg(test)]
pub(crate) fn set_page_fault_for_test(fault: PageFault) {
    PAGE_FAULT.with(|current| current.set(fault));
}

fn current_fault() -> PageFault {
    #[cfg(test)]
    {
        PAGE_FAULT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        PageFault::None
    }
}

fn faulted(fault: PageFault) -> bool {
    #[cfg(test)]
    {
        PAGE_FAULT.with(|current| current.get()) == fault
    }
    #[cfg(not(test))]
    {
        let _ = fault;
        false
    }
}

// ---------------------------------------------------------------- admission

static SHADOW_RESERVED: AtomicUsize = AtomicUsize::new(0);

/// Transient admission: held while the work runs, released on drop.
pub(crate) struct ShadowReservation(usize);

impl ShadowReservation {
    pub(crate) fn admit(bytes: usize) -> Option<Self> {
        SHADOW_RESERVED
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                reserved
                    .checked_add(bytes)
                    .filter(|total| *total <= SHADOW_MEMORY_CEILING_BYTES)
            })
            .ok()
            .map(|_| Self(bytes))
    }

    pub(crate) fn bytes(&self) -> usize {
        self.0
    }
}

impl Drop for ShadowReservation {
    fn drop(&mut self) {
        SHADOW_RESERVED.fetch_sub(self.0, Ordering::AcqRel);
    }
}

/// A page's admission that grows in steps: every step is admitted before
/// the memory it covers is allocated.
struct ShadowBudget {
    reservations: Vec<ShadowReservation>,
    granted: usize,
    used: usize,
}

impl ShadowBudget {
    fn new(base: ShadowReservation) -> Self {
        let granted = base.0;
        Self {
            reservations: vec![base],
            granted,
            used: granted,
        }
    }

    /// Admit `bytes` more; false (nothing admitted) when the ceiling refuses.
    fn charge(&mut self, bytes: usize) -> bool {
        let used = self.used.saturating_add(bytes);
        if used > self.granted {
            let step = (used - self.granted).max(GROWTH_STEP_BYTES);
            let Some(reservation) = ShadowReservation::admit(step) else {
                return false;
            };
            self.granted += step;
            self.reservations.push(reservation);
        }
        self.used = used;
        true
    }
}

// ---------------------------------------------------------------- counts

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeRequestMoneyShadowCounts {
    pub(crate) families: u64,
    pub(crate) families_equal: u64,
    pub(crate) families_differ_tokens: u64,
    pub(crate) families_differ_requests: u64,
    pub(crate) families_differ_grains: u64,
    pub(crate) families_union_partial: u64,
    pub(crate) families_unbuilt: u64,
    pub(crate) families_coverage_complete: u64,
    pub(crate) certificate_mismatch: u64,
    pub(crate) units_counted: u64,
    pub(crate) units_owned: u64,
    pub(crate) units_telemetry_proven: u64,
    pub(crate) units_policy_owned: u64,
    pub(crate) units_two_owner_won: u64,
    pub(crate) units_idless: u64,
    pub(crate) units_removed: u64,
    pub(crate) units_two_owner_lost: u64,
    pub(crate) units_undecided: u64,
    pub(crate) undecided_overflow: u64,
    pub(crate) undecided_collision: u64,
    pub(crate) undecided_scope: u64,
    pub(crate) undecided_message_unknown: u64,
    pub(crate) undecided_telemetry_unswept: u64,
    pub(crate) undecided_telemetry_order: u64,
    pub(crate) undecided_trace_unavailable: u64,
    pub(crate) undecided_stale_holder: u64,
    pub(crate) undecided_births: u64,
    pub(crate) undecided_holder_view: u64,
    pub(crate) unchanged: u64,
    pub(crate) capture_us: u64,
    pub(crate) writer_us: u64,
    pub(crate) save_bytes_today: u64,
    pub(crate) units_immature: u64,
    pub(crate) units_matched: u64,
    pub(crate) units_matched_unpriced: u64,
    pub(crate) units_matched_token_mismatch: u64,
    pub(crate) units_message: u64,
    pub(crate) units_conflict_removed: u64,
    pub(crate) units_added_to_reported: u64,
    pub(crate) reported_row_copies: u64,
    pub(crate) owned_after_retirement: u64,
    pub(crate) possible_retired_copies: u64,
    pub(crate) side_calls: u64,
    pub(crate) side_calls_unpriced: u64,
    pub(crate) side_calls_immature: u64,
    pub(crate) side_calls_two_owner_won: u64,
    pub(crate) side_calls_two_owner_lost: u64,
    pub(crate) side_calls_in_live_body: u64,
    pub(crate) side_calls_moved: u64,
    pub(crate) side_calls_unkeyed: u64,
    pub(crate) side_calls_held_by_absent_member: u64,
    pub(crate) side_call_member_unknown: u64,
    /// Live usage no unit accounts for (the `unexplained` grains).
    pub(crate) unexplained_tokens: u64,
    pub(crate) unbuilt_no_key: u64,
    pub(crate) unbuilt_no_capture: u64,
    pub(crate) unbuilt_capture_refused: u64,
    pub(crate) unbuilt_no_trace: u64,
    pub(crate) unbuilt_placement: u64,
    pub(crate) unbuilt_residue_negative: u64,
    pub(crate) rows_live_roots: u64,
    pub(crate) rows_refused: u64,
    pub(crate) rows_conflicting: u64,
    pub(crate) rows_unavailable_roots: u64,
    pub(crate) tokens_old: u64,
    pub(crate) tokens_new: u64,
    pub(crate) tokens_removed: u64,
    pub(crate) tokens_held: u64,
    pub(crate) tokens_immature: u64,
    pub(crate) tokens_unexplained: u64,
    pub(crate) requests_old: u64,
    pub(crate) requests_new: u64,
    pub(crate) holders_compared: u64,
    pub(crate) admission_bytes: u64,
    /// The page's largest admission held at once (its grown budget and its
    /// batch's rows).
    pub(crate) admitted_peak_bytes: u64,
    pub(crate) refused_budget: u64,
    /// The page's work ran past its deadline: refused, nothing written but
    /// the ledger's own progress.
    pub(crate) refused_deadline: u64,
    /// The writer is still loading this support directory's ledger.
    pub(crate) ledger_loading: u64,
    /// No writer, or the ledger is held elsewhere.
    pub(crate) ledger_unavailable: u64,
    /// The ledger load found a missing or corrupt shard (debt).
    pub(crate) ledger_load_damaged: u64,
    pub(crate) message_records_written: u64,
    pub(crate) message_records_refused: u64,
    pub(crate) message_records_pruned: u64,
    pub(crate) ledger_save_shards: u64,
    pub(crate) ledger_save_bytes: u64,
    /// The page's dirty shards were not admitted (they wait).
    pub(crate) ledger_save_refused: u64,
    /// The page deadline passed while serializing shards (they wait).
    pub(crate) ledger_save_late: u64,
    /// Dirty shards larger than one page's save bound (never written; no
    /// certificate is saved over them).
    pub(crate) ledger_save_oversized: u64,
    /// Ledger loads given up for want of admission (process total).
    pub(crate) ledger_loads_refused: u64,
    /// The writer's outbox was full: the batch was dropped.
    pub(crate) batch_dropped: u64,
    pub(crate) captures_taken: u64,
    pub(crate) captures_purged: u64,
    pub(crate) capture_reserved_bytes: u64,
    pub(crate) work_stopped: u64,
    pub(crate) telemetry_retired_pressure: u64,
    pub(crate) family_memos_dropped: u64,
    /// Memos not advanced because their batch's rows were not all written
    /// (reported by the page after the write).
    pub(crate) family_memos_withheld: u64,
    pub(crate) removed_change_available: u64,
    pub(crate) removed_change_unavailable: u64,
    /// The writer's JSONL outcome of the batches finished since the last
    /// page (rows are written after the page, outside the sync lock).
    pub(crate) jsonl_rows: u64,
    pub(crate) jsonl_truncated: u64,
    pub(crate) jsonl_sealed: u64,
    pub(crate) jsonl_failed: u64,
    /// False coverage rows written for earlier dropped or unwritten batches.
    pub(crate) jsonl_owed_written: u64,
    /// Rows this page handed to the writer.
    pub(crate) jsonl_queued: u64,
    /// Members not in the page whose census `u` was known / unknown
    /// (advisory, shadow only).
    pub(crate) absent_members_old_known: u64,
    pub(crate) absent_members_old_unknown: u64,
    pub(crate) coverage_complete: u64,
    /// The ledger state walk ran out of the page's time: its walked fields
    /// are the last walk's (or zero).
    pub(crate) state_counts_late: u64,
    /// T-empty units a held-unbuilt-older rule would hold (SOURCE, count
    /// only): an unbuilt file of the unit's group born before its holder,
    /// or of unknown birth.
    pub(crate) undecided_unbuilt_older: u64,
    /// Time under the sync lock, every phase included but this line's write.
    pub(crate) elapsed_us: u64,
}

impl ClaudeRequestMoneyShadowCounts {
    pub(crate) fn note_undecided(&mut self, reason: ClaudeUndecidedBy) {
        self.units_undecided += 1;
        let slot = match reason {
            ClaudeUndecidedBy::Overflow => &mut self.undecided_overflow,
            ClaudeUndecidedBy::Collision => &mut self.undecided_collision,
            ClaudeUndecidedBy::Scope => &mut self.undecided_scope,
            ClaudeUndecidedBy::MessageUnknown => &mut self.undecided_message_unknown,
            ClaudeUndecidedBy::TelemetryUnswept => &mut self.undecided_telemetry_unswept,
            ClaudeUndecidedBy::TelemetryOrder => &mut self.undecided_telemetry_order,
            ClaudeUndecidedBy::TraceUnavailable => &mut self.undecided_trace_unavailable,
            ClaudeUndecidedBy::StaleHolder => &mut self.undecided_stale_holder,
            ClaudeUndecidedBy::Births => &mut self.undecided_births,
            ClaudeUndecidedBy::HolderView => &mut self.undecided_holder_view,
        };
        *slot += 1;
    }

    pub(crate) fn note_counted(&mut self, by: ClaudeCountedBy) {
        self.units_counted += 1;
        let slot = match by {
            ClaudeCountedBy::Owned => &mut self.units_owned,
            ClaudeCountedBy::TelemetryProven => &mut self.units_telemetry_proven,
            ClaudeCountedBy::PolicyOwned => &mut self.units_policy_owned,
            ClaudeCountedBy::TwoOwnerWinner => &mut self.units_two_owner_won,
            ClaudeCountedBy::Idless => &mut self.units_idless,
        };
        *slot += 1;
    }
}

#[derive(Debug, Serialize)]
struct ShadowLine<'a> {
    counting: &'static str,
    census_complete: bool,
    counts: &'a ClaudeRequestMoneyShadowCounts,
    tail: &'a ClaudeTelemetryTailCounts,
    rows: &'a ClaudeRowCounts,
    scope: &'a claude_request_ledger::ClaudeScopeDebt,
    ledger: &'a claude_request_ledger::ClaudeLedgerStateCounts,
}

// ---------------------------------------------------------------- output

fn hashed_id(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"claude_request_money_shadow:v1\0");
    digest.update(value.as_bytes());
    format!("{:x}", digest.finalize())[..16].to_owned()
}

/// One side of a B1 grain row.
#[derive(Debug, Serialize)]
struct GrainSideRow {
    requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_5m_tokens: u64,
    cache_creation_1h_tokens: u64,
    unattributed_total_tokens: u64,
    reasoning_output_tokens: u64,
    cost_usd: Option<String>,
}

impl From<&ClaudeGrainSide> for GrainSideRow {
    fn from(side: &ClaudeGrainSide) -> Self {
        Self {
            requests: side.requests,
            input_tokens: side.tokens.input,
            output_tokens: side.tokens.output,
            cache_read_tokens: side.tokens.cache_read,
            cache_creation_5m_tokens: side.tokens.cache_5m,
            cache_creation_1h_tokens: side.tokens.cache_1h,
            unattributed_total_tokens: side.tokens.unattributed,
            reasoning_output_tokens: side.tokens.reasoning,
            cost_usd: side.cost().map(usd_string),
        }
    }
}

/// One differing slice (B1 `grain` row). `snapshot` orders a family's
/// bodies: the reader keeps only each family's latest snapshot.
#[derive(Debug, Serialize)]
struct GrainRow<'a> {
    row: &'static str,
    v: u8,
    snapshot: u64,
    family: &'a str,
    session: String,
    owner: Option<String>,
    hour: &'a str,
    model: &'a str,
    selector: &'a BTreeMap<String, String>,
    request_usage_origin: Option<body::ClaudeRequestUsageOrigin>,
    category: body::ClaudeGrainCategory,
    old: GrainSideRow,
    new: GrainSideRow,
}

#[derive(Debug, Serialize)]
struct RequestsTokens {
    requests: u64,
    tokens: u64,
}

impl From<&ClaudeMoneyTotals> for RequestsTokens {
    fn from(totals: &ClaudeMoneyTotals) -> Self {
        Self {
            requests: totals.requests,
            tokens: totals.tokens,
        }
    }
}

#[derive(Debug, Serialize)]
struct SignedRequestsTokens {
    requests: i128,
    tokens: i128,
}

/// One family's body (B1 `family` row).
#[derive(Debug, Serialize)]
struct FamilyRow {
    row: &'static str,
    v: u8,
    counting: &'static str,
    snapshot: u64,
    observed_unix: u64,
    family: String,
    revision: String,
    census: &'static str,
    census_reason: Option<coverage::CensusReason>,
    key_statuses: BTreeMap<&'static str, u64>,
    p1_reasons: Vec<&'static str>,
    old_available: bool,
    category: ClaudeFamilyCategory,
    coverage_complete: bool,
    members_built: usize,
    members_total: usize,
    old: RequestsTokens,
    new: RequestsTokens,
    /// New minus old: the net usage change (never a removal).
    net_token_change: i128,
    net_request_change: i128,
    /// Cumulative removals the new body declares.
    removed: RequestsTokens,
    /// Removals since the previous complete body over the same union, or
    /// null with `removed_change_unavailable` naming why.
    removed_change: Option<SignedRequestsTokens>,
    removed_change_basis: Option<&'static str>,
    /// The `snapshot` of the family row the change is measured from.
    removed_change_basis_snapshot: Option<u64>,
    removed_change_unavailable: Option<&'static str>,
    held: RequestsTokens,
    held_reasons: Vec<&'static str>,
    immature: RequestsTokens,
    unexplained: RequestsTokens,
    grains: usize,
    /// Census `u` of the members not in this page, and how many were unknown.
    absent_old: RequestsTokens,
    absent_old_unknown: u64,
}

/// One family's rows as the page hands them to the writer: its family row
/// and its differing slices, serialized there (outside the sync lock).
pub(crate) struct FamilyRows {
    row: FamilyRow,
    grains: BTreeMap<ClaudeGrainKey, (ClaudeGrainSide, ClaudeGrainSide)>,
}

impl FamilyRows {
    /// Rows this family writes: its grains and its family row.
    fn rows(&self) -> u64 {
        self.grains.len() as u64 + 1
    }

    /// What these rows hold once they move to the writer (Sol R5-2): a
    /// fixed share per family and grain, plus every owned string and
    /// selector entry of the grain keys at its capacity, so a long model or
    /// selector is charged in full.
    fn owned_bytes(&self) -> usize {
        self.grains.keys().fold(
            FAMILY_BYTES.saturating_add(self.row.family.capacity()),
            |bytes, key| {
                let (bucket_start, model, selector) = &key.live;
                let selector = selector.iter().fold(0_usize, |bytes, (name, value)| {
                    bytes
                        .saturating_add(name.capacity())
                        .saturating_add(value.capacity())
                        .saturating_add(capture::MAP_ENTRY_BYTES)
                });
                bytes
                    .saturating_add(GRAIN_BYTES)
                    .saturating_add(key.member.capacity())
                    .saturating_add(key.owner.capacity())
                    .saturating_add(bucket_start.capacity())
                    .saturating_add(model.capacity())
                    .saturating_add(selector)
            },
        )
    }
}

/// The page's custody flag (B1 `coverage` row).
#[derive(Debug, Clone, Serialize)]
struct CoverageRow {
    row: &'static str,
    v: u8,
    observed_unix: u64,
    coverage_complete: bool,
    families: u64,
    snapshot: u64,
    page_families: u64,
    written: u64,
    unchanged: u64,
    failed: u64,
    holder_view: bool,
    families_incomplete: u64,
    refused: bool,
    truncated: bool,
    telemetry_sweep_complete: bool,
    rows_unavailable_roots: u64,
    /// Owed by a page whose batch was dropped or not written.
    dropped: bool,
}

impl CoverageRow {
    /// The false row a dropped or unwritten batch owes its day.
    fn owed(observed_unix: u64) -> Self {
        Self {
            row: "page",
            v: JSONL_VERSION,
            observed_unix,
            coverage_complete: false,
            families: 0,
            snapshot: 0,
            page_families: 0,
            written: 0,
            unchanged: 0,
            failed: 0,
            holder_view: false,
            families_incomplete: 0,
            refused: false,
            truncated: false,
            telemetry_sweep_complete: false,
            rows_unavailable_roots: 0,
            dropped: true,
        }
    }
}

fn undecided_wire(reason: ClaudeUndecidedBy) -> &'static str {
    match reason {
        ClaudeUndecidedBy::Overflow => "overflow",
        ClaudeUndecidedBy::Collision => "collision",
        ClaudeUndecidedBy::Scope => "scope",
        ClaudeUndecidedBy::MessageUnknown => "message_unknown",
        ClaudeUndecidedBy::TelemetryUnswept => "telemetry_unswept",
        ClaudeUndecidedBy::TelemetryOrder => "telemetry_order",
        ClaudeUndecidedBy::TraceUnavailable => "trace_unavailable",
        ClaudeUndecidedBy::StaleHolder => "stale_holder",
        ClaudeUndecidedBy::Births => "births",
        ClaudeUndecidedBy::HolderView => "holder_view",
    }
}

#[cfg(test)]
thread_local! {
    static SHADOW_LINES: std::cell::RefCell<Vec<serde_json::Value>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn take_shadow_lines_for_test() -> Vec<serde_json::Value> {
    SHADOW_LINES.with(|lines| std::mem::take(&mut *lines.borrow_mut()))
}

fn emit_line(line: &ShadowLine<'_>) {
    let Ok(json) = serde_json::to_string(line) else {
        return;
    };
    #[cfg(test)]
    SHADOW_LINES.with(|lines| {
        if let Ok(value) = serde_json::from_str(&json) {
            lines.borrow_mut().push(value);
        }
    });
    // A log sink failure must not change collection.
    let _ = writeln!(
        std::io::stderr().lock(),
        "local snapshot sync: claude request money shadow {json}"
    );
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Process-monotonic snapshot id: wall-clock microseconds, never repeated.
fn next_snapshot() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as u64);
    LAST.fetch_max(now, Ordering::AcqRel);
    LAST.fetch_add(1, Ordering::AcqRel) + 1
}

/// When each scope's previous shadow ran: captures deposited before it and
/// still not taken belonged to an earlier page and are dropped.
static LAST_SHADOW: Mutex<BTreeMap<PathBuf, Instant>> = Mutex::new(BTreeMap::new());

// ---------------------------------------------------------------- shadow

/// The P1 shadow of one authoritative Claude page. Reads the page's final
/// items, the index, the strict rows and traces the live path already loaded
/// and the captures of this page's parses; mutates only its own ledger. Never
/// fails the page.
#[allow(clippy::too_many_arguments)]
pub(crate) fn shadow_page(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    census_complete: bool,
    coverage: &dyn FamilyCoverage,
) {
    let now = now_unix();
    if !shadow_enabled(support_dir) || shadow_off(support_dir, now) {
        return;
    }
    guarded(|| {
        shadow_page_with_coverage(
            support_dir,
            snapshots,
            index,
            api_report,
            trace_report,
            coverage,
            census_complete,
            now,
        );
    });
}

/// A panic of the shadow ends in the shadow: it is counted, the shadow is
/// off for the rest of the process, and the live page goes on (every hold
/// it took is released by unwinding).
static SHADOW_PANICKED: AtomicBool = AtomicBool::new(false);
static SHADOW_PANICS: AtomicU64 = AtomicU64::new(0);

fn guarded(run: impl FnOnce()) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).is_ok() {
        return;
    }
    SHADOW_PANICKED.store(true, Ordering::Release);
    let panics = SHADOW_PANICS.fetch_add(1, Ordering::AcqRel) + 1;
    let _ = writeln!(
        std::io::stderr().lock(),
        "local snapshot sync: claude request money shadow off after a panic {{\"shadow_panics\":{panics}}}"
    );
}

#[cfg(test)]
pub(crate) fn guarded_for_test(run: impl FnOnce()) -> (bool, u64) {
    guarded(run);
    let panicked = SHADOW_PANICKED.swap(false, Ordering::AcqRel);
    (panicked, SHADOW_PANICS.load(Ordering::Acquire))
}

/// Index keys of each page (root, member) and the indexed members of each
/// page root.
type FamilyMembers = (
    BTreeMap<(String, String), Vec<String>>,
    BTreeMap<String, BTreeSet<String>>,
);

/// None when the deadline passed.
fn family_members(
    index: &ScanIndex,
    roots: &BTreeSet<&str>,
    deadline: Instant,
) -> Option<FamilyMembers> {
    let mut member_keys = BTreeMap::<(String, String), Vec<String>>::new();
    let mut members = BTreeMap::<String, BTreeSet<String>>::new();
    for key in index.files.keys() {
        if Instant::now() >= deadline {
            return None;
        }
        let Some((root, member)) = claude_index_path_family_member(Path::new(key)) else {
            continue;
        };
        if !roots.contains(root.as_str()) || index.confirmed_empty_files.contains(key) {
            continue;
        }
        members
            .entry(root.clone())
            .or_default()
            .insert(member.clone());
        member_keys
            .entry((root, member))
            .or_default()
            .push(key.clone());
    }
    Some((member_keys, members))
}

/// What one page hands to the writer and the log.
struct PageEnd<'a> {
    support_dir: &'a Path,
    now: u64,
    census_complete: bool,
    started: Instant,
    /// The page deadline: the ledger's save stops at it too.
    deadline: Instant,
    tail: ClaudeTelemetryTailCounts,
    rows: ClaudeRowCounts,
    scope: claude_request_ledger::ClaudeScopeDebt,
}

#[cfg(test)]
pub(crate) fn shadow_page_at(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    census_complete: bool,
    now: u64,
) -> ClaudeRequestMoneyShadowCounts {
    store::prime_credit_for_test(support_dir, utc_day(now));
    shadow_page_ready_for_test(
        support_dir,
        snapshots,
        index,
        api_report,
        trace_report,
        census_complete,
        now,
    )
}

/// The actual synchronous page, without the fixture's writer-credit wait.
#[cfg(test)]
pub(crate) fn shadow_page_ready_for_test(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    census_complete: bool,
    now: u64,
) -> ClaudeRequestMoneyShadowCounts {
    let coverage = coverage::InterimFamilyCoverage {
        census_complete,
        ..Default::default()
    };
    shadow_page_with_coverage(
        support_dir,
        snapshots,
        index,
        api_report,
        trace_report,
        &coverage,
        census_complete,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn shadow_page_with_coverage(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    coverage_view: &dyn FamilyCoverage,
    census_complete: bool,
    now: u64,
) -> ClaudeRequestMoneyShadowCounts {
    let started = Instant::now();
    let absolute_deadline = started + PAGE_MAX_ELAPSED;
    let deadline = absolute_deadline - PAGE_CLOSE_RESERVE;
    let snapshot = next_snapshot();
    let mut counts = ClaudeRequestMoneyShadowCounts {
        capture_us: capture::take_capture_us(),
        capture_reserved_bytes: capture::capture_reserved() as u64,
        ..Default::default()
    };
    let mut end = PageEnd {
        support_dir,
        now,
        census_complete,
        started,
        deadline,
        tail: Default::default(),
        rows: Default::default(),
        scope: Default::default(),
    };
    let scope_key = shadow_scope(support_dir);
    let Some(root_funds) = ShadowReservation::admit(snapshots.len().saturating_mul(64)) else {
        counts.refused_budget = 1;
        return refuse(&end, None, index, snapshots.len(), counts);
    };
    let roots = snapshots
        .iter()
        .map(claude_snapshot_family_root_ref)
        .collect::<BTreeSet<_>>();
    // Pre-admit metadata, every failure row, memos and writer buffer. No
    // family-specific scratch is charged until that family's turn.
    let key_bytes = index.files.keys().map(String::len).sum::<usize>();
    let residue_bytes = index
        .claude_request_census
        .records()
        .map(|(key, _)| key.len())
        .sum::<usize>();
    let page_claim_rows = roots
        .iter()
        .filter_map(|root| api_report.evidence.get(*root))
        .map(Vec::len)
        .sum::<usize>();
    let admission = snapshots
        .len()
        .saturating_mul(FAMILY_BYTES + 256)
        .saturating_add(claude_request_ledger::scope_bound(
            index.files.len() + index.claude_request_census.records().count(),
            key_bytes + residue_bytes,
        ))
        .saturating_add(key_bytes.saturating_mul(2))
        .saturating_add(page_claim_rows.saturating_mul(PAGE_HASH_BYTES))
        .saturating_add(
            JSONL_WRITE_BUFFER_BYTES
                + 1024
                + tail_fixed_memory(&ClaudeTelemetryTailBudget::default()),
        );
    counts.admission_bytes = admission.saturating_add(root_funds.bytes()) as u64;
    let Some(base) = ShadowReservation::admit(admission) else {
        counts.refused_budget = 1;
        purge_captures(&scope_key, &mut counts);
        return refuse(&end, None, index, snapshots.len(), counts);
    };
    counts.admitted_peak_bytes = SHADOW_RESERVED.load(Ordering::Acquire) as u64;
    let mut guard = match store::acquire(support_dir) {
        ClaudeLedgerAcquire::Ready(guard) => guard,
        acquired => {
            match acquired {
                ClaudeLedgerAcquire::Loading => counts.ledger_loading = 1,
                _ => counts.ledger_unavailable = 1,
            }
            return refuse(&end, None, index, roots.len(), counts);
        }
    };
    let ledger: &mut ClaudeLedger = &mut guard;
    apply_results(support_dir, ledger, &mut counts);
    if std::mem::take(&mut ledger.load_damaged) {
        counts.ledger_load_damaged = 1;
        drop_certificate(ledger);
    }
    // Telemetry runs first and shares the caller's absolute time bound.
    let mut work = ClaudeLedgerWork::new(WORK_MAX_BYTES, WORK_MAX_STATS, deadline);
    let unloaded = roots
        .iter()
        .copied()
        .filter(|root| !api_report.evidence.contains_key(*root))
        .collect::<Vec<_>>();
    let (tail, root_states) = ClaudeTelemetryTail::advance(
        support_dir,
        ledger,
        now,
        &ClaudeTelemetryTailBudget::default(),
        &unloaded,
        &mut work,
    );
    end.tail = tail;
    counts.work_stopped = u64::from(work.stopped);
    counts.telemetry_retired_pressure =
        claude_request_ledger::retire_telemetry_under_pressure(ledger, deadline);
    if counts.telemetry_retired_pressure > 0 {
        drop_certificate(ledger);
    }
    prune_message_records(ledger, index, &mut counts);
    // Global optional work may run out of time too. Its absence closes
    // every body, while the pre-admitted family failure rows still publish.
    let (member_keys, indexed_members) =
        family_members(index, &roots, deadline).unwrap_or_default();
    let mut by_root = BTreeMap::<&str, Vec<&SnapshotItem>>::new();
    let mut captures = BTreeMap::new();
    let mut groups_owned = BTreeSet::new();
    for item in snapshots {
        let root = claude_snapshot_family_root_ref(item);
        by_root.entry(root).or_default().push(item);
        if Instant::now() >= deadline {
            continue;
        }
        if let Some(keys) = member_keys
            .get(&(root.to_owned(), item.source_session_id.clone()))
            .filter(|keys| keys.len() == 1)
        {
            let key = &keys[0];
            if let Some(group) = claude_request_ledger::claude_project_group(key) {
                groups_owned.insert(group.to_owned());
            }
            let fingerprints = [
                item.source_file_fingerprint.as_deref(),
                index
                    .files
                    .get(key)
                    .map(|entry| entry.source_file_fingerprint.as_str()),
            ];
            if let Some((fingerprint, capture)) =
                fingerprints.iter().flatten().find_map(|fingerprint| {
                    capture::take_capture(&scope_key, key, fingerprint)
                        .map(|capture| (*fingerprint, capture))
                })
            {
                counts.captures_taken += 1;
                note_message_record(ledger, index, key, fingerprint, &capture, &mut counts);
                captures.insert((root.to_owned(), item.source_session_id.clone()), capture);
            }
        }
    }
    purge_captures(&scope_key, &mut counts);
    let page_groups = groups_owned.iter().map(String::as_str).collect();
    let scope = ClaudeLedgerScope::build(index, ledger.census(), &page_groups, &roots, deadline);
    if let Some(scope) = &scope {
        end.scope = scope.debt;
    }
    let holder_view = ClaudeHolderView::of(coverage_view);
    // Retain cross-root live claims even when another family is oversized.
    let root_keys = roots
        .iter()
        .map(|root| (*root, telemetry_key(root)))
        .collect::<BTreeMap<_, _>>();
    let mut page_claims = BTreeMap::<u64, Vec<&str>>::new();
    let mut sessions = BTreeMap::new();
    let mut first_event = BTreeMap::new();
    for (&root, key) in &root_keys {
        sessions.insert(key.clone(), root.to_owned());
        if let Some(rows) = api_report.evidence.get(root) {
            for row in rows {
                if Instant::now() >= deadline {
                    break;
                }
                page_claims
                    .entry(claude_request_hash(&row.request_id))
                    .or_default()
                    .push(key);
                let clock = crate::claude_local_otel::telemetry_tail::event_unix(&row.observed_at);
                first_event
                    .entry(key.clone())
                    .and_modify(|at: &mut u64| *at = (*at).min(clock))
                    .or_insert(clock);
            }
        }
    }
    let mut order = roots.iter().copied().collect::<Vec<_>>();
    order.sort_by_key(|root| {
        ledger
            .get(&family_key(root))
            .map_or(0, |record| record.window())
    });
    let mut families = Vec::with_capacity(roots.len());
    let mut memos = Vec::with_capacity(roots.len());
    let mut reservations = vec![base, root_funds];
    let mut failed = 0;
    let mut written = 0;
    let mut incomplete = 0;
    for root in order {
        if Instant::now() >= absolute_deadline {
            // If exceptional closing work itself exhausts the total, use
            // whole-page refusal instead of carrying on under the live lock.
            counts.refused_deadline = 1;
            drop(families);
            drop(reservations);
            return refuse(&end, Some(ledger), index, roots.len(), counts);
        }
        // Check time before any content walk; remaining roots still flow
        // through the pre-admitted failure publication and memo bookkeeping.
        let expired = scope.is_none() || preflight_check(deadline).is_err();
        let items = &by_root[root];
        let mut family_captures = BTreeMap::new();
        for item in items.iter().take(if expired { 0 } else { items.len() }) {
            if Instant::now() >= deadline {
                break;
            }
            let key = (root.to_owned(), item.source_session_id.clone());
            if let Some(capture) = captures.remove(&key) {
                family_captures.insert(key, capture);
            }
        }
        let scratch = if expired {
            Err("deadline")
        } else {
            family_preflight(
                root,
                items,
                &family_captures,
                ledger,
                api_report,
                trace_report,
                deadline,
            )
        };
        let state = coverage_view.family(root);
        let mut basis = None;
        let mut rows;
        let mut owned_reservation = None;
        let slice = scratch.and_then(|scratch| ShadowReservation::admit(scratch).ok_or("memory"));
        match slice {
            Ok(reservation) => {
                let mut budget = ShadowBudget::new(reservation);
                let result = build_slice(
                    root,
                    items,
                    &member_keys,
                    &indexed_members,
                    family_captures,
                    ledger,
                    index,
                    api_report,
                    trace_report,
                    &root_states,
                    &page_claims,
                    &first_event,
                    &sessions,
                    scope
                        .as_ref()
                        .expect("admitted body requires a complete scope walk"),
                    holder_view,
                    &mut budget,
                    &mut end,
                    &mut counts,
                );
                counts.admitted_peak_bytes = counts
                    .admitted_peak_bytes
                    .max(SHADOW_RESERVED.load(Ordering::Acquire) as u64);
                match result {
                    Ok((body, union, absent, unknown)) => {
                        (rows, basis) = family_rows(
                            root,
                            body,
                            union,
                            absent,
                            unknown,
                            state,
                            now,
                            snapshot,
                            ledger,
                            &mut counts,
                        );
                        // Scratch remains funded during handoff overlap.
                        if !rows.grains.is_empty() {
                            if let Some(owned) = ShadowReservation::admit(rows.owned_bytes()) {
                                owned_reservation = Some(owned);
                            } else {
                                rows.grains.clear();
                                rows.row.grains = 0;
                                rows.row.p1_reasons.push("memory");
                                rows.row.coverage_complete = false;
                                basis = None;
                            }
                        }
                    }
                    Err(reason) => {
                        rows =
                            failure_rows(root, reason, state, now, snapshot, ledger, &mut counts);
                    }
                }
            }
            Err(reason) => {
                rows = failure_rows(root, reason, state, now, snapshot, ledger, &mut counts);
            }
        }
        if !rows.row.old_available && !rows.row.p1_reasons.contains(&"deadline") {
            if let Some(members) = indexed_members.get(root) {
                if let Some(revision) = union_revision_by(members, deadline) {
                    rows.row.revision = hex_revision(&revision);
                }
                rows.row.members_total = members.len().max(items.len());
                rows.row.absent_old_unknown = members.len().saturating_sub(items.len()) as u64;
            }
        }
        let digest = if rows.row.p1_reasons.contains(&"deadline") {
            // Already a bounded failure row: never repeat body construction
            // or tallying after expiry.
            semantic_digest(&mut rows)
        } else if let Some(digest) = semantic_digest_by(&mut rows, Some(deadline)) {
            digest
        } else {
            // The body was built, but its full digest did not finish. Keep
            // known old totals, publish an explicit failure without grains,
            // and never install this body as a complete removal basis.
            counts.families_coverage_complete -= u64::from(rows.row.coverage_complete);
            rows.row.coverage_complete = false;
            rows.row.p1_reasons.push("deadline");
            rows.grains.clear();
            rows.row.grains = 0;
            rows.row.removed_change = None;
            rows.row.removed_change_basis = None;
            rows.row.removed_change_basis_snapshot = None;
            rows.row.removed_change_unavailable = Some("body_incomplete");
            basis = None;
            owned_reservation = None;
            semantic_digest(&mut rows)
        };
        let is_failed = !rows.row.p1_reasons.is_empty();
        incomplete += u64::from(!rows.row.coverage_complete);
        let key = family_key(root);
        let unchanged = !ledger.in_flight(&key)
            && ledger
                .get(&key)
                .and_then(ClaudeRequestCensusRecord::family_memo)
                .and_then(|(_, memo)| memo.published)
                .is_some_and(|published| {
                    published.utc_day == utc_day(now)
                        && published.epoch == process_epoch()
                        && published.digest == digest
                });
        // A row emitted without reaching optional family work does not
        // consume its scheduling turn. It leads the following page,
        // while publication metadata still records the actual page time.
        let scheduling_time = if expired {
            ledger.get(&key).map_or(0, |record| record.window())
        } else {
            now
        };
        memos.push(PendingMemo {
            key,
            basis: if unchanged { None } else { basis },
            observed_unix: scheduling_time,
            published: ClaudeFamilyPublication {
                utc_day: utc_day(now),
                digest,
                epoch: process_epoch(),
                attempted: now,
            },
            row: !unchanged,
        });
        if unchanged {
            counts.unchanged += 1;
        } else {
            failed += u64::from(is_failed);
            written += u64::from(!is_failed);
            if let Some(owned) = owned_reservation {
                reservations.push(owned);
            }
            families.push(rows);
        }
    }
    if faulted(PageFault::LateAtHandOff) || faulted(PageFault::BatchRefused) {
        counts.refused_deadline = u64::from(faulted(PageFault::LateAtHandOff));
        counts.refused_budget = u64::from(faulted(PageFault::BatchRefused));
        drop(families);
        drop(reservations);
        return refuse(&end, Some(ledger), index, roots.len(), counts);
    }
    counts.family_memos_dropped = drop_old_family_memos(ledger, now, deadline);
    let page_complete = incomplete == 0 && telemetry_certified(ledger) && holder_view.complete();
    counts.coverage_complete = u64::from(page_complete);
    let page = CoverageRow {
        row: "page",
        v: JSONL_VERSION,
        observed_unix: now,
        snapshot,
        page_families: roots.len() as u64,
        written,
        unchanged: counts.unchanged,
        failed,
        holder_view: holder_view.complete(),
        coverage_complete: page_complete,
        families: roots.len() as u64,
        families_incomplete: incomplete,
        refused: false,
        truncated: false,
        telemetry_sweep_complete: telemetry_certified(ledger),
        rows_unavailable_roots: counts.rows_unavailable_roots,
        dropped: false,
    };
    // Reuse the already admitted row and buffer storage; no unfunded gap.
    hand_off_reserved(
        &end,
        Some(ledger),
        families,
        page,
        memos,
        reservations,
        &mut counts,
    );
    emit(&end, Some(ledger), index, &mut counts);
    counts
}

/// Preflight charges borrowed input without copying it. Every nested walk
/// checks the same absolute deadline before touching the next item. Once
/// oversized, no remaining content is visited.
#[allow(clippy::too_many_arguments)]
fn family_preflight(
    root: &str,
    items: &[&SnapshotItem],
    captures: &BTreeMap<(String, String), ClaudeResponseCapture>,
    ledger: &ClaudeLedger,
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
    deadline: Instant,
) -> Result<usize, &'static str> {
    let mut bytes = 0_usize;
    let mut charge = |more: usize| {
        preflight_check(deadline)?;
        bytes = bytes.saturating_add(more);
        if bytes > SHADOW_MEMORY_CEILING_BYTES {
            Err("oversize")
        } else {
            Ok(())
        }
    };
    charge(0)?;
    for item in items {
        charge(
            item.claude_usage_occurrences
                .len()
                .saturating_mul(UNIT_BYTES + GRAIN_BYTES + PAGE_HASH_BYTES),
        )?;
        for (key, occurrence) in &item.claude_usage_occurrences {
            charge(
                key.len()
                    .saturating_add(occurrence.model.as_ref().map_or(0, String::len))
                    .saturating_add(occurrence.timestamp.as_ref().map_or(0, String::len))
                    .saturating_mul(16),
            )?;
        }
        for bucket in &item.usage_buckets {
            charge(bucket.model_usage.len().saturating_mul(LIVE_ROW_BYTES))?;
            for row in &bucket.model_usage {
                let fields = [
                    &row.auth_mode,
                    &row.billing_channel,
                    &row.billing_provider,
                    &row.gateway_provider,
                    &row.model_provider,
                    &row.subscription_product,
                ];
                charge(
                    bucket
                        .bucket_start
                        .len()
                        .saturating_add(row.model.len())
                        .saturating_add(
                            fields
                                .iter()
                                .map(|field| field.as_ref().map_or(0, String::len))
                                .sum::<usize>(),
                        )
                        .saturating_mul(16),
                )?;
                for (key, value) in &row.selector_context {
                    charge(key.len().saturating_add(value.len()).saturating_mul(16))?;
                }
            }
        }
    }
    for capture in captures.values() {
        charge(
            capture
                .units()
                .len()
                .saturating_mul(UNIT_BYTES + GRAIN_BYTES + PAGE_HASH_BYTES),
        )?;
    }
    if let Some(rows) = api.evidence.get(root) {
        charge(row_charge(rows.len()))?;
        for row in rows {
            charge(
                (row.request_id.len() + row.model.len() + row.speed.len() + row.effort.len())
                    .saturating_mul(16),
            )?;
        }
    } else {
        charge(row_charge(
            ledger
                .get(&telemetry_key(root))
                .map_or(0, |record| record.request_hashes().len()),
        ))?;
    }
    if let Some(rows) = trace.evidence.get(root) {
        charge(rows.len().saturating_mul(TRACE_ROW_BYTES))?;
        for row in rows {
            charge(
                row.request_id
                    .len()
                    .saturating_add(row.agent_id.len())
                    .saturating_mul(16),
            )?;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
thread_local! {
    static PREFLIGHT_CHECKS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(crate) fn preflight_checks_for_test(checks: Option<usize>) {
    PREFLIGHT_CHECKS.with(|current| current.set(checks));
}
fn preflight_check(deadline: Instant) -> Result<(), &'static str> {
    #[cfg(test)]
    if PREFLIGHT_CHECKS.with(|checks| match checks.get() {
        Some(0) => true,
        Some(left) => {
            checks.set(Some(left - 1));
            false
        }
        None => false,
    }) {
        return Err("deadline");
    }
    if Instant::now() >= deadline {
        Err("deadline")
    } else {
        Ok(())
    }
}

/// One family's scratch is admitted independently; the page scope is borrowed.
#[allow(clippy::too_many_arguments)]
fn build_slice(
    root: &str,
    items: &[&SnapshotItem],
    member_keys: &BTreeMap<(String, String), Vec<String>>,
    indexed_members: &BTreeMap<String, BTreeSet<String>>,
    mut captures: BTreeMap<(String, String), ClaudeResponseCapture>,
    ledger: &ClaudeLedger,
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    root_states: &BTreeMap<String, ClaudeRootTelemetry>,
    page_claims: &BTreeMap<u64, Vec<&str>>,
    first_event: &BTreeMap<String, u64>,
    sessions: &BTreeMap<String, String>,
    scope: &ClaudeLedgerScope,
    holder_view: ClaudeHolderView,
    budget: &mut ShadowBudget,
    end: &mut PageEnd<'_>,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) -> Result<(ClaudeRequestBody, [u8; 32], ClaudeMoneyTotals, u64), &'static str> {
    let deadline = end.deadline;
    let now = end.now;
    let roots = BTreeSet::from([root]);
    let items = items.to_vec();
    let key_of = |root: &str, member: &str| {
        member_keys
            .get(&(root.to_owned(), member.to_owned()))
            .filter(|keys| keys.len() == 1)
            .map(|keys| keys[0].clone())
    };
    // Rows: the live load's, else the facts the tail just brought current.
    let mut root_rows = BTreeMap::<&str, Option<ClaudeRootRows>>::new();
    for &root in &roots {
        if Instant::now() >= deadline {
            return Err("deadline");
        }
        let rows = match api_report.evidence.get(root) {
            Some(evidence) => {
                end.rows.roots_live += 1;
                let (rows, refused) = ClaudeRootRows::from_live(evidence, root, deadline);
                end.rows.rows_refused += refused;
                rows
            }
            None => match root_states.get(root) {
                Some(ClaudeRootTelemetry::Absent) => {
                    end.rows.roots_absent += 1;
                    Some(ClaudeRootRows::default())
                }
                Some(ClaudeRootTelemetry::Current) => match ledger.get(&telemetry_key(root)) {
                    Some(record) => match ClaudeRootRows::from_record_by(record, deadline) {
                        Some(rows) => {
                            end.rows.roots_from_facts += 1;
                            end.rows.rows_decoded += rows.len() as u64;
                            Some(rows)
                        }
                        None => {
                            end.rows.roots_unavailable += 1;
                            None
                        }
                    },
                    None => {
                        end.rows.roots_unavailable += 1;
                        None
                    }
                },
                _ => {
                    end.rows.roots_behind += 1;
                    None
                }
            },
        };
        root_rows.insert(root, rows);
    }
    for rows in root_rows.values().flatten() {
        end.rows.rows_conflicting += rows.conflicts;
    }
    counts.rows_live_roots = end.rows.roots_live;
    counts.rows_refused = end.rows.rows_refused;
    counts.rows_conflicting = end.rows.rows_conflicting;
    counts.rows_unavailable_roots = root_rows.values().filter(|rows| rows.is_none()).count() as u64;

    let mut traces = BTreeMap::<String, BTreeMap<u64, String>>::new();
    for &root in &roots {
        if let Some(trace_rows) = trace_report.evidence.get(root) {
            let mut collected = BTreeMap::new();
            for row in trace_rows {
                if Instant::now() >= deadline {
                    return Err("deadline");
                }
                collected.insert(
                    claude_request_hash(&row.request_id),
                    claude_trace_owner_session_id(root, &row.agent_id),
                );
            }
            traces.insert(root.to_owned(), collected);
        }
    }

    // Page hashes (units and rows), collisions by full id.
    let mut first_id = BTreeMap::<u64, &str>::new();
    let mut collisions = BTreeSet::new();
    let mut checked = 0_usize;
    for item in &items {
        for request_id in item.claude_usage_occurrences.keys() {
            checked += 1;
            if checked % 1024 == 0 && Instant::now() >= deadline {
                return Err("deadline");
            }
            let hash = claude_request_hash(request_id);
            match first_id.get(&hash) {
                Some(first) if *first != request_id.as_str() => {
                    collisions.insert(hash);
                }
                Some(_) => {}
                None => {
                    first_id.insert(hash, request_id.as_str());
                }
            }
        }
    }
    let mut page_hashes = first_id.keys().copied().collect::<Vec<_>>();
    page_hashes.extend(
        root_rows
            .values()
            .flatten()
            .flat_map(|rows| rows.iter().map(|row| row.request_hash)),
    );
    for capture in captures.values() {
        page_hashes.extend(capture.units().iter().filter_map(|unit| match unit.kind {
            capture::CapturedKind::Displaced(hash) => Some(hash),
            _ => None,
        }));
    }
    page_hashes.sort_unstable();
    page_hashes.dedup();
    drop(first_id);
    let mut page_message_hashes = captures
        .values()
        .flat_map(|capture| capture.message_only_hashes())
        .collect::<Vec<_>>();
    page_message_hashes.sort_unstable();
    page_message_hashes.dedup();

    let ledger_view: &ClaudeLedger = ledger;
    let holders = claude_request_ledger::scan_holders(
        &index.claude_request_census,
        ledger_view.census(),
        &page_hashes,
        &page_message_hashes,
        deadline,
        &mut |bytes| budget.charge(bytes),
    );
    let Some(holders) = holders else {
        return Err(if Instant::now() >= deadline {
            "deadline"
        } else {
            "memory"
        });
    };
    counts.holders_compared += holders.compared;

    let ctx = ClaudeClassifyContext {
        index,
        ledger: ledger.census(),
        holders: &holders,
        scope,
        page_claims,
        first_event,
        sessions,
        trace: &traces,
        telemetry_complete_through: telemetry_complete_through(ledger),
        deadline,
        holder_view,
        unbuilt_older: std::cell::Cell::new(0),
    };
    let retired_roots =
        claude_request_ledger::roots_with_retired_records(&index.claude_request_census);

    {
        let items = &items;
        if Instant::now() >= deadline {
            return Err("deadline");
        }
        let keys = items
            .iter()
            .map(|item| {
                (
                    item.source_session_id.as_str(),
                    key_of(root, &item.source_session_id),
                )
            })
            .collect();
        let empty = BTreeSet::new();
        let members = indexed_members.get(root).unwrap_or(&empty);
        let total = members.len().max(items.len());
        let mut family_captures = BTreeMap::new();
        for item in items {
            if let Some(capture) =
                captures.remove(&(root.to_owned(), item.source_session_id.clone()))
            {
                family_captures.insert(item.source_session_id.as_str(), capture);
            }
        }
        // Members not in this page: their census `u` (what the old path last
        // built for that file), advisory only. Missing, malformed or stale
        // is unknown, never zero.
        let present = items
            .iter()
            .map(|item| item.source_session_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut absent_old = ClaudeMoneyTotals::default();
        let mut absent_old_unknown = 0_u64;
        for member in members {
            if Instant::now() >= deadline {
                return Err("deadline");
            }
            if present.contains(member.as_str()) {
                continue;
            }
            let usage = key_of(root, member).and_then(|key| {
                let entry = index.files.get(&key)?;
                let record = index.claude_request_census.get(&key)?;
                record
                    .current_for(&entry.source_file_fingerprint)
                    .then(|| record.old_path_usage())
                    .flatten()
            });
            match usage {
                Some((requests, tokens)) => {
                    counts.absent_members_old_known += 1;
                    absent_old.add(tokens, requests, Some(0));
                }
                None => {
                    counts.absent_members_old_unknown += 1;
                    absent_old_unknown += 1;
                }
            }
        }
        let family = ClaudeFamilyInput {
            root,
            items: items.clone(),
            member_keys: keys,
            indexed_members: members,
            members_total: total,
            rows: root_rows.get(root).and_then(Option::as_ref),
            trace: traces.get(root),
            captures: family_captures,
        };
        let body = build_claude_request_body(&family, &ctx, &collisions, now, counts);
        if ctx.late() {
            return Err("deadline");
        }
        if retired_roots.contains(root) {
            counts.possible_retired_copies += body.units.requests;
        }
        let union = union_revision_by(members, deadline).ok_or("deadline")?;
        Ok((body, union, absent_old, absent_old_unknown))
    }
}

#[allow(clippy::too_many_arguments)]
fn family_rows(
    root: &str,
    body: ClaudeRequestBody,
    union: [u8; 32],
    absent_old: ClaudeMoneyTotals,
    absent_old_unknown: u64,
    census_state: FamilyCensus,
    now: u64,
    snapshot: u64,
    ledger: &ClaudeLedger,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) -> (FamilyRows, Option<([u8; 32], ClaudeFamilyMemo)>) {
    let (census, census_reason, key_statuses) = census_state.wire();
    let mut p1_reasons = Vec::new();
    if body.unbuilt {
        p1_reasons.push("unbuilt");
    }
    if body.members_built < body.members_total {
        p1_reasons.push("union_partial");
    }
    if !body.rows_complete {
        p1_reasons.push("rows_unavailable");
    }
    if !body.certificate_ok {
        p1_reasons.push("certificate");
    }
    if body.held.requests > 0 {
        p1_reasons.push("held");
    }
    let complete = body.coverage_complete(census == "covered") && p1_reasons.is_empty();
    tally(counts, &body, complete);
    let memo_key = family_key(root);
    // The removal delta's basis: the last complete body whose rows were
    // written (a memo moves only when its batch is published), named by
    // its snapshot.
    let memo = ledger
        .get(&memo_key)
        .and_then(ClaudeRequestCensusRecord::family_memo)
        .map(|(revision, memo)| (*revision, memo));
    let (removed_change, basis, unavailable) = match (complete, memo) {
        (false, _) => (None, None, Some("body_incomplete")),
        (true, None) => (None, None, Some("no_previous_body")),
        (true, Some((revision, _))) if revision != union => (None, None, Some("union_changed")),
        // An earlier build's marker of an incomplete first body.
        (true, Some((_, memo))) if memo.removed_requests == u64::MAX => {
            (None, None, Some("no_previous_body"))
        }
        (true, Some((_, memo))) => (
            Some(SignedRequestsTokens {
                requests: i128::from(body.removed.requests) - i128::from(memo.removed_requests),
                tokens: i128::from(body.removed.tokens) - i128::from(memo.removed_tokens),
            }),
            Some("previous_shadow"),
            None,
        ),
    };
    let basis_snapshot = removed_change
        .as_ref()
        .and(memo)
        .map(|(_, memo)| memo.snapshot);
    if removed_change.is_some() {
        counts.removed_change_available += 1;
    } else {
        counts.removed_change_unavailable += 1;
    }
    let row = FamilyRow {
        row: "family",
        v: JSONL_VERSION,
        counting: CLAUDE_REQUEST_COUNTING,
        snapshot,
        observed_unix: now,
        family: hashed_id(root),
        revision: hex_revision(&union),
        census,
        census_reason,
        key_statuses,
        p1_reasons,
        old_available: true,
        category: body.category(),
        coverage_complete: complete,
        members_built: body.members_built,
        members_total: body.members_total,
        old: (&body.old).into(),
        new: (&body.new).into(),
        net_token_change: i128::from(body.new.tokens) - i128::from(body.old.tokens),
        net_request_change: i128::from(body.new.requests) - i128::from(body.old.requests),
        removed: (&body.removed).into(),
        removed_change,
        removed_change_basis: basis,
        removed_change_basis_snapshot: basis_snapshot,
        removed_change_unavailable: unavailable,
        held: (&body.held).into(),
        held_reasons: body
            .held_reasons
            .iter()
            .map(|r| undecided_wire(*r))
            .collect(),
        immature: (&body.immature).into(),
        unexplained: (&body.unexplained).into(),
        grains: body.grains.len(),
        absent_old: (&absent_old).into(),
        absent_old_unknown,
    };

    let basis = complete.then_some((
        union,
        ClaudeFamilyMemo {
            removed_requests: body.removed.requests,
            removed_tokens: body.removed.tokens,
            snapshot,
            published: None,
        },
    ));
    (
        FamilyRows {
            row,
            grains: body.grains,
        },
        basis,
    )
}

fn hex_revision(revision: &[u8; 32]) -> String {
    revision.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn failure_rows(
    root: &str,
    reason: &'static str,
    state: FamilyCensus,
    now: u64,
    snapshot: u64,
    ledger: &ClaudeLedger,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) -> FamilyRows {
    let (mut rows, _) = family_rows(
        root,
        ClaudeRequestBody {
            unbuilt: true,
            ..Default::default()
        },
        [0; 32],
        ClaudeMoneyTotals::default(),
        1,
        state,
        now,
        snapshot,
        ledger,
        counts,
    );
    rows.row.p1_reasons = vec![reason];
    rows.row.old_available = false;
    rows
}

/// Streaming canonical digest, without a second copy of the row or grains.
/// Snapshot, observation time and removal-basis deltas are not semantic content.
fn semantic_digest(rows: &mut FamilyRows) -> u64 {
    semantic_digest_by(rows, None).expect("bounded writer digest")
}

fn semantic_digest_by(rows: &mut FamilyRows, deadline: Option<Instant>) -> Option<u64> {
    struct HashWriter(Sha256, Option<Instant>);
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.1.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "money digest deadline",
                ));
            }
            #[cfg(test)]
            if self.1.is_some()
                && DIGEST_WRITES_FOR_TEST.with(|left| match left.get() {
                    Some(0) => true,
                    Some(n) => {
                        left.set(Some(n - 1));
                        false
                    }
                    None => false,
                })
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "synthetic digest deadline",
                ));
            }
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let row = &mut rows.row;
    let saved = (
        row.snapshot,
        row.observed_unix,
        row.removed_change.take(),
        row.removed_change_basis.take(),
        row.removed_change_basis_snapshot.take(),
        row.removed_change_unavailable.take(),
    );
    row.snapshot = 0;
    row.observed_unix = 0;
    let mut hash = HashWriter(Sha256::new(), deadline);
    let result = serde_json::to_writer(&mut hash, &*row).and_then(|()| {
        for (key, (old, new)) in &rows.grains {
            serde_json::to_writer(&mut hash, &grain_row(row, key, old, new))?;
        }
        Ok(())
    });
    (
        row.snapshot,
        row.observed_unix,
        row.removed_change,
        row.removed_change_basis,
        row.removed_change_basis_snapshot,
        row.removed_change_unavailable,
    ) = saved;
    result.ok()?;
    Some(u64::from_be_bytes(
        hash.0.finalize()[..8].try_into().expect("digest"),
    ))
}

#[cfg(test)]
thread_local! {
    static DIGEST_WRITES_FOR_TEST: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// A page whose shadow does not take its captures: they are dropped by the
/// next page (deposited before this one), and older ones now.
fn purge_captures(scope_key: &Path, counts: &mut ClaudeRequestMoneyShadowCounts) {
    if let Ok(mut last) = LAST_SHADOW.lock() {
        if let Some(previous) = last.insert(scope_key.to_path_buf(), Instant::now()) {
            counts.captures_purged = capture::purge_before(scope_key, previous);
        }
    }
}

/// A refused page: a false coverage row (and the ledger's own progress) go
/// to the writer; nothing else is written.
fn refuse(
    end: &PageEnd<'_>,
    mut ledger: Option<&mut ClaudeLedger>,
    index: &ScanIndex,
    families: usize,
    mut counts: ClaudeRequestMoneyShadowCounts,
) -> ClaudeRequestMoneyShadowCounts {
    let coverage = CoverageRow {
        row: "page",
        v: JSONL_VERSION,
        observed_unix: end.now,
        coverage_complete: false,
        families: families as u64,
        snapshot: 0,
        page_families: families as u64,
        written: 0,
        unchanged: 0,
        failed: families as u64,
        holder_view: false,
        families_incomplete: families as u64,
        refused: true,
        truncated: false,
        telemetry_sweep_complete: false,
        rows_unavailable_roots: 0,
        dropped: false,
    };
    // Without the buffer's admission the writer streams unbuffered.
    let reservation = ShadowReservation::admit(1024 + JSONL_WRITE_BUFFER_BYTES)
        .map(|reservation| (reservation, JSONL_WRITE_BUFFER_BYTES))
        .or_else(|| ShadowReservation::admit(1024).map(|reservation| (reservation, 0)));
    hand_off(
        end,
        ledger.as_deref_mut(),
        Vec::new(),
        coverage,
        Vec::new(),
        reservation,
        &mut counts,
    );
    emit(end, ledger.as_deref(), index, &mut counts);
    counts
}

/// Hand the page's rows, its coverage row, its memos and the ledger's
/// bounded save to the writer (after the page, outside the sync lock). A
/// dropped batch owes its day a false coverage row (Sol R3-6).
fn hand_off(
    end: &PageEnd<'_>,
    ledger: Option<&mut ClaudeLedger>,
    families: Vec<FamilyRows>,
    coverage: CoverageRow,
    memos: Vec<PendingMemo>,
    reservation: Option<(ShadowReservation, usize)>,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    if reservation.is_none() {
        owe_coverage(end.support_dir, end.now, false);
        counts.batch_dropped = 1;
        return;
    }
    let buffer_bytes = reservation.as_ref().map_or(0, |(_, bytes)| *bytes);
    let reservations = reservation
        .into_iter()
        .map(|(reservation, _)| reservation)
        .collect::<Vec<_>>();
    hand_off_reserved_buffer(
        end,
        ledger,
        families,
        coverage,
        memos,
        reservations,
        buffer_bytes,
        counts,
    );
}

#[allow(clippy::too_many_arguments)]
fn hand_off_reserved(
    end: &PageEnd<'_>,
    ledger: Option<&mut ClaudeLedger>,
    families: Vec<FamilyRows>,
    coverage: CoverageRow,
    memos: Vec<PendingMemo>,
    reservations: Vec<ShadowReservation>,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    hand_off_reserved_buffer(
        end,
        ledger,
        families,
        coverage,
        memos,
        reservations,
        JSONL_WRITE_BUFFER_BYTES,
        counts,
    );
}

#[allow(clippy::too_many_arguments)]
fn hand_off_reserved_buffer(
    end: &PageEnd<'_>,
    ledger: Option<&mut ClaudeLedger>,
    families: Vec<FamilyRows>,
    coverage: CoverageRow,
    memos: Vec<PendingMemo>,
    mut reservations: Vec<ShadowReservation>,
    buffer_bytes: usize,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    let mut save = None;
    let mut ledger = ledger;
    if let Some(ledger) = ledger.as_deref_mut() {
        match ledger.take_save(store::SavePolicy {
            support_dir: end.support_dir,
            deadline: end.deadline,
            utc_day: utc_day(end.now),
            min_interval: store::SAVE_MIN_INTERVAL,
        }) {
            Some((taken, reservation)) => {
                counts.ledger_save_shards = taken.shards() as u64;
                counts.ledger_save_bytes = taken.bytes() as u64;
                reservations.push(reservation);
                save = Some(taken);
            }
            None if Instant::now() >= end.deadline => counts.ledger_save_late = 1,
            None => counts.ledger_save_refused = u64::from(ledger.dirty_shards() > 0),
        }
        counts.admitted_peak_bytes = counts
            .admitted_peak_bytes
            .max(SHADOW_RESERVED.load(Ordering::Acquire) as u64);
        counts.ledger_save_oversized = ledger.oversized_shards;
        counts.save_bytes_today = ledger.save_bytes_today;
    }
    counts.ledger_loads_refused = store::loads_refused();
    counts.jsonl_queued = families.iter().map(FamilyRows::rows).sum::<u64>() + 1;
    let job = WriteJob {
        support_dir: end.support_dir.to_path_buf(),
        jsonl: JsonlBatch {
            now: end.now,
            fault: current_fault(),
            families,
            coverage,
            buffer_bytes,
        },
        memos,
        save,
        reservations,
    };
    let outcome = match ledger {
        Some(ledger) => store::submit_batch(ledger, job),
        None => store::submit_unledgered(job),
    };
    if let Err(job) = outcome {
        counts.batch_dropped = 1;
        counts.family_memos_withheld += job.memos.len() as u64;
        owe_coverage(end.support_dir, end.now, false);
    }
}

/// The walked ledger state counts per support directory, and when.
static STATE_COUNTS: Mutex<
    BTreeMap<PathBuf, (Instant, claude_request_ledger::ClaudeLedgerStateCounts)>,
> = Mutex::new(BTreeMap::new());

/// The page's log line (its counts, the tail's, the rows', the scope's and
/// the state of the index's records and the ledger). The record walks are
/// refreshed at most once a minute; the totals are current. `elapsed_us` is
/// taken after every phase under the lock but the line's own write.
fn emit(
    end: &PageEnd<'_>,
    ledger: Option<&ClaudeLedger>,
    index: &ScanIndex,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    let census = &index.claude_request_census;
    let cached = STATE_COUNTS
        .lock()
        .ok()
        .and_then(|cache| cache.get(end.support_dir).copied());
    let fresh = cached.filter(|(at, _)| at.elapsed() < STATE_COUNTS_REFRESH);
    let walked = match fresh {
        Some(_) => None,
        None => claude_request_ledger::ledger_state_counts(census, ledger, end.deadline),
    };
    let state = match (walked, cached) {
        (Some(state), _) => {
            if let (Some(_), Ok(mut cache)) = (ledger, STATE_COUNTS.lock()) {
                cache.insert(end.support_dir.to_path_buf(), (Instant::now(), state));
            }
            state
        }
        // Fresh, or the walk ran out of the page's time: the last walk's
        // fields (none yet: zero) with current totals.
        (None, cached) => {
            counts.state_counts_late = u64::from(fresh.is_none());
            let mut state = cached.map(|(_, state)| state).unwrap_or_default();
            claude_request_ledger::refresh_state_totals(&mut state, census, ledger);
            state
        }
    };
    counts.elapsed_us = end.started.elapsed().as_micros() as u64;
    emit_line(&ShadowLine {
        counting: CLAUDE_REQUEST_COUNTING,
        census_complete: end.census_complete,
        counts,
        tail: &end.tail,
        rows: &end.rows,
        scope: &end.scope,
        ledger: &state,
    });
}

/// The writer's outcome of earlier batches: JSONL counts, and the memos of
/// published batches move now (each refused if the ledger has no room).
fn apply_results(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    for result in store::take_results(support_dir, ledger) {
        counts.writer_us += result.writer_us;
        counts.jsonl_rows += result.jsonl.rows;
        counts.jsonl_truncated += result.jsonl.truncated;
        counts.jsonl_sealed += result.jsonl.sealed;
        counts.jsonl_failed += result.jsonl.failed;
        counts.jsonl_owed_written += result.jsonl.owed_written;
        if !result.jsonl.published {
            counts.family_memos_withheld += result.memos.len() as u64;
            continue;
        }
        for memo in result.memos {
            apply_published_memo(ledger, memo, counts);
        }
    }
}

fn apply_published_memo(
    ledger: &mut ClaudeLedger,
    memo: PendingMemo,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    let previous = ledger
        .get(&memo.key)
        .and_then(ClaudeRequestCensusRecord::family_memo)
        .map(|(revision, basis)| (*revision, basis));
    let (revision, mut basis) = memo.basis.filter(|_| memo.row).or(previous).unwrap_or((
        [0; 32],
        ClaudeFamilyMemo {
            removed_requests: u64::MAX,
            ..Default::default()
        },
    ));
    basis.published = Some(memo.published);
    let record = ClaudeRequestCensusRecord::family_record(revision, memo.observed_unix, basis);
    let fits = ledger.census().serialized_headroom() >= memo.key.len() + 1024;
    let stored = fits && ledger.insert(memo.key, record) == ClaudeRequestCensusInsert::Stored;
    counts.family_memos_withheld += u64::from(!stored);
}

/// Record the message-only ids one parse's capture saw as the ledger's
/// `mh:` record of that file, bound to the file record's revision. Its
/// growth is checked against the ledger's budgets before anything changes.
fn note_message_record(
    ledger: &mut ClaudeLedger,
    index: &ScanIndex,
    key: &str,
    fingerprint: &str,
    capture: &ClaudeResponseCapture,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    if capture.is_refused() {
        return;
    }
    let Some(record) = index
        .claude_request_census
        .get(key)
        .filter(|record| fingerprint_matches(record, fingerprint) && record.retired().is_none())
    else {
        return;
    };
    let Some(_scratch) = ShadowReservation::admit(capture.units().len().saturating_mul(24)) else {
        counts.message_records_refused += 1;
        return;
    };
    let next = ClaudeRequestCensusRecord::message_record(record, capture.message_only_hashes());
    let message = message_key(key);
    if ledger.get(&message) == Some(&next) {
        return;
    }
    let hashes = next.request_hashes().len();
    let census = ledger.census();
    let fits = census.hash_headroom() >= hashes
        && census.serialized_headroom() >= hashes * 11 + message.len() + 512;
    if fits && ledger.insert(message, next) == ClaudeRequestCensusInsert::Stored {
        counts.message_records_written += 1;
    } else {
        counts.message_records_refused += 1;
    }
}

/// A bounded round-robin over the `mh:` records: one whose file record is
/// gone, retired or of another revision is dropped.
fn prune_message_records(
    ledger: &mut ClaudeLedger,
    index: &ScanIndex,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    let cursor = std::mem::take(&mut ledger.message_cursor);
    let due = ledger
        .census()
        .records_with_prefix(MESSAGE_KEY_PREFIX)
        .filter(|(key, _)| key.as_str() > cursor.as_str())
        .take(MESSAGE_PRUNE_PER_PAGE)
        .map(|(key, record)| {
            let file = &key[MESSAGE_KEY_PREFIX.len()..];
            let current = index
                .claude_request_census
                .get(file)
                .is_some_and(|file| file.same_fingerprint(record) && file.retired().is_none());
            (key.clone(), current)
        })
        .collect::<Vec<_>>();
    let wrapped = due.len() < MESSAGE_PRUNE_PER_PAGE;
    let mut last = String::new();
    for (key, current) in due {
        if !current {
            ledger.remove(&key);
            counts.message_records_pruned += 1;
        }
        last = key;
    }
    ledger.message_cursor = if wrapped { String::new() } else { last };
}

fn tally(counts: &mut ClaudeRequestMoneyShadowCounts, body: &ClaudeRequestBody, complete: bool) {
    counts.families += 1;
    match body.category() {
        ClaudeFamilyCategory::Equal => counts.families_equal += 1,
        ClaudeFamilyCategory::DifferTokens => counts.families_differ_tokens += 1,
        ClaudeFamilyCategory::DifferRequests => counts.families_differ_requests += 1,
        ClaudeFamilyCategory::DifferGrains => counts.families_differ_grains += 1,
        ClaudeFamilyCategory::UnionPartial => counts.families_union_partial += 1,
        ClaudeFamilyCategory::Unbuilt => counts.families_unbuilt += 1,
    }
    counts.families_coverage_complete += u64::from(complete);
    counts.certificate_mismatch += u64::from(!body.certificate_ok);
    counts.tokens_old += body.old.tokens;
    counts.tokens_new += body.new.tokens;
    counts.tokens_removed += body.removed.tokens;
    counts.tokens_held += body.held.tokens;
    counts.tokens_immature += body.immature.tokens;
    counts.tokens_unexplained += body.unexplained.tokens;
    counts.requests_old += body.old.requests;
    counts.requests_new += body.new.requests;
}

fn grain_row<'a>(
    family: &'a FamilyRow,
    key: &'a ClaudeGrainKey,
    old: &ClaudeGrainSide,
    new: &ClaudeGrainSide,
) -> GrainRow<'a> {
    let (hour, model, selector) = &key.live;
    GrainRow {
        row: "grain",
        v: JSONL_VERSION,
        snapshot: family.snapshot,
        family: &family.family,
        session: hashed_id(&key.member),
        owner: (!key.owner.is_empty()).then(|| hashed_id(&key.owner)),
        hour,
        model,
        selector,
        request_usage_origin: key.origin,
        category: key.category,
        old: old.into(),
        new: new.into(),
    }
}

/// The union revision a removal delta is bound to: the family's indexed
/// member set.
fn union_revision_by(members: &BTreeSet<String>, deadline: Instant) -> Option<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"claude_request_money_union:v1\0");
    for member in members {
        if Instant::now() >= deadline {
            return None;
        }
        digest.update((member.len() as u64).to_be_bytes());
        digest.update(member.as_bytes());
    }
    Some(digest.finalize().into())
}

/// Drop family memos no page rebuilt within the retention window.
fn drop_old_family_memos(ledger: &mut ClaudeLedger, now: u64, deadline: Instant) -> u64 {
    let cutoff = now.saturating_sub(FAMILY_MEMO_RETENTION_SECONDS);
    let stale = ledger
        .census()
        .records_with_prefix(FAMILY_KEY_PREFIX)
        .take_while(|_| Instant::now() < deadline)
        .filter(|(_, record)| {
            record.family_memo().is_some_and(|(_, memo)| {
                // An unreached family's scheduling turn may remain at zero;
                // retention follows its real last publication, not that priority.
                memo.published
                    .map_or(record.window(), |published| published.attempted)
                    < cutoff
            })
        })
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    let mut dropped = 0;
    for key in &stale {
        if Instant::now() >= deadline {
            break;
        }
        ledger.remove(key);
        dropped += 1;
    }
    dropped
}

fn day_stamp(unix: u64) -> Option<String> {
    let date = time::OffsetDateTime::from_unix_timestamp(i64::try_from(unix).ok()?)
        .ok()?
        .date();
    Some(format!(
        "{:04}{:02}{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    ))
}

fn utc_day(unix: u64) -> u64 {
    day_stamp(unix)
        .and_then(|day| day.parse().ok())
        .unwrap_or(0)
}

fn process_epoch() -> u64 {
    static EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(next_snapshot)
}

const RUN_MARKER: &str = ".claude-request-money-run.json";
fn open_run_marker(support_dir: &Path, days: (u64, u64)) -> bool {
    std::fs::create_dir_all(support_dir).is_ok()
        && store::write_atomic(
            &support_dir.join(RUN_MARKER),
            format!("[{},{}]", days.0, days.1).as_bytes(),
        )
}

fn note_unclean_run(support_dir: &Path, observed: u64) -> bool {
    let path = support_dir.join(RUN_MARKER);
    let read = std::fs::metadata(&path)
        .ok()
        .filter(|meta| meta.len() <= 128)
        .and_then(|_| std::fs::read(&path).ok())
        .and_then(|bytes| serde_json::from_slice::<(u64, u64)>(&bytes).ok());
    let mut persisted = true;
    if let Some((first, last)) = read {
        for day in (first.max(observed.saturating_sub(6 * 86_400)) / 86_400)
            ..=(last.min(observed) / 86_400)
        {
            persisted &= owe_coverage(support_dir, day * 86_400, true);
        }
    } else if path.exists() {
        persisted = owe_coverage(support_dir, observed, true);
    }
    persisted
}

/// Drain a snapshot outside the mutex: fsync never blocks the producer's
/// in-memory debt latch. A wake job closes the idle-writer race.
fn persist_coverage_debt() {
    let debts = COVERAGE_OWED
        .lock()
        .ok()
        .map(|mut owed| std::mem::take(&mut *owed))
        .unwrap_or_default();
    for (dir, days) in debts {
        for observed in days.into_values() {
            owe_coverage(&dir, observed, true);
        }
    }
}

/// False coverage rows owed per support directory: day -> the earliest
/// page that owes it (a dropped batch, or one whose rows were not written).
/// A debt of a write that failed is also a marker file in the day's
/// directory (Sol R3-6), so a restart keeps it: the writer reads the markers
/// back with every batch. A dropped batch's debt is latched in memory only
/// (no file I/O under the sync lock); the writer's next batch writes it.
static COVERAGE_OWED: Mutex<BTreeMap<PathBuf, BTreeMap<String, u64>>> = Mutex::new(BTreeMap::new());

fn day_path(dir: &Path, day: &str) -> PathBuf {
    dir.join(format!("{JSONL_PREFIX}{day}.jsonl"))
}

/// The marker of a day's owed false coverage row (its content: the earliest
/// owing page's `observed_unix`).
fn owed_path(dir: &Path, day: &str) -> PathBuf {
    dir.join(format!(".{JSONL_PREFIX}{day}.owed"))
}

/// The page at `observed_unix` did not reach its day's file: the next batch
/// writes a false coverage row there. `durable` (the writer thread only)
/// also writes the day's marker, a few bytes, once per owing day (a later
/// debt of the same day keeps it).
fn owe_coverage(support_dir: &Path, observed_unix: u64, durable: bool) -> bool {
    let Some(day) = day_stamp(observed_unix) else {
        return false;
    };
    let dir = support_dir.join("diagnostics");
    let marker = owed_path(&dir, &day);
    let persisted = if durable && std::fs::create_dir_all(&dir).is_ok() {
        // Existence cannot prove durability after a failed directory sync.
        // Retry the atomic write and propagate its actual sync result.
        let earliest = std::fs::metadata(&marker)
            .ok()
            .filter(|meta| meta.len() <= 32)
            .and_then(|_| std::fs::read_to_string(&marker).ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map_or(observed_unix, |old| old.min(observed_unix));
        store::write_atomic(&marker, earliest.to_string().as_bytes())
    } else {
        false
    };
    if let Ok(mut owed) = COVERAGE_OWED.lock() {
        let slot = owed
            .entry(support_dir.to_path_buf())
            .or_default()
            .entry(day)
            .or_insert(observed_unix);
        *slot = (*slot).min(observed_unix);
    }
    if !durable {
        store::wake_writer();
    }
    persisted
}

/// A false row of `day` is on disk: its debt is settled.
fn settle_owed(dir: &Path, day: &str) {
    let _ = std::fs::remove_file(owed_path(dir, day));
}

/// The debts owed in `dir` (the process's and the markers on disk), taken.
/// One listing per batch: it also drops own files older than `oldest`.
fn take_owed_coverage(
    support_dir: &Path,
    dir: &Path,
    oldest: Option<&str>,
) -> BTreeMap<String, u64> {
    let mut owed = COVERAGE_OWED
        .lock()
        .ok()
        .and_then(|mut owed| owed.remove(support_dir))
        .unwrap_or_default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return owed;
    };
    for entry in entries.take(JSONL_MAX_DIR_ENTRIES).flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let marker = name
            .strip_prefix('.')
            .and_then(|name| name.strip_prefix(JSONL_PREFIX))
            .and_then(|rest| rest.strip_suffix(".owed"));
        let day = name
            .strip_prefix(JSONL_PREFIX)
            .and_then(|rest| rest.strip_suffix(".jsonl"))
            .or(marker);
        let Some(day) = day.filter(|day| day.len() == 8 && day.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        if oldest.is_some_and(|oldest| day < oldest) {
            let _ = std::fs::remove_file(entry.path());
            continue;
        }
        if marker.is_some() {
            let observed = std::fs::read_to_string(entry.path())
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
                .unwrap_or(0);
            let slot = owed.entry(day.to_owned()).or_insert(observed);
            *slot = (*slot).min(observed);
        }
    }
    if let Some(oldest) = oldest {
        owed.retain(|day, _| day.as_str() >= oldest);
    }
    owed
}

/// One page's rows for today's JSONL file (serialized by the writer).
pub(crate) struct JsonlBatch {
    now: u64,
    fault: PageFault,
    families: Vec<FamilyRows>,
    coverage: CoverageRow,
    /// The admitted stream buffer (0: unbuffered).
    buffer_bytes: usize,
}

/// What the writer did with one batch's rows.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct JsonlOutcome {
    pub(crate) rows: u64,
    pub(crate) truncated: u64,
    pub(crate) sealed: u64,
    pub(crate) failed: u64,
    /// False coverage rows written for earlier batches.
    pub(crate) owed_written: u64,
    /// Every row and the coverage row were written.
    pub(crate) published: bool,
}

/// The file's last byte is not a newline (an earlier write stopped mid-row).
fn ends_mid_line(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut last = [0_u8; 1];
    file.seek(SeekFrom::End(-1)).is_ok() && file.read_exact(&mut last).is_ok() && last[0] != b'\n'
}

fn ends_with_seal(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    #[derive(serde::Deserialize)]
    struct Seal {
        row: String,
        #[serde(default)]
        truncated: bool,
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(size) = file.metadata().map(|meta| meta.len()) else {
        return false;
    };
    let len = size.min(JSONL_SEAL_RESERVE_BYTES) as usize;
    let mut tail = [0_u8; JSONL_SEAL_RESERVE_BYTES as usize];
    if file.seek(SeekFrom::End(-(len as i64))).is_err()
        || file.read_exact(&mut tail[..len]).is_err()
    {
        return false;
    }
    tail[..len]
        .split(|byte| *byte == b'\n')
        .rev()
        .find(|line| !line.is_empty())
        .and_then(|line| serde_json::from_slice::<Seal>(line).ok())
        .is_some_and(|row| row.row == "page" && row.truncated)
        && file.sync_all().is_ok()
        && std::fs::File::open(path.parent().unwrap_or(Path::new(".")))
            .is_ok_and(|dir| dir.sync_all().is_ok())
}

/// Rows appended to one day's file, each serialized straight into the
/// batch's stream buffer (no copy of the rows), under the day's cap.
struct DayFile {
    writer: Option<std::io::BufWriter<std::fs::File>>,
    /// Every write so far succeeded.
    written: bool,
    size: u64,
    /// Ordinary rows stop here; past it go only false coverage rows.
    room: u64,
    /// A row did not fit under `room`: nothing ordinary goes after it.
    sealed: bool,
}

impl DayFile {
    /// Open for appending, first ending a row an earlier failed write left
    /// open.
    fn open(path: &Path, buffer_bytes: usize, room: u64) -> Self {
        let open_row = ends_mid_line(path);
        let size = std::fs::metadata(path).map_or(0, |metadata| metadata.len());
        let mut writer = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
            .map(|file| std::io::BufWriter::with_capacity(buffer_bytes, file));
        let written = match writer.as_mut() {
            Some(writer) => {
                !open_row || size < JSONL_DAY_CAP_BYTES && writer.write_all(b"\n").is_ok()
            }
            None => false,
        };
        Self {
            writer,
            written,
            size: size + u64::from(open_row && size < JSONL_DAY_CAP_BYTES),
            room,
            sealed: ends_with_seal(path),
        }
    }

    /// Append `row` when it fits under `room`; the first that does not seals
    /// the day.
    fn push<T: Serialize>(&mut self, row: &T) -> bool {
        if self.sealed {
            return false;
        }
        let bytes = serialized_len(row) + 1;
        if self.size + bytes > self.room {
            self.sealed = true;
            return false;
        }
        self.write(row, bytes);
        true
    }

    /// Append a false coverage row under the day's hard cap.
    fn push_false(&mut self, row: &CoverageRow) -> bool {
        let bytes = serialized_len(row) + 1;
        if self.size + bytes > JSONL_DAY_CAP_BYTES {
            return false;
        }
        self.write(row, bytes);
        true
    }

    fn write<T: Serialize>(&mut self, row: &T, bytes: u64) {
        self.size += bytes;
        self.written = self.written
            && self.writer.as_mut().is_some_and(|writer| {
                serde_json::to_writer(&mut *writer, row).is_ok() && writer.write_all(b"\n").is_ok()
            });
    }

    /// True when every row reached the file.
    fn finish(self) -> bool {
        self.written
            && self.writer.is_some_and(|mut writer| {
                writer.flush().is_ok() && writer.get_ref().sync_all().is_ok()
            })
    }
}

/// Bytes `value` serializes to (counted, never buffered).
fn serialized_len<T: Serialize>(value: &T) -> u64 {
    struct Count(u64);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len() as u64;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    let _ = serde_json::to_writer(&mut count, value);
    count.0
}

/// Append a batch's rows and its coverage row to the day's capped file
/// (serialized here, from the batch's families), the false coverage rows
/// earlier batches owe their days, and drop own files older than the
/// retention window. A batch whose rows would pass the day's `room` is
/// truncated there and writes a false coverage row (`truncated`, the seal):
/// the day is incomplete from then on, whatever follows. Ordinary rows never
/// pass `room`; past it go only false coverage rows, so a file larger than
/// `room` takes no more ordinary rows and the file stays under its cap. A
/// seal or debt that does not reach the file stays owed (Sol R4-1).
/// Failures are counted, never raised. Runs on the writer thread only.
fn write_jsonl(support_dir: &Path, batch: &mut JsonlBatch) -> JsonlOutcome {
    let mut outcome = JsonlOutcome::default();
    let now = batch.now;
    if batch.fault == PageFault::WriteFailure {
        outcome.failed = 1;
        owe_coverage(support_dir, now, true);
        return outcome;
    }
    let dir = support_dir.join("diagnostics");
    let Some(today) = day_stamp(now).filter(|_| std::fs::create_dir_all(&dir).is_ok()) else {
        outcome.failed += 1;
        owe_coverage(support_dir, now, true);
        return outcome;
    };
    let oldest = day_stamp(now.saturating_sub((JSONL_RETENTION_DAYS * 86_400) as u64));
    let owed = take_owed_coverage(support_dir, &dir, oldest.as_deref());
    let mut owed_today = None;
    for (day, observed) in owed {
        if day == today {
            owed_today = Some(observed);
            continue;
        }
        let mut file = DayFile::open(&day_path(&dir, &day), 0, 0);
        if file.sealed {
            settle_owed(&dir, &day);
            continue;
        }
        if file.push_false(&CoverageRow::owed(observed)) && file.finish() {
            outcome.owed_written += 1;
            settle_owed(&dir, &day);
        } else {
            outcome.failed += 1;
            owe_coverage(support_dir, observed, true);
        }
    }
    let rows = batch.families.iter().map(FamilyRows::rows).sum::<u64>();
    let room = JSONL_DAY_CAP_BYTES - JSONL_SEAL_RESERVE_BYTES;
    let mut file = DayFile::open(&day_path(&dir, &today), batch.buffer_bytes, room);
    if file.sealed || file.size > room {
        // A synced terminal row already discharges any false-row debt.
        if file.sealed {
            settle_owed(&dir, &today);
        }
        outcome.truncated = rows;
        return outcome;
    }
    // Reserve every family row (including failures) and page before grains.
    // Repeated family versions count just like first publications.
    let mut mandatory = serialized_len(&batch.coverage)
        + 1
        + batch
            .families
            .iter()
            .map(|family| serialized_len(&family.row) + 1 + 64)
            .sum::<u64>()
        + owed_today.map_or(0, |observed| {
            serialized_len(&CoverageRow::owed(observed)) + 1
        });
    let mut available = room.saturating_sub(file.size + mandatory);
    for family in &mut batch.families {
        let grains = family
            .grains
            .iter()
            .map(|(key, (old, new))| serialized_len(&grain_row(&family.row, key, old, new)) + 1)
            .sum::<u64>();
        if grains <= available {
            available -= grains;
        } else {
            if family.row.p1_reasons.is_empty() {
                batch.coverage.written -= 1;
                batch.coverage.failed += 1;
            }
            family.grains.clear();
            family.row.grains = 0;
            family.row.p1_reasons.push("grains_omitted");
            family.row.coverage_complete = false;
            batch.coverage.coverage_complete = false;
        }
    }
    mandatory = serialized_len(&batch.coverage)
        + 1
        + batch
            .families
            .iter()
            .map(|family| serialized_len(&family.row) + 1)
            .sum::<u64>()
        + owed_today.map_or(0, |observed| {
            serialized_len(&CoverageRow::owed(observed)) + 1
        });
    if file.size + mandatory > room {
        let mut seal = CoverageRow::owed(now);
        seal.truncated = true;
        let sealed = file.push_false(&seal) && file.finish();
        outcome.truncated = rows;
        outcome.sealed = u64::from(sealed);
        if sealed {
            settle_owed(&dir, &today);
        }
        if !sealed {
            outcome.failed += 1;
            owe_coverage(support_dir, now, true);
        }
        return outcome;
    }
    let owed_fits = owed_today.is_some_and(|observed| file.push(&CoverageRow::owed(observed)));
    let mut kept = 0_u64;
    for family in &batch.families {
        kept += u64::from(file.push(&family.row));
        for (key, (old, new)) in &family.grains {
            kept += u64::from(file.push(&grain_row(&family.row, key, old, new)));
        }
    }
    let coverage_fits = file.push(&batch.coverage);
    let sealed = file.sealed;
    let seal_written = sealed
        && file.push_false(&CoverageRow {
            truncated: true,
            dropped: false,
            ..CoverageRow::owed(now)
        });
    let written = file.finish() && sealed == seal_written && batch.fault != PageFault::SyncFailure;
    outcome.truncated = rows - kept;
    if written {
        outcome.rows = kept + u64::from(coverage_fits) + u64::from(sealed);
        outcome.owed_written += u64::from(owed_fits);
        outcome.sealed = u64::from(sealed);
        if owed_today.is_some() {
            // Its row, or the seal's false row, is on disk.
            settle_owed(&dir, &today);
        }
    } else {
        outcome.failed += 1;
        owe_coverage(support_dir, owed_today.unwrap_or(now).min(now), true);
    }
    outcome.published = written && !sealed;
    outcome
}

#[cfg(test)]
pub(crate) fn owe_coverage_for_test(support_dir: &Path, observed_unix: u64, durable: bool) {
    owe_coverage(support_dir, observed_unix, durable);
}

/// A restart: the process's owed-coverage latch is gone (the markers stay).
#[cfg(test)]
pub(crate) fn forget_owed_coverage_for_test(support_dir: &Path) {
    if let Ok(mut owed) = COVERAGE_OWED.lock() {
        owed.remove(support_dir);
    }
}

/// The day's room for ordinary rows (past it, only false coverage rows).
#[cfg(test)]
pub(crate) fn jsonl_room_for_test() -> u64 {
    JSONL_DAY_CAP_BYTES - JSONL_SEAL_RESERVE_BYTES
}

#[cfg(test)]
pub(crate) fn hashed_id_for_test(value: &str) -> String {
    hashed_id(value)
}

#[cfg(test)]
pub(crate) fn parse_usd_micros_for_test(value: &str) -> Option<u64> {
    parse_usd_micros(value)
}

#[cfg(test)]
pub(crate) fn reserved_for_test() -> usize {
    SHADOW_RESERVED.load(Ordering::Acquire)
}

#[cfg(test)]
mod bounded_tests {
    use super::*;

    #[test]
    fn interim_seam_never_covers_and_preserves_reason_precedence() {
        let view = coverage::InterimFamilyCoverage {
            fence_invalid: true,
            census_complete: true,
            authority_retry: true,
        };
        assert_eq!(
            view.family("root"),
            FamilyCensus::Unknown(coverage::CensusReason::FenceInvalid)
        );
        assert!(!ClaudeHolderView::of(&view).complete());
        let covered = coverage::CoveredForTest;
        assert_eq!(covered.family("root"), FamilyCensus::Covered);
        assert!(ClaudeHolderView::of(&covered).complete());
    }

    #[test]
    fn semantic_digest_ignores_publication_and_delta_but_includes_failure_reasons() {
        let ledger = ClaudeLedger::new_for_test();
        let mut counts = ClaudeRequestMoneyShadowCounts::default();
        let mut rows = failure_rows(
            "root",
            "memory",
            FamilyCensus::Covered,
            1,
            2,
            &ledger,
            &mut counts,
        );
        let first = semantic_digest(&mut rows);
        rows.row.snapshot = 88;
        rows.row.observed_unix = 99;
        rows.row.removed_change = Some(SignedRequestsTokens {
            requests: 1,
            tokens: 20,
        });
        rows.row.removed_change_basis = Some("previous_shadow");
        assert_eq!(first, semantic_digest(&mut rows));
        rows.row.p1_reasons = vec!["deadline"];
        assert_ne!(first, semantic_digest(&mut rows));
    }
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn early_terminal_seal_survives_reopen_below_byte_limit() {
        let scratch = crate::test_scratch::ScratchDir::new("money-early-seal");
        let path = scratch.join("day.jsonl");
        let mut file = DayFile::open(&path, 0, JSONL_DAY_CAP_BYTES - JSONL_SEAL_RESERVE_BYTES);
        let mut seal = CoverageRow::owed(1_786_000_000);
        seal.truncated = true;
        assert!(file.push_false(&seal));
        assert!(file.finish());
        assert!(
            std::fs::metadata(&path).unwrap().len()
                < JSONL_DAY_CAP_BYTES - JSONL_SEAL_RESERVE_BYTES
        );
        let before = std::fs::read(&path).unwrap();
        let mut reopened = DayFile::open(&path, 0, JSONL_DAY_CAP_BYTES - JSONL_SEAL_RESERVE_BYTES);
        assert!(reopened.sealed);
        assert!(!reopened.push(&CoverageRow::owed(1_786_000_001)));
        assert!(reopened.finish());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn recovery_keeps_previous_intent_when_an_existing_debt_cannot_be_synced() {
        let scratch = crate::test_scratch::ScratchDir::new("money-recovery-debt-sync");
        let now = 1_786_000_000;
        assert!(open_run_marker(&scratch, (now, now)));
        assert!(owe_coverage(&scratch, now, true));
        let marker = owed_path(&scratch.join("diagnostics"), &day_stamp(now).unwrap());
        // An earlier failed directory sync may leave a visible marker. Force
        // its retry to fail: mere existence must not allow intent replacement.
        let staged = marker.with_extension("json.tmp");
        std::fs::create_dir(&staged).unwrap();
        let before = std::fs::read(scratch.join(RUN_MARKER)).unwrap();
        assert!(!note_unclean_run(&scratch, now + 86_400));
        assert_eq!(std::fs::read(scratch.join(RUN_MARKER)).unwrap(), before);
        std::fs::remove_dir(staged).unwrap();
        assert!(note_unclean_run(&scratch, now + 86_400));
    }
}

#[cfg(test)]
mod round3_tests {
    use super::*;
    #[test]
    fn expired_and_mid_preflight_abort_before_walking_remaining_content() {
        let ledger = ClaudeLedger::new_for_test();
        let api = ClaudeLocalOtelLoadReport::default();
        let trace = ClaudeTraceOwnershipLoadReport::default();
        let captures = (0..100)
            .map(|at| {
                (
                    ("root".into(), at.to_string()),
                    ClaudeResponseCapture::default(),
                )
            })
            .collect();
        PREFLIGHT_CHECKS.with(|checks| checks.set(Some(100)));
        assert_eq!(
            family_preflight(
                "root",
                &[],
                &captures,
                &ledger,
                &api,
                &trace,
                Instant::now()
            ),
            Err("deadline")
        );
        assert_eq!(PREFLIGHT_CHECKS.with(std::cell::Cell::get), Some(99));
        PREFLIGHT_CHECKS.with(|checks| checks.set(Some(5)));
        assert_eq!(
            family_preflight(
                "root",
                &[],
                &captures,
                &ledger,
                &api,
                &trace,
                Instant::now() + Duration::from_secs(30)
            ),
            Err("deadline")
        );
        assert_eq!(PREFLIGHT_CHECKS.with(std::cell::Cell::get), Some(0));
        PREFLIGHT_CHECKS.with(|checks| checks.set(None));
    }

    #[test]
    fn complete_test_seam_preserves_previous_complete_removal_basis_across_failure() {
        use coverage::{CoveredForTest, FamilyCoverage};
        let mut ledger = ClaudeLedger::new_for_test();
        let mut counts = ClaudeRequestMoneyShadowCounts::default();
        let body = || ClaudeRequestBody {
            certificate_ok: true,
            rows_complete: true,
            members_built: 1,
            members_total: 1,
            removed: ClaudeMoneyTotals {
                requests: 2,
                tokens: 20,
                ..Default::default()
            },
            ..Default::default()
        };
        let (first, basis) = family_rows(
            "root",
            body(),
            [1; 32],
            Default::default(),
            0,
            CoveredForTest.family("root"),
            10,
            100,
            &ledger,
            &mut counts,
        );
        assert!(first.row.coverage_complete);
        assert_eq!(
            first.row.removed_change_unavailable,
            Some("no_previous_body")
        );
        let (revision, memo) = basis.unwrap();
        ledger.insert(
            family_key("root"),
            ClaudeRequestCensusRecord::family_record(revision, 10, memo),
        );
        let (_, unchanged_basis) = family_rows(
            "root",
            body(),
            [1; 32],
            Default::default(),
            0,
            CoveredForTest.family("root"),
            11,
            101,
            &ledger,
            &mut counts,
        );
        apply_published_memo(
            &mut ledger,
            PendingMemo {
                key: family_key("root"),
                basis: unchanged_basis,
                observed_unix: 11,
                published: ClaudeFamilyPublication {
                    utc_day: 0,
                    digest: 1,
                    epoch: 1,
                    attempted: 11,
                },
                row: false,
            },
            &mut counts,
        );
        assert_eq!(
            ledger
                .get(&family_key("root"))
                .unwrap()
                .family_memo()
                .unwrap()
                .1
                .snapshot,
            100,
            "unchanged ack preserves last emitted basis"
        );
        let failed = failure_rows(
            "root",
            "deadline",
            FamilyCensus::Covered,
            11,
            101,
            &ledger,
            &mut counts,
        );
        assert!(!failed.row.coverage_complete);
        assert!(failed.row.removed_change.is_none());
        let (next, _) = family_rows(
            "root",
            body(),
            [1; 32],
            Default::default(),
            0,
            CoveredForTest.family("root"),
            12,
            102,
            &ledger,
            &mut counts,
        );
        assert!(next.row.coverage_complete);
        assert_eq!(next.row.removed_change_basis_snapshot, Some(100));
        assert_eq!(next.row.removed_change_basis, Some("previous_shadow"));
        let change = next.row.removed_change.unwrap();
        assert_eq!((change.requests, change.tokens), (0, 0));
    }
}

#[cfg(test)]
mod digest_deadline_tests {
    use super::*;
    #[test]
    fn money_p1b_digest_stops_inside_serialization_and_restores_observation_fields() {
        let ledger = ClaudeLedger::new_for_test();
        let mut counts = ClaudeRequestMoneyShadowCounts::default();
        let mut rows = failure_rows(
            "root",
            "memory",
            FamilyCensus::Covered,
            10,
            100,
            &ledger,
            &mut counts,
        );
        let before = semantic_digest(&mut rows);
        DIGEST_WRITES_FOR_TEST.with(|left| left.set(Some(5)));
        assert_eq!(
            semantic_digest_by(&mut rows, Some(Instant::now() + Duration::from_secs(30))),
            None
        );
        assert_eq!(DIGEST_WRITES_FOR_TEST.with(std::cell::Cell::get), Some(0));
        DIGEST_WRITES_FOR_TEST.with(|left| left.set(None));
        assert_eq!((rows.row.observed_unix, rows.row.snapshot), (10, 100));
        assert_eq!(semantic_digest(&mut rows), before);
    }
}
