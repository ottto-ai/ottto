//! P1 per-request Claude Code money, shadow only (`claude_request_counting:v1`).
//!
//! With the live revision disabled, nothing here changes an upload byte, a hold,
//! an account decision, a live allowance or a return value. The live
//! finalizer runs exactly as before unless the shadow is armed; then a side
//! capture (its own funded budget, never on `SnapshotItem` or any live
//! reservation) records which live bucket row each response went to, its
//! message identity and the responses the occurrence map does not keep.
//!
//! The shadow reads the scan index. Live revision 3 alone records optional
//! bounded local selection custody; malformed records cannot erase the index. Its ledger (the
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
//! its day. Writer intents persist publication debt; after restart, retained
//! days with existing rows are conservatively re-sealed before new publication. All of its memory is admitted before allocation against the
//! shadow's own ceiling and its work runs under a deadline; a refusal skips
//! the page's shadow, writes a false coverage row and is counted.
//!
//! The shadow never fails or stalls the live page: a panic is caught (the
//! shadow is then off for the rest of the process, counted), every phase
//! under the sync lock checks the page deadline, and a local file
//! (`<support>/claude-request-money-shadow.off`) turns it off without a
//! release. Off, it captures nothing either, and the first off page of a
//! day writes one false coverage row.

// Count money-owned filesystem boundary calls only in opt-in test receipts.
// Outside test builds this expands to the original expression.
macro_rules! money_io {
    ($operation:ident, $expression:expr) => {{
        #[cfg(test)]
        crate::retry_allocation_probe::money_io_attempt(
            crate::retry_allocation_probe::MoneyIoKind::$operation,
        );
        $expression
    }};
}
pub(crate) use money_io;

pub(crate) mod body;
pub(crate) mod capture;
mod emit;
mod selection;
pub(in crate::snapshots) use selection::select_union_candidates;
pub(crate) use selection::{
    bind_union_checkpoints, decode_selections, finalize_synthetic, logical_family_member,
    logical_family_root_ref, record_logical_member, selected_money_files,
    stage_selection_fingerprints, synthetic_fingerprints, union_items_by_source, union_reparse,
    MoneyFileSelection,
};
pub(crate) mod coverage;
pub(crate) mod custody;
#[cfg(test)]
pub(super) mod custody_tests;
pub(crate) mod facts;
pub(crate) mod recovery_scope;
pub(crate) mod rows;
pub(crate) mod store;

use super::claude_request_census::{
    claude_request_hash, family_key, fingerprint_matches, message_key, telemetry_key,
    ClaudeFamilyMemo, ClaudeFamilyPublication, ClaudeRequestCensusInsert,
    ClaudeRequestCensusRecord, FAMILY_KEY_PREFIX, MESSAGE_KEY_PREFIX, TELEMETRY_KEY_PREFIX,
};
use super::claude_request_ledger::{
    self, ClaudeClassifyContext, ClaudeCountedBy, ClaudeLedgerScope, ClaudeScopeFiles,
    ClaudeUndecidedBy,
};
use super::{
    claude_index_path_family_member, claude_snapshot_family_root_ref,
    claude_trace_owner_session_id, ScanIndex, SnapshotItem, SnapshotProvenance, UsageTotals,
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
pub(crate) use store::MoneyReceipt;
/// Debt revision and original authorization time of an immutable attempt.
pub(crate) type RecoveryOffer = ([u8; 32], u64);
use store::{ClaudeLedger, ClaudeLedgerAcquire, PendingMemo, WriteJob};

/// Activation is a separate reviewed change after backend enforcement and parity.
pub(crate) const REQUEST_OWNED_LIVE_ENABLED: bool = false;
pub(crate) const UNPRICED_UNATTRIBUTED_ALLOWED: bool = false;
pub(crate) const REQUEST_OWNED_CONTRACT: &str = "claude_request_owned_usage:v1";
const LIVE_OFF_FILE: &str = "claude-request-owned-live.off";
/// The existing bounded debt codec keeps first-held time and a durable release
/// bit. A release remains until a current rebuild; a new cycle cannot re-hold it.
pub(crate) const UNBUILT_RELEASED: u64 = 1_u64 << 63;
/// Keep at most the saved predecessor and current proposal per physical file.
/// Outstanding contexts share one support ledger; this aggregate ceiling leaves
/// most slots for evidence, watches and debt rather than historical offers.
pub(crate) const MAX_MONEY_OFFERS_PER_FILE: usize = 2;
pub(crate) const MAX_MONEY_OFFERS_PER_CONTEXT: usize = 16_384;

static COLLECTION_FALLBACKS: AtomicU64 = AtomicU64::new(0);
pub(crate) fn note_collection_fallback(support: &Path) {
    if live_enabled(support) && store::live_refused(support) {
        let count = COLLECTION_FALLBACKS.fetch_add(1, Ordering::Relaxed) + 1;
        eprintln!("claude_request_money ordinary_collection_fallbacks={count} admission_refused=1");
    }
}

pub(crate) fn request_owned_live(support_dir: &Path) -> bool {
    live_enabled(support_dir) && !store::live_refused(support_dir)
}

fn live_enabled(support_dir: &Path) -> bool {
    #[cfg(test)]
    let enabled = REQUEST_OWNED_LIVE_ENABLED
        || LIVE_TEST_DIRS
            .lock()
            .expect("live test control")
            .iter()
            .any(|path| path == support_dir);
    #[cfg(not(test))]
    let enabled = REQUEST_OWNED_LIVE_ENABLED;
    enabled
        && !SHADOW_PANICKED.load(Ordering::Acquire)
        && !money_io!(Metadata, support_dir.join(LIVE_OFF_FILE).exists())
        && !money_io!(Metadata, support_dir.join(SHADOW_OFF_FILE).exists())
}
#[cfg(test)]
static LIVE_TEST_DIRS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Flush already queued ledger/output work on an orderly service exit.
/// Abrupt exits still rely on the persisted checkpoints; no signal handler does I/O.
pub fn flush_on_shutdown() {
    store::flush();
}

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
/// Money-added synchronous work under the lock, including capture and
/// closing. It counts money time only (MONEY decision, superseding the one
/// absolute wall deadline from the first finalizer): accumulated capture
/// sections, then the shadow from its entry, which gets what capture left.
/// Native time between or after finalizers is never charged.
pub(crate) const PAGE_MAX_ELAPSED: Duration = Duration::from_millis(250);
/// Leave bounded closing work inside the total, rather than after expiry:
/// optional work stops at 150 ms of money time, closing by 240 ms.
const PAGE_CLOSE_RESERVE: Duration = Duration::from_millis(100);
/// The first scheduled family, and the inputs only bodies use, may run this
/// far into the closing reserve. Fixed setup scales with every page family
/// and with the earlier page's acknowledgements; without this floor, a large
/// or loaded page can spend the whole body window on it and defer every
/// family, page after page. Closing slices stay bounded by the close deadline.
const FIRST_FAMILY_CLOSE_RESERVE: Duration = Duration::from_millis(70);
/// Common setup (acknowledgements, telemetry, retirement) stops this far
/// before the first scheduled family's floor: that family's own setup and
/// body always have this window.
const FIRST_FAMILY_SETUP_RESERVE: Duration = Duration::from_millis(60);
/// Acknowledgements stop this far before the setup stop, so scheduling
/// usually keys every root before family zero (past the stop it selects
/// family zero from the roots keyed so far).
const SCHEDULE_SETUP_RESERVE: Duration = Duration::from_millis(30);
const TELEMETRY_MAX_ELAPSED: Duration = Duration::from_millis(20);
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
    capture::forget_plan(support_dir);
    SHADOW_ENABLED_FOR_TEST
        .lock()
        .expect("shadow control")
        .retain(|dir| dir != support_dir);
}

fn shadow_enabled(support_dir: &Path) -> bool {
    #[cfg(test)]
    {
        sleep_for_test(&SHADOW_ENABLED_DELAY_FOR_TEST);
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
    if first && money_io!(Metadata, support_dir.join(SHADOW_OFF_FILE).exists()) {
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
    #[cfg(test)]
    sleep_for_test(&KILL_SWITCH_DELAY_FOR_TEST);
    let off = SHADOW_PANICKED.load(Ordering::Acquire)
        || money_io!(Metadata, support_dir.join(SHADOW_OFF_FILE).exists());
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
        capture::forget_plan(&scope);
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
        if let Ok(mut off) = SHADOW_OFF.lock() {
            off.remove(&shadow_scope(support_dir));
        }
        return;
    };
    let job = WriteJob {
        support_dir: support_dir.to_path_buf(),
        pending_intent: None,
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
        if let Ok(mut off) = SHADOW_OFF.lock() {
            off.remove(&shadow_scope(support_dir));
        }
    }
}

/// Faults a test injects at the page's last gates (the caller's thread).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum PageFault {
    None,
    /// The deadline passes just before the families are handed over.
    LateAtHandOff,
    /// Dense-page fixture: optional work is already out of time at entry.
    BodyDeadline,
    /// Common setup used everything up to its stop, and later families
    /// have no window: only the first scheduled family's remains.
    SetupOverrun,
    /// Common setup used everything up to its stop.
    SetupStall,
    /// Scheduling used everything up to the setup stop after keying one root
    /// (or as many as `set_schedule_stall_after_for_test` says).
    ScheduleStall,
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

// The last admitted page's family processing order, by root.
#[cfg(test)]
thread_local! {
    static PAGE_SCHEDULE: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

// After how many keyed roots `PageFault::ScheduleStall` stalls (0: one).
#[cfg(test)]
thread_local! {
    static SCHEDULE_STALL_AFTER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn set_schedule_stall_after_for_test(roots: usize) {
    SCHEDULE_STALL_AFTER.with(|after| after.set(roots));
}

#[cfg(test)]
pub(crate) fn family_key_for_test(root: &str) -> String {
    family_key(root)
}

/// The family roots the scope holds waiting captures for.
#[cfg(test)]
pub(crate) fn captured_roots_for_test(scope: &Path) -> BTreeSet<String> {
    capture::captured_index_keys(scope)
        .iter()
        .filter_map(|key| super::claude_index_path_member_ref(Path::new(key)))
        .map(|member| member.root.to_owned())
        .collect()
}

/// Drop every waiting capture except those of `root`'s family files.
#[cfg(test)]
pub(crate) fn keep_captures_of_root_for_test(scope: &Path, root: &str) {
    capture::retain_for_test(scope, |key| {
        super::claude_index_path_member_ref(Path::new(key))
            .is_some_and(|member| member.root == root)
    });
}

#[cfg(test)]
pub(crate) fn last_page_schedule_for_test() -> Vec<String> {
    PAGE_SCHEDULE.with(|schedule| schedule.borrow().clone())
}

// One page's injected wall budget, in place of the first-finalizer clock.
#[cfg(test)]
thread_local! {
    static PAGE_BUDGET: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// Functional probes inject the next page's clock: they check scheduling
/// and body progress, independently of CI CPU contention. Wall bounds are
/// asserted on real-clock pages.
#[cfg(test)]
pub(crate) fn set_next_page_budget_for_test(budget: Duration) {
    PAGE_BUDGET.with(|current| current.set(Some(budget)));
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
        #[cfg(test)]
        let _event = crate::retry_allocation_probe::money_admission_event();
        SHADOW_RESERVED
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                reserved
                    .checked_add(bytes)
                    .filter(|total| *total <= SHADOW_MEMORY_CEILING_BYTES)
            })
            .ok()
            .map(|before| {
                #[cfg(test)]
                crate::retry_allocation_probe::money_admission_changed(before + bytes);
                #[cfg(not(test))]
                let _ = before;
                Self(bytes)
            })
    }

    /// Transfer one retained graph's charge as its owned buffers change.
    /// Growth is admitted before the graph may survive another yield.
    pub(crate) fn resize(&mut self, bytes: usize) -> bool {
        if bytes > self.0 {
            let Some(mut extra) = Self::admit(bytes - self.0) else {
                return false;
            };
            self.0 = bytes;
            extra.0 = 0; // its charge moved into this reservation
        } else {
            #[cfg(test)]
            let _event = crate::retry_allocation_probe::money_admission_event();
            let before = SHADOW_RESERVED.fetch_sub(self.0 - bytes, Ordering::AcqRel);
            #[cfg(test)]
            crate::retry_allocation_probe::money_admission_changed(before - (self.0 - bytes));
            #[cfg(not(test))]
            let _ = before;
            self.0 = bytes;
        }
        true
    }

    pub(crate) fn bytes(&self) -> usize {
        self.0
    }
}

impl Drop for ShadowReservation {
    fn drop(&mut self) {
        #[cfg(test)]
        let _event = crate::retry_allocation_probe::money_admission_event();
        let before = SHADOW_RESERVED.fetch_sub(self.0, Ordering::AcqRel);
        #[cfg(test)]
        crate::retry_allocation_probe::money_admission_changed(before - self.0);
        #[cfg(not(test))]
        let _ = before;
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
    /// Unreached families whose pre-admitted deadline rows the writer renders.
    pub(crate) families_deadline_deferred: u64,
    pub(crate) families_coverage_complete: u64,
    /// Includes missing/unbuilt certificates, not only compared mismatches.
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
    /// Accumulated capture (money) time before the shadow, charged.
    pub(crate) capture_us: u64,
    /// Native wall time between the first money finalizer and shadow entry,
    /// excluding capture time. Receipt only: never charged.
    pub(crate) native_us: u64,
    pub(crate) writer_us: u64,
    pub(crate) result_apply_us: u64,
    /// Admission's unchecked pass (grouping by root and sizing over the
    /// index keys): a documented known limit, charged to money time.
    /// Receipt only.
    pub(crate) admission_us: u64,
    /// Time through common setup, before the first family's own inputs
    /// and body (its stop is a fixed reserve before that family's floor).
    pub(crate) family_setup_us: u64,
    /// Producer work accounting for the unreached family suffix.
    pub(crate) deferred_close_us: u64,
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
    /// The next Full parse's complete capture plan was not installed; the
    /// reason is one of the three below. The page then installed the
    /// oldest-64 fallback (`fallback_plan_installed`) or, failing that,
    /// closed optional capture: never the old plan.
    pub(crate) plan_install_failed: u64,
    /// The close budget ran out during the plan's walk.
    pub(crate) plan_install_failed_deadline: u64,
    /// The capture ceiling refused the plan's keys.
    pub(crate) plan_install_failed_funds: u64,
    /// The plan lock was poisoned.
    pub(crate) plan_install_failed_lock: u64,
    pub(crate) fallback_plan_installed: u64,
    /// A page with fresh captures built no family: no coverage progress.
    pub(crate) full_page_zero_built: u64,
    /// Roots keyed after family zero: scheduling reached the setup stop.
    pub(crate) families_keyed_after_first: u64,
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
    /// Blocking files released at the 24h / completed-census-cycle bound.
    pub(crate) unbuilt_older_released: u64,
    /// Time under the sync lock, every phase included but this line's write.
    pub(crate) elapsed_us: u64,
    /// The page's charged money time: capture plus shadow entry to the end
    /// of the page, including this line's serialization and write and the
    /// drop of the page's locals and ledger guard. Known only after the line
    /// is written, so it is not in it (see `previous_page_money_us`).
    #[serde(skip)]
    pub(crate) money_us: u64,
    /// `money_us` of this scope's previous complete page (0 for none).
    pub(crate) previous_page_money_us: u64,
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
            ClaudeUndecidedBy::UnbuiltOlder => return,
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
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    digest.update(b"claude_request_money_shadow:v1\0");
    digest.update(value.as_bytes());
    hex_bytes(&digest.finish().as_ref()[..8])
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
        ClaudeUndecidedBy::UnbuiltOlder => "unbuilt_older",
        ClaudeUndecidedBy::HolderView => "holder_view",
    }
}

#[cfg(test)]
thread_local! {
    static SHADOW_LINES: std::cell::RefCell<Vec<serde_json::Value>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

// Slow money-only steps outside the shadow body (a kill-switch lookup on a
// slow filesystem, a blocked log sink), on the test's own thread.
#[cfg(test)]
thread_local! {
    static SHADOW_ENABLED_DELAY_FOR_TEST: std::cell::Cell<Duration> =
        const { std::cell::Cell::new(Duration::ZERO) };
    static KILL_SWITCH_DELAY_FOR_TEST: std::cell::Cell<Duration> =
        const { std::cell::Cell::new(Duration::ZERO) };
    static LOG_WRITE_DELAY_FOR_TEST: std::cell::Cell<Duration> =
        const { std::cell::Cell::new(Duration::ZERO) };
}

#[cfg(test)]
fn sleep_for_test(delay: &'static std::thread::LocalKey<std::cell::Cell<Duration>>) {
    let delay = delay.with(std::cell::Cell::get);
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
}

#[cfg(test)]
pub(crate) fn set_shadow_enabled_delay_for_test(delay: Duration) {
    SHADOW_ENABLED_DELAY_FOR_TEST.with(|current| current.set(delay));
}

#[cfg(test)]
pub(crate) fn set_money_step_delays_for_test(kill_switch: Duration, log_write: Duration) {
    KILL_SWITCH_DELAY_FOR_TEST.with(|delay| delay.set(kill_switch));
    LOG_WRITE_DELAY_FOR_TEST.with(|delay| delay.set(log_write));
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
    #[cfg(test)]
    sleep_for_test(&LOG_WRITE_DELAY_FOR_TEST);
    // A log sink failure must not change collection. A blocking sink is
    // money time: the page's `money_us` is taken after this write.
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
    // The page's money clock starts here: the kill-switch check and every
    // later shadow step are money time, never a native gap.
    let entered = Instant::now();
    let now = now_unix();
    if !shadow_enabled(support_dir) {
        return;
    }
    if shadow_off(support_dir, now) {
        capture::charge_since(&shadow_scope(support_dir), entered);
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
            entered,
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

// Catch a panic on every resumed poll, preserving the shadow panic latch.
async fn guarded_resume<T: Default>(future: impl std::future::Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        let mut result = None;
        guarded(|| result = Some(future.as_mut().poll(cx)));
        result.unwrap_or(std::task::Poll::Ready(T::default()))
    })
    .await
}

#[derive(Default)]
struct PageBodies {
    entities: BTreeMap<String, body::ClaudeEntityBody>,
    births: BTreeMap<String, Option<u64>>,
    _reservations: Vec<ShadowBudget>,
}

/// One reached family's view of the page's index walk.
struct FamilyFiles<'i> {
    /// Index keys of each (root, member) of the family.
    member_keys: BTreeMap<(String, String), Vec<String>>,
    /// The family's indexed members.
    indexed_members: BTreeMap<String, BTreeSet<String>>,
    /// The groups of the family's own item files: the only groups its units
    /// consult (§3.1 scope).
    groups: BTreeSet<&'i str>,
}

/// None when the deadline passed.
fn family_files<'i>(
    index: &'i ScanIndex,
    files: &ClaudeScopeFiles<'i>,
    root: &str,
    items: &[&SnapshotItem],
    deadline: Instant,
) -> Option<FamilyFiles<'i>> {
    let mut member_keys = BTreeMap::<(String, String), Vec<String>>::new();
    let mut indexed_members = BTreeMap::<String, BTreeSet<String>>::new();
    for key in files.roots.get(root).into_iter().flatten() {
        if Instant::now() >= deadline {
            return None;
        }
        // Residue records name no current member.
        if !index.files.contains_key(*key) {
            continue;
        }
        let Some((root, member)) = claude_index_path_family_member(Path::new(key)) else {
            continue;
        };
        indexed_members
            .entry(root.clone())
            .or_default()
            .insert(member.clone());
        member_keys
            .entry((root, member))
            .or_default()
            .push((*key).to_owned());
    }
    let mut groups = BTreeSet::new();
    for item in items {
        let Some([key]) = member_keys
            .get(&(root.to_owned(), item.source_session_id.clone()))
            .map(Vec::as_slice)
        else {
            continue;
        };
        if let Some(group) = index
            .files
            .get_key_value(key)
            .and_then(|(key, _)| claude_request_ledger::claude_project_group(key))
        {
            groups.insert(group);
        }
    }
    Some(FamilyFiles {
        member_keys,
        indexed_members,
        groups,
    })
}

/// Add family `root`, and the groups of its own item files, to the page
/// scope. None when the deadline passed.
fn add_family_scope(
    scope: &mut ClaudeLedgerScope,
    index: &ScanIndex,
    census: &custody::Custody,
    files: &ClaudeScopeFiles<'_>,
    family: &FamilyFiles<'_>,
    root: &str,
    deadline: Instant,
) -> Option<()> {
    for group in &family.groups {
        scope.add_group(index, census, group, &files.groups[group], deadline)?;
    }
    let keys = files.roots.get(root).map_or(&[][..], Vec::as_slice);
    scope.add_family(index, census, root, keys, deadline)
}

/// The page roots' own telemetry rows, for every reached family's
/// classification: a claim by any page root's row decides another family's
/// unit, so this one walk covers the rows of every page root.
struct PageClaims<'k> {
    page_claims: BTreeMap<u64, Vec<&'k str>>,
    first_event: BTreeMap<String, u64>,
}

/// The telemetry key of each page root with rows: from its scheduling key
/// when keyed, else hashed. None when the deadline passed.
fn page_claim_keys<'r>(
    order: &[(&'r str, String, u64)],
    unkeyed: impl Iterator<Item = &'r str>,
    api_report: &ClaudeLocalOtelLoadReport,
    deadline: Instant,
) -> Option<Vec<(&'r str, String)>> {
    let mut keys = Vec::new();
    let keyed = order.iter().map(|(root, key, _)| (*root, Some(key)));
    for (root, key) in keyed.chain(unkeyed.map(|root| (root, None))) {
        if Instant::now() >= deadline {
            return None;
        }
        if !api_report.evidence.contains_key(root) {
            continue;
        }
        keys.push((
            root,
            key.map_or_else(
                || telemetry_key(root),
                |key| format!("{TELEMETRY_KEY_PREFIX}{}", &key[FAMILY_KEY_PREFIX.len()..]),
            ),
        ));
    }
    Some(keys)
}

/// A root's scheduling entry: its family key and turn.
fn schedule_entry<'r>(
    scope_key: &Path,
    ledger: &ClaudeLedger,
    root: &'r str,
) -> (&'r str, String, u64) {
    let key = family_key(root);
    let published_turn = ledger.get(&key).map_or(0, |record| record.window());
    let turn = capture::scheduling_turn(scope_key, &key, published_turn);
    (root, key, turn)
}

/// The producer's total schedule order, which the capture plan also uses.
/// Stable input ordering differs after a rotation and cannot break
/// equal-turn ties safely.
fn schedule_order(left: &(&str, String, u64), right: &(&str, String, u64)) -> std::cmp::Ordering {
    left.2.cmp(&right.2).then_with(|| left.1.cmp(&right.1))
}

/// One keyed root's schedule entry, ordered by `schedule_order`.
struct ScheduleTurn<'r>((&'r str, String, u64));

impl PartialEq for ScheduleTurn<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for ScheduleTurn<'_> {}

impl PartialOrd for ScheduleTurn<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduleTurn<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        schedule_order(&self.0, &other.0)
    }
}

/// The oldest `NEXT_PAGE_FAMILIES` captured and uncaptured roots keyed so
/// far, each in a bounded max-heap updated per keyed root. The head of a
/// complete schedule (oldest turns) or a cut-off one (captured roots first)
/// is among these at most twice `NEXT_PAGE_FAMILIES` entries.
#[derive(Default)]
struct ScheduleHead<'r> {
    captured: std::collections::BinaryHeap<ScheduleTurn<'r>>,
    uncaptured: std::collections::BinaryHeap<ScheduleTurn<'r>>,
}

impl<'r> ScheduleHead<'r> {
    /// Keeps `entry` while it is among the oldest of its kind. Returns the
    /// entry that cannot be in the head (`entry` or the one it displaces).
    fn push(
        &mut self,
        entry: (&'r str, String, u64),
        captured: bool,
    ) -> Option<(&'r str, String, u64)> {
        let kept = if captured {
            &mut self.captured
        } else {
            &mut self.uncaptured
        };
        if kept.len() < capture::NEXT_PAGE_FAMILIES {
            kept.push(ScheduleTurn(entry));
            return None;
        }
        let mut newest = kept.peek_mut()?;
        Some(if schedule_order(&entry, &newest.0).is_lt() {
            std::mem::replace(&mut newest.0, entry)
        } else {
            entry
        })
    }

    /// The head in its order (a cut-off schedule ranks captured roots
    /// first) and the kept entries it leaves for the rest of the schedule.
    #[allow(clippy::type_complexity)]
    fn finish(self, cut_off: bool) -> (Vec<(&'r str, String, u64)>, Vec<(&'r str, String, u64)>) {
        let mut kept = self
            .captured
            .into_iter()
            .map(|turn| (false, turn.0))
            .chain(self.uncaptured.into_iter().map(|turn| (cut_off, turn.0)))
            .collect::<Vec<_>>();
        kept.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| schedule_order(&left.1, &right.1))
        });
        let rest = kept.split_off(kept.len().min(capture::NEXT_PAGE_FAMILIES));
        (
            kept.into_iter().map(|(_, entry)| entry).collect(),
            rest.into_iter().map(|(_, entry)| entry).collect(),
        )
    }
}

/// After family zero: key the roots scheduling did not reach and order the
/// page after the reserved turns (`head`, which keep their places; with
/// every root keyed this is the full schedule order). Charged to money time
/// like every deadline row it feeds.
fn complete_schedule<'r>(
    order: &mut Vec<(&'r str, String, u64)>,
    head: usize,
    unkeyed: &mut impl Iterator<Item = &'r str>,
    scope_key: &Path,
    ledger: &ClaudeLedger,
    done: &mut bool,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    if std::mem::replace(done, true) {
        return;
    }
    let keyed = order.len();
    order.extend(unkeyed.map(|root| schedule_entry(scope_key, ledger, root)));
    counts.families_keyed_after_first = (order.len() - keyed) as u64;
    order[head..].sort_by(schedule_order);
    #[cfg(test)]
    PAGE_SCHEDULE.with(|schedule| {
        *schedule.borrow_mut() = order
            .iter()
            .map(|(root, _, _)| (*root).to_owned())
            .collect();
    });
}

/// None when the deadline passed.
fn page_claims<'k>(
    keys: &'k [(&str, String)],
    api_report: &ClaudeLocalOtelLoadReport,
    deadline: Instant,
) -> Option<PageClaims<'k>> {
    let mut claims = PageClaims {
        page_claims: BTreeMap::new(),
        first_event: BTreeMap::new(),
    };
    for (root, key) in keys {
        for row in api_report.evidence.get(*root).into_iter().flatten() {
            if Instant::now() >= deadline {
                return None;
            }
            claims
                .page_claims
                .entry(claude_request_hash(&row.request_id))
                .or_default()
                .push(key);
            let clock = crate::claude_local_otel::telemetry_tail::event_unix(&row.observed_at);
            claims
                .first_event
                .entry(key.clone())
                .and_modify(|at: &mut u64| *at = (*at).min(clock))
                .or_insert(clock);
        }
    }
    Some(claims)
}

/// Page roots' session ids by telemetry key. The schedule already holds
/// each root's digest; it is indexed only when a classification asks.
struct PageSessions<'o, 'r, U> {
    order: &'o [(&'r str, String, u64)],
    /// Page roots scheduling has not keyed yet (family zero only).
    unkeyed: U,
    /// The family's body deadline: indexing stops there (no session).
    deadline: Instant,
    by_digest: std::cell::OnceCell<Option<BTreeMap<std::borrow::Cow<'o, str>, &'r str>>>,
}

impl<'o, 'r, U: Iterator<Item = &'r str> + Clone> claude_request_ledger::ClaudePageSessions
    for PageSessions<'o, 'r, U>
{
    fn page_session(&self, key: &str) -> Option<String> {
        let digest = key.strip_prefix(TELEMETRY_KEY_PREFIX)?;
        self.by_digest
            .get_or_init(|| {
                let mut by_digest = BTreeMap::new();
                for (root, key, _) in self.order {
                    if Instant::now() >= self.deadline {
                        return None;
                    }
                    by_digest.insert(
                        std::borrow::Cow::Borrowed(&key[FAMILY_KEY_PREFIX.len()..]),
                        *root,
                    );
                }
                for root in self.unkeyed.clone() {
                    if Instant::now() >= self.deadline {
                        return None;
                    }
                    let key = telemetry_key(root);
                    by_digest.insert(
                        std::borrow::Cow::Owned(key[TELEMETRY_KEY_PREFIX.len()..].to_owned()),
                        root,
                    );
                }
                Some(by_digest)
            })
            .as_ref()?
            .get(digest)
            .map(|root| (*root).to_owned())
    }
}

/// The rest of the writer's acknowledgements, once per page, after the
/// first scheduled family had its window.
fn apply_rest(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    counts: &mut ClaudeRequestMoneyShadowCounts,
    deadline: Instant,
    done: &mut bool,
) {
    if std::mem::replace(done, true) {
        return;
    }
    let applying = Instant::now();
    apply_results(support_dir, ledger, counts, deadline);
    counts.result_apply_us += applying.elapsed().as_micros() as u64;
}

/// What one page hands to the writer and the log.
struct PageEnd<'a> {
    support_dir: &'a Path,
    now: u64,
    census_complete: bool,
    started: Instant,
    /// Optional body work stops before the closing reserve (the first
    /// scheduled family's floor reaches into it).
    deadline: Instant,
    /// Housekeeping stops here, leaving time for handoff and return.
    close_deadline: Instant,
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

/// Money time at which common setup stops (with no capture time).
#[cfg(test)]
pub(crate) fn setup_stop_for_test() -> Duration {
    PAGE_MAX_ELAPSED - FIRST_FAMILY_CLOSE_RESERVE - FIRST_FAMILY_SETUP_RESERVE
}

#[cfg(test)]
pub(crate) fn set_deferred_compare_cursor_for_test(support_dir: &Path, now: u64, cursor: usize) {
    store::prime_credit_for_test(support_dir, utc_day(now));
    let ClaudeLedgerAcquire::Ready(mut ledger) = store::acquire(support_dir) else {
        panic!("test ledger ready");
    };
    ledger.deferred_compare_cursor = cursor;
}

#[cfg(test)]
pub(crate) fn seed_stale_memo_for_test(support_dir: &Path, now: u64) {
    store::prime_credit_for_test(support_dir, utc_day(now));
    let ClaudeLedgerAcquire::Ready(mut ledger) = store::acquire(support_dir) else {
        panic!("test ledger ready");
    };
    let memo = ClaudeFamilyMemo {
        published: Some(ClaudeFamilyPublication {
            utc_day: utc_day(now),
            digest: 0,
            epoch: process_epoch(),
            attempted: now - FAMILY_MEMO_RETENTION_SECONDS - 1,
        }),
        ..Default::default()
    };
    assert_eq!(
        ledger.insert(
            family_key("stale-never-reappearing"),
            ClaudeRequestCensusRecord::family_record([0; 32], 0, memo)
        ),
        ClaudeRequestCensusInsert::Stored
    );
}

#[allow(clippy::too_many_arguments)]
async fn build_page_at(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    census_complete: bool,
    now: u64,
    live: bool,
    output: &mut PageBodies,
) -> ClaudeRequestMoneyShadowCounts {
    let coverage = coverage::InterimFamilyCoverage {
        census_complete,
        ..Default::default()
    };
    build_page_with_coverage(
        support_dir,
        snapshots,
        index,
        api_report,
        trace_report,
        &coverage,
        census_complete,
        now,
        Instant::now(),
        live,
        output,
    )
    .await
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
        Instant::now(),
    )
}

/// The page from shadow entry to its very end: `money_us` is taken after the
/// body returned, so it includes the log line's serialization and write and
/// the drop of every page local and the ledger guard. The line itself
/// cannot carry that total; the scope's next line reports it as
/// `previous_page_money_us`.
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
    entered: Instant,
) -> ClaudeRequestMoneyShadowCounts {
    let mut output = PageBodies::default();
    let mut counts = crate::snapshot_sync::money_resume::immediate(build_page_with_coverage(
        support_dir,
        snapshots,
        index,
        api_report,
        trace_report,
        coverage_view,
        census_complete,
        now,
        entered,
        false,
        &mut output,
    ))
    .unwrap_or_default();
    counts.money_us = counts
        .capture_us
        .saturating_add(entered.elapsed().as_micros() as u64);
    if let Ok(mut pages) = PAGE_MONEY_US.lock() {
        pages.insert(support_dir.to_path_buf(), counts.money_us);
    }
    counts
}

/// Each scope's last complete page money time, for its next line.
static PAGE_MONEY_US: Mutex<BTreeMap<PathBuf, u64>> = Mutex::new(BTreeMap::new());

#[allow(clippy::too_many_arguments)]
async fn build_page_with_coverage(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    coverage_view: &dyn FamilyCoverage,
    census_complete: bool,
    now: u64,
    started: Instant,
    live: bool,
    output: &mut PageBodies,
) -> ClaudeRequestMoneyShadowCounts {
    let live = live && request_owned_live(support_dir);
    #[cfg(test)]
    PAGE_SCHEDULE.with(|schedule| schedule.borrow_mut().clear());
    let scope_key = shadow_scope(support_dir);
    // From this page on the scope is paged: a refusal before the plan
    // leaves the scope failing closed, never back to its first-page
    // all-eligible capture (MONEY decision).
    capture::mark_paged(&scope_key);
    // `clock.deadline` is `started` plus the money budget capture left, so
    // these are the same offsets in money time: optional work stops at
    // 150 ms, closing at 240 ms, 10 ms for the handoff.
    #[cfg_attr(not(test), allow(unused_mut))]
    let mut clock = capture::take_page_clock(&scope_key, started);
    #[cfg(test)]
    if let Some(budget) = PAGE_BUDGET.with(std::cell::Cell::take) {
        clock.deadline = started + budget;
    }
    let capture_us = clock.capture_us;
    let mut deadline = clock.deadline - PAGE_CLOSE_RESERVE;
    let mut first_family_deadline = clock.deadline - FIRST_FAMILY_CLOSE_RESERVE;
    let close_deadline = clock.deadline - Duration::from_millis(10);
    let snapshot = next_snapshot();
    let day = utc_day(now);
    let epoch = process_epoch();
    let mut counts = ClaudeRequestMoneyShadowCounts {
        capture_us,
        native_us: clock.native_us,
        capture_reserved_bytes: capture::capture_reserved() as u64,
        ..Default::default()
    };
    let mut end = PageEnd {
        support_dir,
        now,
        census_complete,
        started,
        deadline,
        close_deadline,
        tail: Default::default(),
        rows: Default::default(),
        scope: Default::default(),
    };
    if Instant::now() >= clock.deadline {
        // Accumulated capture time alone can exhaust the money budget before
        // any diagnostic page is admitted. Close with one false page, without
        // starting a ledger load, identity walk, body or digest after expiry.
        counts.refused_deadline = 1;
        purge_captures(&scope_key, &mut counts);
        return refuse(&end, None, index, snapshots.len(), counts);
    }
    let Some(root_funds) = ShadowReservation::admit(snapshots.len().saturating_mul(64)) else {
        counts.refused_budget = 1;
        return refuse(&end, None, index, snapshots.len(), counts);
    };
    // Each root's snapshots, grouped in the one admission pass over them.
    let admitting = Instant::now();
    let mut items_by_root = BTreeMap::<&str, Vec<&SnapshotItem>>::new();
    for item in snapshots {
        items_by_root
            .entry(claude_snapshot_family_root_ref(item))
            .or_default()
            .push(item);
    }
    let roots = &items_by_root;
    // Pre-admit metadata, every failure row, memos and writer buffer. No
    // family-specific scratch is charged until that family's turn.
    let key_bytes = index.files.keys().map(String::len).sum::<usize>();
    let residue_bytes = index
        .claude_request_census
        .records()
        .map(|(key, _)| key.len())
        .sum::<usize>();
    let page_claim_rows = roots
        .keys()
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
                + FAMILY_BYTES // one cached canonical failure template
                + 1024
                + tail_fixed_memory(&ClaudeTelemetryTailBudget::default()),
        );
    counts.admission_bytes = admission.saturating_add(root_funds.bytes()) as u64;
    counts.admission_us = admitting.elapsed().as_micros() as u64;
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
    // Common setup stops here, whatever it still has: the first scheduled
    // family's own setup and body keep the window up to their floor. The
    // acknowledgements left resume after that family.
    let setup_deadline = first_family_deadline - FIRST_FAMILY_SETUP_RESERVE;
    let applying = Instant::now();
    apply_results(
        support_dir,
        ledger,
        &mut counts,
        setup_deadline - SCHEDULE_SETUP_RESERVE,
    );
    counts.result_apply_us = applying.elapsed().as_micros() as u64;
    let mut applied_rest = false;
    if std::mem::take(&mut ledger.load_damaged) {
        counts.ledger_load_damaged = 1;
        drop_certificate(ledger);
    }
    // Scheduling keys each root (family key and turn) inside the setup slice.
    // Only the oldest turns are selected before family zero; past the stop,
    // they are the oldest of the roots keyed so far. Roots with a fresh
    // capture (the installed plan's families on a Full parse) are keyed
    // first, so a cut-off schedule still picks a captured family zero. The
    // rest is keyed and sorted after family zero.
    let captured_roots = capture::captured_index_keys(&scope_key)
        .iter()
        .filter_map(|key| super::claude_index_path_member_ref(Path::new(key)))
        .filter_map(|member| roots.get_key_value(member.root).map(|(root, _)| *root))
        .collect::<BTreeSet<_>>();
    let mut unkeyed = captured_roots.iter().copied().chain(
        roots
            .keys()
            .copied()
            .filter(|root| !captured_roots.contains(root)),
    );
    // The oldest turns are kept as roots are keyed; the reserved slots
    // receive them, with no pass over the keyed roots after the stop.
    let reserved = roots.len().min(capture::NEXT_PAGE_FAMILIES);
    let mut order = Vec::with_capacity(roots.len());
    order.resize_with(reserved, || ("", String::new(), 0));
    let mut oldest = ScheduleHead::default();
    let mut keyed = 0;
    for root in unkeyed.by_ref() {
        keyed += 1;
        let entry = schedule_entry(&scope_key, ledger, root);
        order.extend(oldest.push(entry, captured_roots.contains(root)));
        #[cfg(test)]
        if faulted(PageFault::ScheduleStall)
            && keyed == SCHEDULE_STALL_AFTER.with(std::cell::Cell::get).max(1)
        {
            // Scheduling used everything up to the setup stop.
            while Instant::now() < setup_deadline {
                std::hint::spin_loop();
            }
        }
        if Instant::now() >= setup_deadline {
            break;
        }
    }
    // A cut-off schedule ranks the captured roots it keyed first: family
    // zero and the other reserved turns then hold the captured bodies.
    let (head_turns, displaced) = oldest.finish(keyed < roots.len());
    let head = head_turns.len();
    // Fewer roots keyed than reserved slots: nothing follows the slots.
    order.truncate(order.len() - (reserved - head));
    for (slot, entry) in order.iter_mut().zip(head_turns) {
        *slot = entry;
    }
    order.extend(displaced);
    let mut schedule_complete = false;
    let capture_turns = order[..head]
        .iter()
        .map(|(root, _, _)| *root)
        .collect::<BTreeSet<_>>();
    // Only these oldest turns can have a captured body. Prioritize their
    // sidecars in the same order; the bounded global sweep still retains
    // cross-root telemetry debt and never treats an unvisited root as absent.
    let mut work = ClaudeLedgerWork::new(
        WORK_MAX_BYTES,
        WORK_MAX_STATS,
        setup_deadline.min(Instant::now() + TELEMETRY_MAX_ELAPSED),
    );
    let unloaded = order[..head]
        .iter()
        .map(|(root, _, _)| *root)
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
        claude_request_ledger::retire_telemetry_under_pressure(ledger, setup_deadline);
    if counts.telemetry_retired_pressure > 0 {
        drop_certificate(ledger);
    }
    prune_message_records(ledger, index, &mut counts);
    #[cfg(test)]
    if faulted(PageFault::SetupOverrun) || faulted(PageFault::SetupStall) {
        // Common setup used everything up to its stop. It runs busy, as real
        // setup does: a sleeping thread's wake-up can land past the stop.
        while Instant::now() < setup_deadline {
            std::hint::spin_loop();
        }
    }
    // Only scheduled families can be reached. Their body inputs are gathered
    // when the schedule reaches them, in its order: a family the page never
    // reaches costs only its deadline row.
    // Captures deposited after this belong to the next parse.
    let purge_at = Instant::now();
    let located = std::cell::OnceCell::<Option<ClaudeScopeFiles<'_>>>::new();
    let claim_keys = std::cell::OnceCell::new();
    let claims = std::cell::OnceCell::<Option<PageClaims<'_>>>::new();
    let mut scope = ClaudeLedgerScope::default();
    // Positions whose capture this page consumed, ascending (only the
    // scheduled head can be): their turns move to `now`, and they are the
    // fallback plan's exclusions.
    let mut reached_turns = Vec::new();
    let holder_view = ClaudeHolderView::of(coverage_view);
    let mut families = Vec::with_capacity(roots.len());
    let mut memos = Vec::with_capacity(roots.len());
    let mut reservations = vec![base, root_funds];
    let mut failed = 0;
    let mut written = 0;
    let mut incomplete = 0;
    let mut failure_digest = DeadlineDigest::default();
    counts.family_setup_us = started.elapsed().as_micros() as u64;
    // The first scheduled family is always attempted, before the body
    // deadline every later family keeps.
    let mut later_families = end.deadline;
    end.deadline = first_family_deadline;
    if faulted(PageFault::BodyDeadline) {
        (end.deadline, later_families) = (started, started);
    } else if faulted(PageFault::SetupOverrun) {
        later_families = started;
    }
    let mut position = 0;
    while position < order.len() {
        if position > 0 {
            end.deadline = later_families;
            apply_rest(
                support_dir,
                ledger,
                &mut counts,
                deadline,
                &mut applied_rest,
            );
        }
        let mut body_deadline = end.deadline;
        let (root, key, turn) = order[position].clone();
        if !capture_turns.contains(root) || preflight_check(end.deadline).is_err() {
            complete_schedule(
                &mut order,
                head,
                &mut unkeyed,
                &scope_key,
                ledger,
                &mut schedule_complete,
                &mut counts,
            );
            apply_rest(
                support_dir,
                ledger,
                &mut counts,
                deadline,
                &mut applied_rest,
            );
            let deferred_started = Instant::now();
            // Closing hashes only the admitted canonical failure template.
            // Identity/day/epoch suppression is a producer decision, before
            // the writer can consume the day cap on identical deadline rows.
            let deferred = (order.len() - position) as u64;
            // Reserve retention (10ms), plan (at least 10ms: up to the
            // save's slice), and save (10ms) separately; none can consume
            // the following slice.
            let compare_until = end.close_deadline - Duration::from_millis(30);
            let suffix = &order[position..];
            let mut first_uncompared = None;
            // Comparisons rotate from the cursor; rows still follow the
            // schedule. Memos pushed before the rotation wraps move last.
            let first_memo = memos.len();
            let rotation = ledger.deferred_compare_cursor % suffix.len();
            let mut before_wrap = 0;
            for at in deferred_comparison_order(suffix.len(), ledger.deferred_compare_cursor) {
                let (root, key, turn) = &suffix[at];
                let state = coverage_view.family(root);
                // Only a current acknowledged publication can be unchanged.
                // The writer computes the canonical digest before returning
                // its acknowledgement, so new/expired/in-flight rows need no
                // synchronous SHA of the entire deferred wire template.
                // A comparison is optional; never let canonical hashing of
                // a large suffix consume the retention/save/handoff slice.
                // Without a completed comparison we publish the explicit
                // failure, whose digest is finalized by the writer.
                let compare = Instant::now() < compare_until;
                if !compare {
                    first_uncompared.get_or_insert(at);
                }
                let unchanged = compare
                    .then(|| published_digest(ledger, key, day, epoch))
                    .flatten()
                    .is_some_and(|digest| failure_digest.deferred(root, &state, ledger) == digest);
                if unchanged {
                    counts.unchanged += 1;
                    // Nothing was consumed or published. Re-acknowledging an
                    // unchanged deferred memo only dirties the ledger and
                    // makes the following page redo thousands of inserts.
                    continue;
                }
                failed += 1;
                memos.push(PendingMemo {
                    key: key.clone(),
                    basis: None,
                    observed_unix: *turn,
                    published: ClaudeFamilyPublication {
                        utc_day: day,
                        digest: 0, // replaced by the writer's canonical digest
                        epoch,
                        attempted: now,
                    },
                    row: true,
                    deferred: Some((root.to_string(), state)),
                });
                before_wrap += usize::from(at >= rotation);
            }
            memos[first_memo..].rotate_left(before_wrap);
            ledger.deferred_compare_cursor = first_uncompared.unwrap_or(0);
            counts.families += deferred;
            counts.families_unbuilt += deferred;
            counts.families_deadline_deferred += deferred;
            counts.certificate_mismatch += deferred;
            counts.removed_change_unavailable += deferred;
            counts.deferred_close_us = deferred_started.elapsed().as_micros() as u64;
            incomplete += deferred;
            break;
        }
        let items = &roots[root];
        // The page's one index walk and its page roots' claims, when the
        // schedule first reaches a family.
        let files = located
            .get_or_init(|| ClaudeScopeFiles::walk(index, &capture_turns, body_deadline))
            .as_ref();
        let claimed = files.and_then(|_| {
            claims
                .get_or_init(|| {
                    page_claims(
                        claim_keys
                            .get_or_init(|| {
                                page_claim_keys(&order, unkeyed.clone(), api_report, body_deadline)
                            })
                            .as_deref()?,
                        api_report,
                        body_deadline,
                    )
                })
                .as_ref()
        });
        // Then this family's own members, captures and scope, in that order:
        // its captures' message records precede its scope's debt.
        let family = match (files, claimed) {
            (Some(files), Some(_)) => family_files(index, files, root, items, body_deadline),
            _ => None,
        };
        let mut family_captures = BTreeMap::new();
        if let Some(family) = &family {
            for item in items {
                if Instant::now() >= body_deadline {
                    break;
                }
                let Some(keys) = family
                    .member_keys
                    .get(&(root.to_owned(), item.source_session_id.clone()))
                else {
                    continue;
                };
                let Some(key) = keys
                    .iter()
                    .find(|key| {
                        index.files.get(*key).is_some_and(|entry| {
                            item.source_file_fingerprint.as_deref()
                                == Some(&entry.source_file_fingerprint)
                        })
                    })
                    .or_else(|| (keys.len() == 1).then(|| &keys[0]))
                else {
                    continue;
                };
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
                    note_message_record(
                        ledger,
                        index,
                        key,
                        fingerprint,
                        &capture,
                        live,
                        &mut counts,
                    );
                    // Families reached earlier may have scoped this file.
                    scope.refresh_file(index, ledger.census(), key);
                    family_captures.insert(
                        (
                            root.to_owned(),
                            if live {
                                item.source_file_fingerprint.clone().unwrap_or_default()
                            } else {
                                item.source_session_id.clone()
                            },
                        ),
                        capture,
                    );
                }
            }
        }
        let prepared = match (files, &family) {
            (Some(files), Some(family)) => add_family_scope(
                &mut scope,
                index,
                ledger.census(),
                files,
                family,
                root,
                body_deadline,
            )
            .ok_or("deadline"),
            _ => Err("deadline"),
        };
        let capture_consumed = !family_captures.is_empty();
        let scratch = prepared.and_then(|()| {
            family_preflight(
                root,
                items,
                &family_captures,
                ledger,
                api_report,
                trace_report,
                body_deadline,
            )
        });
        let state = coverage_view.family(root);
        let mut basis = None;
        let mut rows;
        let mut owned_reservation = None;
        let slice = scratch.and_then(|scratch| ShadowReservation::admit(scratch).ok_or("memory"));
        match slice {
            Ok(reservation) => {
                let mut budget = ShadowBudget::new(reservation);
                let family = family.as_ref().expect("admitted body requires its files");
                let claims = claimed.expect("admitted body requires the page claims");
                let sessions = PageSessions {
                    order: &order,
                    unkeyed: unkeyed.clone(),
                    deadline: body_deadline,
                    by_digest: Default::default(),
                };
                let before_wait = end.started;
                let result = build_slice(
                    root,
                    items,
                    &family.member_keys,
                    &family.indexed_members,
                    family_captures,
                    ledger,
                    index,
                    api_report,
                    trace_report,
                    &root_states,
                    &claims.page_claims,
                    &claims.first_event,
                    sessions,
                    &mut scope,
                    holder_view,
                    live,
                    &mut budget,
                    &mut end,
                    &mut counts,
                )
                .await;
                let paused = end.started.saturating_duration_since(before_wait);
                deadline += paused;
                body_deadline += paused;
                first_family_deadline += paused;
                clock.deadline += paused;
                counts.admitted_peak_bytes = counts
                    .admitted_peak_bytes
                    .max(SHADOW_RESERVED.load(Ordering::Acquire) as u64);
                match result {
                    Ok((mut body, union, absent, unknown)) => {
                        if live {
                            for item in items {
                                let key = family
                                    .member_keys
                                    .get(&(root.to_owned(), item.source_session_id.clone()))
                                    .and_then(|keys| {
                                        keys.iter()
                                            .min_by_key(|key| selection::primary_order(index, key))
                                    });
                                let birth = key
                                    .and_then(|key| index.claude_request_census.get(key))
                                    .and_then(|record| record.birth())
                                    .map(|birth| birth.unix_seconds);
                                output.births.insert(item.source_session_id.clone(), birth);
                            }
                            output.entities.append(&mut body.entities);
                        }
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
                if live {
                    output._reservations.push(budget);
                }
            }
            Err(reason) => {
                rows = failure_rows(root, reason, state, now, snapshot, ledger, &mut counts);
            }
        }
        if !rows.row.old_available && !rows.row.p1_reasons.contains(&"deadline") {
            if let Some(members) = family
                .as_ref()
                .and_then(|family| family.indexed_members.get(root))
            {
                if let Some(revision) = union_revision_by(members, body_deadline) {
                    rows.row.revision = hex_revision(&revision);
                }
                rows.row.members_total = members.len().max(items.len());
                rows.row.absent_old_unknown = members.len().saturating_sub(items.len()) as u64;
            }
        }
        let digest = if rows.row.p1_reasons.contains(&"deadline") {
            // Already a bounded failure row: never repeat body construction
            // or tallying after expiry.
            if !rows.row.old_available {
                failure_digest.digest(&mut rows)
            } else {
                semantic_digest(&mut rows)
            }
        } else if let Some(digest) = semantic_digest_by(&mut rows, Some(body_deadline)) {
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
        let unchanged = publication_unchanged(ledger, &key, digest, day, epoch);
        // Publication and capture scheduling are distinct. A reached
        // family denied capture keeps its old turn too, otherwise small
        // pages repeatedly pick the same first 64 despite reaching all roots.
        memos.push(PendingMemo {
            key,
            basis: if unchanged { None } else { basis },
            observed_unix: if capture_consumed { now } else { turn },
            published: ClaudeFamilyPublication {
                utc_day: day,
                digest,
                epoch,
                attempted: now,
            },
            row: !unchanged,
            deferred: None,
        });
        if capture_consumed {
            reached_turns.push(position);
        }
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
        // The rest of the schedule, right after family zero and before the
        // loop decides whether another family remains.
        complete_schedule(
            &mut order,
            head,
            &mut unkeyed,
            &scope_key,
            ledger,
            &mut schedule_complete,
            &mut counts,
        );
        position += 1;
    }
    complete_schedule(
        &mut order,
        head,
        &mut unkeyed,
        &scope_key,
        ledger,
        &mut schedule_complete,
        &mut counts,
    );
    // Captures of families the page did not reach.
    counts.captures_purged += capture::purge_before(&scope_key, purge_at);
    end.scope = scope.debt;
    for &position in &reached_turns {
        order[position].2 = now;
    }
    if faulted(PageFault::LateAtHandOff) || faulted(PageFault::BatchRefused) {
        counts.refused_deadline = u64::from(faulted(PageFault::LateAtHandOff));
        counts.refused_budget = u64::from(faulted(PageFault::BatchRefused));
        drop(families);
        drop(reservations);
        return refuse(&end, Some(ledger), index, roots.len(), counts);
    }
    // Optional body work has ended. Housekeeping owns the closing slice;
    // it must not inherit the already-expired body deadline.
    counts.family_memos_dropped = drop_old_family_memos(
        ledger,
        now,
        end.close_deadline
            .checked_sub(Duration::from_millis(20))
            .expect("closing reserve")
            .min(Instant::now() + Duration::from_millis(10)),
    );
    // This only selects optional captures; it grants no publication or
    // coverage evidence. Reached turns yield to deferred turns on a Full
    // reread, without changing native file order or retaining old captures.
    // A page of at most 64 families makes them all eligible.
    // The fallback's O(64) selection, the oldest 64 entries this page did
    // not consume: only the scheduled head can be consumed and the rest of
    // `order` is sorted, so they are among the head's unconsumed entries
    // and the rest's first 64.
    let mut oldest = order[..head]
        .iter()
        .enumerate()
        .filter(|(position, _)| reached_turns.binary_search(position).is_err())
        .map(|(_, entry)| entry)
        .chain(order[head..].iter().take(capture::NEXT_PAGE_FAMILIES))
        .collect::<Vec<_>>();
    oldest.sort_by(|left, right| schedule_order(left, right));
    let fallback = oldest
        .into_iter()
        .take(capture::NEXT_PAGE_FAMILIES)
        .map(|(_, key, turn)| (key.as_str(), *turn, true))
        .chain(reached_turns.iter().map(|&position| {
            let (_, key, turn) = &order[position];
            (key.as_str(), *turn, false)
        }));
    // The plan may use the closing budget up to the save's slice; its
    // walk is bounded by its funds (the capture ceiling).
    let installed = capture::plan_next_page(
        &scope_key,
        order.iter().map(|(_, key, turn)| (key.as_str(), *turn)),
        fallback,
        end.close_deadline
            .checked_sub(Duration::from_millis(10))
            .expect("closing reserve"),
    );
    if let Some(failure) = installed.failure() {
        counts.plan_install_failed = 1;
        *match failure {
            capture::PlanFailure::Deadline => &mut counts.plan_install_failed_deadline,
            capture::PlanFailure::Funds => &mut counts.plan_install_failed_funds,
            capture::PlanFailure::Lock => &mut counts.plan_install_failed_lock,
        } = 1;
    }
    counts.fallback_plan_installed =
        u64::from(matches!(installed, capture::PlanInstall::Fallback(_)));
    counts.full_page_zero_built = u64::from(
        counts.captures_taken + counts.captures_purged > 0
            && counts.families > 0
            && counts.families_unbuilt == counts.families,
    );
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
async fn build_slice(
    root: &str,
    items: &[&SnapshotItem],
    member_keys: &BTreeMap<(String, String), Vec<String>>,
    indexed_members: &BTreeMap<String, BTreeSet<String>>,
    mut captures: BTreeMap<(String, String), ClaudeResponseCapture>,
    ledger: &mut ClaudeLedger,
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    root_states: &BTreeMap<String, ClaudeRootTelemetry>,
    page_claims: &BTreeMap<u64, Vec<&str>>,
    first_event: &BTreeMap<String, u64>,
    sessions: impl claude_request_ledger::ClaudePageSessions + Send,
    scope: &mut ClaudeLedgerScope,
    holder_view: ClaudeHolderView,
    live: bool,
    budget: &mut ShadowBudget,
    end: &mut PageEnd<'_>,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) -> Result<(ClaudeRequestBody, [u8; 32], ClaudeMoneyTotals, u64), &'static str> {
    let mut deadline = end.deadline;
    let now = end.now;
    let roots = BTreeSet::from([root]);
    let items = items.to_vec();
    let key_of = |root: &str, member: &str| {
        member_keys
            .get(&(root.to_owned(), member.to_owned()))
            .and_then(|keys| {
                keys.iter()
                    .min_by_key(|key| selection::primary_order(index, key))
                    .cloned()
            })
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
        traces.insert(root.to_owned(), BTreeMap::new());
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

    if live {
        ledger.finish_rebuild(index, end.census_complete && telemetry_certified(ledger));
        let mut updates = MoneyWatchUpdates::new();
        let complete = schedule_evidence(ledger, index, now, deadline, budget, &mut updates)
            && schedule_trace(ledger, index, &traces, now, deadline, budget, &mut updates);
        let waiting = Instant::now();
        let durable = checkpoint_money_watches_resume(end.support_dir, ledger, updates).await;
        let paused = waiting.elapsed();
        deadline += paused;
        end.deadline += paused;
        end.close_deadline += paused;
        end.started += paused;
        if !complete || !durable {
            return Err("memory");
        }
        counts.unbuilt_older_released +=
            update_unbuilt_lifecycle(index, ledger, &BTreeSet::new(), now, deadline)
                .ok_or("memory")?;
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

    let mut aliases = BTreeMap::<String, String>::new();
    if live {
        let mut primary = BTreeMap::<(Option<&str>, String, String), &str>::new();
        for key in index.files.keys() {
            if Instant::now() >= deadline {
                return Err("deadline");
            }
            if let Some((root, member)) = logical_family_member(index, key) {
                let entry = primary
                    .entry((
                        claude_request_ledger::claude_project_group(key),
                        root,
                        member,
                    ))
                    .or_insert(key);
                if selection::primary_order(index, key) < selection::primary_order(index, entry) {
                    *entry = key;
                }
            }
        }
        for key in index.files.keys() {
            if Instant::now() >= deadline {
                return Err("deadline");
            }
            if let Some((root, member)) = logical_family_member(index, key) {
                if let Some(primary) = primary.get(&(
                    claude_request_ledger::claude_project_group(key),
                    root,
                    member,
                )) {
                    if !budget.charge(key.len() + primary.len() + 128) {
                        return Err("memory");
                    }
                    aliases.insert(key.clone(), (*primary).to_owned());
                }
            }
        }
    }
    struct Sessions<'a> {
        page: &'a dyn claude_request_ledger::ClaudePageSessions,
        aliases: &'a BTreeMap<String, String>,
    }
    impl claude_request_ledger::ClaudePageSessions for Sessions<'_> {
        fn page_session(&self, key: &str) -> Option<String> {
            self.page.page_session(key)
        }
        fn canonical_file<'k>(&'k self, key: &'k str) -> &'k str {
            self.aliases.get(key).map(String::as_str).unwrap_or(key)
        }
    }
    let sessions = Sessions {
        page: &sessions,
        aliases: &aliases,
    };
    let ctx = ClaudeClassifyContext {
        index,
        ledger: ledger.census(),
        holders: &holders,
        scope,
        page_claims,
        first_event,
        sessions: &sessions,
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
        let total = members.len()
            + items
                .iter()
                .map(|item| &item.source_session_id)
                .collect::<BTreeSet<_>>()
                .iter()
                .filter(|member| !members.contains(**member))
                .count();
        let mut family_captures = BTreeMap::new();
        for item in items {
            if let Some(capture) = captures.remove(&(
                root.to_owned(),
                if live {
                    item.source_file_fingerprint.clone().unwrap_or_default()
                } else {
                    item.source_session_id.clone()
                },
            )) {
                family_captures.insert(
                    if live {
                        item.source_file_fingerprint
                            .as_deref()
                            .unwrap_or(&item.source_session_id)
                    } else {
                        item.source_session_id.as_str()
                    },
                    capture,
                );
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
        counts.undecided_unbuilt_older += ctx.unbuilt_older.get();
        let blocking = scope.blocking_files();
        drop(ctx);
        drop(holders);
        if live {
            counts.unbuilt_older_released +=
                update_unbuilt_lifecycle(index, ledger, &blocking, now, deadline)
                    .ok_or("memory")?;
            for (member, entity) in &body.entities {
                if let (Some(key), Some(due)) = (key_of(root, member), entity.due_unix) {
                    let revision = ledger
                        .get(&store::money_key("dirty:", &key))
                        .map(|record| record.money_revision())
                        .unwrap_or_else(|| Sha256::digest(key.as_bytes()).into());
                    if !ledger.put_money(
                        store::money_key("due:", &key),
                        ClaudeRequestCensusRecord::money_debt(revision, due),
                    ) {
                        return Err("memory");
                    }
                }
            }
        }
        let union = union_revision_by(members, deadline).ok_or("deadline")?;
        Ok((body, union, absent_old, absent_old_unknown))
    }
}

pub(crate) fn is_protected_item(index: &ScanIndex, item: &SnapshotItem) -> bool {
    index
        .claude_reemission_exclusions
        .protected_root(claude_snapshot_family_root_ref(item))
}

pub(crate) struct LivePageEvidence<'a> {
    pub(crate) api: &'a ClaudeLocalOtelLoadReport,
    pub(crate) trace: &'a ClaudeTraceOwnershipLoadReport,
    pub(crate) census_complete: bool,
}

/// Build once, publish the P1 comparison, then apply only certified members.
/// Protected entities keep the existing body; failed builds become local holds.
pub(crate) async fn live_page_resume(
    support_dir: &Path,
    snapshots: &mut Vec<SnapshotItem>,
    index: &ScanIndex,
    evidence: LivePageEvidence<'_>,
    identity: Option<&mut super::claude_request_identity::ScanEvidence<'_>>,
    groupings: &mut BTreeMap<String, super::claude_request_identity::Grouping>,
) -> BTreeSet<String> {
    let mut output = PageBodies::default();
    let counts = guarded_resume(build_page_at(
        support_dir,
        snapshots,
        index,
        evidence.api,
        evidence.trace,
        evidence.census_complete,
        page_now(support_dir),
        true,
        &mut output,
    ))
    .await;
    if counts.refused_budget > 0 {
        // A refused build owns no literal body. Release this turn's local
        // holds through the normal finish, then collect ordinary bodies on
        // the next turn rather than retrying saturated live admission forever.
        store::refuse_live(support_dir);
        eprintln!("claude_request_money builder_admission_refused=1");
    }
    apply_live_page(snapshots, index, &output, identity.as_deref(), groupings)
}

fn apply_live_page(
    snapshots: &mut Vec<SnapshotItem>,
    index: &ScanIndex,
    output: &PageBodies,
    identity: Option<&super::claude_request_identity::ScanEvidence<'_>>,
    groupings: &mut BTreeMap<String, super::claude_request_identity::Grouping>,
) -> BTreeSet<String> {
    let mut held = BTreeSet::new();
    let present = snapshots
        .iter()
        .filter_map(|item| item.source_file_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    let page_members = snapshots
        .iter()
        .map(|item| item.source_session_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut custody = BTreeMap::<String, (BTreeSet<&str>, Option<String>)>::new();
    for (key, entry) in &index.files {
        let Some((root, member)) = logical_family_member(index, key) else {
            continue;
        };
        if index.claude_reemission_exclusions.protected_root(&root) {
            continue;
        }
        if !page_members.contains(member.as_str()) {
            continue;
        }
        let (projects, _) = custody.entry(member.clone()).or_default();
        if let Some(project) = claude_request_ledger::claude_project_group(key) {
            projects.insert(project);
        }
        if !present.contains(entry.source_file_fingerprint.as_str()) {
            held.insert(member);
        }
    }
    for item in snapshots.iter() {
        if index
            .claude_reemission_exclusions
            .protected_root(claude_snapshot_family_root_ref(item))
        {
            continue;
        }
        let account = serde_json::to_string(&(
            item.session_account_evidence.as_ref().map(|evidence| {
                (
                    evidence.provider,
                    evidence.account_identifier_hash.as_deref(),
                    evidence.provider_workspace_hash.as_deref(),
                    evidence.identity_hash_scheme,
                )
            }),
            &item.workspace_hash,
            &item.repository_hash,
        ))
        .unwrap_or_default();
        let (projects, first) = custody.entry(item.source_session_id.clone()).or_default();
        if projects.len() > 1 || first.as_ref().is_some_and(|prior| prior != &account) {
            held.insert(item.source_session_id.clone());
        }
        first.get_or_insert(account);
    }
    let mut union_ids = BTreeMap::<String, BTreeSet<String>>::new();
    for item in snapshots.iter() {
        union_ids
            .entry(item.source_session_id.clone())
            .or_default()
            .extend(item.claude_usage_request_ids.iter().cloned());
    }
    let mut activity = BTreeMap::<&str, Option<String>>::new();
    for item in snapshots.iter() {
        let last = activity.entry(&item.source_session_id).or_default();
        for value in [&item.source_last_activity_at, &item.source_ended_at]
            .into_iter()
            .flatten()
        {
            if last
                .as_ref()
                .map_or(true, |prior| super::timestamp_is_after(value, prior))
            {
                *last = Some(value.clone());
            }
        }
    }
    let activity = activity
        .into_iter()
        .map(|(member, clock)| (member.to_owned(), clock))
        .collect::<BTreeMap<_, _>>();
    // Retain one carrier before emission/identity allocation: applying a full
    // union once per physical copy would create quadratic transient memory.
    let mut primaries = BTreeMap::<String, String>::new();
    for key in index.files.keys() {
        if let Some((_, member)) = logical_family_member(index, key) {
            let replace = primaries.get(&member).map_or(true, |prior| {
                selection::primary_order(index, key) < selection::primary_order(index, prior)
            });
            if replace {
                primaries.insert(member, key.clone());
            }
        }
    }
    let mut retained = BTreeSet::new();
    snapshots.retain(|item| {
        if index
            .claude_reemission_exclusions
            .protected_root(claude_snapshot_family_root_ref(item))
        {
            return true;
        }
        let primary = primaries
            .get(&item.source_session_id)
            .and_then(|key| index.files.get(key));
        let primary_present =
            primary.is_some_and(|entry| present.contains(entry.source_file_fingerprint.as_str()));
        let keep = !primary_present
            || primary.is_some_and(|entry| {
                item.source_file_fingerprint.as_deref() == Some(&entry.source_file_fingerprint)
            });
        keep && retained.insert(item.source_session_id.clone())
    });
    for item in snapshots.iter_mut() {
        let member_id = item.source_session_id.clone();
        let root = claude_snapshot_family_root_ref(item);
        if index.claude_reemission_exclusions.protected_root(root) {
            continue;
        }
        let birth = output.births.get(&member_id).copied().flatten();
        if held.contains(&member_id)
            || index.claude_reemission_exclusions.pauses_emission()
            || index
                .claude_reemission_exclusions
                .holds_without_list_before(
                    birth,
                    super::claude_history_upgrade::revision_policy(3)
                        .map_or(u64::MAX, |policy| policy.no_list_birth_cutoff_unix_seconds),
                )
            || !output
                .entities
                .get(&member_id)
                .is_some_and(|entity| emit::apply(item, entity))
        {
            held.insert(item.source_session_id.clone());
        } else if let Some(clock) = activity.get(&member_id).and_then(Option::as_ref) {
            if item
                .source_last_activity_at
                .as_ref()
                .map_or(true, |prior| super::timestamp_is_after(clock, prior))
            {
                item.source_last_activity_at = Some(clock.clone());
            }
            if item
                .source_ended_at
                .as_ref()
                .map_or(true, |prior| super::timestamp_is_after(clock, prior))
            {
                item.source_ended_at = Some(clock.clone());
            }
        }
        if !held.contains(&member_id) {
            if let Some(ids) = union_ids.get(&member_id) {
                item.claude_usage_request_ids = ids.clone();
            }
            if let (Some(evidence), Some(entity)) =
                (identity, output.entities.get(&item.source_session_id))
            {
                if let Some(grouping) =
                    super::claude_request_identity::request_owned_grouping(item, evidence, entity)
                {
                    groupings.insert(item.source_session_id.clone(), grouping);
                }
            }
        }
    }
    held
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn live_page(
    support_dir: &Path,
    snapshots: &mut Vec<SnapshotItem>,
    index: &ScanIndex,
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
    census_complete: bool,
    identity: Option<&super::claude_request_identity::ScanEvidence<'_>>,
    groupings: &mut BTreeMap<String, super::claude_request_identity::Grouping>,
) -> BTreeSet<String> {
    let mut output = PageBodies::default();
    let _ = crate::snapshot_sync::money_resume::drive_for_test(guarded_resume(build_page_at(
        support_dir,
        snapshots,
        index,
        api,
        trace,
        census_complete,
        page_now(support_dir),
        true,
        &mut output,
    )));
    apply_live_page(snapshots, index, &output, identity, groupings)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn live_page_for_test(
    support: &Path,
    snapshots: &mut Vec<SnapshotItem>,
    index: &ScanIndex,
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
    complete: bool,
    identity: Option<&super::claude_request_identity::ScanEvidence<'_>>,
    groupings: &mut BTreeMap<String, super::claude_request_identity::Grouping>,
) -> BTreeSet<String> {
    live_page(
        support, snapshots, index, api, trace, complete, identity, groupings,
    )
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
        .and_then(|record| record.family_memo())
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
    hex_bytes(revision)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
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

fn publication_unchanged(
    ledger: &ClaudeLedger,
    key: &str,
    digest: u64,
    day: u64,
    epoch: u64,
) -> bool {
    published_digest(ledger, key, day, epoch) == Some(digest)
}

fn published_digest(ledger: &ClaudeLedger, key: &str, day: u64, epoch: u64) -> Option<u64> {
    if ledger.in_flight(key) {
        return None;
    }
    ledger
        .get(key)
        .and_then(|record| record.family_memo())
        .and_then(|(_, memo)| memo.published)
        .filter(|published| published.utc_day == day && published.epoch == epoch)
        .map(|published| published.digest)
}

/// Streaming canonical digest, without a second copy of the row or grains.
/// Snapshot, observation time and removal-basis deltas are not semantic content.
fn semantic_digest(rows: &mut FamilyRows) -> u64 {
    semantic_digest_by(rows, None).expect("bounded writer digest")
}

fn semantic_digest_by(rows: &mut FamilyRows, deadline: Option<Instant>) -> Option<u64> {
    // Serde writes punctuation and numbers in tiny chunks. Feeding each one
    // into SHA independently made closing thousands of bounded failure rows
    // dominate the page. Buffer without changing a single canonical byte;
    // keep deadline checks at every serialization write, not just each flush.
    struct HashWriter {
        hash: Sha256,
        deadline: Option<Instant>,
        buffer: [u8; 4096],
        used: usize,
    }
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "money digest deadline",
                ));
            }
            #[cfg(test)]
            if self.deadline.is_some()
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
            let mut remaining = bytes;
            while !remaining.is_empty() {
                let len = remaining.len().min(self.buffer.len() - self.used);
                self.buffer[self.used..self.used + len].copy_from_slice(&remaining[..len]);
                self.used += len;
                remaining = &remaining[len..];
                if self.used == self.buffer.len() {
                    self.hash.update(self.buffer);
                    self.used = 0;
                }
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.hash.update(&self.buffer[..self.used]);
            self.used = 0;
            Ok(())
        }
    }
    let mut hash = HashWriter {
        hash: Sha256::new(),
        deadline,
        buffer: [0; 4096],
        used: 0,
    };
    write_semantic(rows, &mut hash).ok()?;
    hash.flush().ok()?;
    Some(u64::from_be_bytes(
        hash.hash.finalize()[..8].try_into().expect("digest"),
    ))
}

/// The single canonical encoder used by streaming bodies and cached failures.
fn write_semantic(rows: &mut FamilyRows, writer: &mut impl Write) -> serde_json::Result<()> {
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
    let result = serde_json::to_writer(&mut *writer, &*row).and_then(|()| {
        for (key, (old, new)) in &rows.grains {
            serde_json::to_writer(&mut *writer, &grain_row(row, key, old, new))?;
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
    result
}

/// Only `failure_rows(..., "deadline", ...)` uses this cache. Such rows
/// differ solely in family identity and the census wire fields. Serialize
/// one exact canonical template per census shape, then reuse its SHA prefix
/// and suffix bytes. This preserves the digest and unchanged suppression
/// without repeating hundreds of serde calls per deferred family.
#[derive(Default)]
struct DeadlineDigest {
    template: Option<DeadlineTemplate>,
    #[cfg(test)]
    misses: usize,
}
struct DeadlineTemplate {
    census: &'static str,
    reason: Option<coverage::CensusReason>,
    statuses: BTreeMap<&'static str, u64>,
    prefix: ring::digest::Context,
    bytes: Vec<u8>,
    suffix: usize,
}
impl DeadlineDigest {
    fn deferred(&mut self, root: &str, state: &FamilyCensus, ledger: &ClaudeLedger) -> u64 {
        let (census, reason, statuses) = state.wire();
        if self.template.as_ref().is_some_and(|template| {
            template.census == census && template.reason == reason && template.statuses == statuses
        }) {
            // The wire identity has its own domain separator; it is not
            // the scheduling key digest. Hash only the admitted root bytes.
            return self.identity(&hashed_id(root));
        }
        let mut rows = failure_rows(
            root,
            "deadline",
            state.clone(),
            0,
            0,
            ledger,
            &mut Default::default(),
        );
        self.digest(&mut rows)
    }

    fn identity(&self, family: &str) -> u64 {
        let template = self.template.as_ref().expect("canonical deadline template");
        let mut hash = template.prefix.clone();
        hash.update(family.as_bytes());
        hash.update(&template.bytes[template.suffix..]);
        u64::from_be_bytes(hash.finish().as_ref()[..8].try_into().expect("digest"))
    }

    fn digest(&mut self, rows: &mut FamilyRows) -> u64 {
        if rows.row.family.len() != 16 {
            return semantic_digest(rows);
        }
        let matches = self.template.as_ref().is_some_and(|template| {
            template.census == rows.row.census
                && template.reason == rows.row.census_reason
                && template.statuses == rows.row.key_statuses
        });
        if !matches {
            #[cfg(test)]
            {
                self.misses += 1;
            }
            // Fixed admitted buffer: future schema growth cannot allocate
            // beyond the template allowance before falling back.
            self.template = None;
            let mut bytes = vec![0; FAMILY_BYTES];
            let mut writer = std::io::Cursor::new(bytes.as_mut_slice());
            if write_semantic(rows, &mut writer).is_err() {
                return semantic_digest(rows);
            }
            let len = writer.position() as usize;
            bytes.truncate(len);
            let needle = b"\"family\":\"";
            let start = bytes
                .windows(needle.len())
                .position(|part| part == needle)
                .expect("canonical family field")
                + needle.len();
            let suffix = start + rows.row.family.len();
            let mut prefix = ring::digest::Context::new(&ring::digest::SHA256);
            prefix.update(&bytes[..start]);
            self.template = Some(DeadlineTemplate {
                census: rows.row.census,
                reason: rows.row.census_reason,
                statuses: rows.row.key_statuses.clone(),
                prefix,
                bytes,
                suffix,
            });
        }
        self.identity(&rows.row.family)
    }
}

#[cfg(test)]
thread_local! {
    static DIGEST_WRITES_FOR_TEST: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Captures not selected for this page have no cross-page body lifetime.
/// Drop them now so they cannot crowd the next Full page's selected turns.
fn purge_captures(scope_key: &Path, counts: &mut ClaudeRequestMoneyShadowCounts) {
    counts.captures_purged += capture::purge_before(scope_key, Instant::now());
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
/// bounded save to the writer. All durable I/O runs on the writer. A
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
            deadline: end.close_deadline,
            utc_day: utc_day(end.now),
            min_interval: store::SAVE_MIN_INTERVAL,
        }) {
            Some((taken, reservation)) => {
                counts.ledger_save_shards = taken.shards() as u64;
                counts.ledger_save_bytes = taken.bytes() as u64;
                reservations.push(reservation);
                save = Some(taken);
            }
            None if Instant::now() >= end.close_deadline => counts.ledger_save_late = 1,
            None => counts.ledger_save_refused = u64::from(ledger.dirty_shards() > 0),
        }
        counts.admitted_peak_bytes = counts
            .admitted_peak_bytes
            .max(SHADOW_RESERVED.load(Ordering::Acquire) as u64);
        counts.ledger_save_oversized = ledger.oversized_shards;
        counts.save_bytes_today = ledger.save_bytes_today;
    }
    counts.ledger_loads_refused = store::loads_refused();
    counts.jsonl_queued = families.iter().map(FamilyRows::rows).sum::<u64>()
        + memos.iter().filter(|memo| memo.deferred.is_some()).count() as u64
        + 1;
    let job = WriteJob {
        support_dir: end.support_dir.to_path_buf(),
        pending_intent: None,
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
        None => claude_request_ledger::ledger_state_counts(census, ledger, end.close_deadline),
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
    counts.previous_page_money_us = PAGE_MONEY_US
        .lock()
        .ok()
        .and_then(|mut pages| pages.remove(end.support_dir))
        .unwrap_or(0);
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
    deadline: Instant,
) {
    store::consume_results_until(support_dir, ledger, deadline, |ledger, acknowledgement| {
        match acknowledgement {
            store::Acknowledgement::Outcome(jsonl, writer_us) => {
                counts.writer_us += writer_us;
                counts.jsonl_rows += jsonl.rows;
                counts.jsonl_truncated += jsonl.truncated;
                counts.jsonl_sealed += jsonl.sealed;
                counts.jsonl_failed += jsonl.failed;
                counts.jsonl_owed_written += jsonl.owed_written;
            }
            store::Acknowledgement::Memo(memo, true) => apply_published_memo(ledger, memo, counts),
            store::Acknowledgement::Memo(_, false) => counts.family_memos_withheld += 1,
        }
    });
}

fn apply_published_memo(
    ledger: &mut ClaudeLedger,
    memo: PendingMemo,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    let previous = ledger
        .get(&memo.key)
        .and_then(|record| record.family_memo())
        .map(|(revision, basis)| (*revision, basis));
    let (revision, mut basis) = memo.basis.filter(|_| memo.row).or(previous).unwrap_or((
        [0; 32],
        ClaudeFamilyMemo {
            removed_requests: u64::MAX,
            ..Default::default()
        },
    ));
    basis.published = Some(memo.published);
    // An interrupted earlier acknowledgement may land before a later
    // no-capture memo built from stale producer state. Never roll back a
    // capture turn that has already been durably published in between.
    let turn = ledger.get(&memo.key).map_or(memo.observed_unix, |record| {
        record.window().max(memo.observed_unix)
    });
    let record = ClaudeRequestCensusRecord::family_record(revision, turn, basis);
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
    live: bool,
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
    let verified = record.current_holder_for(fingerprint, true);
    let next = ClaudeRequestCensusRecord::message_record(record, capture.message_only_hashes());
    if let Some((root, member)) = live.then(|| logical_family_member(index, key)).flatten() {
        if !ledger.bind_file(key, root, member, record.birth()) {
            counts.message_records_refused += 1;
            return;
        }
    }
    let message = message_key(key);
    if ledger.get(&message).is_some_and(|old| old.matches(&next)) {
        if verified {
            ledger.note_rebuilt(key);
        }
        return;
    }
    let hashes = next.request_hashes().len();
    let census = ledger.census();
    let fits = census.hash_headroom() >= hashes
        && census.serialized_headroom() >= hashes * 11 + message.len() + 512;
    if fits && ledger.insert(message, next) == ClaudeRequestCensusInsert::Stored {
        if verified {
            ledger.note_rebuilt(key);
        }
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
        .message_records_after(&cursor, MESSAGE_PRUNE_PER_PAGE)
        .map(|(key, record)| {
            let file = &key[MESSAGE_KEY_PREFIX.len()..];
            let current = index.claude_request_census.get(file).is_some_and(|file| {
                file.money_revision() == record.money_revision() && file.retired().is_none()
            });
            (key, current)
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

/// Start unfinished comparisons first next page without changing capture turns.
fn deferred_comparison_order(len: usize, start: usize) -> impl Iterator<Item = usize> {
    (0..len).map(move |at| (at + start % len) % len)
}

/// Drop family memos no page rebuilt within the retention window. Cursor
/// advancement includes fresh records, so a fresh prefix cannot hide stale
/// records indefinitely. Scratch and work are bounded independently of size.
fn drop_old_family_memos(ledger: &mut ClaudeLedger, now: u64, deadline: Instant) -> u64 {
    const PER_PAGE: usize = 256;
    let Some(_scratch) = ShadowReservation::admit(PER_PAGE * 256) else {
        return 0;
    };
    let cutoff = now.saturating_sub(FAMILY_MEMO_RETENTION_SECONDS);
    let due = ledger
        .census()
        .records_with_prefix_after(FAMILY_KEY_PREFIX, &ledger.family_cursor)
        .take_while(|_| Instant::now() < deadline)
        .take(PER_PAGE)
        .map(|(key, record)| {
            let stale = record.family_memo().is_some_and(|(_, memo)| {
                // An unreached family's scheduling turn may remain at zero;
                // retention follows its real last publication, not that priority.
                memo.published
                    .map_or(record.window(), |published| published.attempted)
                    < cutoff
            });
            (key.clone(), stale)
        })
        .collect::<Vec<_>>();
    if due.is_empty() && Instant::now() < deadline {
        ledger.family_cursor.clear();
    }
    let mut dropped = 0;
    for (key, stale) in due {
        if Instant::now() >= deadline {
            break;
        }
        if stale {
            ledger.remove(&key);
            dropped += 1;
        }
        ledger.family_cursor = key;
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

/// Persist the latched debts from a snapshot taken outside the mutex: fsync
/// never blocks the producer's in-memory debt latch. A wake job closes the
/// idle-writer race. A debt whose synced marker is still on disk costs one
/// stat and no write; a missing marker (deleted) is written again, so a
/// restart keeps the debt. Unsynced debts are written (or retried).
fn persist_coverage_debt() {
    let debts = COVERAGE_OWED
        .lock()
        .ok()
        .map(|owed| {
            owed.iter()
                .flat_map(|(dir, days)| {
                    days.iter()
                        .map(move |(day, owed)| (dir.clone(), day.clone(), *owed))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (dir, day, owed) in debts {
        let present = || {
            std::fs::symlink_metadata(owed_path(&dir.join("diagnostics"), &day))
                .is_ok_and(|meta| meta.file_type().is_file())
        };
        if !owed.marked || !present() {
            owe_coverage(&dir, owed.observed, true);
        }
    }
}

/// One day's latched debt: the earliest page that owes it, and whether a
/// marker this process synced holds that page (or an earlier one).
#[derive(Debug, Clone, Copy)]
struct OwedDay {
    observed: u64,
    marked: bool,
}

/// False coverage rows owed per support directory: day -> the earliest
/// page that owes it (a dropped batch, or one whose rows were not written).
/// A debt of a write that failed is also a marker file in the day's
/// directory (Sol R3-6), so a restart keeps it: the writer reads the markers
/// back with every batch. A dropped batch's debt is latched in memory only
/// (no file I/O under the sync lock); the writer's next batch writes it.
static COVERAGE_OWED: Mutex<BTreeMap<PathBuf, BTreeMap<String, OwedDay>>> =
    Mutex::new(BTreeMap::new());

fn day_path(dir: &Path, day: &str) -> PathBuf {
    dir.join(format!("{JSONL_PREFIX}{day}.jsonl"))
}

/// The marker of a day's owed false coverage row (its content: the earliest
/// owing page's `observed_unix`).
fn owed_path(dir: &Path, day: &str) -> PathBuf {
    dir.join(format!(".{JSONL_PREFIX}{day}.owed"))
}

/// The page at `observed_unix` did not reach its day's file: the next batch
/// writes a false coverage row there. `durable` also writes the day's marker, a few bytes, once per owing day (a later
/// debt of the same day keeps it).
fn owe_coverage(support_dir: &Path, observed_unix: u64, durable: bool) -> bool {
    let Some(day) = day_stamp(observed_unix) else {
        return false;
    };
    let dir = support_dir.join("diagnostics");
    let marker = owed_path(&dir, &day);
    let marked = if durable && std::fs::create_dir_all(&dir).is_ok() {
        // Existence cannot prove durability after a failed directory sync.
        // Retry the atomic write and propagate its actual sync result.
        let earliest = std::fs::metadata(&marker)
            .ok()
            .filter(|meta| meta.len() <= 32)
            .and_then(|_| std::fs::read_to_string(&marker).ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map_or(observed_unix, |old| old.min(observed_unix));
        store::write_atomic(&marker, earliest.to_string().as_bytes()).then_some(earliest)
    } else {
        None
    };
    if let Ok(mut owed) = COVERAGE_OWED.lock() {
        let slot = owed
            .entry(support_dir.to_path_buf())
            .or_default()
            .entry(day)
            .or_insert(OwedDay {
                observed: observed_unix,
                marked: false,
            });
        // A failed marker write is retried when the writer idles; an earlier
        // page needs a new marker; a later one keeps the synced marker.
        slot.marked = match marked {
            Some(earliest) => earliest <= slot.observed.min(observed_unix),
            None => !durable && slot.marked && observed_unix >= slot.observed,
        };
        slot.observed = slot.observed.min(observed_unix);
    }
    if !durable {
        store::wake_writer();
    }
    marked.is_some()
}

/// A false row of `day` is on disk: its debt is settled.
fn read_marker_time(path: &Path) -> Option<u64> {
    use std::io::Read;
    let mut text = String::new();
    let file = money_io!(Open, std::fs::File::open(path)).ok()?;
    money_io!(Read, file.take(64).read_to_string(&mut text)).ok()?;
    text.parse().ok()
}

fn settle_owed(dir: &Path, day: &str) {
    let _ = money_io!(Mutate, std::fs::remove_file(owed_path(dir, day)));
    if let Ok(entries) = money_io!(ReadDir, std::fs::read_dir(dir)) {
        let prefix = format!(".{JSONL_PREFIX}{day}.");
        let own = format!(".{}.", store::intent_run_id());
        for entry in entries.take(JSONL_MAX_DIR_ENTRIES).flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".pending") && !name.contains(&own) {
                let _ = money_io!(Mutate, std::fs::remove_file(entry.path()));
            }
        }
    }
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
        .unwrap_or_default()
        .into_iter()
        .map(|(day, owed)| (day, owed.observed))
        .collect::<BTreeMap<_, _>>();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return owed;
    };
    for entry in entries.take(JSONL_MAX_DIR_ENTRIES).flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(day) = name
            .strip_prefix('.')
            .and_then(|name| name.strip_prefix(JSONL_PREFIX))
            .and_then(|name| name.strip_suffix(".pending"))
            .and_then(|name| name.split('.').next())
            .filter(|day| day.len() == 8 && day.bytes().all(|b| b.is_ascii_digit()))
        {
            if oldest.is_some_and(|oldest| day < oldest) {
                let _ = money_io!(Mutate, std::fs::remove_file(entry.path()));
                continue;
            }
            if !name.contains(&format!(".{}.", store::intent_run_id())) {
                if let Some(observed) = read_marker_time(&entry.path()) {
                    owed.entry(day.to_owned())
                        .and_modify(|first| *first = (*first).min(observed))
                        .or_insert(observed);
                }
            }
            continue;
        }
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
            let _ = money_io!(Mutate, std::fs::remove_file(entry.path()));
            continue;
        }
        if marker.is_some() {
            let observed = money_io!(ReadFile, std::fs::read_to_string(entry.path()))
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
    let Ok(mut file) = money_io!(Open, std::fs::File::open(path)) else {
        return false;
    };
    let mut last = [0_u8; 1];
    file.seek(SeekFrom::End(-1)).is_ok()
        && money_io!(Read, file.read_exact(&mut last)).is_ok()
        && last[0] != b'\n'
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
        let size =
            money_io!(Metadata, std::fs::metadata(path)).map_or(0, |metadata| metadata.len());
        #[cfg(test)]
        crate::retry_allocation_probe::money_io_attempt(
            crate::retry_allocation_probe::MoneyIoKind::Open,
        );
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
                money_io!(Write, serde_json::to_writer(&mut *writer, row)).is_ok()
                    && money_io!(Write, writer.write_all(b"\n")).is_ok()
            });
    }

    /// True when every row reached the file.
    fn finish(self) -> bool {
        self.written
            && self.writer.is_some_and(|mut writer| {
                money_io!(Write, writer.flush())
                    .and_then(|()| money_io!(Sync, writer.get_ref().sync_all()))
                    .is_ok()
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

/// Conservative crash recovery for queued/refused work that never reached
/// the writer: every retained day containing earlier rows owes false coverage.
/// Fixed day probes avoid an unbounded diagnostics-directory traversal.
fn recover_queued_coverage(support: &Path, now: u64) {
    for days in 0..JSONL_RETENTION_DAYS {
        let observed = now.saturating_sub(days as u64 * 86400);
        if let Some(day) = day_stamp(observed) {
            if money_io!(
                Metadata,
                day_path(&support.join("diagnostics"), &day).exists()
            ) {
                owe_coverage(support, observed, true);
            }
        }
    }
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
    let Some(today) =
        day_stamp(now).filter(|_| money_io!(Mutate, std::fs::create_dir_all(&dir)).is_ok())
    else {
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

/// The selector reads only this support directory's ledger, before taking
/// page custody. Missing/loading state is never interpreted as acceptance.
pub(crate) fn family_root(item: &SnapshotItem) -> &str {
    claude_snapshot_family_root_ref(item)
}

#[cfg(test)]
pub(crate) fn checkpoint_pending(support: &Path) -> bool {
    store::checkpoint_pending(support)
}

pub(crate) fn has_offer(support: &Path, key: &str) -> bool {
    store::has_offer(support, key)
}

pub(crate) fn recovery_offer(support: &Path, key: &str, fp: &str) -> Option<RecoveryOffer> {
    store::recovery_offer(support, key, fp)
}

pub(crate) fn recovery_offer_debt_retired(support: &Path, key: &str, offer: RecoveryOffer) -> bool {
    store::recovery_offer_debt_retired(support, key, offer)
}

pub(crate) fn recovery_offer_covers_debt(
    index: &ScanIndex,
    item: &SnapshotItem,
    offers: &BTreeMap<String, RecoveryOffer>,
) -> bool {
    let Some(support) = index.active_request_money_support_dir.as_deref() else {
        return false;
    };
    let mut found = false;
    for (key, entry) in &index.files {
        let contributes = item.source_file_fingerprint.as_deref()
            == Some(entry.source_file_fingerprint.as_str())
            || index.claude_money_files.get(key).is_some_and(|selection| {
                selection.revision == entry.source_file_fingerprint
                    && selection.root == family_root(item)
                    && selection.member == item.source_session_id
            });
        if contributes {
            found = true;
            if !offers
                .get(key)
                .is_some_and(|offer| store::recovery_debt_is_covered(support, key, *offer))
            {
                return false;
            }
        }
    }
    found
}

/// Evidence rebuilding is independent of adoption. It schedules an opened
/// read for older saved witness revisions while literal offers remain closed.
pub(crate) fn money_rebuild_due(support_dir: &Path, index_key: &str) -> bool {
    request_owned_live(support_dir) && store::rebuild_due(support_dir, index_key)
}

pub(crate) fn money_due(support_dir: &Path, index_key: &str, now: u64) -> bool {
    request_owned_live(support_dir) && store::scheduled(support_dir, index_key, now)
}

fn revision_of<'a>(
    record: impl Into<custody::RecordRef<'a>>,
    deadline: Instant,
) -> Option<[u8; 32]> {
    let record = record.into();
    let mut hash = Sha256::new();
    hash.update(record.money_revision());
    for hashes in record.request_hashes().chunks(1024) {
        if Instant::now() >= deadline {
            return None;
        }
        for request in hashes {
            hash.update(request.to_be_bytes());
        }
    }
    if let Some(facts) = record.facts() {
        for bytes in facts.chunks(8192) {
            if Instant::now() >= deadline {
                return None;
            }
            hash.update(bytes);
        }
    }
    Some(hash.finalize().into())
}

/// Reverse dependencies include former holders as well as current holders.
/// Watches share only hashes; telemetry facts retain their existing custody.
/// Sixteen direct holders are retained per changed key, with family-root
/// fallback for overflow. Every loop is covered by the page deadline.
fn evidence_watch_key(key: &str) -> String {
    store::money_key(
        if key.starts_with(MESSAGE_KEY_PREFIX) {
            "watch:m:"
        } else {
            "watch:r:"
        },
        key,
    )
}

fn schedule_evidence(
    ledger: &mut ClaudeLedger,
    index: &ScanIndex,
    now: u64,
    deadline: Instant,
    budget: &mut ShadowBudget,
    updates: &mut MoneyWatchUpdates,
) -> bool {
    let key_charge = index
        .claude_request_census
        .records()
        .map(|(key, record)| (key.clone(), custody::RecordRef::from(record)))
        .chain(ledger.census().records_with_prefix(TELEMETRY_KEY_PREFIX))
        .chain(ledger.census().records_with_prefix(MESSAGE_KEY_PREFIX))
        .fold(0_usize, |bytes, (key, _)| {
            bytes.saturating_add(key.len()).saturating_add(128)
        });
    if !budget.charge(key_charge) {
        return false;
    }
    let keys = index
        .claude_request_census
        .records()
        .map(|(key, _)| key.clone())
        .chain(
            ledger
                .census()
                .records_with_prefix(TELEMETRY_KEY_PREFIX)
                .map(|(key, _)| key.clone()),
        )
        .chain(
            ledger
                .census()
                .records_with_prefix(MESSAGE_KEY_PREFIX)
                .map(|(key, _)| key.clone()),
        )
        .collect::<Vec<_>>();
    // Resolve family roots once; never walk the index once per dependent.
    let mut roots = BTreeMap::<String, &str>::new();
    for key in index.files.keys() {
        if Instant::now() >= deadline {
            return false;
        }
        if let Some((root, member)) = logical_family_member(index, key) {
            if root == member {
                roots.insert(root, key);
            }
        }
    }
    if !budget.charge(keys.len().saturating_mul(256)) {
        return false;
    }
    let present = keys
        .iter()
        .map(|key| evidence_watch_key(key))
        .collect::<BTreeSet<_>>();
    let missing_charge = ledger
        .census()
        .records_with_prefix("watch:")
        .filter(|(key, _)| !key.starts_with("watch:trace:") && !present.contains(key))
        .fold(0_usize, |bytes, (key, _)| {
            bytes.saturating_add(key.len()).saturating_add(128)
        });
    if !budget.charge(missing_charge) {
        return false;
    }
    let missing = ledger
        .census()
        .records_with_prefix("watch:")
        .filter(|(key, _)| !key.starts_with("watch:trace:") && !present.contains(key))
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for watch in missing {
        if Instant::now() >= deadline {
            return false;
        }
        let Some(old) = ledger.get(&watch) else {
            continue;
        };
        let mut revision = Sha256::new();
        revision.update(old.money_revision());
        revision.update(b"evidence_removed");
        let revision: [u8; 32] = revision.finalize().into();
        let mut affected = BTreeSet::new();
        let mut direct_holders = 0_usize;
        for candidate in index.files.keys() {
            if Instant::now() >= deadline {
                return false;
            }
            let Some((root, _)) = logical_family_member(index, candidate) else {
                continue;
            };
            let mut affected_holder = evidence_watch_key(&telemetry_key(&root)) == watch;
            let holder = if watch.starts_with("watch:m:") {
                ledger.get(&message_key(candidate))
            } else {
                index
                    .claude_request_census
                    .get(candidate)
                    .map(custody::RecordRef::from)
            };
            if let Some(holder) = holder {
                for requests in holder.request_hashes().chunks(1024) {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    if requests
                        .iter()
                        .any(|request| old.request_hashes().binary_search(request).is_ok())
                    {
                        affected_holder = true;
                        break;
                    }
                }
            }
            if affected_holder {
                if direct_holders < 16 {
                    affected.insert(candidate.as_str());
                    direct_holders += 1;
                }
                if let Some(root_key) = roots.get(&root) {
                    affected.insert(*root_key);
                }
            }
        }
        for key in affected {
            if !stage_money_dirty(ledger, key, revision, now) {
                return false;
            }
        }
        // Phase two runs only after dependent debt has crossed a barrier.
        if !stage_money_watch(updates, watch, None, budget) {
            return false;
        }
    }
    for key in keys {
        if Instant::now() >= deadline {
            return false;
        }
        let record = if key.starts_with(TELEMETRY_KEY_PREFIX) || key.starts_with(MESSAGE_KEY_PREFIX)
        {
            ledger.get(&key)
        } else {
            index
                .claude_request_census
                .get(&key)
                .map(custody::RecordRef::from)
        };
        let Some(record) = record.filter(|record| !record.is_birth_stub()) else {
            continue;
        };
        let Some(revision) = revision_of(record, deadline) else {
            return false;
        };
        let watch_key = evidence_watch_key(&key);
        let previous = ledger.get(&watch_key);
        if previous.is_some_and(|previous| previous.money_revision() == revision) {
            continue;
        }
        let watch = record.money_watch(revision);
        let mut affected = BTreeSet::new();
        let mut holders = 0_usize;
        for candidate in index.files.keys() {
            if Instant::now() >= deadline {
                return false;
            }
            let Some((root, _)) = logical_family_member(index, candidate) else {
                continue;
            };
            let direct = *candidate == key
                || message_key(candidate) == key
                || telemetry_key(&root) == key
                || logical_family_member(index, candidate) == logical_family_member(index, &key);
            let mut intersects = false;
            let holder = if key.starts_with(MESSAGE_KEY_PREFIX) {
                ledger.get(&message_key(candidate))
            } else {
                index
                    .claude_request_census
                    .get(candidate)
                    .map(custody::RecordRef::from)
            };
            if let Some(holder) = holder {
                for requests in holder.request_hashes().chunks(1024) {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    if requests.iter().any(|request| {
                        record.request_hashes().binary_search(request).is_ok()
                            || previous.is_some_and(|old| {
                                old.request_hashes().binary_search(request).is_ok()
                            })
                    }) {
                        intersects = true;
                        break;
                    }
                }
            }
            if direct || intersects {
                if holders < 16 {
                    affected.insert(candidate.as_str());
                    holders += 1;
                }
                if let Some(root_key) = roots.get(&root) {
                    affected.insert(*root_key);
                }
            }
        }
        // A per-record commit means a large bootstrap makes progress over
        // bounded pages. The watch moves only after every dirty mark fits.
        for key in affected {
            if !stage_money_dirty(ledger, key, revision, now) {
                return false;
            }
        }
        if !stage_money_watch(updates, watch_key, Some(watch), budget) {
            return false;
        }
    }
    true
}

/// Persist exact offered-body -> current debt bindings before the network
/// boundary. Local holds are bound to the parsed file revision and paced;
/// they never erase v1 authority or account-hold records.
fn retire_money_hold(ledger: &mut ClaudeLedger, key: &str) {
    let hold_key = store::money_key("hold:", key);
    if let Some(hold) = ledger.get(&hold_key) {
        use std::fmt::Write as _;
        let mut fingerprint = String::with_capacity(64);
        for byte in hold.money_revision() {
            let _ = write!(fingerprint, "{byte:02x}");
        }
        ledger.remove(&format!("hold:body:{fingerprint}"));
    }
    ledger.remove(&hold_key);
}

#[cfg(test)]
pub(crate) fn prepare_money_offers(
    support_dir: &Path,
    index: &ScanIndex,
    snapshots: &[SnapshotItem],
    held: &BTreeSet<String>,
) -> bool {
    prepare_money_offers_receipt(support_dir, index, snapshots, held) == MoneyReceipt::Ready
}

pub(crate) fn prepare_money_offers_receipt(
    support_dir: &Path,
    index: &ScanIndex,
    snapshots: &[SnapshotItem],
    held: &BTreeSet<String>,
) -> MoneyReceipt {
    prepare_money_offers_receipt_with_recovery(support_dir, index, snapshots, held, &|_, _| None)
}

/// `recovered` supplies only an immutable attempt's validated, durably saved
/// exact-body ACK bounds. It must never reconstruct a newer offer as proof.
pub(crate) fn prepare_money_offers_receipt_with_recovery(
    support_dir: &Path,
    index: &ScanIndex,
    snapshots: &[SnapshotItem],
    held: &BTreeSet<String>,
    recovered: &dyn Fn(&str, &SnapshotItem) -> Option<RecoveryOffer>,
) -> MoneyReceipt {
    if !request_owned_live(support_dir) {
        return MoneyReceipt::Ready;
    }
    let mut ledger = match store::acquire(support_dir) {
        ClaudeLedgerAcquire::Ready(ledger) => ledger,
        ClaudeLedgerAcquire::Loading => return MoneyReceipt::Pending,
        ClaudeLedgerAcquire::Unavailable => return MoneyReceipt::Refused,
    };
    apply_results(
        support_dir,
        &mut ledger,
        &mut ClaudeRequestMoneyShadowCounts::default(),
        Instant::now() + PAGE_MAX_ELAPSED,
    );
    if ledger.recovering() {
        return MoneyReceipt::Refused;
    }
    let deadline = Instant::now() + PAGE_MAX_ELAPSED;
    let cutoff = page_now(support_dir).saturating_sub(35 * 86400);
    let stale_count = ledger
        .census()
        .records_with_prefix("union:")
        .filter(|(_, record)| record.window() < cutoff)
        .count();
    let Some(_discovery_funds) = ShadowReservation::admit(stale_count.saturating_mul(256)) else {
        return MoneyReceipt::Refused;
    };
    let stale = ledger
        .census()
        .records_with_prefix("union:")
        .filter(|(_, record)| record.window() < cutoff)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for key in stale {
        if Instant::now() >= deadline {
            return MoneyReceipt::Refused;
        }
        ledger.remove(&key);
    }
    let mut offer_count = ledger.census().offer_total();
    let by_source = union_items_by_source(index, snapshots);
    for (key, entry) in &index.files {
        if Instant::now() >= deadline {
            return MoneyReceipt::Refused;
        }
        let Some(item) = by_source.get(entry.source_file_fingerprint.as_str()) else {
            continue;
        };
        if index
            .claude_reemission_exclusions
            .protected_root(claude_snapshot_family_root_ref(item))
        {
            continue;
        }
        if let Some(discovery) = selection::discovery_revision(index, key) {
            let discovery_key = store::money_key("union:", key);
            let observed = ledger
                .get(&discovery_key)
                .filter(|record| record.money_revision() == discovery)
                .map_or_else(|| page_now(support_dir), |record| record.window());
            if !ledger.put_money(
                discovery_key,
                ClaudeRequestCensusRecord::money_debt(discovery, observed),
            ) {
                return MoneyReceipt::Refused;
            }
        }
        if held.contains(&item.source_session_id) {
            let Some(revision) =
                super::claude_request_census::decode_fingerprint(&entry.source_file_fingerprint)
            else {
                return MoneyReceipt::Refused;
            };
            if ledger
                .get(&store::money_key("hold:", key))
                .is_some_and(|hold| {
                    hold.money_revision() == revision && hold.window() > page_now(support_dir)
                })
            {
                continue;
            }
            retire_money_hold(&mut ledger, key);
            if !ledger.put_money(
                store::money_key("hold:", key),
                ClaudeRequestCensusRecord::money_debt(
                    revision,
                    page_now(support_dir).saturating_add(1800),
                ),
            ) {
                return MoneyReceipt::Refused;
            }
            // The restored predecessor keeps its old source revision, so the
            // retry must be readable without a physical file change.
            if !ledger.put_money(
                store::money_key("due:", key),
                ClaudeRequestCensusRecord::money_debt(
                    revision,
                    page_now(support_dir).saturating_add(1800),
                ),
            ) {
                return MoneyReceipt::Refused;
            }
            if !ledger.put_money(
                format!("hold:body:{}", entry.source_file_fingerprint),
                ClaudeRequestCensusRecord::money_debt(
                    revision,
                    page_now(support_dir).saturating_add(1800),
                ),
            ) {
                return MoneyReceipt::Refused;
            }
        } else if item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_CONTRACT) {
            if let Some(original) = recovered(key, item) {
                // A saved replay ACK covers only its original debt/time. Never
                // move this binding to the handoff tick or certify newer debt.
                if !store::recovery_debt_is_covered_in(&ledger, key, original) {
                    return MoneyReceipt::Refused;
                }
                let offer = format!(
                    "{}:{}",
                    store::money_key("offer:", key),
                    item.snapshot_fingerprint
                );
                if ledger.get(&offer).is_some_and(|old| {
                    old.money_revision() == original.0 && old.window() == original.1
                }) {
                    continue;
                }
                let new_offer = ledger.get(&offer).is_none();
                if new_offer
                    && (offer_count >= MAX_MONEY_OFFERS_PER_CONTEXT
                        || ledger.census().offer_count_for(key) >= MAX_MONEY_OFFERS_PER_FILE)
                {
                    return MoneyReceipt::Refused;
                }
                if !ledger.put_money(
                    offer,
                    ClaudeRequestCensusRecord::money_debt(original.0, original.1),
                ) {
                    return MoneyReceipt::Refused;
                }
                offer_count += usize::from(new_offer);
                continue;
            }
            let dirty = store::money_key("dirty:", key);
            let revision = ledger
                .get(&dirty)
                .or_else(|| ledger.get(&store::money_key("due:", key)))
                .map(|record| record.money_revision())
                .unwrap_or_else(|| Sha256::digest(entry.source_file_fingerprint.as_bytes()).into());
            let due_key = store::money_key("due:", key);
            if ledger.get(&due_key).is_none()
                && !ledger.put_money(
                    due_key,
                    ClaudeRequestCensusRecord::money_debt(revision, page_now(support_dir)),
                )
            {
                return MoneyReceipt::Refused;
            }
            let offer = format!(
                "{}:{}",
                store::money_key("offer:", key),
                item.snapshot_fingerprint
            );
            // A re-offer after server pacing covers debt at this new time.
            // Keep future maturity and newer revisions behind their guards.
            if ledger.get(&offer).is_some_and(|old| {
                old.money_revision() == revision && old.window() >= page_now(support_dir)
            }) {
                continue;
            }
            let new_offer = ledger.get(&offer).is_none();
            if new_offer
                && (offer_count >= MAX_MONEY_OFFERS_PER_CONTEXT
                    || ledger.census().offer_count_for(key) >= MAX_MONEY_OFFERS_PER_FILE)
            {
                // The due/dirty obligation is independent and remains owed.
                // Reconciliation must reclaim superseded offers before a new
                // exact body can consume another slot; no POST occurs here.
                return MoneyReceipt::Refused;
            }
            if !ledger.put_money(
                offer,
                ClaudeRequestCensusRecord::money_debt(revision, page_now(support_dir)),
            ) {
                return MoneyReceipt::Refused;
            }
            offer_count += usize::from(new_offer);
        }
    }
    store::checkpoint_receipt(support_dir, &mut ledger)
}

pub(crate) fn money_hold_rereadable(support_dir: &Path, key: &str) -> bool {
    store::hold_rereadable(support_dir, key)
}

pub(crate) fn money_hold_bound(index: &ScanIndex, item: &SnapshotItem) -> bool {
    let Some(support_dir) = index.active_request_money_support_dir.as_deref() else {
        return false;
    };
    let Some(revision) = item.source_file_fingerprint.as_deref() else {
        return false;
    };
    store::hold_revision_bound(support_dir, revision)
}

/// After the selected index is durable, a covering literal ACK clears its
/// dirty/due record. Callers must save the selected index first. An older
/// ACK cannot clear a transfer discovered after its offer; a partial body's
/// ACK leaves a future maturity deadline in place.
pub(crate) fn settle_money_acks(
    support_dir: &Path,
    index: &ScanIndex,
    snapshots: &[SnapshotItem],
    accepted: &BTreeSet<String>,
    bodies: &BTreeMap<String, String>,
) {
    if !request_owned_live(support_dir) {
        return;
    }
    let ClaudeLedgerAcquire::Ready(mut ledger) = store::acquire(support_dir) else {
        return;
    };
    apply_results(
        support_dir,
        &mut ledger,
        &mut ClaudeRequestMoneyShadowCounts::default(),
        Instant::now() + PAGE_MAX_ELAPSED,
    );
    let deadline = Instant::now() + PAGE_MAX_ELAPSED;
    let by_source = union_items_by_source(index, snapshots)
        .into_iter()
        .filter(|(_, item)| {
            item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_CONTRACT)
                && accepted.contains(&item.snapshot_fingerprint)
                && bodies
                    .get(&item.snapshot_fingerprint)
                    .is_some_and(|body| body == &super::snapshot_upload_body_witness(item))
        })
        .collect::<BTreeMap<_, _>>();
    for (key, entry) in &index.files {
        if Instant::now() >= deadline {
            break;
        }
        let Some(item) = by_source.get(entry.source_file_fingerprint.as_str()) else {
            continue;
        };
        // A selected-state rollback may retain the old body of this same
        // physical file. Its ACK does not settle the newly offered body.
        let Some(body) = bodies.get(&item.snapshot_fingerprint) else {
            continue;
        };
        // The finalizer stores domain-separated SET digests, including for
        // one logical entity. Compare that same representation for each
        // primary/secondary checkpoint, never a raw entity/body fingerprint.
        let singleton_set = |domain: &[u8], value: &str| {
            let mut digest = Sha256::new();
            super::update_length_prefixed(&mut digest, domain);
            super::update_length_prefixed(&mut digest, value.as_bytes());
            format!("{:x}", digest.finalize())
        };
        if entry.last_snapshot_fingerprint.as_ref()
            != Some(&singleton_set(
                b"snapshot_file_entity_set:v1",
                &item.snapshot_fingerprint,
            ))
            || entry.last_upload_body_witness.as_ref()
                != Some(&singleton_set(b"snapshot_file_upload_body_set:v1", body))
        {
            continue;
        }
        let offer_key = format!(
            "{}:{}",
            store::money_key("offer:", key),
            item.snapshot_fingerprint
        );
        let Some(offer) = ledger.get(&offer_key) else {
            continue;
        };
        let (revision, offered_at) = (offer.money_revision(), offer.window());
        for prefix in ["dirty:", "due:"] {
            let debt_key = store::money_key(prefix, key);
            if ledger.get(&debt_key).is_some_and(|debt| {
                debt.money_revision() == revision && debt.window() <= offered_at
            }) {
                ledger.remove(&debt_key);
            }
        }
        retire_money_hold(&mut ledger, key);
        ledger.remove(&format!("hold:body:{}", entry.source_file_fingerprint));
        ledger.remove(&offer_key);
    }
    reconcile_money_offers(&mut ledger, index, index, snapshots, deadline);
    // Failure preserves/replays debt; it never manufactures acceptance.
    let _ = store::checkpoint(support_dir, &mut ledger);
}

/// Only called behind a successful selected-index save, with no earlier
/// network operation in flight. Offer bindings are evidence, never debt:
/// removing an obsolete binding cannot remove due/dirty scheduling records.
fn reconcile_money_offers(
    ledger: &mut ClaudeLedger,
    index: &ScanIndex,
    proposed_index: &ScanIndex,
    snapshots: &[SnapshotItem],
    deadline: Instant,
) {
    let Some(_funds) = ShadowReservation::admit(
        index
            .files
            .len()
            .saturating_mul(256)
            .saturating_add(proposed_index.files.len().saturating_mul(512))
            .saturating_add(ledger.census().record_count().saturating_mul(256)),
    ) else {
        return;
    };
    let proposed_sources = union_items_by_source(proposed_index, snapshots);
    let current_offers = proposed_index
        .files
        .iter()
        .filter_map(|(key, entry)| {
            let item = proposed_sources.get(entry.source_file_fingerprint.as_str())?;
            Some(format!(
                "{}:{}",
                store::money_key("offer:", key),
                item.snapshot_fingerprint
            ))
        })
        .collect::<BTreeSet<_>>();
    let by_source = union_items_by_source(index, snapshots);
    let by_member = snapshots
        .iter()
        .map(|item| {
            (
                (
                    claude_snapshot_family_root_ref(item),
                    item.source_session_id.as_str(),
                ),
                item.snapshot_fingerprint.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let current = index
        .files
        .iter()
        .map(|(key, entry)| {
            (
                store::money_key("offer:", key),
                (
                    entry,
                    by_source
                        .get(entry.source_file_fingerprint.as_str())
                        .map(|item| item.snapshot_fingerprint.as_str())
                        .or_else(|| {
                            logical_family_member(index, key).and_then(|(root, member)| {
                                by_member.get(&(root.as_str(), member.as_str())).copied()
                            })
                        }),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut obsolete = Vec::new();
    for (key, _) in ledger.census().records_with_prefix("offer:") {
        if Instant::now() >= deadline {
            return;
        }
        if current_offers.contains(&key) {
            continue;
        }
        let Some((prefix, fingerprint)) = key.rsplit_once(':') else {
            continue;
        };
        let keep = current.get(prefix).is_some_and(|(entry, proposed)| {
            if *proposed == Some(fingerprint) {
                return true;
            }
            let mut digest = Sha256::new();
            super::update_length_prefixed(&mut digest, b"snapshot_file_entity_set:v1");
            super::update_length_prefixed(&mut digest, fingerprint.as_bytes());
            entry.last_snapshot_fingerprint.as_deref()
                == Some(format!("{:x}", digest.finalize()).as_str())
        });
        if !keep {
            obsolete.push(key.clone());
        }
    }
    for key in obsolete {
        ledger.remove(&key);
    }
}

pub(crate) fn reconcile_saved_money_offers(
    support: &Path,
    saved: &ScanIndex,
    proposed_index: &ScanIndex,
    snapshots: &[SnapshotItem],
) {
    if !request_owned_live(support) {
        return;
    }
    let ClaudeLedgerAcquire::Ready(mut ledger) = store::acquire(support) else {
        return;
    };
    apply_results(
        support,
        &mut ledger,
        &mut ClaudeRequestMoneyShadowCounts::default(),
        Instant::now() + PAGE_MAX_ELAPSED,
    );
    let before = ledger.epoch();
    reconcile_money_offers(
        &mut ledger,
        saved,
        proposed_index,
        snapshots,
        Instant::now() + PAGE_MAX_ELAPSED,
    );
    if ledger.epoch() != before {
        let _ = store::checkpoint(support, &mut ledger);
    }
}

/// Reconcile bounded unbuilt debt before classification, then enroll the
/// blockers actually encountered by T-empty decisions. The first-held clock
/// and cycle survive lost/stale/over-budget replacements and process restart.
/// A current verified rebuild clears the marker; passage of time or a completed
/// census cycle releases it without fabricating request evidence.
pub(crate) fn update_unbuilt_lifecycle(
    index: &ScanIndex,
    ledger: &mut ClaudeLedger,
    blocking_files: &BTreeSet<String>,
    now: u64,
    deadline: Instant,
) -> Option<u64> {
    // Do not clear on derivation alone: stale fingerprints, lossy records and
    // birth-only tombstones are still unbuilt. Empty verified files do settle.
    for (key, entry) in &index.files {
        if Instant::now() >= deadline {
            return None;
        }
        if index.confirmed_empty_files.contains(key)
            || index.claude_request_census.get(key).is_some_and(|record| {
                record.retired().is_some()
                    || record.current_holder_for(
                        &entry.source_file_fingerprint,
                        claude_request_ledger::message_known(
                            &index.claude_request_census,
                            ledger.census(),
                            key,
                        ),
                    )
            })
        {
            ledger.remove(&store::money_key("unbuilt:", key));
        }
    }
    let cycle: [u8; 32] = Sha256::digest(
        index
            .resume_census_window_end
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    )
    .into();
    let expired = |record: custody::RecordRef<'_>| {
        record.window() & UNBUILT_RELEASED == 0
            && (now.saturating_sub(record.window()) >= 86400 || record.money_revision() != cycle)
    };
    let mut charge = 0_usize;
    for (key, record) in ledger.census().records_with_prefix("unbuilt:") {
        if Instant::now() >= deadline {
            return None;
        }
        if expired(record) {
            charge = charge.saturating_add(
                2 * (std::mem::size_of::<(String, ClaudeRequestCensusRecord)>() + key.len()),
            );
        }
    }
    let _funds = ShadowReservation::admit(charge)?;
    let mut updates = Vec::new();
    for (key, record) in ledger.census().records_with_prefix("unbuilt:") {
        if Instant::now() >= deadline {
            return None;
        }
        if expired(record) {
            updates.push((
                key.clone(),
                ClaudeRequestCensusRecord::money_debt(
                    record.money_revision(),
                    record.window() | UNBUILT_RELEASED,
                ),
            ));
        }
    }
    let released = updates.len() as u64;
    for (key, record) in updates {
        if !ledger.put_money(key, record) {
            return None;
        }
    }
    for key in blocking_files {
        if Instant::now() >= deadline {
            return None;
        }
        let record_key = store::money_key("unbuilt:", key);
        if ledger.get(&record_key).is_none()
            && !ledger.put_money(
                record_key,
                ClaudeRequestCensusRecord::money_debt(cycle, now),
            )
        {
            return None;
        }
    }
    if released > 0 {
        eprintln!(
            "claude_request_money unbuilt_older_alarm={released} unbuilt_older_released={released}"
        );
    }
    Some(released)
}

/// Page-bounded local cause lookup. Build only in live money mode; the saved
/// index determines whether the physical file changed, appeared as an alias,
/// or belongs to a wholly rebuilt index. It never changes upload eligibility.
pub(crate) fn protected_offer_causes(
    saved: &ScanIndex,
    scan: &super::SourceScanResult,
) -> Option<(BTreeMap<String, u8>, ShadowReservation)> {
    let charge = scan
        .completed_parses()
        .fold(0_usize, |bytes, (_, revision)| {
            bytes.saturating_add(revision.len().saturating_add(128))
        });
    let funds = ShadowReservation::admit(charge)?;
    let mut causes = BTreeMap::new();
    for (key, revision) in scan.completed_parses() {
        let cause = if saved.files.contains_key(key) {
            0
        } else if saved.files.is_empty() {
            2
        } else {
            1
        };
        causes.insert(revision.to_owned(), cause);
    }
    Some((causes, funds))
}

pub(crate) fn note_protected_offers(
    index: &ScanIndex,
    causes: Option<&BTreeMap<String, u8>>,
    items: &[SnapshotItem],
) {
    #[derive(Default, Serialize)]
    struct Counts {
        real_change: u64,
        alias: u64,
        rebuild: u64,
        cause_unavailable: u64,
    }
    let mut counts = Counts::default();
    for item in items {
        if !index
            .claude_reemission_exclusions
            .protected_root(claude_snapshot_family_root_ref(item))
        {
            continue;
        }
        match item
            .source_file_fingerprint
            .as_ref()
            .and_then(|revision| causes?.get(revision))
        {
            Some(0) => counts.real_change += 1,
            Some(1) => counts.alias += 1,
            Some(2) => counts.rebuild += 1,
            _ => counts.cause_unavailable += 1,
        }
    }
    if counts.real_change + counts.alias + counts.rebuild + counts.cause_unavailable > 0 {
        crate::local_resource_diagnostics::claude_money_protected_offers(&counts);
    }
}

pub(crate) fn money_blocking_file(support_dir: &Path, index_key: &str) -> bool {
    request_owned_live(support_dir) && store::blocking_file(support_dir, index_key)
}

pub(crate) fn adoption_prefix(index: &ScanIndex) -> String {
    format!(
        "adopt:entity:v2:{:x}:",
        Sha256::digest(
            index
                .active_upload_context_fingerprint
                .as_deref()
                .or(index.upload_context_fingerprint.as_deref())
                .unwrap_or("")
                .as_bytes()
        )
    )
}

pub(crate) fn recovery_now(support: &Path) -> u64 {
    page_now(support)
}

/// A release latch shares the existing bounded control carrier. It is never
/// evicted by receipt TTL or metadata reclamation while delivery debt exists.
pub(crate) fn recovery_release_receipt(support: &Path, lineage: &str, now: u64) -> MoneyReceipt {
    recovery_latch_receipt(support, lineage, Some(now))
}

pub(crate) fn recovery_finish_receipt(
    support: &Path,
    lineage: &str,
    now: u64,
    resolved: bool,
) -> MoneyReceipt {
    if !resolved {
        return recovery_release_receipt(support, lineage, now);
    }
    let mut ledger = match store::acquire(support) {
        ClaudeLedgerAcquire::Ready(ledger) => ledger,
        ClaudeLedgerAcquire::Loading => return MoneyReceipt::Pending,
        ClaudeLedgerAcquire::Unavailable => return MoneyReceipt::Refused,
    };
    let key = format!("adopt:entity:recovery-release:{lineage}");
    // An older known outcome must not erase a newer unresolved release of the
    // same logical body. Reclamation removes it only after delivery debt ends.
    if ledger.get(&key).is_some_and(|record| record.window() == 0) {
        ledger.remove(&key);
    }
    store::checkpoint_receipt(support, &mut ledger)
}

pub(crate) enum RecoveryAdmission {
    Ready,
    Pending,
    Full,
    Refused,
}

pub(crate) fn recovery_reserve_receipt(support: &Path, lineage: &str) -> RecoveryAdmission {
    let mut ledger = match store::acquire(support) {
        ClaudeLedgerAcquire::Ready(ledger) => ledger,
        ClaudeLedgerAcquire::Loading => return RecoveryAdmission::Pending,
        ClaudeLedgerAcquire::Unavailable => return RecoveryAdmission::Refused,
    };
    let key = format!("adopt:entity:recovery-release:{lineage}");
    if ledger.get(&key).is_none()
        && !ledger.put_money(
            key,
            ClaudeRequestCensusRecord::money_debt(Sha256::digest(lineage.as_bytes()).into(), 0),
        )
    {
        // No field was changed: ordinary bounded control admission, not a
        // failed durable latch commit. Other source controls keep their slots.
        return RecoveryAdmission::Full;
    }
    match store::checkpoint_receipt(support, &mut ledger) {
        MoneyReceipt::Ready => RecoveryAdmission::Ready,
        MoneyReceipt::Pending => RecoveryAdmission::Pending,
        MoneyReceipt::Refused => RecoveryAdmission::Refused,
    }
}

fn recovery_latch_receipt(support: &Path, lineage: &str, released: Option<u64>) -> MoneyReceipt {
    let mut ledger = match store::acquire(support) {
        ClaudeLedgerAcquire::Ready(ledger) => ledger,
        ClaudeLedgerAcquire::Loading => return MoneyReceipt::Pending,
        ClaudeLedgerAcquire::Unavailable => return MoneyReceipt::Refused,
    };
    let key = format!("adopt:entity:recovery-release:{lineage}");
    let now = released.map_or(0, |now| now.max(1));
    if ledger
        .get(&key)
        .map_or(true, |old| released.is_some() && old.window() == 0)
        && !ledger.put_money(
            key,
            ClaudeRequestCensusRecord::money_debt(Sha256::digest(lineage.as_bytes()).into(), now),
        )
    {
        return MoneyReceipt::Refused;
    }
    store::checkpoint_receipt(support, &mut ledger)
}

pub(crate) fn recovery_released(support: &Path, lineage: &str) -> bool {
    store::recovery_released(support, lineage)
}

/// Old send intents did not retain wire bytes. Publish an unresolved episode
/// before removing their global UNKNOWN bit; never rebuild those old bodies.
pub(crate) fn recovery_legacy_receipt(support: &Path) -> (MoneyReceipt, Vec<String>) {
    let mut ledger = match store::acquire(support) {
        ClaudeLedgerAcquire::Ready(ledger) => ledger,
        ClaudeLedgerAcquire::Loading => return (MoneyReceipt::Pending, Vec::new()),
        ClaudeLedgerAcquire::Unavailable => return (MoneyReceipt::Refused, Vec::new()),
    };
    let legacy = ledger
        .census()
        .records_with_prefix("adopt:entity:v2:")
        .filter(|(key, record)| key.ends_with("rates") && record.money_revision()[0] & 0x80 != 0)
        .map(|(key, record)| {
            let id = format!(
                "{:x}",
                Sha256::digest(
                    format!("legacy_unknown:{key}:{:?}", record.money_revision()).as_bytes()
                )
            );
            (key, id)
        })
        .collect::<Vec<_>>();
    let mut episodes = Vec::new();
    for (key, id) in legacy {
        if ledger
            .get(&format!("adopt:entity:recovery-release:{id}"))
            .is_some_and(|r| r.window() > 0)
        {
            let prefix = key.strip_suffix("rates").unwrap();
            let mut revision = [0; 32];
            for (slot, value) in revision
                .chunks_exact_mut(8)
                .zip(ledger.census().adoption_rates(prefix))
            {
                slot.copy_from_slice(&value.to_be_bytes());
            }
            if !ledger.put_money(
                key,
                ClaudeRequestCensusRecord::money_debt(revision, page_now(support)),
            ) {
                return (MoneyReceipt::Refused, Vec::new());
            }
        } else {
            episodes.push(id);
        }
    }
    (store::checkpoint_receipt(support, &mut ledger), episodes)
}

/// State per indexed entity, not per POST. Repeated server holds never
/// inflate the denominator or erase a refusal from conservation accounting.
/// 0 offered, 1 local held, 2 server held, 3 refused, 4 accepted,
/// 5 below retention floor, 6 dominated/stale refusal (settled).
pub(crate) fn note_adoption_outcomes_receipt(
    support_dir: &Path,
    index: &ScanIndex,
    snapshots: &[SnapshotItem],
    outcome: impl Fn(&SnapshotItem) -> u64,
) -> MoneyReceipt {
    if !request_owned_live(support_dir) {
        return MoneyReceipt::Ready;
    }
    let mut ledger = match store::acquire(support_dir) {
        ClaudeLedgerAcquire::Ready(ledger) => ledger,
        ClaudeLedgerAcquire::Loading => return MoneyReceipt::Pending,
        ClaudeLedgerAcquire::Unavailable => return MoneyReceipt::Refused,
    };
    apply_results(
        support_dir,
        &mut ledger,
        &mut ClaudeRequestMoneyShadowCounts::default(),
        Instant::now() + PAGE_MAX_ELAPSED,
    );
    let prefix = adoption_prefix(index);
    let deadline = Instant::now() + PAGE_MAX_ELAPSED;
    let mut seen = BTreeSet::new();
    let mut rates = [0_u64; 4];
    for item in snapshots {
        if Instant::now() >= deadline {
            return MoneyReceipt::Refused;
        }
        let root = claude_snapshot_family_root_ref(item);
        if index.claude_reemission_exclusions.protected_root(root)
            || !seen.insert((root, item.source_session_id.as_str()))
        {
            continue;
        }
        let entity = format!("{root}/{}", item.source_session_id);
        let record_key = store::money_key("adopt:member:v1:", &entity);
        let revision =
            Sha256::digest(format!("{prefix}{}", item.snapshot_fingerprint).as_bytes()).into();
        let proposed = outcome(item);
        let state = if proposed == 0 {
            ledger
                .get(&record_key)
                .filter(|old| old.money_revision() == revision && matches!(old.window(), 3 | 4 | 6))
                .map_or(proposed, |record| record.window())
        } else {
            proposed
        };
        // UNKNOWN is batch-scoped custody, never a global ratio denominator
        // or veto. Recompute explicitly, including an empty resolved slice.
        rates[0] += u64::from(state != 0);
        rates[1] += u64::from(state == 1);
        rates[2] += u64::from(state == 2);
        rates[3] += u64::from(matches!(state, 3 | 6));
        let owner = index
            .files
            .keys()
            .filter(|path| {
                logical_family_member(index, path)
                    .is_some_and(|(r, m)| r == root && m == item.source_session_id)
            })
            .min_by_key(|path| selection::primary_order(index, path))
            .map(String::as_str)
            .or_else(|| {
                index
                    .claude_money_files
                    .iter()
                    .find(|(_, state)| {
                        state.synthetic_body.is_some()
                            && state.root == root
                            && state.member == item.source_session_id
                    })
                    .map(|(key, _)| key.as_str())
            });
        let Some(owner) = owner else {
            return MoneyReceipt::Refused;
        };
        if !ledger.put_entity(
            owner,
            record_key,
            ClaudeRequestCensusRecord::money_debt(revision, state),
            custody::EntityBinding {
                root: root.into(),
                member: item.source_session_id.clone(),
                context: prefix.clone(),
                body: item.snapshot_fingerprint.clone(),
            },
        ) {
            return MoneyReceipt::Refused;
        }
    }
    let rates_key = format!("{prefix}rates");
    if let Some(old) = ledger.get(&rates_key) {
        if old.money_revision()[0] & 0x80 != 0 {
            rates = ledger.census().adoption_rates(&prefix);
        } else if rates[0] == 0 {
            // Empty/UNKNOWN work cannot erase an independent known-outcome
            // pause. It also cannot dilute its page denominator with history.
            for (slot, bytes) in rates.iter_mut().zip(old.money_revision().chunks_exact(8)) {
                *slot = u64::from_be_bytes(bytes.try_into().unwrap());
            }
        }
    }
    let mut revision = [0; 32];
    for (slot, value) in revision.chunks_exact_mut(8).zip(rates) {
        slot.copy_from_slice(&value.to_be_bytes());
    }
    let observed = ledger
        .get(&rates_key)
        .filter(|old| old.money_revision() == revision)
        .map_or_else(|| page_now(support_dir), |record| record.window());
    if !ledger.put_money(
        rates_key,
        ClaudeRequestCensusRecord::money_debt(revision, observed),
    ) {
        return MoneyReceipt::Refused;
    }
    let durable = store::checkpoint_receipt(support_dir, &mut ledger);
    let mut counts = [0_u64; 7];
    if let Some(_counts_funds) =
        ShadowReservation::admit(ledger.census().record_count().saturating_mul(128))
    {
        let mut entities = BTreeSet::new();
        for (key, record) in ledger.census().records_with_prefix("adopt:member:v1:") {
            if entities.insert(key) {
                if let Some(count) = counts.get_mut(record.window() as usize) {
                    *count += 1;
                }
            }
        }
    }
    eprintln!("claude_request_money adoption_offered={} adoption_local_held={} adoption_server_held={} adoption_refused={} adoption_accepted={} adoption_below_retention_floor={} adoption_refused_stale_again={}",
        counts[0], counts[1], counts[2], counts[3], counts[4], counts[5], counts[6]);
    durable
}

pub(crate) fn adoption_paused(support_dir: &Path, index: &ScanIndex) -> bool {
    if index.active_upload_context_fingerprint.is_none()
        && index.upload_context_fingerprint.is_none()
        && store::unresolved_adoption_context(support_dir)
    {
        return true;
    }
    store::adoption_paused(support_dir, &adoption_prefix(index), page_now(support_dir))
}

pub(crate) fn adoption_probe_due(support_dir: &Path, index: &ScanIndex) -> bool {
    if index.active_upload_context_fingerprint.is_none()
        && index.upload_context_fingerprint.is_none()
        && store::unresolved_adoption_context(support_dir)
    {
        return false;
    }
    store::adoption_probe_due(support_dir, &adoption_prefix(index), page_now(support_dir))
}

pub(crate) fn note_route_pause(support_dir: &Path, index: &ScanIndex, paused: bool) {
    if !request_owned_live(support_dir) {
        return;
    }
    let ClaudeLedgerAcquire::Ready(mut ledger) = store::acquire(support_dir) else {
        return;
    };
    let key = format!("{}route", adoption_prefix(index));
    if paused {
        let _ = ledger.put_money(
            key,
            ClaudeRequestCensusRecord::money_debt(
                [0; 32],
                page_now(support_dir).saturating_add(1800),
            ),
        );
        eprintln!("claude_request_money adoption_paused=request_owned_usage_route_unavailable");
    } else {
        ledger.remove(&key);
    }
    let _ = store::checkpoint(support_dir, &mut ledger);
}

pub(crate) fn settle_below_retention_floor(
    support_dir: &Path,
    index: &ScanIndex,
    key: &str,
) -> bool {
    let ClaudeLedgerAcquire::Ready(mut ledger) = store::acquire(support_dir) else {
        return false;
    };
    let Some(entry) = index.files.get(key) else {
        return false;
    };
    let revision = Sha256::digest(entry.source_file_fingerprint.as_bytes()).into();
    ledger.put_entity(
        key,
        store::money_key(
            "adopt:member:v1:",
            &logical_family_member(index, key)
                .map(|(root, member)| format!("{root}/{member}"))
                .unwrap_or_else(|| key.to_owned()),
        ),
        ClaudeRequestCensusRecord::money_debt(revision, 5),
        custody::EntityBinding {
            root: logical_family_member(index, key)
                .map(|(root, _)| root)
                .unwrap_or_default(),
            member: logical_family_member(index, key)
                .map(|(_, member)| member)
                .unwrap_or_default(),
            context: adoption_prefix(index),
            body: entry.source_file_fingerprint.clone(),
        },
    ) && store::checkpoint(support_dir, &mut ledger)
}

pub(crate) fn scheduled_reoffers(index: &ScanIndex, items: &[SnapshotItem]) -> BTreeSet<String> {
    let Some(support) = index.active_request_money_support_dir.as_deref() else {
        return BTreeSet::new();
    };
    let sources = index
        .files
        .iter()
        .filter(|(key, _)| {
            index.claude_money_selection_changed.contains(*key)
                || money_due(support, key, page_now(support))
        })
        .map(|(_, entry)| entry.source_file_fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    items
        .iter()
        .filter(|item| {
            item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_CONTRACT)
                && item
                    .source_file_fingerprint
                    .as_deref()
                    .is_some_and(|source| sources.contains(source))
        })
        .map(|item| item.snapshot_fingerprint.clone())
        .collect()
}

/// Scoped live activation for synthetic callers only. Production still needs
/// the compiled gate; kill files retain their precedence in tests too.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct LiveForTest {
    support: PathBuf,
    inserted: bool,
    shadow_was_enabled: bool,
}
#[cfg(test)]
#[allow(dead_code)]
impl LiveForTest {
    pub(crate) fn new(support: &Path) -> Self {
        let shadow_was_enabled = shadow_enabled(support);
        enable_shadow_for_test(support);
        let mut dirs = LIVE_TEST_DIRS.lock().expect("live test scopes");
        let inserted = !dirs.iter().any(|dir| dir == support);
        if inserted {
            dirs.push(support.to_path_buf());
        }
        Self {
            support: support.to_path_buf(),
            inserted,
            shadow_was_enabled,
        }
    }
}
#[cfg(test)]
impl Drop for LiveForTest {
    fn drop(&mut self) {
        if self.inserted {
            // Release this synthetic owner's parked future and recovery graph
            // even when an assertion unwinds before its normal closeout.
            crate::snapshot_sync::money_resume::forget_for_test(&self.support);
            crate::snapshot_sync::unknown_recovery::forget(&self.support);
            store::flush();
            if let Ok(mut dirs) = LIVE_TEST_DIRS.lock() {
                dirs.retain(|dir| dir != &self.support);
            }
        }
        if !self.shadow_was_enabled {
            disable_shadow_for_test(&self.support);
        }
    }
}

#[cfg(test)]
thread_local! {
    static PAGE_CLOCK: std::cell::RefCell<BTreeMap<PathBuf, u64>> = const { std::cell::RefCell::new(BTreeMap::new()) };
}
#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct PageClockForTest(PathBuf, Option<u64>);
#[cfg(test)]
#[allow(dead_code)]
impl PageClockForTest {
    pub(crate) fn new(support: &Path, now: u64) -> Self {
        Self(
            support.to_path_buf(),
            PAGE_CLOCK.with(|clock| clock.borrow_mut().insert(support.to_path_buf(), now)),
        )
    }
}
#[cfg(test)]
impl Drop for PageClockForTest {
    fn drop(&mut self) {
        PAGE_CLOCK.with(|clock| {
            let mut clock = clock.borrow_mut();
            if let Some(previous) = self.1 {
                clock.insert(self.0.clone(), previous);
            } else {
                clock.remove(&self.0);
            }
        });
    }
}
fn page_now(support: &Path) -> u64 {
    #[cfg(test)]
    if let Some(now) = PAGE_CLOCK.with(|clock| clock.borrow().get(support).copied()) {
        return now;
    }
    let _ = support;
    now_unix()
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn emit_for_test(item: &mut SnapshotItem, entity: &body::ClaudeEntityBody) -> bool {
    emit::apply(item, entity)
}

/// A routing digest replaces per-request watches. Any change invalidates all
/// indexed members of the family, including former owners. Debt is durable
/// before the digest or legacy-watch deletions publish in phase two.
fn schedule_trace(
    ledger: &mut ClaudeLedger,
    index: &ScanIndex,
    traces: &BTreeMap<String, BTreeMap<u64, String>>,
    now: u64,
    deadline: Instant,
    budget: &mut ShadowBudget,
    updates: &mut MoneyWatchUpdates,
) -> bool {
    for (root, trace) in traces {
        let root_hash = format!("{:x}", Sha256::digest(root.as_bytes()));
        let legacy = format!("watch:trace:{root_hash}:");
        let mut digest = Sha256::new();
        for (request, owner) in trace {
            if Instant::now() >= deadline {
                return false;
            }
            digest.update(request.to_be_bytes());
            super::update_length_prefixed(&mut digest, owner.as_bytes());
        }
        let revision = digest.finalize().into();
        let mut watches = Vec::new();
        for key in index.files.keys() {
            if Instant::now() >= deadline {
                return false;
            }
            if logical_family_member(index, key).is_some_and(|(family, _)| family == *root) {
                if !budget.charge(key.len() + 256) {
                    return false;
                }
                watches.push((key.as_str(), store::money_key("watch:trace:file:", key)));
            }
        }
        if watches.is_empty() {
            watches.push(("", format!("watch:trace:otel:{root_hash}")));
        }
        let old_root = format!("watch:trace:v2:{root_hash}");
        let changed = ledger.get(&old_root).is_some()
            || ledger
                .census()
                .records_with_prefix(&legacy)
                .next()
                .is_some()
            || watches.iter().any(|(_, watch)| {
                ledger
                    .get(watch)
                    .map_or(true, |old| old.money_revision() != revision)
            });
        if !changed {
            continue;
        }
        // All family dependents are dirty before any carrier advances seen.
        for (key, _) in &watches {
            if !key.is_empty() && !stage_money_dirty(ledger, key, revision, now) {
                return false;
            }
        }
        for (key, _) in ledger.census().records_with_prefix(&legacy) {
            if !stage_money_watch(updates, key.clone(), None, budget) {
                return false;
            }
        }
        if ledger.get(&old_root).is_some() && !stage_money_watch(updates, old_root, None, budget) {
            return false;
        }
        for (_, watch) in watches {
            if !stage_money_watch(
                updates,
                watch,
                Some(ClaudeRequestCensusRecord::money_debt(revision, 0)),
                budget,
            ) {
                return false;
            }
        }
    }
    true
}

/// Reclaim routing/accounting metadata with no indexed dependent, plus legacy
/// routing entries covered by the mandatory missing-aggregate invalidation.
/// ACKs, holds, offers, due/dirty debt, and ever-indexed tombstones are separate
/// custody and are never removed here. New/reappearing members start unwatched
/// and therefore invalidate on their first routing observation.
pub(crate) fn reclaim_metadata(support: &Path, index: &ScanIndex) -> MoneyReceipt {
    if !live_enabled(support) {
        return MoneyReceipt::Ready;
    }
    let mut ledger = match store::acquire(support) {
        ClaudeLedgerAcquire::Ready(ledger) => ledger,
        ClaudeLedgerAcquire::Loading => return MoneyReceipt::Pending,
        ClaudeLedgerAcquire::Unavailable => return MoneyReceipt::Refused,
    };
    if ledger.metadata_checkpoint || ledger.has_pending_checkpoint() {
        let receipt = store::checkpoint_receipt(support, &mut ledger);
        ledger.metadata_checkpoint = receipt == MoneyReceipt::Pending;
        // Consuming this slice's receipt completes housekeeping for this
        // preparation. Do not start another slice and starve the real scan.
        return receipt;
    }
    let deadline = Instant::now() + PAGE_MAX_ELAPSED;
    let Some(_funds) =
        ShadowReservation::admit(ledger.census().primary_projection_bytes(index.files.len()))
    else {
        return MoneyReceipt::Refused;
    };
    let mut roots = BTreeSet::new();
    let mut entities = BTreeSet::new();
    for key in index.files.keys() {
        if Instant::now() >= deadline {
            return MoneyReceipt::Refused;
        }
        if let Some((root, member)) = logical_family_member(index, key) {
            roots.insert(format!("{:x}", Sha256::digest(root.as_bytes())));
            entities.insert(store::money_key(
                "adopt:member:v1:",
                &format!("{root}/{member}"),
            ));
        }
    }
    let prefix = adoption_prefix(index);
    let recovery_debt_settled = ledger.census().offer_total() == 0
        && ledger
            .census()
            .records_with_prefix("dirty:")
            .next()
            .is_none()
        && ledger.census().records_with_prefix("due:").next().is_none();
    let mut obsolete = Vec::new();
    let mut cursor = None;
    for (key, _) in ledger
        .census()
        .records_after(&ledger.metadata_cursor)
        .take(256)
    {
        if Instant::now() >= deadline {
            break;
        }
        cursor = Some(key.clone());
        let stale_trace = key
            .strip_prefix("watch:trace:")
            .filter(|suffix| !suffix.starts_with("file:") && !suffix.starts_with("otel:"))
            .is_some_and(|suffix| {
                let root = suffix
                    .strip_prefix("v2:")
                    .unwrap_or(suffix)
                    .split(':')
                    .next()
                    .unwrap_or("");
                !roots.contains(root)
                // Legacy per-request metadata is redundant when the new
                // aggregate watch is absent: that absence unconditionally
                // invalidates EVERY family member before any live offer. A
                // crash during reclamation retains the same absence barrier.
                || !suffix.starts_with("v2:")
                    && ledger.get(&format!("watch:trace:v2:{root}")).is_none()
            });
        let stale_adoption = key.starts_with("adopt:entity:")
            && !key.starts_with("adopt:entity:recovery-release:")
            && key != format!("{prefix}rates")
            && key != format!("{prefix}route")
            || key.starts_with("adopt:member:v1:")
                && !entities.contains(&key)
                && ledger.census().retirable_entity(&key);
        if stale_trace
            || stale_adoption
            || recovery_debt_settled && key.starts_with("adopt:entity:recovery-release:")
        {
            obsolete.push(key.clone());
        }
    }
    ledger.metadata_cursor = cursor.unwrap_or_default();
    let reclaimed = !obsolete.is_empty();
    for key in obsolete {
        ledger.remove(&key);
    }
    for key in index.files.keys() {
        if Instant::now() >= deadline {
            return MoneyReceipt::Refused;
        }
        if let Some((root, member)) = logical_family_member(index, key) {
            let birth = index
                .claude_request_census
                .get(key)
                .and_then(|record| record.birth());
            if !ledger.bind_file(key, root, member, birth) {
                return MoneyReceipt::Refused;
            }
        }
    }
    if !ledger.promote(index, deadline) {
        return MoneyReceipt::Refused;
    }
    if ledger.promotions_pending() {
        let receipt = store::checkpoint_receipt(support, &mut ledger);
        ledger.metadata_checkpoint = receipt == MoneyReceipt::Pending;
        return receipt;
    }
    if !reclaimed {
        // ACK settlement may have queued a receipt after the prior finish's
        // last await. Drain it BEFORE adoption reads the custody barrier. A
        // completed diagnostic memo alone never pauses the next scan.
        let receipt = if ledger.unacknowledged_custody() {
            store::checkpoint_receipt(support, &mut ledger)
        } else {
            MoneyReceipt::Ready
        };
        ledger.metadata_checkpoint = receipt == MoneyReceipt::Pending;
        return receipt;
    }

    // Publish this bounded slice before adoption pause reads the ledger. A
    // resumed preparation consumes its receipt once, then advances the scan.
    // Restart before publication restores conservative old metadata only.
    let receipt = store::checkpoint_receipt(support, &mut ledger);
    ledger.metadata_checkpoint = receipt == MoneyReceipt::Pending;
    receipt
}

/// A server hold/skew paces the same exact debt. A new evidence revision
/// replaces its timer, so a real correction can still be offered promptly.
pub(crate) fn pace_money_debt(
    support_dir: &Path,
    index: &ScanIndex,
    items: &[SnapshotItem],
    retry_after: impl Fn(&SnapshotItem) -> Option<u64>,
) {
    if !request_owned_live(support_dir) {
        return;
    }
    let ClaudeLedgerAcquire::Ready(mut ledger) = store::acquire(support_dir) else {
        return;
    };
    let sources = union_items_by_source(index, items)
        .into_iter()
        .filter_map(|(source, item)| Some((source, retry_after(item)?)))
        .collect::<BTreeMap<_, _>>();
    let deadline = Instant::now() + PAGE_MAX_ELAPSED;
    for (key, entry) in &index.files {
        if Instant::now() >= deadline {
            break;
        }
        let Some(retry_after) = sources.get(entry.source_file_fingerprint.as_str()) else {
            continue;
        };
        for prefix in ["dirty:", "due:"] {
            let key = store::money_key(prefix, key);
            if let Some(record) = ledger.get(&key) {
                let record = ClaudeRequestCensusRecord::money_debt(
                    record.money_revision(),
                    record.window().max(*retry_after),
                );
                let _ = ledger.put_money(key, record);
            }
        }
    }
    let _ = store::checkpoint(support_dir, &mut ledger);
}

// Watch publication is phase two. A crash at any earlier data-shard boundary
// leaves the old watch replayable. A later watch write can only follow durable
// dependent invalidation; no cross-shard atomic rename is assumed.
type MoneyWatchUpdates = Vec<(String, Option<ClaudeRequestCensusRecord>)>;

fn stage_money_dirty(
    ledger: &mut ClaudeLedger,
    index_key: &str,
    revision: [u8; 32],
    now: u64,
) -> bool {
    let key = store::money_key("dirty:", index_key);
    if ledger
        .get(&key)
        .is_some_and(|record| record.money_revision() == revision)
    {
        return true;
    }
    ledger.put_money(key, ClaudeRequestCensusRecord::money_debt(revision, now))
}

#[cfg(test)]
fn checkpoint_money_watches(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    updates: MoneyWatchUpdates,
) -> bool {
    checkpoint_money_watches_at(
        support_dir,
        ledger,
        updates,
        Instant::now() + PAGE_MAX_ELAPSED,
    )
}

#[cfg(test)]
fn checkpoint_money_watches_at(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    updates: MoneyWatchUpdates,
    deadline: Instant,
) -> bool {
    if updates.is_empty() {
        return true;
    }
    if !store::checkpoint_until(support_dir, ledger, deadline) {
        return false;
    }
    publish_money_watches(ledger, updates)
}

fn publish_money_watches(ledger: &mut ClaudeLedger, updates: MoneyWatchUpdates) -> bool {
    for (key, record) in updates {
        match record {
            Some(record) => {
                if !ledger.put_money(key, record) {
                    return false;
                }
            }
            None => ledger.remove(&key),
        }
    }
    true
}

async fn checkpoint_money_watches_resume(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    updates: MoneyWatchUpdates,
) -> bool {
    if updates.is_empty() {
        return true;
    }
    let receipt = std::future::poll_fn(|_| match store::checkpoint_receipt(support_dir, ledger) {
        MoneyReceipt::Pending => std::task::Poll::Pending,
        receipt => std::task::Poll::Ready(receipt),
    })
    .await;
    if receipt == MoneyReceipt::Refused {
        return false;
    }
    publish_money_watches(ledger, updates)
}

fn stage_money_watch(
    updates: &mut MoneyWatchUpdates,
    key: String,
    record: Option<ClaudeRequestCensusRecord>,
    budget: &mut ShadowBudget,
) -> bool {
    if !budget.charge(key.capacity()) {
        return false;
    }
    if updates.len() == updates.capacity() {
        let capacity = updates.capacity().max(4).saturating_mul(2);
        if !budget.charge(capacity.saturating_mul(std::mem::size_of::<(
            String,
            Option<ClaudeRequestCensusRecord>,
        )>())) {
            return false;
        }
        updates.reserve_exact(capacity - updates.len());
    }
    updates.push((key, record));
    true
}

const SYNTHETIC_COLLECTOR: &str = "claude_api_synthetic";
fn synthetic(item: &SnapshotItem) -> bool {
    item.provenance.collector == SYNTHETIC_COLLECTOR
}

/// Bounded telemetry-only carriers share the literal builder and normal ACK
/// ledger. Ever-indexed roots live in the separately admitted tolerant ledger;
/// deleted transcripts must never turn into telemetry-only replacements.
pub(crate) fn append_synthetic_sessions(
    support: &Path,
    scan: &mut super::SourceScanResult,
    index: &ScanIndex,
) -> Option<ShadowReservation> {
    if !request_owned_live(support) || !scan.census_complete {
        return None;
    }
    let funds = ShadowReservation::admit(64 * 8192 + index.files.len().saturating_mul(256))?;
    let ClaudeLedgerAcquire::Ready(mut ledger) = store::acquire(support) else {
        return None;
    };
    apply_results(
        support,
        &mut ledger,
        &mut ClaudeRequestMoneyShadowCounts::default(),
        Instant::now() + PAGE_MAX_ELAPSED,
    );
    let deadline = Instant::now() + PAGE_MAX_ELAPSED;
    for key in index.files.keys() {
        if Instant::now() >= deadline {
            return None;
        }
        if let Some((root, _)) = logical_family_member(index, key) {
            let key = store::money_key("ever:", &root);
            if ledger.get(&key).is_none()
                && !ledger.put_money(key, ClaudeRequestCensusRecord::money_debt([0; 32], 0))
            {
                return None;
            }
        }
    }
    if !store::checkpoint(support, &mut ledger) || ledger.load_damaged || ledger.synthetic_closed()
    {
        return None;
    }
    let mut roots = Vec::new();
    for (key, record) in ledger.census().records_with_prefix(TELEMETRY_KEY_PREFIX) {
        if Instant::now() >= deadline {
            return None;
        }
        let Some(header) = record
            .facts()
            .and_then(facts::ClaudeFacts::open)
            .map(|facts| facts.header)
        else {
            continue;
        };
        let root = header.session;
        if root.is_empty()
            || root.len() > 128
            || ledger.get(&store::money_key("ever:", &root)).is_some()
            || index.claude_reemission_exclusions.protected_root(&root)
            || scan
                .snapshots
                .iter()
                .any(|item| claude_snapshot_family_root_ref(item) == root)
        {
            continue;
        }
        if key.as_str() > ledger.synthetic_cursor.as_str() {
            roots.push((key.clone(), root));
        }
        if roots.len() == 64 {
            break;
        }
    }
    if let Some((key, _)) = roots.last() {
        ledger.synthetic_cursor = key.clone();
    } else {
        ledger.synthetic_cursor.clear();
    }
    for (_, root) in roots {
        scan.snapshots
            .push(synthetic_carrier(&root, &scan.census_window_end));
    }
    Some(funds)
}

fn synthetic_carrier(root: &str, collected_at: &str) -> SnapshotItem {
    SnapshotItem {
        first_own_request_at: None,
        claude_file_birth_verdict: Default::default(),
        request_evidence: Vec::new(),
        request_identity_refusals: 0,
        claude_org_markers: None,
        claude_account_withheld_reason: None,
        source_session_id: root.to_owned(),
        snapshot_fingerprint: String::new(),
        status: "final".to_string(),
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_creation_5m_tokens: 0,
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: 0,
        unattributed_total_tokens: 0,
        request_count: 0,
        removed_request_count: None,
        removed_usage: None,
        telemetry_owned_complete: None,
        usage_accounting_contract: None,
        session_account_evidence: None,
        claude_usage_request_ids: BTreeSet::new(),
        claude_usage_occurrences: BTreeMap::new(),
        cache_observations: None,
        cache_observations_state: None,
        cache_base_head_etag: None,
        cache_requests: Vec::new(),
        cache_requests_complete: true,
        avg_duration_ms: None,
        avg_time_to_first_token_ms: None,
        max_duration_ms: None,
        max_time_to_first_token_ms: None,
        peak_context_fill_tokens: None,
        first_turn_context_tokens: None,
        last_turn_context_tokens: None,
        first_turn_context_window_tokens: None,
        peak_context_fill_window_tokens: None,
        last_turn_context_window_tokens: None,
        compaction_count: None,
        compaction_timestamps: Vec::new(),
        compaction_events: Vec::new(),
        local_context_points: Vec::new(),
        compaction_total_pre_tokens: None,
        compaction_total_post_tokens: None,
        compaction_total_cumulative_dropped_tokens: None,
        compaction_total_duration_ms: None,
        context_curve: None,
        claude_context_curve_boundaries: Vec::new(),
        claude_context_curve_identity_complete: false,
        claude_context_curve_request_index_complete: false,
        claude_context_curve_owned_start_proven: false,
        claude_file_birth: Default::default(),
        activity_summary: None,
        tool_usage: None,
        tool_usage_truncated: false,
        session_start: None,
        model_usage: Vec::new(),
        usage_buckets: Vec::new(),
        cost: None,
        session_display_name: None,
        session_display_name_source: None,
        source_started_at: None,
        source_ended_at: None,
        source_last_activity_at: None,
        collected_at: collected_at.to_owned(),
        workspace_hash: None,
        workspace_display_label: None,
        workspace_label_source: None,
        repository_hash: None,
        repository_label: None,
        repository_label_source: None,
        repository_identity_source: None,
        workspace_kind: None,
        source_file_fingerprint: None,
        session_artifacts: Vec::new(),
        provenance: SnapshotProvenance {
            collector: "claude_api_synthetic".to_string(),
            source_file_count: 0,
            input_token_scope: None,
            state_total_tokens: None,
            state_archived: None,
        },
        // Telemetry carries no transcript launcher provenance.
        origin: None,
        originator: None,
        attribution_facts: Vec::new(),
    }
}

#[cfg(test)]
mod scheduling_reconciliation_tests {
    use super::super::claude_request_census::ClaudeTelemetryTailState;
    use super::*;

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn unactivated_index_keeps_adoption_closed_until_context_is_bound() {
        let scratch = crate::test_scratch::ScratchDir::new("money-unactivated-context");
        let _live = LiveForTest::new(&scratch);
        store::reload_for_test(&scratch).unwrap();
        let mut active = ScanIndex::default();
        active.activate_upload_context("context-a".into());
        let prefix = adoption_prefix(&active);
        store::with_ledger_for_test(&scratch, |ledger| {
            assert!(ledger.put_money(
                format!("{prefix}rates"),
                ClaudeRequestCensusRecord::money_debt([0x80; 32], page_now(&scratch))
            ));
            assert!(store::checkpoint_for_test(&scratch, ledger));
        })
        .unwrap();
        store::reload_for_test(&scratch).unwrap();
        let inactive = ScanIndex::default();
        assert!(adoption_paused(&scratch, &inactive));
        assert!(!adoption_probe_due(&scratch, &inactive));
        assert!(
            adoption_paused(&scratch, &active),
            "known local/held/refused ratios keep their authority"
        );
        active.activate_upload_context("context-b".into());
        assert!(
            !adoption_paused(&scratch, &active),
            "explicit current context keeps its independent authority"
        );
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn first_covering_ack_clears_paced_debt_but_preserves_newer_obligations() {
        for newer_debt in [false, true] {
            let scratch = crate::test_scratch::ScratchDir::new("money-paced-ack");
            let _live = LiveForTest::new(&scratch);
            store::reload_for_test(&scratch).unwrap();
            let _clock = PageClockForTest::new(&scratch, 100);
            let key = "/fixture/.claude/projects/group/a.jsonl".to_owned();
            let mut item = crate::snapshots::tests::sample_session_artifact_item();
            item.source_file_fingerprint = Some("01".repeat(32));
            item.snapshot_fingerprint = "03".repeat(32);
            item.usage_accounting_contract = Some(REQUEST_OWNED_CONTRACT.into());
            let body = super::super::snapshot_upload_body_witness(&item);
            let singleton = |domain: &[u8], value: &str| {
                let mut hash = Sha256::new();
                super::super::update_length_prefixed(&mut hash, domain);
                super::super::update_length_prefixed(&mut hash, value.as_bytes());
                format!("{:x}", hash.finalize())
            };
            let mut index = ScanIndex::default();
            index.files.insert(key.clone(), serde_json::from_value(serde_json::json!({
                "size_bytes":1, "modified_unix_seconds":1,
                "source_file_fingerprint":item.source_file_fingerprint,
                "last_snapshot_fingerprint":singleton(b"snapshot_file_entity_set:v1", &item.snapshot_fingerprint),
                "last_upload_body_witness":singleton(b"snapshot_file_upload_body_set:v1", &body)
            })).unwrap());
            let dirty = store::money_key("dirty:", &key);
            let due = store::money_key("due:", &key);
            store::with_ledger_for_test(&scratch, |ledger| {
                assert!(ledger.put_money(
                    dirty.clone(),
                    ClaudeRequestCensusRecord::money_debt([9; 32], 100)
                ));
                assert!(store::checkpoint_for_test(&scratch, ledger));
            })
            .unwrap();
            let prepare = || {
                assert!((0..16).any(|_| {
                    let ready = prepare_money_offers(
                        &scratch,
                        &index,
                        std::slice::from_ref(&item),
                        &BTreeSet::new(),
                    );
                    store::flush();
                    ready
                }));
            };
            prepare();
            pace_money_debt(&scratch, &index, std::slice::from_ref(&item), |_| Some(200));
            store::reload_for_test(&scratch).unwrap();
            let _retry_clock = PageClockForTest::new(&scratch, 200);
            prepare();
            store::with_ledger_for_test(&scratch, |ledger| {
                let offer = format!(
                    "{}:{}",
                    store::money_key("offer:", &key),
                    item.snapshot_fingerprint
                );
                assert_eq!(ledger.get(&offer).unwrap().window(), 200);
                assert_eq!(ledger.census().offer_count_for(&key), 1);
                if newer_debt {
                    assert!(ledger.put_money(
                        dirty.clone(),
                        ClaudeRequestCensusRecord::money_debt([8; 32], 201)
                    ));
                    assert!(ledger.put_money(
                        due.clone(),
                        ClaudeRequestCensusRecord::money_debt([9; 32], 300)
                    ));
                }
                assert!(store::checkpoint_for_test(&scratch, ledger));
            })
            .unwrap();
            index.save(&scratch.join("selected-index.json")).unwrap();
            settle_money_acks(
                &scratch,
                &index,
                std::slice::from_ref(&item),
                &BTreeSet::from([item.snapshot_fingerprint.clone()]),
                &BTreeMap::from([(item.snapshot_fingerprint.clone(), body)]),
            );
            store::reload_for_test(&scratch).unwrap();
            store::with_ledger_for_test(&scratch, |ledger| {
                assert_eq!(ledger.get(&dirty).is_some(), newer_debt);
                assert_eq!(ledger.get(&due).is_some(), newer_debt);
                assert_eq!(ledger.census().offer_count_for(&key), 0);
                if newer_debt {
                    assert_eq!(ledger.get(&dirty).unwrap().money_revision(), [8; 32]);
                    assert_eq!(ledger.get(&due).unwrap().window(), 300);
                }
            })
            .unwrap();
        }
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn preparation_drains_prior_custody_receipt_without_pausing_for_diagnostic_memos() {
        let scratch = crate::test_scratch::ScratchDir::new("money-adoption-prior-receipt");
        let _live = LiveForTest::new(&scratch);
        store::reload_for_test(&scratch).unwrap();
        store::with_ledger_for_test(&scratch, |ledger| {
            assert!(store::checkpoint_for_test(&scratch, ledger));
            assert!(ledger.put_money(
                "due:sentinel".into(),
                ClaudeRequestCensusRecord::money_debt([7; 32], 0)
            ));
            assert!(!store::checkpoint(&scratch, ledger));
            // This memo arrives after the custody snapshot. It must remain
            // dirty without invalidating the real receipt or pausing adoption.
            ledger.insert(
                "fam:diagnostic".into(),
                ClaudeRequestCensusRecord::money_debt([8; 32], 0),
            );
        })
        .unwrap();
        store::flush();
        assert!(checkpoint_pending(&scratch));
        let index = ScanIndex::default();
        assert_eq!(reclaim_metadata(&scratch, &index), MoneyReceipt::Ready);
        assert!(!adoption_paused(&scratch, &index));
        assert!(!checkpoint_pending(&scratch));
        store::with_ledger_for_test(&scratch, |ledger| {
            assert!(
                ledger.dirty_shards() > 0,
                "diagnostic publication is still pending"
            );
            assert_eq!(
                ledger.get("due:sentinel").unwrap().money_revision(),
                [7; 32]
            );
        })
        .unwrap();
        assert_eq!(
            store::load_for_test(&scratch)
                .get("due:sentinel")
                .unwrap()
                .money_revision(),
            [7; 32]
        );
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn trace_digest_replaces_legacy_requests_after_durable_family_invalidation() {
        let scratch = crate::test_scratch::ScratchDir::new("money-trace-replacement");
        let mut index = ScanIndex::default();
        let key = "/fixture/.claude/projects/group/a.jsonl".to_owned();
        index.files.insert(
            key.clone(),
            serde_json::from_value(serde_json::json!({
                "size_bytes":1, "modified_unix_seconds":1,
                "source_file_fingerprint":"01".repeat(32), "last_snapshot_fingerprint":null
            }))
            .unwrap(),
        );
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        item.source_session_id = "a".into();
        item.attribution_facts.clear();
        record_logical_member(&mut index, &key, &"01".repeat(32), &item);
        let mut ledger = ClaudeLedger::new_for_test();
        let legacy = format!("watch:trace:{:x}:", Sha256::digest(b"a"));
        for request in 0..1000 {
            ledger.put_money(
                format!("{legacy}{request:016x}"),
                ClaudeRequestCensusRecord::money_debt([2; 32], 0),
            );
        }
        let mut budget = ShadowBudget::new(ShadowReservation::admit(1024 * 1024).unwrap());
        let traces = BTreeMap::from([("a".to_owned(), BTreeMap::from([(1, "a".to_owned())]))]);
        let mut updates = Vec::new();
        assert!(schedule_trace(
            &mut ledger,
            &index,
            &traces,
            10,
            Instant::now() + Duration::from_secs(5),
            &mut budget,
            &mut updates
        ));
        assert_eq!(ledger.census().records_with_prefix(&legacy).count(), 1000);
        assert!(ledger.get(&store::money_key("dirty:", &key)).is_some());
        let blocked = store::shard_path_for_test(&scratch, &store::money_key("dirty:", &key))
            .with_extension("json.tmp");
        money_io!(Mutate, std::fs::create_dir_all(&blocked)).unwrap();
        assert!(!checkpoint_money_watches(&scratch, &mut ledger, updates));
        assert_eq!(ledger.census().records_with_prefix(&legacy).count(), 1000);
        store::flush();
        std::fs::remove_dir_all(blocked).unwrap();
        assert!(store::checkpoint_for_test(&scratch, &mut ledger));
        let mut updates = Vec::new();
        assert!(schedule_trace(
            &mut ledger,
            &index,
            &traces,
            11,
            Instant::now() + Duration::from_secs(5),
            &mut budget,
            &mut updates
        ));
        assert!(checkpoint_money_watches(&scratch, &mut ledger, updates));
        assert_eq!(
            ledger.census().records_with_prefix("watch:trace:").count(),
            1
        );
        assert!(store::checkpoint_for_test(&scratch, &mut ledger));
        let mut loaded = store::load_for_test(&scratch);
        assert_eq!(
            loaded.census().records_with_prefix("watch:trace:").count(),
            1
        );
        let mut updates = Vec::new();
        assert!(schedule_trace(
            &mut loaded,
            &index,
            &traces,
            12,
            Instant::now() + Duration::from_secs(5),
            &mut budget,
            &mut updates
        ));
        assert!(
            updates.is_empty(),
            "same routing digest is quiet after restart"
        );
        let moved = BTreeMap::from([(
            "a".to_owned(),
            BTreeMap::from([(1, "new-owner".to_owned())]),
        )]);
        let before = loaded
            .get(&store::money_key("dirty:", &key))
            .unwrap()
            .money_revision();
        assert!(schedule_trace(
            &mut loaded,
            &index,
            &moved,
            13,
            Instant::now() + Duration::from_secs(5),
            &mut budget,
            &mut updates
        ));
        assert_ne!(
            loaded
                .get(&store::money_key("dirty:", &key))
                .unwrap()
                .money_revision(),
            before,
            "former family owner stays invalidated"
        );
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn adoption_replaces_context_slots_without_borrowing_terminal_outcomes() {
        let scratch = crate::test_scratch::ScratchDir::new("money-adoption-replacement");
        let _live = LiveForTest::new(&scratch);
        store::reload_for_test(&scratch).unwrap();
        let mut index = ScanIndex::default();
        let item = crate::snapshots::tests::sample_session_artifact_item();
        let key = "/fixture/.claude/projects/group/member.jsonl".to_owned();
        index.files.insert(
            key.clone(),
            serde_json::from_value(serde_json::json!({
                "size_bytes":1, "modified_unix_seconds":1,
                "source_file_fingerprint":"01".repeat(32), "last_snapshot_fingerprint":null
            }))
            .unwrap(),
        );
        record_logical_member(&mut index, &key, &"01".repeat(32), &item);
        for context in 0..40 {
            index.activate_upload_context(format!("context-{context}"));
            crate::snapshot_sync::money_resume::drive_for_test(
                crate::snapshot_sync::money_resume::until(|| {
                    note_adoption_outcomes_receipt(
                        &scratch,
                        &index,
                        std::slice::from_ref(&item),
                        |_| 0,
                    )
                }),
            )
            .unwrap();
            assert!(
                !adoption_paused(&scratch, &index),
                "UNKNOWN cannot pause unrelated entities"
            );
            store::with_ledger_for_test(&scratch, |ledger| {
                let entity = format!("{}/{}", family_root(&item), item.source_session_id);
                assert_eq!(
                    ledger
                        .get(&store::money_key("adopt:member:v1:", &entity))
                        .unwrap()
                        .window(),
                    0,
                    "new context cannot inherit accepted state"
                );
            })
            .unwrap();
            crate::snapshot_sync::money_resume::drive_for_test(
                crate::snapshot_sync::money_resume::until(|| {
                    note_adoption_outcomes_receipt(
                        &scratch,
                        &index,
                        std::slice::from_ref(&item),
                        |_| 4,
                    )
                }),
            )
            .unwrap();
            assert!(!adoption_paused(&scratch, &index));
            for _ in 0..2 {
                crate::snapshot_sync::money_resume::drive_for_test(
                    crate::snapshot_sync::money_resume::until(|| {
                        reclaim_metadata(&scratch, &index)
                    }),
                )
                .unwrap();
            }
            store::with_ledger_for_test(&scratch, |ledger| {
                assert!(
                    ledger.census().records_with_prefix("adopt:").count() <= 2,
                    "one entity slot and current rates only"
                );
                assert!(store::checkpoint_for_test(&scratch, ledger));
            })
            .unwrap();
            store::reload_for_test(&scratch).unwrap();
        }
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn saved_offer_reconciliation_bounds_changed_and_deleted_bodies() {
        let scratch = crate::test_scratch::ScratchDir::new("money-offer-churn");
        let mut index = ScanIndex::default();
        let key = "/fixture/.claude/projects/group/a.jsonl".to_owned();
        let fp = "01".repeat(32);
        index.files.insert(key.clone(), serde_json::from_value(serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":fp,"last_snapshot_fingerprint":null})).unwrap());
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        item.source_file_fingerprint = Some(fp);
        item.snapshot_fingerprint = format!("{:064x}", 63);
        let mut ledger = ClaudeLedger::new_for_test();
        for n in [0, 63] {
            assert!(ledger.put_money(
                format!("{}:{n:064x}", store::money_key("offer:", &key)),
                ClaudeRequestCensusRecord::money_debt([1; 32], n),
            ));
        }
        assert!(!ledger.put_money(
            format!("{}:{:064x}", store::money_key("offer:", &key), 64),
            ClaudeRequestCensusRecord::money_debt([1; 32], 64),
        ));
        let dirty = store::money_key("dirty:", &key);
        ledger.put_money(
            dirty.clone(),
            ClaudeRequestCensusRecord::money_debt([1; 32], 0),
        );
        reconcile_money_offers(
            &mut ledger,
            &ScanIndex::default(),
            &index,
            &[item],
            Instant::now() + PAGE_MAX_ELAPSED,
        );
        assert_eq!(ledger.census().records_with_prefix("offer:").count(), 1);
        assert!(ledger.get(&dirty).is_some());
        index.files.clear();
        reconcile_money_offers(
            &mut ledger,
            &index,
            &index,
            &[],
            Instant::now() + PAGE_MAX_ELAPSED,
        );
        assert!(store::checkpoint_for_test(&scratch, &mut ledger));
        let restored = store::load_for_test(&scratch);
        assert_eq!(restored.census().records_with_prefix("offer:").count(), 0);
        assert!(
            restored.get(&dirty).is_some(),
            "offer cleanup cannot settle current debt"
        );
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn message_transfer_dirties_unchanged_former_holder_in_its_own_namespace() {
        let mut index = ScanIndex::default();
        let a = "/fixture/.claude/projects/group/a.jsonl".to_owned();
        let b = "/fixture/.claude/projects/group/b.jsonl".to_owned();
        for key in [&a, &b] {
            index.files.insert(key.clone(), serde_json::from_value(serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"01".repeat(32),"last_snapshot_fingerprint":null})).unwrap());
        }
        let mut ledger = ClaudeLedger::new_for_test();
        let record = ClaudeRequestCensusRecord::money_debt([1; 32], 0);
        let message = ClaudeRequestCensusRecord::message_record(&record, vec![7]);
        ledger.insert(message_key(&a), message.clone());
        ledger.insert(
            evidence_watch_key(&message_key(&a)),
            message.money_watch(revision_of(&message, Instant::now() + PAGE_MAX_ELAPSED).unwrap()),
        );
        // B has just been restored. A's physical revision is unchanged.
        ledger.insert(message_key(&b), message);
        let mut budget = ShadowBudget::new(ShadowReservation::admit(16384).unwrap());
        let mut updates = Vec::new();
        assert!(schedule_evidence(
            &mut ledger,
            &index,
            100,
            Instant::now() + PAGE_MAX_ELAPSED,
            &mut budget,
            &mut updates
        ));
        assert!(ledger.get(&store::money_key("dirty:", &a)).is_some());
        assert!(ledger.get(&store::money_key("dirty:", &b)).is_some());
        assert_ne!(evidence_watch_key(&message_key(&a)), evidence_watch_key(&a));
        let scratch = crate::test_scratch::ScratchDir::new("money-message-transfer");
        assert!(store::checkpoint_for_test(&scratch, &mut ledger));
        assert!(checkpoint_money_watches(&scratch, &mut ledger, updates));
        assert!(store::checkpoint_for_test(&scratch, &mut ledger));
        let restarted = store::load_for_test(&scratch);
        assert!(restarted.get(&store::money_key("dirty:", &a)).is_some());
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn vanished_evidence_dirties_former_holder_and_retires_watch_once() {
        let mut index = ScanIndex::default();
        let key = "/fixture/.claude/projects/group/holder.jsonl".to_owned();
        let record = ClaudeRequestCensusRecord::telemetry(
            vec![7],
            Box::new([]),
            ClaudeTelemetryTailState::default(),
            1,
        )
        .money_watch([1; 32]);
        index.files.insert(
            key.clone(),
            serde_json::from_value(serde_json::json!({
                "size_bytes": 1, "modified_unix_seconds": 1,
                "source_file_fingerprint": "01".repeat(32), "last_snapshot_fingerprint": null
            }))
            .unwrap(),
        );
        index
            .claude_request_census
            .insert(key.clone(), record.clone());
        let mut ledger = ClaudeLedger::new_for_test();
        let deadline = Instant::now() + Duration::from_secs(2);
        let current_watch = evidence_watch_key(&key);
        ledger.insert(
            current_watch,
            record.money_watch(revision_of(&record, deadline).unwrap()),
        );
        let missing_watch = evidence_watch_key(&telemetry_key("vanished-owner"));
        ledger.insert(missing_watch.clone(), record.money_watch([2; 32]));
        let scratch = crate::test_scratch::ScratchDir::new("money-watch-order");
        let support = scratch.join("support");
        assert!(store::checkpoint_for_test(&support, &mut ledger));
        let mut budget = ShadowBudget::new(ShadowReservation::admit(4096).unwrap());
        let mut updates = MoneyWatchUpdates::new();
        assert!(schedule_evidence(
            &mut ledger,
            &index,
            50,
            Instant::now() + Duration::from_secs(2),
            &mut budget,
            &mut updates
        ));
        let dirty = store::money_key("dirty:", &key);
        assert!(
            ledger.get(&missing_watch).is_some(),
            "phase one retains replay evidence"
        );
        let blocked = store::shard_path_for_test(&support, &dirty).with_extension("json.tmp");
        money_io!(Mutate, std::fs::create_dir_all(&blocked)).unwrap();
        assert!(!checkpoint_money_watches(&support, &mut ledger, updates));
        store::flush();
        let mut reloaded = store::load_for_test(&support);
        assert!(
            reloaded.get(&missing_watch).is_some(),
            "failed dependent write cannot retire the watch"
        );
        assert!(reloaded.get(&dirty).is_none());
        std::fs::remove_dir_all(&blocked).unwrap();
        let mut updates = MoneyWatchUpdates::new();
        assert!(schedule_evidence(
            &mut reloaded,
            &index,
            50,
            Instant::now() + Duration::from_secs(2),
            &mut budget,
            &mut updates
        ));
        assert!(store::checkpoint_for_test(&support, &mut reloaded));
        assert!(checkpoint_money_watches(&support, &mut reloaded, updates));
        assert!(reloaded.get(&missing_watch).is_none());
        assert_eq!(reloaded.get(&dirty).unwrap().window(), 50);
        assert!(store::checkpoint_for_test(&support, &mut reloaded));
        let saved = store::load_for_test(&support);
        assert!(saved.get(&missing_watch).is_none());
        assert_eq!(saved.get(&dirty).unwrap().window(), 50);
        reloaded.remove(&dirty);
        let mut updates = MoneyWatchUpdates::new();
        assert!(schedule_evidence(
            &mut reloaded,
            &index,
            51,
            Instant::now() + Duration::from_secs(2),
            &mut budget,
            &mut updates
        ));
        assert!(updates.is_empty());
        ledger = reloaded;
        assert!(
            ledger.get(&dirty).is_none(),
            "a settled watch deletion is not repeated"
        );
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn no_dirty_buffers_do_not_publish_watches_without_a_flush_ack() {
        let scratch = crate::test_scratch::ScratchDir::new("money-watch-flush-ack");
        let support = scratch.join("support");
        let mut ledger = ClaudeLedger::new_for_test();
        let watch = store::money_key("watch:r:", "/fixture/holder.jsonl");
        ledger.insert(
            watch.clone(),
            ClaudeRequestCensusRecord::money_debt([1; 32], 0),
        );
        let _inflight_buffers = store::take_save_for_test(&mut ledger).unwrap();
        assert_eq!(ledger.dirty_shards(), 0);
        let stalled = store::stall_writer_for_test();
        let timeout = store::flush_timeout_for_test(Duration::from_millis(20));
        assert!(!checkpoint_money_watches(
            &support,
            &mut ledger,
            vec![(watch.clone(), None)]
        ));
        assert!(
            ledger.get(&watch).is_some(),
            "unacknowledged durability keeps replay evidence"
        );
        drop(timeout);
        drop(stalled);
        store::flush();
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn idle_retirement_keeps_consumed_tail_and_does_not_retire_it_again() {
        let mut ledger = ClaudeLedger::new_for_test();
        let header = facts::ClaudeFactsHeader {
            session: "idle-owner".into(),
            ..Default::default()
        };
        let encoded =
            facts::encode(&header, std::iter::empty::<&facts::ClaudeFact>(), 0).into_boxed_slice();
        let key = telemetry_key("idle-owner");
        ledger.insert(
            key.clone(),
            ClaudeRequestCensusRecord::telemetry(
                Vec::new(),
                encoded,
                ClaudeTelemetryTailState {
                    offset: 80,
                    last_append_unix: 1,
                    ..Default::default()
                },
                1,
            ),
        );
        let index = ScanIndex::default();
        let now = 35 * 86400 + 2;
        assert_eq!(
            claude_request_ledger::retire_idle_telemetry(&mut ledger, &index, now),
            0
        );
        let retired = ledger.get(&key).unwrap();
        assert_eq!(retired.tail().unwrap().offset, 80);
        assert_eq!(retired.retired(), None);
        assert_eq!(
            claude_request_ledger::retire_idle_telemetry(&mut ledger, &index, now + 1),
            0
        );
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn offer_ceiling_refuses_new_body_and_preserves_owed_debt() {
        let scratch = crate::test_scratch::ScratchDir::new("money-offer-ceiling");
        let _live = LiveForTest::new(&scratch);
        store::reload_for_test(&scratch).unwrap();
        let mut index = ScanIndex::default();
        let key = "/fixture/.claude/projects/group/a.jsonl".to_owned();
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        item.source_file_fingerprint = Some("01".repeat(32));
        item.snapshot_fingerprint = "03".repeat(32);
        item.usage_accounting_contract = Some(REQUEST_OWNED_CONTRACT.into());
        index.files.insert(key.clone(), serde_json::from_value(serde_json::json!({
            "size_bytes":1, "modified_unix_seconds":1,
            "source_file_fingerprint":item.source_file_fingerprint, "last_snapshot_fingerprint":null
        })).unwrap());
        let dirty = store::money_key("dirty:", &key);
        let offer_prefix = format!("{}:", store::money_key("offer:", &key));
        store::with_ledger_for_test(&scratch, |ledger| {
            ledger.insert(
                dirty.clone(),
                ClaudeRequestCensusRecord::money_debt([9; 32], 0),
            );
            for n in 0..MAX_MONEY_OFFERS_PER_FILE {
                ledger.insert(
                    format!("{offer_prefix}{n:064x}"),
                    ClaudeRequestCensusRecord::money_debt([1; 32], 0),
                );
            }
            assert!(store::checkpoint_for_test(&scratch, ledger));
        })
        .unwrap();
        assert!(!prepare_money_offers(
            &scratch,
            &index,
            &[item],
            &BTreeSet::new()
        ));
        store::with_ledger_for_test(&scratch, |ledger| {
            assert_eq!(ledger.get(&dirty).unwrap().money_revision(), [9; 32]);
            assert_eq!(
                ledger.census().records_with_prefix(&offer_prefix).count(),
                MAX_MONEY_OFFERS_PER_FILE
            );
            assert!(store::checkpoint_for_test(&scratch, ledger));
        })
        .unwrap();
        let reloaded = store::load_for_test(&scratch);
        assert_eq!(reloaded.get(&dirty).unwrap().money_revision(), [9; 32]);
        assert_eq!(
            reloaded.census().records_with_prefix(&offer_prefix).count(),
            MAX_MONEY_OFFERS_PER_FILE
        );
    }
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

    /// A synced debt marker that is still on disk is never rewritten when
    /// the writer passes again (wake, idle, flush): one stat, the same
    /// inode and mtime. A deleted marker is written again on the next pass,
    /// so a restart keeps the debt; an earlier page of the day re-marks it.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn writer_heals_a_deleted_debt_marker_and_never_rewrites_a_present_one() {
        use std::os::unix::fs::MetadataExt;
        let scratch = crate::test_scratch::ScratchDir::new("money-idle-debt-marker");
        let now = 1_786_000_000;
        let diagnostics = scratch.join("diagnostics");
        let day = day_stamp(now).unwrap();
        let marker = owed_path(&diagnostics, &day);
        let stamp = || {
            let meta = std::fs::metadata(&marker).unwrap();
            (meta.ino(), meta.modified().unwrap())
        };
        owe_coverage(&scratch, now, false);
        store::flush();
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), now.to_string());
        let synced = stamp();
        store::wake_writer();
        store::flush();
        store::flush();
        assert_eq!(stamp(), synced, "a present synced marker is not rewritten");
        std::fs::remove_dir_all(&diagnostics).unwrap();
        store::wake_writer();
        store::flush();
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            now.to_string(),
            "the next pass heals a deleted marker"
        );
        let healed = stamp();
        store::flush();
        assert_eq!(stamp(), healed, "a healed marker is not rewritten");
        owe_coverage(&scratch, now - 60, false);
        store::flush();
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            (now - 60).to_string()
        );
        assert_eq!(
            take_owed_coverage(&scratch, &diagnostics, None),
            BTreeMap::from([(day, now - 60)]),
            "the debt stays latched until a batch writes it"
        );
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
                deferred: None,
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
    fn money_p1b_deferred_digest_profile_preserves_canonical_sha256() {
        let coverage = coverage::InterimFamilyCoverage {
            census_complete: true,
            ..Default::default()
        };
        let ledger = ClaudeLedger::new_for_test();
        let roots = (0..8192)
            .map(|at| format!("{at:08x}-1234-4567-890a-123456789abc"))
            .collect::<Vec<_>>();
        let started = Instant::now();
        let states = roots
            .iter()
            .map(|root| std::hint::black_box(coverage.family(root)))
            .collect::<Vec<_>>();
        let coverage_us = started.elapsed().as_micros();
        let started = Instant::now();
        let identities = roots.iter().map(|root| hashed_id(root)).collect::<Vec<_>>();
        let identity_us = started.elapsed().as_micros();
        for (root, identity) in roots.iter().zip(&identities) {
            let mut old = Sha256::new();
            old.update(b"claude_request_money_shadow:v1\0");
            old.update(root.as_bytes());
            assert_eq!(*identity, hex_bytes(&old.finalize()[..8]));
        }
        let mut cached = DeadlineDigest::default();
        let started = Instant::now();
        let digests = roots
            .iter()
            .zip(&states)
            .map(|(root, state)| cached.deferred(root, state, &ledger))
            .collect::<Vec<_>>();
        let digest_us = started.elapsed().as_micros();
        let template = cached.template.as_ref().unwrap();
        let started = Instant::now();
        for (at, identity) in identities.iter().enumerate() {
            let mut bytes = template.bytes.clone();
            bytes[template.suffix - 16..template.suffix].copy_from_slice(identity.as_bytes());
            let expected = Sha256::digest(&bytes);
            assert_eq!(
                digests[at],
                u64::from_be_bytes(expected[..8].try_into().unwrap())
            );
        }
        let software_us = started.elapsed().as_micros();
        let misses = cached.misses;
        assert_eq!(misses, 1, "one template per uniform census shape");
        assert!(
            digest_us <= 175_000,
            "8192 complete comparisons must fit the optional window plus CI tolerance: {digest_us}"
        );
        println!("MONEY_P1B_DIGEST rows=8192 coverage_us={coverage_us} identity_us={identity_us} deferred_us={digest_us} software_oracle_us={software_us} template_misses={misses}");
    }

    #[test]
    fn interrupted_deferred_comparisons_rotate_without_changing_capture_turns() {
        let mut start = 0;
        let mut seen = BTreeSet::new();
        for _ in 0..3 {
            let order = deferred_comparison_order(7, start).collect::<Vec<_>>();
            seen.extend(order.iter().take(3).copied());
            start = order[3]; // same production rule: first unfinished comparison
        }
        assert_eq!(seen, (0..7).collect());
        assert_eq!(deferred_comparison_order(0, start).count(), 0);
    }

    #[test]
    // Its scratch admission (`PER_PAGE * 256`, 64 KiB) is process-wide
    // shadow memory, which other money tests assert exactly.
    #[serial_test::serial(claude_request_money_shadow)]
    fn family_retention_cursor_reaches_stale_records_beyond_a_fresh_prefix() {
        let mut ledger = ClaudeLedger::new_for_test();
        let now = FAMILY_MEMO_RETENTION_SECONDS + 100;
        for at in 0..600 {
            let key = format!("{FAMILY_KEY_PREFIX}{at:064x}");
            assert_eq!(
                ledger.insert(
                    key,
                    ClaudeRequestCensusRecord::family_record(
                        [0; 32],
                        if at == 599 { 1 } else { now },
                        ClaudeFamilyMemo::default()
                    )
                ),
                ClaudeRequestCensusInsert::Stored
            );
        }
        let deadline = || Instant::now() + Duration::from_secs(1);
        assert_eq!(drop_old_family_memos(&mut ledger, now, deadline()), 0);
        assert_eq!(
            ledger.family_cursor,
            format!("{FAMILY_KEY_PREFIX}{:064x}", 255)
        );
        assert_eq!(drop_old_family_memos(&mut ledger, now, Instant::now()), 0);
        assert_eq!(
            ledger.family_cursor,
            format!("{FAMILY_KEY_PREFIX}{:064x}", 255)
        );
        assert_eq!(drop_old_family_memos(&mut ledger, now, deadline()), 0);
        assert_eq!(drop_old_family_memos(&mut ledger, now, deadline()), 1);
        assert!(ledger
            .get(&format!("{FAMILY_KEY_PREFIX}{:064x}", 599))
            .is_none());
        assert_eq!(drop_old_family_memos(&mut ledger, now, deadline()), 0);
        assert!(ledger.family_cursor.is_empty());
        println!("MONEY_P1B_RETENTION records=600 batch=256 expired_advanced=0 stale_tail_dropped=1 wrapped=1");
    }
    #[test]
    fn cached_deadline_digest_matches_canonical_bytes_across_families_and_census_shapes() {
        use coverage::CensusReason;
        let ledger = ClaudeLedger::new_for_test();
        let mut counts = ClaudeRequestMoneyShadowCounts::default();
        let mut cached = DeadlineDigest::default();
        for state in [
            FamilyCensus::Covered,
            FamilyCensus::Unknown(CensusReason::FenceInvalid),
            FamilyCensus::Unknown(CensusReason::CensusIncomplete),
            FamilyCensus::Unknown(CensusReason::AuthorityRetry),
            FamilyCensus::Unknown(CensusReason::StrongViewUnavailable),
            FamilyCensus::Missing {
                keys: vec!["private-key".to_owned()],
                more: 0,
            },
            FamilyCensus::Missing {
                keys: vec![],
                more: 5,
            },
        ] {
            for (at, root) in ["first-root", "second-root", "first-root"]
                .iter()
                .enumerate()
            {
                let mut rows = failure_rows(
                    root,
                    "deadline",
                    state.clone(),
                    at as u64 + 10,
                    at as u64 + 100,
                    &ledger,
                    &mut counts,
                );
                let expected = semantic_digest(&mut rows);
                assert_eq!(cached.digest(&mut rows), expected, "{state:?}: {root}");
                assert_eq!(
                    cached.deferred(root, &state, &ledger),
                    expected,
                    "producer deferred digest must equal the writer canonical digest"
                );
                assert_eq!(
                    (rows.row.observed_unix, rows.row.snapshot),
                    (at as u64 + 10, at as u64 + 100)
                );
            }
        }
    }
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

#[cfg(test)]
mod schedule_head_tests {
    use super::*;

    /// The old head selection over the whole keyed prefix.
    fn select_nth_head<'r>(
        mut order: Vec<(&'r str, String, u64)>,
        captured: &BTreeSet<&str>,
        cut_off: bool,
    ) -> Vec<(&'r str, String, u64)> {
        let head_order = |left: &(&str, String, u64), right: &(&str, String, u64)| {
            let uncaptured = |entry: &(&str, String, u64)| cut_off && !captured.contains(entry.0);
            uncaptured(left)
                .cmp(&uncaptured(right))
                .then_with(|| schedule_order(left, right))
        };
        let head = order.len().min(capture::NEXT_PAGE_FAMILIES);
        if order.len() > head {
            order.select_nth_unstable_by(head - 1, head_order);
        }
        order.truncate(head);
        order.sort_by(head_order);
        order
    }

    /// MONEY round 5: the incrementally kept head equals the old whole-prefix
    /// selection on random keyed prefixes, with equal-turn ties, captured
    /// and uncaptured roots, complete and cut-off schedules; the entries it
    /// leaves are exactly the rest.
    #[test]
    fn schedule_head_equals_select_nth_on_random_prefixes() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        let roots = (0..400)
            .map(|at| format!("root-{at:03}"))
            .collect::<Vec<_>>();
        for case in 0..300 {
            let len = match case % 4 {
                0 => next(capture::NEXT_PAGE_FAMILIES as u64 + 1) as usize,
                _ => next(roots.len() as u64 + 1) as usize,
            };
            let turns = [1, 3, 50, 1 << 40][case % 4];
            let captured_share = next(5);
            let mut picked = roots.iter().map(String::as_str).collect::<Vec<_>>();
            for at in (1..picked.len()).rev() {
                picked.swap(at, next(at as u64 + 1) as usize);
            }
            picked.truncate(len);
            let captured = picked
                .iter()
                .copied()
                .filter(|_| next(4) < captured_share)
                .collect::<BTreeSet<_>>();
            // Captured roots are keyed first, as on a page.
            picked.sort_by_key(|root| !captured.contains(root));
            let entries = picked
                .iter()
                .map(|root| (*root, family_key(root), next(turns)))
                .collect::<Vec<_>>();
            for cut_off in [false, true] {
                let mut oldest = ScheduleHead::default();
                let mut rest = Vec::new();
                for entry in entries.iter().cloned() {
                    let is_captured = captured.contains(entry.0);
                    rest.extend(oldest.push(entry, is_captured));
                }
                let (head, displaced) = oldest.finish(cut_off);
                rest.extend(displaced);
                let expected = select_nth_head(entries.clone(), &captured, cut_off);
                assert_eq!(head, expected, "case {case} cut_off {cut_off}");
                let mut all = head
                    .iter()
                    .chain(&rest)
                    .map(|entry| entry.0)
                    .collect::<Vec<_>>();
                all.sort_unstable();
                let mut keyed = picked.clone();
                keyed.sort_unstable();
                assert_eq!(all, keyed, "case {case}: every keyed root is kept once");
            }
        }
    }
}
