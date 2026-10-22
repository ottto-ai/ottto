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
//! to one writer thread after the page, outside `SNAPSHOT_SYNC_LOCK`.
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
//! its day, written with the next batch. All of its memory is admitted
//! before allocation against the shadow's own ceiling and its work runs
//! under a deadline; a refusal skips the page's shadow, writes a false
//! coverage row and is counted.
//!
//! The shadow never fails or stalls the live page: a panic is caught (the
//! shadow is then off for the rest of the process, counted), every phase
//! under the sync lock checks the page deadline, and a local file
//! (`<support>/claude-request-money-shadow.off`) turns it off without a
//! release.

pub(crate) mod body;
pub(crate) mod capture;
pub(crate) mod facts;
pub(crate) mod rows;
pub(crate) mod store;

use super::claude_request_census::{
    claude_request_hash, family_key, fingerprint_matches, message_key, telemetry_key,
    ClaudeFamilyMemo, ClaudeRequestCensusInsert, ClaudeRequestCensusRecord, FAMILY_KEY_PREFIX,
    MESSAGE_KEY_PREFIX,
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
const JSONL_VERSION: u8 = 2;

/// A unit younger than this is immature: deferred, neither counted nor removed.
pub(crate) const MATURITY_SECONDS: u64 = 60;

/// Aggregate transient shadow memory ceiling (all concurrent pages and the
/// batches waiting for the writer).
pub(crate) const SHADOW_MEMORY_CEILING_BYTES: usize = 64 * 1024 * 1024;

/// The shared per-page I/O budget of every shadow reader.
const WORK_MAX_BYTES: u64 = 16 * 1024 * 1024;
const WORK_MAX_STATS: u64 = 1024;
const WORK_MAX_ELAPSED: Duration = Duration::from_millis(250);
/// The whole page's deadline: enumeration, the census intersections, the
/// scope, grouping, the bodies and the rows. Past it the page is refused.
const PAGE_MAX_ELAPSED: Duration = Duration::from_secs(2);
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

/// The finalizer captures for the money shadow only where it is armed. In
/// tests: a transcript under the parent of an enabled support directory
/// (fixtures keep both side by side); in production: always.
pub(crate) fn capture_armed(path: &Path) -> Option<PathBuf> {
    #[cfg(test)]
    {
        SHADOW_ENABLED_FOR_TEST
            .lock()
            .expect("shadow control")
            .iter()
            .find(|dir| dir.parent().is_some_and(|base| path.starts_with(base)))
            .cloned()
    }
    #[cfg(not(test))]
    {
        let _ = path;
        Some(PathBuf::new())
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

    fn granted(&self) -> usize {
        self.granted
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
struct FamilyRow<'a> {
    row: &'static str,
    v: u8,
    counting: &'static str,
    snapshot: u64,
    observed_unix: u64,
    family: &'a str,
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

/// The page's custody flag (B1 `coverage` row).
#[derive(Debug, Clone, Serialize)]
struct CoverageRow {
    row: &'static str,
    v: u8,
    observed_unix: u64,
    coverage_complete: bool,
    families: u64,
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
            row: "coverage",
            v: JSONL_VERSION,
            observed_unix,
            coverage_complete: false,
            families: 0,
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
pub(crate) fn shadow_page(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    census_complete: bool,
) {
    if !shadow_enabled(support_dir)
        || SHADOW_PANICKED.load(Ordering::Acquire)
        || support_dir.join(SHADOW_OFF_FILE).exists()
    {
        return;
    }
    guarded(|| {
        shadow_page_at(
            support_dir,
            snapshots,
            index,
            api_report,
            trace_report,
            census_complete,
            now_unix(),
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

pub(crate) fn shadow_page_at(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    census_complete: bool,
    now: u64,
) -> ClaudeRequestMoneyShadowCounts {
    let started = Instant::now();
    let deadline = started + PAGE_MAX_ELAPSED;
    let mut counts = ClaudeRequestMoneyShadowCounts::default();
    let scope_key = shadow_scope(support_dir);
    let snapshot = next_snapshot();
    let tail_budget = ClaudeTelemetryTailBudget::default();
    let mut end = PageEnd {
        support_dir,
        now,
        census_complete,
        started,
        deadline,
        tail: ClaudeTelemetryTailCounts::default(),
        rows: ClaudeRowCounts::default(),
        scope: claude_request_ledger::ClaudeScopeDebt::default(),
    };
    // The page's roots (a pointer per item) are the only allocation before
    // admission: everything else is admitted first, from the page's counts.
    let roots = snapshots
        .iter()
        .map(claude_snapshot_family_root_ref)
        .collect::<BTreeSet<_>>();
    let occurrences = snapshots
        .iter()
        .map(|item| item.claude_usage_occurrences.len())
        .sum::<usize>();
    let live_rows = roots
        .iter()
        .filter_map(|root| api_report.evidence.get(*root))
        .map(Vec::len)
        .sum::<usize>();
    let trace_rows = roots
        .iter()
        .filter_map(|root| trace_report.evidence.get(*root))
        .map(Vec::len)
        .sum::<usize>();
    let bucket_rows = snapshots
        .iter()
        .flat_map(|item| &item.usage_buckets)
        .map(|bucket| bucket.model_usage.len())
        .sum::<usize>();
    let key_bytes = index.files.keys().map(String::len).sum::<usize>();
    // Census records of members the index no longer lists: the scope walks
    // them too.
    let (residue_records, residue_key_bytes) = index
        .claude_request_census
        .records()
        .filter(|(key, _)| !index.files.contains_key(*key))
        .fold((0_usize, 0_usize), |(records, bytes), (key, _)| {
            (records + 1, bytes.saturating_add(key.len()))
        });
    let admission = occurrences
        .saturating_mul(UNIT_BYTES + GRAIN_BYTES + PAGE_HASH_BYTES)
        .saturating_add(row_charge(live_rows))
        .saturating_add(trace_rows.saturating_mul(TRACE_ROW_BYTES))
        .saturating_add(bucket_rows.saturating_mul(LIVE_ROW_BYTES))
        .saturating_add(claude_request_ledger::scope_bound(
            index.files.len().saturating_add(residue_records),
            key_bytes.saturating_add(residue_key_bytes),
        ))
        .saturating_add(roots.len().saturating_mul(FAMILY_BYTES))
        .saturating_add(index.files.len().saturating_mul(64))
        .saturating_add(key_bytes)
        .saturating_add(snapshots.len().saturating_mul(64))
        .saturating_add(tail_fixed_memory(&tail_budget));
    counts.admission_bytes = admission as u64;
    let Some(base) = ShadowReservation::admit(admission) else {
        counts.refused_budget = 1;
        purge_captures(&scope_key, &mut counts);
        return refuse(&end, None, index, roots.len(), counts);
    };
    let mut budget = ShadowBudget::new(base);
    let mut guard = match store::acquire(support_dir) {
        ClaudeLedgerAcquire::Ready(guard) => guard,
        acquired => {
            match acquired {
                ClaudeLedgerAcquire::Loading => counts.ledger_loading = 1,
                _ => counts.ledger_unavailable = 1,
            }
            purge_captures(&scope_key, &mut counts);
            return refuse(&end, None, index, roots.len(), counts);
        }
    };
    let ledger: &mut ClaudeLedger = &mut guard;
    apply_results(support_dir, ledger, &mut counts);
    if std::mem::take(&mut ledger.load_damaged) {
        // A shard was lost: its claims are gone, so is the certificate.
        counts.ledger_load_damaged = 1;
        drop_certificate(ledger);
        end.tail.certificate_dropped += 1;
    }

    let Some((member_keys, indexed_members)) = family_members(index, &roots, deadline) else {
        counts.refused_deadline = 1;
        purge_captures(&scope_key, &mut counts);
        return refuse(&end, Some(ledger), index, roots.len(), counts);
    };
    let key_of = |root: &str, member: &str| {
        member_keys
            .get(&(root.to_owned(), member.to_owned()))
            .filter(|keys| keys.len() == 1)
            .map(|keys| keys[0].clone())
    };
    // The items of each root, grouped once.
    let mut by_root = BTreeMap::<&str, Vec<&SnapshotItem>>::new();
    for item in snapshots {
        by_root
            .entry(claude_snapshot_family_root_ref(item))
            .or_default()
            .push(item);
    }

    // Take this page's captures (funded by the capture budget, freed
    // whatever the page decides) and record each parse's message-only ids.
    let mut captures = BTreeMap::<(String, String), ClaudeResponseCapture>::new();
    for item in snapshots {
        let root = claude_snapshot_family_root_ref(item);
        let Some(key) = key_of(root, &item.source_session_id) else {
            continue;
        };
        let fingerprints = [
            item.source_file_fingerprint.as_deref(),
            index
                .files
                .get(&key)
                .map(|entry| entry.source_file_fingerprint.as_str()),
        ];
        let taken = fingerprints.iter().flatten().find_map(|fingerprint| {
            capture::take_capture(&scope_key, &key, fingerprint)
                .map(|capture| (*fingerprint, capture))
        });
        if let Some((fingerprint, capture)) = taken {
            counts.captures_taken += 1;
            note_message_record(ledger, index, &key, fingerprint, &capture, &mut counts);
            captures.insert((root.to_owned(), item.source_session_id.clone()), capture);
        }
    }
    if let Ok(mut last) = LAST_SHADOW.lock() {
        if let Some(previous) = last.insert(scope_key.clone(), Instant::now()) {
            counts.captures_purged = capture::purge_before(&scope_key, previous);
        }
    }
    counts.capture_reserved_bytes = capture::capture_reserved() as u64;
    let captured_units = captures
        .values()
        .map(|capture| capture.units().len())
        .sum::<usize>();
    if !budget.charge(captured_units.saturating_mul(UNIT_BYTES + GRAIN_BYTES + PAGE_HASH_BYTES)) {
        counts.refused_budget = 1;
        return refuse(&end, Some(ledger), index, roots.len(), counts);
    }

    // The ledger: the page roots' sidecars first (the live load did not keep
    // them), then a slice of the sweep, under the shared work budget.
    let mut work = ClaudeLedgerWork::new(WORK_MAX_BYTES, WORK_MAX_STATS, WORK_MAX_ELAPSED);
    let unloaded = roots
        .iter()
        .copied()
        .filter(|root| !api_report.evidence.contains_key(*root))
        .collect::<Vec<_>>();
    let (tail, root_states) =
        ClaudeTelemetryTail::advance(support_dir, ledger, now, &tail_budget, &unloaded, &mut work);
    let dropped = end.tail.certificate_dropped;
    end.tail = tail;
    end.tail.certificate_dropped += dropped;
    counts.telemetry_retired_pressure =
        claude_request_ledger::retire_telemetry_under_pressure(ledger);
    if counts.telemetry_retired_pressure > 0 {
        drop_certificate(ledger);
        end.tail.certificate_dropped += 1;
    }
    prune_message_records(ledger, index, &mut counts);
    counts.work_stopped = u64::from(work.stopped);

    // Rows: the live load's, else the facts the tail just brought current.
    let mut root_rows = BTreeMap::<&str, Option<ClaudeRootRows>>::new();
    for &root in &roots {
        let rows = match api_report.evidence.get(root) {
            Some(evidence) => {
                end.rows.roots_live += 1;
                let (rows, refused) = ClaudeRootRows::from_live(evidence, root);
                end.rows.rows_refused += refused;
                rows
            }
            None => match root_states.get(root) {
                Some(ClaudeRootTelemetry::Absent) => {
                    end.rows.roots_absent += 1;
                    Some(ClaudeRootRows::default())
                }
                Some(ClaudeRootTelemetry::Current) => match ledger.get(&telemetry_key(root)) {
                    Some(record) if budget.charge(row_charge(record.request_hashes().len())) => {
                        match ClaudeRootRows::from_record(record) {
                            Some(rows) => {
                                end.rows.roots_from_facts += 1;
                                end.rows.rows_decoded += rows.len() as u64;
                                Some(rows)
                            }
                            None => {
                                end.rows.roots_unavailable += 1;
                                None
                            }
                        }
                    }
                    Some(_) => {
                        end.rows.roots_refused_memory += 1;
                        None
                    }
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

    // The page roots' own claims (their rows may be ahead of the ledger),
    // first-event times, sessions and traces.
    let root_keys = roots
        .iter()
        .map(|root| (*root, telemetry_key(root)))
        .collect::<BTreeMap<_, _>>();
    let mut page_claims = BTreeMap::<u64, Vec<&str>>::new();
    let mut first_event = BTreeMap::<String, u64>::new();
    let mut sessions = BTreeMap::<String, String>::new();
    for (root, rows) in &root_rows {
        let key = &root_keys[root];
        sessions.insert(key.clone(), (*root).to_owned());
        let Some(rows) = rows else { continue };
        if let Some(earliest) = rows
            .iter()
            .map(|row| row.clock)
            .filter(|clock| *clock > 0)
            .min()
        {
            first_event.insert(key.clone(), earliest);
        }
        for row in rows.iter() {
            page_claims
                .entry(row.request_hash)
                .or_default()
                .push(key.as_str());
        }
    }
    let mut traces = BTreeMap::<String, BTreeMap<u64, String>>::new();
    for &root in &roots {
        if let Some(trace_rows) = trace_report.evidence.get(root) {
            traces.insert(
                root.to_owned(),
                trace_rows
                    .iter()
                    .map(|row| {
                        (
                            claude_request_hash(&row.request_id),
                            claude_trace_owner_session_id(root, &row.agent_id),
                        )
                    })
                    .collect(),
            );
        }
    }

    // Page hashes (units and rows), collisions by full id.
    let mut first_id = BTreeMap::<u64, &str>::new();
    let mut collisions = BTreeSet::new();
    for item in snapshots {
        for request_id in item.claude_usage_occurrences.keys() {
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
    page_hashes.extend(page_claims.keys().copied());
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
        if Instant::now() >= deadline {
            counts.refused_deadline = 1;
        } else {
            counts.refused_budget = 1;
        }
        return refuse(&end, Some(ledger), index, roots.len(), counts);
    };
    counts.holders_compared = holders.compared;
    let page_groups = snapshots
        .iter()
        .filter_map(|item| {
            key_of(
                claude_snapshot_family_root_ref(item),
                &item.source_session_id,
            )
        })
        .collect::<Vec<_>>();
    let page_groups = page_groups
        .iter()
        .filter_map(|key| claude_request_ledger::claude_project_group(key))
        .collect::<BTreeSet<_>>();
    let Some(scope) =
        ClaudeLedgerScope::build(index, ledger_view.census(), &page_groups, &roots, deadline)
    else {
        drop(holders);
        counts.refused_deadline = 1;
        return refuse(&end, Some(ledger), index, roots.len(), counts);
    };
    let complete_through = telemetry_complete_through(ledger_view);
    let ctx = ClaudeClassifyContext {
        index,
        ledger: ledger_view.census(),
        holders: &holders,
        scope: &scope,
        page_claims: &page_claims,
        first_event: &first_event,
        sessions: &sessions,
        trace: &traces,
        telemetry_complete_through: complete_through,
        deadline,
    };
    let retired_roots =
        claude_request_ledger::roots_with_retired_records(&index.claude_request_census);

    let mut bodies = Vec::with_capacity(by_root.len());
    let mut late = false;
    for (&root, items) in &by_root {
        if Instant::now() >= deadline {
            late = true;
            break;
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
        let body = build_claude_request_body(&family, &ctx, &collisions, now, &mut counts);
        if ctx.late() {
            late = true;
            break;
        }
        if retired_roots.contains(root) {
            counts.possible_retired_copies += body.units.requests;
        }
        let union = union_revision(members);
        bodies.push((root, body, union, absent_old, absent_old_unknown));
    }
    // The page's borrowed evidence ends here: the ledger changes below.
    end.scope = scope.debt;
    drop(holders);
    drop(scope);
    if late {
        counts.refused_deadline = 1;
        return refuse(&end, Some(ledger), index, roots.len(), counts);
    }

    // Rows, memos and the coverage flag. Every family of the page writes its
    // rows (the day's cap bounds them); the reader keeps each family's latest
    // by `snapshot`.
    let sweep_complete = telemetry_certified(ledger);
    let mut lines = Vec::new();
    let mut memos = Vec::with_capacity(bodies.len());
    let mut families_incomplete = 0_u64;
    for (root, body, union, absent_old, absent_old_unknown) in bodies {
        let complete = body.coverage_complete(census_complete);
        tally(&mut counts, &body, complete);
        families_incomplete += u64::from(!complete);
        let family = hashed_id(root);
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
        for (key, (old, new)) in &body.grains {
            lines.extend(grain_line(snapshot, &family, key, old, new));
        }
        let row = FamilyRow {
            row: "family",
            v: JSONL_VERSION,
            counting: CLAUDE_REQUEST_COUNTING,
            snapshot,
            observed_unix: now,
            family: &family,
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
        lines.extend(serde_json::to_string(&row).ok());
        // Only a complete body is a basis; it moves when its rows land.
        if complete {
            memos.push(PendingMemo {
                key: memo_key,
                revision: union,
                observed_unix: now,
                memo: ClaudeFamilyMemo {
                    removed_requests: body.removed.requests,
                    removed_tokens: body.removed.tokens,
                    snapshot,
                },
            });
        }
    }
    counts.family_memos_dropped = drop_old_family_memos(ledger, now);
    let page_complete = families_incomplete == 0 && census_complete && sweep_complete;
    counts.coverage_complete = u64::from(page_complete);
    let coverage = CoverageRow {
        row: "coverage",
        v: JSONL_VERSION,
        observed_unix: now,
        coverage_complete: page_complete,
        families: counts.families,
        families_incomplete,
        refused: false,
        truncated: false,
        telemetry_sweep_complete: sweep_complete,
        rows_unavailable_roots: counts.rows_unavailable_roots,
        dropped: false,
    };
    // The rows move to the batch under their own admission (with the
    // writer's one stream buffer); the page's admission ends here.
    let line_bytes =
        lines.iter().map(|line| line.len() + 1).sum::<usize>() + 1024 + JSONL_WRITE_BUFFER_BYTES;
    let batch = ShadowReservation::admit(line_bytes);
    counts.admitted_peak_bytes = budget.granted().saturating_add(line_bytes) as u64;
    drop(budget);
    let Some(reservation) = batch else {
        // The rows cannot be handed over: a refused page (a false coverage
        // row, no memo moves), never a complete one without its rows.
        counts.refused_budget = 1;
        counts.coverage_complete = 0;
        return refuse(&end, Some(ledger), index, roots.len(), counts);
    };
    hand_off(
        &end,
        Some(&mut *ledger),
        lines,
        coverage,
        memos,
        Some((reservation, JSONL_WRITE_BUFFER_BYTES)),
        &mut counts,
    );
    emit(&end, Some(&*ledger), index, &mut counts);
    counts
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
        row: "coverage",
        v: JSONL_VERSION,
        observed_unix: end.now,
        coverage_complete: false,
        families: families as u64,
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
    rows: Vec<String>,
    coverage: CoverageRow,
    memos: Vec<PendingMemo>,
    reservation: Option<(ShadowReservation, usize)>,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    let buffer_bytes = reservation.as_ref().map_or(0, |(_, bytes)| *bytes);
    let mut reservations = reservation
        .into_iter()
        .map(|(reservation, _)| reservation)
        .collect::<Vec<_>>();
    let mut save = None;
    let mut ledger = ledger;
    if let Some(ledger) = ledger.as_deref_mut() {
        match ledger.take_save(end.deadline) {
            Some((taken, reservation)) => {
                counts.ledger_save_shards = taken.shards() as u64;
                counts.ledger_save_bytes = taken.bytes() as u64;
                reservations.push(reservation);
                save = Some(taken);
            }
            None if Instant::now() >= end.deadline => counts.ledger_save_late = 1,
            None => counts.ledger_save_refused = u64::from(ledger.dirty_shards() > 0),
        }
        counts.ledger_save_oversized = ledger.oversized_shards;
    }
    counts.ledger_loads_refused = store::loads_refused();
    counts.jsonl_queued = rows.len() as u64 + 1;
    let job = WriteJob {
        support_dir: end.support_dir.to_path_buf(),
        jsonl: JsonlBatch {
            now: end.now,
            rows,
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
        owe_coverage(end.support_dir, end.now);
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
    let cached = STATE_COUNTS.lock().ok().and_then(|cache| {
        cache
            .get(end.support_dir)
            .filter(|(at, _)| at.elapsed() < STATE_COUNTS_REFRESH)
            .map(|(_, state)| *state)
    });
    let state = match cached {
        Some(mut state) => {
            claude_request_ledger::refresh_state_totals(&mut state, census, ledger);
            state
        }
        None => {
            let state = claude_request_ledger::ledger_state_counts(census, ledger);
            if let (Some(_), Ok(mut cache)) = (ledger, STATE_COUNTS.lock()) {
                cache.insert(end.support_dir.to_path_buf(), (Instant::now(), state));
            }
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
            let record = ClaudeRequestCensusRecord::family_record(
                memo.revision,
                memo.observed_unix,
                memo.memo,
            );
            let fits = ledger.census().serialized_headroom() >= memo.key.len() + 1024;
            let stored =
                fits && ledger.insert(memo.key, record) == ClaudeRequestCensusInsert::Stored;
            counts.family_memos_withheld += u64::from(!stored);
        }
    }
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

fn grain_line(
    snapshot: u64,
    family: &str,
    key: &ClaudeGrainKey,
    old: &ClaudeGrainSide,
    new: &ClaudeGrainSide,
) -> Option<String> {
    let (hour, model, selector) = &key.live;
    serde_json::to_string(&GrainRow {
        row: "grain",
        v: JSONL_VERSION,
        snapshot,
        family,
        session: hashed_id(&key.member),
        owner: (!key.owner.is_empty()).then(|| hashed_id(&key.owner)),
        hour,
        model,
        selector,
        request_usage_origin: key.origin,
        category: key.category,
        old: old.into(),
        new: new.into(),
    })
    .ok()
}

/// The union revision a removal delta is bound to: the family's indexed
/// member set.
fn union_revision(members: &BTreeSet<String>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"claude_request_money_union:v1\0");
    for member in members {
        digest.update((member.len() as u64).to_be_bytes());
        digest.update(member.as_bytes());
    }
    digest.finalize().into()
}

/// Drop family memos no page rebuilt within the retention window.
fn drop_old_family_memos(ledger: &mut ClaudeLedger, now: u64) -> u64 {
    let cutoff = now.saturating_sub(FAMILY_MEMO_RETENTION_SECONDS);
    let stale = ledger
        .census()
        .records_with_prefix(FAMILY_KEY_PREFIX)
        .filter(|(_, record)| record.family_memo().is_some() && record.window() < cutoff)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for key in &stale {
        ledger.remove(key);
    }
    stale.len() as u64
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

/// False coverage rows owed per support directory: day -> the earliest
/// page that owes it (a dropped batch, or one whose rows were not written).
static COVERAGE_OWED: Mutex<BTreeMap<PathBuf, BTreeMap<String, u64>>> = Mutex::new(BTreeMap::new());

/// The page at `observed_unix` did not reach its day's file: the next batch
/// writes a false coverage row there.
fn owe_coverage(support_dir: &Path, observed_unix: u64) {
    let (Some(day), Ok(mut owed)) = (day_stamp(observed_unix), COVERAGE_OWED.lock()) else {
        return;
    };
    let slot = owed
        .entry(support_dir.to_path_buf())
        .or_default()
        .entry(day)
        .or_insert(observed_unix);
    *slot = (*slot).min(observed_unix);
}

fn take_owed_coverage(support_dir: &Path) -> BTreeMap<String, u64> {
    COVERAGE_OWED
        .lock()
        .ok()
        .and_then(|mut owed| owed.remove(support_dir))
        .unwrap_or_default()
}

/// One page's rows for today's JSONL file (written by the writer).
pub(crate) struct JsonlBatch {
    now: u64,
    rows: Vec<String>,
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

/// Append rows to a day's file through a stream buffer of `buffer_bytes`,
/// first ending a row an earlier failed write left open. False when any
/// write failed.
fn append_rows<'a>(
    path: &Path,
    buffer_bytes: usize,
    rows: impl IntoIterator<Item = &'a [u8]>,
) -> bool {
    let open_row = ends_mid_line(path);
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return false;
    };
    let mut writer = std::io::BufWriter::with_capacity(buffer_bytes, file);
    let mut written = !open_row || writer.write_all(b"\n").is_ok();
    for row in rows {
        written = written && writer.write_all(row).is_ok() && writer.write_all(b"\n").is_ok();
    }
    written && writer.flush().is_ok()
}

/// Append a batch's rows and its coverage row to the day's capped file
/// (streamed from the batch's own rows: no second copy), the false coverage
/// rows earlier batches owe their days, and drop own files older than the
/// retention window. When the day's cap would be passed, the file is sealed
/// with a false coverage row (`truncated`) and takes nothing more that day.
/// A batch not written owes its day a false row. Failures are counted,
/// never raised. Runs on the writer thread only.
fn write_jsonl(support_dir: &Path, batch: &JsonlBatch) -> JsonlOutcome {
    let mut outcome = JsonlOutcome::default();
    let now = batch.now;
    let dir = support_dir.join("diagnostics");
    let owed = take_owed_coverage(support_dir);
    let Some(today) = day_stamp(now).filter(|_| std::fs::create_dir_all(&dir).is_ok()) else {
        outcome.failed += 1;
        for (_, observed) in owed {
            owe_coverage(support_dir, observed);
        }
        owe_coverage(support_dir, now);
        return outcome;
    };
    let day_path = |day: &str| dir.join(format!("{JSONL_PREFIX}{day}.jsonl"));
    let sealed_path = |day: &str| dir.join(format!(".{JSONL_PREFIX}{day}.sealed"));
    let mut owed_today = None;
    for (day, observed) in owed {
        if day == today {
            owed_today = Some(observed);
            continue;
        }
        // A sealed day is already false.
        if sealed_path(&day).exists() {
            continue;
        }
        let row = serde_json::to_string(&CoverageRow::owed(observed)).unwrap_or_default();
        if append_rows(&day_path(&day), 0, [row.as_bytes()]) {
            outcome.owed_written += 1;
        } else {
            outcome.failed += 1;
            owe_coverage(support_dir, observed);
        }
    }
    let path = day_path(&today);
    if sealed_path(&today).exists() {
        outcome.truncated += batch.rows.len() as u64;
        return outcome;
    }
    let room = JSONL_DAY_CAP_BYTES - JSONL_SEAL_RESERVE_BYTES;
    let mut size = std::fs::metadata(&path).map_or(0, |metadata| metadata.len());
    let owed_row =
        owed_today.and_then(|observed| serde_json::to_string(&CoverageRow::owed(observed)).ok());
    let coverage_row = serde_json::to_string(&batch.coverage).unwrap_or_default();
    // What fits under the day's cap, in order: the owed row, the rows, the
    // page's coverage row. The first that does not fit seals the day.
    let mut sealed = false;
    let mut fits = |bytes: usize| {
        let bytes = bytes as u64 + 1;
        if sealed || size + bytes > room {
            sealed = true;
            return false;
        }
        size += bytes;
        true
    };
    let owed_fits = owed_row.as_ref().is_some_and(|row| fits(row.len()));
    let kept = batch.rows.iter().filter(|row| fits(row.len())).count();
    let coverage_fits = fits(coverage_row.len());
    let seal_row = sealed.then(|| {
        serde_json::to_string(&CoverageRow {
            truncated: true,
            dropped: false,
            ..CoverageRow::owed(now)
        })
        .unwrap_or_default()
    });
    outcome.truncated = (batch.rows.len() - kept) as u64;
    let rows = owed_row
        .iter()
        .filter(|_| owed_fits)
        .map(String::as_bytes)
        .chain(batch.rows[..kept].iter().map(String::as_bytes))
        .chain(coverage_fits.then_some(coverage_row.as_bytes()))
        .chain(seal_row.as_deref().map(str::as_bytes));
    let written = append_rows(&path, batch.buffer_bytes, rows);
    if written {
        outcome.rows = kept as u64 + u64::from(coverage_fits) + u64::from(sealed);
        outcome.owed_written += u64::from(owed_fits);
    } else {
        outcome.failed += 1;
        owe_coverage(support_dir, owed_today.unwrap_or(now).min(now));
    }
    if sealed {
        outcome.sealed = 1;
        let _ = std::fs::write(sealed_path(&today), b"");
    }
    outcome.published = written && !sealed;
    if let Some(oldest) = day_stamp(now.saturating_sub((JSONL_RETENTION_DAYS * 86_400) as u64)) {
        prune_jsonl(&dir, &oldest);
    }
    outcome
}

/// Drop own day files (and seal markers) older than `oldest`.
fn prune_jsonl(dir: &Path, oldest: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.take(JSONL_MAX_DIR_ENTRIES).flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let day = name
            .strip_prefix(JSONL_PREFIX)
            .and_then(|rest| rest.strip_suffix(".jsonl"))
            .or_else(|| {
                name.strip_prefix('.')
                    .and_then(|name| name.strip_prefix(JSONL_PREFIX))
                    .and_then(|rest| rest.strip_suffix(".sealed"))
            });
        let Some(day) = day else {
            continue;
        };
        if day.len() == 8 && day.bytes().all(|byte| byte.is_ascii_digit()) && day < oldest {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
pub(crate) fn owe_coverage_for_test(support_dir: &Path, observed_unix: u64) {
    owe_coverage(support_dir, observed_unix);
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
