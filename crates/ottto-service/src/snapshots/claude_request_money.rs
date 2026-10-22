//! P1 per-request Claude Code money, shadow only (`claude_request_counting:v1`).
//!
//! The live path is unchanged: nothing here changes an upload byte, a hold,
//! an account decision, a live allowance or a return value. The live
//! finalizer runs exactly as before unless the shadow is armed; then a side
//! capture (its own funded budget, never on `SnapshotItem` or any live
//! reservation) records which live bucket row each response went to, its
//! message identity and the responses the occurrence map does not keep.
//!
//! Each authoritative Claude page builds a second body beside the live one
//! (`body::build_claude_request_body`), checks its certificate, and writes
//! the B1 pricing rows: one `grain` row per differing slice (hour, model,
//! pricing selectors, token components, own costs, an explanation
//! category), one `family` row with old/new totals and the true removal
//! delta, and a `coverage` row that is false whenever anything (a refused
//! page, a truncated day, an unbuilt member, a held unit, unread rows, an
//! unfinished telemetry sweep) leaves the day unusable for the exit
//! criterion. All of its memory is admitted before allocation against the
//! shadow's own ceilings; a refusal skips the page's shadow, writes a false
//! coverage row and is counted.

pub(crate) mod body;
pub(crate) mod capture;
pub(crate) mod rows;

use super::claude_request_census::{
    claude_request_hash, family_key, telemetry_key, ClaudeFamilyMemo, ClaudeRequestCensus,
    ClaudeRequestCensusRecord, FAMILY_KEY_PREFIX, TELEMETRY_KEY_PREFIX,
};
use super::claude_request_ledger::{
    self, ClaudeClassifyContext, ClaudeCountedBy, ClaudeLedgerScope, ClaudeUndecidedBy,
};
use super::{
    claude_index_path_family_member, claude_snapshot_family_root_ref,
    claude_trace_owner_session_id, ScanIndex, SnapshotItem, UsageTotals,
};
use crate::claude_local_otel::telemetry_tail::{
    tail_fixed_memory, telemetry_complete_through, ClaudeLedgerWork, ClaudeTelemetryTail,
    ClaudeTelemetryTailBudget, ClaudeTelemetryTailCounts,
};
use crate::claude_local_otel::{ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipLoadReport};
use body::{
    build_claude_request_body, ClaudeFamilyCategory, ClaudeFamilyInput, ClaudeGrainKey,
    ClaudeGrainSide, ClaudeRequestBody,
};
pub(crate) use capture::ClaudeResponseCapture;
use rows::{ClaudeApiRow, ClaudeRootRows, ClaudeRowCounts, Reconstructed};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) const CLAUDE_REQUEST_COUNTING: &str = "claude_request_counting:v1";
/// Row format of the JSONL (B1 reader `claude_money_shadow_report.py`).
const JSONL_VERSION: u8 = 2;

/// A unit younger than this is immature: deferred, neither counted nor removed.
pub(crate) const MATURITY_SECONDS: u64 = 60;

/// Aggregate transient shadow memory ceiling (all concurrent pages).
pub(crate) const SHADOW_MEMORY_CEILING_BYTES: usize = 64 * 1024 * 1024;
/// The ledger's persistent state in the index (telemetry and message-only
/// hashes, sweeps and family memos), funded for its whole lifetime: the
/// working index, the committed clone and the save buffer.
pub(crate) const LEDGER_FUNDING_CEILING_BYTES: usize = 96 * 1024 * 1024;
const LEDGER_COPIES: usize = 3;

/// The shared per-page work budget of every shadow reader.
const WORK_MAX_BYTES: u64 = 16 * 1024 * 1024;
const WORK_MAX_STATS: u64 = 1024;
const WORK_MAX_ELAPSED: Duration = Duration::from_millis(250);

/// Daily JSONL: per-day byte cap and days kept. The last bytes of the cap
/// are kept for the seal row (a false coverage row naming the truncation).
const JSONL_DAY_CAP_BYTES: u64 = 8 * 1024 * 1024;
const JSONL_SEAL_RESERVE_BYTES: u64 = 512;
const JSONL_RETENTION_DAYS: i64 = 7;
const JSONL_PREFIX: &str = "claude-request-money-shadow-";
const JSONL_MAX_DIR_ENTRIES: usize = 1024;
/// Family memos older than this (no page rebuilt the family) are dropped.
const FAMILY_MEMO_RETENTION_SECONDS: u64 = 35 * 86_400;

// Per-element admission charges (bytes), generous for the owned strings.
const UNIT_BYTES: usize = 512;
const LIVE_ROW_BYTES: usize = 768;
const GRAIN_BYTES: usize = 2048;
const FAMILY_BYTES: usize = 8192;
const TRACE_ROW_BYTES: usize = 160;

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

/// The ledger's persistent state, funded while it lives in the index.
static LEDGER_FUNDED: AtomicUsize = AtomicUsize::new(0);

/// Bytes the ledger's records hold in the index, times its copies.
pub(crate) fn ledger_funding_need(census: &ClaudeRequestCensus) -> usize {
    let (ledger_hashes, message_hashes, ledger_bytes) = census.ledger_totals();
    ledger_hashes
        .saturating_add(message_hashes)
        .saturating_mul(8)
        .saturating_add(ledger_bytes)
        .saturating_mul(LEDGER_COPIES)
}

/// Re-size the persistent funding to the ledger's current need. False when
/// it no longer fits: the ledger must not grow (the tail stops; debt).
fn fund_ledger(census: &ClaudeRequestCensus) -> bool {
    let need = ledger_funding_need(census);
    LEDGER_FUNDED
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |_| {
            (need <= LEDGER_FUNDING_CEILING_BYTES).then_some(need)
        })
        .is_ok()
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
    pub(crate) families_rows_unchanged: u64,
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
    pub(crate) refused_budget: u64,
    pub(crate) ledger_unfunded: u64,
    pub(crate) ledger_funded_bytes: u64,
    pub(crate) captures_taken: u64,
    pub(crate) captures_purged: u64,
    pub(crate) capture_reserved_bytes: u64,
    pub(crate) work_stopped: u64,
    pub(crate) telemetry_retired_pressure: u64,
    pub(crate) family_memos_dropped: u64,
    pub(crate) removed_change_available: u64,
    pub(crate) removed_change_unavailable: u64,
    pub(crate) jsonl_rows: u64,
    pub(crate) jsonl_truncated: u64,
    pub(crate) jsonl_sealed: u64,
    pub(crate) jsonl_failed: u64,
    /// Members not in the page whose census `u` was known / unknown
    /// (advisory, shadow only).
    pub(crate) absent_members_old_known: u64,
    pub(crate) absent_members_old_unknown: u64,
    pub(crate) coverage_complete: u64,
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
#[derive(Debug, Serialize)]
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
/// items, the strict rows and traces the live path already loaded and the
/// captures of this page's parses; mutates only the census's ledger records
/// (`otel:`, `sweep:`, `fam:`). Never fails the page.
pub(crate) fn shadow_page(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &mut ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    census_complete: bool,
) {
    if !shadow_enabled(support_dir) {
        return;
    }
    shadow_page_at(
        support_dir,
        snapshots,
        index,
        api_report,
        trace_report,
        census_complete,
        now_unix(),
    );
}

/// Index keys of each (root, member) and the indexed members of each root.
type FamilyMembers = (
    BTreeMap<(String, String), Vec<String>>,
    BTreeMap<String, BTreeSet<String>>,
);

fn family_members(index: &ScanIndex, roots: &BTreeSet<&str>) -> FamilyMembers {
    let mut member_keys = BTreeMap::<(String, String), Vec<String>>::new();
    let mut members = BTreeMap::<String, BTreeSet<String>>::new();
    for key in index.files.keys() {
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
    (member_keys, members)
}

pub(crate) fn shadow_page_at(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &mut ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    trace_report: &ClaudeTraceOwnershipLoadReport,
    census_complete: bool,
    now: u64,
) -> ClaudeRequestMoneyShadowCounts {
    let started = Instant::now();
    let mut counts = ClaudeRequestMoneyShadowCounts::default();
    let scope_key = shadow_scope(support_dir);
    let snapshot = next_snapshot();
    let tail_budget = ClaudeTelemetryTailBudget::default();
    let roots = snapshots
        .iter()
        .map(claude_snapshot_family_root_ref)
        .collect::<BTreeSet<_>>();
    let (member_keys, indexed_members) = family_members(index, &roots);
    let key_of = |root: &str, member: &str| {
        member_keys
            .get(&(root.to_owned(), member.to_owned()))
            .filter(|keys| keys.len() == 1)
            .map(|keys| keys[0].clone())
    };

    // Take this page's captures first: they are funded by the capture
    // budget and freed whatever the page decides.
    let mut captures = BTreeMap::<(String, String), ClaudeResponseCapture>::new();
    for item in snapshots {
        let root = claude_snapshot_family_root_ref(item);
        let Some(key) = key_of(root, &item.source_session_id) else {
            continue;
        };
        let fingerprints = [
            item.source_file_fingerprint.clone(),
            index
                .files
                .get(&key)
                .map(|entry| entry.source_file_fingerprint.clone()),
        ];
        if let Some(capture) = fingerprints
            .iter()
            .flatten()
            .find_map(|fingerprint| capture::take_capture(&scope_key, &key, fingerprint))
        {
            counts.captures_taken += 1;
            captures.insert((root.to_owned(), item.source_session_id.clone()), capture);
        }
    }
    if let Ok(mut last) = LAST_SHADOW.lock() {
        if let Some(previous) = last.insert(scope_key.clone(), Instant::now()) {
            counts.captures_purged = capture::purge_before(&scope_key, previous);
        }
    }
    counts.capture_reserved_bytes = capture::capture_reserved() as u64;

    // Admission before any allocation: units, live rows, bucket rows, the
    // holders, the scope, grains, families, traces and the tail's fixed
    // memory. Reconstructed rows and the tail's per-file hashes are admitted
    // as they come.
    let units = snapshots
        .iter()
        .map(|item| item.claude_usage_occurrences.len())
        .sum::<usize>()
        .saturating_add(captures.values().map(|c| c.units().len()).sum::<usize>());
    let live_rows = roots
        .iter()
        .filter_map(|root| api_report.evidence.get(*root))
        .flatten()
        .map(rows::row_bound)
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
    let admission = units
        .saturating_mul(UNIT_BYTES + GRAIN_BYTES)
        .saturating_add(live_rows.saturating_mul(2))
        .saturating_add(trace_rows.saturating_mul(TRACE_ROW_BYTES))
        .saturating_add(bucket_rows.saturating_mul(LIVE_ROW_BYTES))
        .saturating_add(claude_request_ledger::holders_bound(
            units.saturating_add(live_rows / 64),
        ))
        .saturating_add(claude_request_ledger::scope_bound(
            index.files.len(),
            key_bytes,
        ))
        .saturating_add(roots.len().saturating_mul(FAMILY_BYTES))
        .saturating_add(index.files.len().saturating_mul(64))
        .saturating_add(tail_fixed_memory(&tail_budget));
    counts.admission_bytes = admission as u64;
    let Some(_reservation) = ShadowReservation::admit(admission) else {
        counts.refused_budget = 1;
        counts.elapsed_us = started.elapsed().as_micros() as u64;
        append_jsonl(
            support_dir,
            now,
            &[],
            Some(CoverageRow {
                row: "coverage",
                v: JSONL_VERSION,
                observed_unix: now,
                coverage_complete: false,
                families: roots.len() as u64,
                families_incomplete: roots.len() as u64,
                refused: true,
                truncated: false,
                telemetry_sweep_complete: false,
                rows_unavailable_roots: 0,
            }),
            &mut counts,
        );
        emit_line(&ShadowLine {
            counting: CLAUDE_REQUEST_COUNTING,
            census_complete,
            counts: &counts,
            tail: &ClaudeTelemetryTailCounts::default(),
            rows: &ClaudeRowCounts::default(),
            scope: &claude_request_ledger::ClaudeScopeDebt::default(),
            ledger: &claude_request_ledger::ledger_state_counts(&index.claude_request_census),
        });
        return counts;
    };

    // The ledger: advance the telemetry sweep under the shared work budget,
    // only while its persistent state is funded.
    let mut work = ClaudeLedgerWork::new(WORK_MAX_BYTES, WORK_MAX_STATS, WORK_MAX_ELAPSED);
    let tail = if fund_ledger(&index.claude_request_census) {
        let tail = ClaudeTelemetryTail::advance(
            support_dir,
            &mut index.claude_request_census,
            now,
            &tail_budget,
            &mut work,
        );
        counts.telemetry_retired_pressure = claude_request_ledger::retire_telemetry_under_pressure(
            &mut index.claude_request_census,
        );
        tail
    } else {
        counts.ledger_unfunded = 1;
        ClaudeTelemetryTailCounts::default()
    };

    // Rows: the live load's, else the fair resumable reconstruction.
    let mut row_counts = ClaudeRowCounts::default();
    let mut root_rows = BTreeMap::<String, Option<ClaudeRootRows>>::new();
    let mut missing = Vec::new();
    for &root in &roots {
        match api_report.evidence.get(root) {
            Some(evidence) => {
                row_counts.roots_live += 1;
                let mut converted = Vec::with_capacity(evidence.len());
                let mut refused = 0;
                for row in evidence {
                    match ClaudeApiRow::from_evidence(row, root) {
                        Some(row) => converted.push(row),
                        None => refused += 1,
                    }
                }
                row_counts.rows_refused += refused;
                root_rows.insert(
                    root.to_owned(),
                    (refused == 0).then(|| ClaudeRootRows::new(converted)),
                );
            }
            None => missing.push(root),
        }
    }
    let mut copy_reservations = Vec::new();
    let mut admit_copy = |bytes: usize| match ShadowReservation::admit(bytes) {
        Some(reservation) => {
            copy_reservations.push(reservation);
            true
        }
        None => false,
    };
    for (root, outcome) in rows::reconstruct_rows(
        support_dir,
        &missing,
        &mut index.claude_request_census,
        &mut work,
        &mut admit_copy,
        &mut row_counts,
    ) {
        let rows = match outcome {
            Reconstructed::Complete(rows) => Some(ClaudeRootRows::new(rows)),
            Reconstructed::Unavailable => None,
        };
        root_rows.insert(root, rows);
    }
    counts.work_stopped = u64::from(work.stopped);
    for rows in root_rows.values().flatten() {
        row_counts.rows_conflicting += rows.conflicts;
    }
    counts.rows_live_roots = row_counts.roots_live;
    counts.rows_refused = row_counts.rows_refused;
    counts.rows_conflicting = row_counts.rows_conflicting;
    counts.rows_unavailable_roots = root_rows.values().filter(|rows| rows.is_none()).count() as u64;

    // Telemetry claims, first-event times and traces of the page's roots.
    let mut page_claims = BTreeMap::<u64, Vec<String>>::new();
    let mut first_event = BTreeMap::<String, u64>::new();
    for (key, record) in index.claude_request_census.records() {
        if let Some(tail) = record
            .tail()
            .filter(|_| key.starts_with(TELEMETRY_KEY_PREFIX))
        {
            first_event.insert(key.clone(), tail.first_event_unix);
        }
    }
    for (root, rows) in &root_rows {
        let Some(rows) = rows else { continue };
        let key = telemetry_key(root);
        let earliest = rows
            .iter()
            .map(|row| row.clock)
            .filter(|clock| *clock > 0)
            .min();
        if let Some(earliest) = earliest {
            let slot = first_event.entry(key.clone()).or_insert(0);
            if *slot == 0 || earliest < *slot {
                *slot = earliest;
            }
        }
        for row in rows.iter() {
            page_claims
                .entry(row.request_hash)
                .or_default()
                .push(key.clone());
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

    let index_ref: &ScanIndex = index;
    let holders = claude_request_ledger::scan_holders(
        &index_ref.claude_request_census,
        &page_hashes,
        &page_message_hashes,
    );
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
    let scope = ClaudeLedgerScope::build(index_ref, &page_groups, &roots);
    let complete_through = telemetry_complete_through(&index_ref.claude_request_census);
    let ctx = ClaudeClassifyContext {
        index: index_ref,
        holders: &holders,
        scope: &scope,
        page_claims: &page_claims,
        first_event: &first_event,
        trace: &traces,
        telemetry_complete_through: complete_through,
    };
    let retired_roots =
        claude_request_ledger::roots_with_retired_records(&index_ref.claude_request_census);

    let mut bodies = Vec::new();
    for &root in &roots {
        let items = snapshots
            .iter()
            .filter(|item| claude_snapshot_family_root_ref(item) == root)
            .collect::<Vec<_>>();
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
        for item in &items {
            if let Some(capture) =
                captures.remove(&(root.to_owned(), item.source_session_id.clone()))
            {
                family_captures.insert(item.source_session_id.as_str(), capture);
            }
        }
        // Members not in this page: their census `u` (what the old path last
        // built for that file), advisory only. Missing, malformed or stale
        // is unknown, never zero.
        let mut absent_old = ClaudeMoneyTotals::default();
        let mut absent_old_unknown = 0_u64;
        for member in members {
            if items.iter().any(|item| item.source_session_id == *member) {
                continue;
            }
            let usage = key_of(root, member).and_then(|key| {
                let entry = index_ref.files.get(&key)?;
                let record = index_ref.claude_request_census.get(&key)?;
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
            items,
            member_keys: keys,
            indexed_members: members,
            members_total: total,
            rows: root_rows.get(root).and_then(Option::as_ref),
            trace: traces.get(root),
            captures: family_captures,
        };
        let body = build_claude_request_body(&family, &ctx, &collisions, now, &mut counts);
        if retired_roots.contains(root) {
            counts.possible_retired_copies += body.units.requests;
        }
        let union = union_revision(members);
        bodies.push((root, body, union, absent_old, absent_old_unknown));
    }
    let scope_debt = scope.debt;
    drop(ctx);
    drop(holders);
    drop(scope);

    // Rows, memos and the coverage flag.
    let sweep_complete = complete_through > 0 && !tail.sweep_debt;
    let mut lines = Vec::new();
    let mut families_incomplete = 0_u64;
    for (root, body, union, absent_old, absent_old_unknown) in bodies {
        let complete = body.coverage_complete(census_complete);
        tally(&mut counts, &body, complete);
        families_incomplete += u64::from(!complete);
        let family = hashed_id(root);
        let memo_key = family_key(root);
        let memo = index
            .claude_request_census
            .get(&memo_key)
            .and_then(ClaudeRequestCensusRecord::family_memo)
            .map(|(revision, memo)| (*revision, memo));
        let (removed_change, basis, unavailable) = match (complete, memo) {
            (false, _) => (None, None, Some("body_incomplete")),
            (true, None) => (None, None, Some("no_previous_body")),
            (true, Some((revision, _))) if revision != union => (None, None, Some("union_changed")),
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
        if removed_change.is_some() {
            counts.removed_change_available += 1;
        } else {
            counts.removed_change_unavailable += 1;
        }
        let mut family_lines = Vec::with_capacity(body.grains.len() + 1);
        for (key, (old, new)) in &body.grains {
            family_lines.push(grain_line(snapshot, &family, key, old, new));
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
        family_lines.push(serde_json::to_string(&row).ok());
        // Skip a family whose rows did not change since its last write today
        // (the reader keeps each family's latest snapshot).
        let digest = rows_digest(now, &body, complete);
        let unchanged = memo.is_some_and(|(_, memo)| memo.rows_digest == digest);
        if unchanged {
            counts.families_rows_unchanged += 1;
        } else {
            lines.extend(family_lines.into_iter().flatten());
        }
        // The memo: removals move only with a complete body.
        let next = match (complete, memo) {
            (true, _) => (
                union,
                ClaudeFamilyMemo {
                    removed_requests: body.removed.requests,
                    removed_tokens: body.removed.tokens,
                    rows_digest: digest,
                },
            ),
            (false, Some((revision, memo))) => (
                revision,
                ClaudeFamilyMemo {
                    rows_digest: digest,
                    ..memo
                },
            ),
            (false, None) => (
                union,
                ClaudeFamilyMemo {
                    removed_requests: u64::MAX,
                    removed_tokens: u64::MAX,
                    rows_digest: digest,
                },
            ),
        };
        let _ = index.claude_request_census.insert(
            memo_key,
            ClaudeRequestCensusRecord::family_record(next.0, now, next.1),
        );
    }
    counts.family_memos_dropped = drop_old_family_memos(&mut index.claude_request_census, now);
    let page_complete = families_incomplete == 0 && census_complete && sweep_complete;
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
    };
    append_jsonl(support_dir, now, &lines, Some(coverage), &mut counts);
    counts.coverage_complete = u64::from(page_complete && counts.jsonl_truncated == 0);
    // The ledger's persistent funding follows what it now holds.
    if !fund_ledger(&index.claude_request_census) {
        counts.ledger_unfunded = 1;
    }
    counts.ledger_funded_bytes = LEDGER_FUNDED.load(Ordering::Acquire) as u64;
    counts.elapsed_us = started.elapsed().as_micros() as u64;
    emit_line(&ShadowLine {
        counting: CLAUDE_REQUEST_COUNTING,
        census_complete,
        counts: &counts,
        tail: &tail,
        rows: &row_counts,
        scope: &scope_debt,
        ledger: &claude_request_ledger::ledger_state_counts(&index.claude_request_census),
    });
    counts
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

/// Digest of what a family's rows say today (day, totals, every slice).
fn rows_digest(now: u64, body: &ClaudeRequestBody, complete: bool) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"claude_request_money_rows:v1\0");
    digest.update((now / 86_400).to_be_bytes());
    digest.update([u8::from(complete), u8::from(body.unbuilt)]);
    for totals in [
        &body.old,
        &body.new,
        &body.removed,
        &body.held,
        &body.immature,
    ] {
        digest.update(totals.tokens.to_be_bytes());
        digest.update(totals.requests.to_be_bytes());
    }
    digest.update((body.members_built as u64).to_be_bytes());
    digest.update((body.members_total as u64).to_be_bytes());
    for (key, (old, new)) in &body.grains {
        let encoded = format!("{key:?}|{old:?}|{new:?}");
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(encoded.as_bytes());
    }
    let digest = digest.finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix).max(1)
}

/// Drop family memos no page rebuilt within the retention window.
fn drop_old_family_memos(census: &mut ClaudeRequestCensus, now: u64) -> u64 {
    let cutoff = now.saturating_sub(FAMILY_MEMO_RETENTION_SECONDS);
    let stale = census
        .records()
        .filter(|(key, record)| {
            key.starts_with(FAMILY_KEY_PREFIX)
                && record.family_memo().is_some()
                && record.window() < cutoff
        })
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for key in &stale {
        census.remove(key);
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

/// The last coverage flag written per (support dir, day) in this process:
/// a coverage row is written when it changes (and once per day file).
static LAST_COVERAGE: Mutex<BTreeMap<PathBuf, (String, bool)>> = Mutex::new(BTreeMap::new());

/// Append the page's rows and its coverage row to today's capped file and
/// drop own files older than the retention window. When the day's cap would
/// be passed, the file is sealed with a false coverage row (`truncated`)
/// and takes nothing more that day. Failures are counted, never raised.
fn append_jsonl(
    support_dir: &Path,
    now: u64,
    rows: &[String],
    coverage: Option<CoverageRow>,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    let Some(today) = day_stamp(now) else {
        counts.jsonl_failed += 1;
        return;
    };
    let dir = support_dir.join("diagnostics");
    if std::fs::create_dir_all(&dir).is_err() {
        counts.jsonl_failed += 1;
        return;
    }
    let path = dir.join(format!("{JSONL_PREFIX}{today}.jsonl"));
    let mut size = std::fs::metadata(&path).map_or(0, |metadata| metadata.len());
    let sealed_marker = dir.join(format!(".{JSONL_PREFIX}{today}.sealed"));
    if sealed_marker.exists() {
        counts.jsonl_truncated += rows.len() as u64;
        return;
    }
    let room = JSONL_DAY_CAP_BYTES - JSONL_SEAL_RESERVE_BYTES;
    let mut buffer = Vec::new();
    let mut sealed = false;
    for row in rows {
        let bytes = row.len() as u64 + 1;
        if size + bytes > room {
            counts.jsonl_truncated += 1;
            sealed = true;
            continue;
        }
        size += bytes;
        buffer.extend_from_slice(row.as_bytes());
        buffer.push(b'\n');
        counts.jsonl_rows += 1;
    }
    let coverage = if sealed {
        counts.jsonl_sealed = 1;
        Some(CoverageRow {
            row: "coverage",
            v: JSONL_VERSION,
            observed_unix: now,
            coverage_complete: false,
            families: 0,
            families_incomplete: 0,
            refused: false,
            truncated: true,
            telemetry_sweep_complete: false,
            rows_unavailable_roots: 0,
        })
    } else {
        coverage
    };
    if let Some(coverage) = coverage {
        let flag = coverage.coverage_complete;
        let changed = LAST_COVERAGE.lock().map_or(true, |mut last| {
            let key = support_dir.to_path_buf();
            let fresh = !path.exists() && buffer.is_empty();
            let previous = last.insert(key, (today.clone(), flag));
            fresh || previous != Some((today.clone(), flag))
        });
        if changed || sealed || !path.exists() {
            if let Ok(json) = serde_json::to_string(&coverage) {
                buffer.extend_from_slice(json.as_bytes());
                buffer.push(b'\n');
                counts.jsonl_rows += 1;
            }
        }
    }
    if !buffer.is_empty() {
        let written = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(&buffer));
        if written.is_err() {
            counts.jsonl_failed += 1;
        }
    }
    if sealed {
        let _ = std::fs::write(&sealed_marker, b"");
    }
    let Some(oldest) = day_stamp(now.saturating_sub((JSONL_RETENTION_DAYS * 86_400) as u64)) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
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
        if day.len() == 8 && day.bytes().all(|byte| byte.is_ascii_digit()) && day < oldest.as_str()
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
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
