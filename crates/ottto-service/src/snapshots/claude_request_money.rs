//! P1 per-request Claude Code money, shadow only (`claude_request_counting:v1`).
//!
//! The live path is unchanged: nothing here changes an upload byte, a hold,
//! an account decision or a return value. Each authoritative Claude page
//! builds a second body beside the live one with `build_claude_request_body`,
//! checks its certificate, diffs it against the live totals and reports
//! content-free counts (one log line per page, one local JSONL row per
//! family with hashed ids). All of its memory is admitted before allocation
//! against a fixed shadow ceiling; a refusal skips the page's shadow and is
//! counted.
//!
//! Units are every response the live finalizer admitted: the request-id
//! (`R`) responses its occurrence map keeps plus the message-only (`M`),
//! idless (`L`) and displaced responses of its side list (#667's
//! `into_parts` keys). The live bucket minus all units is a `residue` grain,
//! so the body conserves the live totals by construction and only the units
//! move.

use super::claude_request_census::claude_request_hash;
use super::claude_request_ledger::{self, ClaudeRequestHolders, ClaudeRequestVerdict};
use super::{
    claude_index_path_family_member, claude_model_hash, claude_snapshot_family_root_ref,
    rfc3339_unix_seconds, validate_claude_api_row, ClaudeResidueKind,
    ClaudeTranscriptUsageOccurrence, ScanIndex, SnapshotItem, UsageTotals,
};
use crate::claude_local_otel::telemetry_tail::{
    tail_memory_bound, ClaudeTelemetryTail, ClaudeTelemetryTailBudget, ClaudeTelemetryTailCounts,
};
use crate::claude_local_otel::{ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) const CLAUDE_REQUEST_COUNTING: &str = "claude_request_counting:v1";

/// A unit younger than this is immature: deferred, neither counted nor removed.
pub(crate) const MATURITY_SECONDS: u64 = 60;

/// Aggregate shadow memory ceiling (all concurrent pages).
pub(crate) const SHADOW_MEMORY_CEILING_BYTES: usize = 32 * 1024 * 1024;

/// Bounded reread of API rows for page roots the live path did not load.
const REREAD_MAX_ROOTS: usize = 16;
const REREAD_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Daily JSONL: per-day byte cap and days kept.
const JSONL_DAY_CAP_BYTES: u64 = 8 * 1024 * 1024;
const JSONL_RETENTION_DAYS: i64 = 7;
const JSONL_PREFIX: &str = "claude-request-money-shadow-";
const JSONL_MAX_DIR_ENTRIES: usize = 1024;

// Per-element admission charges (bytes), generous for the owned strings.
const UNIT_BYTES: usize = 320;
const ROW_BYTES: usize = 320;
const BUCKET_ROW_BYTES: usize = 256;
const FAMILY_BYTES: usize = 4096;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeMoneyTokens {
    pub(crate) input: u64,
    pub(crate) output: u64,
    pub(crate) cache_read: u64,
    pub(crate) cache_5m: u64,
    pub(crate) cache_1h: u64,
    pub(crate) unattributed: u64,
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

    fn add(&mut self, other: &Self) {
        self.input = self.input.saturating_add(other.input);
        self.output = self.output.saturating_add(other.output);
        self.cache_read = self.cache_read.saturating_add(other.cache_read);
        self.cache_5m = self.cache_5m.saturating_add(other.cache_5m);
        self.cache_1h = self.cache_1h.saturating_add(other.cache_1h);
        self.unattributed = self.unattributed.saturating_add(other.unattributed);
    }

    /// `self - other` per category, or None when any category would go
    /// negative (the residue carrier cannot be built).
    fn checked_sub(&self, other: &Self) -> Option<Self> {
        Some(Self {
            input: self.input.checked_sub(other.input)?,
            output: self.output.checked_sub(other.output)?,
            cache_read: self.cache_read.checked_sub(other.cache_read)?,
            cache_5m: self.cache_5m.checked_sub(other.cache_5m)?,
            cache_1h: self.cache_1h.checked_sub(other.cache_1h)?,
            unattributed: self.unattributed.checked_sub(other.unattributed)?,
        })
    }

    fn from_occurrence(occurrence: &ClaudeTranscriptUsageOccurrence) -> Self {
        Self::from_usage(&occurrence.usage)
    }

    fn from_usage(usage: &UsageTotals) -> Self {
        Self {
            input: usage.input_tokens,
            output: usage.output_tokens,
            cache_read: usage.cache_read_tokens,
            cache_5m: usage.cache_creation_5m_tokens,
            cache_1h: usage.cache_creation_1h_tokens,
            unattributed: usage.unattributed_total_tokens,
        }
    }

    fn from_model_usage(row: &super::SnapshotModelUsage) -> Self {
        Self {
            input: row.input_tokens,
            output: row.output_tokens,
            cache_read: row.cache_read_tokens,
            cache_5m: row.cache_creation_5m_tokens,
            cache_1h: row.cache_creation_1h_tokens,
            unattributed: row.unattributed_total_tokens,
        }
    }

    /// An API row's own usage, its cache write read by the shared normalizer
    /// (a contradictory write cannot be priced: None).
    fn from_row(row: &ClaudeLocalOtelEvidence) -> Option<Self> {
        let (cache_5m, cache_1h, unattributed) = match claude_cache_creation(
            row.cache_creation_tokens,
            row.cache_creation_5m_tokens,
            row.cache_creation_1h_tokens,
        ) {
            CacheCreation::Split { five_m, one_h } => (five_m, one_h, 0),
            CacheCreation::Unattributed(total) => (0, 0, total),
            CacheCreation::Contradictory => return None,
        };
        Some(Self {
            input: row.input_tokens,
            output: row.output_tokens,
            cache_read: row.cache_read_tokens,
            cache_5m,
            cache_1h,
            unattributed,
        })
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
    fn add(&mut self, tokens: u64, requests: u64, cost_micros: Option<u64>) {
        self.tokens = self.tokens.saturating_add(tokens);
        self.requests = self.requests.saturating_add(requests);
        match cost_micros {
            Some(cost) => self.cost_micros = self.cost_micros.saturating_add(cost),
            None => self.unpriced = self.unpriced.saturating_add(requests),
        }
    }
}

// ---------------------------------------------------------------- conflicts

/// The total order between two different responses under one key (Sol N3):
/// the larger conserved total, then the larger output, then the smaller
/// message-id hash, then the smaller row fingerprint. `Less` = `left` wins.
pub(crate) fn claude_response_conflict_order(
    left: (&ClaudeMoneyTokens, u64, &str),
    right: (&ClaudeMoneyTokens, u64, &str),
) -> std::cmp::Ordering {
    right
        .0
        .conserved()
        .cmp(&left.0.conserved())
        .then_with(|| right.0.output.cmp(&left.0.output))
        .then_with(|| left.1.cmp(&right.1))
        .then_with(|| left.2.cmp(right.2))
}

/// The strict API rows of one root by request id. Rows failing the shared
/// validator are refused; two different rows for one id keep the winner of
/// the conflict order and count the conflict.
fn strict_rows_by_request<'a>(
    root: &str,
    rows: &'a [ClaudeLocalOtelEvidence],
    counts: &mut ClaudeRequestMoneyShadowCounts,
) -> BTreeMap<&'a str, &'a ClaudeLocalOtelEvidence> {
    let mut by_request = BTreeMap::<&str, (&ClaudeLocalOtelEvidence, ClaudeMoneyTokens)>::new();
    for row in rows {
        if !validate_claude_api_row(row, root) {
            counts.rows_invalid += 1;
            continue;
        }
        let Some(tokens) = ClaudeMoneyTokens::from_row(row) else {
            counts.rows_invalid += 1;
            continue;
        };
        match by_request.get_mut(row.request_id.as_str()) {
            None => {
                by_request.insert(row.request_id.as_str(), (row, tokens));
            }
            Some((kept, kept_tokens)) => {
                if kept.fingerprint == row.fingerprint {
                    continue;
                }
                counts.rows_conflicting += 1;
                let order = claude_response_conflict_order(
                    (&tokens, 0, row.fingerprint.as_str()),
                    (&*kept_tokens, 0, kept.fingerprint.as_str()),
                );
                if order == std::cmp::Ordering::Less {
                    *kept = row;
                    *kept_tokens = tokens;
                }
            }
        }
    }
    by_request
        .into_iter()
        .map(|(request, (row, _))| (request, row))
        .collect()
}

// ---------------------------------------------------------------- body

/// `request_usage_origin` of one grain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClaudeRequestUsageOrigin {
    /// A counted transcript unit with no telemetry row.
    Transcript,
    /// A counted transcript unit matched to its API row: transcript tokens
    /// plus the row's own `cost_usd`.
    TelemetryMatched,
    /// Matched, but the row carries no cost.
    TelemetryUnpriced,
    /// A telemetry-only request (side call): the row's own usage and cost.
    TelemetryReported,
    /// Live usage the P1 units do not cover (M, L, displaced responses).
    Residue,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeGrainKey {
    pub(crate) member: String,
    /// Hour start, unix seconds.
    pub(crate) hour: u64,
    /// `claude_model_hash` of the model.
    pub(crate) model: u64,
    pub(crate) origin: ClaudeRequestUsageOrigin,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeGrain {
    pub(crate) tokens: ClaudeMoneyTokens,
    pub(crate) requests: u64,
    pub(crate) cost_micros: Option<u64>,
}

/// Family category in the JSONL and the counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClaudeFamilyCategory {
    Equal,
    DifferTokens,
    DifferRequests,
    /// A member of the family is not in this page (Sol N5: counted, not
    /// rehydrated).
    UnionPartial,
    /// A member could not be built (no clock or model on a unit, a negative
    /// residue, a path twin).
    Unbuilt,
}

/// Everything one family's shadow body says.
#[derive(Debug, Clone, Default)]
pub(crate) struct ClaudeRequestBody {
    pub(crate) grains: BTreeMap<ClaudeGrainKey, ClaudeGrain>,
    pub(crate) old: ClaudeMoneyTotals,
    pub(crate) new: ClaudeMoneyTotals,
    pub(crate) removed: ClaudeMoneyTotals,
    pub(crate) held: ClaudeMoneyTotals,
    pub(crate) immature: ClaudeMoneyTotals,
    pub(crate) units: ClaudeMoneyTotals,
    pub(crate) by_origin: BTreeMap<ClaudeRequestUsageOrigin, ClaudeMoneyTotals>,
    pub(crate) members_built: usize,
    pub(crate) members_total: usize,
    pub(crate) unbuilt: bool,
    pub(crate) certificate_ok: bool,
    pub(crate) rows_complete: bool,
    /// A message-only unit was classified while some record's `mh` is
    /// unknown: never complete.
    pub(crate) message_unknown: bool,
}

impl ClaudeRequestBody {
    pub(crate) fn category(&self) -> ClaudeFamilyCategory {
        if self.unbuilt {
            ClaudeFamilyCategory::Unbuilt
        } else if self.members_built < self.members_total {
            ClaudeFamilyCategory::UnionPartial
        } else if self.new.tokens != self.old.tokens {
            ClaudeFamilyCategory::DifferTokens
        } else if self.new.requests != self.old.requests {
            ClaudeFamilyCategory::DifferRequests
        } else {
            ClaudeFamilyCategory::Equal
        }
    }

    /// The union is whole, every member was built, the certificate holds and
    /// the root's rows were read. (A member record without `mh` leaves its
    /// message-only ids unknown; the ledger then holds those units.)
    pub(crate) fn coverage_complete(&self, census_complete: bool) -> bool {
        census_complete
            && self.rows_complete
            && self.certificate_ok
            && !self.message_unknown
            && !matches!(
                self.category(),
                ClaudeFamilyCategory::UnionPartial | ClaudeFamilyCategory::Unbuilt
            )
    }

    fn add_grain(
        &mut self,
        key: ClaudeGrainKey,
        tokens: ClaudeMoneyTokens,
        requests: u64,
        cost: Option<u64>,
    ) {
        self.by_origin
            .entry(key.origin)
            .or_default()
            .add(tokens.conserved(), requests, cost);
        self.new.add(tokens.conserved(), requests, cost);
        let grain = self.grains.entry(key).or_default();
        grain.tokens.add(&tokens);
        grain.requests = grain.requests.saturating_add(requests);
        grain.cost_micros = match (grain.cost_micros, cost) {
            (Some(left), Some(right)) => Some(left.saturating_add(right)),
            (None, Some(right)) if grain.requests == requests => Some(right),
            _ => None,
        };
    }
}

/// One family of the page, with what the ledger and the live path know.
pub(crate) struct ClaudeFamilyInput<'a> {
    pub(crate) root: &'a str,
    pub(crate) items: Vec<&'a SnapshotItem>,
    /// Census key of each page member, None for a member with no single key.
    pub(crate) member_keys: BTreeMap<&'a str, Option<String>>,
    pub(crate) members_total: usize,
    /// The root's API rows, None when they could not be read.
    pub(crate) rows: Option<&'a [ClaudeLocalOtelEvidence]>,
}

pub(crate) struct ClaudeLedgerView<'a, 'b> {
    pub(crate) index: &'a ScanIndex,
    pub(crate) holders: &'b ClaudeRequestHolders<'a>,
    pub(crate) collisions: &'b BTreeSet<u64>,
    pub(crate) retired_roots: &'b BTreeSet<String>,
    pub(crate) now_unix: u64,
}

fn parse_usd_micros(value: &str) -> Option<u64> {
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

/// One countable unit of a member file (`claude_request_counting:v1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitKey {
    Request(u64),
    Message(u64),
    Idless,
}

struct Unit<'s> {
    key: UnitKey,
    request_id: Option<&'s str>,
    tokens: ClaudeMoneyTokens,
    hour: u64,
    model: u64,
    clock: u64,
}

fn hour_of(clock: u64) -> u64 {
    clock - clock % 3600
}

/// The shadow body of one family (`claude_request_counting:v1`).
///
/// For every member item: the live buckets are the old totals. Its units are
/// the request-id responses the occurrence map keeps (`R`), the message-only
/// (`M`) and idless (`L`) responses of the finalizer's side list, and any
/// displaced `R` response. Two responses under one `R` key keep the winner
/// of the conflict order (Sol N3); the loser is removed. Each unit is then
/// classified by the ledger and lands in exactly one of counted (a
/// `transcript` / `telemetry_matched` / `telemetry_unpriced` grain),
/// removed, held (undecided or two-owner) or immature. A matched API row is
/// a witness of its transcript unit, never a second unit (Sol N1). Whatever
/// the live bucket holds beyond its units is a `residue` grain (none is
/// expected; it is counted). Telemetry rows with no transcript holder
/// anywhere become `telemetry_reported` grains unless the live body already
/// carries reported usage for the family (then they are already counted in
/// the live buckets and are only counted here).
pub(crate) fn build_claude_request_body(
    family: &ClaudeFamilyInput<'_>,
    ledger: &ClaudeLedgerView<'_, '_>,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) -> ClaudeRequestBody {
    let mut body = ClaudeRequestBody {
        members_total: family.members_total,
        rows_complete: family.rows.is_some(),
        certificate_ok: true,
        ..ClaudeRequestBody::default()
    };
    let rows = strict_rows_by_request(family.root, family.rows.unwrap_or_default(), counts);
    let reported_live = family.items.iter().any(|item| {
        item.usage_accounting_contract.as_deref() == Some("session_exclusive_reported_usage:v1")
    });
    let family_retired = ledger.retired_roots.contains(family.root);
    let retirement_cutoff = ledger
        .now_unix
        .saturating_sub(super::claude_request_census::CLAUDE_TRANSCRIPT_RETIREMENT_SECONDS);
    let mut built_members = BTreeSet::new();
    for item in &family.items {
        let member = item.source_session_id.as_str();
        // Old totals: the live buckets, per (hour, model).
        let mut old = BTreeMap::<(u64, u64), (ClaudeMoneyTokens, u64)>::new();
        let mut buildable = true;
        for bucket in &item.usage_buckets {
            let hour = rfc3339_unix_seconds(&bucket.bucket_start);
            for row in &bucket.model_usage {
                let tokens = ClaudeMoneyTokens::from_model_usage(row);
                let cost = row.cost_usd.as_deref().and_then(parse_usd_micros);
                body.old.add(tokens.conserved(), row.request_count, cost);
                let Some(hour) = hour else {
                    buildable = false;
                    continue;
                };
                let slot = old
                    .entry((hour, claude_model_hash(&row.model)))
                    .or_default();
                slot.0.add(&tokens);
                slot.1 = slot.1.saturating_add(row.request_count);
            }
        }
        // Every unit, placed by its own clock and model.
        let mut units = Vec::with_capacity(
            item.claude_usage_occurrences.len() + item.claude_request_residue.len(),
        );
        let mut unit_totals = ClaudeMoneyTokens::default();
        let mut unit_count = 0_u64;
        let mut displaced = Vec::new();
        for (request_id, occurrence) in &item.claude_usage_occurrences {
            let tokens = ClaudeMoneyTokens::from_occurrence(occurrence);
            unit_totals.add(&tokens);
            unit_count += 1;
            let clock = occurrence
                .timestamp
                .as_deref()
                .and_then(rfc3339_unix_seconds);
            match (clock, occurrence.model.as_deref()) {
                (Some(clock), Some(model)) => units.push(Unit {
                    key: UnitKey::Request(claude_request_hash(request_id)),
                    request_id: Some(request_id.as_str()),
                    tokens,
                    hour: hour_of(clock),
                    model: claude_model_hash(model),
                    clock,
                }),
                _ => buildable = false,
            }
        }
        for residue in &item.claude_request_residue {
            let tokens = ClaudeMoneyTokens::from_usage(&residue.usage);
            unit_totals.add(&tokens);
            unit_count += 1;
            let (Some(clock), Some(model)) = (residue.clock, residue.model_hash) else {
                buildable = false;
                continue;
            };
            let unit = |key| Unit {
                key,
                request_id: None,
                tokens,
                hour: hour_of(clock),
                model,
                clock,
            };
            match residue.kind {
                ClaudeResidueKind::Message(hash) => units.push(unit(UnitKey::Message(hash))),
                ClaudeResidueKind::Idless(_) => units.push(unit(UnitKey::Idless)),
                ClaudeResidueKind::Displaced(hash) => displaced.push(unit(UnitKey::Request(hash))),
            }
        }
        body.units.add(unit_totals.conserved(), unit_count, None);
        let Some(Some(own_key)) = family.member_keys.get(member) else {
            body.unbuilt = true;
            counts.unbuilt_items += 1;
            continue;
        };
        if !buildable {
            body.unbuilt = true;
            counts.unbuilt_items += 1;
            continue;
        }
        // Residue = live bucket - every unit (all verdicts), per (hour, model).
        let mut unit_slots = BTreeMap::<(u64, u64), (ClaudeMoneyTokens, u64)>::new();
        for unit in units.iter().chain(&displaced) {
            let slot = unit_slots.entry((unit.hour, unit.model)).or_default();
            slot.0.add(&unit.tokens);
            slot.1 += 1;
        }
        let mut residue = Vec::new();
        let mut negative = false;
        for ((hour, model), (tokens, requests)) in &old {
            let (unit_tokens, unit_requests) =
                unit_slots.remove(&(*hour, *model)).unwrap_or_default();
            match (
                tokens.checked_sub(&unit_tokens),
                requests.checked_sub(unit_requests),
            ) {
                (Some(tokens), Some(requests)) => residue.push((*hour, *model, tokens, requests)),
                _ => negative = true,
            }
        }
        if negative || !unit_slots.is_empty() {
            counts.residue_negative += 1;
            body.unbuilt = true;
            counts.unbuilt_items += 1;
            continue;
        }
        built_members.insert(member);
        for (hour, model, tokens, requests) in residue {
            if tokens.conserved() == 0 && requests == 0 {
                continue;
            }
            counts.residue_tokens += tokens.conserved();
            body.add_grain(
                ClaudeGrainKey {
                    member: member.to_owned(),
                    hour,
                    model,
                    origin: ClaudeRequestUsageOrigin::Residue,
                },
                tokens,
                requests,
                None,
            );
        }
        // Parts: [counted, removed, held, immature], summed independently of
        // the body's own totals for the certificate.
        let mut parts = [ClaudeMoneyTotals::default(); 4];
        // Conflicts under one `R` key: the order's winner stays a unit.
        for loser in displaced {
            let UnitKey::Request(hash) = loser.key else {
                continue;
            };
            let kept = units
                .iter_mut()
                .find(|unit| unit.key == UnitKey::Request(hash));
            let loser = match kept {
                Some(kept)
                    if claude_response_conflict_order(
                        (&loser.tokens, 0, ""),
                        (&kept.tokens, 0, ""),
                    ) == std::cmp::Ordering::Less =>
                {
                    // The displaced response wins: it takes the kept one's
                    // place (and its request id for the row lookup).
                    let request_id = kept.request_id;
                    let winner = Unit {
                        request_id,
                        ..loser
                    };
                    std::mem::replace(kept, winner)
                }
                _ => loser,
            };
            counts.units_conflict_removed += 1;
            parts[1].add(loser.tokens.conserved(), 1, None);
            body.removed.add(loser.tokens.conserved(), 1, None);
        }
        for unit in units {
            let conserved = unit.tokens.conserved();
            if ledger.now_unix.saturating_sub(unit.clock) < MATURITY_SECONDS {
                counts.units_immature += 1;
                parts[3].add(conserved, 1, None);
                body.immature.add(conserved, 1, None);
                continue;
            }
            let verdict = match unit.key {
                UnitKey::Request(hash) if ledger.collisions.contains(&hash) => {
                    counts.collisions_held += 1;
                    ClaudeRequestVerdict::Undecided
                }
                UnitKey::Request(hash) => {
                    ledger
                        .holders
                        .classify(ledger.index, hash, own_key, family.root)
                }
                UnitKey::Message(hash) => {
                    counts.units_message += 1;
                    body.message_unknown |= ledger.holders.message_unknown;
                    ledger.holders.classify_message(ledger.index, hash, own_key)
                }
                UnitKey::Idless => {
                    counts.idless += 1;
                    ClaudeRequestVerdict::Owned
                }
            };
            match verdict {
                ClaudeRequestVerdict::Owned => counts.units_owned += 1,
                ClaudeRequestVerdict::TelemetryProven => counts.units_telemetry_proven += 1,
                ClaudeRequestVerdict::PolicyOwned => counts.units_policy_owned += 1,
                ClaudeRequestVerdict::Removed => counts.units_removed += 1,
                ClaudeRequestVerdict::Undecided => counts.units_undecided += 1,
                ClaudeRequestVerdict::TwoOwner => counts.units_two_owner += 1,
            }
            if !verdict.counted() {
                if verdict == ClaudeRequestVerdict::Removed {
                    parts[1].add(conserved, 1, None);
                    body.removed.add(conserved, 1, None);
                } else {
                    parts[2].add(conserved, 1, None);
                    body.held.add(conserved, 1, None);
                }
                continue;
            }
            counts.units_counted += 1;
            parts[0].add(conserved, 1, None);
            if family_retired {
                counts.possible_retired_copies += 1;
            }
            if verdict == ClaudeRequestVerdict::Owned && unit.clock < retirement_cutoff {
                counts.owned_after_retirement += 1;
            }
            let (origin, cost) = match unit.request_id.and_then(|id| rows.get(id)) {
                Some(row) => match row.cost_usd_micros {
                    Some(cost) => {
                        counts.units_matched += 1;
                        (ClaudeRequestUsageOrigin::TelemetryMatched, Some(cost))
                    }
                    None => {
                        counts.units_matched_unpriced += 1;
                        (ClaudeRequestUsageOrigin::TelemetryUnpriced, None)
                    }
                },
                None => (ClaudeRequestUsageOrigin::Transcript, None),
            };
            body.add_grain(
                ClaudeGrainKey {
                    member: member.to_owned(),
                    hour: unit.hour,
                    model: unit.model,
                    origin,
                },
                unit.tokens,
                1,
                cost,
            );
        }
        // Certificate: the four parts are disjoint by construction; their
        // union must be every unit of the item (count and tokens).
        let union = parts
            .iter()
            .fold((0_u64, 0_u64), |(tokens, requests), part| {
                (
                    tokens.saturating_add(part.tokens),
                    requests.saturating_add(part.requests),
                )
            });
        if union != (unit_totals.conserved(), unit_count) {
            body.certificate_ok = false;
        }
    }
    body.members_built = built_members.len();
    // Telemetry-only requests (side calls) of the root: no transcript of this
    // family holds them. (A copy in another family's transcript is removed
    // there, so the money is counted once, here.)
    for (request_id, row) in &rows {
        let hash = claude_request_hash(request_id);
        if ledger.holders.has_transcript_holder_in(hash, family.root)
            || family
                .items
                .iter()
                .any(|item| item.claude_usage_occurrences.contains_key(*request_id))
        {
            continue;
        }
        if ledger.holders.telemetry_holders(hash).len() > 1 {
            counts.side_calls_two_owner += 1;
            continue;
        }
        let Some(tokens) = ClaudeMoneyTokens::from_row(row) else {
            continue;
        };
        let Some(clock) = rfc3339_unix_seconds(&row.observed_at) else {
            continue;
        };
        if ledger.now_unix.saturating_sub(clock) < MATURITY_SECONDS {
            counts.side_calls_immature += 1;
            continue;
        }
        counts.side_calls += 1;
        if reported_live {
            // The live body already rebuilt from rows: this usage is in the
            // live buckets, so adding it again would double it.
            counts.side_calls_in_live_body += 1;
            continue;
        }
        if row.cost_usd_micros.is_none() {
            counts.side_calls_unpriced += 1;
        }
        body.add_grain(
            ClaudeGrainKey {
                member: family.root.to_owned(),
                hour: hour_of(clock),
                model: claude_model_hash(&row.model),
                origin: ClaudeRequestUsageOrigin::TelemetryReported,
            },
            tokens,
            1,
            row.cost_usd_micros,
        );
    }
    body
}

// ---------------------------------------------------------------- admission

static SHADOW_RESERVED: AtomicUsize = AtomicUsize::new(0);

/// Aggregate admission: held for the shadow's whole run, released on drop.
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

// ---------------------------------------------------------------- shadow

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeRequestMoneyShadowCounts {
    pub(crate) families: u64,
    pub(crate) families_equal: u64,
    pub(crate) families_differ_tokens: u64,
    pub(crate) families_differ_requests: u64,
    pub(crate) families_union_partial: u64,
    pub(crate) families_unbuilt: u64,
    pub(crate) families_coverage_complete: u64,
    pub(crate) certificate_mismatch: u64,
    pub(crate) units_counted: u64,
    pub(crate) units_owned: u64,
    pub(crate) units_telemetry_proven: u64,
    pub(crate) units_policy_owned: u64,
    pub(crate) units_removed: u64,
    pub(crate) units_undecided: u64,
    pub(crate) units_two_owner: u64,
    pub(crate) units_immature: u64,
    pub(crate) units_matched: u64,
    pub(crate) units_matched_unpriced: u64,
    pub(crate) units_message: u64,
    pub(crate) units_conflict_removed: u64,
    pub(crate) collisions_held: u64,
    pub(crate) owned_after_retirement: u64,
    pub(crate) possible_retired_copies: u64,
    /// Idless (`L`) units: counted by their own file (no key to share).
    pub(crate) idless: u64,
    pub(crate) side_calls: u64,
    pub(crate) side_calls_unpriced: u64,
    pub(crate) side_calls_immature: u64,
    pub(crate) side_calls_two_owner: u64,
    pub(crate) side_calls_in_live_body: u64,
    /// Live usage beyond the units (expected 0).
    pub(crate) residue_tokens: u64,
    pub(crate) rows_invalid: u64,
    pub(crate) rows_conflicting: u64,
    pub(crate) rows_reread_roots: u64,
    pub(crate) rows_reread_bytes: u64,
    pub(crate) rows_unavailable_roots: u64,
    /// The live load reported a fault, so its rows were reread per root.
    pub(crate) rows_live_distrusted: u64,
    pub(crate) unbuilt_items: u64,
    pub(crate) residue_negative: u64,
    pub(crate) tokens_old: u64,
    pub(crate) tokens_new: u64,
    pub(crate) tokens_removed: u64,
    pub(crate) tokens_held: u64,
    pub(crate) tokens_immature: u64,
    pub(crate) requests_old: u64,
    pub(crate) requests_new: u64,
    pub(crate) holders_compared: u64,
    pub(crate) admission_bytes: u64,
    pub(crate) refused_budget: u64,
    pub(crate) jsonl_rows: u64,
    pub(crate) jsonl_truncated: u64,
    pub(crate) jsonl_failed: u64,
    pub(crate) telemetry_retired_pressure: u64,
    /// Members not in the page whose census `u` was known / unknown
    /// (advisory, shadow only).
    pub(crate) absent_members_old_known: u64,
    pub(crate) absent_members_old_unknown: u64,
    pub(crate) elapsed_us: u64,
}

#[derive(Debug, Serialize)]
struct ShadowLine<'a> {
    counting: &'static str,
    census_complete: bool,
    counts: &'a ClaudeRequestMoneyShadowCounts,
    tail: &'a ClaudeTelemetryTailCounts,
    ledger: &'a claude_request_ledger::ClaudeLedgerStateCounts,
}

/// One JSONL row per family: what the B1 shadow pricer needs to recompute
/// `would_hold` with the server's own rule. Ids are hashed.
#[derive(Debug, Serialize)]
struct FamilyRow<'a> {
    v: u8,
    counting: &'static str,
    observed_unix: u64,
    family: String,
    category: ClaudeFamilyCategory,
    coverage_complete: bool,
    members_built: usize,
    members_total: usize,
    old: ClaudeMoneyTotals,
    new: ClaudeMoneyTotals,
    removed: ClaudeMoneyTotals,
    removed_change: i128,
    held: ClaudeMoneyTotals,
    immature: ClaudeMoneyTotals,
    by_origin: &'a BTreeMap<ClaudeRequestUsageOrigin, ClaudeMoneyTotals>,
    grains: usize,
    /// Census `u` of the members not in this page, and how many were unknown.
    absent_old: ClaudeMoneyTotals,
    absent_old_unknown: u64,
}

fn hashed_id(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"claude_request_money_shadow:v1\0");
    digest.update(value.as_bytes());
    format!("{:x}", digest.finalize())[..16].to_owned()
}

#[cfg(test)]
static SHADOW_ENABLED_FOR_TEST: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

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

/// The P1 shadow of one authoritative Claude page. Reads the page's final
/// items and the strict rows the live path already loaded; mutates only the
/// census's `otel:` records (tail state and hashes). Never fails the page.
pub(crate) fn shadow_page(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &mut ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
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
        census_complete,
        now_unix(),
    );
}

pub(crate) fn shadow_page_at(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    index: &mut ScanIndex,
    api_report: &ClaudeLocalOtelLoadReport,
    census_complete: bool,
    now: u64,
) -> ClaudeRequestMoneyShadowCounts {
    let started = std::time::Instant::now();
    let mut counts = ClaudeRequestMoneyShadowCounts::default();
    let tail_budget = ClaudeTelemetryTailBudget::default();
    // Admission before any allocation: units, rows, live rows, holders,
    // families, the reread budget and the tail reader's fixed memory.
    let units = snapshots
        .iter()
        .map(|item| item.claude_usage_occurrences.len() + item.claude_request_residue.len())
        .fold(0_usize, usize::saturating_add);
    let roots = snapshots
        .iter()
        .map(claude_snapshot_family_root_ref)
        .collect::<BTreeSet<_>>();
    let rows = roots
        .iter()
        .filter_map(|root| api_report.evidence.get(*root))
        .map(Vec::len)
        .fold(0_usize, usize::saturating_add);
    let bucket_rows = snapshots
        .iter()
        .flat_map(|item| &item.usage_buckets)
        .map(|bucket| bucket.model_usage.len())
        .fold(0_usize, usize::saturating_add);
    let reread_rows = REREAD_MAX_ROOTS * (REREAD_MAX_FILE_BYTES as usize / 256);
    let admission = units
        .saturating_add(rows)
        .saturating_add(reread_rows)
        .saturating_mul(UNIT_BYTES.max(ROW_BYTES))
        .saturating_add(bucket_rows.saturating_mul(BUCKET_ROW_BYTES))
        .saturating_add(claude_request_ledger::holders_bound(
            units.saturating_add(rows).saturating_add(reread_rows),
        ))
        .saturating_add(roots.len().saturating_mul(FAMILY_BYTES))
        .saturating_add(index.files.len().saturating_mul(64))
        .saturating_add(tail_memory_bound(&tail_budget));
    counts.admission_bytes = admission as u64;
    let Some(_reservation) = ShadowReservation::admit(admission) else {
        counts.refused_budget = 1;
        counts.elapsed_us = started.elapsed().as_micros() as u64;
        emit_line(&ShadowLine {
            counting: CLAUDE_REQUEST_COUNTING,
            census_complete,
            counts: &counts,
            tail: &ClaudeTelemetryTailCounts::default(),
            ledger: &claude_request_ledger::ledger_state_counts(&index.claude_request_census),
        });
        return counts;
    };
    let tail = ClaudeTelemetryTail::advance(
        support_dir,
        &mut index.claude_request_census,
        now,
        &tail_budget,
    );
    counts.telemetry_retired_pressure =
        claude_request_ledger::retire_telemetry_under_pressure(&mut index.claude_request_census);
    let index: &ScanIndex = index;

    // Members of the page's families: census keys and how many there are.
    let mut member_keys = BTreeMap::<(String, String), Vec<String>>::new();
    let mut members_total = BTreeMap::<String, BTreeSet<String>>::new();
    for key in index.files.keys() {
        let Some((root, member)) = claude_index_path_family_member(Path::new(key)) else {
            continue;
        };
        if !roots.contains(root.as_str()) || index.confirmed_empty_files.contains(key) {
            continue;
        }
        members_total
            .entry(root.clone())
            .or_default()
            .insert(member.clone());
        member_keys
            .entry((root, member))
            .or_default()
            .push(key.clone());
    }

    // Rows: the live path's, else one bounded reread. The live health is
    // page-wide, so any fault other than a missing file distrusts every
    // root's live rows (a partial read must never look complete).
    let live = &api_report.health;
    let live_trusted = live.malformed_lines == 0
        && live.unreadable_lines == 0
        && live.oversized_files == 0
        && live.invalid_session_rows == 0
        && live.missing_request_ids == 0
        && live.conflicting_request_ids.is_empty();
    counts.rows_live_distrusted = u64::from(!live_trusted);
    let mut reread = BTreeMap::<String, Vec<ClaudeLocalOtelEvidence>>::new();
    let mut unavailable = BTreeSet::<&str>::new();
    let mut reread_left = REREAD_MAX_ROOTS;
    for &root in &roots {
        if live_trusted && api_report.evidence.contains_key(root) {
            continue;
        }
        match crate::claude_local_otel::claude_api_sidecar_len(support_dir, root) {
            None => {}
            Some(len) if len <= REREAD_MAX_FILE_BYTES && reread_left > 0 => {
                reread_left -= 1;
                let report = crate::claude_local_otel::load_claude_api_request_evidence_report(
                    support_dir,
                    [root.to_owned()],
                );
                counts.rows_reread_roots += 1;
                counts.rows_reread_bytes += len;
                if report.health.is_complete() {
                    reread.insert(
                        root.to_owned(),
                        report.evidence.into_values().flatten().collect(),
                    );
                } else {
                    unavailable.insert(root);
                }
            }
            Some(_) => {
                unavailable.insert(root);
            }
        }
    }
    counts.rows_unavailable_roots = unavailable.len() as u64;
    let rows_of = |root: &str| {
        (!unavailable.contains(root)).then(|| {
            api_report
                .evidence
                .get(root)
                .filter(|_| live_trusted)
                .or_else(|| reread.get(root))
                .map_or(&[][..], Vec::as_slice)
        })
    };

    // Page hashes (units and row ids), collisions by full id.
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
    for &root in &roots {
        for row in rows_of(root).unwrap_or_default() {
            let hash = claude_request_hash(&row.request_id);
            match first_id.get(&hash) {
                Some(first) if *first != row.request_id.as_str() => {
                    collisions.insert(hash);
                }
                Some(_) => {}
                None => {
                    first_id.insert(hash, row.request_id.as_str());
                }
            }
        }
    }
    let page_hashes = first_id.keys().copied().collect::<Vec<_>>();
    drop(first_id);
    let mut page_message_hashes = snapshots
        .iter()
        .flat_map(|item| &item.claude_request_residue)
        .filter_map(|residue| match residue.kind {
            ClaudeResidueKind::Message(hash) => Some(hash),
            _ => None,
        })
        .collect::<Vec<_>>();
    page_message_hashes.sort_unstable();
    page_message_hashes.dedup();
    let holders = claude_request_ledger::scan_holders(
        &index.claude_request_census,
        &page_hashes,
        &page_message_hashes,
    );
    counts.holders_compared = holders.compared;
    let retired_roots =
        claude_request_ledger::roots_with_retired_records(&index.claude_request_census);
    let view = ClaudeLedgerView {
        index,
        holders: &holders,
        collisions: &collisions,
        retired_roots: &retired_roots,
        now_unix: now,
    };

    let mut family_rows = Vec::new();
    for &root in &roots {
        let items = snapshots
            .iter()
            .filter(|item| claude_snapshot_family_root_ref(item) == root)
            .collect::<Vec<_>>();
        let keys = items
            .iter()
            .map(|item| {
                let key = member_keys
                    .get(&(root.to_owned(), item.source_session_id.clone()))
                    .filter(|keys| keys.len() == 1)
                    .map(|keys| keys[0].clone());
                (item.source_session_id.as_str(), key)
            })
            .collect();
        let total = members_total
            .get(root)
            .map_or(0, BTreeSet::len)
            .max(items.len());
        // Members not in this page: their census `u` (what the old path last
        // built for that file), advisory only. Missing, malformed or stale
        // (not current for the entry) is unknown, never zero.
        let mut absent_old = ClaudeMoneyTotals::default();
        let mut absent_old_known = 0_u64;
        let mut absent_old_unknown = 0_u64;
        for member in members_total.get(root).into_iter().flatten() {
            if items
                .iter()
                .any(|item| item.source_session_id == member.as_str())
            {
                continue;
            }
            let usage = member_keys
                .get(&(root.to_owned(), member.clone()))
                .filter(|keys| keys.len() == 1)
                .and_then(|keys| {
                    let key = keys[0].as_str();
                    let entry = index.files.get(key)?;
                    let record = index.claude_request_census.get(key)?;
                    record
                        .current_for(&entry.source_file_fingerprint)
                        .then(|| record.old_path_usage())
                        .flatten()
                });
            match usage {
                Some((requests, tokens)) => {
                    absent_old_known += 1;
                    absent_old.tokens = absent_old.tokens.saturating_add(tokens);
                    absent_old.requests = absent_old.requests.saturating_add(requests);
                }
                None => absent_old_unknown += 1,
            }
        }
        counts.absent_members_old_known += absent_old_known;
        counts.absent_members_old_unknown += absent_old_unknown;
        let family = ClaudeFamilyInput {
            root,
            items,
            member_keys: keys,
            members_total: total,
            rows: rows_of(root),
        };
        let body = build_claude_request_body(&family, &view, &mut counts);
        let category = body.category();
        let complete = body.coverage_complete(census_complete);
        counts.families += 1;
        match category {
            ClaudeFamilyCategory::Equal => counts.families_equal += 1,
            ClaudeFamilyCategory::DifferTokens => counts.families_differ_tokens += 1,
            ClaudeFamilyCategory::DifferRequests => counts.families_differ_requests += 1,
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
        counts.requests_old += body.old.requests;
        counts.requests_new += body.new.requests;
        let row = FamilyRow {
            v: 1,
            counting: CLAUDE_REQUEST_COUNTING,
            observed_unix: now,
            family: hashed_id(root),
            category,
            coverage_complete: complete,
            members_built: body.members_built,
            members_total: body.members_total,
            old: body.old,
            new: body.new,
            removed: body.removed,
            removed_change: i128::from(body.new.tokens) - i128::from(body.old.tokens),
            held: body.held,
            immature: body.immature,
            by_origin: &body.by_origin,
            grains: body.grains.len(),
            absent_old,
            absent_old_unknown,
        };
        if let Ok(json) = serde_json::to_string(&row) {
            family_rows.push(json);
        }
    }
    append_jsonl(support_dir, now, &family_rows, &mut counts);
    counts.elapsed_us = started.elapsed().as_micros() as u64;
    emit_line(&ShadowLine {
        counting: CLAUDE_REQUEST_COUNTING,
        census_complete,
        counts: &counts,
        tail: &tail,
        ledger: &claude_request_ledger::ledger_state_counts(&index.claude_request_census),
    });
    counts
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

/// Append the page's family rows to today's capped file and drop own files
/// older than the retention window. Failures are counted, never raised.
fn append_jsonl(
    support_dir: &Path,
    now: u64,
    rows: &[String],
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    if rows.is_empty() {
        return;
    }
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
    let mut buffer = Vec::new();
    for row in rows {
        let bytes = row.len() as u64 + 1;
        if size + bytes > JSONL_DAY_CAP_BYTES {
            counts.jsonl_truncated += 1;
            continue;
        }
        size += bytes;
        buffer.extend_from_slice(row.as_bytes());
        buffer.push(b'\n');
        counts.jsonl_rows += 1;
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
    let Some(oldest) = day_stamp(now.saturating_sub((JSONL_RETENTION_DAYS * 86_400) as u64)) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.take(JSONL_MAX_DIR_ENTRIES).flatten() {
        let name = entry.file_name();
        let Some(day) = name
            .to_str()
            .and_then(|name| name.strip_prefix(JSONL_PREFIX))
            .and_then(|rest| rest.strip_suffix(".jsonl"))
        else {
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
