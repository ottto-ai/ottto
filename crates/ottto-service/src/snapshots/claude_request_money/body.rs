//! One family's shadow body: its units, their verdicts and the B1 grain rows
//! that price the difference between the live body and the
//! `claude_request_counting:v1` body.
//!
//! The live body is read as it is (every live bucket row of every member
//! item). Each unit is the response (or the reported row) the live path put
//! in exactly one live row: the capture names the row of each finalizer
//! response, and a reported (`session_exclusive_reported_usage:v1`) item's
//! rows are re-keyed exactly as the live rebuild keys them. A unit that the
//! new body does not count leaves its live row as a `removed` grain slice of
//! its own reason; a unit the new body counts where the live body did not
//! (a side call, a message-only or idless response the reported rebuild
//! dropped) is an added slice; a counted unit matched to a costed API row
//! is an `own_cost` slice (same tokens, the row's own money). Whatever a
//! live row holds beyond its units is `unexplained`. So every grain slice is
//! explained by its category except `unexplained`, which is exactly the
//! money the switch would lose without a reason.

use super::super::claude_request_census::claude_request_hash;
use super::super::claude_request_ledger::{
    ClaudeClassifyContext, ClaudeCountedBy, ClaudeRemovedBy, ClaudeRequestVerdict,
    ClaudeUndecidedBy,
};
use super::super::{
    activity_bucket_from_timestamp, build_row_identity, insert_selector_raw, SelectorCapture,
    SnapshotItem, SnapshotModelUsage, CLAUDE_EFFORT_TIERS,
};
use super::capture::{CapturedKind, CapturedRow, ClaudeResponseCapture};
use super::rows::{ClaudeApiRow, ClaudeRootRows};
use super::{
    claude_model_hash, claude_response_conflict_order, claude_response_fingerprint,
    parse_usd_micros, ClaudeMoneyTokens, ClaudeMoneyTotals, ClaudeRequestMoneyShadowCounts,
    MATURITY_SECONDS,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const REPORTED_CONTRACT: &str = "session_exclusive_reported_usage:v1";

/// `request_usage_origin` of a grain (B1); None is a transcript grain. The
/// variant names are the reader's wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub(crate) enum ClaudeRequestUsageOrigin {
    /// A transcript unit with its API row's own `cost_usd`.
    TelemetryMatched,
    /// A telemetry-only request (side call) with its row's own cost.
    TelemetryReported,
    /// A side call whose row carries no cost.
    TelemetryUnpriced,
}

/// Why a grain slice differs (B1's `category`). Every value but
/// `Unexplained` is an explained difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClaudeGrainCategory {
    /// A copy: another file or root owns the request.
    CopiesRemoved,
    /// A side call moved between members of its family.
    Transfer,
    /// Two telemetry roots claim it and another won.
    TwoOwner,
    /// Two responses under one request id: the loser.
    ConflictRule,
    /// Undecided: the new body would hold it (coverage incomplete).
    Held,
    /// Younger than the maturity window: deferred, not dropped.
    Immature,
    /// Same tokens, the matched API row's own money.
    OwnCost,
    /// A telemetry-only request the live body did not carry.
    SideCallAdded,
    /// A message-only response the live (reported) body did not carry.
    MessageOnly,
    /// An idless response the live (reported) body did not carry.
    Idless,
    /// A request the live (reported) body excluded as a legacy copy that the
    /// ledger counts here.
    LegacyExclusion,
    /// Live usage no unit accounts for.
    Unexplained,
}

/// One live bucket row's identity: hour start, model and pricing selectors
/// (the reduced selector context plus the row's billing fields).
pub(crate) type ClaudeLiveKey = (String, String, BTreeMap<String, String>);

fn live_key_of_row(bucket_start: &str, row: &SnapshotModelUsage) -> ClaudeLiveKey {
    let mut selector = row.selector_context.clone();
    for (name, value) in [
        ("reasoning_effort", &row.reasoning_effort),
        ("auth_mode", &row.auth_mode),
        ("billing_channel", &row.billing_channel),
        ("billing_provider", &row.billing_provider),
        ("gateway_provider", &row.gateway_provider),
        ("model_provider", &row.model_provider),
        ("subscription_product", &row.subscription_product),
    ] {
        if let Some(value) = value {
            selector.insert(name.to_owned(), value.clone());
        }
    }
    (bucket_start.to_owned(), row.model.clone(), selector)
}

fn live_key_of_capture(row: &CapturedRow) -> ClaudeLiveKey {
    (
        row.bucket_start.clone(),
        row.model.clone(),
        row.selector.clone(),
    )
}

/// The live reported rebuild's key for one API row, with the transcript
/// occurrence it matched (None for a side call): exactly its selector,
/// speed, effort, model and clock rule.
pub(crate) fn reported_live_key(
    row: &ClaudeApiRow<'_>,
    occurrence: Option<&super::super::ClaudeTranscriptUsageOccurrence>,
) -> Option<ClaudeLiveKey> {
    let mut selector = occurrence
        .map(|occurrence| SelectorCapture::clone(&occurrence.selector))
        .unwrap_or_default();
    if !row.speed.trim().is_empty() {
        insert_selector_raw(
            &mut selector,
            "speed_mode",
            "claude_code.api_request.speed",
            &serde_json::Value::String(row.speed.to_string()),
        );
    }
    let reported_effort = CLAUDE_EFFORT_TIERS
        .contains(&row.effort)
        .then(|| row.effort.to_string());
    let effort = occurrence
        .and_then(|occurrence| occurrence.reasoning_effort.clone())
        .or(reported_effort);
    let (model, timestamp) = match occurrence {
        Some(occurrence) => (
            occurrence
                .model
                .clone()
                .unwrap_or_else(|| row.model.to_string()),
            match &occurrence.timestamp {
                Some(timestamp) => timestamp.clone(),
                None => row.observed_at()?,
            },
        ),
        None => (row.model.to_string(), row.observed_at()?),
    };
    let (bucket_start, _) = activity_bucket_from_timestamp(&timestamp)?;
    let (row_key, mut context, _) = build_row_identity(&model, &selector, effort.as_deref());
    for (name, value) in row_key.billing_fields() {
        if let Some(value) = value {
            context.insert(name.to_owned(), value.to_owned());
        }
    }
    Some((bucket_start, model, context))
}

/// One side of a grain slice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeGrainSide {
    pub(crate) tokens: ClaudeMoneyTokens,
    pub(crate) requests: u64,
    pub(crate) cost_micros: u64,
    /// Contributions without a cost (the side's cost is then unknown).
    pub(crate) unpriced: u64,
    pub(crate) contributions: u64,
}

impl ClaudeGrainSide {
    pub(super) fn add(&mut self, tokens: &ClaudeMoneyTokens, requests: u64, cost: Option<u64>) {
        self.tokens.add(tokens);
        self.requests = self.requests.saturating_add(requests);
        self.contributions += 1;
        match cost {
            Some(cost) => self.cost_micros = self.cost_micros.saturating_add(cost),
            None => self.unpriced += 1,
        }
    }

    /// The side's own money, when every contribution carries one.
    pub(crate) fn cost(&self) -> Option<u64> {
        (self.contributions > 0 && self.unpriced == 0).then_some(self.cost_micros)
    }
}

/// One grain slice's identity (a B1 `grain` row).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeGrainKey {
    pub(crate) member: String,
    /// The entity that owns the slice's usage ("" when unknown).
    pub(crate) owner: String,
    pub(crate) live: ClaudeLiveKey,
    pub(crate) origin: Option<ClaudeRequestUsageOrigin>,
    pub(crate) category: ClaudeGrainCategory,
}

/// Everything one family's shadow body says.
#[derive(Debug, Default)]
pub(crate) struct ClaudeRequestBody {
    /// Differing slices only: (old, new).
    pub(crate) grains: BTreeMap<ClaudeGrainKey, (ClaudeGrainSide, ClaudeGrainSide)>,
    pub(crate) old: ClaudeMoneyTotals,
    pub(crate) new: ClaudeMoneyTotals,
    /// Units the new body declares removed (copies, two-owner losers,
    /// conflict losers, side calls moved out), whether or not the live body
    /// counted them: the cumulative removal B2's rule compares.
    pub(crate) removed: ClaudeMoneyTotals,
    pub(crate) held: ClaudeMoneyTotals,
    pub(crate) immature: ClaudeMoneyTotals,
    pub(crate) unexplained: ClaudeMoneyTotals,
    pub(crate) units: ClaudeMoneyTotals,
    pub(crate) members_built: usize,
    pub(crate) members_total: usize,
    pub(crate) unbuilt: bool,
    pub(crate) certificate_ok: bool,
    pub(crate) rows_complete: bool,
    /// Held reasons seen in the family.
    pub(crate) held_reasons: BTreeSet<ClaudeUndecidedBy>,
}

/// Family category in the JSONL and the counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClaudeFamilyCategory {
    Equal,
    DifferTokens,
    DifferRequests,
    /// Same totals, but money moved between grains (models, hours, origins).
    DifferGrains,
    /// A member of the family is not in this page (Sol N5: counted, not
    /// rehydrated).
    UnionPartial,
    /// A member could not be built.
    Unbuilt,
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
        } else if !self.grains.is_empty() {
            ClaudeFamilyCategory::DifferGrains
        } else {
            ClaudeFamilyCategory::Equal
        }
    }

    /// The union is whole, every member was built, the certificate holds,
    /// the root's rows were read and nothing is held on unknown debt.
    pub(crate) fn coverage_complete(&self, census_complete: bool) -> bool {
        census_complete
            && self.rows_complete
            && self.certificate_ok
            && self.held.requests == 0
            && !matches!(
                self.category(),
                ClaudeFamilyCategory::UnionPartial | ClaudeFamilyCategory::Unbuilt
            )
    }

    fn slice(
        &mut self,
        key: ClaudeGrainKey,
        old: Option<(&ClaudeMoneyTokens, u64, Option<u64>)>,
        new: Option<(&ClaudeMoneyTokens, u64, Option<u64>)>,
    ) {
        let entry = self.grains.entry(key).or_default();
        if let Some((tokens, requests, cost)) = old {
            entry.0.add(tokens, requests, cost);
        }
        if let Some((tokens, requests, cost)) = new {
            entry.1.add(tokens, requests, cost);
        }
    }
}

/// One family of the page, with what the ledger and the live path know.
pub(crate) struct ClaudeFamilyInput<'a> {
    pub(crate) root: &'a str,
    pub(crate) items: Vec<&'a SnapshotItem>,
    /// Census key of each page member, None for a member with no single key.
    pub(crate) member_keys: BTreeMap<&'a str, Option<String>>,
    /// Indexed members of the family (page or not).
    pub(crate) indexed_members: &'a BTreeSet<String>,
    pub(crate) members_total: usize,
    /// The root's API rows, None when they could not be read completely.
    pub(crate) rows: Option<&'a ClaudeRootRows>,
    /// The root's trace (request hash -> trace-named member), when read.
    pub(crate) trace: Option<&'a BTreeMap<u64, String>>,
    /// Each page member's capture (None: none, or refused).
    pub(crate) captures: BTreeMap<&'a str, ClaudeResponseCapture>,
}

/// A unit before its verdict.
struct Unit {
    kind: UnitKind,
    tokens: ClaudeMoneyTokens,
    requests: u64,
    clock: u64,
    message: u64,
    fingerprint: u64,
    /// The live row holding it (None: the live body does not carry it).
    live: Option<ClaudeLiveKey>,
    /// The finalizer's row for it: where the new body keys a transcript
    /// grain (equal to `live` unless the live body is a reported rebuild).
    place: Option<ClaudeLiveKey>,
    /// It won a conflict the live (reported) body resolved the other way.
    conflict_winner: bool,
    /// The live row's own cost of this unit (reported rows: a witness).
    live_cost: Option<u64>,
    /// The live body is the reported rebuild and carries this unit with
    /// its row's money already.
    reported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitKind {
    Request(u64),
    Message(u64),
    Idless,
}

/// Build the family body. `ctx` classifies; `now` is the maturity clock.
pub(crate) fn build_claude_request_body(
    family: &ClaudeFamilyInput<'_>,
    ctx: &ClaudeClassifyContext<'_, '_>,
    collisions: &BTreeSet<u64>,
    now: u64,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) -> ClaudeRequestBody {
    let mut body = ClaudeRequestBody {
        members_total: family.members_total,
        rows_complete: family.rows.is_some(),
        certificate_ok: true,
        ..ClaudeRequestBody::default()
    };
    let empty_rows = ClaudeRootRows::default();
    let rows = family.rows.unwrap_or(&empty_rows);
    // Side-call rows the reported live bodies already carry: hash -> member.
    let mut reported_side_calls = BTreeMap::<u64, (usize, ClaudeLiveKey)>::new();
    let mut family_hashes = BTreeSet::<u64>::new();
    let mut position = 0_usize;
    for item in &family.items {
        for request_id in item.claude_usage_occurrences.keys() {
            if position % 1024 == 1023 && ctx.late() {
                body.unbuilt = true;
                return body;
            }
            position += 1;
            family_hashes.insert(claude_request_hash(request_id));
        }
    }
    for (member_index, item) in family.items.iter().enumerate() {
        // Past the page deadline the page is refused: stop building.
        if ctx.late() {
            body.unbuilt = true;
            return body;
        }
        let member = item.source_session_id.as_str();
        let mut old_rows = BTreeMap::<ClaudeLiveKey, (ClaudeMoneyTokens, u64, Option<u64>)>::new();
        for bucket in &item.usage_buckets {
            for row in &bucket.model_usage {
                position += 1;
                if position % 1024 == 0 && ctx.late() {
                    body.unbuilt = true;
                    return body;
                }
                let tokens = ClaudeMoneyTokens::from_model_usage(row);
                let cost = row.cost_usd.as_deref().and_then(parse_usd_micros);
                body.old.add(tokens.conserved(), row.request_count, cost);
                let slot = old_rows
                    .entry(live_key_of_row(&bucket.bucket_start, row))
                    .or_insert((ClaudeMoneyTokens::default(), 0, Some(0)));
                slot.0.add(&tokens);
                slot.1 = slot.1.saturating_add(row.request_count);
                slot.2 = slot
                    .2
                    .zip(cost)
                    .map(|(left, right)| left.saturating_add(right));
            }
        }
        let Some(Some(own_key)) = family.member_keys.get(member) else {
            body.unbuilt = true;
            counts.unbuilt_no_key += 1;
            continue;
        };
        let Some(capture) = family.captures.get(member) else {
            body.unbuilt = true;
            counts.unbuilt_no_capture += 1;
            continue;
        };
        if capture.is_refused() {
            body.unbuilt = true;
            counts.unbuilt_capture_refused += 1;
            continue;
        }
        let reported = item.usage_accounting_contract.as_deref() == Some(REPORTED_CONTRACT);
        if reported && family.trace.is_none() {
            // The reported rebuild assigned rows by the trace: without it the
            // live rows of this member cannot be named.
            body.unbuilt = true;
            counts.unbuilt_no_trace += 1;
            continue;
        }
        let trace_owner = |hash: u64| {
            family
                .trace
                .and_then(|trace| trace.get(&hash))
                .map(String::as_str)
                .unwrap_or(family.root)
        };
        // Units: the kept request-id responses, then the captured ones.
        let mut units = Vec::with_capacity(item.claude_usage_occurrences.len());
        let mut placement_missing = false;
        for (position, (request_id, occurrence)) in item.claude_usage_occurrences.iter().enumerate()
        {
            if position % 1024 == 1023 && ctx.late() {
                body.unbuilt = true;
                return body;
            }
            // Zero usage: the live path adds no row and there is no money.
            if occurrence.usage.is_zero() {
                continue;
            }
            let hash = claude_request_hash(request_id);
            let tokens = ClaudeMoneyTokens::from_usage(&occurrence.usage);
            let clock = occurrence
                .timestamp
                .as_deref()
                .map(crate::claude_local_otel::telemetry_tail::event_unix)
                .unwrap_or(0);
            let message = capture.message(occurrence.sequence).unwrap_or(0);
            let model = occurrence.model.as_deref().map(claude_model_hash);
            let place = capture
                .placement(occurrence.sequence)
                .map(live_key_of_capture);
            let (live, live_cost) = if reported {
                match rows.get(hash).filter(|_| trace_owner(hash) == member) {
                    Some(row) => match reported_live_key(&row, Some(occurrence)) {
                        Some(key) => (Some(key), row.cost_micros),
                        None => {
                            placement_missing = true;
                            (None, None)
                        }
                    },
                    None => (None, None),
                }
            } else {
                (place.clone(), None)
            };
            if place.is_none() {
                placement_missing = true;
            }
            units.push(Unit {
                kind: UnitKind::Request(hash),
                tokens,
                requests: occurrence.usage.request_count,
                clock,
                message,
                fingerprint: claude_response_fingerprint(&tokens, model, clock, message),
                live,
                place,
                conflict_winner: false,
                live_cost,
                reported,
            });
        }
        let mut displaced = Vec::new();
        for (position, captured) in capture.units().iter().enumerate() {
            if position % 1024 == 1023 && ctx.late() {
                body.unbuilt = true;
                return body;
            }
            if captured.tokens.conserved() == 0 && captured.tokens.reasoning == 0 {
                continue;
            }
            let place = capture
                .placement(captured.sequence)
                .map(live_key_of_capture);
            // A reported rebuild carries only API rows: never these.
            let live = if reported { None } else { place.clone() };
            if place.is_none() {
                placement_missing = true;
            }
            let clock = captured.clock.unwrap_or(0);
            let message = capture.message(captured.sequence).unwrap_or(0);
            let unit = Unit {
                kind: match captured.kind {
                    CapturedKind::Message(hash) => UnitKind::Message(hash),
                    CapturedKind::Idless => UnitKind::Idless,
                    CapturedKind::Displaced(hash) => UnitKind::Request(hash),
                },
                tokens: captured.tokens,
                requests: captured.requests,
                clock,
                message,
                fingerprint: claude_response_fingerprint(
                    &captured.tokens,
                    captured.model,
                    clock,
                    message,
                ),
                live,
                place,
                conflict_winner: false,
                live_cost: None,
                reported,
            };
            match captured.kind {
                CapturedKind::Displaced(_) => displaced.push(unit),
                _ => units.push(unit),
            }
        }
        if placement_missing || units.iter().chain(&displaced).any(|unit| unit.clock == 0) {
            body.unbuilt = true;
            counts.unbuilt_placement += 1;
            continue;
        }
        // A reported item also carries its trace-assigned rows that match no
        // response of its own: side calls (classified with the family), or
        // copies of a request another page member holds as a transcript
        // unit (the live body counts both; the new one the transcript).
        let mut accounted = BTreeMap::<ClaudeLiveKey, (ClaudeMoneyTokens, u64)>::new();
        let mut row_copies = Vec::new();
        if reported {
            let own = item
                .claude_usage_occurrences
                .keys()
                .map(|request_id| claude_request_hash(request_id))
                .collect::<BTreeSet<_>>();
            for (position, row) in rows.iter().enumerate() {
                if position % 1024 == 1023 && ctx.late() {
                    body.unbuilt = true;
                    return body;
                }
                if trace_owner(row.request_hash) != member || own.contains(&row.request_hash) {
                    continue;
                }
                let Some(key) = reported_live_key(&row, None) else {
                    placement_missing = true;
                    continue;
                };
                let slot = accounted.entry(key.clone()).or_default();
                slot.0.add(&row.tokens);
                slot.1 += 1;
                if family_hashes.contains(&row.request_hash) {
                    row_copies.push((key, row));
                } else {
                    reported_side_calls.insert(row.request_hash, (member_index, key));
                }
            }
        }
        if placement_missing {
            body.unbuilt = true;
            counts.unbuilt_placement += 1;
            continue;
        }
        // Conflicts under one `R` key: the order's winner stays a unit; the
        // live body (non-reported) carries both. Units by request hash, once.
        let position = units
            .iter()
            .enumerate()
            .filter_map(|(position, unit)| match unit.kind {
                UnitKind::Request(hash) => Some((hash, position)),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        let mut losers = Vec::new();
        for loser in displaced {
            let UnitKind::Request(hash) = loser.kind else {
                continue;
            };
            let kept = position.get(&hash).map(|position| &mut units[*position]);
            let loser = match kept {
                Some(kept)
                    if claude_response_conflict_order(
                        (&loser.tokens, loser.message, loser.fingerprint),
                        (&kept.tokens, kept.message, kept.fingerprint),
                    ) == std::cmp::Ordering::Less =>
                {
                    // The displaced response wins. In a reported body the
                    // live row matched the kept one; the winner is not in it.
                    let winner = Unit {
                        live: if kept.reported {
                            None
                        } else {
                            loser.live.clone()
                        },
                        conflict_winner: kept.reported,
                        ..loser
                    };
                    std::mem::replace(kept, winner)
                }
                _ => loser,
            };
            counts.units_conflict_removed += 1;
            losers.push(loser);
        }
        for unit in units.iter().chain(&losers) {
            if let Some(live) = &unit.live {
                let slot = accounted.entry(live.clone()).or_default();
                slot.0.add(&unit.tokens);
                slot.1 = slot.1.saturating_add(unit.requests);
            }
        }
        // Residue: live rows minus every unit placed there.
        let mut unexplained = Vec::new();
        let mut negative = false;
        for (key, (tokens, requests, _)) in &old_rows {
            let (unit_tokens, unit_requests) = accounted.remove(key).unwrap_or_default();
            match (
                tokens.checked_sub(&unit_tokens),
                requests.checked_sub(unit_requests),
            ) {
                (Some(rest), Some(rest_requests)) => {
                    if rest.conserved() > 0 || rest.reasoning > 0 || rest_requests > 0 {
                        unexplained.push((key.clone(), rest, rest_requests));
                    }
                }
                _ => negative = true,
            }
        }
        if negative || !accounted.is_empty() {
            counts.unbuilt_residue_negative += 1;
            body.unbuilt = true;
            continue;
        }
        body.members_built += 1;
        for (key, rest, requests) in unexplained {
            counts.unexplained_tokens += rest.conserved();
            body.unexplained.add(rest.conserved(), requests, None);
            body.slice(
                ClaudeGrainKey {
                    member: member.to_owned(),
                    owner: member.to_owned(),
                    live: key,
                    origin: None,
                    category: ClaudeGrainCategory::Unexplained,
                },
                Some((&rest, requests, None)),
                None,
            );
        }
        // Parts [counted, removed, held, immature] for the certificate.
        let mut parts = [ClaudeMoneyTotals::default(); 4];
        let mut unit_totals = ClaudeMoneyTotals::default();
        for (key, row) in row_copies {
            counts.reported_row_copies += 1;
            body.removed.add(row.tokens.conserved(), 1, None);
            body.slice(
                ClaudeGrainKey {
                    member: member.to_owned(),
                    owner: String::new(),
                    live: key,
                    origin: Some(if row.cost_micros.is_some() {
                        ClaudeRequestUsageOrigin::TelemetryReported
                    } else {
                        ClaudeRequestUsageOrigin::TelemetryUnpriced
                    }),
                    category: ClaudeGrainCategory::CopiesRemoved,
                },
                Some((&row.tokens, 1, row.cost_micros)),
                None,
            );
        }
        for loser in &losers {
            let conserved = loser.tokens.conserved();
            unit_totals.add(conserved, loser.requests, None);
            parts[1].add(conserved, loser.requests, None);
            body.removed.add(conserved, loser.requests, None);
            if let Some(live) = &loser.live {
                body.slice(
                    ClaudeGrainKey {
                        member: member.to_owned(),
                        owner: member.to_owned(),
                        live: live.clone(),
                        origin: None,
                        category: ClaudeGrainCategory::ConflictRule,
                    },
                    Some((&loser.tokens, loser.requests, loser.live_cost)),
                    None,
                );
            }
        }
        for (position, unit) in units.iter().enumerate() {
            if position % 1024 == 1023 && ctx.late() {
                body.unbuilt = true;
                return body;
            }
            let conserved = unit.tokens.conserved();
            unit_totals.add(conserved, unit.requests, None);
            let verdict = if now.saturating_sub(unit.clock) < MATURITY_SECONDS {
                None
            } else {
                Some(match unit.kind {
                    UnitKind::Request(hash) if collisions.contains(&hash) => {
                        ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::Collision)
                    }
                    UnitKind::Request(hash) => {
                        ctx.classify_request(hash, unit.clock, own_key, family.root)
                    }
                    UnitKind::Message(hash) => {
                        counts.units_message += 1;
                        ctx.classify_message(hash, own_key)
                    }
                    UnitKind::Idless => {
                        counts.units_idless += 1;
                        ClaudeRequestVerdict::Counted(ClaudeCountedBy::Idless)
                    }
                })
            };
            let removed_category = |reason| match reason {
                ClaudeRemovedBy::Copy => ClaudeGrainCategory::CopiesRemoved,
                ClaudeRemovedBy::TwoOwnerLoser => ClaudeGrainCategory::TwoOwner,
            };
            let (part, category) = match verdict {
                None => {
                    counts.units_immature += 1;
                    body.immature.add(conserved, unit.requests, None);
                    (3, Some(ClaudeGrainCategory::Immature))
                }
                Some(ClaudeRequestVerdict::Undecided(reason)) => {
                    counts.note_undecided(reason);
                    body.held_reasons.insert(reason);
                    body.held.add(conserved, unit.requests, None);
                    (2, Some(ClaudeGrainCategory::Held))
                }
                Some(ClaudeRequestVerdict::Removed(reason)) => {
                    counts.units_removed += 1;
                    if reason == ClaudeRemovedBy::TwoOwnerLoser {
                        counts.units_two_owner_lost += 1;
                    }
                    body.removed.add(conserved, unit.requests, None);
                    (1, Some(removed_category(reason)))
                }
                Some(ClaudeRequestVerdict::Counted(by)) => {
                    counts.note_counted(by);
                    (0, None)
                }
            };
            parts[part].add(conserved, unit.requests, None);
            match category {
                // Not counted: its live slice leaves the new body.
                Some(category) => {
                    if let Some(live) = &unit.live {
                        body.slice(
                            ClaudeGrainKey {
                                member: member.to_owned(),
                                owner: String::new(),
                                live: live.clone(),
                                origin: unit
                                    .reported
                                    .then_some(ClaudeRequestUsageOrigin::TelemetryMatched),
                                category,
                            },
                            Some((&unit.tokens, unit.requests, unit.live_cost)),
                            None,
                        );
                    }
                }
                // Counted: unchanged, its own money, or added.
                None => counted_slice(&mut body, member, unit, rows, counts),
            }
        }
        let union = parts.iter().fold((0_u64, 0_u64), |sum, part| {
            (
                sum.0.saturating_add(part.tokens),
                sum.1.saturating_add(part.requests),
            )
        });
        if union != (unit_totals.tokens, unit_totals.requests) {
            body.certificate_ok = false;
        }
        body.units
            .add(unit_totals.tokens, unit_totals.requests, None);
    }
    side_calls(
        &mut body,
        family,
        ctx,
        rows,
        &family_hashes,
        &reported_side_calls,
        now,
        counts,
    );
    // The new totals: the old ones moved by every slice.
    let mut new_tokens = i128::from(body.old.tokens);
    let mut new_requests = i128::from(body.old.requests);
    for (old, new) in body.grains.values() {
        new_tokens += i128::from(new.tokens.conserved()) - i128::from(old.tokens.conserved());
        new_requests += i128::from(new.requests) - i128::from(old.requests);
    }
    body.new = ClaudeMoneyTotals {
        tokens: u64::try_from(new_tokens.max(0)).unwrap_or(u64::MAX),
        requests: u64::try_from(new_requests.max(0)).unwrap_or(u64::MAX),
        ..ClaudeMoneyTotals::default()
    };
    // Drop slices that changed nothing (an own-cost slice always changes
    // the money; equal tokens with equal origin are no difference).
    body.grains.retain(|key, (old, new)| {
        key.category == ClaudeGrainCategory::OwnCost
            || old.tokens != new.tokens
            || old.requests != new.requests
    });
    body
}

/// A counted transcript unit: unchanged where the live body carries it the
/// same way; its matched row's own money where the live body did not price
/// it; added (at its finalizer row) where the live body, a reported rebuild,
/// dropped it.
fn counted_slice(
    body: &mut ClaudeRequestBody,
    member: &str,
    unit: &Unit,
    rows: &ClaudeRootRows,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    if unit.reported {
        if unit.live.is_some() {
            // The reported body carries it with its row's money: unchanged.
            return;
        }
        let Some(place) = &unit.place else {
            return;
        };
        let category = match unit.kind {
            _ if unit.conflict_winner => ClaudeGrainCategory::ConflictRule,
            UnitKind::Message(_) => ClaudeGrainCategory::MessageOnly,
            UnitKind::Idless => ClaudeGrainCategory::Idless,
            UnitKind::Request(_) => ClaudeGrainCategory::LegacyExclusion,
        };
        counts.units_added_to_reported += 1;
        body.slice(
            ClaudeGrainKey {
                member: member.to_owned(),
                owner: member.to_owned(),
                live: place.clone(),
                origin: None,
                category,
            },
            None,
            Some((&unit.tokens, unit.requests, None)),
        );
        return;
    }
    let Some(live) = &unit.live else {
        return;
    };
    let UnitKind::Request(hash) = unit.kind else {
        return;
    };
    let Some(row) = rows.get(hash) else {
        return;
    };
    let same_tokens = row.tokens.input == unit.tokens.input
        && row.tokens.output == unit.tokens.output
        && row.tokens.cache_read == unit.tokens.cache_read
        && row.cache_creation()
            == unit
                .tokens
                .cache_5m
                .saturating_add(unit.tokens.cache_1h)
                .saturating_add(unit.tokens.unattributed);
    match (row.cost_micros, same_tokens) {
        (Some(cost), true) => {
            counts.units_matched += 1;
            body.slice(
                ClaudeGrainKey {
                    member: member.to_owned(),
                    owner: member.to_owned(),
                    live: live.clone(),
                    origin: Some(ClaudeRequestUsageOrigin::TelemetryMatched),
                    category: ClaudeGrainCategory::OwnCost,
                },
                Some((&unit.tokens, unit.requests, None)),
                Some((&unit.tokens, unit.requests, Some(cost))),
            );
        }
        (None, true) => counts.units_matched_unpriced += 1,
        (_, false) => counts.units_matched_token_mismatch += 1,
    }
}

/// Telemetry-only requests of the root (side calls): no transcript unit of
/// the family holds them. Proven ones are counted once, at the trace-named
/// member (else the root), with their own usage and money, on both live
/// body kinds: added where the live body lacks them, moved where it carries
/// them at another member, unchanged where it carries them there.
#[allow(clippy::too_many_arguments)]
fn side_calls(
    body: &mut ClaudeRequestBody,
    family: &ClaudeFamilyInput<'_>,
    ctx: &ClaudeClassifyContext<'_, '_>,
    rows: &ClaudeRootRows,
    family_hashes: &BTreeSet<u64>,
    reported_side_calls: &BTreeMap<u64, (usize, ClaudeLiveKey)>,
    now: u64,
    counts: &mut ClaudeRequestMoneyShadowCounts,
) {
    let own_telemetry = super::super::claude_request_census::telemetry_key(family.root);
    for (position, row) in rows.iter().enumerate() {
        if position % 1024 == 1023 && ctx.late() {
            body.unbuilt = true;
            return;
        }
        let hash = row.request_hash;
        if family_hashes.contains(&hash) {
            continue;
        }
        let live = reported_side_calls.get(&hash);
        let live_member = live.map(|(index, _)| family.items[*index].source_session_id.as_str());
        let conserved = row.tokens.conserved();
        let absent_holder = ctx.holders.has_transcript_holder_in(hash, family.root);
        if absent_holder && live.is_none() {
            // An indexed member not on this page holds it: that member's
            // transcript unit, not a side call (built with that member).
            counts.side_calls_held_by_absent_member += 1;
            continue;
        }
        body.units.add(conserved, 1, None);
        let origin = if row.cost_micros.is_some() {
            ClaudeRequestUsageOrigin::TelemetryReported
        } else {
            ClaudeRequestUsageOrigin::TelemetryUnpriced
        };
        let leave = |body: &mut ClaudeRequestBody, category| {
            if let (Some((_, key)), Some(member)) = (live, live_member) {
                body.slice(
                    ClaudeGrainKey {
                        member: member.to_owned(),
                        owner: String::new(),
                        live: key.clone(),
                        origin: Some(origin),
                        category,
                    },
                    Some((&row.tokens, 1, row.cost_micros)),
                    None,
                );
            }
        };
        if row.clock == 0 || now.saturating_sub(row.clock) < MATURITY_SECONDS {
            counts.side_calls_immature += 1;
            body.immature.add(conserved, 1, None);
            leave(body, ClaudeGrainCategory::Immature);
            continue;
        }
        if absent_holder {
            // The live (reported) body carries a copy of a request a member
            // not on this page holds as a transcript unit: the new body
            // counts that unit, so this copy leaves.
            counts.side_calls_held_by_absent_member += 1;
            body.removed.add(conserved, 1, None);
            leave(body, ClaudeGrainCategory::CopiesRemoved);
            continue;
        }
        if !ctx.scope.family_complete(family.root) {
            counts.note_undecided(ClaudeUndecidedBy::Scope);
            body.held_reasons.insert(ClaudeUndecidedBy::Scope);
            body.held.add(conserved, 1, None);
            leave(body, ClaudeGrainCategory::Held);
            continue;
        }
        let mut claimants = ctx.telemetry_claimants(hash);
        if !claimants.contains(&own_telemetry.as_str()) {
            claimants.push(own_telemetry.as_str());
            claimants.sort_unstable();
        }
        if claimants.len() >= 2 {
            match ctx.two_owner_winner(&claimants) {
                Some(winner) if winner == own_telemetry => {
                    counts.side_calls_two_owner_won += 1;
                }
                Some(_) => {
                    counts.side_calls_two_owner_lost += 1;
                    body.removed.add(conserved, 1, None);
                    leave(body, ClaudeGrainCategory::TwoOwner);
                    continue;
                }
                None => {
                    counts.note_undecided(ClaudeUndecidedBy::TelemetryOrder);
                    body.held_reasons.insert(ClaudeUndecidedBy::TelemetryOrder);
                    body.held.add(conserved, 1, None);
                    leave(body, ClaudeGrainCategory::Held);
                    continue;
                }
            }
        }
        counts.side_calls += 1;
        if row.cost_micros.is_none() {
            counts.side_calls_unpriced += 1;
        }
        // The trace-named member when its file exists, else the root.
        let named = family
            .trace
            .and_then(|trace| trace.get(&hash))
            .filter(|member| family.indexed_members.contains(member.as_str()))
            .map(String::as_str);
        let member = match named {
            Some(member) => member,
            None => {
                // No trace, no trace row for it, or a member with no file:
                // the root stands in, and the member is unknown.
                counts.side_call_member_unknown += 1;
                family.root
            }
        };
        if live_member == Some(member) {
            counts.side_calls_in_live_body += 1;
            continue;
        }
        let Some(key) = reported_live_key(&row, None) else {
            // No live row to add it at: the body cannot be built.
            counts.side_calls_unkeyed += 1;
            body.unbuilt = true;
            continue;
        };
        if live.is_some() {
            counts.side_calls_moved += 1;
            body.removed.add(conserved, 1, None);
            leave(body, ClaudeGrainCategory::Transfer);
        }
        body.slice(
            ClaudeGrainKey {
                member: member.to_owned(),
                owner: member.to_owned(),
                live: key,
                origin: Some(origin),
                category: if live.is_some() {
                    ClaudeGrainCategory::Transfer
                } else {
                    ClaudeGrainCategory::SideCallAdded
                },
            },
            None,
            Some((&row.tokens, 1, row.cost_micros)),
        );
    }
}

/// E2 side calls use only family-local membership. A skipped copy still
/// supplies membership; an off-page subagent still supplies a census holder.
/// The telemetry row stays at its reporting root; this never elects an owner.
pub(super) fn e2_side_calls(
    items: &mut [SnapshotItem],
    api: &BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>,
    index: &super::super::ScanIndex,
) {
    // Borrow the existing exact-id sets: union/subtraction needs no second
    // corpus-sized request table. Only candidates absent from this page enter
    // the census holder lookup (normally the small auxiliary-call set).
    let mut side_rows = BTreeMap::new();
    let mut candidates = BTreeSet::new();
    for (root, rows) in api {
        let mut remaining = BTreeMap::new();
        let mut conflicts = BTreeSet::new();
        for row in rows
            .iter()
            .filter(|row| super::super::validate_claude_api_row(row, root))
        {
            if items.iter().any(|item| {
                super::super::claude_snapshot_family_root_ref(item) == root
                    && item.claude_usage_request_ids.contains(&row.request_id)
            }) {
                continue;
            }
            if let Some(prior) = remaining.insert(row.request_id.as_str(), row) {
                if prior != row {
                    conflicts.insert(row.request_id.as_str());
                }
            }
            candidates.insert(claude_request_hash(&row.request_id));
        }
        side_rows.insert(root.as_str(), (remaining, conflicts));
    }
    let hashes = candidates.into_iter().collect::<Vec<_>>();
    let empty = super::super::claude_request_census::ClaudeRequestCensus::default();
    let holders = super::super::claude_request_ledger::scan_holders(
        &index.claude_request_census,
        &empty,
        &hashes,
        &[],
        std::time::Instant::now() + std::time::Duration::from_millis(250),
        &mut |_| true,
    );
    let mut roots_done = BTreeSet::new();
    for item in items.iter_mut() {
        let root = super::super::claude_snapshot_family_root(item);
        if item.source_session_id != root || !roots_done.insert(root.clone()) {
            continue;
        }
        let Some(fold) = item.claude_money.as_mut() else {
            continue;
        };
        let Some(holders) = &holders else {
            fold.disclosed += 1;
            continue;
        };
        let Some((rows, conflicts)) = side_rows.get(root.as_str()) else {
            continue;
        };
        for (id, row) in rows {
            let hash = claude_request_hash(id);
            if holders.has_transcript_holder_in(hash, &root) {
                continue;
            }
            if conflicts.contains(id) || holders.overflowed(hash) {
                fold.disclosed += 1;
                continue;
            }
            let mut header = super::facts::ClaudeFactsHeader::default();
            let Some((_, fact)) = super::rows::row_fact(row, &root, &mut header) else {
                continue;
            };
            let api_row = super::rows::ClaudeApiRow {
                request_hash: hash,
                tokens: fact.tokens,
                cost_micros: fact.cost_micros,
                clock: fact.clock,
                model: &row.model,
                speed: &row.speed,
                effort: &row.effort,
            };
            let Some(key) = reported_live_key(&api_row, None) else {
                fold.disclosed += 1;
                continue;
            };
            let origin = if row.cost_usd_micros.is_some() {
                ClaudeRequestUsageOrigin::TelemetryReported
            } else {
                ClaudeRequestUsageOrigin::TelemetryUnpriced
            };
            fold.entity
                .grains
                .entry((key.clone(), Some(origin)))
                .or_default()
                .add(&fact.tokens, 1, row.cost_usd_micros);
            if let Some(at) = super::super::rfc3339_unix_nanos(&row.observed_at) {
                let bounds = fold.entity.bucket_activity.entry(key.0).or_insert((at, at));
                bounds.0 = bounds.0.min(at);
                bounds.1 = bounds.1.max(at);
                fold.entity.activity_nanos = fold.entity.activity_nanos.max(at);
            }
        }
    }
}
