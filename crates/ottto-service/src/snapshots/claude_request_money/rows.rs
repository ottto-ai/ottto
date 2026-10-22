//! The API rows of a page's roots, for the P1 money shadow.
//!
//! Rows come from the live load when it kept the root (a healthy paired
//! root), else from the compact facts the telemetry tail keeps in the root's
//! `otel:` ledger record (`facts`), when the tail read that sidecar to its
//! frozen extent this page. Nothing rereads a sidecar to price it and no
//! decoded row is kept between pages. A root whose rows are not complete
//! (behind, a refused or unreadable line, retired, over budget) has no rows
//! this page: unavailable, never "no rows".
//!
//! Both sources reduce a row to the same fact and resolve two rows for one
//! request by the same conflict order over the fact's content digest.

use super::super::claude_request_census::{claude_request_hash, ClaudeRequestCensusRecord};
use super::super::validate_claude_api_row;
use super::facts::{fact_digest, ClaudeFact, ClaudeFacts, ClaudeFactsHeader, UNREADABLE_STYLE};
use super::{
    claude_cache_creation, claude_response_conflict_order, CacheCreation, ClaudeMoneyTokens,
};
use crate::claude_local_otel::telemetry_tail::event_unix;
use crate::claude_local_otel::ClaudeLocalOtelEvidence;
use std::cmp::Ordering;
use std::sync::Arc;

/// The style strings of the unreadable marker (never a real style).
const UNREADABLE: (&str, &str, &str) = ("\u{1f}unreadable", "", "");

/// One strict API row as the builder reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaudeApiRow<'a> {
    pub(crate) request_hash: u64,
    pub(crate) tokens: ClaudeMoneyTokens,
    pub(crate) cost_micros: Option<u64>,
    /// Event time (unix seconds).
    pub(crate) clock: u64,
    pub(crate) model: &'a str,
    pub(crate) speed: &'a str,
    pub(crate) effort: &'a str,
}

impl ClaudeApiRow<'_> {
    /// The row's flat cache-creation total (split or not).
    pub(crate) fn cache_creation(&self) -> u64 {
        self.tokens
            .cache_5m
            .saturating_add(self.tokens.cache_1h)
            .saturating_add(self.tokens.unattributed)
    }

    /// The event time as RFC 3339 (UTC): the live rebuild keys a row's hour
    /// by its `observed_at`, which floors to the same hour.
    pub(crate) fn observed_at(&self) -> Option<String> {
        time::OffsetDateTime::from_unix_timestamp(i64::try_from(self.clock).ok()?)
            .ok()?
            .format(&time::format_description::well_known::Rfc3339)
            .ok()
    }
}

/// A strict row of `root` as a fact, with its request hash. None: refused by
/// the shared validator. A row whose cache write the shared normalizer cannot
/// read, or whose style the record cannot name, is a fact of
/// `UNREADABLE_STYLE`: its hash still claims the request, its money is not
/// known.
pub(crate) fn row_fact(
    row: &ClaudeLocalOtelEvidence,
    root: &str,
    header: &mut ClaudeFactsHeader,
) -> Option<(u64, ClaudeFact)> {
    if !validate_claude_api_row(row, root) {
        return None;
    }
    let split = match claude_cache_creation(
        row.cache_creation_tokens,
        row.cache_creation_5m_tokens,
        row.cache_creation_1h_tokens,
    ) {
        CacheCreation::Split { five_m, one_h } => Some((five_m, one_h, 0)),
        CacheCreation::Unattributed(total) => Some((0, 0, total)),
        CacheCreation::Contradictory => None,
    };
    let style = split
        .and_then(|_| header.intern(&row.model, &row.speed, &row.effort))
        .unwrap_or(UNREADABLE_STYLE);
    let (cache_5m, cache_1h, unattributed) = split.unwrap_or_default();
    Some((
        claude_request_hash(&row.request_id),
        ClaudeFact {
            tokens: ClaudeMoneyTokens {
                input: row.input_tokens,
                output: row.output_tokens,
                cache_read: row.cache_read_tokens,
                cache_5m,
                cache_1h,
                unattributed,
                reasoning: row.reasoning_output_tokens,
            },
            cost_micros: row.cost_usd_micros,
            clock: event_unix(&row.observed_at),
            style,
        },
    ))
}

fn style_of<'h>(header: &'h ClaudeFactsHeader, fact: &ClaudeFact) -> (&'h str, &'h str, &'h str) {
    if fact.style == UNREADABLE_STYLE {
        return UNREADABLE;
    }
    header.style(fact.style).unwrap_or(UNREADABLE)
}

/// The conflict order between two facts of one request (Sol N3): `Less` =
/// `left` wins. Equal only for the same money.
pub(crate) fn fact_order(
    header: &ClaudeFactsHeader,
    left: &ClaudeFact,
    right: &ClaudeFact,
) -> Ordering {
    claude_response_conflict_order(
        (&left.tokens, 0, fact_digest(left, style_of(header, left))),
        (
            &right.tokens,
            0,
            fact_digest(right, style_of(header, right)),
        ),
    )
}

/// Sort `facts` by hash, keep each request's conflict winner, and return
/// how many dropped rows differed from their winner (a replay is none).
pub(crate) fn resolve_conflicts(
    header: &ClaudeFactsHeader,
    facts: &mut Vec<(u64, ClaudeFact)>,
) -> u64 {
    facts.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| fact_order(header, &left.1, &right.1))
    });
    let mut conflicts = 0;
    facts.dedup_by(|later, kept| {
        if later.0 != kept.0 {
            return false;
        }
        conflicts += u64::from(fact_order(header, &later.1, &kept.1) != Ordering::Equal);
        true
    });
    conflicts
}

/// One root's rows by request hash (sorted, one per request).
#[derive(Debug, Default)]
pub(crate) struct ClaudeRootRows {
    hashes: Option<Arc<[u64]>>,
    facts: Vec<ClaudeFact>,
    header: ClaudeFactsHeader,
    pub(crate) conflicts: u64,
}

/// Admission charge of `rows` decoded rows (facts, their hashes, sort room).
pub(crate) fn rows_bound(rows: usize) -> usize {
    rows.saturating_mul(2 * (std::mem::size_of::<(u64, ClaudeFact)>() + 8))
}

impl ClaudeRootRows {
    /// The live load's rows of `root`: None when any is refused or
    /// unreadable (strict like the live reducer), with the refused count.
    pub(crate) fn from_live(rows: &[ClaudeLocalOtelEvidence], root: &str) -> (Option<Self>, u64) {
        let mut header = ClaudeFactsHeader {
            session: root.to_owned(),
            ..ClaudeFactsHeader::default()
        };
        let mut facts = Vec::with_capacity(rows.len());
        let mut refused = 0_u64;
        for row in rows {
            match row_fact(row, root, &mut header) {
                Some((_, fact)) if fact.style == UNREADABLE_STYLE => refused += 1,
                Some(fact) => facts.push(fact),
                None => refused += 1,
            }
        }
        if refused > 0 {
            return (None, refused);
        }
        let conflicts = resolve_conflicts(&header, &mut facts);
        let hashes = facts.iter().map(|(hash, _)| *hash).collect::<Vec<_>>();
        let rows = Self {
            hashes: (!hashes.is_empty()).then(|| Arc::from(hashes)),
            facts: facts.into_iter().map(|(_, fact)| fact).collect(),
            header,
            conflicts,
        };
        (Some(rows), 0)
    }

    /// The rows a telemetry record's facts hold, sharing its hash buffer.
    /// None unless the record is complete and every row readable (not
    /// retired, not over budget, no refused line).
    pub(crate) fn from_record(record: &ClaudeRequestCensusRecord) -> Option<Self> {
        if record.retired().is_some() || record.over_budget() {
            return None;
        }
        let mut facts = ClaudeFacts::open(record.facts()?)?;
        if facts.header.refused > 0 {
            return None;
        }
        let count = record.request_hashes().len();
        let mut decoded = Vec::with_capacity(count);
        for _ in 0..count {
            let fact = facts.next_fact()?;
            if fact.style == UNREADABLE_STYLE {
                return None;
            }
            decoded.push(fact);
        }
        Some(Self {
            hashes: record.shared_request_hashes(),
            conflicts: facts.header.conflicts,
            header: facts.header,
            facts: decoded,
        })
    }

    fn hashes(&self) -> &[u64] {
        self.hashes.as_deref().unwrap_or(&[])
    }

    fn row(&self, position: usize) -> ClaudeApiRow<'_> {
        let fact = &self.facts[position];
        let (model, speed, effort) = style_of(&self.header, fact);
        ClaudeApiRow {
            request_hash: self.hashes()[position],
            tokens: fact.tokens,
            cost_micros: fact.cost_micros,
            clock: fact.clock,
            model,
            speed,
            effort,
        }
    }

    pub(crate) fn get(&self, request_hash: u64) -> Option<ClaudeApiRow<'_>> {
        self.hashes()
            .binary_search(&request_hash)
            .ok()
            .map(|position| self.row(position))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = ClaudeApiRow<'_>> {
        (0..self.facts.len()).map(|position| self.row(position))
    }

    pub(crate) fn len(&self) -> usize {
        self.facts.len()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ClaudeRowCounts {
    pub(crate) roots_live: u64,
    pub(crate) roots_from_facts: u64,
    pub(crate) roots_absent: u64,
    /// The tail did not read the sidecar to its extent this page.
    pub(crate) roots_behind: u64,
    /// The record is retired, over budget, pre-facts or has a refused line.
    pub(crate) roots_unavailable: u64,
    pub(crate) roots_refused_memory: u64,
    pub(crate) rows_refused: u64,
    pub(crate) rows_conflicting: u64,
    pub(crate) rows_decoded: u64,
}
