//! Optional reported-cost attachment, independent of counting and ownership.
//!
//! The row type identifies the provider. Each report and its holder lookup must
//! cover one session/lineage scope, so request keys never cross either boundary.
//! Readers own replay deduplication and conflicting-key detection; this join
//! never selects a winning value. Callers price tokens when attachment is absent.

use std::collections::BTreeSet;

pub trait ReportedRequest {
    /// Native request identity within the report's scope. Empty keys are
    /// disclosed as incompatible, never attached or offered as side calls.
    fn request_key(&self) -> &str;
    fn reported_cost_micros(&self) -> Option<u64>;
}

/// Borrowed reader output, including its completeness and ambiguity witnesses.
/// Repeated identical exports must already be collapsed by the reader, and all
/// conflicting keys must be listed in `duplicate_keys`.
#[derive(Debug)]
pub struct SessionReport<'r, R> {
    pub rows: &'r [R],
    pub complete: bool,
    pub duplicate_keys: &'r BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Holders<H> {
    None,
    One(H),
    Many,
    /// Already held by a counted/skipped occurrence that cannot receive attach.
    HeldNotAttachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureReason {
    DuplicateReport,
    ManyHolders,
    Incompatible,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Attachment<'r, R, H> {
    Matched {
        row: &'r R,
        holder: H,
    },
    Unheld(&'r R),
    Disclosed {
        row: &'r R,
        reason: DisclosureReason,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JoinCounts {
    pub matched: usize,
    pub unheld: usize,
    pub disclosed: usize,
    /// Reader health only; callers must also check coverage of counted requests.
    pub complete: bool,
}

/// Visit each row once, allocating no storage and preserving optional cost.
/// Callbacks supply existing holder and compatibility rules; their work and
/// allocations are outside the join. HeldNotAttachable rows produce no event,
/// including when the reader marks their key conflicting. Every other
/// conflicting row is disclosed before compatibility is considered.
pub fn join<'r, R, H>(
    report: SessionReport<'r, R>,
    mut holders: impl FnMut(&str) -> Holders<H>,
    mut compatible: impl FnMut(&R, &H) -> bool,
    mut each: impl FnMut(Attachment<'r, R, H>),
) -> JoinCounts
where
    R: ReportedRequest,
{
    let mut counts = JoinCounts {
        complete: report.complete,
        ..JoinCounts::default()
    };
    for row in report.rows {
        let key = row.request_key();
        let holder = holders(key);
        if matches!(holder, Holders::HeldNotAttachable) {
            continue;
        }
        let reason = if key.is_empty() {
            DisclosureReason::Incompatible
        } else if report.duplicate_keys.contains(key) {
            DisclosureReason::DuplicateReport
        } else {
            match holder {
                Holders::None => {
                    counts.unheld += 1;
                    each(Attachment::Unheld(row));
                    continue;
                }
                Holders::One(holder) => {
                    if compatible(row, &holder) {
                        counts.matched += 1;
                        each(Attachment::Matched { row, holder });
                        continue;
                    }
                    DisclosureReason::Incompatible
                }
                Holders::Many => DisclosureReason::ManyHolders,
                Holders::HeldNotAttachable => unreachable!(),
            }
        };
        counts.disclosed += 1;
        each(Attachment::Disclosed { row, reason });
    }
    counts
}

#[cfg(test)]
#[path = "telemetry_attach_tests.rs"]
mod tests;
