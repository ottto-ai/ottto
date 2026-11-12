//! First-read progress (`first_read` V1 on scan-status): which history files
//! belong to a destination's first read, which class each is in, and the
//! block a scan-status report carries. The import list itself is saved in the
//! route's `tail.first_read` rows and changes only in the commit that also
//! commits the file's debt (`state_v2::tail::first_read`).
//!
//! Classes, first match wins: unreadable head or debt is failed; no import
//! debt with positive proof (exact receipt for the whole file, existing
//! zero-use evidence, zero length) is done; import debt held by the history
//! list or the move rule is excluded by policy; import debt with any reason
//! other than unread is held; the rest is owed. "Import debt" is any debt whose
//! first change is a lower bound or no later than the anchor: a file that
//! existed at the anchor and grew after it stays import debt.
use super::*;
use crate::snapshots::state_v2::{
    FirstReadClass as Class, FirstReadEdit, FirstReadMember as Member,
    FirstReadObserved as Observed, FirstReadSummary as Summary, FIRST_READ_BUCKETS,
};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// Coverage boundaries before the anchor, oldest first (D394: 60 days).
const BOUNDARY_DAYS: [u64; 4] = [60, 30, 14, 7];

/// The boundaries `anchor - {60, 30, 14, 7} days`, oldest first.
pub(in crate::snapshots) fn boundaries(anchor_ms: u64) -> [u64; 4] {
    BOUNDARY_DAYS.map(|days| anchor_ms.saturating_sub(days * DAY_MS))
}

/// The age bucket of a witness: how many boundaries are at or before it.
/// Unknown, future or at-or-after-anchor witnesses obstruct every boundary.
pub(in crate::snapshots) fn bucket(anchor_ms: u64, witness_ms: Option<u64>, now_ms: u64) -> u8 {
    let top = (FIRST_READ_BUCKETS - 1) as u8;
    match witness_ms {
        Some(at) if at <= now_ms && at < anchor_ms => {
            boundaries(anchor_ms).iter().filter(|b| **b <= at).count() as u8
        }
        _ => top,
    }
}

/// The oldest boundary strictly later than every obstructing member, from the
/// per-bucket counts; `None` before the listing is certified.
pub(in crate::snapshots) fn complete_since(summary: &Summary) -> Option<u64> {
    summary.certified_at_ms?;
    let newest = summary
        .counts
        .obstruct
        .iter()
        .rposition(|count| *count > 0)
        .unwrap_or(0);
    let boundaries = boundaries(summary.anchor_at_ms);
    match newest {
        0 => Some(boundaries[0]),
        k if k < boundaries.len() => Some(boundaries[k]),
        _ => None,
    }
}

/// The inputs of one member's class, as one observation sees the file.
pub(in crate::snapshots) struct Inputs {
    /// Its head or revisions could not be read.
    pub(in crate::snapshots) unknown: bool,
    /// Every revision still owed after this observation, as its summary.
    pub(in crate::snapshots) owed: Option<DebtSummary>,
    /// Existing per-file no-upload proof, zero length, or an exact receipt
    /// for the whole live file.
    pub(in crate::snapshots) proof: bool,
    /// The history list or the move rule holds it, or it is a terminal member.
    pub(in crate::snapshots) policy: bool,
    pub(in crate::snapshots) mtime_ms: Option<u64>,
    pub(in crate::snapshots) bytes: u64,
}

/// Whether owed debt is import debt of the generation anchored at `anchor_ms`.
fn import(owed: &DebtSummary, anchor_ms: u64) -> bool {
    owed.lower_bound
        || owed
            .earliest_unacked_change_at
            .map_or(true, |at| at <= anchor_ms)
}

/// The member one observation stages; `None` for a file the generation does
/// not admit (live-only debt and no row yet: a change after the anchor).
pub(in crate::snapshots) fn observe(
    anchor_ms: u64,
    now_ms: u64,
    inputs: &Inputs,
    prior: Option<Member>,
) -> Option<Observed> {
    let bucket = bucket(anchor_ms, inputs.mtime_ms, now_ms);
    let member = |class| Member {
        class,
        bucket,
        bytes: inputs.bytes,
    };
    let observed = |class, debt_gone| Observed {
        member: member(class),
        debt_gone,
    };
    if inputs.unknown {
        return Some(observed(Class::Failed, false));
    }
    let import_debt = inputs.owed.as_ref().filter(|owed| import(owed, anchor_ms));
    let Some(owed) = import_debt else {
        if inputs.owed.is_some() && prior.is_none() {
            return None;
        }
        // No import debt: positive proof is done. Without proof a member whose
        // import debt left (only an exact receipt or evidence removes it) is
        // done; a file never seen owing is owed, fail closed.
        return Some(if inputs.proof {
            observed(Class::Done, false)
        } else {
            observed(Class::Owed, true)
        });
    };
    let class = if inputs.policy {
        Class::ExcludedPolicy
    } else if owed.reason_bits & !UNREAD != 0 {
        Class::Held
    } else {
        Class::Owed
    };
    Some(observed(class, false))
}

/// The first read's state for one discovery page: the open generation's
/// anchor, and the members this page observed.
#[derive(Default)]
pub(in crate::snapshots) struct PageState {
    pub(in crate::snapshots) anchor_ms: Option<u64>,
    pub(in crate::snapshots) members: Vec<(String, Observed)>,
    pub(in crate::snapshots) edit: Option<FirstReadEdit>,
}
impl PageState {
    /// The open generation of this route: the committed summary, else the
    /// anchor this pass staged. A first root walk of a pending first read on
    /// an empty index anchors one at its census time; a source with no root
    /// and no root problem certifies an empty one at once. An unreadable
    /// summary is no generation: nothing is written until it reads again.
    pub(in crate::snapshots) fn begin(
        index: &ScanIndex,
        route: &Path,
        anchor_at: Option<(u64, bool)>,
        now_ms: u64,
    ) -> Self {
        let mut page = Self::default();
        match state_v2::first_read_summary(index) {
            Ok(Some(summary)) => {
                page.anchor_ms = summary.open().then_some(summary.anchor_at_ms);
            }
            Ok(None) => match state_v2::staged_first_read_anchor(route) {
                Ok(Some(anchor_ms)) => page.anchor_ms = Some(anchor_ms),
                Ok(None) if index.first_read_pending && index.files.is_empty() => {
                    if let Some((anchor_ms, empty)) = anchor_at {
                        let edit = FirstReadEdit {
                            anchor_at_ms: Some(anchor_ms),
                            certify_at_ms: empty.then_some(now_ms),
                            empty_inventory: empty,
                            ..Default::default()
                        };
                        if state_v2::observe_first_read(route, Vec::new(), Some(edit)).is_ok() {
                            page.anchor_ms = Some(anchor_ms);
                        }
                    }
                }
                _ => {}
            },
            Err(_) => {}
        }
        page
    }

    /// Stage `key`'s member when it changes its committed row (N4).
    pub(in crate::snapshots) fn observe(
        &mut self,
        index: &ScanIndex,
        key: &str,
        inputs: &Inputs,
        now_ms: u64,
    ) {
        let Some(anchor_ms) = self.anchor_ms else {
            return;
        };
        // An unreadable row is left alone: the freeze recount refuses it.
        let Ok(prior) = state_v2::first_read_member(index, key) else {
            return;
        };
        let Some(observed) = observe(anchor_ms, now_ms, inputs, prior) else {
            return;
        };
        if prior != Some(state_v2::resolve_first_read(prior, observed)) {
            self.members.push((key.to_owned(), observed));
        }
    }

    /// Stage this page's members (and edit) for the next commit.
    pub(in crate::snapshots) fn stage(&mut self, route: &Path) -> Result<()> {
        let members = std::mem::take(&mut self.members);
        let edit = self.edit.take();
        if members.is_empty() && edit.is_none() {
            return Ok(());
        }
        state_v2::observe_first_read(route, members, edit)
    }
}

/// Summary fields at the time the block is computed.
pub(in crate::snapshots) fn certify(started_at_ms: u64, anchor_ms: u64) -> Option<FirstReadEdit> {
    (started_at_ms >= anchor_ms).then(|| FirstReadEdit {
        certify_at_ms: Some(started_at_ms),
        ..Default::default()
    })
}

#[cfg(test)]
#[path = "first_read_tests.rs"]
mod tests;
