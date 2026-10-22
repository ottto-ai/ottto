//! The daily audit sample.
//!
//! The reader counts a transcript in pieces, one run's new lines at a time.
//! The audit checks that this equals reading the file whole: each day it
//! re-reads a few files from their start, within `AUDIT_BYTES_PER_DAY`, and
//! compares the numbers per (day, kind) with the file's stored share. On a
//! difference the re-read's result replaces the file's share (no second
//! read) and the run counts it, so the daily run health reports it. No other
//! file is ever read again because of it.
//!
//! Only files read whole under the current parser are sampled: a file whose
//! counting started mid-file, ran under an older parser, went cold or holds
//! ids this build does not know would differ for reasons that are not
//! faults. Picks rotate through the pins in key order from where the last
//! audit stopped (kept in the run record), so every eligible file is
//! sampled in turn. Besides live-at-install work and budgeted rewrite repair,
//! this is the only repeat read from offset zero. Newly created files are read
//! from their start once, then become audit candidates too. Audit bytes are
//! counted on their own.

use super::aggregate::{Bucket, Contribution, Day};
use super::checkpoint::{file_identity, stamp, Checkpoint, Index, Pin, Status, COLD_AFTER_SECS};
use super::{AUDIT_BYTES_PER_DAY, AUDIT_FILES_PER_DAY, PARSER_VERSION};
use crate::composition_kinds::Kind;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Today's audit allowance and where each agent's rotation stands.
#[derive(Debug, Default)]
pub(super) struct AuditRun {
    /// Audit bytes left today (shared by the agents).
    pub(super) left: u64,
    /// Files picked in this run (shared by the agents).
    pub(super) files: usize,
    /// Per agent: the copy key audited (or passed over) last.
    pub(super) after: BTreeMap<String, String>,
}

impl AuditRun {
    pub(super) fn with_budget(left: u64, after: BTreeMap<String, String>) -> Self {
        Self {
            left,
            files: 0,
            after,
        }
    }
}

/// A pin that may be sampled: pinned to a scope, counted from its start,
/// read to its end at its last commit, not waiting for any other work and
/// changed recently enough that its checkpoint is not cold (a cold share
/// cannot be replaced).
fn pin_eligible(pin: &Pin, now_secs: i64) -> bool {
    pin.scope.is_some()
        && pin.mtime.0 >= now_secs - COLD_AFTER_SECS
        && pin.origin == Some(0)
        && pin.start > 0
        && pin.start == pin.size
        && !pin.done
        && !pin.quarantined
        && !pin.waiting
        && !pin.restart_at_end
        && !pin.unscoped
}

/// Pick today's audit files for one agent, in rotation order after the
/// last pick. `busy` holds the keys read this run anyway. Returns (key,
/// path, metadata) of each pick; its bytes are reserved from the budget.
pub(super) fn pick(
    audit: &mut AuditRun,
    agent: &str,
    index: &Index,
    busy: &BTreeSet<&str>,
    now_secs: i64,
) -> Vec<(String, std::path::PathBuf, std::fs::Metadata)> {
    let mut picks = Vec::new();
    let after = audit.after.get(agent).cloned();
    // Keys after the cursor, then from the start up to it.
    let later = |key: &String| after.as_ref().map_or(true, |after| key > after);
    let ordered = index
        .files
        .iter()
        .filter(|(key, _)| later(key))
        .chain(index.files.iter().filter(|(key, _)| !later(key)));
    let mut cursor = after.clone();
    for (key, pin) in ordered {
        if audit.left == 0 || audit.files >= AUDIT_FILES_PER_DAY {
            break;
        }
        if !pin_eligible(pin, now_secs) || busy.contains(key.as_str()) {
            continue;
        }
        if pin.start > AUDIT_BYTES_PER_DAY {
            // Never fits a day's audit: passed over for good.
            cursor = Some(key.clone());
            continue;
        }
        if pin.start > audit.left {
            // First in line tomorrow, with a whole day's budget.
            break;
        }
        cursor = Some(key.clone());
        let Ok(metadata) = std::fs::metadata(Path::new(&pin.path)) else {
            continue;
        };
        if file_identity(&metadata) != (pin.dev, pin.ino)
            || metadata.len() != pin.size
            || stamp(&metadata) != pin.mtime
        {
            // Changed since its last commit: the next run reads it forward.
            continue;
        }
        audit.left -= pin.start;
        audit.files += 1;
        picks.push((key.clone(), std::path::PathBuf::from(&pin.path), metadata));
    }
    if let Some(cursor) = cursor {
        audit.after.insert(agent.to_string(), cursor);
    }
    picks
}

/// The start verdict to re-read a checkpoint with, when it may be audited
/// up to `reserved` bytes: read whole under the current parser, still warm,
/// every id known, request 1 closed under a recorded verdict.
pub(super) fn eligible(checkpoint: &Checkpoint, reserved: u64) -> Option<bool> {
    let fits = checkpoint.offset > 0 && checkpoint.offset <= reserved;
    let whole = checkpoint.origin == Some(0)
        && checkpoint.parser_version == PARSER_VERSION
        && checkpoint.status == Status::Live
        && checkpoint.cold.is_none()
        && !checkpoint.skipping
        && checkpoint.ids_known();
    if !(fits && whole) {
        return None;
    }
    checkpoint.parse.request1_verdict()
}

/// Whether a re-read's share differs from the stored one per (day, kind):
/// events, tokens, residency and images. Lines with no timestamp count on
/// the day they are read, so when the re-read met any, the days cannot
/// match and the numbers are compared per kind over all days instead.
pub(super) fn differs(stored: Option<&Contribution>, reread: &Contribution, undated: bool) -> bool {
    let empty = Contribution::default();
    by_kind(stored.unwrap_or(&empty), undated) != by_kind(reread, undated)
}

fn by_kind(share: &Contribution, undated: bool) -> BTreeMap<(Day, Kind), Bucket> {
    let mut totals: BTreeMap<(Day, Kind), Bucket> = BTreeMap::new();
    for ((day, slot), bucket) in &share.parts {
        let day = if undated { 0 } else { *day };
        let total = totals.entry((day, slot.kind)).or_default();
        total.events += bucket.events;
        total.tokens += bucket.tokens;
        total.residency += bucket.residency;
        total.images += bucket.images;
    }
    totals.retain(|_, bucket| !bucket.is_zero());
    totals
}
