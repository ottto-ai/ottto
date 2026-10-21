//! P1 per-request money ledger (shadow only): who owns each Claude request id.
//!
//! The ledger has no resident index. Its records are #664's census
//! (`claude_request_census`): transcript records keyed by file and telemetry
//! records keyed `otel:<sha256 of the root session id>`. A page sorts its own
//! request hashes once and intersects them with every record's sorted hashes,
//! which is O(total hashes · log page hashes) work per page and no memory
//! kept between pages (design v2 §2.3 planned a SoA owner index; P1 measures
//! the scan first, see the PR body).
//!
//! Nothing here feeds a live decision: verdicts only shape the shadow body.

use super::claude_request_census::{
    is_ledger_key, telemetry_key, ClaudeRequestCensus, ClaudeRequestCensusRecord,
    MAX_CLAUDE_REQUEST_CENSUS_HASHES, TELEMETRY_KEY_PREFIX,
};
use super::{claude_index_path_family_member, ScanIndex};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Holders kept per hash; more makes the id undecided, never a guess.
pub(crate) const MAX_HOLDERS_PER_HASH: usize = 16;

/// Telemetry pressure retirement starts at 90% of the shared hash budget and
/// retires the oldest telemetry records until 80%.
const PRESSURE_START_PERCENT: usize = 90;
const PRESSURE_TARGET_PERCENT: usize = 80;

/// Why one counted unit belongs, or does not belong, to its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeRequestVerdict {
    /// Only this file holds the id.
    Owned,
    /// The root's telemetry claims the id and this file is its family's only
    /// holder.
    TelemetryProven,
    /// Several current holders: the earliest first-seen birth wins, then the
    /// smaller key.
    PolicyOwned,
    /// Another holder, or another root's telemetry, owns it: a copy.
    Removed,
    /// Several holders and one is not current (strict freshness, Sol N6), or
    /// births are partly unknown, or the holder list overflowed.
    Undecided,
    /// Two telemetry roots claim the id.
    TwoOwner,
}

impl ClaudeRequestVerdict {
    pub(crate) fn counted(self) -> bool {
        matches!(
            self,
            Self::Owned | Self::TelemetryProven | Self::PolicyOwned
        )
    }
}

/// The census keys that hold each of a page's hashes.
#[derive(Debug, Default)]
pub(crate) struct ClaudeRequestHolders<'a> {
    transcript: BTreeMap<u64, Vec<&'a str>>,
    /// Message-only (`M`) ids by the transcript records' `mh`.
    message: BTreeMap<u64, Vec<&'a str>>,
    /// Some transcript record does not know its message-only ids (no `mh`).
    pub(crate) message_unknown: bool,
    telemetry: BTreeMap<u64, Vec<&'a str>>,
    overflow: BTreeSet<u64>,
    /// Record hashes compared (the scan's work, for diagnostics).
    pub(crate) compared: u64,
}

/// Bytes `scan_holders` may allocate for `page_hashes` hashes, charged by the
/// shadow's admission before the scan runs.
pub(crate) fn holders_bound(page_hashes: usize) -> usize {
    // Two map entries (node share) plus a full holder vector each.
    page_hashes.saturating_mul(2 * (64 + MAX_HOLDERS_PER_HASH * 16))
}

/// The hashes present in both sorted lists, probing the shorter list into
/// the longer one.
fn intersect(left: &[u64], right: &[u64], compared: &mut u64) -> Vec<u64> {
    let (short, long) = if left.len() <= right.len() {
        (left, right)
    } else {
        (right, left)
    };
    let mut found = Vec::new();
    for hash in short {
        *compared += 1;
        if long.binary_search(hash).is_ok() {
            found.push(*hash);
        }
    }
    found
}

fn hold<'a>(
    map: &mut BTreeMap<u64, Vec<&'a str>>,
    overflow: &mut BTreeSet<u64>,
    hash: u64,
    key: &'a str,
) {
    let list = map.entry(hash).or_default();
    if list.len() < MAX_HOLDERS_PER_HASH {
        list.push(key);
    } else {
        overflow.insert(hash);
    }
}

/// Intersect the page's sorted unique request and message-only hashes with
/// every record. A retired record holds no hashes and so is never a holder.
pub(crate) fn scan_holders<'a>(
    census: &'a ClaudeRequestCensus,
    page_hashes: &[u64],
    page_message_hashes: &[u64],
) -> ClaudeRequestHolders<'a> {
    let mut holders = ClaudeRequestHolders::default();
    for (key, record) in census.records() {
        if key.starts_with("birth:") {
            continue;
        }
        let telemetry = key.starts_with(TELEMETRY_KEY_PREFIX);
        if !telemetry {
            match record.message_hashes() {
                None if record.retired().is_none() => holders.message_unknown = true,
                None => {}
                Some(hashes) => {
                    for hash in intersect(hashes, page_message_hashes, &mut holders.compared) {
                        hold(&mut holders.message, &mut holders.overflow, hash, key);
                    }
                }
            }
        }
        for hash in intersect(record.request_hashes(), page_hashes, &mut holders.compared) {
            let map = if telemetry {
                &mut holders.telemetry
            } else {
                &mut holders.transcript
            };
            hold(map, &mut holders.overflow, hash, key);
        }
    }
    holders
}

impl<'a> ClaudeRequestHolders<'a> {
    /// A transcript record of family `root` holds the hash.
    pub(crate) fn has_transcript_holder_in(&self, hash: u64, root: &str) -> bool {
        self.transcript.get(&hash).is_some_and(|keys| {
            keys.iter().any(|key| {
                claude_index_path_family_member(Path::new(key))
                    .is_some_and(|(holder_root, _)| holder_root == root)
            })
        })
    }

    /// `otel:` keys whose telemetry holds the hash.
    pub(crate) fn telemetry_holders(&self, hash: u64) -> &[&'a str] {
        self.telemetry.get(&hash).map_or(&[][..], Vec::as_slice)
    }

    /// Classify one message-only (`M`) unit. No telemetry row names a
    /// message id, so only the transcript holders decide.
    pub(crate) fn classify_message(
        &self,
        index: &ScanIndex,
        hash: u64,
        own_key: &str,
    ) -> ClaudeRequestVerdict {
        if self.overflow.contains(&hash) {
            return ClaudeRequestVerdict::Undecided;
        }
        let mut holders = self.message.get(&hash).cloned().unwrap_or_default();
        if !holders.contains(&own_key) {
            holders.push(own_key);
        }
        holders.sort_unstable();
        if holders.len() == 1 {
            return ClaudeRequestVerdict::Owned;
        }
        policy(index, &holders, own_key)
    }

    /// Classify one counted unit: request hash `hash` seen in the file at
    /// census key `own_key` of family `own_root`.
    pub(crate) fn classify(
        &self,
        index: &ScanIndex,
        hash: u64,
        own_key: &str,
        own_root: &str,
    ) -> ClaudeRequestVerdict {
        if self.overflow.contains(&hash) {
            return ClaudeRequestVerdict::Undecided;
        }
        let telemetry = self.telemetry_holders(hash);
        if telemetry.len() >= 2 {
            return ClaudeRequestVerdict::TwoOwner;
        }
        let mut holders = self
            .transcript
            .get(&hash)
            .map(|keys| keys.to_vec())
            .unwrap_or_default();
        if !holders.contains(&own_key) {
            holders.push(own_key);
        }
        holders.sort_unstable();
        let root_of =
            |key: &str| claude_index_path_family_member(Path::new(key)).map(|(root, _)| root);
        if let Some(claimant) = telemetry.first() {
            let own_claimed = telemetry_key(own_root) == *claimant;
            if !own_claimed {
                // The request was made by another root: this file's copy is
                // that family's money, not this one's.
                return ClaudeRequestVerdict::Removed;
            }
            let scope = holders
                .iter()
                .copied()
                .filter(|key| root_of(*key).is_some_and(|root| telemetry_key(&root) == *claimant))
                .collect::<Vec<_>>();
            if scope.len() <= 1 {
                return ClaudeRequestVerdict::TelemetryProven;
            }
            return policy(index, &scope, own_key);
        }
        if holders.len() == 1 {
            return ClaudeRequestVerdict::Owned;
        }
        policy(index, &holders, own_key)
    }
}

/// Several holders: decide only when every one is current at its entry's
/// fingerprint (scoped strict completeness), then by first-seen birth, then
/// key. Births partly unknown cannot be ordered.
fn policy(index: &ScanIndex, holders: &[&str], own_key: &str) -> ClaudeRequestVerdict {
    let mut ranked = Vec::with_capacity(holders.len());
    for key in holders {
        let current = index
            .files
            .get(*key)
            .zip(index.claude_request_census.get(key))
            .is_some_and(|(entry, record): (_, &ClaudeRequestCensusRecord)| {
                record.current_for(&entry.source_file_fingerprint)
            });
        if !current {
            return ClaudeRequestVerdict::Undecided;
        }
        let birth = index
            .claude_request_census
            .get(key)
            .and_then(ClaudeRequestCensusRecord::birth)
            .map(|birth| birth.unix_seconds);
        ranked.push((birth, *key));
    }
    let known = ranked.iter().filter(|(birth, _)| birth.is_some()).count();
    if known != 0 && known != ranked.len() {
        return ClaudeRequestVerdict::Undecided;
    }
    let winner = ranked.iter().min().map(|(_, key)| *key);
    if winner == Some(own_key) {
        ClaudeRequestVerdict::PolicyOwned
    } else {
        ClaudeRequestVerdict::Removed
    }
}

/// Roots (family root session ids) that hold at least one retired transcript
/// record: a counted unit there may have a retired copy.
pub(crate) fn roots_with_retired_records(census: &ClaudeRequestCensus) -> BTreeSet<String> {
    census
        .records()
        .filter(|(key, record)| !is_ledger_key(key) && record.retired().is_some())
        .filter_map(|(key, _)| {
            claude_index_path_family_member(Path::new(key)).map(|(root, _)| root)
        })
        .collect()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeLedgerStateCounts {
    pub(crate) transcript_records: u64,
    pub(crate) transcript_retired_records: u64,
    pub(crate) telemetry_records: u64,
    pub(crate) telemetry_retired_records: u64,
    pub(crate) telemetry_hashes: u64,
    pub(crate) birth_stubs: u64,
    pub(crate) census_hashes: u64,
    pub(crate) census_serialized_bytes: u64,
    pub(crate) telemetry_retired_pressure: u64,
    /// Transcript records carrying a census `u` / without one (unknown).
    pub(crate) transcript_u_known: u64,
    pub(crate) transcript_u_unknown: u64,
}

pub(crate) fn ledger_state_counts(census: &ClaudeRequestCensus) -> ClaudeLedgerStateCounts {
    let mut counts = ClaudeLedgerStateCounts {
        census_hashes: census.hash_total() as u64,
        census_serialized_bytes: census.serialized_total() as u64,
        ..ClaudeLedgerStateCounts::default()
    };
    for (key, record) in census.records() {
        if key.starts_with(TELEMETRY_KEY_PREFIX) {
            counts.telemetry_records += 1;
            counts.telemetry_retired_records += u64::from(record.retired().is_some());
            counts.telemetry_hashes += record.request_hashes().len() as u64;
        } else if is_ledger_key(key) {
            counts.birth_stubs += 1;
        } else {
            counts.transcript_records += 1;
            counts.transcript_retired_records += u64::from(record.retired().is_some());
            match record.old_path_usage() {
                Some(_) => counts.transcript_u_known += 1,
                None => counts.transcript_u_unknown += 1,
            }
        }
    }
    counts
}

/// Telemetry retirement under budget pressure only: at 90% of the shared hash
/// budget, retire the telemetry records with the oldest last append until the
/// total is at 80%. A retired telemetry record keeps its tail (the reader
/// never re-adds consumed rows), so its old ids lose their telemetry claim:
/// a later transcript copy of one falls back to policy. Returns how many.
pub(crate) fn retire_telemetry_under_pressure(census: &mut ClaudeRequestCensus) -> u64 {
    let cap = MAX_CLAUDE_REQUEST_CENSUS_HASHES;
    if census.hash_total().saturating_mul(100) < cap * PRESSURE_START_PERCENT {
        return 0;
    }
    let mut candidates = census
        .records()
        .filter(|(key, record)| {
            key.starts_with(TELEMETRY_KEY_PREFIX) && !record.request_hashes().is_empty()
        })
        .map(|(key, record)| {
            (
                record.tail().map_or(0, |tail| tail.last_append_unix),
                key.clone(),
            )
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    let mut retired = 0;
    for (_, key) in candidates {
        if census.hash_total().saturating_mul(100) <= cap * PRESSURE_TARGET_PERCENT {
            break;
        }
        if let Some(mut record) = census.get(&key).cloned() {
            record.retire();
            let _ = census.insert(key, record);
            retired += 1;
        }
    }
    retired
}
