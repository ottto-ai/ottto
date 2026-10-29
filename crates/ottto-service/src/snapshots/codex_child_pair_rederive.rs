//! One-time, bounded validation of pre-#896 cached child creator evidence.
//! This metadata selects a counted native Full; it never supplies account evidence.
use super::*;

pub(super) const MAX_BYTES: u64 = 410_000_000;
pub(super) const MAX_CHILDREN: usize = 64;
pub(super) const MAX_SPENT_BYTES: u64 = MAX_BYTES * 2;
const MAX_LEDGER_BYTES: usize = 256 * 1024;
const MAX_ATTEMPTS: u8 = 2; // first + crash_retry, never renewed on restart

/// SOURCE class L: optional per-entry marker, no content or provider ids.
/// Pending is scheduling only; terminal variants never authorize a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stamp {
    Pending {
        attempts: u8,
        retry_after: u64,
        running: bool,
    },
    Named,
    Conflict,
    Incomplete,
    Unreadable,
    CrashHeld,
}
impl crate::heap_layout_bound::HeapLayoutBound for Stamp {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Pending {
                attempts: _,
                retry_after: _,
                running: _,
            }
            | Self::Named
            | Self::Conflict
            | Self::Incomplete
            | Self::Unreadable
            | Self::CrashHeld => c.add(0),
        }
    }
}

/// Proposed SOURCE class-L per-key reading record. This is negative spend,
/// independent of upload ACK, ordinary audit debt and file-entry replacement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Reading {
    pub(crate) stamp: Stamp,
    pub(crate) source_file_fingerprint: String,
    pub(crate) reserved_extent: u64,
    pub(crate) spent_bytes: u64,
    pub(crate) reserved_at: u64,
}
crate::heap_layout_bound::fields!(Reading; stamp, source_file_fingerprint, reserved_extent, spent_bytes, reserved_at);

pub(super) fn stamp(index: &ScanIndex, key: &str) -> Option<Stamp> {
    index
        .codex_child_pair_reading
        .get(key)
        .map(|reading| reading.stamp)
}

#[cfg(unix)]
pub(super) fn eligible(acc: &SnapshotAccumulator, metadata: &CodexTitleMetadata) -> bool {
    if acc.source != SnapshotSource::Codex || !acc.codex_session_meta_seen {
        return false;
    }
    let Some(child) = acc.codex_creator_header_id.as_deref() else {
        return false;
    };
    if acc.source_session_id.as_deref() != Some(child) {
        return false;
    }
    // This field is assigned from the physical header's forked_from_id, not
    // from sidecar enrichment or the more permissive codex_is_fork flag.
    let fork = acc
        .codex_parent_session_ref
        .as_deref()
        .is_some_and(|parent| parent != child && resolve_codex_identity(parent) == parent);
    // Old retained copies predate finish-time graph decoration. Require the
    // raw native subagent declaration and the SAME direct parent in the
    // already-loaded provider graph. This is graph depth, not header depth.
    let depth_two = acc.origin.thread_source.as_deref() == Some("subagent")
        && acc.origin.source_subagent == Some(true)
        && metadata
            .family_position(child)
            .is_some_and(|(parent, root, depth)| {
                depth == 2
                    && parent != child
                    && root != child
                    && root != parent
                    && acc.origin.parent_session_ref.as_deref() == Some(parent.as_str())
            });
    (fork || depth_two)
        && (acc.codex_creator_evidence_conflicted
            || (depth_two && acc.codex_creator_evidence.is_none()))
}

/// Collect metadata first, sum INDEX sizes, then mark the approved per-key
/// repair cause. This never stages AuditDebt or opens a transcript.
#[cfg(unix)]
pub(super) fn stage(
    index: &mut ScanIndex,
    cache: &sampled_scan::SharedCache,
    metadata: &CodexTitleMetadata,
) {
    if cache.durable_child_pair_budget_stopped() {
        return;
    }
    let now = sampled_scan::now_seconds();
    // Recover only on process entry; a paused cursor keeps its running grant.
    if !cache.durable_child_pair_select_once() {
        return;
    }
    for reading in index.codex_child_pair_reading.values_mut() {
        if let Stamp::Pending {
            attempts,
            running: true,
            ..
        } = reading.stamp
        {
            reading.stamp = if attempts >= MAX_ATTEMPTS {
                Stamp::CrashHeld
            } else {
                Stamp::Pending {
                    attempts,
                    retry_after: now.saturating_add(2),
                    running: false,
                }
            };
        }
    }
    cache.durable_child_pair_alarm(index, now);
    let inventory = cache.durable_child_pair_inventory();
    let keys = index
        .files
        .keys()
        .filter(|key| {
            inventory.contains(&crate::durable_tail_store::key_digest(
                crate::durable_tail_store::DurableSource::Codex,
                key,
            ))
        })
        .cloned()
        .collect::<Vec<_>>();
    for key in keys {
        if index.codex_child_pair_reading.contains_key(&key)
            || !cache.durable_child_pair_candidate(&key, index, metadata)
        {
            continue;
        }
        let entry = &index.files[&key];
        cache.durable_child_pair_count(0, 1);
        cache.durable_child_pair_count(1, entry.size_bytes);
        if index.codex_child_pair_reading.len() >= crate::transcript_cache::CACHE_ENTRIES
            || ledger_byte_bound(&index.codex_child_pair_reading)
                .and_then(|bytes| {
                    bytes.checked_add(reading_byte_bound(&key, &entry.source_file_fingerprint)?)
                })
                .map_or(true, |bytes| bytes > MAX_LEDGER_BYTES)
        {
            cache.durable_child_pair_defer(&key, entry.size_bytes);
            continue; // negative custody is never evicted to admit a new key
        }
        if !cache.durable_child_pair_admit(&key, entry.size_bytes) {
            continue; // unstamped; a later process can select this candidate
        }
        index.codex_child_pair_reading.insert(
            key,
            Reading {
                stamp: Stamp::Pending {
                    attempts: 0,
                    retry_after: now,
                    running: false,
                },
                source_file_fingerprint: entry.source_file_fingerprint.clone(),
                reserved_extent: entry.size_bytes,
                spent_bytes: 0,
                reserved_at: 0,
            },
        );
    }
}

pub(super) fn pending(index: &ScanIndex, key: &str) -> bool {
    matches!(stamp(index, key), Some(Stamp::Pending { .. }))
}

pub(super) fn waiting(index: &ScanIndex, key: &str, now: u64) -> bool {
    matches!(stamp(index, key), Some(Stamp::Pending { retry_after, running: false, .. }) if retry_after > now)
}

/// Force only negative spend into the committed index. Never publish working
/// scan entries, body witnesses, census or ACK state ahead of their owner.
/// Any failure (including an ambiguous post-rename fsync) denies this read.
pub(super) fn reserve(
    index: &mut ScanIndex,
    key: &str,
    extent: u64,
    path: &Path,
    now: u64,
) -> bool {
    reserve_many(index, &[(key.to_owned(), extent)], path, now)
}

fn reserve_many(index: &mut ScanIndex, requests: &[(String, u64)], path: &Path, now: u64) -> bool {
    if requests.is_empty() {
        return false;
    }
    let Ok(file) = File::open(path) else {
        return false;
    };
    let Ok(mut committed) = lenient_decode::read_file(file, "child_rederive_reservation", "codex")
    else {
        return false;
    };
    if committed.generation != index.generation {
        return false;
    }
    // A group obtains all negative reservations in one save. A refused member
    // cannot strand another member's running grant without a RAM owner.
    let mut reservations = BTreeMap::new();
    for (key, extent) in requests {
        let Some(reading) = index.codex_child_pair_reading.get(key) else {
            return false;
        };
        let Stamp::Pending {
            attempts,
            retry_after,
            running,
        } = reading.stamp
        else {
            return false;
        };
        if running
            || attempts >= MAX_ATTEMPTS
            || retry_after > now
            || *extent > reading.reserved_extent
            || reservations.contains_key(key)
            || committed
                .files
                .get(key)
                .map(|entry| &entry.source_file_fingerprint)
                != Some(&reading.source_file_fingerprint)
            || committed
                .files
                .get(key)
                .map(|entry| &entry.source_file_fingerprint)
                != index
                    .files
                    .get(key)
                    .map(|entry| &entry.source_file_fingerprint)
        {
            return false;
        }
        let mut reservation = reading.clone();
        reservation.stamp = Stamp::Pending {
            attempts: attempts + 1,
            retry_after,
            running: true,
        };
        reservation.reserved_at = now;
        reservation.spent_bytes = reservation.spent_bytes.saturating_add(*extent);
        reservations.insert(key.clone(), reservation);
    }
    // Carry prior negative custody without publishing unACKed scan state.
    for (key, reading) in &index.codex_child_pair_reading {
        committed
            .codex_child_pair_reading
            .entry(key.clone())
            .or_insert_with(|| reading.clone());
    }
    for (key, reading) in &reservations {
        committed
            .codex_child_pair_reading
            .insert(key.clone(), reading.clone());
    }
    let spent = committed
        .codex_child_pair_reading
        .values()
        .try_fold(0_u64, |sum, record| sum.checked_add(record.spent_bytes));
    if !valid_ledger(&committed.codex_child_pair_reading)
        || spent.map_or(true, |spent| spent > MAX_SPENT_BYTES)
        || committed.save(path).is_err()
    {
        return false;
    }
    index.generation = committed.generation;
    index.codex_child_pair_reading.extend(reservations);
    true
}

pub(super) fn holds_item(index: &ScanIndex, item: &SnapshotItem) -> bool {
    index.codex_child_pair_reading.iter().any(|(key, reading)| {
        reading.stamp == Stamp::CrashHeld
            && index.files.get(key).is_some_and(|entry| {
                item.source_file_fingerprint.as_deref()
                    == Some(entry.source_file_fingerprint.as_str())
            })
    })
}

// JSON escaping takes at most six bytes per input byte; 256 covers every
// fixed field name, enum tag, punctuation and maximal integer in a Reading.
// This conservative price keeps every emitted map below the decoder's span
// ceiling without allocating another encoded ledger just to admit a key.
fn reading_byte_bound(key: &str, fingerprint: &str) -> Option<usize> {
    key.len()
        .checked_add(fingerprint.len())?
        .checked_mul(6)?
        .checked_add(256)
}
fn ledger_byte_bound(ledger: &BTreeMap<String, Reading>) -> Option<usize> {
    ledger.iter().try_fold(2_usize, |bytes, (key, reading)| {
        bytes.checked_add(reading_byte_bound(key, &reading.source_file_fingerprint)?)
    })
}

pub(super) fn valid_ledger(ledger: &BTreeMap<String, Reading>) -> bool {
    ledger.len() <= crate::transcript_cache::CACHE_ENTRIES
        && ledger_byte_bound(ledger).is_some_and(|bytes| bytes <= MAX_LEDGER_BYTES)
        && ledger.iter().all(|(key, reading)| {
            let attempts = match reading.stamp {
                Stamp::Pending { attempts, .. } => attempts,
                _ => MAX_ATTEMPTS,
            };
            !key.is_empty()
                && key.len() <= 8192
                && !reading.source_file_fingerprint.is_empty()
                && reading.source_file_fingerprint.len() <= 256
                && attempts <= MAX_ATTEMPTS
                && reading.reserved_extent <= MAX_BYTES
                && reading.spent_bytes
                    <= reading.reserved_extent.saturating_mul(u64::from(attempts))
        })
}

pub(super) fn full_reason(
    index: &ScanIndex,
    key: &str,
) -> crate::transcript_acquisition::FullReason {
    use crate::transcript_acquisition::FullReason;
    if matches!(stamp(index, key), Some(Stamp::Pending { attempts: 2, .. })) {
        FullReason::CodexChildRederiveCrashRetry
    } else {
        FullReason::CodexChildRederiveFirst
    }
}

#[cfg(unix)]
pub(super) fn reserve_cached(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    cache: &sampled_scan::SharedCache,
) -> bool {
    let key = local_index_key(&candidate.path);
    let Some(path) = cache.durable_child_pair_index_path() else {
        return false;
    };
    if !cache.durable_child_pair_admit(
        &key,
        index
            .files
            .get(&key)
            .map_or(candidate.size_bytes, |entry| entry.size_bytes),
    ) {
        return false;
    }
    if !reserve(
        index,
        &key,
        candidate.size_bytes,
        &path,
        sampled_scan::now_seconds(),
    ) {
        return false;
    }
    cache.durable_child_pair_full(matches!(
        stamp(index, &key),
        Some(Stamp::Pending { attempts: 2, .. })
    ));
    true
}

#[cfg(unix)]
pub(super) fn reserve_group_cached(
    index: &mut ScanIndex,
    members: &[CandidateFile],
    cache: &sampled_scan::SharedCache,
) -> bool {
    let Some(path) = cache.durable_child_pair_index_path() else {
        return false;
    };
    if !group_allowed(index, members) {
        return false;
    }
    let requests = members
        .iter()
        .map(|member| (local_index_key(&member.path), member.size_bytes))
        .collect::<Vec<_>>();
    if requests
        .iter()
        .any(|(key, extent)| !cache.durable_child_pair_admit(key, *extent))
        || !reserve_many(index, &requests, &path, sampled_scan::now_seconds())
    {
        return false;
    }
    for (key, _) in requests {
        cache.durable_child_pair_full(matches!(
            stamp(index, &key),
            Some(Stamp::Pending { attempts: 2, .. })
        ));
    }
    true
}

/// Only real I/O failure calls this. Busy/setup refusal preserves its grant.
pub(super) fn failed(index: &mut ScanIndex, key: &str, now: u64) -> bool {
    let Some(reading) = index.codex_child_pair_reading.get_mut(key) else {
        return false;
    };
    let Stamp::Pending {
        attempts,
        running: true,
        ..
    } = reading.stamp
    else {
        return false;
    };
    if attempts >= MAX_ATTEMPTS {
        reading.stamp = Stamp::Unreadable;
        true
    } else {
        reading.stamp = Stamp::Pending {
            attempts,
            running: false,
            retry_after: now.saturating_add(2),
        };
        false
    }
}

pub(super) fn outcome(
    index: &ScanIndex,
    key: &str,
    snapshots: &[SnapshotItem],
    complete: bool,
    conflicted: bool,
) -> Option<Stamp> {
    if !matches!(stamp(index, key), Some(Stamp::Pending { .. })) {
        return None;
    }
    Some(if !complete {
        Stamp::Incomplete
    } else if conflicted {
        Stamp::Conflict
    } else if snapshots.iter().any(|item| {
        item.session_account_evidence
            .as_ref()
            .is_some_and(|evidence| {
                evidence.account_identifier_hash.is_some()
                    && evidence.provider_workspace_hash.is_some()
            })
    }) {
        Stamp::Named
    } else {
        Stamp::Incomplete
    })
}

/// A debt-free prefix is not necessarily a verified Full of the current
/// file. Reuse the checkpoint's shared content-stamp and clock witnesses.
pub(super) fn verified_full_current(
    checkpoint: &crate::transcript_acquisition::Checkpoint,
    file: &File,
    now: u64,
) -> bool {
    checkpoint.audit_debt().is_none()
        && checkpoint.last_full_verified() <= now
        && checkpoint.stamp_matches(file).unwrap_or(false)
}

pub(super) fn retire(index: &mut ScanIndex, key: &str, stamp: Stamp) -> bool {
    let Some(reading) = index.codex_child_pair_reading.get_mut(key) else {
        return false;
    };
    if !matches!(reading.stamp, Stamp::Pending { .. }) {
        return false;
    }
    reading.stamp = stamp;
    true
}

pub(super) fn finish(index: &mut ScanIndex, key: &str, stamp: Stamp, _verified: bool) {
    // Terminal credit never satisfies, creates or retires #865 debt.
    retire(index, key, stamp);
}

#[cfg(test)]
pub(super) fn put_stamp(index: &mut ScanIndex, key: &str, stamp: Stamp) {
    let entry = &index.files[key];
    index.codex_child_pair_reading.insert(
        key.to_owned(),
        Reading {
            stamp,
            source_file_fingerprint: entry.source_file_fingerprint.clone(),
            reserved_extent: entry.size_bytes,
            spent_bytes: 0,
            reserved_at: 0,
        },
    );
}

#[cfg(unix)]
pub(super) fn outcome_slot(stamp: Stamp) -> Option<usize> {
    match stamp {
        Stamp::Named => Some(2),
        Stamp::Conflict => Some(3),
        Stamp::Incomplete => Some(4),
        Stamp::Unreadable => Some(5),
        Stamp::Pending { .. } | Stamp::CrashHeld => None,
    }
}

/// A retry delay belongs only to this repair. Compare the ordinary selector
/// ignoring only its Pending marker; every other cause keeps its priority.
/// Discovery has no opened-object fingerprint yet. Project only that missing
/// witness from the index, after requiring unchanged physical metadata. Natural
/// growth and every independent non-audit cause keep their ordinary path.
pub(super) fn repair_candidate(index: &ScanIndex, candidate: &CandidateFile) -> bool {
    let key = local_index_key(&candidate.path);
    let Some(entry) = index.files.get(&key) else {
        return false;
    };
    if entry.size_bytes != candidate.size_bytes
        || entry.modified_unix_seconds != candidate.modified_unix_seconds
        || entry
            .modified_unix_nanos
            .is_some_and(|nanos| nanos != candidate.modified_unix_nanos)
    {
        return false;
    }
    let mut projected = candidate.clone();
    projected.source_file_fingerprint = entry.source_file_fingerprint.clone();
    matches!(
        index.candidate_decision_with_repair_gate(
            &projected,
            sampled_scan::now_seconds(),
            true,
            true
        ),
        (CandidateDecision::Skip, _)
            | (CandidateDecision::Parse, Some(CandidateParseReason::Audit))
    )
}

pub(super) fn ordinary_decision(index: &ScanIndex, candidate: &CandidateFile) -> CandidateDecision {
    index
        .candidate_decision_with_repair_gate(candidate, sampled_scan::now_seconds(), true, true)
        .0
}

pub(super) fn delay_only_repair(index: &ScanIndex, candidate: &CandidateFile, now: u64) -> bool {
    waiting(index, &local_index_key(&candidate.path), now)
        && ordinary_decision(index, candidate) == CandidateDecision::Skip
}

/// Independent debt retains its real deadline. A repair grant requires EVERY
/// quiet member, regardless of other members' unrelated work or future debt.
pub(super) fn group_requires_repair(index: &ScanIndex, members: &[CandidateFile]) -> bool {
    members
        .iter()
        .any(|member| pending(index, &local_index_key(&member.path)))
        && members
            .iter()
            .all(|member| ordinary_decision(index, member) == CandidateDecision::Skip)
}

pub(super) fn group_allowed(index: &ScanIndex, members: &[CandidateFile]) -> bool {
    if !group_requires_repair(index, members) {
        return true;
    }
    members.iter().all(|member| {
        let key = local_index_key(&member.path);
        pending(index, &key) && !waiting(index, &key, sampled_scan::now_seconds())
    })
}

#[cfg(all(test, unix))]
#[path = "codex_child_pair_rederive_tests.rs"]
mod tests;
