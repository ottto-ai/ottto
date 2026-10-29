//! One-time, bounded validation of pre-#896 cached child creator evidence.
//! This metadata selects a counted native Full; it never supplies account evidence.
use super::*;

#[cfg(unix)]
pub(super) const MAX_BYTES: u64 = 5_000_000_000;
const MAX_ATTEMPTS: u8 = 4; // initial attempt, then at most three retries

/// SOURCE class L: optional per-entry marker, no content or provider ids.
/// Pending is scheduling only; terminal variants never authorize a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stamp {
    Pending {
        attempts: u8,
        retry_after: u64,
        running: bool,
        previous_due: Option<u64>,
    },
    Named,
    Conflict,
    Incomplete,
    Unreadable,
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
                previous_due: _,
            }
            | Self::Named
            | Self::Conflict
            | Self::Incomplete
            | Self::Unreadable => c.add(0),
        }
    }
}

pub(super) fn deserialize_stamp<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Stamp>, D::Error> {
    let raw = Option::<Value>::deserialize(deserializer)?;
    // Unknown future state must not erase once-only credit or drop the entry.
    Ok(raw.map(|raw| serde_json::from_value(raw).unwrap_or(Stamp::Unreadable)))
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
    let abandoned = index
        .files
        .iter()
        .filter_map(|(key, entry)| {
            matches!(
                entry.codex_child_pair_rederive,
                Some(Stamp::Pending { running: true, .. })
            )
            .then_some(key)
        })
        .filter(|key| !cache.cursor_job_owns(key))
        .cloned()
        .collect::<Vec<_>>();
    for key in abandoned {
        if failed(index, &key, sampled_scan::now_seconds()) {
            cache.durable_child_pair_count(5, 1);
        }
    }
    let keys = index
        .files
        .iter()
        .filter_map(|(key, entry)| {
            if entry.codex_child_pair_rederive.is_some() {
                return None;
            }
            cache
                .durable_child_pair_candidate(key, index, metadata)
                .then(|| key.clone())
        })
        .collect::<Vec<_>>();
    let bytes: u128 = keys
        .iter()
        .map(|key| u128::from(index.files[key].size_bytes))
        .sum();
    cache.durable_child_pair_count(0, keys.len() as u64);
    cache.durable_child_pair_count(1, u64::try_from(bytes).unwrap_or(u64::MAX));
    if bytes > u128::from(MAX_BYTES) || cache.durable_child_pair_budget_stopped() {
        return;
    }
    let now = sampled_scan::now_seconds();
    for key in keys {
        let entry = index.files.get_mut(&key).expect("selected entry");
        entry.codex_child_pair_rederive = Some(Stamp::Pending {
            attempts: 0,
            retry_after: now,
            running: false,
            previous_due: entry.unverified_deadline(),
        });
    }
}

pub(super) fn pending(index: &ScanIndex, key: &str) -> bool {
    index.files.get(key).is_some_and(pending_entry)
}

pub(super) fn pending_entry(entry: &ScanIndexEntry) -> bool {
    matches!(entry.codex_child_pair_rederive, Some(Stamp::Pending { .. }))
}

pub(super) fn waiting(entry: &ScanIndexEntry, now: u64) -> bool {
    matches!(entry.codex_child_pair_rederive, Some(Stamp::Pending { retry_after, .. }) if retry_after > now && retry_after <= now.saturating_add(8))
}

pub(super) fn begin(index: &mut ScanIndex, key: &str, now: u64) -> bool {
    let Some(Stamp::Pending {
        attempts,
        retry_after,
        running,
        ..
    }) = index
        .files
        .get_mut(key)
        .and_then(|entry| entry.codex_child_pair_rederive.as_mut())
    else {
        return false;
    };
    if *retry_after > now && *retry_after <= now.saturating_add(8) {
        return false;
    }
    if !*running {
        *attempts = attempts.saturating_add(1);
        *running = true;
    }
    true
}

/// Preserve unrelated audit debt. Retiring a repair after a refused or lossy
/// read is not Full verification and must never call complete_full_audit.
fn retire(index: &mut ScanIndex, key: &str, stamp: Stamp) -> bool {
    let Some(entry) = index.files.get_mut(key) else {
        return false;
    };
    if !matches!(entry.codex_child_pair_rederive, Some(Stamp::Pending { .. })) {
        return false;
    }
    // The repair owns no audit debt. Failure must not clear or reschedule
    // the independent marker, including debt staged while this read ran.
    entry.codex_child_pair_rederive = Some(stamp);
    true
}

pub(super) fn failed(index: &mut ScanIndex, key: &str, now: u64) -> bool {
    let Some(Stamp::Pending {
        attempts,
        retry_after,
        running,
        ..
    }) = index
        .files
        .get_mut(key)
        .and_then(|entry| entry.codex_child_pair_rederive.as_mut())
    else {
        return false;
    };
    *running = false;
    if *attempts >= MAX_ATTEMPTS {
        return retire(index, key, Stamp::Unreadable);
    }
    *retry_after = now.saturating_add(1_u64 << u32::from(*attempts).min(3));
    false
}

pub(super) fn outcome(
    index: &ScanIndex,
    key: &str,
    snapshots: &[SnapshotItem],
    complete: bool,
    conflicted: bool,
) -> Option<Stamp> {
    if !matches!(
        index.files.get(key)?.codex_child_pair_rederive,
        Some(Stamp::Pending { .. })
    ) {
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

pub(super) fn finish(index: &mut ScanIndex, key: &str, stamp: Stamp, verified: bool) {
    if verified {
        if let Some(entry) = index.files.get_mut(key) {
            entry.codex_child_pair_rederive = Some(stamp);
        }
    } else {
        retire(index, key, stamp);
    }
}

pub(super) fn carry(retained: &mut ScanIndexEntry, working: &ScanIndexEntry) {
    if let Some(stamp) = working.codex_child_pair_rederive {
        if retained.source_file_fingerprint == working.source_file_fingerprint
            && !matches!(stamp, Stamp::Pending { .. })
        {
            retained.scan_identity_version = working.scan_identity_version.clone();
        }
        retained.codex_child_pair_rederive = Some(stamp);
    }
}

#[cfg(unix)]
pub(super) fn outcome_slot(stamp: Stamp) -> Option<usize> {
    match stamp {
        Stamp::Named => Some(2),
        Stamp::Conflict => Some(3),
        Stamp::Incomplete => Some(4),
        Stamp::Unreadable => Some(5),
        Stamp::Pending { .. } => None,
    }
}

/// A retry delay belongs only to this repair. Compare the ordinary selector
/// ignoring only its Pending marker; every other cause keeps its priority.
fn ordinary_decision(index: &ScanIndex, candidate: &CandidateFile) -> CandidateDecision {
    index
        .candidate_decision_with_repair_gate(candidate, sampled_scan::now_seconds(), true, true)
        .0
}

pub(super) fn delay_only_repair(index: &ScanIndex, candidate: &CandidateFile, now: u64) -> bool {
    let key = local_index_key(&candidate.path);
    index
        .files
        .get(&key)
        .is_some_and(|entry| waiting(entry, now))
        && ordinary_decision(index, candidate) == CandidateDecision::Skip
}

/// Existing joined custody may not broaden a physical-key repair grant.
/// Ordinary growth/context/adoption retains its original whole-group path.
pub(super) fn group_allowed(index: &ScanIndex, members: &[CandidateFile]) -> bool {
    let pending = |index: &ScanIndex, member: &CandidateFile| {
        matches!(
            index
                .files
                .get(&local_index_key(&member.path))
                .and_then(|entry| entry.codex_child_pair_rederive),
            Some(Stamp::Pending { .. })
        )
    };
    if !members.iter().any(|member| pending(index, member)) {
        return true;
    }
    if members
        .iter()
        .any(|member| ordinary_decision(index, member) != CandidateDecision::Skip)
    {
        return true;
    }
    members.iter().all(|member| {
        pending(index, member)
            && !index
                .files
                .get(&local_index_key(&member.path))
                .is_some_and(|entry| waiting(entry, sampled_scan::now_seconds()))
    })
}

#[cfg(all(test, unix))]
#[path = "codex_child_pair_rederive_tests.rs"]
mod tests;
