//! AR1 R1 (Lead B ruling 1, 2026-10-31): a Claude census re-arm keeps the
//! file's fingerprint and marks its request evidence owed
//! (`ScanIndexEntry::evidence_owed`) instead of clearing the fingerprint.
//! Machine-local opt-in marker `claude_evidence_owed_enabled` (#977
//! `local_switch!`); absent marker = main (the re-arm clears).
//!
//! The traversal resolves an owed, unchanged member at selection:
//! - (a) its stored occurrences are bound to this revision: re-stamp them into
//!   the current census window, no read (Lead B ruling 1 conditions a-d);
//! - (c) cap-invalid family, unchanged, its occurrences still do not fit:
//!   stays owed, no read, no credit (Lead B Q3, RF1 #992 KeepOwedNoCredit);
//! - otherwise one counted `Rearmed` parse; with the fingerprint kept the
//!   existing RAM/durable restore may serve it (b), else it reads Full (d).
//!
//! GUARD (RF1 #992, folded here): census completion retires only families
//! with a completed family proof; every other indexed family stays owed.
//!
//! Real invalidations keep main's clear: a traversal context change, an audit
//! cap delay, an unACKed head re-offer and every non-re-arm clear site.
use super::*;

super::terminal_off_policy::local_switch!(
    "claude_evidence_owed_enabled",
    marker_enables = true,
    test_default = false
);
#[cfg(test)]
pub(super) struct EvidenceOwedForTest {
    _switch: super::terminal_off_policy::ThreadSwitchForTest,
}
#[cfg(test)]
impl EvidenceOwedForTest {
    pub(super) fn on() -> Self {
        Self {
            _switch: super::terminal_off_policy::ThreadSwitchForTest::set(&ENABLED, true),
        }
    }
}

/// ON: this re-arm cause owes evidence instead of clearing the fingerprint.
/// A context change and an audit cap delay owe a real re-read.
pub(crate) fn owes(cause: rearm_cause::Cause) -> bool {
    enabled()
        && matches!(
            cause,
            rearm_cause::Cause::NoRetainedTraversal
                | rearm_cause::Cause::TerminalUnhealthyRetry
                | rearm_cause::Cause::CarryInvalidation
        )
}

/// B-P2 under ON: an unACKed head is a real invalidation; it keeps main's
/// cleared fingerprint, never an owed one.
pub(super) fn reoffer_clears(entry: &mut ScanIndexEntry) {
    if entry.evidence_owed {
        entry.evidence_owed = false;
        entry.source_file_fingerprint.clear();
    }
}

/// A reverted (held) entry keeps the working entry's re-arm debt: main clears
/// the fingerprint, an owed working entry marks the retained one owed.
pub(super) fn carry_debt(retained: &mut ScanIndexEntry, working: &ScanIndexEntry) {
    if working.source_file_fingerprint.is_empty() {
        retained.source_file_fingerprint.clear();
    } else if working.evidence_owed {
        retained.evidence_owed = true;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Arm {
    KeptOwed,
    Read,
}

/// Per page: one decision per family, and the pending occurrence count the
/// cap-room rule admits against.
pub(super) struct Page {
    pub(super) families: BTreeMap<String, Arm>,
    pub(super) retained: Option<usize>,
    /// The pending occurrence cap a kept family's re-read must fit.
    pub(super) cap: usize,
}
impl Default for Page {
    fn default() -> Self {
        Self {
            families: BTreeMap::new(),
            retained: None,
            cap: MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        }
    }
}

fn evidence_free(pending: &ClaudeUsageFamilyPending) -> bool {
    pending.member_occurrences.is_empty()
        && pending
            .member_request_id_hashes
            .values()
            .all(BTreeSet::is_empty)
}

/// RF1 #992 KeepOwedNoCredit, per member: cap-invalid family, no stored
/// evidence, no authority quarantine or decode hold, and this exact revision
/// is the one its census record reproduced in the family's window, with an
/// ACKed head.
fn kept_member(
    index: &ScanIndex,
    key: &str,
    entry: &ScanIndexEntry,
    root: &str,
    pending: &ClaudeUsageFamilyPending,
) -> bool {
    let Some(window) = rfc3339_unix_seconds(&pending.census_window_end) else {
        return false;
    };
    index.persistence_available()
        && index.claude_duplicate_request_witness_overflowed
        && pending.invalid
        && evidence_free(pending)
        && !index.claude_usage_authority_quarantine.contains_key(root)
        && !index.decode_holds_family(root)
        && !index.claude_account_deferred_holds.contains_key(key)
        && !index.effective_upload_body_witness_revision_requires_adoption(key)
        && claude_stale_member_independently_accepted(index, key, entry)
        && index
            .claude_request_census
            .retry_carry_record(key)
            .is_some_and(|record| record.reproduces(&entry.source_file_fingerprint, window))
}

/// The indexed members of `root`'s family, by one ordered range from the
/// selected member's key: `<dir>/<root>.jsonl` and `<dir>/<root>/subagents/..`
/// share the `<dir>/<root>` prefix. Never a whole-index pass per family.
fn family<'a>(
    index: &'a ScanIndex,
    key: &'a str,
    root: &'a str,
) -> impl Iterator<Item = (&'a String, &'a ScanIndexEntry)> + 'a {
    let prefix = key
        .strip_suffix(".jsonl")
        .filter(|stem| stem.ends_with(root) && stem[..stem.len() - root.len()].ends_with('/'))
        .or_else(|| {
            let at = key.rfind(&format!("/{root}/subagents/"))?;
            Some(&key[..at + 1 + root.len()])
        })
        .unwrap_or(key);
    index
        .files
        .range::<str, _>((
            std::ops::Bound::Included(prefix),
            std::ops::Bound::Unbounded,
        ))
        .take_while(move |(other, _)| other.starts_with(prefix))
        .filter(move |(other, _)| {
            claude_index_path_member_ref(Path::new(other.as_str()))
                .is_some_and(|member| member.root == root)
        })
}

/// Lead B Q1 cap room: the family's recorded requests fit the pending
/// occurrence cap after what is already retained; admitted in selection order.
fn cap_room(index: &ScanIndex, page: &mut Page, key: &str, root: &str) -> bool {
    let retained = *page.retained.get_or_insert_with(|| {
        index
            .claude_usage_family_pending
            .values()
            .flat_map(|pending| pending.member_occurrences.values())
            .map(BTreeMap::len)
            .fold(0_usize, usize::saturating_add)
    });
    let requests = family(index, key, root)
        .filter_map(|(key, _)| index.claude_request_census.retry_carry_record(key))
        .map(|record| record.request_hashes().len())
        .fold(0_usize, usize::saturating_add);
    match claude_pending_occurrence_count_after_replace(retained, 0, requests, page.cap) {
        Some(next) => {
            page.retained = Some(next);
            true
        }
        None => false,
    }
}

/// The traversal's selection of one candidate (`decision`, `reason` already
/// decided by `candidate_decision_in_window`). Only an owed entry changes.
pub(super) fn resolve(
    index: &mut ScanIndex,
    page: &mut Page,
    candidate: &CandidateFile,
    census_window_end: &str,
    decision: &mut CandidateDecision,
    reason: &mut Option<CandidateParseReason>,
) {
    let key = local_index_key(&candidate.path);
    let Some(entry) = index.files.get(&key).filter(|entry| entry.evidence_owed) else {
        return;
    };
    let family = claude_index_path_family_member(&candidate.path);
    if entry.source_file_fingerprint != candidate.source_file_fingerprint {
        // A real change parses fresh evidence, never against its carried copy.
        if let Some((root, member)) = family.filter(|_| enabled()) {
            if let Some(pending) = index
                .claude_usage_family_pending
                .get_mut(&root)
                .filter(|pending| pending.census_window_end == census_window_end)
            {
                pending.member_occurrences.remove(&member);
                pending.member_request_id_hashes.remove(&member);
            }
        }
        return;
    }
    if *decision != CandidateDecision::Skip {
        // Otherwise selected: the parse records a fresh entry.
        return;
    }
    if let Some((root, member)) = family.filter(|_| enabled()) {
        if restamp(index, &key, &root, &member, census_window_end) {
            if let Some(entry) = index.files.get_mut(&key) {
                entry.evidence_owed = false;
            }
            return;
        }
    }
    let Some(entry) = index.files.get(&key) else {
        return;
    };
    let member = claude_index_path_member_ref(&candidate.path).map(|member| member.root);
    let kept = enabled()
        && member.is_some_and(|root| {
            index
                .claude_usage_family_pending
                .get(root)
                .is_some_and(|pending| kept_member(index, &key, entry, root, pending))
        });
    let arm = match member.filter(|_| kept) {
        // Left by an ON process (switch now OFF), or not kept: main's debt.
        None => Arm::Read,
        Some(root) => match page.families.get(root) {
            Some(arm) => *arm,
            None => {
                let arm = if cap_room(index, page, &key, root) {
                    Arm::Read
                } else {
                    Arm::KeptOwed
                };
                page.families.insert(root.to_owned(), arm);
                arm
            }
        },
    };
    if arm == Arm::Read {
        *decision = CandidateDecision::Parse;
        *reason = Some(CandidateParseReason::Rearmed);
    }
}

/// (a) Lead B ruling 1 (2026-10-31): an unchanged member's stored occurrences
/// count as an observation in this census window, no read, only when
/// (a) the fingerprint is unchanged (the caller), (b) the scan identity and
/// request-identity contracts are unchanged since storage, (c) the stored
/// occurrences are valid and are exactly the request ids its current census
/// record read at this revision, and (d) only window membership moves: the
/// family's stored evidence is stamped with this window, nothing else.
/// A stale family moves only while every other member with stored evidence
/// is still owed: each is verified at its own selection, and owed members
/// stay unobserved for fence coverage until then.
fn restamp(index: &mut ScanIndex, key: &str, root: &str, member: &str, window: &str) -> bool {
    let (Some(entry), Some(pending)) = (
        index.files.get(key),
        index.claude_usage_family_pending.get(root),
    ) else {
        return false;
    };
    let bound = !index.claude_request_identity_contract_changed
        && entry.scan_identity_version.as_deref() == Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
        && !pending.invalid
        && pending
            .member_occurrences
            .get(member)
            .zip(pending.member_request_id_hashes.get(member))
            .is_some_and(|(occurrences, hashes)| {
                occurrences.keys().eq(hashes.iter())
                    && index.claude_request_census.get(key).is_some_and(|record| {
                        record.current_for(&entry.source_file_fingerprint)
                            && record_hashes(hashes).as_deref() == Some(record.request_hashes())
                    })
            });
    if !bound {
        return false;
    }
    if pending.census_window_end != window {
        let others_owed = family(index, key, root).all(|(other, entry)| {
            other == key
                || entry.evidence_owed
                || claude_index_path_family_member(Path::new(other))
                    .is_some_and(|(_, other)| !pending.member_occurrences.contains_key(&other))
        });
        if !others_owed {
            return false;
        }
        if let Some(pending) = index.claude_usage_family_pending.get_mut(root) {
            pending.census_window_end = window.to_owned();
        }
    }
    true
}

/// Pending keys request ids by full SHA-256 hex; a census record keeps the
/// sorted 8-byte prefixes (`claude_request_hash`).
fn record_hashes(hashes: &BTreeSet<String>) -> Option<Vec<u64>> {
    let mut prefixes = hashes
        .iter()
        .map(|hash| u64::from_str_radix(hash.get(..16)?, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    prefixes.sort_unstable();
    prefixes.dedup();
    Some(prefixes)
}

/// The admission drop (RF1 #992 rev F2): an unfinished admission still owes
/// due paths its existing selector has not offered.
pub(super) fn due_unoffered(
    index: &ScanIndex,
    state: &ClaudeRetryAdmission,
    collected_at: &str,
) -> bool {
    let now = rfc3339_unix_seconds(collected_at).unwrap_or_default();
    index
        .files
        .keys()
        .any(|key| claude_retry_path_due(state, &index.claude_usage_authority_quarantine, key, now))
}

/// Only the due cursor stays: the root walk is settled, no root is carried.
/// It completes when that service finishes; the next start then drops it.
pub(super) fn due_only(state: &ClaudeRetryAdmission) -> ClaudeRetryAdmission {
    ClaudeRetryAdmission {
        after_root: Some(state.upper_root.clone()),
        roots_complete: true,
        complete: false,
        progressed: false,
        oversized_root: None,
        oversized_after_path: None,
        storage_deferred: false,
        ..state.clone()
    }
}

/// GUARD: an indexed family this census did not prove stays owed; only a
/// completed family proof retires pending.
pub(super) fn owed_at_completion(
    root_session_id: &str,
    pending: &ClaudeUsageFamilyPending,
    proven: bool,
    indexed_claude_family_ids: &BTreeSet<String>,
) -> bool {
    !proven
        && (indexed_claude_family_ids.contains(root_session_id)
            || pending
                .member_request_id_hashes
                .keys()
                .chain(pending.member_occurrences.keys())
                .any(|member| indexed_claude_family_ids.contains(member)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> ScanIndexEntry {
        serde_json::from_value(serde_json::json!({
            "size_bytes": 1, "modified_unix_seconds": 2,
            "source_file_fingerprint": "revision", "last_snapshot_fingerprint": null
        }))
        .unwrap()
    }

    /// [off=main] Default OFF: only a local regular marker enables it, and an
    /// OFF re-arm clears the fingerprint exactly as main, owing nothing.
    #[test]
    fn switch_defaults_off_and_off_rearm_clears_like_main() {
        let scratch = crate::test_scratch::ScratchDir::new("evidence-owed-policy");
        let marker = scratch.join("claude_evidence_owed_enabled");
        assert!(!enabled_at(&scratch));
        std::fs::write(&marker, b"").unwrap();
        assert!(enabled_at(&scratch));
        std::fs::remove_file(&marker).unwrap();
        std::fs::create_dir(&marker).unwrap();
        assert!(!enabled_at(&scratch));
        assert!(!enabled(), "fixture process never consults host marker");
        for cause in [
            rearm_cause::Cause::NoRetainedTraversal,
            rearm_cause::Cause::TerminalUnhealthyRetry,
            rearm_cause::Cause::CarryInvalidation,
        ] {
            let mut off = entry();
            rearm_cause::clear("/k.jsonl", &mut off, cause);
            assert!(off.source_file_fingerprint.is_empty() && !off.evidence_owed);
            let _on = EvidenceOwedForTest::on();
            let mut on = entry();
            rearm_cause::clear("/k.jsonl", &mut on, cause);
            assert_eq!(
                (on.source_file_fingerprint.as_str(), on.evidence_owed),
                ("revision", true)
            );
            assert!(on.rearmed());
        }
        let _on = EvidenceOwedForTest::on();
        for cause in [
            rearm_cause::Cause::ContextChanged,
            rearm_cause::Cause::AuditCapDelay,
        ] {
            let mut real = entry();
            rearm_cause::clear("/k.jsonl", &mut real, cause);
            assert!(real.source_file_fingerprint.is_empty() && !real.evidence_owed);
        }
    }

    /// [format] An index written before the field decodes not owed and
    /// re-encodes byte-identically; an owed entry round-trips.
    #[test]
    fn evidence_owed_is_downgrade_safe_and_round_trips() {
        let old = serde_json::to_vec(&entry()).unwrap();
        let decoded: ScanIndexEntry = serde_json::from_slice(&old).unwrap();
        assert!(!decoded.evidence_owed);
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), old);
        let mut owed = entry();
        owed.evidence_owed = true;
        let bytes = serde_json::to_vec(&owed).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["evidence_owed"], true);
        assert_eq!(value["source_file_fingerprint"], "revision");
        let back: ScanIndexEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(back.evidence_owed && back.rearmed());
    }
}
