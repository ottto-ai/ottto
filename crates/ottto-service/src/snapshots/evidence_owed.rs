//! AR1 R1 (Lead B ruling 1, 2026-10-31): a Claude census re-arm keeps the
//! file's fingerprint and marks its request evidence owed
//! (`ScanIndexEntry::evidence_owed`) instead of clearing the fingerprint.
//! Machine-local opt-in marker; absent marker = main (the re-arm clears).
//! Switch -> `terminal_off::policy::local_switch!` once #977/#1004 is on main.
//!
//! The traversal resolves an owed, unchanged member at selection:
//! - (a) its stored occurrences are bound to this revision: re-stamp them into
//!   the current census window, no read (Lead B ruling 1 conditions a-d);
//! - (c) cap-invalid family, unchanged, its occurrences still do not fit:
//!   stays owed, no read, no credit (Lead B Q3, RF1 #992 KeepOwedNoCredit);
//! - otherwise one counted `Rearmed` parse; with the fingerprint kept the
//!   existing RAM/durable restore may serve it (b), else it reads Full (d).
//!
//! Real invalidations keep main's clear: a traversal context change, an audit
//! cap delay, an unACKed head re-offer and every non-re-arm clear site.
use super::*;

pub(super) const NAME: &str = "claude_evidence_owed_enabled";

pub(crate) fn enabled() -> bool {
    #[cfg(test)]
    {
        // A test must opt in on its own thread, never read the host setting.
        ENABLED.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        // Pin policy for this process, including worker threads and yields.
        // Ron changes the marker himself and restarts the daemon to apply it.
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| enabled_at(&ottto_core::default_support_dir()))
    }
}

fn enabled_at(support: &Path) -> bool {
    // The owner's local marker is the setting. Refuse symlinks and non-files.
    std::fs::symlink_metadata(support.join(NAME))
        .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
}

#[cfg(test)]
thread_local! {
    static ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) struct EvidenceOwedForTest(bool, std::marker::PhantomData<std::rc::Rc<()>>);
#[cfg(test)]
impl EvidenceOwedForTest {
    pub(crate) fn on() -> Self {
        Self(
            ENABLED.with(|slot| slot.replace(true)),
            std::marker::PhantomData,
        )
    }
}
#[cfg(test)]
impl Drop for EvidenceOwedForTest {
    fn drop(&mut self) {
        ENABLED.with(|slot| slot.set(self.0));
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
enum Arm {
    KeptOwed,
    Read,
}

/// Per page: one decision per family, and the pending occurrence count the
/// cap-room rule admits against.
#[derive(Default)]
pub(super) struct Page {
    families: BTreeMap<String, Arm>,
    retained: Option<usize>,
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

/// Lead B Q1 cap room: the family's recorded requests fit the pending
/// occurrence cap after what is already retained; admitted in selection order.
fn cap_room(index: &ScanIndex, page: &mut Page, root: &str) -> bool {
    let retained = *page.retained.get_or_insert_with(|| {
        index
            .claude_usage_family_pending
            .values()
            .flat_map(|pending| pending.member_occurrences.values())
            .map(BTreeMap::len)
            .fold(0_usize, usize::saturating_add)
    });
    let requests = index
        .files
        .keys()
        .filter(|key| {
            claude_index_path_member_ref(Path::new(key.as_str()))
                .is_some_and(|member| member.root == root)
        })
        .filter_map(|key| index.claude_request_census.retry_carry_record(key))
        .map(|record| record.request_hashes().len())
        .fold(0_usize, usize::saturating_add);
    match claude_pending_occurrence_count_after_replace(
        retained,
        0,
        requests,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    ) {
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
                let arm = if cap_room(index, page, root) {
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
        let others_owed = index.files.iter().all(|(other, entry)| {
            other == key
                || entry.evidence_owed
                || claude_index_path_member_ref(Path::new(other)).map_or(true, |m| m.root != root)
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
