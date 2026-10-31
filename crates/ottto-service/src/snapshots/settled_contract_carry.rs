//! RF1 B1, Lead B ruling Q-B1 (b) (2026-10-31): the Claude stale start under a
//! settled contract. Machine-local opt-in through `pinned_marker`; absent
//! marker means main policy. No ScanIndex field, upload field or remote
//! setting. Counts only.
//!
//! - Q3 classifies each stale family once: Carry (the route's own carry),
//!   KeepOwedNoCredit or Reobserve. Kept: invalid, no stored evidence, closed
//!   fence, every member the exact revision its census record reproduces in
//!   the family's window with an ACKed head. Kept pending stays as it is:
//!   not re-read, not priced, credits nothing. A changed member or an open
//!   fence ends the keep; so does pending occurrence-cap room for its
//!   recorded requests after the start's clears (Lead B Q1).
//! - Sticky admission: an unfinished retry admission no longer forces the
//!   batch path; a whole carry that fits settles its root walk. Unoffered due
//!   service keeps the admission's due cursor until its owner serves it.
//! - Q5: a complete census whose stored evidence is all from its own window,
//!   or empty/invalid, under the recorded contract clears the latch before the
//!   latch's full re-arm.
//! - GUARD: that completion retires only families with a completed family
//!   proof; every other indexed family's pending stays owed.
use super::*;

const NAME: &str = "claude_settled_contract_carry_enabled";

/// ON: the pending occurrence cap a kept family's re-read must fit.
pub(super) fn policy() -> Option<usize> {
    injected().unwrap_or_else(|| {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        terminal_off_policy::pinned_marker(&ENABLED, NAME)
            .then_some(MAX_CLAUDE_PENDING_USAGE_OCCURRENCES)
    })
}

pub(super) fn enabled() -> bool {
    policy().is_some()
}

// No existing options seam reaches both the traversal start and the census
// fold, so a fixture injects the policy (ON and its cap) on its own thread.
#[cfg(test)]
thread_local! {
    static POLICY: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
/// A fixture's injected policy, never the host marker.
#[cfg(test)]
fn injected() -> Option<Option<usize>> {
    Some(POLICY.with(std::cell::Cell::get))
}
#[cfg(not(test))]
fn injected() -> Option<Option<usize>> {
    None
}
#[cfg(test)]
pub(super) struct SettledContractCarryForTest(
    Option<usize>,
    std::marker::PhantomData<std::rc::Rc<()>>,
);
#[cfg(test)]
impl SettledContractCarryForTest {
    pub(super) fn on(cap: usize) -> Self {
        Self(
            POLICY.with(|slot| slot.replace(Some(cap))),
            std::marker::PhantomData,
        )
    }
}
#[cfg(test)]
impl Drop for SettledContractCarryForTest {
    fn drop(&mut self) {
        POLICY.with(|slot| slot.set(self.0));
    }
}

fn evidence_free(pending: &ClaudeUsageFamilyPending) -> bool {
    pending.member_occurrences.is_empty()
        && pending
            .member_request_id_hashes
            .values()
            .all(BTreeSet::is_empty)
}

/// KeepOwedNoCredit per stale family, with (recorded requests, indexed
/// files). One pass over the index; borrowed keys; no proof is granted.
pub(super) fn kept_owed(
    index: &ScanIndex,
    stale: &BTreeSet<String>,
) -> BTreeMap<String, (usize, usize)> {
    if !index.persistence_available() || !index.claude_duplicate_request_witness_overflowed {
        return BTreeMap::new();
    }
    let mut families = stale
        .iter()
        .filter_map(|root| {
            let pending = index.claude_usage_family_pending.get(root)?;
            let window = rfc3339_unix_seconds(&pending.census_window_end)?;
            (pending.invalid
                && evidence_free(pending)
                && !index.claude_usage_authority_quarantine.contains_key(root)
                && !index.decode_holds_family(root))
            .then_some((root.as_str(), (window, 0_usize, 0_usize, true)))
        })
        .collect::<BTreeMap<_, _>>();
    for (key, entry) in &index.files {
        let Some((window, requests, files, kept)) = claude_index_path_member_ref(Path::new(key))
            .and_then(|member| families.get_mut(member.root))
        else {
            continue;
        };
        let record = index.claude_request_census.retry_carry_record(key);
        *files += 1;
        *requests = requests.saturating_add(record.map_or(0, |r| r.request_hashes().len()));
        *kept = *kept
            && !entry.source_file_fingerprint.is_empty()
            && !index.claude_account_deferred_holds.contains_key(key)
            && !index.effective_upload_body_witness_revision_requires_adoption(key)
            && claude_stale_member_independently_accepted(index, key, entry)
            && record.is_some_and(|r| r.reproduces(&entry.source_file_fingerprint, *window));
    }
    families
        .into_iter()
        .filter(|(_, (_, _, files, kept))| *kept && *files > 0)
        .map(|(root, (_, requests, files, _))| (root.to_owned(), (requests, files)))
        .collect()
}

/// Lead B Q1 (rev F3): after this start's clears, kept families whose recorded
/// requests fit `cap` under the accumulation's own count become Reobserve,
/// admitted in root order. Returns them; the rest stay kept.
pub(super) fn reobserve_with_cap_room(
    index: &ScanIndex,
    kept: &mut BTreeMap<String, (usize, usize)>,
    cap: usize,
) -> BTreeSet<String> {
    let mut retained = index
        .claude_usage_family_pending
        .values()
        .flat_map(|pending| pending.member_occurrences.values())
        .map(BTreeMap::len)
        .fold(0_usize, usize::saturating_add);
    let mut reobserve = BTreeSet::new();
    kept.retain(|root, (requests, _)| {
        let Some(next) = claude_pending_occurrence_count_after_replace(retained, 0, *requests, cap)
        else {
            return true;
        };
        retained = next;
        reobserve.insert(root.clone());
        false
    });
    reobserve
}

/// Rev F2: the admission still owes due paths its existing selector has not
/// offered (the same predicate `claude_retry_queue_due_families` serves).
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

/// The whole carry covered every root: only the due cursor stays owed. It
/// completes when that service finishes and the next start then drops it.
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

/// Q5: every stored evidence set is from this census window, or there is none.
pub(super) fn evidence_from_window(index: &ScanIndex, census_window_end: &str) -> bool {
    index.claude_usage_family_pending.values().all(|pending| {
        pending.invalid || evidence_free(pending) || pending.census_window_end == census_window_end
    })
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
