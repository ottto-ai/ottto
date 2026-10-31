//! RF1 B1, Lead B ruling Q-B1 (b) (2026-10-31): the Claude stale start under a
//! settled contract. Machine-local opt-in using the support-directory sentinel
//! pattern of `claude_terminal_off_enabled`; absent marker means main policy.
//! No ScanIndex field, upload field or remote setting. Counts only.
//!
//! - Q3: an invalid family with no stored evidence whose every member is the
//!   exact revision its census record was parsed from in that family's window,
//!   with an ACKed head, behind a closed fence, is kept beside the carry: not
//!   re-read, credits nothing, stays invalid. A changed member or an open fence
//!   ends the keep at the next start.
//! - Sticky admission: an unfinished retry admission no longer forces the
//!   batch path; the whole carry is tried first and, when it fits, replaces
//!   the admission (every uncarried stale family is re-armed as on main).
//! - Q5: a complete census whose stored evidence is all from its own window,
//!   or empty/invalid, under the recorded contract clears the latch before the
//!   latch's full re-arm.
//! - GUARD: that completion retires no invalid or evidence-free pending; it
//!   stays owed until a valid proof.
use super::*;

pub(super) const NAME: &str = "claude_settled_contract_carry_enabled";

pub(super) fn enabled() -> bool {
    #[cfg(test)]
    {
        // A test opts in on its own thread, never reading the host setting.
        ENABLED.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        // Pinned per process; the owner changes the marker and restarts.
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| {
            terminal_off_policy::marker_at(&ottto_core::default_support_dir(), NAME)
        })
    }
}

#[cfg(test)]
thread_local! {
    static ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(super) struct SettledContractCarryForTest(bool, std::marker::PhantomData<std::rc::Rc<()>>);
#[cfg(test)]
impl SettledContractCarryForTest {
    pub(super) fn enabled() -> Self {
        Self(
            ENABLED.with(|slot| slot.replace(true)),
            std::marker::PhantomData,
        )
    }
}
#[cfg(test)]
impl Drop for SettledContractCarryForTest {
    fn drop(&mut self) {
        ENABLED.with(|slot| slot.set(self.0));
    }
}

fn evidence_free(pending: &ClaudeUsageFamilyPending) -> bool {
    pending.member_occurrences.is_empty()
        && pending
            .member_request_id_hashes
            .values()
            .all(BTreeSet::is_empty)
}

/// Q3: stale invalid families a re-read cannot change. Returns the kept roots
/// and their indexed member count. Borrowed keys only; no proof is granted.
pub(super) fn kept_invalid_roots(
    index: &ScanIndex,
    stale: &BTreeSet<String>,
) -> (BTreeSet<String>, usize) {
    if !index.persistence_available() || !index.claude_duplicate_request_witness_overflowed {
        return (BTreeSet::new(), 0);
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
            .then_some((root.as_str(), (window, 0_usize, true)))
        })
        .collect::<BTreeMap<_, _>>();
    if families.is_empty() {
        return (BTreeSet::new(), 0);
    }
    for (key, entry) in &index.files {
        let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
            continue;
        };
        let Some((window, members, kept)) = families.get_mut(member.root) else {
            continue;
        };
        *members += 1;
        *kept = *kept
            && !entry.source_file_fingerprint.is_empty()
            && !index.claude_account_deferred_holds.contains_key(key)
            && !index.effective_upload_body_witness_revision_requires_adoption(key)
            && claude_stale_member_independently_accepted(index, key, entry)
            && index
                .claude_request_census
                .retry_carry_record(key)
                .is_some_and(|record| record.reproduces(&entry.source_file_fingerprint, *window));
    }
    let mut files = 0_usize;
    let roots = families
        .into_iter()
        .filter(|(_, (_, members, kept))| *kept && *members > 0)
        .map(|(root, (_, members, _))| {
            files = files.saturating_add(members);
            root.to_owned()
        })
        .collect();
    (roots, files)
}

/// Q5: every stored evidence set is from this census window, or there is none.
pub(super) fn evidence_from_window(index: &ScanIndex, census_window_end: &str) -> bool {
    index.claude_usage_family_pending.values().all(|pending| {
        pending.invalid || evidence_free(pending) || pending.census_window_end == census_window_end
    })
}

/// GUARD: an indexed family whose pending is invalid or evidence-free stays
/// owed at a complete census; only families that may hold proof retire.
pub(super) fn owed_at_completion(
    root_session_id: &str,
    pending: &ClaudeUsageFamilyPending,
    indexed_claude_family_ids: &BTreeSet<String>,
) -> bool {
    (pending.invalid || evidence_free(pending))
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
    /// [off=main] Default OFF; only a local regular marker enables.
    #[test]
    fn settled_contract_carry_defaults_off_and_only_local_regular_marker_enables() {
        let scratch = crate::test_scratch::ScratchDir::new("settled-contract-carry-policy");
        assert!(!terminal_off_policy::marker_at(&scratch, NAME));
        std::fs::write(scratch.join(NAME), b"").unwrap();
        assert!(terminal_off_policy::marker_at(&scratch, NAME));
        assert!(!enabled(), "fixture process never consults host marker");
        let guard = SettledContractCarryForTest::enabled();
        assert!(enabled());
        assert!(!std::thread::spawn(enabled).join().unwrap());
        drop(guard);
        assert!(!enabled());
    }
}
