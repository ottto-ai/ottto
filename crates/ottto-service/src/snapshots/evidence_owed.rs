//! Evidence owed: the Claude terminal-retry re-arm
//! (`TerminalUnhealthyRetry`) keeps the file's fingerprint and marks its
//! request evidence owed (`ScanIndexEntry::evidence_owed`) instead of
//! clearing the fingerprint. Every other re-arm cause clears it.
//!
//! The traversal resolves an owed, unchanged member at selection:
//! - (a) its stored occurrences are bound to this revision: re-stamp them into
//!   the current census window, no read; a confirmed-empty member whose
//!   current census record holds no requests re-stamps from that record;
//! - (c) cap-invalid family, unchanged, its occurrences still do not fit:
//!   stays owed, no read, no credit;
//! - otherwise one counted `Rearmed` parse, paced per page; with the
//!   fingerprint kept the existing RAM/durable restore may serve it (b), else
//!   it reads Full (d).
use super::*;

/// Only the terminal-retry re-arm owes evidence instead of clearing the
/// fingerprint.
pub(crate) fn owes(cause: rearm_cause::Cause) -> bool {
    cause == rearm_cause::Cause::TerminalUnhealthyRetry
}

/// The one keep-or-clear rule: `owe` keeps a known revision and owes it;
/// otherwise the fingerprint is cleared.
pub(crate) fn keep_or_clear(entry: &mut ScanIndexEntry, owe: bool) {
    if owe && !entry.source_file_fingerprint.is_empty() {
        entry.evidence_owed = true;
    } else {
        entry.source_file_fingerprint.clear();
    }
}

/// Whether `keep_or_clear(entry, owe)` would change `entry`.
fn keep_or_clear_changes(entry: &ScanIndexEntry, owe: bool) -> bool {
    if owe && !entry.source_file_fingerprint.is_empty() {
        !entry.evidence_owed
    } else {
        !entry.source_file_fingerprint.is_empty()
    }
}

/// A reverted (held) entry keeps the working entry's re-arm debt: a cleared
/// working entry clears it, an owed working entry marks it owed. Owed debt is
/// census-window debt only (a needed read clears the fingerprint), so the
/// retained entry may later re-stamp.
pub(super) fn carry_debt(retained: &mut ScanIndexEntry, working: &ScanIndexEntry) {
    if working.rearmed() {
        keep_or_clear(retained, !working.source_file_fingerprint.is_empty());
    }
}

/// Whether `carry_debt(retained, working)` would change `retained`.
pub(super) fn carry_debt_changes(retained: &ScanIndexEntry, working: &ScanIndexEntry) -> bool {
    working.rearmed()
        && keep_or_clear_changes(retained, !working.source_file_fingerprint.is_empty())
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
    /// Owed Fulls this page already admitted, and the one
    /// per-page cap. It reuses the existing paced re-read page allowance
    /// (`BODY_WITNESS_ADOPTION_ONLY_PARSES_PER_PAGE`); the rest wait in the
    /// walk's own queue for later pages.
    pub(super) reads: usize,
    pub(super) read_cap: usize,
}
impl Default for Page {
    fn default() -> Self {
        Self {
            families: BTreeMap::new(),
            retained: None,
            cap: MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            reads: 0,
            read_cap: BODY_WITNESS_ADOPTION_ONLY_PARSES_PER_PAGE,
        }
    }
}

/// The identity contract a pending was built under, as a bounded code plus
/// the body-witness revision the request-money adoption reads. No identity
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EvidenceContract {
    /// 0 = `""` (no permit), 1 = COLLECTOR, 2 = E2_GROUPING.
    c: u8,
    /// `active_effective_upload_body_witness_revision` at accumulation.
    bw: u64,
}
crate::heap_layout_bound::no_heap!(true; EvidenceContract);

impl EvidenceContract {
    /// The contract this cycle builds under, only while the index records
    /// that same real contract (never a placeholder, never unknown).
    pub(crate) fn current(index: &ScanIndex) -> Option<Self> {
        let cycle = claude_request_identity::cycle_contract(true);
        if index.claude_request_identity_contract.as_deref() != Some(cycle) {
            return None;
        }
        let c = match cycle {
            "" => 0,
            claude_request_identity::COLLECTOR => 1,
            claude_request_identity::E2_GROUPING => 2,
            _ => return None,
        };
        Some(Self {
            c,
            bw: index.active_effective_upload_body_witness_revision,
        })
    }
}

/// Accumulate `snapshots` into the index's pending and stamp each touched
/// family: the current contract only if its pending was empty before or
/// already carried that same stamp; otherwise `None` (mixed), so a stamp is
/// never laundered. A durable-tail
/// restore folds here as well: its record is keyed by the recorded contract
/// (`Interpretation::identity_contract`), so it was built under `current`.
pub(super) fn stamped<T>(
    index: &mut ScanIndex,
    snapshots: &[SnapshotItem],
    census_window_end: &str,
    accumulate: impl FnOnce(&mut ScanIndex) -> T,
) -> T {
    let roots = snapshots
        .iter()
        .map(claude_snapshot_family_root)
        .collect::<BTreeSet<_>>();
    stamp_families(index, roots, census_window_end, accumulate)
}

fn stamp_families<T>(
    index: &mut ScanIndex,
    roots: BTreeSet<String>,
    census_window_end: &str,
    accumulate: impl FnOnce(&mut ScanIndex) -> T,
) -> T {
    let current = EvidenceContract::current(index);
    let prior = roots
        .into_iter()
        .map(|root| {
            let before = index
                .claude_usage_family_pending
                .view(&root)
                .filter(|pending| pending.window() == census_window_end && !pending.evidence_free())
                .map(|pending| pending.identity_contract());
            (root, before)
        })
        .collect::<BTreeMap<_, _>>();
    let result = accumulate(index);
    for (root, before) in prior {
        // A pending this accumulation left in another window was not rebuilt:
        // its stamp is not touched.
        // An Unknown family accumulated nothing (the page refused): no stamp.
        if let Some(pending) = index
            .claude_usage_family_pending
            .family_mut(&root)
            .ok()
            .flatten()
            .filter(|pending| pending.census_window_end == census_window_end)
        {
            pending.identity_contract = match before {
                _ if pending.invalid || evidence_free(pending) => None,
                None => current,
                Some(stamp) if stamp.is_some() && stamp == current => current,
                Some(_) => None,
            };
        }
    }
    result
}

fn evidence_free(pending: &ClaudeUsageFamilyPending) -> bool {
    pending.member_occurrences.is_empty()
        && pending
            .member_request_id_hashes
            .values()
            .all(BTreeSet::is_empty)
}

/// Kept owed with no credit, per member: cap-invalid family, no stored
/// evidence, no authority quarantine or decode hold, no identity-contract
/// latch and a contract not left unproven by a latch clear (that member's
/// body is read under the current contract, paced, never kept waiting for cap
/// room), and this exact revision is the one its census record
/// reproduced in the family's window, with an ACKed head.
fn kept_member(
    index: &ScanIndex,
    key: &str,
    entry: &ScanIndexEntry,
    root: &str,
    pending: super::usage_pending::UsageView<'_>,
) -> bool {
    let Some(window) = rfc3339_unix_seconds(pending.window()) else {
        return false;
    };
    index.persistence_available()
        && index.claude_duplicate_request_witness_overflowed
        && pending.invalid()
        && pending.evidence_free()
        && !pending.contract_unproven()
        && !index.claude_request_identity_contract_changed
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

/// The indexed members of `root`'s family, by one ordered range over the
/// `<dir>/<root>` prefix its members share (`FamilyRef`). Never a whole-index
/// pass per family. `None`: the prefix cannot be derived, so the family is
/// unknown, never "this key only".
fn family<'a>(
    index: &'a ScanIndex,
    key: &str,
    root: &'a str,
) -> Option<impl Iterator<Item = (&'a String, &'a ScanIndexEntry)> + 'a> {
    let family = super::claude_family_census_shadow::FamilyRef::of_key(key)
        .filter(|family| family.root() == root)?;
    Some(
        index
            .files
            .range::<str, _>((
                std::ops::Bound::Included(family.prefix()),
                std::ops::Bound::Unbounded,
            ))
            .take_while(move |(other, _)| other.starts_with(family.prefix()))
            .filter(move |(other, _)| {
                claude_index_path_member_ref(Path::new(other.as_str()))
                    .is_some_and(|member| member.root == root)
            }),
    )
}

/// Cap room: the family's recorded requests fit the pending
/// occurrence cap after what is already retained; admitted in selection order.
fn cap_room(index: &ScanIndex, page: &mut Page, key: &str, root: &str) -> bool {
    let retained = *page
        .retained
        .get_or_insert_with(|| index.claude_usage_family_pending.total_occurrences());
    let Some(members) = family(index, key, root) else {
        return false;
    };
    let requests = members
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
    let family = claude_index_path_family_member(&candidate.path);
    // Cold usage pending: an owed member's family is read and re-stamped
    // below, so it is loaded first. Unknown (counted) leaves the member owed.
    if let Some((root, _)) = family.as_ref().filter(|_| {
        index
            .files
            .get(&key)
            .is_some_and(|entry| entry.evidence_owed)
    }) {
        let roots = BTreeSet::from([root.clone()]);
        if super::state_v2::load_usage(index, Some(&roots)).is_err() {
            return;
        }
    }
    // An owed entry a later clear emptied is read like any cleared entry.
    let Some(entry) = index
        .files
        .get(&key)
        .filter(|entry| entry.evidence_owed && !entry.source_file_fingerprint.is_empty())
    else {
        return;
    };
    note_age(
        index,
        family.as_ref().map(|(root, _)| root.as_str()),
        census_window_end,
    );
    if entry.source_file_fingerprint != candidate.source_file_fingerprint {
        // A real change parses fresh evidence, never against its carried copy.
        if let Some((root, member)) = family {
            claude_contract::note(|c| c.evidence_owed.changed += 1);
            // Loaded above.
            if let Some(pending) = index
                .claude_usage_family_pending
                .family_mut(&root)
                .ok()
                .flatten()
                .filter(|pending| pending.census_window_end == census_window_end)
            {
                pending.member_occurrences.remove(&member);
                pending.member_request_id_hashes.remove(&member);
            }
        }
        return;
    }
    if *decision != CandidateDecision::Skip {
        // Selected by another obligation (forced family, authority, audit,
        // upload context, adoption): that selection owns the read, outside
        // this page's owed-read cap. The parse records a fresh entry.
        claude_contract::note(|c| c.evidence_owed.selected_by_other_reason += 1);
        return;
    }
    // A hold's own Skip (authority quarantine, or a validated CONTENT memo
    // under an account hold) is never escalated to a read: the member stays
    // owed, counted by its hold, until a change or the hold's release reads it.
    let held = family
        .as_ref()
        .is_some_and(|(root, _)| index.claude_usage_authority_quarantine.contains_key(root))
        || index.withheld_account_unchanged(&key, candidate);
    if let Some((root, member)) = family {
        if empty_from_record(index, &key, &root) {
            claude_contract::note(|c| c.evidence_owed.restamped_from_record += 1);
            if let Some(entry) = index.files.get_mut(&key) {
                entry.evidence_owed = false;
            }
            return;
        }
        match restamp(index, &key, &root, &member, census_window_end) {
            Ok(()) => {
                // Under the latch only a current-contract read gets here
                // (`current_contract_read`): it equals a Full under the
                // current contract. The latch itself clears only through its
                // own routes.
                let latched = index.claude_request_identity_contract_changed;
                claude_contract::note(|c| {
                    let owed = &mut c.evidence_owed;
                    *if latched {
                        &mut owed.restamped_current_contract
                    } else {
                        &mut owed.restamped
                    } += 1;
                });
                if let Some(entry) = index.files.get_mut(&key) {
                    entry.evidence_owed = false;
                }
                return;
            }
            Err(refusal) => claude_contract::note(|c| {
                let owed = &mut c.evidence_owed;
                *match refusal {
                    Refusal::ContractLatch => &mut owed.refused_contract_latch,
                    Refusal::ContractUnproven => &mut owed.refused_contract_unproven,
                    Refusal::ScanIdentity => &mut owed.refused_scan_identity,
                    Refusal::PendingInvalid => &mut owed.refused_pending_invalid,
                    Refusal::Evidence => &mut owed.refused_evidence,
                    Refusal::Record => &mut owed.refused_record,
                    Refusal::FamilyUnverified => &mut owed.refused_family_unverified,
                    Refusal::NoPending => &mut owed.refused_no_pending,
                } += 1;
            }),
        }
    }
    if held {
        return;
    }
    let Some(entry) = index.files.get(&key) else {
        return;
    };
    let member = claude_index_path_member_ref(&candidate.path).map(|member| member.root);
    let kept = member.is_some_and(|root| {
        index
            .claude_usage_family_pending
            .view(root)
            .is_some_and(|pending| kept_member(index, &key, entry, root, pending))
    });
    let arm = match member.filter(|_| kept) {
        // Not kept: a plain read.
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
        if page.reads >= page.read_cap {
            // Paced: back into the walk's own queue as a re-read (not a
            // census member, like a history-upgrade budget hold), still owed.
            claude_contract::note(|c| c.evidence_owed.deferred_page_cap += 1);
            if let Some(traversal) = index.traversal.as_mut() {
                traversal.pending_candidates.push_back(ScanTraversalPath {
                    scan_root: candidate.scan_root.clone(),
                    path: candidate.path.clone(),
                    census_member: false,
                    watcher_hint: false,
                });
            }
            return;
        }
        page.reads += 1;
    }
    let latched = index.claude_request_identity_contract_changed;
    claude_contract::note(|c| match arm {
        Arm::Read => {
            c.evidence_owed.read += 1;
            c.evidence_owed.identity_owed_read_under_latch += u64::from(latched);
        }
        // Re-examined at every visit: read once its requests fit the cap.
        Arm::KeptOwed => c.evidence_owed.owed_waiting_cap += 1,
    });
    if arm == Arm::Read {
        *decision = CandidateDecision::Parse;
        *reason = Some(CandidateParseReason::Rearmed);
    }
}

/// A traversal started under the recorded identity contract: its census
/// window is the first whose records that contract wrote (W1), unless an
/// earlier one already is (a contract change clears it). Read only by an
/// owed member's re-stamp under the latch (`current_contract_read`).
pub(super) fn start_contract_window(index: &mut ScanIndex, census_window_end: &str) {
    let progress = &mut index.claude_full_rearm_progress;
    if progress.identity_contract_window.is_none() {
        progress.identity_contract_window = rfc3339_unix_seconds(census_window_end);
    }
}

/// Age of this owed member's family evidence window against this census.
fn note_age(index: &ScanIndex, root: Option<&str>, census_window_end: &str) {
    let age = root
        .and_then(|root| index.claude_usage_family_pending.view(root))
        .and_then(|pending| rfc3339_unix_seconds(pending.window()))
        .zip(rfc3339_unix_seconds(census_window_end))
        .map(|(stored, now)| now.saturating_sub(stored));
    claude_contract::note(|c| {
        let owed = &mut c.evidence_owed;
        *match age {
            None => &mut owed.age_unknown,
            Some(age) if age <= 3_600 => &mut owed.age_le_1h,
            Some(age) if age <= 86_400 => &mut owed.age_le_1d,
            Some(age) if age <= 7 * 86_400 => &mut owed.age_le_7d,
            Some(_) => &mut owed.age_gt_7d,
        } += 1;
    });
}

/// Why a re-stamp did not count as an observation (counts only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    ContractLatch,
    ContractUnproven,
    ScanIdentity,
    PendingInvalid,
    Evidence,
    Record,
    FamilyUnverified,
    NoPending,
}

/// (a) An unchanged member's stored occurrences
/// count as an observation in this census window, no read, only when
/// (a) the fingerprint is unchanged (the caller), (b) the scan identity and
/// request-identity contracts are unchanged since storage, (c) the stored
/// occurrences are valid and are exactly the request ids this revision's own
/// loss-free census record read, and (d) only window membership moves: the
/// family's stored evidence is stamped with this window, nothing else.
/// A stale family moves only while every other member with stored evidence
/// is still owed: each is verified at its own selection, and owed members
/// stay unobserved for fence coverage until then.
fn restamp(
    index: &mut ScanIndex,
    key: &str,
    root: &str,
    member: &str,
    window: &str,
) -> Result<(), Refusal> {
    let (Some(entry), Some(pending)) = (
        index.files.get(key),
        // Loaded by `resolve`; a cold family it could not load refused there.
        index
            .claude_usage_family_pending
            .family(root)
            .ok()
            .flatten(),
    ) else {
        return Err(Refusal::NoPending);
    };
    // The contract is unchanged since storage (no latch), or this pending's
    // stamp is the recorded, real contract this cycle runs under. A pending
    // left `contract_unproven` by a latch clear proves its contract only
    // through that stamp. Under the latch the member must also have been read
    // under that contract (`current_contract_read`); otherwise one paced read.
    let latched = index.claude_request_identity_contract_changed;
    let stamped = pending
        .identity_contract
        .is_some_and(|stamp| Some(stamp) == EvidenceContract::current(index));
    if latched && !(stamped && current_contract_read(index, key, entry)) {
        return Err(Refusal::ContractLatch);
    }
    if pending.contract_unproven && !stamped {
        return Err(Refusal::ContractUnproven);
    }
    if entry.scan_identity_version.as_deref() != Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION) {
        return Err(Refusal::ScanIdentity);
    }
    if pending.invalid {
        return Err(Refusal::PendingInvalid);
    }
    let Some(hashes) = pending
        .member_occurrences
        .get(member)
        .zip(pending.member_request_id_hashes.get(member))
        .and_then(|(occurrences, hashes)| occurrences.keys().eq(hashes.iter()).then_some(hashes))
    else {
        return Err(Refusal::Evidence);
    };
    // This revision's own loss-free record: exact, empty, or identity
    // incomplete (an id-less response or a repeated id, a function of the
    // file's bytes alone, so a Full rebuilds this same pending and record).
    // Its ids are the stored ones, one per stored request.
    if !index.claude_request_census.get(key).is_some_and(|record| {
        (record.current_for(&entry.source_file_fingerprint)
            || record.idless_native_for(&entry.source_file_fingerprint))
            && hashes.len() == record.request_hashes().len()
            && record_hashes(hashes).as_deref() == Some(record.request_hashes())
    }) {
        return Err(Refusal::Record);
    }
    if pending.census_window_end != window {
        let others_owed = family(index, key, root).is_some_and(|mut members| {
            members.all(|(other, entry)| {
                other == key
                    || entry.evidence_owed
                    || claude_index_path_family_member(Path::new(other))
                        .is_some_and(|(_, other)| !pending.member_occurrences.contains_key(&other))
            })
        });
        if !others_owed {
            return Err(Refusal::FamilyUnverified);
        }
        if let Ok(Some(pending)) = index.claude_usage_family_pending.family_mut(root) {
            pending.census_window_end = window.to_owned();
        }
    }
    Ok(())
}

/// The member's census record reproduces its revision from the first window
/// started under the recorded identity contract on (W1; a change inside a
/// window counts from the next one), and is loss-free: not lossy, over
/// budget, unverified, a twin or retired. The record's ids must still equal
/// the pending's (checked by `restamp`).
fn current_contract_read(index: &ScanIndex, key: &str, entry: &ScanIndexEntry) -> bool {
    let Some(since) = index.claude_full_rearm_progress.identity_contract_window else {
        return false;
    };
    index.claude_request_census.get(key).is_some_and(|record| {
        record.reproduces_since(&entry.source_file_fingerprint, since, Some(since))
            && !record.is_lossy()
            && !record.over_budget()
    })
}

/// A confirmed-empty member re-stamps from its census record, no read. Its
/// parse yields no snapshot, so a Full of this revision folds nothing into the
/// family's pending; clearing the debt leaves pending exactly as that Full
/// leaves it. Only while the record is this revision's own, under the recorded
/// cycle contract with no latch, and with no account or decode hold: current
/// and holding no requests, or identity incomplete (responses without usage,
/// such as API errors, whose ids it keeps; a Full rewrites the same record, so
/// it stays as is). Changed members never reach here. A member with requests
/// cannot use this: the record keeps 8-byte id prefixes and no usage, not the
/// pending a Full folds.
fn empty_from_record(index: &ScanIndex, key: &str, root: &str) -> bool {
    let Some(entry) = index.files.get(key) else {
        return false;
    };
    !index.claude_request_identity_contract_changed
        && EvidenceContract::current(index).is_some()
        && entry.scan_identity_version.as_deref() == Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
        && index.confirmed_empty_files.contains(key)
        && !index.claude_account_deferred_holds.contains_key(key)
        && !index.decode_holds_family(root)
        && index.claude_request_census.get(key).is_some_and(|record| {
            (record.current_for(&entry.source_file_fingerprint)
                && record.request_hashes().is_empty())
                || record.idless_native_for(&entry.source_file_fingerprint)
        })
}

/// A family with an owed member not observed in this window is not proven
/// at completion: owed evidence earns no credit, retirement or fence decision
/// until it resolves.
pub(super) fn owed_roots(index: &ScanIndex, census_window_end: &str) -> BTreeSet<String> {
    index
        .files
        .iter()
        .filter(|(key, entry)| {
            entry.evidence_owed && !observed_in_window(index, key, census_window_end)
        })
        .filter_map(|(key, _)| claude_index_path_family_member(Path::new(key)))
        .map(|(root, _)| root)
        .collect()
}

/// A read of `key` in this census window: its loss-free census record was
/// written in `census_window_end` and lists exactly the member's pending
/// request ids (one per id). It credits the record's revision, the one read
/// this window, never a committed older one a held upload restored; the
/// credit expires with the window.
pub(super) fn observed_in_window(index: &ScanIndex, key: &str, census_window_end: &str) -> bool {
    let (Some((root, member)), Some(window)) = (
        claude_index_path_family_member(Path::new(key)),
        rfc3339_unix_seconds(census_window_end),
    ) else {
        return false;
    };
    let Some(record) = index.claude_request_census.get(key).filter(|record| {
        record.window() == window
            && record.current_derivation()
            && !record.is_lossy()
            && !record.over_budget()
            && !record.unverified_or_twin()
            && record.retired().is_none()
    }) else {
        return false;
    };
    let empty = BTreeSet::new();
    let hashes = match index.claude_usage_family_pending.family(&root) {
        Ok(None) => &empty,
        Ok(Some(pending)) if !pending.invalid && pending.census_window_end == census_window_end => {
            pending
                .member_request_id_hashes
                .get(&member)
                .unwrap_or(&empty)
        }
        Ok(Some(_)) | Err(_) => return false,
    };
    hashes.len() == record.request_hashes().len()
        && record_hashes(hashes).as_deref() == Some(record.request_hashes())
}

/// Pending keys request ids by full SHA-256 hex; a census record keeps the
/// sorted 8-byte prefixes (`claude_request_hash`).
fn record_hashes(hashes: &BTreeSet<String>) -> Option<Vec<u64>> {
    let mut prefixes = hashes
        .iter()
        .map(|hash| claude_request_census::claude_request_hash_from_pending_key(hash))
        .collect::<Option<Vec<_>>>()?;
    prefixes.sort_unstable();
    prefixes.dedup();
    Some(prefixes)
}

/// The latch clear, by any route (its identity-contract re-arm, a completion
/// whose fence opens, the identity upgrade, a spent cutover): kept pending
/// from another window, or not stamped with the contract this cycle runs
/// under, is marked `contract_unproven`, so an owed member re-stamps only
/// through its own stamp, never through the cleared latch. Only the owed
/// resolver reads the mark.
pub(super) fn mark_unproven_at_latch_clear(index: &mut ScanIndex, census_window_end: &str) {
    let current = EvidenceContract::current(index);
    for pending in index
        .claude_usage_family_pending
        .loaded_all_mut()
        .values_mut()
    {
        if pending.census_window_end != census_window_end || pending.identity_contract != current {
            pending.contract_unproven = true;
        }
    }
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

    /// [behaviour] Only the terminal-retry re-arm keeps the revision owed;
    /// every other re-arm cause clears the fingerprint.
    #[test]
    fn only_the_terminal_retry_rearm_owes() {
        let mut owed = entry();
        rearm_cause::clear(
            "/k.jsonl",
            &mut owed,
            rearm_cause::Cause::TerminalUnhealthyRetry,
        );
        assert_eq!(
            (owed.source_file_fingerprint.as_str(), owed.evidence_owed),
            ("revision", true)
        );
        assert!(owed.rearmed());
        assert_eq!(owed.observed_fingerprint(), "");
        for cause in [
            rearm_cause::Cause::NoRetainedTraversal,
            rearm_cause::Cause::CarryInvalidation,
            rearm_cause::Cause::ContextChanged,
            rearm_cause::Cause::AuditCapDelay,
        ] {
            let mut cleared = entry();
            rearm_cause::clear("/k.jsonl", &mut cleared, cause);
            assert!(cleared.source_file_fingerprint.is_empty() && !cleared.evidence_owed);
        }
    }

    /// [money] Equality readers that stand for "observed" or feed a proof
    /// (`e2` copy proof, native credit, proof corrections, owned start, record
    /// retirement, audits) see an owed revision exactly as a cleared one,
    /// until a re-stamp or read resolves it.
    #[test]
    fn owed_revision_is_unobserved_for_proof_readers_until_resolved() {
        let mut owed = entry();
        rearm_cause::clear(
            "/k.jsonl",
            &mut owed,
            rearm_cause::Cause::TerminalUnhealthyRetry,
        );
        assert_eq!(owed.source_file_fingerprint, "revision");
        assert_eq!(owed.observed_fingerprint(), "");
        let mut cleared = entry();
        cleared.source_file_fingerprint.clear();
        assert_eq!(owed.observed_fingerprint(), cleared.observed_fingerprint());
        owed.evidence_owed = false;
        assert_eq!(owed.observed_fingerprint(), "revision");
    }

    fn pending(window: &str) -> ClaudeUsageFamilyPending {
        ClaudeUsageFamilyPending {
            census_window_end: window.into(),
            member_request_id_hashes: BTreeMap::new(),
            member_occurrences: BTreeMap::new(),
            invalid: false,
            idless_revision: None,
            identity_contract: None,
            contract_unproven: false,
        }
    }

    /// [money] The contract stamp is the contract the WHOLE pending
    /// was built under. Empty pending takes the current contract; a pending
    /// stamped with the current contract keeps it; anything accumulated across
    /// a contract (or body-witness revision) change is `None` and never
    /// laundered back; a placeholder or unknown record stamps `None` (so a
    /// stampless restore gives `None`); invalid evidence is `None`.
    #[test]
    fn contract_stamp_is_written_on_accumulation_and_never_laundered() {
        let mut index = ScanIndex {
            claude_request_identity_contract: Some(
                claude_request_identity::cycle_contract(true).into(),
            ),
            ..Default::default()
        };
        let current = EvidenceContract::current(&index);
        assert!(current.is_some());
        let roots = || BTreeSet::from(["r".to_string()]);
        let add = |index: &mut ScanIndex, member: &str, window: &str| {
            let entry = index
                .claude_usage_family_pending
                .entry("r".into())
                .or_insert_with(|| pending(window));
            if entry.census_window_end != window {
                *entry = pending(window);
            }
            entry
                .member_request_id_hashes
                .insert(member.into(), BTreeSet::from(["a".repeat(64)]));
        };
        let stamp = |index: &ScanIndex| index.claude_usage_family_pending["r"].identity_contract;
        stamp_families(&mut index, roots(), "W", |i| add(i, "m1", "W"));
        assert_eq!(stamp(&index), current, "empty before: current");
        stamp_families(&mut index, roots(), "W", |i| add(i, "m2", "W"));
        assert_eq!(stamp(&index), current, "same contract: kept");
        index.active_effective_upload_body_witness_revision += 1;
        let changed = EvidenceContract::current(&index);
        assert!(changed.is_some() && changed != current);
        stamp_families(&mut index, roots(), "W", |i| add(i, "m3", "W"));
        assert_eq!(stamp(&index), None, "accumulated across a change: mixed");
        stamp_families(&mut index, roots(), "W", |i| add(i, "m4", "W"));
        assert_eq!(stamp(&index), None, "never laundered by new evidence");
        stamp_families(&mut index, roots(), "W2", |i| add(i, "m1", "W2"));
        assert_eq!(stamp(&index), changed, "a new window starts empty");
        for placeholder in [
            Some(CLAUDE_REQUEST_IDENTITY_CONTRACT_CHANGED_MID_TRAVERSAL),
            Some(CLAUDE_E2_IDENTITY_ADOPTION_PENDING),
            None,
        ] {
            let mut held = index.clone();
            held.claude_request_identity_contract = placeholder.map(str::to_owned);
            assert_eq!(EvidenceContract::current(&held), None);
            stamp_families(&mut held, roots(), "W3", |i| add(i, "m1", "W3"));
            assert_eq!(stamp(&held), None, "{placeholder:?}");
        }
        stamp_families(&mut index, roots(), "W2", |i| {
            i.claude_usage_family_pending.get_mut("r").unwrap().invalid = true;
        });
        assert_eq!(stamp(&index), None, "invalid evidence is never stamped");
    }

    /// [format] An old decoder (no fields) rewrites a stamped, contract-unproven
    /// pending without either: the stamp decodes `None` and the family looks
    /// un-exempt. That is safe only because old code has no evidence-owed
    /// re-stamp to misuse it. A damaged stamp decodes `None` without failing
    /// the pending.
    #[test]
    fn contract_stamp_and_unproven_bit_drop_through_an_old_decoder_without_restamp() {
        #[derive(Serialize, Deserialize)]
        struct OldPending {
            census_window_end: String,
            member_request_id_hashes: BTreeMap<String, BTreeSet<String>>,
            #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
            member_occurrences: serde_json::Value,
            invalid: bool,
            #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
            idless_revision: serde_json::Value,
        }
        let index = ScanIndex {
            claude_request_identity_contract: Some(
                claude_request_identity::cycle_contract(true).into(),
            ),
            ..Default::default()
        };
        let mut stamped = pending("W");
        stamped.identity_contract = EvidenceContract::current(&index);
        stamped.contract_unproven = true;
        let written = serde_json::to_value(&stamped).unwrap();
        assert!(written.get("identity_contract").is_some());
        assert_eq!(written["contract_unproven"], true);
        let round: ClaudeUsageFamilyPending = serde_json::from_value(written.clone()).unwrap();
        assert_eq!(round, stamped);
        let old: OldPending = serde_json::from_value(written.clone()).unwrap();
        let rewritten: ClaudeUsageFamilyPending =
            serde_json::from_value(serde_json::to_value(&old).unwrap()).unwrap();
        assert_eq!(rewritten.identity_contract, None);
        assert!(!rewritten.contract_unproven);
        let mut damaged = written;
        damaged["identity_contract"] = serde_json::json!("garbage");
        let damaged: ClaudeUsageFamilyPending = serde_json::from_value(damaged).unwrap();
        assert_eq!(damaged.identity_contract, None);
        assert_eq!(
            serde_json::to_value(pending("W"))
                .unwrap()
                .get("identity_contract"),
            None,
            "unstamped pending keeps its bytes"
        );
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

        // A read the file really needs (here an authority normalization of an
        // unbound record) clears the fingerprint, even on an owed entry: a
        // reader that drops the new fields still selects it for a read.
        let root = "d0000000-1111-4111-8111-111111111111";
        let path = PathBuf::from(format!("/synthetic/{root}.jsonl"));
        let key = local_index_key(&path);
        let revision = "1".repeat(64);
        let mut index = ScanIndex::default();
        let mut owed = entry();
        owed.source_file_fingerprint = revision.clone();
        keep_or_clear(&mut owed, true);
        index.files.insert(key.clone(), owed);
        index.insert_unproven_terminal_claude_authority_for_test(root, &revision);
        index.claude_usage_family_witnesses.remove(root);
        index.drop_unbound_claude_authority_records("test");
        let mut value = serde_json::to_value(&index.files[&key]).unwrap();
        value.as_object_mut().unwrap().remove("evidence_owed");
        let mut older = ScanIndex::default();
        older
            .files
            .insert(key.clone(), serde_json::from_value(value).unwrap());
        assert!(older.files[&key].source_file_fingerprint.is_empty());
        let candidate = CandidateFile {
            physical_identity: None,
            scan_root: PathBuf::from("/synthetic"),
            path,
            size_bytes: 1,
            modified_unix_seconds: 2,
            modified_unix_nanos: 0,
            source_file_fingerprint: revision.clone(),
            legacy_source_file_fingerprint: revision,
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
            withheld_content_stamp: None,
        };
        assert_eq!(
            older.candidate_decision_with_reason_at(&candidate, 0).0,
            CandidateDecision::Parse
        );
    }
}
