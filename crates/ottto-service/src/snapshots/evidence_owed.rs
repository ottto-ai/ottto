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

/// What an owed revision needs to resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Census-window evidence only: a bound re-stamp resolves it.
    Evidence,
    /// The clearing site needs this revision read (a correction to emit, a
    /// witness or account proof to rebuild): restore or one paced Full.
    Read,
}

/// Round 3: every census fingerprint clear goes through here. OFF (or an
/// already cleared entry): main's clear. ON: keep the revision, owe it.
pub(crate) fn clear(entry: &mut ScanIndexEntry, kind: Kind) {
    if enabled() && !entry.source_file_fingerprint.is_empty() {
        entry.evidence_owed = true;
        entry.owed_read |= kind == Kind::Read;
    } else {
        entry.source_file_fingerprint.clear();
    }
}

/// Round 3 (C5 P1): what a Claude traversal started under, persisted on its
/// checkpoint (bounded: one count, one upload-context fingerprint and the
/// configured roots the context fingerprint hashed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TraversalContextInputs {
    pub(crate) backfill_window_days: u64,
    pub(crate) active_upload_context: Option<String>,
    pub(crate) roots: Vec<PathBuf>,
}
crate::heap_layout_bound::fields!(TraversalContextInputs; backfill_window_days, active_upload_context, roots);

/// ON, ContextChanged start: the retained traversal's fingerprint is
/// reproduced from its own roots, backfill and upload context with today's
/// scanner identity and replay generation, and today's roots only add to its
/// roots. Then only roots were added, the backfill changed or the active
/// upload context (policy) changed: unchanged files owe evidence (their upload
/// receipts still own any upload-context read). A replay or scanner identity
/// change, removed roots or an unrecorded start keep main's clear.
pub(super) fn context_change_owes(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &ScanIndex,
    backfill_window_days: u64,
) -> bool {
    let Some(retained) = index.traversal.as_ref() else {
        return false;
    };
    let Some(inputs) = retained.context_inputs.as_ref() else {
        return false;
    };
    let current = roots.iter().collect::<BTreeSet<_>>();
    enabled()
        && source == SnapshotSource::ClaudeCode
        && inputs.roots.iter().all(|root| current.contains(root))
        && (inputs.backfill_window_days != backfill_window_days
            || inputs.active_upload_context != index.active_upload_context_fingerprint
            || inputs.roots.len() != current.len())
        && scan_traversal_context_fingerprint_with(
            source,
            &inputs.roots,
            inputs.active_upload_context.as_deref(),
            index.historical_replay_generation.as_deref(),
            inputs.backfill_window_days,
        ) == retained.context_fingerprint
}

/// B-P2 under ON: an unACKed head is a real invalidation; it keeps main's
/// cleared fingerprint, never an owed one.
pub(super) fn reoffer_clears(entry: &mut ScanIndexEntry) {
    if entry.evidence_owed {
        entry.evidence_owed = false;
        entry.owed_read = false;
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
        retained.owed_read |= working.owed_read;
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
    /// Round 3 (C5 P4): owed Fulls this page already admitted, and the one
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

/// #1025 Q5b (Lead B S1-S6): the identity contract a pending was built
/// under, as a bounded code plus the body-witness revision E2 adoption reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EvidenceContract {
    /// 0 = `""` (no permit), 1 = COLLECTOR, 2 = E2_GROUPING.
    c: u8,
    /// `active_effective_upload_body_witness_revision` at accumulation.
    bw: u64,
}
crate::heap_layout_bound::no_heap!(true; EvidenceContract);

impl EvidenceContract {
    /// S2: the contract this cycle builds under, only while the index records
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

/// S1: accumulate `snapshots` into the index's pending and stamp each touched
/// family: the current contract only if its pending was empty before or
/// already carried that same stamp; otherwise `None` (mixed). Written with the
/// switch OFF too (13a), so the ON flip finds stamped evidence. A durable-tail
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
                .get(&root)
                .filter(|pending| {
                    pending.census_window_end == census_window_end && !evidence_free(pending)
                })
                .map(|pending| pending.identity_contract);
            (root, before)
        })
        .collect::<BTreeMap<_, _>>();
    let result = accumulate(index);
    for (root, before) in prior {
        if let Some(pending) = index.claude_usage_family_pending.get_mut(&root) {
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
    if enabled() {
        note_age(
            index,
            family.as_ref().map(|(root, _)| root.as_str()),
            census_window_end,
        );
    }
    if entry.source_file_fingerprint != candidate.source_file_fingerprint {
        // A real change parses fresh evidence, never against its carried copy.
        if let Some((root, member)) = family.filter(|_| enabled()) {
            claude_contract::note(|c| c.evidence_owed.changed += 1);
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
        if enabled() {
            claude_contract::note(|c| c.evidence_owed.read += 1);
        }
        return;
    }
    let must_read = entry.owed_read;
    if let Some((root, member)) = family.filter(|_| enabled() && !must_read) {
        match restamp(index, &key, &root, &member, census_window_end) {
            Ok(Restamp::Observed) => {
                claude_contract::note(|c| c.evidence_owed.restamped += 1);
                if let Some(entry) = index.files.get_mut(&key) {
                    entry.evidence_owed = false;
                }
                return;
            }
            Ok(Restamp::UnderLatch) => {
                // S3: window membership only. The entry stays owed, so fence
                // coverage, family proof and retirement still see it
                // unobserved until a re-stamp without the latch.
                claude_contract::note(|c| c.evidence_owed.restamped_under_latch += 1);
                return;
            }
            Err(refusal) => claude_contract::note(|c| {
                let owed = &mut c.evidence_owed;
                *match refusal {
                    Refusal::ContractLatch => &mut owed.refused_contract_latch,
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
    let Some(entry) = index.files.get(&key) else {
        return;
    };
    let member = claude_index_path_member_ref(&candidate.path).map(|member| member.root);
    let kept = enabled()
        && !must_read
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
    if enabled() && arm == Arm::Read {
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
    if enabled() {
        claude_contract::note(|c| match arm {
            Arm::Read if must_read => c.evidence_owed.read_required += 1,
            Arm::Read => c.evidence_owed.read += 1,
            // Re-examined at every visit: read once its requests fit the cap.
            Arm::KeptOwed => c.evidence_owed.owed_waiting_cap += 1,
        });
    }
    if arm == Arm::Read {
        *decision = CandidateDecision::Parse;
        *reason = Some(CandidateParseReason::Rearmed);
    }
}

/// D34 age: this owed member's family evidence window against this census.
fn note_age(index: &ScanIndex, root: Option<&str>, census_window_end: &str) {
    let age = root
        .and_then(|root| index.claude_usage_family_pending.get(root))
        .and_then(|pending| rfc3339_unix_seconds(&pending.census_window_end))
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

/// A bound re-stamp: an observation, or (latch set, Q5b stamp current)
/// window membership only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Restamp {
    Observed,
    UnderLatch,
}

/// Why a re-stamp did not count as an observation (counts only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    ContractLatch,
    ScanIdentity,
    PendingInvalid,
    Evidence,
    Record,
    FamilyUnverified,
    NoPending,
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
fn restamp(
    index: &mut ScanIndex,
    key: &str,
    root: &str,
    member: &str,
    window: &str,
) -> Result<Restamp, Refusal> {
    let (Some(entry), Some(pending)) = (
        index.files.get(key),
        index.claude_usage_family_pending.get(root),
    ) else {
        return Err(Refusal::NoPending);
    };
    // Condition 2: no latch (contract unchanged since storage), or Q5b: this
    // pending's stamp is the recorded, real contract this cycle runs under.
    let latched = index.claude_request_identity_contract_changed;
    if latched
        && !pending
            .identity_contract
            .is_some_and(|stamp| Some(stamp) == EvidenceContract::current(index))
    {
        return Err(Refusal::ContractLatch);
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
    if !index.claude_request_census.get(key).is_some_and(|record| {
        record.current_for(&entry.source_file_fingerprint)
            && record_hashes(hashes).as_deref() == Some(record.request_hashes())
    }) {
        return Err(Refusal::Record);
    }
    if pending.census_window_end != window {
        let others_owed = family(index, key, root).all(|(other, entry)| {
            other == key
                || entry.evidence_owed
                || claude_index_path_family_member(Path::new(other))
                    .is_some_and(|(_, other)| !pending.member_occurrences.contains_key(&other))
        });
        if !others_owed {
            return Err(Refusal::FamilyUnverified);
        }
        if let Some(pending) = index.claude_usage_family_pending.get_mut(root) {
            pending.census_window_end = window.to_owned();
        }
    }
    Ok(if latched {
        Restamp::UnderLatch
    } else {
        Restamp::Observed
    })
}

/// S3: under ON a family with an owed member is not proven at completion:
/// owed evidence (including a latch-time Q5b re-stamp) earns no credit,
/// retirement or fence decision until it resolves.
pub(super) fn owed_roots(index: &ScanIndex) -> BTreeSet<String> {
    if !enabled() {
        return BTreeSet::new();
    }
    index
        .files
        .iter()
        .filter(|(_, entry)| entry.evidence_owed)
        .filter_map(|(key, _)| claude_index_path_family_member(Path::new(key)))
        .map(|(root, _)| root)
        .collect()
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

/// Q5 (RF1 #992): every stored evidence set is from this census window, or
/// there is none to mix with the recorded contract. Pending this completion
/// retires (no indexed member, no quarantine: `owed_at_completion`) is none.
pub(super) fn evidence_from_window(
    index: &ScanIndex,
    census_window_end: &str,
    indexed_claude_family_ids: &BTreeSet<String>,
) -> bool {
    index
        .claude_usage_family_pending
        .iter()
        .all(|(root_session_id, pending)| {
            pending.invalid
                || evidence_free(pending)
                || pending.census_window_end == census_window_end
                || !(index
                    .claude_usage_authority_quarantine
                    .contains_key(root_session_id)
                    || owed_at_completion(
                        root_session_id,
                        pending,
                        false,
                        indexed_claude_family_ids,
                    ))
        })
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

    /// [money] Equality readers that stand for "observed" or feed a proof
    /// (E2 copy proof, native credit, proof corrections, owned start, record
    /// retirement, audits) see an owed revision exactly as main's cleared
    /// one, until a re-stamp or read resolves it.
    #[test]
    fn owed_revision_is_unobserved_for_proof_readers_until_resolved() {
        let _on = EvidenceOwedForTest::on();
        let mut owed = entry();
        rearm_cause::clear(
            "/k.jsonl",
            &mut owed,
            rearm_cause::Cause::NoRetainedTraversal,
        );
        assert_eq!(owed.source_file_fingerprint, "revision");
        assert_eq!(owed.observed_fingerprint(), "");
        let mut main = entry();
        main.source_file_fingerprint.clear();
        assert_eq!(owed.observed_fingerprint(), main.observed_fingerprint());
        owed.evidence_owed = false;
        assert_eq!(owed.observed_fingerprint(), "revision");
    }

    /// [off=main] Round 3: every census clear site goes through `clear`. OFF
    /// it is main's clear; ON it keeps the revision owed, and a `Read` site
    /// also marks it must-read (never re-stamped).
    #[test]
    fn census_clear_sites_owe_on_and_clear_off() {
        for kind in [Kind::Evidence, Kind::Read] {
            let mut off = entry();
            clear(&mut off, kind);
            assert!(off.source_file_fingerprint.is_empty() && !off.evidence_owed && !off.owed_read);
            let _on = EvidenceOwedForTest::on();
            let mut on = entry();
            clear(&mut on, kind);
            assert_eq!(on.source_file_fingerprint, "revision");
            assert!(on.evidence_owed && on.rearmed());
            assert_eq!(on.owed_read, kind == Kind::Read);
            assert_eq!(on.observed_fingerprint(), "");
            clear(&mut on, Kind::Evidence);
            assert_eq!(
                on.owed_read,
                kind == Kind::Read,
                "a later evidence clear keeps must-read"
            );
        }
    }

    fn pending(window: &str) -> ClaudeUsageFamilyPending {
        ClaudeUsageFamilyPending {
            census_window_end: window.into(),
            member_request_id_hashes: BTreeMap::new(),
            member_occurrences: BTreeMap::new(),
            invalid: false,
            idless_revision: None,
            identity_contract: None,
        }
    }

    /// [money] Q5b S1/S2 (Lead B): the stamp is the contract the WHOLE pending
    /// was built under. Empty pending takes the current contract; a pending
    /// stamped with the current contract keeps it; anything accumulated across
    /// a contract (or body-witness revision) change is `None` and never
    /// laundered back; a placeholder or unknown record stamps `None` (so a
    /// stampless restore gives `None`); invalid evidence is `None`.
    #[test]
    fn q5b_stamp_is_written_on_accumulation_and_never_laundered() {
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

    /// [format] Q5b S4: an old decoder (no field) rewrites a stamped pending
    /// without the stamp, which then decodes `None`; a damaged stamp decodes
    /// `None` without failing the pending.
    #[test]
    fn q5b_stamp_round_trips_through_an_old_decoder_as_none() {
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
        let written = serde_json::to_value(&stamped).unwrap();
        assert!(written.get("identity_contract").is_some());
        let round: ClaudeUsageFamilyPending = serde_json::from_value(written.clone()).unwrap();
        assert_eq!(round, stamped);
        let old: OldPending = serde_json::from_value(written.clone()).unwrap();
        let rewritten: ClaudeUsageFamilyPending =
            serde_json::from_value(serde_json::to_value(&old).unwrap()).unwrap();
        assert_eq!(rewritten.identity_contract, None);
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

    /// [regress] Round 3 (C5 P1: 57,306 files in 7 ContextChanged starts):
    /// ON, a start whose context only added roots, changed the backfill or the
    /// active upload context owes evidence; a replay change, removed roots, an
    /// unrecorded start or OFF keep main's clear.
    #[test]
    fn context_change_owes_only_for_added_roots_backfill_or_upload_context() {
        let a = [PathBuf::from("/synthetic/root-a")];
        let b = PathBuf::from("/synthetic/root-b");
        let ab = [a[0].clone(), b.clone()];
        let mut index = ScanIndex::default();
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &a,
            &mut index,
            "2026-08-02T07:00:00Z",
            30,
        );
        assert!(index.traversal.as_ref().unwrap().context_inputs.is_some());
        let owes = |index: &ScanIndex, roots: &[PathBuf], days| {
            context_change_owes(SnapshotSource::ClaudeCode, roots, index, days)
        };
        assert!(!owes(&index, &a, 60), "OFF: main");
        let _on = EvidenceOwedForTest::on();
        assert!(owes(&index, &a, 60), "backfill");
        assert!(owes(&index, &ab, 30), "roots added");
        let mut policy = index.clone();
        policy.active_upload_context_fingerprint = Some("policy-b".into());
        assert!(owes(&policy, &a, 30), "upload context");
        assert!(!owes(&index, std::slice::from_ref(&b), 30), "roots removed");
        let mut replay = index.clone();
        replay.historical_replay_generation = Some("replay-b".into());
        assert!(!owes(&replay, &a, 60), "replay");
        let mut unrecorded = index.clone();
        unrecorded.traversal.as_mut().unwrap().context_inputs = None;
        assert!(!owes(&unrecorded, &a, 60), "unrecorded");
        assert!(
            !context_change_owes(SnapshotSource::Codex, &a, &index, 60),
            "Claude only"
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
    }
}
