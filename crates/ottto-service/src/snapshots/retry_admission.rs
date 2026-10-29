// Bounded scheduling for a history whose whole cancellation reserve cannot fit.
// Uncovered families are deferred, not rearmed or promoted into census proof.
const CLAUDE_RETRY_ADMISSION_ROOTS: usize = 128;
const CLAUDE_RETRY_DUE_PATHS: usize = 64;

fn claude_retry_record_due(
    record: &ClaudeUsageAuthorityQuarantineRecord,
    now: u64,
    served_before: u64,
) -> bool {
    (record.disposition == ClaudeUsageAuthorityQuarantineDisposition::RetryPending
        && record.retry_after_unix_seconds <= now
        && record.retry_after_unix_seconds > served_before)
        || record
            .proof_correction
            .as_ref()
            .is_some_and(|correction| !correction.owed_member_ids.is_empty())
}

fn claude_retry_due_family_exists(index: &ScanIndex, collected_at: &str) -> bool {
    if !index.persistence_available() {
        return false;
    }

    let now = rfc3339_unix_seconds(collected_at).unwrap_or_default();
    let served = index
        .traversal
        .as_ref()
        .and_then(|t| rfc3339_unix_seconds(&t.census_window_end))
        .unwrap_or_default();
    index
        .claude_usage_authority_quarantine
        .values()
        .any(|record| claude_retry_record_due(record, now, served))
}

#[cfg(test)]
fn claude_retry_admit_batch(
    index: &ScanIndex,
    stale: &BTreeSet<String>,
    previous: Option<&ClaudeRetryAdmission>,
    collected_at: &str,
) -> (
    ClaudeStaleFamilyCarry,
    BTreeSet<String>,
    ClaudeRetryAdmission,
) {
    claude_retry_admit_batch_observed(
        index,
        stale,
        previous,
        collected_at,
        &mut Default::default(),
        claude_contract_debt_scope(index),
    )
}

fn claude_retry_admit_batch_observed(
    index: &ScanIndex,
    stale: &BTreeSet<String>,
    previous: Option<&ClaudeRetryAdmission>,
    collected_at: &str,
    diagnostics: &mut StaleCarryRejectionCounts,
    debt_scope: Option<&BTreeSet<String>>,
) -> (
    ClaudeStaleFamilyCarry,
    BTreeSet<String>,
    ClaudeRetryAdmission,
) {
    *diagnostics = StaleCarryRejectionCounts::default();
    let mut state = previous
        .filter(|state| {
            !(state.complete
                || (state.roots_complete
                    && state.storage_deferred
                    && state.oversized_root.is_none()
                    && state.due_complete))
        })
        .cloned()
        .unwrap_or_else(|| ClaudeRetryAdmission {
            after_root: None,
            upper_root: stale.last().cloned().unwrap_or_default(),
            complete: false,
            roots_complete: false,
            progressed: false,
            served_before: previous.map(|state| state.due_through).unwrap_or_else(|| {
                index
                    .traversal
                    .as_ref()
                    .and_then(|t| rfc3339_unix_seconds(&t.census_window_end))
                    .unwrap_or_default()
            }),
            due_through: rfc3339_unix_seconds(collected_at).unwrap_or_default(),
            due_after_path: None,
            due_upper_path: index.files.keys().next_back().cloned(),
            due_complete: false,
            oversized_root: None,
            oversized_after_path: None,
            storage_deferred: false,
        });
    state.progressed = false;
    let lower = state
        .after_root
        .clone()
        .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
    let mut batch = stale
        .range((lower, std::ops::Bound::Included(state.upper_root.clone())))
        .take(CLAUDE_RETRY_ADMISSION_ROOTS)
        .cloned()
        .collect::<BTreeSet<_>>();
    loop {
        if batch.is_empty() {
            state.roots_complete = true;
            state.complete =
                state.oversized_root.is_none() && state.due_complete && !state.storage_deferred;
            state.progressed = true;
            return (ClaudeStaleFamilyCarry::default(), batch, state);
        }
        let mut attempt = StaleCarryRejectionCounts::default();
        match claude_stream_accepted_retry_carry_observed(index, &batch, &mut attempt, debt_scope) {
            Ok(carry) => {
                *diagnostics = attempt;
                state.after_root = batch.last().cloned();
                state.roots_complete = state.after_root.as_ref().is_some_and(|after| {
                    !stale
                        .iter()
                        .any(|root| root > after && root <= &state.upper_root)
                });
                state.complete = state.roots_complete
                    && state.oversized_root.is_none()
                    && state.due_complete
                    && !state.storage_deferred;
                state.progressed = true;
                eprintln!("local snapshot census advanced bounded Claude retry admission: covered_families={} carried_families={} complete={}; uncovered pending remains unchanged", batch.len(), carry.roots.len(), state.complete);
                return (carry, batch, state);
            }
            Err(ClaudeRetryAdmissionRefusal::Structure) if batch.len() > 1 => {
                let keep = batch.len().div_ceil(2);
                while batch.len() > keep {
                    batch.pop_last();
                }
            }
            Err(ClaudeRetryAdmissionRefusal::Structure) => {
                *diagnostics = attempt;
                // One bounded, durable fallback at a time. Later fitting roots
                // can advance while it is served; another oversized root waits
                // here instead of losing its obligation or growing a debt map.
                let root = batch.first().expect("singleton");
                if claude_retry_singleton_storage_only_scoped(index, root, debt_scope) {
                    // Structural refusal alone is no read obligation. Retain
                    // uncovered custody and let later roots make progress.
                    // The boolean is scheduling debt, never carry eligibility.
                    if index.claude_request_identity_contract_changed {
                        claude_contract::note(|counts| counts.deferred_by_contract_debt += 1);
                    }
                    state.storage_deferred = true;
                    state.after_root = Some(root.clone());
                    state.roots_complete = !stale
                        .iter()
                        .any(|later| later > root && later <= &state.upper_root);
                    state.complete = false;
                    state.progressed = true;
                    return (ClaudeStaleFamilyCarry::default(), BTreeSet::new(), state);
                }
                if state
                    .oversized_root
                    .as_ref()
                    .is_some_and(|owed| owed != root)
                {
                    return (ClaudeStaleFamilyCarry::default(), BTreeSet::new(), state);
                }
                state.oversized_root = Some(root.clone());
                state.after_root = Some(root.clone());
                state.roots_complete = !stale
                    .iter()
                    .any(|later| later > root && later <= &state.upper_root);
                state.complete = false;
                state.progressed = true;
                eprintln!("local snapshot census retained one oversized Claude retry family for bounded ordinary service; coverage remains incomplete");
                return (ClaudeStaleFamilyCarry::default(), BTreeSet::new(), state);
            }
            Err(_) => {
                *diagnostics = attempt;
                return (ClaudeStaleFamilyCarry::default(), BTreeSet::new(), state);
            }
        }
    }
}

// Recheck the existing accepted-family predicates without allocating its
// all-member carry/cancellation buffers. A fixed 128-identity stack page sorts
// borrowed identities, counts duplicate occurrences and validates pending keys.
// Rescans are finite (ceil(members / 128)), with no heap growth or proof grant.
fn claude_retry_singleton_storage_only(index: &ScanIndex, root: &str) -> bool {
    claude_retry_singleton_storage_only_scoped(index, root, None)
}
fn claude_retry_singleton_storage_only_scoped(
    index: &ScanIndex,
    root: &str,
    debt_scope: Option<&BTreeSet<String>>,
) -> bool {
    let Some(pending) = index.claude_usage_family_pending.get(root) else {
        return false;
    };
    if pending.invalid
        || index.claude_usage_authority_quarantine.contains_key(root)
        || index.decode_holds_family(root)
    {
        return false;
    }
    let mut count = 0usize;
    let mut root_present = false;
    for (key, entry) in &index.files {
        let Some(member) = claude_index_path_member_ref(Path::new(key)).filter(|m| m.root == root)
        else {
            continue;
        };
        count += 1;
        root_present |= member.subagent_stem.is_none();
        if !claude_stale_member_accepted_retry_evidence(index, key, entry, pending, debt_scope) {
            return false;
        }
    }
    if count == 0 || !root_present {
        return false;
    }
    let mut after = None;
    let mut represented = 0usize;
    loop {
        let mut page = [None; CLAUDE_RETRY_ADMISSION_ROOTS];
        let mut len = 0;
        for key in index.files.keys() {
            let Some(member) = claude_index_path_member_ref(Path::new(key))
                .filter(|m| m.root == root && after.map_or(true, |last| *m > last))
            else {
                continue;
            };
            match page[..len].binary_search_by(
                |slot: &Option<(ClaudeIndexPathMemberRef<'_>, usize)>| {
                    slot.expect("filled slot").0.cmp(&member)
                },
            ) {
                Ok(position) => page[position].as_mut().expect("filled slot").1 += 1,
                Err(position) if position < page.len() => {
                    let end = len.min(page.len() - 1);
                    page.copy_within(position..end, position + 1);
                    page[position] = Some((member, 1));
                    len = (len + 1).min(page.len());
                }
                Err(_) => {}
            }
        }
        if len == 0 {
            break;
        }
        if page[..len]
            .iter()
            .any(|slot| slot.expect("filled slot").1 != 1)
        {
            return false;
        }
        let upper = page[len - 1].expect("last slot").0;
        for name in pending
            .member_request_id_hashes
            .keys()
            .chain(pending.member_occurrences.keys())
        {
            let Some(member) = ClaudeIndexPathMemberRef::of_family_member(root, name) else {
                return false;
            };
            if after.map_or(true, |last| member > last) && member <= upper {
                if page[..len]
                    .binary_search_by(|slot| slot.expect("filled slot").0.cmp(&member))
                    .is_err()
                {
                    return false;
                }
                represented += 1;
            }
        }
        after = Some(upper);
    }
    represented == pending.member_request_id_hashes.len() + pending.member_occurrences.len()
}

// The due arm of retry admission: an unfinished due walk, a path after the
// served cursor and within the frozen upper path, whose family record is due by
// the frozen horizon (`now` clamps to `due_through`, idempotently). The
// oversized-root arm stays separate: it never completes the due walk.
fn claude_retry_path_due(
    state: &ClaudeRetryAdmission,
    records: &BTreeMap<String, ClaudeUsageAuthorityQuarantineRecord>,
    key: &str,
    now: u64,
) -> bool {
    !state.due_complete
        && state
            .due_after_path
            .as_deref()
            .map_or(true, |after| key > after)
        && state
            .due_upper_path
            .as_deref()
            .is_some_and(|upper| key <= upper)
        && claude_index_path_member_ref(Path::new(key))
            .and_then(|member| records.get(member.root))
            .is_some_and(|record| {
                claude_retry_record_due(record, now.min(state.due_through), state.served_before)
            })
}

fn claude_retry_path_owed(
    state: &ClaudeRetryAdmission,
    records: &BTreeMap<String, ClaudeUsageAuthorityQuarantineRecord>,
    key: &str,
    now: u64,
) -> bool {
    let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
        return false;
    };
    let oversized = state.oversized_root.as_deref() == Some(member.root)
        && state
            .oversized_after_path
            .as_deref()
            .map_or(true, |after| key > after);
    oversized || claude_retry_path_due(state, records, key, now)
}

fn claude_retry_queue_due_families(index: &mut ScanIndex, collected_at: &str) {
    if !index.persistence_available() {
        return;
    }

    let now = rfc3339_unix_seconds(collected_at).unwrap_or_default();
    let became_storage_only = index
        .claude_stale_family_carry
        .origin
        .as_ref()
        .and_then(|origin| origin.admission.as_ref())
        .and_then(|state| state.oversized_root.as_deref())
        .is_some_and(|root| claude_retry_singleton_storage_only(index, root));
    let Some(state) = index
        .claude_stale_family_carry
        .origin
        .as_mut()
        .and_then(|origin| origin.admission.as_mut())
    else {
        return;
    };
    if became_storage_only {
        state.storage_deferred = true;
        state.oversized_root = None;
        state.oversized_after_path = None;
    }
    let Some(traversal) = index.traversal.as_mut() else {
        return;
    };
    // This cursor advances only when an ordinary selection slot is offered,
    // never when this seed examines or queues a path. Unserved paths therefore
    // retain the original deadline cutoff across ticks, starts and reloads.
    if state.oversized_root.as_ref().is_some_and(|root| {
        !index.files.keys().any(|key| {
            state
                .oversized_after_path
                .as_deref()
                .map_or(true, |after| key.as_str() > after)
                && claude_index_path_member_ref(Path::new(key))
                    .is_some_and(|member| member.root == root)
        })
    }) {
        state.oversized_root = None;
        state.oversized_after_path = None;
        state.progressed = true;
    }
    if !index
        .files
        .keys()
        .any(|key| claude_retry_path_due(state, &index.claude_usage_authority_quarantine, key, now))
    {
        state.due_complete = true;
    }
    state.complete = state.roots_complete
        && state.oversized_root.is_none()
        && state.due_complete
        && !state.storage_deferred;
    if state.roots_complete
        && state.storage_deferred
        && state.oversized_root.is_none()
        && state.due_complete
    {
        // Finishing the root walk does not cover deferred custody, and does
        // not earn another immediate start. Revisit it at ordinary backoff.
        state.progressed = false;
    }
    let mut cost = crate::heap_layout_bound::Counter::new(crate::source_rotation::PARKED_BUDGET);
    if cost
        .add(2 * CLAUDE_RETRY_DUE_PATHS * std::mem::size_of::<ScanTraversalPath>() + 128)
        .is_none()
    {
        return;
    }
    let mut seed = VecDeque::with_capacity(CLAUDE_RETRY_DUE_PATHS);
    for key in index.files.keys() {
        if seed.len() >= CLAUDE_RETRY_DUE_PATHS {
            break;
        }
        if !claude_retry_path_owed(state, &index.claude_usage_authority_quarantine, key, now) {
            continue;
        }
        // First match, not deepest: the root enters the sampled scope hash.
        let Some(root) = traversal.first_matching_scan_root(Path::new(key)) else {
            continue;
        };
        if cost
            .add(
                key.len()
                    .saturating_mul(4)
                    .saturating_add(std::mem::size_of::<ScanTraversalPath>()),
            )
            .is_none()
        {
            break;
        }
        // Discovery or an earlier short page can already own this path. Move
        // that opportunity to the priority prefix rather than duplicating it.
        if let Some(position) = traversal
            .pending_candidates
            .iter()
            .position(|candidate| candidate.path == Path::new(key))
        {
            seed.push_back(
                traversal
                    .pending_candidates
                    .remove(position)
                    .expect("position"),
            );
        } else {
            seed.push_back(ScanTraversalPath {
                scan_root: root.clone(),
                path: PathBuf::from(key),
                census_member: true,
                watcher_hint: false,
            });
        }
    }
    while let Some(path) = seed.pop_back() {
        traversal.pending_candidates.push_front(path);
    }
}

// Keep the real pre-audit selector portable: carry allocation itself requires
// validated native layouts, but deadline priority and cursor service do not.
fn claude_retry_select_due_paths(
    state: &ClaudeRetryAdmission,
    records: &BTreeMap<String, ClaudeUsageAuthorityQuarantineRecord>,
    candidates: &mut VecDeque<ScanTraversalPath>,
    selected: &mut Vec<ScanTraversalPath>,
    now: u64,
    limit: usize,
) {
    while selected.len() < limit {
        let due = candidates.front().is_some_and(|path| {
            claude_retry_path_owed(state, records, &local_index_key(&path.path), now)
        });
        if !due {
            break;
        }
        if let Some(path) = candidates.pop_front() {
            selected.push(path);
        }
    }
}

fn claude_retry_note_offered(
    index: &mut ScanIndex,
    paths: &[ScanTraversalPath],
    collected_at: &str,
) {
    let Some(state) = index
        .claude_stale_family_carry
        .origin
        .as_ref()
        .and_then(|origin| origin.admission.as_ref())
    else {
        return;
    };
    let now = rfc3339_unix_seconds(collected_at)
        .unwrap_or_default()
        .min(state.due_through);
    // Recovery can select owed opportunities before the authority selector.
    // Consume the actually offered contiguous prefix, regardless of which
    // selector chose it. An out-of-order recovery must not skip an unserved gap.
    let offered = |key: &str| paths.iter().any(|path| path.path == Path::new(key));
    let mut due_after = None;
    if !state.due_complete {
        for key in index.files.keys() {
            if !claude_retry_path_due(state, &index.claude_usage_authority_quarantine, key, now) {
                continue;
            }
            if !offered(key) {
                break;
            }
            due_after = Some(key.clone());
        }
    }
    let mut oversized_after = None;
    for key in index.files.keys() {
        if !state
            .oversized_after_path
            .as_deref()
            .map_or(true, |after| key.as_str() > after)
            || !claude_index_path_member_ref(Path::new(key))
                .is_some_and(|member| state.oversized_root.as_deref() == Some(member.root))
        {
            continue;
        }
        if !offered(key) {
            break;
        }
        crate::local_resource_diagnostics::claude_reread::retry_offered();
        oversized_after = Some(key.clone());
    }
    let oversized = state.oversized_root.clone();
    let previous = state.oversized_after_path.clone();
    if oversized_after.is_some() {
        for path in paths {
            let key = local_index_key(&path.path);
            if claude_index_path_member_ref(&path.path)
                .is_some_and(|m| oversized.as_deref() == Some(m.root))
                && previous
                    .as_deref()
                    .map_or(true, |after| key.as_str() > after)
                && oversized_after
                    .as_deref()
                    .is_some_and(|after| key.as_str() <= after)
            {
                if let Some(entry) = index.files.get_mut(&key) {
                    crate::local_resource_diagnostics::claude_reread::clear(
                        crate::local_resource_diagnostics::claude_reread::ClearSite::RetryAdmission,
                        !entry.source_file_fingerprint.is_empty(),
                    );
                    entry.source_file_fingerprint.clear();
                }
            }
        }
    }
    let state = index
        .claude_stale_family_carry
        .origin
        .as_mut()
        .and_then(|origin| origin.admission.as_mut())
        .expect("retained admission");
    state.progressed |= due_after.is_some() || oversized_after.is_some();
    if due_after.is_some() {
        state.due_after_path = due_after;
    }
    if oversized_after.is_some() {
        state.oversized_after_path = oversized_after;
    }
}

#[cfg(test)]
thread_local! {
    static RETRY_ADMISSION_REFUSE_MULTI: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
fn retry_admission_tests_refuse_multi() -> bool {
    RETRY_ADMISSION_REFUSE_MULTI.with(std::cell::Cell::get)
}
