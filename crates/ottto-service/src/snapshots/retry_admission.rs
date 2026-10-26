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
    let mut state = previous
        .filter(|state| !state.complete)
        .cloned()
        .unwrap_or_else(|| ClaudeRetryAdmission {
            after_root: None,
            upper_root: stale.last().cloned().unwrap_or_default(),
            complete: false,
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
            state.complete = state.oversized_root.is_none() && state.due_complete;
            state.progressed = true;
            return (ClaudeStaleFamilyCarry::default(), batch, state);
        }
        match claude_stream_accepted_retry_carry(index, &batch) {
            Ok(carry) => {
                state.after_root = batch.last().cloned();
                state.complete = state.oversized_root.is_none()
                    && state.due_complete
                    && state.after_root.as_ref().is_some_and(|after| {
                        !stale
                            .iter()
                            .any(|root| root > after && root <= &state.upper_root)
                    });
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
                // One bounded, durable fallback at a time. Later fitting roots
                // can advance while it is served; another oversized root waits
                // here instead of losing its obligation or growing a debt map.
                let root = batch.first().expect("singleton");
                if state
                    .oversized_root
                    .as_ref()
                    .is_some_and(|owed| owed != root)
                {
                    return (ClaudeStaleFamilyCarry::default(), BTreeSet::new(), state);
                }
                state.oversized_root = Some(root.clone());
                state.after_root = Some(root.clone());
                state.complete = false;
                state.progressed = true;
                eprintln!("local snapshot census retained one oversized Claude retry family for bounded ordinary service; coverage remains incomplete");
                return (ClaudeStaleFamilyCarry::default(), BTreeSet::new(), state);
            }
            Err(_) => return (ClaudeStaleFamilyCarry::default(), BTreeSet::new(), state),
        }
    }
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
            .is_none_or(|after| key > after);
    let due = !state.due_complete
        && state
            .due_after_path
            .as_deref()
            .is_none_or(|after| key > after)
        && state
            .due_upper_path
            .as_deref()
            .is_some_and(|upper| key <= upper)
        && records.get(member.root).is_some_and(|record| {
            claude_retry_record_due(record, now.min(state.due_through), state.served_before)
        });
    oversized || due
}

fn claude_retry_queue_due_families(index: &mut ScanIndex, collected_at: &str) {
    let now = rfc3339_unix_seconds(collected_at).unwrap_or_default();
    let Some(state) = index
        .claude_stale_family_carry
        .origin
        .as_mut()
        .and_then(|origin| origin.admission.as_mut())
    else {
        return;
    };
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
                .is_none_or(|after| key.as_str() > after)
                && claude_index_path_member_ref(Path::new(key))
                    .is_some_and(|member| member.root == root)
        })
    }) {
        state.oversized_root = None;
        state.oversized_after_path = None;
        state.progressed = true;
    }
    if !index.files.keys().any(|key| {
        !state.due_complete
            && state
                .due_after_path
                .as_deref()
                .is_none_or(|after| key.as_str() > after)
            && state
                .due_upper_path
                .as_deref()
                .is_some_and(|upper| key.as_str() <= upper)
            && claude_index_path_member_ref(Path::new(key))
                .and_then(|member| index.claude_usage_authority_quarantine.get(member.root))
                .is_some_and(|record| {
                    claude_retry_record_due(record, now.min(state.due_through), state.served_before)
                })
    }) {
        state.due_complete = true;
    }
    let roots_done = !index.claude_usage_family_pending.keys().any(|root| {
        state
            .after_root
            .as_deref()
            .is_none_or(|after| root.as_str() > after)
            && root <= &state.upper_root
    });
    state.complete = roots_done && state.oversized_root.is_none() && state.due_complete;
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
        let Some(root) = traversal
            .scan_roots
            .iter()
            .find(|root| Path::new(key).starts_with(root))
        else {
            continue;
        };
        if cost
            .add(
                key.len()
                    .saturating_mul(2)
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

fn claude_retry_note_offered(
    index: &mut ScanIndex,
    paths: &[ScanTraversalPath],
    collected_at: &str,
) {
    let oversized = index
        .claude_stale_family_carry
        .origin
        .as_ref()
        .and_then(|origin| origin.admission.as_ref())
        .and_then(|state| state.oversized_root.clone());
    let context = index
        .traversal
        .as_ref()
        .expect("active traversal")
        .context_fingerprint
        .clone();
    // Observe exactly the fallback keys that are actually about to be cleared.
    // The guard remains observe-only; no acceptance or identity gate is skipped.
    let held = oversized.is_some()
        && index.reread_plan_for_rearms(
            SnapshotSource::ClaudeCode,
            collected_at,
            &context,
            false,
            |key| {
                oversized.as_deref().is_some_and(|root| {
                    claude_index_path_member_ref(Path::new(key)).is_some_and(|m| m.root == root)
                }) && paths.iter().any(|path| path.path == Path::new(key))
            },
        );
    let Some(state) = index
        .claude_stale_family_carry
        .origin
        .as_mut()
        .and_then(|origin| origin.admission.as_mut())
    else {
        return;
    };
    state.progressed |= !paths.is_empty();
    for path in paths {
        let key = local_index_key(&path.path);
        let Some(member) = claude_index_path_member_ref(&path.path) else {
            continue;
        };
        if !state.due_complete
            && state
                .due_after_path
                .as_deref()
                .is_none_or(|after| key.as_str() > after)
        {
            state.due_after_path = Some(key.clone());
        }
        if state.oversized_root.as_deref() == Some(member.root) && !held {
            if let Some(entry) = index.files.get_mut(&key) {
                entry.source_file_fingerprint.clear();
            }
            state.oversized_after_path = Some(key);
        }
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
