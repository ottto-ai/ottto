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
    _refusal: ClaudeRetryAdmissionRefusal,
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
            served_before: 0,
        });
    state.served_before = index
        .traversal
        .as_ref()
        .and_then(|t| rfc3339_unix_seconds(&t.census_window_end))
        .unwrap_or_default();
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
            state.complete = true;
            state.progressed = true;
            return (ClaudeStaleFamilyCarry::default(), batch, state);
        }
        match claude_stream_accepted_retry_carry(index, &batch) {
            Ok(carry) => {
                state.after_root = batch.last().cloned();
                state.complete = state.after_root.as_ref().is_some_and(|after| {
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
                // One indivisible family can exceed the same cap. Do not clear
                // it, credit proof, or pin all later roots behind it. Its normal
                // candidate/authority gates and later retry retain that debt.
                state.after_root = batch.last().cloned();
                state.complete = state.after_root.as_ref().is_some_and(|after| {
                    !stale
                        .iter()
                        .any(|root| root > after && root <= &state.upper_root)
                });
                state.progressed = true;
                eprintln!("local snapshot census deferred one oversized Claude retry family without rearm; bounded admission continues");
                return (ClaudeStaleFamilyCarry::default(), BTreeSet::new(), state);
            }
            Err(_) => return (ClaudeStaleFamilyCarry::default(), BTreeSet::new(), state),
        }
    }
}

fn claude_retry_queue_due_families(index: &mut ScanIndex, collected_at: &str) {
    let now = rfc3339_unix_seconds(collected_at).unwrap_or_default();
    let Some(state) = index
        .claude_stale_family_carry
        .origin
        .as_ref()
        .and_then(|origin| origin.admission.as_ref())
    else {
        return;
    };
    let Some(traversal) = index.traversal.as_mut() else {
        return;
    };
    let mut cost = crate::heap_layout_bound::Counter::new(crate::source_rotation::PARKED_BUDGET);
    for key in index.files.keys() {
        if traversal.pending_candidates.len() >= CLAUDE_RETRY_DUE_PATHS {
            break;
        }
        let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
            continue;
        };
        if !index
            .claude_usage_authority_quarantine
            .get(member.root)
            .is_some_and(|record| claude_retry_record_due(record, now, state.served_before))
        {
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
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root: root.clone(),
            path: PathBuf::from(key),
            census_member: true,
            watcher_hint: false,
        });
    }
}
