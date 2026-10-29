// Temporary containment. No admitted read path or new persisted shape.
// A future paged fold must replace the reconstruction guard, not just flip a
// switch: a changed member may have replaced the old window's negative proof.
// This literal and static assertion belong to every non-test build. There is
// no feature, environment variable, serialized setting or release override.
const CLAUDE_RELEASE_TERMINAL_OFF: bool = true;
const _: () = assert!(CLAUDE_RELEASE_TERMINAL_OFF);

pub(crate) fn claude_terminal_off() -> bool {
    #[cfg(test)]
    if claude_completion_paths_for_test() {
        return false;
    }
    CLAUDE_RELEASE_TERMINAL_OFF
}

// Future-paging coverage only. A fixture must opt in explicitly, on its own
// thread; unwind restores the previous policy. Rc makes the guard !Send/!Sync,
// so moving it cannot silently change another fixture's policy.
#[cfg(test)]
thread_local! {
    static CLAUDE_COMPLETION_PATHS_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
fn claude_completion_paths_for_test() -> bool {
    CLAUDE_COMPLETION_PATHS_FOR_TEST.with(std::cell::Cell::get)
}
#[cfg(test)]
pub(crate) struct ClaudeCompletionPathsForTest {
    previous: bool,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(test)]
impl ClaudeCompletionPathsForTest {
    pub(crate) fn enable() -> Self {
        let previous = CLAUDE_COMPLETION_PATHS_FOR_TEST.with(|slot| slot.replace(true));
        Self {
            previous,
            _thread: std::marker::PhantomData,
        }
    }
}
#[cfg(test)]
impl Drop for ClaudeCompletionPathsForTest {
    fn drop(&mut self) {
        CLAUDE_COMPLETION_PATHS_FOR_TEST.with(|slot| slot.set(self.previous));
    }
}

#[cfg(test)]
mod completion_policy_tests {
    use super::*;

    #[test]
    fn money_upload_and_history_suites_have_no_completion_override() {
        for (suite, source) in [
            ("release-cut money receipts", include_str!("../snapshot_sync/money_equivalence_tests.rs")),
            ("E2 money pipeline", include_str!("../snapshot_sync/claude_money_e2_pipeline_tests.rs")),
            ("real finish", include_str!("../snapshot_sync/permanent_finish_pipeline_tests.rs")),
            ("prior-index finish", include_str!("../snapshot_sync/prior_index_lifetime_tests.rs")),
            ("history upgrade", include_str!("../snapshot_sync/history_upgrade_pipeline_tests.rs")),
            ("authority correction upload", include_str!("../snapshot_sync/authority_proof_correction_pipeline_tests.rs")),
            ("upload batching", include_str!("../snapshot_sync/e2_upload_tests.rs")),
            ("census pipeline", include_str!("../snapshot_sync/census_convergence_pipeline_tests.rs")),
        ] {
            assert!(!source.contains("ClaudeCompletionPathsForTest"), "{suite} must exercise production containment");
        }
        assert!(claude_terminal_off());
    }

    #[test]
    fn release_terminal_policy_is_constant_and_fixture_override_is_thread_scoped() {
        assert!(claude_terminal_off());
        let enabled = ClaudeCompletionPathsForTest::enable();
        assert!(!claude_terminal_off());
        // The non-test branch is this constant, even while this fixture opts in.
        let release_policy = std::hint::black_box(CLAUDE_RELEASE_TERMINAL_OFF);
        assert!(release_policy);
        assert!(std::thread::spawn(claude_terminal_off).join().unwrap());
        {
            let _nested = ClaudeCompletionPathsForTest::enable();
            assert!(!claude_terminal_off());
        }
        assert!(!claude_terminal_off());
        drop(enabled);
        assert!(claude_terminal_off());
        let _ = std::panic::catch_unwind(|| {
            let _unwind = ClaudeCompletionPathsForTest::enable();
            panic!("synthetic fixture unwind");
        });
        assert!(claude_terminal_off());
    }
}

// The containment veto is process policy, never a persisted fence mutation.
// In particular an old reader must reload the pre-containment fence value.
fn claude_effective_duplicate_fence_closed(index: &ScanIndex) -> bool {
    claude_terminal_off() || index.claude_duplicate_request_witness_overflowed
}

fn claude_terminal_reconstructed(index: &ScanIndex, window: &str) -> bool {
    index
        .claude_full_rearm_progress
        .complete_rebuild_read
        .as_ref()
        .is_some_and(|proof| {
            proof.origin.process == claude_full_rearm_process()
                && proof.origin.window_ends.contains(window)
                && proof.members_digest == claude_rebuild_members_digest(index)
                && index.claude_full_rearm_progress.traversal_origin.as_ref() == Some(&proof.origin)
        })
        && claude_family_members_unobserved_count(index, window, false) == 0
        && index
            .claude_usage_family_pending
            .values()
            .all(|p| !p.invalid && p.census_window_end == window)
        && index.decode_holds.is_empty()
        && !index.bounded_sweep_had_unsettled_upload
        && index.claude_usage_authority_quarantine.is_empty()
        && index.claude_account_deferred_holds.is_empty()
        && complete_claude_family_members(index)
            .iter()
            .all(|(root, members)| {
                index
                    .claude_usage_family_pending
                    .get(root)
                    .is_some_and(|pending| {
                        !pending.invalid
                            && pending.census_window_end == window
                            && pending
                                .member_request_id_hashes
                                .keys()
                                .cloned()
                                .collect::<BTreeSet<_>>()
                                == *members
                            && pending
                                .member_occurrences
                                .keys()
                                .cloned()
                                .collect::<BTreeSet<_>>()
                                == *members
                    })
            })
}

pub(crate) fn claude_terminal_authority(index: &ScanIndex, offered: bool, window: &str) -> bool {
    // Only the cfg(test) fixture guard exercises the historical completion
    // algorithms. A release caller must earn reconstruction before authority.
    #[cfg(test)]
    if claude_completion_paths_for_test() {
        return offered;
    }
    offered && !claude_terminal_off() && claude_terminal_reconstructed(index, window)
}

fn claude_redundant_stale_clear_suppressed(index: &ScanIndex) -> bool {
    // Only redundant stale-window debt; independent semantic/context clears
    // and every already-empty fingerprint remain owned by their usual gates.
    claude_terminal_off()
        && !index.claude_request_identity_contract_changed
        && index.upload_context_fingerprint == index.active_upload_context_fingerprint
}

fn claude_terminal_stale_roots(index: &ScanIndex, window: &str) -> BTreeSet<String> {
    index
        .claude_usage_family_pending
        .iter()
        .filter(|(_, p)| p.census_window_end != window)
        .map(|(root, _)| root.clone())
        .collect()
}

fn claude_terminal_unproven(index: &ScanIndex, window: &str) {
    let stale = index
        .claude_usage_family_pending
        .values()
        .filter(|p| p.census_window_end != window)
        .count();
    eprintln!("ALARM claude_terminal_off unproven_families={stale}: stale pending retains UNPROVEN custody until paged reconstruction");
}

static CLAUDE_TERMINAL_OFF_OFFERS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[derive(Default)]
struct StartIdentitySamples {
    files: BTreeSet<(u64, u64)>,
    observations: u64,
    bytes: u64,
}
thread_local! {
    static START_IDENTITY_SAMPLES: std::cell::RefCell<StartIdentitySamples> = std::cell::RefCell::new(StartIdentitySamples::default());
}
#[cfg(test)]
thread_local! {
    static TERMINAL_OFF_BODY_BYTES_FOR_TEST: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static START_IDENTITY_SAMPLE_FOR_TEST: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
}
fn reset_start_identity_samples() {
    START_IDENTITY_SAMPLES.with(|counts| *counts.borrow_mut() = StartIdentitySamples::default());
}
fn note_start_identity_sample(source: SnapshotSource, file: &File, samples: &OpenedContentSamples) {
    if source != SnapshotSource::ClaudeCode {
        return;
    }
    let bytes = (samples.head.len() + samples.tail.as_ref().map_or(0, Vec::len)) as u64;
    START_IDENTITY_SAMPLES.with(|counts| {
        let mut counts = counts.borrow_mut();
        counts.observations += 1;
        counts.bytes += bytes;
        if let Ok(metadata) = file.metadata() {
            if let Some([device, inode]) = physical_identity(&metadata) {
                counts.files.insert((device, inode));
            }
        }
    });
    #[cfg(test)]
    START_IDENTITY_SAMPLE_FOR_TEST.with(|v| {
        let (f, b) = v.get();
        v.set((f + 1, b + bytes));
    });
}

fn terminal_off_offer(index: &ScanIndex, window: &str) {
    use std::sync::atomic::Ordering::Relaxed;
    let offers = CLAUDE_TERMINAL_OFF_OFFERS.fetch_add(1, Relaxed) + 1;
    static SINCE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let since = SINCE.get_or_init(|| unix_seconds(SystemTime::now()).unwrap_or_default());
    eprintln!("ALARM claude_terminal_off offers={offers} since_unix_seconds={since} rearm_full_suppressed=1: terminal authority withheld; ordinary page upload/ACK/save continues");
    START_IDENTITY_SAMPLES.with(|counts| {
        let counts = counts.borrow();
        eprintln!(
            "start_identity_sample files={} observations={} bytes={} scope=walk",
            counts.files.len(),
            counts.observations,
            counts.bytes
        );
    });
    claude_terminal_unproven(index, window);
}

fn claude_terminal_rewind(traversal: &mut ScanTraversalCheckpoint) {
    // Existing queue is durable demand; re-list metadata without throwing it
    // away, changing the frozen window or minting a new native owner.
    for root in &traversal.scan_roots {
        if !traversal
            .pending_directories
            .iter()
            .any(|p| p.path == *root)
        {
            traversal.pending_directories.push_back(ScanTraversalPath {
                scan_root: root.clone(),
                path: root.clone(),
                census_member: true,
                watcher_hint: false,
            });
        }
    }
}

fn refresh_terminal_off_discovery(
    index: &mut ScanIndex,
    roots: &[PathBuf],
    at: &str,
    overflow: bool,
) {
    let now = rfc3339_unix_seconds(at).unwrap_or_default();
    let due = index
        .claude_full_rearm_progress
        .terminal_off_rediscovery_after;
    // Revalidate configured targets EVERY pass, before selecting retained
    // paths, even when the readdir cadence is not due. A retargeted symlink
    // must not leave its old canonical target authorized for collection.
    let mut census = ScanCensus::default();
    let resolved = roots
        .iter()
        .filter_map(|root| {
            resolve_configured_scan_root(SnapshotSource::ClaudeCode, root, &mut census)
        })
        .collect::<Vec<_>>();
    let Some(traversal) = index.traversal.as_mut() else {
        return;
    };
    let changed = traversal.scan_roots != resolved;
    if changed {
        traversal.scan_roots = resolved;
        // Only scheduling authority leaves scope. Accepted bodies, held
        // evidence and negative custody in the index are never retired here.
        traversal
            .pending_directories
            .retain(|p| traversal.scan_roots.contains(&p.scan_root));
        traversal
            .pending_candidates
            .retain(|p| traversal.scan_roots.contains(&p.scan_root));
        index
            .claude_stale_family_carry
            .replay
            .retain(|p| traversal.scan_roots.contains(&p.scan_root));
    }
    if !changed && !overflow && due != 0 && now < due {
        return;
    }
    if !traversal.pending_directories.is_empty() {
        return;
    }
    reset_start_identity_samples();
    claude_terminal_rewind(traversal);
    index
        .claude_full_rearm_progress
        .terminal_off_rediscovery_after = now.saturating_add(300);
    eprintln!("claude_terminal_off rediscovery=1 watcher_loss={} resolved_roots_changed={} directories={} bytes=0: bounded stat/readdir; candidate identity samples counted separately", u8::from(overflow), u8::from(changed), traversal.pending_directories.len());
}

fn carry_admission_debt(index: &ScanIndex, at: &str) -> (usize, u64) {
    let Some(traversal) = index.traversal.as_ref() else {
        return (0, 0);
    };
    let now = rfc3339_unix_seconds(at).unwrap_or_default();
    let mut families = 0;
    let mut oldest = now;
    for (root, pending) in &index.claude_usage_family_pending {
        if pending.census_window_end != traversal.census_window_end
            && !index.claude_stale_family_carry.contains(root)
        {
            families += 1;
            if let Some(time) = rfc3339_unix_seconds(&pending.census_window_end) {
                oldest = oldest.min(time);
            }
        }
    }
    (families, now.saturating_sub(oldest))
}

fn carry_admission_stall(index: &ScanIndex, at: &str) {
    let (families, oldest_age) = carry_admission_debt(index, at);
    eprintln!("ALARM carry_admission_stalled families={families} oldest_age={oldest_age}: denied members remain UNPROVEN; family-scoping B deferred");
}

fn resume_claude_retry_admission(index: &mut ScanIndex, at: &str) {
    let Some(mut previous) = index
        .claude_stale_family_carry
        .origin
        .as_ref()
        .and_then(|o| o.admission.clone())
    else {
        return;
    };
    let now = rfc3339_unix_seconds(at).unwrap_or_default();
    let new_due = index
        .claude_usage_authority_quarantine
        .values()
        .any(|record| {
            record.disposition == ClaudeUsageAuthorityQuarantineDisposition::RetryPending
                && record.retry_after_unix_seconds > previous.due_through
                && record.retry_after_unix_seconds <= now
        });
    if previous.roots_complete && previous.due_complete && new_due {
        previous.complete = false;
        previous.served_before = previous.due_through;
        previous.due_through = now;
        previous.due_after_path = None;
        previous.due_upper_path = index.files.keys().next_back().cloned();
        previous.due_complete = false;
    }
    if previous.complete {
        carry_admission_stall(index, at);
        return;
    }
    // Storage-only debt does not restart the root cursor on every tick. Its
    // alarm is the explicit trigger for the later family-scoping work.
    if previous.roots_complete
        && previous.storage_deferred
        && previous.oversized_root.is_none()
        && previous.due_complete
    {
        carry_admission_stall(index, at);
        return;
    }
    let Some(window) = index
        .traversal
        .as_ref()
        .map(|t| t.census_window_end.clone())
    else {
        return;
    };
    let lower = previous
        .after_root
        .clone()
        .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
    let stale = index
        .claude_usage_family_pending
        .range((
            lower,
            std::ops::Bound::Included(previous.upper_root.clone()),
        ))
        .filter(|(_, p)| p.census_window_end != window)
        .take(CLAUDE_RETRY_ADMISSION_ROOTS + 1)
        .map(|(root, _)| root.clone())
        .collect();
    let (new_carry, _, mut state) = claude_retry_admit_batch_observed(
        index,
        &stale,
        Some(&previous),
        at,
        &mut Default::default(),
        claude_contract_debt_scope(index),
    );
    // Retain EVERY prior batch's cancellation owner. Price the entire union
    // under the existing reserve bound, rather than accumulate unbounded carry.
    let mut roots = index
        .claude_stale_family_carry
        .roots
        .union(&index.claude_stale_family_carry.capped_roots)
        .cloned()
        .collect::<BTreeSet<_>>();
    roots.extend(new_carry.roots.iter().cloned());
    let requested = roots.clone();
    let old = index
        .claude_stale_family_carry
        .roots
        .union(&index.claude_stale_family_carry.capped_roots)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut refused = false;
    let reserve = fund_claude_family_carry_cancellations(index, &mut roots, |_, _| refused = true);
    // A failed cumulative reserve may refuse old roots as well. Never install
    // that subset: it would orphan already compacted carry/replay custody.
    if refused
        || roots != requested
        || !old.is_subset(&roots)
        || !claude_family_carry_cancellation_admitted(
            index.claude_stale_family_carry.replay.len(),
            index.claude_stale_family_carry.replay.capacity(),
            reserve.capacity(),
            index
                .claude_stale_family_carry
                .replay
                .iter()
                .map(|p| {
                    p.path
                        .as_os_str()
                        .len()
                        .saturating_add(p.scan_root.as_os_str().len())
                })
                .sum(),
        )
    {
        state.storage_deferred = true;
        state.complete = false;
        // All newly refused pending remains unmodified; old carry still owns
        // its replay and is refunded by the ordinary resume guard next tick.
    } else {
        let carry = &mut index.claude_stale_family_carry;
        for root in new_carry.roots {
            if let Some(pending) = index.claude_usage_family_pending.get_mut(&root) {
                pending.member_occurrences.clear();
                pending
                    .member_request_id_hashes
                    .values_mut()
                    .for_each(BTreeSet::clear);
            }
            carry.roots.insert(root);
        }
        // The new reserve pays all prior cancellation obligations. Demand
        // already queued is retained; it cannot be discarded with a batch.
        let replay = std::mem::take(&mut carry.replay);
        carry.replay = reserve;
        carry.replay.extend(replay);
    }
    let advanced = state.after_root != previous.after_root;
    if let Some(origin) = index.claude_stale_family_carry.origin.as_mut() {
        origin.admission = Some(state);
    }
    eprintln!(
        "carry_admission_resume batches=1 cursor_advanced={} traversal_restarts=0",
        u8::from(advanced)
    );
    if !advanced {
        carry_admission_stall(index, at);
    }
}

fn enqueue_terminal_off_retry(traversal: &mut ScanTraversalCheckpoint, key: &str) {
    let path = Path::new(key);
    if claude_index_path_member_ref(path).is_none()
        || path.extension().and_then(|v| v.to_str()) != Some("jsonl")
    {
        return;
    }
    let Some(root) = traversal
        .scan_roots
        .iter()
        .filter(|r| path.starts_with(r))
        .max_by_key(|r| r.components().count())
    else {
        return;
    };
    if !traversal.pending_candidates.iter().any(|p| p.path == path) {
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root: root.clone(),
            path: path.to_path_buf(),
            census_member: true,
            watcher_hint: false,
        });
    }
}

impl ScanIndex {
    #[cfg(test)]
    pub(crate) fn has_retained_traversal_for_terminal_off(&self) -> bool {
        self.traversal.is_some()
    }

    fn retain_terminal_off_held_retries(&mut self, keys: &BTreeSet<String>) {
        if !claude_terminal_off() {
            return;
        }
        if let Some(traversal) = self.traversal.as_mut() {
            for key in keys {
                enqueue_terminal_off_retry(traversal, key);
            }
        }
    }

    fn retain_terminal_off_page_retries(
        &self,
        previous: &ScanIndex,
        safe: &BTreeSet<String>,
        selected: &mut ScanIndex,
    ) {
        if !claude_terminal_off() {
            return;
        }
        let Some(traversal) = selected.traversal.as_mut() else {
            return;
        };
        for (key, working) in &self.files {
            if safe.contains(key) || self.decode_holds_file(key) {
                continue;
            }
            if previous.files.get(key).is_some_and(|old| {
                old.source_file_fingerprint == working.source_file_fingerprint
                    && old.last_snapshot_fingerprint == working.last_snapshot_fingerprint
                    && old.last_upload_body_witness == working.last_upload_body_witness
            }) {
                continue;
            }
            enqueue_terminal_off_retry(traversal, key);
        }
    }
}
