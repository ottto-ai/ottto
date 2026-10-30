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
            (
                "release-cut money receipts",
                include_str!("../snapshot_sync/money_equivalence_tests.rs"),
            ),
            (
                "E2 money pipeline",
                include_str!("../snapshot_sync/claude_money_e2_pipeline_tests.rs"),
            ),
            (
                "real finish",
                include_str!("../snapshot_sync/permanent_finish_pipeline_tests.rs"),
            ),
            (
                "prior-index finish",
                include_str!("../snapshot_sync/prior_index_lifetime_tests.rs"),
            ),
            (
                "history upgrade",
                include_str!("../snapshot_sync/history_upgrade_pipeline_tests.rs"),
            ),
            (
                "authority correction upload",
                include_str!("../snapshot_sync/authority_proof_correction_pipeline_tests.rs"),
            ),
            (
                "upload batching",
                include_str!("../snapshot_sync/e2_upload_tests.rs"),
            ),
            (
                "census pipeline",
                include_str!("../snapshot_sync/census_convergence_pipeline_tests.rs"),
            ),
        ] {
            assert!(
                !source.contains("ClaudeCompletionPathsForTest"),
                "{suite} must exercise production containment"
            );
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

// Empty projections cannot earn delivery receipts. This bounded process memo
// suppresses only their redundant UploadContext read, never another read cause.
// Hashes bind the exact path/context/source witness; eviction/restart permits
// another ordinary read and grants no ACK, absence, settlement or proof credit.
const TERMINAL_OFF_EMPTY_CONTEXT_KEYS: usize = 4096;
#[derive(Default)]
struct TerminalOffEmptyContexts {
    keys: BTreeSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    evictions: u64,
}
impl TerminalOffEmptyContexts {
    fn remember(&mut self, key: [u8; 32]) {
        if self.keys.contains(&key) {
            return;
        }
        if self.keys.len() == TERMINAL_OFF_EMPTY_CONTEXT_KEYS {
            let oldest = self.order.pop_front().expect("bounded memo has an owner");
            self.keys.remove(&oldest);
            self.evictions = self.evictions.saturating_add(1);
            eprintln!("upload_context_empty_memo_evicted evictions={} capacity={TERMINAL_OFF_EMPTY_CONTEXT_KEYS}", self.evictions);
        }
        self.keys.insert(key);
        self.order.push_back(key);
    }
}
#[cfg(test)]
thread_local! {
    static TERMINAL_OFF_EMPTY_CONTEXTS: std::cell::RefCell<TerminalOffEmptyContexts> =
        std::cell::RefCell::new(TerminalOffEmptyContexts::default());
    static TERMINAL_OFF_EMPTY_REPARSES_FOR_TEST: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
fn with_terminal_off_empty_contexts<T>(f: impl FnOnce(&mut TerminalOffEmptyContexts) -> T) -> T {
    #[cfg(not(test))]
    {
        static MEMO: std::sync::OnceLock<std::sync::Mutex<TerminalOffEmptyContexts>> =
            std::sync::OnceLock::new();
        f(&mut MEMO
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }
    #[cfg(test)]
    TERMINAL_OFF_EMPTY_CONTEXTS.with(|memo| f(&mut memo.borrow_mut()))
}
fn terminal_off_empty_context_key(index: &ScanIndex, key: &str) -> Option<[u8; 32]> {
    if !claude_terminal_off() || !index.confirmed_empty_files.contains(key) {
        return None;
    }
    let entry = index.files.get(key)?;
    if entry.source_file_fingerprint.is_empty() {
        return None; // Genuine cleared/unknown debt can never reuse the memo.
    }
    let mut digest = Sha256::new();
    for value in [
        "terminal-off-empty-context:v1",
        key,
        index.active_upload_context_fingerprint.as_deref()?,
        &entry.source_file_fingerprint,
        index
            .historical_replay_generation
            .as_deref()
            .unwrap_or("none"),
    ] {
        update_length_prefixed(&mut digest, value.as_bytes());
    }
    digest.update(index.context_curve_replay_epoch.to_be_bytes());
    Some(digest.finalize().into())
}
fn terminal_off_empty_context_seen(index: &ScanIndex, key: &str) -> bool {
    terminal_off_empty_context_key(index, key)
        .is_some_and(|key| with_terminal_off_empty_contexts(|memo| memo.keys.contains(&key)))
}
fn note_terminal_off_empty_context(index: &ScanIndex, key: &str, parsed_fingerprint: &str) {
    if !index
        .files
        .get(key)
        .is_some_and(|entry| entry.source_file_fingerprint == parsed_fingerprint)
    {
        return;
    }
    if let Some(key) = terminal_off_empty_context_key(index, key) {
        with_terminal_off_empty_contexts(|memo| memo.remember(key));
    }
}

// Scheduling only: ordinary ScanIndex reloads must not reset the cadence.
// Fixed-size hashed scopes retain no transcript/path strings. Eviction and a
// process restart fail toward one metadata rewalk, never toward proof.
const TERMINAL_OFF_REDISCOVERY_SCOPES: usize = 64;
#[cfg(not(test))]
static TERMINAL_OFF_REDISCOVERY: std::sync::Mutex<BTreeMap<String, u64>> =
    std::sync::Mutex::new(BTreeMap::new());
#[cfg(test)]
thread_local! {
    static TERMINAL_OFF_REDISCOVERY: std::cell::RefCell<BTreeMap<String, u64>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
}
fn terminal_off_rediscovery_due(scope: String, now: u64, force: bool) -> bool {
    let check = |memo: &mut BTreeMap<String, u64>| {
        if !force && memo.get(&scope).is_some_and(|due| now < *due) {
            return false;
        }
        if !memo.contains_key(&scope) && memo.len() >= TERMINAL_OFF_REDISCOVERY_SCOPES {
            if let Some(oldest) = memo
                .iter()
                .min_by_key(|(_, due)| **due)
                .map(|(key, _)| key.clone())
            {
                memo.remove(&oldest);
                eprintln!("claude_terminal_off rediscovery_memo_evicted=1 capacity=64");
            }
        }
        memo.insert(scope, now.saturating_add(300));
        true
    };
    #[cfg(not(test))]
    {
        check(
            &mut TERMINAL_OFF_REDISCOVERY
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
    #[cfg(test)]
    TERMINAL_OFF_REDISCOVERY.with(|memo| check(&mut memo.borrow_mut()))
}
// Reader/identity fixture drivers model an explicitly due discovery walk,
// rather than an idle daemon tick at the same fixed fixture timestamp.
#[cfg(test)]
pub(crate) fn expire_terminal_off_discovery_for_test(index: &ScanIndex) {
    if let Some(scope) = terminal_off_rediscovery_scope(index) {
        TERMINAL_OFF_REDISCOVERY.with(|memo| memo.borrow_mut().remove(&scope));
    }
}

// A counterfactual preview must not consume the real page owner's process
// scheduling turn. Restore only the test-local memo, including on unwind.
#[cfg(test)]
pub(crate) struct TerminalOffDiscoveryPreviewForTest {
    saved: BTreeMap<String, u64>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(test)]
impl TerminalOffDiscoveryPreviewForTest {
    pub(crate) fn begin() -> Self {
        Self {
            saved: TERMINAL_OFF_REDISCOVERY.with(|memo| memo.borrow().clone()),
            _thread: std::marker::PhantomData,
        }
    }
}
#[cfg(test)]
impl Drop for TerminalOffDiscoveryPreviewForTest {
    fn drop(&mut self) {
        TERMINAL_OFF_REDISCOVERY.with(|memo| *memo.borrow_mut() = std::mem::take(&mut self.saved));
    }
}

fn terminal_off_rediscovery_scope(index: &ScanIndex) -> Option<String> {
    let traversal = index.traversal.as_ref()?;
    let mut digest = Sha256::new();
    for value in [
        "terminal-off-rediscovery:v1",
        index
            .active_upload_context_fingerprint
            .as_deref()
            .unwrap_or("none"),
        index
            .historical_replay_generation
            .as_deref()
            .unwrap_or("none"),
        &traversal.context_fingerprint,
        &traversal.census_window_end,
    ] {
        update_length_prefixed(&mut digest, value.as_bytes());
    }
    for root in &traversal.scan_roots {
        update_length_prefixed(&mut digest, local_index_key(root).as_bytes());
    }
    Some(format!("{:x}", digest.finalize()))
}

fn refresh_terminal_off_discovery(
    index: &mut ScanIndex,
    roots: &[PathBuf],
    now: u64,
    overflow: bool,
) {
    // The selecting page owns this clock, including all cooperative yields.
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
    let scope = terminal_off_rediscovery_scope(index).expect("retained traversal");
    // Cadence parks only discovery of otherwise idle work. It must not
    // suppress already admitted reconstruction/transport/history debt when
    // the corresponding path was consumed earlier in this retained window.
    // This wakes the existing bounded metadata walk; the ordinary candidate
    // selector and privacy/history/backoff gates still own every body read.
    let owed = index
        .terminal_contract_retries
        .values()
        .any(|key| !sampled_audit::candidate_open_blocked(key, now))
        || index.files.iter().any(|(key, entry)| {
            // No receipt can discharge an empty or body-witness-less key.
            // Those keys keep ordinary discovery cadence and independent debt.
            let receipt_mintable = entry.last_upload_body_witness.is_some()
                && index
                    .file_snapshot_fingerprints
                    .get(key)
                    .is_some_and(|members| !members.is_empty());
            let needs_service = (receipt_mintable
                && ((index.file_upload_context_requires_adoption(key)
                    && !index.file_upload_context_waits_for_retry(key))
                    || index.effective_upload_body_witness_revision_requires_adoption(key)))
                || entry.source_file_fingerprint.is_empty()
                || (!entry.has_unverified_source()
                    && entry.scan_identity_version.as_deref()
                        != Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION))
                || sampled_audit::debt_for_key(index, key, now)
                    .is_some_and(|debt| now >= debt.due_unix_seconds);
            // Keep D, but a forbidden open cannot authorize a whole-corpus
            // rewalk. This is metadata-only: #903's same-stat backoff/park
            // remains authoritative, while a changed stat wakes this key.
            needs_service && !sampled_audit::candidate_open_blocked(key, now)
        });
    if !terminal_off_rediscovery_due(scope, now, changed || overflow || owed) {
        return;
    }
    let traversal = index.traversal.as_mut().expect("retained traversal");
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

fn enqueue_terminal_off_retry(
    traversal: &mut ScanTraversalCheckpoint,
    admitted: &ScanTraversalPath,
    census_member: bool,
) {
    // Scope includes the acquisition root. Reconstructing the deepest root
    // here can invent ScopeChanged on unchanged bytes under overlapping roots.
    // A real configured-root change still invalidates this scheduling owner.
    if !traversal.scan_roots.contains(&admitted.scan_root)
        || !admitted.path.starts_with(&admitted.scan_root)
        || claude_index_path_member_ref(&admitted.path).is_none()
        || admitted.path.extension().and_then(|v| v.to_str()) != Some("jsonl")
    {
        return;
    }
    if let Some(queued) = traversal
        .pending_candidates
        .iter_mut()
        .find(|p| p.path == admitted.path)
    {
        queued.scan_root.clone_from(&admitted.scan_root);
    } else {
        let mut retry = admitted.clone();
        retry.census_member = census_member;
        traversal.pending_candidates.push_back(retry);
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
                // Already observed held custody is a reread, not new discovery.
                // G1 lets real-loss/floor retries restart despite rereads.
                if let Some(admitted) = self
                    .claude_full_rearm_progress
                    .terminal_off_admitted
                    .iter()
                    .find(|p| local_index_key(&p.path) == *key)
                {
                    enqueue_terminal_off_retry(traversal, admitted, false);
                }
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
            if let Some(admitted) = self
                .claude_full_rearm_progress
                .terminal_off_admitted
                .iter()
                .find(|p| local_index_key(&p.path) == *key)
            {
                enqueue_terminal_off_retry(traversal, admitted, true);
            }
        }
    }
}

/// Gauges only; clocks are the oldest retained durable evidence, not an
/// invented time of absence. Old records with no clock report unknown_age.
/// This read-only view cannot retire debt, settle an ACK or grant proof.
#[derive(Debug, Serialize)]
struct RetentionGauge {
    items: usize,
    /// Compact retained metadata bytes; excludes the external transcript corpus.
    bytes: Option<usize>,
    oldest_age_seconds: Option<u64>,
    unknown_age: usize,
}
impl Default for RetentionGauge {
    fn default() -> Self {
        Self {
            items: 0,
            bytes: Some(0),
            oldest_age_seconds: None,
            unknown_age: 0,
        }
    }
}
impl RetentionGauge {
    fn charge<T: Serialize + ?Sized>(&mut self, value: &T) {
        self.bytes = Some(
            self.bytes
                .unwrap_or(0)
                .saturating_add(retained_metadata_bytes(value)),
        );
    }
    fn observe(&mut self, count: usize, clock: Option<u64>, now: u64) {
        self.items = self.items.saturating_add(count);
        match clock {
            Some(clock) => {
                self.oldest_age_seconds = Some(
                    self.oldest_age_seconds
                        .unwrap_or(0)
                        .max(now.saturating_sub(clock)),
                )
            }
            None => self.unknown_age = self.unknown_age.saturating_add(count),
        }
    }
}
#[derive(Default, Debug, Serialize)]
struct TerminalRetention {
    retry_pending_families: RetentionGauge,
    file_entries: RetentionGauge,
    accepted_index_acks: RetentionGauge,
    held_history_files: RetentionGauge,
    tombstones: RetentionGauge,
    manifest_withheld: RetentionGauge,
    delayed_proof_families: RetentionGauge,
    owed_correction_members: RetentionGauge,
}
impl ScanIndex {
    fn terminal_off_retention(&self, now: u64) -> TerminalRetention {
        let mut debt = TerminalRetention::default();
        if !claude_terminal_off() {
            return debt;
        }
        for (root, record) in &self.claude_usage_authority_quarantine {
            let clock = self
                .claude_usage_family_pending
                .get(root)
                .and_then(|p| rfc3339_unix_seconds(&p.census_window_end));
            if record.disposition == ClaudeUsageAuthorityQuarantineDisposition::RetryPending {
                // Presence/absence remains UNPROVEN; count every retained owner,
                // including possible absence, rather than stat the corpus here.
                debt.retry_pending_families.observe(1, clock, now);
                debt.retry_pending_families.charge(&(root, record));
            }
            if let Some(correction) = &record.proof_correction {
                debt.owed_correction_members.charge(correction);
                debt.owed_correction_members
                    .observe(correction.owed_member_ids.len(), clock, now);
            }
        }
        // An older witness does not settle this pending census or prove a
        // changed revision. Count all retained pending, including future
        // correction/reconstruction debt behind an existing witness.
        for pending in self.claude_usage_family_pending.values() {
            // This optional extra gauge has potentially corpus-sized occurrence
            // maps. Do not serialize them every page for diagnostics alone.
            debt.delayed_proof_families.bytes = None;
            debt.delayed_proof_families.observe(
                1,
                rfc3339_unix_seconds(&pending.census_window_end),
                now,
            );
        }
        for (key, entry) in &self.files {
            let clock = (entry.modified_unix_seconds > 0).then_some(entry.modified_unix_seconds);
            debt.file_entries.observe(1, clock, now);
            debt.file_entries.charge(&(key, entry));
            if self
                .claude_history_emission_held(&entry.source_file_fingerprint)
                .is_some()
            {
                debt.held_history_files.observe(1, clock, now);
                debt.held_history_files.charge(&(key, entry));
            }
        }
        for fp in &self.accepted_snapshot_fingerprints {
            debt.accepted_index_acks.charge(fp);
            debt.accepted_index_acks.observe(
                1,
                self.snapshot_activity_at
                    .get(fp)
                    .and_then(|at| at.as_deref())
                    .and_then(rfc3339_unix_seconds),
                now,
            );
        }
        for (root, clock) in self.claude_retired_family_tombstones.iter() {
            debt.tombstones.observe(1, Some(*clock), now);
            debt.tombstones.charge(&(root, clock));
        }
        debt.manifest_withheld.observe(
            1,
            self.traversal
                .as_ref()
                .and_then(|t| rfc3339_unix_seconds(&t.census_window_end)),
            now,
        );
        debt
    }
}

// Diagnostic byte accounting streams into a counter: no transcript reads and
// no materialized JSON copy of the retained cohort. Bytes mean compact retained
// metadata, not a claim about allocator RSS or the external transcript corpus.
pub(crate) fn retained_metadata_bytes<T: Serialize + ?Sized>(value: &T) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).expect("retained metadata serialization");
    counter.0
}

// Initial visibility thresholds, not admission caps. Tune using post-release
// M4 gauges. No alarm removes custody or changes a money/proof decision.
const TERMINAL_RETAINED_ACK_ALARM_COUNT: usize = 50_000;
const TERMINAL_RETRY_PENDING_ALARM_COUNT: usize = 1_000;
const TERMINAL_HELD_HISTORY_ALARM_BYTES: usize = 64 * 1024 * 1024;
fn retention_threshold_exceeded(class: u8, count: usize, bytes: usize) -> bool {
    match class {
        1 => count > TERMINAL_RETRY_PENDING_ALARM_COUNT,
        2 => bytes > TERMINAL_HELD_HISTORY_ALARM_BYTES,
        4 => count > TERMINAL_RETAINED_ACK_ALARM_COUNT,
        _ => false,
    }
}
#[derive(Default)]
struct RetentionAlarmWindow {
    window: String,
    fired: u8,
}
impl RetentionAlarmWindow {
    fn observe(&mut self, window: &str, class: u8, exceeded: bool) -> bool {
        if self.window != window {
            self.window = window.into();
            self.fired = 0;
        }
        if !exceeded || self.fired & class != 0 {
            return false;
        }
        self.fired |= class;
        true
    }
}
fn retention_alarm(context: &str, window: &str, class: u8, exceeded: bool) -> bool {
    // Bounded runtime throttle only. Old inactive destinations can be evicted;
    // returning to one can repeat an alarm, never suppress its retained debt.
    static MEMO: OnceLock<Mutex<std::collections::VecDeque<(String, RetentionAlarmWindow)>>> =
        OnceLock::new();
    let Ok(mut memo) = MEMO.get_or_init(Default::default).lock() else {
        return exceeded;
    };
    let at = match memo.iter().position(|(key, _)| key == context) {
        Some(at) => at,
        None => {
            if memo.len() == 64 {
                memo.pop_front();
            }
            memo.push_back((context.into(), RetentionAlarmWindow::default()));
            memo.len() - 1
        }
    };
    memo[at].1.observe(window, class, exceeded)
}
impl ScanIndex {
    fn terminal_retention_alarms(&self, debt: &TerminalRetention) -> serde_json::Value {
        let context = self
            .active_upload_context_fingerprint
            .as_deref()
            .unwrap_or("unknown");
        let window = self
            .traversal
            .as_ref()
            .map(|t| t.census_window_end.as_str())
            .unwrap_or("no_window");
        serde_json::json!({
            "retry_pending_families": retention_alarm(context, window, 1,
                retention_threshold_exceeded(1, debt.retry_pending_families.items, debt.retry_pending_families.bytes.unwrap_or(0))),
            "retained_index_acks": retention_alarm(context, window, 4,
                retention_threshold_exceeded(4, debt.accepted_index_acks.items, debt.accepted_index_acks.bytes.unwrap_or(0))),
            "held_history": retention_alarm(context, window, 2,
                retention_threshold_exceeded(2, debt.held_history_files.items, debt.held_history_files.bytes.unwrap_or(0))),
            "thresholds": {"retry_pending_families": TERMINAL_RETRY_PENDING_ALARM_COUNT,
                "held_history_bytes": TERMINAL_HELD_HISTORY_ALARM_BYTES,
                "retained_acks": TERMINAL_RETAINED_ACK_ALARM_COUNT},
            "visibility_only": true
        })
    }
    pub(crate) fn note_terminal_off_transport_retention(
        &self,
        transport: &BTreeSet<String>,
        bytes: usize,
        oldest_age_seconds: Option<u64>,
        unknown_age: usize,
    ) {
        if !claude_terminal_off() {
            return;
        }
        let context = self
            .active_upload_context_fingerprint
            .as_deref()
            .unwrap_or("unknown");
        let window = self
            .traversal
            .as_ref()
            .map(|t| t.census_window_end.as_str())
            .unwrap_or("no_window");
        let count = transport.len();
        // The ledger can transfer exact ACK custody into the index. Count
        // their union without allocating another set or double-counting it.
        let union_count = self.accepted_snapshot_fingerprints.union(transport).count();
        let alarm = retention_alarm(
            context,
            window,
            4,
            retention_threshold_exceeded(4, union_count, bytes),
        );
        emit_scan_index_containment_line(format!(
            "local snapshot census: source=claude_code terminal_off_retained_acks={} terminal_off_retained_acks_alarm={alarm} retained_ack_union_count={union_count} retained_acks_threshold={} visibility_only=1",
            serde_json::json!({"items":count,"bytes":bytes,"oldest_age_seconds":oldest_age_seconds,
                "unknown_age":unknown_age}), TERMINAL_RETAINED_ACK_ALARM_COUNT));
    }
}

#[cfg(test)]
mod retention_alarm_tests {
    use super::*;
    #[test]
    fn terminal_off_retention_thresholds_alarm_once_per_window_without_disposing_debt() {
        for (class, threshold) in [
            (1, TERMINAL_RETRY_PENDING_ALARM_COUNT),
            (2, TERMINAL_HELD_HISTORY_ALARM_BYTES),
            (4, TERMINAL_RETAINED_ACK_ALARM_COUNT),
        ] {
            let mut memo = RetentionAlarmWindow::default();
            for observed in [threshold - 1, threshold] {
                assert!(!memo.observe(
                    "W1",
                    class,
                    retention_threshold_exceeded(class, observed, observed)
                ));
            }
            assert!(memo.observe(
                "W1",
                class,
                retention_threshold_exceeded(class, threshold + 1, threshold + 1)
            ));
            assert!(!memo.observe("W1", class, true));
            assert!(!memo.observe("W1", class, false));
            assert!(!memo.observe("W1", class, true));
            assert!(memo.observe("W2", class, true));
        }
        let value = BTreeMap::from([("retained", vec!["proof debt"; 17])]);
        assert_eq!(
            retained_metadata_bytes(&value),
            serde_json::to_vec(&value).unwrap().len()
        );
    }
}

// A cancellation replay is already funded/owned. Its obligations must receive
// their existing page allowance before repeatedly requeued ordinary work.
fn terminal_off_replay_before_fifo(
    replay: &mut Vec<ScanTraversalPath>,
    selected: &mut Vec<ScanTraversalPath>,
    limit: usize,
) {
    let count = limit.saturating_sub(selected.len()).min(replay.len());
    selected.extend(replay.drain(..count));
}
