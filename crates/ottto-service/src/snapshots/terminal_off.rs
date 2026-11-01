#[path = "terminal_off/discovery.rs"]
mod terminal_off_discovery;

#[path = "terminal_off/policy.rs"]
mod terminal_off_policy;
#[cfg(test)]
pub(crate) use terminal_off_policy::ClaudeTerminalOffForTest;

/// The machine owner alone opts in. Absent marker/default means main policy.
pub(crate) fn claude_terminal_off() -> bool {
    #[cfg(test)]
    if claude_completion_paths_for_test() {
        return false;
    }
    terminal_off_policy::enabled()
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
    _switch: terminal_off_policy::ThreadSwitchForTest,
}
#[cfg(test)]
impl ClaudeCompletionPathsForTest {
    pub(crate) fn enable() -> Self {
        Self {
            _switch: terminal_off_policy::ThreadSwitchForTest::set(
                &CLAUDE_COMPLETION_PATHS_FOR_TEST,
                true,
            ),
        }
    }
}

#[cfg(test)]
mod completion_policy_tests {
    use super::*;

    /// [behaviour] Containment contract: money upload and history suites have no completion override.
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
        assert!(!claude_terminal_off(), "release default is main");
    }

    /// [behaviour] Containment contract: release terminal policy defaults off and fixture override is thread scoped.
    #[test]
    fn release_terminal_policy_defaults_off_and_fixture_override_is_thread_scoped() {
        assert!(!claude_terminal_off());
        let _containment = ClaudeTerminalOffForTest::enabled();
        assert!(claude_terminal_off());
        let enabled = ClaudeCompletionPathsForTest::enable();
        assert!(!claude_terminal_off());
        assert!(
            !std::thread::spawn(claude_terminal_off).join().unwrap(),
            "new test threads default OFF"
        );
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

pub(crate) fn claude_terminal_authority(_index: &ScanIndex, offered: bool, _window: &str) -> bool {
    // OFF restores the main completion path. ON cannot acquire authority by
    // changing a latch or restoring persisted scheduling/reconstruction data.
    offered && !claude_terminal_off()
}

fn claude_redundant_stale_clear_suppressed(index: &ScanIndex) -> bool {
    // Only redundant stale-window debt; independent semantic/context clears
    // and every already-empty fingerprint remain owned by their usual gates.
    claude_terminal_off()
        && !index.claude_request_identity_contract_changed
        && index.upload_context_fingerprint == index.active_upload_context_fingerprint
}

/// B-P2: stale-family members whose committed head carries a body the server
/// never accepted and no refusal quarantine owns. Unaccepted debt stays
/// debt, so the redundant stale clear is never suppressed for them: they stay
/// Parse and their head is offered again. Empty outside containment.
fn claude_unacked_head_members(index: &ScanIndex, roots: &BTreeSet<String>) -> BTreeSet<String> {
    if !claude_terminal_off() {
        return BTreeSet::new();
    }
    index
        .file_snapshot_fingerprints
        .iter()
        .filter(|(key, head)| {
            claude_index_path_member_ref(Path::new(key.as_str()))
                .is_some_and(|member| roots.contains(member.root))
                && claude_head_has_unacked_body(index, head)
        })
        .map(|(key, _)| key.clone())
        .collect()
}

fn claude_head_has_unacked_body(index: &ScanIndex, head: &BTreeSet<String>) -> bool {
    head.iter().any(|fingerprint| {
        !index.accepted_snapshot_fingerprints.contains(fingerprint)
            && !index
                .quarantined_snapshot_fingerprints
                .contains_key(fingerprint)
    })
}

/// B-P2: the re-armed unACKed head is offered again. Forgetting its upload
/// body witness (as main does for a placeholder) keeps the re-parse from
/// being suppressed as a semantic no-op; the persisted shape is unchanged.
/// Reached only for members `claude_unacked_head_members` returned, which is
/// empty outside containment.
fn claude_reoffer_unacked_head(entry: &mut ScanIndexEntry) {
    evidence_owed::reoffer_clears(entry);
    entry.last_upload_body_witness = None;
}

/// B-P2: a partial checkpoint that reverts an unsettled member to its
/// committed entry keeps the cleared source witness (main) and, under
/// containment, also the cleared body witness while its head is still
/// unACKed, so the re-offer debt survives until that member is parsed.
fn claude_retain_unacked_reoffer(result: &mut ScanIndex, key: &str, working: &ScanIndexEntry) {
    if !claude_terminal_off() || working.last_upload_body_witness.is_some() {
        return;
    }
    let unacked = result
        .file_snapshot_fingerprints
        .get(key)
        .is_some_and(|head| claude_head_has_unacked_body(result, head));
    if let Some(retained) = result.files.get_mut(key).filter(|_| unacked) {
        retained.last_upload_body_witness = None;
    }
}

// Storage for a process memo: one per process, or one per test thread so
// parallel fixtures never share it. A poisoned lock is taken with `into_inner`.
macro_rules! process_memo {
    (fn $with:ident, static $memo:ident: $ty:ty = $init:expr) => {
        #[cfg(not(test))]
        static $memo: std::sync::Mutex<$ty> = std::sync::Mutex::new($init);
        #[cfg(test)]
        thread_local! {
            static $memo: std::cell::RefCell<$ty> = const { std::cell::RefCell::new($init) };
        }
        fn $with<T>(f: impl FnOnce(&mut $ty) -> T) -> T {
            #[cfg(not(test))]
            {
                f(&mut $memo
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner))
            }
            #[cfg(test)]
            $memo.with(|memo| f(&mut memo.borrow_mut()))
        }
    };
}
pub(crate) use process_memo;

// B-P5: under containment neither the identity-contract latch nor
// source-wide context adoption discharges, so an unsuppressed semantic stale
// clear would re-arm every stale pending family at every red-retry or floor
// start. This bounded process memo serves it once per family and generation
// (traversal context, upload context pair, contract and latch). Each key also
// names the traversal its start created, and a later start counts the clear
// as served only when the traversal it replaces is that one. A working index
// discarded after a cancelled page or a failed checkpoint save leaves the
// reloaded traversal unmatched, so its families are cleared again. Eviction or
// restart likewise fails toward one more re-read, never toward proof, ACK or
// settlement.
const TERMINAL_OFF_STALE_CLEAR_KEYS: usize = 16_384;
#[derive(Default)]
struct TerminalOffStaleClears {
    keys: BTreeSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    evictions: u64,
}
impl TerminalOffStaleClears {
    fn remember(&mut self, key: [u8; 32]) {
        if !self.keys.insert(key) {
            return;
        }
        self.order.push_back(key);
        if self.keys.len() > TERMINAL_OFF_STALE_CLEAR_KEYS {
            let oldest = self.order.pop_front().expect("bounded memo has an owner");
            self.keys.remove(&oldest);
            self.evictions = self.evictions.saturating_add(1);
            eprintln!("claude_terminal_off stale_clear_memo_evicted evictions={} capacity={TERMINAL_OFF_STALE_CLEAR_KEYS}", self.evictions);
        }
    }
}
process_memo!(fn with_terminal_off_stale_clears,
static TERMINAL_OFF_STALE_CLEARS: TerminalOffStaleClears = TerminalOffStaleClears {
    keys: BTreeSet::new(),
    order: VecDeque::new(),
    evictions: 0,
});
fn terminal_off_stale_clear_key(
    index: &ScanIndex,
    context: &str,
    traversal_window: &str,
    root: &str,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    for value in [
        "terminal-off-stale-clear:v1",
        context,
        index
            .upload_context_fingerprint
            .as_deref()
            .unwrap_or("none"),
        index
            .active_upload_context_fingerprint
            .as_deref()
            .unwrap_or("none"),
        index
            .claude_request_identity_contract
            .as_deref()
            .unwrap_or("none"),
        if index.claude_request_identity_contract_changed {
            "latched"
        } else {
            "settled"
        },
        traversal_window,
        root,
    ] {
        update_length_prefixed(&mut digest, value.as_bytes());
    }
    digest.finalize().into()
}
/// The stale roots whose semantic clear this generation already served to
/// the traversal this start replaces.
fn terminal_off_stale_clear_served(
    index: &ScanIndex,
    context: &str,
    roots: &BTreeSet<String>,
) -> BTreeSet<String> {
    let Some(prior) = index.traversal.as_ref() else {
        return BTreeSet::new();
    };
    with_terminal_off_stale_clears(|memo| {
        roots
            .iter()
            .filter(|root| {
                memo.keys.contains(&terminal_off_stale_clear_key(
                    index,
                    context,
                    &prior.census_window_end,
                    root,
                ))
            })
            .cloned()
            .collect()
    })
}
/// Records that the traversal starting at `window` carries this generation's
/// semantic clear of `roots`, whether served earlier or by this start.
fn note_terminal_off_stale_clears(
    index: &ScanIndex,
    context: &str,
    window: &str,
    roots: &BTreeSet<String>,
) {
    let keys: Vec<_> = roots
        .iter()
        .map(|root| terminal_off_stale_clear_key(index, context, window, root))
        .collect();
    with_terminal_off_stale_clears(|memo| keys.into_iter().for_each(|key| memo.remember(key)));
}
#[cfg(test)]
fn terminal_off_stale_clear_memo_len_for_test() -> (usize, u64) {
    with_terminal_off_stale_clears(|memo| (memo.keys.len(), memo.evictions))
}

fn claude_terminal_stale_roots(index: &ScanIndex, window: &str) -> BTreeSet<String> {
    index
        .claude_usage_family_pending
        .views()
        .filter(|(_, p)| p.window() != window)
        .map(|(root, _)| root.clone())
        .collect()
}

fn claude_terminal_unproven(index: &ScanIndex, window: &str) {
    if !claude_terminal_off() {
        return;
    }

    let stale = index
        .claude_usage_family_pending
        .views()
        .filter(|(_, p)| p.window() != window)
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
    if !claude_terminal_off() {
        return;
    }

    START_IDENTITY_SAMPLES.with(|counts| *counts.borrow_mut() = StartIdentitySamples::default());
}
fn note_start_identity_sample(source: SnapshotSource, file: &File, samples: &OpenedContentSamples) {
    if source != SnapshotSource::ClaudeCode || !claude_terminal_off() {
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
    if !claude_terminal_off() {
        return;
    }

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
    if !claude_terminal_off() {
        return;
    }

    // Existing queue is durable demand; re-list metadata without throwing it
    // away, changing the frozen window or minting a new native owner.
    for root in &traversal.scan_roots {
        if let Some(position) = traversal
            .pending_directories
            .iter()
            .position(|p| p.path == *root)
        {
            // A pending re-listing root becomes this full rediscovery walk.
            traversal.pending_directories[position].census_member = true;
        } else {
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
process_memo!(fn with_terminal_off_empty_contexts,
static TERMINAL_OFF_EMPTY_CONTEXTS: TerminalOffEmptyContexts = TerminalOffEmptyContexts {
    keys: BTreeSet::new(),
    order: VecDeque::new(),
    evictions: 0,
});
#[cfg(test)]
thread_local! {
    static TERMINAL_OFF_EMPTY_REPARSES_FOR_TEST: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
fn terminal_off_empty_context_key(index: &ScanIndex, key: &str) -> Option<[u8; 32]> {
    if !claude_terminal_off() || !index.confirmed_empty_files.contains(key) {
        return None;
    }
    let entry = index.files.get(key)?;
    if entry.rearmed() {
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
    digest.update(crate::snapshots::RETIRED_CONTEXT_CURVE_REPLAY_EPOCH.to_be_bytes());
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
process_memo!(fn with_terminal_off_rediscovery,
    static TERMINAL_OFF_REDISCOVERY: BTreeMap<String, u64> = BTreeMap::new());
fn terminal_off_cadence_requested(scope: &str, now: u64) -> bool {
    with_terminal_off_rediscovery(|memo| memo.get(scope).map_or(true, |due| now >= *due))
}
fn terminal_off_rediscovery_due(scope: String, now: u64, force: bool) -> bool {
    with_terminal_off_rediscovery(|memo| {
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
    })
}
// Reader/identity fixture drivers model an explicitly due discovery walk,
// rather than an idle daemon tick at the same fixed fixture timestamp.
#[cfg(test)]
pub(crate) fn expire_terminal_off_discovery_for_test(index: &ScanIndex) {
    if let Some(scope) = terminal_off_rediscovery_scope(index) {
        with_terminal_off_rediscovery(|memo| memo.remove(&scope));
    }
}

fn terminal_off_rediscovery_scope(index: &ScanIndex) -> Option<String> {
    terminal_off_traversal_scope(index.traversal.as_ref()?)
}
fn terminal_off_traversal_scope(traversal: &ScanTraversalCheckpoint) -> Option<String> {
    let mut digest = Sha256::new();
    for value in [
        "terminal-off-rediscovery:v2",
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
    file_limit: usize,
) {
    if !claude_terminal_off() {
        return;
    }

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
    let requested = changed || overflow || terminal_off_cadence_requested(&scope, now);
    let start = terminal_off_discovery::prepare(index, now, requested);
    if start {
        terminal_off_rediscovery_due(scope, now, true);
    }
    // Existing gates own every body read. Owed work queues a bounded key,
    // never another whole root walk; retained candidates keep their custody.
    terminal_off_discovery::targeted(index, now, file_limit);
    if !start {
        return;
    }
    let traversal = index.traversal.as_mut().expect("retained traversal");
    reset_start_identity_samples();
    claude_terminal_rewind(traversal);
    eprintln!("claude_terminal_off rediscovery=1 watcher_loss={} resolved_roots_changed={} directories={} bytes=0: bounded stat/readdir; candidate identity samples counted separately", u8::from(overflow), u8::from(changed), traversal.pending_directories.len());
}

fn carry_admission_debt(index: &ScanIndex, at: &str) -> (usize, u64) {
    let Some(traversal) = index.traversal.as_ref() else {
        return (0, 0);
    };
    let now = rfc3339_unix_seconds(at).unwrap_or_default();
    let mut families = 0;
    let mut oldest = now;
    for (root, pending) in index.claude_usage_family_pending.views() {
        if pending.window() != traversal.census_window_end
            && !index.claude_stale_family_carry.contains(root)
        {
            families += 1;
            if let Some(time) = rfc3339_unix_seconds(pending.window()) {
                oldest = oldest.min(time);
            }
        }
    }
    (families, now.saturating_sub(oldest))
}

fn carry_admission_stall(index: &ScanIndex, at: &str) {
    if !claude_terminal_off() {
        return;
    }

    let (families, oldest_age) = carry_admission_debt(index, at);
    eprintln!("ALARM carry_admission_stalled families={families} oldest_age={oldest_age}: denied members remain UNPROVEN; family-scoping B deferred");
}

fn resume_claude_retry_admission(index: &mut ScanIndex, at: &str) {
    if !claude_terminal_off() {
        return;
    }

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
    let stale = index
        .claude_usage_family_pending
        .views()
        .filter(|(root, _)| {
            previous
                .after_root
                .as_ref()
                .map_or(true, |after| *root > after)
                && **root <= previous.upper_root
        })
        .filter(|(_, p)| p.window() != window)
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
        // Cold: a carried family's evidence is cleared, so it is loaded
        // first; an Unknown family (counted) is not carried.
        let _ = state_v2::load_usage(index, Some(&new_carry.roots));
        let carry = &mut index.claude_stale_family_carry;
        for root in new_carry.roots {
            match index.claude_usage_family_pending.family_mut(&root) {
                Ok(Some(pending)) => {
                    pending.member_occurrences.clear();
                    pending
                        .member_request_id_hashes
                        .values_mut()
                        .for_each(BTreeSet::clear);
                }
                Ok(None) => {}
                Err(_) => continue,
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
        let runnable = keys
            .iter()
            .filter(|key| !terminal_off_discovery::retry_blocked(self, key))
            .cloned()
            .collect::<Vec<_>>();
        if let Some(traversal) = self.traversal.as_mut() {
            for key in &runnable {
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
                .view(root)
                .and_then(|p| rfc3339_unix_seconds(p.window()));
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
        for (_, pending) in self.claude_usage_family_pending.views() {
            // This optional extra gauge has potentially corpus-sized occurrence
            // maps. Do not serialize them every page for diagnostics alone.
            debt.delayed_proof_families.bytes = None;
            debt.delayed_proof_families
                .observe(1, rfc3339_unix_seconds(pending.window()), now);
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
    /// [behaviour] Containment contract: retention thresholds alarm once per window without disposing debt.
    #[test]
    fn terminal_off_retention_thresholds_alarm_once_per_window_without_disposing_debt() {
        let _on = ClaudeTerminalOffForTest::enabled();
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

#[cfg(test)]
pub(crate) fn with_terminal_off_audit_now_for_test<T>(now: u64, f: impl FnOnce() -> T) -> T {
    sampled_scan::with_test_now(now, f)
}

// Only #899's added decision sites use this adapter: OFF preserves main's
// fresh-clock call; ON uses the selecting page's one captured #870 clock.
fn terminal_off_decision_now(captured: u64) -> u64 {
    if claude_terminal_off() {
        captured
    } else {
        sampled_scan::now_seconds()
    }
}
