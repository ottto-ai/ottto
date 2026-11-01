//! Best-effort process/source totals, never traversal authority or persisted state.
//! Independent relaxed loads are non-atomic across counters and overflow. A wrap
//! can be visible before its sticky flag: even false cannot prove exact concurrent
//! conservation. First/reset/gap/missing-field/restored-window attribution is UNKNOWN.
use super::SnapshotSource;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// Opt-in (default OFF): settle Claude members of deleted directories as
// removals. Declared beside the NotFound sites it splits so this module's
// fixtures set it on their own thread; no options seam reaches the candidate
// and walk sites. The counters below stay diagnostics only.
super::local_switch::local_switch!(
    "claude_vanished_directory_removal_enabled",
    marker_enables = true,
    test_default = false
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    NotFound,
    RootResolutionUnresolved,
    PreflightFingerprintChanged,
    ComparisonTargetRevisionChanged,
}
impl Cause {
    fn index(self) -> usize {
        match self {
            Self::NotFound => 0,
            Self::RootResolutionUnresolved => 1,
            Self::PreflightFingerprintChanged => 2,
            Self::ComparisonTargetRevisionChanged => 3,
        }
    }
}

/// Where a NotFound was observed. Content-free and process-only: it names a
/// scanner branch, never a path, and is never traversal authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Site {
    /// A queued directory vanished before it was read.
    WalkDirectory,
    /// A directory entry vanished between `readdir` and its `lstat`.
    WalkEntry,
    /// A queued census member (walk, hint or replay) vanished before its stat.
    CandidateWalk,
    /// A forced Claude family member enumerated from the index vanished.
    CandidateForcedIndex,
    /// A selected file vanished before its no-follow open.
    Open,
}
const SITES: usize = 5;
/// Per site: a NotFound that stayed operational loss, then one settled as removal.
const OUTCOMES: usize = 2;
impl Site {
    fn index(self) -> usize {
        match self {
            Self::WalkDirectory => 0,
            Self::WalkEntry => 1,
            Self::CandidateWalk => 2,
            Self::CandidateForcedIndex => 3,
            Self::Open => 4,
        }
    }
}

/// What a vanished Claude census member's retirement dropped with its index
/// entry. Content-free and process-only, like the site split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Vanished {
    /// Its unverified audit debt (SOURCE N2).
    AuditDebtDropped,
    /// Its request-census record (SOURCE N1).
    RequestCensusRemoved,
}
const VANISHED: usize = 2;
impl Vanished {
    fn index(self) -> usize {
        match self {
            Self::AuditDebtDropped => 0,
            Self::RequestCensusRemoved => 1,
        }
    }
}

struct Counters {
    counts: [AtomicU64; 4],
    not_found_sites: [AtomicU64; SITES * OUTCOMES],
    vanished: [AtomicU64; VANISHED],
    parent_missing_removals: AtomicU64,
    vanished_pin_refusals: AtomicU64,
    overflowed: AtomicBool,
}
impl Counters {
    const fn new() -> Self {
        Self {
            counts: [const { AtomicU64::new(0) }; 4],
            not_found_sites: [const { AtomicU64::new(0) }; SITES * OUTCOMES],
            vanished: [const { AtomicU64::new(0) }; VANISHED],
            parent_missing_removals: AtomicU64::new(0),
            vanished_pin_refusals: AtomicU64::new(0),
            overflowed: AtomicBool::new(false),
        }
    }
    fn bump(&self, counter: &AtomicU64) {
        if counter.fetch_add(1, Ordering::Relaxed) == u64::MAX {
            self.overflowed.store(true, Ordering::Relaxed);
        }
    }
    fn record(&self, cause: Cause) {
        self.bump(&self.counts[cause.index()]);
    }
    fn record_not_found_site(&self, site: Site, removal: bool) {
        self.bump(&self.not_found_sites[site.index() * OUTCOMES + usize::from(removal)]);
    }
    fn record_vanished(&self, vanished: Vanished) {
        self.bump(&self.vanished[vanished.index()]);
    }
    fn snapshot(&self) -> Totals {
        Totals {
            version: 1,
            scope: "process_lifetime_not_window",
            counts: std::array::from_fn(|i| self.counts[i].load(Ordering::Relaxed)),
            not_found_sites: std::array::from_fn(|site| {
                std::array::from_fn(|outcome| {
                    self.not_found_sites[site * OUTCOMES + outcome].load(Ordering::Relaxed)
                })
            }),
            vanished_audit_debt_dropped: self.vanished[Vanished::AuditDebtDropped.index()]
                .load(Ordering::Relaxed),
            vanished_request_census_removed: self.vanished[Vanished::RequestCensusRemoved.index()]
                .load(Ordering::Relaxed),
            parent_missing_removals: self.parent_missing_removals.load(Ordering::Relaxed),
            vanished_pin_refusals: self.vanished_pin_refusals.load(Ordering::Relaxed),
            overflowed: self.overflowed.load(Ordering::Relaxed),
        }
    }
}

static TOTALS: [Counters; 3] = [const { Counters::new() }; 3];

/// Fixed order: NotFound, unresolved root, changed preflight, changed target.
/// `not_found_sites` splits the walk, candidate and open NotFounds by site in
/// `Site` order, each `[loss, removal]`; NotFound in `counts` includes both,
/// and root NotFounds have no site. The `vanished_*` counts are what the
/// page merge dropped with a vanished Claude member's retired entry.
/// `parent_missing_removals` (omitted at zero) counts the NotFound
/// removals settled below a missing parent; they are also in the site split.
/// `vanished_pin_refusals` counts absence witnesses refused by the shared pin
/// budget.
/// The sticky flag invalidates exact intervals; false is not a coherence proof.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct Totals {
    version: u8,
    scope: &'static str,
    counts: [u64; 4],
    not_found_sites: [[u64; OUTCOMES]; SITES],
    vanished_audit_debt_dropped: u64,
    vanished_request_census_removed: u64,
    #[serde(skip_serializing_if = "super::is_zero_u64")]
    parent_missing_removals: u64,
    #[serde(skip_serializing_if = "super::is_zero_u64")]
    vanished_pin_refusals: u64,
    overflowed: bool,
}

pub(super) fn increment(count: &mut usize, source: SnapshotSource, cause: Cause) {
    // Preserve the original arithmetic (including overflow behavior) and order.
    *count += 1;
    record(source, cause);
}

fn record(source: SnapshotSource, cause: Cause) {
    TOTALS[source.slot()].record(cause);
    #[cfg(test)]
    TEST_EVENTS.with(|events| {
        if let Some(mut counts) = events.get() {
            counts[source.slot()][cause.index()] += 1;
            events.set(Some(counts));
        }
    });
}

fn record_not_found_site(source: SnapshotSource, site: Site, removal: bool) {
    TOTALS[source.slot()].record_not_found_site(site, removal);
    #[cfg(test)]
    TEST_SITE_EVENTS.with(|events| {
        if let Some(mut counts) = events.get() {
            counts[source.slot()][site.index()][usize::from(removal)] += 1;
            events.set(Some(counts));
        }
    });
}

/// A NotFound at `site` that stays operational loss and turns the traversal red.
pub(super) fn not_found(count: &mut usize, source: SnapshotSource, site: Site) {
    increment(count, source, Cause::NotFound);
    record_not_found_site(source, site, false);
}

/// A NotFound at `site` the scanner settles as a removal. It is recorded in the
/// process totals only and never increments an operational count.
pub(super) fn not_found_removal(source: SnapshotSource, site: Site) {
    record(source, Cause::NotFound);
    record_not_found_site(source, site, true);
}

/// The page merge dropped `vanished` with a vanished Claude member's entry.
pub(super) fn vanished(source: SnapshotSource, vanished: Vanished) {
    TOTALS[source.slot()].record_vanished(vanished);
    #[cfg(test)]
    TEST_VANISHED_EVENTS.with(|events| {
        if let Some(mut counts) = events.get() {
            counts[source.slot()][vanished.index()] += 1;
            events.set(Some(counts));
        }
    });
}

/// A census member below a missing parent settled as a removal.
pub(super) fn parent_missing_removal(source: SnapshotSource) {
    let counters = &TOTALS[source.slot()];
    counters.bump(&counters.parent_missing_removals);
}

/// The shared pin budget refused a new absence witness.
pub(super) fn vanished_pin_refused(source: SnapshotSource) {
    let counters = &TOTALS[source.slot()];
    counters.bump(&counters.vanished_pin_refusals);
}

pub(super) fn snapshot(source: SnapshotSource) -> Totals {
    TOTALS[source.slot()].snapshot()
}

#[cfg(test)]
type SiteEvents = [[[u64; OUTCOMES]; SITES]; 3];

#[cfg(test)]
thread_local! {
    static TEST_EVENTS: std::cell::Cell<Option<[[u64; 4]; 3]>> = const { std::cell::Cell::new(None) };
    static TEST_SITE_EVENTS: std::cell::Cell<Option<SiteEvents>> = const { std::cell::Cell::new(None) };
    static TEST_VANISHED_EVENTS: std::cell::Cell<Option<[[u64; VANISHED]; 3]>> = const { std::cell::Cell::new(None) };
}

/// Observe actual caller-thread producers without global resets or decision hooks.
#[cfg(test)]
pub(super) fn observe<T>(f: impl FnOnce() -> T) -> (T, [[u64; 4]; 3]) {
    struct Reset(Option<[[u64; 4]; 3]>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_EVENTS.with(|events| events.set(self.0));
        }
    }
    let reset = Reset(TEST_EVENTS.with(|events| events.replace(Some([[0; 4]; 3]))));
    let result = f();
    let counts = TEST_EVENTS.with(|events| events.get().unwrap());
    drop(reset);
    (result, counts)
}

/// The caller-thread NotFound site split, per source, `Site` order, `[loss, removal]`.
#[cfg(test)]
pub(super) fn observe_sites<T>(f: impl FnOnce() -> T) -> (T, SiteEvents) {
    struct Reset(Option<SiteEvents>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_SITE_EVENTS.with(|events| events.set(self.0));
        }
    }
    let reset =
        Reset(TEST_SITE_EVENTS.with(|events| events.replace(Some([[[0; OUTCOMES]; SITES]; 3]))));
    let result = f();
    let counts = TEST_SITE_EVENTS.with(|events| events.get().unwrap());
    drop(reset);
    (result, counts)
}

/// The caller-thread vanished-member retirement counts, per source, `Vanished` order.
#[cfg(test)]
pub(super) fn observe_vanished<T>(f: impl FnOnce() -> T) -> (T, [[u64; VANISHED]; 3]) {
    struct Reset(Option<[[u64; VANISHED]; 3]>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_VANISHED_EVENTS.with(|events| events.set(self.0));
        }
    }
    let reset = Reset(TEST_VANISHED_EVENTS.with(|events| events.replace(Some([[0; VANISHED]; 3]))));
    let result = f();
    let counts = TEST_VANISHED_EVENTS.with(|events| events.get().unwrap());
    drop(reset);
    (result, counts)
}

#[cfg(test)]
impl Totals {
    pub(super) fn maximum() -> Self {
        Self {
            version: 1,
            scope: "process_lifetime_not_window",
            counts: [u64::MAX; 4],
            not_found_sites: [[u64::MAX; OUTCOMES]; SITES],
            vanished_audit_debt_dropped: u64::MAX,
            vanished_request_census_removed: u64::MAX,
            parent_missing_removals: u64::MAX,
            vanished_pin_refusals: u64::MAX,
            overflowed: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        advance_bounded_directory_traversal, candidate_from_traversal_path,
        ensure_bounded_traversal, local_index_key, open_and_identify_scan_candidate,
        scan_source_roots_with_limit_and_attribution, OwnedSourceScan, OwnedSourceScanStep,
        ScanCensus, ScanIndex, ScanTraversalPath, SourceScanResult, BACKFILL_WINDOW_DAYS,
    };
    use super::*;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    const NOW: &str = "2026-10-07T12:00:00Z";
    const LATER: &str = "2026-10-07T12:10:00Z";
    const RETRY: &str = "2026-10-07T12:20:00Z";

    fn claude_line(session: &str, request: &str) -> String {
        serde_json::json!({"type":"assistant", "sessionId":session,
            "timestamp":"2026-10-07T10:00:00Z", "requestId":request,
            "message":{"id":format!("{request}-message"), "model":"fixture-model",
                "usage":{"input_tokens":10,"output_tokens":2}}})
        .to_string()
            + "\n"
    }

    /// One real bounded Claude page through the production scan entry.
    fn claude_page(
        index: &mut ScanIndex,
        root: &Path,
        at: &str,
        file_limit: usize,
        hints: &[PathBuf],
    ) -> SourceScanResult {
        super::super::withheld_account::support::clock(&index.withheld_memo);
        scan_source_roots_with_limit_and_attribution(
            SnapshotSource::ClaudeCode,
            &[root.to_path_buf()],
            index,
            at,
            BACKFILL_WINDOW_DAYS,
            file_limit,
            false,
            None,
            None,
            hints,
            false,
        )
        .unwrap()
    }

    /// Pages until the generation retires healthy (its traversal is dropped)
    /// or ends red (discovery done with errors). `hints` go to the first page.
    fn claude_generation(
        index: &mut ScanIndex,
        root: &Path,
        at: &str,
        file_limit: usize,
        hints: &[PathBuf],
    ) -> Vec<SourceScanResult> {
        let mut pages = Vec::new();
        for page in 0..32 {
            let page_hints: &[PathBuf] = if page == 0 { hints } else { &[] };
            pages.push(claude_page(index, root, at, file_limit, page_hints));
            let done = index.traversal.as_ref().map_or(true, |traversal| {
                traversal.pending_directories.is_empty()
                    && traversal.pending_candidates.is_empty()
                    && traversal.counts.has_errors()
            });
            if done {
                return pages;
            }
        }
        panic!("synthetic Claude generation failed to retire within its page bound");
    }

    fn finish(mut state: OwnedSourceScan) -> (ScanIndex, SourceScanResult) {
        for _ in 0..1024 {
            match state.step(None) {
                OwnedSourceScanStep::Pending(next) => state = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
            }
        }
        panic!("synthetic scan failed to finish within its existing step bound");
    }

    #[test]
    fn real_pending_member_and_watcher_absence_have_distinct_outcomes() {
        let dir = crate::test_scratch::ScratchDir::new("disappearance-pending");
        let path = dir.join("missing.jsonl");
        // (source, member, watcher, disappeared, process NotFound, removed).
        // A Claude census member absent beneath its present parent is the same
        // removal as a remove hint; Codex and Pi keep today's loss.
        for (source, member, watcher, expected, event, removed) in [
            (SnapshotSource::Pi, true, false, 1, 1, false),
            (SnapshotSource::Pi, true, true, 0, 0, true),
            (SnapshotSource::Pi, false, false, 0, 0, false),
            (SnapshotSource::Pi, false, true, 0, 0, true),
            (SnapshotSource::Codex, true, false, 1, 1, false),
            (SnapshotSource::ClaudeCode, true, false, 0, 1, true),
            (SnapshotSource::ClaudeCode, true, true, 0, 0, true),
            (SnapshotSource::ClaudeCode, false, false, 0, 0, false),
            (SnapshotSource::ClaudeCode, false, true, 0, 0, true),
        ] {
            let mut census = ScanCensus::default();
            let (candidate, events) = observe(|| {
                candidate_from_traversal_path(
                    source,
                    ScanTraversalPath {
                        scan_root: dir.to_path_buf(),
                        path: path.clone(),
                        census_member: member,
                        watcher_hint: watcher,
                    },
                    &mut census,
                    None,
                    BACKFILL_WINDOW_DAYS,
                    &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
                )
            });
            assert!(candidate.is_none());
            assert_eq!(census.disappeared_file_count, expected, "{source:?}");
            assert_eq!(census.unreadable_path_count, 0);
            let mut expected_events = [[0; 4]; 3];
            expected_events[source.slot()][0] = event;
            assert_eq!(events, expected_events, "{source:?}");
            assert_eq!(
                census.removed_index_keys.contains(&local_index_key(&path)),
                removed,
                "{source:?}"
            );
        }
    }

    #[test]
    fn real_queued_directory_absence_records_once_without_root_fallback() {
        let dir = crate::test_scratch::ScratchDir::new("disappearance-directory");
        let root = dir.join("root");
        fs::create_dir(&root).unwrap();
        let mut index = ScanIndex::default();
        ensure_bounded_traversal(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            NOW,
            BACKFILL_WINDOW_DAYS,
        );
        fs::remove_dir(&root).unwrap();
        let (_, events) = observe(|| {
            advance_bounded_directory_traversal(
                SnapshotSource::Pi,
                &mut index,
                BACKFILL_WINDOW_DAYS,
                None,
            )
        });
        assert_eq!(events, [[0; 4], [0; 4], [1, 0, 0, 0]]);
        assert_eq!(
            index
                .traversal
                .as_ref()
                .unwrap()
                .counts
                .disappeared_file_count,
            1
        );
        assert!(index
            .traversal
            .as_ref()
            .unwrap()
            .pending_directories
            .is_empty());
        assert!(index.files.is_empty());
    }

    #[test]
    fn real_unsuitable_known_root_is_unresolved_without_a_not_found_error() {
        let dir = crate::test_scratch::ScratchDir::new("disappearance-root-type");
        let root = dir.join("configured");
        fs::write(&root, b"synthetic non-directory root").unwrap();
        let mut index = ScanIndex::default();
        index
            .known_configured_scan_roots
            .insert(super::super::local_index_key(&root));
        let (_, events) = observe(|| {
            ensure_bounded_traversal(
                SnapshotSource::Pi,
                std::slice::from_ref(&root),
                &mut index,
                NOW,
                BACKFILL_WINDOW_DAYS,
            )
        });
        assert_eq!(events, [[0; 4], [0; 4], [0, 1, 0, 0]]);
        let traversal = index.traversal.as_ref().unwrap();
        assert_eq!(traversal.counts.disappeared_file_count, 1);
        assert_eq!(traversal.counts.unreadable_path_count, 0);
        assert!(traversal.pending_directories.is_empty());
        assert!(index.files.is_empty());
        assert_eq!(fs::read(&root).unwrap(), b"synthetic non-directory root");
    }

    #[cfg(unix)]
    #[test]
    fn real_dangling_configured_symlink_does_not_double_record_fallback() {
        let dir = crate::test_scratch::ScratchDir::new("disappearance-symlink");
        let root = dir.join("configured");
        std::os::unix::fs::symlink(dir.join("missing"), &root).unwrap();
        let mut index = ScanIndex::default();
        index
            .known_configured_scan_roots
            .insert(super::super::local_index_key(&root));
        let (_, events) = observe(|| {
            ensure_bounded_traversal(
                SnapshotSource::Pi,
                std::slice::from_ref(&root),
                &mut index,
                NOW,
                BACKFILL_WINDOW_DAYS,
            )
        });
        assert_eq!(events, [[0; 4], [0; 4], [1, 0, 0, 0]]);
        assert_eq!(
            index
                .traversal
                .as_ref()
                .unwrap()
                .counts
                .disappeared_file_count,
            1
        );
        assert!(index.files.is_empty());
    }

    #[test]
    fn real_selected_file_removed_before_open_records_only_not_found() {
        let dir = crate::test_scratch::ScratchDir::new("disappearance-open");
        let path = dir.join("session.jsonl");
        let key = local_index_key(&path);
        // N-T2: removed between the candidate stat and the no-follow open. A
        // Claude file beneath its present parent settles as removal and drops
        // this page's observation; Codex and Pi keep today's loss.
        for (source, removal) in [
            (SnapshotSource::Pi, false),
            (SnapshotSource::Codex, false),
            (SnapshotSource::ClaudeCode, true),
        ] {
            fs::write(&path, b"{}\n").unwrap();
            let mut census = ScanCensus::default();
            let candidate = candidate_from_traversal_path(
                source,
                ScanTraversalPath {
                    scan_root: dir.to_path_buf(),
                    path: path.clone(),
                    census_member: true,
                    watcher_hint: false,
                },
                &mut census,
                None,
                BACKFILL_WINDOW_DAYS,
                &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
            )
            .unwrap();
            assert!(census.observed_index_keys.contains(&key));
            fs::remove_file(&path).unwrap();
            let (opened, events) = observe(|| {
                open_and_identify_scan_candidate(
                    source,
                    candidate,
                    &mut census,
                    None,
                    BACKFILL_WINDOW_DAYS,
                    crate::snapshots::DiscoveryRetention::unverified(
                        &crate::snapshots::SharedMap::default(),
                    ),
                )
            });
            assert!(opened.is_none());
            let mut expected_events = [[0; 4]; 3];
            expected_events[source.slot()][0] = 1;
            assert_eq!(events, expected_events, "{source:?}");
            assert_eq!(
                census.disappeared_file_count,
                usize::from(!removal),
                "{source:?}"
            );
            assert_eq!(census.unreadable_path_count, 0);
            assert_eq!(
                census.removed_index_keys.contains(&key),
                removal,
                "{source:?}"
            );
            assert_eq!(
                census.observed_index_keys.contains(&key),
                !removal,
                "{source:?}"
            );
        }
    }

    #[test]
    fn real_changed_quarantined_preflight_rejects_second_open_without_parsing() {
        let dir = crate::test_scratch::ScratchDir::new("disappearance-preflight");
        let session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let path = dir.join(format!("{session}.jsonl"));
        let original = serde_json::json!({"type":"assistant", "sessionId":session,
            "timestamp":"2026-10-07T10:00:00Z", "requestId":"synthetic-request",
            "message":{"id":"synthetic-message", "model":"fixture-model",
                "usage":{"input_tokens":10,"output_tokens":2}}})
        .to_string()
            + "\n";
        fs::write(&path, &original).unwrap();
        let mut index = ScanIndex::default();
        index.insert_retry_pending_claude_authority_for_test(session);
        let state = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            &[dir.to_path_buf()],
            index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
            false,
        );
        assert_eq!(state.identified_candidates.len(), 1);
        assert!(
            !state.identified_candidates[0]
                .source_file_fingerprint
                .is_empty(),
            "the real constructor must have performed the authority prepass"
        );
        let quarantine_before =
            serde_json::to_vec(&state.index.claude_usage_authority_quarantine).unwrap();
        let sidecar_complete = state.sidecar_census_complete;
        // A genuine physical rewrite between the constructor prepass and step's
        // second safe open. No fabricated Cause or scanner decision hook.
        fs::write(&path, format!("{original}{{}}\n")).unwrap();
        let ((index, scan), events) = observe(|| finish(state));
        assert_eq!(events, [[0; 4], [0, 0, 1, 0], [0; 4]]);
        assert_eq!(scan.disappeared_file_count, 1);
        assert_eq!(scan.unreadable_path_count, 0);
        assert_eq!(scan.scanned_file_count, 0);
        assert!(scan.snapshots.is_empty());
        assert!(!scan.census_complete);
        assert_eq!(scan.sidecar_census_complete, sidecar_complete);
        assert_eq!(scan.backfill_file_limit, 10);
        assert!(index.files.is_empty(), "no body was parsed or checkpointed");
        assert_eq!(
            serde_json::to_vec(&index.claude_usage_authority_quarantine).unwrap(),
            quarantine_before
        );
        assert_eq!(
            index
                .traversal
                .as_ref()
                .unwrap()
                .counts
                .disappeared_file_count,
            1,
            "the operational census merges once without another diagnostic event"
        );
    }

    /// N-T1: a walk-queued Claude member is deleted after the walk queued it
    /// and its remove hint is dropped by the queue's dedupe, so the member
    /// reaches its candidate stat without the hint flag. It retires as a
    /// removal: no disappeared count, a complete census, the entry gone.
    #[test]
    fn claude_queued_member_deleted_while_its_remove_hint_is_deduped_retires_as_removal() {
        let dir = crate::test_scratch::ScratchDir::new("absence-deduped-hint");
        let first = "a1111111-1111-4111-8111-111111111111";
        let second = "b2222222-2222-4222-8222-222222222222";
        let first_path = dir.join(format!("{first}.jsonl"));
        let second_path = dir.join(format!("{second}.jsonl"));
        fs::write(&first_path, claude_line(first, "request-first")).unwrap();
        fs::write(&second_path, claude_line(second, "request-second")).unwrap();
        let mut index = ScanIndex::default();
        let baseline = claude_generation(&mut index, &dir, NOW, 1, &[]);
        assert!(baseline.last().unwrap().census_complete);
        assert!(index.files.contains_key(&local_index_key(&second_path)));

        // The next generation walks both and selects only the first.
        let page = claude_page(&mut index, &dir, LATER, 1, &[]);
        assert_eq!(page.disappeared_file_count, 0);
        let queued = &index.traversal.as_ref().unwrap().pending_candidates;
        assert!(queued
            .iter()
            .any(|pending| pending.path == second_path && pending.census_member));
        fs::remove_file(&second_path).unwrap();
        let ((pages, events), sites) = observe_sites(|| {
            observe(|| {
                claude_generation(
                    &mut index,
                    &dir,
                    LATER,
                    1,
                    std::slice::from_ref(&second_path),
                )
            })
        });
        let mut expected_sites = [[[0; OUTCOMES]; SITES]; 3];
        expected_sites[1][Site::CandidateWalk.index()] = [0, 1];
        assert_eq!(sites, expected_sites);
        assert!(
            pages.iter().all(|page| page.disappeared_file_count == 0),
            "a vanished member under its present parent is not loss"
        );
        assert!(pages.last().unwrap().census_complete);
        assert!(index.traversal.is_none(), "the generation retired healthy");
        assert!(!index.files.contains_key(&local_index_key(&second_path)));
        assert!(index.files.contains_key(&local_index_key(&first_path)));
        // The process diagnostic still records the NotFound.
        assert_eq!(events, [[0; 4], [1, 0, 0, 0], [0; 4]]);
    }

    /// A deleted Claude subagent of a quarantined family, carrying unverified
    /// audit debt, in a forced family reparse while membership is not
    /// authoritative (a rejected symlink keeps it so here). The forced
    /// enumeration re-adds it from the index every such generation.
    #[cfg(unix)]
    struct ForcedFamilyFixture {
        dir: crate::test_scratch::ScratchDir,
        member_path: PathBuf,
    }

    #[cfg(unix)]
    const FORCED_ROOT: &str = "c3333333-3333-4333-8333-333333333333";

    #[cfg(unix)]
    impl ForcedFamilyFixture {
        fn new(prefix: &str) -> Self {
            let dir = crate::test_scratch::ScratchDir::new(prefix);
            fs::write(
                dir.join(format!("{FORCED_ROOT}.jsonl")),
                claude_line(FORCED_ROOT, "request-root"),
            )
            .unwrap();
            let subagents = dir.join(FORCED_ROOT).join("subagents");
            fs::create_dir_all(&subagents).unwrap();
            std::os::unix::fs::symlink(dir.join("nowhere"), dir.join("zz-link")).unwrap();
            let member_path = subagents.join("agent-a4d1585d310070d0f.jsonl");
            Self { dir, member_path }
        }

        fn index(&self) -> ScanIndex {
            let mut index = ScanIndex::default();
            index.insert_retry_pending_claude_authority_for_test(FORCED_ROOT);
            let mut entry = super::super::tests::manifest_index_entry(Some("held-member-body"));
            entry.source_file_fingerprint = "held-member-revision".to_string();
            entry.scan_identity_version = Some(format!(
                "{}:4000000000",
                super::super::sampled_audit::UNVERIFIED_IDENTITY
            ));
            assert!(entry.has_unverified_source());
            index
                .files
                .insert(local_index_key(&self.member_path), entry);
            index
        }
    }

    /// [behaviour] N-T3: main records the forced member's NotFound as loss in every such
    /// generation. With the parent present the first one is a removal that
    /// retires the entry together with its unverified audit marker (SOURCE N2,
    /// counted), so the next generation no longer enumerates the member and
    /// records no NotFound at all.
    #[cfg(unix)]
    #[test]
    fn claude_deleted_audit_debt_member_of_forced_quarantined_family_is_removal() {
        let fixture = ForcedFamilyFixture::new("absence-forced-family");
        let member_key = local_index_key(&fixture.member_path);
        let mut index = fixture.index();
        // N3 keeps snapshot incidence; proven absence now releases the
        // unfulfillable account hold without granting body/ACK credit.
        let held = std::collections::BTreeSet::from(["held-member-body".to_string()]);
        index
            .file_snapshot_fingerprints
            .insert(member_key.clone(), held.clone());
        index
            .claude_account_deferred_holds
            .insert(member_key.clone(), "held-member-revision".to_string());
        super::super::sampled_scan::set_test_now(Some(1_000));
        claude_generation(&mut index, &fixture.dir, NOW, 10, &[]);
        assert!(index
            .claude_account_deferred_holds
            .contains_key(&member_key));
        assert!(index.files[&member_key].has_unverified_source());
        for (at, now) in [(LATER, 1_600), (RETRY, 2_200)] {
            super::super::sampled_scan::set_test_now(Some(now));
            let (result, rows) = crate::local_resource_diagnostics::capture(|| {
                observe_vanished(|| {
                    observe_sites(|| {
                        observe(|| claude_generation(&mut index, &fixture.dir, at, 10, &[]))
                    })
                })
            });
            let (((pages, events), sites), vanished) = result;
            let retired = u64::from(at == LATER);
            // Pin the shared #799 keys and meanings independently of the
            // temporary stage/carrier, including zero on the next generation.
            // Count across ALL records so a second emitter cannot hide behind
            // a different stage when these paths compose with #876.
            for (key, expected) in [
                ("audit_retired_absent", serde_json::json!({"events": 1})),
                ("withheld_hold_released", serde_json::json!({"deleted": 1})),
            ] {
                let emissions = rows
                    .iter()
                    .filter(|row| row["counts"].get(key).is_some())
                    .collect::<Vec<_>>();
                assert_eq!(
                    emissions.len(),
                    retired as usize,
                    "{key}: exactly one emission, never duplicate carriers"
                );
                for row in emissions {
                    assert_eq!(row["schema_version"], 2);
                    assert_eq!(row["source"], "claude_code");
                    assert_eq!(row["counts"][key], expected, "{key}: shared count meaning");
                }
            }
            let mut expected_sites = [[[0; OUTCOMES]; SITES]; 3];
            expected_sites[1][Site::CandidateForcedIndex.index()] = [0, retired];
            assert_eq!(sites, expected_sites, "{at}: retired once");
            assert_eq!(events, [[0; 4], [retired, 0, 0, 0], [0; 4]], "{at}");
            assert_eq!(
                vanished,
                [[0; VANISHED], [retired, 0], [0; VANISHED]],
                "{at}: the dropped audit debt is counted once"
            );
            assert!(
                pages.iter().all(|page| page.disappeared_file_count == 0),
                "{at}: the forced member's absence beneath its present parent is not loss"
            );
            let traversal = index.traversal.as_ref().expect("symlink keeps it red");
            assert!(!traversal.observed_index_keys.contains(&member_key));
            assert_eq!(traversal.counts.disappeared_file_count, 0);
            assert_eq!(traversal.counts.symlink_rejected_count, 1);
            assert!(
                !index.files.contains_key(&member_key),
                "{at}: the entry and its marker are gone"
            );
            assert!(!index
                .files
                .values()
                .any(|entry| entry.has_unverified_source()));
            assert_eq!(
                index.file_snapshot_fingerprints.get(&member_key),
                Some(&held)
            );
            assert_eq!(
                index
                    .claude_account_deferred_holds
                    .get(&member_key)
                    .map(String::as_str),
                None,
                "positively absent account hold is released"
            );
        }
        super::super::sampled_scan::set_test_now(None);
    }

    /// Control for N-T3: the same member with its parent directory missing is
    /// not evidence of removal. Its NotFound stays loss, and the entry keeps
    /// its unverified audit marker.
    #[cfg(unix)]
    #[test]
    fn claude_audit_debt_member_below_missing_parent_keeps_entry_and_marker_red() {
        let fixture = ForcedFamilyFixture::new("absence-forced-parent-gone");
        let member_key = local_index_key(&fixture.member_path);
        fs::remove_dir(fixture.member_path.parent().unwrap()).unwrap();
        let mut index = fixture.index();
        let (((pages, events), sites), vanished) = observe_vanished(|| {
            observe_sites(|| observe(|| claude_generation(&mut index, &fixture.dir, NOW, 10, &[])))
        });
        let mut expected_sites = [[[0; OUTCOMES]; SITES]; 3];
        expected_sites[1][Site::CandidateForcedIndex.index()] = [1, 0];
        assert_eq!(sites, expected_sites);
        assert_eq!(events, [[0; 4], [1, 0, 0, 0], [0; 4]]);
        assert_eq!(vanished, [[0; VANISHED]; 3]);
        assert_eq!(
            pages
                .iter()
                .map(|page| page.disappeared_file_count)
                .sum::<usize>(),
            1
        );
        let traversal = index.traversal.as_ref().expect("the loss keeps it red");
        assert!(traversal.counts.has_errors());
        assert_eq!(traversal.counts.disappeared_file_count, 1);
        assert!(index
            .files
            .get(&member_key)
            .is_some_and(|entry| entry.has_unverified_source()));
    }

    /// One bounded walk per `(at, now)` over a deleted session directory, as
    /// observed: a fresh census window whose discovery is still pending
    /// (`pending_directories` > 0), the indexed member enumerated at the forced
    /// index site, then the queued `directory` (if any) read. Returns, per
    /// walk, the member's (disappeared, removed) and the directory's disappeared.
    #[cfg(unix)]
    fn deleted_directory_walk(
        index: &mut ScanIndex,
        root: &Path,
        (at, now): (&str, u64),
        member: &Path,
        directory: Option<&Path>,
    ) -> (usize, bool, usize) {
        super::super::sampled_scan::set_test_now(Some(now));
        super::super::withheld_account::support::clock(&index.withheld_memo);
        index.traversal = None;
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[root.to_path_buf()],
            index,
            at,
            BACKFILL_WINDOW_DAYS,
        );
        let traversal = index.traversal.as_mut().unwrap();
        assert!(
            !traversal.pending_directories.is_empty(),
            "discovery pending"
        );
        if let Some(directory) = directory {
            traversal.pending_directories.push_front(ScanTraversalPath {
                scan_root: root.to_path_buf(),
                path: directory.to_path_buf(),
                census_member: true,
                watcher_hint: false,
            });
        }
        let mut census = ScanCensus::default();
        assert!(super::super::candidate_from_traversal_path_at(
            SnapshotSource::ClaudeCode,
            Site::CandidateForcedIndex,
            ScanTraversalPath {
                scan_root: root.to_path_buf(),
                path: member.to_path_buf(),
                census_member: true,
                watcher_hint: false,
            },
            &mut census,
            None,
            BACKFILL_WINDOW_DAYS,
            &mut crate::snapshots::CandidateDiscovery::new(index, None),
        )
        .is_none());
        let removed = census.removed_index_keys.contains(&local_index_key(member));
        let before = index
            .traversal
            .as_ref()
            .unwrap()
            .counts
            .disappeared_file_count;
        if directory.is_some() {
            advance_bounded_directory_traversal(SnapshotSource::ClaudeCode, index, 7, None);
        }
        let directory_lost = index
            .traversal
            .as_ref()
            .unwrap()
            .counts
            .disappeared_file_count
            - before;
        (census.disappeared_file_count, removed, directory_lost)
    }

    /// A live real root with one indexed subagent member whose whole session
    /// directory was deleted (the common observed shape), plus a gone directory
    /// that was still queued under the live root.
    #[cfg(unix)]
    fn deleted_directory_index(root: &Path) -> (ScanIndex, PathBuf, PathBuf) {
        let member = root
            .join("c4444444-4444-4444-8444-444444444444")
            .join("subagents")
            .join("agent-a4d1585d310070d0f.jsonl");
        let mut index = ScanIndex::default();
        index.files.insert(
            local_index_key(&member),
            super::super::tests::manifest_index_entry(Some("acked-member-body")),
        );
        (index, member, root.join("gone-tool-results"))
    }

    const WALKS: [(&str, u64); 3] = [(NOW, 1_000), (LATER, 1_600), (RETRY, 2_200)];

    /// [off=main] With the switch OFF a member below a deleted directory and a
    /// vanished queued directory stay loss in every walk, as on main.
    #[cfg(unix)]
    #[test]
    fn claude_member_of_deleted_directory_stays_loss_when_switch_off() {
        let dir = crate::test_scratch::ScratchDir::new("absence-deleted-dir-off");
        let root = fs::canonicalize(&dir).unwrap();
        let (mut index, member, directory) = deleted_directory_index(&root);
        for walk in WALKS {
            assert_eq!(
                deleted_directory_walk(&mut index, &root, walk, &member, Some(&directory)),
                (1, false, 1)
            );
        }
        super::super::sampled_scan::set_test_now(None);
        // Only a regular-file owner marker enables it; fixtures never read it.
        let support = crate::test_scratch::ScratchDir::new("vanished-directory-marker");
        let marker = support.join("claude_vanished_directory_removal_enabled");
        fs::create_dir(&marker).unwrap();
        assert!(!enabled_at(&support));
        fs::remove_dir(&marker).unwrap();
        fs::write(&marker, b"").unwrap();
        assert!(enabled_at(&support));
        assert!(!enabled());
    }

    /// [regress] Observed: every Claude walk ended red with 47-71
    /// CandidateForcedIndex losses per process, all members of deleted
    /// directories, observed while discovery was still pending. ON: the first
    /// NotFound stays loss and a strictly later walk settles it; a vanished
    /// queued directory below its live parent settles the same way.
    #[cfg(unix)]
    #[test]
    fn claude_member_of_deleted_directory_is_removal_after_a_later_walk() {
        let dir = crate::test_scratch::ScratchDir::new("absence-deleted-dir-on");
        let root = fs::canonicalize(&dir).unwrap();
        let (mut index, member, directory) = deleted_directory_index(&root);
        let _on = super::super::local_switch::ThreadSwitchForTest::set(&ENABLED, true);
        let [first, second, _] = WALKS;
        assert_eq!(
            deleted_directory_walk(&mut index, &root, first, &member, Some(&directory)),
            (1, false, 1)
        );
        assert_eq!(
            deleted_directory_walk(&mut index, &root, second, &member, Some(&directory)),
            (0, true, 0)
        );
        assert!(snapshot(SnapshotSource::ClaudeCode).parent_missing_removals >= 1);
        super::super::sampled_scan::set_test_now(None);
    }

    /// [money] Settling the deleted member through the page
    /// merge drops its entry exactly as a live-parent removal does. The
    /// accepted (ACKed) ledger stays byte-for-byte, and no zero or removal
    /// body is built for its family.
    #[cfg(unix)]
    #[test]
    fn claude_member_of_deleted_directory_keeps_acked_usage_accepted() {
        let dir = crate::test_scratch::ScratchDir::new("absence-deleted-dir-money");
        let root = fs::canonicalize(&dir).unwrap();
        fs::write(
            root.join(format!("{FORCED_ROOT}.jsonl")),
            claude_line(FORCED_ROOT, "request-root"),
        )
        .unwrap();
        // A rejected symlink keeps family membership non-authoritative, so
        // the forced enumeration reaches the indexed member in this tiny tree.
        std::os::unix::fs::symlink(root.join("nowhere"), root.join("zz-link")).unwrap();
        let member = root
            .join(FORCED_ROOT)
            .join("subagents")
            .join("agent-a4d1585d310070d0f.jsonl");
        let key = local_index_key(&member);
        let acked = "acked-member-body".to_string();
        let mut index = ScanIndex::default();
        index.insert_retry_pending_claude_authority_for_test(FORCED_ROOT);
        index.files.insert(
            key.clone(),
            super::super::tests::manifest_index_entry(Some(&acked)),
        );
        index
            .file_snapshot_fingerprints
            .insert(key.clone(), [acked.clone()].into());
        index.accepted_snapshot_fingerprints.insert(acked.clone());
        let ledger = |index: &ScanIndex| {
            serde_json::to_vec(&(
                &index.accepted_snapshot_fingerprints,
                index.accepted_snapshot_fingerprint_ledger_version,
            ))
            .unwrap()
        };
        let before = ledger(&index);
        let _on = super::super::local_switch::ThreadSwitchForTest::set(&ENABLED, true);
        let mut pages = Vec::new();
        for (at, now) in WALKS {
            super::super::sampled_scan::set_test_now(Some(now));
            pages = claude_generation(&mut index, &root, at, 10, &[]);
            if !index.files.contains_key(&key) {
                break;
            }
        }
        super::super::sampled_scan::set_test_now(None);
        assert!(!index.files.contains_key(&key), "the member was retired");
        assert_eq!(ledger(&index), before, "the accepted ledger is unchanged");
        for snapshot in pages.iter().flat_map(|page| &page.snapshots) {
            assert!(snapshot.removed_usage.is_none());
            assert!(snapshot.removed_request_count.is_none());
            assert!(snapshot.input_tokens + snapshot.output_tokens > 0);
        }
    }

    /// Control: the quarantined family losing one member through N leaves the
    /// family's quarantine, witness, pending and holds exactly as the reviewed
    /// remove-hint retirement of the same member does. N adds no quarantine
    /// rule, so no held body is released by it, and the failure count moves at
    /// most once. Only the vanished member's own entry and marker go (N2).
    #[cfg(unix)]
    #[test]
    fn claude_member_removal_matches_remove_hint_for_quarantined_family() {
        let fixture = ForcedFamilyFixture::new("absence-quarantine-control");
        let initial = fixture.index();
        let failures_before =
            initial.claude_usage_authority_quarantine[FORCED_ROOT].failed_reconstruction_count;
        let mut removal = initial.clone();
        let removal_pages = claude_generation(&mut removal, &fixture.dir, NOW, 10, &[]);
        let mut hinted = initial;
        claude_generation(
            &mut hinted,
            &fixture.dir,
            NOW,
            10,
            std::slice::from_ref(&fixture.member_path),
        );
        assert!(removal_pages
            .iter()
            .all(|page| page.disappeared_file_count == 0));
        let family_state = |index: &ScanIndex| {
            serde_json::json!({
                "quarantine": index.claude_usage_authority_quarantine,
                "witnesses": index.claude_usage_family_witnesses,
                "pending": index.claude_usage_family_pending,
                "deferred_holds": index.claude_account_deferred_holds,
            })
        };
        assert_eq!(family_state(&removal), family_state(&hinted));
        assert!(!removal
            .files
            .contains_key(&local_index_key(&fixture.member_path)));
        let record = removal
            .claude_usage_authority_quarantine
            .get(FORCED_ROOT)
            .expect("the family root is still present, so its quarantine record is kept");
        assert!(record.failed_reconstruction_count <= failures_before.saturating_add(1));
    }

    /// SOURCE N1: the request-census (D1) record of a member retired as a
    /// removal goes with its entry, and that removal is counted.
    #[test]
    fn claude_vanished_member_drops_its_request_census_record_and_counts_it() {
        let dir = crate::test_scratch::ScratchDir::new("absence-request-census");
        let first = "a1111111-1111-4111-8111-111111111111";
        let second = "b2222222-2222-4222-8222-222222222222";
        let first_path = dir.join(format!("{first}.jsonl"));
        let second_path = dir.join(format!("{second}.jsonl"));
        let second_key = local_index_key(&second_path);
        fs::write(&first_path, claude_line(first, "request-first")).unwrap();
        fs::write(&second_path, claude_line(second, "request-second")).unwrap();
        let mut index = ScanIndex::default();
        assert!(
            claude_generation(&mut index, &dir, NOW, 1, &[])
                .last()
                .unwrap()
                .census_complete
        );
        claude_page(&mut index, &dir, LATER, 1, &[]);
        assert!(
            index
                .claude_request_census_for_test()
                .get(&second_key)
                .is_some(),
            "precondition: the real parse recorded the member's census"
        );
        fs::remove_file(&second_path).unwrap();
        let (pages, vanished) =
            observe_vanished(|| claude_generation(&mut index, &dir, LATER, 1, &[]));
        assert!(pages.iter().all(|page| page.disappeared_file_count == 0));
        assert!(!index.files.contains_key(&second_key));
        assert!(index
            .claude_request_census_for_test()
            .get(&second_key)
            .is_none());
        assert_eq!(vanished, [[0; VANISHED], [0, 1], [0; VANISHED]]);
    }

    /// [behaviour] The audit-debt path (SOURCE N2) also drops the member's request-census
    /// (D1) record with its entry and counts both retirements, while the
    /// member's snapshot fingerprints stay (N3).
    #[test]
    fn claude_vanished_audit_debt_member_drops_its_request_census_record_and_counts_it() {
        for account_held in [false, true] {
            let dir = crate::test_scratch::ScratchDir::new("absence-debt-request-census");
            let first = "a1111111-1111-4111-8111-111111111111";
            let second = "b2222222-2222-4222-8222-222222222222";
            let first_path = dir.join(format!("{first}.jsonl"));
            let second_path = dir.join(format!("{second}.jsonl"));
            let second_key = local_index_key(&second_path);
            fs::write(&first_path, claude_line(first, "request-first")).unwrap();
            fs::write(&second_path, claude_line(second, "request-second")).unwrap();
            let mut index = ScanIndex::default();
            assert!(
                claude_generation(&mut index, &dir, NOW, 1, &[])
                    .last()
                    .unwrap()
                    .census_complete
            );
            // The next generation walks both and selects only the first.
            claude_page(&mut index, &dir, LATER, 1, &[]);
            assert!(index
                .traversal
                .as_ref()
                .unwrap()
                .pending_candidates
                .iter()
                .any(|pending| pending.path == second_path && pending.census_member));
            assert!(
                index
                    .claude_request_census_for_test()
                    .get(&second_key)
                    .is_some(),
                "precondition: the real parse recorded the member's census"
            );
            let entry = index.files.get_mut(&second_key).unwrap();
            entry.scan_identity_version = Some(format!(
                "{}:4000000000",
                super::super::sampled_audit::UNVERIFIED_IDENTITY
            ));
            assert!(entry.has_unverified_source());
            if account_held {
                index
                    .claude_account_deferred_holds
                    .insert(second_key.clone(), entry.source_file_fingerprint.clone());
            }
            let fingerprints_before = index.file_snapshot_fingerprints.get(&second_key).cloned();
            fs::remove_file(&second_path).unwrap();
            super::super::sampled_scan::set_test_now(Some(1_000));
            let ((pages, sites), vanished) = observe_vanished(|| {
                observe_sites(|| {
                    let mut pages = claude_generation(&mut index, &dir, LATER, 1, &[]);
                    if account_held {
                        assert!(index
                            .claude_account_deferred_holds
                            .contains_key(&second_key));
                        assert!(index.files[&second_key].has_unverified_source());
                        assert!(index
                            .claude_request_census_for_test()
                            .get(&second_key)
                            .is_some());
                        super::super::sampled_scan::set_test_now(Some(1_600));
                        // A healthy first generation may have retired its
                        // checkpoint while the account hold still needs F4.
                        super::super::line_delivery_tests::next_walk(
                            &mut index,
                            &[dir.to_path_buf()],
                            LATER,
                            BACKFILL_WINDOW_DAYS,
                        );
                        pages.extend(claude_generation(&mut index, &dir, RETRY, 1, &[]));
                    }
                    pages
                })
            });
            super::super::sampled_scan::set_test_now(None);
            let mut expected_sites = [[[0; OUTCOMES]; SITES]; 3];
            expected_sites[1][Site::CandidateWalk.index()] = [0, 1];
            assert_eq!(sites, expected_sites);
            assert!(pages.iter().all(|page| page.disappeared_file_count == 0));
            assert!(
                !index.files.contains_key(&second_key),
                "the entry and its marker are gone"
            );
            assert!(index
                .claude_request_census_for_test()
                .get(&second_key)
                .is_none());
            assert_eq!(vanished, [[0; VANISHED], [1, 1], [0; VANISHED]]);
            assert_eq!(
                index.file_snapshot_fingerprints.get(&second_key),
                fingerprints_before.as_ref()
            );
            assert!(index.files.contains_key(&local_index_key(&first_path)));
        }
    }

    /// D11 through the real pipeline: an indexed Claude file is in the frozen
    /// selection and is deleted beneath its present parent before the page's
    /// safe open. The page merge retires its entry and its request-census
    /// record (counted), the generation finishes healthy, and the next one is
    /// quiet.
    #[test]
    fn claude_selected_member_deleted_before_open_retires_through_the_page_merge() {
        let dir = crate::test_scratch::ScratchDir::new("absence-open-pipeline");
        let first = "a1111111-1111-4111-8111-111111111111";
        let second = "b2222222-2222-4222-8222-222222222222";
        let first_path = dir.join(format!("{first}.jsonl"));
        let second_path = dir.join(format!("{second}.jsonl"));
        let second_key = local_index_key(&second_path);
        fs::write(&first_path, claude_line(first, "request-first")).unwrap();
        fs::write(&second_path, claude_line(second, "request-second")).unwrap();
        let mut index = ScanIndex::default();
        assert!(
            claude_generation(&mut index, &dir, NOW, 10, &[])
                .last()
                .unwrap()
                .census_complete
        );
        assert!(index.traversal.is_none());
        assert!(index.files.contains_key(&second_key));
        assert!(
            index
                .claude_request_census_for_test()
                .get(&second_key)
                .is_some(),
            "precondition: the real parse recorded the member's census"
        );
        let state = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            &[dir.to_path_buf()],
            index,
            LATER,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
        );
        assert!(
            state
                .identified_candidates
                .iter()
                .any(|candidate| candidate.path == second_path),
            "precondition: the frozen selection holds the member"
        );
        fs::remove_file(&second_path).unwrap(); // after frozen selection, before safe open
        let ((((mut index, pages), events), sites), vanished) = observe_vanished(|| {
            observe_sites(|| {
                observe(|| {
                    let (mut index, scan) = finish(state);
                    let mut pages = vec![scan];
                    if index.traversal.is_some() {
                        pages.extend(claude_generation(&mut index, &dir, LATER, 10, &[]));
                    }
                    (index, pages)
                })
            })
        });
        let mut expected_sites = [[[0; OUTCOMES]; SITES]; 3];
        expected_sites[1][Site::Open.index()] = [0, 1];
        assert_eq!(sites, expected_sites);
        assert_eq!(events, [[0; 4], [1, 0, 0, 0], [0; 4]]);
        assert_eq!(vanished, [[0; VANISHED], [0, 1], [0; VANISHED]]);
        assert!(
            pages.iter().all(|page| page.disappeared_file_count == 0),
            "a member deleted before its open beneath its present parent is not loss"
        );
        assert!(pages.last().unwrap().census_complete);
        assert!(index.traversal.is_none(), "the generation retired healthy");
        assert!(!index.files.contains_key(&second_key));
        assert!(index
            .claude_request_census_for_test()
            .get(&second_key)
            .is_none());
        assert!(index.files.contains_key(&local_index_key(&first_path)));

        let ((pages, events), sites) =
            observe_sites(|| observe(|| claude_generation(&mut index, &dir, RETRY, 10, &[])));
        assert_eq!(sites, [[[0; OUTCOMES]; SITES]; 3]);
        assert_eq!(events, [[0; 4]; 3]);
        assert!(pages.iter().all(|page| page.disappeared_file_count == 0));
        assert!(pages.last().unwrap().census_complete);
        assert!(index.traversal.is_none(), "the next generation is quiet");
    }

    /// Control: a single-file rename. The old path, deleted after the walk
    /// queued it, retires as a removal; the new path arrives as a hint and is
    /// indexed in the same generation.
    #[test]
    fn claude_single_file_rename_retires_old_path_and_indexes_new_path() {
        let dir = crate::test_scratch::ScratchDir::new("absence-rename");
        let first = "a1111111-1111-4111-8111-111111111111";
        let second = "b2222222-2222-4222-8222-222222222222";
        let renamed = "d4444444-4444-4444-8444-444444444444";
        let first_path = dir.join(format!("{first}.jsonl"));
        let second_path = dir.join(format!("{second}.jsonl"));
        let renamed_path = dir.join(format!("{renamed}.jsonl"));
        fs::write(&first_path, claude_line(first, "request-first")).unwrap();
        fs::write(&second_path, claude_line(second, "request-second")).unwrap();
        let mut index = ScanIndex::default();
        assert!(
            claude_generation(&mut index, &dir, NOW, 1, &[])
                .last()
                .unwrap()
                .census_complete
        );
        claude_page(&mut index, &dir, LATER, 1, &[]);
        fs::rename(&second_path, &renamed_path).unwrap();
        let pages = claude_generation(
            &mut index,
            &dir,
            LATER,
            1,
            &[second_path.clone(), renamed_path.clone()],
        );
        assert!(pages.iter().all(|page| page.disappeared_file_count == 0));
        assert!(pages.last().unwrap().census_complete);
        assert!(!index.files.contains_key(&local_index_key(&second_path)));
        assert!(index.files.contains_key(&local_index_key(&renamed_path)));
        assert!(index.files.contains_key(&local_index_key(&first_path)));
    }

    /// Control: a missing, renamed or symlinked parent is not evidence of
    /// removal. The Claude NotFound stays loss at the candidate stat and at
    /// the open.
    #[cfg(unix)]
    #[test]
    fn claude_absence_without_a_present_real_parent_stays_red() {
        let dir = crate::test_scratch::ScratchDir::new("absence-parent-gone");
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        for path in [
            dir.join("gone").join("missing.jsonl"),
            link.join("missing.jsonl"),
        ] {
            let mut census = ScanCensus::default();
            let (candidate, events) = observe(|| {
                candidate_from_traversal_path(
                    SnapshotSource::ClaudeCode,
                    ScanTraversalPath {
                        scan_root: dir.to_path_buf(),
                        path: path.clone(),
                        census_member: true,
                        watcher_hint: false,
                    },
                    &mut census,
                    None,
                    BACKFILL_WINDOW_DAYS,
                    &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
                )
            });
            assert!(candidate.is_none());
            assert_eq!(census.disappeared_file_count, 1, "{path:?}");
            assert_eq!(events, [[0; 4], [1, 0, 0, 0], [0; 4]]);
            assert!(census.removed_index_keys.is_empty());
        }

        let project = dir.join("project");
        fs::create_dir(&project).unwrap();
        let path = project.join("session.jsonl");
        fs::write(&path, b"{}\n").unwrap();
        let mut census = ScanCensus::default();
        let candidate = candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            ScanTraversalPath {
                scan_root: dir.to_path_buf(),
                path: path.clone(),
                census_member: true,
                watcher_hint: false,
            },
            &mut census,
            None,
            BACKFILL_WINDOW_DAYS,
            &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
        )
        .unwrap();
        fs::rename(&project, dir.join("project-renamed")).unwrap();
        let (opened, events) = observe(|| {
            open_and_identify_scan_candidate(
                SnapshotSource::ClaudeCode,
                candidate,
                &mut census,
                None,
                BACKFILL_WINDOW_DAYS,
                crate::snapshots::DiscoveryRetention::unverified(
                    &crate::snapshots::SharedMap::default(),
                ),
            )
        });
        assert!(opened.is_none());
        assert_eq!(events, [[0; 4], [1, 0, 0, 0], [0; 4]]);
        assert_eq!(census.disappeared_file_count, 1);
        assert!(census.removed_index_keys.is_empty());
    }

    /// Control: EACCES on the parent is not NotFound and stays Metadata red.
    #[cfg(unix)]
    #[test]
    fn claude_absence_below_inaccessible_parent_stays_metadata_red() {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            // SAFETY: geteuid() is always-successful and has no preconditions.
            unsafe { libc::geteuid() },
            0,
            "this test blocks the parent with chmod 000, which root reads through; run it as a non-root user"
        );
        let dir = crate::test_scratch::ScratchDir::new("absence-parent-eacces");
        let project = dir.join("project");
        fs::create_dir(&project).unwrap();
        let path = project.join("missing.jsonl");
        fs::set_permissions(&project, fs::Permissions::from_mode(0o000)).unwrap();
        let mut census = ScanCensus::default();
        let (candidate, events) = observe(|| {
            candidate_from_traversal_path(
                SnapshotSource::ClaudeCode,
                ScanTraversalPath {
                    scan_root: dir.to_path_buf(),
                    path: path.clone(),
                    census_member: true,
                    watcher_hint: false,
                },
                &mut census,
                None,
                BACKFILL_WINDOW_DAYS,
                &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
            )
        });
        fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(candidate.is_none());
        assert_eq!(events, [[0; 4]; 3]);
        assert_eq!(census.unreadable_path_count, 1);
        assert_eq!(census.disappeared_file_count, 0);
        assert!(census.removed_index_keys.is_empty());
    }

    #[test]
    fn real_not_found_sites_split_loss_and_removal() {
        let dir = crate::test_scratch::ScratchDir::new("disappearance-sites");
        let path = dir.join("session.jsonl");
        let pending = || ScanTraversalPath {
            scan_root: dir.to_path_buf(),
            path: path.clone(),
            census_member: true,
            watcher_hint: false,
        };
        let mut census = ScanCensus::default();
        let (_, sites) = observe_sites(|| {
            for source in [SnapshotSource::Pi, SnapshotSource::ClaudeCode] {
                assert!(candidate_from_traversal_path(
                    source,
                    pending(),
                    &mut census,
                    None,
                    BACKFILL_WINDOW_DAYS,
                    &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
                )
                .is_none());
                fs::write(&path, b"{}\n").unwrap();
                let candidate = candidate_from_traversal_path(
                    source,
                    pending(),
                    &mut census,
                    None,
                    BACKFILL_WINDOW_DAYS,
                    &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
                )
                .unwrap();
                fs::remove_file(&path).unwrap();
                assert!(open_and_identify_scan_candidate(
                    source,
                    candidate,
                    &mut census,
                    None,
                    BACKFILL_WINDOW_DAYS,
                    crate::snapshots::DiscoveryRetention::unverified(
                        &crate::snapshots::SharedMap::default()
                    ),
                )
                .is_none());
            }
        });
        let mut expected = [[[0; OUTCOMES]; SITES]; 3];
        expected[2][Site::CandidateWalk.index()] = [1, 0];
        expected[2][Site::Open.index()] = [1, 0];
        expected[1][Site::CandidateWalk.index()] = [0, 1];
        expected[1][Site::Open.index()] = [0, 1];
        assert_eq!(sites, expected);
        assert_eq!(census.disappeared_file_count, 2, "Pi only");

        let root = dir.join("root");
        fs::create_dir(&root).unwrap();
        let mut index = ScanIndex::default();
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            NOW,
            BACKFILL_WINDOW_DAYS,
        );
        fs::remove_dir(&root).unwrap();
        let (_, sites) = observe_sites(|| {
            advance_bounded_directory_traversal(
                SnapshotSource::ClaudeCode,
                &mut index,
                BACKFILL_WINDOW_DAYS,
                None,
            )
        });
        let mut expected = [[[0; OUTCOMES]; SITES]; 3];
        expected[1][Site::WalkDirectory.index()] = [1, 0];
        assert_eq!(sites, expected, "a vanished queued directory stays loss");
    }
}

#[cfg(test)]
type AbsenceParentProbeHook = Box<dyn FnOnce()>;
#[cfg(test)]
thread_local! {
    static ABSENCE_PARENT_PROBE_HOOK: std::cell::RefCell<Option<AbsenceParentProbeHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn before_absence_parent_probe() {
    let hook = ABSENCE_PARENT_PROBE_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(all(test, unix))]
mod absence_parent_counts_tests {
    use super::super::*;
    use super::{observe_sites, Site, OUTCOMES, SITES};
    use crate::local_resource_diagnostics::{self as lr, claude_reread::Scope};

    fn counts(scope: Scope) -> serde_json::Value {
        serde_json::to_value(scope.finish()).unwrap()
    }

    #[test]
    fn parent_probe_boolean_and_each_refusal_class_are_unchanged() {
        let dir = crate::test_scratch::ScratchDir::new("absence-classes");
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let file = dir.join("file");
        fs::write(&file, b"fixture").unwrap();
        let cycle = dir.join("cycle");
        std::os::unix::fs::symlink(&cycle, &cycle).unwrap();
        // ELOOP supplies an actual metadata error without permission/root assumptions.
        for (parent, suffix, expected) in [
            (dir.join("missing"), "missing", false),
            (link, "symlink", false),
            (file, "not_directory", false),
            (cycle.join("nested"), "metadata_error", false),
            (real, "", true),
        ] {
            let path = parent.join("member.jsonl");
            let original = path
                .parent()
                .and_then(|p| fs::symlink_metadata(p).ok())
                .is_some_and(|p| p.is_dir() && !p.file_type().is_symlink());
            let scope = Scope::begin(true);
            let result =
                claude_absence_is_removal(SnapshotSource::ClaudeCode, &path).is_removal(&path);
            assert_eq!(result, original);
            assert_eq!(result, expected);
            let actual = counts(scope);
            if expected {
                assert_eq!(actual, serde_json::json!({}));
            } else {
                let mut wanted = serde_json::Map::new();
                wanted.insert(format!("claude_absence_parent_{suffix}"), 1.into());
                assert_eq!(actual, serde_json::Value::Object(wanted));
            }
        }
    }

    #[test]
    fn candidate_sites_count_once_and_live_parent_still_removes() {
        let dir = crate::test_scratch::ScratchDir::new("absence-sites-counts");
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        for site in [Site::CandidateWalk, Site::CandidateForcedIndex] {
            for (parent, suffix) in [
                (dir.join("missing"), "missing"),
                (link.clone(), "symlink"),
                (real.clone(), ""),
            ] {
                let path = parent.join("member.jsonl");
                let scope = Scope::begin(true);
                let mut census = ScanCensus::default();
                let (_, events) = observe_sites(|| {
                    candidate_from_traversal_path_at(
                        SnapshotSource::ClaudeCode,
                        site,
                        ScanTraversalPath {
                            scan_root: dir.to_path_buf(),
                            path: path.clone(),
                            census_member: true,
                            watcher_hint: false,
                        },
                        &mut census,
                        None,
                        BACKFILL_WINDOW_DAYS,
                        &mut crate::snapshots::CandidateDiscovery::new(
                            &mut ScanIndex::default(),
                            None,
                        ),
                    )
                });
                let removal = suffix.is_empty();
                assert_eq!(
                    events[1][site.index()],
                    if removal { [0, 1] } else { [1, 0] }
                );
                assert_eq!(census.disappeared_file_count, usize::from(!removal));
                assert_eq!(
                    census.removed_index_keys.contains(&local_index_key(&path)),
                    removal
                );
                let actual = counts(scope);
                let mut wanted = serde_json::Map::new();
                if !removal {
                    wanted.insert(format!("claude_absence_parent_{suffix}"), 1.into());
                }
                assert_eq!(actual, serde_json::Value::Object(wanted));
            }
        }
    }

    #[test]
    fn parent_races_count_file_and_metadata_error_once_per_not_found() {
        for site in [Site::CandidateWalk, Site::CandidateForcedIndex] {
            for metadata_error in [false, true] {
                let dir = crate::test_scratch::ScratchDir::new("absence-parent-race");
                let base = dir.join("parent");
                let parent = if metadata_error {
                    base.join("nested")
                } else {
                    base.clone()
                };
                fs::create_dir_all(&parent).unwrap();
                let path = parent.join("missing.jsonl");
                // The child lstat returns NotFound first; change only the existing
                // parent probe's result, at the production call boundary.
                super::ABSENCE_PARENT_PROBE_HOOK.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        fs::remove_dir(&parent).unwrap();
                        if metadata_error {
                            fs::remove_dir(&base).unwrap();
                            std::os::unix::fs::symlink(&base, &base).unwrap();
                        } else {
                            fs::write(&base, b"fixture").unwrap();
                        }
                    }));
                });
                let scope = Scope::begin(true);
                let mut census = ScanCensus::default();
                let (candidate, events) = observe_sites(|| {
                    candidate_from_traversal_path_at(
                        SnapshotSource::ClaudeCode,
                        site,
                        ScanTraversalPath {
                            scan_root: dir.to_path_buf(),
                            path,
                            census_member: true,
                            watcher_hint: false,
                        },
                        &mut census,
                        None,
                        BACKFILL_WINDOW_DAYS,
                        &mut crate::snapshots::CandidateDiscovery::new(
                            &mut ScanIndex::default(),
                            None,
                        ),
                    )
                });
                assert!(candidate.is_none());
                assert!(super::ABSENCE_PARENT_PROBE_HOOK.with(|hook| hook.borrow().is_none()));
                let mut wanted_events = [[[0; OUTCOMES]; SITES]; 3];
                wanted_events[1][site.index()] = [1, 0];
                assert_eq!(events, wanted_events);
                assert_eq!(census.disappeared_file_count, 1);
                assert!(census.removed_index_keys.is_empty());
                let key = if metadata_error {
                    "claude_absence_parent_metadata_error"
                } else {
                    "claude_absence_parent_not_directory"
                };
                let mut wanted = serde_json::Map::new();
                wanted.insert(key.to_owned(), 1.into());
                assert_eq!(counts(scope), serde_json::Value::Object(wanted));
            }
        }
    }

    #[test]
    fn open_subagent_counts_survive_steps_and_emit_on_existing_page() {
        let dir = crate::test_scratch::ScratchDir::new("absence-open-subagent");
        let parent = dir.join("subagents");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("member.jsonl");
        fs::write(&path, b"{}\n").unwrap();
        let mut census = ScanCensus::default();
        let candidate = candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            ScanTraversalPath {
                scan_root: dir.to_path_buf(),
                path: path.clone(),
                census_member: true,
                watcher_hint: false,
            },
            &mut census,
            None,
            BACKFILL_WINDOW_DAYS,
            &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
        )
        .unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&parent).unwrap();
        let scope = Scope::begin(true);
        let (_, events) = observe_sites(|| {
            open_and_identify_scan_candidate(
                SnapshotSource::ClaudeCode,
                candidate,
                &mut census,
                None,
                BACKFILL_WINDOW_DAYS,
                crate::snapshots::DiscoveryRetention::unverified(
                    &crate::snapshots::SharedMap::default(),
                ),
            )
        });
        assert_eq!(events[1][Site::Open.index()], [1, 0]);
        assert_eq!(census.disappeared_file_count, 1);
        assert!(census.removed_index_keys.is_empty());
        let mut probe = lr::Probe::start();
        probe.page_events.merge(scope.finish());
        let empty_step = Scope::begin(true);
        probe.page_events.merge(empty_step.finish());
        let (_, records) = lr::capture(|| {
            probe.collection(
                "claude_code",
                lr::CollectionCounts {
                    scanned_files: 0,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                    full_causes: Default::default(),
                },
            )
        });
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["stage"], "native_collection_page");
        assert_eq!(records[0]["schema_version"], 2);
        let c = &records[0]["counts"];
        assert_eq!(c["claude_absence_parent_missing"], 1);
        assert_eq!(c["claude_absence_parent_subagent_missing"], 1);
        assert_eq!(
            c.as_object()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with("claude_absence_parent"))
                .count(),
            2
        );
        assert_eq!(counts(Scope::begin(true)), serde_json::json!({}));
    }

    #[test]
    fn other_sources_hints_and_nonmembers_add_no_parent_counts() {
        let dir = crate::test_scratch::ScratchDir::new("absence-excluded");
        for (source, census_member, watcher_hint) in [
            (SnapshotSource::Codex, true, false),
            (SnapshotSource::Pi, true, false),
            (SnapshotSource::ClaudeCode, false, false),
            (SnapshotSource::ClaudeCode, true, true),
        ] {
            let scope = Scope::begin(true);
            let mut census = ScanCensus::default();
            candidate_from_traversal_path(
                source,
                ScanTraversalPath {
                    scan_root: dir.to_path_buf(),
                    path: dir.join("missing/member.jsonl"),
                    census_member,
                    watcher_hint,
                },
                &mut census,
                None,
                BACKFILL_WINDOW_DAYS,
                &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
            );
            assert_eq!(counts(scope), serde_json::json!({}));
        }
    }
}
