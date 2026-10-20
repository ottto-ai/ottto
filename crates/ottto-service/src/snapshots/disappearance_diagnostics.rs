//! Best-effort process/source totals, never traversal authority or persisted state.
//! Independent relaxed loads are non-atomic across counters and overflow. A wrap
//! can be visible before its sticky flag: even false cannot prove exact concurrent
//! conservation. First/reset/gap/missing-field/restored-window attribution is UNKNOWN.
use super::SnapshotSource;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

fn source_index(source: SnapshotSource) -> usize {
    match source {
        SnapshotSource::Codex => 0,
        SnapshotSource::ClaudeCode => 1,
        SnapshotSource::Pi => 2,
    }
}

struct Counters {
    counts: [AtomicU64; 4],
    overflowed: AtomicBool,
}
impl Counters {
    const fn new() -> Self {
        Self {
            counts: [const { AtomicU64::new(0) }; 4],
            overflowed: AtomicBool::new(false),
        }
    }
    fn record(&self, cause: Cause) {
        if self.counts[cause.index()].fetch_add(1, Ordering::Relaxed) == u64::MAX {
            self.overflowed.store(true, Ordering::Relaxed);
        }
    }
    fn snapshot(&self) -> Totals {
        Totals {
            version: 1,
            scope: "process_lifetime_not_window",
            counts: std::array::from_fn(|i| self.counts[i].load(Ordering::Relaxed)),
            overflowed: self.overflowed.load(Ordering::Relaxed),
        }
    }
}

static TOTALS: [Counters; 3] = [const { Counters::new() }; 3];

/// Fixed order: NotFound, unresolved root, changed preflight, changed target.
/// The sticky flag invalidates exact intervals; false is not a coherence proof.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct Totals {
    version: u8,
    scope: &'static str,
    counts: [u64; 4],
    overflowed: bool,
}

pub(super) fn increment(count: &mut usize, source: SnapshotSource, cause: Cause) {
    // Preserve the original arithmetic (including overflow behavior) and order.
    *count += 1;
    TOTALS[source_index(source)].record(cause);
    #[cfg(test)]
    TEST_EVENTS.with(|events| {
        if let Some(mut counts) = events.get() {
            counts[source_index(source)][cause.index()] += 1;
            events.set(Some(counts));
        }
    });
}

pub(super) fn snapshot(source: SnapshotSource) -> Totals {
    TOTALS[source_index(source)].snapshot()
}

#[cfg(test)]
thread_local! {
    static TEST_EVENTS: std::cell::Cell<Option<[[u64; 4]; 3]>> = const { std::cell::Cell::new(None) };
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

#[cfg(test)]
impl Totals {
    pub(super) fn maximum() -> Self {
        Self {
            version: 1,
            scope: "process_lifetime_not_window",
            counts: [u64::MAX; 4],
            overflowed: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        advance_bounded_directory_traversal, candidate_from_traversal_path,
        ensure_bounded_traversal, open_and_identify_scan_candidate, OwnedSourceScan,
        OwnedSourceScanStep, ScanCensus, ScanIndex, ScanTraversalPath, SourceScanResult,
        BACKFILL_WINDOW_DAYS,
    };
    use super::*;
    use std::{collections::BTreeMap, fs};

    const NOW: &str = "2026-10-07T12:00:00Z";

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
        for (member, watcher, expected) in [
            (true, false, 1),
            (true, true, 0),
            (false, false, 0),
            (false, true, 0),
        ] {
            let mut census = ScanCensus::default();
            let (candidate, events) = observe(|| {
                candidate_from_traversal_path(
                    SnapshotSource::Pi,
                    ScanTraversalPath {
                        scan_root: dir.to_path_buf(),
                        path: path.clone(),
                        census_member: member,
                        watcher_hint: watcher,
                    },
                    &mut census,
                    None,
                    BACKFILL_WINDOW_DAYS,
                    &BTreeMap::new(),
                )
            });
            assert!(candidate.is_none());
            assert_eq!(census.disappeared_file_count, expected);
            assert_eq!(census.unreadable_path_count, 0);
            assert_eq!(events, [[0; 4], [0; 4], [expected as u64, 0, 0, 0]]);
            assert_eq!(
                census
                    .removed_index_keys
                    .contains(&super::super::local_index_key(&path)),
                watcher
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
                index.traversal.as_mut().unwrap(),
                BACKFILL_WINDOW_DAYS,
                &index.files,
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
        fs::write(&path, b"{}\n").unwrap();
        let mut census = ScanCensus::default();
        let candidate = candidate_from_traversal_path(
            SnapshotSource::Pi,
            ScanTraversalPath {
                scan_root: dir.to_path_buf(),
                path: path.clone(),
                census_member: true,
                watcher_hint: false,
            },
            &mut census,
            None,
            BACKFILL_WINDOW_DAYS,
            &BTreeMap::new(),
        )
        .unwrap();
        fs::remove_file(&path).unwrap();
        let (opened, events) = observe(|| {
            open_and_identify_scan_candidate(
                SnapshotSource::Pi,
                candidate,
                &mut census,
                None,
                BACKFILL_WINDOW_DAYS,
                &BTreeMap::new(),
            )
        });
        assert!(opened.is_none());
        assert_eq!(events, [[0; 4], [0; 4], [1, 0, 0, 0]]);
        assert_eq!(census.disappeared_file_count, 1);
        assert_eq!(census.unreadable_path_count, 0);
        assert!(census.removed_index_keys.is_empty());
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

    #[test]
    fn isolated_sources_classes_order_and_sticky_wrap() {
        let totals = [const { Counters::new() }; 3];
        let causes = [
            Cause::NotFound,
            Cause::RootResolutionUnresolved,
            Cause::PreflightFingerprintChanged,
            Cause::ComparisonTargetRevisionChanged,
        ];
        for (s, source) in [
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
            SnapshotSource::Pi,
        ]
        .into_iter()
        .enumerate()
        {
            for (c, cause) in causes.into_iter().enumerate() {
                for _ in 0..s * 4 + c + 1 {
                    totals[source_index(source)].record(cause);
                }
            }
        }
        for (s, counters) in totals.iter().enumerate() {
            let value = serde_json::to_value(counters.snapshot()).unwrap();
            let expected_counts: [u64; 4] = std::array::from_fn(|c| (s * 4 + c + 1) as u64);
            assert_eq!(
                value,
                serde_json::json!({"version":1,
                "scope":"process_lifetime_not_window",
                "counts":expected_counts,
                "overflowed":false})
            );
        }
        let counters = Counters::new();
        counters.counts[0].store(u64::MAX, Ordering::Relaxed);
        counters.record(Cause::NotFound);
        assert_eq!(counters.snapshot().counts, [0; 4]);
        assert!(counters.snapshot().overflowed);
        counters.record(Cause::ComparisonTargetRevisionChanged);
        assert!(counters.snapshot().overflowed);

        // Model the observable between-instructions state of a wrapping writer.
        // Isolated primitive test only: this is NOT a scanner producer fixture.
        let between = Counters::new();
        between.counts[0].store(u64::MAX, Ordering::Relaxed);
        assert_eq!(between.counts[0].fetch_add(1, Ordering::Relaxed), u64::MAX);
        assert_eq!(between.snapshot().counts[0], 0);
        assert!(
            !between.snapshot().overflowed,
            "false does not rule out an already visible concurrent wrap"
        );
        between.overflowed.store(true, Ordering::Relaxed);
        assert!(between.snapshot().overflowed);
    }

    #[test]
    fn fixed_storage_bounds_are_target_layout_checks_not_rss_or_capacity_claims() {
        assert!(std::mem::size_of_val(&TOTALS) <= 120);
        assert!(std::mem::size_of::<Totals>() <= 64);
    }

    #[test]
    fn all_eleven_producers_and_only_original_operational_increments() {
        let source = include_str!("../snapshots.rs");
        let pieces: Vec<_> = source
            .split("disappearance_diagnostics::increment(")
            .skip(1)
            .collect();
        assert_eq!(pieces.len(), 11);
        let expected = [
            (
                "census.disappeared_file_count",
                "PreflightFingerprintChanged",
            ),
            (
                "census.disappeared_file_count",
                "ComparisonTargetRevisionChanged",
            ),
            ("census.disappeared_file_count", "RootResolutionUnresolved"),
            ("census.disappeared_file_count", "RootResolutionUnresolved"),
            ("traversal.counts.disappeared_file_count", "NotFound"),
            ("traversal.counts.disappeared_file_count", "NotFound"),
            ("census.disappeared_file_count", "NotFound"),
            ("census.disappeared_file_count", "NotFound"),
            ("census.disappeared_file_count", "NotFound"),
            ("census.disappeared_file_count", "NotFound"),
            ("census.disappeared_file_count", "NotFound"),
        ];
        for (piece, (counter, cause)) in pieces.into_iter().zip(expected) {
            let call = piece.split(");").next().unwrap();
            assert!(call.contains(counter));
            assert!(call.contains(&format!("Cause::{cause}")));
        }
        assert!(!source.contains("disappeared_file_count += 1;"));
        assert!(source
            .contains("traversal.counts.disappeared_file_count += census.disappeared_file_count;"));
        assert_eq!(
            source
                .matches("resolve_configured_scan_root(source, root, &mut census)")
                .count(),
            1
        );
        assert!(source.contains("disappeared_file_count: census.disappeared_file_count,"));
        assert!(source.contains("disappeared_file_count: counts.disappeared_file_count,"));
        let transition = include_str!("traversal_transition.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert_eq!(
            transition
                .matches("disappearance_diagnostics::snapshot(source)")
                .count(),
            2
        );
        let point = include_str!("../local_resource_diagnostics.rs")
            .split("fn traversal_point(")
            .nth(1)
            .unwrap()
            .split("/// One preparation/page observation")
            .next()
            .unwrap();
        assert!(!point.contains("process_sample("));
        assert_eq!(point.matches("emit(&Record").count(), 1);
        // The status/wire producer has no reason field or diagnostic dependency.
        // No new visibility seam is needed in that private production module.
        let status = include_str!("../snapshot_sync.rs");
        assert!(!status.contains("disappearance_process_totals_v1"));
        assert!(!status.contains("disappearance_diagnostics"));
    }
}
