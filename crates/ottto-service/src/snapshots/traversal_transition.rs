//! Local-only, content-free witnesses of actual traversal decisions.
//! No paths, identities, arbitrary strings, persisted fields or extra scans.
use super::{
    rfc3339_unix_seconds, CensusGates, ScanIndex, ScanTraversalCheckpoint, ScanTraversalCounts,
    SnapshotSource,
};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum StartReason {
    NoRetainedTraversal,
    ContextChanged,
    TerminalUnhealthyRetry,
}

#[derive(Serialize)]
struct Previous {
    window_unix_seconds: Option<u64>,
    pending_directories: usize,
    pending_candidates: usize,
    watcher_overflow: bool,
    retry_attempt: u8,
    retry_not_before_unix_seconds: Option<u64>,
    retryable_problems: bool,
    unsettled_residue: bool,
    // This type contains numeric counters and a fixed cause-counter array only.
    counts: ScanTraversalCounts,
}

#[derive(Serialize)]
pub(super) struct Starting {
    event: &'static str,
    reason: StartReason,
    index_generation: u64,
    window_unix_seconds: Option<u64>,
    context_matches: bool,
    retry_due: Option<bool>,
    prior_unsettled_upload: bool,
    previous: Option<Previous>,
    new_retry_attempt: u8,
    pub(super) stale_pending_families: usize,
    pub(super) rearmed_index_files: usize,
}

impl Starting {
    /// Called only AFTER the existing resume/backoff early return. Thus a
    /// retained matching traversal reached the real terminal-unhealthy retry.
    pub(super) fn capture(index: &ScanIndex, now: &str, matches: bool, attempt: u8) -> Self {
        let previous = index.traversal.as_ref().map(|t| Previous {
            window_unix_seconds: rfc3339_unix_seconds(&t.census_window_end),
            pending_directories: t.pending_directories.len(),
            pending_candidates: t.pending_candidates.len(),
            watcher_overflow: t.watcher_hint_seen,
            retry_attempt: t.unhealthy_retry_attempt,
            retry_not_before_unix_seconds: t.unhealthy_retry_not_before_unix_seconds,
            retryable_problems: t.counts.has_retryable_problems(),
            unsettled_residue: t.counts.has_unsettled_residue(),
            counts: t.counts.clone(),
        });
        Self {
            event: "starting",
            reason: match (previous.is_some(), matches) {
                (false, _) => StartReason::NoRetainedTraversal,
                (true, false) => StartReason::ContextChanged,
                (true, true) => StartReason::TerminalUnhealthyRetry,
            },
            index_generation: index.generation,
            window_unix_seconds: rfc3339_unix_seconds(now),
            context_matches: matches,
            retry_due: matches.then_some(true),
            prior_unsettled_upload: index.bounded_sweep_had_unsettled_upload,
            previous,
            new_retry_attempt: attempt,
            stale_pending_families: 0,
            rearmed_index_files: 0,
        }
    }

    pub(super) fn emit(&self, source: SnapshotSource) {
        crate::local_resource_diagnostics::traversal_transition(source.api_slug(), self);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RetireReason {
    Complete,
    CompleteNeedsCleanFollowup,
    WatcherOverflowRestart,
    ParentResolutionRestart,
}

pub(super) fn retiring(
    source: SnapshotSource,
    index_generation: u64,
    traversal: &ScanTraversalCheckpoint,
    raw_complete: bool,
    gates: CensusGates,
) {
    #[derive(Serialize)]
    struct Retiring<'a> {
        event: &'static str,
        reason: RetireReason,
        index_generation: u64,
        window_unix_seconds: Option<u64>,
        raw_census_complete: bool,
        gates: CensusGates,
        counts: &'a ScanTraversalCounts,
    }
    let reason = if raw_complete {
        if gates.clean_followup {
            RetireReason::CompleteNeedsCleanFollowup
        } else {
            RetireReason::Complete
        }
    } else if !gates.frozen_generation {
        RetireReason::WatcherOverflowRestart
    } else {
        RetireReason::ParentResolutionRestart
    };
    crate::local_resource_diagnostics::traversal_transition(
        source.api_slug(),
        &Retiring {
            event: "retiring",
            reason,
            index_generation,
            window_unix_seconds: rfc3339_unix_seconds(&traversal.census_window_end),
            raw_census_complete: raw_complete,
            gates,
            counts: &traversal.counts,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_resource_diagnostics::capture;
    use crate::snapshots::{ensure_bounded_traversal, scan_source_roots, BACKFILL_WINDOW_DAYS};
    use serde_json::{json, Value};

    const T0: &str = "2026-08-01T00:00:00Z";
    const T1: &str = "2026-08-01T00:01:00Z";

    fn start(index: &mut ScanIndex, now: &str, days: u64) -> Vec<Value> {
        capture(|| ensure_bounded_traversal(SnapshotSource::Pi, &[], index, now, days)).1
    }

    #[test]
    fn traversal_transition_real_start_resume_context_and_retry() {
        let mut index = ScanIndex {
            generation: 37,
            ..ScanIndex::default()
        };
        let first = start(&mut index, T0, BACKFILL_WINDOW_DAYS);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0]["counts"]["reason"], "no_retained_traversal");
        assert_eq!(first[0]["counts"]["index_generation"], 37);
        assert_eq!(
            first[0]["counts"]["window_unix_seconds"],
            rfc3339_unix_seconds(T0).unwrap()
        );
        let before = serde_json::to_value(&index).unwrap();
        assert!(start(&mut index, T1, BACKFILL_WINDOW_DAYS).is_empty());
        assert_eq!(serde_json::to_value(&index).unwrap(), before);

        let changed = start(&mut index, T1, BACKFILL_WINDOW_DAYS + 1);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0]["counts"]["reason"], "context_changed");
        assert_eq!(
            changed[0]["counts"]["previous"]["window_unix_seconds"],
            rfc3339_unix_seconds(T0).unwrap()
        );
        assert!(changed[0]["counts"]["retry_due"].is_null());

        let t = index.traversal.as_mut().unwrap();
        t.counts.malformed_json_line_count = 3;
        t.unhealthy_retry_attempt = 2;
        t.unhealthy_retry_not_before_unix_seconds = rfc3339_unix_seconds("2026-08-01T00:03:00Z");
        let before = serde_json::to_value(&index).unwrap();
        assert!(start(&mut index, "2026-08-01T00:02:00Z", BACKFILL_WINDOW_DAYS + 1).is_empty());
        assert_eq!(serde_json::to_value(&index).unwrap(), before);
        let retried = start(&mut index, "2026-08-01T00:03:00Z", BACKFILL_WINDOW_DAYS + 1);
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0]["counts"]["reason"], "terminal_unhealthy_retry");
        assert_eq!(retried[0]["counts"]["retry_due"], true);
        assert_eq!(
            retried[0]["counts"]["previous"]["counts"]["malformed_json_line_count"],
            3
        );
        assert_eq!(retried[0]["counts"]["previous"]["retryable_problems"], true);
        assert_eq!(retried[0]["counts"]["new_retry_attempt"], 2);
        assert_eq!(
            index
                .traversal
                .as_ref()
                .unwrap()
                .counts
                .malformed_json_line_count,
            0
        );
    }

    #[test]
    fn traversal_transition_actual_stale_rearm_is_counted_without_content() {
        let mut index = ScanIndex::default();
        let key = "/not-logged/private-session.jsonl";
        index.files.insert(
            key.into(),
            serde_json::from_value(json!({
                "size_bytes": 1, "modified_unix_seconds": 0,
                "source_file_fingerprint": "private-body-witness",
                "last_snapshot_fingerprint": null
            }))
            .unwrap(),
        );
        index.claude_usage_family_pending.insert(
            "private-session".into(),
            super::super::ClaudeUsageFamilyPending {
                census_window_end: T0.into(),
                member_request_id_hashes: Default::default(),
                member_occurrences: Default::default(),
                invalid: false,
            },
        );
        index.bounded_sweep_had_unsettled_upload = true;
        let (_, rows) = capture(|| {
            ensure_bounded_traversal(
                SnapshotSource::ClaudeCode,
                &[],
                &mut index,
                T1,
                BACKFILL_WINDOW_DAYS,
            )
        });
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["source"], "claude_code");
        assert_eq!(rows[0]["counts"]["prior_unsettled_upload"], true);
        assert_eq!(rows[0]["counts"]["stale_pending_families"], 1);
        assert_eq!(rows[0]["counts"]["rearmed_index_files"], 1);
        assert!(index.files[key].source_file_fingerprint.is_empty());
        assert!(!index.bounded_sweep_had_unsettled_upload);
        assert!(rows[0]["counts"]["previous"].is_null());
        assert_eq!(rows[0]["stage"], "bounded_traversal_transition");
        let serialized = rows[0].to_string();
        for forbidden in [key, "private-session", "private-body-witness"] {
            assert!(!serialized.contains(forbidden));
        }
        assert!(rows[0]["observation"]["shared_process_cpu_delta_us"].is_null());
        assert!(rows[0]["observation"]["process_lifetime_max_rss_bytes"].is_null());
        assert!(rows[0]["process_id"].is_u64());
    }

    #[test]
    fn traversal_transition_actual_retirement_and_clean_followup() {
        let mut index = ScanIndex::default();
        let (scan, rows) = capture(|| {
            scan_source_roots(
                SnapshotSource::Pi,
                &[],
                &mut index,
                T0,
                BACKFILL_WINDOW_DAYS,
            )
            .unwrap()
        });
        assert!(scan.census_complete);
        assert!(index.traversal.is_none());
        let retired = rows
            .iter()
            .find(|row| row["counts"]["event"] == "retiring")
            .unwrap();
        assert_eq!(retired["counts"]["reason"], "complete");
        assert_eq!(retired["counts"]["gates"]["census_complete"], true);

        start(&mut index, T1, BACKFILL_WINDOW_DAYS);
        index.bounded_sweep_had_unsettled_upload = true;
        let (scan, rows) = capture(|| {
            scan_source_roots(
                SnapshotSource::Pi,
                &[],
                &mut index,
                T1,
                BACKFILL_WINDOW_DAYS,
            )
            .unwrap()
        });
        assert!(!scan.census_complete);
        assert!(index.traversal.is_none());
        let retired = rows
            .iter()
            .find(|row| row["counts"]["event"] == "retiring")
            .unwrap();
        assert_eq!(retired["counts"]["reason"], "complete_needs_clean_followup");
        assert_eq!(retired["counts"]["raw_census_complete"], true);
        assert_eq!(retired["counts"]["gates"]["clean_followup"], true);
        assert_eq!(retired["counts"]["gates"]["census_complete"], false);
    }
}
