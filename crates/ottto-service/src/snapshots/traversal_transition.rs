//! Local-only, content-free witnesses of actual traversal decisions.
//! No paths, identities, arbitrary strings, persisted fields or extra scans.
use super::{
    disappearance_diagnostics, rfc3339_unix_seconds, CensusGates, ScanIndex,
    ScanTraversalCheckpoint, ScanTraversalCounts, SnapshotSource,
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
    pub(super) carried_pending_families: usize,
    pub(super) carried_index_files: usize,
    disappearance_process_totals_v1: disappearance_diagnostics::Totals,
}

impl Starting {
    /// Called only AFTER the existing resume/backoff early return. Thus a
    /// retained matching traversal reached the real terminal-unhealthy retry.
    pub(super) fn capture(
        source: SnapshotSource,
        index: &ScanIndex,
        now: &str,
        matches: bool,
        attempt: u8,
    ) -> Self {
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
            disappearance_process_totals_v1: disappearance_diagnostics::snapshot(source),
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
            carried_pending_families: 0,
            carried_index_files: 0,
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
        disappearance_process_totals_v1: disappearance_diagnostics::Totals,
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
            disappearance_process_totals_v1: disappearance_diagnostics::snapshot(source),
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
            first[0]["counts"]["disappearance_process_totals_v1"]["version"],
            1
        );
        assert_eq!(
            first[0]["counts"]["disappearance_process_totals_v1"]["scope"],
            "process_lifetime_not_window"
        );
        assert_eq!(
            first[0]["counts"]["disappearance_process_totals_v1"]["counts"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        let sites = first[0]["counts"]["disappearance_process_totals_v1"]["not_found_sites"]
            .as_array()
            .unwrap();
        assert_eq!(sites.len(), 5);
        assert!(sites
            .iter()
            .all(|site| site.as_array().is_some_and(|slots| slots.len() == 2)));
        assert!(first[0]["counts"]["disappearance_process_totals_v1"]["overflowed"].is_boolean());
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

    #[test]
    fn process_snapshot_is_diagnostic_only_and_restored_counts_have_no_backfill() {
        let mut index = ScanIndex::default();
        start(&mut index, T0, BACKFILL_WINDOW_DAYS);
        index
            .traversal
            .as_mut()
            .unwrap()
            .counts
            .disappeared_file_count = 7;
        let saved = serde_json::to_vec(&index).unwrap();
        let restored: ScanIndex = serde_json::from_slice(&saved).unwrap();
        let manifest_before =
            serde_json::to_vec(&restored.manifest(SnapshotSource::Pi, BACKFILL_WINDOW_DAYS))
                .unwrap();
        let ((starting, rows), events) = disappearance_diagnostics::observe(|| {
            capture(|| {
                let starting = Starting::capture(SnapshotSource::Pi, &restored, T1, true, 1);
                starting.emit(SnapshotSource::Pi);
                starting
            })
        });
        assert_eq!(
            events, [[0; 4]; 3],
            "restoring/copying/emitting is not a producer"
        );
        assert_eq!(serde_json::to_vec(&restored).unwrap(), saved);
        assert_eq!(
            serde_json::to_vec(&restored.manifest(SnapshotSource::Pi, BACKFILL_WINDOW_DAYS))
                .unwrap(),
            manifest_before
        );
        assert_eq!(starting.previous.unwrap().counts.disappeared_file_count, 7);
        assert!(!String::from_utf8(saved)
            .unwrap()
            .contains("disappearance_process_totals_v1"));
        assert!(!String::from_utf8(manifest_before)
            .unwrap()
            .contains("disappearance_process_totals_v1"));
        let mut old_row = rows[0].clone();
        assert!(old_row["counts"]
            .as_object_mut()
            .unwrap()
            .remove("disappearance_process_totals_v1")
            .is_some());
        // Absence is preserved, never deserialized into invented zero reasons.
        let old_row: Value =
            serde_json::from_str(&serde_json::to_string(&old_row).unwrap()).unwrap();
        assert!(old_row["counts"]
            .get("disappearance_process_totals_v1")
            .is_none());
        // Neither a first snapshot nor restored aggregate 7 can establish its
        // historical causes. No global-zero/delta assertion would be valid here.
    }

    fn max_traversal_counts() -> ScanTraversalCounts {
        let mut value = serde_json::to_value(ScanTraversalCounts::default()).unwrap();
        for (name, value) in value.as_object_mut().unwrap() {
            if let Some(object) = value.as_object_mut() {
                for counter in object.get_mut("counts").unwrap().as_array_mut().unwrap() {
                    *counter = json!(u64::MAX);
                }
            } else {
                *value = if name.ends_with("dropped_usage_record_count") {
                    json!(u64::MAX)
                } else {
                    json!(usize::MAX)
                };
            }
        }
        serde_json::from_value(value).unwrap()
    }

    fn assert_complete_max_row(mut row: Value) {
        // Start/retire use the real Rust emitter above. Widen wrapper integers
        // and process totals here without modifying process-global counters.
        row["process_id"] = json!(u32::MAX);
        row["observation"]["observed_unix_ms"] = json!(u64::MAX);
        row["counts"]["window_unix_seconds"] = json!(u64::MAX);
        row["counts"]["disappearance_process_totals_v1"] =
            serde_json::to_value(disappearance_diagnostics::Totals::maximum()).unwrap();
        let totals = &row["counts"]["disappearance_process_totals_v1"];
        assert_eq!(
            totals,
            &json!({"version":1,"scope":"process_lifetime_not_window",
            "counts":[u64::MAX,u64::MAX,u64::MAX,u64::MAX],
            "not_found_sites":([[u64::MAX, u64::MAX]; 5]),"overflowed":true})
        );
        assert_eq!(totals.as_object().unwrap().len(), 5);
        assert_eq!(row["observation"]["wall_elapsed_us"], 0);
        for field in [
            "shared_process_cpu_delta_us",
            "process_lifetime_max_rss_bytes",
            "process_lifetime_max_rss_before_bytes",
        ] {
            assert!(row["observation"][field].is_null());
        }
        // false is one byte longer, even though true is the sticky-wrap case.
        for overflowed in [false, true] {
            row["counts"]["disappearance_process_totals_v1"]["overflowed"] = json!(overflowed);
            let json = serde_json::to_string(&row).unwrap();
            let complete_line = format!("ottto-service: local_resources {json}\n");
            assert!(
                complete_line.len() <= 4096,
                "complete maximum-width row: {} bytes",
                complete_line.len()
            );
            for forbidden in [
                "private-session",
                "private-body-witness",
                "/not-logged/",
                "source_file_fingerprint",
            ] {
                assert!(!complete_line.contains(forbidden));
            }
        }
        // This measures payload, not String additional capacity or allocator peak.
    }

    #[test]
    fn complete_transition_rows_serialize_with_maximum_integers_within_budget() {
        for source in [
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
            SnapshotSource::Pi,
        ] {
            let mut index = ScanIndex::default();
            ensure_bounded_traversal(source, &[], &mut index, T0, BACKFILL_WINDOW_DAYS);
            index.generation = u64::MAX;
            let traversal = index.traversal.as_mut().unwrap();
            traversal.counts = max_traversal_counts();
            let mut starting = Starting::capture(source, &index, T1, true, u8::MAX);
            starting.context_matches = false; // longest boolean spelling
            starting.prior_unsettled_upload = false;
            starting.retry_due = Some(false);
            starting.stale_pending_families = usize::MAX;
            starting.rearmed_index_files = usize::MAX;
            starting.carried_pending_families = usize::MAX;
            starting.carried_index_files = usize::MAX;
            starting.disappearance_process_totals_v1 = disappearance_diagnostics::Totals::maximum();
            let previous = starting.previous.as_mut().unwrap();
            previous.window_unix_seconds = Some(u64::MAX);
            previous.pending_directories = usize::MAX;
            previous.pending_candidates = usize::MAX;
            previous.retry_attempt = u8::MAX;
            previous.retry_not_before_unix_seconds = Some(u64::MAX);
            previous.watcher_overflow = false;
            previous.retryable_problems = false;
            previous.unsettled_residue = false;
            let (_, rows) = capture(|| starting.emit(source));
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["source"], source.api_slug());
            assert_complete_max_row(rows[0].clone());
            let (_, rows) = capture(|| {
                retiring(
                    source,
                    u64::MAX,
                    index.traversal.as_ref().unwrap(),
                    true,
                    CensusGates {
                        clean_followup: true,
                        ..Default::default()
                    },
                )
            });
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["source"], source.api_slug());
            assert_complete_max_row(rows[0].clone());
        }
    }
}
