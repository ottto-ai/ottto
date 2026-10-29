//! Local-only, content-free witnesses of actual traversal decisions.
//! No paths, identities, arbitrary strings, persisted fields or extra scans.
use super::{
    disappearance_diagnostics, rfc3339_unix_seconds, CensusGates, ClaudeAbsenceCounters, ScanIndex,
    ScanTraversalCheckpoint, ScanTraversalCounts, SnapshotSource, UnsettledUploadCause,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

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

fn is_zero(value: &usize) -> bool {
    *value == 0
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
    prior_held_family_roots: usize,
    prior_held_family_set_digest: Option<String>,
    /// Fixed names of the paths that set `prior_unsettled_upload`. Empty
    /// exactly when it is false.
    prior_unsettled_causes: Vec<&'static str>,
    previous: Option<Previous>,
    new_retry_attempt: u8,
    pub(super) stale_pending_families: usize,
    pub(super) rearmed_index_files: usize,
    pub(super) carried_pending_families: usize,
    pub(super) carried_index_files: usize,
    /// Fix 2: stale families whose pending came from a full-rearm window,
    /// how many of them were carried, the files of the rest re-read whole,
    /// and the families and files the per-deadline cap kept without reparse.
    /// Omitted while zero, so every other start row keeps its bytes.
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) rearm_window_families: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) rearm_window_carried_families: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) rearm_window_rearmed_files: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) rearm_window_rearmed_families: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) stale_rearm_capped_families: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) stale_rearm_capped_files: usize,
    disappearance_process_totals_v1: disappearance_diagnostics::Totals,
}

impl Starting {
    pub(super) fn rearm_cause(&self) -> crate::local_resource_diagnostics::rearm_cause::Cause {
        use crate::local_resource_diagnostics::rearm_cause::Cause;
        match self.reason {
            StartReason::NoRetainedTraversal => Cause::NoRetainedTraversal,
            StartReason::ContextChanged => Cause::ContextChanged,
            StartReason::TerminalUnhealthyRetry => Cause::TerminalUnhealthyRetry,
        }
    }
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
        let (prior_held_family_roots, prior_held_family_set_digest) = prior_held_family_observation(
            (source == SnapshotSource::ClaudeCode)
                .then_some(index.claude_full_rearm_progress.held_family_roots.as_ref())
                .flatten(),
        );
        Self {
            prior_held_family_roots,
            prior_held_family_set_digest,
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
            prior_unsettled_causes: UnsettledUploadCause::names(index.unsettled_cause_bits()),
            previous,
            new_retry_attempt: attempt,
            stale_pending_families: 0,
            rearmed_index_files: 0,
            carried_pending_families: 0,
            carried_index_files: 0,
            rearm_window_families: 0,
            rearm_window_carried_families: 0,
            rearm_window_rearmed_files: 0,
            rearm_window_rearmed_families: 0,
            stale_rearm_capped_families: 0,
            stale_rearm_capped_files: 0,
        }
    }

    pub(super) fn emit(&self, source: SnapshotSource) {
        crate::local_resource_diagnostics::traversal_transition(source.api_slug(), self);
    }
}

/// Hash only the persisted canonical digest set, never raw roots. BTreeSet
/// supplies sorted order; fixed-width entries need no separator. Invalid or
/// unknown scope has no digest, matching the existing scope reader's trust.
fn prior_held_family_observation(roots: Option<&BTreeSet<String>>) -> (usize, Option<String>) {
    let Some(roots) = roots.filter(|roots| super::held_family_scope_has_writer_shape(roots)) else {
        return (0, None);
    };
    let mut digest = Sha256::new();
    for root in roots {
        digest.update(root.as_bytes());
    }
    let mut hex = format!("{:x}", digest.finalize());
    hex.truncate(16);
    (roots.len(), Some(hex))
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
    unsettled_causes: u16,
    absence: Option<(ClaudeAbsenceCounters, bool)>,
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
        /// Fixed names of the paths that set the clean follow-up's flag.
        unsettled_causes: Vec<&'static str>,
        counts: &'a ScanTraversalCounts,
        disappearance_process_totals_v1: disappearance_diagnostics::Totals,
        /// Claude only: path-(a) absence retirement process totals (SOURCE
        /// Rounds 11-13, COST names), and the index's tombstone uncertainty
        /// fence.
        #[serde(skip_serializing_if = "Option::is_none")]
        absent_retry_pending_retired: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        absent_family_tombstone_hits: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        retirements_refused: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tombstone_decode_drops: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        absent_family_tombstones_cleared: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        absent_family_tombstone_capacity_refusals: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        absent_family_tombstone_uncertain: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tombstone_fence_raised_on_upgrade: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        absent_family_tombstone_aged_out: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fence_lowering_skipped_scratch_fallback: Option<u64>,
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
            unsettled_causes: UnsettledUploadCause::names(unsettled_causes),
            counts: &traversal.counts,
            disappearance_process_totals_v1: disappearance_diagnostics::snapshot(source),
            absent_retry_pending_retired: absence.map(|(counts, _)| counts.absent_families_retired),
            absent_family_tombstone_hits: absence.map(|(counts, _)| counts.tombstone_hits),
            retirements_refused: absence.map(|(counts, _)| counts.retirements_refused),
            tombstone_decode_drops: absence.map(|(counts, _)| counts.tombstone_decode_drops),
            absent_family_tombstones_cleared: absence.map(|(counts, _)| counts.tombstones_cleared),
            absent_family_tombstone_capacity_refusals: absence
                .map(|(counts, _)| counts.tombstone_capacity_refusals),
            absent_family_tombstone_uncertain: absence.map(|(_, uncertain)| uncertain),
            tombstone_fence_raised_on_upgrade: absence
                .map(|(counts, _)| counts.tombstone_fence_raised_on_upgrade),
            absent_family_tombstone_aged_out: absence
                .map(|(counts, _)| counts.absent_family_tombstone_aged_out),
            fence_lowering_skipped_scratch_fallback: absence
                .map(|(counts, _)| counts.fence_lowering_skipped_scratch_fallback),
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
    const T2: &str = "2026-08-01T00:02:00Z";
    const T3: &str = "2026-08-01T00:03:00Z";

    fn start(index: &mut ScanIndex, now: &str, days: u64) -> Vec<Value> {
        capture(|| ensure_bounded_traversal(SnapshotSource::Pi, &[], index, now, days)).1
    }

    #[test]
    fn prior_held_family_digest_tracks_only_the_canonical_set() {
        let a = "a".repeat(32);
        let b = "b".repeat(32);
        let first = BTreeSet::from([a.clone(), b.clone()]);
        let reversed = BTreeSet::from([b, a.clone()]);
        let observed = prior_held_family_observation(Some(&first));
        assert_eq!(observed.0, 2);
        assert_eq!(observed.1.as_ref().unwrap().len(), 16);
        assert_eq!(observed, prior_held_family_observation(Some(&reversed)));
        assert_ne!(
            observed.1,
            prior_held_family_observation(Some(&BTreeSet::from([a]))).1
        );
        assert_eq!(prior_held_family_observation(None), (0, None));
        assert_eq!(
            prior_held_family_observation(Some(&BTreeSet::new())),
            (0, None)
        );
        assert_eq!(
            prior_held_family_observation(Some(&BTreeSet::from(["not canonical".into()]))),
            (0, None)
        );
        let mut index = ScanIndex::default();
        index.claude_full_rearm_progress.held_family_roots = Some(first);
        let row = serde_json::to_value(Starting::capture(
            SnapshotSource::ClaudeCode,
            &index,
            T1,
            true,
            1,
        ))
        .unwrap();
        assert_eq!(row["prior_held_family_roots"], 2);
        assert_eq!(row["prior_held_family_set_digest"], observed.1.unwrap());
        let other = Starting::capture(SnapshotSource::Pi, &index, T1, true, 1);
        assert_eq!(other.prior_held_family_roots, 0);
        assert!(other.prior_held_family_set_digest.is_none());
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
        for vanished in [
            "vanished_audit_debt_dropped",
            "vanished_request_census_removed",
        ] {
            assert!(first[0]["counts"]["disappearance_process_totals_v1"][vanished].is_u64());
        }
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
                idless_revision: None,
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
        assert_eq!(retired["counts"]["unsettled_causes"], json!([]));

        start(&mut index, T1, BACKFILL_WINDOW_DAYS);
        index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::Shed);
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
        assert_eq!(retired["counts"]["unsettled_causes"], json!(["shed"]));

        // The clean follow-up's start names the prior causes, then clears
        // them with the flag.
        let started = start(&mut index, T2, BACKFILL_WINDOW_DAYS);
        assert_eq!(started.len(), 1);
        assert_eq!(started[0]["counts"]["prior_unsettled_upload"], true);
        assert_eq!(
            started[0]["counts"]["prior_unsettled_causes"],
            json!(["shed"])
        );
        assert!(!index.bounded_sweep_had_unsettled_upload);
        assert!(index.bounded_sweep_unsettled_cause_names().is_empty());
        let started = start(&mut index, T3, BACKFILL_WINDOW_DAYS + 1);
        assert_eq!(started[0]["counts"]["prior_unsettled_upload"], false);
        assert_eq!(started[0]["counts"]["prior_unsettled_causes"], json!([]));
    }

    fn with_unsettled_causes(index: &ScanIndex, causes: u16) -> ScanIndex {
        let mut value = serde_json::to_value(index).unwrap();
        value["bounded_sweep_unsettled_causes"] = json!(causes);
        serde_json::from_value(value).unwrap()
    }

    fn without_unsettled_causes(index: &ScanIndex) -> Value {
        let mut value = serde_json::to_value(index).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("bounded_sweep_unsettled_causes");
        value
    }

    #[test]
    fn unsettled_causes_persist_only_when_set_and_reset_with_the_flag() {
        // Absent when empty: the persisted index is byte-identical to before.
        let empty = ScanIndex::default();
        let saved = serde_json::to_value(&empty).unwrap();
        assert!(saved.get("bounded_sweep_unsettled_causes").is_none());
        // An index saved before the causes existed loads unattributed.
        let mut legacy = saved.clone();
        legacy["bounded_sweep_had_unsettled_upload"] = json!(true);
        let mut legacy: ScanIndex = serde_json::from_value(legacy).unwrap();
        assert!(legacy.bounded_sweep_had_unsettled_upload);
        assert_eq!(
            legacy.bounded_sweep_unsettled_cause_names(),
            ["unattributed"]
        );
        let started = start(&mut legacy, T0, BACKFILL_WINDOW_DAYS);
        assert_eq!(started[0]["counts"]["prior_unsettled_upload"], true);
        assert_eq!(
            started[0]["counts"]["prior_unsettled_causes"],
            json!(["unattributed"])
        );

        // Every cause round-trips, in declaration order.
        let mut marked = ScanIndex::default();
        for cause in [
            UnsettledUploadCause::AdmissionReoffer,
            UnsettledUploadCause::Shed,
            UnsettledUploadCause::LegacyReconcile,
            UnsettledUploadCause::UploadError,
            UnsettledUploadCause::AuthorityCensusWithheld,
            UnsettledUploadCause::DeferredConflict,
            UnsettledUploadCause::CompletedBlockingHolds,
            UnsettledUploadCause::RejectedWithHolds,
            UnsettledUploadCause::Shed,
        ] {
            marked.mark_bounded_sweep_unsettled_by(cause);
        }
        marked.mark_bounded_sweep_unsettled();
        let all = [
            "shed",
            "upload_error",
            "deferred_conflict",
            "rejected_with_holds",
            "completed_blocking_holds",
            "authority_census_withheld",
            "legacy_reconcile",
            "admission_reoffer",
            "unattributed",
        ];
        assert_eq!(marked.bounded_sweep_unsettled_cause_names(), all);
        let restored: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&marked).unwrap()).unwrap();
        assert_eq!(restored.bounded_sweep_unsettled_cause_names(), all);

        // A census-complete finalize clears them with the flag.
        let mut index = ScanIndex::default();
        let mut scan = scan_source_roots(
            SnapshotSource::Pi,
            &[],
            &mut index,
            T0,
            BACKFILL_WINDOW_DAYS,
        )
        .unwrap();
        assert!(scan.census_complete);
        index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::Shed);
        crate::snapshots::finalize_scan_after_policy_with_body_witness(
            SnapshotSource::Pi,
            &mut scan,
            &mut index,
            |_| String::new(),
        );
        assert!(!index.bounded_sweep_had_unsettled_upload);
        assert!(index.bounded_sweep_unsettled_cause_names().is_empty());

        // So does a historical replay reset.
        index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::UploadError);
        index.prepare_historical_replay("unsettled-cause-replay".into());
        assert!(!index.bounded_sweep_had_unsettled_upload);
        assert!(index.bounded_sweep_unsettled_cause_names().is_empty());
    }

    /// A path that marks without naming itself is still named, as
    /// `unattributed`, beside any named path in the same sweep. A flag with no
    /// attribution (an older daemon) is unattributed too, so a later named
    /// mark cannot conceal it. Bits a newer daemon set stay unknown.
    #[test]
    fn plain_and_missing_attribution_are_named_unattributed() {
        let mut plain = ScanIndex::default();
        plain.mark_bounded_sweep_unsettled();
        assert!(plain.bounded_sweep_had_unsettled_upload);
        assert_eq!(
            plain.bounded_sweep_unsettled_cause_names(),
            ["unattributed"]
        );

        let mut named = ScanIndex::default();
        named.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::DeferredConflict);
        assert!(named.bounded_sweep_had_unsettled_upload);
        assert_eq!(
            named.bounded_sweep_unsettled_cause_names(),
            ["deferred_conflict"]
        );

        let mut plain_first = ScanIndex::default();
        plain_first.mark_bounded_sweep_unsettled();
        plain_first.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::Shed);
        let mut named_first = ScanIndex::default();
        named_first.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::Shed);
        named_first.mark_bounded_sweep_unsettled();
        for index in [&plain_first, &named_first] {
            assert!(index.bounded_sweep_had_unsettled_upload);
            assert_eq!(
                index.bounded_sweep_unsettled_cause_names(),
                ["shed", "unattributed"]
            );
        }

        // An older daemon's flag, then a named mark on this daemon.
        let mut legacy = serde_json::to_value(ScanIndex::default()).unwrap();
        legacy["bounded_sweep_had_unsettled_upload"] = json!(true);
        let mut legacy: ScanIndex = serde_json::from_value(legacy).unwrap();
        legacy.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::DeferredConflict);
        assert_eq!(
            legacy.bounded_sweep_unsettled_cause_names(),
            ["deferred_conflict", "unattributed"]
        );
        let mut restored: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        let started = start(&mut restored, T0, BACKFILL_WINDOW_DAYS);
        assert_eq!(
            started[0]["counts"]["prior_unsettled_causes"],
            json!(["deferred_conflict", "unattributed"])
        );

        // A newer daemon's unknown bit stays beside later marks and a reload.
        let flagged = ScanIndex {
            bounded_sweep_had_unsettled_upload: true,
            ..ScanIndex::default()
        };
        let mut newer = with_unsettled_causes(&flagged, 1 << 15);
        assert_eq!(newer.bounded_sweep_unsettled_cause_names(), ["unknown"]);
        newer.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::Shed);
        let newer: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&newer).unwrap()).unwrap();
        assert_eq!(
            newer.bounded_sweep_unsettled_cause_names(),
            ["shed", "unknown"]
        );

        // The flag is authoritative: stored bits without it name nothing.
        let mut stray = with_unsettled_causes(&ScanIndex::default(), u16::MAX);
        assert!(stray.bounded_sweep_unsettled_cause_names().is_empty());
        stray.mark_bounded_sweep_unsettled();
        assert_eq!(
            stray.bounded_sweep_unsettled_cause_names(),
            ["unattributed"]
        );

        // The retiring line names a plain mark too.
        let mut index = ScanIndex::default();
        start(&mut index, T1, BACKFILL_WINDOW_DAYS);
        index.mark_bounded_sweep_unsettled();
        let (_, rows) = capture(|| {
            scan_source_roots(
                SnapshotSource::Pi,
                &[],
                &mut index,
                T1,
                BACKFILL_WINDOW_DAYS,
            )
            .unwrap()
        });
        let retired = rows
            .iter()
            .find(|row| row["counts"]["event"] == "retiring")
            .unwrap();
        assert_eq!(retired["counts"]["reason"], "complete_needs_clean_followup");
        assert_eq!(
            retired["counts"]["unsettled_causes"],
            json!(["unattributed"])
        );
    }

    /// The causes are diagnostics only. An index that differs only in them
    /// takes the same census, start, carry and epoch decisions.
    #[test]
    fn unsettled_causes_alone_change_no_gate() {
        // Terminal: no clean follow-up is owed for causes without the flag.
        for (flag, reason) in [(false, "complete"), (true, "complete_needs_clean_followup")] {
            let mut plain = ScanIndex::default();
            start(&mut plain, T0, BACKFILL_WINDOW_DAYS);
            plain.bounded_sweep_had_unsettled_upload = flag;
            let mut tagged = with_unsettled_causes(&plain, u16::MAX);
            let mut outcomes = Vec::new();
            for index in [&mut plain, &mut tagged] {
                let (scan, rows) = capture(|| {
                    scan_source_roots(SnapshotSource::Pi, &[], index, T0, BACKFILL_WINDOW_DAYS)
                        .unwrap()
                });
                let retired = rows
                    .iter()
                    .find(|row| row["counts"]["event"] == "retiring")
                    .unwrap();
                assert_eq!(retired["counts"]["reason"], reason);
                outcomes.push((
                    scan.census_complete,
                    retired["counts"]["gates"].clone(),
                    without_unsettled_causes(index),
                ));
            }
            assert_eq!(outcomes[0], outcomes[1], "flag={flag}");
        }

        // Finalize: the upload-context epoch advances exactly as without them.
        for flag in [false, true] {
            let mut plain = ScanIndex::default();
            let mut scan = scan_source_roots(
                SnapshotSource::Pi,
                &[],
                &mut plain,
                T0,
                BACKFILL_WINDOW_DAYS,
            )
            .unwrap();
            plain.bounded_sweep_had_unsettled_upload = flag;
            let mut tagged = with_unsettled_causes(&plain, u16::MAX);
            for index in [&mut plain, &mut tagged] {
                index.activate_upload_context("unsettled-cause-context".into());
                crate::snapshots::finalize_scan_after_policy_with_body_witness(
                    SnapshotSource::Pi,
                    &mut scan,
                    index,
                    |_| String::new(),
                );
            }
            assert_eq!(
                plain.upload_context_fingerprint.as_deref(),
                (!flag).then_some("unsettled-cause-context")
            );
            assert_eq!(
                without_unsettled_causes(&plain),
                without_unsettled_causes(&tagged),
                "flag={flag}"
            );
        }

        // Claude start: the stale-family re-arm and carry read the flag only.
        for flag in [false, true] {
            let mut plain = ScanIndex::default();
            plain.files.insert(
                "/not-logged/private-session.jsonl".into(),
                serde_json::from_value(json!({
                    "size_bytes": 1, "modified_unix_seconds": 0,
                    "source_file_fingerprint": "private-body-witness",
                    "last_snapshot_fingerprint": null
                }))
                .unwrap(),
            );
            plain.claude_usage_family_pending.insert(
                "private-session".into(),
                super::super::ClaudeUsageFamilyPending {
                    census_window_end: T0.into(),
                    member_request_id_hashes: Default::default(),
                    member_occurrences: Default::default(),
                    invalid: false,
                    idless_revision: None,
                },
            );
            plain.bounded_sweep_had_unsettled_upload = flag;
            let mut tagged = with_unsettled_causes(&plain, u16::MAX);
            let mut outcomes = Vec::new();
            for index in [&mut plain, &mut tagged] {
                let (_, rows) = capture(|| {
                    ensure_bounded_traversal(
                        SnapshotSource::ClaudeCode,
                        &[],
                        index,
                        T1,
                        BACKFILL_WINDOW_DAYS,
                    )
                });
                let counts = &rows[0]["counts"];
                outcomes.push((
                    [
                        "prior_unsettled_upload",
                        "stale_pending_families",
                        "rearmed_index_files",
                        "carried_pending_families",
                        "carried_index_files",
                    ]
                    .map(|field| counts[field].clone()),
                    without_unsettled_causes(index),
                ));
            }
            assert_eq!(outcomes[0], outcomes[1], "flag={flag}");
        }
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
        value["causes"] = json!({"contributions": vec![u64::MAX; 8]});
        for (name, value) in value.as_object_mut().unwrap() {
            if let Some(object) = value.as_object_mut() {
                let field = if name == "causes" {
                    "contributions"
                } else {
                    "counts"
                };
                for counter in object.get_mut(field).unwrap().as_array_mut().unwrap() {
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
            "not_found_sites":([[u64::MAX, u64::MAX]; 5]),
            "vanished_audit_debt_dropped":u64::MAX,
            "vanished_request_census_removed":u64::MAX,"overflowed":true})
        );
        assert_eq!(totals.as_object().unwrap().len(), 7);
        assert_eq!(row["observation"]["wall_elapsed_us"], 0);
        for field in [
            "shared_process_cpu_delta_us",
            "process_lifetime_max_rss_bytes",
            "process_lifetime_max_rss_before_bytes",
            "stage_peak_footprint_bytes",
            "stage_start_footprint_bytes",
            "stage_end_footprint_bytes",
            "footprint_samples",
            "footprint_sample_failures",
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
            starting.prior_unsettled_causes = UnsettledUploadCause::names(u16::MAX);
            assert_eq!(starting.prior_unsettled_causes.len(), 10);
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
                    u16::MAX,
                    // `false` is the longer spelling of the fence state.
                    (source == SnapshotSource::ClaudeCode).then_some((
                        ClaudeAbsenceCounters {
                            absent_families_retired: u64::MAX,
                            tombstone_hits: u64::MAX,
                            retirements_refused: u64::MAX,
                            tombstone_decode_drops: u64::MAX,
                            tombstones_cleared: u64::MAX,
                            tombstone_capacity_refusals: u64::MAX,
                            tombstone_fence_raised_on_upgrade: u64::MAX,
                            absent_family_tombstone_aged_out: u64::MAX,
                            fence_lowering_skipped_scratch_fallback: u64::MAX,
                        },
                        false,
                    )),
                    CensusGates {
                        clean_followup: true,
                        ..Default::default()
                    },
                )
            });
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["source"], source.api_slug());
            assert_eq!(
                rows[0]["counts"]["unsettled_causes"]
                    .as_array()
                    .unwrap()
                    .len(),
                10
            );
            assert_complete_max_row(rows[0].clone());
        }
    }
    // SOURCE Round 13 F3: the Claude retiring row names every absence total
    // and the fence state with their values (Round 15: and the upgrade fence
    // count; Round 16, SOURCE h733: the aged-out tombstone and refused-drain
    // counts); other sources omit them all.
    #[test]
    fn claude_retiring_rows_publish_the_absence_totals_and_fence_state() {
        const NAMES: [&str; 10] = [
            "absent_retry_pending_retired",
            "absent_family_tombstone_hits",
            "retirements_refused",
            "tombstone_decode_drops",
            "absent_family_tombstones_cleared",
            "absent_family_tombstone_capacity_refusals",
            "absent_family_tombstone_uncertain",
            "tombstone_fence_raised_on_upgrade",
            "absent_family_tombstone_aged_out",
            "fence_lowering_skipped_scratch_fallback",
        ];
        for source in [
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
            SnapshotSource::Pi,
        ] {
            for uncertain in [false, true] {
                let mut index = ScanIndex::default();
                ensure_bounded_traversal(source, &[], &mut index, T0, BACKFILL_WINDOW_DAYS);
                let (_, rows) = capture(|| {
                    retiring(
                        source,
                        7,
                        index.traversal.as_ref().unwrap(),
                        true,
                        0,
                        (source == SnapshotSource::ClaudeCode).then_some((
                            ClaudeAbsenceCounters {
                                absent_families_retired: 1,
                                tombstone_hits: 2,
                                retirements_refused: 3,
                                tombstone_decode_drops: 4,
                                tombstones_cleared: 5,
                                tombstone_capacity_refusals: 6,
                                tombstone_fence_raised_on_upgrade: 8,
                                absent_family_tombstone_aged_out: 9,
                                fence_lowering_skipped_scratch_fallback: 10,
                            },
                            uncertain,
                        )),
                        CensusGates::default(),
                    )
                });
                assert_eq!(rows.len(), 1);
                let counts = &rows[0]["counts"];
                if source == SnapshotSource::ClaudeCode {
                    for (name, value) in NAMES.iter().zip(1..) {
                        if *name == "absent_family_tombstone_uncertain" {
                            assert_eq!(counts[*name], json!(uncertain), "{name}");
                        } else {
                            assert_eq!(counts[*name], json!(value), "{name}");
                        }
                    }
                } else {
                    for name in NAMES {
                        assert!(counts.get(name).is_none(), "{source:?}: {name}");
                    }
                }
            }
        }
    }

    /// Fix 2's start counts are omitted while zero, so every other start row
    /// keeps its bytes, and at maximum width the row stays within budget.
    #[test]
    fn full_rearm_window_start_counts_are_omitted_at_zero_and_bounded() {
        const FIELDS: [&str; 6] = [
            "rearm_window_families",
            "rearm_window_carried_families",
            "rearm_window_rearmed_files",
            "rearm_window_rearmed_families",
            "stale_rearm_capped_families",
            "stale_rearm_capped_files",
        ];
        let source = SnapshotSource::ClaudeCode;
        let mut index = ScanIndex::default();
        ensure_bounded_traversal(source, &[], &mut index, T0, BACKFILL_WINDOW_DAYS);
        let (_, rows) = capture(|| Starting::capture(source, &index, T1, true, 1).emit(source));
        for field in FIELDS {
            assert!(rows[0]["counts"].get(field).is_none(), "{field}");
        }

        index.generation = u64::MAX;
        index.traversal.as_mut().unwrap().counts = max_traversal_counts();
        let mut starting = Starting::capture(source, &index, T1, true, u8::MAX);
        starting.context_matches = false;
        starting.prior_unsettled_upload = false;
        starting.prior_unsettled_causes = UnsettledUploadCause::names(u16::MAX);
        starting.retry_due = Some(false);
        starting.stale_pending_families = usize::MAX;
        starting.rearmed_index_files = usize::MAX;
        starting.carried_pending_families = usize::MAX;
        starting.carried_index_files = usize::MAX;
        starting.rearm_window_families = usize::MAX;
        starting.rearm_window_carried_families = usize::MAX;
        starting.rearm_window_rearmed_files = usize::MAX;
        starting.rearm_window_rearmed_families = usize::MAX;
        starting.stale_rearm_capped_families = usize::MAX;
        starting.stale_rearm_capped_files = usize::MAX;
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
        for field in FIELDS {
            assert_eq!(rows[0]["counts"][field], json!(usize::MAX), "{field}");
        }
        assert_complete_max_row(rows[0].clone());
    }
}
