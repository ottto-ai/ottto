//! Test-only scan projections and fixture inputs for the pipeline oracle.
//! The pipeline installs fixture inputs before stepping; projections only read.
//! Relative keys exclude fixture roots; clocks, tickets and epochs stay private.

use super::*;
use serde_json::{json, Value};

fn relative(key: &str, roots: &[PathBuf]) -> String {
    let path = Path::new(key);
    let (number, suffix) = roots
        .iter()
        .enumerate()
        .filter_map(|(i, root)| path.strip_prefix(root).ok().map(|suffix| (i, suffix)))
        .max_by_key(|(_, suffix)| std::cmp::Reverse(suffix.components().count()))
        .expect("oracle key must belong to a synthetic scan root");
    format!("root-{number}/{}", suffix.to_string_lossy())
}

fn pending(rows: &[PendingIndexFinalization], roots: &[PathBuf]) -> Value {
    json!(rows
        .iter()
        .map(|row| json!({
            "key": relative(&row.index_key, roots),
            "parse_complete": row.parse_complete,
            "parsed_snapshot_count": row.parsed_snapshot_count,
            "previous_snapshot": row.previous_snapshot_fingerprint.is_some(),
            "previous_witness": row.previous_upload_body_witness.is_some(),
        }))
        .collect::<Vec<_>>())
}

thread_local! {
    static SCHEDULE: std::cell::Cell<Option<(usize, bool)>> = const { std::cell::Cell::new(None) };
    static DISCOVERY: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) fn requested_file_limit(default: usize) -> usize {
    SCHEDULE.with(|slot| slot.get().map_or(default, |(limit, _)| limit))
}

pub(super) fn permute_candidates(walk: &mut ScanTraversalCheckpoint) {
    SCHEDULE.with(|slot| {
        if let Some((_, reverse)) = slot.get() {
            let queue = walk.pending_candidates.make_contiguous();
            queue.sort_by(|a, b| a.path.cmp(&b.path));
            if reverse {
                queue.reverse();
            }
            DISCOVERY
                .with(|order| *order.borrow_mut() = queue.iter().map(|p| p.path.clone()).collect());
        }
    });
}

impl OwnedSourceScan {
    /// Count identity/acquisition anchors independently from parser/decoder work.
    /// The archive observer treats any identity sample as wholly unmeasured;
    /// this driver also captures the actual acquisition sample-read seam and
    /// bounded Codex header activity without inventing a header byte receipt.
    pub(crate) fn observe_oracle_io<T>(
        run: impl FnOnce() -> T,
    ) -> (T, sampled_scan::transition_fixture::IoBytes) {
        let identity_before = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
        let activity_before = codex_zst_refusal_tests::activity();
        let headers_before =
            codex_file_join::header_cache_tests::READ_CALLS.with(std::cell::Cell::get);
        let ((result, consumed), anchors) =
            crate::transcript_acquisition::capture_sample_reads(|| {
                sampled_scan::transition_fixture::observe_consumed(run)
            });
        let identity_after = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
        let activity_after = codex_zst_refusal_tests::activity();
        let headers_after =
            codex_file_join::header_cache_tests::READ_CALLS.with(std::cell::Cell::get);
        let measured = (activity_before == activity_after && consumed == 0).then_some(0);
        let anchor_bytes = anchors
            .iter()
            .map(|read| read.result.expect("synthetic anchor read succeeds") as u64)
            .sum::<u64>()
            + identity_after.1
            - identity_before.1;
        (
            result,
            sampled_scan::transition_fixture::IoBytes {
                consumed,
                cheap_checks: measured,
                anchor_reads: Some(anchor_bytes),
                other_reads: measured,
                parse_activity: Some(sampled_scan::transition_fixture::ParseActivity {
                    header_reads: (headers_after - headers_before) as u64,
                    jsonl_parses: (activity_after.1 - activity_before.1) as u64,
                    decoders: (activity_after.0 - activity_before.0) as u64,
                }),
                ..Default::default()
            },
        )
    }

    /// Independent expected window for a settled page: Claude/Pi take one
    /// opened-object head/tail sample per selected file before Skip. Codex
    /// uses its certified physical match without samples. No parser or
    /// acquisition-anchor allowance is granted by this metadata calculation.
    pub(crate) fn oracle_quiet_anchor_window(&self) -> u64 {
        if self.source == SnapshotSource::Codex {
            return 0;
        }
        self.identified_candidates
            .iter()
            .map(|candidate| {
                let size = std::fs::metadata(&candidate.path).unwrap().len();
                let sample = FILE_CONTENT_SAMPLE_BYTES as u64;
                size.min(sample) + if size > sample { sample } else { 0 }
            })
            .sum()
    }

    /// Install fixture scheduling before real prepare performs selection.
    pub(crate) fn with_oracle_schedule<T>(
        schedule: Option<(usize, bool)>,
        run: impl FnOnce() -> T,
    ) -> T {
        struct Restore(Option<(usize, bool)>, Vec<PathBuf>);
        impl Drop for Restore {
            fn drop(&mut self) {
                SCHEDULE.with(|slot| slot.set(self.0));
                DISCOVERY.with(|order| *order.borrow_mut() = std::mem::take(&mut self.1));
            }
        }
        let _restore = Restore(
            SCHEDULE.with(|slot| slot.replace(schedule)),
            DISCOVERY.with(|order| order.take()),
        );
        run()
    }

    pub(crate) fn oracle_schedule_plan(&self) -> Value {
        let selected = self
            .identified_candidates
            .iter()
            .map(|p| relative(&p.path.to_string_lossy(), &self.roots))
            .collect::<Vec<_>>();
        let discovery = DISCOVERY.with(|order| {
            order
                .borrow()
                .iter()
                .map(|p| relative(&p.to_string_lossy(), &self.roots))
                .collect::<Vec<_>>()
        });
        json!({"limit":self.file_limit,"discovery":discovery,"selected":selected})
    }

    pub(crate) fn with_oracle_births<T>(
        births: BTreeMap<String, u64>,
        run: impl FnOnce() -> T,
    ) -> T {
        claude_history_upgrade::with_staged_births_for_test(births, run)
    }

    pub(crate) fn with_oracle_state_budget<T>(bytes: Option<usize>, read: impl FnOnce() -> T) -> T {
        match bytes {
            Some(bytes) => sampled_scan::codex_cursor::with_test_state_budget(bytes, read),
            None => read(),
        }
    }

    /// Fixture input after real prepare: its legacy shell clock is not the
    /// acquisition clock. Keep the page and walk observation horizon equal.
    pub(crate) fn set_oracle_collection_time(&mut self, at: &str) {
        self.collected_at = at.to_owned();
        self.census_window_end = at.to_owned();
        self.census_unix_seconds = rfc3339_unix_seconds(at);
        if let Some(walk) = self.index.traversal.as_mut() {
            walk.census_window_end = at.to_owned();
        }
    }

    pub(crate) fn trace_projection(&self) -> Value {
        json!({
            "active_key": self.active_file.as_ref()
                .map(|active| relative(&active.candidate.path.to_string_lossy(), &self.roots)),
            "join_active": self.codex_join_active.is_some(),
            "candidates": self.identified_candidates.len(),
            "traversal_pending": self.index.traversal.as_ref()
                .map_or(0, |walk| walk.pending_candidates.len()),
            "scanned_file_count": self.scanned_file_count,
            "scanned_session_count": self.scanned_session_count,
            "snapshots": self.snapshots.len(),
            "pending_finalization": pending(&self.pending_finalization, &self.roots),
            "sampled_read_bytes": self.sampling.as_ref().map(|s| (s.native_bytes, s.sample_bytes)),
            "lease_held": self.active_file.holds_lease_for_test(),
            "full_files": self.sampling.as_ref().map(|s| s.full_files),
            "tail_files": self.sampling.as_ref().map(|s| s.tail_files),
            "unchanged_files": self.sampling.as_ref().map(|s| s.unchanged_files),
            "memo_records": self.sampling.as_ref().map(|s| s.cache.counters_for_test().memo_records),
            "memo_hits": self.sampling.as_ref().map(|s| s.cache.counters_for_test().memo_hits),
            "parked_hits": self.sampling.as_ref().map(|s| s.cache.counters_for_test().parked_hits),
            "jobs_state_bound": self.sampling.as_ref().map(|s| s.cache.counters_for_test().jobs_state_bound),
        })
    }
}

impl SourceScanResult {
    pub(crate) fn trace_projection(&self, roots: &[PathBuf]) -> Value {
        json!({
            "snapshots": self.snapshots.len(),
            "pending_finalization": pending(&self.pending_finalization, roots),
            "scanned_file_count": self.scanned_file_count,
            "scanned_session_count": self.scanned_session_count,
            "census_complete": self.census_complete,
            "ownership_incomplete_file_count": self.ownership_incomplete_file_count,
            "residue_count": self.census_residue_index_key_count,
            "continuation_pending": self.continuation_ticket.is_some(),
            "backfill_file_limit": self.backfill_file_limit,
        })
    }
}

#[test]
fn empty_scan_projection_is_read_only() {
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Pi,
        &[],
        ScanIndex::default(),
        "2026-11-01T10:00:00Z",
        183,
        100,
        None,
        &[],
        false,
    );
    let expected = json!({
        "active_key": null, "join_active": false, "candidates": 0,
        "traversal_pending": 0, "scanned_file_count": 0, "scanned_session_count": 0,
        "snapshots": 0, "pending_finalization": [], "sampled_read_bytes": null,
        "memo_records": null, "memo_hits": null, "parked_hits": null, "jobs_state_bound": null, "lease_held": false, "full_files": null, "tail_files": null, "unchanged_files": null,
    });
    assert_eq!(scan.trace_projection(), expected);
    assert_eq!(scan.trace_projection(), expected);
    for _ in 0..1024 {
        match scan.step_fallible(None).expect("empty synthetic scan") {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { scan, .. } => {
                assert_eq!(
                    scan.trace_projection(&[])["pending_finalization"],
                    json!([])
                );
                return;
            }
        }
    }
    panic!("empty scan exceeded step limit");
}

#[test]
fn trace_keys_choose_the_most_specific_root() {
    let roots = [
        PathBuf::from("/fixture"),
        PathBuf::from("/fixture/sessions"),
    ];
    assert_eq!(
        relative("/fixture/sessions/session.jsonl", &roots),
        "root-1/session.jsonl"
    );
}

impl ScanIndex {
    pub(crate) fn oracle_schedule_debt(&self, roots: &[PathBuf]) -> Value {
        let mut holds = BTreeMap::<String, Vec<&str>>::new();
        for root in self.claude_usage_authority_quarantine.keys() {
            holds
                .entry(root.clone())
                .or_default()
                .push("usage_authority");
        }
        for key in self.claude_account_deferred_holds.keys() {
            let (root, _) = claude_index_path_family_member(Path::new(key)).expect("Claude hold");
            holds.entry(root).or_default().push("account_ownership");
        }
        if !self.decode_holds.is_empty() {
            holds.insert("unknown_entity".into(), vec!["decode"]);
        }
        let owed = self
            .files
            .keys()
            .filter(|key| self.file_upload_context_requires_adoption(key))
            .map(|key| relative(key, roots))
            .collect::<Vec<_>>();
        let copy_wait = self
            .claude_request_census
            .records()
            .filter(|(key, _)| {
                self.claude_copy_removals
                    .pending(claude_money_birth_store::location_key(key))
            })
            .map(|(key, _)| relative(key, roots))
            .collect::<Vec<_>>();
        let pending = self.traversal.as_ref().map_or(0, |walk| {
            walk.pending_directories.len() + walk.pending_candidates.len()
        });
        let debt = json!({
            "quarantine":self.quarantined_snapshot_fingerprints.len(),
            "withheld":self.withheld_memo.held_gauge(),
            "native_recovery":self.files.values().filter(|e| e.codex_recovery_is_pending()).count(),
            "terminal_retry":self.terminal_contract_retries.len(),
            "incidence_census":self.accepted_incidence_pending_census,
            "accepted_rebuild":self.accepted_rebuild_pending_since_unix_seconds.is_some(),
            "unsettled":self.bounded_sweep_had_unsettled_upload,
            "residue":self.scan_residue_witness.as_ref().map_or(0, |r| r.index_keys.len()),
            "sidecar_retry":self.claude_desktop_store_retry_not_before_unix_seconds.is_some(),
            "deleted_unaccepted":self.tail_discovery.deleted_unaccepted_files,
        });
        json!({"holds":holds,"owed":owed,"pending":pending,"debt":debt,
            "copy_wait":copy_wait,
            "content_twins":self.claude_request_census.records().filter(|(_, r)| r.is_twin()).count()})
    }
}
