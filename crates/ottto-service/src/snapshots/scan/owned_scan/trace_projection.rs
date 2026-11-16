//! Test-only scan projections and clock/budget inputs for the pipeline oracle.
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

impl OwnedSourceScan {
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
            "audit_marker_count": self.index.files.values().filter(|e| e.has_unverified_source()).count(),
            "audit_slots": self.sampling.as_ref().map(|s| s.audit_slots),
            "audits_started": self.sampling.as_ref().map(|s| s.audits_started),
            "audits_completed": self.sampling.as_ref().map(|s| s.audits_completed),
            "audit_cap_delay": self.sampling.as_ref().map(|s| s.audit_cap_delay),
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
        "memo_records": null, "memo_hits": null, "parked_hits": null, "jobs_state_bound": null, "lease_held": false, "full_files": null, "tail_files": null, "unchanged_files": null, "audit_slots": null, "audits_started": null,
        "audits_completed": null, "audit_cap_delay": null, "audit_marker_count": 0,
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
    /// Seed the same held-at-cap state used by quiet-retirement controls.
    /// These are index-only unavailable keys; no file is created or opened.
    pub(crate) fn oracle_hold_at_audit_cap(
        &mut self,
        path: &Path,
        deferred: &BTreeMap<String, u64>,
        due: u64,
    ) {
        let key = local_index_key(path);
        let fingerprint = self.files[&key].source_file_fingerprint.clone();
        assert!(self.record_claude_account_deferred_holds(
            [(key.as_str(), fingerprint.as_str())],
            deferred
        ));
        assert!(self.claude_account_deferred_holds.contains_key(&key));
        for n in 0..crate::transcript_cache::CACHE_ENTRIES {
            let synthetic = format!("/synthetic-held-unavailable/{n}.jsonl");
            let mut entry = self.files[&key].clone();
            entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
            self.files.insert(synthetic.clone(), entry);
            assert!(self.stage_sampled_audit(
                &synthetic,
                &fingerprint,
                crate::transcript_acquisition::AuditDebt {
                    due_unix_seconds: due
                }
            ));
        }
        self.files.get_mut(&key).unwrap().last_snapshot_fingerprint = None;
    }
}
