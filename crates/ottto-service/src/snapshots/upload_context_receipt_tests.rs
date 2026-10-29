//! Synthetic production-scanner and exact entity-ACK fixtures. No live inputs.
use super::*;
use upload_context_receipt::{Candidate, RearmCounts};
#[path = "upload_context_released_entry_fixture.rs"]
mod released;

const SESSION: &str = "019fa111-2222-7333-8444-555555555555";
struct Fixture {
    _scratch: crate::test_scratch::ScratchDir,
    root: PathBuf,
    path: PathBuf,
    source: SnapshotSource,
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
}
impl Fixture {
    fn new(source: SnapshotSource) -> Self {
        let scratch = crate::test_scratch::ScratchDir::new("upload-context-receipt");
        let root = scratch.join(match source {
            SnapshotSource::Codex => "home/.codex/sessions",
            _ => "home/.claude/projects/synthetic-project",
        });
        fs::create_dir_all(&root).unwrap();
        let path = root.join(match source {
            SnapshotSource::Codex => format!("rollout-2026-10-29T10-00-00-{SESSION}.jsonl"),
            _ => format!("{SESSION}.jsonl"),
        });
        let lines = match source {
            SnapshotSource::Codex => vec![
                json!({"type":"session_meta","payload":{"id":SESSION}}),
                json!({"timestamp":"2026-10-29T10:00:01Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-5.5","total_token_usage":{"input_tokens":12,"output_tokens":4}}}}),
            ],
            _ => vec![
                json!({"type":"assistant","sessionId":SESSION,"timestamp":"2026-10-29T10:00:01Z","requestId":"synthetic-request","message":{"id":"synthetic-message","model":"claude-sonnet-4-6","usage":{"input_tokens":12,"output_tokens":4}}}),
            ],
        };
        fs::write(
            &path,
            lines
                .iter()
                .map(|line| format!("{line}\n"))
                .collect::<String>(),
        )
        .unwrap();
        let mut index = ScanIndex {
            upload_context_fingerprint: Some("c".repeat(64)),
            ..ScanIndex::default()
        };
        index.activate_file_upload_context(source, "d".repeat(64));
        Self {
            _scratch: scratch,
            root,
            path,
            source,
            index,
            cache: Arc::default(),
        }
    }
    fn key(&self) -> String {
        local_index_key(&self.path)
    }
    fn entry(&self) -> &ScanIndexEntry {
        &self.index.files[&self.key()]
    }
    fn walk(&mut self, finalize: bool) -> (SourceScanResult, u64) {
        let mut scan = OwnedSourceScan::new(
            self.source,
            std::slice::from_ref(&self.root),
            std::mem::take(&mut self.index),
            "2026-10-29T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(
            self.cache.clone(),
            crate::transcript_acquisition::Scope("upload-context-fixture".into()),
        );
        let mut bytes = 0;
        loop {
            if let Some(sampling) = scan.sampling.as_ref() {
                bytes = sampling.native_bytes;
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete {
                    index, mut scan, ..
                } => {
                    self.index = index;
                    // Model a source whose census cannot complete; no page can
                    // advance source-wide context even when its file settles.
                    scan.census_complete = false;
                    apply_upload_policy(
                        self.source,
                        &mut scan.snapshots,
                        SnapshotUploadPolicy::default(),
                    );
                    if finalize {
                        finalize_scan_after_policy(self.source, &mut scan, &mut self.index);
                    }
                    return (scan, bytes);
                }
            }
        }
    }
    fn pending(&mut self) -> (Vec<Candidate>, Vec<SnapshotItem>) {
        let (scan, _) = self.walk(true);
        assert_eq!(scan.scanned_file_count, 1);
        assert!(
            !scan.snapshots.is_empty(),
            "a byte-identical old body must still reach the uploader"
        );
        let candidates = self
            .index
            .file_upload_context_ack_candidates(&scan.snapshots);
        assert_eq!(candidates.len(), 1);
        (candidates, scan.snapshots)
    }
    fn adopt(&mut self) -> RearmCounts {
        let committed = self.index.clone();
        let (candidates, items) = self.pending();
        let exact =
            crate::snapshot_sync::upload_context_receipt_tests::exact_acks(self.source, &items);
        let accepted = exact.keys().cloned().collect();
        self.index
            .reconcile_codex_recovery_settlement(&committed, &accepted);
        self.index.record_accepted_snapshot_fingerprints(&accepted);
        self.index
            .accept_file_upload_context_acks(&candidates, &exact)
    }

    fn assert_quiet(&mut self) {
        for _ in 0..3 {
            let (scan, bytes) = self.walk(true);
            assert_eq!((scan.scanned_file_count, bytes), (0, 0));
            assert!(!scan.census_complete);
            assert_eq!(
                self.index.upload_context_fingerprint.as_deref(),
                Some("c".repeat(64).as_str())
            );
        }
    }
}

#[test]
fn codex_incomplete_census_exact_ack_stops_upload_context_for_three_passes() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    assert_eq!(f.adopt().files, 1);
    f.assert_quiet();
}
#[test]
fn claude_fresh_index_and_context_change_are_quiet_after_adoption() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    assert_eq!(f.adopt().files, 1);
    f.assert_quiet();
    let old = f.entry().upload_context_receipt.clone();
    f.index
        .activate_file_upload_context(f.source, "e".repeat(64));
    assert_eq!(
        f.entry().upload_context_receipt,
        old,
        "activation does not rewrite receipts"
    );
    assert_eq!(f.adopt().files, 1);
    f.assert_quiet();
}
#[test]
fn claude_source_context_matched_without_receipts_is_quiet_for_three_relists() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let (_, items) = f.pending();
    f.index.record_accepted_snapshot_fingerprints(
        &items
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect(),
    );
    f.index.upload_context_fingerprint = f.index.active_upload_context_fingerprint.clone();
    assert!(f.entry().upload_context_receipt.is_none());
    assert!(!f.index.file_upload_context_requires_adoption(&f.key()));
    for _ in 0..3 {
        let (scan, bytes) = f.walk(true);
        assert_eq!(
            (scan.scanned_file_count, bytes, scan.snapshots.len()),
            (0, 0, 0)
        );
        assert!(f.entry().upload_context_receipt.is_none());
    }
}
#[test]
fn claude_source_context_matched_mixed_file_is_quiet_for_three_relists() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let (mut scan, _) = f.walk(false);
    // Model a post-policy file group with two distinct entities, through the
    // real finalizer, before settling only one of its entities.
    assert_eq!(scan.snapshots.len(), 1);
    let mut sibling = scan.snapshots[0].clone();
    sibling.source_session_id = "019fa111-2222-7333-8444-666666666666".into();
    scan.snapshots.push(sibling);
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    assert_eq!(f.index.file_snapshot_fingerprints[&f.key()].len(), 2);
    let accepted = scan.snapshots[0].snapshot_fingerprint.clone();
    let refused = scan.snapshots[1].snapshot_fingerprint.clone();
    assert_ne!(accepted, refused);
    f.index
        .record_accepted_snapshot_fingerprints(&BTreeSet::from([accepted.clone()]));
    let mut quarantine = snapshot_quarantine_record(f.source);
    quarantine.witness = f.index.active_quarantine_witness.clone().unwrap();
    quarantine.upload_body_witness = Some(snapshot_upload_body_witness(&scan.snapshots[1]));
    f.index
        .quarantined_snapshot_fingerprints
        .insert(refused.clone(), quarantine);
    f.index.upload_context_fingerprint = f.index.active_upload_context_fingerprint.clone();
    assert!(f.entry().upload_context_receipt.is_none());
    assert!(!f.index.file_upload_context_requires_adoption(&f.key()));
    for _ in 0..3 {
        let (scan, bytes) = f.walk(true);
        assert_eq!(
            (scan.scanned_file_count, bytes, scan.snapshots.len()),
            (0, 0, 0)
        );
        assert_eq!(f.index.file_snapshot_fingerprints[&f.key()].len(), 2);
        assert!(f
            .index
            .quarantined_snapshot_fingerprints
            .contains_key(&refused));
        assert!(f.entry().upload_context_receipt.is_none());
    }
}
#[test]
fn upload_context_receipt_parse_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    f.walk(false);
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn upload_context_receipt_finalize_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    f.walk(true);
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn upload_context_receipt_quarantine_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let (candidates, items) = f.pending();
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(f.source, &items);
    f.index.quarantined_snapshot_fingerprints.insert(
        items[0].snapshot_fingerprint.clone(),
        snapshot_quarantine_record(f.source),
    );
    assert_eq!(
        f.index
            .accept_file_upload_context_acks(&candidates, &exact)
            .files,
        0
    );
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn upload_context_receipt_c_ack_after_switch_to_d_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    f.index
        .activate_file_upload_context(f.source, "c".repeat(64));
    let (candidates, items) = f.pending();
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(f.source, &items);
    f.index
        .activate_file_upload_context(f.source, "d".repeat(64));
    assert_eq!(
        f.index
            .accept_file_upload_context_acks(&candidates, &exact)
            .files,
        0
    );
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn upload_context_receipt_stale_source_witness_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let (candidates, items) = f.pending();
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(f.source, &items);
    let key = f.key();
    f.index.files.get_mut(&key).unwrap().source_file_fingerprint = "e".repeat(64);
    assert_eq!(
        f.index
            .accept_file_upload_context_acks(&candidates, &exact)
            .files,
        0
    );
}
#[test]
fn upload_context_receipt_stale_body_witness_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let (candidates, items) = f.pending();
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(f.source, &items);
    let key = f.key();
    f.index
        .files
        .get_mut(&key)
        .unwrap()
        .last_upload_body_witness = Some("e".repeat(64));
    assert_eq!(
        f.index
            .accept_file_upload_context_acks(&candidates, &exact)
            .files,
        0
    );
}
#[test]
fn upload_context_receipt_stale_generation_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let (candidates, items) = f.pending();
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(f.source, &items);
    f.index.context_curve_replay_epoch += 1;
    assert_eq!(
        f.index
            .accept_file_upload_context_acks(&candidates, &exact)
            .files,
        0
    );
}
#[test]
fn upload_context_receipt_partial_entity_ack_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let (candidates, _) = f.pending();
    assert_eq!(
        f.index
            .accept_file_upload_context_acks(&candidates, &BTreeMap::new())
            .files,
        0
    );
}
#[test]
fn codex_refused_body_backoff_reads_zero_bytes_over_three_relists() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let (_, items) = f.pending();
    let mut refusal = snapshot_quarantine_record(f.source);
    refusal.witness = f.index.active_quarantine_witness.clone().unwrap();
    refusal.upload_body_witness = Some(snapshot_upload_body_witness(&items[0]));
    f.index
        .quarantined_snapshot_fingerprints
        .insert(items[0].snapshot_fingerprint.clone(), refusal);
    f.assert_quiet();
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn claude_held_family_backoff_reads_zero_bytes_over_three_relists() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.pending();
    let revision = f.entry().source_file_fingerprint.clone();
    f.index
        .insert_retry_pending_claude_authority_at_revision_for_test(SESSION, &revision);
    f.assert_quiet();
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn upload_context_receipt_restart_and_generation_rearm_once() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let size = fs::metadata(&f.path).unwrap().len();
    assert_eq!(
        f.adopt(),
        RearmCounts {
            files: 1,
            bytes: size
        }
    );
    let saved_path = f._scratch.join("restart-index.json");
    f.index.save(&saved_path).unwrap();
    f.index = ScanIndex::load(&saved_path).unwrap();
    f.index
        .activate_file_upload_context(f.source, "d".repeat(64));
    f.assert_quiet();
    f.index.context_curve_replay_epoch += 1;
    assert_eq!(
        f.adopt(),
        RearmCounts {
            files: 1,
            bytes: size
        }
    );
    f.assert_quiet();
}
#[test]
fn upload_context_receipt_historical_replay_rearms_retained_entry() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    f.adopt();
    let key = f.key();
    f.index.files.get_mut(&key).unwrap().codex_protected_owner = Some("f".repeat(64));
    assert!(f.index.prepare_historical_replay("synthetic-replay".into()));
    assert!(f.index.files[&key].upload_context_receipt.is_none());
    assert_eq!(f.adopt().files, 1);
    assert!(!f.index.prepare_historical_replay("synthetic-replay".into()));
    // Replay semantics still own the global witness (None after rearm).
    assert!(f.index.upload_context_fingerprint.is_none());
    for _ in 0..3 {
        assert_eq!(f.walk(true).0.scanned_file_count, 0);
    }
}

fn legacy_round_trip(version: &str) {
    let mut f = Fixture::new(SnapshotSource::Codex);
    f.adopt();
    let saved_path = f._scratch.join("downgrade-index.json");
    f.index.save(&saved_path).unwrap();
    let encoded: Value = serde_json::from_slice(&fs::read(&saved_path).unwrap()).unwrap();
    // The complete released per-entry codecs are byte-identical at the two
    // pinned versions. Exercise their actual serde path on every files slot.
    let mut old = encoded.clone();
    for value in old["files"].as_object_mut().unwrap().values_mut() {
        let decoded: released::ScanIndexEntry = serde_json::from_value(value.clone()).unwrap();
        *value = serde_json::to_value(decoded).unwrap();
        assert!(value.get("upload_context_receipt").is_none(), "{version}");
    }
    fs::write(&saved_path, serde_json::to_vec(&old).unwrap()).unwrap();
    f.index = ScanIndex::load(&saved_path).unwrap();
    f.index
        .activate_file_upload_context(f.source, "d".repeat(64));
    assert!(f.entry().upload_context_receipt.is_none());
    assert_eq!(f.adopt().files, 1, "{version} downgrade costs one pass");
    f.assert_quiet();
}
#[test]
fn upload_context_receipt_decoder_0_1_201_ignores_field() {
    legacy_round_trip("0.1.201");
}
#[test]
fn upload_context_receipt_decoder_0_1_202_round_trip_rearms_once() {
    legacy_round_trip("0.1.202");
}
#[test]
fn upload_context_receipt_current_round_trip_and_size() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    f.adopt();
    let entry = f.entry();
    let mut bare = entry.clone();
    bare.upload_context_receipt = None;
    let encoded = serde_json::to_vec(entry).unwrap();
    assert_eq!(
        encoded.len() - serde_json::to_vec(&bare).unwrap().len(),
        304
    );
    let decoded: ScanIndexEntry = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded.upload_context_receipt, entry.upload_context_receipt);
    assert_eq!(std::mem::size_of::<upload_context_receipt::Receipt>(), 80);
    assert_eq!(std::mem::size_of::<ScanIndexEntry>(), 560);
}

#[test]
fn upload_context_receipt_wrong_ack_body_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let (candidates, items) = f.pending();
    let mut exact =
        crate::snapshot_sync::upload_context_receipt_tests::exact_acks(f.source, &items);
    exact.insert(items[0].snapshot_fingerprint.clone(), "e".repeat(64));
    assert_eq!(
        f.index
            .accept_file_upload_context_acks(&candidates, &exact)
            .files,
        0
    );
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn upload_context_receipt_withheld_after_capture_refused() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let (candidates, items) = f.pending();
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(f.source, &items);
    f.index
        .exclude_effective_upload_body_witness_revision_for_source_files(&BTreeSet::from([f
            .entry()
            .source_file_fingerprint
            .clone()]));
    assert_eq!(
        f.index
            .accept_file_upload_context_acks(&candidates, &exact)
            .files,
        0
    );
}
#[test]
fn upload_context_receipt_destination_policy_precedes_admission() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let (mut scan, _) = f.walk(false);
    scan.snapshots[0].session_display_name = Some("Synthetic private title".into());
    scan.snapshots[0].session_display_name_source = Some("synthetic".into());
    apply_upload_policy(
        f.source,
        &mut scan.snapshots,
        SnapshotUploadPolicy {
            session_titles_enabled: false,
            ..SnapshotUploadPolicy::default()
        },
    );
    assert!(scan.snapshots[0].session_display_name.is_none());
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    let candidates = f.index.file_upload_context_ack_candidates(&scan.snapshots);
    let exact =
        crate::snapshot_sync::upload_context_receipt_tests::exact_acks(f.source, &scan.snapshots);
    assert_eq!(
        f.index
            .accept_file_upload_context_acks(&candidates, &exact)
            .files,
        1
    );
}

#[test]
fn upload_context_receipt_partial_checkpoint_accepts_runtime_fields_and_persists_receipt() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let previous = f.index.clone();
    let (_, items) = f.pending();
    f.index = crate::snapshot_sync::upload_context_receipt_tests::partial_context_checkpoint(
        f.source, &f.index, &previous, &items, true,
    );
    assert!(f.entry().upload_context_receipt.is_some());
    f.assert_quiet();
}
#[test]
fn upload_context_receipt_partial_checkpoint_old_ack_refused() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    let previous = f.index.clone();
    let (_, items) = f.pending();
    f.index = crate::snapshot_sync::upload_context_receipt_tests::partial_context_checkpoint(
        f.source, &f.index, &previous, &items, false,
    );
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn upload_context_legacy_activation_preserves_identical_body_noop() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    f.adopt();
    // The legacy/Pi activation path does not enable file receipts.
    f.index.file_upload_context_enabled = false;
    f.index.activate_upload_context("e".repeat(64));
    let (scan, _) = f.walk(true);
    assert_eq!(scan.scanned_file_count, 1);
    assert!(scan.snapshots.is_empty());
    assert!(scan.semantic_noop_count > 0);
}
#[test]
fn upload_context_policy_change_reprojects_old_refusal_then_keeps_backoff() {
    let mut f = Fixture::new(SnapshotSource::Codex);
    f.index
        .activate_file_upload_context(f.source, "c".repeat(64));
    let (_, items) = f.pending();
    let mut refusal = snapshot_quarantine_record(f.source);
    refusal.witness = f.index.active_quarantine_witness.clone().unwrap();
    refusal.upload_body_witness = Some(snapshot_upload_body_witness(&items[0]));
    refusal.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
    refusal.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
    refusal.retry_after_unix_seconds = 0;
    f.index
        .quarantined_snapshot_fingerprints
        .insert(items[0].snapshot_fingerprint.clone(), refusal);
    let original = f.index.quarantined_snapshot_fingerprints.clone();
    f.index
        .activate_file_upload_context(f.source, "d".repeat(64));
    let (scan, _) = f.walk(true);
    assert_eq!(
        scan.scanned_file_count, 1,
        "changed policy can repair a refusal"
    );
    assert!(!scan.snapshots.is_empty());
    let rebound = crate::snapshot_sync::upload_context_receipt_tests::reproject_context_refusal(
        f.source,
        &"d".repeat(64),
        original.clone(),
        &scan.snapshots,
    );
    for (entity, record) in &rebound {
        assert_eq!(record.disposition, original[entity].disposition);
        assert_eq!(
            record.failed_reconstruction_count,
            original[entity].failed_reconstruction_count
        );
        assert_eq!(
            record.retry_after_unix_seconds,
            original[entity].retry_after_unix_seconds
        );
    }
    f.index.quarantined_snapshot_fingerprints = rebound;
    f.assert_quiet();
    assert!(f.entry().upload_context_receipt.is_none());
}

#[test]
fn upload_context_policy_suppressed_file_rearms_on_context_change() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.index
        .activate_file_upload_context(f.source, "c".repeat(64));
    f.pending();
    let key = f.key();
    f.index.confirmed_empty_files.insert(key.clone());
    f.index.file_snapshot_fingerprints.remove(&key);
    let entry = f.index.files.get_mut(&key).unwrap();
    entry.last_snapshot_fingerprint = None;
    entry.last_upload_body_witness = None;
    assert!(!f.index.file_upload_context_requires_adoption(&key));
    f.index
        .activate_file_upload_context(f.source, "d".repeat(64));
    assert!(f.index.file_upload_context_requires_adoption(&key));
    assert_eq!(f.walk(true).0.scanned_file_count, 1);
}
