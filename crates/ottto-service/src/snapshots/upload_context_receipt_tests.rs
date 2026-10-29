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
        let (candidates, items) = self.pending();
        let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(&items);
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
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(&items);
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
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(&items);
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
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(&items);
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
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(&items);
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
    let exact = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(&items);
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
    f.index.active_quarantine_witness = Some(snapshot_quarantine_witness(f.source));
    let mut refusal = snapshot_quarantine_record(f.source);
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
    f.index = serde_json::from_slice(&serde_json::to_vec(&f.index).unwrap()).unwrap();
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
    let encoded = serde_json::to_value(&f.index).unwrap();
    // The complete released per-entry codecs are byte-identical at the two
    // pinned versions. Exercise their actual serde path on every files slot.
    let mut old = encoded.clone();
    for value in old["files"].as_object_mut().unwrap().values_mut() {
        let decoded: released::ScanIndexEntry = serde_json::from_value(value.clone()).unwrap();
        *value = serde_json::to_value(decoded).unwrap();
        assert!(value.get("upload_context_receipt").is_none(), "{version}");
    }
    f.index = serde_json::from_value(old).unwrap();
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
