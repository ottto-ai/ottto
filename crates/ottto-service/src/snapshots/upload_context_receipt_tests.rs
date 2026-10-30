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
    uploader: crate::snapshot_sync::upload_context_receipt_tests::Uploader,
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
            uploader: crate::snapshot_sync::upload_context_receipt_tests::Uploader::new(source),
        }
    }
    fn key(&self) -> String {
        local_index_key(&self.path)
    }
    fn entry(&self) -> &ScanIndexEntry {
        &self.index.files[&self.key()]
    }
    fn walk(&mut self, finalize: bool) -> (SourceScanResult, u64) {
        self.walk_with_file_limit(finalize, 10)
    }
    fn walk_with_file_limit(
        &mut self,
        finalize: bool,
        file_limit: usize,
    ) -> (SourceScanResult, u64) {
        let mut scan = OwnedSourceScan::new(
            self.source,
            std::slice::from_ref(&self.root),
            std::mem::take(&mut self.index),
            "2026-10-29T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
            file_limit,
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
        let (_, items) = self.pending();
        self.uploader.activate(
            self.source,
            self.index
                .active_upload_context_fingerprint
                .clone()
                .unwrap(),
            &mut self.index,
        );
        let (files, bytes) = self
            .uploader
            .send(self.source, &mut self.index, &committed, &items)
            .unwrap();
        RearmCounts {
            files,
            bytes,
            local_bytes: self.index.context_read_counts.local_bytes,
        }
    }

    fn send_ordering_page(&mut self, previous: &ScanIndex, scan: &SourceScanResult) -> (u64, u64) {
        self.uploader.activate(
            self.source,
            self.index
                .active_upload_context_fingerprint
                .clone()
                .unwrap(),
            &mut self.index,
        );
        let before = (
            self.uploader.received_item_bytes,
            self.uploader.received_catchup_bytes,
            self.uploader.received_resend_bytes,
        );
        let counts = self
            .uploader
            .send(self.source, &mut self.index, previous, &scan.snapshots)
            .unwrap();
        let catchup = self.uploader.received_catchup_bytes - before.1;
        let ordinary = self.uploader.received_item_bytes - before.0 - catchup;
        // These small ordering fixtures need no oversized wire/native exception.
        assert!(
            catchup
                <= (crate::snapshot_sync::SNAPSHOT_BATCH_MAX_BYTES as u64).saturating_sub(ordinary)
        );
        assert_eq!(
            self.uploader.counts().1,
            self.uploader.received_resend_bytes - before.2,
            "resend counter equals actual received item bytes, including changed revisions"
        );
        counts
    }

    fn assert_quiet(&mut self) {
        // Freeze the ceiling before any quiet walk can enlarge the index.
        let settled_group_members = self
            .index
            .files
            .values()
            .filter(|entry| {
                entry.codex_joined_member_set.is_some()
                    && entry
                        .upload_context_receipt
                        .as_ref()
                        .is_some_and(|receipt| {
                            self.index.active_upload_context_fingerprint.as_ref()
                                == Some(&receipt.context_fingerprint)
                                && receipt.replay_generation
                                    == self.index.context_curve_replay_epoch
                                && receipt.source_witness == entry.source_file_fingerprint
                                && entry.last_upload_body_witness.as_ref()
                                    == Some(&receipt.body_witness)
                        })
            })
            .count();
        let held_quarantine = !self.index.quarantined_snapshot_fingerprints.is_empty();
        for quiet_call in 0..3 {
            if held_quarantine && quiet_call > 0 {
                assert!(
                    !self.index.quarantined_snapshot_fingerprints.is_empty(),
                    "refusal quarantine survives settlement before quiet call {}",
                    quiet_call + 1
                );
            }
            self.uploader.prepare_for_scan(
                self.source,
                self.index
                    .active_upload_context_fingerprint
                    .clone()
                    .unwrap(),
                &mut self.index,
            );
            let previous = self.index.clone();
            let (((scan, bytes), parses), group_bytes) =
                terminal_contract_retry::group_body_bytes(|| {
                    terminal_contract_retry::source_acquisitions(|| self.walk(true))
                });
            // Per-census unchanged-group identity walks pre-exist on main; no body read.
            assert!(
                parses.is_empty(),
                "no body parser is stepped on a quiet or held page; quiet_call={} parses={parses:?} sampled_bytes={bytes} group_body_bytes={group_bytes}",
                quiet_call + 1
            );
            assert_eq!(bytes, 0);
            assert_eq!(
                group_bytes, 0,
                "no physical group body bytes after adoption"
            );
            assert!(
                scan.scanned_file_count <= settled_group_members,
                "quiet metadata work cannot exceed the settled alias population"
            );
            let before = self.uploader.posts.len();
            self.uploader
                .send(self.source, &mut self.index, &previous, &scan.snapshots)
                .unwrap();
            assert_eq!(self.uploader.posts.len(), before, "no POST after adoption");
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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::Codex);
    assert_eq!(f.adopt().files, 1);
    f.assert_quiet();
}
#[test]
fn claude_fresh_index_and_context_change_are_quiet_after_adoption() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::Codex);
    f.walk(false);
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn upload_context_receipt_finalize_refused() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::Codex);
    f.walk(true);
    assert!(f.entry().upload_context_receipt.is_none());
}
#[test]
fn upload_context_receipt_quarantine_refused() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::Codex);
    let size = fs::metadata(&f.path).unwrap().len();
    let counts = f.adopt();
    assert_eq!(counts.files, 1);
    assert_eq!(
        counts.bytes,
        f.uploader
            .posts
            .last()
            .unwrap()
            .iter()
            .map(|item| serde_json::to_vec(item).unwrap().len() as u64)
            .sum::<u64>(),
        "wire item bytes, not native file length"
    );
    assert!(counts.local_bytes <= size);
    let saved_path = f._scratch.join("restart-index.json");
    f.index.save(&saved_path).unwrap();
    f.index = ScanIndex::load(&saved_path).unwrap();
    f.index
        .activate_file_upload_context(f.source, "d".repeat(64));
    f.assert_quiet();
    f.index.context_curve_replay_epoch += 1;
    // The real prepare resets both index and upload progress for a new replay.
    f.uploader.replay("synthetic-curve-epoch-1");
    let counts = f.adopt();
    assert_eq!(counts.files, 1);
    assert_eq!(
        counts.bytes,
        f.uploader
            .posts
            .last()
            .unwrap()
            .iter()
            .map(|item| serde_json::to_vec(item).unwrap().len() as u64)
            .sum::<u64>(),
        "wire item bytes, not native file length"
    );
    assert!(counts.local_bytes <= size);
    f.assert_quiet();
}
#[test]
fn upload_context_receipt_historical_replay_rearms_retained_entry() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::Codex);
    f.adopt();
    let key = f.key();
    f.index.files.get_mut(&key).unwrap().codex_protected_owner = Some("f".repeat(64));
    assert!(f.index.prepare_historical_replay("synthetic-replay".into()));
    f.uploader.replay("synthetic-replay");
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
    // Downgrade saves also pass progress through the old unknown-field codec.
    f.uploader.forget_stamps();
    f.index
        .activate_file_upload_context(f.source, "d".repeat(64));
    assert!(f.entry().upload_context_receipt.is_none());
    assert_eq!(f.adopt().files, 1, "{version} downgrade costs one pass");
    f.assert_quiet();
}
#[test]
fn upload_context_receipt_decoder_0_1_201_ignores_field() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    legacy_round_trip("0.1.201");
}
#[test]
fn upload_context_receipt_decoder_0_1_202_round_trip_rearms_once() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    legacy_round_trip("0.1.202");
}
#[test]
fn upload_context_receipt_current_round_trip_and_size() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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

#[test]
fn real_uploader_identical_context_change_resends_once_then_three_quiet_relists() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut f = Fixture::new(source);
        f.adopt();
        let accepted = f.uploader.posts.last().unwrap().clone();
        f.index.activate_file_upload_context(source, "e".repeat(64));
        assert_eq!(f.adopt().files, 1);
        assert_eq!(f.uploader.posts.len(), 2);
        assert_eq!(
            *f.uploader.posts.last().unwrap(),
            accepted,
            "all sent bytes, tokens, cost and request fields unchanged"
        );
        let counts = f.uploader.counts();
        assert_eq!((counts.0, counts.2, counts.3), (1, 1, 0));
        assert!(counts.1 > 0);
        for _ in 0..3 {
            let previous = f.index.clone();
            let (scan, bytes) = f.walk(true);
            assert_eq!((scan.scanned_file_count, bytes), (0, 0));
            f.uploader.activate(source, "e".repeat(64), &mut f.index);
            f.uploader
                .send(source, &mut f.index, &previous, &scan.snapshots)
                .unwrap();
            assert_eq!(f.uploader.posts.len(), 2);
            assert_eq!(f.uploader.counts(), (0, 0, 0, 0));
        }
    }
}

fn uploader_group(f: &mut Fixture, count: usize) -> Vec<SnapshotItem> {
    let (mut scan, _) = f.walk(false);
    let template = scan.snapshots[0].clone();
    scan.snapshots = (0..count)
        .map(|n| {
            let mut item = template.clone();
            item.source_session_id = format!("context-group-{n:04}");
            item
        })
        .collect();
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    scan.snapshots
}
#[test]
fn real_uploader_restart_mid_context_catchup_never_resends_reacked_entities() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let empty = f.index.clone();
    let items = uploader_group(&mut f, 51);
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &empty, &items)
            .unwrap()
            .0,
        1
    );
    let committed = f.index.clone();
    f.uploader.activate(f.source, "e".repeat(64), &mut f.index);
    f.uploader.fail_after = Some(f.uploader.posts.len() + 1);
    assert!(f
        .uploader
        .send(f.source, &mut f.index, &committed, &items)
        .is_err());
    let reacked = f
        .uploader
        .posts
        .last()
        .unwrap()
        .iter()
        .map(|v| v["snapshot_fingerprint"].clone())
        .collect::<Vec<_>>();
    assert!(!reacked.is_empty() && reacked.len() < items.len());
    f.uploader.restart(f.source, &"e".repeat(64));
    f.uploader.fail_after = None;
    f.uploader.activate(f.source, "e".repeat(64), &mut f.index);
    let before = f.uploader.posts.len();
    f.uploader
        .send(f.source, &mut f.index, &committed, &items)
        .unwrap();
    let resumed = f.uploader.posts[before..]
        .iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(resumed.len(), items.len() - reacked.len());
    assert!(resumed
        .iter()
        .all(|v| !reacked.contains(&v["snapshot_fingerprint"])));
    assert_eq!(f.uploader.counts().0 as usize, resumed.len());
    f.uploader.activate(f.source, "e".repeat(64), &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &committed, &items)
        .unwrap();
    assert_eq!(f.uploader.posts.len(), before + 1);
    assert_eq!(f.uploader.counts(), (0, 0, 0, 0));
}
#[test]
fn real_uploader_same_context_transport_retry_has_zero_context_resends() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let previous = f.index.clone();
    let items = uploader_group(&mut f, 51);
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    f.uploader.fail_after = Some(1);
    assert!(f
        .uploader
        .send(f.source, &mut f.index, &previous, &items)
        .is_err());
    let first = f.uploader.posts[0].len();
    f.uploader.restart(f.source, &"d".repeat(64));
    f.uploader.fail_after = None;
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &previous, &items)
        .unwrap();
    assert_eq!(f.uploader.posts[1].len(), items.len() - first);
    assert_eq!(f.uploader.counts(), (0, 0, 0, 0));
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &previous, &items)
        .unwrap();
    assert_eq!(f.uploader.posts.len(), 2);
    assert_eq!(f.uploader.counts(), (0, 0, 0, 0));
}
#[test]
fn real_uploader_old_unstamped_progress_with_equal_source_context_resends_nothing() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let previous = f.index.clone();
    let (_, items) = f.pending();
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &previous, &items)
        .unwrap();
    f.uploader.forget_stamps();
    let key = f.key();
    f.index.files.get_mut(&key).unwrap().upload_context_receipt = None;
    f.index.upload_context_fingerprint = Some("d".repeat(64));
    let previous = f.index.clone();
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &previous, &items)
            .unwrap()
            .0,
        0
    );
    assert_eq!(f.uploader.posts.len(), 1);
    assert_eq!(f.uploader.counts(), (0, 0, 0, 0));
    for _ in 0..3 {
        let (scan, bytes) = f.walk(true);
        assert_eq!((scan.scanned_file_count, bytes), (0, 0));
    }
}
#[test]
fn real_uploader_new_usage_precedes_pending_context_catchup() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.adopt();
    let previous = f.index.clone();
    f.index
        .activate_file_upload_context(f.source, "e".repeat(64));
    let (mut scan, _) = f.walk(false);
    let mut new_usage = scan.snapshots[0].clone();
    new_usage.source_session_id = "zz-new-usage".into();
    scan.snapshots.push(new_usage);
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    f.uploader.activate(f.source, "e".repeat(64), &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &previous, &scan.snapshots)
        .unwrap();
    let posts = &f.uploader.posts[1..];
    assert_eq!(posts[0][0]["source_session_id"], "zz-new-usage");
    assert_eq!(posts[0].len(), 1, "ordinary usage has its own first POST");
    assert_eq!(posts.iter().map(Vec::len).sum::<usize>(), 2);
    assert!(posts
        .iter()
        .all(|post| serde_json::to_vec(post).unwrap().len() <= 2 * 1024 * 1024));
}
#[test]
fn real_uploader_not_stored_backs_off_but_growth_earns_receipt() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.adopt();
    f.index
        .activate_file_upload_context(f.source, "e".repeat(64));
    let previous = f.index.clone();
    let (_, items) = f.pending();
    f.uploader.activate(f.source, "e".repeat(64), &mut f.index);
    f.uploader.not_stored = true;
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &previous, &items)
            .unwrap()
            .0,
        0
    );
    assert_eq!(f.uploader.fresh_count(), 0);
    assert_eq!(f.uploader.not_stored_files(), 1);
    assert_ne!(
        f.entry()
            .upload_context_receipt
            .as_ref()
            .unwrap()
            .context_fingerprint,
        "e".repeat(64)
    );
    let posts = f.uploader.posts.len();
    for _ in 0..3 {
        f.uploader
            .prepare_for_scan(f.source, "e".repeat(64), &mut f.index);
        let (scan, bytes) = f.walk(true);
        assert_eq!((scan.scanned_file_count, bytes), (0, 0));
        assert_eq!(f.uploader.posts.len(), posts);
    }
    let mut body = fs::read_to_string(&f.path).unwrap();
    body.push_str(&format!("{}\n",json!({"type":"assistant","sessionId":SESSION,"timestamp":"2026-10-29T10:02:01Z","requestId":"grown-request","message":{"id":"grown-message","model":"claude-sonnet-4-6","usage":{"input_tokens":30,"output_tokens":10}}})));
    fs::write(&f.path, body).unwrap();
    f.uploader.not_stored = false;
    assert_eq!(f.adopt().files, 1);
    assert_eq!(f.uploader.posts.len(), posts + 1);
    assert_eq!(
        f.entry()
            .upload_context_receipt
            .as_ref()
            .unwrap()
            .context_fingerprint,
        "e".repeat(64)
    );
}
#[test]
fn real_uploader_duplicate_refusal_mints_nothing_and_does_not_loop() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.adopt();
    f.index
        .activate_file_upload_context(f.source, "e".repeat(64));
    let previous = f.index.clone();
    let (_, items) = f.pending();
    f.uploader.activate(f.source, "e".repeat(64), &mut f.index);
    f.uploader.refuse = true;
    f.uploader
        .send(f.source, &mut f.index, &previous, &items)
        .unwrap();
    assert_eq!(f.uploader.fresh_count(), 0);
    assert_ne!(
        f.entry()
            .upload_context_receipt
            .as_ref()
            .unwrap()
            .context_fingerprint,
        "e".repeat(64)
    );
    let posts = f.uploader.posts.len();
    for _ in 0..3 {
        f.uploader
            .prepare_for_scan(f.source, "e".repeat(64), &mut f.index);
        let (scan, bytes) = f.walk(true);
        assert_eq!((scan.scanned_file_count, bytes), (0, 0));
        assert_eq!(f.uploader.posts.len(), posts);
    }
}
#[test]
fn real_uploader_privacy_reducing_context_uses_destination_policy() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let previous = f.index.clone();
    let (mut scan, _) = f.walk(false);
    scan.snapshots[0].session_display_name = Some("synthetic title".into());
    scan.snapshots[0].session_display_name_source = Some("synthetic".into());
    let on = SnapshotUploadPolicy {
        session_titles_enabled: true,
        ..SnapshotUploadPolicy::default()
    };
    apply_upload_policy(f.source, &mut scan.snapshots, on);
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &previous, &scan.snapshots)
        .unwrap();
    assert_eq!(
        f.uploader.posts.last().unwrap()[0]["session_display_name"],
        "synthetic title"
    );
    let previous = f.index.clone();
    f.index
        .activate_file_upload_context(f.source, "e".repeat(64));
    let off = SnapshotUploadPolicy {
        session_titles_enabled: false,
        ..SnapshotUploadPolicy::default()
    };
    apply_upload_policy(f.source, &mut scan.snapshots, off);
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    f.uploader.activate(f.source, "e".repeat(64), &mut f.index);
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &previous, &scan.snapshots)
            .unwrap()
            .0,
        1
    );
    assert_eq!(
        f.uploader.counts().3,
        1,
        "D-policy projection is a changed ordinary revision"
    );
    assert!(f.uploader.posts.last().unwrap()[0]
        .get("session_display_name")
        .map_or(true, serde_json::Value::is_null));
}

#[test]
fn real_uploader_context_catchup_spends_only_budget_left_after_new_usage() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut f = Fixture::new(source);
        let empty = f.index.clone();
        let old = uploader_group(&mut f, 3);
        f.uploader.activate(source, "d".repeat(64), &mut f.index);
        f.uploader.send(source, &mut f.index, &empty, &old).unwrap();
        let previous = f.index.clone();
        f.index.activate_file_upload_context(source, "e".repeat(64));
        let (mut scan, _) = f.walk(false);
        let mut usage = old[0].clone();
        usage.source_session_id = "zz-new-usage".into();
        scan.snapshots = old.clone();
        scan.snapshots.push(usage);
        finalize_scan_after_policy(source, &mut scan, &mut f.index);
        let usage = scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == "zz-new-usage")
            .unwrap();
        // Exactly enough packing allowance for ordinary usage plus one old
        // body, including separators and the conservative array reserve.
        let ordinary_bytes = serde_json::to_vec(usage).unwrap().len() + 3;
        let old_bytes = old
            .iter()
            .map(|item| serde_json::to_vec(item).unwrap().len() + 3)
            .max()
            .unwrap();
        f.uploader.activate(source, "e".repeat(64), &mut f.index);
        f.uploader.set_byte_allowance(ordinary_bytes + old_bytes);
        let first = f.uploader.posts.len();
        let received_before = f.uploader.received_catchup_bytes;
        f.uploader
            .send(source, &mut f.index, &previous, &scan.snapshots)
            .unwrap();
        let posts = &f.uploader.posts[first..];
        assert_eq!(posts[0].len(), 1);
        assert_eq!(posts[0][0]["source_session_id"], "zz-new-usage");
        assert_eq!(
            posts.iter().map(Vec::len).sum::<usize>(),
            2,
            "only one catch-up fits the remainder"
        );
        assert_eq!(f.uploader.counts().2, 1);
        assert!(f.uploader.received_catchup_bytes - received_before <= old_bytes as u64);
        let reacked = posts
            .iter()
            .flatten()
            .map(|item| item["snapshot_fingerprint"].clone())
            .collect::<Vec<_>>();
        f.uploader.restart(source, &"e".repeat(64));
        f.uploader.activate(source, "e".repeat(64), &mut f.index);
        f.uploader.set_byte_allowance(2 * old_bytes);
        let next = f.uploader.posts.len();
        let received_before = f.uploader.received_catchup_bytes;
        f.uploader
            .send(source, &mut f.index, &previous, &scan.snapshots)
            .unwrap();
        let remaining = f.uploader.posts[next..]
            .iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(
            remaining.len(),
            2,
            "remaining catch-up continues on the next pass"
        );
        assert!(remaining
            .iter()
            .all(|item| !reacked.contains(&item["snapshot_fingerprint"])));
        assert_eq!(f.uploader.counts().2, 2);
        assert!(f.uploader.received_catchup_bytes - received_before <= (2 * old_bytes) as u64);
    }
}

/// Cold acquisition on every page makes repeated Full reads observable. Each
/// file must get its real ACK/receipt in the same page as its sole body parse.
#[test]
fn real_scan_context_catchup_reads_each_file_once_across_many_passes() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut f = Fixture::new(source);
        let template = fs::read_to_string(&f.path).unwrap();
        let mut paths = vec![f.path.clone()];
        for n in 1..8 {
            let session = format!("019fa111-2222-7333-8444-{n:012}");
            let name = match source {
                SnapshotSource::Codex => format!("rollout-2026-10-29T10-00-00-{session}.jsonl"),
                _ => format!("{session}.jsonl"),
            };
            let path = f.root.join(name);
            fs::write(&path, template.replace(SESSION, &session)).unwrap();
            paths.push(path);
        }
        // Populate the actual index/ACK ledger, without direct receipt writes.
        for _ in 0..8 {
            let previous = f.index.clone();
            let (scan, _) = f.walk(true);
            f.uploader.activate(source, "d".repeat(64), &mut f.index);
            f.uploader
                .send(source, &mut f.index, &previous, &scan.snapshots)
                .unwrap();
            if paths.iter().all(|path| {
                f.index
                    .files
                    .get(&local_index_key(path))
                    .is_some_and(|entry| entry.upload_context_receipt.is_some())
            }) {
                break;
            }
        }
        assert!(paths
            .iter()
            .all(|path| f.index.files[&local_index_key(path)]
                .upload_context_receipt
                .is_some()));
        // Change the last (not FIFO-first) file. It must read before history.
        let changed = paths.last().unwrap().clone();
        let mut body = fs::read_to_string(&changed).unwrap();
        let changed_session = "019fa111-2222-7333-8444-000000000007";
        let growth = match source {
            SnapshotSource::Codex => {
                json!({"timestamp":"2026-10-29T10:02:01Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-5.5","total_token_usage":{"input_tokens":24,"output_tokens":8}}}})
            }
            _ => {
                json!({"type":"assistant","sessionId":changed_session,"timestamp":"2026-10-29T10:02:01Z","requestId":"changed-request","message":{"id":"changed-message","model":"claude-sonnet-4-6","usage":{"input_tokens":24,"output_tokens":8}}})
            }
        };
        body.push_str(&format!("{growth}\n"));
        fs::write(&changed, body).unwrap();
        let native_total: u64 = paths
            .iter()
            .map(|path| fs::metadata(path).unwrap().len())
            .sum();
        let changed_bytes = fs::metadata(&changed).unwrap().len();
        let max_other = paths
            .iter()
            .filter(|path| **path != changed)
            .map(|path| fs::metadata(path).unwrap().len())
            .max()
            .unwrap();
        let read_limit = changed_bytes + max_other;
        f.index.activate_file_upload_context(source, "e".repeat(64));
        let mut parses = BTreeMap::<PathBuf, usize>::new();
        let mut passes = 0;
        let mut local_bytes = 0;
        let mut all_read_bytes = 0;
        for _ in 0..40 {
            f.cache = Arc::default(); // force cold Full, not a retained-cache shortcut
            let previous = f.index.clone();
            let (((scan, _), per_file), order) =
                upload_context_read::with_read_limit(read_limit, || {
                    terminal_contract_retry::source_acquisitions(|| f.walk(true))
                });
            let read_bytes: u64 = per_file
                .keys()
                .map(|path| fs::metadata(path).unwrap().len())
                .sum();
            assert!(
                read_bytes <= read_limit,
                "native read budget is hard for every selected page"
            );
            if passes == 0 {
                assert_eq!(
                    order.first(),
                    Some(&changed),
                    "ordinary changed file reads first"
                );
                assert!(
                    order.len() >= 2,
                    "catch-up uses the remaining native allowance in that same pass"
                );
            }
            all_read_bytes += read_bytes;
            local_bytes += f.index.context_read_counts.local_bytes;
            for (path, count) in per_file {
                *parses.entry(path).or_default() += count;
            }
            f.uploader.activate(source, "e".repeat(64), &mut f.index);
            let before = f.uploader.posts.len();
            let catchup_before = f.uploader.received_catchup_bytes;
            let received_before = f.uploader.received_item_bytes;
            let emitted = f
                .uploader
                .send(source, &mut f.index, &previous, &scan.snapshots)
                .unwrap();
            assert_eq!(
                emitted.0 as usize,
                order.len(),
                "every parsed file earns its receipt this pass"
            );
            assert_eq!(
                f.uploader.posts[before..]
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>(),
                order.len()
            );
            let catchup_wire = f.uploader.received_catchup_bytes - catchup_before;
            let ordinary_wire = f.uploader.received_item_bytes - received_before - catchup_wire;
            assert!(
                catchup_wire
                    <= (crate::snapshot_sync::SNAPSHOT_BATCH_MAX_BYTES as u64)
                        .saturating_sub(ordinary_wire),
                "actual catch-up wire stays under the remaining allowance on every page"
            );
            passes += 1;
            if paths.iter().all(|path| {
                f.index.files[&local_index_key(path)]
                    .upload_context_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.context_fingerprint == "e".repeat(64))
            }) {
                break;
            }
        }
        assert!(passes > 3);
        assert_eq!(parses.len(), paths.len());
        assert!(
            parses.values().all(|count| *count == 1),
            "a wire-deferred tail must never be re-parsed"
        );
        assert_eq!(all_read_bytes, native_total);
        assert_eq!(
            local_bytes,
            native_total - changed_bytes,
            "local_bytes counts actual context body acquisition only"
        );
        f.assert_quiet();
    }
}

#[test]
fn real_scan_joined_codex_context_catchup_admits_the_whole_alias_unit() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (root, _) = codex_file_join::tests::counting_v2_fixture();
    let _cutover = codex_counting_version::TestCutover::set(0);
    let mut f = Fixture::new(SnapshotSource::Codex);
    fs::remove_file(&f.path).unwrap();
    for name in ["a", "b"] {
        let body = fs::read_to_string(root.join("sessions").join(format!("{name}.jsonl"))).unwrap();
        fs::write(
            f.root.join(format!("{name}.jsonl")),
            body.replace("2026-10-01", "2026-10-29"),
        )
        .unwrap();
    }
    fs::remove_dir_all(root).unwrap();
    f.path = f.root.join("a.jsonl");
    let previous = f.index.clone();
    let (scan, _) = f.walk(true);
    assert_eq!(scan.scanned_file_count, 2);
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &previous, &scan.snapshots)
            .unwrap()
            .0,
        2
    );
    f.index
        .activate_file_upload_context(f.source, "e".repeat(64));
    f.cache = Arc::default();
    let previous = f.index.clone();
    let ((scan, _), group_bytes) = terminal_contract_retry::group_body_bytes(|| f.walk(true));
    assert!(
        group_bytes > 0,
        "the physical group-read probe observes real replay before adoption"
    );
    assert_eq!(scan.scanned_file_count, 2, "joined aliases are admitted atomically, not permanently deferred after the first reservation");
    f.uploader.activate(f.source, "e".repeat(64), &mut f.index);
    let received_before = f.uploader.received_item_bytes;
    let (files, rearm_bytes) = f
        .uploader
        .send(f.source, &mut f.index, &previous, &scan.snapshots)
        .unwrap();
    assert_eq!(files, 2);
    let wire_bytes = f.uploader.received_item_bytes - received_before;
    assert_eq!(f.uploader.counts().1, wire_bytes);
    assert_eq!(
        rearm_bytes, wire_bytes,
        "joined aliases do not double-count wire bodies"
    );
    for name in ["a", "b"] {
        let key = local_index_key(&f.root.join(format!("{name}.jsonl")));
        let receipt = f.index.files[&key]
            .upload_context_receipt
            .as_ref()
            .expect("every physical alias earned its current-context receipt");
        assert_eq!(
            Some(&receipt.context_fingerprint),
            f.index.active_upload_context_fingerprint.as_ref()
        );
        assert!(!f.index.file_upload_context_requires_adoption(&key));
    }
    f.assert_quiet();
}

#[test]
fn real_scan_oversized_context_unit_gets_all_fresh_acks_without_reparse() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let previous = f.index.clone();
    let (mut scan, _) = f.walk(false);
    let template = scan.snapshots[0].clone();
    // Synthetic post-policy multi-entity file shape, through the real finalizer
    // and uploader. Each legal-sized item fits; their sum exceeds the pass cap.
    scan.snapshots = (0..4)
        .map(|n| {
            let mut item = template.clone();
            item.source_session_id = format!("oversized-group-{n}");
            item.session_display_name = Some("x".repeat(600 * 1024));
            item.session_display_name_source = Some("synthetic".into());
            item
        })
        .collect();
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    let items = scan.snapshots.clone();
    assert!(items
        .iter()
        .all(|item| serde_json::to_vec(item).unwrap().len() < MAX_SNAPSHOT_ITEM_WIRE_BYTES));
    assert!(
        serde_json::to_vec(&items).unwrap().len() > crate::snapshot_sync::SNAPSHOT_BATCH_MAX_BYTES
    );
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &previous, &items)
            .unwrap()
            .0,
        1
    );
    f.index
        .activate_file_upload_context(f.source, "e".repeat(64));
    f.cache = Arc::default();
    let previous = f.index.clone();
    let (((mut scan, _), parses), _) =
        upload_context_read::with_read_limit(fs::metadata(&f.path).unwrap().len(), || {
            terminal_contract_retry::source_acquisitions(|| f.walk(false))
        });
    assert_eq!(parses.get(&f.path), Some(&1));
    assert!(
        f.index.context_read_counts.wire_allowance > crate::snapshot_sync::SNAPSHOT_BATCH_MAX_BYTES
    );
    scan.snapshots = items;
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    f.uploader.activate(f.source, "e".repeat(64), &mut f.index);
    let first = f.uploader.posts.len();
    let received_before = f.uploader.received_catchup_bytes;
    let allowance = f.index.context_read_counts.wire_allowance as u64;
    assert_eq!(
        f.index.context_read_counts.files, 1,
        "the oversized exception admits one logical file alone"
    );
    assert!(f.index.context_read_counts.local_bytes <= fs::metadata(&f.path).unwrap().len());
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &previous, &scan.snapshots)
            .unwrap()
            .0,
        1,
        "the complete unit receives fresh ACKs in the same pass"
    );
    assert_eq!(
        f.uploader.posts[first..]
            .iter()
            .map(Vec::len)
            .sum::<usize>(),
        4
    );
    assert!(f.uploader.posts[first..]
        .iter()
        .all(|post| serde_json::to_vec(post).unwrap().len()
            <= crate::snapshot_sync::SNAPSHOT_BATCH_MAX_BYTES));
    let received = f.uploader.received_catchup_bytes - received_before;
    assert!(received > crate::snapshot_sync::SNAPSHOT_BATCH_MAX_BYTES as u64);
    assert!(received <= allowance);
    assert_eq!(f.uploader.counts().1, received);
    f.assert_quiet();
}

#[test]
fn real_scan_ordinary_codex_group_precedes_context_group_under_read_cap() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (root, _) = codex_file_join::tests::counting_v2_fixture();
    let _cutover = codex_counting_version::TestCutover::set(0);
    let mut f = Fixture::new(SnapshotSource::Codex);
    fs::remove_file(&f.path).unwrap();
    for (name, original, other) in [
        ("a", "a", false),
        ("b", "b", false),
        ("c", "a", true),
        ("d", "b", true),
    ] {
        let mut body = fs::read_to_string(root.join("sessions").join(format!("{original}.jsonl")))
            .unwrap()
            .replace("2026-10-01", "2026-10-29");
        if other {
            body = body.replace(
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            );
        }
        fs::write(f.root.join(format!("{name}.jsonl")), body).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
    f.path = f.root.join("a.jsonl");
    let previous = f.index.clone();
    let (scan, _) = f.walk(true);
    assert_eq!(scan.scanned_file_count, 4);
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    assert_eq!(f.send_ordering_page(&previous, &scan).0, 4);
    let path = f.root.join("d.jsonl");
    let mut changed = fs::read_to_string(&path).unwrap();
    changed.push(' '); // physical growth forces the joined unit's ordinary read
    fs::write(&path, changed).unwrap();
    let limit = ["c", "d"]
        .iter()
        .map(|name| {
            fs::metadata(f.root.join(format!("{name}.jsonl")))
                .unwrap()
                .len()
        })
        .sum();
    f.index
        .activate_file_upload_context(f.source, "e".repeat(64));
    f.cache = Arc::default();
    let previous = f.index.clone();
    let ((scan, _), order) =
        upload_context_read::with_read_limit(limit, || f.walk_with_file_limit(true, 3));
    assert!(
        order
            .first()
            .is_some_and(|path| path.ends_with("c.jsonl") || path.ends_with("d.jsonl")),
        "changed group goes before lexically earlier context-only group"
    );
    assert_eq!(scan.scanned_file_count, 2);
    assert_eq!(f.send_ordering_page(&previous, &scan).0, 2);
    f.cache = Arc::default();
    let previous = f.index.clone();
    let (scan, _) = f.walk(true);
    assert_eq!(
        scan.scanned_file_count, 2,
        "deferred context group continues next pass"
    );
    assert_eq!(f.send_ordering_page(&previous, &scan).0, 2);
    f.assert_quiet();
}

// Real scanner and transport; a context census member must not consume the
// ordinary singleton's slot, including an oversized own-page alias group.
fn ordinary_singleton_precedes_context_group(same_size_rewrite: bool) {
    for members in [2, 3] {
        let (root, _) = codex_file_join::tests::counting_v2_fixture();
        let _cutover = codex_counting_version::TestCutover::set(0);
        let mut f = Fixture::new(SnapshotSource::Codex);
        let singleton = f.root.join("z.jsonl");
        fs::rename(&f.path, &singleton).unwrap();
        f.path = singleton.clone();
        let original = fs::read(&singleton).unwrap();
        if !same_size_rewrite {
            fs::remove_file(&singleton).unwrap();
        }
        let names = if members == 2 {
            vec!["a", "b"]
        } else {
            vec!["a", "b", "c"]
        };
        for name in &names {
            let body = if *name == "c" {
                // A genuine continuation after b's 300, never a copied candidate.
                let mut rows = codex_file_join::tests::member(
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "r-c",
                    100,
                    400,
                );
                let created = rows[0]["timestamp"].clone();
                rows[0]["payload"]["timestamp"] = created.clone();
                rows[1]["timestamp"] = json!("2026-10-01T10:03:01Z");
                rows[1]["payload"]["turn_id"] = json!("turn-c");
                rows.insert(
                    1,
                    json!({"type":"event_msg","timestamp":created,
                        "payload":{"type":"task_started","turn_id":"turn-c"}}),
                );
                let finished = rows.last().unwrap()["timestamp"].clone();
                rows.push(json!({"type":"event_msg","timestamp":finished,
                    "payload":{"type":"task_complete","turn_id":"turn-c"}}));
                rows.into_iter()
                    .map(|row| format!("{row}\n"))
                    .collect::<String>()
            } else {
                fs::read_to_string(root.join("sessions").join(format!("{name}.jsonl"))).unwrap()
            };
            fs::write(
                f.root.join(format!("{name}.jsonl")),
                body.replace("2026-10-01", "2026-10-29"),
            )
            .unwrap();
        }
        fs::remove_dir_all(root).unwrap();
        let previous = f.index.clone();
        let (scan, _) = f.walk(true);
        f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
        assert_eq!(
            f.send_ordering_page(&previous, &scan).0,
            members + u64::from(same_size_rewrite)
        );
        let prior_modified =
            same_size_rewrite.then(|| fs::metadata(&singleton).unwrap().modified().unwrap());
        fs::write(&singleton, &original).unwrap();
        if let Some(prior) = prior_modified {
            fs::File::options()
                .write(true)
                .open(&singleton)
                .unwrap()
                .set_times(
                    fs::FileTimes::new().set_modified(prior + std::time::Duration::from_secs(2)),
                )
                .unwrap();
            assert_eq!(
                fs::metadata(&singleton).unwrap().len(),
                original.len() as u64
            );
        }
        f.index
            .activate_file_upload_context(f.source, "e".repeat(64));
        // Use the scanner's real discovery, then place the reachable traversal
        // shape from the review at the front: one context alias and an unhinted
        // ordinary singleton. Inventory still supplies the remaining aliases.
        ensure_bounded_traversal(
            f.source,
            std::slice::from_ref(&f.root),
            &mut f.index,
            "2026-10-29T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
        );
        let traversal = f.index.traversal.as_mut().unwrap();
        advance_bounded_directory_traversal(
            f.source,
            traversal,
            BACKFILL_WINDOW_DAYS,
            &f.index.files,
        );
        let a = f.root.join("a.jsonl");
        traversal
            .pending_candidates
            .make_contiguous()
            .sort_by_key(|pending| {
                if pending.path == a {
                    0
                } else if pending.path == singleton {
                    1
                } else {
                    2
                }
            });
        assert!(traversal
            .pending_candidates
            .iter()
            .all(|pending| !pending.watcher_hint));
        assert_eq!(traversal.pending_candidates[0].path, a);
        assert_eq!(traversal.pending_candidates[1].path, singleton);
        f.cache = Arc::default();
        let previous = f.index.clone();
        let (((scan, native), reads), group_native) =
            terminal_contract_retry::group_body_bytes(|| {
                terminal_contract_retry::source_acquisitions(|| f.walk_with_file_limit(true, 2))
            });
        assert!(native + group_native <= sampled_scan::codex_cursor::Limits::current().singleton());
        assert_eq!(
            scan.scanned_file_count, 1,
            "ordinary singleton owns its slot"
        );
        assert_eq!(
            reads,
            BTreeMap::from([(singleton.clone(), 1)]),
            "context group stays unparsed"
        );
        assert_eq!(group_native, 0);
        for name in &names {
            let key = local_index_key(&f.root.join(format!("{name}.jsonl")));
            assert!(
                f.index.file_upload_context_requires_adoption(&key),
                "group remains owed"
            );
            assert!(f
                .index
                .traversal
                .as_ref()
                .unwrap()
                .pending_candidates
                .iter()
                .any(|pending| local_index_key(&pending.path) == key));
        }
        let first = f.uploader.posts.len();
        assert_eq!(f.send_ordering_page(&previous, &scan).0, 1);
        assert!(f.uploader.posts[first..]
            .iter()
            .flatten()
            .all(|item| item["source_session_id"] == SESSION));
        f.cache = Arc::default();
        let previous = f.index.clone();
        let (((scan, native), reads), group_native) =
            terminal_contract_retry::group_body_bytes(|| {
                terminal_contract_retry::source_acquisitions(|| f.walk_with_file_limit(true, 2))
            });
        assert!(native + group_native <= sampled_scan::codex_cursor::Limits::current().singleton());
        assert_eq!(
            scan.scanned_file_count as u64, members,
            "context group runs on its later page"
        );
        assert_eq!(
            group_native,
            names
                .iter()
                .map(|name| fs::metadata(f.root.join(format!("{name}.jsonl")))
                    .unwrap()
                    .len())
                .sum::<u64>(),
            "every context member is physically read once"
        );
        // A joined job constructs one SourceFileParser at its canonical live
        // member; the job's tier reader covers the physical aliases.
        assert_eq!(reads.len(), 1);
        assert!(reads.iter().all(|(path, count)| *count == 1
            && names
                .iter()
                .any(|name| *path == f.root.join(format!("{name}.jsonl")))));
        assert_eq!(f.send_ordering_page(&previous, &scan).0, members);
        for name in &names {
            let key = local_index_key(&f.root.join(format!("{name}.jsonl")));
            let receipt = f.index.files[&key]
                .upload_context_receipt
                .as_ref()
                .expect("every physical alias earned a receipt from this ACK");
            assert_eq!(
                Some(&receipt.context_fingerprint),
                f.index.active_upload_context_fingerprint.as_ref()
            );
            assert!(!f.index.file_upload_context_requires_adoption(&key));
        }
        f.assert_quiet();
    }
}
#[test]
fn real_scan_new_unhinted_singleton_precedes_context_group_at_file_limit_two() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    ordinary_singleton_precedes_context_group(false);
}
#[test]
fn real_scan_same_size_rewrite_precedes_context_group_at_file_limit_two() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    ordinary_singleton_precedes_context_group(true);
}

#[test]
fn real_scan_settled_alias_cannot_evict_an_ordinary_singleton_beside_ordinary_group() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (root, _) = codex_file_join::tests::counting_v2_fixture();
    let _cutover = codex_counting_version::TestCutover::set(0);
    let mut f = Fixture::new(SnapshotSource::Codex);
    let singleton = f.root.join("z.jsonl");
    let body = fs::read(&f.path).unwrap();
    fs::remove_file(&f.path).unwrap();
    for (name, original, other) in [
        ("a", "a", false),
        ("b", "b", false),
        ("c", "a", true),
        ("d", "b", true),
    ] {
        let mut body = fs::read_to_string(root.join("sessions").join(format!("{original}.jsonl")))
            .unwrap()
            .replace("2026-10-01", "2026-10-29");
        if other {
            body = body.replace(
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            );
        }
        fs::write(f.root.join(format!("{name}.jsonl")), body).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
    let previous = f.index.clone();
    let (scan, _) = f.walk(true);
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &previous, &scan.snapshots)
            .unwrap()
            .0,
        4
    );
    assert!(
        f.uploader
            .finish_adopted_index(&mut f.index, &BTreeSet::new())
            .unwrap()
            > 0,
        "setup transfers adopted ACKs through the real saved-index finish"
    );
    // A remains receipt-settled. B has ordinary physical work; z is new.
    fs::write(&singleton, body).unwrap();
    let d = f.root.join("d.jsonl");
    let prior_modified = fs::metadata(&d).unwrap().modified().unwrap();
    let body = fs::read(&d).unwrap();
    fs::write(&d, &body).unwrap();
    fs::File::options()
        .write(true)
        .open(&d)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(prior_modified + std::time::Duration::from_secs(2)),
        )
        .unwrap();
    assert_eq!(fs::metadata(&d).unwrap().len(), body.len() as u64);
    // Growing this ORDINARY group would give it a dedicated freshness page
    // before unhinted z. Ordinary-vs-ordinary scheduling is allowed; a context
    // group may never do that. Keep size fixed to exercise normal file slots.
    assert!(!codex_fresh_data_pending(
        &ScanTraversalPath {
            scan_root: f.root.clone(),
            path: d,
            census_member: true,
            watcher_hint: false,
        },
        &f.index.files
    ));
    f.index.traversal = None;
    ensure_bounded_traversal(
        f.source,
        std::slice::from_ref(&f.root),
        &mut f.index,
        "2026-10-29T12:00:00Z",
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = f.index.traversal.as_mut().unwrap();
    advance_bounded_directory_traversal(f.source, traversal, BACKFILL_WINDOW_DAYS, &f.index.files);
    traversal
        .pending_candidates
        .make_contiguous()
        .sort_by_key(
            |pending| match pending.path.file_stem().and_then(|name| name.to_str()) {
                Some("a") => 0,
                Some("c") => 1,
                Some("z") => 2,
                _ => 3,
            },
        );
    let ordinary_group = [f.root.join("c.jsonl"), f.root.join("d.jsonl")];
    let group_bytes = ordinary_group
        .iter()
        .map(|path| fs::metadata(path).unwrap().len())
        .sum::<u64>();
    let expected_modified = fs::metadata(&ordinary_group[1])
        .unwrap()
        .modified()
        .unwrap();
    let mut singleton_parses = 0;
    let mut group_parses = 0;
    let mut total_group_bytes = 0;
    // Ordinary B and z may share a page or run on separate pages. Observe the
    // bounded service window, not a filename/hash-dependent ordinary schedule.
    for page in 0..3 {
        f.cache = Arc::default();
        let previous = f.index.clone();
        let (((scan, native), reads), physical_group_bytes) =
            terminal_contract_retry::group_body_bytes(|| {
                terminal_contract_retry::source_acquisitions(|| f.walk_with_file_limit(true, 3))
            });
        assert!(scan.scanned_file_count <= 3);
        assert!(
            native + physical_group_bytes
                <= sampled_scan::codex_cursor::Limits::current().singleton()
        );
        assert!(
            reads.iter().all(|(path, count)| {
                *count == 1 && (path == &singleton || ordinary_group.contains(path))
            }),
            "settled a/b never acquire a body parser"
        );
        let representatives = reads
            .iter()
            .filter(|(path, _)| ordinary_group.contains(path))
            .count();
        assert!(representatives <= 1, "B uses one joined canonical parser");
        let group_admitted = representatives == 1;
        singleton_parses += reads.get(&singleton).copied().unwrap_or(0);
        group_parses += representatives;
        assert!(
            singleton_parses <= 1 && group_parses <= 1,
            "STOP for Lead A: an ordinary item was parsed twice without another change"
        );
        total_group_bytes += physical_group_bytes;
        if group_admitted {
            // All group-body I/O belongs to c/d, once each; a/b contribute none.
            assert_eq!(physical_group_bytes, group_bytes);
            let changed = &f.index.files[&local_index_key(&ordinary_group[1])];
            assert_eq!(
                changed.modified_unix_nanos,
                expected_modified
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_nanos() as u64)
            );
            assert_ne!(
                changed.source_file_fingerprint,
                previous.files[&local_index_key(&ordinary_group[1])].source_file_fingerprint
            );
            assert!(changed.codex_joined_member_set.is_some());
        } else {
            assert_eq!(physical_group_bytes, 0, "no hidden settled-group body read");
            if group_parses == 0 {
                for path in &ordinary_group {
                    let key = local_index_key(path);
                    let pending = f
                        .index
                        .traversal
                        .as_ref()
                        .unwrap()
                        .pending_candidates
                        .iter()
                        .find(|pending| local_index_key(&pending.path) == key)
                        .expect("deferred ordinary group remains owed in traversal");
                    assert!(pending.census_member);
                    assert_eq!(
                        f.index.files[&key].source_file_fingerprint,
                        previous.files[&key].source_file_fingerprint
                    );
                    assert_eq!(
                        f.index.files[&key].last_upload_body_witness,
                        previous.files[&key].last_upload_body_witness
                    );
                    assert_eq!(
                        f.index.files[&key].upload_context_receipt,
                        previous.files[&key].upload_context_receipt,
                        "deferred B receives no credit"
                    );
                }
            }
        }
        assert_eq!(
            f.index.context_read_counts.local_bytes, 0,
            "this page has ordinary work and settled metadata, no context catch-up"
        );
        let first = f.uploader.posts.len();
        f.send_ordering_page(&previous, &scan);
        let posted = f.uploader.posts[first..]
            .iter()
            .flatten()
            .collect::<Vec<_>>();
        assert!(posted
            .iter()
            .all(|item| item["source_session_id"] == SESSION
                || item["source_session_id"] == "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"));
        if reads.contains_key(&singleton) {
            assert!(posted
                .iter()
                .any(|item| item["source_session_id"] == SESSION));
        }
        let group_posted = posted
            .iter()
            .any(|item| item["source_session_id"] == "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        eprintln!(
            "settled-alias page={} reads={reads:?} B_admitted={group_admitted} B_posted={group_posted} sampled_bytes={native} group_body_bytes={physical_group_bytes} POSTs={} B_owed={:?}",
            page + 1,
            f.uploader.posts.len() - first,
            ordinary_group.iter().map(|path| f.index.file_upload_context_requires_adoption(&local_index_key(path))).collect::<Vec<_>>()
        );
        assert!(!group_posted || group_admitted, "unadmitted B cannot POST");
        assert!(
            !group_admitted || group_posted,
            "B admission must POST and receive a fresh ACK after setup ACK retirement"
        );
        if group_posted {
            for path in &ordinary_group {
                let entry = &f.index.files[&local_index_key(path)];
                let receipt = entry
                    .upload_context_receipt
                    .as_ref()
                    .expect("normal accepted B response earns its receipt");
                assert_eq!(receipt.context_fingerprint, "d".repeat(64));
                assert_eq!(receipt.source_witness, entry.source_file_fingerprint);
                assert_eq!(
                    Some(&receipt.body_witness),
                    entry.last_upload_body_witness.as_ref()
                );
            }
        }
    }
    assert_eq!(
        singleton_parses, 1,
        "ordinary z is served exactly once within three pages"
    );
    assert_eq!(
        group_parses, 1,
        "ordinary B is served exactly once within three pages"
    );
    assert_eq!(
        total_group_bytes, group_bytes,
        "physical group body bytes are exactly one c/d replay, with no a/b read"
    );
    for path in ordinary_group.iter().chain(std::iter::once(&singleton)) {
        let key = local_index_key(path);
        let entry = &f.index.files[&key];
        let receipt = entry
            .upload_context_receipt
            .as_ref()
            .expect("ordinary work is settled before entering quiet checks");
        assert_eq!(
            Some(&receipt.context_fingerprint),
            f.index.active_upload_context_fingerprint.as_ref()
        );
        assert_eq!(receipt.source_witness, entry.source_file_fingerprint);
        assert_eq!(
            Some(&receipt.body_witness),
            entry.last_upload_body_witness.as_ref()
        );
        assert!(
            !f.index.file_upload_context_requires_adoption(&key),
            "ordinary work owes no adoption before quiet checks"
        );
    }
    f.assert_quiet();
}

// A retained post-policy group can contain multiple entities even when the
// current parser emits one session. Model that existing index shape through
// the real finalizer (as the source-matched mixed control does), settle only
// the accepted sibling through validated transport, and retain refusal debt.
// This is a selection/transport fixture, not a monetary equivalence oracle.
fn c1_retained_mixed_file() -> (Fixture, SnapshotItem) {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let mut row: Value = serde_json::from_str(fs::read_to_string(&f.path).unwrap().trim()).unwrap();
    row["customTitle"] = json!("Synthetic private title");
    fs::write(&f.path, format!("{row}\n")).unwrap();
    let (mut scan, _) = f.walk(false);
    assert_eq!(scan.snapshots.len(), 1);
    assert!(scan.snapshots[0].session_display_name.is_some());
    let mut sibling = scan.snapshots[0].clone();
    sibling.source_session_id = "019fa111-2222-7333-8444-666666666666".into();
    scan.snapshots.push(sibling);
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    assert_eq!(f.index.file_snapshot_fingerprints[&f.key()].len(), 2);
    let refused = scan.snapshots[1].clone();
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    f.uploader.hold_body(&mut f.index, &refused, false);
    let previous = f.index.clone();
    f.uploader
        .send(f.source, &mut f.index, &previous, &scan.snapshots[..1])
        .unwrap();
    assert_eq!(f.uploader.fresh_count(), 1, "one actual exact ACK");
    assert!(
        f.entry().upload_context_receipt.is_none(),
        "no partial file receipt"
    );
    assert_ne!(
        f.index.upload_context_fingerprint,
        f.index.active_upload_context_fingerprint
    );
    assert!(f.uploader.retains_quarantine(&refused.snapshot_fingerprint));
    (f, refused)
}

#[test]
fn c1_mixed_current_context_holds_three_relists_with_zero_body_reads() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (mut f, refused) = c1_retained_mixed_file();
    let persisted = serde_json::to_value(&f.index).unwrap();
    f.uploader
        .prepare_for_scan(f.source, "d".repeat(64), &mut f.index);
    assert_eq!(
        serde_json::to_value(&f.index).unwrap(),
        persisted,
        "view never persists"
    );
    f.assert_quiet(); // Three walks assert actual parses AND native/group bytes.
    assert!(f.index.mixed_context_view.held_files > 0);
    assert!(f.entry().upload_context_receipt.is_none());
    assert!(f.uploader.retains_quarantine(&refused.snapshot_fingerprint));
    assert!(!claude_terminal_authority(
        &f.index,
        true,
        "2026-10-29T12:00:00Z"
    ));
}

#[test]
fn c1_privacy_reduction_never_holds_old_context_siblings() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (mut f, refused) = c1_retained_mixed_file();
    f.uploader.policy = SnapshotUploadPolicy {
        session_titles_enabled: false,
        ..SnapshotUploadPolicy::default()
    };
    f.uploader
        .prepare_for_scan(f.source, "e".repeat(64), &mut f.index);
    assert!(f.index.file_upload_context_requires_adoption(&f.key()));
    let previous = f.index.clone();
    let (mut scan, _) = f.walk(false);
    assert_eq!(scan.scanned_file_count, 1, "D gets its own projection");
    assert!(scan
        .snapshots
        .iter()
        .any(|item| item.session_display_name.is_some()));
    apply_upload_policy(f.source, &mut scan.snapshots, f.uploader.policy);
    assert!(scan
        .snapshots
        .iter()
        .all(|item| item.session_display_name.is_none()));
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &previous, &scan.snapshots)
        .unwrap();
    assert!(f
        .uploader
        .posts
        .last()
        .unwrap()
        .iter()
        .all(|item| item.get("session_display_name").is_none_or(Value::is_null)));
    assert_eq!(f.index.mixed_context_view.held_files, 0);
    assert!(f.uploader.retains_quarantine(&refused.snapshot_fingerprint));
    f.assert_quiet();
}

#[test]
fn c1_terminal_ends_hold_and_destination_siblings_rearm_once_then_quiet() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (mut f, refused) = c1_retained_mixed_file();
    f.uploader.hold_body(&mut f.index, &refused, true);
    f.uploader
        .prepare_for_scan(f.source, "d".repeat(64), &mut f.index);
    assert!(
        !f.index.file_upload_context_waits_for_retry(&f.key()),
        "terminal ends hold"
    );
    f.assert_quiet(); // A sibling already ACKed under this context is not re-sent.
    assert_eq!(f.index.mixed_context_view.held_files, 0);
    // Move C→D after the terminal transition: D cannot use C's sibling ACK.
    f.uploader
        .prepare_for_scan(f.source, "e".repeat(64), &mut f.index);
    let previous = f.index.clone();
    let (scan, _) = f.walk(true);
    assert_eq!(scan.scanned_file_count, 1);
    let before = f.uploader.posts.len();
    let (rearmed, _) = f
        .uploader
        .send(f.source, &mut f.index, &previous, &scan.snapshots)
        .unwrap();
    assert_eq!(rearmed, 1, "one counted D re-arm");
    assert_eq!(f.uploader.posts.len(), before + 1);
    f.assert_quiet();
    assert_eq!(f.uploader.posts.len(), before + 1, "no repeat D POST");
    assert!(f.uploader.retains_quarantine(&refused.snapshot_fingerprint));
    assert_ne!(
        f.index.upload_context_fingerprint,
        f.index.active_upload_context_fingerprint
    );
}

#[test]
fn c1_missing_current_stamp_or_cleared_source_never_holds_a_context_move() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (mut f, _) = c1_retained_mixed_file();
    f.uploader.forget_stamps();
    f.uploader
        .prepare_for_scan(f.source, "d".repeat(64), &mut f.index);
    assert!(!f.index.file_upload_context_waits_for_retry(&f.key()));
    let key = f.key();
    f.index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    f.uploader
        .prepare_for_scan(f.source, "d".repeat(64), &mut f.index);
    assert!(!f.index.file_upload_context_waits_for_retry(&key));
    assert!(
        f.entry().source_file_fingerprint.is_empty(),
        "no overwritten clear debt"
    );
}

#[test]
fn c1_hold_count_uses_prepared_cooldown_and_lease_views() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (mut f, refused) = c1_retained_mixed_file();
    let entity = refused.snapshot_fingerprint.clone();
    let record = f
        .index
        .quarantined_snapshot_fingerprints
        .get_mut(&entity)
        .unwrap();
    record.retry_after_unix_seconds = 0;
    let body = record.upload_body_witness.clone().unwrap();
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    assert_eq!(
        f.index.mixed_context_view.held_files, 0,
        "not counted at early activation"
    );
    f.index.activate_reason_reoffer_retries(BTreeMap::new());
    f.index.activate_reason_reoffer_cooldowns(BTreeMap::new());
    assert!(
        !f.index.file_upload_context_waits_for_retry(&f.key()),
        "ordinary timer due"
    );
    let exact = BTreeMap::from([(entity, body)]);
    f.index.activate_reason_reoffer_cooldowns(exact.clone());
    f.index.count_mixed_file_context_holds();
    assert_eq!(
        f.index.mixed_context_view.held_files, 1,
        "prepared cooldown parks the exact body"
    );
    f.index.activate_reason_reoffer_retries(exact);
    f.index.count_mixed_file_context_holds();
    assert_eq!(
        f.index.mixed_context_view.held_files, 0,
        "prepared lease makes it runnable"
    );
    assert!(f.uploader.retains_quarantine(&refused.snapshot_fingerprint));
    assert!(
        f.entry().upload_context_receipt.is_none(),
        "no credit from a gauge"
    );
}

#[test]
fn terminal_off_receipt_context_move_uses_paced_catchup_then_three_quiet_walks() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    let original = fs::read_to_string(&f.path).unwrap();
    for session in [
        "019fa111-2222-7333-8444-666666666666",
        "019fa111-2222-7333-8444-777777777777",
    ] {
        fs::write(
            f.root.join(format!("{session}.jsonl")),
            original.replace(SESSION, session),
        )
        .unwrap();
    }
    let previous = f.index.clone();
    let (scan, _) = f.walk(true);
    assert_eq!(scan.scanned_file_count, 3);
    f.uploader.activate(f.source, "d".repeat(64), &mut f.index);
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &previous, &scan.snapshots)
            .unwrap()
            .0,
        3
    );
    f.assert_quiet();
    let limit = fs::metadata(&f.path).unwrap().len();
    let mut posted = 0;
    for _ in 0..3 {
        f.uploader
            .prepare_for_scan(f.source, "e".repeat(64), &mut f.index);
        let previous = f.index.clone();
        let ((scan, bytes), reads) = upload_context_read::with_read_limit(limit, || f.walk(true));
        assert_eq!(
            scan.scanned_file_count, 1,
            "one file fits the catch-up native allowance"
        );
        assert_eq!(reads.len(), 1);
        assert!(
            bytes <= limit,
            "context catch-up never bypasses the reader allowance"
        );
        let (files, _) = f
            .uploader
            .send(f.source, &mut f.index, &previous, &scan.snapshots)
            .unwrap();
        assert_eq!(files, 1, "one newly ACKed file per pass");
        posted += files;
        assert!(!scan.census_complete);
    }
    assert_eq!(posted, 3);
    assert!(f.index.files.values().all(|entry| entry
        .upload_context_receipt
        .as_ref()
        .is_some_and(|r| r.context_fingerprint == "e".repeat(64))));
    let posts = f.uploader.posts.len();
    f.assert_quiet();
    assert_eq!(f.uploader.posts.len(), posts);
    assert_eq!(
        f.index.upload_context_fingerprint.as_deref(),
        Some("c".repeat(64).as_str())
    );
}

#[test]
fn terminal_off_context_mismatch_cannot_wake_parked_key_until_stat_change() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    sampled_audit::reset_open_backoff_for_test();
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    assert_eq!(f.adopt().files, 1);
    f.assert_quiet();
    let key = f.key();
    let now = sampled_scan::now_seconds();
    let due = now - 1;
    f.index
        .claude_request_census_mut_for_test()
        .insert_for_test(
            &key,
            claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
                &"ab".repeat(32),
                0,
                claude_request_census::ClaudeRequestCensusShape::IdentityIncomplete,
                vec![1],
            )
            .with_unverified_for_test(true),
        );
    f.index.held_audit_progress = Some(sampled_audit::HeldAuditProgress {
        key: key.clone(),
        due,
        attempted: false,
    });
    for _ in 0..8 {
        sampled_audit::progress_open_failed(&mut f.index, &key, now);
    }
    assert!(sampled_audit::candidate_open_blocked(&key, now));
    let failed = sampled_audit::held_audit_open_failed(now);
    let samples = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    for _ in 0..3 {
        f.uploader
            .prepare_for_scan(f.source, "e".repeat(64), &mut f.index);
        let (scan, bytes) = sampled_scan::with_test_now(now, || f.walk(true));
        assert_eq!((scan.scanned_file_count, bytes), (0, 0));
        assert_eq!(
            START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get),
            samples
        );
        assert_eq!(sampled_audit::held_audit_open_failed(now), failed);
        assert_eq!(sampled_audit::failed_open_debt(&key, now), Some(due));
        assert_eq!(
            f.entry()
                .upload_context_receipt
                .as_ref()
                .unwrap()
                .context_fingerprint,
            "d".repeat(64)
        );
        assert!(!scan.census_complete);
    }
    let mut file = fs::OpenOptions::new().append(true).open(&f.path).unwrap();
    use std::io::Write;
    file.write_all(b"{\"type\":\"user\",\"message\":{\"content\":\"stat wake\"}}\n")
        .unwrap();
    drop(file);
    f.uploader
        .prepare_for_scan(f.source, "e".repeat(64), &mut f.index);
    let previous = f.index.clone();
    let (scan, _) = sampled_scan::with_test_now(now, || f.walk(true));
    assert_eq!(
        scan.scanned_file_count, 1,
        "only stat change clears the blocked open"
    );
    f.uploader
        .send(f.source, &mut f.index, &previous, &scan.snapshots)
        .unwrap();
    assert_eq!(
        f.entry()
            .upload_context_receipt
            .as_ref()
            .unwrap()
            .context_fingerprint,
        "e".repeat(64)
    );
    sampled_audit::reset_open_backoff_for_test();
}

fn b1_quiet_preparations(f: &mut Fixture, now: u64) {
    let samples = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    let body = TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get);
    let reparses = TERMINAL_OFF_EMPTY_REPARSES_FOR_TEST.with(std::cell::Cell::get);
    for offset in 1..=3 {
        f.uploader.prepare_for_scan(
            f.source,
            f.index.active_upload_context_fingerprint.clone().unwrap(),
            &mut f.index,
        );
        let previous = f.index.clone();
        let ((scan, bytes), reads) = terminal_contract_retry::source_acquisitions(|| {
            sampled_scan::with_test_now(now + offset, || f.walk(true))
        });
        assert_eq!(
            START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get),
            samples,
            "no walk samples"
        );
        assert_eq!(
            TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get),
            body,
            "no Full/body bytes"
        );
        assert_eq!(
            TERMINAL_OFF_EMPTY_REPARSES_FOR_TEST.with(std::cell::Cell::get),
            reparses,
            "no confirmed_empty_reparse"
        );
        assert_eq!(bytes, 0);
        assert!(reads.is_empty(), "no transcript parser stepped");
        assert_eq!(scan.scanned_file_count, 0);
        assert!(!scan.census_complete);
        let posts = f.uploader.posts.len();
        f.uploader
            .send(f.source, &mut f.index, &previous, &scan.snapshots)
            .unwrap();
        assert_eq!(f.uploader.posts.len(), posts, "no POST without new bodies");
    }
}

#[test]
fn terminal_off_empty_and_three_normal_files_stay_quiet_then_context_rereads_empty_once() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.index.upload_context_fingerprint = None; // Actual fresh source-wide context.
    let empty = f.root.join("019fa111-2222-7333-8444-888888888888.jsonl");
    fs::write(
        &empty,
        "{\"type\":\"user\",\"message\":{\"content\":\"no usage\"}}\n",
    )
    .unwrap();
    let key = local_index_key(&empty);
    let original = fs::read_to_string(&f.path).unwrap();
    for session in [
        "019fa111-2222-7333-8444-666666666666",
        "019fa111-2222-7333-8444-777777777777",
    ] {
        fs::write(
            f.root.join(format!("{session}.jsonl")),
            original.replace(SESSION, session),
        )
        .unwrap();
    }
    let now = sampled_scan::now_seconds();
    f.uploader
        .prepare_for_scan(f.source, "d".repeat(64), &mut f.index);
    let previous = f.index.clone();
    let (scan, _) = sampled_scan::with_test_now(now, || f.walk(true));
    assert_eq!(
        scan.scanned_file_count, 4,
        "1 nonzero-byte empty + N=3 ordinary files"
    );
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &previous, &scan.snapshots)
            .unwrap()
            .0,
        3
    );
    assert!(f.index.confirmed_empty_files.contains(&key));
    assert!(f.index.files[&key].last_upload_body_witness.is_none());
    assert!(
        f.index.files[&key].upload_context_receipt.is_none(),
        "no fake empty receipt"
    );
    assert!(terminal_off_empty_context_seen(&f.index, &key));
    assert!(!f.index.file_upload_context_requires_adoption(&key));
    b1_quiet_preparations(&mut f, now);
    // Even an independent forced metadata walk/cadence cannot reparse it for context.
    expire_terminal_off_discovery_for_test(&f.index);
    let (_, _, saved_evictions) = with_terminal_off_empty_contexts(|memo| {
        (memo.keys.len(), memo.order.len(), memo.evictions)
    });
    let reparses = TERMINAL_OFF_EMPTY_REPARSES_FOR_TEST.with(std::cell::Cell::get);
    let (same, _) = sampled_scan::with_test_now(now + 5, || f.walk(true));
    assert_eq!(same.scanned_file_count, 0);
    assert_eq!(
        TERMINAL_OFF_EMPTY_REPARSES_FOR_TEST.with(std::cell::Cell::get),
        reparses
    );
    let original_bodies = scan
        .snapshots
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect::<BTreeMap<_, _>>();
    f.uploader
        .prepare_for_scan(f.source, "e".repeat(64), &mut f.index);
    assert!(!terminal_off_empty_context_seen(&f.index, &key));
    let mut accepted = 0;
    let mut inputs = 0;
    let mut outputs = 0;
    let mut seen = BTreeSet::new();
    let mut empty_reads = 0;
    // #901's existing context-read/wire allowance services one ordinary
    // catch-up file per page here. Drain real pages; do not widen the budget.
    for pass in 0..3 {
        f.uploader
            .prepare_for_scan(f.source, "e".repeat(64), &mut f.index);
        let previous = f.index.clone();
        let ((changed, _), reads) = terminal_contract_retry::source_acquisitions(|| {
            sampled_scan::with_test_now(now + 6 + pass, || f.walk(true))
        });
        empty_reads += reads
            .iter()
            .filter(|(path, _)| *path == &empty)
            .map(|(_, n)| n)
            .sum::<usize>();
        for item in &changed.snapshots {
            assert!(
                seen.insert(item.source_session_id.clone()),
                "each ordinary body once under E"
            );
            assert_eq!(
                snapshot_upload_body_witness(item),
                original_bodies[&item.source_session_id],
                "context pacing never changes the body"
            );
            inputs += item.input_tokens;
            outputs += item.output_tokens;
        }
        accepted += f
            .uploader
            .send(f.source, &mut f.index, &previous, &changed.snapshots)
            .unwrap()
            .0;
        assert!(!changed.census_complete);
    }
    assert_eq!(accepted, 3, "all three real exact ACKs, across paced pages");
    assert_eq!(seen.len(), 3);
    assert_eq!((inputs, outputs), (36, 12));
    assert_eq!(empty_reads, 1, "one empty read under E across the drain");
    assert_eq!(
        TERMINAL_OFF_EMPTY_REPARSES_FOR_TEST.with(std::cell::Cell::get) - reparses,
        1
    );
    b1_quiet_preparations(&mut f, now + 8);
    assert!(
        f.index.upload_context_fingerprint.is_none(),
        "source context still unadopted"
    );
    assert!(f.index.files[&key].upload_context_receipt.is_none());
    assert_eq!(
        with_terminal_off_empty_contexts(|memo| memo.evictions),
        saved_evictions
    );
}

#[test]
fn terminal_off_held_history_without_body_witness_does_not_force_rediscovery() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.index.upload_context_fingerprint = None;
    f.index.activate_effective_upload_body_witness_revision(2);
    f.index
        .adopt_effective_upload_body_witness_revision_monotonically();
    f.index.claude_no_list_policy = claude_history_upgrade::NoListPolicy::HoldUnverified;
    f.index.claude_history_cutoff_unix_seconds = Some(u64::MAX);
    let now = sampled_scan::now_seconds();
    f.uploader
        .prepare_for_scan(f.source, "d".repeat(64), &mut f.index);
    let (scan, _) = sampled_scan::with_test_now(now, || f.walk(true));
    assert_eq!(scan.scanned_file_count, 1);
    assert!(
        scan.snapshots.is_empty(),
        "ordinary history privacy gate still withholds bodies"
    );
    assert!(f.entry().last_upload_body_witness.is_none());
    assert!(
        !f.index.confirmed_empty_files.contains(&f.key()),
        "held local bodies are not proven empty"
    );
    assert!(
        f.index
            .effective_upload_body_witness_revision_requires_adoption(&f.key()),
        "witness debt is retained"
    );
    assert!(
        f.index.file_upload_context_requires_adoption(&f.key()),
        "no fake receipt/empty memo"
    );
    assert!(!terminal_off_empty_context_seen(&f.index, &f.key()));
    b1_quiet_preparations(&mut f, now);
    assert!(f.entry().upload_context_receipt.is_none());
    assert_eq!(
        f.entry().effective_upload_body_witness_revision,
        0,
        "hold never stamped"
    );
}

#[test]
fn terminal_off_empty_memo_requires_finalization_and_cannot_mask_cleared_debt() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    fs::write(
        &f.path,
        "{\"type\":\"user\",\"message\":{\"content\":\"no usage\"}}\n",
    )
    .unwrap();
    let (mut scan, _) = f.walk(false);
    assert_eq!(scan.scanned_file_count, 1);
    assert!(
        !terminal_off_empty_context_seen(&f.index, &f.key()),
        "parse alone did not finalize policy"
    );
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    assert!(terminal_off_empty_context_seen(&f.index, &f.key()));
    assert!(f.entry().upload_context_receipt.is_none());
    let persisted = serde_json::to_value(&f.index).unwrap();
    let loaded: ScanIndex = serde_json::from_value(persisted.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&loaded).unwrap(),
        persisted,
        "no memo field in persisted state"
    );
    let key = f.key();
    f.index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    assert!(!terminal_off_empty_context_seen(&f.index, &key));
    assert!(
        f.index.file_upload_context_requires_adoption(&key),
        "genuine cleared debt is unchanged"
    );
    assert!(f.entry().source_file_fingerprint.is_empty());
}
