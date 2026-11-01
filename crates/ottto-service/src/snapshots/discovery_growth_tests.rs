//! R5: real discovery/acquisition, classification and Completed restoration.
//! Fixtures contain synthetic transcripts only. Existing native Tail assertions
//! in line_delivery_tests remain exact and unchanged.
use super::line_delivery::{DeliveryEnd, DeliveryMode, FileView, LineObserver, PhysicalLine, Want};
use super::*;
use crate::local_resource_diagnostics::capture;

const SESSION: &str = "5e551011-0000-4000-8000-00000000d171";

struct Fixture {
    root: PathBuf,
    path: PathBuf,
    cache: Arc<sampled_scan::SharedCache>,
}
impl Fixture {
    fn new() -> Self {
        let root = crate::test_scratch::unique_path("discovery-growth-fate");
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        Self {
            path: root.join(format!("{SESSION}.jsonl")),
            root,
            cache: Arc::new(sampled_scan::SharedCache::default()),
        }
    }
    fn append(&self, uuid: &str) {
        let line = json!({"type":"assistant", "sessionId":SESSION, "uuid":uuid,
            "cwd":"/synthetic", "timestamp":"2026-10-06T10:00:00.000Z",
            "requestId":format!("req_{uuid}"), "message": {
                "id":format!("msg_{uuid}"), "model":"claude-opus-4-8", "role":"assistant",
                "usage":{"input_tokens":10,"output_tokens":20}}});
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap();
        writeln!(file, "{line}").unwrap();
    }
    fn codex_turn(&self, n: u64) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap();
        if n == 1 {
            writeln!(
                file,
                "{}",
                json!({"type":"session_meta",
                "timestamp":"2026-10-27T09:00:00Z","payload":{"id":SESSION}})
            )
            .unwrap();
        }
        writeln!(
            file,
            "{}",
            json!({"timestamp":"2026-10-27T10:00:00Z",
            "type":"event_msg", "payload":{"type":"token_count","info":{
            "model":"gpt-5.2", "total_token_usage":{"input_tokens":n*10,
                "cached_input_tokens":n*2,"output_tokens":n*3},
            "last_token_usage":{"input_tokens":10,"cached_input_tokens":2,
                "output_tokens":3}}}})
        )
        .unwrap();
    }
    fn retained_codex(&self) -> ScanIndex {
        self.codex_turn(1);
        let (mut index, scan, _, _) = self.page(SnapshotSource::Codex, ScanIndex::default());
        assert_eq!(scan.snapshots.len(), 1);
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        ensure_bounded_traversal(
            SnapshotSource::Codex,
            std::slice::from_ref(&self.root),
            &mut index,
            &now,
            7,
        );
        advance_bounded_directory_traversal(SnapshotSource::Codex, &mut index, 7, None);
        let traversal = index.traversal.as_mut().unwrap();
        // This known member was already consumed. Saved retryable loss
        // elsewhere retains the roster; the retry is not due yet.
        traversal.pending_candidates.clear();
        traversal.counts.unreadable_path_count = 1;
        traversal.unhealthy_retry_not_before_unix_seconds =
            Some(sampled_scan::now_seconds() + UNHEALTHY_SCAN_RETRY_MAX_SECONDS);
        index
    }
    fn age(&self, days: u64) {
        let modified = SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
        File::options()
            .write(true)
            .open(&self.path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
    }
    fn page(
        &self,
        source: SnapshotSource,
        index: ScanIndex,
    ) -> (ScanIndex, SourceScanResult, Reads, Vec<Value>) {
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        self.page_with(source, index, &now, &[])
    }
    fn page_hinted(
        &self,
        source: SnapshotSource,
        index: ScanIndex,
        hints: &[PathBuf],
    ) -> (ScanIndex, SourceScanResult, Reads, Vec<Value>) {
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        self.page_with(source, index, &now, hints)
    }
    fn page_at(
        &self,
        source: SnapshotSource,
        index: ScanIndex,
        now: &str,
    ) -> (ScanIndex, SourceScanResult, Reads, Vec<Value>) {
        self.page_with(source, index, now, &[])
    }
    fn page_with(
        &self,
        source: SnapshotSource,
        mut index: ScanIndex,
        now: &str,
        hints: &[PathBuf],
    ) -> (ScanIndex, SourceScanResult, Reads, Vec<Value>) {
        self.cache.bind_withheld(&mut index);
        let reads = Reads::default();
        let ((index, result), rows) = capture(|| {
            let mut scan = OwnedSourceScan::new(
                source,
                std::slice::from_ref(&self.root),
                index,
                now,
                7,
                10,
                false,
                None,
                hints,
                false,
            )
            .with_sampled_acquisition(
                self.cache.clone(),
                crate::transcript_acquisition::Scope("growth-fate".into()),
            )
            .with_line_observer("test", Box::new(reads.clone()));
            for _ in 0..100_000 {
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete {
                        mut index,
                        mut scan,
                        ..
                    } => {
                        apply_upload_policy(
                            source,
                            &mut scan.snapshots,
                            SnapshotUploadPolicy::default(),
                        );
                        finalize_scan_after_policy(source, &mut scan, &mut index);
                        let accepted = scan
                            .snapshots
                            .iter()
                            .map(|item| item.snapshot_fingerprint.clone())
                            .collect();
                        index.record_accepted_snapshot_fingerprints(&accepted);
                        return (index, scan);
                    }
                }
            }
            panic!("bounded scan did not finish");
        });
        (index, result, reads, rows)
    }
    fn save_and_report(&self, index: &mut ScanIndex, scan: &SourceScanResult) -> Value {
        let path = self.root.join("index.json");
        // Preserve the production save's updated optimistic-concurrency stamp
        // in the index passed into the next real page.
        index.save(&path).unwrap();
        let saved = ScanIndex::load(&path).unwrap();
        let (_, rows) = capture(|| scan.report_discovery_growth_after_save(&saved));
        assert_eq!(rows.len(), 1, "one saved-page observation row");
        assert_eq!(rows[0]["stage"], "discovery_growth_fate");
        assert_eq!(rows[0]["source"], scan.source.api_slug());
        assert_eq!(rows[0]["schema_version"], 2);
        let encoded = serde_json::to_string(&rows[0]).unwrap();
        assert!(!encoded.contains(SESSION));
        assert!(!encoded.contains(&self.root.to_string_lossy().to_string()));
        assert!(encoded.len() < 2048);
        rows[0]["counts"].clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[derive(Clone, Default)]
struct Reads(Arc<Mutex<(Vec<DeliveryMode>, usize)>>);
impl LineObserver for Reads {
    fn begin(&mut self, view: &FileView) -> Want {
        self.0.lock().unwrap().0.push(view.mode);
        Want::Lines
    }
    fn line(&mut self, _: &FileView, _: &PhysicalLine<'_>) {
        self.0.lock().unwrap().1 += 1;
    }
    fn end(&mut self, _: &FileView, _: &DeliveryEnd) {}
}
fn growth_mode() -> DeliveryMode {
    if crate::heap_layout_bound::layout_supported() {
        DeliveryMode::Tail
    } else {
        DeliveryMode::Full
    }
}
fn fate(counts: &Value, committed: u64, retained: u64) {
    assert_eq!(
        counts["discovery_retained_grown_fate"],
        json!({
        "committed":committed, "still_retained":retained, "unindexed":0})
    );
    assert_eq!(counts["observation_overflow"], 0);
}
/// [behaviour] Grown refused then two unchanged passes read no extra body bytes.

#[test]
fn grown_refused_then_two_unchanged_passes_read_no_extra_body_bytes() {
    let f = Fixture::new();
    let source = SnapshotSource::ClaudeCode;
    let key = local_index_key(&f.path);
    f.append("committed");
    let (baseline, _, _, _) = f.page(source, ScanIndex::default());
    let committed_size = baseline.files[&key].size_bytes;
    f.append("withheld");
    f.age(91);
    let live_size = fs::metadata(&f.path).unwrap().len();
    let (parsed, scan, reads, _) = f.page(source, baseline.clone());
    assert_eq!(reads.0.lock().unwrap().0, vec![growth_mode()]);
    assert_eq!(parsed.files[&key].size_bytes, live_size);
    // Real classify filters the withheld body, Completed restores the prior
    // committed extent, and the completion stamp controls subsequent retries.
    let mut committed =
        crate::snapshot_sync::withheld_support::settle_withheld(&baseline, parsed, scan.clone());
    assert_eq!(committed.files[&key].size_bytes, committed_size);
    assert!(committed.claude_account_deferred_holds.contains_key(&key));
    let counts = f.save_and_report(&mut committed, &scan);
    fate(&counts, 0, 1); // a working parse is not a committed catch-up
    assert_eq!(counts["discovery_retained_grown_age"]["gt_90d"], 1);
    for pass in 0..2 {
        let (mut idle, scan, reads, rows) = f.page(source, committed);
        assert!(
            reads.0.lock().unwrap().0.is_empty(),
            "pass {pass}: no acquisition"
        );
        assert_eq!(reads.0.lock().unwrap().1, 0);
        assert_eq!(scan.scanned_file_count, 0);
        assert!(scan.snapshots.is_empty());
        let page = rows
            .iter()
            .find(|row| row["stage"] == "native_collection_page")
            .unwrap();
        assert_eq!(
            page["counts"]["sampled_acquisition"]["completed_native_bytes"], 0,
            "pass {pass}: zero extra body bytes; SOURCE permits existing identity samples"
        );
        assert_eq!(idle.files[&key].size_bytes, committed_size);
        assert!(idle.claude_account_deferred_holds.contains_key(&key));
        let counts = f.save_and_report(&mut idle, &scan);
        fate(&counts, 0, 1);
        assert_eq!(counts["discovery_retained_grown_age"]["gt_90d"], 1);
        committed = ScanIndex::load(&f.root.join("index.json")).unwrap();
    }
}
/// [behaviour] Grown catchup reports committed only against saved extent.

#[test]
fn grown_catchup_reports_committed_only_against_saved_extent() {
    let f = Fixture::new();
    f.append("first");
    let (baseline, _, _, _) = f.page(SnapshotSource::ClaudeCode, ScanIndex::default());
    f.append("second");
    f.age(31);
    let (mut caught_up, scan, reads, _) = f.page(SnapshotSource::ClaudeCode, baseline);
    assert_eq!(reads.0.lock().unwrap().0, vec![growth_mode()]);
    let counts = f.save_and_report(&mut caught_up, &scan);
    fate(&counts, 1, 0);
    assert_eq!(
        counts["discovery_retained_grown_age"],
        json!({"le_30d":0,"d31_90":0,"gt_90d":0,"unknown":0})
    );
}
/// [behaviour] Oversized grown age is disclosed for every source without body reads.

#[test]
fn oversized_grown_age_is_disclosed_for_every_source_without_body_reads() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let f = Fixture::new();
        let cap = max_jsonl_file_bytes(source);
        File::create(&f.path).unwrap().set_len(cap + 1).unwrap();
        f.age(91);
        let key = local_index_key(&f.path);
        let mut index = ScanIndex::default();
        let mut entry = super::tests::manifest_index_entry(None);
        entry.size_bytes = cap;
        index.files.insert(key.clone(), entry);
        let (mut next, scan, reads, _) = f.page(source, index);
        assert_eq!(next.files[&key].size_bytes, cap);
        assert!(reads.0.lock().unwrap().0.is_empty());
        assert_eq!(scan.scanned_file_count, 0);
        let counts = f.save_and_report(&mut next, &scan);
        fate(&counts, 0, 1);
        assert_eq!(counts["discovery_retained_grown_age"]["gt_90d"], 1);
    }
}

/// [behaviour] SOURCE's rewrite control: the same inode is truncated and rewritten past
/// the committed extent with a changed prefix. Growth retention discovers it;
/// acquisition's existing prefix samples force the counted Full rebuild.
#[test]
fn truncate_then_regrow_past_committed_extent_rebuilds_from_zero() {
    let f = Fixture::new();
    f.append("old");
    let key = local_index_key(&f.path);
    let (baseline, _, _, _) = f.page(SnapshotSource::ClaudeCode, ScanIndex::default());
    let prior = baseline.files[&key].size_bytes;
    File::create(&f.path).unwrap(); // truncate the existing object
    f.append("replacement");
    f.append("new-tail");
    f.age(31);
    assert!(fs::metadata(&f.path).unwrap().len() > prior);
    let (mut rewritten, scan, reads, _) = f.page(SnapshotSource::ClaudeCode, baseline);
    assert_eq!(
        reads.0.lock().unwrap().0,
        vec![DeliveryMode::Full],
        "rewrite must not Tail from the previous committed extent"
    );
    assert_eq!(
        reads.0.lock().unwrap().1,
        2,
        "rebuild delivers the entire rewritten file"
    );
    fate(&f.save_and_report(&mut rewritten, &scan), 1, 0);
}

/// [behaviour] Portable certificate/selector seam: the cursor's retained-prefix completion
/// is reproduced from a real ReadPlan seal, without a supported-layout override.
/// The subsequent aged discovery and catch-up are ordinary production scans.
/// Covers the in-memory seam, not the ordinary index-reload boundary: retaining
/// the fragment witness across source preparations is a separate follow-up.
#[test]
fn certified_codex_fragment_is_not_growth_or_a_recurring_acquisition() {
    use crate::transcript_acquisition::{AuditDebt, ReadPlan, Scope};
    let f = Fixture::new();
    let source = SnapshotSource::Codex;
    let token = |n| {
        json!({"timestamp":"2026-10-06T10:00:00Z", "type":"event_msg",
        "payload":{"type":"token_count","info":{"model":"fixture-model",
        "total_token_usage":{"input_tokens":n,"output_tokens":n},
        "last_token_usage":{"input_tokens":10,"output_tokens":10}}}})
        .to_string()
    };
    let prefix = format!(
        "{}\n{}\n",
        json!({"type":"session_meta",
        "timestamp":"2026-10-06T09:00:00Z","payload":{"id":SESSION}}),
        token(10)
    );
    fs::write(&f.path, &prefix).unwrap();
    let (mut index, baseline, _, _) = f.page(source, ScanIndex::default());
    assert_eq!(baseline.snapshots.len(), 1, "real indexed Codex prefix");
    fs::OpenOptions::new()
        .append(true)
        .open(&f.path)
        .unwrap()
        .write_all(token(20).as_bytes())
        .unwrap();
    f.age(91); // age BEFORE binding the completion; no artificial stale witness
    let key = local_index_key(&f.path);
    let mut candidate = candidate_from_traversal_path(
        source,
        ScanTraversalPath {
            scan_root: f.root.clone(),
            path: f.path.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut ScanCensus::default(),
        None,
        7,
        &mut crate::snapshots::CandidateDiscovery::new(&mut index, None),
    )
    .unwrap();
    prepare_owned_scan_candidate(
        source,
        &mut candidate,
        &CodexTitleMetadata::default(),
        &ClaudeTitleMetadata::default(),
        None,
    );
    // Reopening starts at the prepared-sidecar boundary. The opened result's
    // fingerprint already includes transcript identity and is not a sidecar.
    let prepared_candidate = candidate.clone();
    let (candidate, mut file) = open_and_identify_scan_candidate(
        source,
        candidate,
        &mut ScanCensus::default(),
        None,
        7,
        discovery_retention!(index),
    )
    .unwrap();
    let now = sampled_scan::now_seconds();
    let scope = Scope("fragment-control".into());
    let mut plan = ReadPlan::prepare(&mut file, None, &scope, None, now).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_record_fragment(&bytes[..prefix.len()], true)
        .unwrap();
    plan.observe_record_fragment(&bytes[prefix.len()..], false)
        .unwrap();
    let checkpoint = plan
        .commit_sealed_prefix(&mut file, true, &scope, now, now, false, bytes.len() as u64)
        .unwrap();
    assert_eq!(checkpoint.sealed_offset(), prefix.len() as u64);
    let fragment = codex_fragment::BoundFragment::bind(&candidate, checkpoint.sealed_offset())
        .expect("known object birth is required; no length-only witness");
    let mut recorded = candidate.clone();
    recorded.size_bytes = checkpoint.sealed_offset();
    index.record(
        recorded,
        Some(baseline.snapshots[0].snapshot_fingerprint.clone()),
        ScanParseOutcome::Snapshot,
    );
    index.files.get_mut(&key).unwrap().codex_fragment = Some(Box::new(fragment));
    index.stage_sampled_audit(
        &key,
        &candidate.source_file_fingerprint,
        AuditDebt {
            due_unix_seconds: now + crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
        },
    );
    assert!(
        index.files[&key].has_unverified_source(),
        "independent custody kept"
    );
    assert!(
        index.candidate_decision(&candidate) == CandidateDecision::Skip,
        "a certified unchanged fragment must not select another parse"
    );
    let encoded = serde_json::to_value(&index).unwrap();
    assert!(
        encoded["files"][&key].get("codex_fragment").is_none(),
        "RAM only"
    );
    // Metadata-only change: the certified prefix still names the observed EOF,
    // so ctime adoption must use that extent, not just the committed prefix.
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&f.path).unwrap().permissions().mode();
    fs::set_permissions(&f.path, fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
    let (metadata_only, _) = open_and_identify_scan_candidate(
        source,
        prepared_candidate,
        &mut ScanCensus::default(),
        None,
        7,
        discovery_retention!(index),
    )
    .unwrap();
    let entry = &index.files[&key];
    assert_ne!(
        entry.size_bytes, metadata_only.size_bytes,
        "certified prefix"
    );
    assert_ne!(
        metadata_only.opened_object_identity, candidate.opened_object_identity,
        "chmod changes the live ctime identity, which remains the TOCTOU witness"
    );
    assert_eq!(
        metadata_only.fingerprint_changed_nanos, entry.opened_changed_nanos,
        "the certified-prefix extent must allow stored-ctime adoption"
    );
    assert!(entry.codex_fragment.as_ref().unwrap().matches(
        entry.size_bytes,
        metadata_only.size_bytes,
        codex_fragment::Stamp::candidate(&metadata_only),
    ));
    assert_eq!(
        metadata_only.source_file_fingerprint, candidate.source_file_fingerprint,
        "the adopted trigger keeps known_fragment bound to the sampled fingerprint"
    );
    assert_eq!(
        index.candidate_decision_with_reason(&metadata_only),
        (CandidateDecision::Skip, None),
        "metadata alone cannot select TranscriptChanged or another acquisition"
    );
    let metadata = fs::metadata(&f.path).unwrap();
    for _ in 0..2 {
        let page = discovery_growth::Page::default();
        let retention = discovery_retention!(index, &page);
        retention.observe_stamped_growth(
            &f.path,
            metadata.len(),
            candidate.modified_unix_seconds,
            codex_fragment::Stamp::metadata(&metadata),
        );
        let (_, rows) = capture(|| {
            assert!(
                retention.owes_stamped(
                    source,
                    &f.path,
                    metadata.len(),
                    codex_fragment::Stamp::metadata(&metadata)
                ),
                "audit still owes it"
            )
        });
        assert!(!rows
            .iter()
            .any(|row| row.to_string().contains("\"grown\":1")));
        assert_eq!(
            page.counts(&index, now)
                .discovery_retained_grown_fate
                .still_retained,
            0,
            "known fragment is excluded from growth population"
        );
        let (next, scan, reads, rows) = f.page(source, index);
        assert_eq!(
            scan.scanned_file_count, 0,
            "unchanged aged fragment: no acquisition"
        );
        assert!(scan.snapshots.is_empty());
        assert!(reads.0.lock().unwrap().0.is_empty());
        assert!(
            !rows
                .iter()
                .any(|row| row["counts"]["discovery_retained"]["grown"]
                    .as_u64()
                    .is_some_and(|n| n != 0)),
            "no grown events"
        );
        assert!(
            !rows
                .iter()
                .any(|row| row["counts"].get("codex_fragment_tail_repeat").is_some()),
            "retained witness within a preparation: zero repeat counter"
        );
        assert!(next.files[&key].has_unverified_source());
        index = next;
    }
    // Portable completion seam: two ordinary index reloads lose only the RAM
    // witness. A real revalidated Tail plan/native reader consumes the known
    // fragment only. This does not claim a native cache-owner test on Linux.
    for _preparation in 0..2 {
        let reloaded: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        let entry = &reloaded.files[&key];
        assert!(entry.codex_fragment.is_none());
        let mut file = File::open(&f.path).unwrap();
        let plan = ReadPlan::prepare(&mut file, Some(&checkpoint), &scope, None, now).unwrap();
        assert_eq!(plan.mode(), crate::transcript_acquisition::ReadMode::Tail);
        let start = plan.start_offset();
        assert_eq!(start, entry.size_bytes);
        let len = candidate.size_bytes - start;
        let mut reader = BoundedJsonlReader::new(BufReader::new(file), 1024 * 1024, false);
        reader.set_extent_limit(len);
        reader.acquisition = Some(plan);
        while let JsonlReaderStep::Line | JsonlReaderStep::Partial = reader
            .step(|_| panic!("unterminated fragment must remain withheld"))
            .unwrap()
        {}
        assert!(reader.sealed_fragment());
        assert_eq!(reader.last_complete_line_end(), 0);
        assert_eq!(reader.consumed_bytes(), len);
        let (_, rows) = capture(|| {
            codex_fragment::note_tail_repeat(
                entry,
                &candidate,
                codex_fragment::TailRead {
                    mode: reader.acquisition.as_ref().unwrap().mode(),
                    start,
                    end: start + reader.consumed_bytes(),
                    terminated_end: reader.last_complete_line_end(),
                },
                Some(now),
                7,
            );
            crate::local_resource_diagnostics::Probe::start().collection(
                "codex",
                crate::local_resource_diagnostics::CollectionCounts {
                    scanned_files: 0,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                    full_causes: Default::default(),
                },
            );
        });
        assert_eq!(
            rows[0]["counts"]["codex_fragment_tail_repeat"],
            json!({"files":1,"bytes":len}),
            "one fragment-only Tail per reloaded preparation"
        );
        let (_, rows) = capture(|| {
            crate::local_resource_diagnostics::Probe::start().collection(
                "codex",
                crate::local_resource_diagnostics::CollectionCounts {
                    scanned_files: 0,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                    full_causes: Default::default(),
                },
            )
        });
        assert!(
            rows[0]["counts"]
                .get("codex_fragment_tail_repeat")
                .is_none(),
            "counter drained per page"
        );
    }
    // Missing binding/object changes must not turn a length heuristic into Skip.
    let mut without = index.clone();
    without.files.get_mut(&key).unwrap().codex_fragment = None;
    assert_eq!(
        without.candidate_decision(&candidate),
        CandidateDecision::Parse
    );
    fs::OpenOptions::new()
        .append(true)
        .open(&f.path)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    f.age(91);
    let (caught, scan, reads, rows) = f.page(source, index);
    assert!(
        !rows
            .iter()
            .any(|row| row["counts"].get("codex_fragment_tail_repeat").is_some()),
        "real terminated growth is not a fragment repeat"
    );
    assert!(
        rows.iter()
            .map(|row| row["counts"]["discovery_retained"]["grown"]
                .as_u64()
                .unwrap_or(0))
            .sum::<u64>()
            > 0,
        "real aged growth has positive grown credit"
    );
    assert_eq!(reads.0.lock().unwrap().0, vec![growth_mode()]);
    assert_eq!(scan.snapshots.len(), 1, "terminated record catches up once");
    assert_eq!(
        caught.files[&key].size_bytes,
        fs::metadata(&f.path).unwrap().len()
    );
    // Whole-body equality with a cold ordinary Full, not token-only equality.
    let mut cold_scan = OwnedSourceScan::new(
        source,
        std::slice::from_ref(&f.root),
        ScanIndex::default(),
        &scan.snapshots[0].collected_at,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
    );
    let (cold_index, cold) = loop {
        match cold_scan.step(None) {
            OwnedSourceScanStep::Pending(next) => cold_scan = next,
            OwnedSourceScanStep::Complete {
                mut scan,
                mut index,
                ..
            } => {
                apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
                finalize_scan_after_policy(source, &mut scan, &mut index);
                break (index, scan);
            }
        }
    };
    assert_eq!(
        serde_json::to_value(&scan.snapshots).unwrap(),
        serde_json::to_value(&cold.snapshots).unwrap(),
        "catch-up body == cold Full"
    );
    sampled_scan::transition_fixture::money_oracle::assert_equivalent(
        &sampled_scan::transition_fixture::scan_money(source, &cold_index, &cold),
        &sampled_scan::transition_fixture::scan_money(source, &caught, &scan),
    );
    let (_, idle, reads, _) = f.page(source, caught);
    assert!(idle.snapshots.is_empty(), "emitted once");
    assert!(reads.0.lock().unwrap().0.is_empty());
}

/// One usage record (with the session header first) in each source's format.
fn usage_records(source: SnapshotSource, session: &str, n: u64, header: bool) -> String {
    let at = "2026-10-06T10:00:00Z";
    let (head, line) = match source {
        SnapshotSource::ClaudeCode => (
            None,
            json!({"type":"assistant", "sessionId":session, "uuid":format!("{session}-{n}"),
            "cwd":"/synthetic", "timestamp":at, "requestId":format!("req_{session}_{n}"),
            "message": {"id":format!("msg_{session}_{n}"), "model":"claude-opus-4-8",
            "role":"assistant", "usage":{"input_tokens":10,"output_tokens":20}}}),
        ),
        SnapshotSource::Codex => (
            Some(json!({"type":"session_meta", "timestamp":at, "payload":{"id":session}})),
            json!({"timestamp":at, "type":"event_msg", "payload":{"type":"token_count",
            "info":{"model":"fixture-model",
            "total_token_usage":{"input_tokens":10 * n,"output_tokens":10 * n},
            "last_token_usage":{"input_tokens":10,"output_tokens":10}}}}),
        ),
        SnapshotSource::Pi => (
            Some(json!({"type":"session", "session_id":session, "cwd":"/work", "timestamp":at})),
            json!({"type":"message_end", "message":{"provider":"openai", "model":"gpt-5.4",
            "api":"responses", "timestamp":1_791_280_800_000_u64 + n,
            "usage":{"input":12,"output":4,"cacheRead":0,"cacheWrite":0}}}),
        ),
    };
    let head = head.filter(|_| header).map(|head| format!("{head}\n"));
    format!("{}{line}\n", head.unwrap_or_default())
}

fn append_records(path: &Path, text: &str) {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    file.write_all(text.as_bytes()).unwrap();
}

const UNCHANGED: &str = "0a000000-0000-4000-8000-00000000000a";
const GROWN: &str = "0b000000-0000-4000-8000-00000000000b";
const CREATED: &str = "0c000000-0000-4000-8000-00000000000c";
const REARMED: &str = "0d000000-0000-4000-8000-00000000000d";
const NESTED: &str = "0e000000-0000-4000-8000-00000000000e";
/// Root entries once CREATED exists: four files and the `nested` directory.
const ROOT_ENTRIES: usize = 5;

/// A kept generation whose first walk has finished and whose members were
/// all served, over four read files (one in `nested/`); `listing_due`
/// backdates its walk.
fn kept_generation(f: &Fixture, source: SnapshotSource, listing_due: bool) -> ScanIndex {
    for session in [UNCHANGED, GROWN, REARMED] {
        let path = f.root.join(format!("{session}.jsonl"));
        append_records(&path, &usage_records(source, session, 1, true));
    }
    fs::create_dir_all(f.root.join("nested")).unwrap();
    append_records(
        &f.root.join("nested").join(format!("{NESTED}.jsonl")),
        &usage_records(source, NESTED, 1, true),
    );
    let (mut index, _, reads, _) = f.page(source, ScanIndex::default());
    assert_eq!(
        reads.0.lock().unwrap().0.len(),
        4,
        "{source:?}: first reads"
    );
    let now = OffsetDateTime::now_utc();
    let collected_at = now.format(&Rfc3339).unwrap();
    ensure_bounded_traversal(
        source,
        std::slice::from_ref(&f.root),
        &mut index,
        &collected_at,
        7,
    );
    advance_bounded_directory_traversal(source, &mut index, 7, None);
    let traversal = index.traversal.as_mut().unwrap();
    assert!(traversal.pending_directories.is_empty());
    traversal.pending_candidates.clear();
    let due = now.unix_timestamp() as u64 - LISTING_INTERVAL_SECONDS - 60;
    traversal.listing_started_unix_seconds = Some(if listing_due {
        due
    } else {
        now.unix_timestamp() as u64
    });
    index
}

fn modes(reads: &Reads) -> Vec<String> {
    let mut modes = reads
        .0
        .lock()
        .unwrap()
        .0
        .iter()
        .map(|mode| format!("{mode:?}"))
        .collect::<Vec<_>>();
    modes.sort();
    modes
}

/// Pages until the generation has nothing queued (or retired).
struct Run {
    scans: Vec<SourceScanResult>,
    modes: Vec<String>,
    starts: usize,
}

fn run_pages(f: &Fixture, source: SnapshotSource, mut index: ScanIndex) -> Run {
    let mut run = Run {
        scans: Vec::new(),
        modes: Vec::new(),
        starts: 0,
    };
    for _ in 0..8 {
        let (next, scan, reads, rows) = f.page(source, index);
        index = next;
        run.modes.extend(modes(&reads));
        run.starts += rows
            .iter()
            .filter(|row| {
                row["stage"] == "bounded_traversal_transition"
                    && row["counts"]["event"] == "starting"
            })
            .count();
        run.scans.push(scan);
        if index.traversal.as_ref().map_or(true, |traversal| {
            traversal.pending_directories.is_empty() && traversal.pending_candidates.is_empty()
        }) {
            run.modes.sort();
            return run;
        }
    }
    panic!("{source:?}: the re-listing pass must drain within 8 pages");
}

/// Census completion and every loss count a page reports.
fn census(scan: &SourceScanResult) -> Value {
    json!([
        scan.census_complete,
        scan.symlink_rejected_count,
        scan.directory_entry_cap_exceeded_count,
        scan.unreadable_path_count,
        scan.oversized_file_count,
        scan.disappeared_file_count,
        scan.malformed_json_line_count,
        scan.invalid_utf8_line_count,
        scan.over_line_cap_count,
        scan.recognized_usage_drop_count,
        scan.ownership_incomplete_file_count,
        scan.zero_snapshot_usage_evidence_count,
        scan.dropped_usage_record_count,
    ])
}

/// [behaviour] A kept generation's re-listing pass reads exactly the files
/// that changed (grown by acquisition's growth mode, created by Full) and
/// nothing settled, for every source, whether the pass fits one page or spans
/// pages (directory budget below the entry count). It starts no generation,
/// adds no ownership-incomplete count and leaves census completion and every
/// loss count equal to the same generation without a pass. After a restart a
/// pass over a quiet corpus reads zero bytes and emits nothing.
#[test]
fn listing_repass_reads_only_changed_files_for_every_source() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let change = |f: &Fixture| {
            append_records(
                &f.root.join(format!("{GROWN}.jsonl")),
                &usage_records(source, GROWN, 2, false),
            );
            append_records(
                &f.root.join(format!("{CREATED}.jsonl")),
                &usage_records(source, CREATED, 1, true),
            );
        };
        let f = Fixture::new();
        let index = kept_generation(&f, source, false);
        change(&f);
        let without_pass = run_pages(&f, source, index);
        // Acquisition keeps the read mode: Pi re-reads a grown session in
        // Full; only what is queued is under test here.
        let grown_mode = match source {
            SnapshotSource::Pi => DeliveryMode::Full,
            _ => growth_mode(),
        };
        let mut expected = vec![
            format!("{:?}", DeliveryMode::Full),
            format!("{grown_mode:?}"),
        ];
        expected.sort();
        for budget in [MAX_SCAN_DIRECTORY_ENTRIES_PER_TICK, ROOT_ENTRIES] {
            let f = Fixture::new();
            let index = kept_generation(&f, source, true);
            change(&f);
            let run = with_test_directory_entries(budget, || run_pages(&f, source, index));
            assert_eq!(run.modes, expected, "{source:?} budget {budget}");
            assert_eq!(
                run.starts, 0,
                "{source:?} budget {budget}: no new generation"
            );
            assert!(
                budget == MAX_SCAN_DIRECTORY_ENTRIES_PER_TICK || run.scans.len() > 1,
                "{source:?}: the small budget spans pages"
            );
            assert!(run
                .scans
                .iter()
                .all(|scan| scan.ownership_incomplete_file_count == 0));
            assert_eq!(
                census(run.scans.last().unwrap()),
                census(without_pass.scans.last().unwrap()),
                "{source:?} budget {budget}"
            );
        }

        // Quiet corpus after a restart: saved index, no retained checkpoint.
        let mut f = Fixture::new();
        let mut index = kept_generation(&f, source, true);
        let path = f.root.join("index.json");
        index.save(&path).unwrap();
        let index = ScanIndex::load(&path).unwrap();
        f.cache = Arc::new(sampled_scan::SharedCache::default());
        let opens = all_transcript_opens_for_test();
        let ((quiet_index, scan, reads, rows), consumed) =
            sampled_scan::transition_fixture::observe_consumed(|| f.page(source, index));
        // The reloaded generation ran its due pass; no first walk replaced it.
        assert!(!rows.iter().any(|row| {
            row["stage"] == "bounded_traversal_transition" && row["counts"]["event"] == "starting"
        }));
        if let Some(traversal) = quiet_index.traversal.as_ref() {
            assert!(traversal.counts.listing_generations >= 1, "{source:?}");
        }
        assert!(scan.snapshots.is_empty(), "{source:?}");
        assert_eq!(scan.scanned_file_count, 0, "{source:?}");
        // Zero opens measures zero identity, cheap and other reads.
        let measured = (all_transcript_opens_for_test() == opens).then_some(0);
        let mut quiet = sampled_scan::transition_fixture::RouteResult::emitted(
            sampled_scan::transition_fixture::Mode::Restart,
            source,
            Vec::new(),
            &[],
        );
        quiet.modes = (reads.0.lock().unwrap().0.len(), 0, 0);
        quiet.io = sampled_scan::transition_fixture::IoBytes {
            consumed,
            cheap_checks: measured,
            anchor_reads: measured,
            other_reads: measured,
            ..Default::default()
        };
        sampled_scan::transition_fixture::money_oracle::assert_quiet_restart_zero_bytes(&quiet);
    }
}

/// [regress] A re-armed (owed) file whose stamp is unchanged stays
/// schedulable through the re-listing pass and through the watcher-hint
/// filter, and a pass queues it as the hint rule does (a census member for
/// Claude/Pi). A settled file with a metadata-only change and its hint is
/// never read. Before the fix both paths skipped the owed file on its stamp.
#[test]
fn owed_unchanged_file_stays_schedulable_and_settled_file_is_not_read() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        for hinted in [false, true] {
            let mut f = Fixture::new();
            let mut index = kept_generation(&f, source, !hinted);
            // A restart: no retained acquisition checkpoint.
            f.cache = Arc::new(sampled_scan::SharedCache::default());
            let rearmed = f.root.join(format!("{REARMED}.jsonl"));
            let unchanged = f.root.join(format!("{UNCHANGED}.jsonl"));
            let key = local_index_key(&rearmed);
            index
                .files
                .get_mut(&key)
                .unwrap()
                .source_file_fingerprint
                .clear();
            // Metadata-only changes (ctime).
            for path in [&rearmed, &unchanged] {
                let original = fs::metadata(path).unwrap().permissions();
                let mut read_only = original.clone();
                read_only.set_readonly(true);
                fs::set_permissions(path, read_only).unwrap();
                fs::set_permissions(path, original).unwrap();
            }
            if !hinted {
                let mut walked = index.clone();
                let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
                start_due_listing_pass(walked.traversal.as_mut().unwrap(), &now);
                advance_bounded_directory_traversal(source, &mut walked, 7, None);
                let queued = &walked.traversal.as_ref().unwrap().pending_candidates;
                let owed = queued
                    .iter()
                    .find(|pending| pending.path == rearmed)
                    .expect("the owed file is queued");
                assert_eq!(owed.census_member, source != SnapshotSource::Codex);
                assert!(!queued.iter().any(|pending| pending.path == unchanged));
            }
            let hints = if hinted {
                vec![rearmed.clone(), unchanged.clone()]
            } else {
                Vec::new()
            };
            let (index, scan, reads, _) = f.page_hinted(source, index, &hints);
            assert_eq!(
                modes(&reads),
                vec![format!("{:?}", DeliveryMode::Full)],
                "{source:?} hinted {hinted}"
            );
            assert_eq!(scan.scanned_file_count, 1, "{source:?} hinted {hinted}");
            assert!(
                !index.files[&key].source_file_fingerprint.is_empty(),
                "{source:?} hinted {hinted}: the owed work resolved"
            );
        }
    }
}

/// [regress] An owed file whose stamp stays unchanged (a held revert keeps
/// clearing its fingerprint) is queued by the re-listing pass at most once
/// per file per six hours, counted apart from changed files; a pass inside
/// the interval leaves it alone, and the queued offer reads Full once.
#[test]
fn owed_unchanged_file_is_requeued_once_per_six_hours() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let mut f = Fixture::new();
        let mut index = kept_generation(&f, source, false);
        let rearmed = f.root.join(format!("{REARMED}.jsonl"));
        let key = local_index_key(&rearmed);
        let queued = |index: &ScanIndex| {
            let traversal = index.traversal.as_ref().unwrap();
            (
                traversal
                    .pending_candidates
                    .iter()
                    .filter(|pending| pending.path == rearmed)
                    .count(),
                traversal.counts.listing_owed_requeued,
                traversal.counts.listing_changes_without_hint,
            )
        };
        index
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        relist(source, &mut index);
        assert_eq!(queued(&index), (1, 1, 0), "{source:?}: first offer");
        let offer = index.clone();
        // Its read is out of scope here; the fingerprint stays cleared.
        for _ in 0..3 {
            index.traversal.as_mut().unwrap().pending_candidates.clear();
            relist(source, &mut index);
            assert_eq!(queued(&index), (0, 1, 0), "{source:?}: paced");
        }
        let traversal = index.traversal.as_mut().unwrap();
        traversal.pending_candidates.clear();
        *traversal
            .listing_owed_requeued_unix_seconds
            .get_mut(&key)
            .unwrap() -= LISTING_OWED_PACE_SECONDS;
        relist(source, &mut index);
        assert_eq!(queued(&index), (1, 2, 0), "{source:?}: after six hours");

        f.cache = Arc::new(sampled_scan::SharedCache::default());
        let (_, scan, reads, _) = f.page(source, offer);
        assert_eq!(
            modes(&reads),
            vec![format!("{:?}", DeliveryMode::Full)],
            "{source:?}"
        );
        assert_eq!(scan.scanned_file_count, 1, "{source:?}");
    }
}

/// [money] Re-listing uses archive stamps and custody after native-entry retirement;
/// unchanged debt is paced, settlement stays quiet, growth queues, and size debt stays isolated.
#[test]
fn archive_relisting_preserves_custody_and_owed_pacing() {
    use crate::local_resource_diagnostics::CodexZstCause;
    use codex_compressed_input::{ArchiveDisposition, ArchiveEvidence};
    for disposition in [
        ArchiveDisposition::Acquired,
        ArchiveDisposition::Empty,
        ArchiveDisposition::Pending,
        ArchiveDisposition::Held {
            cause: CodexZstCause::HeaderInvalid,
            quiet: true,
        },
        ArchiveDisposition::Held {
            cause: CodexZstCause::CorrectionUnapplied,
            quiet: true,
        },
    ] {
        let f = Fixture::new();
        let mut index = kept_generation(&f, SnapshotSource::Codex, false);
        let path = f.root.join("archive.jsonl.zst");
        fs::write(&path, b"synthetic").unwrap();
        let key = local_index_key(&path);
        let mut archive = ArchiveEvidence::from_metadata(fs::metadata(&path).unwrap()).unwrap();
        archive.owner = Some("synthetic".into());
        archive.disposition = disposition;
        archive.work.as_mut().unwrap().decoded = true;
        let owed = archive.owed_cause().is_some();
        index.archives.insert(key.clone(), archive);
        // Settled archive custody wins even over a re-armed ordinary entry.
        // Owed archives have no native entry after reconciliation retires it.
        if !owed {
            index.files.insert(key.clone(), ScanIndexEntry::default());
        }
        index
            .traversal
            .as_mut()
            .unwrap()
            .observed_index_keys
            .insert(key.clone());
        assert_eq!(discovery_retention!(index).owes(&path), owed);
        for pass in 0..3 {
            index.traversal.as_mut().unwrap().pending_candidates.clear();
            relist(SnapshotSource::Codex, &mut index);
            let traversal = index.traversal.as_ref().unwrap();
            assert_eq!(
                traversal.pending_candidates.len(),
                usize::from(owed && pass == 0)
            );
            assert_eq!(traversal.counts.listing_owed_requeued, u64::from(owed));
            assert_eq!(traversal.counts.listing_changes_without_hint, 0);
            assert!(traversal
                .pending_candidates
                .iter()
                .all(|p| p.path == path && !p.census_member));
        }
        if owed {
            *index
                .traversal
                .as_mut()
                .unwrap()
                .listing_owed_requeued_unix_seconds
                .get_mut(&key)
                .unwrap() -= LISTING_OWED_PACE_SECONDS;
            relist(SnapshotSource::Codex, &mut index);
            assert_eq!(
                index.traversal.as_ref().unwrap().pending_candidates.len(),
                1
            );
            assert_eq!(
                index
                    .traversal
                    .as_ref()
                    .unwrap()
                    .counts
                    .listing_owed_requeued,
                2
            );
        }
        index.traversal.as_mut().unwrap().pending_candidates.clear();
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"growth")
            .unwrap();
        relist(SnapshotSource::Codex, &mut index);
        let traversal = index.traversal.as_ref().unwrap();
        assert_eq!(traversal.pending_candidates.len(), 1);
        assert_eq!(traversal.pending_candidates[0].path, path);
        assert_eq!(traversal.counts.listing_changes_without_hint, 1);
    }
    let f = Fixture::new();
    let mut index = kept_generation(&f, SnapshotSource::Codex, false);
    let path = f.root.join("oversized.jsonl.zst");
    fs::File::create(&path)
        .unwrap()
        .set_len(max_jsonl_file_bytes(SnapshotSource::Codex) + 1)
        .unwrap();
    relist(SnapshotSource::Codex, &mut index);
    let traversal = index.traversal.as_ref().unwrap();
    assert!(traversal.pending_candidates.is_empty());
    assert_eq!(traversal.counts.oversized_file_count, 0);
    assert_eq!(traversal.counts.unreadable_path_count, 0);
    assert!(index
        .archive_pass
        .deferred
        .contains(&local_index_key(&path)));
    let (_, logs) = capture(|| index.disclose_archive_debt());
    assert!(index.archive_owed_count() > 0);
    assert!(logs.iter().any(|row| row["stage"] == "durable_tail_alarm"));
}

/// [format] The owed re-queue pacing map is scheduling evidence only. Through
/// the production loader an absent, valid, malformed or over-cap map keeps the
/// traversal (census, counts and queued work) unchanged; undecodable stamps
/// are dropped and an over-cap map keeps only its newest stamps.
#[test]
fn listing_owed_pacing_map_decodes_leniently_and_keeps_the_traversal() {
    let f = Fixture::new();
    let mut index = kept_generation(&f, SnapshotSource::ClaudeCode, false);
    let traversal = index.traversal.as_mut().unwrap();
    traversal.pending_candidates.push_back(ScanTraversalPath {
        scan_root: f.root.clone(),
        path: f.root.join(format!("{GROWN}.jsonl")),
        census_member: true,
        watcher_hint: false,
    });
    traversal.counts.unreadable_path_count = 1;
    let saved = serde_json::to_value(&index).unwrap();
    let over_cap = (0..MAX_LISTING_OWED_PACES as u64 + 3)
        .map(|at| (format!("/synthetic/{at:05}.jsonl"), json!(at)))
        .collect::<serde_json::Map<_, _>>();
    let newest = (3..MAX_LISTING_OWED_PACES as u64 + 3)
        .map(|at| (format!("/synthetic/{at:05}.jsonl"), json!(at)))
        .collect::<serde_json::Map<_, _>>();
    let cases = [
        (None, json!({})),
        (
            Some(json!({"/synthetic/a.jsonl": 5})),
            json!({"/synthetic/a.jsonl": 5}),
        ),
        (
            Some(json!({"/synthetic/a.jsonl": "future-shape", "/synthetic/b.jsonl": 7})),
            json!({"/synthetic/b.jsonl": 7}),
        ),
        (Some(json!("future-shape")), json!({})),
        (Some(Value::Object(over_cap)), Value::Object(newest)),
    ];
    let mut baseline = None;
    for (number, (stored, expected)) in cases.into_iter().enumerate() {
        let mut old = saved.clone();
        if let Some(stored) = stored {
            old["traversal"]["listing_owed_requeued_unix_seconds"] = stored;
        }
        let path = f.root.join(format!("paces-{number}.json"));
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        let loaded = ScanIndex::load(&path).expect("the pacing map never fails the index");
        let mut traversal = serde_json::to_value(loaded.traversal.as_ref().unwrap()).unwrap();
        let paces = traversal
            .as_object_mut()
            .unwrap()
            .remove("listing_owed_requeued_unix_seconds")
            .unwrap_or_else(|| json!({}));
        assert_eq!(paces, expected, "case {number}");
        let kept = loaded.traversal.as_ref().unwrap();
        assert_eq!(kept.counts.unreadable_path_count, 1, "case {number}");
        assert_eq!(
            kept.pending_candidates.len(),
            1,
            "case {number}: queued work"
        );
        let baseline = baseline.get_or_insert_with(|| traversal.clone());
        assert_eq!(&traversal, baseline, "case {number}: traversal kept");
    }
}

/// Starts a due re-listing pass on a kept generation and walks it.
fn relist(source: SnapshotSource, index: &mut ScanIndex) {
    let now = OffsetDateTime::now_utc();
    let traversal = index.traversal.as_mut().unwrap();
    traversal.listing_started_unix_seconds =
        Some(now.unix_timestamp() as u64 - LISTING_INTERVAL_SECONDS - 60);
    start_due_listing_pass(traversal, &now.format(&Rfc3339).unwrap());
    advance_bounded_directory_traversal(source, index, 7, None);
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_directories
        .is_empty());
}

/// [money] A known Codex rollout append with no directory move or watcher
/// hint is queued once by the re-listing pass, Tail-read once, and emits the
/// same whole money body as a cold Full.
#[test]
fn retained_codex_stat_growth_tails_once_with_full_money() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let f = Fixture::new();
    let mut index = f.retained_codex();
    f.codex_turn(2);
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .codex_join_directory_census
        .as_ref()
        .unwrap()
        .moved_directories()
        .is_empty());
    // A second pass before selection cannot duplicate queued work.
    for _ in 0..2 {
        relist(SnapshotSource::Codex, &mut index);
        let traversal = index.traversal.as_ref().unwrap();
        assert_eq!(traversal.counts.listing_changes_without_hint, 1);
        assert_eq!(traversal.pending_candidates.len(), 1);
        assert!(!traversal.pending_candidates[0].census_member);
    }
    let (caught, scan, reads, _) = f.page(SnapshotSource::Codex, index);
    assert_eq!(reads.0.lock().unwrap().0, vec![DeliveryMode::Tail]);
    assert_eq!(scan.snapshots.len(), 1);
    let item = &scan.snapshots[0];
    assert_eq!(item.input_tokens, 20);
    assert_eq!(item.cache_read_tokens, 4);
    assert_eq!(item.output_tokens, 6);
    assert_eq!(item.request_count, 2);
    f.cache.clear();
    let (cold_index, cold, _, _) = f.page_at(
        SnapshotSource::Codex,
        ScanIndex::default(),
        &scan.snapshots[0].collected_at,
    );
    sampled_scan::transition_fixture::money_oracle::assert_equivalent(
        &sampled_scan::transition_fixture::scan_money(SnapshotSource::Codex, &cold_index, &cold),
        &sampled_scan::transition_fixture::scan_money(SnapshotSource::Codex, &caught, &scan),
    );
    let (_, idle, reads, _) = f.page(SnapshotSource::Codex, caught);
    assert!(idle.snapshots.is_empty());
    assert!(reads.0.lock().unwrap().0.is_empty());
}

/// [behaviour] The re-listing pass queues and acquires nothing for unchanged
/// bytes (a ctime-only change included) or for inventory-held growth while
/// its refusal evidence stays unchanged.
#[test]
fn retained_codex_unchanged_or_inventory_held_member_is_not_enqueued() {
    for held_growth in [false, true] {
        let f = Fixture::new();
        let mut index = f.retained_codex();
        if held_growth {
            f.codex_turn(2);
            let key = local_index_key(&f.path);
            index
                .traversal
                .as_mut()
                .unwrap()
                .residue
                .codex_inventory_hold = Some(CodexInventoryHold {
                owed: BTreeSet::from([key.clone()]),
                refused_headers: BTreeMap::from([(key, codex_file_join::path_witness(&f.path))]),
                ..CodexInventoryHold::default()
            });
        } else {
            let original = fs::metadata(&f.path).unwrap().permissions();
            let mut read_only = original.clone();
            read_only.set_readonly(true);
            fs::set_permissions(&f.path, read_only).unwrap();
            fs::set_permissions(&f.path, original).unwrap();
        }
        for _ in 0..2 {
            relist(SnapshotSource::Codex, &mut index);
            let traversal = index.traversal.as_ref().unwrap();
            assert!(traversal.pending_candidates.is_empty());
            assert_eq!(traversal.counts.listing_changes_without_hint, 0);
        }
        let (_, scan, reads, _) = f.page(SnapshotSource::Codex, index);
        assert!(scan.snapshots.is_empty());
        assert!(reads.0.lock().unwrap().0.is_empty());
    }
}

/// [behaviour] A watcher hint for a settled file is dropped unless this
/// cycle leased one of its snapshots for a reason re-offer; the leased hint
/// is kept for the ordinary candidate gate.
#[test]
fn leased_reoffer_hint_survives_the_settled_hint_filter() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let f = Fixture::new();
        let mut index = kept_generation(&f, source, false);
        let unchanged = f.root.join(format!("{UNCHANGED}.jsonl"));
        let hints = [unchanged.clone()];
        assert!(
            changed_watcher_hints(&index, &hints).is_empty(),
            "{source:?}: a settled hint is dropped"
        );
        let fingerprint = index.file_snapshot_fingerprints[&local_index_key(&unchanged)]
            .first()
            .expect("the read recorded its snapshot")
            .clone();
        let leased =
            index.activate_reason_reoffer_retries(BTreeMap::from([(fingerprint, "body".into())]));
        assert_eq!(leased, vec![unchanged.clone()], "{source:?}");
        assert_eq!(
            changed_watcher_hints(&index, &hints),
            vec![unchanged],
            "{source:?}: the leased hint is kept"
        );
    }
}
