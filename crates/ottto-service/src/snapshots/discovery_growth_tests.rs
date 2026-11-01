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
        self.page_at(source, index, &now)
    }
    fn page_at(
        &self,
        source: SnapshotSource,
        mut index: ScanIndex,
        now: &str,
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
                &[],
                false,
                true,
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
        true,
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

/// [money] F3: a known default-home rollout append with no directory move or
/// watcher hint is Tail-read once and emits the same whole money body as Full.
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
    refresh_retained_codex_roster(
        SnapshotSource::Codex,
        index.traversal.as_mut().unwrap(),
        7,
        discovery_retention!(index),
    );
    let traversal = index.traversal.as_ref().unwrap();
    assert_eq!(traversal.counts.codex_roster_growth_enqueued, 1);
    assert_eq!(traversal.pending_candidates.len(), 1);
    assert!(!traversal.pending_candidates[0].census_member);
    // A second refresh before selection cannot duplicate queued work.
    refresh_retained_codex_roster(
        SnapshotSource::Codex,
        index.traversal.as_mut().unwrap(),
        7,
        discovery_retention!(index),
    );
    assert_eq!(
        index
            .traversal
            .as_ref()
            .unwrap()
            .counts
            .codex_roster_growth_enqueued,
        1
    );
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

/// [behaviour] Unchanged bytes and inventory-held growth cannot enqueue or
/// acquire again while their stat/refusal evidence stays unchanged.
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
            f.age(1); // mtime alone cannot grant another acquisition
        }
        for _ in 0..2 {
            refresh_retained_codex_roster(
                SnapshotSource::Codex,
                index.traversal.as_mut().unwrap(),
                7,
                discovery_retention!(index),
            );
            let traversal = index.traversal.as_ref().unwrap();
            assert!(traversal.pending_candidates.is_empty());
            assert_eq!(traversal.counts.codex_roster_growth_enqueued, 0);
        }
        let (_, scan, reads, _) = f.page(SnapshotSource::Codex, index);
        assert!(scan.snapshots.is_empty());
        assert!(reads.0.lock().unwrap().0.is_empty());
    }
}
