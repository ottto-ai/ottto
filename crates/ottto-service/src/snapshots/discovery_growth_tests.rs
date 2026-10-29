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
        let reads = Reads::default();
        let ((index, result), rows) = capture(|| {
            let mut scan = OwnedSourceScan::new(
                source,
                std::slice::from_ref(&self.root),
                index,
                &now,
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
    fn save_and_report(&self, index: &ScanIndex, scan: &SourceScanResult) -> Value {
        let path = self.root.join("index.json");
        let mut checkpoint = index.clone();
        checkpoint.save(&path).unwrap();
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
        crate::snapshot_sync::settle_withheld_for_test(&baseline, parsed, scan.clone());
    assert_eq!(committed.files[&key].size_bytes, committed_size);
    assert!(committed.claude_account_deferred_holds.contains_key(&key));
    let counts = f.save_and_report(&committed, &scan);
    fate(&counts, 0, 1); // a working parse is not a committed catch-up
    assert_eq!(counts["discovery_retained_grown_age"]["gt_90d"], 1);
    for pass in 0..2 {
        let (idle, scan, reads, rows) = f.page(source, committed);
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
        let counts = f.save_and_report(&idle, &scan);
        fate(&counts, 0, 1);
        assert_eq!(counts["discovery_retained_grown_age"]["gt_90d"], 1);
        committed = ScanIndex::load(&f.root.join("index.json")).unwrap();
    }
}

#[test]
fn grown_catchup_reports_committed_only_against_saved_extent() {
    let f = Fixture::new();
    f.append("first");
    let (baseline, _, _, _) = f.page(SnapshotSource::ClaudeCode, ScanIndex::default());
    f.append("second");
    f.age(31);
    let (caught_up, scan, reads, _) = f.page(SnapshotSource::ClaudeCode, baseline);
    assert_eq!(reads.0.lock().unwrap().0, vec![growth_mode()]);
    let counts = f.save_and_report(&caught_up, &scan);
    fate(&counts, 1, 0);
    assert_eq!(
        counts["discovery_retained_grown_age"],
        json!({"le_30d":0,"d31_90":0,"gt_90d":0,"unknown":0})
    );
}

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
        let (next, scan, reads, _) = f.page(source, index);
        assert_eq!(next.files[&key].size_bytes, cap);
        assert!(reads.0.lock().unwrap().0.is_empty());
        assert_eq!(scan.scanned_file_count, 0);
        let counts = f.save_and_report(&next, &scan);
        fate(&counts, 0, 1);
        assert_eq!(counts["discovery_retained_grown_age"]["gt_90d"], 1);
    }
}

/// SOURCE's rewrite control: the same inode is truncated and rewritten past
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
    let (rewritten, scan, reads, _) = f.page(SnapshotSource::ClaudeCode, baseline);
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
    fate(&f.save_and_report(&rewritten, &scan), 1, 0);
}
