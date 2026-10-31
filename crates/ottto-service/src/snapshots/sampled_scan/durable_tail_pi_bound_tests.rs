//! P-ACTIVE-BOUND for Pi (E5 growth-hold audit, Lead A 2026-10-29): Pi
//! enters E1's ONE shared fallback and per-key pace owner. A structural
//! `ActiveOverBudget` is the counted no-record Full under
//! `degraded_no_record{active_bound}`, at most once per key
//! per 6 h; `LeaseBusy` stays a counted fair delay. A full pace map evicting
//! its oldest stamp is the shared owner's (`m3_owed_tests`). This row adds no
//! Pi path: it drives the real OwnedSourceScan over a native Pi receipt and
//! reads the shared owner's slot 2.
use super::*;

const SOURCE: SnapshotSource = SnapshotSource::Pi;
const AT: &str = "2026-10-29T12:00:00Z";

fn pi_row(response: &str, input: u64) -> String {
    serde_json::json!({"type":"message","id":response,"parentId":"a0000000",
        "timestamp":"2026-10-27T07:00:01Z","message":{"role":"assistant",
            "provider":"openai","model":"gpt-5.4","api":"openai-responses",
            "timestamp":"2026-10-27T07:00:01Z","stopReason":"stop",
            "content":[{"type":"text","text":"Synthetic answer."}],"responseId":response,
            "usage":{"input":input,"output":2,"cacheRead":0,"cacheWrite":0,
                "totalTokens":input+2,"cost":{"total":0.001}}}})
    .to_string()
        + "\n"
}

/// One synthetic Pi session, its committed index and the real store beside it.
struct PiBound {
    root: crate::test_scratch::ScratchDir,
    sessions: PathBuf,
    path: PathBuf,
    key: String,
    index_path: PathBuf,
    namespace: Scope,
}
impl PiBound {
    fn new(name: &str) -> Self {
        let root = crate::test_scratch::ScratchDir::new(name);
        test_locks::hold(&root);
        let sessions = root.join("sessions");
        std::fs::create_dir(&sessions).unwrap();
        let path = sessions.join("session.jsonl");
        let header = serde_json::json!({"type":"session","version":3,"id":"synthetic-pi-bound",
            "timestamp":"2026-10-27T06:00:00Z","cwd":"/synthetic/pi-work"})
        .to_string()
            + "\n";
        std::fs::write(&path, header + &pi_row("seed", 10)).unwrap();
        Self {
            key: local_index_key(&path),
            index_path: root.join("index.json"),
            namespace: Scope("pi-active-bound".into()),
            root,
            sessions,
            path,
        }
    }

    fn owner(&self) -> Arc<SharedCache> {
        let cache = Arc::new(SharedCache::default());
        cache.durable_begin_pass(SOURCE, &self.index_path, &self.namespace, true);
        cache
    }

    /// One complete native pass under a 1-day window: (Full, Tail, bytes).
    fn run(
        &self,
        cache: Arc<SharedCache>,
        index: ScanIndex,
    ) -> (ScanIndex, SourceScanResult, (usize, usize, u64)) {
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            SOURCE,
            std::slice::from_ref(&self.sessions),
            index,
            AT,
            1,
            100,
            false,
            None,
            &[],
            false,
            true,
            true,
        )
        .with_sampled_acquisition(cache, self.namespace.clone());
        let mut modes = (0, 0, 0);
        for _ in 0..10_000 {
            if let Some(c) = scan.sampling.as_ref() {
                modes = (c.full_files, c.tail_files, c.native_bytes);
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
            }
        }
        panic!("scan did not finish");
    }

    /// The ACK as the daemon records it, then index save, post-save write and GC.
    fn commit(&self, cache: &SharedCache, index: &mut ScanIndex, scan: &SourceScanResult) {
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect(),
        );
        index.save(&self.index_path).unwrap();
        crate::snapshots::durable_after_save_and_retire(
            cache,
            &self.root,
            SOURCE,
            index,
            &self.index_path,
        );
    }

    /// Warm owner: a native Full that receipts the Pi record, ACKed and saved.
    fn warm(&self) -> (Arc<SharedCache>, ScanIndex) {
        let cache = self.owner();
        let (mut index, mut first, modes) = self.run(cache.clone(), ScanIndex::default());
        assert_eq!(modes.0, 1, "first native Pi acquisition");
        pi_wire(&mut index, &mut first);
        assert_eq!(first.snapshots[0].request_count, 1);
        self.commit(&cache, &mut index, &first);
        assert!(
            !self.disk().is_empty(),
            "native Pi receipt before any bound"
        );
        (cache, index)
    }

    /// Appends one row, then puts the opened source beyond the 1-day window.
    fn grow(&self, response: &str, input: u64) -> u64 {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .unwrap()
            .write_all(pi_row(response, input).as_bytes())
            .unwrap();
        File::open(&self.path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1793059200),
                ),
            )
            .unwrap();
        std::fs::metadata(&self.path).unwrap().len()
    }

    fn disk(&self) -> BTreeMap<PathBuf, (Vec<u8>, Vec<i128>)> {
        store_snapshot(&store::store_dir_for_index(&self.index_path))
    }

    /// An independent cold Full over the same prior index and bytes.
    fn cold_wire(&self, prior: ScanIndex, end: u64) -> Vec<u8> {
        let (mut index, mut cold, modes) = self.run(Arc::new(SharedCache::default()), prior);
        assert_eq!(modes, (1, 0, end), "independent cold Full control");
        pi_wire(&mut index, &mut cold)
    }
}

/// The emitted upload body, through the production policy and finalization.
fn pi_wire(index: &mut ScanIndex, scan: &mut SourceScanResult) -> Vec<u8> {
    index.bind_session_accounts(SOURCE, "pi-bound-machine", &mut scan.snapshots, &[]);
    apply_upload_policy(SOURCE, &mut scan.snapshots, SnapshotUploadPolicy::default());
    finalize_scan_after_policy(SOURCE, scan, index);
    assert!(!scan.snapshots.is_empty());
    let body = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SOURCE.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some("fixture".into()),
        snapshots: scan.snapshots.clone(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    validate_snapshot_batch_request(&body).unwrap();
    serde_json::to_vec(&body).unwrap()
}

fn pi_events<'a>(
    events: &'a [serde_json::Value],
    pointer: &'a str,
) -> impl Iterator<Item = &'a serde_json::Value> + 'a {
    events
        .iter()
        .filter(|e| e["source"] == "pi")
        .filter_map(move |e| e.pointer(pointer))
}

// The file grows past the active bound, then idles past the 1-day window:
// exactly one counted read + publish (no record, store byte-identical, the
// source alarm), nothing pruned. A second growth inside 6 h is a counted delay
// that keeps the old committed size; the next paced read publishes it.
/// [format] Unfundable Pi growth keeps its predecessor and paces native fallback.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native decode layout")]
fn pi_structural_growth_paced_no_record_publish_and_no_prune() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let _reset = ResetActiveBudget;
    let f = PiBound::new("pi-structural-growth");
    let (cache, index) = f.warm();
    cache.retained().unwrap().clear();
    let original_disk = f.disk();
    let end = f.grow("growth-1", 20);
    let now = std::time::SystemTime::now();
    cache.durable().unwrap().retail_full_now = Some(now);
    let records_read = cache.durable_counters(SOURCE).unwrap().1.records_read;
    store::active::set_active_budget_for_test(Some(
        crate::snapshots::sampled_scan::transition_fixture::structural_active_budget(&f.key),
    ));
    let prior = index.clone();
    let (((mut next, mut caught, modes), reads), events) =
        crate::local_resource_diagnostics::capture(|| a0h_observe(|| f.run(cache.clone(), index)));
    assert_eq!(modes, (1, 0, end), "exactly one counted Full");
    assert_eq!(reads.1, end, "actual single Full input extent");
    assert_eq!(
        cache.durable_counters(SOURCE).unwrap().1.records_read - records_read,
        1,
        "the record was reached and refused at decode, not missing"
    );
    assert_eq!(caught.snapshots.len(), 1, "published");
    assert_eq!(caught.snapshots[0].request_count, 2, "cumulative, once");
    assert_eq!(next.files[&f.key].size_bytes, end, "paced read commits");
    assert!(
        cache.retained().unwrap().peek(&f.key).is_none(),
        "no-record publication retains no optional graph"
    );
    assert_eq!(f.disk(), original_disk, "no record written or removed");
    {
        let counters = &cache.durable().unwrap().counters;
        assert_eq!(counters.active_bound[2], [1, 0], "one structural Full");
        assert_eq!(
            (counters.active_bound[0], counters.active_bound[1]),
            ([0, 0], [0, 0])
        );
        assert_eq!(counters.pace_evicted[2], 0);
    }
    assert!(
        pi_events(&events, "/counts/degraded_no_record/active_bound")
            .any(|v| v == &serde_json::json!([1, 1])),
        "existing named exception alarm, source=pi"
    );
    assert!(pi_events(
        &events,
        "/counts/full_reads/degraded_no_record/active_bound"
    )
    .any(|v| v == &serde_json::json!(1)));
    let evictions = pi_events(&events, "/counts/pace_evicted").collect::<Vec<_>>();
    assert!(evictions.is_empty());
    let actual = pi_wire(&mut next, &mut caught);
    assert_eq!(
        actual,
        f.cold_wire(prior, end),
        "whole body equals cold Full"
    );
    f.commit(&cache, &mut next, &caught);
    let mut index = next;

    let grown = f.grow("growth-2", 30);
    let entry = serde_json::to_value(&index.files[&f.key]).unwrap();
    for pass in 0..2 {
        let (((held, output, modes), reads), events) =
            crate::local_resource_diagnostics::capture(|| {
                a0h_observe(|| f.run(cache.clone(), index))
            });
        assert!(
            output.snapshots.is_empty(),
            "{pass}: delayed, not published"
        );
        assert_eq!(modes, (0, 0, 0), "{pass}");
        assert_eq!(reads.1, 0, "{pass}");
        assert_eq!(
            serde_json::to_value(&held.files[&f.key]).unwrap(),
            entry,
            "{pass}: entry kept with its old size, never pruned"
        );
        assert_eq!(output.oversized_file_count, 0);
        assert!(
            pi_events(&events, "/counts/active_bound_delay/active_bound")
                .any(|v| v == &serde_json::json!([1, pass + 1])),
            "{pass}: counted delay"
        );
        index = held;
    }
    assert_eq!(cache.durable().unwrap().counters.active_bound[2], [1, 2]);
    cache.durable().unwrap().retail_full_now =
        Some(now + std::time::Duration::from_secs(PACE_SECS));
    let prior = index.clone();
    let (mut caught_index, mut caught, modes) = f.run(cache.clone(), index);
    assert_eq!(modes, (1, 0, grown), "the next paced read");
    assert_eq!(caught.snapshots[0].request_count, 3);
    assert_eq!(caught_index.files[&f.key].size_bytes, grown);
    assert_eq!(cache.durable().unwrap().counters.active_bound[2], [2, 2]);
    let actual = pi_wire(&mut caught_index, &mut caught);
    assert_eq!(actual, f.cold_wire(prior, grown));
    f.commit(&cache, &mut caught_index, &caught);
    drop(cache);
    let (_, idle, modes) = f.run(f.owner(), ScanIndex::load(&f.index_path).unwrap());
    assert!(idle.snapshots.is_empty(), "no duplicate publication");
    // Nothing is owed after catch-up, so ordinary quiet-file retirement of
    // the aged entry is safe; the contract here is no reacquisition.
    assert_eq!(modes, (0, 0, 0), "restart reacquires nothing");
}
