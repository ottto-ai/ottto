// Synthetic real-scan admission and native parse/finalize memory receipts.
// Each memory case runs alone in a fresh process; fixture generation happens
// in the parent. Measurements report observations, never establish a budget.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const MIB: u64 = 1024 * 1024;
const SESSION: &str = "019e2700-5555-7000-9000-555555555555";
const AT: &str = "2026-10-27T08:00:00Z";
const RECEIPT: &str = "claude_cap_memory_receipt: ";
const TEST: &str = "snapshots::tests::claude_file_cap_tests::large_claude_native_memory_and_append";
const CHILD: &str = "OTTTO_CLAUDE_CAP_MEMORY_CHILD";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        Self(temp_dir("claude-file-cap"))
    }
    fn path(&self) -> PathBuf {
        self.0.join(format!("{SESSION}.jsonl"))
    }
    fn scan(&self, source: SnapshotSource, index: &mut ScanIndex, hour: u8) -> SourceScanResult {
        scan_source_roots_with_limit(
            source,
            std::slice::from_ref(&self.0),
            index,
            &format!("2026-10-27T{hour:02}:00:00Z"),
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            false,
        )
        .expect("native scan")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn usage(n: u64) -> Value {
    json!({"type":"assistant","sessionId":SESSION,"uuid":format!("assistant-{n}"),
        "timestamp":AT,"requestId":format!("req-{n}"),
        "message":{"id":format!("msg-{n}"),"role":"assistant",
        "model":if n % 2 == 0 {"claude-sonnet-4-6"} else {"claude-opus-4-6"},
        "content":[{"type":"text","text":"Synthetic analysis of a test fixture."},
        {"type":"tool_use","id":format!("tool-{n}"),"name":"Read","input":{"file_path":"fixture.txt"}}],
        "usage":{"input_tokens":100,"output_tokens":10,"cache_read_input_tokens":20,"cache_creation_input_tokens":0}}})
}
fn write_row(writer: &mut impl Write, value: &Value) -> u64 {
    let bytes = serde_json::to_vec(value).unwrap();
    writer.write_all(&bytes).unwrap();
    writer.write_all(b"\n").unwrap();
    bytes.len() as u64 + 1
}
// Every ~9 KiB contains a unique usage-bearing response, text, and a tool
// result. Both sizes stay below the existing 65,536 response-record cap.
fn write_mixed(fixture: &Fixture, target: u64) -> (u64, u64) {
    let mut writer = BufWriter::new(File::create(fixture.path()).unwrap());
    let mut bytes = write_row(
        &mut writer,
        &json!({"type":"user","sessionId":SESSION,
        "timestamp":AT,"message":{"role":"user","content":"Synthetic large session"}}),
    );
    let padding = "Synthetic tool output and text. ".repeat(256);
    let mut requests = 0;
    while bytes < target {
        bytes += write_row(&mut writer, &usage(requests));
        bytes += write_row(
            &mut writer,
            &json!({"type":"user","sessionId":SESSION,
            "uuid":format!("user-{requests}"),"timestamp":AT,
            "message":{"role":"user","content":[{"type":"tool_result",
            "tool_use_id":format!("tool-{requests}"),"content":padding}]}}),
        );
        requests += 1;
    }
    writer.flush().unwrap();
    assert!(requests < MAX_CLAUDE_RESPONSE_RECORDS_PER_FILE as u64);
    assert_eq!(fs::metadata(fixture.path()).unwrap().len(), bytes);
    (bytes, requests)
}
fn assert_native(scan: &SourceScanResult, requests: u64) {
    assert_eq!(scan.oversized_file_count, 0);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(scan.malformed_json_line_count, 0);
    assert_eq!(scan.over_line_cap_count, 0);
    assert_eq!(scan.dropped_usage_record_count, 0);
    assert!(scan.census_complete);
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].request_count, requests);
    assert_eq!(scan.snapshots[0].input_tokens, requests * 100);
    assert_eq!(scan.snapshots[0].output_tokens, requests * 10);
    assert_eq!(scan.snapshots[0].cache_read_tokens, requests * 20);
}

#[test]
fn oversized_claude_shrink_then_grow_keeps_unread_content_unproven() {
    let fixture = Fixture::new();
    let path = fixture.path();
    let mut file = File::create(&path).unwrap();
    let valid_size = write_row(&mut file, &usage(0));
    file.set_len(MAX_JSONL_FILE_BYTES + 1).unwrap();
    drop(file);
    let key = local_index_key(&path);
    let mut index = ScanIndex::default();
    let skipped = fixture.scan(SnapshotSource::ClaudeCode, &mut index, 9);
    assert_eq!(skipped.oversized_file_count, 1);
    assert_eq!(skipped.scanned_file_count, 0);
    assert!(skipped.snapshots.is_empty());
    assert!(!skipped.census_complete);
    assert!(
        !index.files.contains_key(&key),
        "no proof before native read"
    );
    assert!(!index.file_snapshot_fingerprints.contains_key(&key));

    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(valid_size)
        .unwrap();
    let mut admitted = fixture.scan(SnapshotSource::ClaudeCode, &mut index, 11);
    assert_native(&admitted, 1);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut admitted, &mut index);
    let prior = index.files[&key].source_file_fingerprint.clone();
    assert!(!prior.is_empty());

    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_JSONL_FILE_BYTES + 1)
        .unwrap();
    let grown = fixture.scan(SnapshotSource::ClaudeCode, &mut index, 13);
    assert_eq!(grown.oversized_file_count, 1);
    assert_eq!(grown.scanned_file_count, 0);
    assert!(grown.snapshots.is_empty());
    assert!(!grown.census_complete);
    assert_eq!(
        index.files[&key].source_file_fingerprint, prior,
        "oversized content cannot replace prior read authority"
    );

    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(valid_size)
        .unwrap();
    assert_native(&fixture.scan(SnapshotSource::ClaudeCode, &mut index, 15), 1);
}

#[test]
fn each_source_admits_its_exact_file_cap_and_refuses_one_more_byte() {
    for (source, limit) in [
        (SnapshotSource::ClaudeCode, 1024 * MIB),
        (SnapshotSource::Pi, 256 * MIB),
        (SnapshotSource::Codex, 2048 * MIB),
    ] {
        let fixture = Fixture::new();
        let file = File::create(fixture.path()).unwrap();
        for (bytes, admitted) in [(limit, true), (limit + 1, false)] {
            file.set_len(bytes).unwrap();
            let mut census = ScanCensus::default();
            let candidate = candidate_from_traversal_path(
                source,
                ScanTraversalPath {
                    scan_root: fixture.0.clone(),
                    path: fixture.path(),
                    census_member: true,
                    watcher_hint: false,
                },
                &mut census,
                None,
                BACKFILL_WINDOW_DAYS,
                &BTreeMap::new(),
            );
            assert_eq!(candidate.is_some(), admitted, "{source:?} at {bytes}");
            assert_eq!(census.oversized_file_count, usize::from(!admitted));
            if let Some(candidate) = candidate {
                assert_eq!(candidate.size_bytes, limit);
            }
        }
    }
    assert_eq!(MAX_JSONL_LINE_BYTES, 16 * 1024 * 1024);
}

#[test]
fn pi_still_refuses_above_256_mib() {
    let fixture = Fixture::new();
    File::create(fixture.path())
        .unwrap()
        .set_len(256 * MIB + 1)
        .unwrap();
    let mut index = ScanIndex::default();
    let scan = fixture.scan(SnapshotSource::Pi, &mut index, 9);
    assert_eq!(scan.oversized_file_count, 1);
    assert_eq!(scan.scanned_file_count, 0);
    assert!(scan.snapshots.is_empty());
    assert!(!scan.census_complete);
    assert!(index.files.is_empty());
}

fn peak_rss() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the complete rusage on success.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    let native = u64::try_from(usage.ru_maxrss).unwrap();
    if cfg!(target_os = "macos") {
        native
    } else {
        native * 1024
    }
}

// Same Darwin TASK_VM_INFO rev3 layout used by the existing E2 benchmark.
#[cfg(target_os = "macos")]
fn footprint() -> (u64, u64) {
    #[repr(C)]
    #[derive(Default)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        resident_size_peak: u64,
        device: u64,
        device_peak: u64,
        internal: u64,
        internal_peak: u64,
        external: u64,
        external_peak: u64,
        reusable: u64,
        reusable_peak: u64,
        purgeable_volatile_pmap: u64,
        purgeable_volatile_resident: u64,
        purgeable_volatile_virtual: u64,
        compressed: u64,
        compressed_peak: u64,
        compressed_lifetime: u64,
        phys_footprint: u64,
        min_address: u64,
        max_address: u64,
        ledger_phys_footprint_peak: i64,
        ledger_rest: [i64; 20],
    }
    extern "C" {
        static mach_task_self_: u32;
        fn task_info(task: u32, flavor: u32, info: *mut i32, count: *mut u32) -> i32;
    }
    let mut vm = TaskVmInfo::default();
    let mut count = (std::mem::size_of::<TaskVmInfo>() / 4) as u32;
    // SAFETY: TASK_VM_INFO (22) fills at most count words in this rev3 buffer.
    assert_eq!(
        unsafe {
            task_info(
                mach_task_self_,
                22,
                (&mut vm as *mut TaskVmInfo).cast(),
                &mut count,
            )
        },
        0
    );
    assert_eq!(count, (std::mem::size_of::<TaskVmInfo>() / 4) as u32);
    assert!(vm.ledger_phys_footprint_peak > 0);
    (vm.phys_footprint, vm.ledger_phys_footprint_peak as u64)
}
#[cfg(not(target_os = "macos"))]
fn footprint() -> (u64, u64) {
    (0, 0)
}

fn measured_child(root: PathBuf, requests: u64, bytes: u64) {
    // The parent owns cleanup. Deliberately avoid Fixture's destructor here.
    let fixture = std::mem::ManuallyDrop::new(Fixture(root));
    assert_eq!(fs::metadata(fixture.path()).unwrap().len(), bytes);
    let before = footprint();
    let mut index = ScanIndex::default();
    let mut scan = fixture.scan(SnapshotSource::ClaudeCode, &mut index, 9);
    assert_native(&scan, requests);
    let after = footprint();
    let rss = peak_rss();
    println!(
        "\n{RECEIPT}{}",
        json!({
            "fixture_bytes":bytes,"requests":requests,"platform":std::env::consts::OS,
            "rustc":env!("OTTTO_SCAN_LAYOUT_RUSTC"),
            "phys_footprint_before_bytes":before.0,"phys_footprint_after_bytes":after.0,
            "phys_footprint_peak_bytes":after.1,"peak_rss_bytes":rss,
            "native_parse_and_finalize":true,"artifacts_enabled":false,"curve_enabled":true,
            "request_identity_capture":claude_request_identity::capture_by_default()
        })
    );
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    drop(scan);
    if bytes > 256 * MIB {
        // ctime-only metadata changes do not select another native read.
        let path = fixture.path();
        let mtime = fs::metadata(&path).unwrap().modified().unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
        let (idle, reads) = terminal_contract_retry::source_acquisitions(|| {
            fixture.scan(SnapshotSource::ClaudeCode, &mut index, 10)
        });
        assert_eq!(idle.scanned_file_count, 0);
        assert!(reads.is_empty());
        let mut file = File::options().append(true).open(path).unwrap();
        write_row(&mut file, &usage(requests));
        drop(file);
        let (append, reads) = terminal_contract_retry::source_acquisitions(|| {
            fixture.scan(SnapshotSource::ClaudeCode, &mut index, 11)
        });
        assert_native(&append, requests + 1);
        assert_eq!(reads.values().sum::<usize>(), 1);
    }
}

#[test]
fn large_claude_native_memory_and_append() {
    if let Some(root) = std::env::var_os(CHILD) {
        measured_child(
            root.into(),
            std::env::var("OTTTO_CLAUDE_CAP_REQUESTS")
                .unwrap()
                .parse()
                .unwrap(),
            std::env::var("OTTTO_CLAUDE_CAP_BYTES")
                .unwrap()
                .parse()
                .unwrap(),
        );
        return;
    }
    let mut receipts = Vec::new();
    for mib in [200, 400] {
        let fixture = Fixture::new();
        let (bytes, requests) = write_mixed(&fixture, mib * MIB);
        assert!(bytes >= mib * MIB && bytes < (mib + 1) * MIB);
        let child = Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, &fixture.0)
            .env("OTTTO_CLAUDE_CAP_REQUESTS", requests.to_string())
            .env("OTTTO_CLAUDE_CAP_BYTES", bytes.to_string())
            .output()
            .unwrap();
        let stdout = String::from_utf8(child.stdout).unwrap();
        assert!(
            child.status.success(),
            "memory child failed: {stdout}\n{}",
            String::from_utf8_lossy(&child.stderr)
        );
        let lines = stdout
            .lines()
            .filter_map(|line| line.strip_prefix(RECEIPT))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "one actual native measurement per child");
        println!("{RECEIPT}{}", lines[0]);
        receipts.push(serde_json::from_str::<Value>(lines[0]).unwrap());
    }
    let delta = |key: &str| {
        receipts[1][key].as_u64().unwrap() as i64 - receipts[0][key].as_u64().unwrap() as i64
    };
    println!(
        "claude_cap_memory_delta: {}",
        json!({
        "control_mib":200,"large_mib":400,
        "phys_footprint_peak_delta_bytes":delta("phys_footprint_peak_bytes"),
        "peak_rss_delta_bytes":delta("peak_rss_bytes"),
        "no_resource_budget_inferred":true})
    );
}

// Drive the shipping cooperative scheduler with native scan frames, not a
// reimplementation of candidate selection or a mocked parser. Refused parking
// models an opaque/unaccountable frame; it grants no substitute positive bound.
#[derive(Default)]
struct HistoryReceipt {
    turn_ticks: std::cell::Cell<u64>,
    visits_peak: usize,
    bytes_peak: usize,
    owed_seen: u64,
    budget_held: u64,
}

struct Rotation {
    ready: Vec<(SnapshotSource, OwnedSourceScan)>,
    completed: Vec<(SnapshotSource, ScanIndex, SourceScanResult)>,
    starts: Vec<(PathBuf, Option<crate::transcript_acquisition::ReadMode>)>,
    refuse_parking: bool,
    refusals: std::cell::Cell<usize>,
    deferred_revocations: usize,
    history_receipt: Option<HistoryReceipt>,
    started: std::time::Instant,
}
impl crate::source_rotation::Owner for Rotation {
    type Source = SnapshotSource;
    type Frame = OwnedSourceScan;
    type Completed = (SnapshotSource, ScanIndex, SourceScanResult);
    fn prepare(
        &mut self,
        source: SnapshotSource,
        _: Option<usize>,
    ) -> anyhow::Result<Option<Self::Frame>> {
        Ok(self
            .ready
            .iter()
            .position(|(s, _)| *s == source)
            .map(|at| self.ready.remove(at).1))
    }
    fn validate(&mut self, _: &Self::Frame) -> anyhow::Result<()> {
        Ok(())
    }
    fn step(
        &mut self,
        mut frame: Self::Frame,
        _: Option<usize>,
    ) -> crate::source_rotation::Step<Self::Frame, Self::Completed> {
        if let Some(receipt) = self.history_receipt.as_mut() {
            #[cfg(target_os = "macos")]
            assert!(
                crate::heap_layout_bound::layout_supported(),
                "native layout receipt required"
            );
            // Production accounting rejects Linux layouts. The native positive
            // receipt must be measured on the validated macOS toolchain; Linux
            // still executes every scheduling/revision/debt assertion below.
            if crate::heap_layout_bound::layout_supported() {
                use crate::heap_layout_bound::{Counter, HeapLayoutBound};
                let mut counter = Counter::new(crate::source_rotation::PARKED_BUDGET);
                let measured = counter
                    .add(std::mem::size_of_val(&frame))
                    .and_then(|()| frame.heap_bound(&mut counter));
                assert!(measured.is_some(),
                    "combined history/large-Full frame must fit existing bytes and visits: bytes={} visits={}",
                    counter.bytes, counter.visits_for_test());
                receipt.visits_peak = receipt.visits_peak.max(counter.visits_for_test());
                receipt.bytes_peak = receipt.bytes_peak.max(counter.bytes);
            }
            receipt.owed_seen = receipt.owed_seen.max(frame.history_upgrade.owed);
            receipt.budget_held = receipt
                .budget_held
                .max(frame.history_upgrade.denied_for(&[HistoryHold::Budget]));
        }
        if frame.native_comparison_ready() {
            for key in &frame.index.claude_large_full_deferred {
                assert!(
                    !frame
                        .native_comparison
                        .as_ref()
                        .unwrap()
                        .has_skip_for_test(key),
                    "a deferred file earns no actual unchanged-proof skip"
                );
            }
            let api = BTreeMap::new();
            let trace = BTreeMap::new();
            let healthy_roots = BTreeSet::new();
            let qualification =
                frame.prepare_native_comparison(claude_native_comparison::PairedRows {
                    api: &api,
                    trace: &trace,
                    healthy_roots: &healthy_roots,
                });
            let window = claude_native_comparison::Controller::new(qualification)
                .into_window(&frame.census_window_end)
                .expect("ordinary native window");
            for key in &frame.index.claude_large_full_deferred {
                let (root, _) = claude_index_path_family_member(Path::new(key)).unwrap();
                assert!(
                    window.root_revoked_for_test(&root),
                    "deferral cannot revive old native-comparison eligibility"
                );
                self.deferred_revocations += 1;
            }
        }
        if let Some(active) = frame.active_file.as_deref() {
            if active.parser.source_read_probe.is_some() {
                self.starts.push((
                    active.candidate.path.clone(),
                    active.sampling.as_ref().map(|a| a.mode),
                ));
            }
        }
        let source = frame.source;
        match frame.step(None) {
            OwnedSourceScanStep::Pending(next) => crate::source_rotation::Step::Pending(next),
            OwnedSourceScanStep::Complete { index, scan, .. } => {
                crate::source_rotation::Step::Complete((source, index, scan))
            }
        }
    }
    fn bound(&self, frame: &Self::Frame, limit: usize) -> Option<usize> {
        if self.refuse_parking {
            self.refusals.set(self.refusals.get() + 1);
            None
        } else {
            crate::heap_layout_bound::bound(frame, limit)
        }
    }
    fn finish(&mut self, completed: Self::Completed, _: Option<usize>) -> anyhow::Result<()> {
        self.completed.push(completed);
        Ok(())
    }
    fn outcome(&mut self, _: SnapshotSource, result: anyhow::Result<()>) {
        result.unwrap();
    }
    fn monotonic(&self) -> std::time::Duration {
        if let Some(receipt) = self.history_receipt.as_ref() {
            // A deterministic owner clock exercises parking on quiet walks
            // too, without changing the scheduler's shipping turn budget.
            let tick = receipt.turn_ticks.get() + 1;
            receipt.turn_ticks.set(tick);
            return std::time::Duration::from_secs(tick);
        }
        self.started.elapsed()
    }
}
fn rotation_scan(
    source: SnapshotSource,
    root: &Path,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
    hints: &[PathBuf],
) -> OwnedSourceScan {
    let mut scan = OwnedSourceScan::new(
        source,
        &[root.to_owned()],
        index,
        "2026-10-27T12:00:00Z",
        BACKFILL_WINDOW_DAYS,
        MAX_BACKFILL_FILES_PER_SOURCE,
        false,
        None,
        hints,
        false,
        true,
    )
    .with_sampled_acquisition(
        Arc::clone(cache),
        crate::transcript_acquisition::Scope("large-full-scheduler".into()),
    );
    scan.enable_native_comparison();
    scan
}
fn write_populated_large(path: &Path, session: &str) {
    let mut out = BufWriter::new(File::create(path).unwrap());
    let mut first = usage(0);
    first["sessionId"] = json!(session);
    first["requestId"] = json!(format!("req-{session}"));
    first["message"]["id"] = json!(format!("msg-{session}"));
    write_row(&mut out, &first);
    // Actual JSON/text bytes, no sparse holes or invalid-zero padding. Keep
    // the existing memory test's denser unique-request workload separately.
    let mut row = serde_json::to_vec(&json!({"type":"user","sessionId":session,
        "timestamp":AT,"message":{"role":"user","content":[{"type":"tool_result",
        "tool_use_id":"tool-0","content":"Synthetic tool output. ".repeat(49152)}]}}))
    .unwrap();
    row.push(b'\n');
    let mut bytes = first.to_string().len() as u64 + 1;
    while bytes <= 256 * MIB {
        out.write_all(&row).unwrap();
        bytes += row.len() as u64;
    }
    out.flush().unwrap();
    assert!(bytes > 256 * MIB && bytes < 258 * MIB);
    assert_eq!(fs::metadata(path).unwrap().len(), bytes);
}
fn write_pi_progress(root: &Path, pass: usize) -> PathBuf {
    let path = root.join(format!("pi-{pass}.jsonl"));
    let mut out = File::create(&path).unwrap();
    write_row(
        &mut out,
        &json!({"type":"session","id":format!("sibling-{pass}"),"timestamp":AT}),
    );
    write_row(
        &mut out,
        &json!({"type":"message","id":format!("message-{pass}"),"timestamp":AT,
        "message":{"role":"assistant","model":"gpt-5.4","provider":"openai","api":"responses",
        "content":[{"type":"text","text":"Synthetic sibling progress"}],"usage":{"input":12,"output":4}}}),
    );
    path
}

#[test]
fn large_claude_fulls_rotate_with_sibling_and_audits() {
    use crate::transcript_acquisition::{FullReason, ReadMode};
    let claude = Fixture::new();
    let pi = Fixture::new();
    let large = (0..3)
        .map(|n| {
            let session = format!("019e2700-5555-7000-9000-{n:012}");
            let path = claude.0.join(format!("{session}.jsonl"));
            write_populated_large(&path, &session);
            path
        })
        .collect::<Vec<_>>();
    // These small files must all pass in the same initial pass, even after
    // the large Full allowance has been spent.
    let small = (3..6)
        .map(|n| {
            let session = format!("019e2700-5555-7000-9000-{n:012}");
            let path = claude.0.join(format!("{session}.jsonl"));
            let mut row = usage(n);
            row["sessionId"] = json!(session);
            fs::write(&path, format!("{row}\n")).unwrap();
            path
        })
        .collect::<Vec<_>>();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut index = ScanIndex::default();
    let mut pi_index = ScanIndex::default();
    let mut read = BTreeSet::new();
    let mut first_audit = None;
    // Three first-admission passes, then three overdue-audit passes. Re-owe
    // the first audit immediately and hint it: oldest deferrals still win.
    for pass in 0..7 {
        if pass == 3 {
            assert_eq!(read.len(), 3);
            for path in &large {
                index
                    .files
                    .get_mut(&local_index_key(path))
                    .unwrap()
                    .set_unverified_deadline(1);
            }
            read.clear();
        }
        if pass == 4 {
            // A forced fresh walk (including oversized periodic recovery)
            // must preserve older deferrals ahead of the newly re-owed audit.
            index.traversal = None;
        }
        let hints = first_audit.iter().cloned().collect::<Vec<_>>();
        let pi_path = write_pi_progress(&pi.0, pass);
        let mut owner = Rotation {
            ready: vec![
                (
                    SnapshotSource::ClaudeCode,
                    rotation_scan(
                        SnapshotSource::ClaudeCode,
                        &claude.0,
                        std::mem::take(&mut index),
                        &cache,
                        &hints,
                    ),
                ),
                (
                    SnapshotSource::Pi,
                    rotation_scan(
                        SnapshotSource::Pi,
                        &pi.0,
                        std::mem::take(&mut pi_index),
                        &cache,
                        &[],
                    ),
                ),
            ],
            completed: Vec::new(),
            starts: Vec::new(),
            // Exercise both ordinary bounded rotation and serial fallback.
            refuse_parking: pass % 2 == 1,
            refusals: std::cell::Cell::new(0),
            deferred_revocations: 0,
            history_receipt: None,
            started: std::time::Instant::now(),
        };
        let (_, acquisitions) = terminal_contract_retry::source_acquisitions(|| {
            crate::source_rotation::run(
                &mut owner,
                &[SnapshotSource::ClaudeCode, SnapshotSource::Pi],
                crate::source_rotation::PARKED_BUDGET,
            );
        });
        assert_eq!(owner.completed.len(), 2, "both sources finish pass {pass}");
        assert_eq!(
            owner.deferred_revocations,
            [2, 1, 0, 2, 2, 1, 0][pass],
            "unread deferred roots retain BASE negative revocations"
        );
        if owner.refuse_parking {
            assert!(
                owner.refusals.get() > 0,
                "real scheduler attempted and refused parking"
            );
        }
        let starts = owner
            .starts
            .iter()
            .filter(|(path, _)| large.contains(path))
            .collect::<Vec<_>>();
        assert_eq!(starts.len(), 1, "exactly one large read in pass {pass}");
        let (path, mode) = starts[0];
        assert!(matches!(mode, Some(ReadMode::Full(_))));
        if pass >= 3 {
            assert_eq!(*mode, Some(ReadMode::Full(FullReason::AuditDue)));
        }
        if pass == 3 {
            first_audit = Some(path.clone());
        }
        if pass < 6 {
            assert!(
                read.insert(path.clone()),
                "oldest deferral wins over newly hinted audit in pass {pass}"
            );
        }
        assert_eq!(acquisitions.get(path), Some(&1));
        assert_eq!(
            acquisitions.get(&pi_path),
            Some(&1),
            "Pi progresses on every pass"
        );
        for (source, mut next_index, mut scan) in owner.completed {
            if source == SnapshotSource::ClaudeCode {
                assert_eq!(scan.oversized_file_count, 0);
                assert_eq!(scan.scanned_file_count, if pass == 0 { 4 } else { 1 });
                for deferred in large.iter().filter(|p| !read.contains(*p)) {
                    let key = local_index_key(deferred);
                    if pass < 3 {
                        assert!(
                            !next_index.files.contains_key(&key),
                            "deferred admission has no proof"
                        );
                        assert!(!next_index.file_snapshot_fingerprints.contains_key(&key));
                    } else if pass < 6 {
                        assert!(
                            next_index.files[&key].audit_requires_full(sampled_scan::now_seconds()),
                            "unread audit debt survives"
                        );
                    }
                    if pass < 2 || (3..6).contains(&pass) {
                        assert!(!acquisitions.contains_key(deferred));
                    }
                }
                if pass == 0 {
                    for path in &small {
                        assert_eq!(acquisitions.get(path), Some(&1));
                    }
                }
                if matches!(pass, 0 | 1 | 3 | 4 | 5) {
                    assert!(!scan.census_complete);
                    assert!(scan.scan_cap_hit);
                    assert!(
                        scan.skipped_file_count_due_to_limit > 0,
                        "debt stays visible"
                    );
                }
                finalize_scan_after_policy(source, &mut scan, &mut next_index);
                // Exercise the same persisted scheduling order after restart.
                index = lenient_decode::read(
                    std::io::Cursor::new(serde_json::to_vec(&next_index).unwrap()),
                    "load",
                    "claude_code",
                )
                .unwrap();
            } else {
                assert_eq!(source, SnapshotSource::Pi);
                assert_eq!(scan.scanned_file_count, 1);
                assert_eq!(scan.snapshots.len(), 1);
                assert_eq!(scan.snapshots[0].input_tokens, 12);
                finalize_scan_after_policy(source, &mut scan, &mut next_index);
                pi_index = next_index;
            }
        }
        if pass == 3 {
            index
                .files
                .get_mut(&local_index_key(first_audit.as_ref().unwrap()))
                .unwrap()
                .set_unverified_deadline(1);
        }
        println!("claude_large_full_scheduler_receipt: pass={pass} large_fulls=1 pi_reads=1 parking_refused={}", owner.refusals.get() > 0);
    }
}

#[test]
fn overflow_and_decode_fallback_eventually_read_every_large_file() {
    let fixture = Fixture::new();
    let large = (0..3)
        .map(|n| {
            let session = format!("019e2700-6666-7000-9000-{n:012}");
            let path = fixture.0.join(format!("{session}.jsonl"));
            write_populated_large(&path, &session);
            path
        })
        .collect::<Vec<_>>();
    for damaged in [false, true] {
        let mut index = ScanIndex::default();
        for n in 0..=claude_large_full::MAX_KEYS {
            index
                .claude_large_full_deferred
                .push_back(local_index_key(&fixture.0.join(format!("stale-{n}.jsonl"))));
        }
        assert!(index.claude_large_full_deferred.overflowing());
        let mut stored = serde_json::to_value(&index).unwrap();
        if damaged {
            stored["claude_large_full_deferred"] =
                json!({"keys":["x".repeat(claude_large_full::MAX_BYTES+1)]});
        }
        index = lenient_decode::read(
            std::io::Cursor::new(serde_json::to_vec(&stored).unwrap()),
            "load",
            "claude_code",
        )
        .unwrap();
        assert!(index.claude_large_full_deferred.overflowing());
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut read = BTreeSet::new();
        let mut hot = None;
        for pass in 0..3 {
            let hints = hot.iter().cloned().collect::<Vec<_>>();
            let mut owner = Rotation {
                ready: vec![(
                    SnapshotSource::ClaudeCode,
                    rotation_scan(
                        SnapshotSource::ClaudeCode,
                        &fixture.0,
                        std::mem::take(&mut index),
                        &cache,
                        &hints,
                    ),
                )],
                completed: Vec::new(),
                starts: Vec::new(),
                refuse_parking: true,
                refusals: std::cell::Cell::new(0),
                deferred_revocations: 0,
                history_receipt: None,
                started: std::time::Instant::now(),
            };
            let (_, acquisitions) = terminal_contract_retry::source_acquisitions(|| {
                crate::source_rotation::run(
                    &mut owner,
                    &[SnapshotSource::ClaudeCode],
                    crate::source_rotation::PARKED_BUDGET,
                );
            });
            let starts = owner
                .starts
                .iter()
                .filter(|(path, _)| large.contains(path))
                .collect::<Vec<_>>();
            assert_eq!(
                starts.len(),
                1,
                "one native large Full, damaged={damaged} pass={pass}"
            );
            let (path, mode) = starts[0];
            assert!(matches!(
                mode,
                Some(crate::transcript_acquisition::ReadMode::Full(_))
            ));
            assert!(
                read.insert(path.clone()),
                "a hot audit cannot starve overflow debt"
            );
            assert_eq!(acquisitions.get(path), Some(&1));
            if hot.is_none() {
                hot = Some(path.clone());
            }
            let (source, mut next, mut scan) = owner.completed.pop().unwrap();
            assert_eq!(scan.scanned_file_count, 1);
            for unread in large.iter().filter(|path| !read.contains(*path)) {
                let key = local_index_key(unread);
                assert!(
                    !next.files.contains_key(&key),
                    "unread overflow has no index/proof"
                );
                assert!(!next.file_snapshot_fingerprints.contains_key(&key));
                assert!(!acquisitions.contains_key(unread));
            }
            if pass < 2 {
                assert!(!scan.census_complete);
                assert!(scan.scan_cap_hit);
                assert!(scan.skipped_file_count_due_to_limit > 0);
            }
            finalize_scan_after_policy(source, &mut scan, &mut next);
            next.files
                .get_mut(&local_index_key(hot.as_ref().unwrap()))
                .unwrap()
                .set_unverified_deadline(1);
            index = lenient_decode::read(
                std::io::Cursor::new(serde_json::to_vec(&next).unwrap()),
                "load",
                "claude_code",
            )
            .unwrap();
            assert!(
                index.claude_large_full_deferred.is_empty(),
                "overflow priority does not accumulate keys"
            );
            println!("claude_large_full_overflow_receipt: damaged={damaged} pass={pass} large_fulls=1 read={}",read.len());
        }
        assert_eq!(read.len(), 3);
    }
}

// Shipping revision-3 history policy and the real 1 GiB history page budget:
// four populated >256 MiB files cannot all reserve on one page. Both gates
// must compose without granting a deferred file a revision, blocking small
// files, or losing the switch-on re-read when the census walk closes.
#[test]
fn large_history_upgrade_is_paced_and_owed_history_drains() {
    use crate::transcript_acquisition::ReadMode;
    use claude_reemission_exclusions::ReemissionExclusions;
    assert!(claude_request_money::e2::enabled());
    assert_eq!(claude_history_upgrade::max_gated_claude_revision(), 3);
    assert_eq!(body_witness_adoption_byte_budget(), 1024 * MIB);
    let fixture = Fixture::new();
    let pi = Fixture::new();
    let support = Fixture::new();
    let list = ReemissionExclusions::path(&support.0);
    fs::create_dir_all(list.parent().unwrap()).unwrap();
    fs::write(&list, "").unwrap();
    let large = (0..4)
        .map(|n| {
            let session = format!("019e2700-7777-7000-9000-{n:012}");
            let path = fixture.0.join(format!("{session}.jsonl"));
            write_populated_large(&path, &session);
            path
        })
        .collect::<Vec<_>>();
    let small = (4..7)
        .map(|n| {
            let session = format!("019e2700-7777-7000-9000-{n:012}");
            let path = fixture.0.join(format!("{session}.jsonl"));
            let mut row = usage(n);
            row["sessionId"] = json!(session);
            row["requestId"] = json!(format!("req-{session}"));
            row["message"]["id"] = json!(format!("msg-{session}"));
            fs::write(&path, format!("{row}\n")).unwrap();
            path
        })
        .collect::<Vec<_>>();
    let mut index = ScanIndex::default();
    let mut pi_index = ScanIndex::default();
    let mut upgrades = BTreeSet::new();
    let mut peak = 0;
    let mut budget_held = false;
    let mut quiet_walks = 0;
    // Four first admissions at revision 2, switch on 3, then require two
    // quiet completed walks after every file has adopted. No gate override.
    for pass in 0..16 {
        // Model a restart or a reduction refused by the retained-entry cap.
        // This fixture must exercise native Full history reads on macOS too,
        // rather than zero-byte Unchanged reuse of its tiny usage reduction.
        // Durable revision, census and audit state still carry between passes.
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let revision = if pass < 4 { 2 } else { 3 };
        index.activate_upload_context("large-history-composition".into());
        index.activate_effective_upload_body_witness_revision(revision);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(&support.0);
        let owed_before = index
            .files
            .values()
            .filter(|entry| entry.effective_upload_body_witness_revision < revision)
            .count();
        let pi_path = write_pi_progress(&pi.0, pass);
        let mut owner = Rotation {
            ready: vec![
                (
                    SnapshotSource::ClaudeCode,
                    rotation_scan(
                        SnapshotSource::ClaudeCode,
                        &fixture.0,
                        std::mem::take(&mut index),
                        &cache,
                        &[],
                    ),
                ),
                (
                    SnapshotSource::Pi,
                    rotation_scan(
                        SnapshotSource::Pi,
                        &pi.0,
                        std::mem::take(&mut pi_index),
                        &cache,
                        &[],
                    ),
                ),
            ],
            completed: Vec::new(),
            starts: Vec::new(),
            refuse_parking: pass % 2 == 1,
            refusals: std::cell::Cell::new(0),
            deferred_revocations: 0,
            history_receipt: Some(HistoryReceipt::default()),
            started: std::time::Instant::now(),
        };
        let (_, acquisitions) = terminal_contract_retry::source_acquisitions(|| {
            crate::source_rotation::run(
                &mut owner,
                &[SnapshotSource::ClaudeCode, SnapshotSource::Pi],
                crate::source_rotation::PARKED_BUDGET,
            );
        });
        assert_eq!(
            owner.completed.len(),
            2,
            "both sources complete each history pass"
        );
        assert_eq!(
            acquisitions.get(&pi_path),
            Some(&1),
            "Pi progresses every history pass"
        );
        if owner.refuse_parking {
            assert!(owner.refusals.get() > 0);
        }
        let started = owner
            .starts
            .iter()
            .filter(|(path, _)| large.contains(path))
            .collect::<Vec<_>>();
        assert!(started.len() <= 1, "one large Full per history pass {pass}");
        if let Some((path, mode)) = started.first() {
            assert!(matches!(mode, Some(ReadMode::Full(_))));
            assert_eq!(acquisitions.get(path), Some(&1));
            if revision == 3 {
                assert!(upgrades.insert(path.clone()), "no second upgrade read");
            }
        }
        let claude_at = owner
            .completed
            .iter()
            .position(|(source, _, _)| *source == SnapshotSource::ClaudeCode)
            .unwrap();
        let (_, mut next, mut scan) = owner.completed.remove(claude_at);
        let (pi_source, mut pi_next, mut pi_scan) = owner.completed.pop().unwrap();
        assert_eq!(pi_source, SnapshotSource::Pi);
        assert_eq!(pi_scan.scanned_file_count, 1);
        assert_eq!(pi_scan.snapshots.len(), 1);
        assert_eq!(pi_scan.snapshots[0].input_tokens, 12);
        finalize_scan_after_policy(pi_source, &mut pi_scan, &mut pi_next);
        pi_index = pi_next;
        assert_eq!(scan.oversized_file_count, 0);
        if pass < 4 {
            assert_eq!(started.len(), 1, "first admission is paced too");
            for path in &large {
                if !acquisitions.contains_key(path)
                    && !next.files.contains_key(&local_index_key(path))
                {
                    assert!(!next
                        .file_snapshot_fingerprints
                        .contains_key(&local_index_key(path)));
                }
            }
        }
        if pass == 4 {
            assert_eq!(owed_before, 7);
            assert_eq!(started.len(), 1);
            for path in &small {
                assert_eq!(
                    acquisitions.get(path),
                    Some(&1),
                    "small upgrade progresses immediately"
                );
            }
        }
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut next);
        next.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect(),
        );
        if pass == 3 {
            assert_eq!(next.files.len(), 7);
            assert!(next
                .files
                .values()
                .all(|e| e.effective_upload_body_witness_revision == 2));
        }
        if revision == 3 {
            for path in &large {
                let stamp =
                    next.files[&local_index_key(path)].effective_upload_body_witness_revision;
                assert_eq!(
                    stamp,
                    if upgrades.contains(path) { 3 } else { 2 },
                    "unread upgrade keeps its prior revision"
                );
            }
            if pass == 4 {
                for path in &small {
                    assert_eq!(
                        next.files[&local_index_key(path)].effective_upload_body_witness_revision,
                        3
                    );
                }
            }
        }
        let owed_after = next
            .files
            .values()
            .filter(|entry| entry.effective_upload_body_witness_revision < revision)
            .count();
        let receipt = owner.history_receipt.unwrap();
        peak = peak.max(receipt.visits_peak);
        budget_held |= receipt.budget_held > 0;
        println!("claude_large_history_receipt: pass={pass} revision={revision} large_fulls={} owed_before={owed_before} owed_after={owed_after} history_upgrade_owed={} budget_held={} pi_reads=1 visits_peak={} bytes_peak={} census_complete={}",
            started.len(), receipt.owed_seen, receipt.budget_held,
            receipt.visits_peak, receipt.bytes_peak, scan.census_complete);
        if revision == 3 && owed_before == 0 {
            assert_eq!(scan.scanned_file_count, 0, "no second history re-read");
            assert_eq!(receipt.owed_seen, 0, "history_upgrade_owed drains");
            quiet_walks += usize::from(scan.census_complete);
        }
        index = lenient_decode::read(
            std::io::Cursor::new(serde_json::to_vec(&next).unwrap()),
            "load",
            "claude_code",
        )
        .unwrap();
        if quiet_walks == 2 {
            break;
        }
    }
    assert_eq!(upgrades.len(), 4, "all large history eventually upgrades");
    assert_eq!(quiet_walks, 2, "two quiet completed walks");
    assert!(
        budget_held,
        "exercise #805's real paced history byte gate too"
    );
    assert!(peak <= 4096);
    println!(
        "claude_large_history_visit_peak: {peak}/4096 layout_supported={}",
        crate::heap_layout_bound::layout_supported()
    );
}

/// SOURCE condition: real deferred reads keep the census incomplete and
/// preserve existing session/family custody, including absence-retirement debt.
#[test]
fn deferred_large_full_keeps_census_family_and_no_skip_credit() {
    let fixture = Fixture::new();
    let paths = (0..3)
        .map(|n| {
            let session = format!("019e2700-8888-7000-9000-{n:012}");
            let path = fixture.0.join(format!("{session}.jsonl"));
            let mut row = usage(n);
            row["sessionId"] = json!(session);
            fs::write(&path, format!("{row}\n")).unwrap();
            (session, path)
        })
        .collect::<Vec<_>>();
    let mut index = ScanIndex::default();
    let mut baseline = fixture.scan(SnapshotSource::ClaudeCode, &mut index, 9);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut baseline, &mut index);
    assert_eq!(index.files.len(), 3);
    for (session, path) in &paths {
        assert!(
            index
                .file_snapshot_fingerprints
                .get(&local_index_key(path))
                .is_some_and(|members| !members.is_empty()),
            "baseline membership is real"
        );
        let revision = index.files[&local_index_key(path)]
            .source_file_fingerprint
            .clone();
        index.insert_retry_pending_claude_authority_at_revision_for_test(session, &revision);
        index.insert_claude_usage_family_pending_for_test(session, "2026-10-27T09:00:00Z");
        write_populated_large(path, session);
    }
    let previous = index.clone();
    let before = claude_absence_counters_for_test();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut owner = Rotation {
        ready: vec![(
            SnapshotSource::ClaudeCode,
            rotation_scan(SnapshotSource::ClaudeCode, &fixture.0, index, &cache, &[]),
        )],
        completed: Vec::new(),
        starts: Vec::new(),
        refuse_parking: false,
        refusals: std::cell::Cell::new(0),
        deferred_revocations: 0,
        history_receipt: None,
        started: std::time::Instant::now(),
    };
    let (_, reads) = terminal_contract_retry::source_acquisitions(|| {
        crate::source_rotation::run(
            &mut owner,
            &[SnapshotSource::ClaudeCode],
            crate::source_rotation::PARKED_BUDGET,
        );
    });
    assert_eq!(reads.len(), 1);
    assert_eq!(
        owner.deferred_revocations, 2,
        "no comparison eligibility for either deferral"
    );
    let (_, next, scan) = owner.completed.pop().unwrap();
    assert!(!scan.census_complete);
    assert!(scan.skipped_file_count_due_to_limit >= 2);
    assert_eq!(
        claude_absence_counters_for_test().absent_families_retired,
        before.absent_families_retired
    );
    assert_eq!(next.files.len(), 3, "no session source disappears");
    for (session, path) in paths.iter().filter(|(_, p)| !reads.contains_key(p)) {
        let key = local_index_key(path);
        assert!(next.claude_usage_family_pending_retained_for_test(session));
        assert!(next.claude_authority_record_for_test(session).is_some());
        assert!(
            !next.claude_root_tombstoned(session),
            "no absence retirement"
        );
        assert_eq!(
            next.file_snapshot_fingerprints.get(&key),
            previous.file_snapshot_fingerprints.get(&key),
            "no session membership retraction"
        );
    }
    println!("claude_large_full_source_receipt: deferred=2 census_complete=false absence_retirements=0 membership_retractions=0 unchanged_skip_credit=0");
}
