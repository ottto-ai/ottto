// Synthetic real-scan admission and native parse/finalize memory receipts.
// The memory case runs alone in a fresh process; fixture generation happens
// in the parent. Measurements report observations, never establish a budget.
use super::*;
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
const MIB: u64 = 1024 * 1024;
const SESSION: &str = "019e2700-5555-7000-9000-555555555555";
const AT: &str = "2026-10-27T08:00:00Z";
#[cfg(target_os = "macos")]
const RECEIPT: &str = "claude_cap_memory_receipt: ";
#[cfg(target_os = "macos")]
const TEST: &str = "snapshots::tests::claude_file_cap_tests::large_claude_native_memory";
#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn peak_rss() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the complete rusage on success.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    u64::try_from(usage.ru_maxrss).unwrap()
}

// Same Darwin TASK_VM_INFO rev3 layout used by the existing `e2` benchmark.
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

#[cfg(target_os = "macos")]
fn measured_child(root: PathBuf, requests: u64, bytes: u64) {
    // The parent owns cleanup. Deliberately avoid Fixture's destructor here.
    let fixture = std::mem::ManuallyDrop::new(Fixture(root));
    assert_eq!(fs::metadata(fixture.path()).unwrap().len(), bytes);
    let before = footprint();
    let mut index = ScanIndex::default();
    let scan = fixture.scan(SnapshotSource::ClaudeCode, &mut index, 9);
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
            "request_identity_capture":true
        })
    );
}

#[cfg(target_os = "macos")]
#[test]
fn large_claude_native_memory() {
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
    let mib = 500;
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
}

fn source_rows(source: SnapshotSource, n: u64) -> Vec<Value> {
    match source {
        SnapshotSource::ClaudeCode => vec![usage(n)],
        SnapshotSource::Codex => {
            let mut rows = Vec::new();
            if n == 1 {
                rows.push(json!({"type":"session_meta", "timestamp":AT,
                    "payload":{"id":SESSION}}));
            }
            rows.push(json!({"type":"event_msg", "timestamp":AT,
                "payload":{"type":"token_count", "info":{"model":"gpt-5.2",
                    "total_token_usage":{"input_tokens":n*100, "output_tokens":n*10},
                    "last_token_usage":{"input_tokens":100, "output_tokens":10}}}}));
            rows
        }
        SnapshotSource::Pi => {
            let mut rows = Vec::new();
            if n == 1 {
                rows.push(json!({"type":"session", "version":3, "id":SESSION, "timestamp":AT}));
            }
            rows.push(
                json!({"type":"message", "id":format!("entry-{n}"), "timestamp":AT,
                "message":{"role":"assistant", "provider":"openai", "model":"gpt-5.4",
                    "responseId":format!("response-{n}"), "timestamp":1793088000000u64,
                    "usage":{"input":100, "output":10, "cacheRead":0, "cacheWrite":0}}}),
            );
            rows
        }
    }
}

/// [regress] All sources admit metadata above the former cap, publish usage, and Tail growth.
#[test]
fn former_caps_admit_usage_and_tail_for_all_sources() {
    use crate::transcript_acquisition::{ReadMode, ReadPlan, Scope};
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let fixture = Fixture::new();
        let mut prefix = Vec::new();
        for row in source_rows(source, 1) {
            write_row(&mut prefix, &row);
        }
        fs::write(fixture.path(), &prefix).unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .open(fixture.path())
            .unwrap();
        file.set_len(former_file_cap(source) + 1).unwrap();
        let mut candidate = candidate_from_traversal_path(
            source,
            ScanTraversalPath {
                scan_root: fixture.0.clone(),
                path: fixture.path(),
                census_member: true,
                watcher_hint: true,
            },
            &mut ScanCensus::default(),
            None,
            BACKFILL_WINDOW_DAYS,
            &mut CandidateDiscovery::new(&mut ScanIndex::default(), None, None),
        )
        .unwrap();
        assert_eq!(
            open_candidate_file(source, &mut candidate)
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            former_file_cap(source) + 1
        );
        // The large length tests admission only; native usage and Tail need no padding I/O.
        file.set_len(prefix.len() as u64).unwrap();
        let mut index = ScanIndex::default();
        let mut scan = fixture.scan(source, &mut index, 9);
        finalize_scan_after_policy(source, &mut scan, &mut index);
        assert_eq!(scan.oversized_file_count, 0);
        assert_eq!(scan.scanned_file_count, 1);
        assert_eq!(
            scan.snapshots.iter().map(|s| s.input_tokens).sum::<u64>(),
            100
        );
        assert_eq!(
            scan.snapshots.iter().map(|s| s.output_tokens).sum::<u64>(),
            10
        );
        let scope = Scope("former-file-cap-growth".into());
        let mut reader = File::open(fixture.path()).unwrap();
        let mut plan = ReadPlan::prepare(&mut reader, None, &scope, None, 100).unwrap();
        reader.read_exact(&mut vec![0; prefix.len()]).unwrap();
        plan.observe_record_fragment(&prefix, true).unwrap();
        let checkpoint = plan
            .commit_after_native_completion(&reader, &scope, 100)
            .unwrap();
        let mut expected = Vec::new();
        for row in source_rows(source, 2) {
            write_row(&mut expected, &row);
        }
        let former_size_seam = prefix.len() as u64 + expected.len() as u64 / 2;
        fs::OpenOptions::new()
            .append(true)
            .open(fixture.path())
            .unwrap()
            .write_all(&expected)
            .unwrap();
        assert!((prefix.len() as u64) < former_size_seam);
        assert!(fs::metadata(fixture.path()).unwrap().len() > former_size_seam);
        let mut reader = File::open(fixture.path()).unwrap();
        let tail = ReadPlan::prepare(&mut reader, Some(&checkpoint), &scope, None, 101).unwrap();
        assert_eq!(tail.mode(), ReadMode::Tail);
        assert_eq!(tail.start_offset(), prefix.len() as u64);
        let mut suffix = Vec::new();
        reader.read_to_end(&mut suffix).unwrap();
        assert_eq!(suffix, expected);
        let scan = fixture.scan(source, &mut index, 10);
        assert_eq!(
            scan.snapshots.iter().map(|s| s.input_tokens).sum::<u64>(),
            200
        );
    }
}

/// [format] Retired file-size refusal debt and counts decode without a state migration.
#[test]
fn retired_file_size_debt_decodes_and_clears_without_a_state_migration() {
    let mut old = serde_json::to_value(terminal_unhealthy_traversal(String::new())).unwrap();
    old["oversized_discovery"] = json!({
        "synthetic_path_hash": {"content_hash":"synthetic_content_hash", "observations":1}
    });
    old["counts"]["oversized_file_count"] = json!(1);
    old["counts"]["disappeared_file_count"] = json!(0);
    let decoded: ScanTraversalCheckpoint = serde_json::from_value(old).unwrap();
    assert_eq!(decoded.counts.oversized_file_count, 1);
    assert_eq!(decoded.oversized_discovery.len(), 1);
    let mut index = ScanIndex {
        traversal: Some(decoded),
        ..ScanIndex::default()
    };
    index.clear_retired_file_size_debt();
    let decoded = index.traversal.unwrap();
    assert_eq!(decoded.counts.oversized_file_count, 0);
    assert!(!decoded.counts.has_errors());
    let saved = serde_json::to_value(decoded).unwrap();
    assert!(saved.get("oversized_discovery").is_none());
    assert_eq!(saved["counts"]["oversized_file_count"], 0);
}
