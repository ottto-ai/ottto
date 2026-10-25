//! Explicit, serial, synthetic macOS screening. This does not satisfy the
//! separate real-history activation gate or bound whole-daemon memory.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle;
use crate::transcript_acquisition::Scope;
use std::io::{BufWriter, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TEST: &str = "snapshots::codex_counting_rss_tests::codex_v2_synthetic_peak_rss";
const CHILD: &str = "OTTTO_SYNTHETIC_RSS_CHILD";
const NOW: &str = "2026-10-25T12:00:00Z";
const AT: &str = "2026-10-25T10:00:00Z";
const HISTORY: &str = "019fa111-2222-7333-8444-000000000001";
const PENDING: &str = "019fa111-2222-7333-8444-000000000002";
const CLOSED_TURNS: u64 = 10_000;
const RSS_CAP: u64 = 1024 * 1024 * 1024;
const CPU_CAP_US: u64 = 120_000_000;
const WALL_CAP: Duration = Duration::from_secs(300);
const REVISION: &str = "codex-rss-synthetic-v1";

type Money = BTreeMap<String, Value>;

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn header(id: &str) -> Value {
    json!({"timestamp":AT,"type":"session_meta","payload":{"id":id,"timestamp":AT,"source":"cli"}})
}
fn event(kind: &str, turn: &str) -> Value {
    json!({"timestamp":AT,"type":"event_msg","payload":{"type":kind,"turn_id":turn}})
}
fn tokens(n: u64) -> Value {
    json!({"input_tokens":n*100,"cached_input_tokens":n*20,"cache_write_input_tokens":0,
        "output_tokens":n*10,"reasoning_output_tokens":n*2,"total_tokens":n*110})
}
fn ui(n: u64, model: &str) -> Value {
    json!({"timestamp":AT,"type":"event_msg","payload":{"type":"token_count","info":{
        "model":model,"last_token_usage":tokens(1),"total_token_usage":tokens(n)}}})
}
fn pending_ui(n: u64, padding: usize) -> Value {
    let mut value = ui(n + 1, &format!("rss-{n:02}-{}", "m".repeat(padding)));
    // Populate every selector accepted from a raw Codex row, including the
    // hoisted billing dimensions. Attribution/platform are not raw inputs.
    for key in [
        "service_tier",
        "speed_mode",
        "batch_mode",
        "region_mode",
        "cache_ttl",
        "mode",
        "context_bucket",
        "gateway_provider",
        "auth_mode",
        "billing_channel",
        "subscription_product",
    ] {
        value["payload"]["info"][key] = json!("synthetic");
    }
    value
}
fn pending_padding() -> usize {
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
    codex_counting_version::configure(
        &mut accumulator,
        codex_counting_version::AckEvidence::None,
        Some(0),
    );
    for value in [
        header(PENDING),
        event("task_started", "pending"),
        pending_ui(1, 0),
    ] {
        apply_codex_line(&value, &mut accumulator);
    }
    let (rows, min, max) = accumulator
        .codex_counting
        .as_ref()
        .unwrap()
        .rss_pending_shape();
    assert_eq!(rows, 1);
    assert_eq!(min, max);
    codex_usage_occurrence::MAX_PENDING_ROW_CONTENT_BYTES - max
}
fn write_row(file: &mut impl Write, value: &Value, records: &mut u64) {
    serde_json::to_writer(&mut *file, value).unwrap();
    file.write_all(b"\n").unwrap();
    *records += 1;
    assert!(*records <= 100_000, "fixture record cap");
}
// Four real native reductions consume about 92% of the existing state
// budget. Preparation/probes write only the parent's temporary fixture.
fn pressure_file(path: &Path, records: usize) {
    let mut file = BufWriter::new(File::create(path).unwrap());
    for n in 0..records {
        let value = json!({"type":"assistant","sessionId":"pressure","timestamp":AT,
            "requestId":format!("req-{n}"),"message":{"id":format!("resp-{n}"),
            "model":"fixture-model","usage":{"input_tokens":100,"cache_read_input_tokens":20,"output_tokens":10}}});
        serde_json::to_writer(&mut file, &value).unwrap();
        file.write_all(b"\n").unwrap();
    }
    file.flush().unwrap();
}
fn pressure_reduction(
    path: &Path,
) -> crate::transcript_cache::Retained<sampled_jsonl::CachedJsonlReduction> {
    let source = SnapshotSource::ClaudeCode;
    let mut file = File::open(path).unwrap();
    opened_object_identity(source, &mut file).unwrap();
    let metadata = CodexTitleMetadata::default();
    let mut parser = OwnedJsonlParser::new(
        file,
        path,
        source,
        apply_claude_code_line,
        Some(&metadata),
        None,
        None,
        false,
        false,
    )
    .unwrap();
    let scope = Scope("synthetic-pressure".into());
    let now = sampled_scan::now_seconds();
    parser.prepare_acquisition(None, &scope, None, now).unwrap();
    while !parser.step().unwrap() {}
    let retained = parser
        .retain_reduction(
            &scope,
            now,
            sampled_scan::RetainBudget::granted_unclassified(crate::transcript_cache::ENTRY_BYTES),
        )
        .unwrap()
        .unwrap();
    crate::transcript_cache::Retained {
        checkpoint: retained.checkpoint,
        state: retained.reduction.expect("pressure entry must fit"),
    }
}
fn prefill(root: &Path, cache: &sampled_scan::SharedCache) -> usize {
    for n in 0..4 {
        let retained = pressure_reduction(&root.join("pressure.jsonl"));
        assert!(cache
            .retained()
            .unwrap()
            .insert(format!("synthetic-pressure-{n}"), retained));
    }
    let resident = crate::heap_layout_bound::bound(cache, usize::MAX).unwrap();
    assert!(resident >= cache_policy_tests::POLICY_STATE_BYTES * 90 / 100);
    assert!(resident <= cache_policy_tests::POLICY_STATE_BYTES);
    resident
}
fn prepare_pressure(root: &Path) -> usize {
    let path = root.join("pressure.jsonl");
    let charge = |n| {
        pressure_file(&path, n);
        let retained = pressure_reduction(&path);
        crate::heap_layout_bound::bound(&retained, usize::MAX).unwrap()
    };
    let target = cache_policy_tests::POLICY_STATE_BYTES / 1000 * 230;
    let high = charge(1400);
    let slope = (high - charge(700)) / 700;
    assert!(slope > 0);
    let correct = |n: usize, bytes: usize| {
        (n as isize + (target as isize - bytes as isize) / slope as isize).max(1) as usize
    };
    let mut n = correct(1400, high);
    for _ in 0..5 {
        assert!(n < 10_000, "pressure fixture record cap");
        let bytes = charge(n);
        if bytes.abs_diff(target) <= target / 100 {
            return n;
        }
        n = correct(n, bytes);
    }
    panic!("pressure fixture could not meet its fixed charge target");
}
fn prepare(root: &Path) -> (u64, u64, u64) {
    let sessions = root.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let mut records = 0;
    let mut file = BufWriter::new(File::create(sessions.join("history.jsonl")).unwrap());
    write_row(&mut file, &header(HISTORY), &mut records);
    // About 210 MB, streamed with one small reusable decoded output row.
    let output = json!({"timestamp":AT,"type":"response_item","payload":{
        "type":"function_call_output","call_id":"synthetic","output":"x".repeat(20*1024)}});
    for n in 1..=CLOSED_TURNS {
        let turn = format!("closed-{n}");
        for value in [
            event("task_started", &turn),
            json!({"timestamp":AT,"type":"turn_context","payload":{"turn_id":turn,"model":"fixture-model"}}),
            json!({"timestamp":AT,"type":"token_usage_record","payload":{
                "thread_id":HISTORY,"turn_id":turn,"response_id":format!("response-{n}"),
                "usage":tokens(1),"thread_token_usage":tokens(n)}}),
            ui(n, "fixture-model"),
        ] {
            write_row(&mut file, &value, &mut records);
        }
        write_row(&mut file, &output, &mut records);
        write_row(&mut file, &event("task_complete", &turn), &mut records);
        if n % 100 == 0 {
            write_row(
                &mut file,
                &json!({"timestamp":AT,"type":"compacted","payload":{"replacement_history":[]}}),
                &mut records,
            );
        }
    }
    file.flush().unwrap();
    let padding = pending_padding();
    let mut file = BufWriter::new(File::create(sessions.join("pending.jsonl")).unwrap());
    for value in [
        header(PENDING),
        ui(1, "fixture-model"),
        event("task_started", "pending"),
    ] {
        write_row(&mut file, &value, &mut records);
    }
    for n in 1..=64 {
        write_row(&mut file, &pending_ui(n, padding), &mut records);
    }
    file.flush().unwrap();
    let cold_len = fs::metadata(sessions.join("pending.jsonl")).unwrap().len();
    // Use the existing admitted native join shape without changing eligibility.
    let joined = native_join_fixture_root(false);
    for name in ["a.jsonl", "b.jsonl"] {
        let text = fs::read_to_string(joined.join("sessions").join(name)).unwrap();
        fs::write(
            sessions.join(name),
            text.replace("2026-10-01", "2026-10-25"),
        )
        .unwrap();
        records += 3;
    }
    fs::remove_dir_all(joined).unwrap();
    records += prepare_pressure(root) as u64;
    let mut tail = File::create(root.join("tail.jsonl")).unwrap();
    write_row(&mut tail, &pending_ui(65, padding), &mut records);
    write_row(&mut tail, &event("task_complete", "pending"), &mut records);
    let bytes: u64 = fs::read_dir(&sessions)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum::<u64>()
        + tail.metadata().unwrap().len()
        + fs::metadata(root.join("pressure.jsonl")).unwrap().len();
    assert!(bytes > 200 * 1024 * 1024 && bytes <= RSS_CAP);
    assert!(fs::read_dir(sessions).unwrap().count() < 8);
    assert!(records <= 100_000);
    (bytes, records, cold_len)
}
fn reset(root: &Path, cold_len: u64) {
    fs::OpenOptions::new()
        .write(true)
        .open(root.join("sessions/pending.jsonl"))
        .unwrap()
        .set_len(cold_len)
        .unwrap();
}
fn append_tail(root: &Path) {
    let tail = fs::read(root.join("tail.jsonl")).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(root.join("sessions/pending.jsonl"))
        .unwrap()
        .write_all(&tail)
        .unwrap();
}
fn money(item: &SnapshotItem) -> Value {
    json!({"input":item.input_tokens,"read":item.cache_read_tokens,
        "write_5m":item.cache_creation_5m_tokens,"write_1h":item.cache_creation_1h_tokens,
        "output":item.output_tokens,"reasoning":item.reasoning_output_tokens,
        "unattributed":item.unattributed_total_tokens,"requests":item.request_count,
        "models":item.model_usage.iter().map(semantic_model_usage).collect::<Vec<_>>(),
        "buckets":semantic_usage_buckets(item)})
}
#[derive(Default)]
struct Observed {
    pages: u64,
    tails: usize,
    max_pending_rows: usize,
    maximal_rows_seen: bool,
    open_debt_seen: bool,
    overflow_seen: bool,
    joined_seen: bool,
}
/// Complete one bounded acquisition, including all cursor pages, with the
/// same production namespace/cache. `None` is the unpaged full-read control.
fn acquire(
    root: &Path,
    mut index: ScanIndex,
    cache: Option<&Arc<sampled_scan::SharedCache>>,
    out: &mut Money,
    observed: &mut Observed,
) -> ScanIndex {
    for _ in 0..32 {
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            8,
            false,
            None,
            &[],
            false,
            false,
        );
        if let Some(cache) = cache {
            scan = scan.with_sampled_acquisition(Arc::clone(cache), Scope("synthetic-rss".into()));
        }
        loop {
            if let Some(counting) = scan
                .active_file
                .as_deref()
                .and_then(|a| a.parser.accumulator.codex_counting.as_ref())
            {
                let (rows, min, max) = counting.rss_pending_shape();
                observed.max_pending_rows = observed.max_pending_rows.max(rows);
                if rows == 64 {
                    assert_eq!((min, max), (4096, 4096), "all 64 rows at the content cap");
                    observed.maximal_rows_seen = true;
                }
            }
            if let Some(context) = scan.sampling.as_ref() {
                observed.tails = observed.tails.max(context.tail_files);
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete {
                    index: mut next,
                    mut scan,
                    ..
                } => {
                    observed.pages += 1;
                    assert_eq!(scan.malformed_json_line_count, 0);
                    assert_eq!(scan.dropped_usage_record_count, 0);
                    assert_eq!(scan.ownership_incomplete_file_count, 0);
                    assert_eq!(scan.over_line_cap_count, 0);
                    if let Some(c) = scan.codex_counting_v2.as_ref() {
                        observed.open_debt_seen |= c.open_turn_ui_pending_events_this_scan == 64;
                        observed.overflow_seen |= c.pending_overflow_flushes > 0;
                    }
                    for item in &scan.snapshots {
                        out.insert(item.source_session_id.clone(), money(item));
                    }
                    finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut next);
                    observed.joined_seen |= next
                        .files
                        .values()
                        .any(|entry| entry.codex_joined_member_set.is_some());
                    let complete = scan.census_complete;
                    index = next;
                    if complete && cache.is_none_or(|cache| cache.cursor_slot_free()) {
                        return index;
                    }
                    break;
                }
            }
        }
    }
    panic!("acquisition exceeded 32 pages");
}
fn process_sample() -> (u64, u64) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the complete struct on success.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    let micros = |t: libc::timeval| {
        u64::try_from(t.tv_sec).unwrap() * 1_000_000 + u64::try_from(t.tv_usec).unwrap()
    };
    // This explicit test rejects non-macOS layouts before sampling: RSS is bytes.
    (
        u64::try_from(usage.ru_maxrss).unwrap(),
        micros(usage.ru_utime) + micros(usage.ru_stime),
    )
}
fn measured_child(root: &Path, case: &str) {
    let start = Instant::now();
    // Process-lifetime caps, enforced during acquisition, not just at EOF.
    std::thread::spawn(move || loop {
        let (rss, cpu) = process_sample();
        if rss > RSS_CAP || cpu > CPU_CAP_US || start.elapsed() > WALL_CAP {
            eprintln!("synthetic RSS child exceeded a fixed resource cap");
            std::process::exit(90);
        }
        std::thread::sleep(Duration::from_millis(100));
    });
    let _cutover = (case == "v2").then(|| codex_counting_version::TestCutover::set(0));
    let expected: Vec<Money> =
        serde_json::from_slice(&fs::read(root.join(format!("{case}-expected.json"))).unwrap())
            .unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut out = Money::new();
    let mut observed = Observed::default();
    let ((retained_prefill, retained_cold, retained_tail), counts) =
        cache_lifecycle::observe(|| {
            let retained_prefill = prefill(root, &cache);
            let index = acquire(
                root,
                ScanIndex::default(),
                Some(&cache),
                &mut out,
                &mut observed,
            );
            assert_eq!(out, expected[0], "cold money differs across paging");
            assert!(
                cache
                    .retained_sealed_offset(&local_index_key(&root.join("sessions/pending.jsonl")))
                    .is_some(),
                "open-turn file must actually be retained"
            );
            let retained_cold = crate::heap_layout_bound::bound(&*cache, usize::MAX).unwrap();
            append_tail(root);
            acquire(root, index, Some(&cache), &mut out, &mut observed);
            assert_eq!(out, expected[1], "tail money differs from a full read");
            let retained_tail = crate::heap_layout_bound::bound(&*cache, usize::MAX).unwrap();
            (retained_prefill, retained_cold, retained_tail)
        });
    let cursor = cache.counters_for_test();
    assert!(counts.take_hit > 0 && counts.insert_admitted > 4);
    assert!(
        counts.copy_refusal_entries_evicted
            + counts.cursor_reservation_entries_evicted
            + counts.insert_entries_evicted
            + counts.clear_entries_released
            > 0,
        "actual cache pressure must release entries"
    );
    assert!(cursor.jobs_paused > 0 && cursor.jobs_resumed > 0);
    assert!(observed.tails > 0 && observed.joined_seen);
    if case == "v2" {
        assert!(observed.maximal_rows_seen && observed.open_debt_seen && observed.overflow_seen);
    }
    let (rss, cpu) = process_sample();
    assert!(rss <= RSS_CAP && cpu <= CPU_CAP_US && start.elapsed() <= WALL_CAP);
    let metadata: Value =
        serde_json::from_slice(&fs::read(root.join("metadata.json")).unwrap()).unwrap();
    println!(
        "\ncodex_v2_rss_receipt: {}",
        json!({"fixture_revision":REVISION,"case":case,
        "sha":std::env::var("GITHUB_SHA").expect("CI SHA receipt"),"input":metadata,
        "rustc":env!("OTTTO_SCAN_LAYOUT_RUSTC"),"layout_supported":true,
        "peak_rss_bytes":rss,"cpu_us":cpu,"wall_us":start.elapsed().as_micros(),
        "retained_prefill_bytes":retained_prefill,"retained_cold_bytes":retained_cold,"retained_tail_bytes":retained_tail,
        "cache_take_hit":counts.take_hit,"cache_insert_admitted":counts.insert_admitted,
        "cursor_paused":cursor.jobs_paused,"cursor_resumed":cursor.jobs_resumed,
        "tail_files":observed.tails,"pages":observed.pages,"max_pending_rows":observed.max_pending_rows,
        "maximal_rows_seen":observed.maximal_rows_seen,"open_debt_seen":observed.open_debt_seen,
        "overflow_seen":observed.overflow_seen,"joined_seen":observed.joined_seen,
        "money_matches_full_read":true,"cache_counts":counts})
    );
}

#[test]
#[ignore = "dedicated macOS CI step: serial bounded synthetic child-process measurement"]
fn codex_v2_synthetic_peak_rss() {
    assert!(
        crate::heap_layout_bound::layout_supported(),
        "supported native layout required"
    );
    assert!(env!("OTTTO_SCAN_LAYOUT_RUSTC").starts_with("rustc 1.95.0 "));
    if let Ok(case) = std::env::var(CHILD) {
        assert!(matches!(case.as_str(), "legacy" | "v2"));
        measured_child(
            Path::new(&std::env::var("OTTTO_SYNTHETIC_RSS_ROOT").unwrap()),
            &case,
        );
        return;
    }
    let started = Instant::now();
    let fixture = Fixture(std::env::temp_dir().join(format!(
            "ottto-synthetic-rss-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    let root = &fixture.0;
    let (bytes, records, cold_len) = prepare(root);
    fs::write(
        root.join("metadata.json"),
        json!({"decoded_bytes":bytes,"records":records,"files":5,
        "closed_turns":CLOSED_TURNS,"pending_rows":64,"pending_row_content_bytes":4096})
        .to_string(),
    )
    .unwrap();
    // Controls and fixture generation live ONLY in the unmeasured parent.
    for case in ["legacy", "v2"] {
        reset(root, cold_len);
        let _cutover = (case == "v2").then(|| codex_counting_version::TestCutover::set(0));
        let mut cold = Money::new();
        acquire(
            root,
            ScanIndex::default(),
            None,
            &mut cold,
            &mut Observed::default(),
        );
        assert_eq!(
            cold.len(),
            3,
            "large singleton, pending singleton, admitted joined group"
        );
        append_tail(root);
        let mut tail = Money::new();
        acquire(
            root,
            ScanIndex::default(),
            None,
            &mut tail,
            &mut Observed::default(),
        );
        assert_eq!(tail.len(), 3);
        fs::write(
            root.join(format!("{case}-expected.json")),
            serde_json::to_vec(&[cold, tail]).unwrap(),
        )
        .unwrap();
    }
    for case in ["legacy", "v2"] {
        reset(root, cold_len);
        let log = root.join(format!("{case}.log"));
        let file = File::create(&log).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                TEST,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, case)
            .env("OTTTO_SYNTHETIC_RSS_ROOT", root)
            .stdout(Stdio::from(file.try_clone().unwrap()))
            .stderr(Stdio::from(file))
            .spawn()
            .unwrap();
        let child_started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if child_started.elapsed() > WALL_CAP || started.elapsed() > Duration::from_secs(900) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("synthetic measurement exceeded fixed wall cap");
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let log = fs::read_to_string(log).unwrap();
        assert!(status.success(), "{case} child failed: {log}");
        let receipts: Vec<_> = log
            .lines()
            .filter(|line| line.starts_with("codex_v2_rss_receipt: "))
            .collect();
        assert_eq!(receipts.len(), 1, "one receipt per child required");
        println!("\n{}", receipts[0]);
    }
    assert!(started.elapsed() <= Duration::from_secs(900));
}
