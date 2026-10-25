//! Explicit, serial, synthetic macOS screening. This does not satisfy the
//! separate real-history activation gate or bound whole-daemon memory.
//!
//! Opt-in real mode (`OTTTO_CODEX_RSS_REAL_DIR`, never set in CI) runs the
//! same children over a frozen private directory of Codex rollouts. It prints
//! only counts, sizes, hashes, resources and token totals: no record content,
//! session ids, model names or paths, including on failure.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle;
use crate::transcript_acquisition::Scope;
use std::io::{BufWriter, Write};
use std::os::unix::fs::PermissionsExt;
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
const REVISION: &str = "codex-rss-synthetic-v1";
const REAL_DIR: &str = "OTTTO_CODEX_RSS_REAL_DIR";
const RECEIPT: &str = "codex_v2_rss_receipt: ";
const REAL_RECEIPT: &str = "codex_v2_rss_real_receipt: ";
// Planned per-child read: the cold prefix plus a worst-case full re-read.
const REAL_CHILD_DECODED_CAP: u64 = 2 * 1024 * 1024 * 1024;
const REAL_TAIL_BYTES: u64 = 1024 * 1024;

struct Caps {
    rss: u64,
    cpu_us: u64,
    wall: Duration,
    total: Duration,
    pages: usize,
}
const SYNTHETIC_CAPS: Caps = Caps {
    rss: RSS_CAP,
    cpu_us: 120_000_000,
    wall: Duration::from_secs(300),
    total: Duration::from_secs(900),
    pages: 32,
};
const REAL_CAPS: Caps = Caps {
    rss: 1536 * 1024 * 1024,
    cpu_us: 300_000_000,
    wall: Duration::from_secs(600),
    total: Duration::from_secs(1800),
    pages: 48,
};
fn real_mode() -> bool {
    std::env::var_os(REAL_DIR).is_some()
}
fn caps() -> &'static Caps {
    if real_mode() {
        &REAL_CAPS
    } else {
        &SYNTHETIC_CAPS
    }
}

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
/// Private run settings shared by the real-mode parent and children; never printed.
fn real_config(root: &Path) -> Value {
    serde_json::from_slice(&fs::read(root.join("real.json")).unwrap()).unwrap()
}
fn target(root: &Path) -> PathBuf {
    if real_mode() {
        let name = real_config(root)["target"].as_str().unwrap().to_string();
        root.join("sessions").join(name)
    } else {
        root.join("sessions/pending.jsonl")
    }
}
fn scan_now(root: &Path) -> String {
    if real_mode() {
        real_config(root)["now"].as_str().unwrap().to_string()
    } else {
        NOW.to_string()
    }
}
/// Pages of one acquisition share a census window. A later acquisition
/// needs a new window even when both rounds run within one wall-clock second.
fn next_census_time(now: &str) -> String {
    (OffsetDateTime::parse(now, &Rfc3339).unwrap() + time::Duration::seconds(1))
        .format(&Rfc3339)
        .unwrap()
}
fn reset(root: &Path, cold_len: u64) {
    fs::OpenOptions::new()
        .write(true)
        .open(target(root))
        .unwrap()
        .set_len(cold_len)
        .unwrap();
}
fn append_tail(root: &Path) {
    let tail = fs::read(root.join("tail.jsonl")).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(target(root))
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
#[derive(Default, Serialize)]
struct SelectionCounts {
    full_files: usize,
    tail_files: usize,
    unchanged_files: usize,
    // FullReason::slot() order; numeric counts only, no file identities.
    full_reasons: [usize; 11],
    scanned_files: usize,
}
#[derive(Default)]
struct Observed {
    pages: u64,
    tails: usize,
    selection: SelectionCounts,
    max_priority_witnesses: usize,
    max_pending_rows: usize,
    maximal_rows_seen: bool,
    open_debt_seen: bool,
    overflow_seen: bool,
    joined_seen: bool,
    // Real mode reports these instead of asserting a clean synthetic shape.
    malformed_lines: usize,
    dropped_usage_records: u64,
    ownership_incomplete_files: usize,
    over_line_cap: usize,
}
/// Complete one bounded acquisition, including all cursor pages, with the
/// same production namespace/cache. `None` is the unpaged full-read control.
fn acquire(
    root: &Path,
    mut index: ScanIndex,
    cache: Option<&Arc<sampled_scan::SharedCache>>,
    out: &mut Money,
    observed: &mut Observed,
    now: &str,
) -> ScanIndex {
    let real = real_mode();
    // Keep read modes for this acquisition separately from the cold round.
    observed.selection = SelectionCounts::default();
    for _ in 0..caps().pages {
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            index,
            now,
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
        let mut selected = SelectionCounts::default();
        loop {
            if let Some(accumulator) = scan.active_file.as_deref().map(|a| &a.parser.accumulator) {
                observed.max_priority_witnesses = observed.max_priority_witnesses.max(
                    accumulator
                        .codex_observed_priority_turns
                        .as_ref()
                        .map_or(0, BTreeMap::len),
                );
            }
            if let Some(counting) = scan
                .active_file
                .as_deref()
                .and_then(|a| a.parser.accumulator.codex_counting.as_ref())
            {
                let (rows, min, max) = counting.rss_pending_shape();
                observed.max_pending_rows = observed.max_pending_rows.max(rows);
                if rows == 64 && !real {
                    assert_eq!((min, max), (4096, 4096), "all 64 rows at the content cap");
                    observed.maximal_rows_seen = true;
                }
            }
            if let Some(context) = scan.sampling.as_ref() {
                observed.tails = observed.tails.max(context.tail_files);
                selected.full_files = context.full_files;
                selected.tail_files = context.tail_files;
                selected.unchanged_files = context.unchanged_files;
                selected.full_reasons = context.full_reasons;
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete {
                    index: mut next,
                    mut scan,
                    ..
                } => {
                    observed.pages += 1;
                    observed.selection.full_files += selected.full_files;
                    observed.selection.tail_files += selected.tail_files;
                    observed.selection.unchanged_files += selected.unchanged_files;
                    for (total, count) in observed
                        .selection
                        .full_reasons
                        .iter_mut()
                        .zip(selected.full_reasons)
                    {
                        *total += count;
                    }
                    observed.selection.scanned_files += scan.scanned_file_count;
                    observed.malformed_lines += scan.malformed_json_line_count;
                    observed.dropped_usage_records += scan.dropped_usage_record_count;
                    observed.ownership_incomplete_files += scan.ownership_incomplete_file_count;
                    observed.over_line_cap += scan.over_line_cap_count;
                    if !real {
                        assert_eq!(scan.malformed_json_line_count, 0);
                        assert_eq!(scan.dropped_usage_record_count, 0);
                        assert_eq!(scan.ownership_incomplete_file_count, 0);
                        assert_eq!(scan.over_line_cap_count, 0);
                    }
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
    panic!("acquisition exceeded its fixed page cap");
}
/// Exercise the real-history fallback with a small, entirely synthetic file:
/// more turn witnesses than the retained cache allows, and multiple cursor pages.
#[test]
fn grown_unretained_history_is_read_in_the_next_rss_round() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for case in ["legacy", "v2"] {
        let _cutover = (case == "v2").then(|| codex_counting_version::TestCutover::set(0));
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "ottto-rss-tail-regression-{}-{}-{case}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        )));
        let root = &fixture.0;
        fs::create_dir_all(root.join("sessions")).unwrap();
        let path = root.join("sessions/pending.jsonl");
        let mut file = BufWriter::new(File::create(&path).unwrap());
        let mut records = 0;
        write_row(&mut file, &header(PENDING), &mut records);
        let turns = sampled_jsonl::MAX_PRIORITY_WITNESSES as u64 + 1;
        for n in 1..=turns {
            let turn = format!("closed-{n}");
            for value in [
                event("task_started", &turn),
                ui(n, "fixture-model"),
                event("task_complete", &turn),
            ] {
                write_row(&mut file, &value, &mut records);
            }
        }
        file.flush().unwrap();
        drop(file);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut out = Money::new();
        let mut observed = Observed::default();
        sampled_scan::codex_cursor::with_test_limits(32 * 1024, 16 * 1024, 1024, || {
            let index = acquire(
                root,
                ScanIndex::default(),
                Some(&cache),
                &mut out,
                &mut observed,
                NOW,
            );
            assert!(observed.max_priority_witnesses > sampled_jsonl::MAX_PRIORITY_WITNESSES);
            assert!(cache
                .retained_sealed_offset(&local_index_key(&path))
                .is_none());
            assert!(cache.counters_for_test().jobs_paused > 0);
            let cold = out.clone();
            let mut tail = BufWriter::new(File::create(root.join("tail.jsonl")).unwrap());
            write_row(&mut tail, &ui(turns + 1, "fixture-model"), &mut records);
            tail.flush().unwrap();
            drop(tail);
            append_tail(root);
            acquire(
                root,
                index,
                Some(&cache),
                &mut out,
                &mut observed,
                &next_census_time(NOW),
            );
            // No retained copy: the appended round must be a real full re-read.
            assert!(observed.selection.scanned_files > 0);
            assert!(observed.selection.full_files > 0);
            assert_eq!(observed.selection.tail_files, 0);
            assert!(
                observed.selection.full_reasons
                    [crate::transcript_acquisition::FullReason::StateMissing.slot()]
                    > 0
            );
            assert!(out != cold, "the appended usage must affect money");
            let mut full = Money::new();
            acquire(
                root,
                ScanIndex::default(),
                None,
                &mut full,
                &mut Observed::default(),
                NOW,
            );
            assert_eq!(
                out, full,
                "{case} appended money must match an unpaged full read"
            );
        });
    }
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
/// Process-lifetime caps, enforced during acquisition, not just at EOF.
fn watchdog(start: Instant, rss_cap: u64, cpu_cap_us: u64, wall: Duration) {
    std::thread::spawn(move || loop {
        let (rss, cpu) = process_sample();
        if rss > rss_cap || cpu > cpu_cap_us || start.elapsed() > wall {
            eprintln!("RSS measurement exceeded a fixed resource cap");
            std::process::exit(90);
        }
        std::thread::sleep(Duration::from_millis(100));
    });
}
/// Numbers only: summed money dimensions across sessions.
fn totals(money: &Money) -> Value {
    let mut out = BTreeMap::<&str, u64>::new();
    for item in money.values() {
        for key in [
            "input",
            "read",
            "write_5m",
            "write_1h",
            "output",
            "reasoning",
            "unattributed",
            "requests",
        ] {
            let total = out.entry(key).or_default();
            *total = total.saturating_add(item[key].as_u64().unwrap_or(0));
        }
    }
    json!(out)
}
fn measured_child(root: &Path, case: &str) {
    let start = Instant::now();
    let real = real_mode();
    let caps = caps();
    watchdog(start, caps.rss, caps.cpu_us, caps.wall);
    let _cutover = (case == "v2").then(|| codex_counting_version::TestCutover::set(0));
    let expected: Vec<Money> =
        serde_json::from_slice(&fs::read(root.join(format!("{case}-expected.json"))).unwrap())
            .unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut out = Money::new();
    let mut observed = Observed::default();
    let mut retained_after_cold = false;
    let cold_now = scan_now(root);
    let tail_now = next_census_time(&cold_now);
    let ((retained_prefill, retained_cold, retained_tail), counts) =
        cache_lifecycle::observe(|| {
            // Synthetic pressure entries are not mixed into real histories.
            let retained_prefill = if real { 0 } else { prefill(root, &cache) };
            let index = acquire(
                root,
                ScanIndex::default(),
                Some(&cache),
                &mut out,
                &mut observed,
                &cold_now,
            );
            retained_after_cold = cache
                .retained_sealed_offset(&local_index_key(&target(root)))
                .is_some();
            if !real {
                assert_eq!(out, expected[0], "cold money differs across paging");
                assert!(
                    retained_after_cold,
                    "open-turn file must actually be retained"
                );
            }
            let retained_cold = crate::heap_layout_bound::bound(&*cache, usize::MAX).unwrap();
            append_tail(root);
            acquire(
                root,
                index,
                Some(&cache),
                &mut out,
                &mut observed,
                &tail_now,
            );
            if !real {
                assert_eq!(out, expected[1], "tail money differs from a full read");
            }
            let retained_tail = crate::heap_layout_bound::bound(&*cache, usize::MAX).unwrap();
            (retained_prefill, retained_cold, retained_tail)
        });
    let cursor = cache.counters_for_test();
    let metadata: Value =
        serde_json::from_slice(&fs::read(root.join("metadata.json")).unwrap()).unwrap();
    if real {
        // Paged cold + retained tail against the unpaged full read. Never
        // format either map: keys are session ids and model names.
        let full = expected.last().unwrap();
        let matches = out == *full;
        let (rss, cpu) = process_sample();
        println!(
            "\n{REAL_RECEIPT}{}",
            json!({"mode":"real","case":case,
            "sha":std::env::var("GITHUB_SHA").expect("source SHA receipt"),"input":metadata,
            "rustc":env!("OTTTO_SCAN_LAYOUT_RUSTC"),"layout_supported":true,
            "peak_rss_bytes":rss,"cpu_us":cpu,"wall_us":start.elapsed().as_micros(),
            "retained_cold_bytes":retained_cold,"retained_tail_bytes":retained_tail,
            "retained_after_cold":retained_after_cold,
            "cache_take_hit":counts.take_hit,"cache_insert_admitted":counts.insert_admitted,
            "cursor_paused":cursor.jobs_paused,"cursor_resumed":cursor.jobs_resumed,
            "tail_files":observed.tails,"tail_selected_reason":observed.selection,
            "max_priority_witnesses":observed.max_priority_witnesses,
            "priority_witness_cap":sampled_jsonl::MAX_PRIORITY_WITNESSES,
            "pages":observed.pages,"max_pending_rows":observed.max_pending_rows,
            "open_debt_seen":observed.open_debt_seen,"overflow_seen":observed.overflow_seen,
            "scan_counts":{"malformed_lines":observed.malformed_lines,
                "dropped_usage_records":observed.dropped_usage_records,
                "ownership_incomplete_files":observed.ownership_incomplete_files,
                "over_line_cap":observed.over_line_cap},
            "sessions":out.len(),"full_read_sessions":full.len(),
            "totals":totals(&out),"full_read_totals":totals(full),
            "money_matches_full_read":matches,"cache_counts":counts})
        );
        assert!(rss <= caps.rss && cpu <= caps.cpu_us && start.elapsed() <= caps.wall);
        assert!(
            observed.selection.scanned_files > 0,
            "real tail round must scan the grown file"
        );
        assert!(matches, "real paged money differs from the full read");
        return;
    }
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
    assert!(rss <= caps.rss && cpu <= caps.cpu_us && start.elapsed() <= caps.wall);
    println!(
        "\n{RECEIPT}{}",
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

fn sha256_file(path: &Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    format!("{:x}", digest.finalize())
}
/// Copy every top-level `.jsonl` of the frozen directory into the private
/// work root, then split the largest at a line boundary into a cold prefix
/// and a small retained-round tail. Content is only parsed, never printed.
fn prepare_real(src: &Path, root: &Path) -> u64 {
    let sessions = root.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let mut names: Vec<_> = fs::read_dir(src)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry.file_type().unwrap().is_file()
                && entry.file_name().to_string_lossy().ends_with(".jsonl")
        })
        .map(|entry| entry.file_name())
        .collect();
    names.sort();
    assert!(
        (1..=8).contains(&names.len()),
        "real mode needs 1..=8 top-level .jsonl files"
    );
    let sizes: Vec<u64> = names
        .iter()
        .map(|name| fs::metadata(src.join(name)).unwrap().len())
        .collect();
    let total: u64 = sizes.iter().sum();
    assert!(
        total.saturating_mul(2) <= REAL_CHILD_DECODED_CAP,
        "real input exceeds the per-child decoded cap"
    );
    let mut files = Vec::new();
    for (name, &bytes) in names.iter().zip(&sizes) {
        let copy = sessions.join(name);
        assert_eq!(fs::copy(src.join(name), &copy).unwrap(), bytes);
        // The frozen source is read-only; the work copy is truncated and appended.
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o600)).unwrap();
        files.push(json!({"bytes":bytes,"sha256":sha256_file(&copy)}));
    }
    let largest = (0..names.len()).max_by_key(|&n| sizes[n]).unwrap();
    let len = sizes[largest];
    assert!(len >= 2, "real history too small to split");
    let window = len.min(32 * 1024 * 1024);
    let start = len - window;
    let mut file = File::open(sessions.join(&names[largest])).unwrap();
    file.seek(SeekFrom::Start(start)).unwrap();
    let mut bytes = Vec::new();
    file.take(window).read_to_end(&mut bytes).unwrap();
    // First boundary at or after the target tail size, else the last before
    // it; the final byte is never a split point.
    let wanted = (window - REAL_TAIL_BYTES.min(window / 2)) as usize;
    let split = bytes[wanted..bytes.len() - 1]
        .iter()
        .position(|&b| b == b'\n')
        .map(|n| wanted + n)
        .or_else(|| bytes[..wanted].iter().rposition(|&b| b == b'\n'))
        .expect("real history needs a line boundary near its end");
    let cold_len = start + split as u64 + 1;
    assert!(cold_len < len);
    fs::write(root.join("tail.jsonl"), &bytes[split + 1..]).unwrap();
    fs::write(
        root.join("real.json"),
        json!({"target":names[largest].to_str().unwrap(),"now":crate::backfill::now_rfc3339()})
            .to_string(),
    )
    .unwrap();
    fs::write(
        root.join("metadata.json"),
        json!({"files":names.len(),"decoded_bytes":total,"cold_bytes":total - (len - cold_len),
        "tail_bytes":len - cold_len,"files_sha256":files})
        .to_string(),
    )
    .unwrap();
    cold_len
}
fn prepare_synthetic(root: &Path) -> u64 {
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
            &scan_now(root),
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
            &scan_now(root),
        );
        assert_eq!(tail.len(), 3);
        fs::write(
            root.join(format!("{case}-expected.json")),
            serde_json::to_vec(&[cold, tail]).unwrap(),
        )
        .unwrap();
    }
    cold_len
}
/// The unmeasured parent's unpaged full-read controls over the whole input.
fn real_controls(root: &Path) {
    for case in ["legacy", "v2"] {
        let _cutover = (case == "v2").then(|| codex_counting_version::TestCutover::set(0));
        let mut full = Money::new();
        acquire(
            root,
            ScanIndex::default(),
            None,
            &mut full,
            &mut Observed::default(),
            &scan_now(root),
        );
        fs::write(
            root.join(format!("{case}-expected.json")),
            serde_json::to_vec(&[full]).unwrap(),
        )
        .unwrap();
    }
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
    let caps = caps();
    let real_src = std::env::var_os(REAL_DIR).map(PathBuf::from);
    let real = real_src.is_some();
    if real {
        // The parent's controls read the whole private input; bound them too.
        watchdog(started, caps.rss, 2 * caps.cpu_us, caps.total);
    }
    // Real work copies stay inside the private frozen directory.
    let fixture = Fixture(
        real_src
            .clone()
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "{}-{}-{}",
                if real {
                    ".ottto-rss-real-work"
                } else {
                    "ottto-synthetic-rss"
                },
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )),
    );
    let root = &fixture.0;
    let cold_len = match &real_src {
        Some(src) => {
            let cold_len = prepare_real(src, root);
            real_controls(root);
            cold_len
        }
        None => prepare_synthetic(root),
    };
    let prefix = if real { REAL_RECEIPT } else { RECEIPT };
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
            if child_started.elapsed() > caps.wall || started.elapsed() > caps.total {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("RSS measurement exceeded fixed wall cap");
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let log = String::from_utf8_lossy(&fs::read(log).unwrap()).into_owned();
        let receipts: Vec<_> = log
            .lines()
            .filter(|line| line.starts_with(prefix))
            .collect();
        if real {
            // The child log may hold private panic text: relay receipts only.
            for receipt in &receipts {
                println!("\n{receipt}");
            }
            assert!(status.success(), "{case} child failed: {status}");
            assert_eq!(receipts.len(), 1, "one receipt per child required");
            continue;
        }
        assert!(status.success(), "{case} child failed: {log}");
        assert_eq!(receipts.len(), 1, "one receipt per child required");
        println!("\n{}", receipts[0]);
    }
    assert!(started.elapsed() <= caps.total);
}
