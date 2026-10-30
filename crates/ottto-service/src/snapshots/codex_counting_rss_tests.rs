//! Regression: unretained history must be reread after appended usage.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle;
use crate::transcript_acquisition::Scope;
use std::io::{BufWriter, Write};

const NOW: &str = "2026-10-25T12:00:00Z";
const AT: &str = "2026-10-25T10:00:00Z";
const PENDING: &str = "019fa111-2222-7333-8444-000000000002";

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

fn write_row(file: &mut impl Write, value: &Value, records: &mut u64) {
    serde_json::to_writer(&mut *file, value).unwrap();
    file.write_all(b"\n").unwrap();
    *records += 1;
    assert!(*records <= 100_000, "fixture record cap");
}

fn next_census_time(now: &str) -> String {
    (OffsetDateTime::parse(now, &Rfc3339).unwrap() + time::Duration::seconds(1))
        .format(&Rfc3339)
        .unwrap()
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

fn acquire(
    root: &Path,
    mut index: ScanIndex,
    cache: Option<&Arc<sampled_scan::SharedCache>>,
    out: &mut Money,
    observed: &mut Observed,
    now: &str,
) -> ScanIndex {
    let real = false;
    // Keep read modes for this acquisition separately from the cold round.
    observed.selection = SelectionCounts::default();
    for _ in 0..32 {
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
