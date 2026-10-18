//! Offline cursor-job, page-budget, S5 reader and singleton-memo tests.
//! Every fixture is synthetic; no provider account content.
use super::*;
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const NOW: &str = "2026-10-07T12:00:00Z";
const SESSION: &str = "019fa111-2222-7333-8444-555555555555";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ottto-codex-cursor-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        fs::write(&path, bytes).unwrap();
        Self(path)
    }
    fn append(&self, bytes: &[u8]) {
        let mut file = OpenOptions::new().append(true).open(&self.0).unwrap();
        file.write_all(bytes).unwrap();
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_file(&self.0);
    }
}

fn limits(cursor: u64, singleton: u64, skip_chunk: usize) -> Limits {
    Limits {
        cursor,
        singleton,
        skip_chunk,
    }
}

#[test]
fn page_budget_plans_cursor_singleton_and_deferral() {
    let limits = limits(100, 50, 8);
    let mut page = PageBudget::default();
    assert_eq!(page.plan(limits, 40, true, false), StartPlan::Singleton);
    assert_eq!(page.plan(limits, 60, true, false), StartPlan::Cursor);
    // One slot: a second large file waits for the next page.
    assert_eq!(page.plan(limits, 60, false, false), StartPlan::Defer);
    // After three invalidations the file is read unpaged, as before.
    assert_eq!(page.plan(limits, 60, false, true), StartPlan::Singleton);
    page.charge(false, 30);
    assert_eq!(page.plan(limits, 20, true, false), StartPlan::Singleton);
    assert_eq!(page.plan(limits, 21, true, false), StartPlan::Defer);
    page.charge(false, 40);
    // An unchanged file costs nothing and is never deferred.
    assert_eq!(page.plan(limits, 0, true, false), StartPlan::Singleton);
    assert!(!page.cursor_exhausted(limits));
    page.charge(true, 100);
    assert!(page.cursor_exhausted(limits));
    assert_eq!(page.plan(limits, 60, true, false), StartPlan::Defer);
}

#[test]
fn open_stamp_accepts_growth_and_refuses_shrink_or_replacement() {
    let temp = Temp::new("stamp", b"{\"a\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let open = OpenStamp::capture(&file).unwrap();
    assert!(open.append_compatible(&open.clone()));
    temp.append(b"{\"b\":2}\n");
    let grown = OpenStamp::capture(&file).unwrap();
    assert!(grown.extent > open.extent);
    assert!(open.append_compatible(&grown));
    fs::write(&temp.0, b"{}\n").unwrap();
    assert!(!open.append_compatible(&OpenStamp::capture(&file).unwrap()));
    let other = Temp::new("stamp-replacement", b"{\"a\":1}\n");
    fs::rename(&other.0, &temp.0).unwrap();
    let replaced = OpenStamp::capture(&File::open(&temp.0).unwrap()).unwrap();
    assert!(!open.append_compatible(&replaced));
}

fn reader_input() -> (Vec<u8>, u64, u64) {
    let mut input = b"{\"n\":1}\n".to_vec();
    input.extend_from_slice(format!("{{\"big\":\"{}\"}}\n", "x".repeat(200)).as_bytes());
    let second = input.len() as u64;
    input.extend_from_slice(b"{\"n\":2}\n");
    let frozen = input.len() as u64;
    input.extend_from_slice(b"{\"n\":3,\"after\":true}\n");
    (input, second, frozen)
}

#[test]
fn cursor_reader_chunks_overlong_skip_and_freezes_extent() {
    let (input, second, frozen) = reader_input();
    let mut reader =
        BoundedJsonlReader::new(BufReader::with_capacity(16, input.as_slice()), 64, false);
    reader.set_chunked_skip(32);
    // The frozen extent cuts the fourth record five bytes in.
    reader.set_extent_limit(frozen + 5);
    let mut seen = Vec::new();
    assert_eq!(
        reader.step(|value| seen.push(value.clone())).unwrap(),
        JsonlReaderStep::Line
    );
    assert_eq!(reader.record_start_offset(), 0);
    assert_eq!(reader.last_complete_line_end(), 8);
    assert!(!reader.lossy_prefix());
    let mut partials = 0;
    loop {
        match reader.step(|value| seen.push(value.clone())).unwrap() {
            JsonlReaderStep::Partial => {
                partials += 1;
                // A paused skip delivers and counts nothing.
                assert_eq!(reader.report.physical_line_count, 1);
                assert!(reader.buf.len() <= 64);
            }
            JsonlReaderStep::Line => break,
            JsonlReaderStep::Complete(_) => panic!("overlong line must finish"),
        }
    }
    assert!(partials > 0, "the skip paused at least once");
    assert_eq!(reader.record_start_offset(), 8);
    assert_eq!(reader.last_complete_line_end(), second);
    assert_eq!(reader.report.over_line_cap_count, 1);
    assert!(reader.lossy_prefix());
    assert_eq!(
        reader.step(|value| seen.push(value.clone())).unwrap(),
        JsonlReaderStep::Line
    );
    assert_eq!(reader.record_start_offset(), second);
    assert!(matches!(
        reader.step(|value| seen.push(value.clone())).unwrap(),
        JsonlReaderStep::Complete(_)
    ));
    assert!(reader.sealed_fragment());
    assert_eq!(reader.consumed_bytes(), frozen + 5);
    assert_eq!(reader.last_complete_line_end(), frozen);
    assert_eq!(reader.report.physical_line_count, 3);
    assert_eq!(seen, vec![json!({"n":1}), json!({"n":2})]);
}

#[test]
fn chunked_reader_matches_unchunked_reader_without_extent() {
    let (input, _, _) = reader_input();
    let read = |chunked: bool| {
        let mut reader =
            BoundedJsonlReader::new(BufReader::with_capacity(16, input.as_slice()), 64, true);
        if chunked {
            reader.set_chunked_skip(32);
        }
        let mut seen = Vec::new();
        loop {
            match reader.step(|value| seen.push(value.clone())).unwrap() {
                JsonlReaderStep::Line | JsonlReaderStep::Partial => {}
                JsonlReaderStep::Complete(report) => {
                    assert!(!reader.sealed_fragment());
                    return (seen, report, reader.consumed_bytes());
                }
            }
        }
    };
    let chunked = read(true);
    assert_eq!(chunked, read(false));
    assert_eq!(chunked.2, input.len() as u64);
    assert_eq!(chunked.1.physical_line_count, 4);
}

#[test]
fn monotone_holds_are_fork_and_broken_ordinal_streams_only() {
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
    assert!(!held_monotone(&accumulator));
    accumulator.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
    assert!(held_monotone(&accumulator));
    for boundary in [
        CodexOwnershipBoundary::NativeCreatedThread,
        CodexOwnershipBoundary::Ordinal { start: 3 },
    ] {
        accumulator.codex_ownership_boundary = boundary;
        accumulator.codex_ordinal_sequence_valid = true;
        assert!(!held_monotone(&accumulator));
        accumulator.codex_ordinal_sequence_valid = false;
        assert!(held_monotone(&accumulator));
    }
    accumulator.codex_ownership_boundary = CodexOwnershipBoundary::AllLocal;
    assert!(!held_monotone(&accumulator));
    assert_eq!(memo_counting_decision(), "legacy");
}

fn disclosure() -> Disclosure {
    Disclosure {
        ownership_incomplete_file_count: 1,
        zero_snapshot_usage_evidence: false,
        state_only_blocked_session_ids: vec![SESSION.into()],
        diagnostic_reason: FileReason::OwnershipIncomplete,
        parsed_snapshot_count: 0,
    }
}

#[test]
fn memo_entry_matches_growth_but_not_prefix_or_parent_change() {
    let temp = Temp::new("memo", b"{\"n\":1}\n{\"n\":2}\n");
    let file = File::open(&temp.0).unwrap();
    assert!(LiveWitness::read(&file, 0).is_none());
    assert!(LiveWitness::read(&file, 10_000).is_none());
    let live = LiveWitness::read(&file, 8).unwrap();
    let parent = Some(("parent".to_owned(), Some("ledger-1".to_owned())));
    let entry = MemoEntry::new("digest".into(), live, parent, disclosure());
    assert_eq!(entry.parent_ref(), Some("parent"));
    assert!(entry.matches("digest", &file, Some("ledger-1".into())));
    assert!(!entry.matches("other", &file, Some("ledger-1".into())));
    assert!(!entry.matches("digest", &file, Some("ledger-2".into())));
    assert!(!entry.matches("digest", &file, None));
    // Growth past the refused offset cannot cure the hold: still a hit.
    temp.append(b"{\"n\":3}\n");
    assert!(entry.matches("digest", &file, Some("ledger-1".into())));
    // A rewritten prefix is a miss (re-read).
    fs::write(&temp.0, b"{\"n\":9}\n{\"n\":2}\n{\"n\":3}\n").unwrap();
    assert!(!entry.matches("digest", &file, Some("ledger-1".into())));
}

#[test]
fn singleton_memo_is_bounded_lru_with_frozen_charges() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let temp = Temp::new("memo-lru", b"{\"n\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let entry = MemoEntry::new(
        "digest".into(),
        LiveWitness::read(&file, 8).unwrap(),
        None,
        disclosure(),
    );
    let mut memo = SingletonMemo::default();
    for index in 0..MEMO_ENTRIES {
        assert!(memo.insert(format!("key-{index}"), entry.clone()));
    }
    memo.touch("key-0");
    assert!(memo.insert("key-new".into(), entry.clone()));
    assert_eq!(memo.entries.len(), MEMO_ENTRIES);
    assert!(memo.entries.contains_key("key-0"));
    assert!(!memo.entries.contains_key("key-1"));
    assert!(memo.entries.values().all(|entry| entry.charge > 0));
    let charged = crate::heap_layout_bound::bound(&memo, usize::MAX).unwrap();
    let frozen: usize = memo.entries.values().map(|entry| entry.charge).sum();
    assert!(charged >= frozen);
    memo.remove("key-0");
    assert!(!memo.entries.contains_key("key-0"));
}

fn codex_line(value: Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(&value).unwrap();
    line.push(b'\n');
    line
}

fn token_line(n: u64) -> Vec<u8> {
    codex_line(
        json!({"timestamp": "2026-10-07T10:30:00Z", "type": "event_msg",
        "payload": {"type": "token_count", "info": {"model": "fixture-model",
        "total_token_usage": {"input_tokens": n * 100, "cached_input_tokens": n * 50,
            "output_tokens": n * 10},
        "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
            "output_tokens": 10}}}}),
    )
}

struct ScanRoot {
    _dir: Temp,
    root: PathBuf,
}
impl ScanRoot {
    fn new(lines: usize) -> Self {
        let dir = Temp::new("scan", b"");
        fs::remove_file(&dir.0).unwrap();
        let root = dir.0.join("home/.codex/sessions");
        fs::create_dir_all(&root).unwrap();
        let mut body = codex_line(json!({"timestamp": "2026-10-07T10:00:00Z",
            "type": "session_meta", "payload": {"id": SESSION}}));
        for n in 1..=lines as u64 {
            body.extend(token_line(n));
        }
        fs::write(
            root.join(format!("rollout-2026-10-07T10-00-00-{SESSION}.jsonl")),
            body,
        )
        .unwrap();
        Self { _dir: dir, root }
    }
}

/// One page: one `OwnedSourceScan` stepped to completion, then the same
/// post-policy finalization the production collector applies.
fn page(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
) -> (ScanIndex, SourceScanResult) {
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    );
    if let Some(cache) = cache {
        scan = scan.with_sampled_acquisition(cache, Scope("cursor-fixture".into()));
    }
    loop {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan);
            }
        }
    }
}

fn fingerprints(scan: &SourceScanResult) -> Vec<String> {
    scan.snapshots
        .iter()
        .map(|snapshot| snapshot.snapshot_fingerprint.clone())
        .collect()
}

#[test]
fn paged_singleton_matches_unpaged_read_across_scan_objects() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(80);
    let (_, unpaged) = page(&fixture, ScanIndex::default(), None);
    assert!(!unpaged.snapshots.is_empty());
    let cache = Arc::new(SharedCache::default());
    let paged = with_test_limits(2048, 1024, 64, || {
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            let completed = cache
                .with_cursor(|cursor| cursor.counters.jobs_completed)
                .unwrap();
            if completed > 0 {
                return scan;
            }
            assert!(
                scan.snapshots.is_empty(),
                "a paused job publishes nothing for its file"
            );
        }
        panic!("cursor job did not complete within 64 pages");
    });
    let counters = cache.with_cursor(|cursor| {
        (
            cursor.counters.jobs_started,
            cursor.counters.jobs_paused,
            cursor.counters.jobs_resumed,
            cursor.counters.jobs_completed,
            cursor.counters.jobs_invalidated,
            cursor.counters.jobs_lost,
        )
    });
    eprintln!("CODEX_CURSOR_PARITY counters={counters:?}");
    let (started, paused, resumed, completed, invalidated, lost) = counters.unwrap();
    assert_eq!((started, completed, invalidated, lost), (1, 1, 0, 0));
    assert!(paused > 0 && resumed == paused);
    assert!(cache.cursor_slot_free());
    assert_eq!(cache.cursor_charge(), 0);
    assert_eq!(fingerprints(&paged), fingerprints(&unpaged));
}

#[test]
fn uncached_scan_never_pages() {
    let fixture = ScanRoot::new(40);
    let (_, full) = page(&fixture, ScanIndex::default(), None);
    let scaled = with_test_limits(256, 128, 16, || {
        page(&fixture, ScanIndex::default(), None).1
    });
    assert_eq!(fingerprints(&scaled), fingerprints(&full));
}

/// §r sizing at the measured event counts. Prints the figures for the PR;
/// asserts only invariants. CI only (heavy; never run on the Mac).
#[test]
fn accumulator_heap_bound_at_measured_event_counts() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // (case, token counts or UI events, native items, turns, compactions)
    let cases = [
        (
            "A-3653fb67",
            12_468_usize,
            12_162_usize,
            0_usize,
            109_usize,
            true,
        ),
        ("B-486c5751", 9_990, 6_873, 0, 81, false),
        ("C-af9d28a0", 8_134, 8_174, 0, 53, false),
        ("D-c61fd635", 4_771, 4_783, 1_164, 70, false),
    ];
    for (case, first, native, turns, compactions, token_counts) in cases {
        let mut body = codex_line(json!({"timestamp": "2026-10-07T10:00:00Z",
            "type": "session_meta", "payload": {"id": SESSION}}));
        let events = first + native + turns + compactions;
        for event in 0..events {
            let line = if event % (events / compactions.max(1)).max(1) == 0
                && event / (events / compactions.max(1)).max(1) < compactions
            {
                codex_line(
                    json!({"timestamp": "2026-10-07T10:10:00Z", "type": "compacted",
                    "payload": {"replacement_history": []}}),
                )
            } else if turns > 0 && event % (events / turns).max(1) == 1 {
                codex_line(
                    json!({"timestamp": "2026-10-07T10:10:00Z", "type": "turn_context",
                    "payload": {"turn_id": format!("turn-{event}"), "model": "fixture-model"}}),
                )
            } else if event % 2 == 0 {
                if token_counts {
                    token_line(event as u64 + 1)
                } else {
                    codex_line(json!({"timestamp": "2026-10-07T10:10:00Z",
                        "type": "event_msg", "payload": {"type": "agent_message",
                        "message": "synthetic"}}))
                }
            } else {
                codex_line(json!({"timestamp": "2026-10-07T10:10:00Z",
                    "type": "response_item", "payload": {"type": "message",
                    "role": "assistant", "content": [{"type": "output_text",
                    "text": "synthetic"}]}}))
            };
            body.extend(line);
        }
        body.extend(codex_line(json!({"timestamp": "2026-10-07T10:20:00Z",
            "big": "x".repeat(MAX_JSONL_LINE_BYTES + 1)})));
        let temp = Temp::new("sizing", &body);
        let mut parser = OwnedJsonlParser::new(
            File::open(&temp.0).unwrap(),
            &temp.0,
            SnapshotSource::Codex,
            apply_codex_line,
            Some(&CodexTitleMetadata::default()),
            None,
            None,
            false,
            true,
        )
        .unwrap();
        let mut peak = None::<usize>;
        let mut first_pause = None::<usize>;
        let mut steps = 0_usize;
        while !parser.step().unwrap() {
            steps += 1;
            if steps % 2_048 == 0 {
                let bound = crate::heap_layout_bound::bound(&parser, usize::MAX);
                first_pause = first_pause.or(bound);
                peak = peak.max(bound);
            }
        }
        let accumulator = crate::heap_layout_bound::bound(&parser.accumulator, usize::MAX);
        let walked = crate::heap_layout_bound::bound(&parser, usize::MAX);
        let buffer = parser.reader.buf.capacity();
        eprintln!(
            "CODEX_SIZING case={case} events={events} final_parser={walked:?} \
             peak_parser={peak:?} accumulator={accumulator:?} reader_buffer_capacity={buffer} \
             over_line_cap={}",
            parser.reader.report.over_line_cap_count
        );
        assert_eq!(parser.reader.report.over_line_cap_count, 1);
        if let (Some(walked), Some(accumulator)) = (walked, accumulator) {
            // The paused charge walks the reader buffer with the accumulator.
            assert!(walked >= accumulator.saturating_add(buffer));
        }
        if let (Some(first), Some(peak)) = (first_pause, peak) {
            assert!(peak >= first);
        }
    }
}
