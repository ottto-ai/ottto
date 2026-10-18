//! Offline cursor-job, page-budget, S5 reader and singleton-memo tests.
//! Every fixture is synthetic; no provider account content.
use super::*;
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::os::unix::fs::FileExt;
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
    assert_eq!(page.plan(limits, 40, true, true), StartPlan::Singleton);
    assert_eq!(page.plan(limits, 60, true, true), StartPlan::Cursor);
    // One slot: a second large file waits for the next page. There is no
    // unpaged fallback on a supported build.
    assert_eq!(page.plan(limits, 60, false, true), StartPlan::Defer);
    // C4: without layout support the cursor is off as a whole and a large
    // file reads in its page as before; small reads keep their budget.
    assert_eq!(page.plan(limits, 60, true, false), StartPlan::Unpaged);
    assert_eq!(page.plan(limits, 60, false, false), StartPlan::Unpaged);
    assert_eq!(page.plan(limits, 40, true, false), StartPlan::Singleton);
    page.charge(false, 30);
    assert_eq!(page.plan(limits, 20, true, true), StartPlan::Singleton);
    assert_eq!(page.plan(limits, 21, true, true), StartPlan::Defer);
    assert_eq!(page.plan(limits, 21, true, false), StartPlan::Defer);
    page.charge(false, 40);
    // An unchanged file costs nothing and is never deferred.
    assert_eq!(page.plan(limits, 0, true, true), StartPlan::Singleton);
    assert!(!page.cursor_exhausted(limits));
    page.charge(true, 100);
    assert!(page.cursor_exhausted(limits));
    assert_eq!(page.plan(limits, 60, true, true), StartPlan::Defer);
    // The disabled cursor is disclosed once per scan object.
    let cache = SharedCache::default();
    page.disclose_disabled(&cache);
    page.disclose_disabled(&cache);
    let disclosed = |cache: &SharedCache| {
        cache
            .with_cursor(|cursor| cursor.counters.cursor_disabled_unsupported_layout)
            .unwrap()
    };
    assert_eq!(disclosed(&cache), 1);
    PageBudget::default().disclose_disabled(&cache);
    assert_eq!(disclosed(&cache), 2);
}

#[test]
fn repeated_invalidations_end_as_member_changed_and_parked_files_wake_on_input_change() {
    let mut state = CursorState::default();
    for _ in 1..MEMBER_CHANGED_AFTER {
        assert!(!invalidated(&mut state, "key"));
    }
    assert!(invalidated(&mut state, "key"));
    assert_eq!(
        state.counters.jobs_invalidated,
        u64::from(MEMBER_CHANGED_AFTER)
    );
    assert_eq!(state.counters.jobs_member_changed, 1);
    // The count restarts after the disclosure.
    assert!(!invalidated(&mut state, "key"));
    let cache = SharedCache::default();
    cache.with_cursor(|cursor| {
        park(
            cursor,
            "key".into(),
            Parked {
                source_file_fingerprint: "revision-1".into(),
                dependencies: Some("dependencies".into()),
                disclosure: disclosure(),
            },
        )
    });
    // Unchanged inputs: the parked debt is disclosed again, nothing is read.
    let parked = cache.cursor_parked("key", "revision-1", Some("dependencies"));
    assert_eq!(
        parked.map(|disclosure| disclosure.state_only_blocked_session_ids),
        Some(vec![SESSION.to_owned()])
    );
    assert!(cache
        .cursor_parked("key", "revision-1", Some("other"))
        .is_none());
    // A changed dependency woke it: the record is gone and the file retries.
    assert!(cache
        .cursor_parked("key", "revision-1", Some("dependencies"))
        .is_none());
    cache.with_cursor(|cursor| {
        for index in 0..=PARKED_KEYS {
            park(
                cursor,
                format!("key-{index:03}"),
                Parked {
                    source_file_fingerprint: "revision-1".into(),
                    dependencies: None,
                    disclosure: disclosure(),
                },
            );
        }
        assert_eq!(cursor.parked.len(), PARKED_KEYS);
        assert_eq!(cursor.counters.parked_hits, 1);
    });
    cache.clear();
    assert!(cache
        .with_cursor(|cursor| cursor.parked.is_empty())
        .unwrap());
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
    assert_eq!(reader.last_complete_line_end(), second);
    assert_eq!(reader.report.over_line_cap_count, 1);
    assert!(reader.lossy_prefix());
    assert_eq!(
        reader.step(|value| seen.push(value.clone())).unwrap(),
        JsonlReaderStep::Line
    );
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

/// Parent S5 "Critical" (R1-B4): at sealed cursor completion a final record
/// without its newline at or before the frozen extent is never parsed,
/// counted or certified, even when no byte beyond the extent is visible.
/// A read without an extent keeps today's trailing-line behavior.
#[test]
fn sealed_completion_withholds_unterminated_record_even_at_end_of_file() {
    let mut input = b"{\"n\":1}\n{\"n\":2}\n".to_vec();
    let sealed = input.len() as u64;
    input.extend_from_slice(b"{\"n\":3}");
    let read = |extent: Option<u64>| {
        let mut reader =
            BoundedJsonlReader::new(BufReader::with_capacity(16, input.as_slice()), 64, false);
        if let Some(extent) = extent {
            reader.set_extent_limit(extent);
        }
        let mut seen = Vec::new();
        loop {
            match reader.step(|value| seen.push(value.clone())).unwrap() {
                JsonlReaderStep::Line | JsonlReaderStep::Partial => {}
                JsonlReaderStep::Complete(report) => return (seen, report, reader),
            }
        }
    };
    // The file ends exactly at the extent: nothing beyond it is visible.
    let (seen, report, reader) = read(Some(input.len() as u64));
    assert_eq!(seen, vec![json!({"n":1}), json!({"n":2})]);
    assert!(reader.sealed_fragment());
    assert_eq!(report.physical_line_count, 2);
    assert_eq!(report.parsed_json_line_count, 2);
    assert_eq!(reader.last_complete_line_end(), sealed);
    assert!(reader.consumed_bytes() > reader.last_complete_line_end());
    // Unchanged non-cursor trailing-line behavior: the last line is parsed.
    let (seen, report, reader) = read(None);
    assert_eq!(seen, vec![json!({"n":1}), json!({"n":2}), json!({"n":3})]);
    assert!(!reader.sealed_fragment());
    assert_eq!(report.physical_line_count, 3);
    assert_eq!(report.parsed_json_line_count, 3);
}

/// S12 (R1-B5): `finish` honours a grown object only for the identity the
/// passed certificate proved, and only while the held FD is still that
/// object and no shorter than the frozen extent.
#[test]
fn sealed_prefix_grant_holds_only_for_the_certified_object() {
    let temp = Temp::new("prefix-grant", b"{\"a\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let open = OpenStamp::capture(&file).unwrap();
    let grant = SealedPrefix {
        dev: open.dev,
        ino: open.ino,
        extent: open.extent,
    };
    assert!(grant.holds(&file));
    temp.append(b"{\"b\":2}\n");
    assert!(grant.holds(&file), "growth past the frozen extent");
    assert!(!SealedPrefix {
        extent: open.extent + 1_000,
        ..grant
    }
    .holds(&file));
    let other = Temp::new("prefix-grant-other", b"{\"a\":1}\n{\"b\":2}\n");
    assert!(!grant.holds(&File::open(&other.0).unwrap()));
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
    // A parented created thread keeps the ordinal-only rule.
    accumulator.codex_parent_session_ref = Some("parent".into());
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

/// C6: #597's parentless created-thread hold is memoized only where an
/// append cannot cure it.
#[test]
fn parentless_created_thread_hold_is_monotone_only_when_append_incurable() {
    let proven = || {
        let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
        accumulator.codex_ownership_boundary = CodexOwnershipBoundary::NativeCreatedThread;
        accumulator.codex_ordinal_sequence_valid = true;
        accumulator.codex_sidecar_projected_next_ordinal = Some(1);
        accumulator
    };
    // Every set-only conjunct holds; only usage (append-curable) may be
    // missing: never memoized.
    assert!(!held_monotone(&proven()));
    let incurable: [fn(&mut SnapshotAccumulator); 5] = [
        |a| a.codex_ordinal_sequence_valid = false,
        |a| a.codex_native_created_thread_valid = false,
        |a| a.codex_creator_evidence_conflicted = true,
        |a| a.origin.parent_session_ref = Some("parent".into()),
        |a| a.origin.source_subagent = Some(true),
    ];
    for set in incurable {
        let mut accumulator = proven();
        set(&mut accumulator);
        assert!(held_monotone(&accumulator));
    }
    // Missing sidecar projection (no `trace_id`, or a disagreeing state
    // row): no append cures it, a sidecar change does. It is memoized, and
    // the sidecar facts in `reduction_dependencies` (the memo digest) wake it.
    let mut accumulator = proven();
    accumulator.codex_sidecar_projected_next_ordinal = None;
    assert!(held_monotone(&accumulator));
    // A parent ref makes it a parented created thread: ordinal rule only.
    accumulator.codex_parent_session_ref = Some("parent".into());
    assert!(!held_monotone(&accumulator));
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

/// C2: no time-based expiry. A memo entry wakes on cheap changed evidence
/// only: an object change, shrink or same-length stamp change of the held
/// file, a head or boundary sample mismatch at the refused offset, or a
/// changed digest dependency or parent ledger.
///
/// Premise (disclosed): an in-place interior edit outside the samples that
/// also appends is not detected until the entry is lost (restart, LRU
/// eviction) or a dependency changes. A miss is never treated as proof of
/// uniqueness; it only costs a re-read.
#[test]
fn memo_entry_matches_growth_but_not_prefix_or_parent_change() {
    let temp = Temp::new("memo", b"{\"n\":1}\n{\"n\":2}\n");
    let file = File::open(&temp.0).unwrap();
    assert!(LiveWitness::read(&file, 0).is_none());
    assert!(LiveWitness::read(&file, 10_000).is_none());
    let live = LiveWitness::read(&file, 8).unwrap();
    let stamp = OpenStamp::capture(&file).unwrap();
    let parent = Some(("parent".to_owned(), Some("ledger-1".to_owned())));
    let entry = MemoEntry::new("digest".into(), live, stamp, parent, disclosure());
    assert_eq!(entry.parent_ref(), Some("parent"));
    assert!(entry
        .matches("digest", &file, Some("ledger-1".into()))
        .is_some());
    assert!(entry
        .matches("other", &file, Some("ledger-1".into()))
        .is_none());
    assert!(entry
        .matches("digest", &file, Some("ledger-2".into()))
        .is_none());
    assert!(entry.matches("digest", &file, None).is_none());
    // Growth past the refused offset cannot cure the hold: still a hit, and
    // the hit returns the grown stamp for the entry to keep.
    temp.append(b"{\"n\":3}\n");
    let grown = entry
        .matches("digest", &file, Some("ledger-1".into()))
        .expect("growth is a hit");
    assert!(grown.extent > entry.stamp.extent);
    let mut refreshed = entry.clone();
    refreshed.stamp = grown;
    // No timer: an entry whose evidence is unchanged keeps matching.
    assert!(refreshed
        .matches("digest", &file, Some("ledger-1".into()))
        .is_some());
    // A same-length stamp change (an in-place write elsewhere) wakes it.
    OpenOptions::new()
        .write(true)
        .open(&temp.0)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
        .unwrap();
    assert!(refreshed
        .matches("digest", &file, Some("ledger-1".into()))
        .is_none());
    // A rewritten prefix is a miss (re-read).
    fs::write(&temp.0, b"{\"n\":9}\n{\"n\":2}\n{\"n\":3}\n").unwrap();
    assert!(entry
        .matches("digest", &file, Some("ledger-1".into()))
        .is_none());
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
        OpenStamp::capture(&file).unwrap(),
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
    // A cache reset drops every memo entry with the paused slot.
    let cache = SharedCache::default();
    cache.memo_record("key".into(), entry);
    assert!(cache.memo_lookup("key").is_some());
    cache.clear();
    assert!(cache.memo_lookup("key").is_none());
    assert!(cache.cursor_slot_free());
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

const SESSION_B: &str = "019fa111-2222-7333-8444-666666666666";

struct ScanRoot {
    _dir: Temp,
    root: PathBuf,
}
impl ScanRoot {
    fn new(lines: usize) -> Self {
        Self::with_sessions(&[(SESSION, lines)])
    }
    fn with_sessions(sessions: &[(&str, usize)]) -> Self {
        let dir = Temp::new("scan", b"");
        fs::remove_file(&dir.0).unwrap();
        let root = dir.0.join("home/.codex/sessions");
        fs::create_dir_all(&root).unwrap();
        let fixture = Self { _dir: dir, root };
        for (session, lines) in sessions {
            let mut body = codex_line(json!({"timestamp": "2026-10-07T10:00:00Z",
                "type": "session_meta", "payload": {"id": session}}));
            for n in 1..=*lines as u64 {
                body.extend(token_line(n));
            }
            fs::write(fixture.file(session), body).unwrap();
        }
        fixture
    }
    fn file(&self, session: &str) -> PathBuf {
        self.root
            .join(format!("rollout-2026-10-07T10-00-00-{session}.jsonl"))
    }
    fn append(&self, session: &str, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(self.file(session))
            .unwrap();
        file.write_all(bytes).unwrap();
    }
    fn len(&self, session: &str) -> u64 {
        fs::metadata(self.file(session)).unwrap().len()
    }
}

/// One page: one `OwnedSourceScan` stepped to completion, then the same
/// post-policy finalization the production collector applies.
fn page(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
) -> (ScanIndex, SourceScanResult) {
    let (index, scan, _) = page_in(fixture, index, cache, "cursor-fixture");
    (index, scan)
}

/// Read modes selected in one page: (full, tail).
type Modes = (usize, usize);

fn page_in(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
    namespace: &str,
) -> (ScanIndex, SourceScanResult, Modes) {
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
        scan = scan.with_sampled_acquisition(cache, Scope(namespace.into()));
    }
    let mut modes = (0, 0);
    loop {
        if let Some(context) = scan.sampling.as_ref() {
            modes = (context.full_files, context.tail_files);
        }
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
                return (index, scan, modes);
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
                .with_cursor(|cursor| cursor.counters.jobs_certified)
                .unwrap();
            if completed > 0 {
                // The attempt consumed the path that held the census.
                assert!(index
                    .traversal
                    .as_ref()
                    .map_or(true, |traversal| traversal.pending_candidates.is_empty()));
                return scan;
            }
            assert!(
                scan.snapshots.is_empty(),
                "a paused job publishes nothing for its file"
            );
        }
        panic!(
            "cursor job did not complete within 64 pages: {}",
            counters(&cache)
        );
    });
    let counters = cache.with_cursor(|cursor| {
        (
            cursor.counters.jobs_started,
            cursor.counters.jobs_paused,
            cursor.counters.jobs_resumed,
            cursor.counters.jobs_certified,
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

fn counter(cache: &SharedCache, read: fn(&Counters) -> u64) -> u64 {
    cache.with_cursor(|cursor| read(&cursor.counters)).unwrap()
}

fn counters(cache: &SharedCache) -> String {
    cache
        .with_cursor(|cursor| format!("{:?}", cursor.counters))
        .unwrap_or_default()
}

fn pending_hint(index: &ScanIndex, path: &Path) -> Option<bool> {
    index
        .traversal
        .as_ref()?
        .pending_candidates
        .iter()
        .find(|pending| pending.path == path)
        .map(|pending| pending.watcher_hint)
}

/// Restores the real scan clock when a test ends or panics.
struct TestClock;
impl TestClock {
    fn set(&self, now: u64) {
        super::super::set_test_now(Some(now));
    }
}
impl Drop for TestClock {
    fn drop(&mut self) {
        super::super::set_test_now(None);
    }
}

/// R2-M6 #1 with the §e.2 essential-acceptance assertions (i)–(iii): an
/// active singleton larger than B, appended every page.
#[test]
fn active_member_larger_than_budget_appended_every_page_audit_semantics() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    let interval = crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS;
    // Lever (i) is undecided, so P1 runs outcome D (strict `AuditDue`).
    // Under G a tail would also be permitted while an audit is queued; the
    // per-page tail check below holds under both outcomes.
    const LEVER_GRACE: bool = false;
    const B: u64 = 2048;
    with_test_limits(B, 8192, 64, || {
        // (i) and (ii): a short page interval, well inside the deadline.
        let fixture = ScanRoot::new(80);
        let path = fixture.file(SESSION);
        let key = local_index_key(&path);
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        let mut now = 1_900_000_000_u64;
        let mut next_line = 81;
        let mut opened = None;
        for _ in 0..64 {
            clock.set(now);
            let started = counter(&cache, |c| c.jobs_started);
            let open_length = fixture.len(SESSION);
            let (next, scan, _) =
                page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
            index = next;
            if counter(&cache, |c| c.jobs_started) > started {
                opened = Some((now, open_length));
            }
            if counter(&cache, |c| c.jobs_certified) == 1 {
                assert!(!scan.snapshots.is_empty(), "the certified read publishes");
                break;
            }
            assert!(scan.snapshots.is_empty(), "a paused job publishes nothing");
            fixture.append(SESSION, &token_line(next_line));
            next_line += 1;
            now += 10;
        }
        let (t_start, open_length) = opened.expect("a cursor job opened");
        let certified = cache
            .retained_checkpoint(&key)
            .unwrap_or_else(|| panic!("certified prefix retained: {}", counters(&cache)));
        // (i) `[0, s)` with `s <= L0`, verified at the read's start.
        assert_eq!(counter(&cache, |c| c.jobs_certified), 1);
        assert_eq!(counter(&cache, |c| c.jobs_invalidated), 0);
        assert!(certified.sealed_offset() <= open_length);
        assert!(certified.sealed_offset() < fixture.len(SESSION));
        assert_eq!(certified.last_full_verified(), t_start);
        assert_eq!(certified.audit_debt(), None);
        // Appends during the job were never marked read: the path stays
        // pending as a watcher hint (C7) and the next page tails from `s`.
        assert_eq!(pending_hint(&index, &path), Some(true));
        fixture.append(SESSION, &token_line(next_line));
        next_line += 1;
        now += 10;
        clock.set(now);
        let (_, scan, modes) = page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
        // (ii) a tail from `s` while the deadline permits.
        assert_eq!(modes, (0, 1));
        assert!(!scan.snapshots.is_empty());
        let tailed = cache.retained_checkpoint(&key).expect("tail retained");
        assert_eq!(tailed.sealed_offset(), fixture.len(SESSION));
        assert_eq!(tailed.last_full_verified(), t_start);
        assert_eq!(counter(&cache, |c| c.jobs_started), 1);

        // (iii) scaled `L > L_max`: pages 600 s apart, so one read of
        // `ceil(L/B)` pages outlives the interval.
        let fixture = ScanRoot::new(80);
        let path = fixture.file(SESSION);
        let key = local_index_key(&path);
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        let mut opened = None;
        let mut completions = Vec::new();
        let mut tails = 0;
        for page_number in 0..64_u64 {
            clock.set(now);
            let started = counter(&cache, |c| c.jobs_started);
            let certified = counter(&cache, |c| c.jobs_certified);
            let retained = cache.retained_checkpoint(&key);
            let open_length = fixture.len(SESSION);
            let (next, scan, modes) =
                page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
            index = next;
            if counter(&cache, |c| c.jobs_started) > started {
                opened = Some((now, open_length));
            }
            if modes.1 > 0 {
                // Every tail is permitted by the deadline or by G's grace.
                let permitted = retained
                    .as_ref()
                    .is_some_and(|retained| now < retained.last_full_verified() + interval);
                assert!(permitted || LEVER_GRACE, "tail past the audit deadline");
                tails += modes.1;
            }
            if counter(&cache, |c| c.jobs_certified) > certified {
                let (t_start, open_length) = opened.expect("job opened");
                let checkpoint = cache.retained_checkpoint(&key).expect("certificate");
                assert!(
                    !scan.snapshots.is_empty(),
                    "each audit completion publishes"
                );
                assert!(checkpoint.sealed_offset() <= open_length);
                // No deadline reset: verified at read start, still due.
                assert_eq!(checkpoint.last_full_verified(), t_start);
                assert_eq!(
                    checkpoint.audit_debt().map(|debt| debt.due_unix_seconds),
                    Some(t_start + interval)
                );
                let due = index.files[&key]
                    .audit_obligation(now)
                    .map(|debt| debt.due_unix_seconds);
                assert!(due.is_some_and(|due| due <= t_start + interval && due <= now));
                completions.push((page_number, open_length));
                if completions.len() == 2 {
                    break;
                }
            } else {
                assert!(
                    scan.snapshots.is_empty(),
                    "nothing publishes between audits"
                );
            }
            fixture.append(SESSION, &token_line(next_line));
            next_line += 1;
            now += 600;
        }
        assert_eq!(completions.len(), 2, "two audits: {}", counters(&cache));
        let (first, _) = completions[0];
        let (second, open_length) = completions[1];
        // The next audit opens right after a completion and publishes every
        // `ceil(L/B)` pages; a page overshoots B by at most one record.
        let record = token_line(next_line).len() as u64;
        let pages = second - first;
        assert!(
            open_length.div_ceil(B + record) <= pages && pages <= open_length.div_ceil(B),
            "{pages} pages for {open_length} bytes"
        );
        assert_eq!(counter(&cache, |c| c.audit_overdue), 2);
        if !LEVER_GRACE {
            assert_eq!(tails, 0, "outcome D: no tails above L_max");
        }
    });
}

/// C1 at scan level: an in-place edit of already-parsed bytes inside the
/// head sample, made while the paused job's file also grew, invalidates the
/// attempt. Nothing publishes, nothing commits, and the path stays pending;
/// the next attempt certifies the stable file.
#[test]
fn grown_member_with_in_place_head_edit_restarts_and_publishes_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let path = fixture.file(SESSION);
    let key = local_index_key(&path);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 4096, 64, || {
        let (mut index, scan) = page(&fixture, ScanIndex::default(), Some(Arc::clone(&cache)));
        assert!(scan.snapshots.is_empty());
        assert!(
            !cache.cursor_slot_free(),
            "the job paused: {}",
            counters(&cache)
        );
        // Same length, inside `[0, 4 KiB)`: `10:00:00` becomes `10:00:01`.
        let bytes = fs::read(&path).unwrap();
        let at = bytes
            .windows(8)
            .position(|window| window == b"10:00:00")
            .unwrap()
            + 7;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all_at(b"1", at as u64)
            .unwrap();
        fixture.append(SESSION, &token_line(41));
        for _ in 0..32 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if counter(&cache, |c| c.jobs_invalidated) == 1 {
                assert!(
                    scan.snapshots.is_empty(),
                    "an invalidated attempt publishes nothing"
                );
                assert_eq!(counter(&cache, |c| c.jobs_certified), 0);
                assert!(cache.retained_checkpoint(&key).is_none());
                assert!(
                    pending_hint(&index, &path).is_some(),
                    "the path stays pending"
                );
                break;
            }
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_invalidated),
            1,
            "{}",
            counters(&cache)
        );
        for _ in 0..32 {
            let (next, _) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_certified),
            1,
            "{}",
            counters(&cache)
        );
        assert_eq!(counter(&cache, |c| c.jobs_started), 2);
        assert_eq!(counter(&cache, |c| c.jobs_member_changed), 0);
    });
}

/// C7: a singleton deferred by the aggregate page budget goes back to
/// `pending_candidates` with its selection flags, watcher hint included.
#[test]
fn singleton_aggregate_page_budget_defers_via_pending_keeps_hint() {
    let fixture = ScanRoot::with_sessions(&[(SESSION, 8), (SESSION_B, 8)]);
    let size = fixture.len(SESSION).max(fixture.len(SESSION_B));
    let mut index = ScanIndex::default();
    // The traversal checkpoint fixture: this generation's census with both
    // files pending as watcher hints.
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.as_mut().unwrap();
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        traversal,
        BACKFILL_WINDOW_DAYS,
        &index.files,
    );
    for pending in &mut traversal.pending_candidates {
        pending.watcher_hint = true;
    }
    let paths = [fixture.file(SESSION), fixture.file(SESSION_B)];
    assert!(paths
        .iter()
        .all(|path| traversal.pending_candidates.iter().any(|p| &p.path == path)));
    let cache = Arc::new(SharedCache::default());
    let (index, scan) = with_test_limits(1 << 20, size + size / 2, 64, || {
        page(&fixture, index, Some(Arc::clone(&cache)))
    });
    assert_eq!(counter(&cache, |c| c.deferred), 1);
    assert_eq!(counter(&cache, |c| c.jobs_started), 0);
    let deferred: Vec<_> = paths
        .iter()
        .filter(|path| pending_hint(&index, path).is_some())
        .collect();
    assert_eq!(
        deferred.len(),
        1,
        "exactly one file waits for the next page"
    );
    assert_eq!(pending_hint(&index, deferred[0]), Some(true));
    assert!(!scan.snapshots.is_empty(), "the first file was read");
    let (index, scan) = with_test_limits(1 << 20, size + size / 2, 64, || {
        page(&fixture, index, Some(Arc::clone(&cache)))
    });
    assert!(!scan.snapshots.is_empty(), "the deferred file is read next");
    assert!(paths
        .iter()
        .all(|path| pending_hint(&index, path).is_none()));
}

/// A paused job from another namespace (account, destination or reduction
/// settings changed) is evicted at resume and its file restarts under the
/// new namespace.
#[test]
fn namespace_change_evicts_paused_job_and_restarts_it() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let cache = Arc::new(SharedCache::default());
    let paused_namespace = |cache: &SharedCache| {
        cache
            .with_cursor(|cursor| match &cursor.slot {
                Slot::Paused(job) => job.cursor.as_ref().map(|meta| meta.namespace.clone()),
                Slot::Empty | Slot::ActiveElsewhere { .. } => None,
            })
            .flatten()
    };
    with_test_limits(2048, 4096, 64, || {
        let (index, _, _) = page_in(
            &fixture,
            ScanIndex::default(),
            Some(Arc::clone(&cache)),
            "ns-a",
        );
        assert_eq!(
            paused_namespace(&cache).as_deref(),
            Some("ns-a"),
            "{}",
            counters(&cache)
        );
        assert!(cache.cursor_charge() > 0);
        let (_, scan, _) = page_in(&fixture, index, Some(Arc::clone(&cache)), "ns-b");
        assert!(scan.snapshots.is_empty());
        assert_eq!(counter(&cache, |c| c.jobs_lost), 1);
        assert_eq!(counter(&cache, |c| c.jobs_started), 2);
        assert_eq!(paused_namespace(&cache).as_deref(), Some("ns-b"));
    });
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
