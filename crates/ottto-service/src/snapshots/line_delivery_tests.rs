//! LD: the physical-line hook at the one reader, the per-pass lifecycle,
//! excluded reads, K10 counters and E3's selection-identity conditions.
use super::line_delivery::{DeliveryEnd, DeliveryMode, FileView, LineObserver, PhysicalLine, Want};
use super::*;
use crate::local_resource_diagnostics::{capture, CollectionCounts, Probe};
use crate::transcript_acquisition::FileObject;
use std::cell::RefCell;
use std::io::Cursor;

const NOW: &str = "2026-10-07T12:00:00Z";
const SESSION: &str = "5e551011-0000-4000-8000-00000000d1d1";

#[derive(Clone, Debug, PartialEq)]
enum Event {
    Begin(FileView),
    Line(Option<Value>),
    End(DeliveryEnd),
}

/// The minimal test observer: records every call.
#[derive(Clone, Default)]
struct Recorder {
    events: Arc<Mutex<Vec<Event>>>,
    skip: bool,
}
impl Recorder {
    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
    fn push(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
    fn lines(&self) -> Vec<Event> {
        self.events()
            .into_iter()
            .filter(|event| matches!(event, Event::Line(_)))
            .collect()
    }
    fn ends(&self) -> Vec<DeliveryEnd> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::End(end) => Some(end),
                _ => None,
            })
            .collect()
    }
}
impl LineObserver for Recorder {
    fn begin(&mut self, file: &FileView) -> Want {
        self.push(Event::Begin(*file));
        if self.skip {
            Want::Skip
        } else {
            Want::Lines
        }
    }
    fn line(&mut self, _: &FileView, line: &PhysicalLine<'_>) {
        self.push(Event::Line(line.value.cloned()));
    }
    fn end(&mut self, _: &FileView, end: &DeliveryEnd) {
        self.push(Event::End(*end));
    }
}

struct Root(PathBuf);
impl Root {
    fn new(label: &str) -> Self {
        let dir = crate::test_scratch::unique_path(label);
        fs::create_dir_all(dir.join("projects")).unwrap();
        // Walked paths are compared with these: no temp-dir symlink.
        Self(fs::canonicalize(dir).unwrap())
    }
    fn projects(&self) -> PathBuf {
        self.0.join("projects")
    }
    fn file(&self, name: &str) -> PathBuf {
        self.projects().join(format!("{name}.jsonl"))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn row(cwd: &str, uuid: &str) -> Value {
    session_row(SESSION, cwd, uuid)
}
fn session_row(session: &str, cwd: &str, uuid: &str) -> Value {
    json!({"type": "user", "sessionId": session, "uuid": uuid, "cwd": cwd,
        "timestamp": "2026-10-06T10:00:00.000Z",
        "message": {"role": "user", "content": "hi"}})
}
fn raw(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn append(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn new_scan(root: &Path, index: ScanIndex) -> OwnedSourceScan {
    OwnedSourceScan::new(
        SnapshotSource::ClaudeCode,
        &[root.to_path_buf()],
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
}

/// Step to completion; returns the index, result and the number of steps.
fn finish(mut scan: OwnedSourceScan) -> (ScanIndex, SourceScanResult, usize) {
    for steps in 1..100_000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    SnapshotSource::ClaudeCode,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan, steps);
            }
        }
    }
    panic!("scan did not finish");
}

fn step_until(
    mut scan: OwnedSourceScan,
    done: impl Fn(&OwnedSourceScan) -> bool,
) -> OwnedSourceScan {
    for _ in 0..100_000 {
        if done(&scan) {
            return scan;
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { .. } => panic!("completed before the condition"),
        }
    }
    panic!("condition never held");
}

/// One Claude page with an optional observer and sampled cache, plus its
/// `local_resources` rows.
fn claude_page(
    root: &Path,
    index: ScanIndex,
    observer: Option<&Recorder>,
    cache: Option<&Arc<sampled_scan::SharedCache>>,
) -> (ScanIndex, SourceScanResult, usize, Vec<Value>) {
    let ((index, result, steps), rows) = capture(|| {
        let mut scan = new_scan(root, index);
        if let Some(cache) = cache {
            scan = scan.with_sampled_acquisition(
                cache.clone(),
                crate::transcript_acquisition::Scope("ld-tests".into()),
            );
        }
        if let Some(observer) = observer {
            scan = scan.with_line_observer("test", Box::new(observer.clone()));
        }
        finish(scan)
    });
    (index, result, steps, rows)
}

fn page_counts(rows: &[Value]) -> Value {
    rows.iter()
        .find(|row| row["stage"] == "native_collection_page")
        .expect("page line")["counts"]
        .clone()
}

// ---- The reader hook ----

#[derive(Debug, PartialEq)]
enum Seen {
    Tap { length: u64, value: Option<Value> },
    Money(Value),
}

fn tap(seen: &RefCell<Vec<Seen>>) -> impl FnMut(u64, &PhysicalLine<'_>) + '_ {
    move |length: u64, line: &PhysicalLine<'_>| {
        let value = line.value.cloned();
        seen.borrow_mut().push(Seen::Tap { length, value })
    }
}

fn drive(
    reader: &mut BoundedJsonlReader<impl BufRead>,
    seen: &RefCell<Vec<Seen>>,
) -> JsonlReadReport {
    loop {
        let step = reader
            .step_lines(
                |value| seen.borrow_mut().push(Seen::Money(value.clone())),
                Some(&mut tap(seen)),
            )
            .unwrap();
        if let JsonlReaderStep::Complete(report) = step {
            return report;
        }
    }
}

/// D1/D2: every newline-complete physical line reaches the tap with its
/// physical length, blank, malformed and invalid-UTF-8 lines with no value. The
/// tap borrows the one parse that money then receives; the report and money
/// stream are those of the untapped reader. An unterminated EOF line goes to
/// money only.
#[test]
fn reader_lends_every_complete_line_its_one_parse_before_money() {
    let first = json!({"cwd": "/w/a", "n": 1});
    let crlf = json!({"cwd": "/w/b", "n": 2});
    let last = json!({"cwd": "/w/c", "n": 3});
    let mut physical: Vec<Vec<u8>> = vec![
        [raw(&first), b"\n".to_vec()].concat(),
        b"\n".to_vec(),
        b"   \n".to_vec(),
        b"{not json\n".to_vec(),
        b"\xff\xfe\n".to_vec(),
        [raw(&crlf), b"\r\n".to_vec()].concat(),
    ];
    let mut bytes = physical.concat();
    bytes.extend(raw(&last));
    let seen = RefCell::new(Vec::new());
    let mut reader = BoundedJsonlReader::new(Cursor::new(bytes.clone()), 1024, false);
    let report = drive(&mut reader, &seen);

    let mut expected = Vec::new();
    let mut start = 0;
    let values = [
        Some(first.clone()),
        None,
        None,
        None,
        None,
        Some(crlf.clone()),
    ];
    for (line, value) in physical.drain(..).zip(values) {
        let length = line.len() as u64;
        expected.push(Seen::Tap {
            length,
            value: value.clone(),
        });
        if let Some(value) = value {
            expected.push(Seen::Money(value));
        }
        start += length;
    }
    expected.push(Seen::Money(last.clone()));
    assert_eq!(*seen.borrow(), expected);
    assert_eq!(reader.last_complete_line_end(), start);
    assert!(reader.consumed_bytes() > start, "the EOF line was consumed");

    let mut untapped = Vec::new();
    let plain = read_bounded_jsonl_lines(Cursor::new(bytes), 1024, |value| {
        untapped.push(value.clone())
    })
    .unwrap();
    assert_eq!(report, plain, "byte-identical JsonlReadReport");
    assert_eq!(untapped, vec![first, crlf, last]);
    assert_eq!(report.physical_line_count, 7);
    assert_eq!(report.parsed_json_line_count, 3);
    assert_eq!(report.malformed_json_line_count, 1);
    assert_eq!(report.invalid_utf8_line_count, 1);
}

/// D2/D3: an overlong line skipped across paused steps is delivered once,
/// at its newline, with no value and its whole physical length; money still
/// receives the salvaged Codex envelope.
#[test]
fn overlong_line_is_empty_and_valueless_while_money_keeps_salvage() {
    let short = json!({"timestamp": "2026-10-01T00:00:00Z", "ordinal": 6});
    let after = json!({"timestamp": "2026-10-01T00:00:02Z", "ordinal": 8});
    let overlong = format!(
        "{{\"timestamp\":\"2026-10-01T00:00:01Z\",\"ordinal\":7,\"payload\":\"{}\"}}\n",
        "x".repeat(400)
    );
    let lines = [
        [raw(&short), b"\n".to_vec()].concat(),
        overlong.into_bytes(),
        [raw(&after), b"\n".to_vec()].concat(),
    ];
    let seen = RefCell::new(Vec::new());
    let mut reader = BoundedJsonlReader::new(
        std::io::BufReader::with_capacity(16, Cursor::new(lines.concat())),
        64,
        true,
    );
    reader.set_chunked_skip(32);
    let mut partial = 0;
    let report = loop {
        let step = reader
            .step_lines(
                |value| seen.borrow_mut().push(Seen::Money(value.clone())),
                Some(&mut tap(&seen)),
            )
            .unwrap();
        match step {
            JsonlReaderStep::Partial => partial += 1,
            JsonlReaderStep::Line => {}
            JsonlReaderStep::Complete(report) => break report,
        }
    };
    assert!(partial > 0, "the skip paused across steps");
    let seen = seen.into_inner();
    let taps = seen
        .iter()
        .filter(|seen| matches!(seen, Seen::Tap { .. }))
        .collect::<Vec<_>>();
    assert_eq!(
        *taps[1],
        Seen::Tap {
            length: lines[1].len() as u64,
            value: None,
        }
    );
    assert_eq!(taps.len(), 3);
    let lengths = taps.iter().map(|seen| match seen {
        Seen::Tap { length, .. } => *length,
        Seen::Money(_) => 0,
    });
    assert_eq!(lengths.sum::<u64>(), lines.concat().len() as u64);
    let money = seen
        .iter()
        .filter_map(|seen| match seen {
            Seen::Money(value) => Some(value.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(money.len(), 3, "salvaged envelope still reaches money");
    assert_eq!(money[1]["ordinal"], 7);
    assert_eq!(report.over_line_cap_count, 1);
}

/// D6: a frozen-extent read withholds its unterminated record; applying it at
/// an unchanged EOF reaches money only. Once its newline arrives, the next
/// read from the sealed offset delivers it exactly once.
#[test]
fn sealed_fragment_is_delivered_only_after_its_newline() {
    let done = json!({"cwd": "/w/a"});
    let pending = json!({"cwd": "/w/late"});
    let mut bytes = [raw(&done), b"\n".to_vec()].concat();
    let sealed = bytes.len() as u64;
    bytes.extend(raw(&pending));
    let seen = RefCell::new(Vec::new());
    let mut reader = BoundedJsonlReader::new(Cursor::new(bytes.clone()), 1024, false);
    reader.set_extent_limit(bytes.len() as u64);
    drive(&mut reader, &seen);
    assert!(reader.sealed_fragment());
    assert_eq!(reader.last_complete_line_end(), sealed);
    assert!(
        reader.apply_sealed_fragment(|value| seen.borrow_mut().push(Seen::Money(value.clone())))
    );
    let taps = |seen: &[Seen]| {
        seen.iter()
            .filter(|seen| matches!(seen, Seen::Tap { .. }))
            .count()
    };
    assert_eq!(taps(&seen.borrow()), 1, "never the fragment");
    assert_eq!(seen.borrow().last(), Some(&Seen::Money(pending.clone())));

    let mut tail = bytes[sealed as usize..].to_vec();
    tail.push(b'\n');
    let next = RefCell::new(Vec::new());
    let mut reader = BoundedJsonlReader::new(Cursor::new(tail.clone()), 1024, false);
    reader.set_extent_limit(tail.len() as u64);
    drive(&mut reader, &next);
    assert_eq!(
        next.into_inner(),
        vec![
            Seen::Tap {
                length: tail.len() as u64,
                value: Some(pending.clone()),
            },
            Seen::Money(pending),
        ],
        "exactly once, newline included"
    );
}

// ---- The scan lifecycle ----

/// A read without a ReadPlan: `Full` on the held object, every physical line
/// including an inherited CRLF row, `Complete` without the unterminated tail,
/// and the K10 page counts. With the newline written, the next read delivers
/// that line exactly once.
#[test]
fn unplanned_claude_read_delivers_all_lines_from_zero_and_counts_them() {
    let root = Root::new("ld-unplanned");
    let path = root.file(SESSION);
    let first = row("/w/one", "u1");
    let mut inherited = row("/w/inherited", "u2");
    inherited["forkedFrom"] = json!({"sessionId": "parent", "messageUuid": "m1"});
    let late = row("/w/late", "u3");
    let physical: Vec<Vec<u8>> = vec![
        [raw(&first), b"\n".to_vec()].concat(),
        b"\n".to_vec(),
        b"{not json\n".to_vec(),
        b"\xff\xfe\n".to_vec(),
        [raw(&inherited), b"\r\n".to_vec()].concat(),
    ];
    append(&path, &physical.concat());
    append(&path, &raw(&late));
    let recorder = Recorder::default();
    let (_, result, _, rows) = claude_page(
        &root.projects(),
        ScanIndex::default(),
        Some(&recorder),
        None,
    );
    assert_eq!(result.scanned_file_count, 1);

    let held = fs::metadata(&path).unwrap();
    let mut expected = vec![Event::Begin(FileView {
        source: SnapshotSource::ClaudeCode,
        object: FileObject::of(&fs::File::open(&path).unwrap()).unwrap().0,
        mtime: held.modified().ok(),
        mode: DeliveryMode::Full,
    })];
    let values = [Some(first), None, None, None, Some(inherited)];
    expected.extend(values.into_iter().map(Event::Line));
    expected.push(Event::End(DeliveryEnd::Complete));
    assert_eq!(recorder.events(), expected);

    let sealed = physical.concat().len() as u64;
    let counts = &page_counts(&rows)["line_delivery"]["test"];
    assert_eq!(counts["lines"], 5);
    assert_eq!(counts["bytes"], sealed, "physical bytes, no fragment");
    assert!(counts.get("incomplete").is_none());

    append(&path, b"\n");
    let after = Recorder::default();
    let (_, _, _, rows) = claude_page(&root.projects(), ScanIndex::default(), Some(&after), None);
    let delivered_late = after
        .lines()
        .into_iter()
        .filter(|line| *line == Event::Line(Some(late.clone())))
        .count();
    assert_eq!(delivered_late, 1);
    let total = fs::metadata(&path).unwrap().len();
    assert_eq!(after.ends(), vec![DeliveryEnd::Complete]);
    assert_eq!(page_counts(&rows)["line_delivery"]["test"]["bytes"], total);
}

/// E3 condition 2: registering an observer changes neither which files a
/// pass selects, its results, nor its step (page) boundaries.
#[test]
fn registration_changes_no_selection_result_or_step_boundary() {
    let root = Root::new("ld-identity");
    for (session, cwd) in [
        ("5e551011-0000-4000-8000-00000000d1da", "/w/a"),
        ("5e551011-0000-4000-8000-00000000d1db", "/w/b"),
        ("5e551011-0000-4000-8000-00000000d1dc", "/w/c"),
    ] {
        let mut body = Vec::new();
        for n in 0..3 {
            body.extend(raw(&session_row(session, cwd, &format!("{cwd}{n}"))));
            body.push(b'\n');
        }
        body.extend(b"{broken\n");
        append(&root.file(session), &body);
    }
    let recorder = Recorder::default();
    let (bare_index, bare, bare_steps, _) =
        claude_page(&root.projects(), ScanIndex::default(), None, None);
    let (seen_index, seen, seen_steps, _) = claude_page(
        &root.projects(),
        ScanIndex::default(),
        Some(&recorder),
        None,
    );
    assert_eq!(bare_steps, seen_steps, "same step boundaries");
    assert_eq!(bare.scanned_file_count, 3);
    assert_eq!(bare.scanned_file_count, seen.scanned_file_count);
    assert_eq!(bare.discovered_file_count, seen.discovered_file_count);
    assert_eq!(bare.semantic_noop_count, seen.semantic_noop_count);
    assert_eq!(bare.census_complete, seen.census_complete);
    let fingerprints = |result: &SourceScanResult| {
        result
            .snapshots
            .iter()
            .map(|snapshot| snapshot.snapshot_fingerprint.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(fingerprints(&bare), fingerprints(&seen));
    assert_eq!(
        serde_json::to_value(&bare_index.files).unwrap(),
        serde_json::to_value(&seen_index.files).unwrap()
    );
    assert_eq!(recorder.ends().len(), 3, "one end per file");
    assert_eq!(recorder.lines().len(), 12);
}

/// `Want::Skip`: no line is delivered, the begin still ends once, and the
/// page counts no lines or bytes.
#[test]
fn skip_delivers_no_lines_and_ends_once() {
    let root = Root::new("ld-skip");
    append(
        &root.file(SESSION),
        &[raw(&row("/w/one", "u1")), b"\n".to_vec()].concat(),
    );
    let recorder = Recorder {
        skip: true,
        ..Recorder::default()
    };
    let (_, _, _, rows) = claude_page(
        &root.projects(),
        ScanIndex::default(),
        Some(&recorder),
        None,
    );
    let events = recorder.events();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], Event::Begin(_)));
    assert!(matches!(events[1], Event::End(DeliveryEnd::Complete)));
    let counts = &page_counts(&rows)["line_delivery"]["test"];
    assert!(counts.get("lines").is_none() && counts.get("bytes").is_none());
}

/// D4/R5: a native comparison target is excluded at the one begin site; its
/// role is final before the first dispatch.
#[test]
fn comparison_target_read_calls_no_observer() {
    let root = Root::new("ld-comparison");
    append(
        &root.file(SESSION),
        &[raw(&row("/w/one", "u1")), b"\n".to_vec()].concat(),
    );
    let recorder = Recorder::default();
    let mut scan = step_until(
        new_scan(&root.projects(), ScanIndex::default())
            .with_line_observer("test", Box::new(recorder.clone())),
        |scan| scan.active_file.is_some(),
    );
    scan.active_file.as_deref_mut().unwrap().comparison_target = true;
    let (_, result, _) = finish(scan);
    assert_eq!(result.scanned_file_count, 1, "the file was read");
    assert_eq!(recorder.events(), Vec::new());
}

/// D4/R5: a side read is rejected by the same begin predicate.
#[test]
fn side_read_calls_no_observer() {
    let root = Root::new("ld-side");
    append(
        &root.file(SESSION),
        &[raw(&row("/w/one", "u1")), b"\n".to_vec()].concat(),
    );
    let recorder = Recorder::default();
    let mut scan = step_until(
        new_scan(&root.projects(), ScanIndex::default())
            .with_line_observer("test", Box::new(recorder.clone())),
        |scan| scan.active_file.is_some(),
    );
    let active = scan.active_file.as_deref_mut().unwrap();
    active.side_origin = Some(SideOrigin {
        guard: crate::local_resource_diagnostics::codex_side_lifecycle::SideReadGuard::start(1),
        dev_ino: (0, 0),
    });
    scan.line_delivery
        .as_mut()
        .unwrap()
        .begin_armed(scan.active_file.as_deref().unwrap());
    let active = scan.active_file.as_deref_mut().unwrap();
    active.side_origin.take().unwrap().end();
    finish(scan);
    assert_eq!(recorder.events(), Vec::new());
}

/// D4/O-E1-G: Codex group member reads replay through the group job and call
/// no observer.
#[test]
fn codex_group_member_reads_call_no_observer() {
    let (root, _) = super::codex_file_join::tests::fixture();
    let recorder = Recorder::default();
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        ScanIndex::default(),
        "2026-10-06T23:00:00Z",
        7,
        2,
        false,
        None,
        &[],
        false,
        false,
    )
    .with_line_observer("test", Box::new(recorder.clone()));
    let result = loop {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { scan, .. } => break scan,
        }
    };
    assert_eq!(result.scanned_file_count, 2);
    assert_eq!(result.snapshots.len(), 2, "one alias per group member");
    assert_eq!(recorder.events(), Vec::new());
    fs::remove_dir_all(root).unwrap();
}

fn three_line_file(root: &Root) {
    for n in 0..3 {
        append(
            &root.file(SESSION),
            &[raw(&row("/w/one", &format!("u{n}"))), b"\n".to_vec()].concat(),
        );
    }
}

fn two_lines_delivered(recorder: &Recorder) -> impl Fn(&OwnedSourceScan) -> bool + '_ {
    move |_| recorder.lines().len() >= 2
}

/// D6: an open file removed between steps ends once `Incomplete`, also when
/// the page completes in that same step.
#[test]
fn file_removed_mid_read_ends_incomplete() {
    let root = Root::new("ld-held");
    three_line_file(&root);
    let recorder = Recorder::default();
    let mut scan = step_until(
        new_scan(&root.projects(), ScanIndex::default())
            .with_line_observer("test", Box::new(recorder.clone())),
        two_lines_delivered(&recorder),
    );
    drop(scan.active_file.take());
    finish(scan);
    assert_eq!(recorder.ends(), vec![DeliveryEnd::Incomplete]);
}

/// D6: a failed read ends once `Incomplete` and is counted.
#[test]
fn failed_read_ends_incomplete_and_is_counted() {
    let root = Root::new("ld-failed");
    three_line_file(&root);
    let recorder = Recorder::default();
    let mut scan = step_until(
        new_scan(&root.projects(), ScanIndex::default())
            .with_line_observer("test", Box::new(recorder.clone())),
        two_lines_delivered(&recorder),
    );
    scan.active_file
        .as_deref_mut()
        .unwrap()
        .parser
        .reader
        .failure = Some(std::io::ErrorKind::Other);
    let ((_, _, _), rows) = capture(|| finish(scan));
    assert_eq!(recorder.ends(), vec![DeliveryEnd::Incomplete]);
    assert_eq!(page_counts(&rows)["line_delivery"]["test"]["incomplete"], 1);
}

/// D6: a pass dropped mid-file still ends its open file once `Incomplete`.
#[test]
fn dropped_pass_ends_open_file_once_incomplete() {
    let root = Root::new("ld-dropped");
    three_line_file(&root);
    let recorder = Recorder::default();
    let scan = step_until(
        new_scan(&root.projects(), ScanIndex::default())
            .with_line_observer("test", Box::new(recorder.clone())),
        two_lines_delivered(&recorder),
    );
    drop(scan);
    assert_eq!(recorder.ends(), vec![DeliveryEnd::Incomplete]);
}

/// Sampled acquisition (layout-supported builds): a Full starts at 0; after
/// growth a Tail starts at the prior sealed offset (or a reset Full), and the
/// line that was an unterminated fragment is delivered once; an unchanged
/// file delivers nothing; a rewrite is a Full from 0 again.
#[test]
fn sampled_full_tail_unchanged_and_reset_deliver_by_mode() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = Root::new("ld-sampled");
    let path = root.file(SESSION);
    let late = row("/w/late", "u9");
    for n in 0..3 {
        append(
            &path,
            &[raw(&row("/w/one", &format!("u{n}"))), b"\n".to_vec()].concat(),
        );
    }
    let sealed = fs::metadata(&path).unwrap().len();
    append(&path, &raw(&late));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let delivered = |rows: &[Value]| page_counts(rows)["line_delivery"]["test"]["bytes"].clone();

    let first = Recorder::default();
    let (index, _, _, rows) = claude_page(
        &root.projects(),
        ScanIndex::default(),
        Some(&first),
        Some(&cache),
    );
    let Some(Event::Begin(view)) = first.events().first().cloned() else {
        panic!("no begin: {:?}", first.events());
    };
    assert_eq!(view.mode, DeliveryMode::Full);
    assert_eq!(first.ends(), vec![DeliveryEnd::Complete]);
    assert_eq!(delivered(&rows), sealed, "from 0, fragment withheld");

    append(&path, b"\n");
    append(
        &path,
        &[raw(&row("/w/two", "u10")), b"\n".to_vec()].concat(),
    );
    let total = fs::metadata(&path).unwrap().len();
    let grown = Recorder::default();
    let (index, _, _, rows) = claude_page(&root.projects(), index, Some(&grown), Some(&cache));
    let Some(Event::Begin(view)) = grown.events().first().cloned() else {
        panic!("no begin: {:?}", grown.events());
    };
    match view.mode {
        DeliveryMode::Tail => assert_eq!(delivered(&rows), total - sealed, "from sealed"),
        DeliveryMode::Full => assert_eq!(delivered(&rows), total),
        DeliveryMode::Unchanged => panic!("grown file"),
    }
    let late_lines = grown
        .lines()
        .into_iter()
        .filter(|line| *line == Event::Line(Some(late.clone())))
        .count();
    assert_eq!(late_lines, 1, "delivered once after its newline");

    let unchanged = Recorder::default();
    let (index, _, _, _) = claude_page(&root.projects(), index, Some(&unchanged), Some(&cache));
    assert_eq!(unchanged.lines(), Vec::new());

    let rewrite = [raw(&row("/w/new", "n1")), b"\n".to_vec()].concat();
    fs::write(&path, &rewrite).unwrap();
    let rewritten = Recorder::default();
    let (_, _, _, rows) = claude_page(&root.projects(), index, Some(&rewritten), Some(&cache));
    let Some(Event::Begin(view)) = rewritten.events().first().cloned() else {
        panic!("no begin: {:?}", rewritten.events());
    };
    assert_eq!(view.mode, DeliveryMode::Full);
    assert_eq!(rewritten.lines().len(), 1);
    assert_eq!(delivered(&rows), rewrite.len() as u64, "from 0");
}

// ---- E3 condition 1: unselected counters after unchanged gate decisions ----

fn set_old(path: &Path) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1)),
        )
        .unwrap();
}

fn unselected_page(source: &str) -> Value {
    let (_, rows) = capture(|| {
        Probe::start().collection(
            source,
            CollectionCounts {
                scanned_files: 0,
                semantic_noops: 0,
                sampled_acquisition: None,
            },
        )
    });
    page_counts(&rows)
        .get("line_delivery_unselected")
        .cloned()
        .unwrap_or(Value::Null)
}

/// A file with an accepted sampled generation keeps verification rescue.
fn rescue(files: &mut BTreeMap<String, ScanIndexEntry>, path: &Path) {
    let mut entry = super::tests::manifest_index_entry(None);
    entry.set_unverified_deadline(0);
    files.insert(local_index_key(path), entry);
}

fn candidates(index: &ScanIndex) -> Vec<PathBuf> {
    let mut paths = index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

/// Gate 1 (the bounded walk): age and size skips are counted after the
/// existing decisions; the rescued old file and the young file are selected
/// exactly as before, and counter state is no gate input.
#[test]
fn walk_gate_counts_age_and_size_skips_without_changing_selection() {
    let root = Root::new("ld-walk-gate");
    let project = root.projects().join("p");
    fs::create_dir_all(&project).unwrap();
    let file = |name: &str| project.join(format!("{name}.jsonl"));
    for name in ["young", "old", "rescued"] {
        append(&file(name), b"{}\n");
    }
    set_old(&file("old"));
    set_old(&file("rescued"));
    fs::File::create(file("big"))
        .unwrap()
        .set_len(MAX_JSONL_FILE_BYTES + 1)
        .unwrap();
    let mut prepared = ScanIndex::default();
    rescue(&mut prepared.files, &file("rescued"));
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[root.projects()],
        &mut prepared,
        NOW,
        30,
    );
    let walk = || {
        let mut index = prepared.clone();
        while !index
            .traversal
            .as_ref()
            .unwrap()
            .pending_directories
            .is_empty()
        {
            advance_bounded_directory_traversal(
                SnapshotSource::ClaudeCode,
                index.traversal.as_mut().unwrap(),
                30,
                &index.files,
            );
        }
        let counts = &index.traversal.as_ref().unwrap().counts;
        let decided = (
            candidates(&index),
            counts.discovered_file_count,
            counts.oversized_file_count,
        );
        (decided, unselected_page("claude_code"))
    };
    let (first, counted) = walk();
    let (second, recounted) = walk();
    assert_eq!(first, second, "counter state is no gate input");
    let mut selected = vec![file("rescued"), file("young")];
    selected.sort();
    assert_eq!(first, (selected, 3, 1));
    assert_eq!(counted, json!({"age": 1, "size": 1}));
    assert_eq!(recounted, counted);
}

/// Gate 2 (Codex retained-roster refresh): the same conditions for files
/// appearing in an already-walked directory.
#[test]
fn roster_gate_counts_age_and_size_skips_without_changing_selection() {
    let root = Root::new("ld-roster-gate");
    let day = root.projects().join("2026/10/01");
    fs::create_dir_all(&day).unwrap();
    let file = |name: &str| day.join(format!("rollout-{name}.jsonl"));
    append(&file("first"), b"{}\n");
    let mut index = ScanIndex::default();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &[root.projects()],
        &mut index,
        NOW,
        30,
    );
    while !index
        .traversal
        .as_ref()
        .unwrap()
        .pending_directories
        .is_empty()
    {
        advance_bounded_directory_traversal(
            SnapshotSource::Codex,
            index.traversal.as_mut().unwrap(),
            30,
            &index.files,
        );
    }
    unselected_page("codex");
    std::thread::sleep(std::time::Duration::from_millis(50));
    for name in ["young", "old", "rescued"] {
        append(&file(name), b"{}\n");
    }
    set_old(&file("old"));
    set_old(&file("rescued"));
    fs::File::create(file("big"))
        .unwrap()
        .set_len(MAX_CODEX_JSONL_FILE_BYTES + 1)
        .unwrap();
    rescue(&mut index.files, &file("rescued"));
    let refresh = || {
        let mut index = index.clone();
        refresh_retained_codex_roster(
            SnapshotSource::Codex,
            index.traversal.as_mut().unwrap(),
            30,
            &index.files,
        );
        let counts = &index.traversal.as_ref().unwrap().counts;
        let decided = (
            candidates(&index),
            counts.discovered_file_count,
            counts.oversized_file_count,
        );
        (decided, unselected_page("codex"))
    };
    let (first, counted) = refresh();
    let (second, recounted) = refresh();
    assert_eq!(first, second, "counter state is no gate input");
    let mut selected = vec![file("first"), file("rescued"), file("young")];
    selected.sort();
    assert_eq!(first, (selected, 4, 1));
    assert_eq!(counted, json!({"age": 1, "size": 1}));
    assert_eq!(recounted, counted);
}
