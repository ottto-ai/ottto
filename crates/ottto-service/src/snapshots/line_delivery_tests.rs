//! LD: the physical-line hook at the one reader, the per-pass lifecycle,
//! excluded reads, K10 counters and E3's selection-identity conditions.
use super::line_delivery::{DeliveryEnd, DeliveryMode, FileView, LineObserver, PhysicalLine, Want};
use super::*;
use crate::codex_prelude_footprint::tests::metric;
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
    offsets: Arc<Mutex<Vec<(u64, u64)>>>,
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
    fn line(&mut self, file: &FileView, line: &PhysicalLine<'_>) {
        self.offsets.lock().unwrap().push((file.start, line.end));
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
    )
}

/// Step to completion; returns the index, result and the number of steps.
fn finish(mut scan: OwnedSourceScan) -> (ScanIndex, SourceScanResult, usize) {
    withheld_account::support::clock(&scan.index.withheld_memo);
    let source = scan.source;
    for steps in 1..100_000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    source,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(source, &mut projected, &mut index);
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
    assert!(recorder
        .events()
        .iter()
        .any(|e| matches!(e, Event::Begin(v) if v.source == SnapshotSource::ClaudeCode)));
    assert_eq!(result.scanned_file_count, 1);

    let held = fs::metadata(&path).unwrap();
    let mut expected = vec![Event::Begin(FileView {
        source: SnapshotSource::ClaudeCode,
        object: FileObject::of(&fs::File::open(&path).unwrap()).unwrap().0,
        mtime: held.modified().ok(),
        mode: DeliveryMode::Full,
        root: Some(0),
        start: 0,
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
        .begin_armed(scan.active_file.as_deref().unwrap(), &scan.roots);
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
    )
    .with_line_observer("test", Box::new(recorder.clone()));
    scan = step_until(scan, |s| {
        s.active_file.as_deref().is_some_and(|a| a.group.is_some())
    });
    assert!(!scan
        .active_file
        .as_deref()
        .unwrap()
        .is_primary_for(SnapshotSource::Codex));
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

/// Linux too: a real Tail plan positions the held reader; production begin
/// and physical-line delivery preserve its nonzero absolute byte origin.
#[test]
fn planned_tail_delivers_absolute_offsets_on_linux() {
    use crate::transcript_acquisition::{ReadMode, ReadPlan, Scope};
    use std::io::Read as _;

    let root = Root::new("ld-planned-offsets");
    let path = root.file(SESSION);
    let prefix = [raw(&row("/w/prefix", "u0")), b"\n".to_vec()].concat();
    fs::write(&path, &prefix).unwrap();
    let scope = Scope("ld-planned-offsets".into());
    let mut file = File::open(&path).unwrap();
    let mut full = ReadPlan::prepare(&mut file, None, &scope, None, 100).unwrap();
    let mut read = Vec::new();
    file.read_to_end(&mut read).unwrap();
    full.observe_complete_records(&read).unwrap();
    let checkpoint = full
        .commit_after_native_completion(&file, &scope, 100)
        .unwrap();
    let rows = [row("/w/one", "u1"), row("/w/two-longer", "u2")];
    let bytes = rows
        .clone()
        .map(|value| [raw(&value), b"\n".to_vec()].concat());
    for row in &bytes {
        append(&path, row);
    }

    let recorder = Recorder::default();
    let mut scan = step_until(
        new_scan(&root.projects(), ScanIndex::default())
            .with_line_observer("test", Box::new(recorder.clone())),
        |scan| scan.active_file.is_some(),
    );
    let mut active = scan.active_file.take().unwrap();
    let reader = &mut active.parser.reader;
    assert_eq!(reader.consumed_bytes(), 0);
    let tail = ReadPlan::prepare(
        reader.reader.get_mut(),
        Some(&checkpoint),
        &scope,
        None,
        101,
    )
    .unwrap();
    assert_eq!(tail.mode(), ReadMode::Tail);
    let start = tail.start_offset();
    assert_eq!(start, prefix.len() as u64);
    assert!(start > 0);
    reader.set_extent_limit(tail.frozen_length() - start);
    reader.acquisition = Some(tail);
    let delivery = scan.line_delivery.as_mut().unwrap();
    delivery.begin_armed(&active, &scan.roots);
    let Some(Event::Begin(view)) = recorder.events().first().cloned() else {
        panic!("expected begin");
    };
    assert_eq!(view.mode, DeliveryMode::Tail);
    assert_eq!(view.start, start);

    let mut consumed = 0;
    for (n, bytes) in bytes.iter().enumerate() {
        assert!(!delivery.step(&mut active.parser).unwrap());
        consumed += bytes.len() as u64;
        assert_eq!(active.parser.reader.consumed_bytes(), consumed);
        let offsets = recorder.offsets.lock().unwrap();
        assert_eq!(offsets.len(), n + 1);
        assert_eq!(offsets[n], (start, start + consumed));
        assert_ne!(offsets[n].1, consumed, "end must be absolute");
    }
    assert!(delivery.step(&mut active.parser).unwrap());
    assert_eq!(
        recorder.lines(),
        rows.map(|value| Event::Line(Some(value))),
        "only the appended rows were delivered"
    );
    assert_eq!(recorder.ends(), [DeliveryEnd::Complete]);
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

/// Review #4 (layout-supported builds): a Codex Tail that meets a protected
/// tier ends at EOF, then its in-place Full replacement is delivered as one
/// fresh Full from 0: every line once, the Tail's line not repeated.
#[test]
fn in_place_full_fallback_after_tail_is_one_fresh_full_delivery() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = Root::new("ld-fallback");
    let sessions = root.0.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let id = "019fa111-2222-7333-8444-555555555555";
    let path = sessions.join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
    let usage = |n: u64, hour: u32| {
        json!({"type": "event_msg", "timestamp": format!("2026-10-07T{hour}:00:00Z"),
            "payload": {"type": "token_count", "info": {"model": "fixture-model",
            "total_token_usage": {"input_tokens": n, "cached_input_tokens": n / 2, "output_tokens": n / 10},
            "last_token_usage": {"input_tokens": n, "cached_input_tokens": n / 2, "output_tokens": n / 10}}}})
    };
    let meta = json!({"type": "session_meta", "payload": {"id": id}});
    let first = usage(100, 10);
    let mut priority = usage(140, 11);
    priority["payload"]["service_tier"] = json!("priority");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let page = |index: ScanIndex, observer: &Recorder| {
        let scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            std::slice::from_ref(&sessions),
            index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
        )
        .with_sampled_acquisition(
            cache.clone(),
            crate::transcript_acquisition::Scope("ld-tests".into()),
        )
        .with_line_observer("test", Box::new(observer.clone()));
        finish(scan).0
    };
    for value in [&meta, &first] {
        append(&path, &[raw(value), b"\n".to_vec()].concat());
    }
    let index = page(ScanIndex::default(), &Recorder::default());
    append(&path, &[raw(&priority), b"\n".to_vec()].concat());
    let recorder = Recorder::default();
    page(index, &recorder);

    let events = recorder.events();
    let modes: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Begin(view) => Some(view.mode),
            _ => None,
        })
        .collect();
    assert_eq!(
        modes,
        [DeliveryMode::Tail, DeliveryMode::Full],
        "{events:?}"
    );
    let line = |value: &Value| Event::Line(Some(value.clone()));
    let complete = Event::End(DeliveryEnd::Complete);
    assert_eq!(
        events[1..],
        [
            line(&priority),
            complete.clone(),
            events[3].clone(),
            line(&meta),
            line(&first),
            line(&priority),
            complete,
        ]
    );
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

fn discovery_page(source: &str) -> Value {
    let (_, rows) = capture(|| {
        Probe::start().collection(
            source,
            CollectionCounts {
                scanned_files: 0,
                semantic_noops: 0,
                sampled_acquisition: None,
                full_causes: Default::default(),
            },
        )
    });
    page_counts(&rows)
}

fn unselected_page(source: &str) -> Value {
    discovery_page(source)
        .get("line_delivery_unselected")
        .cloned()
        .unwrap_or(Value::Null)
}

/// A file with an accepted sampled generation keeps verification rescue.
fn rescue(files: &mut SharedMap<String, ScanIndexEntry>, path: &Path) {
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
        .set_len(MAX_CLAUDE_JSONL_FILE_BYTES + 1)
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
                &mut index,
                30,
                None,
                None,
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
        advance_bounded_directory_traversal(SnapshotSource::Codex, &mut index, 30, None, None);
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
            discovery_retention!(index),
            (&index.files).into(),
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

// ---- E3: withheld-account holds stay discoverable until they resolve ----

/// The key holds a parsed revision withheld for an unresolved account.
fn withhold(index: &mut ScanIndex, path: &Path) {
    index
        .claude_account_deferred_holds
        .insert(local_index_key(path), "held-source".into());
}

pub(in crate::snapshots) fn walk_all(index: &mut ScanIndex, days: u64) {
    while !index
        .traversal
        .as_ref()
        .unwrap()
        .pending_directories
        .is_empty()
    {
        advance_bounded_directory_traversal(SnapshotSource::ClaudeCode, index, days, None, None);
    }
}

/// Complete a later real bounded walk, even if a healthy page retired its checkpoint.
/// The caller owns the configured roots and prior observed window; a retained
/// checkpoint can advance that window, but is not required to recover the scope.
pub(in crate::snapshots) fn next_walk(
    index: &mut ScanIndex,
    roots: &[PathBuf],
    after: &str,
    days: u64,
) {
    let after = OffsetDateTime::parse(after, &Rfc3339).unwrap();
    let prior = index.traversal.take().map_or(after, |previous| {
        OffsetDateTime::parse(&previous.census_window_end, &Rfc3339)
            .unwrap()
            .max(after)
    });
    let at = (prior + time::Duration::seconds(1))
        .format(&Rfc3339)
        .unwrap();
    ensure_bounded_traversal(SnapshotSource::ClaudeCode, roots, index, &at, days);
    walk_all(index, days);
}

/// [behaviour] Gate 1 with a 7-day request: an aged withheld key is still discovered and
/// observed, an oversized one is observed, kept unread and counted, and once
/// the holds resolve the ordinary window and size skips apply again.
#[test]
fn walk_gate_keeps_withheld_account_keys_until_their_hold_resolves() {
    let root = Root::new("ld-withheld-walk");
    let project = root.projects().join("p");
    fs::create_dir_all(&project).unwrap();
    let file = |name: &str| project.join(format!("{name}.jsonl"));
    for name in ["held", "old"] {
        append(&file(name), b"{}\n");
        set_old(&file(name));
    }
    fs::File::create(file("big"))
        .unwrap()
        .set_len(MAX_CLAUDE_JSONL_FILE_BYTES + 1)
        .unwrap();
    let mut held = ScanIndex::default();
    withhold(&mut held, &file("held"));
    withhold(&mut held, &file("big"));
    let resolved = ScanIndex::default();
    let walk = |prepared: &ScanIndex| {
        let mut index = prepared.clone();
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[root.projects()],
            &mut index,
            NOW,
            7,
        );
        walk_all(&mut index, 7);
        let traversal = index.traversal.as_ref().unwrap();
        let observed = ["held", "old", "big"]
            .into_iter()
            .filter(|name| {
                traversal
                    .observed_index_keys
                    .contains(&local_index_key(&file(name)))
            })
            .collect::<Vec<_>>();
        (
            candidates(&index),
            observed,
            traversal.counts.oversized_file_count,
            unselected_page("claude_code"),
        )
    };
    // Before the exemption the aged held key was skipped for age: no
    // candidate, not observed, and `age: 2` with no withheld count.
    assert_eq!(
        walk(&held),
        (
            vec![file("held")],
            vec!["held", "big"],
            1,
            json!({"age": 1, "size": 1, "withheld_oversized": 1})
        )
    );
    assert_eq!(
        walk(&resolved),
        (Vec::new(), vec!["big"], 1, json!({"age": 2, "size": 1}))
    );
}

/// [behaviour] Gates 3 and 4 (candidate revalidation, opened-object recheck): an aged
/// withheld key opens and stays observed; unheld, the same file is removed
/// from the census as out of window. An oversized withheld key is observed,
/// never opened, and counted.
#[test]
fn candidate_and_open_gates_keep_withheld_account_keys() {
    let root = Root::new("ld-withheld-open");
    let aged = root.file(SESSION);
    append(&aged, b"{}\n");
    set_old(&aged);
    let big = root.file("big");
    fs::File::create(&big)
        .unwrap()
        .set_len(MAX_CLAUDE_JSONL_FILE_BYTES + 1)
        .unwrap();
    let census_at = rfc3339_unix_seconds(NOW);
    assert!(census_at.is_some(), "the window is applied");
    let gates = |path: &Path, holds: &BTreeMap<String, String>| {
        let key = local_index_key(path);
        let mut census = ScanCensus::default();
        let opened = candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            ScanTraversalPath {
                scan_root: root.projects(),
                path: path.to_path_buf(),
                census_member: true,
                watcher_hint: false,
            },
            &mut census,
            census_at,
            7,
            &mut crate::snapshots::CandidateDiscovery::new(
                &mut ScanIndex {
                    claude_account_deferred_holds: holds.clone(),
                    ..ScanIndex::default()
                },
                None,
                None,
            ),
        )
        .map(|candidate| {
            open_and_identify_scan_candidate(
                SnapshotSource::ClaudeCode,
                candidate,
                &mut census,
                census_at,
                7,
                crate::snapshots::DiscoveryRetention {
                    files: &SharedMap::default(),
                    account_holds: holds,
                    memo: None,
                    growth: None,
                },
            )
            .is_some()
        });
        (
            opened,
            census.observed_index_keys.contains(&key),
            census.removed_index_keys.contains(&key),
            unselected_page("claude_code"),
        )
    };
    let held = |path: &Path| BTreeMap::from([(local_index_key(path), "held-source".to_string())]);
    // Before the exemption: (None, false, true): removed as out of window.
    assert_eq!(
        gates(&aged, &held(&aged)),
        (Some(true), true, false, Value::Null)
    );
    assert_eq!(
        gates(&aged, &BTreeMap::new()),
        (None, false, true, Value::Null)
    );
    assert_eq!(
        gates(&big, &held(&big)),
        (None, true, false, json!({"withheld_oversized": 1}))
    );
    assert_eq!(
        gates(&big, &BTreeMap::new()),
        (None, true, false, Value::Null)
    );
}

/// [behaviour] Sleep/restart retention is source-neutral: only real positive growth
/// gains an exemption, including growth beyond the size cap (observed only).
/// Gate counters are decisions, and overlapping owed arms count only once.
#[test]
fn grown_retention_covers_age_gates_without_counting_overlapping_arms_twice() {
    for (source, recovery_overlap) in [
        (SnapshotSource::ClaudeCode, false),
        (SnapshotSource::Codex, false),
        (SnapshotSource::ClaudeCode, true),
        (SnapshotSource::Codex, true),
    ] {
        let root = Root::new("ld-grown-gates");
        let directory = root.projects().join("2026/10/01");
        fs::create_dir_all(&directory).unwrap();
        let path = |name: &str| directory.join(format!("rollout-{name}.jsonl"));
        let mut index = ScanIndex::default();
        for (name, committed) in [("grown", 2), ("held", 2), ("equal", 3), ("truncated", 4)] {
            append(&path(name), b"{}\n");
            set_old(&path(name));
            let mut entry = super::tests::manifest_index_entry(None);
            entry.size_bytes = committed;
            assert!(!entry.has_unverified_source());
            if recovery_overlap && name == "grown" {
                entry.set_unverified_deadline(0);
                assert!(entry.has_unverified_source());
            }
            index.files.insert(local_index_key(&path(name)), entry);
        }
        // Both arms apply to the same reverted committed entry.
        withhold(&mut index, &path("held"));
        assert!(
            discovery_retention!(index).owes(&path("held")),
            "hold arm is live"
        );
        assert!(
            fs::metadata(path("held")).unwrap().len()
                > index.files[&local_index_key(&path("held"))].size_bytes,
            "reverted committed entry still owes growth"
        );
        let cap = max_jsonl_file_bytes(source);
        File::create(path("big")).unwrap().set_len(cap + 1).unwrap();
        set_old(&path("big"));
        let mut big = super::tests::manifest_index_entry(None);
        big.size_bytes = cap;
        index.files.insert(local_index_key(&path("big")), big);
        ensure_bounded_traversal(source, &[root.projects()], &mut index, NOW, 7);
        while !index
            .traversal
            .as_ref()
            .unwrap()
            .pending_directories
            .is_empty()
        {
            advance_bounded_directory_traversal(source, &mut index, 7, None, None);
        }
        assert_eq!(candidates(&index), vec![path("grown"), path("held")]);
        assert_eq!(
            index.traversal.as_ref().unwrap().observed_index_keys,
            std::collections::BTreeSet::from(
                ["big", "grown", "held"].map(|name| local_index_key(&path(name)))
            )
        );
        let counts = discovery_page(source.api_slug());
        assert_eq!(counts["discovery_retained"], json!({"grown": 3}));
        assert_eq!(
            counts["line_delivery_unselected"],
            json!({"age": 2, "size": 1})
        );
        assert!(reconcile_missing_index_entries_with_limit(
            &mut index,
            usize::MAX
        ));
        assert_eq!(
            index.files.keys().cloned().collect::<BTreeSet<_>>(),
            ["big", "grown", "held"]
                .map(|name| local_index_key(&path(name)))
                .into(),
            "F-INDEX keeps observed growth, including over-cap growth"
        );

        // Revalidation and opened-object recheck each use their current length.
        // Restore the equal/truncated controls, retired by complete census above.
        for (name, size) in [("equal", 3), ("truncated", 4)] {
            let mut entry = super::tests::manifest_index_entry(None);
            entry.size_bytes = size;
            index.files.insert(local_index_key(&path(name)), entry);
        }
        for (name, retained) in [
            ("grown", true),
            ("held", true),
            ("equal", false),
            ("truncated", false),
        ] {
            let mut census = ScanCensus::default();
            let candidate = candidate_from_traversal_path(
                source,
                ScanTraversalPath {
                    scan_root: root.projects(),
                    path: path(name),
                    census_member: true,
                    watcher_hint: false,
                },
                &mut census,
                rfc3339_unix_seconds(NOW),
                7,
                &mut crate::snapshots::CandidateDiscovery::new(&mut index, None, None),
            );
            assert_eq!(candidate.is_some(), retained, "candidate {name}");
            assert_eq!(
                census
                    .observed_index_keys
                    .contains(&local_index_key(&path(name))),
                retained
            );
            if recovery_overlap && name == "grown" {
                assert_eq!(
                    discovery_page(source.api_slug())["discovery_retained"],
                    json!({"grown": 1}),
                    "candidate counts growth once despite recovery"
                );
            }
            // Obtain a recent-window candidate independently so even the
            // rejected controls exercise the opened-object age gate.
            let candidate = candidate_from_traversal_path(
                source,
                ScanTraversalPath {
                    scan_root: root.projects(),
                    path: path(name),
                    census_member: true,
                    watcher_hint: false,
                },
                &mut ScanCensus::default(),
                None,
                7,
                &mut crate::snapshots::CandidateDiscovery::new(&mut index, None, None),
            )
            .unwrap();
            if recovery_overlap && name == "grown" {
                assert!(
                    discovery_page(source.api_slug())
                        .get("discovery_retained")
                        .is_none(),
                    "recent candidate does not count growth"
                );
                assert!(open_and_identify_scan_candidate_with_rescue_at(
                    source,
                    candidate.clone(),
                    &mut ScanCensus::default(),
                    CandidateWindow {
                        census_unix_seconds: rfc3339_unix_seconds(NOW),
                        backfill_window_days: 7,
                        retention: discovery_retention!(index),
                        growth: None,
                    },
                    true,
                    None,
                )
                .is_some());
                assert!(
                    discovery_page(source.api_slug())
                        .get("discovery_retained")
                        .is_none(),
                    "caller verification rescue keeps its counter boundary"
                );
            }
            assert_eq!(
                open_and_identify_scan_candidate(
                    source,
                    candidate,
                    &mut ScanCensus::default(),
                    rfc3339_unix_seconds(NOW),
                    7,
                    discovery_retention!(index)
                )
                .is_some(),
                retained,
                "open {name}"
            );
            if recovery_overlap && name == "grown" {
                assert_eq!(
                    discovery_page(source.api_slug())["discovery_retained"],
                    json!({"grown": 1}),
                    "open counts growth once despite recovery"
                );
            }
            if source == SnapshotSource::Codex {
                assert_eq!(
                    codex_parent_outside_window(
                        discovery_retention!(index),
                        &path(name),
                        &File::open(path(name)).unwrap(),
                        rfc3339_unix_seconds(NOW),
                        7,
                        (&index.files).into(),
                    ),
                    !retained,
                    "Codex parent {name}"
                );
                if recovery_overlap && name == "grown" {
                    assert_eq!(
                        discovery_page(source.api_slug())["discovery_retained"],
                        json!({"grown": 1}),
                        "parent counts growth once despite recovery"
                    );
                }
            }
        }
        let expected = if source == SnapshotSource::Codex {
            6
        } else {
            4
        };
        // In the overlap case the grown key's per-gate events were drained above;
        // the held key still contributes once at each of the same gates.
        let expected = if recovery_overlap {
            expected / 2
        } else {
            expected
        };
        assert_eq!(
            discovery_page(source.api_slug())["discovery_retained"],
            json!({"grown": expected}),
            "one event per aged gate, not per arm"
        );
        assert!(
            discovery_page(source.api_slug())
                .get("discovery_retained")
                .is_none(),
            "page deltas drain to zero"
        );

        if recovery_overlap && source == SnapshotSource::Codex {
            // Make the indexed grown key newly visible to the retained roster.
            index
                .traversal
                .as_mut()
                .unwrap()
                .codex_rollout_paths
                .remove(&local_index_key(&path("grown")));
            File::open(&directory)
                .unwrap()
                .set_modified(UNIX_EPOCH)
                .unwrap();
            refresh_retained_codex_roster(
                source,
                index.traversal.as_mut().unwrap(),
                7,
                discovery_retention!(index),
                (&index.files).into(),
            );
            assert!(candidates(&index).contains(&path("grown")));
            assert_eq!(
                discovery_page(source.api_slug())["discovery_retained"],
                json!({"grown": 1}),
                "roster counts growth once despite recovery"
            );
        }
    }
}

/// [behaviour] A file can be newly noticed by a retained Codex directory roster after
/// sleep. The roster must use the same committed-size growth exemption.
#[test]
fn codex_roster_retains_aged_indexed_growth() {
    let root = Root::new("ld-grown-roster");
    let directory = root.projects().join("2026/10/01");
    fs::create_dir_all(&directory).unwrap();
    append(&directory.join("rollout-first.jsonl"), b"{}\n");
    let mut index = ScanIndex::default();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &[root.projects()],
        &mut index,
        NOW,
        7,
    );
    while !index
        .traversal
        .as_ref()
        .unwrap()
        .pending_directories
        .is_empty()
    {
        advance_bounded_directory_traversal(SnapshotSource::Codex, &mut index, 7, None, None);
    }
    discovery_page("codex");
    // Match the existing roster fixture's directory-change granularity.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let path = directory.join("rollout-grown.jsonl");
    append(&path, b"{}\n");
    set_old(&path);
    let mut entry = super::tests::manifest_index_entry(None);
    entry.size_bytes = 2;
    index.files.insert(local_index_key(&path), entry);
    assert!(!index
        .traversal
        .as_ref()
        .unwrap()
        .codex_rollout_paths
        .contains(&local_index_key(&path)));
    refresh_retained_codex_roster(
        SnapshotSource::Codex,
        index.traversal.as_mut().unwrap(),
        7,
        discovery_retention!(index),
        (&index.files).into(),
    );
    assert!(candidates(&index).contains(&path));
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .observed_index_keys
        .contains(&local_index_key(&path)));
    assert_eq!(
        discovery_page("codex")["discovery_retained"],
        json!({"grown": 1})
    );
}

/// [behaviour] The scan seam must share the virtual-slot clock, including when the
/// discovery growth arm admits an aged key that main would have filtered.
#[test]
fn grown_virtual_audit_uses_the_scheduling_clock_before_and_at_due() {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestCensusRecord as Record, ClaudeRequestCensusShape as Shape,
    };
    use crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS as INTERVAL;
    struct Clock;
    impl Drop for Clock {
        fn drop(&mut self) {
            sampled_scan::set_test_now(None);
        }
    }
    let _clock = Clock;
    let wall = sampled_scan::now_seconds();
    let now = wall - 4 * INTERVAL;
    let due = now + INTERVAL;
    assert!(due < wall, "wall time would prematurely select this slot");
    sampled_scan::set_test_now(Some(now));
    let root = Root::new("ld-grown-virtual-clock");
    let path = root.file(SESSION);
    let key = local_index_key(&path);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    append(&path, &assistant_line("u1"));
    let (mut index, _, _, _) =
        claude_page(&root.projects(), ScanIndex::default(), None, Some(&cache));
    assert!(index.claude_account_deferred_holds.is_empty());
    assert!(!index.files[&key].has_unverified_source());
    let template = index.files[&key].clone();
    let record = Record::synthetic_for_test(
        &template.source_file_fingerprint,
        1,
        Shape::IdentityIncomplete,
        vec![1],
    )
    .with_unverified_for_test(true);
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, record);
    // Reserve all but the existing last slot, as in the real erased-hold
    // regression; no restored marker can hide the virtual-slot clock seam.
    for n in 0..crate::transcript_cache::CACHE_ENTRIES - 1 {
        let mut pending = template.clone();
        pending.set_unverified_deadline(now);
        index
            .files
            .insert(format!("/unavailable-clock-debt/{n}"), pending);
    }
    index.held_audit_progress = Some(sampled_audit::HeldAuditProgress {
        key: key.clone(),
        due,
        attempted: false,
    });
    append(&path, &assistant_line("u2"));
    File::open(&path).unwrap().set_modified(UNIX_EPOCH).unwrap();
    cache.clear();
    let length = fs::metadata(&path).unwrap().len();
    assert!(length > index.files[&key].size_bytes);
    assert!(!discovery_retention!(index).owes(&path));
    assert!(discovery_retention!(index).owes_with_len(SnapshotSource::ClaudeCode, &path, length));
    assert!(sampled_audit::awaits_hold_deadline_restoration(
        &index, &key
    ));
    for _ in 0..2 {
        let observer = Recorder::default();
        let (next, result, _, _) =
            claude_page(&root.projects(), index, Some(&observer), Some(&cache));
        assert!(
            observer.events().is_empty(),
            "future slot schedules no acquisition or delivery"
        );
        assert_eq!(result.scanned_file_count, 0);
        let slot = next.held_audit_progress.as_ref().unwrap();
        assert_eq!(slot.due, due);
        assert!(!slot.attempted);
        index = next;
    }
    sampled_scan::set_test_now(Some(due));
    let observer = Recorder::default();
    let (_, result, _, _) = claude_page(&root.projects(), index, Some(&observer), Some(&cache));
    let modes = observer
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Begin(view) => Some(view.mode),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(modes, vec![DeliveryMode::Full], "due recovery reads once");
    assert_eq!(result.scanned_file_count, 1);
}

/// [behaviour] Growth followed by more than W of downtime is still read exactly once.
/// Committing the new length releases this exemption; generic Tail audit debt
/// is discharged explicitly before asserting ordinary aging, as in the hold fixture.
#[test]
fn grown_indexed_file_is_read_after_sleep_then_ages_after_commit() {
    let root = Root::new("ld-grown-sleep");
    let path = root.file(SESSION);
    let key = local_index_key(&path);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    // Freeze the comparison's collection clock before either path executes;
    // a native Tail and cold Full can finish on opposite sides of a second.
    let after_sleep = days_from_now(8);
    let page = |index: ScanIndex, days| {
        let now = if days == 8 {
            after_sleep.clone()
        } else {
            days_from_now(days)
        };
        let recorder = Recorder::default();
        let ((index, result, _), _) = capture(|| {
            finish(
                OwnedSourceScan::new(
                    SnapshotSource::ClaudeCode,
                    &[root.projects()],
                    index,
                    &now,
                    7,
                    10,
                    false,
                    None,
                    &[],
                    false,
                )
                .with_sampled_acquisition(
                    cache.clone(),
                    crate::transcript_acquisition::Scope("ld-grown-sleep".into()),
                )
                .with_line_observer("test", Box::new(recorder.clone())),
            )
        });
        (index, result, recorder)
    };
    append(&path, &assistant_line("u1"));
    let (committed, first, _) = page(ScanIndex::default(), 0);
    assert_eq!(first.scanned_file_count, 1);
    assert!(committed.claude_account_deferred_holds.is_empty());
    assert!(!committed.files[&key].has_unverified_source());
    append(&path, &assistant_line("u2"));
    let length = fs::metadata(&path).unwrap().len();
    assert!(length > committed.files[&key].size_bytes);
    // No in-process pacing or hold witness is needed: only the committed index.
    let (mut caught_up, result, recorder) = page(committed, 8);
    let modes = recorder
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Begin(view) => Some(view.mode),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(modes, vec![held_growth_mode()], "aged growth is read once");
    assert_eq!(
        recorder.lines().len(),
        if held_growth_mode() == DeliveryMode::Tail {
            1
        } else {
            2
        }
    );
    assert_eq!(
        result
            .snapshots
            .iter()
            .filter(|item| item.source_session_id == SESSION)
            .count(),
        1
    );
    assert_eq!(
        caught_up.files[&key].size_bytes, length,
        "new committed size catches up"
    );
    // Keep the raw full-body comparison and the shared emitted-money oracle.
    let (cold_index, cold, _) = finish(OwnedSourceScan::new(
        SnapshotSource::ClaudeCode,
        &[root.projects()],
        ScanIndex::default(),
        &after_sleep,
        730,
        10,
        false,
        None,
        &[],
        false,
    ));
    assert_eq!(
        serde_json::to_value(&result.snapshots).unwrap(),
        serde_json::to_value(&cold.snapshots).unwrap(),
        "aged growth == cold Full body"
    );
    sampled_scan::transition_fixture::money_oracle::assert_equivalent(
        &sampled_scan::transition_fixture::scan_money(
            SnapshotSource::ClaudeCode,
            &cold_index,
            &cold,
        ),
        &sampled_scan::transition_fixture::scan_money(
            SnapshotSource::ClaudeCode,
            &caught_up,
            &result,
        ),
    );
    let fingerprint = caught_up.files[&key].source_file_fingerprint.clone();
    assert_eq!(
        caught_up.files[&key].has_unverified_source(),
        held_growth_mode() == DeliveryMode::Tail
    );
    if caught_up.files[&key].has_unverified_source() {
        assert!(caught_up.complete_full_audit(&key, &fingerprint));
    }
    assert!(!discovery_retention!(caught_up).owes_with_len(
        SnapshotSource::ClaudeCode,
        &path,
        length
    ));
    let (aged, again, recorder) = page(caught_up, 9);
    assert!(recorder.events().is_empty());
    assert_eq!(again.scanned_file_count, 0);
    assert!(
        !aged.files.contains_key(&key),
        "normal aging resumes after commit"
    );
}

/// A Tail needs the retained reduction, which the RAM cache admits only where
/// `heap_layout_bound::layout_supported()` holds (macOS on the pinned rustc).
/// Elsewhere (Linux CI) the cache refuses retention (`retention_bound_refused`),
/// so every read is `Full(StateMissing)`, as for the other sampled-mode tests.
/// Never pin macOS to Full: a macOS Full here is E1's acquisition binding (W1).
fn held_growth_mode() -> DeliveryMode {
    if crate::heap_layout_bound::layout_supported() {
        DeliveryMode::Tail
    } else {
        DeliveryMode::Full
    }
}

/// [money] F4 releases once after ten minutes without acquiring or emitting money.
#[test]
#[cfg(unix)]
fn absent_account_hold_retires_without_money_or_completion_credit() {
    use sampled_scan::transition_fixture::{money_oracle, Accepted, Mode, RouteResult};
    let root = Root::new("ld-withheld-f4-money");
    let path = root.file(SESSION);
    append(&path, &assistant_line("f4"));
    let (mut index, cold_scan, _) = finish(new_scan(&root.projects(), ScanIndex::default()));
    assert!(!cold_scan.snapshots.is_empty());
    let mut request = super::tests::valid_v6_batch_request();
    request.snapshots = cold_scan.snapshots.clone();
    request.source = SnapshotSource::ClaudeCode.api_slug().into();
    let mut cold = RouteResult::emitted(
        Mode::ColdFull,
        SnapshotSource::ClaudeCode,
        vec![serde_json::to_vec(&request).unwrap()],
        &cold_scan.snapshots,
    );
    cold.accepted = cold_scan
        .snapshots
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                Accepted {
                    body: cold.snapshots[&item.source_session_id].clone(),
                    witness: snapshot_upload_body_witness(item),
                },
            )
        })
        .collect();
    let key = local_index_key(&path);
    let fingerprint = index.files[&key].source_file_fingerprint.clone();
    let tokens = cold_scan
        .snapshots
        .iter()
        .map(|item| (item.snapshot_fingerprint.clone(), 30))
        .collect();
    assert!(
        index.record_claude_account_deferred_holds([(key.as_str(), fingerprint.as_str())], &tokens)
    );
    assert_eq!(index.claude_account_deferred_hold_count(), 1);
    fs::remove_file(&path).unwrap();
    crate::local_resource_diagnostics::withheld_support::take_withheld();
    let mut releases = Vec::new();
    for (now, held) in [(1_000, 1), (1_599, 1), (1_600, 0), (2_200, 0)] {
        sampled_scan::set_test_now(Some(now));
        let at = (OffsetDateTime::parse(NOW, &Rfc3339).unwrap()
            + time::Duration::seconds(now as i64))
        .format(&Rfc3339)
        .unwrap();
        let ((next, scan, _), rows) = capture(|| {
            finish(OwnedSourceScan::new(
                SnapshotSource::ClaudeCode,
                &[root.projects()],
                index,
                &at,
                BACKFILL_WINDOW_DAYS,
                10,
                false,
                None,
                &[],
                false,
            ))
        });
        releases.extend(
            rows.into_iter()
                .filter_map(|row| row["counts"]["withheld_hold_released"].as_object().cloned()),
        );
        index = next;
        assert_eq!(index.claude_account_deferred_hold_count(), held);
        assert_eq!(scan.scanned_file_count, 0);
        assert!(scan.snapshots.is_empty());
        let mut route = RouteResult::emitted(
            Mode::Ram,
            SnapshotSource::ClaudeCode,
            Vec::new(),
            &scan.snapshots,
        );
        route.accepted = cold.accepted.clone();
        money_oracle::assert_held(SESSION, &cold, &route, &cold);
    }
    sampled_scan::set_test_now(None);
    assert_eq!(
        releases,
        vec![json!({"deleted": 1, "deleted_tokens": 30})
            .as_object()
            .unwrap()
            .clone()]
    );
}

/// [behaviour] F-INDEX and census completion: a present aged withheld key is observed, so
/// reconciliation and the raw-census prune keep its entry and hold. A held key
/// whose file is gone is still proved absent and retired with its hold, so a
/// deleted file cannot pin the hold (and the unsettled receipt) forever.
#[test]
fn reconciliation_keeps_present_withheld_keys_and_retires_absent_ones() {
    let root = Root::new("ld-withheld-reconcile");
    let project = root.projects().join("p");
    fs::create_dir_all(&project).unwrap();
    let file = |name: &str| project.join(format!("{name}.jsonl"));
    for name in ["held", "old"] {
        append(&file(name), b"{}\n");
        set_old(&file(name));
    }
    let mut index = ScanIndex::default();
    // Reconciliation itself may record the first NotFound. Use the same
    // clock for that observation and the explicit 599/600-second probes.
    sampled_scan::set_test_now(Some(1_000));
    withheld_account::support::clock(&index.withheld_memo);
    for name in ["held", "old", "gone"] {
        let mut entry = super::tests::manifest_index_entry(Some(name));
        // Present controls are unchanged, not grown since the committed size.
        if name != "gone" {
            entry.size_bytes = fs::metadata(file(name)).unwrap().len();
        }
        index.files.insert(local_index_key(&file(name)), entry);
    }
    withhold(&mut index, &file("held"));
    withhold(&mut index, &file("gone"));
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[root.projects()],
        &mut index,
        NOW,
        7,
    );
    walk_all(&mut index, 7);
    assert!(reconcile_missing_index_entries_with_limit(
        &mut index,
        usize::MAX
    ));
    // The gone key is never a candidate: its release reads nothing.
    assert_eq!(candidates(&index), vec![file("held")]);
    index.probe_absent_claude_account_deferred_holds();
    assert_eq!(index.claude_account_deferred_hold_count(), 2);
    next_walk(&mut index, &[root.projects()], NOW, 7);
    sampled_scan::set_test_now(Some(1_599));
    index.probe_absent_claude_account_deferred_holds();
    assert_eq!(index.claude_account_deferred_hold_count(), 2);
    sampled_scan::set_test_now(Some(1_600));
    index.probe_absent_claude_account_deferred_holds();
    sampled_scan::set_test_now(None);
    // Lead A round 2: "deleted held file: hold released, counted".
    assert_eq!(
        crate::local_resource_diagnostics::withheld_support::take_withheld()[0],
        BTreeMap::from([("deleted", 1)])
    );
    let held = BTreeSet::from([local_index_key(&file("held"))]);
    // Before the exemption both sets were empty: the aged held key was not
    // observed, so reconciliation dropped its entry and hold.
    assert_eq!(index.files.keys().cloned().collect::<BTreeSet<_>>(), held);
    assert_eq!(
        index
            .claude_account_deferred_holds
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        held
    );
}

/// RFC 3339 for the real clock plus `days`: transcript mtimes are real.
fn days_from_now(days: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    OffsetDateTime::from_unix_timestamp((now + days * 86_400) as i64)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

fn assistant_line(uuid: &str) -> Vec<u8> {
    let value = json!({"type": "assistant", "sessionId": SESSION, "uuid": uuid,
        "cwd": "/w/one", "timestamp": "2026-10-06T10:00:00.000Z",
        "requestId": format!("req_{uuid}"),
        "message": {"id": format!("msg_{uuid}"), "model": "claude-opus-4-8",
            "role": "assistant", "usage": {"input_tokens": 10, "output_tokens": 20}}});
    [raw(&value), b"\n".to_vec()].concat()
}

/// [behaviour] HOLD RULE fixture (GUARDRAILS "No hold may drop a growing file"): a key
/// whose account stays unresolved grows over held passes, grows again and then
/// idles past a 7-day window. The next page still discovers it, reads only the
/// unread growth as a Tail, emits the session once, and keeps the entry and
/// hold through census completion. After the hold resolves, the next aged page
/// neither reads nor keeps the key: normal aging resumes.
#[test]
fn withheld_account_growth_is_read_after_idling_past_the_window() {
    let root = Root::new("ld-withheld-aged");
    let path = root.file(SESSION);
    let key = local_index_key(&path);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let page = |index: ScanIndex, collected_at: &str| {
        let recorder = Recorder::default();
        let ((index, result, _), _) = capture(|| {
            finish(
                OwnedSourceScan::new(
                    SnapshotSource::ClaudeCode,
                    &[root.projects()],
                    index,
                    collected_at,
                    7,
                    10,
                    false,
                    None,
                    &[],
                    false,
                )
                .with_sampled_acquisition(
                    cache.clone(),
                    crate::transcript_acquisition::Scope("ld-withheld-aged".into()),
                )
                .with_line_observer("test", Box::new(recorder.clone())),
            )
        });
        (index, result, recorder)
    };
    let today = days_from_now(0);
    append(&path, &assistant_line("u1"));
    let (committed, first, _) = page(ScanIndex::default(), &today);
    assert_eq!(first.scanned_file_count, 1);
    // Held passes: each parse is withheld, so the key keeps its committed
    // revision and the hold names the parsed one.
    let mut held = committed;
    for uuid in ["u2", "u3"] {
        append(&path, &assistant_line(uuid));
        let (parsed, result, _) = page(held.clone(), &today);
        assert_eq!(result.scanned_file_count, 1, "growth while held is read");
        held.claude_account_deferred_holds.insert(
            key.clone(),
            parsed.files[&key].source_file_fingerprint.clone(),
        );
    }
    // Unread growth, then the file idles past the window.
    append(&path, &assistant_line("u4"));
    let aged = days_from_now(8);
    let (parsed, result, recorder) = page(held, &aged);
    let begins = recorder
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Begin(view) => Some(view),
            _ => None,
        })
        .collect::<Vec<_>>();
    // Before the exemption: no read at all, and reconciliation dropped the
    // entry and hold, so u4 was never uploaded.
    assert_eq!(begins.len(), 1, "the aged held key is discovered once");
    assert_eq!(
        begins[0].mode,
        held_growth_mode(),
        "held growth reads as a counted Tail, never a Full"
    );
    // A Tail delivers only the unread u4 line; a Full (no retained reduction)
    // all four. Either way u4 is read: no drop.
    let delivered = if held_growth_mode() == DeliveryMode::Tail {
        1
    } else {
        4
    };
    assert_eq!(
        recorder.lines().len(),
        delivered,
        "the unread u4 line is read"
    );
    assert_eq!(
        result
            .snapshots
            .iter()
            .filter(|snapshot| snapshot.source_session_id == SESSION)
            .count(),
        1
    );
    assert!(parsed.files.contains_key(&key), "census completion kept it");
    assert!(parsed.claude_account_deferred_holds.contains_key(&key));
    // The account binds: the next parse resolves the hold.
    let mut resolved = parsed;
    assert!(
        resolved.record_claude_account_deferred_holds(result.completed_parses(), &BTreeMap::new())
    );
    assert!(resolved.claude_account_deferred_holds.is_empty());
    // The u4 Tail (supported layouts only) is an accepted sampled generation:
    // `sampled_audit` stages its pre-existing audit debt, which keeps the key
    // owed until a Full audit, held or not. A Full (Linux) stages none. Clear
    // it as a completed audit would, so only the hold arm is under test.
    let entry = &resolved.files[&key];
    assert_eq!(
        entry.has_unverified_source(),
        held_growth_mode() == DeliveryMode::Tail,
        "only a Tail stages audit debt"
    );
    let fingerprint = entry.source_file_fingerprint.clone();
    if entry.has_unverified_source() {
        assert!(resolved.complete_full_audit(&key, &fingerprint));
    }
    // The exemption ends at resolution: nothing owes the resolved key.
    assert!(!discovery_retention!(resolved).owes(&path));
    let (after, again, recorder) = page(resolved, &days_from_now(9));
    assert_eq!(recorder.events(), Vec::new(), "aged and no longer held");
    assert_eq!(again.scanned_file_count, 0);
    assert!(!after.files.contains_key(&key), "ordinary aging retires it");
}

/// [money] M3: grown held usage survives an aged in-root rename; unknown generation keeps debt.
#[test]
#[cfg(unix)]
fn renamed_aged_account_hold_moves_custody_before_age_or_keeps_uncertain_debt() {
    use sampled_scan::transition_fixture::{money_oracle, scan_money, Accepted};
    for (known_generation, hint_only) in
        [(true, false), (false, false), (true, true), (false, true)]
    {
        let root = Root::new("ld-held-rename-money");
        let original = root
            .projects()
            .join("original")
            .join(format!("{SESSION}.jsonl"));
        let moved = root
            .projects()
            .join("moved")
            .join(format!("{SESSION}.jsonl"));
        fs::create_dir_all(original.parent().unwrap()).unwrap();
        fs::create_dir_all(moved.parent().unwrap()).unwrap();
        let old_key = local_index_key(&original);
        let new_key = local_index_key(&moved);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let source = SnapshotSource::ClaudeCode;
        let make = |mut index: ScanIndex, at: &str, days| {
            cache.bind_withheld(&mut index);
            OwnedSourceScan::new(
                source,
                &[root.projects()],
                index,
                at,
                days,
                10,
                false,
                None,
                &[],
                false,
            )
            .with_sampled_acquisition(
                cache.clone(),
                crate::transcript_acquisition::Scope("held-rename-money".into()),
            )
        };
        let now = OffsetDateTime::now_utc();
        let today = now.format(&Rfc3339).unwrap();
        sampled_scan::set_test_now(Some(now.unix_timestamp() as u64));
        append(&original, &assistant_line("rename-accepted"));
        let (baseline, first, _) = finish(make(ScanIndex::default(), &today, 7));
        let mut prior = scan_money(source, &baseline, &first);
        prior.accepted = first
            .snapshots
            .iter()
            .map(|item| {
                (
                    item.source_session_id.clone(),
                    Accepted {
                        body: prior.snapshots[&item.source_session_id].clone(),
                        witness: snapshot_upload_body_witness(item),
                    },
                )
            })
            .collect();
        assert!(
            !prior.accepted.is_empty(),
            "positive accepted money is the floor"
        );
        append(&original, &assistant_line("rename-held"));
        let (mut parsed, second, _) = finish(make(baseline.clone(), &today, 7));
        parsed.accepted_snapshot_fingerprints = baseline.accepted_snapshot_fingerprints.clone();
        let mut held =
            crate::snapshot_sync::withheld_support::settle_withheld(&baseline, parsed, second);
        assert_eq!(held.claude_account_deferred_hold_count(), 1);
        let incidence = held.file_snapshot_fingerprints[&old_key].clone();
        let committed_size = held.files[&old_key].size_bytes;
        // Growth is unread when the pathname changes; rename preserves mtime.
        append(&original, &assistant_line("rename-unread"));
        let modified = fs::metadata(&original).unwrap().modified().unwrap();
        let (cold_index, mut cold_scan, _) = finish(OwnedSourceScan::new(
            source,
            &[root.projects()],
            ScanIndex::default(),
            &today,
            7,
            10,
            false,
            None,
            &[],
            false,
        ));
        if !known_generation {
            // Real legacy/unknown owner state, using its existing observation API.
            let birth = claude_context_file_birth::ClaudeOpenedBirth::from_metadata(
                &fs::metadata(&original).unwrap(),
            )
            .birth;
            held.claude_money_birth_store = Default::default();
            held.claude_money_birth_store
                .record_observation(SESSION, &old_key, i128::from(birth));
        }
        let aged = now + time::Duration::days(731); // beyond min(requested=1000, 730 days)
        let at = aged.format(&Rfc3339).unwrap();
        // The cold reference must be discovered before the age cutoff. Align
        // only its collection clock with the aged route, then build both whole
        // envelopes through scan_money; all usage and ownership fields remain.
        for item in &mut cold_scan.snapshots {
            item.collected_at = at.clone();
        }
        let cold = scan_money(source, &cold_index, &cold_scan);
        sampled_scan::set_test_now(Some(aged.unix_timestamp() as u64));
        if hint_only {
            // Walk A before the rename, then leave its candidate backlog open.
            // D can arrive only by hint in this generation, even after 600 s.
            held.traversal = None;
            ensure_bounded_traversal(source, &[root.projects()], &mut held, &at, 1_000);
            walk_all(&mut held, 1_000);
            assert!(held
                .traversal
                .as_ref()
                .unwrap()
                .observed_index_keys
                .contains(&old_key));
        }
        let old_location = claude_money_birth_store::location_key(&old_key);
        let new_location = claude_money_birth_store::location_key(&new_key);
        let holder = claude_money_birth_store::location_key("synthetic-holder");
        held.claude_copy_removals.store(
            old_location,
            BTreeMap::from([(holder, BTreeSet::from([7]))]),
        );
        assert!(held.claude_copy_removals.advance_hold(old_location));
        held.claude_money_birth_store.set_money_marks(&old_key, 1);
        crate::local_resource_diagnostics::withheld_support::take_withheld();
        fs::rename(&original, &moved).unwrap();
        assert_eq!(fs::metadata(&moved).unwrap().modified().unwrap(), modified);
        let checkpoint = root.0.join("held-rename-index.json");
        held.save(&checkpoint).unwrap();
        held = ScanIndex::load(&checkpoint).unwrap();
        let mut active = held.clone();
        if hint_only {
            withheld_account::support::clock(&active.withheld_memo);
            for offset in [0, 600, 1_200] {
                sampled_scan::set_test_now(Some(aged.unix_timestamp() as u64 + offset));
                active.probe_absent_claude_account_deferred_holds();
                assert!(
                    active.claude_account_deferred_holds.contains_key(&old_key),
                    "a resumed walk that predates NotFound cannot release custody"
                );
                assert!(active.files.contains_key(&old_key));
            }
            enqueue_watcher_hints(
                source,
                active.traversal.as_mut().unwrap(),
                std::slice::from_ref(&moved),
                false,
            );
            let hinted = active
                .traversal
                .as_mut()
                .unwrap()
                .pending_candidates
                .iter()
                .position(|p| p.path == moved)
                .expect("destination hint");
            let pending = active
                .traversal
                .as_mut()
                .unwrap()
                .pending_candidates
                .remove(hinted)
                .unwrap();
            let candidate = candidate_from_traversal_path(
                source,
                pending,
                &mut ScanCensus::default(),
                rfc3339_unix_seconds(&at),
                1_000,
                &mut CandidateDiscovery::new(&mut active, None, None),
            );
            assert!(
                candidate.is_none(),
                "old observed path keeps ambiguous custody until a later walk"
            );
            assert!(
                active
                    .traversal
                    .as_ref()
                    .unwrap()
                    .observed_index_keys
                    .contains(&new_key),
                "candidate metadata must record same-member presence before age refusal"
            );
            active.probe_absent_claude_account_deferred_holds();
            assert!(active.claude_account_deferred_holds.contains_key(&old_key));
            next_walk(&mut active, &[root.projects()], &at, 1_000);
        }
        let scan = make(active, &at, 1_000);
        assert!(
            crate::local_resource_diagnostics::withheld_support::take_withheld()[0].is_empty(),
            "custody transfer/uncertainty grants neither ReleasedDeleted nor ReleasedResolved"
        );
        if known_generation {
            assert!(scan.index.claude_copy_removals.get(old_location).is_empty());
            assert_eq!(
                scan.index.claude_copy_removals.get(new_location)[0]
                    .1
                    .as_ref(),
                &[7]
            );
            assert!(scan.index.claude_copy_removals.pending(new_location));
            assert_eq!(
                scan.index
                    .claude_money_birth_store
                    .money_marks(old_location),
                0
            );
            assert_eq!(
                scan.index
                    .claude_money_birth_store
                    .money_marks(new_location),
                1
            );
            assert!(scan
                .index
                .claude_account_deferred_holds
                .contains_key(&new_key));
            assert!(!scan
                .index
                .claude_account_deferred_holds
                .contains_key(&old_key));
            assert_eq!(scan.index.files[&new_key].size_bytes, committed_size);
            assert_eq!(scan.index.file_snapshot_fingerprints[&new_key], incidence);
            assert!(!scan.index.files.contains_key(&old_key));
            let (mut resolved, result, _) = finish(scan);
            // Recovery control: B was already parsed/bound before the next walk
            // could transfer A. Reuse those real results, not another fixture.
            let mut raced = held.clone();
            raced
                .files
                .insert(new_key.clone(), resolved.files[&new_key].clone());
            raced.file_snapshot_fingerprints.insert(
                new_key.clone(),
                resolved.file_snapshot_fingerprints[&new_key].clone(),
            );
            raced
                .accepted_snapshot_fingerprints
                .extend(resolved.accepted_snapshot_fingerprints.clone());
            raced
                .snapshot_activity_at
                .extend(resolved.snapshot_activity_at.clone());
            let opened = claude_context_file_birth::ClaudeOpenedBirth::from_metadata(
                &fs::metadata(&moved).unwrap(),
            );
            raced.claude_money_birth_store.record_opened(
                SESSION,
                &new_key,
                i128::from(opened.birth),
                opened,
            );
            let recovery = make(raced, &at, 1_000);
            assert!(!recovery
                .index
                .claude_account_deferred_holds
                .contains_key(&old_key));
            assert!(recovery
                .index
                .claude_account_deferred_holds
                .contains_key(&new_key));
            assert_eq!(
                recovery.index.files[&new_key].last_upload_body_witness,
                resolved.files[&new_key].last_upload_body_witness
            );
            assert_eq!(
                recovery.index.file_snapshot_fingerprints[&new_key],
                resolved.file_snapshot_fingerprints[&new_key]
            );
            assert!(incidence.is_subset(&recovery.index.accepted_rebuild_incidence[&new_key]));
            // Both native held restoration and partial-commit selection use the
            // moved baseline; neither may resurrect the old pathname or commit growth.
            let withheld = crate::snapshot_sync::withheld_support::settle_withheld(
                &held,
                resolved.clone(),
                result.clone(),
            );
            assert_eq!(withheld.files[&new_key].size_bytes, committed_size);
            assert_eq!(withheld.file_snapshot_fingerprints[&new_key], incidence);
            assert!(withheld
                .claude_account_deferred_holds
                .contains_key(&new_key));
            assert!(!withheld.files.contains_key(&old_key));
            let mut committed = held.clone();
            committed.rehome_withheld_baseline(&resolved);
            let partial =
                resolved.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
            assert_eq!(partial.files[&new_key].size_bytes, committed_size);
            assert!(!partial.files.contains_key(&old_key));
            money_oracle::assert_equivalent(&cold, &scan_money(source, &resolved, &result));
            assert_eq!(
                result
                    .snapshots
                    .iter()
                    .filter(|item| item.source_session_id == SESSION)
                    .count(),
                1
            );
            assert!(result.completed_parses().all(|(key, _)| key == new_key));
            assert!(resolved
                .record_claude_account_deferred_holds(result.completed_parses(), &BTreeMap::new()));
            assert!(resolved.claude_account_deferred_holds.is_empty());
            let entry = &resolved.files[&new_key];
            if entry.has_unverified_source() {
                let fingerprint = entry.source_file_fingerprint.clone();
                assert!(resolved.complete_full_audit(&new_key, &fingerprint));
            }
            let (_, quiet, _) = finish(make(resolved, &at, 1_000));
            assert!(
                quiet.snapshots.is_empty(),
                "accepted moved usage emits once"
            );
        } else {
            let (mut kept, result, _) = finish(scan);
            for offset in [0, 600, 1_200] {
                if offset != 0 {
                    sampled_scan::set_test_now(Some(aged.unix_timestamp() as u64 + offset));
                    let (next, quiet, _) = finish(make(kept, &at, 1_000));
                    kept = next;
                    assert!(quiet.snapshots.is_empty());
                }
                let mut route = scan_money(source, &kept, &result);
                route.accepted = prior.accepted.clone();
                money_oracle::assert_held(SESSION, &prior, &route, &cold);
                assert!(kept.claude_account_deferred_holds.contains_key(&old_key));
                assert_eq!(kept.files[&old_key].size_bytes, committed_size);
                assert_eq!(kept.file_snapshot_fingerprints[&old_key], incidence);
                assert!(!kept.claude_account_deferred_holds.contains_key(&new_key));
            }
        }
        sampled_scan::set_test_now(None);
    }
}

/// [behaviour] Option C (Lead A, round 2) and fixture (c): within a process a held key
/// whose content stamp and account evidence are unchanged has no parse or
/// line delivery over many passes (bounded identity samples remain). It re-parses exactly once after an account
/// evidence change, at most once after a restart, and as a Tail on growth;
/// each re-parse is counted by trigger.
#[test]
fn withheld_account_reparses_only_on_start_evidence_or_growth() {
    use crate::local_resource_diagnostics::withheld_support::take_withheld;
    let root = Root::new("ld-withheld-memo");
    let support = root.0.join("support");
    let sidecars = support.join(crate::claude_local_otel::STORE_DIR);
    fs::create_dir_all(&sidecars).unwrap();
    let api_sidecar = sidecars.join(format!("{:x}.jsonl", Sha256::digest(SESSION.as_bytes())));
    let path = root.file(SESSION);
    let key = local_index_key(&path);
    let today = days_from_now(0);
    let clamp_events = std::cell::Cell::new(0_u64);
    let last_page = RefCell::new(Value::Null);
    let page = |mut index: ScanIndex, cache: &Arc<sampled_scan::SharedCache>| {
        cache.bind_withheld(&mut index);
        let recorder = Recorder::default();
        let ((index, result, _), rows) = capture(|| {
            finish(
                OwnedSourceScan::new(
                    SnapshotSource::ClaudeCode,
                    &[root.projects()],
                    index,
                    &today,
                    7,
                    10,
                    false,
                    Some(support.as_path()),
                    &[],
                    false,
                )
                .with_sampled_acquisition(
                    cache.clone(),
                    crate::transcript_acquisition::Scope("ld-withheld-memo".into()),
                )
                .with_line_observer("test", Box::new(recorder.clone())),
            )
        });
        for row in &rows {
            clamp_events.set(
                clamp_events.get()
                    + row["counts"]["withheld_birth_clamp_accepted"]["events"]
                        .as_u64()
                        .unwrap_or(0),
            );
            if row["stage"] == "native_collection_page" {
                *last_page.borrow_mut() = row.clone();
            }
        }
        let reads = recorder
            .events()
            .into_iter()
            .filter_map(|event| match event {
                Event::Begin(view) => Some(view.mode),
                _ => None,
            })
            .collect::<Vec<_>>();
        (index, result, reads)
    };
    // The resolver withholds the parse, as ScanSettlement records it; only the
    // hold commits, so the key keeps its committed revision.
    let checkpoint = root.0.join("held-index.json");
    let withhold = |committed: &mut ScanIndex, parsed: ScanIndex, result: &SourceScanResult| {
        // Exercise classify -> Completed settlement -> durable save/reload;
        // copying the hold map misses the real fingerprint restore seam.
        *committed = crate::snapshot_sync::withheld_support::settle_withheld(
            committed,
            parsed,
            result.clone(),
        );
        assert!(committed.claude_account_deferred_holds.contains_key(&key));
        assert!(!committed.files[&key].source_file_fingerprint.is_empty());
        committed.save(&checkpoint).unwrap();
        *committed = ScanIndex::load(&checkpoint).unwrap();
    };
    let touch = || {
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_times(fs::FileTimes::new().set_modified(SystemTime::now()))
            .unwrap();
    };
    let reparses = || {
        let [_, reparses, _] = take_withheld();
        reparses
    };
    let cache = Arc::new(sampled_scan::SharedCache::default());
    append(&path, &assistant_line("u1"));
    // macOS setattrlist(2): backdating mtime before creation also backdates
    // creation. Establish an unchanged-birth control BEFORE recording generation;
    // later touches then change only mtime/ctime on APFS as well as Linux.
    let file = File::options().write(true).open(&path).unwrap();
    file.set_modified(UNIX_EPOCH + std::time::Duration::from_secs(100))
        .unwrap();
    file.set_modified(SystemTime::now()).unwrap();
    let original_birth = file.metadata().unwrap().created().ok();

    let (mut committed, _, reads) = page(ScanIndex::default(), &cache);
    assert_eq!(reads.len(), 1);
    append(&path, &assistant_line("u2"));
    let (parsed, result, reads) = page(committed.clone(), &cache);
    assert_eq!(reads.len(), 1);
    withhold(&mut committed, parsed, &result);
    assert_eq!(reparses(), BTreeMap::new(), "a new hold is no re-parse");
    touch(); // Before the very first memo lookup: completion must store content.

    // Before round 2 every pass re-read the key (TranscriptChanged against
    // its old committed revision).
    for pass in 0..3 {
        let (_, _, reads) = page(committed.clone(), &cache);
        assert_eq!(reads, Vec::new(), "unchanged pass {pass}: Skip, no parse");
    }
    assert_eq!(reparses(), BTreeMap::new());

    // A held Tail's audit debt is carried onto the reverted committed entry
    // (`committable_subset_with_local_holds`), where no audit can settle it.
    // Past due, it must not force a Full on every pass of an unchanged key.
    let fingerprint = committed.files[&key].source_file_fingerprint.clone();
    let debt = crate::transcript_acquisition::AuditDebt {
        due_unix_seconds: 1,
    };
    assert!(committed.stage_sampled_audit(&key, &fingerprint, debt));
    assert!(committed.files[&key].audit_requires_full(2));
    for pass in 0..2 {
        let (_, _, reads) = page(committed.clone(), &cache);
        assert_eq!(reads, Vec::new(), "held audit debt, pass {pass}: deferred");
    }
    assert_eq!(reparses(), BTreeMap::new());
    // The binding parse discharges it (#876-A's aging fixture); clear it so the
    // later steps keep their read modes.
    assert!(committed.complete_full_audit(&key, &fingerprint));

    // Account evidence arrives (the api sidecar the resolver reads).
    fs::write(&api_sidecar, b"{}\n").unwrap();
    let (parsed, result, reads) = page(committed.clone(), &cache);
    assert_eq!(reads.len(), 1, "one re-parse on an evidence change");
    withhold(&mut committed, parsed, &result);
    assert_eq!(reparses(), BTreeMap::from([("evidence", 1)]));
    touch();
    assert_eq!(page(committed.clone(), &cache).2, Vec::new());

    // A restart: an empty process memo and RAM cache.
    withheld_account::support::restart(&committed.withheld_memo);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (parsed, result, reads) = page(committed.clone(), &cache);
    assert_eq!(reads.len(), 1, "at most one re-parse per held key");
    withhold(&mut committed, parsed, &result);
    assert_eq!(reparses(), BTreeMap::from([("start", 1)]));
    assert_eq!(page(committed.clone(), &cache).2, Vec::new());

    append(&path, &assistant_line("u3"));
    let (parsed, result, reads) = page(committed.clone(), &cache);
    assert_eq!(
        reads,
        vec![held_growth_mode()],
        "growth is a Tail, never Full"
    );
    withhold(&mut committed, parsed, &result);
    assert_eq!(reparses(), BTreeMap::from([("growth", 1)]));
    touch();
    assert_eq!(page(committed.clone(), &cache).2, Vec::new());

    // SOURCE condition 1: a metadata-only touch (mtime and ctime move, the
    // content does not) has no parse, aged past the window or recent.
    let touch = |modified: SystemTime| {
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
    };
    let hour_ago = SystemTime::now() - std::time::Duration::from_secs(3_600);
    for modified in [UNIX_EPOCH + std::time::Duration::from_secs(100), hour_ago] {
        touch(modified);
        assert_eq!(
            fs::metadata(&path).unwrap().created().ok(),
            original_birth,
            "a pure touch must preserve the object-generation premise"
        );
        assert_eq!(page(committed.clone(), &cache).2, Vec::new(), "a touch");
    }
    assert_eq!(reparses(), BTreeMap::new(), "a touch is no re-parse");

    // Explicit forward touch after the completed memo: neither a parse nor
    // a clamp transition, on native metadata as well as the portable path.
    touch(SystemTime::now());
    assert_eq!(
        page(committed.clone(), &cache).2,
        Vec::new(),
        "forward touch after memo"
    );
    assert_eq!(
        clamp_events.get(),
        0,
        "forward touch never accepts a birth clamp"
    );
    assert_eq!(
        last_page.borrow()["counts"]["sampled_acquisition"]["full_selections"],
        0
    );
    assert_eq!(reparses(), BTreeMap::new());

    // cp -p style: truncate the EXISTING object, restore the identical bytes,
    // then backdate mtime below the memo's recorded birth, without unlinking.
    let identical = fs::read(&path).unwrap();
    let before_overwrite = fs::metadata(&path).unwrap();
    let object = physical_identity(&before_overwrite).unwrap();
    let preserved_time = UNIX_EPOCH + std::time::Duration::from_secs(75);
    {
        let mut file = File::options()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        assert_eq!(physical_identity(&file.metadata().unwrap()), Some(object));
        file.write_all(&identical).unwrap();
        file.set_times(fs::FileTimes::new().set_modified(preserved_time))
            .unwrap();
    }
    let after_overwrite = fs::metadata(&path).unwrap();
    assert_eq!(
        physical_identity(&after_overwrite),
        Some(object),
        "overwrite preserves device and inode"
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        identical,
        "the entire body is identical"
    );
    #[cfg(target_os = "macos")]
    {
        assert!(before_overwrite.created().unwrap() > preserved_time);
        assert_eq!(after_overwrite.created().unwrap(), preserved_time);
    }
    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        after_overwrite.created().ok(),
        before_overwrite.created().ok()
    );
    for pass in 0..3 {
        assert_eq!(
            page(committed.clone(), &cache).2,
            Vec::new(),
            "same-content overwrite pass {pass}: no acquisition or delivery"
        );
        assert_eq!(
            last_page.borrow()["counts"]["sampled_acquisition"]["full_selections"],
            0
        );
    }
    assert_eq!(
        clamp_events.get(),
        u64::from(cfg!(target_os = "macos")),
        "overwrite accepts exactly one clamp on macOS"
    );
    assert_eq!(
        reparses(),
        BTreeMap::new(),
        "identical overwrite never re-parses"
    );
    // Isolate the next existing case's event delta; do not reset its memo.
    clamp_events.set(0);

    // The original r24 failure: move mtime BELOW birth AFTER CONTENT exists.
    // On APFS this also clamps birth; Linux retains its original birth.
    let before = fs::metadata(&path).unwrap();
    let backward = UNIX_EPOCH + std::time::Duration::from_secs(50);
    touch(backward);
    #[cfg(target_os = "macos")]
    {
        assert!(before.created().unwrap() > backward);
        assert_eq!(fs::metadata(&path).unwrap().created().unwrap(), backward);
    }
    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        fs::metadata(&path).unwrap().created().ok(),
        before.created().ok()
    );
    for pass in 0..3 {
        assert_eq!(
            page(committed.clone(), &cache).2,
            Vec::new(),
            "post-memo backward touch {pass}"
        );
    }
    assert_eq!(
        clamp_events.get(),
        u64::from(cfg!(target_os = "macos")),
        "one clamp acceptance, never per-pass"
    );
    assert_eq!(reparses(), BTreeMap::new());

    // Equal length plus a changed sampled byte must still read Full. Keep the
    // same object and repeat the clamp signature; samples must veto acceptance.
    let bytes = fs::read(&path).unwrap();
    let offset = bytes.windows(2).position(|w| w == b"u1").unwrap();
    let mut file = File::options().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(offset as u64)).unwrap();
    file.write_all(b"v").unwrap();
    touch(UNIX_EPOCH + std::time::Duration::from_secs(25));
    assert_eq!(fs::metadata(&path).unwrap().len(), bytes.len() as u64);
    let (parsed, result, reads) = page(committed.clone(), &cache);
    assert_eq!(
        reads,
        vec![DeliveryMode::Full],
        "changed sampled byte never inherits clamp Skip"
    );
    let reason = if crate::heap_layout_bound::layout_supported() {
        "same_size_edit"
    } else {
        "state_missing"
    };
    assert_eq!(
        last_page.borrow()["counts"]["sampled_acquisition"]["page_events"]["full_reasons"][reason],
        1
    );
    assert_eq!(clamp_events.get(), u64::from(cfg!(target_os = "macos")));
    withhold(&mut committed, parsed, &result);
    assert_eq!(reparses(), BTreeMap::from([("evidence", 1)]));

    // SOURCE condition 2: the account binds on new evidence; that parse is
    // the one read, and later generations read nothing.
    fs::write(&api_sidecar, b"{}\n{}\n").unwrap();
    let (mut bound, result, reads) = page(committed, &cache);
    assert_eq!(reads.len(), 1, "the binding read happens once");
    assert!(bound.record_claude_account_deferred_holds(result.completed_parses(), &BTreeMap::new()));
    assert!(bound.claude_account_deferred_holds.is_empty());
    let [released, reparses, _] = take_withheld();
    assert_eq!(released, BTreeMap::from([("resolved", 1)]));
    assert_eq!(reparses, BTreeMap::from([("evidence", 1)]));
    for generation in 0..2 {
        let (_, again, reads) = page(bound.clone(), &cache);
        assert_eq!(reads, Vec::new(), "generation {generation} after binding");
        assert_eq!(again.scanned_file_count, 0);
    }

    // Regression: a second path for the held session participates in the
    // constructor's twin preflight. Reload must bind the warm CONTENT memo
    // before that preflight, or ForcedFamily reparses it on every page.
    let twin = root
        .projects()
        .join("twin")
        .join(format!("{SESSION}.jsonl"));
    fs::create_dir_all(twin.parent().unwrap()).unwrap();
    fs::copy(&path, &twin).unwrap();
    append(&path, &assistant_line("twin-held"));
    append(&twin, &assistant_line("twin-held"));
    let (parsed, result, _) = page(bound.clone(), &cache);
    withhold(&mut bound, parsed, &result);
    assert_eq!(bound.claude_account_deferred_hold_count(), 2);
    let incidence = bound.file_snapshot_fingerprints.clone();
    for generation in 0..2 {
        let (quiet, again, reads) = page(bound.clone(), &cache);
        assert!(reads.is_empty(), "held twins, generation {generation}");
        assert_eq!(again.scanned_file_count, 0);
        assert!(again.snapshots.is_empty());
        assert_eq!(quiet.claude_account_deferred_hold_count(), 2);
        assert_eq!(quiet.file_snapshot_fingerprints, incidence);
    }
}

#[test]
fn codex_prelude_registration_preserves_money_receipts_proofs_and_body_with_salvage() {
    let root = Root::new("prelude-money");
    let sessions = root.0.join("sessions");
    fs::create_dir(&sessions).unwrap();
    let id = "019fa111-2222-7333-8444-555555555555";
    let path = sessions.join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
    let usage = |n| json!({"type":"event_msg","timestamp":"2026-10-07T10:00:02Z","payload":{"type":"token_count","service_tier":"priority","info":{"model_context_window":200000,"model":"gpt-5","last_token_usage":{"input_tokens":n,"output_tokens":2,"total_tokens":n+2},"total_token_usage":{"input_tokens":n,"output_tokens":2,"total_tokens":n+2}}}});
    for overlong in [false, true] {
        let mut data=[raw(&json!({"type":"session_meta","timestamp":"2026-10-07T10:00:00Z","payload":{"id":id,"cwd":root.0,"timestamp":"2026-10-07T10:00:00Z","context_window":200000}})),b"\n".to_vec(),raw(&usage(100)),b"\n".to_vec()].concat();
        if overlong {
            data.extend(format!("{{\"timestamp\":\"2026-10-07T10:00:01Z\",\"ordinal\":2,\"type\":\"response_item\",\"payload\":\"{}\"}}\n","x".repeat(MAX_JSONL_LINE_BYTES+1)).as_bytes());
        }
        data.extend(raw(&usage(140)));
        data.push(b'\n');
        fs::write(&path, data).unwrap();
        let page = |observer: bool| {
            let feed = Arc::new(crate::codex_prelude_footprint::CodexPreludeFeed::default());
            let cache = Arc::new(sampled_scan::SharedCache::default());
            let result = capture(|| {
                let scan = OwnedSourceScan::new(
                    SnapshotSource::Codex,
                    std::slice::from_ref(&sessions),
                    ScanIndex::default(),
                    NOW,
                    BACKFILL_WINDOW_DAYS,
                    10,
                    false,
                    None,
                    &[],
                    false,
                )
                .with_sampled_acquisition(
                    cache,
                    crate::transcript_acquisition::Scope("prelude-money".into()),
                );
                let scan = if observer {
                    scan.with_line_observer(
                        "codex_prelude",
                        feed.observer(std::slice::from_ref(&sessions)),
                    )
                } else {
                    scan
                };
                finish(scan)
            });
            (result, feed.metrics())
        };
        let (((bare_index, bare, bare_steps), bare_counts), _) = page(false);
        let (((seen_index, seen, seen_steps), seen_counts), metrics) = page(true);
        assert!(metrics.split_whitespace().any(|m| m == "feed_files=1"));
        assert!(metrics.split_whitespace().any(|m| m == "root_missing=0"));
        assert!(
            page_counts(&seen_counts)["line_delivery"]["codex_prelude"]["lines"]
                .as_u64()
                .unwrap_or(0)
                > 0
        );
        assert_eq!(bare_steps, seen_steps);
        assert!(!bare.snapshots.is_empty());
        assert_eq!(
            serde_json::to_vec(&bare.snapshots).unwrap(),
            serde_json::to_vec(&seen.snapshots).unwrap(),
            "token totals and emitted bodies"
        );
        assert_eq!(
            serde_json::to_value(&bare_index.files).unwrap(),
            serde_json::to_value(&seen_index.files).unwrap(),
            "TierReplay receipts and ownership checkpoints"
        );
        assert_eq!(
            serde_json::to_value(&bare_index.codex_parent_prefix_proofs).unwrap(),
            serde_json::to_value(&seen_index.codex_parent_prefix_proofs).unwrap(),
            "fresh-session proof maps may both be empty; inherited proof is not covered"
        );
        assert!(
            bare_index
                .files
                .values()
                .any(|e| e.codex_captured_tier_receipt.is_some()
                    || e.codex_applied_tier_receipt.is_some()),
            "nonempty TierReplay evidence"
        );
        assert_eq!(bare.over_line_cap_count, usize::from(overlong));
        let a = page_counts(&bare_counts);
        let b = page_counts(&seen_counts);
        for key in [
            "completed_native_bytes",
            "completed_guard_bytes",
            "full_selections",
            "tail_selections",
            "unchanged_selections",
        ] {
            assert_eq!(
                a["sampled_acquisition"][key], b["sampled_acquisition"][key],
                "equal tracked acquisition work, not interception of every open: {key}"
            );
        }
    }
}

#[test]
fn codex_scan_destruction_counts_nonterminal_prelude_gap() {
    let root = Root::new("prelude-drop");
    let sessions = root.0.join("sessions");
    fs::create_dir(&sessions).unwrap();
    let id = "019fa111-2222-7333-8444-555555555555";
    let path = sessions.join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
    append(
        &path,
        &[
            raw(&json!({"type":"session_meta","payload":{"id":id}})),
            b"\n".to_vec(),
            raw(&json!({"type":"token_usage_record","payload":{"usage":{"input_tokens":9}}})),
            b"\n".to_vec(),
        ]
        .concat(),
    );
    let feed = Arc::new(crate::codex_prelude_footprint::CodexPreludeFeed::default());
    let scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&sessions),
        ScanIndex::default(),
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
    )
    .with_line_observer(
        "codex_prelude",
        feed.observer(std::slice::from_ref(&sessions)),
    );
    let scan = step_until(scan, |s| {
        s.active_file
            .as_ref()
            .is_some_and(|a| a.parser.reader.consumed_bytes() > 0)
    });
    drop(scan);
    // The terminal parser row was beyond the interrupted page. A resumed
    // suffix is deliberately unarmed before LD2 and cannot repair this prefix.
    assert_eq!(metric(&feed, "codex_prelude_gap_dropped"), 1);
    assert_eq!(metric(&feed, "pending"), 0);
}

#[test]
fn codex_cursor_yield_drops_prefix_before_late_token_record() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = Root::new("prelude-cursor");
    let sessions = root.0.join("sessions");
    fs::create_dir(&sessions).unwrap();
    let id = "019fa111-2222-7333-8444-555555555555";
    let path = sessions.join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
    append(&path,&[raw(&json!({"type":"session_meta","timestamp":"2026-10-07T10:00:00Z","payload":{"id":id,"cwd":root.0,"context_window":200000}})),b"\n".to_vec()].concat());
    for _ in 0..60 {
        append(
            &path,
            &[raw(&json!({"padding":"x".repeat(100)})), b"\n".to_vec()].concat(),
        );
    }
    append(&path,&[raw(&json!({"type":"event_msg","timestamp":"2026-10-07T10:00:01Z","payload":{"type":"token_count","info":{"model":"gpt-5","last_token_usage":{"input_tokens":100,"output_tokens":2},"total_token_usage":{"input_tokens":100,"output_tokens":2}}}})),b"\n".to_vec()].concat());
    let feed = Arc::new(crate::codex_prelude_footprint::CodexPreludeFeed::default());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    sampled_scan::codex_cursor::with_test_limits(2048, 1024, 64, || {
        let mut index = ScanIndex::default();
        let mut completion_page = None;
        for page in 0..16 {
            let scan = OwnedSourceScan::new(
                SnapshotSource::Codex,
                std::slice::from_ref(&sessions),
                index,
                NOW,
                BACKFILL_WINDOW_DAYS,
                10,
                false,
                None,
                &[],
                false,
            )
            .with_sampled_acquisition(
                Arc::clone(&cache),
                crate::transcript_acquisition::Scope("prelude-cursor".into()),
            )
            .with_line_observer(
                "codex_prelude",
                feed.observer(std::slice::from_ref(&sessions)),
            );
            let (next, result, _) = finish(scan);
            index = next;
            assert_eq!(metric(&feed, "pending"), 0);
            assert_eq!(metric(&feed, "codex_prelude_gap_dropped"), 1);
            if !result.snapshots.is_empty() {
                completion_page = Some(page);
                break;
            }
        }
        let page = completion_page.expect("cursor never completed");
        assert!(page > 0);
    });
}

/// A feed restart with the same warm RAM acquisition cache; no process restart
/// or disk restore is exercised.
#[test]
fn codex_warm_acquisition_after_feed_restart_is_unseen_not_a_new_prelude() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = Root::new("prelude-warm-restart");
    let sessions = root.0.join("sessions");
    fs::create_dir(&sessions).unwrap();
    let id = "019fa111-2222-7333-8444-555555555555";
    let path = sessions.join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
    let token = |n| json!({"type":"event_msg","timestamp":"2026-10-07T10:00:01Z","payload":{"type":"token_count","info":{"model":"gpt-5","model_context_window":200000,"last_token_usage":{"input_tokens":n,"output_tokens":2},"total_token_usage":{"input_tokens":n,"output_tokens":2}}}});
    append(
        &path,
        &[
            raw(&json!({"type":"session_meta","payload":{"id":id,"cwd":root.0}})),
            b"\n".to_vec(),
            raw(&token(100)),
            b"\n".to_vec(),
        ]
        .concat(),
    );
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let page = |index, feed: &Arc<crate::codex_prelude_footprint::CodexPreludeFeed>| {
        let scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            std::slice::from_ref(&sessions),
            index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
        )
        .with_sampled_acquisition(
            Arc::clone(&cache),
            crate::transcript_acquisition::Scope("prelude-restart".into()),
        )
        .with_line_observer(
            "codex_prelude",
            feed.observer(std::slice::from_ref(&sessions)),
        );
        finish(scan).0
    };
    let feed = Arc::new(crate::codex_prelude_footprint::CodexPreludeFeed::default());
    let index = page(ScanIndex::default(), &feed);
    append(&path, &[raw(&token(140)), b"\n".to_vec()].concat());
    let restarted = Arc::new(crate::codex_prelude_footprint::CodexPreludeFeed::default());
    let index = page(index, &restarted);
    page(index, &restarted);
    assert_eq!(metric(&restarted, "codex_prelude_unseen_prefix"), 1);
    assert_eq!(metric(&restarted, "pending"), 0);
    assert_eq!(Recorder::default().declared_heap_bytes(), 64 * 1024);
    assert_eq!(
        feed.observer(std::slice::from_ref(&sessions))
            .declared_heap_bytes(),
        256 * 1024
    );
}

#[cfg(unix)]
#[test]
fn codex_symlinked_root_leaf_resolves_home_and_delivers_lines() {
    let root = Root::new("prelude-symlink-root");
    let home = root.0.join("home");
    let real = root.0.join("relocated");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&real).unwrap();
    let sessions = home.join("sessions");
    std::os::unix::fs::symlink(&real, &sessions).unwrap();
    let id = "019fa111-2222-7333-8444-555555555555";
    let path = real.join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
    let data = [raw(&json!({"type":"session_meta","timestamp":"2026-10-07T10:00:00Z","payload":{"id":id,"cwd":home,"context_window":200000}})), b"\n".to_vec(), raw(&json!({"type":"event_msg","timestamp":"2026-10-07T10:00:01Z","payload":{"type":"token_count","info":{"model":"gpt-5","model_context_window":200000,"last_token_usage":{"input_tokens":100,"output_tokens":2},"total_token_usage":{"input_tokens":100,"output_tokens":2}}}})), b"\n".to_vec()].concat();
    fs::write(path, data).unwrap();
    let feed = Arc::new(crate::codex_prelude_footprint::CodexPreludeFeed::default());
    let scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&sessions),
        ScanIndex::default(),
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
    )
    .with_line_observer(
        "codex_prelude",
        feed.observer(std::slice::from_ref(&sessions)),
    );
    let (_, counts) = capture(|| finish(scan));
    assert!(feed
        .metrics()
        .split_whitespace()
        .any(|m| m == "feed_files=1"));
    assert!(feed
        .metrics()
        .split_whitespace()
        .any(|m| m == "root_missing=0"));
    assert!(
        page_counts(&counts)["line_delivery"]["codex_prelude"]["lines"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
}

/// Drive the physical reader into the live production observer. The second
/// fixture reader starts at the last complete newline after an actual append;
/// this checks delivery, not acquisition's sealed-fragment restart policy.
#[test]
fn codex_live_observer_waits_for_the_physical_newline_then_observes_once() {
    use std::io::{Seek, SeekFrom};
    let root = Root::new("prelude-live-newline");
    let path = root.file("fixture");
    let meta = raw(
        &json!({"type":"session_meta","payload":{"id":"live","cwd":root.0,"context_window":200000}}),
    );
    let usage = raw(&json!({"type":"token_usage_record","payload":{"usage":{"input_tokens":17}}}));
    fs::write(
        &path,
        [meta.clone(), b"\n".to_vec(), usage.clone()].concat(),
    )
    .unwrap();
    let (object, held) = FileObject::of(&fs::File::open(&path).unwrap()).unwrap();
    let view = FileView {
        source: SnapshotSource::Codex,
        object,
        mtime: held.modified().ok(),
        mode: DeliveryMode::Full,
        root: Some(0),
        start: 0,
    };
    let roots = [root.projects()];
    let feed = Arc::new(crate::codex_prelude_footprint::CodexPreludeFeed::default());
    let mut observer = feed.observer(&roots);
    assert_eq!(observer.begin(&view), Want::Lines);
    let mut reader = BoundedJsonlReader::new(
        std::io::BufReader::new(fs::File::open(&path).unwrap()),
        1024,
        false,
    );
    let mut delivered = Vec::new();
    loop {
        let step = reader
            .step_lines(
                |_| {},
                Some(&mut |_, line: &PhysicalLine<'_>| {
                    delivered.push((line.end, line.value.cloned()));
                    observer.line(&view, line);
                }),
            )
            .unwrap();
        if matches!(step, JsonlReaderStep::Complete(_)) {
            break;
        }
    }
    observer.end(&view, &DeliveryEnd::Complete);
    let complete_end = meta.len() as u64 + 1;
    assert_eq!(
        delivered,
        vec![(complete_end, Some(serde_json::from_slice(&meta).unwrap()))]
    );
    assert!(feed.done_for_test().is_empty());
    assert_eq!(metric(&feed, "pending"), 1);
    append(&path, b"\n");
    let mut file = fs::File::open(&path).unwrap();
    file.seek(SeekFrom::Start(complete_end)).unwrap();
    let tail = FileView {
        mode: DeliveryMode::Tail,
        start: complete_end,
        ..view
    };
    let mut observer = feed.observer(&roots);
    assert_eq!(observer.begin(&tail), Want::Lines);
    let mut reader = BoundedJsonlReader::new(std::io::BufReader::new(file), 1024, false);
    let mut appended = Vec::new();
    loop {
        let step = reader
            .step_lines(
                |_| {},
                Some(&mut |_, line: &PhysicalLine<'_>| {
                    // An unplanned test reader starts at zero; LD adds ReadPlan.start
                    // in production. Supply that same absolute origin for this Tail.
                    let line = PhysicalLine {
                        end: complete_end + line.end,
                        ..*line
                    };
                    appended.push(line.value.cloned());
                    observer.line(&tail, &line);
                }),
            )
            .unwrap();
        if matches!(step, JsonlReaderStep::Complete(_)) {
            break;
        }
    }
    observer.end(&tail, &DeliveryEnd::Complete);
    assert_eq!(
        appended,
        vec![Some(serde_json::from_slice(&usage).unwrap())]
    );
    let done = feed.done_for_test();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].1.first_input_tokens, Some(17));
    assert_eq!(metric(&feed, "pending"), 0);
    assert_eq!(metric(&feed, "codex_prelude_gap_dropped"), 0);
    let mut observer = feed.observer(&roots);
    assert_eq!(
        observer.begin(&FileView {
            start: fs::metadata(&path).unwrap().len(),
            ..tail
        }),
        Want::Skip
    );
    observer.end(&tail, &DeliveryEnd::Complete);
    assert_eq!(feed.done_for_test().len(), 1);
}

#[test]
fn codex_live_observer_skips_an_actual_overlong_row_before_terminal_usage() {
    let root = Root::new("prelude-live-overlong");
    let path = root.file("fixture");
    let meta = raw(
        &json!({"type":"session_meta","payload":{"id":"live","cwd":root.0,"context_window":200000}}),
    );
    let oversized = raw(
        &json!({"type":"token_usage_record","padding":"x".repeat(4096),"payload":{"usage":{"input_tokens":777}}}),
    );
    let usage = raw(&json!({"type":"token_usage_record","payload":{"usage":{"input_tokens":19}}}));
    fs::write(
        &path,
        [
            meta,
            b"\n".to_vec(),
            oversized,
            b"\n".to_vec(),
            usage,
            b"\n".to_vec(),
        ]
        .concat(),
    )
    .unwrap();
    let (object, held) = FileObject::of(&fs::File::open(&path).unwrap()).unwrap();
    let view = FileView {
        source: SnapshotSource::Codex,
        object,
        mtime: held.modified().ok(),
        mode: DeliveryMode::Full,
        root: Some(0),
        start: 0,
    };
    let feed = Arc::new(crate::codex_prelude_footprint::CodexPreludeFeed::default());
    let mut observer = feed.observer(&[root.projects()]);
    assert_eq!(observer.begin(&view), Want::Lines);
    let mut reader = BoundedJsonlReader::new(
        std::io::BufReader::with_capacity(64, fs::File::open(&path).unwrap()),
        1024,
        true,
    );
    reader.set_chunked_skip(64);
    let mut delivered = Vec::new();
    let report = loop {
        let step = reader
            .step_lines(
                |_| {},
                Some(&mut |_, line: &PhysicalLine<'_>| {
                    delivered.push((line.end, line.value.cloned()));
                    observer.line(&view, line);
                }),
            )
            .unwrap();
        if let JsonlReaderStep::Complete(report) = step {
            break report;
        }
    };
    observer.end(&view, &DeliveryEnd::Complete);
    assert_eq!(report.over_line_cap_count, 1);
    assert_eq!(delivered.len(), 3);
    assert_eq!(delivered[0].1.as_ref().unwrap()["type"], "session_meta");
    assert_eq!(delivered[1].1, None);
    assert_eq!(
        delivered[2].1.as_ref().unwrap()["payload"]["usage"]["input_tokens"],
        19
    );
    assert_eq!(delivered[2].0, fs::metadata(&path).unwrap().len());
    let done = feed.done_for_test();
    assert_eq!(done.len(), 1);
    assert_eq!(
        done[0].1.first_input_tokens,
        Some(19),
        "777 must not terminate the live observer"
    );
    assert_eq!(metric(&feed, "codex_prelude_gap_dropped"), 0);
}

/// [behaviour] Real Completed account settlement carries Tail audit debt onto the committed
/// subset. Only positively proven deletion may retire both obligations.
#[test]
fn completed_withheld_sampled_deletion_releases_debt_with_and_without_hint() {
    use crate::local_resource_diagnostics::withheld_support::take_withheld;
    for hinted in [false, true] {
        let root = Root::new(if hinted {
            "ld-deleted-hint"
        } else {
            "ld-deleted-census"
        });
        let path = root.file(SESSION);
        let key = local_index_key(&path);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let page = |index: ScanIndex, hints: &[PathBuf], at: &str| {
            let recorder = Recorder::default();
            let ((index, scan, _), counts) = capture(|| {
                finish(
                    OwnedSourceScan::new(
                        SnapshotSource::ClaudeCode,
                        &[root.projects()],
                        index,
                        at,
                        7,
                        10,
                        false,
                        None,
                        hints,
                        false,
                    )
                    .with_sampled_acquisition(
                        cache.clone(),
                        crate::transcript_acquisition::Scope("deleted-held".into()),
                    )
                    .with_line_observer("test", Box::new(recorder.clone())),
                )
            });
            (index, scan, recorder, page_counts(&counts))
        };
        append(&path, &assistant_line("u1"));
        let (previous, _, _, _) = page(ScanIndex::default(), &[], &days_from_now(0));
        append(&path, &assistant_line("u2"));
        let (mut parsed, scan, recorder, _) = page(previous.clone(), &[], &days_from_now(0));
        let modes: Vec<_> = recorder
            .events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Begin(v) => Some(v.mode),
                _ => None,
            })
            .collect();
        assert_eq!(modes, vec![held_growth_mode()]);
        // `finish` normally simulates accepted upload for reader tests. This
        // page instead enters account classification BEFORE upload, so only
        // the baseline's real ACKs exist at this production seam.
        parsed.accepted_snapshot_fingerprints = previous.accepted_snapshot_fingerprints.clone();
        let mut held =
            crate::snapshot_sync::withheld_support::settle_withheld(&previous, parsed, scan);
        assert_eq!(
            held.accepted_snapshot_fingerprints, previous.accepted_snapshot_fingerprints,
            "account-held acquisition grants no ACK"
        );
        assert!(held.claude_account_deferred_holds.contains_key(&key));
        // Linux refuses the native cache layout; still exercise the same audit
        // obligation in CI without pretending it performed a Tail there.
        if !held.files[&key].has_unverified_source() {
            let fp = held.files[&key].source_file_fingerprint.clone();
            assert!(held.stage_sampled_audit(
                &key,
                &fp,
                crate::transcript_acquisition::AuditDebt {
                    due_unix_seconds: 1
                }
            ));
        }
        assert!(!crate::snapshot_sync::withheld_support::withheld_settled(
            &held
        ));
        let known_tokens = serde_json::to_value(held.withheld_memo.held_gauge().unwrap()).unwrap()
            ["withheld_held_tokens"]
            .as_u64()
            .unwrap();
        assert!(known_tokens > 0);
        let incidence = held.file_snapshot_fingerprints[&key].clone();
        let acknowledgements = held.accepted_snapshot_fingerprints.clone();
        take_withheld();
        fs::remove_file(&path).unwrap();
        let hints = if hinted {
            vec![path.clone()]
        } else {
            Vec::new()
        };
        sampled_scan::set_test_now(Some(1_000));
        let (first, scan, recorder, _) = page(held, &hints, &days_from_now(0));
        assert!(first.claude_account_deferred_holds.contains_key(&key));
        assert!(first.files[&key].has_unverified_source());
        assert!(recorder.events().is_empty());
        assert_eq!(scan.scanned_file_count, 0);
        sampled_scan::set_test_now(Some(1_600));
        let deletion_baseline = first.clone();
        let (removed, scan, recorder, counts) = page(first, &hints, &days_from_now(1));
        sampled_scan::set_test_now(None);
        let removed = crate::snapshot_sync::withheld_support::settle_withheld(
            &deletion_baseline,
            removed,
            scan.clone(),
        );
        assert!(
            recorder.events().is_empty(),
            "removal never acquires a transcript"
        );
        assert_eq!(scan.scanned_file_count, 0);
        if !hinted {
            assert!(
                scan.census_complete,
                "NO-HINT removal uses a healthy completed census"
            );
            assert_eq!(scan.disappeared_file_count, 0);
            assert_eq!(scan.symlink_rejected_count, 0);
            assert_eq!(scan.unreadable_path_count, 0);
        }
        assert!(!removed.files.contains_key(&key));
        assert!(!removed.claude_account_deferred_holds.contains_key(&key));
        assert!(crate::snapshot_sync::withheld_support::withheld_settled(
            &removed
        ));
        // SOURCE N3 applies equally to the NO-HINT healthy-census path:
        // removal discharges only the now-unfulfillable debt, never incidence
        // custody or an entity ACK. Completed settlement remains unblocked.
        assert_eq!(
            removed.file_snapshot_fingerprints.get(&key),
            Some(&incidence)
        );
        assert_eq!(removed.accepted_snapshot_fingerprints, acknowledgements);
        assert_eq!(counts["withheld_hold_released"]["deleted"], 1);
        assert_eq!(
            counts["withheld_hold_released"]["deleted_tokens"],
            known_tokens
        );
        assert_eq!(counts["audit_retired_absent"]["events"], 1);
        assert!(
            removed.withheld_memo.held_gauge().is_none(),
            "no gauge membership remains"
        );
        append(&path, &assistant_line("new-object"));
        let (_, scan, recorder, _) = page(removed, &[], &days_from_now(1));
        assert_eq!(scan.scanned_file_count, 1, "recreation is A1 FirstRead");
        assert!(recorder
            .events()
            .iter()
            .any(|e| matches!(e, Event::Begin(v) if v.mode == DeliveryMode::Full)));
    }
}
/// [behaviour] Withheld missing parent keeps account and audit debt.

#[test]
fn withheld_missing_parent_keeps_account_and_audit_debt() {
    let root = Root::new("ld-missing-parent-held");
    let parent = root.projects().join("missing");
    fs::create_dir(&parent).unwrap();
    let path = parent.join(format!("{SESSION}.jsonl"));
    let key = local_index_key(&path);
    append(&path, &assistant_line("u1"));
    let (previous, _, _) = finish(new_scan(&root.projects(), ScanIndex::default()));
    append(&path, &assistant_line("u2"));
    let (parsed, scan, _) = finish(new_scan(&root.projects(), previous.clone()));
    let mut held = crate::snapshot_sync::withheld_support::settle_withheld(&previous, parsed, scan);
    let fp = held.files[&key].source_file_fingerprint.clone();
    assert!(held.stage_sampled_audit(
        &key,
        &fp,
        crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: 1
        }
    ));
    // A missing configured root is uncertain; a missing project beneath a
    // readable configured root is now positive absence.
    fs::remove_dir_all(root.projects()).unwrap();
    assert!(!sampled_audit::proven_absent(&path, &[root.projects()]));
    let (kept, _, _) = finish(new_scan(&root.projects(), held));
    assert!(kept.files[&key].has_unverified_source());
    assert!(kept.claude_account_deferred_holds.contains_key(&key));
    assert!(!crate::snapshot_sync::withheld_support::withheld_settled(
        &kept
    ));
}

/// [behaviour] Deleting a project beneath a readable root retires both indexed debts,
/// through either a remove hint or the existing bounded reconciliation page.
#[test]
fn withheld_removed_project_releases_account_and_audit_debt() {
    for hinted in [false, true] {
        let root = Root::new("ld-removed-project-held");
        let project = root.projects().join("project");
        // A normal Claude root session under projects/<p>. An arbitrary
        // session/subagents/<uuid> path is not a valid subagent identity.
        let parent = project.clone();
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join(format!("{SESSION}.jsonl"));
        let key = local_index_key(&path);
        append(&path, &assistant_line("u1"));
        let (previous, initial, _) = finish(new_scan(&root.projects(), ScanIndex::default()));
        assert_eq!(initial.scanned_file_count, 1);
        assert!(previous.files.contains_key(&key));
        append(&path, &assistant_line("u2"));
        let (mut parsed, scan, _) = finish(new_scan(&root.projects(), previous.clone()));
        assert_eq!(scan.scanned_file_count, 1);
        assert!(
            !scan.snapshots.is_empty(),
            "growth produces an account-held body"
        );
        // `finish` normally simulates accepted upload for reader tests. This
        // page instead enters account classification BEFORE upload, so only
        // the baseline's real ACKs exist at this production seam.
        parsed.accepted_snapshot_fingerprints = previous.accepted_snapshot_fingerprints.clone();
        let mut held =
            crate::snapshot_sync::withheld_support::settle_withheld(&previous, parsed, scan);
        assert_eq!(
            held.accepted_snapshot_fingerprints, previous.accepted_snapshot_fingerprints,
            "account-held acquisition grants no ACK"
        );
        assert!(held.claude_account_deferred_holds.contains_key(&key));
        let fp = held.files[&key].source_file_fingerprint.clone();
        assert!(held.stage_sampled_audit(
            &key,
            &fp,
            crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: 1
            }
        ));
        let incidence = held.file_snapshot_fingerprints[&key].clone();
        let acknowledgements = held.accepted_snapshot_fingerprints.clone();
        let known_tokens = serde_json::to_value(held.withheld_memo.held_gauge().unwrap()).unwrap()
            ["withheld_held_tokens"]
            .as_u64()
            .unwrap();
        assert!(known_tokens > 0);
        fs::remove_dir_all(&project).unwrap();
        assert!(sampled_audit::proven_absent(&path, &[root.projects()]));
        let hints = if hinted { vec![path.clone()] } else { vec![] };
        sampled_scan::set_test_now(Some(1_000));
        let recorder = Recorder::default();
        let (held, first, _) = finish(
            new_scan(&root.projects(), held).with_line_observer("test", Box::new(recorder.clone())),
        );
        assert!(held.claude_account_deferred_holds.contains_key(&key));
        assert!(held.files[&key].has_unverified_source());
        assert!(recorder.events().is_empty());
        assert_eq!(first.scanned_file_count, 0);
        sampled_scan::set_test_now(Some(1_600));
        let recorder = Recorder::default();
        let baseline = held.clone();
        let ((after, scan, _), counts) = capture(|| {
            finish(
                OwnedSourceScan::new(
                    SnapshotSource::ClaudeCode,
                    &[root.projects()],
                    held,
                    "2026-10-07T12:10:00Z",
                    BACKFILL_WINDOW_DAYS,
                    10,
                    false,
                    None,
                    &hints,
                    false,
                )
                .with_line_observer("test", Box::new(recorder.clone())),
            )
        });
        sampled_scan::set_test_now(None);
        assert!(recorder.events().is_empty(), "absence never acquires bytes");
        assert_eq!(scan.scanned_file_count, 0);
        if !hinted {
            assert!(scan.census_complete);
        }
        let after = crate::snapshot_sync::withheld_support::settle_withheld(&baseline, after, scan);
        assert!(!after.files.contains_key(&key));
        assert!(!after.claude_account_deferred_holds.contains_key(&key));
        assert!(crate::snapshot_sync::withheld_support::withheld_settled(
            &after
        ));
        assert_eq!(after.file_snapshot_fingerprints.get(&key), Some(&incidence));
        assert_eq!(after.accepted_snapshot_fingerprints, acknowledgements);
        assert!(after.withheld_memo.held_gauge().is_none());
        let counts = page_counts(&counts);
        assert_eq!(counts["withheld_hold_released"]["deleted"], 1);
        assert_eq!(
            counts["withheld_hold_released"]["deleted_tokens"],
            known_tokens
        );
        assert_eq!(counts["audit_retired_absent"]["events"], 1);
        fs::create_dir_all(&parent).unwrap();
        append(&path, &assistant_line("new-object"));
        let recorder = Recorder::default();
        let (_, scan, _) = finish(
            new_scan(&root.projects(), after)
                .with_line_observer("test", Box::new(recorder.clone())),
        );
        assert_eq!(scan.scanned_file_count, 1, "recreation is A1 FirstRead");
        assert!(recorder
            .events()
            .iter()
            .any(|event| matches!(event, Event::Begin(view) if view.mode == DeliveryMode::Full)));
    }
}

/// [behaviour] Exercise the real rotation admission/discard protocol over multiple cycles.
/// An opaque sibling graph (as on unsupported Linux layouts) must not discard
/// this portable, already charged memo. An actual exhausted budget discloses
/// unavailable details and the durable held population instead of hiding it.
#[test]
fn withheld_memo_survives_owner_cycles_and_discloses_budget_refusal() {
    use crate::source_rotation::{Owner, Step};
    struct Cycle {
        index: ScanIndex,
        root: PathBuf,
        cache: Arc<sampled_scan::SharedCache>,
        rows: Vec<Value>,
        reads: usize,
    }
    impl Owner for Cycle {
        type Source = ();
        type Frame = ();
        type Completed = ();
        fn prepare(&mut self, _: (), _: Option<usize>) -> Result<Option<()>> {
            Ok(Some(()))
        }
        fn validate(&mut self, _: &()) -> Result<()> {
            Ok(())
        }
        fn step(&mut self, _: (), _: Option<usize>) -> Step<(), ()> {
            let recorder = Recorder::default();
            let mut index = self.index.clone();
            self.cache.bind_withheld(&mut index);
            let ((index, _, _), counts) = capture(|| {
                finish(
                    OwnedSourceScan::new(
                        SnapshotSource::ClaudeCode,
                        std::slice::from_ref(&self.root),
                        index,
                        &days_from_now(0),
                        7,
                        10,
                        false,
                        None,
                        &[],
                        false,
                    )
                    .with_sampled_acquisition(
                        self.cache.clone(),
                        crate::transcript_acquisition::Scope("owner-held".into()),
                    )
                    .with_line_observer("test", Box::new(recorder.clone())),
                )
            });
            self.index = index;
            self.reads += recorder
                .events()
                .iter()
                .filter(|e| matches!(e, Event::Begin(_)))
                .count();
            self.rows.push(page_counts(&counts));
            Step::Complete(())
        }
        fn finish(&mut self, _: (), _: Option<usize>) -> Result<()> {
            Ok(())
        }
        fn outcome(&mut self, _: (), result: Result<()>) {
            result.unwrap();
        }
        fn monotonic(&self) -> std::time::Duration {
            std::time::Duration::ZERO
        }
        fn retained_bound(&self, limit: usize) -> Option<usize> {
            crate::snapshot_sync::retained_with_withheld(&self.index.withheld_memo, limit, |_| None)
        }
        fn discard_retained(&mut self) {
            self.index.withheld_memo.discard_if_refused();
        }
        fn retained_budget_unavailable(&mut self) {
            self.index.withheld_memo.discard_retained();
            self.discard_retained();
        }
    }
    let root = Root::new("ld-held-owner");
    let path = root.file(SESSION);
    append(&path, &assistant_line("u1"));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut previous = ScanIndex::default();
    cache.bind_withheld(&mut previous);
    let (parsed, result, _) = finish(
        OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            &[root.projects()],
            previous.clone(),
            &days_from_now(0),
            7,
            10,
            false,
            None,
            &[],
            false,
        )
        .with_sampled_acquisition(
            cache.clone(),
            crate::transcript_acquisition::Scope("owner-held".into()),
        ),
    );
    let held = crate::snapshot_sync::withheld_support::settle_withheld(&previous, parsed, result);
    let mut owner = Cycle {
        index: held,
        root: root.projects(),
        cache,
        rows: Vec::new(),
        reads: 0,
    };
    for day in [1, 31, 91] {
        sampled_scan::set_test_now(Some(
            sampled_scan::now_seconds().saturating_add(day * 86_400),
        ));
        crate::source_rotation::run(&mut owner, &[()], crate::source_rotation::PARKED_BUDGET);
        let row = owner.rows.last().unwrap();
        assert_eq!(row["withheld_held_count"], 1);
        assert_eq!(row["withheld_memo_unavailable"], false);
        assert_eq!(row["withheld_held_tokens"], 30);
    }
    assert_eq!(
        owner.reads, 0,
        "unrelated layout refusal must not rearm idle held files"
    );
    assert_eq!(owner.rows.last().unwrap()["withheld_held_age"]["gt_90d"], 1);
    crate::source_rotation::run(&mut owner, &[()], 0);
    let row = owner.rows.last().unwrap();
    assert_eq!(row["withheld_held_count"], 1);
    assert_eq!(row["withheld_memo_unavailable"], true);
    assert!(
        row.get("withheld_held_tokens").is_none(),
        "refused details are unknown, never fabricated zero"
    );
    sampled_scan::set_test_now(None);
}

/// [format] Hold-only checkpoints must use the same positive proof as indexed holds.
/// A missing project beneath a readable root is positive absence; a missing
/// configured root remains uncertain even after checkpoint reload.
#[test]
fn withheld_new_completed_checkpoint_requires_positive_absence() {
    for removed in ["root", "project", "file"] {
        let missing_root = removed == "root";
        let root = Root::new("ld-held-new-absence");
        let parent = root.projects().join("project");
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join(format!("{SESSION}.jsonl"));
        let key = local_index_key(&path);
        append(&path, &assistant_line("held-new"));
        let previous = ScanIndex::default();
        let (parsed, scan, _) = finish(new_scan(&root.projects(), previous.clone()));
        let mut held =
            crate::snapshot_sync::withheld_support::settle_withheld(&previous, parsed, scan);
        assert!(!held.files.contains_key(&key));
        assert!(held.claude_account_deferred_holds.contains_key(&key));
        let checkpoint = root.0.join("hold-only.json");
        held.save(&checkpoint).unwrap();
        let held = ScanIndex::load(&checkpoint).unwrap();
        fs::remove_file(&path).unwrap();
        if removed == "project" {
            fs::remove_dir(&parent).unwrap();
        } else if missing_root {
            fs::remove_dir_all(root.projects()).unwrap();
        }
        sampled_scan::set_test_now(Some(1_000));
        let (held, first, _) = finish(new_scan(&root.projects(), held));
        assert!(held.claude_account_deferred_holds.contains_key(&key));
        assert_eq!(first.scanned_file_count, 0);
        sampled_scan::set_test_now(Some(1_600));
        let recorder = Recorder::default();
        let ((after, _, _), counts) = capture(|| {
            finish(
                OwnedSourceScan::new(
                    SnapshotSource::ClaudeCode,
                    &[root.projects()],
                    held,
                    "2026-10-07T12:10:00Z",
                    BACKFILL_WINDOW_DAYS,
                    10,
                    false,
                    None,
                    &[],
                    false,
                )
                .with_line_observer("test", Box::new(recorder.clone())),
            )
        });
        sampled_scan::set_test_now(None);
        assert!(recorder.events().is_empty(), "absence never parses");
        assert_eq!(
            after.claude_account_deferred_holds.contains_key(&key),
            missing_root
        );
        assert_eq!(
            crate::snapshot_sync::withheld_support::withheld_settled(&after),
            !missing_root
        );
        let counts = page_counts(&counts);
        assert_eq!(
            counts["withheld_hold_released"]["deleted"]
                .as_u64()
                .unwrap_or(0),
            u64::from(!missing_root)
        );
        assert_eq!(
            counts["audit_retired_absent"]["events"]
                .as_u64()
                .unwrap_or(0),
            0
        );
    }
}

/// [behaviour] A remove hint is not authority to follow an intermediate symlink into a
/// different tree and call its ENOENT a deletion of the original owed object.
#[cfg(unix)]
#[test]
fn withheld_remove_hint_through_intermediate_symlink_keeps_both_debts() {
    let root = Root::new("ld-held-symlink-ancestor");
    let project = root.projects().join("project");
    let parent = project.join("nested");
    fs::create_dir_all(&parent).unwrap();
    let path = parent.join(format!("{SESSION}.jsonl"));
    let key = local_index_key(&path);
    append(&path, &assistant_line("u1"));
    let (previous, _, _) = finish(new_scan(&root.projects(), ScanIndex::default()));
    append(&path, &assistant_line("u2"));
    let (parsed, scan, _) = finish(new_scan(&root.projects(), previous.clone()));
    let mut held = crate::snapshot_sync::withheld_support::settle_withheld(&previous, parsed, scan);
    let fp = held.files[&key].source_file_fingerprint.clone();
    assert!(held.stage_sampled_audit(
        &key,
        &fp,
        crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: 1
        }
    ));
    let incidence = held.file_snapshot_fingerprints[&key].clone();
    let moved = root.0.join("original");
    fs::rename(&project, &moved).unwrap();
    let replacement = root.0.join("replacement");
    fs::create_dir_all(replacement.join("nested")).unwrap();
    std::os::unix::fs::symlink(&replacement, &project).unwrap();
    assert!(moved
        .join("nested")
        .join(path.file_name().unwrap())
        .exists());
    let recorder = Recorder::default();
    let ((after, _, _), counts) = capture(|| {
        finish(
            OwnedSourceScan::new(
                SnapshotSource::ClaudeCode,
                &[root.projects()],
                held,
                NOW,
                7,
                10,
                false,
                None,
                std::slice::from_ref(&path),
                false,
            )
            .with_line_observer("test", Box::new(recorder.clone())),
        )
    });
    assert!(recorder.events().is_empty());
    assert!(after.files[&key].has_unverified_source());
    assert!(after.claude_account_deferred_holds.contains_key(&key));
    assert_eq!(after.file_snapshot_fingerprints.get(&key), Some(&incidence));
    assert!(!crate::snapshot_sync::withheld_support::withheld_settled(
        &after
    ));
    let counts = page_counts(&counts);
    assert_eq!(
        counts["withheld_hold_released"]["deleted"]
            .as_u64()
            .unwrap_or(0),
        0
    );
    assert_eq!(
        counts["audit_retired_absent"]["events"]
            .as_u64()
            .unwrap_or(0),
        0
    );
}

/// Build the same opened-object/sidecar CONTENT witness used by the real
/// scan, so selector controls do not accidentally invalidate every memo.
fn withheld_recovery_candidate(root: &Root, path: &Path, index: &ScanIndex) -> CandidateFile {
    let entry = &index.files[&local_index_key(path)];
    let mut candidate = CandidateFile {
        path: path.to_path_buf(),
        scan_root: root.projects(),
        size_bytes: entry.size_bytes,
        modified_unix_seconds: entry.modified_unix_seconds,
        modified_unix_nanos: entry.modified_unix_nanos.unwrap_or_default(),
        source_file_fingerprint: String::new(),
        physical_identity: None,
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    };
    let scan = new_scan(&root.projects(), index.clone());
    prepare_owned_scan_candidate(
        SnapshotSource::ClaudeCode,
        &mut candidate,
        &scan.codex_title_metadata,
        &scan.claude_title_metadata,
        None,
    );
    open_and_identify_scan_candidate(
        SnapshotSource::ClaudeCode,
        candidate,
        &mut ScanCensus::default(),
        None,
        BACKFILL_WINDOW_DAYS,
        DiscoveryRetention {
            files: &index.files,
            account_holds: &index.claude_account_deferred_holds,
            memo: Some(&index.withheld_memo),
            growth: None,
        },
    )
    .unwrap()
    .0
}

/// Every trigger reads unchanged committed content, creates its hold through
/// real classify/Completed/save/load, then recovers its missing advisory state.
fn withheld_equal_fingerprint_recovers_after(failure: &str) {
    for reason in [
        CandidateParseReason::UploadContext,
        CandidateParseReason::BodyWitnessAdoption,
        CandidateParseReason::ActivityOrQuarantineRetry,
    ] {
        withheld_equal_fingerprint_recovers_for_reason(failure, reason);
    }
}

fn withheld_equal_fingerprint_recovers_for_reason(failure: &str, reason: CandidateParseReason) {
    use crate::local_resource_diagnostics::withheld_support::take_withheld;
    struct ClockReset;
    impl Drop for ClockReset {
        fn drop(&mut self) {
            sampled_scan::set_test_now(None);
        }
    }
    let _clock_reset = ClockReset;
    const DAY: u64 = 86_400;
    sampled_scan::set_test_now(Some(200 * DAY));
    let root = Root::new("ld-equal-held-memo-recovery");
    let path = root.file(SESSION);
    let key = local_index_key(&path);
    append(&path, &assistant_line("equal-revision"));
    let revision =
        crate::snapshot_sync::effective_upload_body_witness_revision(SnapshotSource::ClaudeCode);
    let activate = |index: &mut ScanIndex, revision| {
        index.activate_quarantine_witness(SnapshotSource::ClaudeCode);
        index.activate_effective_upload_body_witness_revision(revision);
        index.adopt_effective_upload_body_witness_revision_monotonically();
    };
    let memo = withheld_account::Memo::default();
    let page = |mut index: ScanIndex, revision| {
        // Production reactivates these RAM fields after EVERY load, before
        // taking the committed baseline. A zero revision would hide the loop.
        index.withheld_memo = memo.clone();
        activate(&mut index, revision);
        let recorder = Recorder::default();
        let (index, scan, _) = finish(
            new_scan(&root.projects(), index)
                .with_line_observer("test", Box::new(recorder.clone())),
        );
        (index, scan, recorder)
    };
    let old_revision = if reason == CandidateParseReason::BodyWitnessAdoption {
        revision - 1
    } else {
        revision
    };
    let (mut previous, _, _) = page(ScanIndex::default(), old_revision);
    let fingerprint = previous.files[&key].source_file_fingerprint.clone();
    assert_eq!(
        previous.files[&key].effective_upload_body_witness_revision,
        old_revision
    );
    match reason {
        CandidateParseReason::UploadContext => {
            previous.upload_context_fingerprint = Some("retry-context".into());
            // The prior checkpoint enters with unresolved context debt.
            // The reader may drain its census before account settlement.
            previous.bounded_sweep_had_unsettled_upload = true;
        }
        CandidateParseReason::BodyWitnessAdoption => {}
        CandidateParseReason::ActivityOrQuarantineRetry => {
            // A legacy checkpoint lacks the activity map. Its repair selects
            // the unchanged file through the actual activity/retry gate.
            for fingerprint in &previous.file_snapshot_fingerprints[&key] {
                previous.snapshot_activity_at.remove(fingerprint);
            }
        }
        _ => unreachable!(),
    }
    activate(&mut previous, revision);
    let candidate = withheld_recovery_candidate(&root, &path, &previous);
    assert_eq!(candidate.source_file_fingerprint, fingerprint);
    assert_eq!(
        previous.candidate_decision_with_reason_at(&candidate, 1),
        (CandidateDecision::Parse, Some(reason)),
    );
    let accepted = previous.accepted_snapshot_fingerprints.clone();
    let previous_body = previous.files[&key].last_upload_body_witness.clone();
    let previous_entities = previous.file_snapshot_fingerprints[&key].clone();
    let (mut parsed, scan, recorder) = page(previous.clone(), revision);
    // finish() simulates upload ACKs for reader fixtures. Account settlement
    // happens before upload, so keep only the real committed ACK baseline.
    parsed.accepted_snapshot_fingerprints = accepted.clone();
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(parsed.files[&key].source_file_fingerprint, fingerprint);
    assert!(!recorder.events().is_empty());
    let mut held = crate::snapshot_sync::withheld_support::settle_withheld(&previous, parsed, scan);
    assert_eq!(held.files[&key].source_file_fingerprint, fingerprint);
    assert!(held.claude_account_deferred_holds.contains_key(&key));
    if reason == CandidateParseReason::UploadContext {
        // A drained reader can adopt its global context at finalization. The
        // real checkpoint subset restores the previous context independently
        // of that read and the Completed per-file account restoration. Exercise
        // that composition, rather than assuming the old sweep flag survives.
        held = held.committable_subset(&previous, &accepted, &BTreeMap::new());
        assert_ne!(
            held.upload_context_fingerprint, held.active_upload_context_fingerprint,
            "real checkpoint preserves the unsettled context debt"
        );
    }
    let checkpoint = root.0.join("equal-held.json");
    let reload = |index: &mut ScanIndex| {
        index.save(&checkpoint).unwrap();
        let mut index = ScanIndex::load(&checkpoint).unwrap();
        index.withheld_memo = memo.clone();
        activate(&mut index, revision);
        index
    };
    let no_credit = |index: &ScanIndex| {
        assert_eq!(
            index.files[&key].effective_upload_body_witness_revision,
            old_revision
        );
        assert_eq!(index.files[&key].last_upload_body_witness, previous_body);
        assert_eq!(index.file_snapshot_fingerprints[&key], previous_entities);
        assert_eq!(
            index.accepted_snapshot_fingerprints, accepted,
            "no new ACK credit"
        );
        assert!(!crate::snapshot_sync::withheld_support::withheld_settled(
            index
        ));
    };
    let gauge = || serde_json::to_value(memo.held_gauge()).unwrap();
    let available = |bucket: &str| {
        let row = gauge();
        assert_eq!(row["withheld_held_count"], 1);
        assert_eq!(row["withheld_memo_unavailable"], false);
        assert_eq!(row["withheld_held_tokens"], 30);
        assert_eq!(row["withheld_held_age"][bucket], 1);
        assert_eq!(
            row["withheld_held_age"]
                .as_object()
                .unwrap()
                .values()
                .map(|count| count.as_u64().unwrap())
                .sum::<u64>(),
            1
        );
    };
    held = reload(&mut held);
    no_credit(&held);
    available("le_30d");
    for pass in 0..3 {
        let (quiet, scan, recorder) = page(held.clone(), revision);
        assert!(
            recorder.events().is_empty(),
            "valid CONTENT skips: {reason:?}, {pass}"
        );
        assert_eq!(scan.scanned_file_count, 0);
        no_credit(&quiet);
        available("le_30d");
    }
    take_withheld();

    let mut candidate = withheld_recovery_candidate(&root, &path, &held);
    assert!(held.withheld_account_unchanged(&key, &candidate));
    // Keep the ordinary stale-activity decision present explicitly: Completed
    // can repair it when the entity hash stays the same, but a restored older
    // entity set need not have that clock. CONTENT defers only this local debt.
    let mut missing_activity = held.clone();
    for fingerprint in &previous_entities {
        missing_activity.snapshot_activity_at.remove(fingerprint);
    }
    assert_eq!(
        missing_activity.candidate_decision_at(&candidate, 1),
        CandidateDecision::Skip
    );
    // New retry authority must still precede that Skip.
    let entity_fingerprint = previous_entities.iter().next().unwrap();
    let mut retry = held.clone();
    let mut quarantine = snapshot_quarantine_record(SnapshotSource::ClaudeCode);
    quarantine.retry_after_unix_seconds = 0;
    retry
        .quarantined_snapshot_fingerprints
        .insert(entity_fingerprint.clone(), quarantine);
    assert_eq!(
        retry.candidate_decision_with_reason_at(&candidate, 1),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::ActivityOrQuarantineRetry)
        )
    );
    let mut authority = held.clone();
    let (family, member) = claude_index_path_family_member(&path).unwrap();
    let proof = authority
        .claude_usage_family_witnesses
        .get(&family)
        .map(claude_usage_family_witness_fingerprint)
        .unwrap_or_default();
    authority.claude_usage_authority_quarantine.insert(
        family,
        ClaudeUsageAuthorityQuarantineRecord {
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.into(),
            proven_witness_fingerprint: proof.clone(),
            member_source_file_fingerprints: BTreeMap::from([(
                member.clone(),
                fingerprint.clone(),
            )]),
            failed_reconstruction_count: 1,
            disposition: ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
            retry_after_unix_seconds: u64::MAX,
            proof_correction: Some(ClaudeAuthorityProofCorrection {
                proof_witness_fingerprint: proof,
                owed_member_ids: BTreeSet::from([member]),
            }),
        },
    );
    assert_eq!(
        authority.candidate_decision_with_reason_at(&candidate, 1),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::AuthorityQuarantine)
        )
    );
    let mut audited = held.clone();
    assert!(audited.stage_sampled_audit(
        &key,
        &fingerprint,
        crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: 1
        }
    ));
    assert!(audited.files[&key].audit_requires_full(2));
    assert_eq!(
        audited.candidate_decision_at(&candidate, 2),
        CandidateDecision::Skip
    );
    audited
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    assert_eq!(
        audited.candidate_decision_with_reason_at(&candidate, 2),
        (CandidateDecision::Parse, Some(CandidateParseReason::Audit))
    );
    let mut context = held.clone();
    context.activate_upload_context("new-authority".into());
    assert!(!context.withheld_account_unchanged(&key, &candidate));
    assert_eq!(
        context.candidate_decision_at(&candidate, 1),
        CandidateDecision::Parse
    );
    let mut other_revision = held.clone();
    activate(&mut other_revision, revision - 1);
    assert!(!other_revision.withheld_account_unchanged(&key, &candidate));
    assert_eq!(
        other_revision.candidate_decision_at(&candidate, 1),
        CandidateDecision::Parse
    );
    let mut rearmed = held.clone();
    rearmed
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    assert_eq!(
        rearmed.candidate_decision_at(&candidate, 1),
        CandidateDecision::Parse
    );
    let mut evidence = candidate.clone();
    evidence.withheld_content_stamp = Some("different-account-evidence".into());
    assert_eq!(
        held.candidate_decision_at(&evidence, 1),
        CandidateDecision::Parse
    );

    match failure {
        "missing" => withheld_account::support::restart(&memo),
        "refused" => assert!(memo.retained_bound(0).is_none()),
        "poisoned" => withheld_account::support::poison(&memo),
        "no-birth" => {
            // The production no-generation witness, with a nonempty committed
            // fingerprint: matching samples alone cannot grant a Skip.
            candidate.withheld_content_stamp = withheld_account::content_stamp(
                candidate.size_bytes,
                None,
                &OpenedContentSamples {
                    head: vec![],
                    tail: None,
                },
            );
            assert!(candidate.withheld_content_stamp.is_none());
        }
        _ => unreachable!(),
    }
    assert_eq!(
        held.candidate_decision_at(&candidate, 1),
        CandidateDecision::Parse,
        "{failure}"
    );
    if failure != "no-birth" {
        let row = gauge();
        assert_eq!(row["withheld_held_count"], 1);
        assert_eq!(row["withheld_memo_unavailable"], true);
        assert!(row.get("withheld_held_tokens").is_none());
        assert!(row.get("withheld_held_age").is_none());
    }
    // The real owner discards refused/poisoned state before its next cycle.
    // The filesystem supplies a valid birth on the recovery parse below.
    memo.discard_if_refused();
    let (mut parsed, scan, recorder) = page(held.clone(), revision);
    parsed.accepted_snapshot_fingerprints = accepted.clone();
    assert_eq!(
        scan.scanned_file_count, 1,
        "{failure}: one actual recovery parse"
    );
    assert_eq!(
        recorder
            .events()
            .iter()
            .filter(|e| matches!(e, Event::Begin(_)))
            .count(),
        1
    );
    held = crate::snapshot_sync::withheld_support::settle_withheld(&held, parsed, scan);
    held = reload(&mut held);
    assert_eq!(
        held.files[&key].source_file_fingerprint,
        candidate.source_file_fingerprint
    );
    no_credit(&held);
    available("le_30d");
    let [_, reparses, _] = take_withheld();
    assert_eq!(reparses, BTreeMap::from([("start", 1)]), "{failure}");
    for pass in 0..3 {
        let (quiet, scan, recorder) = page(held.clone(), revision);
        assert!(
            recorder.events().is_empty(),
            "{failure}: rebuilt memo skips {pass}"
        );
        assert_eq!(scan.scanned_file_count, 0);
        no_credit(&quiet);
        available("le_30d");
    }
    sampled_scan::set_test_now(Some(231 * DAY));
    let (quiet, scan, recorder) = page(held, revision);
    assert!(recorder.events().is_empty());
    assert_eq!(scan.scanned_file_count, 0);
    no_credit(&quiet);
    available("31_90d");
    assert!(take_withheld()[1].is_empty());
}
/// [behaviour] Withheld equal fingerprint recovers from missing memo.

#[test]
fn withheld_equal_fingerprint_recovers_from_missing_memo() {
    withheld_equal_fingerprint_recovers_after("missing");
}
