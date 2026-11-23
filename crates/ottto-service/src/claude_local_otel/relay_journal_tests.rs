//! The shared relay journal: stored before the answer, drained in order to the
//! per-session files, replayed after a crash, and fenced by uninstall.
use super::tests::{api_log_body, llm_span, trace_body};
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::{self, observe};
use crate::test_scratch::ScratchDir;

fn handles() -> AppendHandles {
    AppendHandles {
        cap: 2,
        ..AppendHandles::default()
    }
}

fn api(session: &str, request: &str) -> ClaudeLocalOtelEvidence {
    ClaudeLocalOtelEvidence {
        session_id: session.into(),
        request_id: request.into(),
        ..Default::default()
    }
}

fn trace(session: &str, request: &str) -> ClaudeTraceOwnershipEvidence {
    ClaudeTraceOwnershipEvidence {
        session_id: session.into(),
        request_id: request.into(),
        ..Default::default()
    }
}

fn line(row: &impl Serialize) -> Vec<u8> {
    let mut line = serde_json::to_vec(row).unwrap();
    line.push(b'\n');
    line
}

fn journal_bytes(dir: &Path) -> Vec<u8> {
    fs::read(relay_journal::journal_path(dir)).unwrap()
}

/// One valid tagged row for `session`, padded with JSON whitespace to `size`.
fn padded(session: &str, size: u64) -> Vec<u8> {
    let mut row = format!(r#"a{{"session_id":"{session}""#).into_bytes();
    row.resize(size as usize - 2, b' ');
    row.extend_from_slice(b"}\n");
    row
}

fn tagged(rows: &[ClaudeLocalOtelEvidence]) -> Vec<u8> {
    let tagged = rows
        .iter()
        .map(|row| [&b"a"[..], line(row).as_slice()].concat());
    tagged.collect::<Vec<_>>().concat()
}

/// [behaviour] A capture returns only after its rows are in the journal; the
/// per-session file is untouched until a drain. Arrival counters (the walk
/// gate's input) move at the journal append, never again at the drain.
#[test]
fn capture_stores_rows_in_the_journal_and_counts_them_at_arrival() {
    let dir = ScratchDir::new("relay-journal-arrival");
    relay_journal::keep_rows_waiting_for_test(true);
    let body = api_log_body();
    let ((stored, rows_after_capture), counts) = observe(|| {
        let stored =
            capture_claude_api_request_logs(&dir, &body, "application/x-protobuf").unwrap();
        (stored, cache_lifecycle::otlp_relay_rows())
    });
    assert_eq!((stored, rows_after_capture), (1, (1, 0)));
    let row = &api_evidence_from_protobuf(&body).unwrap()[0];
    let mut expected = vec![b'a'];
    expected.extend(line(row));
    assert_eq!(journal_bytes(&dir), expected);
    assert!(!evidence_path(&dir, "sess-protobuf").exists());
    assert_eq!(counts.otlp_relay_appended_rows, 1);
    assert_eq!(counts.otlp_relay_appended_bytes, expected.len() as u64 - 1);
    assert_eq!(counts.otlp_relay_journal_appends_cumulative, 1);
    assert_eq!(counts.otlp_relay_file_appends_cumulative, 0);

    let (_, counts) = observe(|| drain_relay_journal(&dir).unwrap());
    assert_eq!(counts.otlp_relay_appended_rows, 0);
    assert_eq!(counts.otlp_relay_journal_drained_rows_cumulative, 1);
    assert_eq!(
        fs::read(evidence_path(&dir, "sess-protobuf")).unwrap(),
        line(row)
    );

    // A journal that cannot be written fails the capture as a store error (500).
    fs::remove_file(relay_journal::journal_path(&dir)).unwrap();
    fs::create_dir(relay_journal::journal_path(&dir)).unwrap();
    let error = capture_claude_api_request_logs(&dir, &body, "application/x-protobuf").unwrap_err();
    assert!(!is_undecodable_body(&error));
    relay_journal::keep_rows_waiting_for_test(false);
}

/// [behaviour] A drain appends each file's rows in arrival order, once per
/// file, notices their roots only then, and empties the journal.
#[test]
fn drain_moves_rows_in_order_with_one_append_per_file() {
    let dir = ScratchDir::new("relay-journal-drain");
    relay_journal::keep_rows_waiting_for_test(true);
    telemetry_notices::configure(&dir, true).unwrap();
    let mut handles = handles();
    let internal = crate::internal_session::internal_session_id();
    let first = [api("s-a", "r1"), api("s-b", "r2"), api(&internal, "r3")];
    let second = [api("s-a", "r4")];
    let traces = [trace("s-a", "r5"), trace("s-a", "r6")];
    for rows in [&first[..], &second[..]] {
        let rows = rows.iter().map(|row| (row.session_id.as_ref(), row));
        relay_journal::append(&mut handles, &dir, relay_journal::Kind::Api, rows).unwrap();
    }
    let rows = traces.iter().map(|row| (row.session_id.as_ref(), row));
    relay_journal::append(&mut handles, &dir, relay_journal::Kind::Trace, rows).unwrap();
    assert!(telemetry_notices::pending(&dir).unwrap().is_empty());

    let (_, counts) = observe(|| relay_journal::drain_locked(&mut handles, &dir).unwrap());
    assert_eq!(counts.otlp_relay_file_appends_cumulative, 3);
    assert_eq!(counts.otlp_relay_journal_drains_cumulative, 1);
    assert_eq!(counts.otlp_relay_journal_drained_rows_cumulative, 5);
    assert_eq!(counts.otlp_relay_journal_skipped_lines_cumulative, 0);
    assert_eq!(
        fs::read(evidence_path(&dir, "s-a")).unwrap(),
        [line(&first[0]), line(&second[0])].concat()
    );
    assert_eq!(
        fs::read(evidence_path(&dir, "s-b")).unwrap(),
        line(&first[1])
    );
    assert_eq!(
        fs::read(trace_evidence_path(&dir, "s-a")).unwrap(),
        [line(&traces[0]), line(&traces[1])].concat()
    );
    assert!(!evidence_path(&dir, &internal).exists());
    assert!(journal_bytes(&dir).is_empty());
    assert_eq!(
        telemetry_notices::pending(&dir).unwrap(),
        BTreeSet::from(["s-a".to_string(), "s-b".to_string()])
    );
    // An empty journal is not a drain.
    let (_, counts) = observe(|| relay_journal::drain_locked(&mut handles, &dir).unwrap());
    assert_eq!(counts.otlp_relay_journal_drains_cumulative, 0);
    telemetry_notices::configure(&dir, false).unwrap();
    relay_journal::keep_rows_waiting_for_test(false);
}

/// [behaviour] The first drain in a process replays `prev`, then the
/// journal, before any reader; `prev` then holds both until a later drain.
#[test]
fn startup_drain_replays_prev_then_the_journal() {
    let dir = ScratchDir::new("relay-journal-startup");
    let (older, newer) = (api("s-start", "r1"), api("s-start", "r2"));
    let owner = trace("s-start", "r2");
    let (journal, prev) = (
        relay_journal::journal_path(&dir),
        relay_journal::prev_path(&dir),
    );
    fs::create_dir_all(prev.parent().unwrap()).unwrap();
    let left = [
        &b"a"[..],
        line(&newer).as_slice(),
        b"t",
        line(&owner).as_slice(),
    ]
    .concat();
    fs::write(&prev, [&b"a"[..], line(&older).as_slice()].concat()).unwrap();
    fs::write(&journal, &left).unwrap();
    let (_, counts) = observe(|| relay_journal::drain_locked(&mut handles(), &dir).unwrap());
    assert_eq!(counts.otlp_relay_journal_drained_rows_cumulative, 3);
    assert_eq!(
        fs::read(evidence_path(&dir, "s-start")).unwrap(),
        [line(&older), line(&newer)].concat()
    );
    assert_eq!(
        fs::read(trace_evidence_path(&dir, "s-start")).unwrap(),
        line(&owner)
    );
    assert!(journal_bytes(&dir).is_empty());
    assert_eq!(
        fs::read(&prev).unwrap(),
        [&b"a"[..], line(&older).as_slice(), &left].concat()
    );
}

/// [behaviour] A drain renames the journal to `prev` and keeps `prev` until a
/// drain at least a minute later replaces it, so drained rows keep an on-disk
/// copy until their per-session writes have been written back.
#[test]
fn prev_is_kept_until_a_later_drain_replaces_it() {
    let dir = ScratchDir::new("relay-journal-rotate");
    let mut handles = handles();
    relay_journal::keep_rows_waiting_for_test(true);
    let prev = relay_journal::prev_path(&dir);
    let rows = [api("s-r", "r1"), api("s-r", "r2"), api("s-r", "r3")];
    let tagged = |row: &ClaudeLocalOtelEvidence| [&b"a"[..], line(row).as_slice()].concat();
    let store = |handles: &mut AppendHandles, row: &ClaudeLocalOtelEvidence| {
        relay_journal::append(handles, &dir, relay_journal::Kind::Api, [("s-r", row)]).unwrap();
        relay_journal::drain_locked(handles, &dir).unwrap();
    };
    store(&mut handles, &rows[0]);
    assert_eq!(fs::read(&prev).unwrap(), tagged(&rows[0]));
    // A drain within the minute adds to `prev` instead of replacing it.
    store(&mut handles, &rows[1]);
    assert_eq!(
        fs::read(&prev).unwrap(),
        [tagged(&rows[0]), tagged(&rows[1])].concat()
    );
    let state = handles.journals.get_mut(&dir.to_path_buf()).unwrap();
    state.prev_drained = Instant::now().checked_sub(Duration::from_secs(61));
    store(&mut handles, &rows[2]);
    assert_eq!(fs::read(&prev).unwrap(), tagged(&rows[2]));
    assert_eq!(
        fs::read(evidence_path(&dir, "s-r")).unwrap(),
        rows.iter().map(line).collect::<Vec<_>>().concat()
    );
    relay_journal::keep_rows_waiting_for_test(false);
}

/// [regress] A crash after the per-session appends replays every row from
/// `prev` at the next start; the readers still see each row once and stay
/// complete.
#[test]
fn replay_after_a_crash_mid_drain_reads_each_row_once() {
    let dir = ScratchDir::new("relay-journal-replay");
    relay_journal::keep_rows_waiting_for_test(true);
    capture_claude_api_request_logs(&dir, &api_log_body(), "application/x-protobuf").unwrap();
    let traces = trace_body(vec![llm_span("req-replay", Some("agent-a"))]);
    capture_claude_llm_request_traces(&dir, &traces, "application/x-protobuf").unwrap();
    relay_journal::drain_locked(&mut handles(), &dir).unwrap();
    // A new process: `prev` is replayed into the same per-session files.
    relay_journal::drain_locked(&mut handles(), &dir).unwrap();
    relay_journal::keep_rows_waiting_for_test(false);

    let api_file = fs::read(evidence_path(&dir, "sess-protobuf")).unwrap();
    assert_eq!(api_file.iter().filter(|&&b| b == b'\n').count(), 2);
    let report = load_claude_api_request_evidence_report(&dir, ["sess-protobuf".to_string()]);
    assert!(report.health.is_complete());
    assert_eq!(report.evidence["sess-protobuf"].len(), 1);
    let loaded = load_claude_effort_evidence(&dir, ["sess-protobuf".to_string()]).unwrap();
    assert_eq!(loaded["sess-protobuf"].len(), 1);

    let trace_file = fs::read(trace_evidence_path(&dir, "sess-traces")).unwrap();
    assert_eq!(trace_file.iter().filter(|&&b| b == b'\n').count(), 2);
    let report = load_claude_trace_ownership_evidence(&dir, ["sess-traces".to_string()]);
    assert!(report.is_complete());
    assert_eq!(report.evidence["sess-traces"].len(), 1);
}

/// [regress] A torn line from a crash mid-append is never copied, does not
/// swallow the next request's row, and does not block the rows after it.
#[test]
fn torn_journal_lines_are_skipped_without_blocking_the_rest() {
    let dir = ScratchDir::new("relay-journal-torn");
    let mut handles = handles();
    relay_journal::keep_rows_waiting_for_test(true);
    let path = relay_journal::journal_path(&dir);
    let (one, two) = (api("s-torn", "r1"), trace("s-torn", "r2"));
    let append_torn = || {
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"a{"session_id":"s-to"#).unwrap();
    };
    relay_journal::append(
        &mut handles,
        &dir,
        relay_journal::Kind::Api,
        [("s-torn", &one)],
    )
    .unwrap();
    append_torn(); // Crash mid-append; the daemon restarts and takes a request.
    relay_journal::append(
        &mut handles,
        &dir,
        relay_journal::Kind::Trace,
        [("s-torn", &two)],
    )
    .unwrap();
    append_torn(); // Crash again, leaving a torn last line.
    let (_, counts) = observe(|| drain_relay_journal(&dir).unwrap());
    relay_journal::keep_rows_waiting_for_test(false);
    assert_eq!(counts.otlp_relay_journal_skipped_lines_cumulative, 2);
    assert_eq!(counts.otlp_relay_journal_drained_rows_cumulative, 2);
    assert_eq!(fs::read(evidence_path(&dir, "s-torn")).unwrap(), line(&one));
    assert_eq!(
        fs::read(trace_evidence_path(&dir, "s-torn")).unwrap(),
        line(&two)
    );
    assert!(journal_bytes(&dir).is_empty());
}

/// [behaviour] One per-session file refuses: its rows wait in the journal,
/// alone and in order, and count as kept; the other files drain once; once
/// `prev` rotates, only that stem's unlink is held; once the file accepts,
/// its rows move once.
#[test]
fn a_refusing_file_keeps_only_its_rows_and_holds_only_its_stem() {
    let dir = ScratchDir::new("relay-journal-refuse");
    let mut handles = handles();
    relay_journal::keep_rows_waiting_for_test(true);
    let (good, bad) = (
        [api("s-good", "r1")],
        [api("s-bad", "r2"), api("s-bad", "r3")],
    );
    let blocked = evidence_path(&dir, "s-bad");
    fs::create_dir_all(&blocked).unwrap(); // A directory where the file belongs.
    let rows = [&bad[0], &good[0], &bad[1]];
    let rows = rows.into_iter().map(|row| (row.session_id.as_ref(), row));
    relay_journal::append(&mut handles, &dir, relay_journal::Kind::Api, rows).unwrap();
    let (drained, counts) = observe(|| relay_journal::drain_locked(&mut handles, &dir));
    drained.unwrap();
    assert_eq!(counts.otlp_relay_journal_drained_rows_cumulative, 1);
    let waiting = bad
        .iter()
        .map(|row| [&b"a"[..], line(row).as_slice()].concat());
    assert_eq!(journal_bytes(&dir), waiting.collect::<Vec<_>>().concat());
    let kept_bytes = (line(&bad[0]).len() + line(&bad[1]).len()) as u64;
    assert_eq!(relay_journal::kept_totals(&handles), (2, kept_bytes));

    let pair = |root: &str| TelemetryPair {
        request_ids: BTreeSet::new(),
        first_observed: 0,
        last_write: 0,
        bytes: 0,
        generations: [
            telemetry_member(&evidence_path(&dir, root)).ok().flatten(),
            None,
        ],
    };
    let held = pair("s-bad");
    let stem = telemetry_stem("s-bad");
    assert!(!unlink_telemetry_pair_locked(&mut handles, &dir, &stem, &held).unwrap());
    // `prev` still holds the drained row until a drain a minute later
    // replaces it with the journal, which holds only the refused rows.
    let freed = pair("s-good");
    let stem = telemetry_stem("s-good");
    assert!(!unlink_telemetry_pair_locked(&mut handles, &dir, &stem, &freed).unwrap());
    let state = handles.journals.get_mut(&dir.to_path_buf()).unwrap();
    state.prev_drained = Instant::now().checked_sub(Duration::from_secs(61));
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    assert!(unlink_telemetry_pair_locked(&mut handles, &dir, &stem, &freed).unwrap());

    fs::remove_dir(&blocked).unwrap();
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    relay_journal::keep_rows_waiting_for_test(false);
    assert_eq!(
        fs::read(&blocked).unwrap(),
        [line(&bad[0]), line(&bad[1])].concat()
    );
    assert!(
        !evidence_path(&dir, "s-good").exists(),
        "drained rows are not copied again"
    );
    assert!(journal_bytes(&dir).is_empty());
    assert_eq!(relay_journal::kept_totals(&handles), (0, 0));
}

/// [regress] A per-session file left ending in a fragment (a crash
/// mid-append) is ended before the drained rows, so the full row reads and
/// only the fragment line is skipped.
#[test]
fn a_torn_session_file_tail_never_joins_a_drained_row() {
    let dir = ScratchDir::new("relay-journal-session-tail");
    let path = evidence_path(&dir, "sess-protobuf");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, br#"{"session_id":"sess-protobuf","requ"#).unwrap();
    capture_claude_api_request_logs(&dir, &api_log_body(), "application/x-protobuf").unwrap();
    let report = load_claude_api_request_evidence_report(&dir, ["sess-protobuf".to_string()]);
    assert_eq!(report.evidence["sess-protobuf"].len(), 1);
    assert_eq!(report.health.malformed_lines, 1);
}

/// [behaviour] Notice eligibility is fixed at capture: a root captured while
/// notices are active is noticed at the drain even if they were deactivated
/// meanwhile; a root captured while inactive is not, even if reactivated.
#[test]
fn notice_eligibility_is_taken_at_capture_and_delivered_at_the_drain() {
    let dir = ScratchDir::new("relay-journal-notices");
    let mut handles = handles();
    relay_journal::keep_rows_waiting_for_test(true);
    let (active, inactive) = (api("s-active", "r1"), api("s-inactive", "r2"));
    // Captured while active, deactivated before the drain: still noticed.
    telemetry_notices::configure(&dir, true).unwrap();
    let row = [("s-active", &active)];
    relay_journal::append(&mut handles, &dir, relay_journal::Kind::Api, row).unwrap();
    telemetry_notices::configure(&dir, false).unwrap();
    assert!(telemetry_notices::pending(&dir).unwrap().is_empty());
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    let noticed = BTreeSet::from(["s-active".to_string()]);
    assert_eq!(telemetry_notices::pending(&dir).unwrap(), noticed);
    // Captured while inactive, reactivated before the drain: not noticed.
    let row = [("s-inactive", &inactive)];
    relay_journal::append(&mut handles, &dir, relay_journal::Kind::Api, row).unwrap();
    telemetry_notices::configure(&dir, true).unwrap();
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    relay_journal::keep_rows_waiting_for_test(false);
    assert!(evidence_path(&dir, "s-inactive").exists());
    assert_eq!(telemetry_notices::pending(&dir).unwrap(), noticed);
    telemetry_notices::configure(&dir, false).unwrap();
}

/// [behaviour] The uninstall fence refuses new journal rows and stops drains,
/// so waiting rows never recreate a per-session file; the journal lives under
/// `local-otel` and goes with it.
#[test]
fn uninstall_fence_refuses_and_discards_the_journal() {
    let dir = ScratchDir::new("relay-journal-uninstall");
    let mut handles = handles();
    relay_journal::keep_rows_waiting_for_test(true);
    let row = api("s-uninstall", "r1");
    relay_journal::append(
        &mut handles,
        &dir,
        relay_journal::Kind::Api,
        [("s-uninstall", &row)],
    )
    .unwrap();
    handles.disable();
    let refused = relay_journal::append(
        &mut handles,
        &dir,
        relay_journal::Kind::Api,
        [("s-uninstall", &row)],
    );
    assert!(refused.is_err());
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    assert!(!evidence_path(&dir, "s-uninstall").exists());
    assert!(relay_journal::journal_path(&dir).starts_with(dir.join("local-otel")));
    fs::remove_dir_all(dir.join("local-otel")).unwrap();
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    assert!(!dir.join("local-otel").exists());
    relay_journal::keep_rows_waiting_for_test(false);
}

/// [behaviour] With scans stalled, a request that takes the journal a
/// threshold past its length after the last drain drains it inline and still
/// succeeds. Refused rows just under a threshold leave the journal there, yet
/// the requests after the drain never redrain; only another threshold of new
/// rows does.
#[test]
fn a_refused_backlog_drains_inline_once_per_threshold_of_new_rows() {
    let dir = ScratchDir::new("relay-journal-cap");
    let mut handles = handles();
    relay_journal::keep_rows_waiting_for_test(true);
    let path = relay_journal::journal_path(&dir);
    fs::create_dir_all(evidence_path(&dir, "s-bad")).unwrap(); // It refuses rows.
    let backlog = padded("s-bad", relay_journal::DRAIN_AT_BYTES - 10);
    fs::write(&path, &backlog).unwrap();
    let rows: Vec<_> = (0..20).map(|n| api("s-ok", &format!("r{n}"))).collect();
    let ((), counts) = observe(|| {
        for row in &rows {
            let row = [("s-ok", row)];
            let stored = relay_journal::append(&mut handles, &dir, relay_journal::Kind::Api, row);
            assert_eq!(stored.unwrap(), 1);
        }
    });
    assert_eq!(counts.otlp_relay_journal_drains_cumulative, 1);
    let ok = evidence_path(&dir, "s-ok");
    assert_eq!(fs::read(&ok).unwrap(), line(&rows[0]));
    assert_eq!(
        journal_bytes(&dir),
        [backlog.clone(), tagged(&rows[1..])].concat()
    );

    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&padded("s-big", relay_journal::DRAIN_AT_BYTES))
        .unwrap();
    drop(file);
    let last = api("s-ok", "r-last");
    let (stored, counts) = observe(|| {
        relay_journal::append(
            &mut handles,
            &dir,
            relay_journal::Kind::Api,
            [("s-ok", &last)],
        )
    });
    relay_journal::keep_rows_waiting_for_test(false);
    assert_eq!(stored.unwrap(), 1);
    assert_eq!(counts.otlp_relay_journal_drains_cumulative, 1);
    assert_eq!(journal_bytes(&dir), backlog);
    let every = rows.iter().chain([&last]).map(line);
    assert_eq!(fs::read(&ok).unwrap(), every.collect::<Vec<_>>().concat());
}

/// [behaviour] Refused rows past 32 MiB raise one counts-only local alarm per
/// drain, and stay in the journal.
#[test]
fn a_refused_backlog_past_the_alert_size_raises_a_local_alarm() {
    let dir = ScratchDir::new("relay-journal-kept-alarm");
    let mut handles = handles();
    fs::create_dir_all(evidence_path(&dir, "s-bad")).unwrap(); // It refuses rows.
    let backlog = padded("s-bad", 33 << 20);
    fs::write(relay_journal::journal_path(&dir), &backlog).unwrap();
    let (drained, records) = crate::local_resource_diagnostics::capture(|| {
        relay_journal::drain_locked(&mut handles, &dir)
    });
    drained.unwrap();
    let alarms: Vec<_> = records
        .iter()
        .filter(|record| record["stage"] == "otlp_relay_journal_kept_alarm")
        .collect();
    assert_eq!(alarms.len(), 1);
    let counts = &alarms[0]["counts"];
    assert_eq!(counts["otlp_relay_journal_kept_rows"], 1);
    assert_eq!(
        counts["otlp_relay_journal_kept_bytes"],
        backlog.len() as u64 - 1
    );
    assert_eq!(journal_bytes(&dir), backlog);
}

/// [regress] `prev` holds its stems' unlinks while it exists. Once its rows
/// reached their files a minute ago, a drain with an empty journal removes it,
/// so a restart after retention removed a pair never recreates the pair.
#[test]
fn an_idle_prev_is_removed_so_a_restart_never_recreates_a_removed_pair() {
    let dir = ScratchDir::new("relay-journal-prev-retention");
    let mut handles = handles();
    relay_journal::keep_rows_waiting_for_test(true);
    let row = api("s-old", "r1");
    let rows = [("s-old", &row)];
    relay_journal::append(&mut handles, &dir, relay_journal::Kind::Api, rows).unwrap();
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    let (prev, file) = (relay_journal::prev_path(&dir), evidence_path(&dir, "s-old"));
    let stem = telemetry_stem("s-old");
    let pair = || TelemetryPair {
        request_ids: BTreeSet::new(),
        first_observed: 0,
        last_write: 0,
        bytes: 0,
        generations: [telemetry_member(&file).ok().flatten(), None],
    };
    assert!(journal_bytes(&dir).is_empty());
    assert!(relay_journal::waits_for(&dir, &stem));
    assert!(!unlink_telemetry_pair_locked(&mut handles, &dir, &stem, &pair()).unwrap());
    // Within the minute, a drain with an empty journal keeps `prev`.
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    assert!(prev.exists());

    let state = handles.journals.get_mut(&dir.to_path_buf()).unwrap();
    state.prev_drained = Instant::now().checked_sub(Duration::from_secs(61));
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    assert!(!prev.exists());
    // Already gone is fine.
    relay_journal::drain_locked(&mut handles, &dir).unwrap();
    assert!(!relay_journal::waits_for(&dir, &stem));
    assert!(unlink_telemetry_pair_locked(&mut handles, &dir, &stem, &pair()).unwrap());
    assert!(!file.exists());
    // A restart: the first drain of a new process has nothing to replay.
    relay_journal::drain_locked(&mut self::handles(), &dir).unwrap();
    relay_journal::keep_rows_waiting_for_test(false);
    assert!(!file.exists());
    assert!(!trace_evidence_path(&dir, "s-old").exists());
}

/// [regress] A fragment that ends in a space inside a string value is still a
/// fragment: it is ended before the next row, both in a replayed `prev` and in
/// a per-session file, so no full row joins it and is lost.
#[test]
fn a_fragment_ending_in_a_space_is_ended_before_the_next_row() {
    let dir = ScratchDir::new("relay-journal-space-fragment");
    let fragment = br#"{"session_id":"s-frag","request_id":"r "#;
    let file = evidence_path(&dir, "s-frag");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(&file, fragment).unwrap();
    // A crash also left `prev` ending in a tagged fragment; a restart replays it.
    let rows = [api("s-frag", "r1"), api("s-frag", "r2")];
    fs::write(
        relay_journal::prev_path(&dir),
        [&b"a"[..], fragment].concat(),
    )
    .unwrap();
    fs::write(relay_journal::journal_path(&dir), tagged(&rows)).unwrap();
    relay_journal::drain_locked(&mut handles(), &dir).unwrap();
    assert_eq!(
        fs::read(&file).unwrap(),
        [
            &fragment[..],
            b"\n",
            line(&rows[0]).as_slice(),
            line(&rows[1]).as_slice()
        ]
        .concat()
    );
}
