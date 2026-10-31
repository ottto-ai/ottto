//! The strict trace reader stops at the opened length and drops rows read
//! from a file that grew or was replaced. Fixtures are synthetic.
use super::*;

/// Main's trace reader before the bound (ba8e21a7f), frozen as the stable
/// input reference. It streams the opened file to EOF.
fn main_reference(support_dir: &Path, session_id: &str) -> ClaudeTraceOwnershipLoadReport {
    let mut report = ClaudeTraceOwnershipLoadReport::default();
    let path = trace_evidence_path(support_dir, session_id);
    let metadata = fs::metadata(&path).unwrap();
    assert!(metadata.is_file() && metadata.len() < MAX_EVIDENCE_FILE_BYTES);
    let mut decoder = TraceSidecarDecoder::new(session_id, Vec::new());
    decoder.report = report;
    for line in BufReader::new(File::open(&path).unwrap()).lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => {
                decoder.report.unreadable_lines += 1;
                continue;
            }
        };
        decoder.push_line(line.as_bytes());
    }
    decoder.finish_eof(None);
    let (rows, decoded_report) = decoder.into_output();
    report = decoded_report;
    if !rows.is_empty() {
        report.evidence.insert(session_id.to_owned(), rows);
    }
    report
}

fn trace_row(session_id: &str, request_id: &str) -> ClaudeTraceOwnershipEvidence {
    trace_evidence_from_attrs(
        &BTreeMap::from([
            ("session.id".into(), session_id.into()),
            ("request_id".into(), request_id.into()),
        ]),
        Some("2026-10-30T10:00:00Z".into()),
    )
    .unwrap()
}

fn bytes_read(
    read: impl FnOnce() -> ClaudeTraceOwnershipLoadReport,
) -> (ClaudeTraceOwnershipLoadReport, u64) {
    let before = TRACE_BYTES_FOR_TEST.with(std::cell::Cell::get);
    let report = read();
    (
        report,
        TRACE_BYTES_FOR_TEST.with(std::cell::Cell::get) - before,
    )
}

#[test]
fn strict_trace_read_of_stable_input_equals_main_rows_and_health() {
    let scratch = crate::test_scratch::ScratchDir::new("trace-bound-stable");
    let clean = trace_row("stable-clean", "owned-X");
    append_trace_ownership_evidence(&scratch, &clean).unwrap();
    append_trace_ownership_evidence(&scratch, &clean).unwrap();
    append_trace_ownership_evidence(&scratch, &trace_row("stable-clean", "owned-Y")).unwrap();
    // Unhealthy but stable input keeps main's exact counters too.
    let mixed = trace_row("stable-mixed", "owned-Z");
    append_trace_ownership_evidence(&scratch, &mixed).unwrap();
    let mixed_path = trace_evidence_path(&scratch, &mixed.session_id);
    OpenOptions::new()
        .append(true)
        .open(&mixed_path)
        .unwrap()
        .write_all(b"{not json\n")
        .unwrap();
    append_trace_ownership_evidence(&scratch, &trace_row("stable-mixed", "owned-W")).unwrap();

    for (session_id, complete, rows) in [("stable-clean", true, 2), ("stable-mixed", false, 2)] {
        let len = fs::metadata(trace_evidence_path(&scratch, session_id))
            .unwrap()
            .len();
        let main = main_reference(&scratch, session_id);
        let (bounded, bytes) =
            bytes_read(|| load_claude_trace_ownership_evidence(&scratch, [session_id.into()]));
        assert_eq!(
            bounded, main,
            "{session_id}: rows, dedupe and health equal main"
        );
        assert_eq!(
            bytes, len,
            "{session_id}: a stable file is read once to EOF"
        );
        assert_eq!(bounded.is_complete(), complete, "{session_id}");
        assert_eq!(bounded.evidence[session_id].len(), rows, "{session_id}");
        assert!(bounded.rows_discarded.is_empty(), "{session_id}");
    }
    assert_eq!(main_reference(&scratch, "stable-mixed").malformed_lines, 1);
}

#[test]
fn strict_trace_read_discards_rows_when_a_real_writer_appends_past_opened_length() {
    let scratch = crate::test_scratch::ScratchDir::new("trace-bound-append");
    let first = trace_row("growing", "owned-X");
    append_trace_ownership_evidence(&scratch, &first).unwrap();
    let path = trace_evidence_path(&scratch, &first.session_id);
    let opened_len = fs::metadata(&path).unwrap().len();
    let support = scratch.to_path_buf();
    before_next_trace_read_for_test(move |_| {
        // The real capture writer appends one complete row mid-read.
        append_trace_ownership_evidence(&support, &trace_row("growing", "owned-Y")).unwrap();
    });
    let (report, bytes) =
        bytes_read(|| load_claude_trace_ownership_evidence(&scratch, ["growing".into()]));
    assert_eq!(
        bytes,
        opened_len + 1,
        "opened length plus one growth sentinel"
    );
    assert!(report.evidence.is_empty(), "a grown file grants no rows");
    assert!(!report.is_complete());
    assert_eq!(report.oversized_files, 1);
    assert_eq!(
        report.rows_discarded,
        ClaudeTraceRowsDiscarded {
            cap: 1,
            cap_rows: 1,
            ..Default::default()
        }
    );

    // Once the writer is done, the next read is complete again.
    let (settled, bytes) =
        bytes_read(|| load_claude_trace_ownership_evidence(&scratch, ["growing".into()]));
    assert_eq!(bytes, fs::metadata(&path).unwrap().len());
    assert!(settled.is_complete());
    assert_eq!(settled.evidence["growing"].len(), 2);
    assert!(settled.rows_discarded.is_empty());
}

#[test]
fn strict_trace_read_stops_at_opened_length_when_a_real_writer_crosses_the_capture_cap() {
    let scratch = crate::test_scratch::ScratchDir::new("trace-bound-capture-cap");
    let row = trace_row("capped", "owned-X");
    append_trace_ownership_evidence(&scratch, &row).unwrap();
    let path = trace_evidence_path(&scratch, &row.session_id);
    let opened_len = fs::metadata(&path).unwrap().len();
    let support = scratch.to_path_buf();
    let mut encoded = serde_json::to_vec(&row).unwrap();
    encoded.push(b'\n');
    before_next_trace_read_for_test(move |path| {
        // Valid re-exported rows in small chunks; the final real capture call
        // crosses the on-disk cap and refuses proof.
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        let mut left = (MAX_EVIDENCE_FILE_BYTES - 1 - opened_len) / (encoded.len() as u64);
        while left > 0 {
            let count = left.min(256);
            file.write_all(&encoded.repeat(count as usize)).unwrap();
            left -= count;
        }
        drop(file);
        assert!(append_trace_ownership_evidence(&support, &row).is_err());
        assert!(fs::metadata(path).unwrap().len() >= MAX_EVIDENCE_FILE_BYTES);
    });
    let (report, bytes) =
        bytes_read(|| load_claude_trace_ownership_evidence(&scratch, ["capped".into()]));
    assert_eq!(bytes, opened_len + 1, "the writer cannot extend the read");
    assert!(report.evidence.is_empty());
    assert!(!report.is_complete());
    assert_eq!(report.rows_discarded.cap, 1);
    assert_eq!(report.rows_discarded.generation, 0);
}

#[cfg(unix)]
#[test]
fn strict_trace_read_discards_rows_when_the_path_is_replaced_while_open() {
    let scratch = crate::test_scratch::ScratchDir::new("trace-bound-replace");
    let row = trace_row("replaced", "owned-X");
    append_trace_ownership_evidence(&scratch, &row).unwrap();
    let path = trace_evidence_path(&scratch, &row.session_id);
    let opened_len = fs::metadata(&path).unwrap().len();
    before_next_trace_read_for_test(move |path| {
        // Same bytes under a new inode: the opened object no longer is the
        // path's file, so its rows prove nothing about the current file.
        let staged = path.with_extension("staged");
        fs::copy(path, &staged).unwrap();
        fs::rename(&staged, path).unwrap();
    });
    let (report, bytes) =
        bytes_read(|| load_claude_trace_ownership_evidence(&scratch, ["replaced".into()]));
    assert_eq!(bytes, opened_len, "the opened file itself did not grow");
    assert!(report.evidence.is_empty(), "a replaced file grants no rows");
    assert!(!report.is_complete());
    assert_eq!(report.oversized_files, 1);
    assert_eq!(
        report.rows_discarded,
        ClaudeTraceRowsDiscarded {
            generation: 1,
            generation_rows: 1,
            ..Default::default()
        }
    );

    let settled = load_claude_trace_ownership_evidence(&scratch, ["replaced".into()]);
    assert!(settled.is_complete());
    assert_eq!(settled.evidence["replaced"], vec![row]);
}
