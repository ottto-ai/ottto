use super::*;
#[test]
fn terminal_off_strict_growing_trace_obeys_actual_reader_allowance() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scratch = crate::test_scratch::ScratchDir::new("strict-growing-trace");
    let root = "growing".to_string();
    let path = trace_evidence_path(&scratch, &root);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"{}\n").unwrap();
    TRACE_BEFORE_READ.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|path| {
            OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(&vec![b'x'; 1024 * 1024])
                .unwrap();
        }))
    });
    let budget = strict_budget::StrictReadBudget::new(4096);
    let before = TRACE_BYTES_FOR_TEST.with(std::cell::Cell::get);
    let report = load_claude_trace_ownership_evidence(&scratch, [root]);
    let bytes = TRACE_BYTES_FOR_TEST.with(std::cell::Cell::get) - before;
    assert_eq!(bytes, 4, "pre-open length plus one growth sentinel");
    assert_eq!(budget.consumed(), bytes);
    assert!(!report.is_complete());
    assert!(
        report.evidence.is_empty(),
        "a truncated prefix is never complete/absent proof"
    );
}

#[test]
fn default_off_stable_trace_rows_and_health_equal_main_reference() {
    assert!(!crate::snapshots::claude_terminal_off());
    let scratch = crate::test_scratch::ScratchDir::new("off-stable-trace-main");
    let row = trace_evidence_from_attrs(
        &BTreeMap::from([
            ("session.id".into(), "off-trace".into()),
            ("request_id".into(), "owned-X".into()),
        ]),
        Some("2026-10-30T10:00:00Z".into()),
    )
    .unwrap();
    append_trace_ownership_evidence(&scratch, &row).unwrap();
    append_trace_ownership_evidence(&scratch, &row).unwrap();
    let main =
        load_claude_trace_ownership_evidence_main_reference(&scratch, [row.session_id.clone()]);
    let bounded = load_claude_trace_ownership_evidence(&scratch, [row.session_id]);
    assert_eq!(
        bounded, main,
        "stable rows, dedupe and health counters are identical"
    );
    assert!(bounded.is_complete());
}

#[test]
fn default_off_trace_crossing_real_capture_cap_is_bounded_and_never_complete() {
    assert!(!crate::snapshots::claude_terminal_off());
    let scratch = crate::test_scratch::ScratchDir::new("off-growing-trace-real-cap");
    let row = trace_evidence_from_attrs(
        &BTreeMap::from([
            ("session.id".into(), "off-growing".into()),
            ("request_id".into(), "owned-X".into()),
        ]),
        Some("2026-10-30T10:00:00Z".into()),
    )
    .unwrap();
    append_trace_ownership_evidence(&scratch, &row).unwrap();
    let path = trace_evidence_path(&scratch, &row.session_id);
    let opened_len = fs::metadata(&path).unwrap().len();
    let support = scratch.to_path_buf();
    let mut encoded = serde_json::to_vec(&row).unwrap();
    encoded.push(b'\n');
    TRACE_BEFORE_READ.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |path| {
            // Re-exported valid rows, bounded small write chunks. The final REAL
            // capture call crosses its actual on-disk cap and refuses proof.
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
        }))
    });
    let before = TRACE_BYTES_FOR_TEST.with(std::cell::Cell::get);
    let report = load_claude_trace_ownership_evidence(&scratch, ["off-growing".into()]);
    assert_eq!(
        TRACE_BYTES_FOR_TEST.with(std::cell::Cell::get) - before,
        opened_len + 1
    );
    assert!(!report.is_complete());
    assert!(
        report.evidence.is_empty(),
        "oversized/racing data grants no ownership or absence proof"
    );
}

#[test]
fn terminal_off_on_api_allowance_caps_each_open_and_read() {
    let _on = crate::snapshots::ClaudeTerminalOffForTest::enabled();
    assert!(crate::snapshots::claude_terminal_off());
    let scratch = crate::test_scratch::ScratchDir::new("on-api-allowance");
    let path = evidence_path(&scratch, "cap-root");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    for phase in ["stat", "opened", "append"] {
        fs::write(
            &path,
            if phase == "stat" {
                vec![b' '; 32]
            } else {
                b"{}\n".to_vec()
            },
        )
        .unwrap();
        API_READ_RECEIPT.with(|r| r.set((0, 0, false)));
        let grow: ApiReadHook = Box::new(|path| {
            OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(&[b' '; 64])
                .unwrap();
        });
        match phase {
            "opened" => API_BEFORE_OPEN.with(|h| *h.borrow_mut() = Some(grow)),
            "append" => API_BEFORE_READ.with(|h| *h.borrow_mut() = Some(grow)),
            _ => {}
        }
        let budget = strict_budget::StrictReadBudget::new(32);
        assert!(crate::snapshots::claude_terminal_off());
        let (rows, witness) = decode_api_sidecar(&scratch, "cap-root").unwrap();
        let (opens, bytes, _) = API_READ_RECEIPT.with(|r| r.get());
        let expected = match phase {
            "stat" => (0, 0),
            "opened" => (1, 0),
            _ => (1, 4),
        };
        assert_eq!((opens, bytes), expected, "{phase}");
        assert_eq!(budget.consumed(), bytes as u64);
        assert!(budget.consumed() <= 32);
        assert_eq!(witness.health.oversized_files, 1);
        assert!(!witness.health.is_complete());
        assert!(witness.generation.is_none());
        assert!(
            rows.is_empty(),
            "incomplete evidence grants no ownership or ACK credit"
        );
    }
}
