use super::*;
/// [regress] Containment regression: strict growing trace obeys actual reader allowance.
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
