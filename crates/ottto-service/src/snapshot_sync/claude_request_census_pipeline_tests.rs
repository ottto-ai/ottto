// Slice D1 through the executed page pipeline of `finish_sync_source` (the
// `PipelineFixture` stages): request-census records survive held reverts and
// partial commits as the working index's, and records change no decision.
// Fixtures are synthetic.

fn census_pipeline_window(census_window_end: &str) -> u64 {
    OffsetDateTime::parse(census_window_end, &Rfc3339)
        .expect("census window")
        .unix_timestamp()
        .try_into()
        .expect("unix seconds")
}

/// TD1g and TD1h. An account-deferred key's entry reverts to its accepted
/// revision, but its record stays the revision this window parsed (records
/// follow `self`, never `previous`). At the complete terminal of the same
/// census window that record covers the key by `window`, so the hold is not a
/// missing record.
#[test]
#[serial(source_manifests)]
fn census_records_keep_the_held_revision_and_cover_it_in_window() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("claude-census-records-held");
    let baseline = fixture.baseline();
    let held_key = PipelineFixture::key(&baseline, PIPELINE_HELD_SESSION);
    let baseline_record = baseline
        .claude_request_census_for_test()
        .get(&held_key)
        .expect("baseline record")
        .clone();
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");

    let pages = fixture.traversal(9, &PIPELINE_HOLD_CYCLE);
    let (first, last) = (&pages[0], pages.last().expect("terminal page"));
    assert_eq!(
        first.held.len(),
        1,
        "the changed owner-unproven body is held"
    );
    assert_eq!(first.index.claude_account_deferred_hold_count(), 1);
    // TD1g: the reverted entry, the NEW record.
    let record = first
        .index
        .claude_request_census_for_test()
        .get(&held_key)
        .expect("held key keeps a record");
    assert_ne!(record, &baseline_record);
    assert!(record
        .request_hashes_for_test()
        .contains(&crate::snapshots::claude_request_census::claude_request_hash("req_0_2")));
    assert_ne!(
        record.fingerprint_hex_for_test(),
        first.index.files[&held_key].source_file_fingerprint,
        "the entry reverted; the record did not"
    );
    assert_eq!(
        record.window_for_test(),
        census_pipeline_window(&first.scan.census_window_end)
    );

    // TD1h: covered in-window at the terminal of the same census window.
    assert!(last.scan.census_complete);
    assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
    assert!(last.index.claude_account_deferred_hold_count() <= 1);
    let shadow = last
        .scan
        .claude_request_census_shadow
        .expect("complete Claude terminal measures the shadow");
    assert_eq!(shadow.family_keys, PIPELINE_SESSIONS.len());
    assert!(shadow.covered_by_window >= 1, "{shadow:?}");
    assert_eq!(shadow.missing_account_hold, 0, "{shadow:?}");
    assert_eq!(
        shadow.covered_by_fingerprint + shadow.covered_by_window,
        shadow.family_keys,
        "{shadow:?}"
    );
    assert!(shadow.would_open, "{shadow:?}");
    // Non-terminal pages measure nothing.
    assert!(pages[..pages.len() - 1]
        .iter()
        .all(|page| page.scan.claude_request_census_shadow.is_none()));
}

const CENSUS_PARITY_ID_LESS: &str = "d4444444-4444-4444-8444-444444444444";
const CENSUS_PARITY_COPY: &str = "e5555555-5555-4555-8555-555555555555";

/// Every decision one pipeline page made or persisted, path-independent.
fn census_parity_page_facts(fixture: &PipelineFixture, page: &PipelinePage) -> serde_json::Value {
    serde_json::json!({
        "discovered": page.scan.discovered_file_count,
        "scanned": page.scan.scanned_file_count,
        "complete": page.scan.census_complete,
        "cap_hit": page.scan.scan_cap_hit,
        "window": page.scan.census_window_end,
        "bodies": page
            .scan
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<Vec<_>>(),
        "uploaded": page.uploaded,
        "held": page.held,
        "progress_blocking": page.progress_blocking,
        "fully_settled": page.fully_settled,
        "backfill_succeeded": page.backfill_succeeded,
        "decisions": page.index.claude_census_decision_view_for_test(&fixture.base),
    })
}

/// One arm: a multi-window corpus with an id-less member, a copied request,
/// a terminal authority family (h559 correction debt is never dropped by a
/// record), a held change and plain appends. Returns each page's facts and
/// the final record count.
fn census_parity_arm(name: &str, records: bool) -> (Vec<serde_json::Value>, usize) {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new(name);
    if !records {
        crate::snapshots::claude_request_census::disable_records_under_for_test(&fixture.root);
    }
    std::fs::write(
        fixture.root.join(format!("{CENSUS_PARITY_ID_LESS}.jsonl")),
        format!(
            "{{\"timestamp\":\"2026-08-02T07:00:05Z\",\"type\":\"assistant\",\"sessionId\":\"{CENSUS_PARITY_ID_LESS}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
        ),
    )
    .expect("write id-less transcript");
    std::fs::write(
        fixture.root.join(format!("{CENSUS_PARITY_COPY}.jsonl")),
        pipeline_transcript_line(CENSUS_PARITY_COPY, "req_1_1", 7),
    )
    .expect("write copied-request transcript");
    let mut facts = Vec::new();
    let mut run = |hour: u32, cycle: &PipelineCycle<'_>| {
        for page in fixture.traversal(hour, cycle) {
            facts.push(census_parity_page_facts(&fixture, &page));
        }
    };
    run(
        8,
        &PipelineCycle {
            upload_context: "upload-context-1",
            replay_generation: "replay-generation-1",
            proven_owner_session: Some(PIPELINE_HELD_SESSION),
            first_page_upload: PipelineUpload::Accept,
            historical_replay: false,
        },
    );
    let terminal_root = PIPELINE_SESSIONS[2];
    let mut index = ScanIndex::load(&fixture.index_path).expect("load scan index");
    let revision = index
        .files
        .iter()
        .find(|(key, _)| key.ends_with(&format!("{terminal_root}.jsonl")))
        .map(|(_, entry)| entry.source_file_fingerprint.clone())
        .filter(|revision| revision.len() == 64)
        // A rearmed entry has no revision; any well-formed one seeds the debt.
        .unwrap_or_else(|| "c".repeat(64));
    index.insert_unproven_terminal_claude_authority_for_test(terminal_root, &revision);
    index.save(&fixture.index_path).expect("save scan index");
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
    run(9, &PIPELINE_HOLD_CYCLE);
    fixture.append(terminal_root, "req_2_2");
    fixture.append(CENSUS_PARITY_COPY, "req_copy_2");
    run(10, &PIPELINE_HOLD_CYCLE);
    run(
        11,
        &PipelineCycle {
            proven_owner_session: Some(PIPELINE_HELD_SESSION),
            ..PIPELINE_HOLD_CYCLE
        },
    );
    let index = ScanIndex::load(&fixture.index_path).expect("reload scan index");
    let record_count = index.claude_request_census_for_test().len_for_test();
    (facts, record_count)
}

/// Zero behavior change: the same corpus with records on and with records
/// off makes the same scan, upload, hold, settlement, rearm, fence, pending,
/// quarantine and manifest-feeding decisions on every page. Only the record
/// map and the shadow counters differ.
#[test]
#[serial(source_manifests)]
fn census_records_change_no_pipeline_decision() {
    let (with_records, record_count) = census_parity_arm("claude-census-parity-records", true);
    let (control, control_record_count) = census_parity_arm("claude-census-parity-control", false);
    assert!(record_count > 0, "the records arm wrote records");
    assert_eq!(control_record_count, 0, "the control arm wrote none");
    assert!(with_records.len() >= 4, "{} pages", with_records.len());
    assert_eq!(with_records.len(), control.len());
    for (page, (records, control)) in with_records.iter().zip(&control).enumerate() {
        assert_eq!(records, control, "page {page}");
    }
}
