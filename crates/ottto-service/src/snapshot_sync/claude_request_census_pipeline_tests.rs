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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
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

    // Retained same-window records remain evidence; terminal-off never turns
    // them into an OPEN fence or complete-census shadow proof.
    assert!(!last.scan.census_complete);
    assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
    assert!(last.index.claude_account_deferred_hold_count() <= 1);
    assert!(pages
        .iter()
        .all(|page| page.scan.claude_request_census_shadow.is_none()));
    assert!(pages
        .iter()
        .all(|page| page.uploaded.is_disjoint(&page.held)));
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
            .map(|item| (item.snapshot_fingerprint.clone(), snapshot_upload_body_witness(item)))
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
    index.seed_census_correction_for_test(terminal_root);
    let debt = index
        .claude_authority_record_for_test(terminal_root)
        .expect("authority");
    let correction = debt.correction.clone().expect("live correction grant");
    assert!(!correction.1.is_empty(), "a real member owes a correction");
    let mut reset = index.clone();
    reset.prepare_historical_replay("replay-generation-2".to_owned());
    let after = reset
        .claude_authority_record_for_test(terminal_root)
        .expect("reset retains authority");
    assert_eq!(after.correction, Some(correction));
    assert_eq!(
        after.member_source_file_fingerprints,
        debt.member_source_file_fingerprints
    );
    assert_eq!(
        after.proven_witness_fingerprint,
        debt.proven_witness_fingerprint
    );
    assert!(
        after.bound_to_retained_witness,
        "reset keeps the original proof binding"
    );
    index.save(&fixture.index_path).expect("save scan index");
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
    run(
        9,
        &PipelineCycle {
            replay_generation: "replay-generation-2",
            historical_replay: true,
            ..PIPELINE_HOLD_CYCLE
        },
    );
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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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

struct CensusPreHoldBodies {
    offered: Vec<(String, String)>,
    held: BTreeSet<String>,
    uploadable: Vec<(String, String)>,
    discovered: usize,
    scanned: usize,
    complete: bool,
    reset_owed_members: usize,
}

fn census_body_facts(items: &[crate::snapshots::SnapshotItem]) -> Vec<(String, String)> {
    let mut bodies = items
        .iter()
        .map(|item| {
            (
                item.snapshot_fingerprint.clone(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect::<Vec<_>>();
    bodies.sort_unstable();
    bodies
}

/// Observe the same immutable page input at the production boundary before
/// LocalHoldSettlement removes held entities. This preview does not save its
/// index. The actual fixture page below then checks the same selection, hold
/// set and surviving bodies while executing upload, settlement and persistence.
fn census_pre_hold_bodies(
    fixture: &PipelineFixture,
    collected_at: &str,
    cycle: &PipelineCycle<'_>,
) -> CensusPreHoldBodies {
    let _preview = crate::snapshots::TerminalOffDiscoveryPreviewForTest::begin();
    let mut index = ScanIndex::load(&fixture.index_path).expect("preview index");
    index.activate_upload_context(cycle.upload_context.to_owned());
    let mut reset_owed_members = 0;
    if cycle.historical_replay {
        let before = index.claude_authority_record_for_test(PIPELINE_SESSIONS[2]);
        index.prepare_historical_replay(cycle.replay_generation.to_owned());
        if let Some(before) = before.filter(|debt| debt.correction.is_some()) {
            let correction = before.correction.as_ref().expect("live correction");
            assert!(!correction.1.is_empty(), "a member still owes correction");
            let after = index
                .claude_authority_record_for_test(PIPELINE_SESSIONS[2])
                .expect("the actual page reset preserves its authority");
            assert_eq!(after.correction, before.correction);
            assert_eq!(
                after.member_source_file_fingerprints,
                before.member_source_file_fingerprints
            );
            assert_eq!(
                after.proven_witness_fingerprint,
                before.proven_witness_fingerprint
            );
            assert!(
                after.bound_to_retained_witness,
                "reset preserves the proof binding"
            );
            reset_owed_members = correction.1.len();
        }
    }
    index.activate_effective_upload_body_witness_revision(effective_upload_body_witness_revision(
        SnapshotSource::ClaudeCode,
    ));
    let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.root),
        &mut index,
        collected_at,
        183,
        PIPELINE_PAGE_FILES,
        true,
    )
    .expect("preview bounded page");
    let (mut disposition, _, _) =
        apply_claude_local_evidence_to_scan(&fixture.support, &mut scan, &mut index);
    if let Some(owner) = cycle.proven_owner_session {
        for item in scan
            .snapshots
            .iter_mut()
            .filter(|item| item.source_session_id == owner)
        {
            for row in item.model_usage.iter_mut().chain(
                item.usage_buckets
                    .iter_mut()
                    .flat_map(|bucket| bucket.model_usage.iter_mut()),
            ) {
                row.account_identifier_hash = Some("a".repeat(64));
            }
        }
    }
    let deferred = index.bind_session_accounts_with_mixed(
        SnapshotSource::ClaudeCode,
        PIPELINE_MACHINE_ID,
        &mut scan.snapshots,
        &[],
        &disposition.mixed_uploads,
    );
    disposition.defer_sessions(deferred);
    apply_upload_policy(
        SnapshotSource::ClaudeCode,
        &mut scan.snapshots,
        SnapshotUploadPolicy::default(),
    );
    let progress = test_upload_progress();
    exclude_held_effective_body_witness_revision(&mut index, &scan.snapshots, &disposition);
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::ClaudeCode,
        &mut scan,
        &mut index,
        |item| {
            effective_snapshot_upload_body_witness(
                item,
                &progress,
                false,
                false,
                &BTreeSet::new(),
                &disposition,
            )
        },
    );
    let offered = census_body_facts(&scan.snapshots);
    let holds = LocalHoldSettlement::classify(
        SnapshotSource::ClaudeCode,
        &mut index,
        &mut scan,
        &disposition,
    );
    assert!(holds
        .held_fingerprints
        .iter()
        .all(|held| offered.iter().any(|(fingerprint, _)| fingerprint == held)));
    CensusPreHoldBodies {
        offered,
        held: holds.held_fingerprints,
        uploadable: census_body_facts(&scan.snapshots),
        discovered: scan.discovered_file_count,
        scanned: scan.scanned_file_count,
        complete: scan.census_complete,
        reset_owed_members,
    }
}

fn census_pre_hold_parity_arm(name: &str, records: bool) -> (Vec<serde_json::Value>, usize, usize) {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new(name);
    if !records {
        crate::snapshots::claude_request_census::disable_records_under_for_test(&fixture.root);
    }
    fixture.baseline();
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
    std::fs::write(
        fixture.root.join(format!("{CENSUS_PARITY_COPY}.jsonl")),
        pipeline_transcript_line(CENSUS_PARITY_COPY, "req_1_1", 7),
    )
    .unwrap();
    std::fs::write(fixture.root.join(format!("{CENSUS_PARITY_ID_LESS}.jsonl")), format!(
        "{{\"timestamp\":\"2026-08-02T07:00:05Z\",\"type\":\"assistant\",\"sessionId\":\"{CENSUS_PARITY_ID_LESS}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
    )).unwrap();
    let mut facts = Vec::new();
    let mut held_bodies = 0;
    let mut reset_owed_members = 0;
    for hour in [9, 10, 11] {
        if hour == 10 {
            let mut index = ScanIndex::load(&fixture.index_path).expect("index before replay");
            let root = PIPELINE_SESSIONS[2];
            let key = PipelineFixture::key(&index, root);
            let revision = &index.files[&key].source_file_fingerprint;
            let revision = if revision.len() == 64 {
                revision.clone()
            } else {
                "c".repeat(64)
            };
            index.insert_unproven_terminal_claude_authority_for_test(root, &revision);
            index.seed_census_correction_for_test(root);
            let debt = index
                .claude_authority_record_for_test(root)
                .expect("seeded debt");
            assert!(!debt
                .correction
                .expect("a live correction grant")
                .1
                .is_empty());
            index
                .save(&fixture.index_path)
                .expect("save live debt before the actual replay page");
        }
        let cycle = PipelineCycle {
            historical_replay: hour == 10,
            proven_owner_session: (hour == 11).then_some(PIPELINE_HELD_SESSION),
            ..PIPELINE_HOLD_CYCLE
        };
        // Match PipelineFixture::traversal's observation bound. A replay can
        // retire a generation for clean followup without reaching a terminal.
        for number in 0..PIPELINE_MAX_PAGES {
            let at = format!("2026-08-02T{hour:02}:{number:02}:00Z");
            let before = census_pre_hold_bodies(&fixture, &at, &cycle);
            let page = fixture.page(&at, &cycle, PipelineUpload::Accept);
            assert_eq!(before.discovered, page.scan.discovered_file_count);
            assert_eq!(before.scanned, page.scan.scanned_file_count);
            assert_eq!(before.complete, page.scan.census_complete);
            assert_eq!(
                before.held, page.held,
                "preview observes the actual hold set"
            );
            assert_eq!(before.uploadable, census_body_facts(&page.scan.snapshots));
            let held = before
                .offered
                .iter()
                .filter(|(fingerprint, _)| before.held.contains(fingerprint))
                .cloned()
                .collect::<Vec<_>>();
            held_bodies += held.len();
            reset_owed_members += before.reset_owed_members;
            facts.push(serde_json::json!({
                "offered": before.offered, "held_bodies": held,
                "reset_owed_members": before.reset_owed_members,
                "page": census_parity_page_facts(&fixture, &page),
            }));
            if page.scan.census_complete {
                break;
            }
        }
    }
    (facts, held_bodies, reset_owed_members)
}

/// Compare every candidate body before hold filtering, including candidates
/// absent from the returned PipelinePage and its committed body witnesses.
#[test]
#[serial(source_manifests)]
fn census_every_offered_and_held_body_matches_control() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // Pre-E2 invariant: E2 reads census records as copy-holder evidence.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (records, records_held, records_reset_owed) =
        census_pre_hold_parity_arm("census-all-bodies-records", true);
    let (control, control_held, control_reset_owed) =
        census_pre_hold_parity_arm("census-all-bodies-control", false);
    assert!(
        records_held > 0,
        "the proof must observe actual held bodies"
    );
    assert_eq!(records_held, control_held);
    assert!(
        records_reset_owed > 0,
        "the actual reset preserved nonempty correction debt"
    );
    assert_eq!(records_reset_owed, control_reset_owed);
    assert_eq!(records, control);
}
