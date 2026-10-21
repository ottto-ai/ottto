// StateMissing characterization baselines through the bounded Claude pipeline.
// Each test asserts TODAY's behavior, which is the defect, so it passes on
// main; the assertions a fix flips are marked `FLIPS`. Every other assertion
// is a precondition or an invariant that must keep holding after the fix.
// Fixtures are the stable-proof re-arm and census-convergence pipeline
// fixtures, unchanged; nothing here edits a clock, witness or index by hand.
// Each test writes one count-only `STATEMISSING_BASELINE` line to stderr.

use super::*;

/// Exact bytes of every family member transcript, by member session.
fn statemissing_family_bytes(fixture: &RearmFixture) -> BTreeMap<String, Vec<u8>> {
    std::iter::once(None)
        .chain(REARM_AGENTS.iter().map(|agent| Some(*agent)))
        .map(|agent| {
            (
                rearm_member_session(agent),
                std::fs::read(fixture.member_path(agent)).expect("read family member transcript"),
            )
        })
        .collect()
}

/// Defect: the terminal proof-candidate re-arm (`snapshots.rs`, the
/// `proof_candidate` disjunct of the census re-arm) clears every earlier-page
/// member of a proven Claude family at EVERY healthy terminal, with no
/// witness-changed condition. Two consecutive healthy windows with no file
/// change and an unchanged proof therefore end with all three members
/// re-armed, and each next window re-reads all three only to find a semantic
/// no-op: nothing is offered and every accepted head is unchanged.
///
/// Expected after the fix: an unchanged proof whose bodies were already
/// accepted re-arms nothing, so these windows end with zero re-arm debt and
/// the windows after them read zero files. A changed witness must still
/// re-arm (control: `statemissing_baseline_changed_witness_still_rearms_
/// earlier_page_member` in `snapshots/statemissing_baseline_fold_tests.rs`;
/// the first proof's re-arm is asserted by `RearmFixture::establish`).
#[test]
#[serial(source_manifests)]
fn statemissing_baseline_unchanged_proof_rearms_family_at_every_healthy_terminal() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = RearmFixture::new("statemissing-baseline-proof-loop");
    let family = rearm_family_sessions();
    // Hour 8 proves the family on its terminal page; hour 9 rebuilds and
    // delivers every member from that proof (asserted by `establish`).
    let established = fixture.establish();
    let rebuilt = ScanIndex::load(&fixture.index_path).expect("load the rebuilt index");
    let proof = rebuilt
        .claude_usage_family_witness_digest_for_test(REARM_ROOT)
        .expect("the healthy terminal retains the family proof");
    let bytes = statemissing_family_bytes(&fixture);
    // FLIPS: hour 9 is the first healthy window with no file change and the
    // same proof, and it still re-arms every earlier-page member.
    assert_eq!(RearmFixture::family_rearm_debt(&rebuilt), family.len());

    let mut reads = Vec::new();
    let mut noops = Vec::new();
    let mut debts = Vec::new();
    for hour in [10, 11] {
        let pages = fixture.generation(hour);
        let last = pages.last().expect("terminal page");
        // Preconditions: a complete, healthy, settled window with no file
        // change and no hold, under the same proof, whose family members all
        // sit on earlier pages than the terminal one.
        assert_eq!(
            statemissing_family_bytes(&fixture),
            bytes,
            "hour {hour}: no member transcript changed"
        );
        assert!(last.scan.census_complete, "hour {hour}");
        assert!(last.fully_settled, "hour {hour}");
        assert!(pages.iter().all(|page| page.held.is_empty()), "hour {hour}");
        assert!(last.duplicate_census.census_complete, "hour {hour}");
        assert!(!last.duplicate_census.census_invalid, "hour {hour}");
        assert!(
            last.parsed.is_disjoint(&family),
            "hour {hour}: no family member is parsed on the terminal page"
        );
        assert_eq!(
            last.index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .as_deref(),
            Some(proof.as_str()),
            "hour {hour}: the family proof is unchanged"
        );
        assert_eq!(
            RearmFixture::family_heads(&last.index),
            established.heads,
            "hour {hour}: every accepted head is unchanged"
        );
        // The re-read is a semantic no-op: every member reparses to its
        // accepted body, so the finalizer drops it and nothing is offered.
        assert_eq!(rearm_parsed(&pages), family, "hour {hour}");
        assert!(
            pages.iter().all(|page| page.offered.is_empty()),
            "hour {hour}: nothing is offered"
        );
        let window_noops = pages
            .iter()
            .map(|page| page.scan.semantic_noop_count)
            .sum::<usize>();
        assert_eq!(window_noops, family.len(), "hour {hour}");
        // FLIPS: today the window re-reads every member and its terminal
        // re-arms every member again.
        let window_reads = rearm_reads(&pages);
        let window_debt = RearmFixture::family_rearm_debt(&last.index);
        assert_eq!(window_reads, family.len(), "hour {hour}");
        assert_eq!(window_debt, family.len(), "hour {hour}");
        reads.push(window_reads);
        noops.push(window_noops);
        debts.push(window_debt);
    }
    eprintln!(
        "STATEMISSING_BASELINE test=T1_proof_candidate_rearm hour9_debt={} reads_per_unchanged_window={reads:?} semantic_noops_per_window={noops:?} terminal_debt_per_window={debts:?} offered=0 proof_unchanged=true",
        RearmFixture::family_rearm_debt(&rebuilt)
    );
}

const STATEMISSING_RETRY_CYCLE: PipelineCycle<'static> = PipelineCycle {
    upload_context: "upload-context-1",
    replay_generation: "replay-generation-1",
    proven_owner_session: Some(PIPELINE_HELD_SESSION),
    first_page_upload: PipelineUpload::Accept,
    historical_replay: false,
};
/// The window's terminal page clock, 2026-08-02T09:01:00Z, plus the first
/// unhealthy retry delay (60 s).
const STATEMISSING_RETRY_DEADLINE: u64 = 1_785_661_260 + 60;

/// One census window after the baseline, then the next traversal start.
struct StatemissingRetry {
    baseline: ScanIndex,
    window: Vec<PipelinePage>,
    retry: Vec<PipelinePage>,
    changed_key: String,
    unaffected_key: String,
}

fn statemissing_parsed_keys(pages: &[PipelinePage]) -> BTreeSet<String> {
    pages
        .iter()
        .flat_map(|page| page.scan.completed_parses().map(|(key, _)| key.to_string()))
        .collect()
}

/// Family roles over the census-convergence fixture, whose three single-file
/// families have no local reports, so no proof re-arm runs: `changed` gets
/// one appended request before the window, `unaffected` stays unchanged, and
/// `unrelated` is optionally deleted after the window's first page walked
/// and queued it. Its second page then meets it as NotFound.
fn statemissing_unrelated_disappearance(name: &str, delete_unrelated: bool) -> StatemissingRetry {
    let [changed, unaffected, unrelated] = PIPELINE_SESSIONS;
    let fixture = PipelineFixture::new(name);
    let baseline = fixture.baseline();
    let changed_key = PipelineFixture::key(&baseline, changed);
    let unaffected_key = PipelineFixture::key(&baseline, unaffected);
    fixture.append(changed, "req_0_2");
    let mut window = vec![fixture.page(
        "2026-08-02T09:00:00Z",
        &STATEMISSING_RETRY_CYCLE,
        PipelineUpload::Accept,
    )];
    if delete_unrelated {
        std::fs::remove_file(fixture.root.join(format!("{unrelated}.jsonl")))
            .expect("delete the unrelated transcript after it was queued");
    }
    window.push(fixture.page(
        "2026-08-02T09:01:00Z",
        &STATEMISSING_RETRY_CYCLE,
        PipelineUpload::Accept,
    ));
    let mut retry = Vec::new();
    for minute in 3..3 + PIPELINE_MAX_PAGES {
        let page = fixture.page(
            &format!("2026-08-02T09:{minute:02}:00Z"),
            &STATEMISSING_RETRY_CYCLE,
            PipelineUpload::Accept,
        );
        let complete = page.scan.census_complete;
        retry.push(page);
        if complete {
            break;
        }
    }
    StatemissingRetry {
        baseline,
        window,
        retry,
        changed_key,
        unaffected_key,
    }
}

/// Shared preconditions: the window's first page read only the changed
/// family; nothing else changed; and the next traversal completes healthy.
fn statemissing_assert_retry_preconditions(run: &StatemissingRetry) {
    let first = &run.window[0];
    assert!(!first.scan.census_complete);
    assert_eq!(
        statemissing_parsed_keys(std::slice::from_ref(first)),
        BTreeSet::from([run.changed_key.clone()]),
        "the window reads only the changed family"
    );
    assert_ne!(
        first.index.files[&run.changed_key].source_file_fingerprint,
        run.baseline.files[&run.changed_key].source_file_fingerprint
    );
    let retried = run.retry.last().expect("retry page");
    assert!(
        retried.scan.census_complete,
        "the next traversal completes healthy"
    );
    for page in &run.retry {
        assert!(page.held.is_empty());
        assert!(
            page.uploaded.is_empty(),
            "the next traversal offers nothing"
        );
    }
    // Non-affected family: exact revision and accepted entities throughout,
    // and never reparsed.
    for page in run.window.iter().chain(&run.retry) {
        assert_eq!(
            page.index.files[&run.unaffected_key].source_file_fingerprint,
            run.baseline.files[&run.unaffected_key].source_file_fingerprint
        );
        assert_eq!(
            page.index.file_snapshot_fingerprints[&run.unaffected_key],
            run.baseline.file_snapshot_fingerprints[&run.unaffected_key]
        );
    }
    assert!(!statemissing_parsed_keys(&run.window).contains(&run.unaffected_key));
    assert!(!statemissing_parsed_keys(&run.retry).contains(&run.unaffected_key));
    // The changed family keeps the revision its window parsed.
    assert_eq!(
        retried.index.files[&run.changed_key].source_file_fingerprint,
        first.index.files[&run.changed_key].source_file_fingerprint
    );
}

/// Defect: one unrelated file that is walked and then deleted before it is
/// opened counts as disappeared and turns the whole Claude traversal red.
/// Census-window pending then never retires, and the next traversal start
/// (`ensure_bounded_traversal`, the stale-pending re-arm) clears the revision
/// of every family parsed in that red window. Here that is the changed
/// family, which did not change again: the next traversal re-reads it only to
/// find a semantic no-op, while the non-affected family keeps its exact
/// revision and is not read. The fixture has no shared cache, so the re-read
/// is an unsampled native full parse; in the daemon a saturated or wiped
/// cache makes it `Full(StateMissing)` (see T3).
///
/// Expected after the fix: an unrelated disappearance re-arms no unchanged
/// family, so the next traversal reads zero files, as the healthy control
/// `statemissing_baseline_healthy_window_rearms_no_family_at_next_start`
/// does today.
#[test]
#[serial(source_manifests)]
fn statemissing_baseline_unrelated_disappearance_rearms_unchanged_family_at_retry() {
    let _source_manifests = SourceManifestTestGuard::new();
    let run =
        statemissing_unrelated_disappearance("statemissing-baseline-unrelated-disappearance", true);
    statemissing_assert_retry_preconditions(&run);
    let red = &run.window[1];
    // Preconditions: the deletion alone made the terminal red, and the red
    // witness and the window's pending survive it.
    assert_eq!(red.scan.disappeared_file_count, 1);
    assert_eq!(red.scan.scanned_file_count, 0);
    assert!(!red.scan.census_complete);
    assert!(red.index.scan_traversal_in_progress_for_test());
    let saved = serde_json::to_value(&red.index).expect("encode the red index");
    assert_eq!(saved["traversal"]["unhealthy_retry_attempt"], 1);
    assert_eq!(
        saved["traversal"]["unhealthy_retry_not_before_unix_seconds"],
        STATEMISSING_RETRY_DEADLINE
    );
    let pending = saved["claude_usage_family_pending"]
        .as_object()
        .expect("the red window keeps its family pending");
    assert_eq!(
        pending.keys().cloned().collect::<Vec<_>>(),
        vec![PIPELINE_SESSIONS[0].to_string()],
        "only the family parsed in the red window is pending"
    );
    assert_eq!(
        pending[PIPELINE_SESSIONS[0]]["census_window_end"],
        run.window[0].scan.census_window_end.as_str()
    );
    assert_eq!(pending[PIPELINE_SESSIONS[0]]["invalid"], false);
    // The first retry page starts after the deadline.
    assert_ne!(
        run.retry[0].scan.census_window_end,
        run.window[0].scan.census_window_end
    );

    // FLIPS: the next traversal start re-arms the unchanged family, which is
    // re-read as a semantic no-op.
    let reread = statemissing_parsed_keys(&run.retry);
    let reads = run
        .retry
        .iter()
        .map(|page| page.scan.scanned_file_count)
        .sum::<usize>();
    let noops = run
        .retry
        .iter()
        .map(|page| page.scan.semantic_noop_count)
        .sum::<usize>();
    assert_eq!(reread, BTreeSet::from([run.changed_key.clone()]));
    assert_eq!(reads, 1);
    assert_eq!(noops, 1);
    eprintln!(
        "STATEMISSING_BASELINE test=T2_unrelated_disappearance arm=deleted window_disappeared={} window_red=true pending_families={} retry_attempt=1 retry_reads={reads} retry_semantic_noops={noops} unaffected_reads=0 unaffected_revision_unchanged=true",
        red.scan.disappeared_file_count,
        pending.len()
    );
}

/// Control for the unrelated-disappearance baseline: the same window without
/// the deletion ends healthy and complete, retires its pending, and the next
/// traversal reads nothing. This holds today and after the fix.
#[test]
#[serial(source_manifests)]
fn statemissing_baseline_healthy_window_rearms_no_family_at_next_start() {
    let _source_manifests = SourceManifestTestGuard::new();
    let run = statemissing_unrelated_disappearance("statemissing-baseline-healthy-window", false);
    statemissing_assert_retry_preconditions(&run);
    let terminal = &run.window[1];
    assert_eq!(terminal.scan.disappeared_file_count, 0);
    assert!(terminal.scan.census_complete);
    assert!(!terminal.index.scan_traversal_in_progress_for_test());
    let saved = serde_json::to_value(&terminal.index).expect("encode the settled index");
    assert!(saved.get("claude_usage_family_pending").is_none());
    let reads = run
        .retry
        .iter()
        .map(|page| page.scan.scanned_file_count)
        .sum::<usize>();
    assert!(statemissing_parsed_keys(&run.retry).is_empty());
    assert_eq!(reads, 0);
    eprintln!(
        "STATEMISSING_BASELINE test=T2_unrelated_disappearance arm=control window_disappeared=0 window_red=false retry_reads={reads}"
    );
}
