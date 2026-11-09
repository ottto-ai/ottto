//! Evidence chunks: a page's families run through the evidence body in packed
//! chunks, with the rows of one chunk resident at a time.
use super::*;

impl StreamedChecks {
    /// One enrichment against both references: the whole-corpus fold, then
    /// the page as one evidence chunk (reads not compared: a scope root two
    /// chunks name is decoded by each; only the chunk counters move).
    pub(super) fn compare_references(
        &mut self,
        terminal: bool,
        [whole, one]: [ComparedSide<'_>; 2],
        packed: ComparedSide<'_>,
        chunks: usize,
    ) {
        let context_only = CONTEXT_ONLY.with(|diverged| diverged.get().is_some());
        self.compare_reference(terminal, context_only, whole, packed);
        let counted = *self;
        self.compare_reference(terminal, context_only, one, packed);
        *self = Self {
            chunked: counted.chunked + usize::from(chunks > 1),
            max_chunks: counted.max_chunks.max(chunks),
            ..counted
        };
    }

    fn compare_reference(
        &mut self,
        terminal: bool,
        context_only: bool,
        reference: ComparedSide<'_>,
        packed: ComparedSide<'_>,
    ) {
        if context_only {
            self.compare_context_only(terminal, reference, packed);
        } else {
            self.compare(terminal, reference, packed);
        }
    }

    /// The expected multi-root difference: ROOT's body may differ in its
    /// context posture only (`CONTEXT_FIELDS`); with that posture (and the
    /// exact-body binding of its admitted request identity) made equal,
    /// bodies, holds, accepted buckets, wire bytes, totals, placement, the
    /// post-ACK ledger and re-emission are equal.
    fn compare_context_only(
        &mut self,
        terminal: bool,
        reference: ComparedSide<'_>,
        packed: ComparedSide<'_>,
    ) {
        use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode};
        let ((reference, reference_accepted, _), (packed, accepted, _)) = (reference, packed);
        let sessions = |page: &Page| {
            (page.scan.snapshots.iter())
                .map(|item| item.source_session_id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(sessions(reference), sessions(packed), "the same bodies");
        let mut neutral = twin(reference);
        for (item, packed) in neutral
            .scan
            .snapshots
            .iter_mut()
            .zip(&packed.scan.snapshots)
        {
            let mut differences = Vec::new();
            money_oracle::diff(
                "",
                &serde_json::to_value(&*item).unwrap(),
                &serde_json::to_value(packed).unwrap(),
                &mut differences,
            );
            let paths = (differences.iter())
                .filter_map(|difference| difference.split_once(": "))
                .map(|(path, _)| path)
                .collect::<BTreeSet<_>>();
            assert!(
                paths.iter().all(|path| CONTEXT_FIELDS.contains(path)),
                "{}: only the context posture may differ: {differences:?}",
                item.source_session_id
            );
            if !paths.is_empty() {
                assert_eq!(item.source_session_id, ROOT, "only ROOT's posture differs");
                CONTEXT_ONLY.with(|diverged| diverged.set(diverged.get().map(|n| n + 1)));
                match_context_posture(item, packed);
                // The admitted request identity binds the exact body.
                neutral
                    .disposition
                    .mixed_uploads
                    .admit_request_identity(item);
            }
        }
        assert_eq!(
            canonical(&neutral.scan.snapshots),
            canonical(&packed.scan.snapshots),
            "bodies, posture matched"
        );
        assert_eq!(reference.scan.census_complete, packed.scan.census_complete);
        let holds = |page: &Page| {
            let mut disposition = page.disposition.clone();
            disposition.context_file_birth = Default::default();
            disposition
        };
        assert_eq!(holds(&neutral), holds(packed), "holds");
        assert_eq!(reference_accepted, accepted, "accepted buckets");
        let carried = [reference, packed].map(|page| carried_forward(&page.scan.snapshots));
        assert_eq!(carried[0], carried[1], "carried accounts");
        let [cold, route] =
            [(&neutral, Mode::ColdFull), (packed, Mode::Ram)].map(|(page, mode)| acked(page, mode));
        assert_eq!(
            cold.as_ref().map(|route| &route.batches),
            route.as_ref().map(|route| &route.batches),
            "wire bytes"
        );
        if let (Some(cold), Some(route)) = (cold, route) {
            if !cold.snapshots.is_empty() {
                money_oracle::assert_equivalent(&cold, &route);
                money_oracle::assert_no_smaller_reemit(ROOT, &cold, &route, &cold, false);
                if terminal {
                    self.terminal += 1;
                } else {
                    self.non_terminal += 1;
                }
            }
        }
    }
}

thread_local! {
    /// `Some(count)` while a test expects the multi-root context difference:
    /// the bodies it was seen in.
    static CONTEXT_ONLY: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// The body fields (as `money_oracle::diff` paths) a request id reported by
/// two families' side files can change: one pass over the page sees both
/// owners and withholds ROOT's context posture; a chunk sees one and admits
/// it. Seventeen posture fields and the fingerprint.
const CONTEXT_FIELDS: &[&str] = &[
    "/cache_observations",
    "/compaction_count",
    "/first_own_request_at",
    "/first_turn_context_tokens",
    "/last_turn_context_tokens",
    "/peak_context_fill_tokens",
    "/session_start/first_request_cache_read_tokens",
    "/session_start/first_request_cache_write_1h_tokens",
    "/session_start/first_request_cache_write_5m_tokens",
    "/session_start/first_request_uncached_input_tokens",
    "/session_start/opening_file_overflow",
    "/session_start/opening_output_tokens",
    "/session_start/opening_request_count",
    "/session_start/opening_tool_calls",
    "/session_start/opening_truncated_outputs",
    "/session_start/request_2_context_tokens",
    "/session_start/request_3_context_tokens",
    "/snapshot_fingerprint",
];

/// Gives `item` the context posture (and its local inputs) of `from`.
fn match_context_posture(item: &mut SnapshotItem, from: &SnapshotItem) {
    item.claude_file_birth_verdict = from.claude_file_birth_verdict;
    item.session_start = from.session_start.clone();
    item.peak_context_fill_tokens = from.peak_context_fill_tokens;
    item.first_turn_context_tokens = from.first_turn_context_tokens;
    item.last_turn_context_tokens = from.last_turn_context_tokens;
    item.compaction_count = from.compaction_count;
    item.compaction_timestamps = from.compaction_timestamps.clone();
    item.compaction_events = from.compaction_events.clone();
    item.first_own_request_at = from.first_own_request_at.clone();
    item.local_context_points = from.local_context_points.clone();
    item.compaction_total_pre_tokens = from.compaction_total_pre_tokens;
    item.compaction_total_post_tokens = from.compaction_total_post_tokens;
    item.compaction_total_cumulative_dropped_tokens =
        from.compaction_total_cumulative_dropped_tokens;
    item.compaction_total_duration_ms = from.compaction_total_duration_ms;
    item.cache_observations = from.cache_observations.clone();
    item.cache_observations_state = from.cache_observations_state.clone();
    item.snapshot_fingerprint = from.snapshot_fingerprint.clone();
}

/// The finished page uploaded and ACKed, with the accepted ledger observed;
/// `None` when the upload does not complete.
fn acked(
    page: &Page,
    mode: crate::snapshots::sampled_scan::transition_fixture::Mode,
) -> Option<crate::snapshots::sampled_scan::transition_fixture::RouteResult> {
    let mut sent = twin(page);
    sent.finish();
    let mut progress = e2_progress();
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let (status, batches, _) = upload(&sent.scan.snapshots, &mut progress, ack);
    if !matches!(status, Ok(ResumableUploadResult::Completed)) {
        return None;
    }
    let mut route = crate::snapshots::sampled_scan::transition_fixture::RouteResult::emitted(
        mode,
        SnapshotSource::ClaudeCode,
        batches,
        &sent.scan.snapshots,
    );
    route.accepted_identity_buckets = Some(
        serde_json::to_value(
            (sent.scan.snapshots.iter())
                .map(|item| {
                    let id = &item.source_session_id;
                    (id, progress.accepted_identity_buckets.get(id))
                })
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap(),
    );
    Some(route)
}

/// Runs a reference arm leaving this thread's remembered tripwire vetoes and
/// reemission latch as they were, so the compared fold starts from the same
/// process state.
pub(super) fn isolated<T>(f: impl FnOnce() -> T) -> T {
    crate::snapshots::with_remembered_tripwire_restored_for_test(|| {
        crate::snapshots::with_claude_reemission_stop_restored_for_test(f)
    })
}

const BIG: &str = "6338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const SMALL: &str = "7338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const SMALLER: &str = "8338a80a-f36e-4cbc-a5bb-50fc66430ba5";

/// Three unrelated roots on one page: BIG with six paired requests, SMALL and
/// SMALLER with two each. Returns the corpus and its scanner.
fn three_family_page(name: &str) -> (Corpus, E2ScanFixture) {
    let mut c = Corpus::new(name);
    for (session, requests) in [(BIG, 6), (SMALL, 2), (SMALLER, 2)] {
        let ids = (0..requests)
            .map(|at| format!("{}-{at}", &session[..4]))
            .collect::<Vec<_>>();
        c.root(
            session,
            &ids.iter()
                .map(|id| line(session, id, AT, 10))
                .collect::<String>(),
        );
        c.evidence_for(
            session,
            &ids.iter()
                .map(|id| api_for(session, id, 10, 100))
                .collect::<Vec<_>>(),
            &ids.iter()
                .map(|id| trace_for(session, id, ""))
                .collect::<Vec<_>>(),
        );
    }
    (c, E2ScanFixture::default())
}

/// [behaviour] The evidence stage holds one chunk of whole families' rows at a
/// time, not the page's: on a page of three unrelated roots the most rows any
/// evidence read keeps is the largest family's (BIG: 6 API + 6 trace rows),
/// and every root's rows are still read once. Each read reports its chunk's
/// families and side-file bytes.
#[test]
fn evidence_keeps_the_largest_group_not_the_page() {
    with_e2(|| {
        let (c, scanner) = three_family_page("e2-evidence-largest-group");
        let mut page = c.raw(&scanner, ScanIndex::default(), 100, false, &[]);
        assert_eq!(
            page.scan.snapshots.len(),
            3,
            "one page holds all three roots"
        );
        let (_, records) = crate::local_resource_diagnostics::capture(|| page.enrich(&c));
        let reads = records
            .iter()
            .filter(|record| record["stage"] == "evidence_read")
            .map(|record| &record["counts"]["evidence_mem"])
            .collect::<Vec<_>>();
        let kept = reads
            .iter()
            .map(|mem| mem["kept_rows"].as_u64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            kept.iter().sum::<u64>(),
            20,
            "every root's rows, once: {kept:?}"
        );
        assert_eq!(
            kept.iter().max(),
            Some(&12),
            "the most rows kept at once is the largest family's, not the page sum: {kept:?}"
        );
        let largest = reads.iter().find(|mem| mem["kept_rows"] == 12).unwrap();
        assert_eq!(largest["groups"], 1, "the largest family runs alone");
        assert_eq!(
            reads
                .iter()
                .map(|mem| mem["groups"].as_u64().unwrap())
                .sum::<u64>(),
            3,
            "each family runs in one chunk"
        );
        let batch = largest["side_file_bytes"].as_u64().unwrap();
        assert!(
            (reads.iter()).all(|mem| mem["side_file_bytes"].as_u64().unwrap() <= batch),
            "the largest family's bytes are the batch size"
        );
        assert_eq!(page.stats.api_evidence_row_count, 10);
        assert_eq!(page.stats.trace_evidence_row_count, 10);
        assert_eq!(page.stats.complete_sidecar_root_count, 3);
    });
}

/// The three-family page swept to a terminal census. Its first page is a
/// real next-fit boundary: BIG alone, then SMALL and SMALLER together.
fn three_family_sweep() {
    with_e2(|| {
        let (c, scanner) = three_family_page("e2-chunked-three-families");
        let mut index = ScanIndex::default();
        for pass in 0..6 {
            let before = crate::snapshot_sync::evidence_chunks_for_test();
            let mut page = c.raw(&scanner, index, 100, true, &[]);
            let families = page.scan.snapshots.len();
            page.enrich(&c);
            if pass == 0 {
                assert_eq!(families, 3, "one page holds all three roots");
                assert_eq!(
                    crate::snapshot_sync::evidence_chunks_for_test() - before,
                    2,
                    "three families pack into two chunks"
                );
            }
            page.finish();
            index = c.reload(&mut page.index);
            if page.scan.census_complete {
                break;
            }
        }
    });
}

/// Path twins of ROOT with another family's file between them in page
/// order: the twins share a chunk, the other family runs in the next one,
/// and the emitted body goes back to the first twin's slot.
fn twins_beside_another_family() {
    with_e2(|| {
        let mut c = Corpus::new("e2-chunked-twins-interleaved");
        c.write_at(
            &format!("a-original/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("m-other/{BIG}.jsonl"),
            &(line(BIG, "other-1", AT, 10) + &line(BIG, "other-2", AT, 10)),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("z-copy/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-11-04T07:03:10Z", 20)),
            "2026-11-04T07:03:00Z",
        );
        c.evidence(
            &[api("r1", 10, 100), api("r2", 20, 200)],
            &[trace("r1", ""), trace("r2", "")],
        );
        c.evidence_for(
            BIG,
            &[
                api_for(BIG, "other-1", 10, 100),
                api_for(BIG, "other-2", 10, 100),
            ],
            &[trace_for(BIG, "other-1", ""), trace_for(BIG, "other-2", "")],
        );
        let scanner = E2ScanFixture::default();
        let before = crate::snapshot_sync::evidence_chunks_for_test();
        let mut page = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(scanner.paths().len(), 3, "every file was opened");
        assert_eq!(
            crate::snapshot_sync::evidence_chunks_for_test() - before,
            2,
            "the twins' family and the other family run as two chunks"
        );
        let sessions = page
            .scan
            .snapshots
            .iter()
            .map(|item| item.source_session_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(sessions, [ROOT, BIG], "one body per session, in page order");
        page.finish();
    });
}

/// [money] Packing a page's families into evidence chunks emits exactly what
/// the page as one chunk emits, and what a fold keeping every root's rows
/// emits (all `StreamedChecks`), on non-terminal and terminal passes: a real
/// next-fit boundary, the five streamed-sweep roots on one page and three per
/// page, and path twins interleaved with another family. The multi-root sweep
/// has its own regression below.
#[test]
fn chunked_evidence_equals_one_chunk() {
    let checks = streamed_checks(|| {
        three_family_sweep();
        five_root_sweep_paged(false, 5);
        five_root_sweep_paged(false, 3);
        twins_beside_another_family();
    });
    assert!(
        checks.chunked > 0
            && checks.max_chunks >= 2
            && checks.non_terminal > 0
            && checks.terminal > 0,
        "the arm must compare packed pages on non-terminal and terminal passes: {checks:?}"
    );
}

/// [money] Regression for the multi-root sweep on one page (a request id two
/// families' side files report; local data has none). Packed chunks and the
/// page as one chunk (and the whole-corpus fold) differ only in ROOT's
/// context posture; with it matched, bodies, holds, accepted buckets, wire
/// bytes, totals, placement, the post-ACK ledger and re-emission are equal on
/// every pass, non-terminal and terminal, across the fixture's store reloads.
#[test]
fn multi_root_ids_change_only_the_context_posture() {
    CONTEXT_ONLY.with(|diverged| diverged.set(Some(0)));
    let checks = streamed_checks(|| five_root_sweep_paged(true, 5));
    let diverged = CONTEXT_ONLY.with(std::cell::Cell::take);
    assert!(
        diverged.is_some_and(|bodies| bodies > 0),
        "the observed posture difference is reproduced: {diverged:?}"
    );
    assert!(
        checks.chunked > 0 && checks.non_terminal > 0 && checks.terminal > 0,
        "packed pages compared on non-terminal and terminal passes: {checks:?}"
    );
}
