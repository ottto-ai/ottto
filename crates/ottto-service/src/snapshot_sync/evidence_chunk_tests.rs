//! Evidence chunks: a page's families run through the evidence body in packed
//! chunks, with the rows of one chunk resident at a time.
use super::*;

impl StreamedChecks {
    /// One enrichment: the packed evidence chunks against the page as one
    /// chunk, with the same byte and money checks. A scope root two chunks
    /// name is decoded by each, so reads are not compared, and only the
    /// chunk counters move.
    pub(super) fn compare_chunked(
        &mut self,
        terminal: bool,
        one: ComparedSide<'_>,
        packed: ComparedSide<'_>,
        chunks: usize,
    ) {
        let counted = *self;
        self.compare(terminal, one, packed);
        *self = Self {
            chunked: counted.chunked + usize::from(chunks > 1),
            max_chunks: counted.max_chunks.max(chunks),
            ..counted
        };
    }
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
/// stays out: a request id two roots' side files report is outside the
/// chunked domain (each chunk's tripwire sees only its own rows).
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
