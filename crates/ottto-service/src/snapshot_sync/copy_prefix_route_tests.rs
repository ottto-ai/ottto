// Included inside the money-equivalence fixture for its Disk and page arms.
// Not a cross-build receipt: it prints no MONEY_EQUIVALENCE line.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};

fn route(mode: Mode, page: &Page) -> RouteResult {
    let (status, wire, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let copy = body(page, COPY).expect("the grown resume publishes");
    assert_eq!(copy.removed_request_count, Some(2), "{mode:?}");
    RouteResult::emitted(mode, SnapshotSource::ClaudeCode, wire, &page.scan.snapshots)
}

/// Deliver a finished page: its exact ACKs earn per-file upload-context
/// receipts, as the service records them after settlement.
fn deliver(page: &mut Page) -> BTreeMap<String, String> {
    deliver_counting(page).0
}

/// `deliver`, also returning the page's POST count.
fn deliver_counting(page: &mut Page) -> (BTreeMap<String, String>, usize) {
    let mut progress = e2_progress();
    let (status, sent, _) = upload(&page.scan.snapshots, &mut progress, ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let acks = std::mem::take(&mut progress.fresh_context_body_acks);
    accept_upload_context_acks_for_test(&mut page.index, &page.scan.snapshots, &acks);
    (acks, sent.len())
}

/// The warm owner reads Full, is delivered as the service delivers every
/// page, and commits; its saved index is every arm's prior.
fn warm_delivered(c: &Corpus, disk: &Disk) -> (E2ScanFixture, ScanIndex) {
    let scanner = E2ScanFixture::default();
    disk.begin(&scanner, SnapshotSource::ClaudeCode);
    let mut warm = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
    warm.enrich(c);
    warm.finish();
    deliver(&mut warm);
    let prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);
    (scanner, prior)
}

fn opened(scanner: &E2ScanFixture, path: &Path) -> bool {
    scanner
        .paths()
        .iter()
        .any(|opened| opened.file_name() == path.file_name())
}

/// [money] Copy-prefix dedupe through every acquisition route: a resumed main
/// file whose uncertified writer copied an earlier session's requests, with
/// own turns after them. RAM Tail, cold Full and a restored owner remove the
/// same copied prefix and emit the same bodies, totals and placement, with a
/// restart between pages.
#[test]
fn resumed_copy_prefix_dedupe_is_route_equivalent() {
    if !supported("resumed_copy_prefix_dedupe") {
        return;
    }
    with_e2(|| {
        let mut c = corpus("resumed_copy_prefix_dedupe");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        input_clock(&holder);
        let disk = Disk::new(&c);
        let (scanner, prior) = warm_delivered(&c, &disk);
        let path = c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        input_clock(&path);
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let mut first = c.raw(&scanner, prior, 100, true, &[]);
        first.enrich(&c);
        first.finish();
        let copy = body(&first, COPY).expect("the resumed file publishes");
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (1, Some(2))
        );
        // The page is delivered: its exact ACKs earn per-file upload-context
        // receipts as the service records them, so only the grown copy is
        // read on the next pages; the delivered holder stays proven.
        let acks = deliver(&mut first);
        if let Some(why) = upload_context_owed_diagnosis_for_test(
            &first.index,
            &holder,
            &first.scan.snapshots,
            &acks,
        ) {
            panic!(
                "the delivered holder owes its proof (modes {:?}): {why}",
                first.modes
            );
        }
        let prior = disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);
        let mut priors = [prior.clone(), prior.clone(), prior];
        let mut bodies = Vec::new();
        for (request, at) in [("d", D.1), ("e", "2026-08-02T07:09:10Z")] {
            append(&path, &line_by(COPY, request, at, 10, RESUME_WRITER));
            input_clock(&path);
            for (arm, prior) in ["ram", "cold", "disk"].iter().zip(&priors) {
                // The page activates the same context before it selects.
                let mut prior = prior.clone();
                prior.activate_upload_context("e2-synthetic-destination".into());
                if let Some(why) =
                    upload_context_owed_diagnosis_for_test(&prior, &holder, &[], &BTreeMap::new())
                {
                    panic!("page {request}: the {arm} prior owes the holder again: {why}");
                }
            }
            let restart = disk.owner(SnapshotSource::ClaudeCode);
            let mut pages = claude_pages(&c, &scanner, &restart, priors, (0, 1, 0), (0, 1, 0));
            finish_claude_pages(&c, &mut pages);
            bodies.push(compare_claude_uploads(&pages));
            let [tail, full, mut disk_page] = pages;
            let cold = route(Mode::ColdFull, &full);
            money_oracle::assert_equivalent(&cold, &route(Mode::Ram, &tail));
            money_oracle::assert_equivalent(&cold, &route(Mode::DiskRestore, &disk_page));
            let next = disk.commit(
                &disk_page.cache,
                SnapshotSource::ClaudeCode,
                &mut disk_page.index,
            );
            priors = [tail.index, full.index, next];
        }
        assert_ne!(bodies[0].raw, bodies[1].raw, "the second page adds money");
    });
}

/// [regress] A holder whose page was never delivered owes its upload-context
/// proof, as a production file without a receipt does. Re-read beside a new
/// copy of its prefix, its identical body is offered and exact-ACKed and it
/// earns its receipt. A family re-arm on that page may clear its revision for
/// one forced reparse, so it is read at most once more; the restored revision
/// lets the receipt prove, and later pages neither read nor POST anything.
#[test]
fn never_delivered_holder_is_read_at_most_once_more_beside_a_new_copy() {
    if !supported("never_delivered_holder_reread_bound") {
        return;
    }
    with_e2(|| {
        let mut c = corpus("never_delivered_holder_reread_bound");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        input_clock(&holder);
        let disk = Disk::new(&c);
        // Committed, never delivered: no receipt.
        let (scanner, mut prior) = warm_claude(&c, &disk);
        let path = c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        input_clock(&path);
        let mut reads = Vec::new();
        let mut posts = Vec::new();
        for page in 1..=4 {
            disk.begin(&scanner, SnapshotSource::ClaudeCode);
            let mut p = c.raw(&scanner, prior, 100, true, &[]);
            p.enrich(&c);
            p.finish();
            reads.push(opened(&scanner, &holder));
            let (_, sent) = deliver_counting(&mut p);
            posts.push(sent);
            if page == 1 {
                assert!(reads[0], "the owed holder is re-read beside the new copy");
                assert!(
                    upload_context_receipt_earned_for_test(&p.index, &holder),
                    "page 1 earns the holder's receipt: {:?}",
                    upload_context_owed_diagnosis_for_test(
                        &p.index,
                        &holder,
                        &p.scan.snapshots,
                        &BTreeMap::new()
                    )
                );
            }
            let diagnosis =
                upload_context_owed_diagnosis_for_test(&p.index, &holder, &[], &BTreeMap::new());
            prior = disk.commit(&p.cache, SnapshotSource::ClaudeCode, &mut p.index);
            if page >= 2 {
                assert!(
                    diagnosis.is_none(),
                    "page {page}: the holder owes its proof again: {diagnosis:?}"
                );
            }
        }
        assert!(
            reads[1..].iter().filter(|read| **read).count() <= 1,
            "the holder is read at most once more after it earns its receipt: {reads:?}"
        );
        assert_eq!(
            (&reads[2..], &posts[2..]),
            (&[false, false][..], &[0_usize, 0][..]),
            "pages 3-4 read and POST nothing (reads {reads:?}, posts {posts:?})"
        );
    });
}
