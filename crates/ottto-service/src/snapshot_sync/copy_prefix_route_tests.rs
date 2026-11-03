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
fn deliver(page: &mut Page) {
    deliver_counting(page);
}

/// `deliver`, also returning the page's POST count.
fn deliver_counting(page: &mut Page) -> usize {
    let mut progress = e2_progress();
    let (status, sent, _) = upload(&page.scan.snapshots, &mut progress, ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let acks = std::mem::take(&mut progress.fresh_context_body_acks);
    accept_upload_context_acks_for_test(&mut page.index, &page.scan.snapshots, &acks);
    sent.len()
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
    assert!(disk.records() > 0, "the warm owner persists its records");
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
/// restart between pages. The delivered holder's accepted body is what lets
/// the prefix go.
#[test]
fn resumed_copy_prefix_dedupe_is_route_equivalent() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("resumed_copy_prefix_dedupe") {
        return;
    }
    with_e2(|| {
        let mut c = corpus("resumed_copy_prefix_dedupe");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        input_clock(&holder);
        let mut disk = Disk::new(&c);
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
        deliver(&mut first);
        assert!(
            !upload_context_owed_for_test(&first.index, &holder),
            "the delivered holder owes its proof (modes {:?})",
            first.modes
        );
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
                assert!(
                    !upload_context_owed_for_test(&prior, &holder),
                    "page {request}: the {arm} prior owes the holder again"
                );
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
/// proof, as a production file without a receipt does. That proof alone
/// selects no read: the holder is never read, stays owed and never becomes an
/// accepted origin (e2.rs `origin_accepted`). The new copy therefore holds its
/// copied prefix for the bounded prefix hold (copy_removals.rs `advance_hold`,
/// `HOLD_PASSES` = 3): page 1 emits only its own turn, page 2 re-parses it
/// from the pending hold (snapshots.rs `claude_copy_removals.pending`) with
/// an identical body and no POST, page 3 expires the hold and emits the
/// restored prefix once (e2.rs `defer_prefix`), and page 4 is quiet. The
/// never-delivered holder's requests are counted once, in the copy.
#[test]
fn never_delivered_holder_is_never_read_and_the_copy_hold_expires_once() {
    // As every owner of this harness: commits persist durable records.
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
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
        let mut copy_requests = Vec::new();
        for page in 1..=4 {
            disk.begin(&scanner, SnapshotSource::ClaudeCode);
            let mut p = c.raw(&scanner, prior, 100, true, &[]);
            p.enrich(&c);
            p.finish();
            reads.push(opened(&scanner, &holder));
            copy_requests.push(
                p.scan
                    .snapshots
                    .iter()
                    .find(|item| item.source_session_id == COPY)
                    .map(|item| item.request_count),
            );
            posts.push(deliver_counting(&mut p));
            assert!(
                upload_context_owed_for_test(&p.index, &holder),
                "page {page}: the holder's proof stays owed, paid by its next read"
            );
            prior = disk.commit(&p.cache, SnapshotSource::ClaudeCode, &mut p.index);
        }
        assert_eq!(reads, [false; 4], "the owed holder is never read");
        assert_eq!(
            (posts.as_slice(), copy_requests.as_slice()),
            (&[1_usize, 0, 1, 0][..], &[Some(1), None, Some(3), None][..]),
            "own turn, held, expired prefix once, quiet"
        );
    });
}

/// [regress] The server's head already covers the origin (changed there, by an
/// operator admission): its answer settles no body, so the daemon keeps a learned
/// head but no receipt or stamp. That is no acceptance: the copy keeps the prefix.
#[test]
fn server_learned_head_is_not_an_accepted_origin() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("server_learned_head_origin") {
        return;
    }
    with_e2(|| {
        let mut c = corpus("server_learned_head_origin");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        input_clock(&holder);
        let disk = Disk::new(&c);
        let scanner = E2ScanFixture::default();
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let mut warm = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
        warm.enrich(&c);
        warm.finish();
        let mut progress = e2_progress();
        let (status, _, _) = upload(&warm.scan.snapshots, &mut progress, |batch| {
            let mut response = ack(batch)?;
            for mut entity in std::mem::take(&mut response.accepted_entities) {
                entity.unchanged_basis = Some("usage_identical".into());
                if entity.head_etag.is_some() {
                    entity.head_etag = Some("3".repeat(64));
                }
                response.unchanged_entities.push(entity);
            }
            Ok(response)
        });
        assert!(status.is_ok());
        assert!(progress.fresh_context_body_acks.is_empty());
        assert!(progress.accepted_body_contexts.is_empty());
        let acks = std::mem::take(&mut progress.fresh_context_body_acks);
        accept_upload_context_acks_for_test(&mut warm.index, &warm.scan.snapshots, &acks);
        assert!(!upload_context_receipt_earned_for_test(
            &warm.index,
            &holder
        ));
        let prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);

        let path = c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        input_clock(&path);
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let mut page = c.raw(&scanner, prior, 100, true, &[]);
        page.enrich(&c);
        page.finish();
        let copy = body(&page, COPY).expect("the copy's own turn publishes");
        assert_eq!(
            copy.request_count, 1,
            "only its own turn, while the prefix waits"
        );
        assert_eq!(copy.removed_request_count.unwrap_or(0), 0);
    });
}
