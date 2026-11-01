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
    let mut progress = e2_progress();
    let (status, _, _) = upload(&page.scan.snapshots, &mut progress, ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let acks = std::mem::take(&mut progress.fresh_context_body_acks);
    accept_upload_context_acks_for_test(&mut page.index, &page.scan.snapshots, &acks);
    acks
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
        let (scanner, prior) = warm_claude(&c, &disk);
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
        // read on the next pages. The warm page was never delivered, so the
        // unchanged holder owes its proof here, as a production file without
        // a receipt does: the page that re-reads it must offer its identical
        // bodies and earn the receipt, or it is re-read on every page.
        let acks = deliver(&mut first);
        if let Some(why) = upload_context_owed_diagnosis_for_test(
            &first.index,
            &holder,
            &first.scan.snapshots,
            &acks,
        ) {
            panic!(
                "the re-read holder still owes its proof (modes {:?}): {why}",
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
