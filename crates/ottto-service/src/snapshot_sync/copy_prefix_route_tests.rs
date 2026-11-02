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

/// [money] Copy-prefix dedupe through every acquisition route: a resumed main
/// file whose uncertified writer copied an earlier session's requests, with
/// own turns after them. RAM Tail, cold Full and a restored owner remove the
/// same copied prefix and emit the same bodies, totals and placement, with a
/// restart between pages.
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
        let prior = disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);
        let mut priors = [prior.clone(), prior.clone(), prior];
        let mut bodies = Vec::new();
        for (request, at) in [("d", D.1), ("e", "2026-08-02T07:09:10Z")] {
            append(&path, &line_by(COPY, request, at, 10, RESUME_WRITER));
            input_clock(&path);
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
