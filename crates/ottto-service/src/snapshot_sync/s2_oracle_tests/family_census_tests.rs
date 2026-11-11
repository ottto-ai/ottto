//! Fork-first membership through the native pipeline and post-ACK oracle.
use super::*;

fn child() -> String {
    format!("{ROOT}_agent-000")
}
fn only_child(mut p: Page) -> Page {
    p.scan
        .snapshots
        .retain(|item| item.source_session_id == child());
    p
}
fn copied(c: &mut Corpus) -> PathBuf {
    c.agent(
        0,
        &(line(ROOT, "fork", AT, 10) + &line(ROOT, "own", "2026-08-02T07:01:00Z", 20)),
    )
}
fn stale(index: &mut ScanIndex, root: &Path) {
    let key = root.to_string_lossy();
    let record = index
        .claude_request_census
        .get(key.as_ref())
        .unwrap()
        .clone();
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(key.as_ref(), record.with_modified_for_test(Some(1)));
}

/// [money] A stale positive, growing parent, current page and durable restart
/// all remove exactly the same first response. The parent is really off-page.
#[test]
fn stale_parent_positive_survives_growth_current_and_restart() {
    with_e2(|| {
        let mut c = corpus("family-census-stale");
        let root = c.root(ROOT, &line(ROOT, "fork", AT, 10));
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let mut prior = commit(&session, page(&c, index, 100, true));
        stale(&mut prior, &root);
        let child_path = copied(&mut c);
        let scanner = E2ScanFixture::capturing_identity();
        let read = |index| {
            let mut p = c.raw(&scanner, index, 1, true, std::slice::from_ref(&child_path));
            assert!(
                !scanner.paths().contains(&root),
                "root must stay on another page"
            );
            p.enrich(&c);
            let b = body(&p, &child()).expect("child is folded");
            assert_eq!(
                (b.request_count, b.removed_request_count),
                (1, Some(1)),
                "stale parent positive must remove the copy"
            );
            only_child(p)
        };
        let first = result(&read(prior.clone()), Mode::Ram);
        append(&root, &line(ROOT, "growth", "2026-08-02T07:02:00Z", 30));
        let grown = result(&read(prior.clone()), Mode::Ram);
        let mut saved = prior.clone();
        let restored = session.save_reload(&mut saved);
        let restarted = result(&read(restored), Mode::Restart);
        let current = result(&only_child(page(&c, prior, 100, true)), Mode::DiskRestore);
        let cold = result(
            &only_child(page(&c, ScanIndex::default(), 100, false)),
            Mode::ColdFull,
        );
        for route in [&first, &grown, &current, &restarted] {
            money_oracle::assert_equivalent(&cold, route);
        }
    });
}
