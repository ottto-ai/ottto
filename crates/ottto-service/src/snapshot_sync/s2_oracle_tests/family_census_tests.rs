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
        .claude_request_census_for_test()
        .get(key.as_ref())
        .unwrap()
        .clone();
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(key.as_ref(), record.with_modified_for_test(Some(1)));
}

/// [money] A stale positive, growing parent, current page and durable restart
/// all remove exactly the same first response with the parent off the fold page.
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
        let read = |index| {
            let p = child_page(&c, index, &child_path);
            let b = body(&p, &child()).expect("child is folded");
            assert_eq!(
                (b.request_count, b.removed_request_count),
                (1, Some(1)),
                "stale parent positive must remove the copy"
            );
            p
        };
        let first_page = read(prior);
        let first = result(&first_page, Mode::Ram);
        let prior = commit(&session, first_page);
        append(&root, &line(ROOT, "growth", "2026-08-02T07:02:00Z", 30));
        refold(&child_path);
        let grown_page = read(prior);
        let grown = result(&grown_page, Mode::Ram);
        let prior = commit(&session, grown_page);
        refold(&child_path);
        refold(&root);
        let current_page = hinted(&c, prior, 100, true, &[root.clone(), child_path.clone()]);
        assert!(
            body(&current_page, ROOT).is_some(),
            "current parent is parsed"
        );
        let current = result(&only_child(twin(&current_page)), Mode::DiskRestore);
        let mut saved = commit(&session, current_page);
        let restored = session.save_reload(&mut saved);
        append(
            &root,
            &line(ROOT, "restart-growth", "2026-08-02T07:03:00Z", 7),
        );
        refold(&child_path);
        let restarted = result(&child_page(&c, restored, &child_path), Mode::Restart);
        let cold = result(
            &only_child(page(&c, ScanIndex::default(), 100, false)),
            Mode::ColdFull,
        );
        for route in [&first, &grown, &current, &restarted] {
            money_oracle::assert_equivalent(&cold, route);
        }
    });
}

fn refold(path: &Path) {
    // Ordinary provider growth with no additional usage changes the revision.
    append(
        path,
        "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"continue\"}}\n",
    );
}
fn child_page(c: &Corpus, mut index: ScanIndex, path: &Path) -> Page {
    let root = c.root.join(format!("{ROOT}.jsonl"));
    let key = root.to_str().unwrap();
    let census = index.claude_request_census_for_test().get(key).cloned();
    crate::snapshots::e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let mut p = c.raw(
        &E2ScanFixture::capturing_identity(),
        index,
        100,
        true,
        &[path.to_path_buf()],
    );
    // As in context_posture_survives_a_split_family_refold, reproduce the
    // deferred-root page at the real fold boundary. The parsers are native;
    // only the child participates, against the root census saved before it.
    p.scan
        .snapshots
        .retain(|item| item.source_session_id == child());
    match census {
        Some(record) => p
            .index
            .claude_request_census_mut_for_test()
            .insert_for_test(key, record),
        None => p
            .index
            .claude_request_census_mut_for_test()
            .invalidate_keeping_birth_for_test(key),
    }
    assert!(body(&p, ROOT).is_none(), "root stays off the fold page");
    assert!(body(&p, &child()).is_some(), "native child fold");
    p.enrich(c);
    p
}

/// [money] With no census the copy counts, including an accepted legacy +1.
/// Parsing the root then ordinary child growth offers one correction and goes quiet.
#[test]
fn first_sighting_and_legacy_overcount_converge_on_the_next_child_fold() {
    with_e2(|| {
        let mut c = corpus("family-census-first-sighting");
        let root = c.root(ROOT, &line(ROOT, "fork", AT, 10));
        let path = copied(&mut c);
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let first = child_page(&c, index, &path);
        assert!(first
            .index
            .claude_request_census_for_test()
            .get(root.to_str().unwrap())
            .is_none());
        assert_eq!(body(&first, &child()).unwrap().request_count, 2);
        let prior = commit(&session, first);
        refold(&root);
        let parent = hinted(&c, prior, 100, true, std::slice::from_ref(&root));
        assert!(body(&parent, ROOT).is_some());
        let prior = commit(&session, parent);
        refold(&path);
        let corrected = child_page(&c, prior, &path);
        let b = body(&corrected, &child()).unwrap();
        assert_eq!((b.request_count, b.removed_request_count), (1, Some(1)));
        let cold = result(
            &only_child(page(&c, ScanIndex::default(), 100, false)),
            Mode::ColdFull,
        );
        money_oracle::assert_equivalent(&cold, &result(&corrected, Mode::Restart));
        let mut offered = twin(&corrected);
        offered.finish();
        assert_eq!(offered.scan.snapshots.len(), 1, "one corrective offer");
        let prior = commit(&session, corrected);
        // Plain Claude uses the same observed object/parser seams as the
        // existing resident-wave quiet control. Never fabricate zero I/O.
        let (mut quiet, io) = fixture::observe_codex_quiet(|| page(&c, prior, 100, true));
        quiet.finish();
        assert!(quiet.scan.snapshots.is_empty(), "no repeated correction");
        assert_eq!(io.consumed, 0, "quiet restart reads no transcript bytes");
        let mut quiet_route = result(&quiet, Mode::Restart);
        quiet_route.io = io;
        quiet_route.modes = quiet.modes;
        money_oracle::assert_quiet_restart_zero_bytes(&quiet_route);
    });
}

/// [money] A completed rewrite replaces positive membership. Only the next
/// child fold restores its first response; the old positive is not unioned forever.
#[test]
fn root_rewrite_removing_the_id_restores_the_child_response() {
    with_e2(|| {
        let mut c = corpus("family-census-rewrite");
        let root = c.root(ROOT, &line(ROOT, "fork", AT, 10));
        let path = copied(&mut c);
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let seed = page(&c, index, 100, true);
        assert_eq!(body(&seed, &child()).unwrap().request_count, 1);
        let prior = commit(&session, seed);
        std::fs::write(&root, line(ROOT, "replacement", "2026-08-02T07:02:00Z", 31)).unwrap();
        let rewritten = hinted(&c, prior, 100, true, std::slice::from_ref(&root));
        assert!(body(&rewritten, ROOT).is_some());
        let prior = commit(&session, rewritten);
        refold(&path);
        let restored = child_page(&c, prior, &path);
        assert_eq!(body(&restored, &child()).unwrap().request_count, 2);
        let cold = result(
            &only_child(page(&c, ScanIndex::default(), 100, false)),
            Mode::ColdFull,
        );
        money_oracle::assert_equivalent(&cold, &result(&restored, Mode::Restart));
    });
}

/// [money] Local membership is not an ACK. The child temporarily lacks the
/// root's response at the destination, then converges when the root is delivered.
#[test]
fn never_uploaded_root_exposes_transient_undercount_then_converges() {
    with_e2(|| {
        let mut c = corpus("family-census-unuploaded");
        let root = c.root(ROOT, &line(ROOT, "fork", AT, 10));
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let mut unsent = page(&c, index, 100, true);
        unsent.finish();
        assert!(unsent.delivered.is_none());
        let mut prior = session.save_reload(&mut unsent.index);
        assert!(prior.files[root.to_str().unwrap()]
            .upload_context_receipt
            .is_none());
        stale(&mut prior, &root);
        let path = copied(&mut c);
        let child_only = child_page(&c, prior, &path);
        assert_eq!(
            body(&child_only, &child()).unwrap().request_count,
            1,
            "the root response is not yet at the server"
        );
        let cold_child = result(
            &only_child(page(&c, ScanIndex::default(), 100, false)),
            Mode::ColdFull,
        );
        money_oracle::assert_equivalent(&cold_child, &result(&child_only, Mode::Ram));
        let prior = commit(&session, child_only);
        append(
            &root,
            &line(ROOT, "delivered-later", "2026-08-02T07:02:00Z", 30),
        );
        refold(&path);
        let converged = hinted(&c, prior, 100, true, &[root, path]);
        assert_eq!(total(&converged), 3, "root 2 plus child 1 before exact ACK");
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        money_oracle::assert_equivalent(&cold, &result(&converged, Mode::Restart));
        let _ = commit(&session, converged);
    });
}

/// [money] The corrected duplicate leaves its own account grain. Native twin
/// restoration still precedes family removal; all retained rows and ACK buckets
/// agree with cold Full across a switch, side call and evidence gap.
#[test]
fn stale_family_proof_preserves_two_account_placement_and_twin_order() {
    with_e2(|| {
        let mut c = corpus("family-census-placement-twin");
        let root = c.root(ROOT, &line(ROOT, "fork", AT, 10));
        let text = line(ROOT, "fork", AT, 10)
            + &line(ROOT, "a", "2026-08-02T07:01:00Z", 20)
            + &line(ROOT, "b", "2026-08-02T07:02:00Z", 30)
            + &line(ROOT, "gap", "2026-08-02T07:03:00Z", 7);
        let path = c.agent(0, &text);
        c.evidence(
            &[
                api_login(ROOT, "fork", 10, '1', Some('7')),
                api_login(ROOT, "a", 20, '1', Some('7')),
                api_login(ROOT, "b", 30, '2', Some('8')),
                api_login(ROOT, "side", 4, '2', Some('8')),
            ],
            &[
                trace("fork", ""),
                trace("a", "agent-000"),
                trace("b", "agent-000"),
                trace("side", "agent-000"),
            ],
        );
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let mut prior = commit(&session, page(&c, index, 100, true));
        stale(&mut prior, &root);
        refold(&path);
        let warm = child_page(&c, prior, &path);
        assert_eq!(
            body(&warm, &child()).unwrap().request_count,
            4,
            "own a, b, gap and side; parent copy removed once"
        );
        let cold = result(
            &only_child(page(&c, ScanIndex::default(), 100, false)),
            Mode::ColdFull,
        );
        assert!(accounts(&cold).len() >= 2, "nonempty two-account control");
        let actual = result(&warm, Mode::Restart);
        assert!(!actual
            .accepted_identity_buckets
            .as_ref()
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty());
        money_oracle::assert_equivalent(&cold, &actual);
        // A same-member path twin whose old first response has no earlier
        // eligible page holder is restored by the twin rule before family dedup.
        c.write_at(
            &format!("other/{ROOT}.jsonl"),
            &line(ROOT, "fork", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("other/{ROOT}/subagents/agent-000.jsonl"),
            &text,
            "2026-08-02T07:00:30Z",
        );
        let twins = page(&c, ScanIndex::default(), 100, false);
        assert_eq!(
            body(&twins, &child()).unwrap().removed_request_count,
            Some(2),
            "both family copies removed after native twin restoration"
        );
        let twin_route = result(&twins, Mode::ColdFull);
        let restored = page(&c, ScanIndex::default(), 100, true);
        money_oracle::assert_equivalent(&twin_route, &result(&restored, Mode::Restart));
    });
}
