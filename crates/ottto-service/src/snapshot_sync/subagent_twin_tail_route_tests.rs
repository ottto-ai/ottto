// A subagent stored in two homes whose last shared response is inside the
// copy slack before the later home's birth: routes and the rule-4 re-owe.
use crate::snapshots::{history_local_count, HistoryLocalCount};

const TAIL_AGENT: &str = "agent-7a11";

fn tail_member() -> String {
    format!("{ROOT}_{TAIL_AGENT}")
}

/// Two homes of one subagent; the later is born 114 ms after the last of
/// three shared responses. Also a lone sibling subagent and the root.
fn tail_pair(name: &str) -> (Corpus, ScanIndex) {
    let mut c = Corpus::new(name);
    c.root(ROOT, &line(ROOT, "root-only", A.1, 10));
    let lone = c.write_at(
        &format!("old/{ROOT}/subagents/agent-lone.jsonl"),
        &line(ROOT, "lone-1", A.1, 9),
        "2026-08-02T07:00:00Z",
    );
    let text = line(ROOT, "tail-1", "2026-08-02T07:01:00Z", 20)
        + &line(ROOT, "tail-2", "2026-08-02T07:02:00Z", 21)
        + &line(ROOT, "tail-3", "2026-08-02T07:02:59.886Z", 22);
    let paths = [
        c.write_at(
            &format!("old/{ROOT}/subagents/{TAIL_AGENT}.jsonl"),
            &text,
            "2026-08-02T07:00:00Z",
        ),
        c.write_at(
            &format!("new/{ROOT}/subagents/{TAIL_AGENT}.jsonl"),
            &text,
            BORN,
        ),
    ];
    let mut index = ScanIndex::default();
    let (lone_member, member) = (format!("{ROOT}_agent-lone"), tail_member());
    for (member, path) in [(&lone_member, &lone)]
        .into_iter()
        .chain(paths.iter().map(|path| (&member, path)))
    {
        index.claude_money_birth_store.record_observation(
            member,
            &path.to_string_lossy(),
            c.births[path],
        );
    }
    (c, index)
}

/// An accepted over-counted body: the released pre-cutoff behaviour counted
/// every shared response in both homes (`released_subagent_copies`).
fn over_counted(c: &Corpus, index: ScanIndex) -> (ScanIndex, SnapshotItem) {
    let mut page = c.raw(
        &E2ScanFixture::with_subagent_births(),
        index.clone(),
        100,
        true,
        &[],
    );
    let committed = page.committed.clone();
    e2::pipeline_test_observer::released_subagent_copies(&mut page.scan.snapshots);
    page.enrich(c);
    page.finish();
    let head = body(&page, &tail_member()).unwrap().clone();
    assert_eq!((head.request_count, head.output_tokens), (6, 126));
    assert_eq!(head.removed_request_count, Some(0));
    let prior = settle(c, &committed, page, &mut e2_progress());
    (prior, head)
}

/// Each indexed file's stored body revision.
fn revisions(index: &ScanIndex) -> BTreeMap<String, u64> {
    index
        .files
        .iter()
        .map(|(key, entry)| (key.clone(), entry.effective_upload_body_witness_revision))
        .collect()
}

/// [money] T4/T7: from an accepted over-counted body, cold, retained and
/// restarted owners emit the same corrected body (each shared request once).
/// Rule 4 re-owes the pair once (not the root or the lone sibling); after a
/// restart nothing is re-owed again. The receiver accepts the decrease, and
/// the next unchanged page uploads nothing.
#[cfg(unix)]
#[test]
fn subagent_twin_tail_corrects_the_accepted_head_once() {
    with_e2(|| {
        let (c, index) = tail_pair("subagent-twin-tail-routes");
        let (prior, _) = over_counted(&c, index);
        let mut routes = Vec::new();
        for (mode, sampled) in [
            (Mode::ColdFull, false),
            (Mode::Ram, true),
            (Mode::Restart, true),
        ] {
            let mut index = prior.clone();
            if mode == Mode::Restart {
                index = c.reload(&mut index);
            }
            owe(&mut index);
            let mut page = ready(
                &c,
                &E2ScanFixture::with_subagent_births(),
                index,
                100,
                sampled,
            );
            page.finish();
            let item = body(&page, &tail_member()).unwrap();
            assert_eq!(
                (item.request_count, item.output_tokens),
                (3, 63),
                "{mode:?}"
            );
            assert_eq!(item.removed_request_count, Some(3), "{mode:?}");
            routes.push(captured(&page, mode));
        }
        for route in &routes[1..] {
            money_oracle::assert_equivalent(&routes[0], route);
        }
        // The restart arm committed through this corpus's route: upgrade a
        // fresh copy of the same accepted body.
        let (c, index) = tail_pair("subagent-twin-tail-upgrade");
        let (mut prior, head) = over_counted(&c, index);
        prior.claude_money_birth_store.set_money_rule_version(3);
        prior.activate_effective_upload_body_witness_revision(3);
        let before = revisions(&prior);
        let reowed = history_local_count(HistoryLocalCount::Reowed);
        e2::apply_money_rules(&mut prior);
        assert_eq!(prior.claude_money_birth_store.money_rule_version(), 4);
        assert_eq!(
            history_local_count(HistoryLocalCount::Reowed),
            reowed + 2,
            "the pair only"
        );
        // The root and the lone sibling keep their revisions: their co-read
        // is the existing family closure, not a new re-owe.
        for (key, revision) in revisions(&prior) {
            let expected = if key.contains(TAIL_AGENT) {
                2
            } else {
                before[&key]
            };
            assert_eq!(revision, expected, "{key}");
        }
        prior = c.reload(&mut prior);
        let settled = revisions(&prior);
        let reowed = history_local_count(HistoryLocalCount::Reowed);
        e2::apply_money_rules(&mut prior);
        assert_eq!(
            (
                history_local_count(HistoryLocalCount::Reowed),
                revisions(&prior)
            ),
            (reowed, settled),
            "no second re-owe after restart"
        );
        let mut page = ready(
            &c,
            &E2ScanFixture::with_subagent_births(),
            prior.clone(),
            100,
            false,
        );
        page.finish();
        let etag = snapshot_upload_body_witness(&head);
        let item = page
            .scan
            .snapshots
            .iter_mut()
            .find(|item| item.source_session_id == tail_member())
            .unwrap();
        assert_eq!((item.request_count, item.output_tokens), (3, 63));
        assert_eq!(item.removed_request_count, Some(3));
        item.cache_base_head_etag = Some(etag.clone());
        assert!(receiver_accepts(&head, item, &etag));
        let mut posts = 0;
        let mut progress = e2_progress();
        let (status, _, _) = upload(&page.scan.snapshots, &mut progress, |items| {
            for item in items
                .iter()
                .filter(|item| item.source_session_id == tail_member())
            {
                assert!(receiver_accepts(&head, item, &etag));
                posts += 1;
            }
            ack(items)
        });
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(posts, 1);
        prior = settle(&c, &prior, page, &mut progress);
        let (quiet, consumed) = observe_consumed(|| {
            ready(
                &c,
                &E2ScanFixture::with_subagent_births(),
                prior,
                100,
                false,
            )
        });
        assert_eq!(consumed, 0);
        assert!(quiet.scan.snapshots.is_empty());
    });
}

/// [money] T7: from version 2, rules 3 and 4 select the same pair: the jump
/// to version 4 re-owes each key once. Without a pair, rule 4 re-owes nothing.
#[cfg(unix)]
#[test]
fn subagent_twin_tail_rule_four_unions_with_rule_three() {
    with_e2(|| {
        let (c, index) = tail_pair("subagent-twin-tail-union");
        let (mut prior, _) = over_counted(&c, index);
        prior.claude_money_birth_store.set_money_rule_version(2);
        prior.activate_effective_upload_body_witness_revision(3);
        e2::take_diag();
        let reowed = history_local_count(HistoryLocalCount::Reowed);
        e2::apply_money_rules(&mut prior);
        assert_eq!(prior.claude_money_birth_store.money_rule_version(), 4);
        assert_eq!(copy_diag(&["money_rule_v3_reowed"]), [2]);
        assert_eq!(history_local_count(HistoryLocalCount::Reowed), reowed + 2);
        let mut c = Corpus::new("subagent-twin-tail-none");
        c.root(ROOT, &line(ROOT, "root-only", A.1, 10));
        c.write_at(
            &format!("old/{ROOT}/subagents/agent-lone.jsonl"),
            &line(ROOT, "lone-1", A.1, 9),
            "2026-08-02T07:00:00Z",
        );
        let mut lone = warm(&c);
        lone.claude_money_birth_store.set_money_rule_version(3);
        lone.activate_effective_upload_body_witness_revision(3);
        let reowed = history_local_count(HistoryLocalCount::Reowed);
        e2::apply_money_rules(&mut lone);
        assert_eq!(lone.claude_money_birth_store.money_rule_version(), 4);
        assert_eq!(history_local_count(HistoryLocalCount::Reowed), reowed);
    });
}
