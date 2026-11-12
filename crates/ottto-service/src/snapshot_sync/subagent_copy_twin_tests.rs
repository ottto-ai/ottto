// Pre-cutoff all-copy subagent path twins, including the observed 26-pair shape.
use super::*;

const AGENT: &str = "agent-5200";

fn member() -> String {
    format!("{ROOT}_{AGENT}")
}

fn pair(name: &str) -> (Corpus, [PathBuf; 2], ScanIndex) {
    let mut c = Corpus::new(name);
    c.root(ROOT, &line(ROOT, "root-only", A.1, 10));
    let text = responses(ROOT, 0, 26, 11_525, A.1);
    let paths = [
        c.write_at(
            &format!("old/{ROOT}/subagents/{AGENT}.jsonl"),
            &text,
            "2026-08-02T07:00:00Z",
        ),
        c.write_at(&format!("new/{ROOT}/subagents/{AGENT}.jsonl"), &text, BORN),
    ];
    let mut index = ScanIndex::default();
    // File-system probes precede parsing. Supply the fixture's historical
    // observations for child paths too, so discovery order cannot use today's birth.
    for path in &paths {
        index.claude_money_birth_store.record_observation(
            &member(),
            &path.to_string_lossy(),
            c.births[path],
        );
    }
    (c, paths, index)
}

fn legacy(c: &Corpus, index: ScanIndex) -> (ScanIndex, SnapshotItem) {
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
    let head = body(&page, &member()).unwrap().clone();
    assert_eq!((head.request_count, head.output_tokens), (52, 23_050));
    assert_eq!(head.removed_request_count, Some(0));
    let prior = settle(c, &committed, page, &mut e2_progress());
    (prior, head)
}

/// [money] Same 26 pairs: co-page declares 26 removals; either singleton
/// counts 26; cold/retained/restarted owners agree. A changed device refuses
/// the old certificate without changing births or the twin decision.
#[cfg(unix)]
#[test]
fn subagent_all_copy_twins_conserve_pages_restart_and_device_replace() {
    with_e2(|| {
        let (c, paths, index) = pair("subagent-copied-pages");
        let (prior, _) = legacy(&c, index);
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
            let item = body(&page, &member()).unwrap();
            assert_eq!((item.request_count, item.output_tokens), (26, 11_525));
            assert_eq!(item.removed_request_count, Some(26));
            assert_eq!(item.removed_usage.as_ref().unwrap().output_tokens, 11_525);
            routes.push(captured(&page, mode));
        }
        for route in &routes[1..] {
            money_oracle::assert_equivalent(&routes[0], route);
        }
        // Isolate real parsed folds before the ordinary page decision. The
        // absent-twin proof remains unchanged and both singleton pages count once.
        for path in &paths {
            let mut index = prior.clone();
            owe(&mut index);
            index = crate::snapshots::e2_pipeline_scan_fixture::save_reload_for_test(
                &mut index,
                &c.base.join("singleton-index.json"),
            );
            let mut page = c.raw(
                &E2ScanFixture::with_subagent_births(),
                index,
                100,
                true,
                &[],
            );
            let location = location_key(&path.to_string_lossy());
            page.scan.snapshots.retain(|item| {
                item.claude_money
                    .as_deref()
                    .and_then(e2::FileFold::location_key)
                    == Some(location)
            });
            assert_eq!(page.scan.snapshots.len(), 1, "one native singleton fold");
            e2::take_diag();
            page.enrich(&c);
            page.finish();
            let item = body(&page, &member()).unwrap();
            assert_eq!((item.request_count, item.output_tokens), (26, 11_525));
            assert_eq!(page.disposition.quarantined_entity_count(), 0);
            assert!(
                e2::take_diag().get("twin_redundant").copied().unwrap_or(0) > 0,
                "the absent twin is positively proven redundant"
            );
        }

        let (device_c, device_paths, device_index) = pair("subagent-copied-device");
        let (mut replaced, _) = legacy(&device_c, device_index.clone());
        let paths = &device_paths;
        let c = &device_c;
        let births = paths
            .iter()
            .map(|p| {
                replaced
                    .claude_money_birth_store
                    .observed_birth(&member(), &p.to_string_lossy())
            })
            .collect::<Vec<_>>();
        for path in paths {
            crate::snapshots::e2_pipeline_scan_fixture::renumber_device_for_test(
                &mut replaced,
                &path.to_string_lossy(),
            );
        }
        owe(&mut replaced);
        let scanner = E2ScanFixture::with_subagent_births();
        let mut page = ready(c, &scanner, replaced, 100, true);
        page.finish();
        let item = body(&page, &member()).unwrap();
        assert_eq!((item.request_count, item.output_tokens), (26, 11_525));
        assert_eq!(item.removed_request_count, Some(26));
        assert!(
            page.modes.0 >= 2,
            "both refused device certificates read Full"
        );
        assert_eq!(
            paths
                .iter()
                .map(|p| page
                    .index
                    .claude_money_birth_store
                    .observed_birth(&member(), &p.to_string_lossy()))
                .collect::<Vec<_>>(),
            births
        );
        let mut expected = ready(
            c,
            &E2ScanFixture::with_subagent_births(),
            device_index,
            100,
            false,
        );
        expected.finish();
        let expected = captured(&expected, Mode::ColdFull);
        money_oracle::assert_equivalent(&expected, &captured(&page, Mode::Restart));
    });
}

/// [money] A pre-cutoff copied prefix counts once and the appended own
/// response still counts immediately.
#[test]
fn subagent_twin_with_own_turn_counts_the_prefix_once() {
    with_e2(|| {
        let (mut c, paths, index) = pair("subagent-copied-own-turn");
        let (prior, _) = legacy(&c, index);
        let text = std::fs::read_to_string(&paths[1]).unwrap() + &line(ROOT, "new-own", C.1, 7);
        c.write_at(&format!("new/{ROOT}/subagents/{AGENT}.jsonl"), &text, BORN);
        let mut index = prior;
        owe(&mut index);
        let page = ready(
            &c,
            &E2ScanFixture::with_subagent_births(),
            index,
            100,
            false,
        );
        assert_eq!(body(&page, &member()).unwrap().request_count, 27);
        assert_eq!(
            body(&page, &member()).unwrap().removed_request_count,
            Some(26)
        );
    });
}

/// [money] Idle shared-id subagent homes both re-owe once; after restart
/// one explained 52→26 correction is accepted, then no second re-owe or
/// quiet upload occurs.
#[test]
fn subagent_twin_version_three_converges_once() {
    with_e2(|| {
        let (c, paths, index) = pair("subagent-copied-convergence");
        let (mut prior, head) = legacy(&c, index);
        prior.claude_money_birth_store.set_money_rule_version(2);
        prior.activate_effective_upload_body_witness_revision(3);
        e2::take_diag();
        e2::apply_money_rules(&mut prior);
        assert_eq!(prior.claude_money_birth_store.money_rule_version(), 3);
        assert_eq!(copy_diag(&["money_rule_v3_reowed"]), [2]);
        for path in &paths {
            assert_eq!(
                prior.files[path.to_str().unwrap()].effective_upload_body_witness_revision,
                2
            );
        }
        prior = c.reload(&mut prior);
        e2::apply_money_rules(&mut prior);
        assert_eq!(copy_diag(&["money_rule_v3_reowed"]), [0]);
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
            .find(|item| item.source_session_id == member())
            .unwrap();
        assert_eq!((item.request_count, item.output_tokens), (26, 11_525));
        assert_eq!(item.removed_request_count, Some(26));
        item.cache_base_head_etag = Some(etag.clone());
        assert!(receiver_accepts(&head, item, &etag));
        let mut unexplained = item.clone();
        unexplained.removed_request_count = Some(0);
        unexplained.removed_usage = None;
        assert!(!receiver_accepts(&head, &unexplained, &etag));
        let mut posts = 0;
        let mut progress = e2_progress();
        let (status, _, _) = upload(&page.scan.snapshots, &mut progress, |items| {
            for item in items
                .iter()
                .filter(|item| item.source_session_id == member())
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

/// [money] A pre-cutoff shared prefix is removed once, while unmatched
/// pre-birth responses are own turns. Co-page, copy alone and restart
/// conserve the same native body and account placement.
#[test]
fn subagent_prefix_with_prebirth_own_turns_counts_once() {
    with_e2(|| {
        let (mut c, paths, index) = pair("subagent-prefix-prebirth-own");
        let own =
            line(ROOT, "own-before-birth-1", A.1, 7) + &line(ROOT, "own-before-birth-2", A.1, 9);
        let text = std::fs::read_to_string(&paths[1]).unwrap() + &own;
        c.write_at(&format!("new/{ROOT}/subagents/{AGENT}.jsonl"), &text, BORN);
        let scanner = E2ScanFixture::with_subagent_births();
        let mut first = ready(&c, &scanner, index.clone(), 100, true);
        first.finish();
        let item = body(&first, &member()).unwrap();
        assert_eq!((item.request_count, item.output_tokens), (28, 11_541));
        assert_eq!(item.removed_request_count, Some(26));
        let expected = captured(&first, Mode::ColdFull);
        let committed = first.committed.clone();
        let prior = settle(&c, &committed, first, &mut e2_progress());
        for mode in [Mode::Ram, Mode::Restart] {
            let mut index = prior.clone();
            if mode == Mode::Restart {
                index = crate::snapshots::e2_pipeline_scan_fixture::save_reload_for_test(
                    &mut index,
                    &c.base.join("prefix-restart.json"),
                );
            }
            owe(&mut index);
            let mut page = ready(&c, &scanner, index, 100, true);
            page.finish();
            assert_eq!(
                body(&page, &member()).unwrap().removed_request_count,
                Some(26)
            );
            money_oracle::assert_equivalent(&expected, &captured(&page, mode));
        }
        // The copy alone includes both the shared prefix and its two own
        // responses; the original's ids are all present, so absence is safe.
        {
            let path = &paths[1];
            let mut index = prior.clone();
            owe(&mut index);
            index = crate::snapshots::e2_pipeline_scan_fixture::save_reload_for_test(
                &mut index,
                &c.base.join("prefix-singleton.json"),
            );
            let mut page = c.raw(&scanner, index, 100, true, &[]);
            let location = location_key(&path.to_string_lossy());
            page.scan.snapshots.retain(|item| {
                item.claude_money
                    .as_deref()
                    .and_then(e2::FileFold::location_key)
                    == Some(location)
            });
            assert_eq!(page.scan.snapshots.len(), 1);
            page.enrich(&c);
            page.finish();
            assert_eq!(
                (
                    body(&page, &member()).unwrap().request_count,
                    body(&page, &member()).unwrap().output_tokens
                ),
                (28, 11_541)
            );
        }
        let mut index = prior;
        index.claude_money_birth_store.set_money_rule_version(2);
        index.activate_effective_upload_body_witness_revision(3);
        e2::take_diag();
        e2::apply_money_rules(&mut index);
        assert_eq!(
            copy_diag(&["money_rule_v3_reowed"]),
            [2],
            "prefix pairs are selected too"
        );
    });
}
