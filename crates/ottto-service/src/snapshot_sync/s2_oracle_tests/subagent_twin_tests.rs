//! Same-member copies through native scan, final POST and exact ACK.
use super::*;

const START: &str = "2026-11-05T00:00:00Z";
const TURN: &str = "2026-11-05T07:01:00Z";
const COPY_BIRTH: &str = "2026-11-05T07:03:00Z";
const GROW: &str = "2026-11-05T07:05:00Z";

fn member(home: &str, agent: usize) -> String {
    format!("{home}/{ROOT}/subagents/agent-{agent:03}.jsonl")
}

fn child(agent: usize) -> String {
    format!("{ROOT}_agent-{agent:03}")
}

/// One main pair, two child pairs and an untwinned child. Main copies use
/// their existing resumed-prefix proof; the new rule affects only children.
fn twins(name: &str, reverse: bool, clock: &str, idless: bool, positive: bool) -> Corpus {
    let mut c = corpus(name);
    let (old, new) = if reverse { ("z", "a") } else { ("a", "z") };
    let root = line(ROOT, "root-fork", START, 10);
    c.write_at(
        &format!("{old}/{ROOT}.jsonl"),
        &root,
        "2026-11-04T07:00:00Z",
    );
    c.write_at(
        &format!("{new}/{ROOT}.jsonl"),
        &(root.clone() + &line(ROOT, "resume", "2026-11-05T07:04:00Z", 11)),
        COPY_BIRTH,
    );
    for agent in 0..2 {
        let mut text = root.clone() + &line(ROOT, &format!("child-{agent}"), clock, 20);
        if positive {
            text += &line(ROOT, &format!("switch-{agent}"), TURN, 30);
            text += &line(ROOT, &format!("gap-{agent}"), TURN, 7);
        }
        if idless && agent == 0 {
            let mut value: serde_json::Value =
                serde_json::from_str(&line(ROOT, "idless", TURN, 4)).unwrap();
            value.as_object_mut().unwrap().remove("requestId");
            value["message"].as_object_mut().unwrap().remove("id");
            text += &(value.to_string() + "\n");
        }
        if positive && agent == 0 {
            text += &line(ROOT, "old", AT, 6);
        }
        c.write_at(&member(old, agent), &text, "2026-11-04T07:00:00Z");
        if positive && agent == 0 {
            text += &line(ROOT, "copy-own", GROW, 13);
        }
        c.write_at(&member(new, agent), &text, COPY_BIRTH);
    }
    c.write_at(
        &member(old, 2),
        &line(ROOT, "untwinned", TURN, 9),
        "2026-11-04T07:00:00Z",
    );
    if positive {
        let mut rows = vec![api_login(ROOT, "root-fork", 10, '1', Some('7'))];
        for agent in 0..2 {
            rows.push(api_login(
                ROOT,
                &format!("child-{agent}"),
                20,
                '1',
                Some('7'),
            ));
            rows.push(api_login(
                ROOT,
                &format!("switch-{agent}"),
                30,
                '2',
                Some('8'),
            ));
        }
        rows.push(api_login(ROOT, "side", 4, '2', Some('8')));
        rows.push(api_login(ROOT, "copy-own", 13, '2', Some('8')));
        let mut traces = vec![trace("root-fork", "")];
        for agent in 0..2 {
            for r in ["child", "switch"] {
                traces.push(trace(&format!("{r}-{agent}"), &format!("agent-{agent:03}")));
            }
        }
        traces.push(trace("side", "000"));
        traces.push(trace("copy-own", "agent-000"));
        c.evidence(&rows, &traces);
    }
    c
}

fn cold(c: &Corpus) -> RouteResult {
    result(&page(c, ScanIndex::default(), 100, false), Mode::ColdFull)
}

/// Check native Full, continuation, persisted restore, upgrade and replay
/// after a crash before upload against identical final POST bytes/placement.
fn routes(c: &Corpus) -> RouteResult {
    let expected = cold(c);
    let main = c
        .births
        .iter()
        .filter(|(path, _)| path.file_name().unwrap() == format!("{ROOT}.jsonl").as_str())
        .max_by_key(|(_, birth)| *birth)
        .unwrap()
        .0;
    let original = std::fs::read_to_string(main).unwrap();
    for (mode, upgrade) in [
        (Mode::Ram, false),
        (Mode::DiskRestore, false),
        (Mode::Restart, false),
        (Mode::Restart, true),
    ] {
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join(format!("state-{mode:?}-{upgrade}")),
        );
        let scanner = E2ScanFixture::capturing_identity();
        let mut first = c.raw(&scanner, index, 100, true, &[]);
        first.enrich(c);
        money_oracle::assert_equivalent(&expected, &result(&first, mode));
        // Save native inputs without accepting; the next real change continues them.
        first.finish();
        let mut prior = session.save_reload(&mut first.index);
        if upgrade {
            prior = fixture::upgrade_from_legacy_store(&prior, &c.base.join("legacy.json"));
        }
        // Saved undelivered work alone selects no read. A real append drives
        // the continuation/restart instead of demanding an unchanged re-offer.
        append(main, &line(ROOT, "restart-growth", GROW, 8));
        let grown = cold(c);
        let mut again = if mode == Mode::Ram {
            c.raw(&scanner, prior, 100, true, &[])
        } else {
            c.raw(&E2ScanFixture::capturing_identity(), prior, 100, true, &[])
        };
        again.enrich(c);
        money_oracle::assert_equivalent(&grown, &result(&again, mode));
        // An upgraded prior continues on its own route, never the session's.
        if upgrade {
            again.finish();
        } else {
            let _ = commit(&session, again);
        }
        std::fs::write(main, &original).unwrap();
    }
    expected
}

/// [regress] Identified child requests count once in both discovery orders;
/// the parent repeat is removed once and idless copies remain counted.
#[test]
fn identical_family_and_idless_copies() {
    with_e2(|| {
        for reverse in [false, true] {
            let c = twins(
                &format!("subagent-twin-identical-{reverse}"),
                reverse,
                TURN,
                true,
                false,
            );
            e2::take_diag();
            let expected = routes(&c);
            assert_eq!(expected.snapshots.len(), 4, "one final entity per member");
            assert_eq!(expected.snapshots[ROOT]["request_count"], 2);
            assert_eq!(
                expected.snapshots[&child(0)]["request_count"],
                3,
                "two idless copies count"
            );
            assert_eq!(expected.snapshots[&child(1)]["request_count"], 1);
            assert_eq!(expected.snapshots[&child(2)]["request_count"], 1);
            for agent in 0..2 {
                assert_eq!(
                    expected.snapshots[&child(agent)]["removed_request_count"],
                    3,
                    "parent repeat on both paths plus one child twin"
                );
            }
            assert!(e2::take_diag()["copy_prefix_twin_page_removed"] >= 4);
        }
    });
}

/// [money] The inclusive gate is each duplicated occurrence's timestamp,
/// including all-copy children. Missing clocks count through the native
/// bucket fallback and never reach the gate.
#[test]
fn occurrence_boundary_counts_unusable_and_old_copies() {
    with_e2(|| {
        for (name, clock, counted, removed) in [
            ("before", "2026-11-04T23:59:59.999999999Z", 2, 2),
            ("equal", START, 1, 3),
            ("after", TURN, 1, 3),
            ("missing", "", 2, 2),
        ] {
            let mut c = twins(
                &format!("subagent-twin-cutoff-{name}"),
                false,
                clock,
                false,
                false,
            );
            if name == "missing" {
                for agent in 0..2 {
                    for home in ["a", "z"] {
                        let path = c.root.join(member(home, agent));
                        let text = std::fs::read_to_string(&path).unwrap();
                        let text = text
                            .lines()
                            .map(|text| {
                                let mut row: serde_json::Value =
                                    serde_json::from_str(text).unwrap();
                                if row["requestId"] == format!("child-{agent}") {
                                    row.as_object_mut().unwrap().remove("timestamp");
                                }
                                row.to_string() + "\n"
                            })
                            .collect::<String>();
                        c.write_at(
                            &member(home, agent),
                            &text,
                            if home == "a" {
                                "2026-11-04T07:00:00Z"
                            } else {
                                COPY_BIRTH
                            },
                        );
                    }
                }
            }
            let actual = routes(&c);
            for agent in 0..2 {
                assert_eq!(
                    actual.snapshots[&child(agent)]["request_count"],
                    counted,
                    "{name}"
                );
                assert_eq!(
                    actual.snapshots[&child(agent)]["removed_request_count"],
                    removed,
                    "{name}"
                );
            }
        }
    });
}

/// Body fields a multi-file session's carrier sets: the first page item
/// carries the summed entity, and a Tail page lists its hinted file first, so
/// the ended-at time (and the hashes over it) can follow the read route. This
/// pre-existing difference has no money effect.
const CARRIER_END: [&str; 6] = [
    "source_ended_at",
    "semantic_envelope/component_hashes/lifecycle_activity",
    "semantic_envelope/content_hash",
    "semantic_envelope/revision_hash",
    "semantic_envelope/revision_v2_hash",
    "snapshot_fingerprint",
];

/// Money, placement and removed fields exact; any other body difference is
/// pinned to a changed ended-at time plus the hashes derived from it.
fn assert_money_equivalent_but_carrier_end(expected: &RouteResult, other: &RouteResult) {
    money_oracle::assert_placement_equivalent(expected, other);
    let mut money = Vec::new();
    money_oracle::entity_differences(expected, other, &mut money);
    assert!(money.is_empty(), "{:?}:\n{}", other.mode, money.join("\n"));
    let mut body = Vec::new();
    money_oracle::diff(
        "normalized_batch",
        &expected.normalized,
        &other.normalized,
        &mut body,
    );
    let mut changed = std::collections::BTreeMap::<&str, bool>::new();
    for line in &body {
        let path = line.split(':').next().unwrap();
        let (snapshot, field) = CARRIER_END
            .iter()
            .find_map(|field| Some((path.strip_suffix(field)?, *field)))
            .unwrap_or_else(|| panic!("{:?}: body drift beyond the carrier: {line}", other.mode));
        *changed.entry(snapshot).or_default() |= field == "source_ended_at";
    }
    assert!(
        changed.values().all(|ended| *ended),
        "{:?}: hashes changed without an ended-at change:\n{}",
        other.mode,
        body.join("\n")
    );
}

/// [money] Append to either child, then opposite children, then only the
/// main: the old shared prefix stays singular while distinct suffixes add.
#[test]
fn growth_on_either_home_and_main_only() {
    with_e2(|| {
        for reverse in [false, true] {
            let c = twins(
                &format!("subagent-twin-growth-{reverse}"),
                reverse,
                TURN,
                false,
                false,
            );
            let (session, index) = StateV2ColdSession::publish(
                Source::Claude,
                &ScanIndex::default(),
                &c.base.join("state"),
            );
            let first = page(&c, index, 100, true);
            let mut prior = commit(&session, first);
            let mut additions = 0;
            for (step, relative) in [
                member("a", 0),
                member("z", 0),
                member("a", 1),
                member("z", 1),
                format!("z/{ROOT}.jsonl"),
            ]
            .iter()
            .enumerate()
            {
                let path = c.root.join(relative);
                append(&path, &line(ROOT, &format!("growth-{step}"), GROW, 8));
                let expected = cold(&c);
                // Save the prior before either scan takes its growth claim.
                let restored_prior = session.save_reload(&mut prior);
                // The main-only append moves the main session's carrier to the
                // hinted file on Tail; children grow a carrier on both routes.
                let check: fn(&RouteResult, &RouteResult) = if step == 4 {
                    assert_money_equivalent_but_carrier_end
                } else {
                    money_oracle::assert_equivalent
                };
                let warm = hinted(&c, prior.clone(), 100, true, std::slice::from_ref(&path));
                assert_eq!(warm.modes.0, 0, "append/forced family use Tail");
                assert!(warm.modes.1 > 0);
                check(&expected, &result(&warm, Mode::Ram));
                let restored = hinted(&c, restored_prior, 100, true, std::slice::from_ref(&path));
                check(&expected, &result(&restored, Mode::DiskRestore));
                additions += 1;
                let sum = expected
                    .snapshots
                    .values()
                    .map(|s| s["request_count"].as_u64().unwrap())
                    .sum::<u64>();
                assert_eq!(sum, 5 + additions, "each append adds exactly one request");
                prior = commit(&session, warm);
            }
        }
    });
}

/// [money] Two accounts, a mid-child switch, a priced side call, an
/// estimated evidence gap and a tagged row match one-home placement.
#[test]
fn positive_placement_matches_one_home() {
    with_e2(|| {
        let c = twins("subagent-twin-positive", false, TURN, false, true);
        let actual = routes(&c);
        assert!(accounts(&actual).len() >= 2);
        assert_eq!(actual.snapshots[&child(0)]["removed_request_count"], 5);
        assert_eq!(
            actual.snapshots[&child(0)]["removed_usage"]["input_tokens"],
            77
        );
        assert_eq!(
            actual.snapshots[&child(0)]["cost"]["total_cost_usd"],
            "0.00067"
        );
        let mut one = corpus("subagent-twin-positive-one-home");
        for agent in 0..3 {
            let text = std::fs::read_to_string(c.root.join(member("a", agent))).unwrap();
            let text = if agent == 0 {
                // A kept pre-boundary copy has no own login row before it, so it
                // takes the session's starting account, as z's kept "old" does.
                let (fork, rest) = text.split_once('\n').unwrap();
                format!("{fork}\n{}{rest}", line(ROOT, "old-copy", AT, 6))
                    + &line(ROOT, "copy-own", GROW, 13)
            } else {
                text
            };
            one.write_at(&member("a", agent), &text, "2026-11-04T07:00:00Z");
        }
        let text = std::fs::read_to_string(c.root.join(format!("z/{ROOT}.jsonl"))).unwrap();
        one.write_at(&format!("a/{ROOT}.jsonl"), &text, "2026-11-04T07:00:00Z");
        // Reuse the same synthetic evidence, with independent native transcript reads.
        one.support = c.support.clone();
        let single = cold(&one);
        money_oracle::assert_placement_equivalent(&single, &actual);
        for (id, expected) in &single.snapshots {
            let got = &actual.snapshots[id];
            for field in [
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_creation_5m_tokens",
                "cache_creation_1h_tokens",
                "reasoning_output_tokens",
                "unattributed_total_tokens",
                "request_count",
                "cost",
            ] {
                assert_eq!(expected.get(field), got.get(field), "{id}/{field}");
            }
        }
    });
}

/// [format] Replay before upload, recover an exact ACK before save,
/// restart between pages, then read zero transcript bytes on a quiet restart.
#[test]
fn restart_boundaries_and_quiet_settlement() {
    with_e2(|| {
        let mut c = twins("subagent-twin-restart", false, TURN, false, false);
        c.root(COPY, &line(COPY, "independent", TURN, 6));
        let expected = cold(&c);
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let first = page(&c, index.clone(), 1, true);
        // A crash before upload cannot grant an ACK or lose either member; the
        // restarted process starts with fresh route state, as its own install.
        let replay = page(
            &c,
            crate::snapshots::e2_pipeline_scan_fixture::own_install_for_test(
                &ScanIndex::load(session.path()).unwrap(),
                &c.base,
            ),
            100,
            true,
        );
        let restarted = result(&replay, Mode::Restart);
        money_oracle::assert_equivalent(&expected, &restarted);
        for agent in 0..2 {
            assert_eq!(restarted.snapshots[&child(agent)]["request_count"], 1);
            assert_eq!(
                restarted.snapshots[&child(agent)]["removed_request_count"],
                3
            );
        }
        let mut delivered = result(&first, Mode::Restart).snapshots;
        let mut prior = commit(&session, first);
        for _ in 0..10 {
            let next = page(&c, prior.clone(), 1, true);
            let observed = result(&next, Mode::Restart);
            delivered.extend(observed.snapshots);
            let done = next.scan.census_complete;
            prior = commit(&session, next);
            if done {
                break;
            }
        }
        assert!(prior.files.len() >= 7, "every twin was read across pages");
        assert_eq!(
            delivered, expected.snapshots,
            "all pages preserve complete final bodies"
        );
        // The exact ACK is recorded in the existing receipt ledger; losing the
        // index save replays the same bytes, with no synthetic acceptance bit.
        let mut owed = page(&c, ScanIndex::default(), 100, true);
        owed.finish();
        let mut progress = e2_progress();
        assert_eq!(
            upload(&owed.scan.snapshots, &mut progress, ack).0.unwrap(),
            ResumableUploadResult::Completed
        );
        let recovered = settle(&c, &owed.committed, twin(&owed), &mut progress);
        for item in &owed.scan.snapshots {
            assert!(progress
                .accepted_fingerprints
                .contains(&item.snapshot_fingerprint));
            assert_eq!(
                progress
                    .fresh_context_body_acks
                    .get(&item.snapshot_fingerprint),
                Some(&snapshot_upload_body_witness(item)),
                "exact ACK before save"
            );
        }
        let quiet = fixture::observe_consumed(|| page(&c, recovered, 100, true));
        assert_eq!(quiet.1, 0, "quiet restart consumes zero transcript bytes");
        assert!(
            quiet.0.scan.snapshots.is_empty(),
            "quiet restart sends nothing"
        );
    });
}

/// [money] A doubled pre-boundary accepted child stays doubled, including
/// after new eligible shared work: the accepted prefix is never corrected.
#[test]
fn accepted_pre_boundary_body_keeps_its_count_and_witness() {
    with_e2(|| {
        let c = twins("subagent-twin-accepted", false, AT, false, false);
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let first = page(&c, index, 100, true);
        assert_eq!(body(&first, &child(0)).unwrap().request_count, 2);
        let mut before = result(&first, Mode::ColdFull);
        accepted(&mut before, &first.scan.snapshots);
        let prior = commit(&session, first);
        let quiet = page(&c, prior.clone(), 100, true);
        assert!(quiet.scan.snapshots.is_empty());
        let main = c.root.join(format!("z/{ROOT}.jsonl"));
        append(&main, &line(ROOT, "main-only", GROW, 8));
        let pulled = hinted(&c, prior, 100, true, &[main]);
        let same = body(&pulled, &child(0)).unwrap();
        assert_eq!(same.request_count, 2);
        assert_eq!(
            snapshot_upload_body_witness(same),
            before.accepted[&child(0)].witness
        );
        let prior = commit(&session, pulled);
        for home in ["a", "z"] {
            append(
                &c.root.join(member(home, 0)),
                &line(ROOT, "eligible", TURN, 8),
            );
        }
        let path = c.root.join(member("z", 0));
        let grown = hinted(&c, prior, 100, true, &[path]);
        assert_eq!(
            body(&grown, &child(0)).unwrap().request_count,
            3,
            "old prefix twice, eligible new request once"
        );
        let expected = cold(&c);
        money_oracle::assert_equivalent(&expected, &result(&grown, Mode::Restart));
        let fingerprint = body(&grown, &child(0))
            .unwrap()
            .snapshot_fingerprint
            .clone();
        let witness = snapshot_upload_body_witness(body(&grown, &child(0)).unwrap());
        let (settled, progress) = commit_with_progress(&session, grown);
        assert!(settled.accepted_snapshot_fingerprint_recorded(&fingerprint));
        assert_eq!(
            progress.accepted_body_witnesses.get(&fingerprint),
            Some(&witness)
        );
    });
}
