// Request-local placement through the native scan, Tail, durable store and ACK adapters.
use super::claude_login_only_org_tests::{parts_conserve, placements, Placement};
use super::state_v2_money_tests::routed;
use super::*;
use crate::snapshots::claude_request_identity::{
    take_identity_counts, AcceptedBuckets, SPANLESS_FIRST_REQUEST_FROM, TELEMETRY,
};
use crate::snapshots::e2_pipeline_scan_fixture::route_of;
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle::{assert_equivalent, assert_no_smaller_reemit, assert_quiet_restart_zero_bytes},
    upgrade_from_legacy_store, Mode,
};
use crate::snapshots::AccountSource;

/// RFC 3339 `offset` seconds from the span-less first-request cutoff.
fn cutoff_clock(offset: i64) -> String {
    OffsetDateTime::from_unix_timestamp(
        i64::try_from(SPANLESS_FIRST_REQUEST_FROM).unwrap() + offset,
    )
    .unwrap()
    .format(&Rfc3339)
    .unwrap()
}

/// The rows observed at `at`, re-signed.
fn stamp(rows: &mut [crate::claude_local_otel::ClaudeLocalOtelEvidence], at: &str) {
    for row in rows {
        row.observed_at = at.into();
        row.fingerprint.clear();
        row.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(row).unwrap())
        );
    }
}

/// The placement of `login`'s complete telemetry with `org`.
fn own(login: char, org: char, source: Option<AccountSource>) -> Placement {
    (
        TELEMETRY.to_owned(),
        Some(login.to_string().repeat(64)),
        Some(org.to_string().repeat(64)),
        source,
    )
}

/// One page of `scanner` over `index`, with this cycle's account-source hints.
fn pass(c: &Corpus, scanner: &E2ScanFixture, index: ScanIndex) -> Page {
    let mut accepted = AcceptedBuckets::for_test();
    accepted.set_account_source_enabled(true);
    let mut page = c.raw(scanner, index, 100, true, &[]);
    page.enrich_with(c, Some(&mut accepted));
    deliver_page(page)
}

/// [money] A span-less start seeds only its own stream; switching, gaps and side calls
/// retain placement through Tail, restore and upgrade. Deliberately red before the rule.
#[test]
fn first_request_own_login_transition_oracle() {
    with_e2(|| {
        let mut c = Corpus::new("first-request-own-login");
        let at = cutoff_clock(0);
        let parent = c.root(ROOT, &line(ROOT, "first", &at, 11));
        let mut rows = vec![api_login(ROOT, "first", 11, 'a', Some('b'))];
        stamp(&mut rows, &at);
        c.evidence(&rows, &[]);
        let scanner = E2ScanFixture::capturing_identity();
        let warm = pass(&c, &scanner, ScanIndex::default());
        let prior = settle(&c, &ScanIndex::default(), warm, &mut e2_progress());
        append(
            &parent,
            &(line(ROOT, "gap-a", &cutoff_clock(1), 12)
                + &line(ROOT, "switch", &cutoff_clock(2), 13)
                + &line(ROOT, "gap-c", &cutoff_clock(3), 14)),
        );
        c.agent(0, &line(ROOT, "child-gap", &cutoff_clock(4), 15));
        rows.extend([
            api_login(ROOT, "switch", 13, 'c', Some('d')),
            api_login(ROOT, "side", 4, 'c', Some('d')),
        ]);
        stamp(&mut rows, &at);
        c.evidence(&rows, &[trace("switch", ""), trace("side", "")]);
        // Both owners read the same committed heads and neither commits while
        // reading: the retained owner keeps its RAM, the restarted one has only
        // the state database. Only the retained page is settled below.
        let route = route_of(&prior).unwrap();
        scanner.on_committed_route(&route);
        let mut tail = pass(&c, &scanner, prior.clone());
        let restored_owner = E2ScanFixture::capturing_identity();
        restored_owner.on_committed_route(&route);
        let mut restored = pass(&c, &restored_owner, prior.clone());
        let upgraded = upgrade_from_legacy_store(&prior, &c.base.join("upgrade.json"));
        let mut upgrade = pass(&c, &E2ScanFixture::capturing_identity(), upgraded);
        let mut cold = pass(
            &c,
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
        );
        for page in [&mut tail, &mut restored, &mut upgrade, &mut cold] {
            page.finish();
        }
        assert!(tail.modes.1 > 0, "the retained owner must Tail the growth");
        assert!(
            restored.modes.1 > 0,
            "the restored owner must Tail committed heads"
        );
        assert_eq!(
            cold.modes.1 + cold.modes.2,
            0,
            "cold Full cannot reuse a head"
        );
        let expected = routed(&cold, cold.upload_policy);
        for page in [&tail, &restored, &upgrade] {
            let route = routed(page, page.upload_policy);
            assert_equivalent(&expected, &route);
            assert_no_smaller_reemit(ROOT, &expected, &route, &expected, false);
        }
        let item = body(&cold, ROOT).expect("nonempty positive control");
        let placed = placements(item);
        assert_eq!(
            placed.get(&own('a', 'b', None)),
            Some(&1),
            "span-less first owns A"
        );
        assert_eq!(
            placed.get(&own('a', 'b', Some(AccountSource::CarriedForward))),
            Some(&1)
        );
        assert_eq!(
            placed.get(&own('c', 'd', None)),
            Some(&2),
            "switch and side call own C"
        );
        assert_eq!(
            placed.get(&own('c', 'd', Some(AccountSource::CarriedForward))),
            Some(&1)
        );
        assert!(parts_conserve(item));
        assert_eq!(item.request_count, 5);
        let a = "a".repeat(64);
        let child = body(&cold, &format!("{ROOT}_agent-000")).expect("child emitted");
        assert!(parts_conserve(child));
        assert!(
            placements(child)
                .keys()
                .all(|(_, login, _, _)| login.as_ref() == Some(&a)),
            "child uses root start A, never the later switch C"
        );
        // The accepted upload's exact receipts are saved; an unchanged restarted scan
        // must consume no transcript byte and publish no smaller replacement.
        let settled = settle(&c, &prior, tail, &mut e2_progress());
        let restarted = E2ScanFixture::capturing_identity();
        restarted.on_committed_route(&route_of(&settled).unwrap());
        let ((quiet, bytes), samples) = crate::transcript_acquisition::capture_sample_reads(|| {
            crate::snapshots::sampled_scan::transition_fixture::observe_consumed(|| {
                ready(&c, &restarted, settled, 100, true)
            })
        });
        assert!(
            restarted.paths().is_empty(),
            "metadata-only restart selects no transcript"
        );
        let mut quiet_route = routed(&quiet, quiet.upload_policy);
        quiet_route.mode = Mode::Restart;
        quiet_route.modes = quiet.modes;
        quiet_route.io.consumed = bytes;
        // No selected transcript means no head/named-line/other transcript reader;
        // acquisition's actual sample reads are captured independently above.
        quiet_route.io.cheap_checks = Some(0);
        quiet_route.io.other_reads = Some(0);
        quiet_route.io.anchor_reads = Some(
            samples
                .iter()
                .map(|read| u64::try_from(read.result.expect("sample read succeeds")).unwrap())
                .sum(),
        );
        assert_quiet_restart_zero_bytes(&quiet_route);
        assert!(
            quiet.scan.snapshots.is_empty(),
            "quiet restart emits no replacement"
        );
    });
}

/// [money] Growth after an ACKed span-less first: a later id-less or
/// multi-iteration response (next hour) leaves the accepted hour's own A share,
/// its carried gap and the child's start unchanged, with the warm pass's
/// accepted buckets carried into Tail. Deliberately red before the rule.
#[test]
fn first_request_own_login_survives_later_growth() {
    for later in ["id-less", "multi-iteration"] {
        with_e2(|| {
            let mut c = Corpus::new(&format!("first-request-growth-{later}"));
            let parent = c.root(
                ROOT,
                &(line(ROOT, "first", &cutoff_clock(0), 11)
                    + &line(ROOT, "gap-a", &cutoff_clock(1), 12)),
            );
            c.agent(0, &line(ROOT, "child-gap", &cutoff_clock(2), 15));
            let mut rows = vec![api_login(ROOT, "first", 11, 'a', Some('b'))];
            stamp(&mut rows, &cutoff_clock(0));
            c.evidence(&rows, &[]);
            let mut ledger = AcceptedBuckets::for_test();
            ledger.set_account_source_enabled(true);
            let scanner = E2ScanFixture::capturing_identity();
            let mut warm = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
            warm.enrich_with(&c, Some(&mut ledger));
            for item in &warm.scan.snapshots {
                ledger.record(&serde_json::to_value(item).unwrap());
            }
            let accepted = body(&warm, ROOT).expect("the root publishes").clone();
            let prior = settle(
                &c,
                &ScanIndex::default(),
                deliver_page(warm),
                &mut e2_progress(),
            );
            let mut next: serde_json::Value =
                serde_json::from_str(&line(ROOT, "later", &cutoff_clock(3600), 13)).unwrap();
            if later == "id-less" {
                next.as_object_mut().unwrap().remove("requestId");
            } else {
                next["message"]["usage"]["iterations"] = json!([
                    {"input_tokens": 6, "output_tokens": 6},
                    {"input_tokens": 7, "output_tokens": 7}
                ]);
            }
            append(&parent, &(next.to_string() + "\n"));
            let mut tail = c.raw(&scanner, prior, 100, true, &[]);
            assert!(tail.modes.1 > 0, "{later}: the growth reads as Tail");
            take_identity_counts();
            tail.enrich_with(&c, Some(&mut ledger));
            let counts = serde_json::to_value(take_identity_counts()).unwrap();
            assert_eq!(
                identity_count(&counts, "accepted_share_changed"),
                0,
                "{later}: no ACKed share moves"
            );
            let hour = accepted.usage_buckets[0].bucket_start.clone();
            let accepted_hour = |item: &SnapshotItem| {
                let mut only = item.clone();
                only.usage_buckets
                    .retain(|bucket| bucket.bucket_start == hour);
                placements(&only)
            };
            assert_eq!(
                accepted_hour(&accepted),
                BTreeMap::from([
                    (own('a', 'b', None), 1),
                    (own('a', 'b', Some(AccountSource::CarriedForward)), 1),
                ]),
                "span-less first owns A and seeds its gap"
            );
            let root = body(&tail, ROOT).expect("the grown root publishes");
            assert_eq!(
                accepted_hour(root),
                accepted_hour(&accepted),
                "{later}: the accepted hour is unchanged"
            );
            assert!(parts_conserve(root));
            assert_eq!(root.request_count, accepted.request_count + 1, "{later}");
            let a = "a".repeat(64);
            if let Some(child) = body(&tail, &format!("{ROOT}_agent-000")) {
                assert!(
                    placements(child)
                        .keys()
                        .all(|(_, login, _, _)| login.as_ref() == Some(&a)),
                    "{later}: the child keeps root start A"
                );
            }
        });
    }
}

/// [money] A resume copy holding the span-less first's copied response never
/// takes the original's own login; the original keeps it, and each request
/// counts exactly once.
#[test]
fn first_request_own_login_copy_never_takes_the_original_login() {
    with_e2(|| {
        let mut c = Corpus::new("first-request-own-login-copy");
        let at = cutoff_clock(0);
        c.root(ROOT, &line(ROOT, "first", &at, 11));
        let mut rows = vec![api_login(ROOT, "first", 11, 'a', Some('b'))];
        stamp(&mut rows, &at);
        c.evidence(&rows, &[]);
        let scanner = E2ScanFixture::capturing_identity();
        let warm = pass(&c, &scanner, ScanIndex::default());
        assert_eq!(
            body(&warm, ROOT).map(|root| placements(root).get(&own('a', 'b', None)).copied()),
            Some(Some(1)),
            "span-less first owns A"
        );
        let prior = settle(&c, &ScanIndex::default(), warm, &mut e2_progress());
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(line(COPY, "first", &at, 11) + &line(COPY, "own", &cutoff_clock(190), 0)),
            &cutoff_clock(180),
        );
        let mut tail = pass(&c, &scanner, prior);
        let mut cold = pass(
            &c,
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
        );
        for page in [&mut tail, &mut cold] {
            page.finish();
        }
        for page in [&tail, &cold] {
            let copy = body(page, COPY).expect("the copy publishes");
            assert!(parts_conserve(copy));
            assert_eq!(
                placements(copy).get(&own('a', 'b', None)),
                None,
                "the copy never takes the original's own login"
            );
            if let Some(root) = body(page, ROOT) {
                assert_eq!(placements(root).get(&own('a', 'b', None)), Some(&1));
            }
        }
        let root = body(&cold, ROOT).expect("cold Full publishes the original");
        let copy = body(&cold, COPY).expect("cold Full publishes the copy");
        assert_eq!(
            root.request_count + copy.request_count,
            2,
            "the original's request and the copy's own turn, each once"
        );
    });
}
