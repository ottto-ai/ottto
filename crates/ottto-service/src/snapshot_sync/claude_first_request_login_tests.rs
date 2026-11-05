// Request-local placement through the native scan, Tail, durable store and ACK adapters.
use super::claude_login_only_org_tests::{parts_conserve, placements};
use super::state_v2_money_tests::routed;
use super::*;
use crate::snapshots::claude_request_identity::{AcceptedBuckets, TELEMETRY};
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle::{assert_equivalent, assert_no_smaller_reemit, assert_quiet_restart_zero_bytes},
    upgrade_from_legacy_store, Mode,
};
use crate::snapshots::AccountSource;

/// [money] A span-less start seeds only its own stream; switching, gaps and side calls
/// retain placement through Tail, restore and upgrade. Deliberately red before the rule.
#[test]
fn first_request_own_login_transition_oracle() {
    with_e2(|| {
        let mut c = Corpus::new("first-request-own-login");
        let at = "2026-11-06T00:00:00Z";
        let parent = c.root(ROOT, &line(ROOT, "first", at, 11));
        let mut rows = vec![api_login(ROOT, "first", 11, 'a', Some('b'))];
        let stamp = |rows: &mut Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>| {
            for row in rows {
                row.observed_at = at.into();
                row.fingerprint.clear();
                row.fingerprint = format!(
                    "sha256:{:x}",
                    Sha256::digest(serde_json::to_vec(row).unwrap())
                );
            }
        };
        stamp(&mut rows);
        c.evidence(&rows, &[]);
        let pass = |scanner: &E2ScanFixture, index: ScanIndex| {
            let mut accepted = AcceptedBuckets::for_test();
            accepted.set_account_source_enabled(true);
            let mut page = c.raw(scanner, index, 100, true, &[]);
            page.enrich_with(&c, Some(&mut accepted));
            deliver_page(page)
        };
        let scanner = E2ScanFixture::capturing_identity();
        let warm = pass(&scanner, ScanIndex::default());
        let prior = settle(&c, &ScanIndex::default(), warm, &mut e2_progress());
        append(
            &parent,
            &(line(ROOT, "gap-a", "2026-11-06T00:00:01Z", 12)
                + &line(ROOT, "switch", "2026-11-06T00:00:02Z", 13)
                + &line(ROOT, "gap-c", "2026-11-06T00:00:03Z", 14)),
        );
        let child = c.root.join(format!("{ROOT}/subagents/agent-000.jsonl"));
        std::fs::create_dir_all(child.parent().unwrap()).unwrap();
        std::fs::write(&child, line(ROOT, "child-gap", "2026-11-06T00:00:04Z", 15)).unwrap();
        rows.extend([
            api_login(ROOT, "switch", 13, 'c', Some('d')),
            api_login(ROOT, "side", 4, 'c', Some('d')),
        ]);
        stamp(&mut rows);
        c.evidence(&rows, &[trace("switch", ""), trace("side", "")]);
        let mut tail = pass(&scanner, prior.clone());
        let restored_owner = E2ScanFixture::capturing_identity();
        let saved_route = crate::snapshots::e2_pipeline_scan_fixture::route_of(&prior).unwrap();
        restored_owner.on_committed_route(&saved_route);
        let mut restored = pass(&restored_owner, prior.clone());
        let upgraded = upgrade_from_legacy_store(&prior, &c.base.join("upgrade.json"));
        let mut upgrade = pass(&E2ScanFixture::capturing_identity(), upgraded);
        let mut cold = pass(&E2ScanFixture::capturing_identity(), ScanIndex::default());
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
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let cc = "c".repeat(64);
        let d = "d".repeat(64);
        let key = |login: &String, org: &String, source| {
            (
                TELEMETRY.to_owned(),
                Some(login.clone()),
                Some(org.clone()),
                source,
            )
        };
        let placed = placements(item);
        assert_eq!(
            placed.get(&key(&a, &b, None)),
            Some(&1),
            "span-less first owns A"
        );
        assert_eq!(
            placed.get(&key(&a, &b, Some(AccountSource::CarriedForward))),
            Some(&1)
        );
        assert_eq!(
            placed.get(&key(&cc, &d, None)),
            Some(&2),
            "switch and side call own C"
        );
        assert_eq!(
            placed.get(&key(&cc, &d, Some(AccountSource::CarriedForward))),
            Some(&1)
        );
        assert!(parts_conserve(item));
        assert_eq!(item.request_count, 5);
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
        restarted.on_committed_route(
            &crate::snapshots::e2_pipeline_scan_fixture::route_of(&settled).unwrap(),
        );
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
