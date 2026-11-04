// The latest valid org line governs requests from `ACCOUNT_RULE_FROM` (T);
// earlier requests keep the terminal trust rule. Runs on the real e2 pipeline
// fixture, as `claude_login_only_org_tests` does.
use super::claude_login_only_org_tests::{parts_conserve, placements};
use super::state_v2_money_tests::routed;
use super::*;
use crate::snapshots::claude_request_identity::{
    AcceptedBuckets, TELEMETRY, TELEMETRY_LOGIN, TRANSCRIPT_ORG,
};
use crate::snapshots::sampled_scan::transition_fixture::money_oracle::assert_equivalent;

/// [money] Positive control straddling T, two logins: org line 1 and gap r0,
/// an unexplained flip to org 2 and gap r1 before T; from T gap r2, complete
/// telemetry r3 (login c, org d), login-only r4 (login a) and a side call
/// (login a, org 1). Before T the flip stays refused (r0, r1: org 1); from T
/// it places the gap r2 (org 2, B1/B2); own telemetry keeps r3 (B4/B7) and
/// login-only r4 never borrows it (B11). Tokens and requests are conserved,
/// and a restarted Tail over the head before T equals the cold Full under the
/// money oracle (B1c).
#[test]
fn org_line_governs_from_t_and_a_restarted_tail_matches_cold() {
    with_e2(|| {
        let (uuid_1, uuid_2) = (
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        );
        let org = |uuid: &str| ottto_core::billing_identity_hash("anthropic", "organization", uuid);
        let (org_1, org_2) = (org(uuid_1).unwrap(), org(uuid_2).unwrap());
        let marker = |uuid: &str| {
            json!({"type":"attachment", "sessionId":ROOT,
                "attachment":{"type":"credential_org", "organizationUuid":uuid}})
            .to_string()
                + "\n"
        };
        let mut side = api_login(ROOT, "side", 4, 'a', Some('b'));
        side.request_identity
            .as_mut()
            .unwrap()
            .organization
            .log_record_hash = Some(org_1.clone());
        side.fingerprint.clear();
        side.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&side).unwrap())
        );
        let mut c = Corpus::new("org-line-from-t");
        let path = c.root(
            ROOT,
            &(marker(uuid_1)
                + &line(ROOT, "r0", "2026-11-04T23:59:00Z", 11)
                + &marker(uuid_2)
                + &line(ROOT, "r1", "2026-11-04T23:59:30Z", 12)),
        );
        c.evidence(&[side.clone()], &[trace_for(ROOT, "side", "")]);
        let pass = |scanner: &E2ScanFixture, index: ScanIndex| {
            let mut accepted = AcceptedBuckets::for_test();
            accepted.set_account_source_enabled(true);
            let mut page = c.raw(scanner, index, 100, true, &[]);
            page.enrich_with(&c, Some(&mut accepted));
            page.finish();
            page
        };
        let checks = streamed_checks(|| {
            let scanner = E2ScanFixture::capturing_identity();
            let mut warm = ready(&c, &scanner, ScanIndex::default(), 100, true);
            warm.finish();
            let prior = c.reload(&mut warm.index);
            append(
                &path,
                &(line(ROOT, "r2", "2026-11-05T00:00:10Z", 13)
                    + &line(ROOT, "r3", "2026-11-05T00:00:20Z", 14)
                    + &line(ROOT, "r4", "2026-11-05T00:00:30Z", 15)),
            );
            c.evidence(
                &[
                    api_login(ROOT, "r3", 14, 'c', Some('d')),
                    api_login(ROOT, "r4", 15, 'a', None),
                    side,
                ],
                &[
                    trace_for(ROOT, "r3", ""),
                    trace_for(ROOT, "r4", ""),
                    trace_for(ROOT, "side", ""),
                ],
            );
            let tail = pass(&scanner, prior);
            assert_mode(tail.modes, (0, 1, 0));
            let cold = pass(&E2ScanFixture::capturing_identity(), ScanIndex::default());
            let item = body(&cold, ROOT).expect("the session publishes");
            let (a, c_login, d) = ("a".repeat(64), "c".repeat(64), "d".repeat(64));
            let at = |basis: &str, login: Option<&String>, org: Option<&String>| {
                (
                    basis.to_owned(),
                    login.cloned(),
                    org.cloned(),
                    None::<crate::snapshots::AccountSource>,
                )
            };
            assert_eq!(
                (placements(item), parts_conserve(item), item.request_count),
                (
                    BTreeMap::from([
                        // r0, r1: before T the flip is refused.
                        (at(TRANSCRIPT_ORG, None, Some(&org_1)), 2),
                        // r2: from T the latest line governs the gap.
                        (at(TRANSCRIPT_ORG, None, Some(&org_2)), 1),
                        // r3 and the side call: their own complete telemetry.
                        (at(TELEMETRY, Some(&c_login), Some(&d)), 1),
                        (at(TELEMETRY, Some(&a), Some(&org_1)), 1),
                        // r4: login-only telemetry keeps no org.
                        (at(TELEMETRY_LOGIN, Some(&a), None), 1),
                    ]),
                    true,
                    6,
                ),
                "placements, conservation, requests"
            );
            assert_equivalent(
                &routed(&cold, cold.upload_policy),
                &routed(&tail, tail.upload_policy),
            );
        });
        assert!(
            checks.terminal + checks.non_terminal > 0,
            "the streamed and whole folds were compared"
        );
    });
}
