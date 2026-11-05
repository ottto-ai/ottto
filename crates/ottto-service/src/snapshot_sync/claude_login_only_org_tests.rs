// Login-only Claude telemetry keeps its login and never borrows a trusted
// transcript marker's org, even one that complete telemetry pairs with that
// login. Runs on the real e2 pipeline fixture: its corpus, evidence, streamed
// comparison and upload are the native test adapters.
use super::state_v2_money_tests::routed;
use super::*;
use crate::snapshots::claude_request_identity::{
    AcceptedBuckets, TELEMETRY, TELEMETRY_LOGIN, TRANSCRIPT_ORG,
};
use crate::snapshots::sampled_scan::transition_fixture::money_oracle::assert_equivalent;
use crate::snapshots::AccountSource;

/// (basis, login, org, account source); untagged shares have an empty basis.
pub(super) type Placement = (
    String,
    Option<String>,
    Option<String>,
    Option<AccountSource>,
);

/// Requests per placement over `item`'s bucket rows.
pub(super) fn placements(item: &SnapshotItem) -> BTreeMap<Placement, u64> {
    let mut placed = BTreeMap::new();
    for row in item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
    {
        let shares = match &row.identity_parts {
            Some(parts) => parts
                .iter()
                .map(|part| {
                    (
                        &part.account_identifier_hash,
                        part.evidence_ref,
                        part.request_count,
                    )
                })
                .collect(),
            None => vec![(
                &row.account_identifier_hash,
                row.evidence_ref,
                row.request_count,
            )],
        };
        for (login, at, requests) in shares {
            let key = at.map_or((String::new(), None, None, None), |at| {
                let evidence = &item.request_evidence[usize::from(at)];
                (
                    evidence.identity_basis.clone(),
                    login.clone(),
                    evidence.provider_workspace_hash.clone(),
                    evidence.account_source,
                )
            });
            *placed.entry(key).or_default() += requests;
        }
    }
    placed
}

/// Every identity part sums to its bucket row.
pub(super) fn parts_conserve(item: &SnapshotItem) -> bool {
    item.usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
        .all(|row| {
            row.identity_parts.as_ref().map_or(true, |parts| {
                parts.iter().map(|part| part.input_tokens).sum::<u64>() == row.input_tokens
                    && parts.iter().map(|part| part.request_count).sum::<u64>() == row.request_count
            })
        })
}

/// [money] One session, two logins: gap r0, trusted marker org B, marker-placed
/// gap r1, login-only r2 of login A (its first own request), gap r3, then a
/// switch to (C, D) at r4, and a side call whose complete telemetry pairs A
/// with B. Old -> new placement: r2 (A, B) -> (A, no org); r0 untagged ->
/// (A, no org) carried backward; r3 marker org B -> (A, no org) carried
/// forward; r1, r4 and the side call unchanged. Tokens and requests are
/// conserved, and a Tail over the marker head equals a cold Full under the
/// money oracle, with every enrichment also compared streamed against whole.
#[test]
fn login_only_telemetry_never_borrows_a_proven_marker_org() {
    with_e2(|| {
        let org_uuid = "11111111-1111-4111-8111-111111111111";
        let org_b =
            ottto_core::billing_identity_hash("anthropic", "organization", org_uuid).unwrap();
        let marker = json!({"type":"attachment", "sessionId":ROOT,
            "attachment":{"type":"credential_org", "organizationUuid":org_uuid}})
        .to_string()
            + "\n";
        let mut side = api_login(ROOT, "side", 4, 'a', Some('b'));
        std::sync::Arc::make_mut(side.request_identity.as_mut().unwrap())
            .organization
            .log_record_hash = Some(org_b.clone());
        side.fingerprint.clear();
        side.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&side).unwrap())
        );
        let r2 = api_login(ROOT, "r2", 13, 'a', None);
        let mut c = Corpus::new("login-only-org");
        let path = c.root(
            ROOT,
            &(line(ROOT, "r0", "2026-08-02T07:00:20Z", 11)
                + &marker
                + &line(ROOT, "r1", "2026-08-02T07:00:30Z", 12)
                + &line(ROOT, "r2", "2026-08-02T07:00:40Z", 13)),
        );
        c.evidence(
            &[r2.clone(), side.clone()],
            &[trace_for(ROOT, "r2", ""), trace_for(ROOT, "side", "")],
        );
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
                &(line(ROOT, "r3", "2026-08-02T07:00:50Z", 14)
                    + &line(ROOT, "r4", "2026-08-02T07:01:00Z", 15)),
            );
            c.evidence(
                &[r2, api_login(ROOT, "r4", 15, 'c', Some('d')), side],
                &[
                    trace_for(ROOT, "r2", ""),
                    trace_for(ROOT, "r4", ""),
                    trace_for(ROOT, "side", ""),
                ],
            );
            let tail = pass(&scanner, prior);
            assert_mode(tail.modes, (0, 1, 0));
            let cold = pass(&E2ScanFixture::capturing_identity(), ScanIndex::default());
            let item = body(&cold, ROOT).expect("the session publishes");
            let (a, c_login, d) = ("a".repeat(64), "c".repeat(64), "d".repeat(64));
            let at = |basis: &str,
                      login: Option<&String>,
                      org: Option<&String>,
                      source: Option<AccountSource>| {
                (basis.to_owned(), login.cloned(), org.cloned(), source)
            };
            assert_eq!(
                (placements(item), parts_conserve(item), item.request_count),
                (
                    BTreeMap::from([
                        // r0, r2, r3: login A with no org.
                        (
                            at(
                                TELEMETRY_LOGIN,
                                Some(&a),
                                None,
                                Some(AccountSource::CarriedBackward)
                            ),
                            1
                        ),
                        (at(TELEMETRY_LOGIN, Some(&a), None, None), 1),
                        (
                            at(
                                TELEMETRY_LOGIN,
                                Some(&a),
                                None,
                                Some(AccountSource::CarriedForward)
                            ),
                            1
                        ),
                        // r1: the marker org.
                        (at(TRANSCRIPT_ORG, None, Some(&org_b), None), 1),
                        // r4 and the side call: their own complete telemetry.
                        (at(TELEMETRY, Some(&c_login), Some(&d), None), 1),
                        (at(TELEMETRY, Some(&a), Some(&org_b), None), 1),
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
