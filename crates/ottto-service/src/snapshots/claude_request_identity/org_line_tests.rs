// The latest valid org line governs requests from `ACCOUNT_RULE_FROM`; earlier
// requests keep the terminal trust rule. Unit rows for `request_accounts`; the
// pipeline positive control is `claude_org_line_money_tests`.
use super::*;
use serde_json::json;

const ORG_1: &str = "11111111-1111-4111-8111-111111111111";
const ORG_2: &str = "22222222-2222-4222-8222-222222222222";

fn org_hash(uuid: &str) -> Option<String> {
    marker_org_hash(&json!({ "organizationUuid": uuid }))
}

/// Org 1 at 0, a same-org repeat at 1, an unexplained flip to org 2 at 3.
fn flipped() -> OrgMarkers {
    let mut markers = None;
    for (uuid, position) in [(ORG_1, 0), (ORG_1, 1), (ORG_2, 3)] {
        let line = json!({"type": "attachment",
            "attachment": {"type": "credential_org", "organizationUuid": uuid}});
        note_marker_line(&mut markers, &line, position);
    }
    *markers.unwrap()
}

fn orgs<const N: usize>(accounts: &RequestAccounts, sequences: [u64; N]) -> [Option<String>; N] {
    sequences.map(|sequence| accounts.account(sequence).and_then(|key| key.org.clone()))
}

fn splits(accounts: &RequestAccounts) -> Vec<u64> {
    accounts
        .runs
        .iter()
        .filter(|run| run.split)
        .map(|run| run.position)
        .collect()
}

/// [money] B1/B1b: a flip refused before `trust_from` keeps its earlier org
/// up to it and governs from it through one split run. A real line at
/// `trust_from` needs no split, so no same-position collision (B7).
#[test]
fn flip_line_before_t_governs_requests_from_trust_from() {
    let markers = flipped();
    let (one, two) = (org_hash(ORG_1), org_hash(ORG_2));
    let old = request_accounts(Some(&markers), None, Some(0), false, &[], None);
    assert_eq!(
        orgs(&old, [0, 3, 9]),
        [one.clone(), one.clone(), one.clone()]
    );
    assert!(splits(&old).is_empty());

    let split = request_accounts(Some(&markers), None, Some(0), false, &[], Some(5));
    assert_eq!(
        orgs(&split, [0, 3, 4, 5, 9]),
        [
            one.clone(),
            one.clone(),
            one.clone(),
            two.clone(),
            two.clone()
        ]
    );
    assert_eq!(splits(&split), vec![5]);

    let at_line = request_accounts(Some(&markers), None, Some(0), false, &[], Some(3));
    assert!(splits(&at_line).is_empty());
    assert_eq!(orgs(&at_line, [2, 3]), [one, two]);
}

/// [money] B8: classify and `trust_from` gate on the same provider time; an
/// unparseable time keeps the earlier rule in both.
#[test]
fn account_rule_gates_on_the_request_provider_time() {
    let from = u64::try_from(ACCOUNT_RULE_FROM / 1_000).unwrap();
    assert_eq!(rfc3339_unix_seconds("2026-11-05T00:00:00Z"), Some(from));
    assert!(!from_account_rule(Some(from - 1)));
    assert!(from_account_rule(Some(from)));
    assert!(!from_account_rule(None));
    let markers = flipped();
    assert_eq!(
        markers.verdict(3, from_account_rule(Some(from - 1))),
        MarkerVerdict::UntrustedFlip
    );
    assert_eq!(
        markers.verdict(3, from_account_rule(Some(from))),
        MarkerVerdict::Trusted(org_hash(ORG_2).as_deref().unwrap())
    );
}

/// [money] B9: both native-copy rebuilds keep `trust_from`, so a copied
/// prefix straddling T keeps the org line from it.
#[test]
fn native_copy_rebuilds_keep_trust_from() {
    let markers = flipped();
    let mut accounts = request_accounts(Some(&markers), None, Some(0), false, &[], Some(5));
    accounts.observe(0, false);
    accounts.observe(1, true);
    let decided = accounts
        .after_copy_decision(Some(&markers), &[(1, 2)], None)
        .expect("the copied repeat is excluded");
    assert_eq!(
        (decided.trust_from, orgs(&decided, [4, 9])),
        (Some(5), [org_hash(ORG_1), org_hash(ORG_2)])
    );
    accounts.finish_native(Some(&markers), true);
    assert_eq!(
        (accounts.trust_from, orgs(&accounts, [4, 9])),
        (Some(5), [org_hash(ORG_1), org_hash(ORG_2)])
    );
}
