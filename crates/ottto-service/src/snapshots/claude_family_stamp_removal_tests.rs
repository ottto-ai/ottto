// A Claude family member's account comes only from its own request telemetry
// or creator record, never from a sibling's. One money table over the real
// evidence stage, owner gate and upload selection, against what the removed
// family stamp emitted. Synthetic fixtures only.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle::{assert_equivalent, assert_held},
    Accepted, Mode, RouteResult,
};

const CHILD_AGENT: &str = "a4d1585d310070d0f";
const MACHINE: &str = "synthetic-machine";

fn login(account: char) -> String {
    account.to_string().repeat(64)
}

/// One page's bodies as the uploader emits them.
fn route(mode: Mode, items: &[SnapshotItem]) -> RouteResult {
    let mut request = valid_v6_batch_request();
    request.source = SnapshotSource::ClaudeCode.api_slug().into();
    request.snapshots = items.to_vec();
    let batch = serde_json::to_vec(&request).unwrap();
    RouteResult::emitted(mode, SnapshotSource::ClaudeCode, vec![batch], items)
}

/// What the removed stamp did to a family member: the family's one login on
/// every row, with no request evidence behind it.
fn stamped(item: &SnapshotItem, account: &str) -> SnapshotItem {
    let mut item = item.clone();
    if set_claude_account_hash(&mut item, Some(account.to_string())) {
        rebuild_retagged_model_usage(&mut item);
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
    }
    item
}

/// The owner gate and upload selection of one page: the uploadable items.
fn uploadable(index: &mut ScanIndex, items: &[SnapshotItem]) -> Vec<SnapshotItem> {
    let mut page = items.to_vec();
    let deferred = index.bind_session_accounts(SnapshotSource::ClaudeCode, MACHINE, &mut page, &[]);
    let mut disposition = ClaudeUsageAuthorityDisposition::default();
    disposition.defer_sessions(deferred);
    disposition.retain_uploadable(&mut page);
    page
}

/// [money] Without the family stamp: a member with its own telemetry keeps
/// the same login and bytes (C1); a member without it stays Unknown with its
/// creator head unchanged (C2). A stamped body the server holds is never
/// replaced by Unknown while its session is bound, whether its ACK was kept
/// or lost (C4), including after an older store's family proof is dropped
/// (C5); an unbound session uploads Unknown, the disclosed residual. Families
/// on two accounts, with a switch or a side call, emit the same bytes as
/// before, and the candidate roots are unchanged (C7).
#[test]
fn family_stamp_removal_money_table() {
    let (dir, parent, items) = claude_account_family_fixture(false);
    let child = items[1].source_session_id.clone();
    let a = login('a');

    // C7: the roots the evidence stage reads are the files' own.
    let roots = |items: &[SnapshotItem]| {
        items
            .iter()
            .map(claude_snapshot_family_root)
            .collect::<BTreeSet<_>>()
    };
    let family = claude_account_family_evidence(&parent, &vec![a.clone(); 5]);
    let mut current = items.clone();
    apply_claude_effort_evidence(&mut current, &family);
    assert_eq!(roots(&current), roots(&items));
    assert_eq!(roots(&current).len(), 1, "one candidate root");

    // The parent's own telemetry still places it; the child is untouched.
    assert_eq!(exact_session_account_hash(&current[0]), Some(a.clone()));
    assert_eq!(
        serde_json::to_value(&current[1]).unwrap(),
        serde_json::to_value(&items[1]).unwrap(),
        "C2: no stamp"
    );
    assert_eq!(exact_session_account_hash(&current[1]), None, "C2: Unknown");
    assert_eq!(
        current[1].session_account_evidence, items[1].session_account_evidence,
        "C2: the creator head is unchanged"
    );
    let previous = vec![current[0].clone(), stamped(&current[1], &a)];
    assert_eq!(exact_session_account_hash(&previous[1]), Some(a.clone()));
    let cold = route(Mode::ColdFull, &current);

    // C4/C5: the previous build emitted the stamped child; its session is bound.
    for (case, acked, upgraded, bound) in [
        ("local tagged ACK", true, false, true),
        ("lost first ACK, bound", false, false, true),
        ("listed after upgrade, bound", true, true, true),
        ("lost first ACK, unbound", false, false, false),
        ("listed after upgrade, unbound", false, true, false),
    ] {
        let mut index = ScanIndex::default();
        if bound {
            assert_eq!(uploadable(&mut index, &previous).len(), 2, "{case}");
        }
        if upgraded {
            // An older store's family proof decodes and drops.
            let mut stored = serde_json::to_value(&index).unwrap();
            stored["claude_account_family_witnesses"] = json!({parent.as_str(): {
                "account_identifier_hash": a, "evidence_request_count": 5,
                "members": {parent.as_str(): 4, child.as_str(): 1},
                "member_request_id_fingerprints": {parent.as_str(): "b".repeat(64),
                    child.as_str(): "c".repeat(64)}}});
            index = serde_json::from_value(stored).unwrap();
            let saved = serde_json::to_value(&index).unwrap();
            assert!(
                saved.get("claude_account_family_witnesses").is_none(),
                "{case}"
            );
        }
        let mut prior = route(Mode::ColdFull, &previous);
        if acked {
            prior.accepted.insert(
                child.clone(),
                Accepted {
                    body: prior.snapshots[&child].clone(),
                    witness: snapshot_upload_body_witness(&previous[1]),
                },
            );
        }
        let sent = uploadable(&mut index, &current);
        let mut resent = route(Mode::Restart, &sent);
        resent.accepted = prior.accepted.clone();
        if bound {
            // Deferred: the server keeps the stamped placement it holds.
            assert_eq!(sent.len(), 1, "{case}");
            assert_eq!(sent[0].source_session_id, parent, "{case}");
            if acked {
                assert_held(&child, &prior, &resent, &cold);
            } else {
                assert!(!resent.snapshots.contains_key(&child), "{case}");
            }
        } else {
            // Unbound: uploads Unknown; nothing local named the stamp.
            assert_eq!(sent.len(), 2, "{case}");
            assert_equivalent(&cold, &resent);
            assert_eq!(exact_session_account_hash(&sent[1]), None, "{case}");
        }
    }

    // C1: the child's own telemetry and trace owner give the same login the
    // stamp gave, so its body is the same bytes with or without the stamp
    // (the stamp ran in the evidence stage, before this request pass).
    let (owned_dir, owned_parent, owned) = claude_account_family_fixture(true);
    let mut child_owned = owned[1].clone();
    let api = vec![complete_api_row(&owned_parent, "req_5", 5, 10, 1, 0)];
    let trace = vec![complete_trace_row(&owned_parent, "req_5", CHILD_AGENT)];
    assert!(d1_subagent_account_specimen(&mut child_owned, &api, &trace));
    assert_eq!(exact_session_account_hash(&child_owned), Some(a.clone()));
    let mut with_stamp = stamped(&owned[1], &a);
    d1_subagent_account_specimen(&mut with_stamp, &api, &trace);
    assert_equivalent(
        &route(Mode::ColdFull, std::slice::from_ref(&with_stamp)),
        &route(Mode::Ram, std::slice::from_ref(&child_owned)),
    );

    // Positive controls: two accounts with a switch at req_3, and a side call
    // on the second account. No single login, so neither build stamped.
    let b = login('b');
    let switch = claude_account_family_evidence(
        &parent,
        &[a.clone(), a.clone(), b.clone(), b.clone(), b.clone()],
    );
    let mut side = family.clone();
    let mut call = side[&parent][0].clone();
    call.fingerprint = "family-side".into();
    call.request_id = "req_side".into();
    call.account_identifier_hash = Some(b.clone());
    side.get_mut(&parent).unwrap().push(call);
    for (case, evidence) in [("switch", switch), ("side call", side)] {
        let mut page = items.clone();
        apply_claude_effort_evidence(&mut page, &evidence);
        assert_eq!(exact_session_account_hash(&page[0]), None, "{case}");
        assert_eq!(exact_session_account_hash(&page[1]), None, "{case}");
        assert_equivalent(&route(Mode::ColdFull, &items), &route(Mode::Ram, &page));
    }
    fs::remove_dir_all(dir).unwrap();
    fs::remove_dir_all(owned_dir).unwrap();
}
