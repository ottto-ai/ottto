//! Reused-session heads come only from validated read snapshots.
use super::*;
use crate::snapshots::usage_pending::tests::family;

fn hydrate(path: &Path) -> (ScanIndex, u64) {
    telemetry::pass_start();
    let index = load_with(path, false).unwrap().unwrap();
    (index, telemetry::decoded_rows_for_test())
}

/// [behaviour] Unchanged families skip decoding, changed families refold, and
/// deletion/reopen discard old memo entries without changing the stored graph.
#[test]
fn reused_session_refolds_only_changed_usage_families() {
    let f = Fixture::new();
    let mut pre = ScanIndex::default();
    for root in ["changed", "unchanged", "removed"] {
        pre.claude_usage_family_pending
            .insert(root.into(), family("w1", 2, false));
    }
    f.import_graph(Some(&pre));
    fence::publish(&f.path, &f.identity(), &mut false).unwrap();
    let initial = load_with(&f.path, false).unwrap().unwrap();
    let runtime = initial.v2().persistence_v2.clone().unwrap();
    runtime
        .session
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .usage_memo
        .clear();
    let (first, first_rows) = hydrate(&f.path);
    let per_family = 1 + pre.claude_usage_family_pending["changed"]
        .member_request_id_hashes
        .len() as u64;
    let (mut second, second_rows) = hydrate(&f.path);
    assert!(Arc::ptr_eq(
        &runtime,
        second.v2().persistence_v2.as_ref().unwrap()
    ));
    assert_eq!(
        first_rows - second_rows,
        3 * per_family,
        "each unchanged family skips its row and interned request sets"
    );
    let mut expected = materialized(&first);
    assert_eq!(
        serde_json::to_vec(&expected).unwrap(),
        serde_json::to_vec(&materialized(&second)).unwrap()
    );
    load_usage(&mut second, &BTreeSet::from(["changed".into()])).unwrap();
    second
        .claude_usage_family_pending
        .family_mut("changed")
        .unwrap()
        .unwrap()
        .invalid = true;
    assert!(save_with(&f.path, &mut second).unwrap());
    let (mut third, third_rows) = hydrate(&f.path);
    assert!(Arc::ptr_eq(
        &runtime,
        third.v2().persistence_v2.as_ref().unwrap()
    ));
    assert_eq!(
        third_rows,
        second_rows + per_family,
        "only changed family refolds"
    );
    expected.generation = third.generation;
    expected
        .claude_usage_family_pending
        .get_mut("changed")
        .unwrap()
        .invalid = true;
    assert_eq!(
        serde_json::to_vec(&materialized(&third)).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    third.claude_usage_family_pending.discard("removed");
    assert!(save_with(&f.path, &mut third).unwrap());
    let (fourth, _) = hydrate(&f.path);
    let memo: kinds_accounts::UsageMemo = {
        let guard = runtime.session.lock().unwrap();
        let blob = &guard.as_ref().unwrap().usage_memo;
        serde_json::from_slice(&codec::expand(blob, isize::MAX as u64).unwrap()).unwrap()
    };
    assert_eq!(
        memo.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from(["changed".into(), "unchanged".into()])
    );
    let expected = materialized(&fourth);
    // A fresh session repeats the eager sweep.
    runtime.session.lock().unwrap().take();
    let (reopened, reopened_rows) = hydrate(&f.path);
    assert!(!Arc::ptr_eq(
        &runtime,
        reopened.v2().persistence_v2.as_ref().unwrap()
    ));
    assert!(reopened_rows >= second_rows + 2 * per_family);
    assert_eq!(
        serde_json::to_vec(&expected).unwrap(),
        serde_json::to_vec(&materialized(&reopened)).unwrap()
    );
}
