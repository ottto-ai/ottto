use super::*;
use crate::snapshots::claude_copy_containment::tests::native;
use std::io::Write;

const A: &str = "0b6b6c2e-0000-4000-8000-0000000000aa";
const B: &str = "0b6b6c2e-0000-4000-8000-0000000000bb";
const C: &str = "0b6b6c2e-0000-4000-8000-0000000000cc";

fn key(n: u8) -> ScopedSession {
    ScopedSession::new([1; 32], [n; 32])
}

fn allowance() -> Allowance {
    Allowance {
        owner_slots: crate::snapshots::MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        held_slots: crate::snapshots::MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS,
        heap_bytes: 64 * 1024 * 1024, // Synthetic shared remainder, not a runtime cap.
    }
}

fn observed(session: &str, requests: &[&str]) -> BTreeSet<String> {
    native(session, requests).claude_usage_request_ids
}

/// Seed a tiny component graph ONLY for lookup/removal tests, which mint no
/// permit and do not test admission. Never use it for positive budget claims.
fn seeded_links() -> MembershipIndex {
    let mut pool = MembershipIndex::default();
    for (held, session, ids) in [
        (key(1), A, vec!["req_shared", "req_a"]),
        (key(2), B, vec!["req_shared", "req_b"]),
    ] {
        let mut reverse = HeldMembership::default();
        for id in observed(session, &ids) {
            let id = pool
                .by_id
                .get_key_value(&id)
                .map(|(key, _)| key.clone())
                .unwrap_or_else(|| Arc::new(id));
            pool.by_id.entry(id.clone()).or_default().insert(held);
            reverse.ids.insert(id);
        }
        pool.memberships += reverse.ids.len();
        pool.by_held.insert(held, reverse);
    }
    pool
}

#[test]
fn copy_containment_membership_borrowed_native_lookup_is_not_global_coverage() {
    let pool = seeded_links();
    let peer = observed(C, &["req_shared", "req_new"]);
    let mut owners = BTreeSet::new();
    let (links, allocations) = crate::retry_allocation_probe::measure(|| {
        // Count-only callback keeps this lookup itself allocation-free.
        pool.for_each_cached_native_link(&peer, |_| {})
    });
    assert_eq!(links, 2);
    assert_eq!(allocations.allocations, 0);
    pool.for_each_cached_native_link(&peer, |held| {
        owners.insert(held);
    });
    assert_eq!(owners, BTreeSet::from([key(1), key(2)]));
    assert_eq!(
        pool.for_each_cached_native_link(&observed(C, &["req_unrelated"]), |_| panic!(
            "unrelated wake"
        )),
        0
    );
    writeln!(std::io::stderr().lock(), "copy_containment_membership_lookup: seeded_component=true admission_proved=false actual_native_links=2 unrelated_links=0 borrowed_lookup_allocations=0 miss_is_not_coverage=true").unwrap();
}

#[test]
fn copy_containment_membership_reverse_removal_visits_only_held_links() {
    let mut pool = seeded_links();
    assert_eq!(pool.remove(key(1)), 2);
    assert_eq!(pool.memberships, 2);
    assert_eq!(pool.by_held.len(), 1);
    assert!(pool.by_id.contains_key(&"req_shared".to_string()));
    assert!(!pool.by_id.contains_key(&"req_a".to_string()));
    assert_eq!(
        pool.by_id[&Arc::new("req_shared".to_string())],
        BTreeSet::from([key(2)])
    );
    assert_eq!(pool.remove(key(1)), 0);
    assert_eq!(pool.remove(key(2)), 2);
    assert!(pool.by_id.is_empty());
}

#[test]
fn copy_containment_membership_refuses_before_allocating_when_layout_or_peak_unknown() {
    let mut pool = MembershipIndex::default();
    let ids = observed(A, &["req1", "req2"]);
    let mut budget = allowance();
    budget.heap_bytes = 0;
    let (outcome, allocations) =
        crate::retry_allocation_probe::measure(|| pool.insert(key(1), ids, &budget));
    assert!(matches!(
        outcome,
        Err(Refused::UnavailableLayout | Refused::HeapBudget)
    ));
    assert_eq!(allocations.allocations, 0);
    assert!(pool.by_id.is_empty() && pool.by_held.is_empty());
    assert_eq!(pool.memberships, 0);
}

#[test]
fn copy_containment_membership_real_admission_and_once_per_peer_revision_or_guard_refusal() {
    let mut pool = MembershipIndex::default();
    let budget = allowance();
    let first = pool.insert(key(1), observed(A, &["req_shared", "req_a"]), &budget);
    if first == Err(Refused::UnavailableLayout) {
        assert!(pool.by_id.is_empty() && pool.by_held.is_empty());
        writeln!(std::io::stderr().lock(), "copy_containment_membership_admission: layout_unavailable=true no_admission=true positive_event_path_executed=false").unwrap();
        return;
    }
    let first_bound = first.expect("supported-layout synthetic input must fit");
    pool.insert(key(2), observed(B, &["req_shared", "req_b"]), &budget)
        .unwrap();
    let peer = observed(C, &["req_shared", "req_a"]);
    let mut events = BTreeSet::new();
    assert_eq!(
        pool.observe_peer(key(3), [1; 32], &peer, &budget, |held| {
            events.insert(held);
        })
        .unwrap(),
        2
    );
    assert_eq!(events, BTreeSet::from([key(1), key(2)]));
    for _ in 0..12 {
        assert_eq!(
            pool.observe_peer(key(3), [1; 32], &peer, &budget, |_| panic!(
                "same revision woke again"
            ))
            .unwrap(),
            0
        );
    }
    assert_eq!(
        pool.observe_peer(key(3), [2; 32], &peer, &budget, |_| {})
            .unwrap(),
        2
    );
    assert_eq!(
        pool.observe_peer(key(3), [2; 32], &peer, &budget, |_| panic!(
            "changed revision twice"
        ))
        .unwrap(),
        0
    );
    let actual = heap_layout_bound::completed_bound(&pool, budget.heap_bytes).unwrap();
    assert!(actual <= pool.charged_heap_upper_bound);
    writeln!(std::io::stderr().lock(), "copy_containment_membership_admission: layout_unavailable=false positive_event_path_executed=true repeated_peer_revisions=12 repeated_wakes=0 changed_peer_wakes=2 first_peak_bound={first_bound} retained_bound={actual} charged_upper_bound={} scanner_read_ack_unproved=true", pool.charged_heap_upper_bound).unwrap();
}

#[test]
fn copy_containment_membership_owner_refusal_does_not_consume_event_or_allocate() {
    let mut pool = MembershipIndex::default();
    let budget = allowance();
    if pool.insert(key(1), observed(A, &["req_shared"]), &budget) == Err(Refused::UnavailableLayout)
    {
        assert!(pool.by_held.is_empty());
        return;
    }
    let peer = observed(C, &["req_shared"]);
    let mut refused = allowance();
    refused.owner_slots = 1; // Exactly the existing membership; no new peer slot.
    let (outcome, allocations) = crate::retry_allocation_probe::measure(|| {
        pool.observe_peer(key(3), [1; 32], &peer, &refused, |_| {
            panic!("refused event emitted")
        })
    });
    assert_eq!(outcome, Err(Refused::OwnerBudget));
    assert_eq!(allocations.allocations, 0);
    assert_eq!(pool.peer_witnesses, 0);
    assert_eq!(
        pool.observe_peer(key(3), [1; 32], &peer, &budget, |_| {})
            .unwrap(),
        1
    );
}
