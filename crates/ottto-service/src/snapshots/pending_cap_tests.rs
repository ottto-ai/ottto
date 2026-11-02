// Capacity never invalidates: a corpus over the old pending-occurrence cap
// accumulates exactly what an unbounded one does.
use super::*;

/// [regress] Over the old cap nothing is invalidated. A page whose retained
/// occurrences exceed a budget of 1 accumulates the same families as the
/// unbounded budget, none invalid, and only the high-water alarm differs.
#[test]
fn a_corpus_over_the_old_cap_is_not_invalidated() {
    let (root, parent, items) = claude_account_family_fixture(false);
    // A copy of the first member under its own root: the two families share
    // its requests.
    let copy_id = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    let mut copy = items[0].clone();
    copy.source_session_id = copy_id.to_string();
    for fact in &mut copy.attribution_facts {
        if fact.value == parent {
            fact.value = copy_id.to_string();
        }
    }
    let mut shared = items.clone();
    shared.push(copy);

    let accumulate = |max_occurrences: usize| {
        let mut pending = UsagePending::default();
        let counts = accumulate_claude_usage_family_pending_with_limit(
            &shared,
            &mut pending,
            "2026-08-02T07:10:00Z",
            max_occurrences,
        )
        .unwrap();
        (pending, counts)
    };
    let (unbounded, counts) = accumulate(MAX_CLAUDE_PENDING_USAGE_OCCURRENCES);
    let (capped, capped_counts) = accumulate(1);
    assert_eq!(capped, unbounded);
    assert!(capped.values().all(|family| !family.invalid));
    assert!(counts.pending_occurrence_count > 1);
    assert!(!counts.pending_occurrence_cap_alarm);
    assert_eq!(
        capped_counts,
        ClaudeDuplicateCensusCounts {
            pending_occurrence_cap_alarm: true,
            ..counts
        }
    );
    let _ = fs::remove_dir_all(root);
}
