use super::*;
use crate::snapshot_sync::retained_with_withheld;
use crate::source_rotation::{Owner, PaidReservation, Step, PARKED_BUDGET};
use std::time::Duration;

fn seed_held_memo(memo: &withheld_account::Memo) {
    let mut index = ScanIndex {
        withheld_memo: memo.clone(),
        ..ScanIndex::default()
    };
    let mut deferred = BTreeMap::new();
    for slot in 0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS {
        let key = format!("/opaque/owner-charge-{slot}.jsonl");
        let fingerprint = format!("held-{slot}");
        index
            .file_snapshot_fingerprints
            .insert(key, BTreeSet::from([fingerprint.clone()]));
        deferred.insert(fingerprint, 1);
    }
    let keys: Vec<_> = index.file_snapshot_fingerprints.keys().cloned().collect();
    assert!(index.record_claude_account_deferred_holds(
        keys.iter().map(|key| (key.as_str(), "parsed")),
        &deferred,
    ));
    assert_eq!(
        index.claude_account_deferred_hold_count(),
        MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
    );
}

fn assert_unavailable_population(memo: &withheld_account::Memo) {
    assert_eq!(
        serde_json::to_value(memo.held_gauge()).unwrap(),
        json!({
            "withheld_held_count": MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS,
            "withheld_memo_unavailable": true
        }),
        "refusal preserves population and omits unknown tokens/ages"
    );
    assert!(memo.census().is_none());
}
/// [behaviour] Withheld refusal preserves a fully admitted sibling charge.

#[test]
fn withheld_refusal_preserves_a_fully_admitted_sibling_charge() {
    let state = withheld_account::Memo::default();
    seed_held_memo(&state);
    assert!(state.retained_bound(PARKED_BUDGET).is_some());
    // Include the no-remainder case: even an empty memo's conservative charge
    // must not make a fully admitted sibling trigger owner-wide discard.
    for limit in [PARKED_BUDGET, 0] {
        assert_eq!(
            retained_with_withheld(&state, limit, |available| {
                assert_eq!(available, limit, "siblings receive the full allowance");
                Some(available)
            }),
            Some(limit)
        );
        assert_unavailable_population(&state);
    }
}
/// [behaviour] Unsupported sibling preserves only a memo that fits the allowance.

#[test]
fn unsupported_sibling_preserves_only_a_memo_that_fits_the_allowance() {
    let state = withheld_account::Memo::default();
    seed_held_memo(&state);
    let memo = state.retained_bound(PARKED_BUDGET).unwrap();
    assert_eq!(retained_with_withheld(&state, memo, |_| None), None);
    // This is the rotation's sibling-refusal cleanup, not an admission of an
    // unpriced sibling. The portable graph must survive this exact-fit case.
    state.discard_if_refused();
    assert_eq!(state.retained_bound(memo), Some(memo));
    let gauge = serde_json::to_value(state.held_gauge()).unwrap();
    assert_eq!(gauge["withheld_memo_unavailable"], false);
    assert_eq!(
        gauge["withheld_held_tokens"],
        MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
    );
    assert_eq!(retained_with_withheld(&state, memo - 1, |_| None), None);
    state.discard_if_refused();
    assert_unavailable_population(&state);
}

struct Cycle {
    memo: withheld_account::Memo,
    native: Arc<claude_native_comparison::lifecycle::Lifecycle>,
    versions: Arc<codex_version::CodexVersionFeed>,
    memo_charge: usize,
    discards: usize,
    completions: usize,
}
impl Cycle {
    fn other_bound(&self, limit: usize) -> Option<usize> {
        let versions = crate::heap_layout_bound::bound(&self.versions, limit)?;
        let native = self.native.retained_bound(limit.checked_sub(versions)?)?;
        versions.checked_add(native)
    }
}
// One serial source: the rotation budget alone creates the contention.
impl Owner for Cycle {
    type Source = ();
    type Frame = ();
    type Completed = ();

    fn prepare(&mut self, _: (), remaining: Option<usize>) -> Result<Option<()>> {
        assert!(remaining.is_some());
        Ok(Some(()))
    }
    fn validate(&mut self, _: &()) -> Result<()> {
        Ok(())
    }
    fn step(&mut self, _: (), remaining: Option<usize>) -> Step<(), ()> {
        assert!(remaining.is_some());
        Step::Complete(())
    }
    fn finish(&mut self, _: (), remaining: Option<usize>) -> Result<()> {
        let empty_memo = self.memo.retained_bound(PARKED_BUDGET).unwrap();
        let available = remaining.unwrap() + self.other_bound(PARKED_BUDGET).unwrap() + empty_memo;
        seed_held_memo(&self.memo);
        let other = self.other_bound(available).unwrap();
        assert!(self.memo_charge <= available, "memo alone fits");
        assert!(other <= available, "real sibling graphs alone fit");
        assert!(
            self.memo_charge + other > available,
            "composition must refuse one graph"
        );
        Ok(())
    }
    fn outcome(&mut self, _: (), result: Result<()>) {
        result.unwrap();
        self.completions += 1;
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn retained_bound(&self, limit: usize) -> Option<usize> {
        retained_with_withheld(&self.memo, limit, |available| self.other_bound(available))
    }
    fn discard_retained(&mut self) {
        self.discards += 1;
        // Match SnapshotCycleOwner's native and memo cleanup. This real native
        // policy graph would latch process_base_exit if composition refused it.
        self.native.discard_retained();
        self.memo.discard_if_refused();
    }
    fn retained_budget_unavailable(&mut self) {
        self.memo.discard_retained();
        self.discard_retained();
    }
}
/// [behaviour] Cap sized memo refusal does not base exit real native comparison.

#[test]
fn cap_sized_memo_refusal_does_not_base_exit_real_native_comparison() {
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("UNEXECUTED positive native owner charge: unsupported layout; no gate override");
        return;
    }
    assert_eq!(PARKED_BUDGET, 8 * 1024 * 1024);
    let native = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut lease = native.begin();
    lease.bind("owner-charge-context".into());
    lease.observe_policy_page("owner-charge-window", 1);
    let mut credit = PaidReservation::from_remainder(Some(PARKED_BUDGET), 0, 0);
    assert!(lease
        .defer_family("native-family", false, (1, 1), &mut credit)
        .unwrap());
    lease.note_selected_save(true);
    lease.finish(true);
    assert!(native.retained_valid_for_test());
    let native_charge = native.retained_bound(PARKED_BUDGET).unwrap();
    assert!(native_charge > 0, "retain the real family-policy graph");

    let state = withheld_account::Memo::default();
    seed_held_memo(&state);
    let memo_charge = state.retained_bound(PARKED_BUDGET).unwrap();
    let mut owner = Cycle {
        memo: state.clone(),
        native,
        versions: Arc::new(codex_version::CodexVersionFeed::new(None)),
        memo_charge,
        discards: 0,
        completions: 0,
    };
    let other = owner.other_bound(PARKED_BUDGET).unwrap();
    assert_eq!(
        owner.retained_bound(PARKED_BUDGET),
        Some(other + memo_charge)
    );
    assert!(
        other + memo_charge < PARKED_BUDGET,
        "both fit in the full allowance"
    );
    // Let source completion populate the hold memo under a rotation budget
    // where memo alone fits but memo + native/versions do not. A zero-sized
    // source charges no queue bytes.
    state.discard_retained();
    crate::source_rotation::run(&mut owner, &[()], memo_charge + other / 2);
    assert_eq!(owner.completions, 1);
    assert_eq!(
        owner.discards, 0,
        "memo refusal must not reach owner-wide discard"
    );
    assert_unavailable_population(&state);
    assert_eq!(
        owner.native.retained_bound(PARKED_BUDGET),
        Some(native_charge)
    );
    let status = owner.native.status();
    assert!(!status.process_base_exit);
    assert_eq!(status.deferred_family_count, Some(1));
    assert!(owner.native.retained_valid_for_test());
    let mut next = owner.native.begin();
    next.bind("owner-charge-context".into());
    assert!(
        next.allowed(),
        "memo pressure cannot permanently BASE-exit native comparison"
    );
    assert!(
        !next.family_can_optimize("native-family"),
        "the existing family latch survives"
    );
    next.note_selected_save(true);
    next.finish(true);
    assert!(!owner.native.status().process_base_exit);
}
