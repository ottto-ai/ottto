use super::*;
use crate::snapshot_sync::retained_with_withheld;
use crate::source_rotation::{Owner, PaidReservation, Step, PARKED_BUDGET};
use std::mem::size_of;
use std::time::Duration;

fn seed_held_memo() {
    let mut index = ScanIndex::default();
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

fn assert_unavailable_population() {
    assert_eq!(
        serde_json::to_value(withheld_account::held_gauge()).unwrap(),
        json!({
            "withheld_held_count": MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS,
            "withheld_memo_unavailable": true
        }),
        "refusal preserves population and omits unknown tokens/ages"
    );
    assert!(withheld_account::census().is_none());
}

#[test]
fn withheld_refusal_preserves_a_fully_admitted_sibling_charge() {
    seed_held_memo();
    assert!(withheld_account::retained_bound(PARKED_BUDGET).is_some());
    // Include the no-remainder case: even an empty memo's conservative charge
    // must not make a fully admitted sibling trigger owner-wide discard.
    for limit in [PARKED_BUDGET, 0] {
        assert_eq!(
            retained_with_withheld(limit, |available| {
                assert_eq!(available, limit, "siblings receive the full allowance");
                Some(available)
            }),
            Some(limit)
        );
        assert_unavailable_population();
    }
}

#[test]
fn unsupported_sibling_preserves_only_a_memo_that_fits_the_allowance() {
    seed_held_memo();
    let memo = withheld_account::retained_bound(PARKED_BUDGET).unwrap();
    assert_eq!(retained_with_withheld(memo, |_| None), None);
    // This is the rotation's sibling-refusal cleanup, not an admission of an
    // unpriced sibling. The portable graph must survive this exact-fit case.
    withheld_account::discard_if_refused();
    assert_eq!(withheld_account::retained_bound(memo), Some(memo));
    let gauge = serde_json::to_value(withheld_account::held_gauge()).unwrap();
    assert_eq!(gauge["withheld_memo_unavailable"], false);
    assert_eq!(
        gauge["withheld_held_tokens"],
        MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
    );
    assert_eq!(retained_with_withheld(memo - 1, |_| None), None);
    withheld_account::discard_if_refused();
    assert_unavailable_population();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Parked,
    Holds,
}

struct Frame {
    source: Source,
    steps_left: usize,
    storage: Vec<u8>,
}
impl crate::heap_layout_bound::HeapLayoutBound for Frame {
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.storage, counter)
    }
}

struct Cycle {
    native: Arc<claude_native_comparison::lifecycle::Lifecycle>,
    versions: Arc<codex_version::CodexVersionFeed>,
    storage_bytes: usize,
    parked_charge: usize,
    memo_charge: usize,
    discards: usize,
    parks: usize,
    completions: usize,
}
impl Cycle {
    fn other_bound(&self, limit: usize) -> Option<usize> {
        let versions = crate::heap_layout_bound::bound(&self.versions, limit)?;
        let native = self.native.retained_bound(limit.checked_sub(versions)?)?;
        versions.checked_add(native)
    }
}
impl Owner for Cycle {
    type Source = Source;
    type Frame = Frame;
    type Completed = Source;

    fn prepare(&mut self, source: Source, remaining: Option<usize>) -> Result<Option<Frame>> {
        assert!(remaining.is_some());
        Ok(Some(Frame {
            source,
            steps_left: if source == Source::Parked { 65 } else { 0 },
            storage: vec![
                0;
                if source == Source::Parked {
                    self.storage_bytes
                } else {
                    0
                }
            ],
        }))
    }
    fn validate(&mut self, _: &Frame) -> Result<()> {
        Ok(())
    }
    fn step(&mut self, mut frame: Frame, remaining: Option<usize>) -> Step<Frame, Source> {
        assert!(remaining.is_some());
        if frame.steps_left == 0 {
            Step::Complete(frame.source)
        } else {
            frame.steps_left -= 1;
            Step::Pending(frame)
        }
    }
    fn bound(&self, frame: &Frame, limit: usize) -> Option<usize> {
        let bytes = crate::heap_layout_bound::bound(frame, limit)?;
        assert_eq!(bytes, self.parked_charge);
        Some(bytes)
    }
    fn finish(&mut self, source: Source, remaining: Option<usize>) -> Result<()> {
        assert!(remaining.is_some());
        if source == Source::Holds {
            assert_eq!(self.parks, 1, "sibling still owns a real parked allocation");
            let empty_memo = withheld_account::retained_bound(PARKED_BUDGET).unwrap();
            let available =
                remaining.unwrap() + self.other_bound(PARKED_BUDGET).unwrap() + empty_memo;
            seed_held_memo();
            let other = self.other_bound(available).unwrap();
            assert!(self.memo_charge <= available, "memo alone fits");
            assert!(other <= available, "real sibling graphs alone fit");
            assert!(
                self.memo_charge + other > available,
                "composition must refuse one graph"
            );
        }
        Ok(())
    }
    fn outcome(&mut self, _: Source, result: Result<()>) {
        result.unwrap();
        self.completions += 1;
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn parked(&mut self, bytes: usize) {
        assert!(bytes <= PARKED_BUDGET);
        self.parks += 1;
    }
    fn retained_bound(&self, limit: usize) -> Option<usize> {
        retained_with_withheld(limit, |available| self.other_bound(available))
    }
    fn discard_retained(&mut self) {
        self.discards += 1;
        // Match SnapshotCycleOwner's native and memo cleanup. This real native
        // policy graph would latch process_base_exit if composition refused it.
        self.native.discard_retained();
        withheld_account::discard_if_refused();
    }
    fn retained_budget_unavailable(&mut self) {
        withheld_account::discard_retained();
        self.discard_retained();
    }
}

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

    seed_held_memo();
    let memo_charge = withheld_account::retained_bound(PARKED_BUDGET).unwrap();
    let mut owner = Cycle {
        native,
        versions: Arc::new(codex_version::CodexVersionFeed::new(None)),
        storage_bytes: 0,
        parked_charge: 0,
        memo_charge,
        discards: 0,
        parks: 0,
        completions: 0,
    };
    let other = owner.other_bound(PARKED_BUDGET).unwrap();
    assert_eq!(
        owner.retained_bound(PARKED_BUDGET),
        Some(other + memo_charge)
    );
    assert!(
        other + memo_charge < PARKED_BUDGET,
        "both fit without a parked sibling"
    );
    // First park a frame, then let sibling completion populate the hold memo.
    // Target contention where memo alone fits but memo + native/versions do not.
    withheld_account::discard_retained();
    let queue = 2 * (size_of::<(Source, Frame, usize)>() + size_of::<Source>());
    let available = memo_charge + other / 2;
    owner.parked_charge = PARKED_BUDGET - queue - available;
    owner.storage_bytes = owner.parked_charge - size_of::<Frame>();
    crate::source_rotation::run(&mut owner, &[Source::Parked, Source::Holds], PARKED_BUDGET);
    assert_eq!(owner.parks, 1);
    assert_eq!(owner.completions, 2);
    assert_eq!(
        owner.discards, 0,
        "memo refusal must not reach owner-wide discard"
    );
    assert_unavailable_population();
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
