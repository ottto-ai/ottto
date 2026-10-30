//! Cooperative collection turns inside the existing snapshot cycle owner.
use anyhow::Result;
use std::collections::VecDeque;
use std::mem::size_of;
use std::time::Duration;

pub(crate) const OVERLAP_BUDGET: usize = 32 * 1024 * 1024;
// Reserve the rest of the shared budget for any independently admitted optional
// complete-body send. Ordinary serial scan/upload remains the active baseline.
pub(crate) const PARKED_BUDGET: usize = OVERLAP_BUDGET / 4;
const TURN_STEPS: usize = 64;
const TURN_TIME: Duration = Duration::from_millis(16);

/// One moving reservation paid from the current rotation remainder. No Clone,
/// persistence, independent allowance or second owner. Actual owned storage is
/// counted by its containing graph; only unused future storage is charged here.
pub(crate) struct PaidReservation {
    total: usize,
    allocated: usize,
    remaining: Option<usize>,
    recovery: usize,
}
impl PaidReservation {
    pub(crate) fn from_remainder(
        remaining: Option<usize>,
        total: usize,
        allocated: usize,
    ) -> Option<Self> {
        (allocated <= total && total <= remaining?).then_some(Self {
            total,
            allocated,
            remaining,
            recovery: 0,
        })
    }
    /// Check BEFORE avoidable allocation. A failed request leaves all existing
    /// recovery capacity owned and paid; it is never an instruction to drop it.
    pub(crate) fn permits(&self, prospective_allocated: usize) -> bool {
        prospective_allocated
            .checked_add(self.recovery)
            .is_some_and(|needed| needed <= self.total)
    }
    /// Replace future credit with actual owned storage after a bounded move or
    /// allocation. The caller has already preflighted capacity with permits().
    pub(crate) fn record_allocated(&mut self, allocated: usize) -> bool {
        if !self.permits(allocated) {
            return false;
        }
        self.allocated = allocated;
        true
    }
    /// Refresh from the SAME rotation after queues, parked siblings and
    /// retained process owners. Unknown prevents new optional growth, while
    /// the already-paid recovery promise remains owned.
    pub(crate) fn at_turn(&mut self, remaining: Option<usize>) {
        self.remaining = remaining;
    }
    pub(crate) fn allocated(&self) -> usize {
        self.allocated
    }
    pub(crate) fn allocation_ceiling(&self) -> usize {
        self.total
    }
    /// A private canonical constructor has dropped every temporary/result it
    /// created. Release only its extra peak, retaining all capacity that was
    /// funded before the call and every mandatory recovery promise.
    pub(crate) fn release_temporary_peak(&mut self, previous_ceiling: usize) {
        self.total = self
            .total
            .min(previous_ceiling.max(self.allocated + self.recovery));
    }
    pub(crate) fn grow_for(&mut self, prospective_allocated: usize) -> bool {
        let Some(needed) = prospective_allocated.checked_add(self.recovery) else {
            return false;
        };
        let total = self.total.max(needed);
        if !self.remaining.is_some_and(|available| total <= available) {
            return false;
        }
        self.total = total;
        true
    }
    /// Protect mandatory selected-state restoration before any deferral or
    /// offer. Later optional allocations cannot consume this unused credit.
    pub(crate) fn reserve_recovery(&mut self, bytes: usize) -> bool {
        let recovery = self.recovery.max(bytes);
        let Some(needed) = self.allocated.checked_add(recovery) else {
            return false;
        };
        let total = self.total.max(needed);
        if !self.remaining.is_some_and(|available| total <= available) {
            return false;
        }
        self.total = total;
        self.recovery = recovery;
        true
    }
    /// Mandatory recovery may use its existing credit even after the current
    /// optional allowance becomes unknown. This grants no new allocation.
    #[cfg(test)]
    pub(crate) fn permits_recovery_peak(&self, prospective_allocated: usize) -> bool {
        prospective_allocated <= self.total
    }
    pub(crate) fn recovery_is_reserved(&self) -> bool {
        self.recovery != 0
            && self
                .allocated
                .checked_add(self.recovery)
                .is_some_and(|needed| needed <= self.total)
    }
    #[cfg(test)]
    pub(crate) fn recovery_bytes_for_test(&self) -> usize {
        self.recovery
    }
    #[cfg(test)]
    pub(crate) fn remaining_for_test(&self) -> Option<usize> {
        self.remaining
    }
    pub(crate) fn retire_speculation(&mut self) {
        // Call only after speculative temporaries are gone and actual owned
        // storage was reconciled. Never release protected recovery capacity.
        self.total = self.allocated + self.recovery;
    }
    fn unused(&self) -> usize {
        self.total - self.allocated
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for PaidReservation {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        counter.add(self.unused())
    }
}

pub(crate) enum Step<F, C> {
    Pending(F),
    Complete(C),
    Refused(LocalRefusal),
}
/// Local collection admission failure. It has no transport/backend evidence
/// and is never represented as a completed or empty source census.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LocalRefusal(pub(crate) &'static str);
impl std::fmt::Display for LocalRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for LocalRefusal {}
pub(crate) trait Owner {
    type Source: Copy;
    type Frame;
    type Completed;
    fn prepare(
        &mut self,
        source: Self::Source,
        remaining: Option<usize>,
    ) -> Result<Option<Self::Frame>>;
    fn validate(&mut self, frame: &Self::Frame) -> Result<()>;
    fn step(
        &mut self,
        frame: Self::Frame,
        remaining: Option<usize>,
    ) -> Step<Self::Frame, Self::Completed>;
    fn bound(&self, frame: &Self::Frame, limit: usize) -> Option<usize>;
    fn finish(&mut self, completed: Self::Completed, remaining: Option<usize>) -> Result<()>;
    fn outcome(&mut self, source: Self::Source, result: Result<()>);
    fn monotonic(&self) -> Duration;
    fn parked(&mut self, _bytes: usize) {}
    fn serial_fallback(
        &mut self,
        _source: Self::Source,
        _cause: crate::local_resource_diagnostics::SerialFallbackCause,
    ) {
    }
    /// Optional process-retained graphs outside every moving/parked frame.
    /// A graph moved into a frame is charged by `bound`, never here as well.
    /// Concrete owners must use the existing requested-layout admission;
    /// unsupported layout, unavailable locks or unknown ownership return None.
    fn retained_bound(&self, _limit: usize) -> Option<usize> {
        Some(0)
    }
    /// Drop the whole optional window AND its permit, including tombstones.
    /// Accounting refusal must never forget a revocation and revive a root.
    fn discard_retained(&mut self) {}
    /// One optional turn after all due siblings have been offered. Every
    /// parked source remains busy, so a retry cannot publish beneath its
    /// unfinished native parser. No new thread, timer or parser ownership.
    fn boundary(&mut self, _busy: impl Iterator<Item = Self::Source>) {}
}

/// The rotation owns the one allowance: queues + parked frames + carry.
/// No independently granted carry budget. A refused charge gets one discard
/// and one recheck; persistent unknown runs the same active frame serially.
fn retained_remainder<O: Owner>(owner: &mut O, available: Option<usize>) -> Option<(usize, usize)> {
    let Some(available) = available else {
        owner.discard_retained();
        return None;
    };
    if let Some(bytes) = owner.retained_bound(available).filter(|b| *b <= available) {
        return Some((available - bytes, bytes));
    }
    owner.discard_retained();
    let bytes = owner
        .retained_bound(available)
        .filter(|b| *b <= available)?;
    Some((available - bytes, bytes))
}

pub(crate) fn run<O: Owner>(owner: &mut O, sources: &[O::Source], parked_budget: usize) {
    let mut remaining: VecDeque<_> = sources.iter().copied().collect();
    let mut parked = VecDeque::<(O::Source, O::Frame, usize)>::with_capacity(sources.len());
    // Charge queue capacity even when spare slots are empty. Frame bounds
    // additionally include their inline bytes, deliberately overcounting them.
    let queue_bytes = parked
        .capacity()
        .checked_mul(size_of::<(O::Source, O::Frame, usize)>())
        .and_then(|n| {
            remaining
                .capacity()
                .checked_mul(size_of::<O::Source>())
                .and_then(|m| n.checked_add(m))
        });
    let budget = queue_bytes.and_then(|n| parked_budget.checked_sub(n));
    let mut parked_bytes = 0usize;
    loop {
        if remaining.is_empty() {
            owner.boundary(parked.iter().map(|(source, _, _)| *source));
        }
        // Includes carry entering a new cycle and ownership changes made by a
        // finished sibling. Queue capacity and already parked frames stay paid.
        let _ = retained_remainder(owner, budget.and_then(|b| b.checked_sub(parked_bytes)));
        // Offer each due sibling before returning to a previously parked source.
        let (source, frame) = if let Some(source) = remaining.pop_front() {
            let available =
                retained_remainder(owner, budget.and_then(|b| b.checked_sub(parked_bytes)))
                    .map(|(available, _)| available);
            match owner.prepare(source, available) {
                Ok(Some(frame)) => (source, frame),
                Ok(None) => {
                    owner.outcome(source, Ok(()));
                    continue;
                }
                Err(error) => {
                    owner.outcome(source, Err(error));
                    continue;
                }
            }
        } else if let Some((source, frame, bytes)) = parked.pop_front() {
            parked_bytes -= bytes;
            (source, frame)
        } else {
            break;
        };
        let mut frame = Some(frame);
        'source_turn: loop {
            if let Err(error) = owner.validate(frame.as_ref().expect("active frame")) {
                // Drop working parser/index/progress together. Durable ACKs and
                // the last canonical index remain ordinary-recovery authority.
                owner.outcome(source, Err(error));
                break;
            }
            let started = owner.monotonic();
            let mut complete = None;
            // One conservative snapshot for this serial turn: siblings cannot
            // run and process carry is published only by finish. A moved-out
            // carry may leave this smaller than necessary, never larger. Do
            // not walk a retained graph again for every physical parser step.
            let available =
                retained_remainder(owner, budget.and_then(|b| b.checked_sub(parked_bytes)))
                    .map(|(available, _)| available);
            for _ in 0..TURN_STEPS {
                match owner.step(frame.take().expect("active frame"), available) {
                    Step::Pending(next) => frame = Some(next),
                    Step::Complete(result) => {
                        complete = Some(result);
                        break;
                    }
                    Step::Refused(reason) => {
                        owner.outcome(source, Err(reason.into()));
                        break 'source_turn;
                    }
                }
                if owner.monotonic().saturating_sub(started) >= TURN_TIME {
                    break;
                }
            }
            if let Some(result) = complete {
                let available =
                    retained_remainder(owner, budget.and_then(|b| b.checked_sub(parked_bytes)))
                        .map(|(available, _)| available);
                let result = owner.finish(result, available);
                // A finish may move a graph out of the completed frame into
                // process retention. Admit it against the SAME remaining space.
                let _ = retained_remainder(owner, budget.and_then(|b| b.checked_sub(parked_bytes)));
                owner.outcome(source, result);
                break;
            }
            if !remaining.is_empty() || !parked.is_empty() {
                use crate::local_resource_diagnostics::SerialFallbackCause;
                let mut cause = SerialFallbackCause::BudgetExhausted;
                if let Some((available, retained)) =
                    retained_remainder(owner, budget.and_then(|b| b.checked_sub(parked_bytes)))
                {
                    if let Some(bytes) =
                        owner.bound(frame.as_ref().expect("active frame"), available)
                    {
                        if bytes <= available {
                            parked_bytes += bytes;
                            parked.push_back((source, frame.take().expect("active frame"), bytes));
                            owner.parked(
                                parked_bytes
                                    .saturating_add(retained)
                                    .saturating_add(queue_bytes.unwrap_or(parked_budget)),
                            );
                            break;
                        }
                    } else {
                        cause = SerialFallbackCause::BoundNone;
                    }
                } else if budget.and_then(|b| b.checked_sub(parked_bytes)).is_some() {
                    cause = SerialFallbackCause::BoundNone;
                }
                owner.serial_fallback(source, cause);
            }
            // Unsupported layout, opaque state or budget exhaustion: continue
            // this SAME owned frame serially. Never restart files for a turn.
        }
    }
}

#[cfg(test)]
mod retained_budget_tests {
    use super::*;

    // Synthetic admission costs test the real rotation's ownership/arithmetic,
    // not compiler layout, allocator bytes or natural memory savings.
    struct Carry {
        charge: usize,
        root_revoked: bool,
    }
    struct Frame {
        source: usize,
        left: usize,
        carry: Option<Box<Carry>>,
    }
    struct ProofOwner {
        steps: Vec<usize>,
        frame_charge: usize,
        carry: Option<Box<Carry>>,
        take_at: Option<usize>,
        create_at: Option<usize>,
        create_charge: usize,
        fail_at: Option<usize>,
        refuse_at: Option<usize>,
        unknown: bool,
        persistent_unknown: bool,
        discards: usize,
        parks: Vec<usize>,
        outcomes: Vec<(usize, bool)>,
        moves: Vec<usize>,
        step_count: usize,
        allowances: Vec<(&'static str, usize, Option<usize>)>,
    }
    impl Default for ProofOwner {
        fn default() -> Self {
            Self {
                steps: vec![TURN_STEPS + 1, 1],
                frame_charge: PARKED_BUDGET / 2,
                carry: None,
                take_at: None,
                create_at: None,
                create_charge: 0,
                fail_at: None,
                refuse_at: None,
                unknown: false,
                persistent_unknown: false,
                discards: 0,
                parks: Vec::new(),
                outcomes: Vec::new(),
                moves: Vec::new(),
                step_count: 0,
                allowances: Vec::new(),
            }
        }
    }
    impl Owner for ProofOwner {
        type Source = usize;
        type Frame = Frame;
        type Completed = Frame;
        fn prepare(&mut self, source: usize, remaining: Option<usize>) -> Result<Option<Frame>> {
            self.allowances.push(("prepare", source, remaining));
            let carry = (self.take_at == Some(source))
                .then(|| self.carry.take())
                .flatten();
            if let Some(graph) = carry.as_ref() {
                self.moves.push(graph.as_ref() as *const Carry as usize);
            }
            Ok(Some(Frame {
                source,
                left: self.steps[source],
                carry,
            }))
        }
        fn validate(&mut self, _: &Frame) -> Result<()> {
            Ok(())
        }
        fn step(&mut self, mut frame: Frame, remaining: Option<usize>) -> Step<Frame, Frame> {
            self.allowances.push(("step", frame.source, remaining));
            self.step_count += 1;
            if self.refuse_at == Some(frame.source) {
                return Step::Refused(LocalRefusal("synthetic local collection admission refusal"));
            }
            assert!(
                self.step_count < 1024,
                "accounting cannot restart or loop a source"
            );
            frame.left -= 1;
            if frame.left == 0 {
                Step::Complete(frame)
            } else {
                Step::Pending(frame)
            }
        }
        fn bound(&self, frame: &Frame, _limit: usize) -> Option<usize> {
            self.frame_charge
                .checked_add(frame.carry.as_ref().map_or(0, |graph| graph.charge))
        }
        fn finish(&mut self, frame: Frame, remaining: Option<usize>) -> Result<()> {
            self.allowances.push(("finish", frame.source, remaining));
            if self.fail_at == Some(frame.source) {
                return Err(anyhow::anyhow!("synthetic selected save failure"));
            }
            if let Some(graph) = frame.carry {
                assert!(graph.root_revoked, "moving ownership cannot revive a root");
                self.moves.push(graph.as_ref() as *const Carry as usize);
                assert!(self.carry.is_none());
                self.carry = Some(graph);
            }
            if self.create_at == Some(frame.source) {
                assert!(self.carry.is_none());
                self.carry = Some(Box::new(Carry {
                    charge: self.create_charge,
                    root_revoked: true,
                }));
            }
            Ok(())
        }
        fn outcome(&mut self, source: usize, result: Result<()>) {
            self.outcomes.push((source, result.is_ok()));
        }
        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
        fn parked(&mut self, bytes: usize) {
            assert!(bytes <= PARKED_BUDGET);
            self.parks.push(bytes);
        }
        fn serial_fallback(
            &mut self,
            source: usize,
            cause: crate::local_resource_diagnostics::SerialFallbackCause,
        ) {
            crate::local_resource_diagnostics::source_rotation_serial_fallback(
                ["claude_code", "codex"][source],
                cause,
            );
        }
        fn retained_bound(&self, limit: usize) -> Option<usize> {
            if self.persistent_unknown || (self.unknown && self.carry.is_some()) {
                return None;
            }
            let bytes = self.carry.as_ref().map_or(0, |graph| graph.charge);
            (bytes <= limit).then_some(bytes)
        }
        fn discard_retained(&mut self) {
            self.discards += 1;
            self.carry = None;
        }
    }

    #[test]
    /// [behaviour] Serial parking refusals reach the existing per-source page counter once each.
    fn serial_fallback_counts_unknown_and_excess_bounds() {
        use crate::local_resource_diagnostics::{capture, CollectionCounts, Probe};
        let emit_page = |source| {
            Probe::start().collection(
                source,
                CollectionCounts {
                    scanned_files: 0,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                    full_causes: Default::default(),
                },
            );
        };
        // Other rotation fixtures can leave this thread's page counts pending.
        capture(|| {
            emit_page("claude_code");
            emit_page("codex");
        });
        for (charge, expected) in [
            (usize::MAX, serde_json::json!({"bound_none": 2})),
            (PARKED_BUDGET, serde_json::json!({"budget_exhausted": 2})),
            (0, serde_json::Value::Null),
        ] {
            let mut owner = ProofOwner {
                steps: vec![2 * TURN_STEPS + 1, TURN_STEPS + 1],
                frame_charge: charge,
                take_at: Some(0),
                carry: Some(Box::new(Carry {
                    charge: 1,
                    root_revoked: true,
                })),
                ..Default::default()
            };
            let (_, rows) = capture(|| {
                run(&mut owner, &[0, 1], PARKED_BUDGET);
                for source in ["codex", "claude_code", "claude_code"] {
                    emit_page(source);
                }
            });
            assert!(owner.outcomes.iter().all(|(_, ok)| *ok));
            assert_eq!(owner.outcomes.len(), 2);
            assert_eq!(rows.len(), 3, "fallback adds no emitter");
            assert!(rows[0]["counts"]["source_rotation_serial_fallback"].is_null());
            assert_eq!(
                rows[1]["counts"]["source_rotation_serial_fallback"],
                expected
            );
            assert!(rows[2]["counts"]["source_rotation_serial_fallback"].is_null());
        }
    }

    #[test]
    fn native_comparison_local_refusal_never_finishes_source_and_siblings_progress() {
        let mut owner = ProofOwner {
            refuse_at: Some(0),
            ..Default::default()
        };
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        assert_eq!(owner.outcomes, [(0, false), (1, true)]);
        assert!(!owner
            .allowances
            .iter()
            .any(|(stage, source, _)| *stage == "finish" && *source == 0));
        assert!(owner
            .allowances
            .iter()
            .any(|(stage, source, _)| *stage == "finish" && *source == 1));
        assert_eq!(
            owner.step_count, 2,
            "refused source never restarts in the rotation"
        );
    }

    #[test]
    fn retained_budget_equality_overflow_and_unrepresentable_queue_fail_closed() {
        let mut owner = ProofOwner {
            carry: Some(Box::new(Carry {
                charge: 100,
                root_revoked: true,
            })),
            ..Default::default()
        };
        assert_eq!(retained_remainder(&mut owner, Some(100)), Some((0, 100)));
        assert_eq!(owner.discards, 0);
        owner.carry.as_mut().unwrap().charge = 101;
        assert_eq!(retained_remainder(&mut owner, Some(100)), Some((100, 0)));
        assert!(owner.carry.is_none());
        owner.carry = Some(Box::new(Carry {
            charge: usize::MAX,
            root_revoked: true,
        }));
        assert_eq!(retained_remainder(&mut owner, None), None);
        assert!(owner.carry.is_none());
    }

    #[test]
    fn retained_budget_finish_cannot_borrow_already_parked_siblings_space() {
        let mut owner = ProofOwner {
            create_at: Some(1),
            create_charge: PARKED_BUDGET / 2 + PARKED_BUDGET / 4,
            ..Default::default()
        };
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        assert_eq!(owner.parks.len(), 1, "first source was genuinely parked");
        assert_eq!(owner.outcomes, vec![(1, true), (0, true)]);
        assert!(
            owner.carry.is_none(),
            "finish must discard excess carry before resuming sibling"
        );
        assert_eq!(owner.discards, 1);
    }

    #[test]
    fn retained_budget_moves_one_graph_through_frame_finish_and_next_cycle() {
        let graph = Box::new(Carry {
            charge: PARKED_BUDGET / 2,
            root_revoked: true,
        });
        let pointer = graph.as_ref() as *const Carry as usize;
        let mut owner = ProofOwner {
            carry: Some(graph),
            take_at: Some(0),
            frame_charge: 128,
            ..Default::default()
        };
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        assert_eq!(
            owner.parks.len(),
            1,
            "moving carry into a frame must not double charge it"
        );
        assert_eq!(owner.discards, 0);
        assert_eq!(owner.moves, vec![pointer, pointer]);
        assert_eq!(
            owner.carry.as_ref().unwrap().as_ref() as *const Carry as usize,
            pointer
        );
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        assert_eq!(owner.parks.len(), 2);
        assert_eq!(owner.moves, vec![pointer; 4]);
        assert_eq!(owner.discards, 0);
        assert!(
            ProofOwner::default().carry.is_none(),
            "fresh restart has no graph or grant"
        );
    }

    #[test]
    fn retained_budget_refused_layout_or_persistent_unknown_never_restarts() {
        for persistent in [false, true] {
            let mut owner = ProofOwner {
                carry: Some(Box::new(Carry {
                    charge: 100,
                    root_revoked: true,
                })),
                unknown: true,
                persistent_unknown: persistent,
                ..Default::default()
            };
            run(&mut owner, &[0, 1], PARKED_BUDGET);
            assert!(owner.carry.is_none());
            assert!(owner.discards > 0);
            assert_eq!(owner.step_count, TURN_STEPS + 2);
            assert_eq!(owner.outcomes.len(), 2);
            if persistent {
                assert!(
                    owner.parks.is_empty(),
                    "unaccountable retention uses serial base"
                );
                assert_eq!(owner.outcomes, vec![(0, true), (1, true)]);
            }
        }
    }

    #[test]
    fn retained_budget_failed_finish_drops_moving_graph_without_retention() {
        let mut owner = ProofOwner {
            carry: Some(Box::new(Carry {
                charge: 100,
                root_revoked: true,
            })),
            take_at: Some(0),
            fail_at: Some(0),
            ..Default::default()
        };
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        assert_eq!(owner.outcomes, vec![(1, true), (0, false)]);
        assert!(owner.carry.is_none());
        assert_eq!(
            owner.moves.len(),
            1,
            "failed frame never transfers back to retention"
        );
    }

    #[test]
    fn native_comparison_remainder_reaches_prepare_step_finish_after_sibling_charge() {
        let mut owner = ProofOwner::default();
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        let granted = |stage, source| {
            owner
                .allowances
                .iter()
                .filter(|(s, n, _)| *s == stage && *n == source)
                .map(|(_, _, bytes)| bytes.expect("known existing allowance"))
                .collect::<Vec<_>>()
        };
        let first = granted("prepare", 0)[0];
        let sibling = granted("prepare", 1)[0];
        assert_eq!(
            first - sibling,
            owner.frame_charge,
            "parked first source is paid before sibling prepare"
        );
        assert!(granted("step", 1).iter().all(|bytes| *bytes == sibling));
        assert_eq!(granted("finish", 1), vec![sibling]);
        assert!(first < PARKED_BUDGET, "queue storage is already paid");
        assert_eq!(owner.outcomes, vec![(1, true), (0, true)]);
    }

    #[test]
    fn native_comparison_unknown_remainder_is_none_at_all_existing_owner_seams() {
        let mut owner = ProofOwner {
            persistent_unknown: true,
            ..Default::default()
        };
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        assert!(owner.allowances.iter().all(|(_, _, bytes)| bytes.is_none()));
        assert_eq!(
            owner.outcomes,
            vec![(0, true), (1, true)],
            "unknown optional budget preserves ordinary serial collection"
        );
    }

    #[test]
    fn native_comparison_paid_reservation_exact_limit_refusal_preserves_obligation() {
        assert!(PaidReservation::from_remainder(None, 1, 0).is_none());
        assert!(PaidReservation::from_remainder(Some(63), 64, 0).is_none());
        assert!(PaidReservation::from_remainder(Some(64), 64, 65).is_none());
        let mut paid = PaidReservation::from_remainder(Some(64), 64, 0).unwrap();
        assert!(paid.permits(64));
        assert!(!paid.permits(65));
        assert!(!paid.record_allocated(65));
        assert_eq!(
            paid.unused(),
            64,
            "refusal does not abandon required future recovery"
        );
        assert!(paid.record_allocated(64));
        assert_eq!(paid.unused(), 0);
        assert!(paid.record_allocated(0));
        assert_eq!(
            paid.unused(),
            64,
            "freed storage remains paid until reservation retires"
        );
    }

    #[test]
    fn native_comparison_paid_recovery_cannot_be_spent_on_later_optional_growth() {
        let mut paid = PaidReservation::from_remainder(Some(64), 32, 8).unwrap();
        assert!(paid.reserve_recovery(16));
        assert!(!paid.permits(17));
        assert!(paid.grow_for(17));
        assert!(paid.record_allocated(17));
        assert_eq!(paid.unused(), 16);
        assert!(!paid.reserve_recovery(48));
        assert_eq!(
            paid.unused(),
            16,
            "refused enlargement preserves the funded promise"
        );
        let before_constructor = paid.allocation_ceiling();
        assert!(paid.grow_for(32));
        paid.release_temporary_peak(before_constructor);
        assert_eq!(paid.allocation_ceiling(), before_constructor);
        assert_eq!(paid.unused(), 16, "temporary refund preserves recovery");
        paid.at_turn(None);
        assert!(
            !paid.grow_for(17),
            "unknown new allowance grants no optional growth"
        );
        assert!(paid.permits_recovery_peak(33));
        assert!(!paid.permits_recovery_peak(34));
        assert!(paid.record_allocated(8));
        assert!(
            paid.permits_recovery_peak(33),
            "releasing storage cannot discard paid recovery"
        );
    }

    #[test]
    fn native_comparison_paid_reservation_replaces_charge_on_real_allocation_and_move() {
        if !crate::heap_layout_bound::layout_supported() {
            eprintln!("native_comparison_paid_reservation: supported_positive=UNEXECUTED");
            return;
        }
        struct Reserved {
            storage: Vec<u8>,
            paid: PaidReservation,
        }
        crate::heap_layout_bound::fields!(Reserved; storage, paid);
        let mut frame = Reserved {
            storage: Vec::new(),
            paid: PaidReservation::from_remainder(Some(4096), 4096, 0).unwrap(),
        };
        let bound = |value: &Reserved| crate::heap_layout_bound::bound(value, 8192).unwrap();
        let before = bound(&frame);
        assert!(frame.paid.permits(4096));
        frame.storage.try_reserve_exact(4096).unwrap();
        assert!(frame.paid.record_allocated(frame.storage.capacity()));
        assert_eq!(
            bound(&frame),
            before,
            "capacity replaces future credit, never double granted"
        );
        let mut completed = frame; // no reservation/storage clone
        assert_eq!(bound(&completed), before);
        drop(std::mem::take(&mut completed.storage));
        assert!(completed.paid.record_allocated(0));
        assert_eq!(
            bound(&completed),
            before,
            "unused recovery remains part of parked charge"
        );
    }
}
