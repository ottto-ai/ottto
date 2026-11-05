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
    fn finish(&mut self, completed: Self::Completed, remaining: Option<usize>) -> Result<()>;
    fn outcome(&mut self, source: Self::Source, result: Result<()>);
    fn monotonic(&self) -> Duration;
    /// Optional process-retained graphs outside the active frame. A graph
    /// moved into the frame is not retained and is never charged here.
    /// Concrete owners must use the existing requested-layout admission;
    /// unsupported layout, unavailable locks or unknown ownership return None.
    fn retained_bound(&self, _limit: usize) -> Option<usize> {
        Some(0)
    }
    /// Drop the whole optional window AND its permit, including tombstones.
    /// Accounting refusal must never forget a revocation and revive a root.
    fn discard_retained(&mut self) {}
    /// No allowance exists even for independently bounded advisory state.
    fn retained_budget_unavailable(&mut self) {
        self.discard_retained();
    }
    /// One optional turn after all due sources have been offered and run
    /// serially. No new thread, timer or parser ownership.
    fn boundary(&mut self) {}
}

/// The rotation owns the one allowance: queue + carry.
/// No independently granted carry budget. A refused charge gets one discard
/// and one recheck; persistent unknown runs the same active frame serially.
fn retained_remainder<O: Owner>(owner: &mut O, available: Option<usize>) -> Option<(usize, usize)> {
    let Some(available) = available else {
        owner.retained_budget_unavailable();
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

pub(crate) fn run<O: Owner>(owner: &mut O, sources: &[O::Source], rotation_budget: usize) {
    let mut remaining: VecDeque<_> = sources.iter().copied().collect();
    // Charge queue capacity even when spare slots are empty.
    let budget = remaining
        .capacity()
        .checked_mul(size_of::<O::Source>())
        .and_then(|n| rotation_budget.checked_sub(n));
    loop {
        if remaining.is_empty() {
            owner.boundary();
        }
        // Includes carry entering a new cycle and ownership changes made by a
        // finished source. Queue capacity stays paid.
        let _ = retained_remainder(owner, budget);
        let Some(source) = remaining.pop_front() else {
            break;
        };
        let available = retained_remainder(owner, budget).map(|(available, _)| available);
        let frame = match owner.prepare(source, available) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                owner.outcome(source, Ok(()));
                continue;
            }
            Err(error) => {
                owner.outcome(source, Err(error));
                continue;
            }
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
            let available = retained_remainder(owner, budget).map(|(available, _)| available);
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
                let available = retained_remainder(owner, budget).map(|(available, _)| available);
                let result = owner.finish(result, available);
                // A finish may move a graph out of the completed frame into
                // process retention. Admit it against the SAME remaining space.
                let _ = retained_remainder(owner, budget);
                owner.outcome(source, result);
                break;
            }
            // Continue this SAME owned frame serially. Never restart files
            // for a turn.
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
        carry: Option<Box<Carry>>,
        take_at: Option<usize>,
        create_at: Option<usize>,
        create_charge: usize,
        fail_at: Option<usize>,
        refuse_at: Option<usize>,
        unknown: bool,
        persistent_unknown: bool,
        discards: usize,
        outcomes: Vec<(usize, bool)>,
        moves: Vec<usize>,
        step_count: usize,
        allowances: Vec<(&'static str, usize, Option<usize>)>,
    }
    impl Default for ProofOwner {
        fn default() -> Self {
            Self {
                steps: vec![TURN_STEPS + 1, 1],
                carry: None,
                take_at: None,
                create_at: None,
                create_charge: 0,
                fail_at: None,
                refuse_at: None,
                unknown: false,
                persistent_unknown: false,
                discards: 0,
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
    fn local_refusal_never_finishes_source_and_siblings_progress() {
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
    fn retained_budget_finish_cannot_keep_carry_over_the_allowance() {
        // Queue capacity is already paid, so the full allowance no longer fits.
        let mut owner = ProofOwner {
            create_at: Some(0),
            create_charge: PARKED_BUDGET,
            ..Default::default()
        };
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        assert_eq!(owner.outcomes, vec![(0, true), (1, true)]);
        assert!(
            owner.carry.is_none(),
            "finish must discard excess carry before the next source"
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
            ..Default::default()
        };
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        assert_eq!(owner.discards, 0);
        assert_eq!(owner.moves, vec![pointer, pointer]);
        assert_eq!(
            owner.carry.as_ref().unwrap().as_ref() as *const Carry as usize,
            pointer
        );
        run(&mut owner, &[0, 1], PARKED_BUDGET);
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
        assert_eq!(owner.outcomes, vec![(0, false), (1, true)]);
        assert!(owner.carry.is_none());
        assert_eq!(
            owner.moves.len(),
            1,
            "failed frame never transfers back to retention"
        );
    }

    #[test]
    fn remainder_reaches_prepare_step_finish() {
        let mut owner = ProofOwner::default();
        run(&mut owner, &[0, 1], PARKED_BUDGET);
        let granted = |stage| {
            owner
                .allowances
                .iter()
                .filter(|(s, _, _)| *s == stage)
                .map(|(_, _, bytes)| bytes.expect("known existing allowance"))
                .collect::<Vec<_>>()
        };
        let first = granted("prepare")[0];
        assert_eq!(granted("prepare"), vec![first; 2]);
        assert!(granted("step").iter().all(|bytes| *bytes == first));
        assert_eq!(granted("finish"), vec![first; 2]);
        assert!(first < PARKED_BUDGET, "queue storage is already paid");
        assert_eq!(owner.outcomes, vec![(0, true), (1, true)]);
    }

    #[test]
    fn unknown_remainder_is_none_at_all_existing_owner_seams() {
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
}
