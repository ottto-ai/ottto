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
}
pub(crate) trait Owner {
    type Source: Copy;
    type Frame;
    type Completed;
    fn prepare(&mut self, source: Self::Source) -> Result<Option<Self::Frame>>;
    fn validate(&mut self, frame: &Self::Frame) -> Result<()>;
    fn step(&mut self, frame: Self::Frame) -> Step<Self::Frame, Self::Completed>;
    fn bound(&self, frame: &Self::Frame, limit: usize) -> Option<usize>;
    fn finish(&mut self, completed: Self::Completed) -> Result<()>;
    fn outcome(&mut self, source: Self::Source, result: Result<()>);
    fn monotonic(&self) -> Duration;
    fn parked(&mut self, _bytes: usize) {}
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
            match owner.prepare(source) {
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
        loop {
            if let Err(error) = owner.validate(frame.as_ref().expect("active frame")) {
                // Drop working parser/index/progress together. Durable ACKs and
                // the last canonical index remain ordinary-recovery authority.
                owner.outcome(source, Err(error));
                break;
            }
            let started = owner.monotonic();
            let mut complete = None;
            for _ in 0..TURN_STEPS {
                match owner.step(frame.take().expect("active frame")) {
                    Step::Pending(next) => frame = Some(next),
                    Step::Complete(result) => {
                        complete = Some(result);
                        break;
                    }
                }
                if owner.monotonic().saturating_sub(started) >= TURN_TIME {
                    break;
                }
            }
            if let Some(result) = complete {
                let result = owner.finish(result);
                // A finish may move a graph out of the completed frame into
                // process retention. Admit it against the SAME remaining space.
                let _ = retained_remainder(owner, budget.and_then(|b| b.checked_sub(parked_bytes)));
                owner.outcome(source, result);
                break;
            }
            if !remaining.is_empty() || !parked.is_empty() {
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
                    }
                }
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
        unknown: bool,
        persistent_unknown: bool,
        discards: usize,
        parks: Vec<usize>,
        outcomes: Vec<(usize, bool)>,
        moves: Vec<usize>,
        step_count: usize,
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
                unknown: false,
                persistent_unknown: false,
                discards: 0,
                parks: Vec::new(),
                outcomes: Vec::new(),
                moves: Vec::new(),
                step_count: 0,
            }
        }
    }
    impl Owner for ProofOwner {
        type Source = usize;
        type Frame = Frame;
        type Completed = Frame;
        fn prepare(&mut self, source: usize) -> Result<Option<Frame>> {
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
        fn step(&mut self, mut frame: Frame) -> Step<Frame, Frame> {
            self.step_count += 1;
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
        fn bound(&self, frame: &Frame, limit: usize) -> Option<usize> {
            let bytes = self
                .frame_charge
                .checked_add(frame.carry.as_ref().map_or(0, |graph| graph.charge))?;
            (bytes <= limit).then_some(bytes)
        }
        fn finish(&mut self, frame: Frame) -> Result<()> {
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
}
