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
    let budget = queue_bytes
        .and_then(|n| parked_budget.checked_sub(n))
        .unwrap_or(0);
    let mut parked_bytes = 0usize;
    loop {
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
                owner.outcome(source, result);
                break;
            }
            if !remaining.is_empty() || !parked.is_empty() {
                if let Some(bytes) = owner.bound(
                    frame.as_ref().expect("active frame"),
                    budget.saturating_sub(parked_bytes),
                ) {
                    if bytes <= budget.saturating_sub(parked_bytes) {
                        parked_bytes += bytes;
                        parked.push_back((source, frame.take().expect("active frame"), bytes));
                        owner.parked(
                            parked_bytes.saturating_add(queue_bytes.unwrap_or(parked_budget)),
                        );
                        break;
                    }
                }
            }
            // Unsupported layout, opaque state or budget exhaustion: continue
            // this SAME owned frame serially. Never restart files for a turn.
        }
    }
}
