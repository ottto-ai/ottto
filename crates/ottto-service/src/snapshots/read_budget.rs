//! The one per-pass allowance for deferrable re-reads and its oldest-first
//! waiting queue, shared by every cause of a deferred read. No clock takes part:
//! a burst defers by passes. Nondeferrable reads are charged and reported as
//! overshoot, so the limit is an allowance, not a bound on bytes read.
// Later causes read the stats and take from the budget directly.
#![allow(dead_code)]

use std::collections::VecDeque;

/// One source's per-pass allowance for deferrable re-reads. Nondeferrable reads
/// are charged too and reported as overshoot; it never refuses them.
#[derive(Debug)]
pub(crate) struct ReadBudget {
    limit: u64,
    spent: u64,
}

impl ReadBudget {
    pub(crate) fn new(limit_bytes: u64) -> Self {
        Self {
            limit: limit_bytes,
            spent: 0,
        }
    }

    /// Spends unconditionally; the pass's total stays visible to later takes.
    pub(crate) fn charge(&mut self, bytes: u64) {
        self.spent = self.spent.saturating_add(bytes);
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.spent)
    }

    /// The first take in a pass always fits, so a file larger than the limit
    /// reads alone instead of waiting forever.
    pub(crate) fn try_take(&mut self, bytes: u64) -> bool {
        let fits = self.spent == 0 || bytes <= self.remaining();
        if fits {
            self.charge(bytes);
        }
        fits
    }
}

/// Process totals of one queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReadBudgetStats {
    /// Bytes of started reads.
    pub(crate) admitted_bytes: u64,
    /// Bytes of refused attempts; a waiter refused twice counts twice.
    pub(crate) deferred_bytes: u64,
    /// Refused attempts.
    pub(crate) deferred: u64,
    /// The longest wait from enrolment to a started read.
    pub(crate) max_wait_passes: u32,
    /// Started bytes past what the pass had left: bypasses, the pass's first
    /// read and its front waiter are never refused.
    pub(crate) overshoot_bytes: u64,
    /// Front waiters that did not return during their reserved pass.
    pub(crate) dropped_waiters: u64,
}

#[derive(Clone, Copy)]
struct ReadWait<K> {
    key: K,
    bytes: u64,
    seen_pass: u32,
    enrolled_pass: u32,
}

/// Reads waiting across passes, oldest first and bounded. A key past capacity
/// keeps retrying and enrols when space frees.
pub(crate) struct ReadWaitQueue<K: Copy + Eq> {
    capacity: usize,
    pass: u32,
    /// The front entries covered by this pass's budget.
    reserved: usize,
    reserved_bytes: u64,
    /// The queue's front already read this pass.
    front_read: bool,
    waiting: VecDeque<ReadWait<K>>,
    stats: ReadBudgetStats,
}

impl<K: Copy + Eq> ReadWaitQueue<K> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            pass: 0,
            reserved: 0,
            reserved_bytes: 0,
            front_read: false,
            waiting: VecDeque::new(),
            stats: ReadBudgetStats::default(),
        }
    }

    /// Resident bytes of one entry, for the owner's prepaid bound.
    pub(crate) const fn entry_bytes() -> usize {
        std::mem::size_of::<ReadWait<K>>()
    }

    /// Reserves `budget` for the oldest waiters. A front waiter that did not
    /// return during its reserved pass has left this path and cannot hold the
    /// budget: it leaves only the queue, never data. Its owner keeps the work
    /// and it re-enrols at the back if it returns.
    pub(crate) fn begin_pass(&mut self, budget: &ReadBudget) {
        let (pass, reserved) = (self.pass, self.reserved);
        let before = self.waiting.len();
        let mut position = 0;
        self.waiting.retain(|wait| {
            let keep = position >= reserved || wait.seen_pass == pass;
            position += 1;
            keep
        });
        self.stats.dropped_waiters += (before - self.waiting.len()) as u64;
        self.pass = pass.wrapping_add(1);
        self.reserved = 0;
        self.reserved_bytes = 0;
        self.front_read = false;
        for wait in &self.waiting {
            if self.reserved > 0 && self.reserved_bytes.saturating_add(wait.bytes) > budget.limit {
                break;
            }
            self.reserved += 1;
            self.reserved_bytes = self.reserved_bytes.saturating_add(wait.bytes);
        }
    }

    /// Whether `key` may read `bytes` now. Only `start` spends budget or leaves
    /// the queue; without it this is a free probe. A refused key waits in the
    /// queue and is re-offered by its owner next pass. The pass's first front
    /// waiter always reads, so the queue cannot stall; any other reserved waiter
    /// that grew since its refusal must still fit.
    ///
    /// `bypass` reads now; a started bypass is charged and reported as overshoot
    /// past what the pass had left. Its causes stay few: growth near the source file
    /// cap, where rotation can remove discovery, and the members of a group
    /// whose probes already admitted it as one read.
    pub(crate) fn admit(
        &mut self,
        budget: &mut ReadBudget,
        key: K,
        bytes: u64,
        bypass: bool,
        start: bool,
    ) -> bool {
        let position = self.waiting.iter().position(|wait| wait.key == key);
        let admitted = bypass
            || match position {
                Some(0) if self.reserved > 0 && !self.front_read => true,
                Some(position) if position < self.reserved => {
                    budget
                        .spent
                        .saturating_add(
                            self.reserved_bytes
                                .saturating_sub(self.waiting[position].bytes),
                        )
                        .saturating_add(bytes)
                        <= budget.limit
                }
                Some(_) => false,
                None => {
                    (self.reserved == 0 && budget.spent == 0)
                        || budget
                            .spent
                            .saturating_add(self.reserved_bytes)
                            .saturating_add(bytes)
                            <= budget.limit
                }
            };
        if admitted && start {
            if let Some(position) = position {
                if position < self.reserved {
                    self.front_read |= position == 0;
                    self.reserved -= 1;
                    self.reserved_bytes = self
                        .reserved_bytes
                        .saturating_sub(self.waiting[position].bytes);
                }
                let wait = self.pass.wrapping_sub(self.waiting[position].enrolled_pass);
                self.stats.max_wait_passes = self.stats.max_wait_passes.max(wait);
                self.waiting.remove(position);
            }
            self.stats.overshoot_bytes = self
                .stats
                .overshoot_bytes
                .saturating_add(bytes.saturating_sub(budget.remaining()));
            budget.charge(bytes);
            self.stats.admitted_bytes = self.stats.admitted_bytes.saturating_add(bytes);
            return true;
        }
        if !admitted {
            self.stats.deferred += 1;
            self.stats.deferred_bytes = self.stats.deferred_bytes.saturating_add(bytes);
        }
        match position {
            Some(position) => {
                let pass = self.pass;
                let wait = &mut self.waiting[position];
                wait.seen_pass = pass;
                if !admitted {
                    if position < self.reserved {
                        self.reserved_bytes = self
                            .reserved_bytes
                            .saturating_sub(wait.bytes)
                            .saturating_add(bytes);
                    }
                    wait.bytes = bytes;
                }
            }
            None if !admitted && self.waiting.len() < self.capacity => {
                self.waiting.push_back(ReadWait {
                    key,
                    bytes,
                    seen_pass: self.pass,
                    enrolled_pass: self.pass,
                });
            }
            None => {}
        }
        admitted
    }

    pub(crate) fn stats(&self) -> ReadBudgetStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: u64 = 10;

    fn next_pass(queue: &mut ReadWaitQueue<u32>) -> ReadBudget {
        let budget = ReadBudget::new(LIMIT);
        queue.begin_pass(&budget);
        budget
    }

    /// [money] The budget's first take always fits; later takes need room.
    #[test]
    fn first_take_in_a_pass_always_fits() {
        let mut budget = ReadBudget::new(LIMIT);
        assert_eq!(budget.remaining(), LIMIT);
        assert!(budget.try_take(25), "alone past the limit");
        assert_eq!(budget.remaining(), 0);
        assert!(!budget.try_take(1));
        let mut budget = ReadBudget::new(LIMIT);
        budget.charge(4);
        assert!(budget.try_take(6));
        assert!(!budget.try_take(1));
    }

    /// [money] The queue defers past the budget, drains oldest first and drops
    /// a waiter that left the path, so no key waits behind a departed one.
    #[test]
    fn defers_drains_oldest_first_and_drops_departed_waiters() {
        let mut queue = ReadWaitQueue::new(256);
        let mut budget = next_pass(&mut queue);
        assert!(
            queue.admit(&mut budget, 1, 25, false, true),
            "alone past it"
        );
        assert!(!queue.admit(&mut budget, 2, 6, false, true));
        assert!(!queue.admit(&mut budget, 3, 6, false, true));
        let mut budget = next_pass(&mut queue);
        assert!(
            !queue.admit(&mut budget, 4, 5, false, true),
            "behind the oldest"
        );
        assert!(
            queue.admit(&mut budget, 5, 4, false, true),
            "fits what remains"
        );
        assert!(
            !queue.admit(&mut budget, 3, 6, false, true),
            "not yet its turn"
        );
        assert!(queue.admit(&mut budget, 2, 6, false, true));
        let mut budget = next_pass(&mut queue);
        assert!(queue.admit(&mut budget, 3, 6, false, false), "probe");
        assert_eq!(budget.remaining(), LIMIT, "a probe spends nothing");
        assert!(queue.admit(&mut budget, 3, 6, false, true));
        assert!(!queue.admit(&mut budget, 4, 5, false, false));
        assert!(queue.admit(&mut budget, 6, 100, true, true), "bypass");
        assert_eq!(budget.spent, 106, "a started bypass is still charged");
        let budget = next_pass(&mut queue);
        assert_eq!(queue.reserved, 1);
        queue.begin_pass(&budget);
        assert!(
            queue.waiting.is_empty(),
            "the departed waiter holds nothing"
        );
        let stats = queue.stats();
        assert_eq!(stats.dropped_waiters, 1);
        assert_eq!(stats.max_wait_passes, 2);
        assert_eq!(stats.admitted_bytes, 25 + 4 + 6 + 6 + 100);
        assert_eq!(stats.deferred, 5);
        assert_eq!(stats.overshoot_bytes, 15 + 96);
    }

    /// [money] Growth since a refusal cannot break the bound: only the pass's
    /// first front waiter reads regardless, and the other stays first in line.
    #[test]
    fn a_reserved_waiter_that_grew_must_still_fit() {
        let mut queue = ReadWaitQueue::new(256);
        let mut budget = next_pass(&mut queue);
        budget.charge(1);
        assert!(!queue.admit(&mut budget, 1, 5, false, true));
        assert!(!queue.admit(&mut budget, 2, 5, false, true));
        let mut budget = next_pass(&mut queue);
        assert_eq!(queue.reserved, 2);
        assert!(queue.admit(&mut budget, 1, 8, false, true), "front reads");
        assert!(
            !queue.admit(&mut budget, 2, 8, false, true),
            "no longer fits"
        );
        let mut budget = next_pass(&mut queue);
        assert!(queue.admit(&mut budget, 2, 8, false, true));
        assert!(queue.waiting.is_empty());
    }

    /// [behaviour] A key past capacity stays out of the bounded queue.
    #[test]
    fn queue_is_bounded() {
        let mut queue = ReadWaitQueue::new(3);
        let mut budget = next_pass(&mut queue);
        budget.charge(1);
        for key in 0..4 {
            assert!(!queue.admit(&mut budget, key, 11, false, true));
        }
        assert_eq!(queue.waiting.len(), 3);
    }
}
