//! The one per-pass read byte budget and its oldest-first waiting queue, shared
//! by every cause of a deferred read. No clock takes part: a burst defers by
//! passes, and each source and pass reads a bounded number of bytes.
// Later causes read the stats and take from the budget directly.
#![allow(dead_code)]

use std::collections::VecDeque;

/// One source's read bytes for one pass.
#[derive(Clone, Copy, Debug)]
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
    /// queue and is re-offered by its owner next pass.
    ///
    /// `bypass` reads now and a started bypass is still charged, so the pass's
    /// total stays bounded. Its causes stay few: growth near the source file
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
                Some(position) => position < self.reserved,
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
                    self.reserved -= 1;
                    self.reserved_bytes = self
                        .reserved_bytes
                        .saturating_sub(self.waiting[position].bytes);
                }
                let wait = self.pass.wrapping_sub(self.waiting[position].enrolled_pass);
                self.stats.max_wait_passes = self.stats.max_wait_passes.max(wait);
                self.waiting.remove(position);
            }
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
