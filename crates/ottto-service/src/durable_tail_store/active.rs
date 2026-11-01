//! Process-wide ownership of transient durable-record allocations.
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

pub(crate) const ACTIVE_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(test)]
thread_local! {
    static REFUSE_NEXT_CHARGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TEST_BUDGET: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(crate) fn set_active_budget_for_test(bytes: Option<u64>) {
    TEST_BUDGET.with(|budget| budget.set(bytes));
    if bytes.is_none() {
        REFUSE_NEXT_CHARGE.with(|slot| slot.set(false));
    }
}
#[cfg(test)]
pub(crate) fn refuse_next_charge() {
    REFUSE_NEXT_CHARGE.with(|slot| slot.set(true));
}
fn active_budget() -> u64 {
    #[cfg(test)]
    if let Some(bytes) = TEST_BUDGET.with(|budget| budget.get()) {
        return bytes.min(ACTIVE_BYTES);
    }
    ACTIVE_BYTES
}
const WAIT: Duration = Duration::from_secs(20);
// Fixed FIFO slots: waiting never allocates or holds another scan lock.
static OWNER: Mutex<Owner> = Mutex::new(Owner {
    busy: false,
    next: 0,
    queue: [0; 64],
    len: 0,
});
static WAKE: Condvar = Condvar::new();
struct Owner {
    busy: bool,
    next: u64,
    queue: [u64; 64],
    len: usize,
}
pub(crate) struct ActiveLease {
    source: &'static str,
    bytes: u64,
    peak: u64,
    released: bool,
}
impl ActiveLease {
    pub(crate) fn acquire(source: &'static str) -> LeaseWait {
        #[cfg(test)]
        if let Some(timeout) = tests::NEXT_TIMEOUT.with(|slot| slot.take()) {
            return Self::acquire_for(source, timeout);
        }
        Self::acquire_for(source, WAIT)
    }
    #[cfg(test)]
    pub(crate) fn timeout_next_acquire_for_test(timeout: Duration) {
        tests::NEXT_TIMEOUT.with(|slot| slot.set(Some(timeout)));
    }
    fn acquire_for(source: &'static str, timeout: Duration) -> LeaseWait {
        let start = Instant::now();
        let outcome = Self::wait(source, timeout);
        event(
            source,
            "active_wait_us",
            start.elapsed().as_micros().min(u64::MAX as u128) as u64,
        );
        event(source, "active_wait_busy", u64::from(outcome.is_none()));
        outcome.map_or(LeaseWait::Busy, LeaseWait::Granted)
    }
    fn wait(source: &'static str, timeout: Duration) -> Option<Self> {
        Self::wait_on(timeout, &OWNER, &WAKE)?;
        Some(Self {
            source,
            bytes: 0,
            peak: 0,
            released: false,
        })
    }
    fn wait_on(timeout: Duration, owner: &Mutex<Owner>, wake: &Condvar) -> Option<()> {
        let deadline = Instant::now().checked_add(timeout)?;
        let mut owner = owner.lock().ok()?;
        if owner.len == owner.queue.len() {
            return None;
        }
        let ticket = owner.next.checked_add(1)?;
        owner.next = ticket;
        let at = owner.len;
        owner.queue[at] = ticket;
        owner.len += 1;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let at = owner.queue[..owner.len].iter().position(|t| *t == ticket)?;
                owner.queue[at..].rotate_left(1);
                owner.len -= 1;
                wake.notify_all();
                return None;
            }
            if !owner.busy && owner.queue[0] == ticket {
                owner.queue.rotate_left(1);
                owner.len -= 1;
                owner.busy = true;
                return Some(());
            }
            owner = wake.wait_timeout(owner, remaining).ok()?.0;
        }
    }
    pub(crate) fn charge(&mut self, bytes: u64) -> Result<(), ActiveOverBudget> {
        #[cfg(test)]
        if REFUSE_NEXT_CHARGE.with(|slot| slot.replace(false)) {
            event(self.source, "active_budget_refused", 1);
            return Err(ActiveOverBudget);
        }
        let total = self
            .bytes
            .checked_add(bytes)
            .filter(|n| *n <= active_budget())
            .ok_or_else(|| {
                event(self.source, "active_budget_refused", 1);
                ActiveOverBudget
            })?;
        self.bytes = total;
        self.peak = self.peak.max(total);
        event(self.source, "active_current_bytes", total);
        Ok(())
    }
    /// Refund only after the associated allocations are dropped or moved to
    /// separately retained credit. An invalid refund cannot increase credit.
    pub(crate) fn refund(&mut self, bytes: u64) -> Result<(), ActiveOverBudget> {
        self.bytes = self.bytes.checked_sub(bytes).ok_or(ActiveOverBudget)?;
        event(self.source, "active_current_bytes", self.bytes);
        Ok(())
    }
    pub(crate) fn release(mut self) {
        self.finish(false);
    }
    fn finish(&mut self, leaked: bool) {
        if !self.released {
            event(self.source, "active_peak_bytes", self.peak);
            event(self.source, "active_current_bytes", 0);
            event(self.source, "active_drop_release", u64::from(leaked));
            self.bytes = 0;
            self.released = true;
            if let Ok(mut owner) = OWNER.lock() {
                owner.busy = false;
                WAKE.notify_all();
            }
        }
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for ActiveLease {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            source: _,
            bytes: _,
            peak: _,
            released: _,
        } = self;
        c.add(0) // Fixed fields only; the process owner is static, never walked.
    }
}
impl Drop for ActiveLease {
    fn drop(&mut self) {
        self.finish(true);
    }
}

pub(crate) enum LeaseWait {
    Granted(ActiveLease),
    Busy,
    OverBudget,
}
#[derive(Debug)]
pub(crate) struct ActiveOverBudget;
fn event(source: &str, name: &'static str, value: u64) {
    crate::local_resource_diagnostics::durable_tail_alarm(
        source,
        &serde_json::json!({(name): value}),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        pub(super) static NEXT_TIMEOUT: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
    }
    fn isolated_owner() -> Mutex<Owner> {
        Mutex::new(Owner {
            busy: false,
            next: 0,
            queue: [0; 64],
            len: 0,
        })
    }

    /// [behaviour] poisoned isolated owner refuses without poisoning global owner.
    #[test]
    fn poisoned_isolated_owner_refuses_without_poisoning_global_owner() {
        let owner = isolated_owner();
        let wake = Condvar::new();
        assert!(std::panic::catch_unwind(|| {
            let _guard = owner.lock().unwrap();
            panic!("isolated poison");
        })
        .is_err());
        assert!(owner.is_poisoned());
        assert!(ActiveLease::wait_on(WAIT, &owner, &wake).is_none());
        assert!(!OWNER.is_poisoned());
    }
}
