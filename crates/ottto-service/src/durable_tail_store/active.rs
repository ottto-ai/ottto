//! Process-wide ownership of transient durable-record allocations.
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

pub(crate) const ACTIVE_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(test)]
thread_local! {
    static TEST_BUDGET: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(crate) fn set_active_budget_for_test(bytes: Option<u64>) {
    TEST_BUDGET.with(|budget| budget.set(bytes));
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
        #[cfg(test)]
        tests::registered(ticket);
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
        let total = self
            .bytes
            .checked_add(bytes)
            .filter(|n| *n <= active_budget())
            .ok_or_else(|| {
                event(self.source, "active_budget_refused", 1);
                ActiveOverBudget
            })?;
        self.bytes = total;
        event(self.source, "active_current_bytes", total);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn charged_for_test(&self) -> u64 {
        self.bytes
    }
    pub(crate) fn release(mut self) {
        self.finish(false);
    }
    fn finish(&mut self, leaked: bool) {
        if !self.released {
            event(self.source, "active_peak_bytes", self.bytes);
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
    use crate::local_resource_diagnostics::capture;
    use std::sync::mpsc;

    thread_local! {
        static QUEUED: std::cell::RefCell<Option<mpsc::Sender<u64>>> = const { std::cell::RefCell::new(None) };
        pub(super) static NEXT_TIMEOUT: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
    }
    pub(super) fn registered(ticket: u64) {
        QUEUED.with(|sender| {
            if let Some(sender) = sender.borrow().as_ref() {
                sender.send(ticket).unwrap();
            }
        });
    }

    #[test]
    fn tiny_budget_is_thread_local_checked_and_cannot_raise_the_production_cap() {
        if !crate::test_isolation::run_here() {
            return;
        }
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                set_active_budget_for_test(None);
            }
        }
        let _reset = Reset;
        set_active_budget_for_test(Some(7));
        assert_eq!(active_budget(), 7);
        assert_eq!(
            std::thread::spawn(active_budget).join().unwrap(),
            ACTIVE_BYTES
        );
        let mut lease = granted();
        lease.charge(7).unwrap();
        assert!(lease.charge(1).is_err());
        assert_eq!(lease.bytes, 7);
        assert!(lease.charge(u64::MAX).is_err());
        lease.release();
        set_active_budget_for_test(Some(u64::MAX));
        assert_eq!(active_budget(), ACTIVE_BYTES);
        set_active_budget_for_test(None);
        let mut lease = granted();
        lease.charge(ACTIVE_BYTES).unwrap();
        lease.release();
    }

    fn granted() -> ActiveLease {
        match ActiveLease::acquire("claude_code") {
            LeaseWait::Granted(lease) => lease,
            LeaseWait::Busy | LeaseWait::OverBudget => panic!("test owner unavailable"),
        }
    }

    fn isolated_owner() -> Mutex<Owner> {
        Mutex::new(Owner {
            busy: false,
            next: 0,
            queue: [0; 64],
            len: 0,
        })
    }

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

    #[test]
    fn full_isolated_queue_refuses_without_registering_or_taking_ownership() {
        let owner = isolated_owner();
        let wake = Condvar::new();
        {
            let mut state = owner.lock().unwrap();
            for (i, ticket) in state.queue.iter_mut().enumerate() {
                *ticket = i as u64 + 1;
            }
            state.len = state.queue.len();
            state.next = state.len as u64;
        }
        assert!(ActiveLease::wait_on(WAIT, &owner, &wake).is_none());
        let state = owner.lock().unwrap();
        assert!(!state.busy);
        assert_eq!(state.len, 64);
        assert_eq!(state.next, 64);
        assert_eq!(state.queue, std::array::from_fn(|i| i as u64 + 1));
    }

    #[test]
    fn checked_credit_explicit_release_and_counted_drop() {
        let (_, events) = capture(|| {
            let mut lease = granted();
            lease.charge(ACTIVE_BYTES).unwrap();
            assert!(matches!(lease.charge(1), Err(ActiveOverBudget)));
            assert!(matches!(lease.charge(u64::MAX), Err(ActiveOverBudget)));
            assert_eq!(lease.bytes, ACTIVE_BYTES);
            lease.release();
            drop(granted());
            granted().release();
        });
        let counters = events
            .iter()
            .map(|event| &event["counts"])
            .collect::<Vec<_>>();
        assert!(counters
            .iter()
            .any(|c| c["active_peak_bytes"] == ACTIVE_BYTES));
        assert_eq!(
            counters
                .iter()
                .filter(|c| c["active_drop_release"] == 1)
                .count(),
            1
        );
        assert!(
            counters
                .iter()
                .filter(|c| c["active_current_bytes"] == 0)
                .count()
                >= 3
        );
    }

    #[test]
    fn timeout_removes_ticket_and_live_waiters_progress_in_fifo_order() {
        let first = granted();
        assert_eq!(WAIT, Duration::from_secs(20));
        let (expired, expire_events) = capture(|| {
            matches!(
                ActiveLease::acquire_for("codex", Duration::from_millis(5)),
                LeaseWait::Busy
            )
        });
        assert!(expired);
        assert!(expire_events
            .iter()
            .any(|e| e["counts"]["active_wait_busy"] == 1));
        assert!(!expire_events
            .iter()
            .any(|e| e["counts"].get("active_current_bytes").is_some()));
        let (ready, receive) = mpsc::channel();
        let (queued, registrations) = mpsc::channel();
        let a_queued = queued.clone();
        let a_ready = ready.clone();
        let a = std::thread::spawn(move || {
            QUEUED.with(|sender| *sender.borrow_mut() = Some(a_queued));
            let lease = ActiveLease::wait("claude_code", WAIT).expect("first queued");
            a_ready.send("a").unwrap();
            lease.release();
        });
        let first_ticket = registrations.recv_timeout(Duration::from_secs(5)).unwrap();
        let b = std::thread::spawn(move || {
            QUEUED.with(|sender| *sender.borrow_mut() = Some(queued));
            let lease = ActiveLease::wait("codex", WAIT).expect("second queued");
            ready.send("b").unwrap();
            lease.release();
        });
        assert!(registrations.recv_timeout(Duration::from_secs(5)).unwrap() > first_ticket);
        first.release();
        assert_eq!(
            receive.recv_timeout(WAIT + Duration::from_secs(1)).unwrap(),
            "a"
        );
        assert_eq!(
            receive.recv_timeout(WAIT + Duration::from_secs(1)).unwrap(),
            "b"
        );
        a.join().unwrap();
        b.join().unwrap();
        granted().release();
    }
}
