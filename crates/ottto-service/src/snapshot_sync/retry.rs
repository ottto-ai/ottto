//! In-place resend budgets and their test clock share one source page.
use super::{uniform_duration, UploadFailureDiagnostics, UploadShed};
use std::time::{Duration, Instant};

// A short, explicitly transient batch failure is resent in place rather than
// abandoning the page and marking the bounded sweep unsettled: a 429/503 whose
// Retry-After is at most 5 s (cursor allocation and shared-lock timeouts send
// 1 s) or a fast 500/502. The wait holds the sync lock, so each source page
// gets at most two resends and 10 s of waiting, shared by its cache-head
// bootstrap stages and its main upload. A failure that took 15 s or longer is
// overload and is never resent; the identity deferral, recognized by its code,
// keeps its backoff whatever its Retry-After.
pub(super) const SNAPSHOT_INPLACE_RETRY_LIMIT: usize = 2;

const SNAPSHOT_INPLACE_RETRY_MAX_WAIT: Duration = Duration::from_secs(5);

pub(super) const SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET: Duration = Duration::from_secs(10);

const SNAPSHOT_INPLACE_RETRY_FAST_FAILURE: Duration = Duration::from_secs(15);

const SNAPSHOT_INPLACE_RETRY_SERVER_ERROR_WAIT: Duration = Duration::from_secs(2);

const SNAPSHOT_INPLACE_RETRY_MIN_WAIT: Duration = Duration::from_millis(250);

/// The wait before resending a failed batch in place, with the HTTP status
/// that earned it, or `None` when the failure keeps its existing path. The
/// wait is never earlier than the server's own `Retry-After`.
fn transient_inplace_retry_wait(error: &anyhow::Error) -> Option<(u16, Duration)> {
    let (status, base) = if let Some(shed) = error.downcast_ref::<UploadShed>() {
        // The identity deferral waits on the identity, not on this request:
        // excluded by its code before any admission, even with a short
        // Retry-After.
        if shed.is_original_identity_unavailable() {
            return None;
        }
        // No Retry-After keeps the jittered ladder; a long one is not worth
        // holding the sync lock for.
        let retry_after = shed
            .retry_after
            .filter(|wait| *wait <= SNAPSHOT_INPLACE_RETRY_MAX_WAIT)?;
        (shed.status, retry_after)
    } else {
        let status = error
            .downcast_ref::<UploadFailureDiagnostics>()?
            .transient_batch_status()?;
        (status, SNAPSHOT_INPLACE_RETRY_SERVER_ERROR_WAIT)
    };
    let base = base.max(SNAPSHOT_INPLACE_RETRY_MIN_WAIT);
    let wait = (base + uniform_duration(base.mul_f64(0.2))).min(SNAPSHOT_INPLACE_RETRY_MAX_WAIT);
    Some((status, wait))
}

/// In-place resends spent by one source page: every batch of its cache-head
/// bootstrap stages and of its main upload draws on the same budget.
#[derive(Default)]
pub(super) struct InplaceRetryBudget {
    pub(super) resends: usize,
    pub(super) waited: Duration,
}

impl InplaceRetryBudget {
    pub(super) fn admit(
        &self,
        error: &anyhow::Error,
        failed_after: Duration,
    ) -> Option<(u16, Duration)> {
        if self.resends >= SNAPSHOT_INPLACE_RETRY_LIMIT
            || failed_after >= SNAPSHOT_INPLACE_RETRY_FAST_FAILURE
        {
            return None;
        }
        transient_inplace_retry_wait(error)
            .filter(|(_, wait)| self.waited + *wait <= SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET)
    }
}

pub(super) fn inplace_retry_failed_after(started: Instant) -> Duration {
    #[cfg(test)]
    if let Some(failed_after) = INPLACE_RETRY_TEST_CLOCK
        .with(|clock| clock.borrow().as_ref().and_then(|clock| clock.failed_after))
    {
        return failed_after;
    }
    started.elapsed()
}

pub(super) fn inplace_retry_sleep(wait: Duration) {
    #[cfg(test)]
    if INPLACE_RETRY_TEST_CLOCK.with(|clock| match clock.borrow_mut().as_mut() {
        Some(clock) => {
            clock.waits.push(wait);
            true
        }
        None => false,
    }) {
        return;
    }
    std::thread::sleep(wait);
}

/// Test-only stand-in for the in-place resend clock: it records every wait
/// instead of sleeping and may override how long a failed POST took.
#[cfg(test)]
struct InplaceRetryTestClock {
    failed_after: Option<Duration>,
    waits: Vec<Duration>,
}

#[cfg(test)]
thread_local! {
    static INPLACE_RETRY_TEST_CLOCK: std::cell::RefCell<Option<InplaceRetryTestClock>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `body` with this thread's in-place resend clock replaced. Returns the
/// result and every wait the uploader asked for, in order.
#[cfg(test)]
pub(super) fn with_inplace_retry_test_clock<R>(
    failed_after: Option<Duration>,
    body: impl FnOnce() -> R,
) -> (R, Vec<Duration>) {
    INPLACE_RETRY_TEST_CLOCK.with(|clock| {
        *clock.borrow_mut() = Some(InplaceRetryTestClock {
            failed_after,
            waits: Vec::new(),
        });
    });
    let result = body();
    let waits = INPLACE_RETRY_TEST_CLOCK
        .with(|clock| clock.borrow_mut().take())
        .map(|clock| clock.waits)
        .unwrap_or_default();
    (result, waits)
}
