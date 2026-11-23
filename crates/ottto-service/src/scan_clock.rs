//! Scheduling clock. Production uses the native UTC and monotonic clocks.
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(crate) fn now() -> Instant {
    #[cfg(test)]
    if let Some(clock) = TEST_CLOCK.with(std::cell::Cell::get) {
        return clock.1;
    }
    Instant::now()
}

pub(crate) fn utc_seconds() -> u64 {
    #[cfg(test)]
    if let Some(clock) = TEST_CLOCK.with(std::cell::Cell::get) {
        return clock.0;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
thread_local! {
    static TEST_CLOCK: std::cell::Cell<Option<(u64, Instant)>> = const { std::cell::Cell::new(None) };
    static EPOCH: Instant = Instant::now();
}

/// One virtual epoch supplies both clocks. Scopes nest and restore on unwind.
#[cfg(test)]
pub(crate) fn with_clock<T>(seconds: u64, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<(u64, Instant)>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_CLOCK.with(|clock| clock.set(self.0));
        }
    }
    let instant = EPOCH.with(|epoch| *epoch + std::time::Duration::from_secs(seconds));
    let _reset = Reset(TEST_CLOCK.with(|clock| clock.replace(Some((seconds, instant)))));
    run()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    /// [behaviour] Acquisition, retries and TTL share one clock without sleeping.
    #[test]
    fn scan_clock_advances_utc_and_monotonic_and_restores() {
        crate::snapshots::sampled_scan::transition_fixture::with_scan_clock(100, || {
            let start = now();
            assert_eq!(utc_seconds(), 100);
            crate::snapshots::sampled_scan::transition_fixture::with_scan_clock(3700, || {
                assert_eq!(utc_seconds(), 3700);
                assert_eq!(now().duration_since(start).as_secs(), 3600);
            });
            assert!(std::panic::catch_unwind(|| with_clock(4000, || panic!("cancel"))).is_err());
            assert_eq!(utc_seconds(), 100);
            assert_eq!(now(), start);
        });
    }
}
