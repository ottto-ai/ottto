//! When the collector calls `codex cloud list`.
//!
//! Head (the newest provider page): every five minutes at first, doubling
//! after each successful head listing that the server accepted nothing new
//! from, up to once a day; an `accepted` upload resets it to five minutes.
//! One daily crawl walks every page, continuing every five minutes across
//! slices and UTC days until it reaches the end. Listing off, an unsupported
//! server or a cloud backoff means no call. All times are monotonic; only the
//! crawl's completion date is a UTC day.

use std::time::{Duration, Instant};
use time::Date;

pub(super) const FAST_HEAD_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub(super) const MAX_HEAD_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Listing is off (or the server refused it): read the hint again after this.
pub(super) const OFF_RECHECK_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// The server lacks the route: check again after this.
pub(super) const UNSUPPORTED_RECHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// The supervisor never sleeps longer than this, so the daily crawl and the
/// rechecks still run when nothing else wakes it.
pub(super) const SUPERVISOR_FALLBACK_WAIT: Duration = Duration::from_secs(6 * 60 * 60);
pub(super) const CRAWL_CONTINUATION_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Pacing per work slice, not coverage: a crawl resumes where it stopped.
pub(super) const MAX_SLICE_PAGES: usize = 10;

/// Constant-space cursor cycle detection (Brent): a provider cursor chain
/// that revisits a cursor is reported without retaining the chain.
#[derive(Clone)]
pub(super) struct CursorCycle {
    tortoise: Option<[u8; 32]>,
    power: u64,
    steps: u64,
}

impl Default for CursorCycle {
    fn default() -> Self {
        Self {
            tortoise: None,
            power: 1,
            steps: 0,
        }
    }
}

impl CursorCycle {
    /// True when `digest` repeats the retained cursor.
    pub(super) fn repeats(&mut self, digest: [u8; 32]) -> bool {
        if self.tortoise == Some(digest) {
            return true;
        }
        self.steps += 1;
        if self.steps == self.power {
            self.tortoise = Some(digest);
            self.power = self.power.saturating_mul(2);
            self.steps = 0;
        }
        false
    }
}

/// An unfinished daily crawl. The raw provider cursor lives only here, in
/// memory; a restart starts a new crawl and the ACK cache suppresses repeats.
#[derive(Clone)]
pub(super) struct Crawl {
    pub(super) cursor: Option<String>,
    pub(super) pages_seen: u64,
    pub(super) cycle: CursorCycle,
    pub(super) next_slice: Instant,
}

#[derive(Clone, Default)]
pub(super) struct CloudSchedule {
    /// The destination and local user these facts belong to; a different
    /// scope resets all.
    pub(super) scope: Option<[u8; 32]>,
    pub(super) last_head_attempt: Option<Instant>,
    pub(super) crawl: Option<Crawl>,
    /// UTC day of the last crawl that reached the end (persisted).
    pub(super) crawl_completed: Option<Date>,
    pub(super) crawl_completed_loaded: bool,
    /// UTC day a crawl ended without reaching a proven end (an ambiguous or
    /// cycling cursor chain); the next crawl starts the following day.
    pub(super) crawl_ended: Option<Date>,
    /// Cloud-only backoff after a failed slice, anchored at the failure.
    pub(super) retry_not_before: Option<Instant>,
    pub(super) consecutive_failures: u32,
    /// Listing is off, the server refused it, or the server lacks the route.
    /// No call before this instant.
    pub(super) unsupported_until: Option<Instant>,
}

/// What a due slice should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Due {
    pub(super) head: bool,
    pub(super) crawl: bool,
}

impl CloudSchedule {
    pub(super) fn reset_for_scope(&mut self, scope: [u8; 32]) {
        if self.scope != Some(scope) {
            *self = Self {
                scope: Some(scope),
                ..Self::default()
            };
        }
    }

    /// Drop transient work (cursor, backoff) when collection stops locally.
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    fn head_due_at(&self, now: Instant, head_interval: Duration) -> Instant {
        match self.last_head_attempt {
            Some(last) => last + head_interval,
            None => now,
        }
    }

    fn crawl_due_at(&self, now: Instant, today: Date) -> Option<Instant> {
        match &self.crawl {
            Some(crawl) => Some(crawl.next_slice),
            None if self.crawl_completed != Some(today) && self.crawl_ended != Some(today) => {
                Some(now)
            }
            None => None,
        }
    }

    /// The next instant any work is due. Backoff and the unsupported-server
    /// recheck defer, never discard, due work.
    pub(super) fn next_due(&self, now: Instant, today: Date, head_interval: Duration) -> Instant {
        let mut due = self.head_due_at(now, head_interval);
        if let Some(crawl) = self.crawl_due_at(now, today) {
            due = due.min(crawl);
        }
        if let Some(until) = self.unsupported_until {
            due = due.max(until);
        }
        if let Some(retry) = self.retry_not_before {
            due = due.max(retry);
        }
        due
    }

    pub(super) fn due(&self, now: Instant, today: Date, head_interval: Duration) -> Due {
        if self.unsupported_until.is_some_and(|until| until > now)
            || self.retry_not_before.is_some_and(|retry| retry > now)
        {
            return Due {
                head: false,
                crawl: false,
            };
        }
        Due {
            head: self.head_due_at(now, head_interval) <= now,
            crawl: self.crawl_due_at(now, today).is_some_and(|at| at <= now),
        }
    }

    pub(super) fn note_failure(&mut self, now: Instant, backoff: Duration) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.retry_not_before = Some(now + backoff);
    }

    pub(super) fn note_success(&mut self) {
        self.consecutive_failures = 0;
        self.retry_not_before = None;
        self.unsupported_until = None;
    }
}

/// The head interval after `unchanged` successful head listings in a row
/// that the server accepted nothing new from: 5, 10, 20 … 1280 minutes, then
/// one day. Kept in memory only; a restart starts at five minutes.
pub(super) fn head_interval(unchanged: u32) -> Duration {
    FAST_HEAD_INTERVAL
        .checked_mul(1_u32.checked_shl(unchanged).unwrap_or(u32::MAX))
        .map_or(MAX_HEAD_INTERVAL, |interval| {
            interval.min(MAX_HEAD_INTERVAL)
        })
}
