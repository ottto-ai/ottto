//! When the collector calls `codex cloud list`.
//!
//! Head (the newest provider page): every five minutes while that page holds
//! a queued, running or unknown task; every 30 minutes while local Codex is
//! active; otherwise every six hours. One daily crawl walks every page,
//! continuing every five minutes across slices and UTC days until it reaches
//! the end. No consent, a pause, an unsupported server or a cloud backoff
//! means no call. All times are monotonic; only the crawl's completion date is
//! a UTC day.

use std::time::{Duration, Instant};
use time::Date;

pub(super) const FAST_HEAD_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub(super) const ACTIVE_HEAD_INTERVAL: Duration = Duration::from_secs(30 * 60);
pub(super) const IDLE_HEAD_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
pub(super) const CRAWL_CONTINUATION_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Pacing per work slice, not coverage: a crawl resumes where it stopped.
pub(super) const MAX_SLICE_PAGES: usize = 10;

/// Constant-space cursor cycle detection (Brent): a provider cursor chain
/// that revisits a cursor is reported without retaining the chain.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub(super) struct Crawl {
    pub(super) cursor: Option<String>,
    pub(super) pages_seen: u64,
    pub(super) cycle: CursorCycle,
    pub(super) next_slice: Instant,
}

#[derive(Debug, Clone, Default)]
pub(super) struct CloudSchedule {
    /// The consent scope these facts belong to; a different scope resets all.
    pub(super) scope: Option<[u8; 32]>,
    pub(super) last_head_attempt: Option<Instant>,
    /// The latest successful head page held a queued/running/unknown task.
    pub(super) head_nonterminal: bool,
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
    /// The server does not authorize collection (paused, policy-disabled or
    /// an older server). Recheck at the idle cadence or on a local wake.
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

    /// Drop transient work (cursor, backoff) after a pause, revoke or wake.
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    pub(super) fn head_interval(&self, now: Instant, last_activity: Option<Instant>) -> Duration {
        if self.head_nonterminal {
            FAST_HEAD_INTERVAL
        } else if last_activity.is_some_and(|activity| {
            now.saturating_duration_since(activity)
                <= crate::adaptive_collector::CadenceConfig::default().warm_window
        }) {
            ACTIVE_HEAD_INTERVAL
        } else {
            IDLE_HEAD_INTERVAL
        }
    }

    fn head_due_at(&self, now: Instant, last_activity: Option<Instant>) -> Instant {
        match self.last_head_attempt {
            Some(last) => last + self.head_interval(now, last_activity),
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
    pub(super) fn next_due(
        &self,
        now: Instant,
        today: Date,
        last_activity: Option<Instant>,
    ) -> Instant {
        let mut due = self.head_due_at(now, last_activity);
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

    pub(super) fn due(&self, now: Instant, today: Date, last_activity: Option<Instant>) -> Due {
        if self.unsupported_until.is_some_and(|until| until > now)
            || self.retry_not_before.is_some_and(|retry| retry > now)
        {
            return Due {
                head: false,
                crawl: false,
            };
        }
        Due {
            head: self.head_due_at(now, last_activity) <= now,
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
