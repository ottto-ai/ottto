//! Scan limits: the epoch gates that date which usage a rule counts, and the
//! per-tick listing, backfill and unhealthy-retry budgets.

use crate::snapshots::rfc3339_unix_seconds;

/// 2026-11-09T00:00:00Z, a 00:00Z expected on/after install on every machine.
/// Codex thread-settings tiers and
/// `TieredForward` lines count only evidence and usage dated from here, so a
/// request's row is a function of its file's bytes on every read route and
/// usage accepted before the release keeps exactly the row it had.
pub(in crate::snapshots) const CODEX_FORWARD_EVIDENCE_FROM_UNIX_SECONDS: u64 = 1_794_182_400;

/// 2026-11-04T00:00:00Z, a 00:00Z expected on/after install of the release
/// that carries the Legacy repeat gate. Legacy drops an equal-total repeat
/// only when the repeated line itself is dated from here, so its row is a
/// function of its file's bytes on every read route and history before this
/// keeps exactly the rows it had. Correcting older repeats is an operator
/// decision.
pub(in crate::snapshots) const CODEX_LEGACY_REPEAT_FROM_UNIX_SECONDS: u64 = 1_793_750_400;

/// `false` for a missing or unparsable timestamp.
pub(in crate::snapshots) fn dated_on_or_after(
    timestamp: Option<&str>,
    from_unix_seconds: u64,
) -> bool {
    timestamp
        .and_then(rfc3339_unix_seconds)
        .is_some_and(|seconds| seconds >= from_unix_seconds)
}

pub(in crate::snapshots) fn in_codex_forward_evidence_epoch(timestamp: Option<&str>) -> bool {
    dated_on_or_after(timestamp, CODEX_FORWARD_EVIDENCE_FROM_UNIX_SECONDS)
}

// Per-page read budget, not a history bound: discovery queues every file in
// the window into the durable traversal and the rest continues next page.
pub const MAX_BACKFILL_FILES_PER_SOURCE: usize = 10_000;
// Directory discovery has its own per-tick pacing budget, never a refusal.
// Recursively walking an arbitrarily large tree in one tick made it O(all
// paths); the durable traversal below spends about this many directory entries
// and resumes next tick. One directory wider than the whole budget is listed
// in full on a fresh tick, and that overdraw ends the tick.
pub const MAX_SCAN_DIRECTORY_ENTRIES_PER_TICK: usize = 10_000;
pub const MAX_WATCHER_HINTED_FILES_PER_TICK: usize = 256;
/// The gap between metadata-only re-listing passes of one kept generation
/// (the cold cadence tier). Two passes fit in the freshness alarm window, so a
/// complete walk refreshes the discovery stamp before it can alarm.
pub(crate) const LISTING_INTERVAL_SECONDS: u64 = 3 * 60 * 60;
/// A re-listing pass queues an owed file whose stamp is unchanged at most
/// once per this interval.
pub(in crate::snapshots) const LISTING_OWED_PACE_SECONDS: u64 = 6 * 60 * 60;
pub(in crate::snapshots) const UNHEALTHY_SCAN_RETRY_BASE_SECONDS: u64 = 60;
pub(in crate::snapshots) const UNHEALTHY_SCAN_RETRY_MAX_SECONDS: u64 = 60 * 60;
/// The retry attempt at which the exponential delay reaches its ceiling
/// (`60 * 2^6` seconds is clamped to one hour). The attempt counter saturates
/// here: a traversal that stays terminal-unhealthy is re-walked at most hourly
/// and its persisted witness never grows past this value. The counter clears
/// only when a generation completes (the traversal is dropped) or the scan
/// context changes (a fresh traversal starts at zero).
pub(in crate::snapshots) const UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS: u8 = 7;

pub const BACKFILL_WINDOW_DAYS: u64 = 730;
