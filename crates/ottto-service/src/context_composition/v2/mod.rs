//! The new-lines composition reader (kinds_version 2).
//!
//! The kinds_version 1 harvest re-reads every settled transcript of a
//! workspace on each cycle. This reader reads each transcript once: a
//! per-file checkpoint remembers how far the file was read and the parse
//! state at that point (open tool calls, the residency of lines still in
//! context, copied-history mode), so a later run reads only the lines added
//! since. Its daily rows, part, tool, file and session totals live in local
//! state per repository scope, and the upload sends only the days that
//! changed.
//!
//! - `reader`: bounded line reader (length at open, complete lines only,
//!   16 MiB line guard).
//! - `decode`: typed borrowed views of transcript lines and the text
//!   measurement over them, with no whole-line `Value` trees.
//! - `claude`, `codex`: the per-line handlers, resumable at any line.
//! - `aggregate`: per-scope totals and the residency of open lines.
//! - `checkpoint`: per-file checkpoints, file pins and the run record.
//! - `scope`: the stable repository scope a file belongs to.
//! - `harvest`: the daily run (gate, budgets, discovery, commit per scope).
//! - `upload`: the changed-days kinds_version 2 payload.
//!
//! Methodology changes apply forward only: a checkpoint keeps its offset
//! when the parser changes, so old bytes are never read twice.
//!
//! The reader replaces the kinds_version 1 harvest when the compile-time
//! switch `CHANGED_DAYS_UPLOAD_ENABLED` is on (see `changed_days_enabled`);
//! with the switch off the kinds_version 1 harvest runs unchanged.

mod aggregate;
mod checkpoint;
mod claude;
mod codex;
mod decode;
mod file;
mod harvest;
mod health;
mod reader;
mod scope;
mod upload;

pub use harvest::run_context_composition_worker;
pub(super) use harvest::spawn_v2_sync;

use std::time::Duration;

/// Compile-time switch for the changed-days reader and uploader. On: the
/// daemon runs this reader and uploads changed days (kinds_version 2), and the
/// kinds_version 1 harvest no longer runs. Set it back to `false` to return to
/// the kinds_version 1 harvest; the reader's local state stays on disk and is
/// not read while the switch is off.
const CHANGED_DAYS_UPLOAD_ENABLED: bool = true;
/// Development override for the switch above (truthy value turns it on;
/// debug builds only). It matters only while the switch is off.
const CHANGED_DAYS_ENV: &str = "OTTTO_CONTEXT_COMPOSITION_CHANGED_DAYS";

pub(super) fn changed_days_enabled() -> bool {
    changed_days_gate(
        CHANGED_DAYS_UPLOAD_ENABLED,
        cfg!(debug_assertions),
        std::env::var(CHANGED_DAYS_ENV).ok().as_deref(),
    )
}

/// The switch decision. The override works in debug builds only: in a
/// release build with the switch off it would stop the kinds_version 1
/// uploads and spend the once-per-install first run early.
fn changed_days_gate(switch: bool, debug_build: bool, override_value: Option<&str>) -> bool {
    switch || (debug_build && override_value.is_some_and(super::harvest::is_truthy))
}

/// Local state folder, under the composition state folder.
const STATE_DIR: &str = "v2";
/// Bumped when the local state layout changes incompatibly; a mismatch reads
/// as bad state (the scope is set aside and counted, never a failure or a
/// re-read). Once released, a layout change must ship a migration of the old
/// state instead of a bump: a bump would set every scope aside.
const STATE_SCHEMA: u32 = 1;
/// Parser identity recorded on each checkpoint at its first read. Changing it
/// never re-reads old bytes. Retained for older checkpoint readers on rollback.
const PARSER_VERSION: &str = "context-composition-reader-v2.1";
const COLLECTOR_VERSION: &str = "context-composition-0.2.0";

// Run gate.
/// The loop wakes this often and runs at most once per UTC day.
const WAKE_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// The daemon must have been up this long before a run, so a start-up burst
/// never stacks on other start-up work.
const MIN_UPTIME: Duration = Duration::from_secs(15 * 60);
/// Wall-clock cap for one run. A cut run commits the scopes it finished; the
/// rest continues the next day.
const RUN_WALL_CAP: Duration = Duration::from_secs(30 * 60);

// Budgets.
/// Full reads (rewritten files, and full reads still waiting from an
/// earlier build's install) and reads after a state fallback, per day.
/// New bytes are not capped.
const REPAIR_BYTES_PER_DAY: u64 = 1024 * 1024 * 1024;

// Retention.
/// Daily rows kept (the server's capture-window cap).
const KEEP_DAYS: i32 = 92;
/// Days of per-day file, tool and part maps (the 30-day period).
const PERIOD_DAYS: i32 = 30;
/// A Claude record dated more than this before its transcript was born (or
/// first seen) was copied from an earlier transcript by a resume or fork: it
/// adds residency only. Copies keep their original timestamps.
const COPIED_SLACK_SECS: i64 = 60;
/// Pins and checkpoints of files gone this long are dropped.
const FORGET_MISSING_DAYS: i32 = 30;

// Caps.
const MAX_FILES_PER_DAY: usize = 1000;
const MAX_ALL_FILES: usize = 2000;
const MAX_ALL_TOOLS: usize = 500;
const MAX_OPEN_CALLS: usize = 4096;
const MAX_ITEMS_PER_CALL: usize = 32;

// Upload.
const UPLOAD_TOP_FILES: usize = 100;
const UPLOAD_TOP_SESSIONS: usize = 50;
const UPLOAD_TOP_TOOLS: usize = 20;
const UPLOAD_TOP_SERVERS: usize = 10;
const UPLOAD_MAX_PARTS: usize = 48;
const MAX_TOOL_LABEL_CHARS: usize = 64;
/// Re-upload at least this often when nothing changed.
const UPLOAD_STALENESS_SECS: i64 = 7 * 24 * 60 * 60;

#[cfg(test)]
mod tests;
