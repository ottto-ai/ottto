//! Daily run health: one post per agent per daily run.
//!
//! The worker records each agent's run counts in `health.json` as the agent
//! starts and again when it finishes (after its scopes committed). The
//! daemon side posts them once the worker has exited, adding the counts only
//! it knows (worker timeouts and failures), so a run killed midway still
//! reports. The record is marked sent before the first request: a refused
//! or failed post is logged once and counted, never retried within the day,
//! and the server raises one aggregated alarm a day from what arrives.
//!
//! The body holds counts only, exactly the server's fields (it refuses any
//! other), each within the server's bounds.

use super::aggregate::{date_of, Day};
use super::checkpoint::{read_json, write_json};
use super::harvest::SourceStats;
use super::{COLLECTOR_VERSION, STATE_SCHEMA};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

// The server's bounds.
const MAX_FILES: u64 = 10_000_000;
const MAX_DAYS: u64 = 3_660;
const MAX_CPU_SECONDS: u64 = 10_000_000;
const MAX_DURATION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_BIGINT: u64 = i64::MAX as u64;
const MAX_INT: u64 = i32::MAX as u64;

fn health_path(state_dir: &Path) -> PathBuf {
    state_dir.join("health.json")
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct HealthRecord {
    pub(super) schema: u32,
    pub(super) run_day: Day,
    /// Set before the first post: a run's health is sent at most once.
    pub(super) posted: bool,
    pub(super) entries: Vec<HealthEntry>,
}

/// One agent's counts in one daily run.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct HealthEntry {
    /// The wire agent source.
    pub(super) agent_source: String,
    /// The agent's run ended (also when cut by the wall cap).
    pub(super) finished: bool,
    /// Unix seconds: the end of the agent's run (its start until then).
    pub(super) scan_completed_at: i64,
    pub(super) files_checked: u64,
    pub(super) audit_differences: u64,
    pub(super) full_read_waiting_files: u64,
    pub(super) full_read_backlog_bytes: u64,
    pub(super) backlog_growth_days: u64,
    pub(super) bytes_read: u64,
    pub(super) cpu_seconds: u64,
    pub(super) duration_ms: u64,
    pub(super) accounted_bytes: u64,
    pub(super) scopes_quarantined: u64,
    pub(super) files_quarantined: u64,
    pub(super) agent_resets: u64,
    pub(super) checkpoint_restarts: u64,
}

impl HealthEntry {
    pub(super) fn started(agent_source: &str, now: OffsetDateTime) -> Self {
        Self {
            agent_source: agent_source.to_string(),
            scan_completed_at: now.unix_timestamp(),
            ..Self::default()
        }
    }

    pub(super) fn finished(
        agent_source: &str,
        stats: &SourceStats,
        backlog_growth_days: u32,
        completed: OffsetDateTime,
    ) -> Self {
        Self {
            agent_source: agent_source.to_string(),
            finished: true,
            scan_completed_at: completed.unix_timestamp(),
            files_checked: stats.files_checked,
            audit_differences: stats.audit_differences,
            full_read_waiting_files: stats.full_read_waiting_files,
            full_read_backlog_bytes: stats.full_read_backlog_bytes,
            backlog_growth_days: u64::from(backlog_growth_days),
            bytes_read: stats.bytes_new
                + stats.bytes_repair
                + stats.bytes_head
                + stats.bytes_failed
                + stats.bytes_audit,
            // Nearest whole second of the reading thread's own CPU time.
            cpu_seconds: (stats.cpu_micros + 500_000) / 1_000_000,
            duration_ms: stats.wall_micros / 1000,
            accounted_bytes: stats.peak_accounted_bytes as u64,
            scopes_quarantined: stats.scopes_quarantined,
            files_quarantined: stats.files_quarantined,
            agent_resets: stats.agent_resets,
            checkpoint_restarts: stats.checkpoint_restarts,
        }
    }
}

/// The worker's record of today's run.
pub(super) struct HealthLog {
    path: PathBuf,
    record: HealthRecord,
}

impl HealthLog {
    /// Start today's record (replacing the previous run's).
    pub(super) fn begin(state_dir: &Path, run_day: Day) -> Self {
        let log = Self {
            path: health_path(state_dir),
            record: HealthRecord {
                schema: STATE_SCHEMA,
                run_day,
                posted: false,
                entries: Vec::new(),
            },
        };
        log.save();
        log
    }

    /// Record an agent's counts (replacing its earlier entry).
    pub(super) fn set(&mut self, entry: HealthEntry) {
        match self
            .record
            .entries
            .iter_mut()
            .find(|old| old.agent_source == entry.agent_source)
        {
            Some(old) => *old = entry,
            None => self.record.entries.push(entry),
        }
        self.save();
    }

    fn save(&self) {
        // Health is best effort: a failed write loses only the report.
        let _ = write_json(&self.path, &self.record);
    }
}

/// What only the daemon side knows about the worker that ran.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct WorkerCounts {
    pub(super) timeouts: u64,
    pub(super) failures: u64,
}

/// Take the last run's unsent record and mark it sent, before any post.
/// `None` when there is nothing to send, or when the mark cannot be saved
/// (sending then could repeat the same day's report).
pub(super) fn take_pending(state_dir: &Path, today: Day) -> Option<HealthRecord> {
    let path = health_path(state_dir);
    let mut record = read_json::<HealthRecord>(&path).ok().flatten()?;
    if record.schema != STATE_SCHEMA
        || record.posted
        || record.entries.is_empty()
        // A run that began just before midnight still reports.
        || record.run_day < today - 1
    {
        return None;
    }
    record.posted = true;
    write_json(&path, &record).ok()?;
    Some(record)
}

/// The run-health request body: exactly the server's fields.
pub(super) fn body(
    entry: &HealthEntry,
    run_day: Day,
    machine_id: &str,
    worker: WorkerCounts,
) -> Option<Value> {
    let run_date = date_of(run_day)?;
    let completed = OffsetDateTime::from_unix_timestamp(entry.scan_completed_at)
        .ok()?
        .format(&Rfc3339)
        .ok()?;
    Some(json!({
        "agent_source": entry.agent_source,
        "machine_id": machine_id,
        "run_date": super::super::measure::date_ymd(run_date),
        "scan_completed_at": completed,
        "files_checked": entry.files_checked.min(MAX_FILES),
        "audit_differences": entry.audit_differences.min(MAX_FILES),
        "full_read_waiting_files": entry.full_read_waiting_files.min(MAX_FILES),
        "full_read_backlog_bytes": entry.full_read_backlog_bytes.min(MAX_BIGINT),
        "backlog_growth_days": entry.backlog_growth_days.min(MAX_DAYS),
        "bytes_read": entry.bytes_read.min(MAX_BIGINT),
        "cpu_seconds": entry.cpu_seconds.min(MAX_CPU_SECONDS),
        "duration_ms": entry.duration_ms.min(MAX_DURATION_MS),
        "accounted_bytes": entry.accounted_bytes.min(MAX_BIGINT),
        "collector_version": COLLECTOR_VERSION,
        "scopes_quarantined": entry.scopes_quarantined.min(MAX_INT),
        "files_quarantined": entry.files_quarantined.min(MAX_INT),
        "agent_resets": entry.agent_resets.min(MAX_INT),
        "checkpoint_restarts": entry.checkpoint_restarts.min(MAX_INT),
        "worker_timeouts": worker.timeouts.min(MAX_INT),
        "worker_failures": worker.failures.min(MAX_INT),
    }))
}

pub(super) trait HealthPoster {
    /// One request; an error is any refusal or failure.
    fn post(&mut self, agent_source: &str, body: &Value) -> Result<()>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct PostCounts {
    pub(super) sent: u64,
    pub(super) failed: u64,
}

/// Post each agent's entry once. A failure is logged once and counted.
pub(super) fn send(
    record: &HealthRecord,
    machine_id: &str,
    worker: WorkerCounts,
    poster: &mut dyn HealthPoster,
) -> PostCounts {
    let mut counts = PostCounts::default();
    for entry in &record.entries {
        let result = body(entry, record.run_day, machine_id, worker)
            .ok_or_else(|| anyhow::anyhow!("run health out of range"))
            .and_then(|body| poster.post(&entry.agent_source, &body));
        match result {
            Ok(()) => counts.sent += 1,
            Err(error) => {
                counts.failed += 1;
                eprintln!(
                    "context composition run health not sent for {}: {}",
                    entry.agent_source,
                    crate::snapshot_sync::safe_error(&error)
                );
            }
        }
    }
    counts
}
