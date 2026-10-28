//! The daily run: gate, discovery, budgets, reading, commit per scope and
//! upload.
//!
//! The loop wakes hourly and runs once per UTC day, after the daemon has
//! been up for `MIN_UPTIME`, at utility QoS. The day is saved when the run
//! starts, so a crash never repeats a day. New bytes are read without a cap;
//! full reads (files rewritten in place) share
//! `REPAIR_BYTES_PER_DAY`, newest first, each up to its size when granted,
//! and the rest wait for a later day (counted). A run stops at
//! `RUN_WALL_CAP`; each scope commits on its own, so a cut run never counts
//! anything twice.
//!
//! First run (no pins yet) is strictly forward-only: every file it finds,
//! even one still being written, starts at its current size (counted as
//! `install_forward_only`); nothing written before the install is read. An
//! install record is saved before any scope commits. If the first run stops
//! before its pins are saved, the next run finds the record without pins and
//! resets the agent the same way (counted). Later, a file with no pin that
//! was born after the last saved scan started is new and read from its
//! start; any other file with no pin (or no known birth time) starts at its
//! current size, counted. Full reads still waiting from an earlier build's
//! install keep draining within the repair budget.
//!
//! Bad state is quarantined and counted. On a later run its files restart
//! at their current ends; no prior generation or transcript history is replayed.
//!
//! Every wake (even when no run is due) records the linked worktrees of each
//! repository scope, read from the shared git folder without starting git,
//! so a session whose worktree is removed before the next run still counts
//! in its repository.

use super::super::harvest::{
    agent_source_label, destination_identity, local_harvest_disabled, org_disabled_marker_path,
    read_marker, write_marker,
};
use super::aggregate::{day_of, Aggregate, Day, StoredContribution, Window};
use super::checkpoint::{
    birth_secs, born_secs, file_identity, fingerprints, fingerprints_match, install_path,
    prefix_matches, read_json, stamp, write_json, write_packed, Checkpoint, Index, InstallRecord,
    Pin, RunRecord, Stamp, Status, StoredParse, COLD_AFTER_SECS,
};
use super::file::{
    head_cwds, new_parse_state, new_parse_state_before, read_lines, LineSink, LineStats, Names,
    Source,
};
use super::health::{HealthEntry, HealthLog, HealthPoster, PostCounts, WorkerCounts};
use super::scope::{
    checkpoint_members, highest_generation, linked_worktrees, load_scope, resolved_missing,
    save_scope, scope_file_stem, scope_files, scope_path, set_aside, shard_id, update_members,
    verify_commit, GitScopeResolver, Scope, ScopeInfo, ScopeResolver,
};
use super::upload::{
    upload_scope, UploadOutcome, UploadReceipt, UploadResult, UploadTarget, Uploader,
};
use super::{
    COPIED_SLACK_SECS, FORGET_MISSING_DAYS, KEEP_DAYS, MIN_UPTIME, PARSER_VERSION,
    REPAIR_BYTES_PER_DAY, RUN_WALL_CAP, STATE_DIR, STATE_SCHEMA, WAKE_INTERVAL,
};
use crate::composition_kinds::{GitRootCache, KindsVersion};
use crate::snapshot_client::{
    load_snapshot_device_credentials, workspace_labels_allowed, SnapshotApiClient,
};
use crate::snapshots::SnapshotSource;
use anyhow::{anyhow, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(super) fn state_dir(support_dir: &Path) -> PathBuf {
    support_dir.join("context_composition").join(STATE_DIR)
}

// -------------------------------------------------------------------------
// Loop and gate.
// -------------------------------------------------------------------------

pub(in crate::context_composition) fn spawn_v2_sync() -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-context-composition-v2".to_string())
        .spawn(move || {
            set_utility_qos();
            let started = Instant::now();
            let mut worktrees = WorktreeCache::default();
            loop {
                let wait = MIN_UPTIME.saturating_sub(started.elapsed());
                if !wait.is_zero() {
                    std::thread::sleep(wait);
                }
                if let Err(error) = run_wake(&mut worktrees) {
                    eprintln!(
                        "context composition run skipped: {}",
                        crate::snapshot_sync::safe_error(&error)
                    );
                }
                // All daily state, pipe buffers and superseded hourly
                // metadata have dropped before this single relief call.
                release_memory();
                std::thread::sleep(WAKE_INTERVAL);
            }
        })
        .map_err(|error| anyhow!("spawn context composition reader: {error}"))?;
    Ok(())
}

fn run_wake(worktrees: &mut WorktreeCache) -> Result<()> {
    // Pin reloads can allocate as much as a scan. Keep both in the worker;
    // only the hourly folder map returns to the scheduler.
    let mut command = Command::new(std::env::current_exe()?);
    command.arg("context-composition-worker");
    let result = run_worker_process(&mut command, worktrees);
    let (timeouts, failures, locked) = match result
        .as_ref()
        .err()
        .and_then(|e| e.downcast_ref::<WorkerError>())
    {
        Some(WorkerError::Timeout) => (1, 0, 0),
        Some(WorkerError::Locked) => (0, 0, 1),
        _ if result.is_err() => (0, 1, 0),
        _ => (0, 0, 0),
    };
    // After the worker exited, so its scopes have committed (or it died).
    let health = post_run_health(WorkerCounts { timeouts, failures });
    eprintln!("context_composition_v2_metrics source=parent worker_timeouts={timeouts} worker_failures={failures} worker_lock_busy={locked} health_sent={} health_failed={}", health.sent, health.failed);
    *worktrees = result?;
    Ok(())
}

/// Send the last daily run's health once (see `health`). Credentials are
/// loaded only when a run left an unsent record.
fn post_run_health(worker: WorkerCounts) -> PostCounts {
    let dir = state_dir(&ottto_core::default_support_dir());
    let today = day_of(OffsetDateTime::now_utc().date());
    let Some(record) = take_run_health(&dir, today) else {
        return PostCounts::default();
    };
    let mut poster = match ClientHealthPoster::load() {
        Ok(poster) => poster,
        Err(error) => {
            eprintln!(
                "context composition run health not sent: {}",
                crate::snapshot_sync::safe_error(&error)
            );
            return PostCounts {
                sent: 0,
                failed: record.entries.len() as u64,
            };
        }
    };
    let (destination, machine_id) = (poster.destination.clone(), poster.machine_id.clone());
    super::health::send(&record, &destination, &machine_id, worker, &mut poster)
}

/// Mark the daily record while holding the state lease, then release it
/// before credentials, DNS or network work can block another worker.
pub(super) fn take_run_health(dir: &Path, today: Day) -> Option<super::health::HealthRecord> {
    // SIGKILL is asynchronous: allow the OS to release the dead worker's
    // lease without turning an optional health report into an unbounded wait.
    let until = Instant::now() + std::time::Duration::from_secs(1);
    let _lease = loop {
        if let Some(lease) = lock_state(dir).ok()? {
            break lease;
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    super::health::take_pending(dir, today)
}

/// Posts with the composition upload's credentials: a relay token per agent.
struct ClientHealthPoster {
    client: SnapshotApiClient,
    device: ottto_core::LocalDeviceBinding,
    device_secret: String,
    machine_id: String,
    destination: String,
}

impl ClientHealthPoster {
    fn load() -> Result<Self> {
        let (device, device_secret) = load_snapshot_device_credentials()?;
        let Some(machine_id) = crate::snapshot_sync::snapshot_machine_id(&device)? else {
            return Err(anyhow!("machine identity is missing"));
        };
        let api_base_url = crate::snapshot_sync::snapshot_api_base_url()?;
        Ok(Self {
            client: SnapshotApiClient::new(api_base_url.clone()),
            destination: destination_identity(&device, &machine_id, &api_base_url),
            device,
            device_secret,
            machine_id,
        })
    }
}

impl HealthPoster for ClientHealthPoster {
    fn post(&mut self, agent_source: &str, body: &Value) -> Result<()> {
        let source = [SnapshotSource::ClaudeCode, SnapshotSource::Codex]
            .into_iter()
            .find(|source| agent_source_label(*source) == agent_source)
            .ok_or_else(|| anyhow!("unknown agent source"))?;
        let token = self.client.issue_composition_health_relay_token(
            &self.device,
            &self.device_secret,
            source,
            std::time::Duration::from_secs(10),
        )?;
        self.client
            .post_context_composition_run_health(&token, body)
            .map(|_| ())
    }
}

// A marker lets the same runner be exercised by the Rust test harness,
// whose own progress lines also go to stdout. The reply contains folder
// metadata only; daily checkpoints and aggregates never cross this pipe.
const WORKER_REPLY: &[u8] = b"composition-worker-v1 ";

pub(super) fn write_worker_reply(reply: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    out.write_all(b"\n")?;
    out.write_all(WORKER_REPLY)?;
    serde_json::to_writer(&mut out, reply)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// The whole parent/worker exchange is bounded by the scan cap plus a
/// margin. The worker enforces the same cap on itself, so a worker whose
/// parent died still exits and frees the state lock.
pub(super) const WORKER_CAP: std::time::Duration =
    std::time::Duration::from_secs(RUN_WALL_CAP.as_secs() + 5 * 60);

/// Exit status of a worker stopped by its own watchdog.
pub(super) const WORKER_WATCHDOG_EXIT: i32 = 70;

/// Wait for process exit before returning any hourly metadata. System malloc
/// can retain free pages even after thread exit and pressure relief; process
/// teardown releases those pages without changing the daemon's allocator.
pub(super) fn run_worker_process<I: Serialize, O: DeserializeOwned>(
    command: &mut Command,
    input: &I,
) -> Result<O> {
    run_worker_process_timeout(command, input, WORKER_CAP)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum WorkerError {
    Timeout,
    Failed,
    Locked,
}
impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "composition worker {self:?}")
    }
}
impl std::error::Error for WorkerError {}

enum WorkerEvent {
    Wrote(std::io::Result<()>),
    Output(std::io::Result<Vec<u8>>),
    Exited(std::io::Result<std::process::ExitStatus>),
}

pub(super) fn run_worker_process_timeout<I: Serialize, O: DeserializeOwned>(
    command: &mut Command,
    input: &I,
    timeout: std::time::Duration,
) -> Result<O> {
    use std::io::{Read, Write};
    use std::sync::mpsc::RecvTimeoutError;
    let deadline = Instant::now() + timeout;
    let bytes = serde_json::to_vec(input)?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let pid = child.id();
    let mut stdin = child.stdin.take().expect("piped worker input");
    let stdout = child.stdout.take().expect("piped worker output");
    let (send, recv) = std::sync::mpsc::channel();
    let send_input = send.clone();
    let writer = std::thread::spawn(move || {
        let result = stdin.write_all(&bytes);
        drop(stdin);
        let _ = send_input.send(WorkerEvent::Wrote(result));
    });
    let send_output = send.clone();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes);
        let result = result.and_then(|_| {
            if bytes.len() > 16 * 1024 * 1024 {
                Err(std::io::Error::other("worker reply too large"))
            } else {
                Ok(bytes)
            }
        });
        let _ = send_output.send(WorkerEvent::Output(result));
    });
    // The only thread that waits for the worker: a kill never leaves the
    // scheduler blocked on a process stuck in the file system.
    let reaper = std::thread::spawn(move || {
        let _ = send.send(WorkerEvent::Exited(child.wait()));
    });
    let exchange = (|| -> Result<O> {
        let mut status: Option<std::process::ExitStatus> = None;
        let mut wrote: Option<std::io::Result<()>> = None;
        let mut output: Option<std::io::Result<Vec<u8>>> = None;
        loop {
            // The exit status decides first: a worker that found the lock
            // busy exits before reading its input, so the write may fail.
            if let Some(status) = &status {
                if status.code() == Some(75) {
                    return Err(WorkerError::Locked.into());
                }
                if !status.success() {
                    return Err(WorkerError::Failed.into());
                }
                match (&wrote, &output) {
                    (Some(Err(_)), _) | (_, Some(Err(_))) => return Err(WorkerError::Failed.into()),
                    (Some(Ok(())), Some(Ok(bytes))) => {
                        let reply = bytes
                            .split(|b| *b == b'\n')
                            .rev()
                            .find_map(|line| line.strip_prefix(WORKER_REPLY))
                            .ok_or(WorkerError::Failed)?;
                        return serde_json::from_slice(reply)
                            .map_err(|_| WorkerError::Failed.into());
                    }
                    _ => {}
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match recv.recv_timeout(left) {
                Ok(WorkerEvent::Wrote(result)) => wrote = Some(result),
                Ok(WorkerEvent::Output(result)) => output = Some(result),
                Ok(WorkerEvent::Exited(result)) => {
                    status = Some(result.map_err(|_| WorkerError::Failed)?)
                }
                Err(RecvTimeoutError::Timeout) => return Err(WorkerError::Timeout.into()),
                Err(RecvTimeoutError::Disconnected) => return Err(WorkerError::Failed.into()),
            }
        }
    })();
    if exchange.is_ok() {
        let _ = writer.join();
        let _ = reader.join();
        let _ = reaper.join();
        return exchange;
    }
    // Kill the private process group as well: a child holding a pipe must
    // not keep either I/O thread alive. The reaper thread collects the
    // worker; none of these threads is joined here.
    #[cfg(unix)]
    // SAFETY: this child was started in its own process group.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = pid;
    drop((writer, reader, reaper));
    exchange
}

/// Stop this worker after `cap` even when its scan is stuck, so an orphaned
/// worker cannot hold the state lock forever.
pub(super) fn start_watchdog(cap: std::time::Duration) {
    let _ = std::thread::Builder::new()
        .name("ottto-context-composition-watchdog".to_string())
        .spawn(move || {
            std::thread::sleep(cap);
            eprintln!("context_composition_v2_metrics source=worker worker_watchdog=1");
            std::process::exit(WORKER_WATCHDOG_EXIT);
        });
}

/// The OS releases this exclusive lease even if the parent or worker dies.
/// It covers hourly mapping and the saved-day check as well as the scan.
pub(super) fn lock_state(dir: &Path) -> std::io::Result<Option<File>> {
    super::checkpoint::create_dir_durable(dir)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("worker.lock"))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: flock operates on this live file descriptor.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(error);
        }
    }
    #[cfg(not(unix))]
    return Err(std::io::Error::other("worker locking is unsupported"));
    #[cfg(unix)]
    Ok(Some(lock))
}

/// Private service entry point. It starts neither the daemon nor any other
/// collector.
#[doc(hidden)]
pub fn run_context_composition_worker() -> Result<()> {
    set_utility_qos();
    let support_dir = ottto_core::default_support_dir();
    let Some(_lease) = lock_state(&state_dir(&support_dir))? else {
        eprintln!("context_composition_v2_metrics source=worker worker_lock_busy=1");
        std::process::exit(75);
    };
    start_watchdog(WORKER_CAP);
    let mut worktrees: WorktreeCache = serde_json::from_reader(std::io::stdin().lock())?;
    let home = crate::snapshot_sync::home_dir()?;
    if let Err(error) = run_if_due(&home, &support_dir, &mut worktrees) {
        eprintln!(
            "context composition run skipped: {}",
            crate::snapshot_sync::safe_error(&error)
        );
    }
    write_worker_reply(&worktrees)
}

/// Background work: let the system run it on efficiency cores and behind
/// interactive work.
pub(super) fn set_utility_qos() {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
        }
        const QOS_CLASS_UTILITY: u32 = 0x11;
        // SAFETY: sets the calling thread's own QoS class; no pointers.
        let _ = unsafe { pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0) };
    }
}

/// CPU time of the calling thread, in microseconds.
pub(super) fn thread_cpu_micros() -> Option<u64> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut spec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes the struct it is given.
        if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut spec) } != 0 {
            return None;
        }
        Some(spec.tv_sec as u64 * 1_000_000 + spec.tv_nsec as u64 / 1_000)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    None
}

/// The order the sources read in on `today`. It alternates by day, so a run
/// cut by the wall cap never starves the same source day after day.
pub(super) fn source_order(today: Day) -> [(SnapshotSource, Source); 2] {
    let claude = (SnapshotSource::ClaudeCode, Source::Claude);
    let codex = (SnapshotSource::Codex, Source::Codex);
    if today.rem_euclid(2) == 0 {
        [claude, codex]
    } else {
        [codex, claude]
    }
}

/// Run once if today's run has not started yet.
fn run_if_due(home: &Path, support_dir: &Path, worktrees: &mut WorktreeCache) -> Result<()> {
    if local_harvest_disabled(support_dir) {
        return Ok(());
    }
    let now = OffsetDateTime::now_utc();
    let dir = state_dir(support_dir);
    let today = day_of(now.date());
    let Some(mut record) = begin_run(&dir, now)? else {
        map_worktrees(&dir, today, worktrees);
        return Ok(());
    };
    // Read only the non-secret destination metadata needed to fence health.
    // Keychain access and all scanning setup follow the durable attempts.
    let device = ottto_core::FileDeviceStore::default()
        .load()?
        .ok_or_else(|| anyhow!("relay device binding is missing"))?;
    let Some(machine_id) = crate::snapshot_sync::snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = crate::snapshot_sync::snapshot_api_base_url()?;
    let enabled = crate::snapshot_sync::enabled_snapshot_sources(&device);
    let destination = destination_identity(&device, &machine_id, &api_base_url);
    // Persist attempts before root discovery, identity-state loading or network
    // setup. A worker killed there must still leave a report for the parent.
    let mut health = begin_run_health(support_dir, &dir, today, &destination, &enabled, now);
    map_worktrees(&dir, today, worktrees);
    let (current_device, device_secret) = load_snapshot_device_credentials()?;
    if current_device != device {
        return Err(anyhow!("relay device binding changed during setup"));
    }
    let client = SnapshotApiClient::new(api_base_url.clone());
    let mut resolver = GitScopeResolver;
    let start_destination = crate::snapshots::start_verdict_store::destination(
        &crate::snapshot_sync::snapshot_upload_destination_namespace(&device, &device_secret),
        &api_base_url,
        &machine_id,
    );
    let mut run = Run {
        start_verdicts: crate::snapshots::start_verdict_store::load(
            support_dir,
            &start_destination,
            now.unix_timestamp(),
        ),
        state_dir: dir.clone(),
        now,
        deadline: Instant::now() + RUN_WALL_CAP,
        resolver: &mut resolver,
        repair_left: REPAIR_BYTES_PER_DAY.saturating_sub(record.repair_used),
    };
    for (snapshot_source, source) in source_order(today) {
        if !enabled.contains(&snapshot_source) || Instant::now() >= run.deadline {
            continue;
        }
        let roots = match crate::snapshot_roots::registered_scan_roots(snapshot_source, home) {
            Ok(roots) => roots,
            Err(error) => {
                // A partial root list would start missing transcripts over.
                eprintln!(
                    "context composition run skipped for {}: {}",
                    agent_source_label(snapshot_source),
                    crate::snapshot_sync::safe_error(&error)
                );
                continue;
            }
        };
        // The shared context-harvest activity gate (org opt-out, labels).
        let relay_token = client
            .issue_relay_token(&device, &device_secret, snapshot_source)
            .ok();
        let marker = org_disabled_marker_path(support_dir, snapshot_source);
        let mut labels_enabled = workspace_labels_allowed(None);
        let mut details_enabled = false;
        if let Some(token) = relay_token.as_deref() {
            match client.get_activity_hint(token) {
                Ok(hint) if !hint.context_footprint_harvest_enabled => {
                    write_marker(&marker, &destination);
                    health.remove(agent_source_label(snapshot_source));
                    continue;
                }
                Ok(hint) => {
                    let _ = fs::remove_file(&marker);
                    labels_enabled = workspace_labels_allowed(Some(&hint));
                    details_enabled = super::upload::details_enabled(
                        hint.context_composition_details_contract.as_deref(),
                    );
                }
                Err(_) if read_marker(&marker).as_deref() == Some(destination.as_str()) => {
                    health.remove(agent_source_label(snapshot_source));
                    continue;
                }
                Err(_) => {}
            }
        } else if read_marker(&marker).as_deref() == Some(destination.as_str()) {
            health.remove(agent_source_label(snapshot_source));
            continue;
        }
        let mut uploader = relay_token.map(|token| ClientUploader {
            client: &client,
            relay_token: token,
        });
        let target = uploader.as_mut().map(|uploader| UploadTarget {
            uploader: uploader as &mut dyn Uploader,
            machine_id: &machine_id,
            destination: &destination,
            labels_enabled,
            details_enabled,
        });
        let agent = agent_source_label(snapshot_source);
        health.set(HealthEntry::started(agent, OffsetDateTime::now_utc()));
        let stats = run_source(&mut run, source, &roots, target);
        let growth_days = record
            .backlog
            .entry(source.label().to_string())
            .or_default()
            .record(today, stats.full_read_backlog_bytes);
        health.set(HealthEntry::finished(
            agent,
            &stats,
            growth_days,
            OffsetDateTime::now_utc(),
        ));
        print_metrics(source, &stats, now);
    }
    record.repair_used = REPAIR_BYTES_PER_DAY.saturating_sub(run.repair_left);
    let _ = write_json(&dir.join("run.json"), &record);
    Ok(())
}

/// Seed enabled attempts, excluding the destination's known organization opt-outs.
pub(super) fn begin_run_health(
    support_dir: &Path,
    dir: &Path,
    today: Day,
    destination: &str,
    enabled: &[SnapshotSource],
    now: OffsetDateTime,
) -> HealthLog {
    let mut entries = Vec::new();
    for (source, _) in source_order(today) {
        if enabled.contains(&source)
            && read_marker(&org_disabled_marker_path(support_dir, source)).as_deref()
                != Some(destination)
        {
            entries.push(HealthEntry::started(agent_source_label(source), now));
        }
    }
    HealthLog::begin_attempts(dir, today, destination, entries)
}

/// Start today's run: `None` when it already started. The day is saved
/// before any reading.
pub(super) fn begin_run(dir: &Path, now: OffsetDateTime) -> Result<Option<RunRecord>> {
    let today = day_of(now.date());
    let path = dir.join("run.json");
    let mut record = read_json::<RunRecord>(&path)
        .ok()
        .flatten()
        .filter(|record| record.schema == STATE_SCHEMA)
        .unwrap_or_default();
    if record.last_run_day.is_some_and(|day| day >= today) {
        return Ok(None);
    }
    record.schema = STATE_SCHEMA;
    record.last_run_day = Some(today);
    record.last_run_started = Some(now.unix_timestamp());
    if record.repair_day != today {
        record.repair_day = today;
        record.repair_used = 0;
    }
    write_json(&path, &record)
        .map_err(|error| anyhow!("save composition run day failed: {error}"))?;
    Ok(Some(record))
}

struct ClientUploader<'a> {
    client: &'a SnapshotApiClient,
    relay_token: String,
}

impl Uploader for ClientUploader<'_> {
    fn upload(&mut self, request: &Value) -> Result<UploadReceipt> {
        let body = serde_json::to_vec(request)?;
        let response = self
            .client
            .upload_context_composition_body(&self.relay_token, &body)?;
        Ok(UploadReceipt {
            payload_bytes: body.len() as u64,
            rows_written: response
                .get("daily_rollup_rows_written")
                .and_then(Value::as_u64),
        })
    }
}

fn print_metrics(source: Source, stats: &SourceStats, now: OffsetDateTime) {
    let at = now.format(&Rfc3339).unwrap_or_default();
    let lines = &stats.lines;
    eprintln!(
        "context_composition_v2_metrics at={at} source={} bytes_new={} bytes_repair={} bytes_head={} bytes_failed={} files_read={} files_failed={} quarantined={} new_files={} dormant_found={} install_forward_only={} verdict_deferred={} lines={} prefix_skipped={} classifier_skipped={} too_long={} bad_lines={} dropped_calls={} dropped_items={} unnamed_files={} name_lookups_skipped={} web_search_in_call={} scan_errors={} repair_waiting={} repair_waiting_bytes={} repair_restarted={} cold_compacted={} cold_restarted={} bad_state={} agent_resets={} scopes_quarantined={} files_quarantined={} checkpoint_restarts={} pins_rebuilt={} moved={} switched={} archived={} archived_unpinned={} duplicates={} unscoped={} scopes_committed={} scopes_failed={} uploaded={} upload_unchanged={} upload_failed={} upload_dropped_non_v2={} upload_dropped_unsafe={} upload_payload_bytes={} upload_rows_written={} files_checked={} full_read_waiting_files={} full_read_backlog_bytes={} bytes_read={} cut={} cpu_ms={} wall_ms={} peak_accounted_bytes={} state_bytes={}",
        source.label(),
        stats.bytes_new,
        stats.bytes_repair,
        stats.bytes_head,
        stats.bytes_failed,
        stats.files_read,
        stats.files_failed,
        stats.quarantined,
        stats.new_files,
        stats.dormant_found,
        stats.install_forward_only,
        stats.verdict_deferred,
        lines.lines,
        lines.prefix_skipped,
        lines.classifier_skipped,
        lines.too_long,
        lines.bad_lines,
        lines.dropped_calls,
        lines.dropped_items,
        lines.unnamed_files,
        stats.name_lookups_skipped,
        lines.web_search_in_call,
        stats.scan_errors,
        stats.repair_waiting,
        stats.repair_waiting_bytes,
        stats.repair_restarted,
        stats.cold_compacted,
        stats.cold_restarted,
        stats.bad_state,
        stats.agent_resets,
        stats.scopes_quarantined,
        stats.files_quarantined,
        stats.checkpoint_restarts,
        stats.pins_rebuilt,
        stats.moved,
        stats.switched,
        stats.archived,
        stats.archived_unpinned,
        stats.duplicates,
        stats.unscoped,
        stats.scopes_committed,
        stats.scopes_failed,
        stats.uploaded,
        stats.upload_unchanged,
        stats.upload_failed,
        stats.upload_dropped_non_v2,
        stats.upload_dropped_unsafe,
        stats.upload_payload_bytes,
        stats.upload_rows_written,
        stats.files_checked,
        stats.full_read_waiting_files,
        stats.full_read_backlog_bytes,
        stats.bytes_new + stats.bytes_repair + stats.bytes_head + stats.bytes_failed,
        stats.cut,
        stats.cpu_micros / 1000,
        stats.wall_micros / 1000,
        stats.peak_accounted_bytes,
        stats.state_bytes,
    );
}

// -------------------------------------------------------------------------
// Worktree map (every wake).
// -------------------------------------------------------------------------

/// What the last wake saw of one agent's pins, so a wake with nothing new
/// reads only the shared git folders, never the pins.
#[derive(Default, Serialize, Deserialize)]
pub(super) struct WorktreeCache {
    seen: BTreeMap<Source, SeenIndex>,
}

#[derive(Serialize, Deserialize)]
struct SeenIndex {
    /// Size and modification time of the pins file when read.
    witness: (u64, Stamp),
    /// Live repository scopes and their shared git folders.
    repositories: Vec<(String, PathBuf)>,
    known: BTreeSet<String>,
}

impl SeenIndex {
    fn new(index: &Index, witness: (u64, Stamp), today: Day) -> Self {
        Self {
            witness,
            repositories: index
                .scope_info
                .iter()
                .filter(|(scope, _)| !scope_retired(index, scope, today))
                .filter_map(|(scope, info)| {
                    Some((scope.clone(), PathBuf::from(info.common_dir.as_deref()?)))
                })
                .collect(),
            known: index.cwd_scopes.keys().cloned().collect(),
        }
    }
}

fn index_witness(path: &Path) -> Option<(u64, Stamp)> {
    let metadata = fs::metadata(path).ok()?;
    Some((metadata.len(), stamp(&metadata)))
}

/// Record every linked worktree of each live repository scope in the pins'
/// folder map. Returns the folders added.
pub(super) fn map_worktrees(state_dir: &Path, today: Day, cache: &mut WorktreeCache) -> u64 {
    let mut added = 0;
    for source in [Source::Claude, Source::Codex] {
        let path = index_path(state_dir, source);
        let Some(witness) = index_witness(&path) else {
            cache.seen.remove(&source);
            continue;
        };
        if cache.seen.get(&source).map(|seen| seen.witness) != Some(witness) {
            let Ok(Some(index)) = read_json::<Index>(&path) else {
                cache.seen.remove(&source);
                continue;
            };
            if index.schema != STATE_SCHEMA {
                continue;
            }
            cache
                .seen
                .insert(source, SeenIndex::new(&index, witness, today));
        }
        let Some(seen) = cache.seen.get(&source) else {
            continue;
        };
        let mut new: Vec<(String, String)> = Vec::new();
        for (scope, common_dir) in &seen.repositories {
            for worktree in linked_worktrees(common_dir) {
                let key = worktree.to_string_lossy().into_owned();
                if !seen.known.contains(&key) {
                    new.push((key, scope.clone()));
                }
            }
        }
        if new.is_empty() {
            continue;
        }
        let Ok(Some(mut index)) = read_json::<Index>(&path) else {
            continue;
        };
        for (folder, scope) in new {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                index.cwd_scopes.entry(folder)
            {
                entry.insert(scope);
                added += 1;
            }
        }
        if write_json(&path, &index).is_ok() {
            if let Some(witness) = index_witness(&path) {
                cache
                    .seen
                    .insert(source, SeenIndex::new(&index, witness, today));
            }
        }
    }
    added
}

/// A scope no pin has named for `KEEP_DAYS`: its rows have all left the
/// window, so it is neither refreshed nor mapped any more.
fn scope_retired(index: &Index, scope: &str, today: Day) -> bool {
    index
        .scope_last_pinned
        .get(scope)
        .is_some_and(|day| *day < today - KEEP_DAYS)
}

// -------------------------------------------------------------------------
// One run.
// -------------------------------------------------------------------------

pub(super) struct Run<'a> {
    pub(super) state_dir: PathBuf,
    pub(super) now: OffsetDateTime,
    pub(super) deadline: Instant,
    pub(super) resolver: &'a mut dyn ScopeResolver,
    /// Full-read bytes left today (shared by the sources).
    pub(super) repair_left: u64,
    pub(super) start_verdicts: crate::snapshots::start_verdict_store::Verdicts,
}

#[derive(Debug, Default, Clone)]
#[cfg_attr(test, derive(Serialize, Deserialize))]
pub(super) struct SourceStats {
    pub(super) bytes_new: u64,
    pub(super) bytes_repair: u64,
    /// Head reads: scoping new files and fixing a new checkpoint's identity.
    pub(super) bytes_head: u64,
    /// Bytes read by reads that then failed (their lines did not count).
    pub(super) bytes_failed: u64,
    /// Transcripts the walk found (one per copy key and copy).
    pub(super) files_checked: u64,
    /// Files waiting for a full read at the end of the run, and their bytes.
    pub(super) full_read_waiting_files: u64,
    pub(super) full_read_backlog_bytes: u64,
    pub(super) files_read: u64,
    pub(super) files_failed: u64,
    /// Files quarantined in this run (failed twice in a row).
    pub(super) quarantined: u64,
    pub(super) new_files: u64,
    pub(super) dormant_found: u64,
    /// Files an install or agent reset started at their current end (a
    /// subset of `dormant_found`): their earlier bytes are never read.
    pub(super) install_forward_only: u64,
    /// Fresh openings left unread while their snapshot verdict is pending.
    pub(super) verdict_deferred: u64,
    pub(super) moved: u64,
    /// A larger copy holding the same read bytes took over a pin.
    pub(super) switched: u64,
    pub(super) archived: u64,
    /// Codex archives (`.jsonl.zst`) found this run with no plain copy and no
    /// pin: never read while plain, or read and then forgotten after
    /// `FORGET_MISSING_DAYS`. Composition never decodes an archive
    /// (`CompressedCompositionUnsupported`).
    pub(super) archived_unpinned: u64,
    pub(super) duplicates: u64,
    pub(super) unscoped: u64,
    pub(super) scan_errors: u64,
    pub(super) repair_waiting: u64,
    pub(super) repair_waiting_bytes: u64,
    pub(super) repair_restarted: u64,
    /// Checkpoints made cold this run (see `Checkpoint::compact`).
    pub(super) cold_compacted: u64,
    /// Cold files rewritten: restarted at their end, not read again.
    pub(super) cold_restarted: u64,
    pub(super) bad_state: u64,
    pub(super) agent_resets: u64,
    /// Scopes set aside because their state cannot be used.
    pub(super) scopes_quarantined: u64,
    /// Files in scopes set aside because their state cannot be used.
    pub(super) files_quarantined: u64,
    /// Checkpoints naming ids this build does not know: restarted at their
    /// end, their counted history kept.
    pub(super) checkpoint_restarts: u64,
    pub(super) pins_rebuilt: u64,
    pub(super) scopes_committed: u64,
    pub(super) scopes_failed: u64,
    pub(super) uploaded: u64,
    pub(super) upload_unchanged: u64,
    pub(super) upload_failed: u64,
    pub(super) upload_dropped_non_v2: u64,
    pub(super) upload_dropped_unsafe: u64,
    /// Request bytes of the uploads sent, and the daily rows the server
    /// reported written for them.
    pub(super) upload_payload_bytes: u64,
    pub(super) upload_rows_written: u64,
    /// File-name lookups not made because the scan's folder cache was full
    /// (those files keep their basename).
    pub(super) name_lookups_skipped: u64,
    pub(super) lines: LineStats,
    pub(super) cut: bool,
    pub(super) cpu_micros: u64,
    pub(super) wall_micros: u64,
    pub(super) peak_accounted_bytes: usize,
    pub(super) state_bytes: u64,
}

/// A transcript found on disk.
#[derive(Debug, Clone)]
struct Found {
    path: PathBuf,
    identity: (u64, u64),
    size: u64,
    stamp: Stamp,
    /// Birth time, else modification time: orders a scope's reads.
    birth: i64,
    /// Birth time where the file system records one: decides whether a
    /// file with no pin is new.
    born: Option<i64>,
}

impl Found {
    fn new(path: PathBuf, metadata: &Metadata) -> Self {
        Self {
            path,
            identity: file_identity(metadata),
            size: metadata.len(),
            stamp: stamp(metadata),
            birth: birth_secs(metadata),
            born: born_secs(metadata),
        }
    }
}

/// How a file is read this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// From its checkpoint (or its pin's start).
    Forward,
    /// From its start, replacing its earlier contribution.
    Full,
    /// From its current end, keeping its earlier contribution.
    RestartAtEnd,
}

struct Work {
    key: String,
    found: Found,
    mode: Mode,
    /// A full read's granted end: bytes appended after the grant wait for
    /// the next run, so the repair budget is never exceeded.
    reserved: Option<u64>,
}

impl Work {
    fn new(key: String, found: Found, mode: Mode) -> Self {
        Self {
            key,
            found,
            mode,
            reserved: None,
        }
    }
}

pub(super) fn index_path(dir: &Path, source: Source) -> PathBuf {
    dir.join(format!("index-{}.json", source.label()))
}

fn copy_key_text(path: &Path) -> String {
    super::super::discovery::transcript_copy_key(path)
        .iter()
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Stream directory entries. Unchanged files update their pin in place;
/// only files needing work retain a path/metadata row after the visit.
fn walk(
    source: Source,
    roots: &[PathBuf],
    index: &mut Index,
    today: Day,
    stats: &mut SourceStats,
) -> (
    BTreeMap<String, Vec<Found>>,
    BTreeSet<String>,
    BTreeSet<u64>,
) {
    fn visit(dir: &Path, callback: &mut impl FnMut(PathBuf, Metadata, bool)) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                visit(&path, callback);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(".jsonl") {
                callback(path, metadata, false);
            } else if name.ends_with(".jsonl.zst") {
                callback(
                    path.with_file_name(name.trim_end_matches(".zst")),
                    metadata,
                    true,
                );
            }
        }
    }
    let mut found: BTreeMap<String, Vec<Found>> = BTreeMap::new();
    let mut archived = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut callback = |path: PathBuf, metadata: Metadata, compressed: bool| {
        if source == Source::Claude
            && crate::snapshots::claude_transcript_excluded_from_snapshots(&path)
        {
            return;
        }
        let key = copy_key_text(&path);
        if compressed {
            archived.insert(key);
            return;
        }
        let hash = super::aggregate::stable_hash(key.as_bytes());
        if !seen.insert(hash) {
            stats.duplicates += 1;
        }
        if let Some(pin) = index.files.get_mut(&key) {
            pin.last_seen = today;
            let identity = file_identity(&metadata);
            if (pin.dev, pin.ino) == identity && pin.path != path.to_string_lossy() {
                pin.path = path.to_string_lossy().into_owned();
                stats.moved += 1;
            }
            if (pin.dev, pin.ino) == identity
                && metadata.len() == pin.size
                && stamp(&metadata) == pin.mtime
                && !pin.waiting
                && !pin.restart_at_end
                && (pin.start >= metadata.len() || pin.unscoped || pin.done || pin.quarantined)
            {
                return;
            }
            // The pinned copy wins unless this candidate is larger and
            // still contains the committed prefix (checked below).
            if (pin.dev, pin.ino) != identity
                && pin.path != path.to_string_lossy()
                && Path::new(&pin.path).is_file()
            {
                let larger = metadata.len() > pin.size
                    && File::open(&path)
                        .is_ok_and(|file| prefix_matches(&file, pin.start, pin.head, pin.tail));
                if !larger {
                    return;
                }
                stats.switched += 1;
            }
        }
        found
            .entry(key)
            .or_default()
            .push(Found::new(path, &metadata));
    };
    for root in roots {
        visit(root, &mut callback);
    }
    (found, archived, seen)
}

/// Recover manifest-last commits after a crash with an otherwise valid index.
/// A missing index is never reconstructed: it resets the whole agent instead.
fn reconcile_pins(
    run: &Run,
    source: Source,
    index: &mut Index,
    today: Day,
    stats: &mut SourceStats,
) -> u64 {
    let state_dir = &run.state_dir;
    let mut rebuilt = 0;
    for scope_id in disk_scopes(state_dir, source) {
        let path = scope_path(state_dir, source, &scope_id);
        #[derive(Deserialize)]
        struct Generation {
            generation: u64,
        }
        let saved = read_json::<Generation>(&path);
        if matches!(&saved, Ok(None))
            && !index.scope_generations.contains_key(&scope_id)
            && !path.with_extension("committed").exists()
        {
            // Shard writes can precede the first manifest. The intact
            // installation pins still authorize their unfinished first read.
            continue;
        }
        if let Ok(Some(saved)) = saved {
            if index.scope_generations.get(&scope_id) == Some(&saved.generation) {
                continue;
            }
        } else {
            // A pending reset deliberately has no active manifest.
            if index.quarantined_scopes.contains_key(&scope_id) {
                continue;
            }
            stats.bad_state += 1;
            quarantine_scope(run, source, &scope_id, &path, index, today, stats);
            continue;
        }
        let loaded = load_scope(&path, source, &scope_id).ok().flatten();
        let Some(mut scope) = loaded else {
            stats.bad_state += 1;
            quarantine_scope(run, source, &scope_id, &path, index, today, stats);
            continue;
        };
        if scope.load_all_shards(&path).is_err() {
            stats.bad_state += 1;
            quarantine_scope(run, source, &scope_id, &path, index, today, stats);
            continue;
        }
        for (key, checkpoint) in scope.files {
            let Some(pin) = index.files.get_mut(&key) else {
                // Committed by a run that stopped before saving its pins:
                // reading goes on from the checkpoint, in this scope.
                index.files.insert(
                    key,
                    Pin {
                        path: checkpoint.path.clone(),
                        dev: checkpoint.dev,
                        ino: checkpoint.ino,
                        scope: Some(scope_id.clone()),
                        start: checkpoint.offset,
                        size: checkpoint.size,
                        mtime: checkpoint.mtime,
                        waiting: false,
                        done: checkpoint.status == Status::Done,
                        last_seen: checkpoint.last_seen,
                        first_seen: checkpoint.created,
                        unscoped: false,
                        failures: 0,
                        quarantined: false,
                        restart_at_end: false,
                        head: checkpoint.head,
                        tail: checkpoint.tail,
                    },
                );
                rebuilt += 1;
                continue;
            };
            pin.scope = Some(scope_id.clone());
            // Even an equal offset can be an old checkpoint retained
            // after a failed reset. Only a successful reset read and
            // its final index write clear this conservative decision.
            if pin.restart_at_end {
                continue;
            }
            pin.dev = checkpoint.dev;
            pin.ino = checkpoint.ino;
            pin.path = checkpoint.path.clone();
            pin.start = checkpoint.offset;
            pin.size = checkpoint.size;
            pin.mtime = checkpoint.mtime;
            pin.head = checkpoint.head;
            pin.tail = checkpoint.tail;
            pin.waiting = false;
            rebuilt += 1;
        }
        if !scope.info.workspace_path.is_empty() {
            index
                .cwd_scopes
                .insert(scope.info.workspace_path.clone(), scope_id.clone());
        }
        index.scope_info.insert(scope_id.clone(), scope.info);
        index.scope_last_pinned.insert(scope_id.clone(), today);
        index.scope_generations.insert(scope_id, scope.generation);
    }
    rebuilt
}

fn disk_scopes(state_dir: &Path, source: Source) -> BTreeSet<String> {
    let prefix = format!("{}-", source.label());
    fs::read_dir(state_dir.join("scopes"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()?
                .strip_prefix(&prefix)?
                .split('.')
                .next()
                .map(str::to_string)
        })
        .collect()
}

/// Every index, shard, name cache and upload buffer belongs to this source
/// invocation. Allocator relief runs once after the worker process has exited.
pub(super) fn run_source(
    run: &mut Run,
    source: Source,
    roots: &[PathBuf],
    target: Option<UploadTarget>,
) -> SourceStats {
    let started = Instant::now();
    let cpu_started = thread_cpu_micros();
    let mut stats = run_source_inner(run, source, roots, target);
    finish(&mut stats, started, cpu_started);
    stats
}

pub(super) fn release_memory() {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
        }
        // SAFETY: a null zone requests relief from all system malloc zones.
        unsafe {
            malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: asks the process allocator to release free pages.
        unsafe {
            libc::malloc_trim(0);
        }
    }
}

fn run_source_inner(
    run: &mut Run,
    source: Source,
    roots: &[PathBuf],
    mut target: Option<UploadTarget>,
) -> SourceStats {
    let started = Instant::now();
    let cpu_started = thread_cpu_micros();
    let mut stats = SourceStats::default();
    let today = day_of(run.now.date());
    let window = Window::ending(today);
    let now_secs = run.now.unix_timestamp();
    let path = index_path(&run.state_dir, source);
    let install_file = install_path(&run.state_dir, source.label());
    let saved = read_json::<Index>(&path);
    let scopes_on_disk = disk_scopes(&run.state_dir, source);
    let prior_install = install_file.exists();
    let valid = matches!(&saved, Ok(Some(index)) if index.schema == STATE_SCHEMA);
    let first_run = matches!(&saved, Ok(None)) && !prior_install && scopes_on_disk.is_empty();
    let agent_reset = !valid && !first_run;
    let mut index = match saved {
        Ok(Some(index)) if valid => index,
        _ => Index::new(now_secs),
    };
    if agent_reset {
        stats.bad_state += 1;
        stats.agent_resets += 1;
        // Persist the reset before any state moves. A crash cannot turn a
        // missing index into an installation with permission to read history.
        if write_json(
            &install_file,
            &InstallRecord {
                schema: STATE_SCHEMA,
                cutoff: now_secs,
            },
        )
        .is_err()
        {
            stats.scopes_failed += 1;
            return stats;
        }
    } else if valid {
        stats.pins_rebuilt = reconcile_pins(run, source, &mut index, today, &mut stats);
    }
    // The last saved discovery boundary, held at a deferred opening's birth
    // until it can be read. Files born at or after it are new bytes unless
    // pins or crash-recovered checkpoints already account for them.
    let previous_scan = index.last_scan_started.filter(|_| valid);
    index.last_scan_started = Some(now_secs);

    // Discovery: pick one copy per key and decide what needs reading.
    let (found, archived, seen) = walk(source, roots, &mut index, today, &mut stats);
    stats.files_checked = seen.len() as u64 + stats.duplicates;
    let mut work: Vec<Work> = Vec::new();
    let mut present: BTreeMap<String, Found> = BTreeMap::new();
    for (key, mut copies) in found {
        let pin = index.files.get(&key);
        let pinned = pin.and_then(|pin| {
            copies
                .iter()
                .position(|copy| copy.identity == (pin.dev, pin.ino))
                .or_else(|| {
                    copies
                        .iter()
                        .position(|copy| copy.path == Path::new(&pin.path))
                })
        });
        let chosen = match pinned {
            Some(index) => {
                let index = match pin.filter(|pin| pin.scope.is_some()) {
                    Some(pin) => larger_copy(&copies, index, pin).map_or(index, |larger| {
                        stats.switched += 1;
                        larger
                    }),
                    None => index,
                };
                copies.swap_remove(index)
            }
            None => {
                // The newest copy (ties: path order), as the v1 reader does.
                copies.sort_by(|a, b| b.stamp.cmp(&a.stamp).then_with(|| a.path.cmp(&b.path)));
                copies.remove(0)
            }
        };
        // Duplicate entries were counted while streaming the walk.
        present.insert(key, chosen);
    }
    let mut pending_openings = false;
    for (key, file) in &present {
        let needs = match index.files.get_mut(key) {
            None => {
                // Born after the last saved scan: new bytes, read from zero.
                // An unknown birth time is never taken as new. An install or
                // reset has no saved scan, so it starts every file it finds at
                // its current end, however recently it was written.
                let new = file
                    .born
                    .zip(previous_scan)
                    .is_some_and(|(born, last)| born >= last);
                if new && !agent_reset {
                    let pending = opening_verdict_pending(run, source, file, &mut stats);
                    if pending != Some(false) {
                        // No pin or checkpoint is created. Preserve new-byte
                        // eligibility for the next daily run; it reads
                        // Forward from zero without a repair grant.
                        index.last_scan_started = Some(
                            index
                                .last_scan_started
                                .unwrap_or(now_secs)
                                .min(file.born.unwrap()),
                        );
                        pending_openings = true;
                        if pending == Some(true) {
                            stats.verdict_deferred += 1;
                            // A previously unseen workspace can disappear
                            // before tomorrow. Cache its scope while it still
                            // exists, without creating a file pin/checkpoint.
                            match head_cwds(&file.path, run.deadline) {
                                Ok((cwds, bytes)) => {
                                    stats.bytes_head += bytes;
                                    if matches!(
                                        find_scope(run.resolver, &mut index, &cwds, today),
                                        Scoping::Failed
                                    ) {
                                        stats.scan_errors += 1;
                                    }
                                }
                                Err(error) => {
                                    if error.kind() == std::io::ErrorKind::TimedOut {
                                        stats.cut = true;
                                    } else {
                                        stats.scan_errors += 1;
                                    }
                                }
                            }
                        }
                        continue;
                    }
                }
                let start = if new { 0 } else { file.size };
                if !new {
                    stats.dormant_found += 1;
                    if first_run || agent_reset {
                        stats.install_forward_only += 1;
                    } else {
                        stats.checkpoint_restarts += 1;
                    }
                }
                index.files.insert(
                    key.clone(),
                    Pin {
                        path: file.path.to_string_lossy().into_owned(),
                        dev: file.identity.0,
                        ino: file.identity.1,
                        scope: None,
                        start,
                        size: file.size,
                        mtime: file.stamp,
                        waiting: false,
                        done: false,
                        last_seen: today,
                        // First seen by the install run when it found it.
                        first_seen: now_secs,
                        unscoped: false,
                        failures: 0,
                        quarantined: false,
                        restart_at_end: !first_run && !new,
                        head: Default::default(),
                        tail: Default::default(),
                    },
                );
                start < file.size || agent_reset
            }
            Some(pin) => {
                pin.last_seen = today;
                if pin.done {
                    continue;
                }
                let same = file.identity == (pin.dev, pin.ino);
                if !same && pin.quarantined {
                    // Another file took the quarantined one's place.
                    pin.quarantined = false;
                    pin.failures = 0;
                }
                if pin.quarantined {
                    continue;
                }
                let path_text = file.path.to_string_lossy().into_owned();
                if same && pin.path != path_text {
                    stats.moved += 1;
                    pin.path = path_text.clone();
                }
                if !same && pin.scope.is_none() {
                    // Never read: adopt the new file at the same start.
                    pin.dev = file.identity.0;
                    pin.ino = file.identity.1;
                    pin.path = path_text;
                    pin.start = pin.start.min(file.size);
                }
                // Unread bytes of a pinned file are read; an unpinned file
                // whose scoping failed is retried (one that named no folder
                // waits until it changes).
                pin.waiting
                    || pin.restart_at_end
                    || !same
                    || file.size != pin.size
                    || file.stamp != pin.mtime
                    || (pin.start < file.size && (pin.scope.is_some() || !pin.unscoped))
            }
        };
        if needs {
            let mode = if index.files[key].restart_at_end {
                Mode::RestartAtEnd
            } else {
                Mode::Forward
            };
            work.push(Work::new(key.clone(), file.clone(), mode));
        }
    }
    if first_run {
        // Saved before any scope can commit. Only its presence is used: a
        // crash before this run saves its pins becomes an agent reset, never
        // a second installation.
        let record = InstallRecord {
            schema: STATE_SCHEMA,
            cutoff: now_secs,
        };
        if write_packed(&install_file, &record).is_err() {
            // Nothing is read without it; the first run starts again on a
            // later day.
            stats.scan_errors += 1;
            finish(&mut stats, started, cpu_started);
            return stats;
        }
    }
    for key in &archived {
        if seen.contains(&super::aggregate::stable_hash(key.as_bytes())) {
            continue;
        }
        if let Some(pin) = index.files.get_mut(key) {
            if !pin.done {
                // Codex compressed the rollout: it is finished.
                pin.done = true;
                stats.archived += 1;
            }
        } else {
            stats.archived_unpinned += 1;
        }
    }
    index
        .files
        .retain(|_, pin| pin.last_seen >= today - FORGET_MISSING_DAYS);

    // Scope every file that will be read.
    let mut scoped = Vec::with_capacity(work.len());
    for item in work {
        let Some(pin) = index.files.get(&item.key) else {
            continue;
        };
        if pin.scope.is_some() {
            scoped.push(item);
            continue;
        }
        let cwds = match head_cwds(&item.found.path, run.deadline) {
            Ok((cwds, bytes)) => {
                stats.bytes_head += bytes;
                cwds
            }
            Err(_) => {
                stats.scan_errors += 1;
                continue;
            }
        };
        let scoping = find_scope(run.resolver, &mut index, &cwds, today);
        let Some(pin) = index.files.get_mut(&item.key) else {
            continue;
        };
        match scoping {
            Scoping::Found(scope) => {
                pin.scope = Some(scope);
                pin.unscoped = false;
                scoped.push(item);
            }
            Scoping::Unscoped => {
                stats.unscoped += 1;
                pin.unscoped = true;
                pin.size = item.found.size;
                pin.mtime = item.found.stamp;
            }
            // Retried the next day.
            Scoping::Failed => stats.scan_errors += 1,
        }
    }
    let mut work = scoped;

    if agent_reset {
        let mut scopes = scopes_on_disk;
        scopes.extend(index.files.values().filter_map(|pin| pin.scope.clone()));
        for scope in scopes {
            let path = scope_path(&run.state_dir, source, &scope);
            quarantine_scope(run, source, &scope, &path, &mut index, today, &mut stats);
        }
    }
    // Pending resets include unchanged files: every current file is pinned
    // at its current end on the first later run, before any new tail is read.
    let mut pending = index.quarantined_scopes.clone();
    let marker_dir = run.state_dir.join("quarantined-scopes");
    for entry in fs::read_dir(marker_dir).into_iter().flatten().flatten() {
        let name = entry.file_name();
        if let Some(id) = name
            .to_str()
            .and_then(|n| n.strip_prefix(&format!("{}-", source.label())))
            .and_then(|n| n.strip_suffix(".json"))
        {
            match read_json::<Day>(&entry.path()) {
                Ok(Some(day)) => {
                    pending.insert(id.to_string(), day);
                }
                _ => {
                    stats.bad_state += 1;
                    quarantine_scope(
                        run,
                        source,
                        id,
                        &scope_path(&run.state_dir, source, id),
                        &mut index,
                        today,
                        &mut stats,
                    );
                    pending.insert(id.to_string(), today);
                }
            }
        }
    }
    let mut reset_prepared = false;
    let mut resetting = Vec::new();
    for (scope_id, day) in pending {
        let path = scope_path(&run.state_dir, source, &scope_id);
        #[derive(Deserialize)]
        struct ResetDate {
            history_reset_at: Option<Day>,
        }
        let applied = read_json::<ResetDate>(&path)
            .ok()
            .flatten()
            .is_some_and(|s| s.history_reset_at == Some(day));
        if applied {
            index.quarantined_scopes.remove(&scope_id);
            continue;
        }
        if index
            .quarantined_scopes
            .insert(scope_id.clone(), day)
            .is_none()
        {
            stats.scopes_quarantined += 1;
            for pin in index
                .files
                .values_mut()
                .filter(|pin| pin.scope.as_deref() == Some(scope_id.as_str()))
            {
                pin.restart_at_end = true;
                pin.waiting = false;
            }
            stats.files_quarantined += index
                .files
                .values()
                .filter(|pin| pin.scope.as_deref() == Some(&scope_id))
                .count() as u64;
        }
        if day >= today {
            work.retain(|item| {
                index.files.get(&item.key).and_then(|p| p.scope.as_deref()) != Some(&scope_id)
            });
            continue;
        }
        work.retain(|item| {
            index.files.get(&item.key).and_then(|p| p.scope.as_deref()) != Some(&scope_id)
        });
        reset_prepared = true;
        resetting.push(scope_id.clone());
        for (key, pin) in &mut index.files {
            if pin.scope.as_deref() != Some(&scope_id) {
                continue;
            }
            pin.restart_at_end = true;
            pin.waiting = false;
            pin.quarantined = false;
            pin.failures = 0;
            if let Some(file) = present.get(key) {
                work.push(Work::new(key.clone(), file.clone(), Mode::RestartAtEnd));
            } else if let Ok(metadata) = fs::metadata(&pin.path) {
                work.push(Work::new(
                    key.clone(),
                    Found::new(PathBuf::from(&pin.path), &metadata),
                    Mode::RestartAtEnd,
                ));
            }
        }
    }

    if reset_prepared {
        // Before any reset manifest can commit, every unfinished file's
        // restart decision must survive a crash or a partial scope commit.
        match write_json(&path, &index) {
            Ok(bytes) => stats.state_bytes += bytes,
            Err(_) => {
                stats.scopes_failed += 1;
                return stats;
            }
        }
    }

    // Full reads waiting for budget, newest first.
    let mut waiting: Vec<&mut Work> = work
        .iter_mut()
        .filter(|item| index.files.get(&item.key).is_some_and(|pin| pin.waiting))
        .collect();
    waiting.sort_by_key(|item| std::cmp::Reverse(item.found.stamp));
    for item in waiting {
        item.mode = grant(run, &mut stats, item.found.size);
        if item.mode == Mode::Full {
            item.reserved = Some(item.found.size);
        }
    }
    work.retain(|item| {
        let waiting = index.files.get(&item.key).is_some_and(|pin| pin.waiting);
        !waiting || item.mode != Mode::Forward
    });

    let mut by_scope: BTreeMap<String, Vec<Work>> = BTreeMap::new();
    for item in work {
        let scope = index
            .files
            .get(&item.key)
            .and_then(|pin| pin.scope.clone())
            .unwrap_or_default();
        by_scope.entry(scope).or_default().push(item);
    }
    // A reset scope whose files are all gone still commits (empty), so its
    // reset is applied and never stays pending.
    for scope in resetting {
        by_scope.entry(scope).or_default();
    }
    let mut order: Vec<(Stamp, String)> = by_scope
        .iter()
        .map(|(scope, items)| {
            let newest = items
                .iter()
                .map(|item| item.found.stamp)
                .max()
                .unwrap_or_default();
            (newest, scope.clone())
        })
        .collect();
    order.sort_by(|a, b| b.cmp(a));

    // One folder cache for the whole scan: file names resolve when their
    // line is read.
    let mut names = GitRootCache::v2();
    let mut uploaded = BTreeSet::new();
    for (_, scope_id) in order {
        if stats.cut {
            break;
        }
        let items = by_scope.remove(&scope_id).unwrap_or_default();
        let Some(scope) = process_scope(
            run, source, &scope_id, items, &mut index, window, &mut names, &mut stats,
        ) else {
            continue;
        };
        if let Some(target) = target.as_mut() {
            let result = upload_scope(&run.state_dir, source, &scope, target, run.now, window);
            count_upload(source, result, &mut stats);
            uploaded.insert(scope_id);
        }
        #[cfg(test)]
        if tests::crash_now(stats.scopes_committed) {
            finish(&mut stats, started, cpu_started);
            return stats;
        }
    }
    stats.name_lookups_skipped = names.skipped();
    tidy_index(&mut index, today, pending_openings);
    for (key, pin) in index
        .files
        .iter()
        .filter(|(_, pin)| pin.waiting && !pin.done && !pin.quarantined)
    {
        // Its size now (a waiting file is always found by the walk); the
        // pin keeps the size of its last commit.
        stats.full_read_waiting_files += 1;
        stats.full_read_backlog_bytes += present.get(key).map_or(pin.size, |file| file.size);
    }

    if let Some(target) = target.as_mut() {
        upload_other_scopes(
            run, source, &mut index, &uploaded, target, window, &mut stats,
        );
    }
    if let Ok(bytes) = write_json(&path, &index) {
        stats.state_bytes += bytes;
        // Keep the durable installation witness: a missing index is a reset.
    }

    finish(&mut stats, started, cpu_started);
    stats
}

/// A copy of the pinned transcript that is larger than the pinned one and
/// still holds the bytes read so far (the session went on in another
/// folder): the largest such copy takes over.
fn larger_copy(copies: &[Found], pinned: usize, pin: &Pin) -> Option<usize> {
    let pinned_size = copies[pinned].size;
    let mut larger: Vec<usize> = (0..copies.len())
        .filter(|index| *index != pinned && copies[*index].size > pinned_size)
        .collect();
    larger.sort_by_key(|index| std::cmp::Reverse(copies[*index].size));
    larger.into_iter().find(|index| {
        File::open(&copies[*index].path)
            .is_ok_and(|file| prefix_matches(&file, pin.start, pin.head, pin.tail))
    })
}

enum Scoping {
    Found(String),
    /// No folder in the first lines exists or is known.
    Unscoped,
    /// The folder could not be resolved now.
    Failed,
}

/// The scope of a transcript from the folders its first lines name: the
/// first one that exists (resolved once per folder), or a folder that is
/// gone but known (a recorded worktree, or below a repository folder).
fn find_scope(
    resolver: &mut dyn ScopeResolver,
    index: &mut Index,
    cwds: &[String],
    today: Day,
) -> Scoping {
    for cwd in cwds {
        if Path::new(cwd).is_dir() {
            if let Some(scope) = index.cwd_scopes.get(cwd) {
                return Scoping::Found(scope.clone());
            }
            let Some((scope, info)) = resolver.resolve(Path::new(cwd)) else {
                return Scoping::Failed;
            };
            index.cwd_scopes.insert(cwd.clone(), scope.clone());
            // First sight wins: the saved key never changes.
            index.scope_info.entry(scope.clone()).or_insert(info);
            index.scope_last_pinned.insert(scope.clone(), today);
            return Scoping::Found(scope);
        }
        if let Some(scope) = known_scope(index, cwd) {
            return Scoping::Found(scope);
        }
    }
    Scoping::Unscoped
}

/// The scope of a folder that no longer exists: an exact entry of the folder
/// map, or the nearest parent entry that is a repository scope.
fn known_scope(index: &Index, cwd: &str) -> Option<String> {
    let path = PathBuf::from(cwd);
    let resolved = resolved_missing(&path);
    for candidate in std::iter::once(path).chain(resolved) {
        for (depth, folder) in candidate.ancestors().enumerate() {
            let Some(scope) = folder.to_str().and_then(|text| index.cwd_scopes.get(text)) else {
                continue;
            };
            let repository = index
                .scope_info
                .get(scope)
                .is_some_and(|info| info.identity.repository_hash.is_some());
            if depth == 0 || repository {
                return Some(scope.clone());
            }
        }
    }
    None
}

/// End of a run: note the scopes pins still name, and drop folder entries
/// nothing needs any more (their scope has no pins, or the folder is gone
/// and no file waits to be scoped).
fn tidy_index(index: &mut Index, today: Day, pending_openings: bool) {
    let Index {
        files,
        cwd_scopes,
        scope_last_pinned,
        ..
    } = index;
    let mut pinned: BTreeSet<&str> = BTreeSet::new();
    let mut waiting_for_scope = false;
    for pin in files.values() {
        match pin.scope.as_deref() {
            Some(scope) => {
                pinned.insert(scope);
            }
            None => {
                waiting_for_scope |=
                    !pin.unscoped && !pin.done && !pin.quarantined && pin.start < pin.size;
            }
        }
    }
    for scope in &pinned {
        scope_last_pinned.insert((*scope).to_string(), today);
    }
    // Deferred openings have no pins yet. Retain cached worktree mappings
    // until they can be scoped, including worktrees deleted before reading.
    if pending_openings {
        return;
    }
    cwd_scopes.retain(|folder, scope| {
        pinned.contains(scope.as_str()) && (waiting_for_scope || Path::new(folder).is_dir())
    });
}

fn finish(stats: &mut SourceStats, started: Instant, cpu_started: Option<u64>) {
    stats.wall_micros = started.elapsed().as_micros() as u64;
    stats.cpu_micros = match (cpu_started, thread_cpu_micros()) {
        (Some(start), Some(end)) => end.saturating_sub(start),
        _ => 0,
    };
}

/// Grant a full read from the budget: read it now, wait, or (larger than a
/// whole day's budget) restart it at its end.
fn grant(run: &mut Run, stats: &mut SourceStats, size: u64) -> Mode {
    if size > REPAIR_BYTES_PER_DAY {
        stats.repair_restarted += 1;
        return Mode::RestartAtEnd;
    }
    if size <= run.repair_left {
        run.repair_left -= size;
        return Mode::Full;
    }
    stats.repair_waiting += 1;
    stats.repair_waiting_bytes += size;
    Mode::Forward
}

/// Wait only before an opening is first classified. A missing verdict may
/// delay it for less than six hours from birth, never from its last deferral.
/// Once counted, later verdict transitions do not reconcile contributions:
/// the reader moves forward and never rereads history for a verdict change.
fn opening_verdict_pending(
    run: &Run,
    source: Source,
    file: &Found,
    stats: &mut SourceStats,
) -> Option<bool> {
    let now = run.now.unix_timestamp();
    if !file
        .born
        .is_some_and(|born| born <= now && now - born < 6 * 3600)
    {
        return Some(false);
    }
    let (state, bytes) = match new_parse_state_before(source, &file.path, run.deadline) {
        Ok(head) => head,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::TimedOut {
                stats.cut = true;
            } else {
                stats.scan_errors += 1;
            }
            return None;
        }
    };
    stats.bytes_head += bytes;
    Some(
        run.start_verdicts
            .lookup(source.label(), &state.session, now)
            .is_none(),
    )
}

/// Failed reads in a row that quarantine a file.
const QUARANTINE_AFTER: u8 = 2;

#[allow(clippy::too_many_arguments)]
fn process_scope(
    run: &mut Run,
    source: Source,
    scope_id: &str,
    mut items: Vec<Work>,
    index: &mut Index,
    window: Window,
    names: &mut GitRootCache,
    stats: &mut SourceStats,
) -> Option<Scope> {
    let today = window.today;
    let path = scope_path(&run.state_dir, source, scope_id);
    let info = index
        .scope_info
        .get(scope_id)
        .cloned()
        .unwrap_or(ScopeInfo {
            workspace_hash: scope_id.to_string(),
            workspace_path: String::new(),
            identity: Default::default(),
            common_dir: None,
        });
    let reset = index.quarantined_scopes.get(scope_id).copied();
    if reset.is_some_and(|day| day >= today) {
        return None;
    }
    let mut scope = if let Some(day) = reset {
        // Finish moving any files left by a crash after the reset marker.
        if set_aside(
            &run.state_dir,
            &format!("{}-{day}", scope_file_stem(source, scope_id)),
            &scope_files(&path),
        )
        .is_err()
        {
            stats.scopes_failed += 1;
            return None;
        }
        let mut scope = Scope::new(scope_id, info);
        scope.history_reset_at = Some(day);
        scope
    } else {
        let known = index.scope_generations.contains_key(scope_id)
            || path.with_extension("committed").exists();
        match load_scope(&path, source, scope_id) {
            Ok(Some(scope)) => scope,
            Ok(None) if !known => {
                forget_upload(&run.state_dir, source, scope_id);
                Scope::new(scope_id, info)
            }
            _ => {
                stats.bad_state += 1;
                quarantine_scope(run, source, scope_id, &path, index, today, stats);
                return None;
            }
        }
    };
    let generation = scope.generation.max(highest_generation(&path)) + 1;
    let legacy = std::mem::take(&mut scope.files);
    let mut groups: BTreeMap<u16, Vec<Work>> = BTreeMap::new();
    for item in items.drain(..) {
        groups.entry(shard_id(&item.key)).or_default().push(item);
    }
    // Migration reads state only, never transcript history. The switch has
    // not shipped, but preserve existing local checkpoints when upgrading.
    let mut legacy_groups: BTreeMap<u16, BTreeMap<String, Checkpoint>> = BTreeMap::new();
    for (key, checkpoint) in legacy {
        scope.file_sessions.extend(checkpoint_members(&checkpoint));
        let id = shard_id(&key);
        groups.entry(id).or_default();
        legacy_groups.entry(id).or_default().insert(key, checkpoint);
    }
    // The shards read now are checked before anything is read. An untouched
    // shard keeps its reference; it is checked when it is first loaded.
    if !scope
        .verify_shards(&path, groups.keys().copied().collect::<Vec<_>>())
        .is_empty()
    {
        stats.bad_state += 1;
        quarantine_scope(run, source, scope_id, &path, index, today, stats);
        return None;
    }
    let mut removed = Vec::new();
    let mut added = Vec::new();
    let mut updates = Vec::new();
    let mut groups = groups.into_iter();
    for (id, mut items) in groups.by_ref() {
        if stats.cut || Instant::now() >= run.deadline {
            stats.cut = true;
            break;
        }
        let legacy = legacy_groups.remove(&id);
        let migrating = legacy.is_some();
        scope.files = legacy.unwrap_or_default();
        if scope.load_shard(&path, id).is_err() {
            stats.bad_state += 1;
            quarantine_scope(run, source, scope_id, &path, index, today, stats);
            return None;
        }
        if items.is_empty() && !migrating {
            // Nothing to read or move: the shard keeps its reference.
            scope.files.clear();
            continue;
        }
        let held = scope.accounted_bytes();
        stats.peak_accounted_bytes = stats.peak_accounted_bytes.max(held);
        // Oldest transcript first (a stable order).
        items.sort_by(|a, b| {
            let created = |item: &Work| {
                scope
                    .files
                    .get(&item.key)
                    .map_or(item.found.birth, |checkpoint| checkpoint.created)
            };
            created(a)
                .cmp(&created(b))
                .then_with(|| a.found.path.cmp(&b.found.path))
        });
        let mut read_files: Vec<(String, Checkpoint)> = Vec::new();
        for item in items {
            if Instant::now() >= run.deadline {
                stats.cut = true;
                break;
            }
            let Some((start, first_seen)) = index
                .files
                .get(&item.key)
                .map(|pin| (pin.start, pin.first_seen))
            else {
                continue;
            };
            match read_file(
                run, source, &mut scope, &item, start, first_seen, window, generation, names, held,
                stats,
            ) {
                Ok(Some(Outcome::Read(checkpoint))) => {
                    if let Some(old) = scope.files.get(&item.key) {
                        removed.extend(checkpoint_members(old));
                    }
                    added.extend(checkpoint_members(&checkpoint));
                    read_files.push((item.key, *checkpoint));
                }
                Ok(Some(Outcome::Waiting)) => {
                    if let Some(pin) = index.files.get_mut(&item.key) {
                        pin.waiting = true;
                    }
                }
                Ok(None) => {}
                Err(ReadFailed) => {
                    // Nothing of this read counted; the rest of the scope
                    // commits. Retried the next day, then quarantined.
                    stats.files_failed += 1;
                    if let Some(pin) = index.files.get_mut(&item.key) {
                        pin.failures = pin.failures.saturating_add(1);
                        if pin.failures >= QUARANTINE_AFTER {
                            pin.quarantined = true;
                            stats.quarantined += 1;
                        }
                    }
                }
            }
        }

        let read_keys: Vec<String> = read_files.iter().map(|(key, _)| key.clone()).collect();
        scope.files.extend(read_files);
        // Files unchanged for `COLD_AFTER_SECS` and not read now go cold.
        let cold_before = run.now.unix_timestamp() - COLD_AFTER_SECS;
        let read_now: BTreeSet<&str> = read_keys.iter().map(String::as_str).collect();
        let mut compacted = 0;
        // Checkpoints follow their pins: a file forgotten by the pins is gone.
        // A pin with no scope (rebuilt pins that lost it) is pinned here again,
        // never dropped.
        let mut repin = Vec::new();
        scope.files.retain(|key, checkpoint| {
            let Some(pin) = index.files.get(key) else {
                return false;
            };
            match pin.scope.as_deref() {
                Some(scope) if scope == scope_id => {}
                None => repin.push(key.clone()),
                Some(_) => return false,
            }
            if pin.last_seen == today {
                checkpoint.last_seen = today;
            }
            if pin.done {
                checkpoint.status = Status::Done;
            }
            checkpoint.prune(window.floor);
            if checkpoint.mtime.0 < cold_before
                && !read_now.contains(key.as_str())
                && checkpoint.compact()
            {
                compacted += 1;
            }
            true
        });
        stats.cold_compacted += compacted;
        for key in repin {
            if let Some(pin) = index.files.get_mut(&key) {
                pin.scope = Some(scope_id.to_string());
            }
        }
        for key in read_keys {
            if let (Some(checkpoint), Some(old)) = (scope.files.get(&key), index.files.get(&key)) {
                let mut pin = old.clone();
                pin.start = checkpoint.offset;
                pin.size = checkpoint.size;
                pin.mtime = checkpoint.mtime;
                pin.dev = checkpoint.dev;
                pin.ino = checkpoint.ino;
                pin.path = checkpoint.path.clone();
                pin.head = checkpoint.head;
                pin.tail = checkpoint.tail;
                pin.waiting = false;
                pin.restart_at_end = false;
                pin.failures = 0;
                updates.push((key, pin));
            }
        }
        match scope.save_shard(&path, id, generation) {
            Ok(bytes) => stats.state_bytes += bytes,
            Err(_) => {
                stats.scopes_failed += 1;
                return None;
            }
        }
        scope.files.clear();
    }
    update_members(&mut scope.file_sessions, removed, added, window.floor);
    scope.agg.prune(window);
    // Every checkpoint commit advances generation, even when all new lines
    // were intentionally skipped. Generation names must never be overwritten.
    scope.generation = generation;

    #[cfg(test)]
    if tests::fail_scope_commit() {
        stats.scopes_failed += 1;
        return None;
    }
    match save_scope(&path, source, &scope) {
        Ok(bytes) => {
            stats.state_bytes += bytes;
            // Writing streams the scope to the file.
            stats.peak_accounted_bytes = stats.peak_accounted_bytes.max(scope.accounted_bytes());
        }
        Err(_) => {
            stats.scopes_failed += 1;
            return None;
        }
    }
    if !verify_commit(&path, source, &scope) {
        // Leave failed state for counted quarantine on the next run.
        stats.scopes_failed += 1;
        return None;
    }
    // A first committed scope remains distinguishable from uncommitted
    // shard writes if both its manifest and index are later lost. Write this
    // receipt once, after verification; partial first scopes stay pending.
    let committed = path.with_extension("committed");
    if !committed.is_file() {
        match write_json(&committed, &scope.generation) {
            Ok(bytes) => stats.state_bytes += bytes,
            Err(_) => {
                stats.scopes_failed += 1;
                return None;
            }
        }
    }
    stats.scopes_committed += 1;
    scope.clean_shards(&path);
    index.quarantined_scopes.remove(scope_id);
    for (key, pin) in updates {
        index.files.insert(key, pin);
    }
    index
        .scope_generations
        .insert(scope_id.to_string(), scope.generation);
    Some(scope)
}

/// Persist a reset decision before moving state; never read quarantined history.
fn quarantine_scope(
    run: &Run,
    source: Source,
    scope_id: &str,
    path: &Path,
    index: &mut Index,
    today: Day,
    stats: &mut SourceStats,
) {
    let label = format!(
        "{}-{}",
        scope_file_stem(source, scope_id),
        run.now.unix_timestamp()
    );
    // Persist the stop decision independently of the index, before moving
    // the last state artifacts out of the scope directory.
    let marked = write_json(
        &scope_quarantine_marker(&run.state_dir, source, scope_id),
        &today,
    );
    if marked.is_err() || set_aside(&run.state_dir, &label, &scope_files(path)).is_err() {
        stats.scopes_failed += 1;
    }
    for pin in index
        .files
        .values_mut()
        .filter(|pin| pin.scope.as_deref() == Some(scope_id))
    {
        pin.restart_at_end = true;
        pin.waiting = false;
    }
    stats.files_quarantined += index
        .files
        .values()
        .filter(|pin| pin.scope.as_deref() == Some(scope_id))
        .count() as u64;
    index.quarantined_scopes.insert(scope_id.to_string(), today);
    index.scope_generations.remove(scope_id);
    stats.scopes_quarantined += 1;
}

fn scope_quarantine_marker(state_dir: &Path, source: Source, scope_id: &str) -> PathBuf {
    state_dir
        .join("quarantined-scopes")
        .join(format!("{}.json", scope_file_stem(source, scope_id)))
}

enum Outcome {
    Read(Box<Checkpoint>),
    Waiting,
}

/// A read failed: nothing it read counts, and the file keeps its last
/// checkpoint.
struct ReadFailed;

/// A new checkpoint's `created`: the file's birth, or its first sight when
/// earlier (or its birth is unknown).
fn created_at(born: Option<i64>, first_seen: i64) -> i64 {
    match (born, first_seen) {
        (Some(born), first_seen) if first_seen > 0 => born.min(first_seen),
        (Some(born), _) => born,
        (None, first_seen) => first_seen,
    }
}

#[allow(clippy::too_many_arguments)]
fn read_file(
    run: &mut Run,
    source: Source,
    scope: &mut Scope,
    item: &Work,
    pin_start: u64,
    first_seen: i64,
    window: Window,
    generation: u64,
    names: &mut GitRootCache,
    held: usize,
    stats: &mut SourceStats,
) -> Result<Option<Outcome>, ReadFailed> {
    #[cfg(test)]
    tests::before_open(&item.found.path);
    let opened = File::open(&item.found.path)
        .and_then(|file| Ok((file.metadata()?, file.try_clone()?, file)));
    let Ok((metadata, reader_file, file)) = opened else {
        stats.scan_errors += 1;
        return Ok(None);
    };
    let size = metadata.len();
    let identity = file_identity(&metadata);
    let file_stamp = stamp(&metadata);
    // The scope keeps this checkpoint until the read succeeds.
    let mut existing = scope.files.get(&item.key).cloned();
    let mut mode = item.mode;
    if mode == Mode::RestartAtEnd {
        stats.checkpoint_restarts += 1;
    }
    let mut reserved = item.reserved;
    if let Some(checkpoint) = existing
        .as_mut()
        .filter(|checkpoint| !checkpoint.ids_known())
    {
        // Ids this build does not know (from another build): only this
        // checkpoint restarts at its end. What it counted stays in the totals
        // and, like a cold file's share, can never be replaced, so a later
        // rewrite never adds it twice.
        if mode != Mode::RestartAtEnd {
            stats.checkpoint_restarts += 1;
        }
        checkpoint.compact();
        if mode == Mode::Full {
            run.repair_left += reserved.take().unwrap_or(0);
        }
        mode = Mode::RestartAtEnd;
    }
    if mode == Mode::Forward {
        if let Some(checkpoint) = &existing {
            if checkpoint.status == Status::Done {
                return Ok(None);
            }
            let rewritten = size < checkpoint.offset || !fingerprints_match(&file, checkpoint);
            if rewritten && checkpoint.cold.is_some() {
                stats.cold_restarted += 1;
                mode = Mode::RestartAtEnd;
            } else if rewritten {
                // Repair, not recovery: a file rewritten in place is read
                // again from its start within the daily repair budget
                // (counted in `bytes_repair`), and the read replaces the
                // file's own share. Cold files and reset state never take
                // this path.
                mode = grant(run, stats, size);
                if mode == Mode::Forward {
                    return Ok(Some(Outcome::Waiting));
                }
                reserved = Some(size);
            }
        }
    }
    // A cold file's share of the totals is gone, so a full read could not
    // replace it: it restarts at its end instead.
    if mode == Mode::Full
        && existing
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.cold.is_some())
    {
        stats.cold_restarted += 1;
        mode = Mode::RestartAtEnd;
    }
    // A full read stops at its granted end; later appends are read forward
    // by the next run.
    let end_at = match (mode, reserved) {
        (Mode::Full, Some(reserved)) => reserved.min(size),
        _ => size,
    };
    let created = existing.as_ref().map_or_else(
        || created_at(item.found.born, first_seen),
        |checkpoint| checkpoint.created,
    );
    let mut old_share = None;
    let restart_state = (mode == Mode::RestartAtEnd)
        .then(|| existing.as_ref().map(|old| old.parse.restart_state()))
        .flatten();
    let cold = existing
        .as_ref()
        .and_then(|checkpoint| checkpoint.cold.clone());
    let (mut checkpoint, mut state) = match (mode, existing) {
        (Mode::Forward, Some(checkpoint)) => {
            // Checked above: a checkpoint whose state does not load is
            // read again in full.
            let state = checkpoint.parse.clone().into_state().ok_or(ReadFailed)?;
            (checkpoint, state)
        }
        (mode, existing) => {
            let offset = match mode {
                Mode::Full => 0,
                Mode::RestartAtEnd => size,
                Mode::Forward => pin_start.min(size),
            };
            let mut contribution = StoredContribution::default();
            if let Some(old) = existing {
                if matches!(mode, Mode::Full) {
                    // Replaced once the read succeeds (the days still in the
                    // window; older days stay in all-history totals).
                    let mut share = old.contribution;
                    share.prune(window.floor);
                    old_share = share.into_share();
                } else {
                    contribution = old.contribution;
                }
            }
            if mode == Mode::Forward && offset == 0 {
                stats.new_files += 1;
            }
            let (state, head_bytes) = match restart_state {
                Some(state) => (state, 0),
                None => new_parse_state(source, &item.found.path, offset),
            };
            stats.bytes_head += head_bytes;
            (
                Checkpoint {
                    path: String::new(),
                    dev: 0,
                    ino: 0,
                    created,
                    offset,
                    skipping: false,
                    head: Default::default(),
                    tail: Default::default(),
                    size: 0,
                    mtime: (0, 0),
                    parser_version: PARSER_VERSION.to_string(),
                    status: Status::Live,
                    parse: StoredParse::default(),
                    contribution,
                    last_seen: window.today,
                    cold,
                },
                state,
            )
        }
    };
    state.start_measured =
        run.start_verdicts
            .get(source.label(), &state.session, run.now.unix_timestamp())
            == crate::snapshots::StartVerdict::Measured;
    let mut contribution = std::mem::take(&mut checkpoint.contribution)
        .into_share()
        .unwrap_or_default();
    let mut delta = Aggregate::default();
    let mut out = LineSink {
        sink: super::aggregate::Sink {
            base: &scope.agg,
            agg: &mut delta,
            contribution: &mut contribution,
            window,
            generation,
        },
        copied_before: Some(checkpoint.created - COPIED_SLACK_SECS),
        fallback_day: window.today,
        stats: &mut stats.lines,
        kinds: KindsVersion::V2,
        names: Names::Resolve {
            cache: names,
            workspace: Path::new(&scope.info.workspace_path),
            repository_hash: scope.info.identity.repository_hash.as_deref(),
        },
    };
    let end = match read_lines(
        reader_file,
        checkpoint.offset,
        end_at,
        checkpoint.skipping,
        source,
        &mut state,
        &mut out,
        run.deadline,
    ) {
        Ok(end) => end,
        Err(failed) => {
            stats.scan_errors += 1;
            stats.bytes_failed += failed.bytes;
            return Err(ReadFailed);
        }
    };
    out.sink.session_start(&state.session, state.min_ts);
    #[cfg(test)]
    if tests::fail_read(&item.found.path) {
        stats.bytes_failed += end.bytes;
        return Err(ReadFailed);
    }
    let Ok((head, tail)) = fingerprints(&file, end.offset) else {
        stats.scan_errors += 1;
        stats.bytes_failed += end.bytes;
        return Err(ReadFailed);
    };
    // `held`: the scope's checkpoints and totals as loaded.
    stats.peak_accounted_bytes = stats
        .peak_accounted_bytes
        .max(held + end.buffer_bytes + state.accounted_bytes() + delta.accounted_bytes());
    // The read succeeded: only now does it change the scope's totals.
    if let Some(old) = old_share {
        scope.agg.subtract(&old, generation);
    }
    scope.agg.merge(delta);
    match mode {
        Mode::Full => {
            stats.files_read += 1;
            stats.bytes_repair += end.bytes;
        }
        Mode::Forward | Mode::RestartAtEnd => {
            stats.files_read += 1;
            stats.bytes_new += end.bytes;
        }
    }
    stats.cut |= end.cut;
    state.open.retain(|(day, _, _)| *day >= window.floor);
    checkpoint.offset = end.offset;
    checkpoint.skipping = end.skipping;
    checkpoint.head = head;
    checkpoint.tail = tail;
    checkpoint.size = size;
    checkpoint.mtime = file_stamp;
    checkpoint.dev = identity.0;
    checkpoint.ino = identity.1;
    checkpoint.path = item.found.path.to_string_lossy().into_owned();
    checkpoint.last_seen = window.today;
    checkpoint.parse = StoredParse::from_state(&state);
    checkpoint.contribution = StoredContribution::from_share(&contribution);
    if mode == Mode::RestartAtEnd {
        checkpoint.compact();
    }
    Ok(Some(Outcome::Read(Box::new(checkpoint))))
}

/// A new or fallen-back scope: drop the upload acknowledgment so every day
/// it holds is sent.
fn forget_upload(state_dir: &Path, source: Source, scope_id: &str) {
    let _ = fs::remove_file(super::upload::ack_path(state_dir, source, scope_id));
}

fn count_upload(source: Source, result: UploadResult, stats: &mut SourceStats) {
    match result.outcome {
        UploadOutcome::Uploaded => {
            stats.uploaded += 1;
            let receipt = result.receipt.unwrap_or_default();
            stats.upload_payload_bytes += receipt.payload_bytes;
            stats.upload_rows_written += receipt.rows_written.unwrap_or(0);
            // One line per upload: request size and the rows the server
            // wrote for it (absent when the response did not say).
            eprintln!(
                "context_composition_v2_upload source={} payload_bytes={} daily_rollup_rows_written={}",
                source.label(),
                receipt.payload_bytes,
                receipt
                    .rows_written
                    .map_or_else(|| "unknown".to_string(), |rows| rows.to_string()),
            );
        }
        UploadOutcome::Unchanged => stats.upload_unchanged += 1,
        UploadOutcome::Failed => stats.upload_failed += 1,
    }
    stats.upload_dropped_non_v2 += result.dropped_non_v2;
    stats.upload_dropped_unsafe += result.dropped_unsafe;
}

/// Scopes not read in this run: retry an unacknowledged change, or refresh
/// a week-old upload. A scope no pin named for `KEEP_DAYS` is left alone.
fn upload_other_scopes(
    run: &Run,
    source: Source,
    index: &mut Index,
    done: &BTreeSet<String>,
    target: &mut UploadTarget,
    window: Window,
    stats: &mut SourceStats,
) {
    for (scope_id, generation) in index.scope_generations.clone() {
        let scope_id = &scope_id;
        if done.contains(scope_id)
            || scope_retired(index, scope_id, window.today)
            || index.quarantined_scopes.contains_key(scope_id)
        {
            continue;
        }
        let ack_path = super::upload::ack_path(&run.state_dir, source, scope_id);
        let ack = read_json::<super::upload::UploadAck>(&ack_path)
            .ok()
            .flatten()
            .filter(|ack| ack.destination == target.destination);
        let due = ack.as_ref().map_or(true, |ack| {
            ack.generation < generation
                || ack.details_enabled != target.details_enabled
                || run.now.unix_timestamp() - ack.posted_at >= super::UPLOAD_STALENESS_SECS
        });
        if !due {
            continue;
        }
        let path = scope_path(&run.state_dir, source, scope_id);
        // An upload is built from the totals, whose hash `load_scope`
        // checks; shards are checked when a read first loads them.
        let loaded = load_scope(&path, source, scope_id);
        let mut scope = match loaded {
            Ok(Some(scope)) => scope,
            _ => {
                stats.bad_state += 1;
                quarantine_scope(run, source, scope_id, &path, index, window.today, stats);
                continue;
            }
        };
        scope.agg.prune(window);
        let result = upload_scope(&run.state_dir, source, &scope, target, run.now, window);
        count_upload(source, result, stats);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::cell::{Cell, RefCell};
    use std::path::{Path, PathBuf};

    thread_local! {
        static FAIL_SCOPE_COMMIT: Cell<bool> = const { Cell::new(false) };
        static FAIL_READ: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        static CRASH_AFTER: Cell<Option<u64>> = const { Cell::new(None) };
        static GROW: RefCell<Option<(PathBuf, Vec<u8>)>> = const { RefCell::new(None) };
    }

    /// Simulate a crash (no pins write) once `commits` scopes committed.
    pub(in super::super) fn set_crash_after(commits: Option<u64>) {
        CRASH_AFTER.with(|cell| cell.set(commits));
    }

    pub(super) fn crash_now(committed: u64) -> bool {
        CRASH_AFTER.with(|cell| cell.get().is_some_and(|after| committed >= after))
    }

    /// Append `bytes` to `path` once, between discovery and its open.
    pub(in super::super) fn set_grow_before_open(path: &Path, bytes: Vec<u8>) {
        GROW.with(|cell| *cell.borrow_mut() = Some((path.to_path_buf(), bytes)));
    }

    pub(super) fn before_open(path: &Path) {
        let grow = GROW.with(|cell| {
            let mut cell = cell.borrow_mut();
            if cell.as_ref().is_some_and(|(grow, _)| grow == path) {
                cell.take()
            } else {
                None
            }
        });
        if let Some((path, bytes)) = grow {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
            file.write_all(&bytes).unwrap();
        }
    }

    /// Simulate a read error after the lines of `path` were counted.
    pub(in super::super) fn set_fail_read(path: Option<&Path>) {
        FAIL_READ.with(|cell| *cell.borrow_mut() = path.map(Path::to_path_buf));
    }

    pub(super) fn fail_read(path: &Path) -> bool {
        FAIL_READ.with(|cell| cell.borrow().as_deref() == Some(path))
    }

    /// Simulate a crash between the pins write and the scope commit.
    pub(in super::super) fn set_fail_scope_commit(fail: bool) {
        FAIL_SCOPE_COMMIT.with(|cell| cell.set(fail));
    }

    pub(super) fn fail_scope_commit() -> bool {
        FAIL_SCOPE_COMMIT.with(Cell::get)
    }
}
