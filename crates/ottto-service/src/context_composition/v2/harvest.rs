//! The daily run: gate, discovery, budgets, reading, commit per scope and
//! upload.
//!
//! The loop wakes hourly and runs once per UTC day, after the daemon has
//! been up for `MIN_UPTIME`, at utility QoS. The day is saved when the run
//! starts, so a crash never repeats a day. New bytes are read without a cap;
//! full reads (files rewritten in place, files live at install) share
//! `REPAIR_BYTES_PER_DAY`, newest first, each up to its size when granted,
//! and the rest wait for a later day (counted). A run stops at
//! `RUN_WALL_CAP`; each scope commits on its own, so a cut run never counts
//! anything twice.
//!
//! First run (no pins yet) is forward-only: files modified in the last
//! `LIVE_AT_INSTALL` are read once from their start within the repair
//! budget; every other file starts at its current size. That discovery is
//! saved before any scope commits, so a crashed first run resumes it. Later,
//! a file born after the previous run started is new and read from its
//! start; a file first seen but older starts at its current size.
//!
//! State that cannot be used is never rebuilt from transcripts. A scope
//! goes back to its previous committed generation and reads only what that
//! generation is behind on (repair budget); without one, the scope (or the
//! files of a damaged checkpoint shard) is set aside. Each case is counted
//! for the daily run-health alert.
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
use super::file::{head_cwds, new_parse_state, read_lines, LineSink, LineStats, Names, Source};
use super::scope::{
    checkpoint_members, highest_generation, keep_previous, linked_worktrees, load_previous,
    load_scope, prev_path, resolved_missing, save_scope, scope_file_stem, scope_files, scope_path,
    set_aside, shard_id, update_members, verify_commit, GitScopeResolver, Scope, ScopeInfo,
    ScopeResolver,
};
use super::upload::{upload_scope, UploadOutcome, UploadResult, UploadTarget, Uploader};
use super::{
    COPIED_SLACK_SECS, FORGET_MISSING_DAYS, KEEP_DAYS, LIVE_AT_INSTALL, MIN_UPTIME, PARSER_VERSION,
    REPAIR_BYTES_PER_DAY, RUN_WALL_CAP, STATE_DIR, STATE_SCHEMA, WAKE_INTERVAL,
};
use crate::composition_kinds::{GitRootCache, KindsVersion};
use crate::snapshot_client::{load_snapshot_device_credentials, SnapshotApiClient};
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
    *worktrees = run_worker_process(&mut command, worktrees)?;
    Ok(())
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

/// Wait for process exit before returning any hourly metadata. System malloc
/// can retain free pages even after thread exit and pressure relief; process
/// teardown releases those pages without changing the daemon's allocator.
pub(super) fn run_worker_process<I: Serialize, O: DeserializeOwned>(
    command: &mut Command,
    input: &I,
) -> Result<O> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let write = (|| -> Result<()> {
        use std::io::Write;
        let mut pipe = std::io::BufWriter::new(child.stdin.take().expect("piped worker input"));
        serde_json::to_writer(&mut pipe, input)?;
        pipe.flush()?;
        Ok(())
    })();
    if let Err(error) = write {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!("composition worker failed: {}", output.status));
    }
    let reply = output
        .stdout
        .split(|byte| *byte == b'\n')
        .rev()
        .find_map(|line| line.strip_prefix(WORKER_REPLY))
        .ok_or_else(|| anyhow!("composition worker reply is missing"))?;
    Ok(serde_json::from_slice(reply)?)
}

/// Private service entry point. It starts neither the daemon nor any other
/// collector. The existing release gate also applies to direct invocation.
#[doc(hidden)]
pub fn run_context_composition_worker() -> Result<()> {
    if !super::changed_days_enabled() {
        return Err(anyhow!("changed-days composition reader is disabled"));
    }
    set_utility_qos();
    let mut worktrees: WorktreeCache = serde_json::from_reader(std::io::stdin().lock())?;
    let home = crate::snapshot_sync::home_dir()?;
    let support_dir = ottto_core::default_support_dir();
    if !local_harvest_disabled(&support_dir) {
        let today = day_of(OffsetDateTime::now_utc().date());
        map_worktrees(&state_dir(&support_dir), today, &mut worktrees);
    }
    if let Err(error) = run_if_due(&home, &support_dir) {
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
fn run_if_due(home: &Path, support_dir: &Path) -> Result<()> {
    if local_harvest_disabled(support_dir) {
        return Ok(());
    }
    let now = OffsetDateTime::now_utc();
    let dir = state_dir(support_dir);
    let Some(mut record) = begin_run(&dir, now)? else {
        return Ok(());
    };
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = crate::snapshot_sync::snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = crate::snapshot_sync::snapshot_api_base_url();
    let client = SnapshotApiClient::new(api_base_url.clone());
    let enabled = crate::snapshot_sync::enabled_snapshot_sources(&device);
    let destination = destination_identity(&device, &machine_id, &api_base_url);
    let mut resolver = GitScopeResolver;
    let mut run = Run {
        state_dir: dir.clone(),
        now,
        deadline: Instant::now() + RUN_WALL_CAP,
        resolver: &mut resolver,
        repair_left: REPAIR_BYTES_PER_DAY.saturating_sub(record.repair_used),
    };
    for (snapshot_source, source) in source_order(day_of(now.date())) {
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
        let mut labels_enabled = true;
        if let Some(token) = relay_token.as_deref() {
            match client.get_activity_hint(token) {
                Ok(hint) if !hint.context_footprint_harvest_enabled => {
                    write_marker(&marker, &destination);
                    continue;
                }
                Ok(hint) => {
                    let _ = fs::remove_file(&marker);
                    labels_enabled = hint.workspace_labels_enabled;
                }
                Err(_) if read_marker(&marker).as_deref() == Some(destination.as_str()) => continue,
                Err(_) => {}
            }
        } else if read_marker(&marker).as_deref() == Some(destination.as_str()) {
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
        });
        let stats = run_source(&mut run, source, &roots, target);
        print_metrics(source, &stats, now);
    }
    record.repair_used = REPAIR_BYTES_PER_DAY.saturating_sub(run.repair_left);
    let _ = write_json(&dir.join("run.json"), &record);
    Ok(())
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
    fn upload(&mut self, request: &Value) -> Result<()> {
        self.client
            .upload_context_composition(&self.relay_token, request)
            .map(|_| ())
    }
}

fn print_metrics(source: Source, stats: &SourceStats, now: OffsetDateTime) {
    let at = now.format(&Rfc3339).unwrap_or_default();
    let lines = &stats.lines;
    eprintln!(
        "context_composition_v2_metrics at={at} source={} bytes_new={} bytes_repair={} bytes_head={} bytes_failed={} files_read={} files_failed={} quarantined={} new_files={} dormant_found={} lines={} prefix_skipped={} classifier_skipped={} too_long={} bad_lines={} dropped_calls={} dropped_items={} unnamed_files={} name_lookups_skipped={} web_search_in_call={} scan_errors={} repair_waiting={} repair_waiting_bytes={} repair_restarted={} cold_compacted={} cold_restarted={} bad_state={} state_fallbacks={} scopes_quarantined={} files_quarantined={} checkpoint_restarts={} pins_rebuilt={} moved={} switched={} archived={} duplicates={} unscoped={} scopes_committed={} scopes_failed={} uploaded={} upload_unchanged={} upload_failed={} upload_dropped_non_v2={} upload_dropped_unsafe={} cut={} cpu_ms={} wall_ms={} peak_accounted_bytes={} state_bytes={}",
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
        stats.state_fallbacks,
        stats.scopes_quarantined,
        stats.files_quarantined,
        stats.checkpoint_restarts,
        stats.pins_rebuilt,
        stats.moved,
        stats.switched,
        stats.archived,
        stats.duplicates,
        stats.unscoped,
        stats.scopes_committed,
        stats.scopes_failed,
        stats.uploaded,
        stats.upload_unchanged,
        stats.upload_failed,
        stats.upload_dropped_non_v2,
        stats.upload_dropped_unsafe,
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
    pub(super) files_read: u64,
    pub(super) files_failed: u64,
    /// Files quarantined in this run (failed twice in a row).
    pub(super) quarantined: u64,
    pub(super) new_files: u64,
    pub(super) dormant_found: u64,
    pub(super) moved: u64,
    /// A larger copy holding the same read bytes took over a pin.
    pub(super) switched: u64,
    pub(super) archived: u64,
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
    /// Scopes whose newest state could not be used and that went back to
    /// their previous committed generation.
    pub(super) state_fallbacks: u64,
    /// Scopes set aside: unusable state and no good earlier generation.
    pub(super) scopes_quarantined: u64,
    /// Files set aside because the checkpoint shard holding them was
    /// damaged in every kept generation.
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
    /// Birth time, else modification time: decides whether a file is new.
    birth: i64,
    /// Birth time where the file system records one.
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
    /// Bytes of a forward read already counted by a failed generation and
    /// read again after a fallback (charged to the repair budget).
    catch_up: u64,
    /// Scoped in this run (no committed checkpoint can exist).
    fresh: bool,
    /// Added by a fallback only to catch up; dropped when nothing is behind.
    catch_up_only: bool,
}

impl Work {
    fn new(key: String, found: Found, mode: Mode) -> Self {
        Self {
            key,
            found,
            mode,
            reserved: None,
            catch_up: 0,
            fresh: false,
            catch_up_only: false,
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

/// Bad pins: rebuild them from the scope states, whose checkpoints hold each
/// file's path, identity, offset, size and scope. Files no scope holds start
/// over as found-but-old.
fn rebuild_pins(
    state_dir: &Path,
    source: Source,
    index: &mut Index,
    today: Day,
    only_uncommitted: bool,
) -> u64 {
    let Ok(entries) = fs::read_dir(state_dir.join("scopes")) else {
        return 0;
    };
    let prefix = format!("{}-", source.label());
    let mut rebuilt = 0;
    // A scope whose newest manifest is gone still has its previous one.
    let scope_ids: BTreeSet<String> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?.strip_prefix(&prefix)?;
            name.strip_suffix(".prev.json")
                .or_else(|| name.strip_suffix(".json"))
                .filter(|id| !id.contains('.'))
                .map(str::to_string)
        })
        .collect();
    for scope_id in scope_ids {
        let path = scope_path(state_dir, source, &scope_id);
        if only_uncommitted {
            #[derive(serde::Deserialize)]
            struct Generation {
                generation: u64,
            }
            let Ok(Some(saved)) = read_json::<Generation>(&path) else {
                continue;
            };
            if index.scope_generations.get(&scope_id) == Some(&saved.generation) {
                continue;
            }
        }
        let hydrate = |mut scope: Scope| scope.load_all_shards(&path).ok().map(|()| scope);
        // Lost pins with unusable newest state: the previous generation's
        // checkpoints, whose older offsets make the scope's fallback catch up.
        let Some(scope) = load_scope(&path, source, &scope_id)
            .ok()
            .flatten()
            .and_then(hydrate)
            .or_else(|| {
                (!only_uncommitted)
                    .then(|| load_previous(&path, source, &scope_id))
                    .flatten()
                    .and_then(hydrate)
            })
        else {
            continue;
        };
        for (key, checkpoint) in &scope.files {
            index.files.insert(
                key.clone(),
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
                    head: checkpoint.head,
                    tail: checkpoint.tail,
                    origin: None,
                },
            );
            rebuilt += 1;
        }
        if !scope.info.workspace_path.is_empty() {
            index
                .cwd_scopes
                .insert(scope.info.workspace_path.clone(), scope_id.clone());
        }
        index.scope_info.insert(scope_id.clone(), scope.info);
        index
            .scope_generations
            .insert(scope_id.clone(), scope.generation);
        index.scope_last_pinned.insert(scope_id, today);
    }
    rebuilt
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
    let (mut index, mut first_run) = match read_json::<Index>(&path) {
        Ok(Some(index)) if index.schema == STATE_SCHEMA => (index, false),
        Ok(None) => (Index::new(now_secs), true),
        _ => {
            stats.bad_state += 1;
            let mut index = Index::new(now_secs);
            index.last_scan_started = Some(now_secs);
            stats.pins_rebuilt = rebuild_pins(&run.state_dir, source, &mut index, today, false);
            (index, false)
        }
    };
    // A first run can commit a scope before its only pins write. Recover
    // those manifests even when the pins file has never existed, and resume
    // the first run's discovery from its install record: its cutoff and
    // starting offsets, never the restart time.
    let mut install = None;
    if first_run {
        install = read_json::<InstallRecord>(&install_file)
            .ok()
            .flatten()
            .filter(|record| record.schema == STATE_SCHEMA);
        let recovered = rebuild_pins(&run.state_dir, source, &mut index, today, false);
        stats.pins_rebuilt += recovered;
        if let Some(record) = &install {
            first_run = false;
            index.created = record.cutoff;
            index.last_scan_started = Some(record.cutoff);
        } else if recovered > 0 {
            // Committed scopes without pins or an install record: pins lost
            // after a completed first run, as with bad pins.
            first_run = false;
            index.last_scan_started = Some(now_secs);
        }
    } else {
        // Generation comparison also works on filesystems whose timestamps
        // cannot distinguish the manifest commit from the previous pins write.
        stats.pins_rebuilt += rebuild_pins(&run.state_dir, source, &mut index, today, true);
    }
    let previous_scan = index.last_scan_started;
    index.last_scan_started = Some(now_secs);

    // Discovery: pick one copy per key and decide what needs reading.
    let (found, archived, seen) = walk(roots, &mut index, today, &mut stats);
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
    for (key, file) in &present {
        let needs = match index.files.get_mut(key) {
            None => {
                let recorded = install
                    .as_ref()
                    .and_then(|record| Some((record.starts.get(key)?, record)));
                let (new, start, waiting) = match recorded {
                    // Found by the interrupted first run.
                    Some((start, record)) => {
                        let live = record.live.contains(key);
                        (live, (*start).min(file.size), live)
                    }
                    None => {
                        let new = if first_run {
                            now_secs - file.stamp.0 <= LIVE_AT_INSTALL.as_secs() as i64
                        } else {
                            previous_scan.is_some_and(|last| file.birth >= last)
                        };
                        // Files live at install read from their start
                        // within the repair budget.
                        (new, if new { 0 } else { file.size }, new && first_run)
                    }
                };
                if !new {
                    stats.dormant_found += 1;
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
                        waiting,
                        done: false,
                        last_seen: today,
                        // First seen by the install run when it found it.
                        first_seen: recorded.map_or(now_secs, |(_, record)| record.cutoff),
                        unscoped: false,
                        failures: 0,
                        quarantined: false,
                        head: Default::default(),
                        tail: Default::default(),
                        origin: Some(start),
                    },
                );
                start < file.size
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
                    || !same
                    || file.size != pin.size
                    || file.stamp != pin.mtime
                    || (pin.start < file.size && (pin.scope.is_some() || !pin.unscoped))
            }
        };
        if needs {
            work.push(Work::new(key.clone(), file.clone(), Mode::Forward));
        }
    }
    if first_run {
        // Saved before any scope can commit: a crash later in this run
        // resumes from this discovery instead of the restart time.
        let record = InstallRecord {
            schema: STATE_SCHEMA,
            cutoff: now_secs,
            starts: index
                .files
                .iter()
                .map(|(key, pin)| (key.clone(), pin.start))
                .collect(),
            live: index
                .files
                .iter()
                .filter(|(_, pin)| pin.waiting)
                .map(|(key, _)| key.clone())
                .collect(),
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
        }
    }
    index
        .files
        .retain(|_, pin| pin.last_seen >= today - FORGET_MISSING_DAYS);

    // Scope every file that will be read.
    let mut scoped = Vec::with_capacity(work.len());
    for mut item in work {
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
                item.fresh = true;
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
            run, source, &scope_id, items, &mut index, &present, window, &mut names, &mut stats,
        ) else {
            continue;
        };
        if let Some(target) = target.as_mut() {
            let result = upload_scope(&run.state_dir, source, &scope, target, run.now, window);
            count_upload(result, &mut stats);
            uploaded.insert(scope_id);
        }
        #[cfg(test)]
        if tests::crash_now(stats.scopes_committed) {
            finish(&mut stats, started, cpu_started);
            return stats;
        }
    }
    stats.name_lookups_skipped = names.skipped();
    tidy_index(&mut index, today);
    if let Ok(bytes) = write_json(&path, &index) {
        stats.state_bytes += bytes;
        // The pins now hold the first run's discovery.
        let _ = fs::remove_file(&install_file);
    }

    if let Some(target) = target.as_mut() {
        upload_other_scopes(run, source, &index, &uploaded, target, window, &mut stats);
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
fn tidy_index(index: &mut Index, today: Day) {
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

/// Failed reads in a row that quarantine a file.
const QUARANTINE_AFTER: u8 = 2;

/// Where a scope's state came from this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// Never committed.
    Fresh,
    /// The newest committed generation.
    Current,
    /// The previous generation: the newest could not be used.
    Fallback,
}

#[allow(clippy::too_many_arguments)]
fn process_scope(
    run: &mut Run,
    source: Source,
    scope_id: &str,
    mut items: Vec<Work>,
    index: &mut Index,
    present: &BTreeMap<String, Found>,
    window: Window,
    names: &mut GitRootCache,
    stats: &mut SourceStats,
) -> Option<Scope> {
    if index.quarantined_scopes.contains_key(scope_id) {
        // Set aside: never read, rebuilt or uploaded again.
        return None;
    }
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
    let known = index.scope_generations.contains_key(scope_id) || prev_path(&path).is_file();
    let loaded = match load_scope(&path, source, scope_id) {
        // A scope the pins know but whose state is gone is bad state too.
        Ok(None) if known => Err(()),
        loaded => loaded,
    };
    let previous = || load_previous(&path, source, scope_id);
    // Shards are checked before any transcript byte is read, so a damaged
    // one can still send the whole scope back to its previous generation.
    let mut damaged = BTreeSet::new();
    let (mut scope, base) = match loaded {
        Ok(None) => {
            forget_upload(&run.state_dir, source, scope_id);
            (Scope::new(scope_id, info), Base::Fresh)
        }
        Ok(Some(mut scope)) => {
            damaged = scope.verify_shards(&path, items.iter().map(|item| shard_id(&item.key)));
            if damaged.is_empty() {
                (scope, Base::Current)
            } else {
                stats.bad_state += 1;
                match previous() {
                    Some(previous) => (previous, Base::Fallback),
                    None => (scope, Base::Current),
                }
            }
        }
        Err(()) => {
            // Never rebuilt from transcripts: the previous generation, or
            // the scope is set aside.
            stats.bad_state += 1;
            match previous() {
                Some(previous) => (previous, Base::Fallback),
                None => {
                    quarantine_scope(run, source, scope_id, &path, index, today, stats);
                    return None;
                }
            }
        }
    };
    let generation = if base == Base::Fallback {
        // The previous generation's offsets are older than the pins': every
        // pinned file that generation is behind on reads the difference.
        stats.state_fallbacks += 1;
        let listed: BTreeSet<String> = items.iter().map(|item| item.key.clone()).collect();
        for (key, pin) in &index.files {
            if pin.scope.as_deref() != Some(scope_id)
                || pin.done
                || pin.quarantined
                || listed.contains(key)
            {
                continue;
            }
            let Some(found) = present.get(key).cloned().or_else(|| {
                let path = PathBuf::from(&pin.path);
                let metadata = fs::metadata(&path).ok()?;
                Some(Found::new(path, &metadata))
            }) else {
                continue;
            };
            let mut item = Work::new(key.clone(), found, Mode::Forward);
            item.catch_up_only = true;
            items.push(item);
        }
        damaged = scope.verify_shards(&path, items.iter().map(|item| shard_id(&item.key)));
        // Every day is sent again: the acknowledged upload may hold the
        // failed generation's rows.
        forget_upload(&run.state_dir, source, scope_id);
        // Names the failed generation wrote are never reused.
        scope
            .generation
            .max(index.scope_generations.get(scope_id).copied().unwrap_or(0))
            .max(highest_generation(&path))
            + 1
    } else {
        scope.generation + 1
    };
    // Kept by this commit's cleanup next to the new generation.
    let kept = scope.refs();
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
    let mut removed = Vec::new();
    let mut added = Vec::new();
    let mut updates = Vec::new();
    for (id, mut items) in groups {
        if stats.cut || Instant::now() >= run.deadline {
            stats.cut = true;
            break;
        }
        let legacy = legacy_groups.remove(&id);
        let migrating = legacy.is_some();
        scope.files = legacy.unwrap_or_default();
        if damaged.contains(&id) || scope.load_shard(&path, id).is_err() {
            // No kept generation holds this shard. Its files are set aside
            // (counted), never re-read and never moved on from an empty
            // checkpoint; files first scoped now still read.
            stats.bad_state += 1;
            scope.files.clear();
            if let Some(file) = scope.drop_shard(&path, id) {
                let label = format!(
                    "{}-s{id:03}-{}",
                    scope_file_stem(source, scope_id),
                    run.now.unix_timestamp()
                );
                let _ = set_aside(&run.state_dir, &label, &[file]);
            }
            let fresh: BTreeSet<String> = items
                .iter()
                .filter(|item| item.fresh)
                .map(|item| item.key.clone())
                .collect();
            for (key, pin) in index.files.iter_mut() {
                if pin.scope.as_deref() == Some(scope_id)
                    && shard_id(key) == id
                    && !pin.done
                    && !pin.quarantined
                    && !fresh.contains(key)
                {
                    pin.quarantined = true;
                    stats.files_quarantined += 1;
                }
            }
            items.retain(|item| fresh.contains(&item.key));
        }
        if base == Base::Fallback {
            items.retain_mut(|item| {
                if item.mode != Mode::Forward {
                    return true;
                }
                let Some(pin) = index.files.get(&item.key) else {
                    return !item.catch_up_only;
                };
                let from = scope.files.get(&item.key).map_or_else(
                    || pin.origin.unwrap_or(pin.start),
                    |checkpoint| checkpoint.offset,
                );
                let behind = pin.start.min(item.found.size).saturating_sub(from);
                if behind == 0 {
                    return !item.catch_up_only;
                }
                if behind <= run.repair_left {
                    run.repair_left -= behind;
                    item.catch_up = behind;
                } else {
                    // Counted; its earlier totals stay as committed.
                    stats.repair_restarted += 1;
                    item.mode = Mode::RestartAtEnd;
                }
                true
            });
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
            // After a fallback, a file the previous generation never held
            // reads from where its first read started.
            let Some((start, first_seen)) = index.files.get(&item.key).map(|pin| {
                let start = match base {
                    Base::Fallback => pin.origin.unwrap_or(pin.start),
                    _ => pin.start,
                };
                (start, pin.first_seen)
            }) else {
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
    // The generation now committed stays, as the fallback, until the new
    // one is verified. After a fallback the previous one already is.
    if base == Base::Current && keep_previous(&path).is_err() {
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
        // Nothing is cleaned and the pins keep their offsets: the next run
        // falls back to the kept generation.
        stats.scopes_failed += 1;
        return None;
    }
    stats.scopes_committed += 1;
    scope.clean_shards(&path, &kept);
    for (key, pin) in updates {
        index.files.insert(key, pin);
    }
    index
        .scope_generations
        .insert(scope_id.to_string(), scope.generation);
    Some(scope)
}

/// Unusable state and no good earlier generation: move the scope's files
/// aside and stop reading, updating and uploading it (counted). Its
/// transcripts are never read again to rebuild it.
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
    if set_aside(&run.state_dir, &label, &scope_files(path)).is_err() {
        stats.scopes_failed += 1;
    }
    index.quarantined_scopes.insert(scope_id.to_string(), today);
    index.scope_generations.remove(scope_id);
    stats.scopes_quarantined += 1;
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
    let mut reserved = item.reserved;
    if let Some(checkpoint) = existing
        .as_mut()
        .filter(|checkpoint| !checkpoint.ids_known())
    {
        // Ids this build does not know (from another build): only this
        // checkpoint restarts at its end. What it counted stays in the totals
        // and, like a cold file's share, can never be replaced, so a later
        // rewrite never adds it twice.
        stats.checkpoint_restarts += 1;
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
                if mode == Mode::Full {
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
    stats.files_read += 1;
    if mode == Mode::Full {
        stats.bytes_repair += end.bytes;
    } else {
        let repair = item.catch_up.min(end.bytes);
        stats.bytes_repair += repair;
        stats.bytes_new += end.bytes - repair;
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
    Ok(Some(Outcome::Read(Box::new(checkpoint))))
}

/// A new or fallen-back scope: drop the upload acknowledgment so every day
/// it holds is sent.
fn forget_upload(state_dir: &Path, source: Source, scope_id: &str) {
    let _ = fs::remove_file(super::upload::ack_path(state_dir, source, scope_id));
}

fn count_upload(result: UploadResult, stats: &mut SourceStats) {
    match result.outcome {
        UploadOutcome::Uploaded => stats.uploaded += 1,
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
    index: &Index,
    done: &BTreeSet<String>,
    target: &mut UploadTarget,
    window: Window,
    stats: &mut SourceStats,
) {
    for (scope_id, generation) in &index.scope_generations {
        if done.contains(scope_id) || scope_retired(index, scope_id, window.today) {
            continue;
        }
        let ack_path = super::upload::ack_path(&run.state_dir, source, scope_id);
        let ack = read_json::<super::upload::UploadAck>(&ack_path)
            .ok()
            .flatten()
            .filter(|ack| ack.destination == target.destination);
        let due = ack.as_ref().map_or(true, |ack| {
            ack.generation < *generation
                || run.now.unix_timestamp() - ack.posted_at >= super::UPLOAD_STALENESS_SECS
        });
        if !due {
            continue;
        }
        let path = scope_path(&run.state_dir, source, scope_id);
        let Ok(Some(mut scope)) = load_scope(&path, source, scope_id) else {
            continue;
        };
        scope.agg.prune(window);
        let result = upload_scope(&run.state_dir, source, &scope, target, run.now, window);
        count_upload(result, stats);
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
