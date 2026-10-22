//! The daily run: gate, discovery, budgets, reading, commit per scope and
//! upload.
//!
//! The loop wakes hourly and runs once per UTC day, after the daemon has
//! been up for `MIN_UPTIME`, at utility QoS. The day is saved when the run
//! starts, so a crash never repeats a day. New bytes are read without a cap;
//! full reads (files rewritten in place, bad state, files live at install)
//! share `REPAIR_BYTES_PER_DAY`, newest first, and the rest wait for a later
//! day (counted). A run stops at `RUN_WALL_CAP`; each scope commits on its
//! own, so a cut run never counts anything twice.
//!
//! First run (no pins yet) is forward-only: files modified in the last
//! `LIVE_AT_INSTALL` are read once from their start within the repair
//! budget; every other file starts at its current size. Later, a file born
//! after the previous run started is new and read from its start; a file
//! first seen but older starts at its current size.

use super::super::harvest::{
    agent_source_label, destination_identity, local_harvest_disabled, org_disabled_marker_path,
    read_marker, write_marker,
};
use super::aggregate::{day_of, load_contribution, store_contribution, Window};
use super::checkpoint::{
    birth_secs, file_identity, fingerprints, fingerprints_match, read_json, stamp, write_json,
    Checkpoint, Index, Pin, RunRecord, Stamp, Status, StoredParse,
};
use super::file::{new_parse_state, read_lines, LineSink, LineStats, Source};
use super::ownership::{remove_unreferenced, Ownership};
use super::scope::{
    load_scope, ownership_dir, save_scope, scope_path, GitScopeResolver, Scope, ScopeInfo,
    ScopeResolver,
};
use super::upload::{upload_scope, UploadOutcome, UploadTarget, Uploader};
use super::{
    FORGET_MISSING_DAYS, LIVE_AT_INSTALL, MIN_UPTIME, PARSER_VERSION, REPAIR_BYTES_PER_DAY,
    RUN_WALL_CAP, STATE_DIR, STATE_SCHEMA, WAKE_INTERVAL,
};
use crate::context_footprint::first_existing_cwd_from_jsonl;
use crate::snapshot_client::{load_snapshot_device_credentials, SnapshotApiClient};
use crate::snapshots::SnapshotSource;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::path::{Path, PathBuf};
use std::time::Instant;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(super) fn state_dir(support_dir: &Path) -> PathBuf {
    support_dir.join("context_composition").join(STATE_DIR)
}

// -------------------------------------------------------------------------
// Loop and gate.
// -------------------------------------------------------------------------

pub(in crate::context_composition) fn spawn_v2_sync(
    home: PathBuf,
    support_dir: PathBuf,
) -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-context-composition-v2".to_string())
        .spawn(move || {
            set_utility_qos();
            let started = Instant::now();
            loop {
                let wait = MIN_UPTIME.saturating_sub(started.elapsed());
                if !wait.is_zero() {
                    std::thread::sleep(wait);
                }
                if let Err(error) = run_if_due(&home, &support_dir) {
                    eprintln!(
                        "context composition run skipped: {}",
                        crate::snapshot_sync::safe_error(&error)
                    );
                }
                std::thread::sleep(WAKE_INTERVAL);
            }
        })
        .map_err(|error| anyhow!("spawn context composition reader: {error}"))?;
    Ok(())
}

/// Background work: let the system run it on efficiency cores and behind
/// interactive work.
fn set_utility_qos() {
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
    for (snapshot_source, source) in [
        (SnapshotSource::ClaudeCode, Source::Claude),
        (SnapshotSource::Codex, Source::Codex),
    ] {
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
        "context_composition_v2_metrics at={at} source={} bytes_new={} bytes_repair={} files_read={} new_files={} lines={} prefix_skipped={} too_long={} bad_lines={} repair_waiting={} repair_waiting_bytes={} repair_restarted={} bad_state={} moved={} archived={} duplicates={} unscoped={} scopes_committed={} scopes_failed={} uploaded={} upload_unchanged={} upload_failed={} cut={} cpu_ms={} wall_ms={} peak_accounted_bytes={} state_bytes={}",
        source.label(),
        stats.bytes_new,
        stats.bytes_repair,
        stats.files_read,
        stats.new_files,
        lines.lines,
        lines.prefix_skipped,
        lines.too_long,
        lines.bad_lines,
        stats.repair_waiting,
        stats.repair_waiting_bytes,
        stats.repair_restarted,
        stats.bad_state,
        stats.moved,
        stats.archived,
        stats.duplicates,
        stats.unscoped,
        stats.scopes_committed,
        stats.scopes_failed,
        stats.uploaded,
        stats.upload_unchanged,
        stats.upload_failed,
        stats.cut,
        stats.cpu_micros / 1000,
        stats.wall_micros / 1000,
        stats.peak_accounted_bytes,
        stats.state_bytes,
    );
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
pub(super) struct SourceStats {
    pub(super) bytes_new: u64,
    pub(super) bytes_repair: u64,
    pub(super) files_read: u64,
    pub(super) new_files: u64,
    pub(super) dormant_found: u64,
    pub(super) moved: u64,
    pub(super) archived: u64,
    pub(super) duplicates: u64,
    pub(super) unscoped: u64,
    pub(super) scan_errors: u64,
    pub(super) repair_waiting: u64,
    pub(super) repair_waiting_bytes: u64,
    pub(super) repair_restarted: u64,
    pub(super) bad_state: u64,
    pub(super) scopes_committed: u64,
    pub(super) scopes_failed: u64,
    pub(super) uploaded: u64,
    pub(super) upload_unchanged: u64,
    pub(super) upload_failed: u64,
    pub(super) lines: LineStats,
    pub(super) cut: bool,
    pub(super) cpu_micros: u64,
    pub(super) wall_micros: u64,
    pub(super) peak_accounted_bytes: usize,
    pub(super) state_bytes: u64,
    pub(super) ownership_lost: u64,
}

/// A transcript found on disk.
#[derive(Debug, Clone)]
struct Found {
    path: PathBuf,
    identity: (u64, u64),
    size: u64,
    stamp: Stamp,
    birth: i64,
}

impl Found {
    fn new(path: PathBuf, metadata: &Metadata) -> Self {
        Self {
            path,
            identity: file_identity(metadata),
            size: metadata.len(),
            stamp: stamp(metadata),
            birth: birth_secs(metadata),
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
}

fn index_path(dir: &Path, source: Source) -> PathBuf {
    dir.join(format!("index-{}.json", source.label()))
}

fn copy_key_text(path: &Path) -> String {
    super::super::discovery::transcript_copy_key(path)
        .iter()
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Every `.jsonl` (and compressed `.jsonl.zst`) under the roots.
fn walk(roots: &[PathBuf]) -> (BTreeMap<String, Vec<Found>>, BTreeSet<String>) {
    fn visit(dir: &Path, found: &mut BTreeMap<String, Vec<Found>>, zst: &mut BTreeSet<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                visit(&path, found, zst);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(".jsonl") {
                found
                    .entry(copy_key_text(&path))
                    .or_default()
                    .push(Found::new(path, &metadata));
            } else if let Some(stem) = name.strip_suffix(".zst") {
                if stem.ends_with(".jsonl") {
                    zst.insert(copy_key_text(&path.with_file_name(stem)));
                }
            }
        }
    }
    let mut found = BTreeMap::new();
    let mut zst = BTreeSet::new();
    for root in roots {
        visit(root, &mut found, &mut zst);
    }
    (found, zst)
}

pub(super) fn run_source(
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
    let (mut index, first_run) = match read_json::<Index>(&path) {
        Ok(Some(index)) if index.schema == STATE_SCHEMA => (index, false),
        Ok(None) => (Index::new(now_secs), true),
        // Bad pins: every file starts over as found-but-old; scopes keep
        // their checkpoints, which win once a file grows.
        _ => {
            stats.bad_state += 1;
            let mut index = Index::new(now_secs);
            index.last_scan_started = Some(now_secs);
            (index, false)
        }
    };
    let previous_scan = index.last_scan_started;
    index.last_scan_started = Some(now_secs);

    // Discovery: pick one copy per key and decide what needs reading.
    let (found, archived) = walk(roots);
    let mut work: Vec<Work> = Vec::new();
    let mut present: BTreeMap<String, Found> = BTreeMap::new();
    for (key, mut copies) in found {
        let chosen = match index.files.get(&key) {
            Some(pin) => copies
                .iter()
                .position(|copy| copy.identity == (pin.dev, pin.ino))
                .or_else(|| {
                    copies
                        .iter()
                        .position(|copy| copy.path == Path::new(&pin.path))
                }),
            None => None,
        };
        let chosen = match chosen {
            Some(index) => copies.swap_remove(index),
            None => {
                // The newest copy (ties: path order), as the v1 reader does.
                copies.sort_by(|a, b| b.stamp.cmp(&a.stamp).then_with(|| a.path.cmp(&b.path)));
                copies.remove(0)
            }
        };
        stats.duplicates += copies.len() as u64;
        present.insert(key, chosen);
    }
    for (key, file) in &present {
        let needs = match index.files.get_mut(key) {
            None => {
                let new = if first_run {
                    now_secs - file.stamp.0 <= LIVE_AT_INSTALL.as_secs() as i64
                } else {
                    previous_scan.is_some_and(|last| file.birth >= last)
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
                        start: if new { 0 } else { file.size },
                        size: file.size,
                        mtime: file.stamp,
                        // Files live at install read from their start
                        // within the repair budget.
                        waiting: new && first_run,
                        done: false,
                        last_seen: today,
                    },
                );
                new && file.size > 0
            }
            Some(pin) => {
                pin.last_seen = today;
                if pin.done {
                    continue;
                }
                let same = file.identity == (pin.dev, pin.ino);
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
                pin.waiting
                    || !same
                    || file.size != pin.size
                    || file.stamp != pin.mtime
                    || (pin.scope.is_some() && pin.start < file.size)
            }
        };
        if needs {
            work.push(Work {
                key: key.clone(),
                found: file.clone(),
                mode: Mode::Forward,
            });
        }
    }
    for key in &archived {
        if present.contains_key(key) {
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
    work.retain(|item| {
        let Some(pin) = index.files.get_mut(&item.key) else {
            return false;
        };
        if pin.scope.is_some() {
            return true;
        }
        let cwd = match first_existing_cwd_from_jsonl(&item.found.path, run.deadline) {
            Ok(Some(cwd)) => cwd,
            Ok(None) => {
                stats.unscoped += 1;
                pin.size = item.found.size;
                pin.mtime = item.found.stamp;
                return false;
            }
            Err(_) => {
                stats.scan_errors += 1;
                return false;
            }
        };
        let scope_id = match index.cwd_scopes.get(&cwd) {
            Some(scope) => scope.clone(),
            None => {
                let Some((scope, info)) = run.resolver.resolve(Path::new(&cwd)) else {
                    stats.scan_errors += 1;
                    return false;
                };
                index.cwd_scopes.insert(cwd, scope.clone());
                // First sight wins: the saved key never changes.
                index.scope_info.entry(scope.clone()).or_insert(info);
                scope
            }
        };
        pin.scope = Some(scope_id);
        true
    });

    // Full reads waiting for budget, newest first.
    let mut waiting: Vec<&mut Work> = work
        .iter_mut()
        .filter(|item| index.files.get(&item.key).is_some_and(|pin| pin.waiting))
        .collect();
    waiting.sort_by_key(|item| std::cmp::Reverse(item.found.stamp));
    for item in waiting {
        item.mode = grant(run, &mut stats, item.found.size);
    }
    work.retain(|item| {
        let waiting = index.files.get(&item.key).is_some_and(|pin| pin.waiting);
        !waiting || item.mode != Mode::Forward
    });

    // Pins first, so no file ever counts in two scopes.
    if write_json(&path, &index).is_err() {
        stats.scopes_failed += 1;
        finish(&mut stats, started, cpu_started);
        return stats;
    }

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

    let mut uploaded = BTreeSet::new();
    for (_, scope_id) in order {
        if stats.cut {
            break;
        }
        let items = by_scope.remove(&scope_id).unwrap_or_default();
        let Some(scope) = process_scope(
            run, source, &scope_id, items, &mut index, &present, window, &mut stats,
        ) else {
            continue;
        };
        if let Some(target) = target.as_mut() {
            let outcome = upload_scope(&run.state_dir, source, &scope, target, run.now, window);
            count_upload(outcome, &mut stats);
            uploaded.insert(scope_id);
        }
    }
    let _ = write_json(&path, &index);

    if let Some(target) = target.as_mut() {
        upload_other_scopes(run, source, &index, &uploaded, target, window, &mut stats);
    }
    finish(&mut stats, started, cpu_started);
    stats
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

#[allow(clippy::too_many_arguments)]
fn process_scope(
    run: &mut Run,
    source: Source,
    scope_id: &str,
    mut items: Vec<Work>,
    index: &mut Index,
    present: &BTreeMap<String, Found>,
    window: Window,
    stats: &mut SourceStats,
) -> Option<Scope> {
    let path = scope_path(&run.state_dir, source, scope_id);
    let info = index
        .scope_info
        .get(scope_id)
        .cloned()
        .unwrap_or(ScopeInfo {
            workspace_hash: scope_id.to_string(),
            workspace_path: String::new(),
            identity: Default::default(),
        });
    let loaded = match load_scope(&path, source, scope_id) {
        // A scope the pins know but whose state is gone is bad state too.
        Ok(None) if index.scope_generations.contains_key(scope_id) => Err(()),
        loaded => loaded,
    };
    let mut scope = match loaded {
        Ok(Some(scope)) => scope,
        Ok(None) => Scope::new(scope_id, info),
        Err(()) => {
            // Bad state: read the scope's files again from their start,
            // within the budget, newest first; the rest wait.
            stats.bad_state += 1;
            let mut files: Vec<(String, Found)> = index
                .files
                .iter()
                .filter(|(_, pin)| pin.scope.as_deref() == Some(scope_id) && !pin.done)
                .filter_map(|(key, _)| Some((key.clone(), present.get(key)?.clone())))
                .collect();
            files.sort_by_key(|(_, found)| std::cmp::Reverse(found.stamp));
            items.clear();
            for (key, found) in files {
                let mode = grant(run, stats, found.size);
                if let Some(pin) = index.files.get_mut(&key) {
                    pin.waiting = mode == Mode::Forward;
                }
                if mode != Mode::Forward {
                    items.push(Work { key, found, mode });
                }
            }
            Scope::new(scope_id, info)
        }
    };
    let generation = scope.generation + 1;
    let own_dir = ownership_dir(&run.state_dir, source, scope_id);
    let mut ownership = match source {
        Source::Claude => {
            let ownership = Ownership::load(&own_dir, &scope.ownership_logs);
            stats.ownership_lost += ownership.lost_entries;
            Some(ownership)
        }
        Source::Codex => None,
    };
    // Creation order: the transcript created first owns copied records.
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
    let today = window.today;
    let mut read_files: Vec<(String, Checkpoint)> = Vec::new();
    for item in items {
        if Instant::now() >= run.deadline {
            stats.cut = true;
            break;
        }
        let Some(start) = index.files.get(&item.key).map(|pin| pin.start) else {
            continue;
        };
        match read_file(
            run,
            source,
            &mut scope,
            &item,
            start,
            ownership.as_mut(),
            window,
            generation,
            stats,
        ) {
            Some(Outcome::Read(checkpoint)) => {
                read_files.push((item.key, *checkpoint));
            }
            Some(Outcome::Waiting) => {
                if let Some(pin) = index.files.get_mut(&item.key) {
                    pin.waiting = true;
                }
            }
            None => {}
        }
        if let Some(ownership) = ownership.as_ref() {
            stats.peak_accounted_bytes = stats
                .peak_accounted_bytes
                .max(ownership.accounted_bytes() + scope.agg.accounted_bytes());
        }
    }

    let read_keys: Vec<String> = read_files.iter().map(|(key, _)| key.clone()).collect();
    scope.files.extend(read_files);
    // Checkpoints follow their pins: a file forgotten by the pins is gone.
    scope.files.retain(|key, checkpoint| {
        let keep = index
            .files
            .get(key)
            .is_some_and(|pin| pin.scope.as_deref() == Some(scope_id));
        if keep {
            if index
                .files
                .get(key)
                .is_some_and(|pin| pin.last_seen == today)
            {
                checkpoint.last_seen = today;
            }
            checkpoint
                .contribution
                .retain(|(day, _, _)| *day >= window.floor);
        }
        keep
    });
    scope.agg.prune(window);
    if scope
        .agg
        .day_generation
        .values()
        .any(|day_generation| *day_generation == generation)
    {
        scope.generation = generation;
    }

    // Commit: ownership log, then the scope (which names the log length).
    if let Some(ownership) = ownership.as_ref() {
        match ownership.write(&own_dir, &scope.ownership_logs, window) {
            Ok(lengths) => scope.ownership_logs = lengths,
            Err(_) => {
                stats.scopes_failed += 1;
                return None;
            }
        }
    }
    #[cfg(test)]
    if tests::fail_scope_commit() {
        stats.scopes_failed += 1;
        return None;
    }
    match save_scope(&path, source, &scope) {
        Ok(bytes) => stats.state_bytes += bytes,
        Err(_) => {
            stats.scopes_failed += 1;
            return None;
        }
    }
    if ownership.is_some() {
        remove_unreferenced(&own_dir, &scope.ownership_logs);
    }
    stats.scopes_committed += 1;
    for key in read_keys {
        let (Some(pin), Some(checkpoint)) = (index.files.get_mut(&key), scope.files.get(&key))
        else {
            continue;
        };
        pin.start = checkpoint.offset;
        pin.size = checkpoint.size;
        pin.mtime = checkpoint.mtime;
        pin.dev = checkpoint.dev;
        pin.ino = checkpoint.ino;
        pin.path = checkpoint.path.clone();
        pin.waiting = false;
    }
    index
        .scope_generations
        .insert(scope_id.to_string(), scope.generation);
    Some(scope)
}

enum Outcome {
    Read(Box<Checkpoint>),
    Waiting,
}

#[allow(clippy::too_many_arguments)]
fn read_file(
    run: &mut Run,
    source: Source,
    scope: &mut Scope,
    item: &Work,
    pin_start: u64,
    ownership: Option<&mut Ownership>,
    window: Window,
    generation: u64,
    stats: &mut SourceStats,
) -> Option<Outcome> {
    let file = File::open(&item.found.path).ok()?;
    let metadata = file.metadata().ok()?;
    let size = metadata.len();
    let identity = file_identity(&metadata);
    let file_stamp = stamp(&metadata);
    let existing = scope.files.remove(&item.key);
    let mut mode = item.mode;
    if mode == Mode::Forward {
        if let Some(checkpoint) = &existing {
            if checkpoint.status == Status::Done {
                scope.files.insert(item.key.clone(), existing?);
                return None;
            }
            let rewritten = size < checkpoint.offset
                || !fingerprints_match(&file, checkpoint)
                || checkpoint.parse.clone().into_state().is_none();
            if rewritten {
                mode = grant(run, stats, size);
                if mode == Mode::Forward {
                    scope.files.insert(item.key.clone(), existing?);
                    return Some(Outcome::Waiting);
                }
            }
        }
    }
    let file_id = existing
        .as_ref()
        .map_or_else(|| scope.allocate_file_id(), |checkpoint| checkpoint.file_id);
    let created = existing
        .as_ref()
        .map_or(item.found.birth, |checkpoint| checkpoint.created);
    let (mut checkpoint, mut state) = match (mode, existing) {
        (Mode::Forward, Some(checkpoint)) => {
            let state = checkpoint.parse.clone().into_state()?;
            (checkpoint, state)
        }
        (mode, existing) => {
            let offset = match mode {
                Mode::Full => 0,
                Mode::RestartAtEnd => size,
                Mode::Forward => pin_start.min(size),
            };
            let mut contribution = Vec::new();
            if let Some(old) = existing {
                if mode == Mode::Full {
                    // Replace this file's earlier share.
                    if let Some(old) = load_contribution(old.contribution) {
                        scope.agg.subtract(&old, generation);
                    }
                } else {
                    contribution = old.contribution;
                }
            }
            if mode == Mode::Forward && offset == 0 {
                stats.new_files += 1;
            }
            let state = new_parse_state(source, &item.found.path, offset);
            (
                Checkpoint {
                    path: String::new(),
                    dev: 0,
                    ino: 0,
                    file_id,
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
                },
                state,
            )
        }
    };
    let mut contribution =
        load_contribution(std::mem::take(&mut checkpoint.contribution)).unwrap_or_default();
    let reader_file = file.try_clone().ok()?;
    let mut out = LineSink {
        sink: super::aggregate::Sink {
            agg: &mut scope.agg,
            contribution: &mut contribution,
            window,
            generation,
        },
        ownership,
        file_id,
        fallback_day: window.today,
        stats: &mut stats.lines,
    };
    let end = match read_lines(
        reader_file,
        checkpoint.offset,
        size,
        checkpoint.skipping,
        source,
        &mut state,
        &mut out,
        run.deadline,
    ) {
        Ok(end) => end,
        Err(_) => {
            stats.scan_errors += 1;
            return None;
        }
    };
    out.sink.session_start(&state.session, state.min_ts);
    stats.files_read += 1;
    if mode == Mode::Full {
        stats.bytes_repair += end.bytes;
    } else {
        stats.bytes_new += end.bytes;
    }
    stats.cut |= end.cut;
    stats.peak_accounted_bytes = stats
        .peak_accounted_bytes
        .max(end.buffer_bytes + state.accounted_bytes() + scope.agg.accounted_bytes());
    state.open.retain(|(day, _, _)| *day >= window.floor);
    let (head, tail) = fingerprints(&file, end.offset).ok()?;
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
    checkpoint.contribution = store_contribution(&contribution);
    Some(Outcome::Read(Box::new(checkpoint)))
}

fn count_upload(outcome: UploadOutcome, stats: &mut SourceStats) {
    match outcome {
        UploadOutcome::Uploaded => stats.uploaded += 1,
        UploadOutcome::Unchanged => stats.upload_unchanged += 1,
        UploadOutcome::Failed => stats.upload_failed += 1,
    }
}

/// Scopes not read in this run: retry an unacknowledged change, or refresh
/// a week-old upload.
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
        if done.contains(scope_id) {
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
        let outcome = upload_scope(&run.state_dir, source, &scope, target, run.now, window);
        count_upload(outcome, stats);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::cell::Cell;

    thread_local! {
        static FAIL_SCOPE_COMMIT: Cell<bool> = const { Cell::new(false) };
    }

    /// Simulate a crash between the ownership log write and the scope commit.
    pub(in super::super) fn set_fail_scope_commit(fail: bool) {
        FAIL_SCOPE_COMMIT.with(|cell| cell.set(fail));
    }

    pub(super) fn fail_scope_commit() -> bool {
        FAIL_SCOPE_COMMIT.with(Cell::get)
    }
}
