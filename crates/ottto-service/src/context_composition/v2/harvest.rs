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
    birth_secs, born_secs, file_identity, fingerprints, fingerprints_match, prefix_matches,
    read_json, stamp, write_json, Checkpoint, Index, Pin, RunRecord, Stamp, Status, StoredParse,
};
use super::file::{head_cwds, new_parse_state, read_lines, LineSink, LineStats, Names, Source};
use super::scope::{
    linked_worktrees, load_scope, resolved_missing, save_scope, scope_path, GitScopeResolver,
    Scope, ScopeInfo, ScopeResolver,
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
            let mut worktrees = WorktreeCache::default();
            loop {
                let wait = MIN_UPTIME.saturating_sub(started.elapsed());
                if !wait.is_zero() {
                    std::thread::sleep(wait);
                }
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
        "context_composition_v2_metrics at={at} source={} bytes_new={} bytes_repair={} bytes_head={} bytes_failed={} files_read={} files_failed={} quarantined={} new_files={} dormant_found={} lines={} prefix_skipped={} classifier_skipped={} too_long={} bad_lines={} dropped_calls={} dropped_items={} unnamed_files={} name_lookups_skipped={} web_search_in_call={} scan_errors={} repair_waiting={} repair_waiting_bytes={} repair_restarted={} bad_state={} pins_rebuilt={} moved={} switched={} archived={} duplicates={} unscoped={} scopes_committed={} scopes_failed={} uploaded={} upload_unchanged={} upload_failed={} upload_dropped_non_v2={} upload_dropped_unsafe={} cut={} cpu_ms={} wall_ms={} peak_accounted_bytes={} state_bytes={}",
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
        stats.bad_state,
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
#[derive(Default)]
pub(super) struct WorktreeCache {
    seen: BTreeMap<Source, SeenIndex>,
}

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
    pub(super) bad_state: u64,
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

/// Bad pins: rebuild them from the scope states, whose checkpoints hold each
/// file's path, identity, offset, size and scope. Files no scope holds start
/// over as found-but-old.
fn rebuild_pins(state_dir: &Path, source: Source, index: &mut Index, today: Day) -> u64 {
    let Ok(entries) = fs::read_dir(state_dir.join("scopes")) else {
        return 0;
    };
    let prefix = format!("{}-", source.label());
    let mut rebuilt = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(scope_id) = name
            .to_str()
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|id| !id.contains('.'))
            .map(str::to_string)
        else {
            continue;
        };
        let Ok(Some(scope)) = load_scope(&entry.path(), source, &scope_id) else {
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
        _ => {
            stats.bad_state += 1;
            let mut index = Index::new(now_secs);
            index.last_scan_started = Some(now_secs);
            stats.pins_rebuilt = rebuild_pins(&run.state_dir, source, &mut index, today);
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
                        first_seen: now_secs,
                        unscoped: false,
                        failures: 0,
                        quarantined: false,
                        head: Default::default(),
                        tail: Default::default(),
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
    match write_json(&path, &index) {
        Ok(bytes) => stats.state_bytes += bytes,
        Err(_) => {
            stats.scopes_failed += 1;
            finish(&mut stats, started, cpu_started);
            return stats;
        }
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
    }
    stats.name_lookups_skipped = names.skipped();
    tidy_index(&mut index, today);
    if let Ok(bytes) = write_json(&path, &index) {
        stats.state_bytes += bytes;
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
    let loaded = match load_scope(&path, source, scope_id) {
        // A scope the pins know but whose state is gone is bad state too.
        Ok(None) if index.scope_generations.contains_key(scope_id) => Err(()),
        loaded => loaded,
    };
    let mut scope = match loaded {
        Ok(Some(scope)) => scope,
        Ok(None) => {
            forget_upload(&run.state_dir, source, scope_id);
            Scope::new(scope_id, info)
        }
        Err(()) => {
            // Bad state: read the scope's files again from their start,
            // within the budget, newest first; the rest wait.
            stats.bad_state += 1;
            let mut files: Vec<(String, Found)> = index
                .files
                .iter()
                .filter(|(_, pin)| {
                    pin.scope.as_deref() == Some(scope_id) && !pin.done && !pin.quarantined
                })
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
            forget_upload(&run.state_dir, source, scope_id);
            Scope::new(scope_id, info)
        }
    };
    // The loaded checkpoints and totals stay in memory for the whole scope;
    // loading held the file's bytes next to them.
    let held = scope.accounted_bytes();
    let loaded_bytes = fs::metadata(&path).map_or(0, |metadata| metadata.len() as usize);
    stats.peak_accounted_bytes = stats.peak_accounted_bytes.max(held + loaded_bytes);
    let generation = scope.generation + 1;
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
    let today = window.today;
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
        checkpoint.contribution.prune(window.floor);
        true
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

    #[cfg(test)]
    if tests::fail_scope_commit() {
        stats.scopes_failed += 1;
        return None;
    }
    match save_scope(&path, source, &scope) {
        Ok(bytes) => {
            stats.state_bytes += bytes;
            // Writing serializes the whole scope into one buffer.
            stats.peak_accounted_bytes = stats
                .peak_accounted_bytes
                .max(scope.accounted_bytes() + bytes as usize);
        }
        Err(_) => {
            stats.scopes_failed += 1;
            return None;
        }
    }
    stats.scopes_committed += 1;
    for key in repin {
        if let Some(pin) = index.files.get_mut(&key) {
            pin.scope = Some(scope_id.to_string());
        }
    }
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
        pin.head = checkpoint.head;
        pin.tail = checkpoint.tail;
        pin.waiting = false;
        pin.failures = 0;
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
    let opened = File::open(&item.found.path)
        .and_then(|file| Ok((file.metadata()?, file.try_clone()?, file)));
    let Ok((metadata, reader_file, file)) = opened else {
        stats.scan_errors += 1;
        return Ok(None);
    };
    let size = metadata.len();
    let identity = file_identity(&metadata);
    let file_stamp = stamp(&metadata);
    let existing = scope.files.get(&item.key);
    let mut mode = item.mode;
    if mode == Mode::Forward {
        if let Some(checkpoint) = existing {
            if checkpoint.status == Status::Done {
                return Ok(None);
            }
            let rewritten = size < checkpoint.offset
                || !fingerprints_match(&file, checkpoint)
                || checkpoint.parse.clone().into_state().is_none();
            if rewritten {
                mode = grant(run, stats, size);
                if mode == Mode::Forward {
                    return Ok(Some(Outcome::Waiting));
                }
            }
        }
    }
    // The scope keeps this checkpoint until the read succeeds.
    let existing = existing.cloned();
    let created = existing.as_ref().map_or_else(
        || created_at(item.found.born, first_seen),
        |checkpoint| checkpoint.created,
    );
    let mut old_share = None;
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
            let (state, head_bytes) = new_parse_state(source, &item.found.path, offset);
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
        size,
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
        stats.bytes_new += end.bytes;
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

/// A rebuilt scope starts its generations again: drop the upload
/// acknowledgment so every rebuilt day is sent.
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
