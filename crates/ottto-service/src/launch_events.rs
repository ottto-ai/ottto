//! Content-free launch-event intake: the Direct controller -> worker edge.
//!
//! Ottto can already draw Claude -> Claude and Codex -> Codex family trees,
//! because each provider owns identifiers for its own subagents. It cannot draw
//! the edge where a controller in one app starts a worker somewhere else: no
//! provider owns both halves. The 2026-07-29 cross-app evidence contract refused
//! to guess that edge from timing, repository, worktree, model, or process
//! ancestry, and named the only acceptable Direct source -- a launcher that
//! emits BOTH exact session references in a typed event.
//!
//! This module is the collector side of that contract. An instrumented launcher
//! writes one JSON file per launch into `~/.ottto/launch-events/pending/`; this
//! module reads it, validates it far more strictly than it needs to, and turns
//! an accepted event into ordinary session attribution facts on the WORKER
//! session. It never invents an edge, never widens the schema, and never reads
//! anything the event file does not literally contain.
//!
//! # What an event may contain
//!
//! Exactly the nine keys of `agent_launch.v1`, all of them identifiers, fixed
//! enums, null source-inapplicable identifiers, or a timestamp:
//!
//! ```json
//! {
//!   "schema": "agent_launch.v1",
//!   "controller_session_ref": "<uuid>",
//!   "worker_session_ref": "<uuid>",
//!   "relationship_kind": "launched",
//!   "workflow_ref": "<uuid>",
//!   "pr_ref": 1653,
//!   "launch_ts": "2026-08-09T15:17:21Z",
//!   "capture_source": "launcher_event:landing_repair",
//!   "evidence": "direct"
//! }
//! ```
//!
//! There is deliberately no field that can hold free text. A path, a prompt
//! fragment, an argv element, or an environment value cannot survive the UUID,
//! integer, and enum checks below, so it can never reach a fact. An extra key --
//! even a harmless-looking one -- rejects the whole file rather than being
//! ignored, because "ignore what you do not understand" is how a content-free
//! channel stops being content-free.
//!
//! # Fail closed
//!
//! An absent edge is recoverable; a wrong edge is not. Every ambiguous case
//! therefore yields no fact: an unknown schema version, a malformed reference, a
//! filename that does not match the (controller, worker, attempt) triple it
//! claims, a session that launched itself, an uninstrumented launcher family,
//! and -- most importantly -- two different controllers claiming the same
//! worker, which drops BOTH events instead of picking one.
//!
//! # Lifecycle
//!
//! `pending/` is an inbox, drained in bounded lookup continuations. A valid event moves to
//! `processed/` and stays readable there for [`PROCESSED_RETENTION`]; a rejected
//! one moves to `rejected/` for [`REJECTED_RETENTION`] with a reason CODE in the
//! log and never its contents. After intake, a read-only sweep checks both
//! pending and processed claims: directory mutation during draining must never
//! hide a pending conflict. Only a complete demanded sweep supplies facts.
//! Retained events remain available when a transcript is first imported,
//! re-scanned, or replayed; they are not consumed with its first observation. Filenames are the SHA-256 of the triple, so re-emitting the same
//! launch resolves to the same path and can never produce a second edge.
//!
//! Intake files a processed event as `<worker>.<digest>.json`, a filename
//! index: a lookup reads `processed/` names only and opens just the demanded
//! workers' files, so its cost follows the demand, not the 30-day store.
//! Every claim on one worker shares that prefix, so the two-controllers rule
//! still sees all of them. A legacy `<digest>.json` name, written by an older
//! release, is re-filed under its worker by the slow sweep, before the claim
//! passes stamp the directories, so later lookups skip it by name too. The
//! slow sweep, which also expires old events, runs at most once a day per
//! process, never as part of each lookup.

use crate::hex::is_uuid;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// The only schema this intake understands. A file naming any other version is
/// rejected outright: a v2 emitter and a v1 reader disagreeing about what a
/// field means is exactly the case where a wrong edge gets minted quietly.
const LAUNCH_EVENT_SCHEMA: &str = "agent_launch.v1";
const RELATIONSHIP_KIND: &str = "launched";
const EVIDENCE_STRENGTH: &str = "direct";

/// Parser version for the evidence of every launch-derived fact.
///
/// The backend hard-validates this against `[a-z][a-z0-9_]{0,23}:v[0-9]{1,4}`
/// and 422s the WHOLE batch on a miss, so the launcher family never rides here
/// -- it rides as `agent_kind`, which is an allowlisted attribution field.
pub(crate) const LAUNCH_EVENT_SOURCE_VERSION: &str = "launcher_event:v1";

/// Evidence kind for launch-derived facts. This identifies a local launcher
/// assertion, with provider evidence taking precedence. It supplies no provider,
/// account or payer authentication. Unsupported consumers may drop these facts
/// while retaining the session, so the truthful token must remain unchanged.
pub(crate) const LAUNCH_EVENT_EVIDENCE_KIND: &str = "launcher_event";

const DROP_ROOT_DIR: &str = ".ottto/launch-events";
const PENDING_SUBDIR: &str = "pending";
const PROCESSED_SUBDIR: &str = "processed";
const REJECTED_SUBDIR: &str = "rejected";

/// A well-formed event is ~360 bytes. The cap exists so a truncated, appended,
/// or hostile file is refused by `stat` before it is ever read into memory.
const MAX_EVENT_FILE_BYTES: u64 = 4 * 1_024;
/// Bound a continuation, not the retained store's completeness. Every entry
/// participates before a demanded worker can receive a unique edge.
const LOOKUP_ENTRIES_PER_STEP: usize = 256;
/// Only the current transcript demand batch is retained; later batches use the
/// same complete store walk, so this is never a global worker admission cap.
pub(crate) const MAX_DEMANDED_WORKERS: usize = 512;

/// How long an accepted event stays joinable.
///
/// It has to outlive every path that can bring a worker transcript back to the
/// scanner long after the launch: a stalled upload, a checkpoint reset, an
/// explicit replay, or a machine that was simply off. Thirty days is the same
/// order as the backfill window and costs a few hundred bytes per launch.
const PROCESSED_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Rejected files are kept only long enough to be diagnosed by hand.
const REJECTED_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Reuse a completed demanded batch within one source context for at most a
/// minute. Fresh contexts always revalidate files, including same-name edits.
const INVENTORY_TTL: Duration = Duration::from_secs(60);

/// Instrumented launcher families, and the worker role each one starts.
///
/// This is an allowlist in both directions: an unlisted `capture_source` cannot
/// claim Direct evidence, and the `agent_kind` a launch produces is chosen HERE
/// rather than read from the file, so the event can never supply its own label.
const CAPTURE_SOURCE_LANDING_REPAIR: &str = "launcher_event:landing_repair";
const CAPTURE_SOURCE_GPT_SOL_RELAY: &str = "launcher_event:gpt_sol_relay";
const CAPTURE_SOURCE_OPUS_CLI_AGENT: &str = "launcher_event:opus_cli_agent";
const CAPTURE_SOURCE_HELPER_AGENT: &str = "launcher_event:helper_agent";
const CAPTURE_SOURCES: &[(&str, &str)] = &[
    (CAPTURE_SOURCE_LANDING_REPAIR, "pr-fixer"),
    (CAPTURE_SOURCE_GPT_SOL_RELAY, "gpt-sol"),
    (CAPTURE_SOURCE_OPUS_CLI_AGENT, "opus-cli-agent"),
    (CAPTURE_SOURCE_HELPER_AGENT, "helper-agent"),
];

/// How often one process walks `processed/` to delete expired events. Lookups
/// never stat files they do not open; expiry is this slow sweep's job.
const PROCESSED_SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Lookup phases, in order. Only intake and re-filing change the directories;
/// both run before the claim passes stamp them, so neither unsettles the
/// lookup that made the change.
const PHASE_INTAKE: usize = 0;
/// Slow sweep only: re-file legacy `<digest>.json` processed names.
const PHASE_REFILE: usize = 1;
const PHASE_PENDING_CLAIMS: usize = 2;
const PHASE_PROCESSED_CLAIMS: usize = 3;
/// Slow sweep only: remove expired processed events.
const PHASE_PROCESSED_EXPIRY: usize = 4;
const PHASE_REJECTED_EXPIRY: usize = 5;

/// One accepted launch event, reduced to what a fact may carry.
///
/// `pr_ref` is validated on the way in -- a non-integer is a broken emitter and
/// rejects the file -- but is deliberately NOT retained: there is no allowlisted
/// attribution field for a pull-request number, and a value with nowhere honest
/// to go does not belong in daemon memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LaunchEvent {
    /// The session that ordered the launch. Becomes `parent_session_ref`.
    pub(crate) controller_session_ref: String,
    /// The session the launcher started. This is the fact's owner.
    pub(crate) worker_session_ref: String,
    /// The launcher's own attempt id. Becomes `workflow_ref`.
    pub(crate) workflow_ref: Option<String>,
    /// Worker role, resolved from the capture source allowlist.
    pub(crate) agent_kind: &'static str,
}

#[derive(Default)]
pub(crate) struct LaunchEventInventory {
    root: Option<PathBuf>,
    lookup: Mutex<Lookup>,
}

#[derive(Default)]
struct Lookup {
    workers: BTreeMap<String, Option<LaunchEvent>>,
    ambiguous: BTreeSet<String>,
    phase: usize,
    entries: Option<fs::ReadDir>,
    complete: bool,
    failed: bool,
    /// This lookup runs the slow sweep (re-file and expiry).
    sweep: bool,
    loaded_at: Option<Instant>,
    /// Counts only, for the lookup diagnostic: processed files skipped by
    /// name, event files opened, legacy names re-filed, and expired files the
    /// slow sweep removed.
    skipped_by_name: u64,
    opened: u64,
    refiled: u64,
    swept: u64,
    pending_stamp: Option<SystemTime>,
    processed_stamp: Option<SystemTime>,
}

impl LaunchEventInventory {
    // The old process-wide full-inventory cache hid every worker outside its
    // retained prefix. A context now retains only its current demand batch.
    pub(crate) fn cached(home: &Path) -> Self {
        Self::refresh(home)
    }

    pub(crate) fn refresh(home: &Path) -> Self {
        Self {
            root: Some(home.join(DROP_ROOT_DIR)),
            lookup: Mutex::new(Lookup::default()),
        }
    }

    /// One bounded continuation. false means that uniqueness remains unproved;
    /// intake and read-only claim passes are separate so moving an inbox entry
    /// cannot hide a claim skipped by the platform's directory iterator.
    /// errors must remain owed by the native scanner, never become a negative hit.
    pub(crate) fn prepared(&self, workers: &[String]) -> bool {
        let Ok(lookup) = self.lookup.lock() else {
            return false;
        };
        if self.root.is_none() || !workers.iter().any(|worker| is_uuid(worker)) {
            return true;
        }
        lookup.complete
            && !lookup.failed
            && lookup
                .loaded_at
                .is_some_and(|at| at.elapsed() < INVENTORY_TTL)
            && workers
                .iter()
                .filter(|worker| is_uuid(worker))
                .all(|worker| lookup.workers.contains_key(&worker.to_ascii_lowercase()))
    }

    pub(crate) fn prepare_step(&self, workers: &[String]) -> Result<bool, ()> {
        let mut lookup = self.lookup.lock().map_err(|_| ())?;
        let Some(root) = self.root.as_deref() else {
            return Ok(true);
        };
        let mut wanted = BTreeSet::new();
        for worker in workers.iter().filter(|worker| is_uuid(worker)) {
            wanted.insert(worker.to_ascii_lowercase());
            if wanted.len() > MAX_DEMANDED_WORKERS {
                eprintln!("ottto-service: launch lookup demand exceeds bounded batch: limit={MAX_DEMANDED_WORKERS}; split demand before retry");
                return Err(());
            }
        }
        if wanted.is_empty() {
            return Ok(true);
        }
        let fresh = lookup
            .loaded_at
            .is_some_and(|at| at.elapsed() < INVENTORY_TTL)
            && lookup.pending_stamp == directory_stamp(&root.join(PENDING_SUBDIR))
            && lookup.processed_stamp == directory_stamp(&root.join(PROCESSED_SUBDIR));
        if lookup.complete
            && fresh
            && wanted
                .iter()
                .all(|worker| lookup.workers.contains_key(worker))
        {
            return if lookup.failed { Err(()) } else { Ok(true) };
        }
        if lookup.complete || lookup.workers.is_empty() {
            *lookup = Lookup {
                workers: wanted
                    .iter()
                    .cloned()
                    .map(|worker| (worker, None))
                    .collect(),
                ..Lookup::default()
            };
        }
        // A header-owned worker can arrive while a different batch is sweeping.
        // Finish the current sweep, but yield before certifying that new demand.
        let demand_matches = wanted
            .iter()
            .all(|worker| lookup.workers.contains_key(worker));
        for _ in 0..LOOKUP_ENTRIES_PER_STEP {
            if lookup.entries.is_none() {
                // Re-filing and expiry of processed events are a slow sweep,
                // not part of every lookup.
                if lookup.phase == PHASE_REFILE {
                    lookup.sweep = processed_sweep_due(root);
                }
                if matches!(lookup.phase, PHASE_REFILE | PHASE_PROCESSED_EXPIRY) && !lookup.sweep {
                    if advance_phase(root, &mut lookup) {
                        return finish_lookup(root, &mut lookup).map(|_| demand_matches);
                    }
                    continue;
                }
                let subdir = match lookup.phase {
                    PHASE_INTAKE | PHASE_PENDING_CLAIMS => PENDING_SUBDIR,
                    PHASE_REFILE | PHASE_PROCESSED_CLAIMS | PHASE_PROCESSED_EXPIRY => {
                        PROCESSED_SUBDIR
                    }
                    _ => REJECTED_SUBDIR,
                };
                match fs::read_dir(root.join(subdir)) {
                    Ok(entries) => lookup.entries = Some(entries),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if advance_phase(root, &mut lookup) {
                            return finish_lookup(root, &mut lookup).map(|_| demand_matches);
                        }
                        continue;
                    }
                    Err(_) => {
                        // Rejected files are maintenance only, never claims.
                        // Preserve a complete pending/processed proof when
                        // rejected-directory cleanup is unavailable.
                        lookup.failed |= lookup.phase != PHASE_REJECTED_EXPIRY;
                        return finish_lookup(root, &mut lookup).map(|_| demand_matches);
                    }
                }
            }
            match lookup.entries.as_mut().and_then(Iterator::next) {
                Some(Ok(entry)) => {
                    let path = entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                        continue;
                    }
                    // The filename index: a processed event named for its
                    // worker is opened only when that worker is demanded.
                    // Every claim on one worker shares the prefix, so the
                    // two-controllers rule still sees all of them.
                    if lookup.phase == PHASE_PROCESSED_CLAIMS {
                        if let Some(worker) = indexed_worker(&path) {
                            if !lookup.workers.contains_key(worker) {
                                lookup.skipped_by_name += 1;
                                continue;
                            }
                        }
                    }
                    match entry.file_type() {
                        Ok(kind) if kind.is_file() => {}
                        Ok(kind) if kind.is_symlink() => {
                            if lookup.phase == PHASE_INTAKE {
                                reject(&path, &root.join(REJECTED_SUBDIR), "not_regular");
                            }
                            continue;
                        }
                        Ok(_) => continue,
                        Err(_) => {
                            lookup.failed |= lookup.phase != PHASE_REJECTED_EXPIRY;
                            continue;
                        }
                    }
                    let retention = if lookup.phase == PHASE_REJECTED_EXPIRY {
                        REJECTED_RETENTION
                    } else {
                        PROCESSED_RETENTION
                    };
                    if is_expired(&path, retention) {
                        if (lookup.phase == PHASE_INTAKE || lookup.phase >= PHASE_PROCESSED_EXPIRY)
                            && fs::remove_file(&path).is_ok()
                        {
                            lookup.swept += 1;
                        }
                        continue;
                    }
                    if lookup.phase == PHASE_REFILE {
                        // One open per legacy name, once; a file that fails
                        // validation stays put for the claim pass to reject.
                        if indexed_worker(&path).is_none() {
                            lookup.opened += 1;
                            if let Ok(event) = read_and_validate(&path) {
                                if relocate_processed(&path, &root.join(PROCESSED_SUBDIR), &event) {
                                    lookup.refiled += 1;
                                }
                            }
                        }
                        continue;
                    }
                    if lookup.phase >= PHASE_PROCESSED_EXPIRY {
                        continue;
                    }
                    lookup.opened += 1;
                    match read_and_validate(&path) {
                        Ok(event) if lookup.phase == PHASE_INTAKE => {
                            if !relocate_processed(&path, &root.join(PROCESSED_SUBDIR), &event) {
                                lookup.failed = true;
                            }
                        }
                        Ok(event) => {
                            if let Some(slot) = lookup.workers.get_mut(&event.worker_session_ref) {
                                if slot.as_ref().is_some_and(|existing| existing != &event) {
                                    lookup.ambiguous.insert(event.worker_session_ref.clone());
                                } else {
                                    *slot = Some(event);
                                }
                            }
                        }
                        Err(reason) => {
                            if reason == "unreadable" {
                                lookup.failed = true;
                            } else if lookup.phase == PHASE_INTAKE {
                                reject(&path, &root.join(REJECTED_SUBDIR), reason);
                            } else {
                                // Quarantine changes the directory fence. This
                                // batch stays owed until a fresh stable sweep.
                                reject(&path, &root.join(REJECTED_SUBDIR), reason);
                                lookup.failed = true;
                            }
                        }
                    }
                }
                Some(Err(_)) => lookup.failed |= lookup.phase != PHASE_REJECTED_EXPIRY,
                None => {
                    lookup.entries = None;
                    if advance_phase(root, &mut lookup) {
                        return finish_lookup(root, &mut lookup).map(|_| demand_matches);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Only a completed demanded sweep can supply a fact. Native collection
    /// and synchronous audit callers prepare explicitly before finalization.
    /// Digest of the events naming `workers`, part of those files' source
    /// fingerprint whatever the attribution setting.
    pub(crate) fn witness(&self, workers: &[String]) -> Option<String> {
        let mut hasher = Sha256::new();
        let mut any = false;
        for worker in workers {
            if let Some(event) = self.matching(worker) {
                any = true;
                hasher.update(event.controller_session_ref.as_bytes());
                hasher.update([0]);
                hasher.update(event.worker_session_ref.as_bytes());
                hasher.update([0]);
                hasher.update(event.workflow_ref.as_deref().unwrap_or("").as_bytes());
                hasher.update([0]);
                hasher.update(event.agent_kind.as_bytes());
                hasher.update([0]);
            }
        }
        any.then(|| format!("{:x}", hasher.finalize()))
    }

    pub(crate) fn matching(&self, worker: &str) -> Option<LaunchEvent> {
        let lookup = self.lookup.lock().ok()?;
        if !lookup.complete || lookup.failed {
            return None;
        }
        lookup
            .workers
            .get(&worker.to_ascii_lowercase())
            .cloned()
            .flatten()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lookup
            .lock()
            .unwrap()
            .workers
            .values()
            .flatten()
            .count()
    }

    #[cfg(test)]
    pub(crate) fn from_events(events: Vec<LaunchEvent>) -> Self {
        Self {
            root: None,
            lookup: Mutex::new(Lookup {
                workers: events
                    .into_iter()
                    .map(|event| (event.worker_session_ref.clone(), Some(event)))
                    .collect(),
                complete: true,
                ..Lookup::default()
            }),
        }
    }
}

pub(crate) fn valid_worker(worker: &str) -> bool {
    is_uuid(worker)
}

/// The two inbox directories a launch event lands in or moves to.
pub(crate) fn inbox_dirs(home: &Path) -> [PathBuf; 2] {
    let root = home.join(DROP_ROOT_DIR);
    [root.join(PENDING_SUBDIR), root.join(PROCESSED_SUBDIR)]
}

fn directory_stamp(dir: &Path) -> Option<SystemTime> {
    fs::metadata(dir)
        .and_then(|metadata| metadata.modified())
        .ok()
}

fn advance_phase(root: &Path, lookup: &mut Lookup) -> bool {
    lookup.phase += 1;
    if lookup.phase == PHASE_PENDING_CLAIMS {
        lookup.pending_stamp = directory_stamp(&root.join(PENDING_SUBDIR));
        lookup.processed_stamp = directory_stamp(&root.join(PROCESSED_SUBDIR));
    }
    lookup.phase > PHASE_REJECTED_EXPIRY
}

fn finish_lookup(root: &Path, lookup: &mut Lookup) -> Result<bool, ()> {
    lookup.entries = None;
    if lookup.phase >= PHASE_PENDING_CLAIMS
        && (lookup.pending_stamp != directory_stamp(&root.join(PENDING_SUBDIR))
            || lookup.processed_stamp != directory_stamp(&root.join(PROCESSED_SUBDIR)))
    {
        lookup.failed = true;
    }
    for worker in &lookup.ambiguous {
        lookup.workers.insert(worker.clone(), None);
    }
    if !lookup.ambiguous.is_empty() {
        eprintln!(
            "ottto-service: launch lookup withheld ambiguous worker claims: count={}",
            lookup.ambiguous.len()
        );
    }
    if lookup.failed {
        eprintln!("ottto-service: launch lookup incomplete: local evidence changed or was unreadable; work remains owed");
    }
    // Only a lookup that opened, re-filed or removed an event file reports.
    // Skipping a filed name is a directory read, so a Mac whose retained
    // events are all filed and undemanded writes no line per scan.
    if lookup.phase != PHASE_INTAKE && lookup.opened + lookup.swept > 0 {
        crate::local_resource_diagnostics::traversal_point(
            "launch_event_lookup",
            "unknown",
            &LookupCounts {
                demanded_workers: lookup.workers.len() as u64,
                processed_skipped_by_name: lookup.skipped_by_name,
                event_files_opened: lookup.opened,
                legacy_files_refiled: lookup.refiled,
                expired_files_removed: lookup.swept,
            },
        );
    }
    lookup.complete = true;
    lookup.loaded_at = Some(Instant::now());
    if lookup.failed {
        Err(())
    } else {
        Ok(true)
    }
}

/// The lookup diagnostic: counts only, never a reference or a name.
#[derive(serde::Serialize)]
struct LookupCounts {
    demanded_workers: u64,
    processed_skipped_by_name: u64,
    event_files_opened: u64,
    legacy_files_refiled: u64,
    expired_files_removed: u64,
}

/// The worker a processed event is filed under (`<worker>.<digest>.json`), or
/// `None` for a legacy `<digest>.json` name, which the slow sweep re-files.
fn indexed_worker(path: &Path) -> Option<&str> {
    let (worker, digest) = path.file_stem()?.to_str()?.split_once('.')?;
    (is_uuid(worker)
        && !worker.bytes().any(|byte| byte.is_ascii_uppercase())
        && crate::hex::is_sha256_any_case(digest))
    .then_some(worker)
}

static LAST_PROCESSED_SWEEP: Mutex<BTreeMap<PathBuf, Instant>> = Mutex::new(BTreeMap::new());

/// Tests: the next lookup under `home` runs the processed expiry sweep.
#[cfg(test)]
pub(crate) fn forget_processed_sweep(home: &Path) {
    LAST_PROCESSED_SWEEP
        .lock()
        .unwrap()
        .remove(&home.join(DROP_ROOT_DIR));
}

/// True at most once per [`PROCESSED_SWEEP_INTERVAL`] for one drop root in
/// this process: the first lookup after a start re-files and expires, later
/// ones skip both.
fn processed_sweep_due(root: &Path) -> bool {
    let Ok(mut last) = LAST_PROCESSED_SWEEP.lock() else {
        return true;
    };
    match last.get(root) {
        Some(at) if at.elapsed() < PROCESSED_SWEEP_INTERVAL => false,
        _ => {
            last.insert(root.to_path_buf(), Instant::now());
            true
        }
    }
}

/// Small maintenance/test listing only; no whole-directory vector or sorting.
#[cfg(test)]
fn bounded_entries(dir: &Path, limit: usize) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .take(limit)
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect()
}

fn is_expired(path: &Path, retention: Duration) -> bool {
    let Ok(modified) = fs::metadata(path).and_then(|metadata| metadata.modified()) else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|age| age > retention)
        .unwrap_or(false)
}

/// Move a file into `destination`, keeping its identity-bearing name.
///
/// A same-named file already there is the SAME launch by construction (the name
/// is the triple hash), so the overwrite is what makes replay idempotent.
fn relocate(path: &Path, destination: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    if fs::create_dir_all(destination).is_err() {
        return false;
    }
    fs::rename(path, destination.join(name)).is_ok()
}

/// Move a validated pending event into `processed/`, filed under its worker:
/// `<worker>.<digest>.json`. The digest is the same triple hash, so a replayed
/// launch still lands on the same name.
fn relocate_processed(path: &Path, processed: &Path, event: &LaunchEvent) -> bool {
    if fs::create_dir_all(processed).is_err() {
        return false;
    }
    let name = format!("{}.{}.json", event.worker_session_ref, event_digest(event));
    fs::rename(path, processed.join(name)).is_ok()
}

/// Quarantine a file and say why in a CODE, never in its contents.
///
/// The only other thing logged is a 16-character prefix of the file's own name,
/// and only when that name is the expected hex digest -- so the log line is a
/// hash prefix and a fixed reason token, with no path, no reference, and no
/// payload.
fn reject(path: &Path, rejected: &Path, reason: &'static str) {
    eprintln!(
        "ottto-service: rejected a launch event ({}): {reason}",
        redacted_label(path)
    );
    let _ = relocate(path, rejected);
}

fn redacted_label(path: &Path) -> String {
    let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
        return "unnamed".to_string();
    };
    // A processed name leads with its worker id, which is never logged.
    let stem = stem.rsplit_once('.').map_or(stem, |(_, digest)| digest);
    if crate::hex::is_sha256_any_case(stem) {
        return stem[..16].to_string();
    }
    "unnamed".to_string()
}

fn read_and_validate(path: &Path) -> Result<LaunchEvent, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "unreadable")?;
    if !metadata.is_file() {
        return Err("not_regular");
    }
    if metadata.len() > MAX_EVENT_FILE_BYTES {
        return Err("oversize");
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| "unreadable")?;
    let opened = file.metadata().map_err(|_| "unreadable")?;
    if !opened.is_file() || opened.len() > MAX_EVENT_FILE_BYTES {
        return Err("oversize");
    }
    let mut raw = String::new();
    (&file)
        .take(MAX_EVENT_FILE_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidData {
                "not_utf8"
            } else {
                "unreadable"
            }
        })?;
    if raw.len() as u64 > MAX_EVENT_FILE_BYTES {
        return Err("oversize");
    }
    let after = file.metadata().map_err(|_| "unreadable")?;
    if opened.len() != after.len() || opened.modified().ok() != after.modified().ok() {
        return Err("unreadable");
    }
    let event = validate_event(&raw)?;
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or("unnamed")?;
    // `<digest>` as the emitter writes it, or `<worker>.<digest>` once filed
    // in `processed/`; either way the name must match this exact event.
    let digest = match stem.split_once('.') {
        Some((worker, digest)) if worker == event.worker_session_ref => digest,
        Some(_) => return Err("filename_mismatch"),
        None => stem,
    };
    if digest != event_digest(&event) {
        return Err("filename_mismatch");
    }
    Ok(event)
}

/// The whole trust boundary, in one function with no I/O.
pub(crate) fn validate_event(raw: &str) -> Result<LaunchEvent, &'static str> {
    let value: Value = serde_json::from_str(raw).map_err(|_| "not_json")?;
    let object: &Map<String, Value> = value.as_object().ok_or("not_object")?;

    // Membership first, in both directions: every allowlisted key present, and
    // no key outside the allowlist. An unknown key is a rejected FILE, not an
    // ignored field -- silently dropping it is how an unreviewed value ends up
    // travelling in a channel whose whole promise is that it cannot.
    const KEYS: [&str; 9] = [
        "schema",
        "controller_session_ref",
        "worker_session_ref",
        "relationship_kind",
        "workflow_ref",
        "pr_ref",
        "launch_ts",
        "capture_source",
        "evidence",
    ];
    if object.keys().any(|key| !KEYS.contains(&key.as_str())) {
        return Err("unknown_key");
    }
    if KEYS.iter().any(|key| !object.contains_key(*key)) {
        return Err("missing_key");
    }

    if string_field(object, "schema") != Some(LAUNCH_EVENT_SCHEMA) {
        return Err("unknown_schema");
    }
    if string_field(object, "relationship_kind") != Some(RELATIONSHIP_KIND) {
        return Err("bad_relationship_kind");
    }
    if string_field(object, "evidence") != Some(EVIDENCE_STRENGTH) {
        return Err("bad_evidence");
    }

    let capture_source = string_field(object, "capture_source").ok_or("unknown_capture_source")?;
    let agent_kind = CAPTURE_SOURCES
        .iter()
        .find(|(source, _)| *source == capture_source)
        .map(|(_, kind)| *kind)
        .ok_or("unknown_capture_source")?;

    let controller_session_ref =
        controller_session_ref_field(object, "controller_session_ref", capture_source)
            .ok_or("bad_controller_ref")?;
    let worker_session_ref =
        session_ref_field(object, "worker_session_ref").ok_or("bad_worker_ref")?;
    let workflow_ref = match capture_source {
        CAPTURE_SOURCE_LANDING_REPAIR => {
            Some(session_ref_field(object, "workflow_ref").ok_or("bad_workflow_ref")?)
        }
        CAPTURE_SOURCE_GPT_SOL_RELAY if object.get("workflow_ref").is_some_and(Value::is_null) => {
            None
        }
        CAPTURE_SOURCE_GPT_SOL_RELAY => return Err("bad_workflow_ref"),
        CAPTURE_SOURCE_OPUS_CLI_AGENT if object.get("workflow_ref").is_some_and(Value::is_null) => {
            None
        }
        CAPTURE_SOURCE_OPUS_CLI_AGENT => {
            Some(session_ref_field(object, "workflow_ref").ok_or("bad_workflow_ref")?)
        }
        CAPTURE_SOURCE_HELPER_AGENT if object.get("workflow_ref").is_some_and(Value::is_null) => {
            None
        }
        CAPTURE_SOURCE_HELPER_AGENT => {
            Some(session_ref_field(object, "workflow_ref").ok_or("bad_workflow_ref")?)
        }
        _ => return Err("unknown_capture_source"),
    };
    // A session cannot launch itself. Reaching here means one of the two
    // bindings is wrong, and there is no way to tell which.
    if controller_session_ref == worker_session_ref {
        return Err("self_launch");
    }

    match capture_source {
        CAPTURE_SOURCE_LANDING_REPAIR => match object.get("pr_ref").and_then(Value::as_i64) {
            Some(pr_ref) if pr_ref > 0 => {}
            _ => return Err("bad_pr_ref"),
        },
        CAPTURE_SOURCE_GPT_SOL_RELAY if object.get("pr_ref").is_some_and(Value::is_null) => {}
        CAPTURE_SOURCE_GPT_SOL_RELAY => return Err("bad_pr_ref"),
        CAPTURE_SOURCE_OPUS_CLI_AGENT if object.get("pr_ref").is_some_and(Value::is_null) => {}
        CAPTURE_SOURCE_OPUS_CLI_AGENT => match object.get("pr_ref").and_then(Value::as_i64) {
            Some(pr_ref) if pr_ref > 0 => {}
            _ => return Err("bad_pr_ref"),
        },
        CAPTURE_SOURCE_HELPER_AGENT if object.get("pr_ref").is_some_and(Value::is_null) => {}
        CAPTURE_SOURCE_HELPER_AGENT => return Err("bad_pr_ref"),
        _ => return Err("unknown_capture_source"),
    }
    if !is_utc_second_timestamp(string_field(object, "launch_ts").unwrap_or_default()) {
        return Err("bad_launch_ts");
    }

    Ok(LaunchEvent {
        controller_session_ref,
        worker_session_ref,
        workflow_ref,
        agent_kind,
    })
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

/// The privacy chokepoint, mirroring the emitter's own.
///
/// Workers and repair-family controllers are plain UUIDs. The gpt-sol relay is
/// the sole exception for controller refs: Claude subagent transcripts are
/// collected under the exact re-keyed form `<rootUUID>_agent-<17 hex>`, so that
/// capture family may name precisely that form. No other composite reaches a
/// fact, and workers remain UUID-only.
fn session_ref_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    let value = string_field(object, key)?;
    if !is_uuid(value) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn controller_session_ref_field(
    object: &Map<String, Value>,
    key: &str,
    capture_source: &str,
) -> Option<String> {
    let value = string_field(object, key)?;
    if is_uuid(value) {
        return Some(value.to_ascii_lowercase());
    }
    if capture_source == CAPTURE_SOURCE_GPT_SOL_RELAY && is_claude_subagent_session_ref(value) {
        return Some(value.to_ascii_lowercase());
    }
    None
}

fn is_claude_subagent_session_ref(value: &str) -> bool {
    let Some((root, agent_ref)) = value.split_once("_agent-") else {
        return false;
    };
    is_uuid(root) && agent_ref.len() == 17 && agent_ref.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// `YYYY-MM-DDTHH:MM:SSZ` exactly -- the emitter's own format.
///
/// Strict rather than lenient: a timestamp with an offset, sub-second precision,
/// or a missing zone would still parse as "a time", and this field is the
/// observation time of Direct evidence.
fn is_utc_second_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20 {
        return false;
    }
    let digits = [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    if digits.iter().any(|index| !bytes[*index].is_ascii_digit()) {
        return false;
    }
    bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
}

/// `sha256(controller \n worker \n attempt)`, the emitter's own file identity.
pub(crate) fn event_digest(event: &LaunchEvent) -> String {
    let mut digest = Sha256::new();
    digest.update(event.controller_session_ref.as_bytes());
    digest.update(b"\n");
    digest.update(event.worker_session_ref.as_bytes());
    digest.update(b"\n");
    if let Some(workflow_ref) = event.workflow_ref.as_deref() {
        digest.update(workflow_ref.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    const CONTROLLER: &str = "a9789dcf-1e4a-4a6e-8abd-f30094efb269";
    const WORKER: &str = "019f6822-403f-7652-a308-b0c12142e337";
    const ATTEMPT: &str = "402d846d-c13c-4743-8326-580e4ca70e30";

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("ottto-{name}-{unique}"))
    }

    fn event_json(overrides: &[(&str, &str)]) -> String {
        let mut fields: Vec<(String, String)> = vec![
            ("schema".to_string(), format!("\"{LAUNCH_EVENT_SCHEMA}\"")),
            (
                "controller_session_ref".to_string(),
                format!("\"{CONTROLLER}\""),
            ),
            ("worker_session_ref".to_string(), format!("\"{WORKER}\"")),
            (
                "relationship_kind".to_string(),
                format!("\"{RELATIONSHIP_KIND}\""),
            ),
            ("workflow_ref".to_string(), format!("\"{ATTEMPT}\"")),
            ("pr_ref".to_string(), "1653".to_string()),
            (
                "launch_ts".to_string(),
                "\"2026-08-09T15:17:21Z\"".to_string(),
            ),
            (
                "capture_source".to_string(),
                "\"launcher_event:landing_repair\"".to_string(),
            ),
            ("evidence".to_string(), "\"direct\"".to_string()),
        ];
        for (key, raw) in overrides {
            if raw.is_empty() {
                fields.retain(|(name, _)| name != key);
                continue;
            }
            match fields.iter_mut().find(|(name, _)| name == key) {
                Some(entry) => entry.1 = (*raw).to_string(),
                None => fields.push(((*key).to_string(), (*raw).to_string())),
            }
        }
        let body = fields
            .iter()
            .map(|(key, raw)| format!("\"{key}\":{raw}"))
            .collect::<Vec<_>>()
            .join(",");
        format!("{{{body}}}")
    }

    fn refresh_fixture(home: &Path) -> LaunchEventInventory {
        let inventory = LaunchEventInventory::refresh(home);
        for _ in 0..100 {
            match inventory.prepare_step(&[WORKER.to_string()]) {
                Ok(false) => continue,
                Ok(true) => return inventory,
                Err(()) => panic!("fixture lookup incomplete"),
            }
        }
        panic!("fixture lookup never completed");
    }

    fn drop_event(home: &Path, raw: &str, name: Option<&str>) -> PathBuf {
        let pending = home.join(DROP_ROOT_DIR).join(PENDING_SUBDIR);
        fs::create_dir_all(&pending).expect("pending dir");
        let file_name = match name {
            Some(value) => value.to_string(),
            None => {
                let event = validate_event(raw).expect("valid fixture");
                format!("{}.json", event_digest(&event))
            }
        };
        let path = pending.join(file_name);
        fs::write(&path, raw).expect("event file");
        path
    }

    #[test]
    fn well_formed_event_binds_the_worker_to_its_controller() {
        let event = validate_event(&event_json(&[])).expect("valid event");
        assert_eq!(event.controller_session_ref, CONTROLLER);
        assert_eq!(event.worker_session_ref, WORKER);
        assert_eq!(event.workflow_ref.as_deref(), Some(ATTEMPT));
        assert_eq!(event.agent_kind, "pr-fixer");
    }

    /// Every fail-closed row of the producer's matrix that reaches a FILE.
    /// Rows about the launch never happening produce no file at all and are the
    /// emitter's own tests; these are the ones this side has to refuse.
    #[test]
    fn malformed_events_fail_closed() {
        let cases: [(&str, String); 16] = [
            ("unknown_key", event_json(&[("prompt", "\"leak\"")])),
            ("missing_key", event_json(&[("workflow_ref", "")])),
            (
                "unknown_schema",
                event_json(&[("schema", "\"agent_launch.v2\"")]),
            ),
            (
                "unknown_schema",
                event_json(&[("schema", "\"agent_launch.v1 \"")]),
            ),
            (
                "bad_relationship_kind",
                event_json(&[("relationship_kind", "\"parent\"")]),
            ),
            ("bad_evidence", event_json(&[("evidence", "\"inferred\"")])),
            (
                "unknown_capture_source",
                event_json(&[("capture_source", "\"launcher_event:unknown\"")]),
            ),
            (
                "bad_controller_ref",
                event_json(&[("controller_session_ref", "\"not-a-uuid\"")]),
            ),
            (
                "bad_controller_ref",
                event_json(&[("controller_session_ref", "\"/Users/someone/repo\"")]),
            ),
            (
                "bad_worker_ref",
                event_json(&[(
                    "worker_session_ref",
                    "\"019f6822-403f-7652-a308-b0c12142e337_agent-abc\"",
                )]),
            ),
            (
                "bad_workflow_ref",
                event_json(&[("workflow_ref", "\"402d846d-c13c-4743-8326\"")]),
            ),
            (
                "self_launch",
                event_json(&[("worker_session_ref", &format!("\"{CONTROLLER}\""))]),
            ),
            ("bad_pr_ref", event_json(&[("pr_ref", "\"1653\"")])),
            ("bad_pr_ref", event_json(&[("pr_ref", "0")])),
            (
                "bad_launch_ts",
                event_json(&[("launch_ts", "\"2026-08-09T15:17:21.500Z\"")]),
            ),
            (
                "bad_launch_ts",
                event_json(&[("launch_ts", "\"2026-08-09T15:17:21+03:00\"")]),
            ),
        ];
        for (expected, raw) in cases {
            assert_eq!(
                validate_event(&raw),
                Err(expected),
                "case {expected}: {raw}"
            );
        }
        assert_eq!(validate_event("not json at all"), Err("not_json"));
        assert_eq!(validate_event("[]"), Err("not_object"));
    }

    #[test]
    fn oversize_file_is_refused_before_it_is_parsed() {
        let home = temp_dir("launch-oversize");
        let raw = event_json(&[]);
        let event = validate_event(&raw).expect("valid fixture");
        let padded = format!("{}{}", " ".repeat(MAX_EVENT_FILE_BYTES as usize), raw);
        drop_event(
            &home,
            &padded,
            Some(&format!("{}.json", event_digest(&event))),
        );

        let inventory = refresh_fixture(&home);

        assert_eq!(inventory.len(), 0);
        let rejected = home.join(DROP_ROOT_DIR).join(REJECTED_SUBDIR);
        assert_eq!(bounded_entries(&rejected, 8).len(), 1);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn accepted_event_moves_to_processed_and_stays_joinable() {
        let home = temp_dir("launch-lifecycle");
        drop_event(&home, &event_json(&[]), None);

        let inventory = refresh_fixture(&home);

        assert_eq!(
            inventory.matching(WORKER).map(|event| event.agent_kind),
            Some("pr-fixer")
        );
        let root = home.join(DROP_ROOT_DIR);
        assert_eq!(bounded_entries(&root.join(PENDING_SUBDIR), 8).len(), 0);
        assert_eq!(bounded_entries(&root.join(PROCESSED_SUBDIR), 8).len(), 1);

        // A later scan of the same worker -- the normal case, since the event is
        // written at spawn and the transcript is parsed repeatedly afterwards --
        // still finds the edge.
        let replayed = refresh_fixture(&home);
        assert_eq!(replayed.matching(WORKER), inventory.matching(WORKER));
        let _ = fs::remove_dir_all(&home);
    }

    struct TestHome(PathBuf);
    impl TestHome {
        fn new() -> Self {
            let root = temp_dir("launch-complete");
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn worker(n: usize) -> String {
        format!("{n:08x}-2222-3333-4444-555555555555")
    }
    fn retained(home: &Path, n: usize) -> (String, PathBuf) {
        let id = worker(n);
        let raw = event_json(&[
            ("worker_session_ref", &format!("\"{id}\"")),
            ("capture_source", "\"launcher_event:opus_cli_agent\""),
            ("workflow_ref", "null"),
            ("pr_ref", "null"),
        ]);
        let event = validate_event(&raw).unwrap();
        let dir = home.join(DROP_ROOT_DIR).join(PROCESSED_SUBDIR);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{id}.{}.json", event_digest(&event)));
        fs::write(&path, raw).unwrap();
        (id, path)
    }
    fn complete(inventory: &LaunchEventInventory, workers: &[String]) -> usize {
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 1000);
            match inventory.prepare_step(workers) {
                Ok(false) => {}
                Ok(true) => return steps,
                Err(()) => panic!("lookup incomplete"),
            }
        }
    }

    #[test]
    fn every_retained_worker_is_joinable_across_batches_above_the_old_caps() {
        let home = TestHome::new();
        let workers: Vec<_> = (1..=5400).map(|n| retained(&home.0, n).0).collect();
        let inventory = LaunchEventInventory::refresh(&home.0);
        for batch in workers.chunks(MAX_DEMANDED_WORKERS) {
            assert!(complete(&inventory, batch) > 1);
            assert!(inventory.lookup.lock().unwrap().workers.len() <= MAX_DEMANDED_WORKERS);
            for id in batch {
                assert_eq!(inventory.matching(id).unwrap().worker_session_ref, *id);
            }
        }
        // A fresh process/context has no cursor or cache dependency for import.
        let restarted = LaunchEventInventory::refresh(&home.0);
        complete(&restarted, &[workers[5399].clone()]);
        assert!(restarted.matching(&workers[5399]).is_some());
    }

    #[test]
    fn partial_pages_never_certify_uniqueness_and_late_conflicts_withhold_every_claim() {
        let home = TestHome::new();
        for n in 1..=1100 {
            retained(&home.0, n);
        }
        let id = worker(1100);
        let raw = event_json(&[
            ("worker_session_ref", &format!("\"{id}\"")),
            (
                "controller_session_ref",
                "\"11111111-2222-3333-4444-555555555555\"",
            ),
        ]);
        drop_event(&home.0, &raw, None);
        let inventory = LaunchEventInventory::refresh(&home.0);
        assert_eq!(inventory.prepare_step(std::slice::from_ref(&id)), Ok(false));
        assert!(inventory.matching(&id).is_none());
        assert!(complete(&inventory, std::slice::from_ref(&id)) > 1);
        assert!(inventory.matching(&id).is_none());
        assert_eq!(inventory.lookup.lock().unwrap().ambiguous.len(), 1);
    }

    #[test]
    fn edit_removal_expiry_and_pending_backlog_recheck_the_same_forward_path() {
        let home = TestHome::new();
        let (id, path) = retained(&home.0, 1);
        let inventory = LaunchEventInventory::refresh(&home.0);
        complete(&inventory, std::slice::from_ref(&id));
        assert!(inventory.matching(&id).is_some());
        // Same-name changes are revalidated by a fresh ordinary context, not a migration.
        let raw = event_json(&[
            ("worker_session_ref", &format!("\"{id}\"")),
            ("capture_source", "\"launcher_event:opus_cli_agent\""),
            ("workflow_ref", "null"),
            ("pr_ref", "null"),
            ("prompt", "\"invalid\""),
        ]);
        fs::write(&path, raw).unwrap();
        let edited = LaunchEventInventory::refresh(&home.0);
        let mut result = edited.prepare_step(std::slice::from_ref(&id));
        while result == Ok(false) {
            result = edited.prepare_step(std::slice::from_ref(&id));
        }
        assert_eq!(result, Err(()));
        assert!(edited.matching(&id).is_none());
        assert!(!path.exists());
        let removed = LaunchEventInventory::refresh(&home.0);
        complete(&removed, std::slice::from_ref(&id));
        assert!(removed.matching(&id).is_none());
        for n in 2..=600 {
            let (_, path) = retained(&home.0, n);
            let pending = home.0.join(DROP_ROOT_DIR).join(PENDING_SUBDIR);
            fs::create_dir_all(&pending).unwrap();
            fs::rename(&path, pending.join(path.file_name().unwrap())).unwrap();
        }
        let backlog = LaunchEventInventory::refresh(&home.0);
        let last = worker(600);
        assert!(complete(&backlog, std::slice::from_ref(&last)) > 1);
        assert!(backlog.matching(&last).is_some());
        let (_, path) = retained(&home.0, 1);
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::now() - PROCESSED_RETENTION - Duration::from_secs(1)),
        )
        .unwrap();
        // Expiry is the slow sweep's job; make the next lookup the one that sweeps.
        forget_processed_sweep(&home.0);
        let expired = LaunchEventInventory::refresh(&home.0);
        // Cleanup may change the directory fence once; the next context converges.
        while expired.prepare_step(std::slice::from_ref(&id)) == Ok(false) {}
        let after_cleanup = LaunchEventInventory::refresh(&home.0);
        complete(&after_cleanup, std::slice::from_ref(&id));
        assert!(after_cleanup.matching(&id).is_none());
        assert!(!path.exists());
    }

    fn helper_event(worker: &str, controller: &str) -> String {
        event_json(&[
            ("worker_session_ref", &format!("\"{worker}\"")),
            ("controller_session_ref", &format!("\"{controller}\"")),
            ("capture_source", "\"launcher_event:helper_agent\""),
            ("pr_ref", "null"),
        ])
    }

    /// [behaviour] The helper launcher's events are accepted as `helper-agent`,
    /// with an attempt id or none, and never with a pull-request number.
    #[test]
    fn helper_agent_events_are_an_instrumented_launcher() {
        let event = validate_event(&helper_event(WORKER, CONTROLLER)).expect("helper event");
        assert_eq!(event.agent_kind, "helper-agent");
        assert_eq!(event.workflow_ref.as_deref(), Some(ATTEMPT));
        let no_attempt = event_json(&[
            ("capture_source", "\"launcher_event:helper_agent\""),
            ("workflow_ref", "null"),
            ("pr_ref", "null"),
        ]);
        assert_eq!(validate_event(&no_attempt).unwrap().workflow_ref, None);
        let with_pr = event_json(&[("capture_source", "\"launcher_event:helper_agent\"")]);
        assert_eq!(validate_event(&with_pr), Err("bad_pr_ref"));
    }

    /// [behaviour] Intake files a processed event under its worker, and a
    /// lookup opens only the demanded workers' files: the others are skipped
    /// by name, with no open and no stat.
    #[test]
    fn processed_events_are_filed_by_worker_and_opened_only_on_demand() {
        let home = TestHome::new();
        let (first, second) = (worker(1), worker(2));
        for id in [&first, &second] {
            drop_event(&home.0, &helper_event(id, CONTROLLER), None);
        }
        let intake = LaunchEventInventory::refresh(&home.0);
        complete(&intake, std::slice::from_ref(&first));
        assert_eq!(intake.matching(&first).unwrap().agent_kind, "helper-agent");
        let processed = home.0.join(DROP_ROOT_DIR).join(PROCESSED_SUBDIR);
        let mut names = bounded_entries(&processed, 8)
            .iter()
            .map(|path| path.file_name().unwrap().to_str().unwrap().to_string())
            .collect::<Vec<_>>();
        names.sort();
        let expected = |id: &str| {
            let event = validate_event(&helper_event(id, CONTROLLER)).unwrap();
            format!("{id}.{}.json", event_digest(&event))
        };
        assert_eq!(names, [expected(&first), expected(&second)]);

        let lookup = LaunchEventInventory::refresh(&home.0);
        complete(&lookup, std::slice::from_ref(&second));
        assert_eq!(lookup.matching(&second).unwrap().worker_session_ref, second);
        let counts = lookup.lookup.lock().unwrap();
        assert_eq!(counts.opened, 1, "only the demanded worker's file");
        assert_eq!(counts.skipped_by_name, 1);
    }

    /// [behaviour] The slow sweep re-files an older release's `<digest>.json`
    /// processed names under their worker once, in the lookup that sweeps,
    /// without unsettling it. Later lookups skip them by name, and a lookup
    /// that only skips names opens and removes nothing, so it writes no line.
    #[test]
    fn legacy_processed_names_are_refiled_once_then_skipped_by_name() {
        let home = TestHome::new();
        let processed = home.0.join(DROP_ROOT_DIR).join(PROCESSED_SUBDIR);
        fs::create_dir_all(&processed).unwrap();
        let (first, second) = (worker(1), worker(2));
        for id in [&first, &second] {
            let raw = helper_event(id, CONTROLLER);
            let event = validate_event(&raw).unwrap();
            fs::write(
                processed.join(format!("{}.json", event_digest(&event))),
                raw,
            )
            .unwrap();
        }
        let sweeping = LaunchEventInventory::refresh(&home.0);
        complete(&sweeping, std::slice::from_ref(&second));
        assert_eq!(
            sweeping.matching(&second).unwrap().worker_session_ref,
            second
        );
        {
            let counts = sweeping.lookup.lock().unwrap();
            assert_eq!(counts.refiled, 2);
            assert_eq!(
                counts.opened, 3,
                "two legacy names once, then the demanded file"
            );
            assert_eq!(counts.skipped_by_name, 1);
        }
        assert!(bounded_entries(&processed, 8)
            .iter()
            .all(|path| indexed_worker(path).is_some()));

        let later = LaunchEventInventory::refresh(&home.0);
        complete(&later, std::slice::from_ref(&first));
        assert_eq!(later.matching(&first).unwrap().worker_session_ref, first);
        let counts = later.lookup.lock().unwrap();
        assert_eq!(
            (counts.refiled, counts.opened, counts.skipped_by_name),
            (0, 1, 1)
        );
        drop(counts);

        let undemanded = LaunchEventInventory::refresh(&home.0);
        complete(&undemanded, &[worker(3)]);
        let counts = undemanded.lookup.lock().unwrap();
        assert_eq!(
            (counts.opened, counts.swept, counts.skipped_by_name),
            (0, 0, 2)
        );
    }

    /// [behaviour] Two controllers claiming one worker still withhold both
    /// when both claims are filed under that worker.
    #[test]
    fn filed_claims_from_two_controllers_withhold_the_worker() {
        let home = TestHome::new();
        let id = worker(7);
        let other = "11111111-2222-3333-4444-555555555555";
        for controller in [CONTROLLER, other] {
            drop_event(&home.0, &helper_event(&id, controller), None);
        }
        let intake = LaunchEventInventory::refresh(&home.0);
        let _ = complete(&intake, std::slice::from_ref(&id));
        let lookup = LaunchEventInventory::refresh(&home.0);
        complete(&lookup, std::slice::from_ref(&id));
        assert!(lookup.matching(&id).is_none());
        assert_eq!(lookup.lookup.lock().unwrap().ambiguous.len(), 1);
    }

    /// [behaviour] A filed name must lead with the event's own worker.
    #[test]
    fn a_filed_name_for_another_worker_is_a_mismatch() {
        let home = temp_dir("launch-filed-mismatch");
        fs::create_dir_all(&home).unwrap();
        let raw = helper_event(WORKER, CONTROLLER);
        let event = validate_event(&raw).unwrap();
        let wrong = home.join(format!("{}.{}.json", worker(9), event_digest(&event)));
        fs::write(&wrong, &raw).unwrap();
        assert_eq!(read_and_validate(&wrong), Err("filename_mismatch"));
        let right = home.join(format!("{WORKER}.{}.json", event_digest(&event)));
        fs::write(&right, &raw).unwrap();
        assert_eq!(read_and_validate(&right), Ok(event));
        assert_eq!(
            indexed_worker(&right),
            Some(WORKER),
            "a filed name names its worker"
        );
        assert_eq!(indexed_worker(&home.join("ab.json")), None);
        let _ = fs::remove_dir_all(&home);
    }

    /// [behaviour] The processed sweep runs once per interval per drop root.
    #[test]
    fn the_processed_sweep_is_due_once_per_interval() {
        let root = temp_dir("launch-sweep-gate");
        assert!(processed_sweep_due(&root));
        assert!(!processed_sweep_due(&root));
        LAST_PROCESSED_SWEEP.lock().unwrap().remove(&root);
    }

    #[test]
    fn reject_log_label_is_a_hash_prefix_or_nothing() {
        assert_eq!(
            redacted_label(Path::new("/tmp/report-for-pr-1653.json")),
            "unnamed"
        );
        assert_eq!(
            redacted_label(Path::new(&format!("/tmp/{}.json", "ab".repeat(32)))),
            "abababababababab"
        );
        // A filed name's worker id is never logged, only its digest prefix.
        assert_eq!(
            redacted_label(Path::new(&format!(
                "/tmp/{WORKER}.{}.json",
                "cd".repeat(32)
            ))),
            "cdcdcdcdcdcdcdcd"
        );
    }
}

crate::heap_layout_bound::fields!(LaunchEventInventory; root, lookup);
impl crate::heap_layout_bound::HeapLayoutBound for Lookup {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            workers,
            ambiguous,
            phase,
            entries,
            complete,
            failed,
            sweep,
            loaded_at,
            skipped_by_name,
            opened,
            refiled,
            swept,
            pending_stamp,
            processed_stamp,
        } = self;
        // std's directory iterator owns opaque platform allocation. Refuse
        // optional overlap rather than inventing a bound while it is parked.
        if entries.is_some() {
            return None;
        }
        workers.heap_bound(c)?;
        ambiguous.heap_bound(c)?;
        phase.heap_bound(c)?;
        complete.heap_bound(c)?;
        failed.heap_bound(c)?;
        sweep.heap_bound(c)?;
        let _ = (
            loaded_at,
            skipped_by_name,
            opened,
            refiled,
            swept,
            pending_stamp,
            processed_stamp,
        );
        c.add(0)
    }
}

crate::heap_layout_bound::fields!(LaunchEvent; controller_session_ref, worker_session_ref, workflow_ref, agent_kind);
