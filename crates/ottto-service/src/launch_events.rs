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
const CAPTURE_SOURCES: &[(&str, &str)] = &[
    (CAPTURE_SOURCE_LANDING_REPAIR, "pr-fixer"),
    (CAPTURE_SOURCE_GPT_SOL_RELAY, "gpt-sol"),
    (CAPTURE_SOURCE_OPUS_CLI_AGENT, "opus-cli-agent"),
];

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
    loaded_at: Option<Instant>,
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
                let subdir = match lookup.phase {
                    0 | 1 => PENDING_SUBDIR,
                    2 | 3 => PROCESSED_SUBDIR,
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
                        lookup.failed = true;
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
                    match entry.file_type() {
                        Ok(kind) if kind.is_file() => {}
                        Ok(kind) if kind.is_symlink() => {
                            if lookup.phase == 0 {
                                reject(&path, &root.join(REJECTED_SUBDIR), "not_regular");
                            }
                            continue;
                        }
                        Ok(_) => continue,
                        Err(_) => {
                            lookup.failed = true;
                            continue;
                        }
                    }
                    let retention = if lookup.phase == 4 {
                        REJECTED_RETENTION
                    } else {
                        PROCESSED_RETENTION
                    };
                    if is_expired(&path, retention) {
                        if lookup.phase == 0 || lookup.phase >= 3 {
                            let _ = fs::remove_file(&path);
                        }
                        continue;
                    }
                    if lookup.phase >= 3 {
                        continue;
                    }
                    match read_and_validate(&path) {
                        Ok(_) if lookup.phase == 0 => {
                            if !relocate(&path, &root.join(PROCESSED_SUBDIR)) {
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
                            } else if lookup.phase == 0 {
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
                Some(Err(_)) => lookup.failed = true,
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

fn directory_stamp(dir: &Path) -> Option<SystemTime> {
    fs::metadata(dir)
        .and_then(|metadata| metadata.modified())
        .ok()
}

fn advance_phase(root: &Path, lookup: &mut Lookup) -> bool {
    lookup.phase += 1;
    if lookup.phase == 1 {
        lookup.pending_stamp = directory_stamp(&root.join(PENDING_SUBDIR));
        lookup.processed_stamp = directory_stamp(&root.join(PROCESSED_SUBDIR));
    }
    lookup.phase > 4
}

fn finish_lookup(root: &Path, lookup: &mut Lookup) -> Result<bool, ()> {
    lookup.entries = None;
    if lookup.phase != 0
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
    lookup.complete = true;
    lookup.loaded_at = Some(Instant::now());
    if lookup.failed {
        Err(())
    } else {
        Ok(true)
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
    if stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
    let expected = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or("unnamed")?;
    if expected != event_digest(&event) {
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

fn is_uuid(value: &str) -> bool {
    let groups = [8usize, 4, 4, 4, 12];
    let mut parts = value.split('-');
    for expected in groups {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.len() != expected || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
    }
    parts.next().is_none()
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
    const RELAY_CONTROLLER: &str = "a9789dcf-1e4a-4a6e-8abd-f30094efb269_agent-ad32608db4eecb2af";
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

    #[test]
    fn gpt_sol_relay_accepts_only_the_collectors_exact_controller_forms() {
        for controller in [CONTROLLER, RELAY_CONTROLLER] {
            let event = validate_event(&event_json(&[
                ("capture_source", "\"launcher_event:gpt_sol_relay\""),
                ("controller_session_ref", &format!("\"{controller}\"")),
                ("workflow_ref", "null"),
                ("pr_ref", "null"),
            ]))
            .expect("valid relay event");
            assert_eq!(event.controller_session_ref, controller);
            assert_eq!(event.worker_session_ref, WORKER);
            assert_eq!(event.workflow_ref, None);
            assert_eq!(event.agent_kind, "gpt-sol");
        }

        for controller in [
            "a9789dcf-1e4a-4a6e-8abd-f30094efb269_agent-short",
            "a9789dcf-1e4a-4a6e-8abd-f30094efb269_agent-ad32608db4eecb2az",
            "a9789dcf-1e4a-4a6e-8abd-f30094efb269/agent-ad32608db4eecb2af",
            "not-a-uuid_agent-ad32608db4eecb2af",
        ] {
            assert_eq!(
                validate_event(&event_json(&[
                    ("capture_source", "\"launcher_event:gpt_sol_relay\""),
                    ("controller_session_ref", &format!("\"{controller}\"")),
                    ("workflow_ref", "null"),
                    ("pr_ref", "null"),
                ])),
                Err("bad_controller_ref"),
                "accepted malformed composite {controller}"
            );
        }
    }

    #[test]
    fn composite_controller_and_null_metadata_are_relay_family_only() {
        assert_eq!(
            validate_event(&event_json(&[(
                "controller_session_ref",
                &format!("\"{RELAY_CONTROLLER}\""),
            )])),
            Err("bad_controller_ref")
        );
        for (field, raw, expected) in [
            ("workflow_ref", format!("\"{ATTEMPT}\""), "bad_workflow_ref"),
            ("pr_ref", "1653".to_string(), "bad_pr_ref"),
        ] {
            assert_eq!(
                validate_event(&event_json(&[
                    ("capture_source", "\"launcher_event:gpt_sol_relay\""),
                    ("workflow_ref", "null"),
                    ("pr_ref", "null"),
                    (field, raw.as_str()),
                ])),
                Err(expected)
            );
        }
        assert_eq!(
            validate_event(&event_json(&[("workflow_ref", "null")])),
            Err("bad_workflow_ref")
        );
        assert_eq!(
            validate_event(&event_json(&[("pr_ref", "null")])),
            Err("bad_pr_ref")
        );
    }

    #[test]
    fn uppercase_references_normalize_to_the_emitter_form() {
        let event = validate_event(&event_json(&[(
            "controller_session_ref",
            "\"A9789DCF-1E4A-4A6E-8ABD-F30094EFB269\"",
        )]))
        .expect("valid event");
        assert_eq!(event.controller_session_ref, CONTROLLER);
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
    fn filename_must_match_the_triple_it_claims() {
        let home = temp_dir("launch-filename");
        drop_event(
            &home,
            &event_json(&[]),
            Some(&format!("{}.json", "0".repeat(64))),
        );

        let inventory = refresh_fixture(&home);

        assert_eq!(inventory.len(), 0);
        assert_eq!(
            bounded_entries(&home.join(DROP_ROOT_DIR).join(REJECTED_SUBDIR), 8).len(),
            1
        );
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

    #[test]
    fn replaying_the_same_launch_keeps_exactly_one_event() {
        let home = temp_dir("launch-replay");
        drop_event(&home, &event_json(&[]), None);
        refresh_fixture(&home);
        // The launcher re-emits after a retry: same triple, same filename.
        drop_event(&home, &event_json(&[]), None);

        let inventory = refresh_fixture(&home);

        assert_eq!(inventory.len(), 1);
        assert_eq!(
            bounded_entries(&home.join(DROP_ROOT_DIR).join(PROCESSED_SUBDIR), 8).len(),
            1
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn two_controllers_claiming_one_worker_withhold_both_edges() {
        let home = temp_dir("launch-ambiguous");
        drop_event(&home, &event_json(&[]), None);
        drop_event(
            &home,
            &event_json(&[(
                "controller_session_ref",
                "\"11111111-2222-3333-4444-555555555555\"",
            )]),
            None,
        );

        let inventory = refresh_fixture(&home);

        assert!(inventory.matching(WORKER).is_none());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn rejected_file_never_reaches_the_inventory_or_the_processed_store() {
        let home = temp_dir("launch-rejected");
        let raw = event_json(&[("prompt", "\"secret prompt text\"")]);
        drop_event(&home, &raw, Some(&format!("{}.json", "a".repeat(64))));

        let inventory = refresh_fixture(&home);

        assert_eq!(inventory.len(), 0);
        let root = home.join(DROP_ROOT_DIR);
        assert_eq!(bounded_entries(&root.join(PROCESSED_SUBDIR), 8).len(), 0);
        assert_eq!(bounded_entries(&root.join(REJECTED_SUBDIR), 8).len(), 1);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn absent_drop_root_is_an_empty_inventory() {
        let home = temp_dir("launch-absent");
        assert_eq!(refresh_fixture(&home).len(), 0);
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
        let path = dir.join(format!("{}.json", event_digest(&event)));
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
    fn opus_contract_preserves_legacy_and_refuses_arbitrary_or_reserved_families() {
        for workflow in ["null".to_string(), format!("\"{ATTEMPT}\"")] {
            for pr in ["null", "7"] {
                let event = validate_event(&event_json(&[
                    ("capture_source", "\"launcher_event:opus_cli_agent\""),
                    ("workflow_ref", &workflow),
                    ("pr_ref", pr),
                ]))
                .unwrap();
                assert_eq!(event.agent_kind, "opus-cli-agent");
            }
        }
        for source in [
            "launcher_event:pr_fixer",
            "launcher_event:gpt_sol",
            "launcher_event:codex_subagent",
            "launcher_event:workflow_subagent",
            "launcher_event:other_slug",
            "launcher_event:",
            "launcher_event:Opus",
            "launcher_event:x/y",
        ] {
            assert_eq!(
                validate_event(&event_json(&[("capture_source", &format!("\"{source}\""))])),
                Err("unknown_capture_source")
            );
        }
        for value in ["0", "-1", "1.5", "\"7\""] {
            assert_eq!(
                validate_event(&event_json(&[
                    ("capture_source", "\"launcher_event:opus_cli_agent\""),
                    ("pr_ref", value)
                ])),
                Err("bad_pr_ref")
            );
        }
        assert_eq!(
            validate_event(&event_json(&[
                ("capture_source", "\"launcher_event:opus_cli_agent\""),
                ("controller_session_ref", &format!("\"{RELAY_CONTROLLER}\""))
            ])),
            Err("bad_controller_ref")
        );
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
        assert_eq!(inventory.prepare_step(&[id.clone()]), Ok(false));
        assert!(inventory.matching(&id).is_none());
        assert!(complete(&inventory, &[id.clone()]) > 1);
        assert!(inventory.matching(&id).is_none());
        assert_eq!(inventory.lookup.lock().unwrap().ambiguous.len(), 1);
    }

    #[test]
    fn non_uuid_transcripts_need_no_launch_lookup_or_drop_directory() {
        let home = TestHome::new();
        let inventory = LaunchEventInventory::refresh(&home.0);
        let workers = vec!["opaque-provider-session".to_string()];
        assert!(inventory.prepared(&workers));
        assert_eq!(inventory.prepare_step(&workers), Ok(true));
        assert!(inventory.matching(&workers[0]).is_none());
        assert!(!home.0.join(DROP_ROOT_DIR).exists());
    }

    #[test]
    fn duplicate_demands_do_not_consume_slots_and_changed_demands_yield_until_prepared() {
        let home = TestHome::new();
        for n in 1..=600 {
            retained(&home.0, n);
        }
        let first = worker(1);
        let second = worker(600);
        let inventory = LaunchEventInventory::refresh(&home.0);
        let duplicates = vec![first.clone(); MAX_DEMANDED_WORKERS + 1];
        assert_eq!(inventory.prepare_step(&duplicates), Ok(false));
        // Finish the original cursor without pretending the newly demanded
        // worker was included in its complete retained-store pass.
        while !inventory.lookup.lock().unwrap().complete {
            assert_eq!(inventory.prepare_step(&[second.clone()]), Ok(false));
        }
        assert!(!inventory.prepared(&[second.clone()]));
        assert!(inventory.matching(&second).is_none());
        complete(&inventory, &[second.clone()]);
        assert!(inventory.prepared(&[second.clone()]));
        assert!(inventory.matching(&second).is_some());
        complete(&inventory, &duplicates);
        assert_eq!(inventory.lookup.lock().unwrap().workers.len(), 1);
    }

    #[test]
    fn excess_demand_is_disclosed_instead_of_certifying_a_truncated_batch() {
        let home = TestHome::new();
        let demanded: Vec<_> = (1..=MAX_DEMANDED_WORKERS + 1).map(worker).collect();
        let inventory = LaunchEventInventory::refresh(&home.0);
        assert_eq!(inventory.prepare_step(&demanded), Err(()));
        assert!(inventory
            .matching(&demanded[MAX_DEMANDED_WORKERS])
            .is_none());
        for batch in demanded.chunks(MAX_DEMANDED_WORKERS) {
            complete(&inventory, batch);
        }
    }

    #[test]
    fn edit_removal_expiry_and_pending_backlog_recheck_the_same_forward_path() {
        let home = TestHome::new();
        let (id, path) = retained(&home.0, 1);
        let inventory = LaunchEventInventory::refresh(&home.0);
        complete(&inventory, &[id.clone()]);
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
        let mut result = edited.prepare_step(&[id.clone()]);
        while result == Ok(false) {
            result = edited.prepare_step(&[id.clone()]);
        }
        assert_eq!(result, Err(()));
        assert!(edited.matching(&id).is_none());
        assert!(!path.exists());
        let removed = LaunchEventInventory::refresh(&home.0);
        complete(&removed, &[id.clone()]);
        assert!(removed.matching(&id).is_none());
        for n in 2..=600 {
            let (_, path) = retained(&home.0, n);
            let pending = home.0.join(DROP_ROOT_DIR).join(PENDING_SUBDIR);
            fs::create_dir_all(&pending).unwrap();
            fs::rename(&path, pending.join(path.file_name().unwrap())).unwrap();
        }
        let backlog = LaunchEventInventory::refresh(&home.0);
        let last = worker(600);
        assert!(complete(&backlog, &[last.clone()]) > 1);
        assert!(backlog.matching(&last).is_some());
        let (_, path) = retained(&home.0, 1);
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::now() - PROCESSED_RETENTION - Duration::from_secs(1)),
        )
        .unwrap();
        let expired = LaunchEventInventory::refresh(&home.0);
        // Cleanup may change the directory fence once; the next context converges.
        while expired.prepare_step(&[id.clone()]) == Ok(false) {}
        let after_cleanup = LaunchEventInventory::refresh(&home.0);
        complete(&after_cleanup, &[id.clone()]);
        assert!(after_cleanup.matching(&id).is_none());
        assert!(!path.exists());
    }

    #[test]
    #[ignore = "bounded synthetic resource measurement; run natively in serial isolation"]
    fn measure_demanded_launch_lookup_resources() {
        let home = TestHome::new();
        for count in [2700usize, 5400] {
            for n in if count == 2700 { 1..=2700 } else { 2701..=5400 } {
                retained(&home.0, n);
            }
            // Demand size, not retained volume, owns the map ceiling.
            let demanded: Vec<_> = (1..=MAX_DEMANDED_WORKERS)
                .map(|n| worker(n + count - MAX_DEMANDED_WORKERS))
                .collect();
            let inventory = LaunchEventInventory::refresh(&home.0);
            let probe = crate::local_resource_diagnostics::Probe::start();
            let started = Instant::now();
            let mut max_step_us = 0u128;
            let ((steps, _), allocation) = crate::retry_allocation_probe::measure_process(|| {
                let mut steps = 0;
                loop {
                    steps += 1;
                    let at = Instant::now();
                    let result = inventory.prepare_step(&demanded).unwrap();
                    max_step_us = max_step_us.max(at.elapsed().as_micros());
                    if result {
                        break;
                    }
                }
                (steps, inventory.len())
            });
            for id in &demanded {
                assert!(inventory.matching(id).is_some());
            }
            assert!(
                allocation.requested_peak < 512 * 1024,
                "demand map and Rust scratch budget"
            );
            probe.collection(
                "unknown",
                crate::local_resource_diagnostics::CollectionCounts {
                    scanned_files: 0,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                },
            );
            println!(
                "LAUNCH_LOOKUP_RESOURCES {}",
                serde_json::json!({
                    "retained_files":count, "demanded_workers":demanded.len(), "steps":steps,
                    "wall_us":started.elapsed().as_micros(), "max_step_wall_us":max_step_us,
                    "directory_entries_per_step":LOOKUP_ENTRIES_PER_STEP,
                    "event_bytes_per_step_max":LOOKUP_ENTRIES_PER_STEP as u64 * (MAX_EVENT_FILE_BYTES + 1),
                    "requested_scope_peak_bytes":allocation.requested_peak,
                    "requested_scope_live_bytes":allocation.requested_live,
                    "opaque_directory_os_allocation_not_in_requested_rust_scope":true
                })
            );
        }
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
            loaded_at,
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
        let _ = (loaded_at, pending_stamp, processed_stamp);
        c.add(0)
    }
}

crate::heap_layout_bound::fields!(LaunchEvent; controller_session_ref, worker_session_ref, workflow_ref, agent_kind);
