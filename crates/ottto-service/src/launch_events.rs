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
//! enums, or a timestamp:
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
//! `pending/` is an inbox and drains on every refresh. A valid event moves to
//! `processed/` and stays readable there for [`PROCESSED_RETENTION`]; a rejected
//! one moves to `rejected/` for [`REJECTED_RETENTION`] with a reason CODE in the
//! log and never its contents. The inventory is built from `processed/`, not
//! from `pending/`, because an event is written at spawn -- before the worker
//! has written its first transcript line -- and the fact has to still be
//! available whenever that transcript is finally scanned, re-scanned, or
//! replayed. Filenames are the SHA-256 of the triple, so re-emitting the same
//! launch resolves to the same path and can never produce a second edge.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
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

/// Evidence kind for launch-derived facts.
///
/// Deliberately a NEW vocabulary token rather than a reused existing one. None
/// of the deployed kinds is honest here: the event is not provider-native, not a
/// provider-owned artifact, not a scheduler-definition match, and not a live
/// process check. The backend tolerates an unknown evidence kind by DROPPING
/// that one fact, counting it, and storing the session
/// (`_quarantine_unrecognized_attribution_facts`), so emitting the truthful
/// token costs nothing today and starts working the moment the backend enum
/// lists it -- with no backfill, because these facts re-emit on every scan of
/// the worker session. Mislabelling the edge to make it land sooner would put a
/// false provenance string in front of a customer, which is the one thing this
/// whole capture path exists to avoid.
pub(crate) const LAUNCH_EVENT_EVIDENCE_KIND: &str = "launcher_event";

const DROP_ROOT_DIR: &str = ".ottto/launch-events";
const PENDING_SUBDIR: &str = "pending";
const PROCESSED_SUBDIR: &str = "processed";
const REJECTED_SUBDIR: &str = "rejected";

/// A well-formed event is ~360 bytes. The cap exists so a truncated, appended,
/// or hostile file is refused by `stat` before it is ever read into memory.
const MAX_EVENT_FILE_BYTES: u64 = 4 * 1_024;
/// Per-refresh work ceilings. The drop root is a low-volume inbox; these bound
/// the cost of a directory that somehow is not.
const MAX_PENDING_FILES_PER_REFRESH: usize = 256;
const MAX_PROCESSED_FILES_PER_REFRESH: usize = 1_024;
const MAX_REJECTED_FILES_PER_REFRESH: usize = 1_024;
/// Inventory ceiling. Retention is what normally bounds this; the cap is the
/// backstop that keeps a runaway launcher from growing daemon memory.
const MAX_RETAINED_EVENTS: usize = 512;

/// How long an accepted event stays joinable.
///
/// It has to outlive every path that can bring a worker transcript back to the
/// scanner long after the launch: a stalled upload, a checkpoint reset, an
/// explicit replay, or a machine that was simply off. Thirty days is the same
/// order as the backfill window and costs a few hundred bytes per launch.
const PROCESSED_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Rejected files are kept only long enough to be diagnosed by hand.
const REJECTED_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Refresh ceiling. The transcript scan itself runs on a negotiated cadence of
/// minutes, so this only stops the three per-cycle source contexts from each
/// re-listing the same directory.
const INVENTORY_TTL: Duration = Duration::from_secs(60);

/// Instrumented launcher families, and the worker role each one starts.
///
/// This is an allowlist in both directions: an unlisted `capture_source` cannot
/// claim Direct evidence, and the `agent_kind` a launch produces is chosen HERE
/// rather than read from the file, so the event can never supply its own label.
/// Adding the gpt-sol relay is a one-line widening on this side and on the
/// emitter's `CAPTURE_SOURCES`; the emitter refuses it today on purpose.
const CAPTURE_SOURCES: &[(&str, &str)] = &[("launcher_event:landing_repair", "pr-fixer")];

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
    pub(crate) workflow_ref: String,
    /// Worker role, resolved from the capture source allowlist.
    pub(crate) agent_kind: &'static str,
}

#[derive(Clone, Default)]
pub(crate) struct LaunchEventInventory {
    events: BTreeMap<String, LaunchEvent>,
}

struct CachedInventory {
    loaded_at: Instant,
    home: PathBuf,
    inventory: LaunchEventInventory,
}

impl LaunchEventInventory {
    /// Refresh at most once per [`INVENTORY_TTL`], draining `pending/` as a side
    /// effect. Every mutation is a rename or an expiry delete, so repeating it
    /// -- from another source's context in the same cycle, from the audit tool,
    /// or after a crash mid-drain -- converges on the same state.
    pub(crate) fn cached(home: &Path) -> Self {
        static CACHE: OnceLock<Mutex<Option<CachedInventory>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = cache.lock() {
            if let Some(cached) = guard.as_ref() {
                if cached.home == home && cached.loaded_at.elapsed() < INVENTORY_TTL {
                    return cached.inventory.clone();
                }
            }
        }
        let inventory = Self::refresh(home);
        if let Ok(mut guard) = cache.lock() {
            *guard = Some(CachedInventory {
                loaded_at: Instant::now(),
                home: home.to_path_buf(),
                inventory: inventory.clone(),
            });
        }
        inventory
    }

    /// Drain, retire, and load in one pass. Public for tests, which need a
    /// deterministic refresh rather than a TTL-cached one.
    pub(crate) fn refresh(home: &Path) -> Self {
        let root = home.join(DROP_ROOT_DIR);
        if !root.is_dir() {
            return Self::default();
        }
        let pending = root.join(PENDING_SUBDIR);
        let processed = root.join(PROCESSED_SUBDIR);
        let rejected = root.join(REJECTED_SUBDIR);

        drain_pending(&pending, &processed, &rejected);
        let events = load_processed(&processed, &rejected);
        prune_expired(
            &rejected,
            REJECTED_RETENTION,
            MAX_REJECTED_FILES_PER_REFRESH,
        );
        Self { events }
    }

    /// The launch that started `worker_session_ref`, when exactly one is known.
    pub(crate) fn matching(&self, worker_session_ref: &str) -> Option<&LaunchEvent> {
        self.events.get(worker_session_ref)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }

    #[cfg(test)]
    pub(crate) fn from_events(events: Vec<LaunchEvent>) -> Self {
        Self {
            events: events
                .into_iter()
                .map(|event| (event.worker_session_ref.clone(), event))
                .collect(),
        }
    }
}

/// Validate every file in `pending/` and move it out: accepted events to
/// `processed/`, everything else to `rejected/`.
fn drain_pending(pending: &Path, processed: &Path, rejected: &Path) {
    for path in bounded_entries(pending, MAX_PENDING_FILES_PER_REFRESH) {
        match read_and_validate(&path) {
            Ok(_) => relocate(&path, processed),
            Err(reason) => reject(&path, rejected, reason),
        }
    }
}

/// Build the inventory from the retained store, expiring what is too old.
///
/// Re-validating here is not paranoia for its own sake: `processed/` is an
/// ordinary user-writable directory, and the facts it produces are Direct
/// evidence. A file that decayed, was edited, or was dropped in by hand gets the
/// same treatment a bad `pending/` file gets.
fn load_processed(processed: &Path, rejected: &Path) -> BTreeMap<String, LaunchEvent> {
    let mut events: BTreeMap<String, LaunchEvent> = BTreeMap::new();
    let mut ambiguous: BTreeSet<String> = BTreeSet::new();
    for path in bounded_entries(processed, MAX_PROCESSED_FILES_PER_REFRESH) {
        if is_expired(&path, PROCESSED_RETENTION) {
            let _ = fs::remove_file(&path);
            continue;
        }
        let event = match read_and_validate(&path) {
            Ok(event) => event,
            Err(reason) => {
                reject(&path, rejected, reason);
                continue;
            }
        };
        if events.len() >= MAX_RETAINED_EVENTS && !events.contains_key(&event.worker_session_ref) {
            continue;
        }
        match events.get(&event.worker_session_ref) {
            // Same worker, different controller: one of the two bindings is
            // wrong and nothing here can tell which. Both lose.
            Some(existing) if existing != &event => {
                ambiguous.insert(event.worker_session_ref.clone());
            }
            _ => {
                events.insert(event.worker_session_ref.clone(), event);
            }
        }
    }
    for worker_session_ref in ambiguous {
        events.remove(&worker_session_ref);
        eprintln!(
            "ottto-service: withheld a launch edge: two launch events name the same worker session \
             with different controllers"
        );
    }
    events
}

fn prune_expired(dir: &Path, retention: Duration, limit: usize) {
    for path in bounded_entries(dir, limit) {
        if is_expired(&path, retention) {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Deterministic, bounded listing of the JSON files directly inside `dir`.
///
/// Sorted so a truncated refresh is reproducible rather than arbitrary, and
/// non-recursive so a directory planted inside the drop root cannot enlarge the
/// scan.
fn bounded_entries(dir: &Path, limit: usize) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths.truncate(limit);
    paths
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
fn relocate(path: &Path, destination: &Path) {
    let Some(name) = path.file_name() else {
        return;
    };
    if fs::create_dir_all(destination).is_err() {
        return;
    }
    let _ = fs::rename(path, destination.join(name));
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
    relocate(path, rejected);
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
    let metadata = fs::metadata(path).map_err(|_| "unreadable")?;
    if metadata.len() > MAX_EVENT_FILE_BYTES {
        return Err("oversize");
    }
    let mut raw = String::new();
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut raw))
        .map_err(|_| "unreadable")?;
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
        session_ref_field(object, "controller_session_ref").ok_or("bad_controller_ref")?;
    let worker_session_ref =
        session_ref_field(object, "worker_session_ref").ok_or("bad_worker_ref")?;
    let workflow_ref = session_ref_field(object, "workflow_ref").ok_or("bad_workflow_ref")?;
    // A session cannot launch itself. Reaching here means one of the two
    // bindings is wrong, and there is no way to tell which.
    if controller_session_ref == worker_session_ref {
        return Err("self_launch");
    }

    match object.get("pr_ref").and_then(Value::as_i64) {
        Some(pr_ref) if pr_ref > 0 => {}
        _ => return Err("bad_pr_ref"),
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
/// A plausible LOCAL session identity here is a plain UUID: the launcher assigns
/// the Claude worker's id itself and parses the Codex worker's from a run
/// header, and both are UUIDs. Provider-derived composite refs
/// (`<uuid>_agent-<id>`) belong to subagent transcripts the provider already
/// links, and are refused here so a launch event cannot reach into a family the
/// provider owns. Anything that is not exactly a UUID -- a path, a branch name,
/// a prompt fragment -- dies here and can never reach a fact.
fn session_ref_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    let value = string_field(object, key)?;
    if !is_uuid(value) {
        return None;
    }
    Some(value.to_ascii_lowercase())
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
    digest.update(event.workflow_ref.as_bytes());
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
        assert_eq!(event.workflow_ref, ATTEMPT);
        assert_eq!(event.agent_kind, "pr-fixer");
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
                event_json(&[("capture_source", "\"launcher_event:gpt_sol_relay\"")]),
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

        let inventory = LaunchEventInventory::refresh(&home);

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

        let inventory = LaunchEventInventory::refresh(&home);

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

        let inventory = LaunchEventInventory::refresh(&home);

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
        let replayed = LaunchEventInventory::refresh(&home);
        assert_eq!(replayed.matching(WORKER), inventory.matching(WORKER));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn replaying_the_same_launch_keeps_exactly_one_event() {
        let home = temp_dir("launch-replay");
        drop_event(&home, &event_json(&[]), None);
        LaunchEventInventory::refresh(&home);
        // The launcher re-emits after a retry: same triple, same filename.
        drop_event(&home, &event_json(&[]), None);

        let inventory = LaunchEventInventory::refresh(&home);

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

        let inventory = LaunchEventInventory::refresh(&home);

        assert!(inventory.matching(WORKER).is_none());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn rejected_file_never_reaches_the_inventory_or_the_processed_store() {
        let home = temp_dir("launch-rejected");
        let raw = event_json(&[("prompt", "\"secret prompt text\"")]);
        drop_event(&home, &raw, Some(&format!("{}.json", "a".repeat(64))));

        let inventory = LaunchEventInventory::refresh(&home);

        assert_eq!(inventory.len(), 0);
        let root = home.join(DROP_ROOT_DIR);
        assert_eq!(bounded_entries(&root.join(PROCESSED_SUBDIR), 8).len(), 0);
        assert_eq!(bounded_entries(&root.join(REJECTED_SUBDIR), 8).len(), 1);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn absent_drop_root_is_an_empty_inventory() {
        let home = temp_dir("launch-absent");
        assert_eq!(LaunchEventInventory::refresh(&home).len(), 0);
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
