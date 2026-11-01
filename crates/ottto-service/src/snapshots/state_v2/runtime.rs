//! Locked runtime routing. A load that names its support dir converts v1 to the
//! store; any other load stays v1 before publication. Custody evidence always wins.
use super::*;
use anyhow::{bail, ensure, Context};
use import::{Mapper, Pace, Pause};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum Hold {
    Future,
    UnknownRecordKind,
    DbUnavailable,
    ForeignBinding,
    FenceLost,
    NewerSchema,
    MigrationFailed,
    ReloadRequired,
    IntegrityRetry,
    SaveCeiling,
    SaveOversize,
    SaveFull,
    ReferenceDrift,
    AckCustody,
}
impl std::fmt::Display for Hold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Future | Self::UnknownRecordKind => "scan_index_representation_refused",
            Self::DbUnavailable => "state_v2_db_unavailable",
            Self::ForeignBinding => "state_v2_foreign_binding",
            Self::NewerSchema => "state_v2_newer_schema_refused",
            Self::MigrationFailed => "state_v2_migration_failed",
            Self::SaveCeiling => "state_v2_save_ceiling",
            Self::SaveOversize => "state_v2_save_oversize",
            Self::SaveFull => "state_v2_sqlite_full",
            Self::IntegrityRetry => "state_v2_integrity_retry",
            Self::ReferenceDrift => "state_v2_reference_drift",
            Self::ReloadRequired => "current_index_requires_reload",
            Self::FenceLost => "state_v2_fence_lost",
            Self::AckCustody => "state_v2_ack_custody_hold",
        })
    }
}
impl std::error::Error for Hold {}
impl Hold {
    pub(super) fn storage(error: anyhow::Error) -> anyhow::Error {
        // Keep only the content-free typed cause, including through SQLite's
        // conversion wrapper; arbitrary engine messages still stay private.
        if error
            .chain()
            .any(|cause| matches!(cause.downcast_ref::<Self>(), Some(Self::UnknownRecordKind)))
        {
            return Self::UnknownRecordKind.into();
        }
        if let Some(hold) = error.downcast_ref::<Self>() {
            return (*hold).into();
        }
        let reason = error
            .downcast_ref::<rusqlite::Error>()
            .and_then(|e| e.sqlite_error_code())
            .map(|c| match c {
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => "busy",
                _ => "engine",
            })
            .unwrap_or("integrity_or_io");
        telemetry::event("db_unavailable", &reason);
        // Content-free cause: where (outermost static state_v2_* code) and what
        // (innermost code, io kind or SQLite extended code); never text or paths.
        let code = |e: &(dyn std::error::Error + 'static)| {
            let text = e.to_string();
            (text.starts_with("state_v2_")
                && text.len() <= 64
                && text
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
            .then_some(text)
            .or_else(|| {
                e.downcast_ref::<std::io::Error>()
                    .map(|io| format!("io_{:?}", io.kind()))
            })
            .or_else(|| match e.downcast_ref::<rusqlite::Error>() {
                Some(rusqlite::Error::SqliteFailure(f, _)) => {
                    Some(format!("sqlite_{}", f.extended_code))
                }
                _ => None,
            })
        };
        let codes = error.chain().filter_map(code).collect::<Vec<_>>();
        let cause = serde_json::json!({ "at": codes.first(), "cause": codes.last() });
        telemetry::event("db_unavailable_cause", &cause);
        let hold = if sqlite::disk_full(&error) {
            telemetry::event("sqlite_full", &1);
            Self::SaveFull
        } else if Self::ceiling_cause(&error).is_some() {
            Self::SaveCeiling
        } else if error
            .chain()
            .any(|e| e.to_string() == "state_v2_foreign_binding")
        {
            Self::ForeignBinding
        } else if error.chain().any(|e| {
            // A key this build does not know, inside a known row, was written
            // by a newer build: hold until upgrade, never as a data fault.
            let text = e.to_string();
            text == "scan_index_representation_refused"
                || text.starts_with("state_v2_ignored_field")
        }) {
            Self::Future
        } else if error
            .chain()
            .any(|e| e.to_string() == "current_index_requires_reload")
        {
            Self::ReloadRequired
        } else {
            Self::DbUnavailable
        };
        // Do not retain arbitrary engine messages/paths in public health output.
        hold.into()
    }
    /// Content-free cause of save pressure: the charged-work ceiling or one
    /// logical row over its value cap. Both hold as `SaveCeiling`.
    fn ceiling_cause(error: &anyhow::Error) -> Option<&'static str> {
        error.chain().find_map(|e| match e.to_string().as_str() {
            "state_v2_save_ceiling" => Some("charged_work"),
            "state_v2_value_admission" => Some("value_admission"),
            _ => None,
        })
    }
}
struct RouteState {
    pace: Pace,
    latched: bool,
    inventory_ready: bool,
    original: Option<import::Original>,
    runtimes: Vec<std::sync::Weak<Runtime>>,
    current: Option<Arc<Runtime>>,
    // Logical row commitments, consumed by the next save or discarded at idle.
    save_digests: Option<kinds::Baseline>,
    page_limit: usize,
    requested_page: usize,
    save_hold: Option<Hold>,
    // Page-one pressure names the last admitted file, never upload authority.
    last_read: Option<(String, u64)>,
    save_retry_completed: bool,
    pass_written_start: Option<u64>,
    // Live ACK custody exceeded the companion bound: no collection before this.
    custody_retry_at: Option<Instant>,
}
impl RouteState {
    fn custody_held(&self) -> bool {
        self.custody_retry_at.is_some_and(|at| Instant::now() < at)
    }
    fn reduce_page(&mut self) {
        let previous = self.page_limit;
        self.page_limit = (self.page_limit / 2).max(1);
        if self.page_limit < previous {
            telemetry::event("save_page_reduced", &self.page_limit);
        }
    }
    fn saved_page(&mut self, over_target: bool, claim_only: bool) {
        // A small claim/CAS-only write cannot resolve an oversized collection
        // delta. Only a normal or local recovery save may lift its fence.
        if claim_only {
            return;
        }
        // A cursor-only save after a paced skip cannot resolve the held file.
        if self.save_hold == Some(Hold::SaveOversize) && !self.save_retry_completed {
            return;
        }
        self.save_hold = None;
        self.last_read = None;
        self.save_retry_completed = false;
        if over_target {
            self.reduce_page();
        } else {
            self.page_limit = self.page_limit.saturating_add(25).min(self.requested_page);
        }
    }
}
type RouteHandle = Arc<Mutex<RouteState>>;
fn states() -> &'static Mutex<BTreeMap<PathBuf, RouteHandle>> {
    static STATES: OnceLock<Mutex<BTreeMap<PathBuf, RouteHandle>>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(BTreeMap::new()))
}
fn with_state<T>(path: &Path, f: impl FnOnce(&mut RouteState) -> Result<T>) -> Result<T> {
    let state = {
        let mut states = states().lock().map_err(|_| Hold::DbUnavailable)?;
        // Latches are never evicted. Release the registry before blocking work.
        states
            .entry(path.to_owned())
            .or_insert_with(|| {
                Arc::new(Mutex::new(RouteState {
                    pace: Pace::default(),
                    latched: false,
                    inventory_ready: false,
                    original: None,
                    runtimes: Vec::new(),
                    current: None,
                    save_digests: None,
                    page_limit: 250,
                    requested_page: 250,
                    save_hold: None,
                    last_read: None,
                    save_retry_completed: false,
                    pass_written_start: None,
                    custody_retry_at: None,
                }))
            })
            .clone()
    };
    let mut state = state.lock().map_err(|_| Hold::DbUnavailable)?;
    f(&mut state)
}

fn route_needed(path: &Path, custody: bool) -> Result<bool> {
    Ok(states()
        .lock()
        .map_err(|_| Hold::DbUnavailable)?
        .contains_key(path)
        || custody)
}
/// Probe custody without admitting a v1 path to the route registry or decoding
/// its index. A paused, unpublished import does not change progress ordering.
pub(in super::super) fn published(path: &Path) -> Result<bool> {
    if binding(path).is_none() {
        return Ok(false);
    }
    let state = states()
        .lock()
        .map_err(|_| Hold::DbUnavailable)?
        .get(path)
        .cloned();
    if let Some(state) = state {
        if state.lock().map_err(|_| Hold::DbUnavailable)?.latched {
            return Ok(true);
        }
    }
    held(fence::evidence(path))
}

fn binding(path: &Path) -> Option<super::super::scan_index_persistence::Binding> {
    super::super::scan_index_integration::scan_index_storage_binding(path)
        .filter(|b| v2_on(b.source))
}

pub(in super::super) struct Session {
    db: sqlite::Sqlite,
    cx: KindCx,
    identity: Identity,
    path: PathBuf,
    reload: bool,
    stamp: (u64, u64),
}
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StateV2Session")
    }
}

fn held<T>(result: Result<T>) -> Result<T> {
    let result = result.map_err(Hold::storage);
    if let Err(error) = &result {
        if let Some(hold) = error.downcast_ref::<Hold>() {
            telemetry::event("hold", hold);
        }
    }
    result
}

/// Present root: caller already owns CheckpointLock, BEFORE v1 decode.
/// Missing root calls the same function from check_missing's existing lock.
pub(in super::super) fn load_locked(
    path: &Path,
    support: Option<&Path>,
    custody: bool,
) -> Result<(Option<ScanIndex>, bool)> {
    // Do not probe the Claude sentinel for Codex, Pi or unbound paths.
    if binding(path).is_none() {
        return Ok((None, false));
    }
    // Without a support dir (unit tests, tools) only an existing route loads.
    let importable = support.is_some();
    let index = load_with_custody(path, importable, custody)?;
    let sample_v1 = importable && index.is_none();
    Ok((index, sample_v1))
}
fn load_with_custody(path: &Path, importable: bool, custody: bool) -> Result<Option<ScanIndex>> {
    let Some(binding) = binding(path) else {
        return Ok(None);
    };
    if !importable && !route_needed(path, custody)? {
        return Ok(None);
    }
    let mut load_started = None;
    let result = held(with_state(path, |state| {
        state.inventory_ready = false;
        state.original = None;
        state.save_digests = None;
        let pair = fence::reconcile(path, &binding, state.latched)?;
        state.pass_written_start = (importable || pair.is_some())
            .then(telemetry::process_written_bytes)
            .flatten();
        if let Some((identity, db_path)) = pair {
            load_started = Some(Instant::now());
            state.latched = true;
            telemetry::baseline(path);
            if let Some(runtime) = state.current.clone() {
                let mut guard = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
                if let Some(session) = guard.as_mut() {
                    // A store marked for reload refuses reads; reopen it
                    // below instead of probing its stamp.
                    // Either owner may demand a reload; both reopen below.
                    let stamp = (!session.reload && !session.db.reload_required())
                        .then(|| session.db.stamp())
                        .transpose()?;
                    if let Some(stamp) = stamp
                        .filter(|stamp| session.identity == identity && session.stamp == *stamp)
                    {
                        super::ack::ProgressRecovery::recover_route(&identity, stamp.0, path)?;
                        // Reuse the connection, but hydrate the durable graph each pass.
                        let _gauge = telemetry::Stage::new(telemetry::Kind::Hydrate);
                        let (mut index, mut cx) = Mapper.hydrate_context(&mut session.db)?;
                        #[cfg(test)]
                        if let Some(key) = tests::DELETE_DURING_HYDRATE.with(std::cell::Cell::take)
                        {
                            let stamps = sqlite::delete_row_elsewhere_for_test(&session.db, &key);
                            tests::RACED_STAMPS.with(|raced| raced.set(Some(stamps)));
                        }
                        ensure!(index.generation == stamp.0, Hold::DbUnavailable);
                        // The image read must be the stamp this session holds:
                        // after a commit from elsewhere neither its baseline
                        // nor its lineage is adopted; reopen below.
                        if session.db.stamp()? == stamp {
                            // Digest the exact persisted image: a save then
                            // also persists whatever normalization changes.
                            let digests = kinds::baseline(&index, &mut cx)?;
                            normalize_hydrated(&mut index)?;
                            state.save_digests = Some(digests);
                            // Same session and stamp: rollovers its commits
                            // wrote stay committed for graphs that outlive
                            // this load.
                            if !session.cx.ambiguous {
                                cx.cold_rolled = std::mem::take(&mut session.cx.cold_rolled);
                            }
                            session.cx = cx;
                            index.v2_mut().persistence_v2 = Some(runtime.clone());
                            telemetry::event("route", &"v2");
                            return Ok(Some(index));
                        }
                    }
                }
                // Invalidate every old clone before replacing the connection.
                guard.take();
                state.save_digests = None;
                state.current = None;
            }
            let _gauge = telemetry::Stage::new(telemetry::Kind::Hydrate);
            let (deadline, work) = purge_policy();
            let mut db = sqlite::Sqlite::open_with_policy(&db_path, &identity, deadline, work)
                .map_err(Hold::storage)?;
            db.path_extractor(Mapper::private_paths);
            db.reference_extractor(Mapper::references);
            // Static stage labels: Hold::storage reports where a reopen failed.
            let stamp = db.stamp().context("state_v2_open_stamp")?;
            super::ack::ProgressRecovery::recover_route(&identity, stamp.0, path)
                .context("state_v2_open_recover")?;
            let (mut index, mut cx) = Mapper
                .hydrate_context(&mut db)
                .context("state_v2_open_hydrate")?;
            let stamp = db.stamp().context("state_v2_open_stamp")?;
            ensure!(index.generation == stamp.0, Hold::DbUnavailable);
            let digests = kinds::baseline(&index, &mut cx)?;
            normalize_hydrated(&mut index).context("state_v2_open_normalize")?;
            db.audit_headers().context("state_v2_open_audit_headers")?;
            state.save_digests = Some(digests);
            index.v2_mut().persistence_v2 = Some(Arc::new(Runtime {
                active: true,
                session: Mutex::new(Some(Session {
                    db,
                    cx,
                    identity,
                    path: path.to_owned(),
                    reload: false,
                    stamp,
                })),
            }));
            register(state, &index)?;
            telemetry::event("route", &"v2");
            return Ok(Some(index));
        }
        if !importable {
            return Ok(None);
        }
        let now = Instant::now();
        if let Some(first) = state.pace.start(now) {
            telemetry::event(
                "import_attempt",
                &if first { "first_in_process" } else { "retry" },
            );
            if first
                && (fence::exists(path)?
                    || fence::exists(&fence::sibling(path, ".v1-readonly"))?
                    || fence::exists(&fence::sibling(path, ".v2.sqlite.import"))?)
            {
                telemetry::event("import_restart_attempt", &1);
            }
            // Inventory precedes v1 recovery/decoding and never creates artifacts.
            match Mapper.inventory_context(path) {
                Ok(original) => {
                    state.inventory_ready = true;
                    state.original = original;
                }
                Err(class) => {
                    pause(state, class);
                }
            }
        }
        telemetry::event("route", &"v1");
        Ok(None)
    }));
    if let Some(started) = load_started {
        telemetry::event(
            "load_span",
            &serde_json::json!({
                "duration_ms": started.elapsed().as_millis(),
                "generation": result.as_ref().ok().and_then(|index| index.as_ref()).map(|index| index.generation)
            }),
        );
    }
    if result.is_err() {
        with_state(path, |state| {
            if state.latched || state.current.as_ref().is_some_and(|runtime| runtime.active) {
                telemetry::abort_pass();
            }
            state.save_digests = None;
            if let Some(runtime) = state.current.take() {
                runtime
                    .session
                    .lock()
                    .map_err(|_| Hold::DbUnavailable)?
                    .take();
            }
            Ok(())
        })?;
    }
    result
}
fn normalize_hydrated(index: &mut ScanIndex) -> Result<()> {
    use super::super::lenient_decode;
    lenient_decode::post_decode_hydrated(index, "load", "claude_code").map_err(
        |error| match error {
            lenient_decode::Error::Refused("schema_version" | "accepted-ledger version") => {
                Hold::Future.into()
            }
            error => error.into(),
        },
    )
}

fn pause(state: &mut RouteState, class: Pause) {
    state.inventory_ready = false;
    state.original = None;
    telemetry::event("import_paused", &class);
    telemetry::event("import_paused_alarm", &1);
}

/// Import is attempted only on the normalized available graph and only if the
/// pre-decode inventory acquired a due slot. No writes on any paused path.
pub(in super::super) fn after_v1_locked(path: &Path, index: &mut ScanIndex) -> Result<()> {
    let Some(binding) = binding(path) else {
        return Ok(());
    };
    if !states()
        .lock()
        .map_err(|_| Hold::DbUnavailable)?
        .contains_key(path)
    {
        return Ok(());
    }
    with_state(path, |state| {
        if !state.inventory_ready {
            return Ok(());
        }
        state.inventory_ready = false;
        if !index.persistence_available() {
            pause(state, Pause::Partial);
            return Ok(());
        }
        let _gauge = telemetry::Stage::import(path);
        let result = (|| -> Result<KindCx> {
            let original = state.original.as_mut().ok_or(Pause::Mismatch)?;
            original.unchanged()?;
            // Progress locking belongs to the actual conversion attempt,
            // never the read-only inventory or a paused conversion.
            original.capture_progress(path)?;
            telemetry::event(
                "orphan_removed",
                &fence::cleanup_unpublished(path, state.latched)?,
            );
            let mut random = [0_u8; 16];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
            let generation = Mapper.import_generation(index)?;
            let identity = Identity {
                format: FORMAT,
                db_id: random.iter().map(|b| format!("{b:02x}")).collect(),
                binding,
                fence_generation: generation,
            };
            let original = state.original.as_ref().ok_or(Pause::Mismatch)?;
            let identity = original.retry_identity(identity)?;
            original.preserve(path)?;
            telemetry::baseline(path);
            let import = fence::sibling(path, ".v2.sqlite.import");
            let mut db = sqlite::Sqlite::create_import(&import)?;
            db.path_extractor(Mapper::private_paths);
            db.reference_extractor(Mapper::references);
            db.control("identity", &identity)?;
            db.control("generation", &index.generation)?;
            let cx = Mapper.import_graph(&mut db, index, state.original.as_ref())?;
            original.unchanged()?;
            original.publish_import(path, &identity, db, &mut state.latched)?;
            Ok(cx)
        })();
        // One gauge per import attempt, including one refused for an over-cap row.
        telemetry::row_cap_save();
        let mut cx = match result {
            Ok(cx) => {
                telemetry::event("import_done", &1);
                cx
            }
            Err(error) if state.latched => return Err(Hold::storage(error)),
            Err(error) => {
                let class = error.downcast_ref::<Pause>().copied().unwrap_or(Pause::Io);
                pause(state, class);
                return Ok(());
            }
        };
        // Publication succeeded: adoption failure is a hold, never a v1 result.
        let (identity, db_path) =
            fence::reconcile(path, &binding_for(path)?, true)?.ok_or(Hold::DbUnavailable)?;
        let (deadline, work) = purge_policy();
        let mut db = sqlite::Sqlite::open_with_policy(&db_path, &identity, deadline, work)
            .map_err(Hold::storage)?;
        db.path_extractor(Mapper::private_paths);
        db.reference_extractor(Mapper::references);
        db.audit_headers()?;
        let stamp = db.stamp()?;
        ensure!(
            stamp.0 == Mapper.import_generation(index)?,
            Hold::DbUnavailable
        );
        index.generation = stamp.0;
        let digests = kinds::baseline(index, &mut cx)?;
        index.v2_mut().persistence_v2 = Some(Arc::new(Runtime {
            active: true,
            session: Mutex::new(Some(Session {
                db,
                cx,
                identity,
                path: path.to_owned(),
                reload: false,
                stamp,
            })),
        }));
        telemetry::pass_start();
        register(state, index)?;
        state.save_digests = Some(digests);
        Ok(())
    })
}
fn binding_for(path: &Path) -> Result<super::super::scan_index_persistence::Binding> {
    binding(path).ok_or_else(|| Hold::ForeignBinding.into())
}

/// All save routes check independent evidence before any v1 CAS or publication.
pub(in super::super) fn save_locked(
    path: &Path,
    index: &mut ScanIndex,
    claim_only: bool,
    progress_owner: Option<&crate::snapshot_sync::SnapshotProgressLock>,
    custody: bool,
) -> Result<bool> {
    save_with_custody(path, index, claim_only, progress_owner, custody)
}
fn save_with_custody(
    path: &Path,
    index: &mut ScanIndex,
    claim_only: bool,
    progress_owner: Option<&crate::snapshot_sync::SnapshotProgressLock>,
    custody: bool,
) -> Result<bool> {
    if binding(path).is_none() {
        ensure!(index.v2().persistence_v2.is_none(), Hold::ForeignBinding);
        return Ok(false);
    }
    if index.v2().persistence_v2.is_none() && !route_needed(path, custody)? {
        return Ok(false);
    }
    // This accessor authenticates the owner/session; call before route/session locks.
    let claim_generation = super::super::sampled_audit::own_growth_claim_generation(index, path);
    let runtime = index.v2().persistence_v2.clone();
    let expected = claim_generation.unwrap_or(index.generation);
    let result = with_save_session(path, runtime, expected, claim_only, |state, session, id| {
        let previous = match state.save_digests.take() {
            Some(previous) => previous,
            None => {
                // A pass may save more than once (including claim-only saves).
                // The preceding save dropped its baseline; read committed state.
                ensure!(session.db.stamp()? == session.stamp, Hold::ReloadRequired);
                let (previous, mut cx) = Mapper.hydrate_context(&mut session.db)?;
                ensure!(session.db.stamp()? == session.stamp, Hold::ReloadRequired);
                let digests = kinds::baseline(&previous, &mut cx)?;
                // Committed rollovers outlive the dropped baseline: a sibling
                // graph saved after a claim-only save still skips them.
                cx.cold_rolled = std::mem::take(&mut session.cx.cold_rolled);
                session.cx = cx;
                digests
            }
        };
        ensure!(previous.generation == session.stamp.0, Hold::ReloadRequired);
        if claim_generation.is_some() {
            index.generation = previous.generation;
        }
        recovered_write(path, progress_owner, &id, session, |session| {
            let digests = Mapper.save(
                &mut session.db,
                &id,
                previous,
                index,
                &mut session.cx,
                claim_only,
            )?;
            session.stamp = session.db.stamp()?;
            state.saved_page(session.db.save_over_target(), claim_only);
            if !claim_only && !session.reload {
                state.save_digests = Some(digests);
            }
            Ok(true)
        })
    })
    .map(|saved| saved.unwrap_or(false));
    if result.as_ref().is_ok_and(|saved| *saved) && !claim_only {
        super::super::sampled_audit::renew_growth_claims(index, path);
    }
    result
}
/// Custody shared by both v2 writes: fence and session checks, then a stale
/// graph is refused before any write without invalidating the healthy
/// session. A failed write keeps its pressure hold and reopens the session.
/// `None`: no runtime and no published store.
fn with_save_session<T>(
    path: &Path,
    runtime: Option<Arc<Runtime>>,
    expected: u64,
    claim_only: bool,
    write: impl FnOnce(&mut RouteState, &mut Session, Identity) -> Result<T>,
) -> Result<Option<T>> {
    let binding = binding_for(path)?;
    let mut stale_graph = false;
    let mut ceiling = None;
    let mut result = held(with_state(path, |state| {
        let pair = fence::reconcile(path, &binding, state.latched)?;
        let Some(runtime) = runtime else {
            ensure!(pair.is_none(), Hold::DbUnavailable);
            return Ok(None);
        };
        let (identity, _) = pair.ok_or(Hold::FenceLost)?;
        state.latched = true;
        let mut session = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
        let session = session.as_mut().ok_or(Hold::DbUnavailable)?;
        ensure!(
            !session.reload && session.identity == identity && session.path == path,
            Hold::ForeignBinding
        );
        telemetry::baseline(path);
        let _gauge = telemetry::Stage::new(telemetry::Kind::Save);
        if expected != session.stamp.0 {
            // Refuse this graph without invalidating another graph's healthy
            // session or its durable claim-only lineage. No save has begun.
            stale_graph = true;
            bail!(Hold::ReloadRequired);
        }
        let written = write(state, session, identity);
        if let Err(error) = &written {
            ceiling = Hold::ceiling_cause(error).map(|c| (c, session.db.refused_save_bytes()));
        }
        written.map(Some)
    }));
    if let Err(error) = &result {
        if stale_graph {
            return result;
        }
        with_state(path, |state| {
            state.save_digests = None;
            state.save_retry_completed = false;
            if let (Some(Hold::SaveCeiling), Some((cause, bytes))) =
                (error.downcast_ref::<Hold>(), ceiling)
            {
                // A save-pressure hold is never silent: alarm with its fixed cause.
                telemetry::event("save_ceiling_alarm", &bytes);
                telemetry::event("save_ceiling_cause", &cause);
            }
            if (!claim_only || state.save_hold != Some(Hold::SaveOversize))
                && matches!(error.downcast_ref::<Hold>(), Some(Hold::SaveCeiling))
            {
                state.save_hold = Some(if state.page_limit == 1 {
                    telemetry::event("save_oversize_alarm", &1);
                    Hold::SaveOversize
                } else {
                    state.reduce_page();
                    Hold::SaveCeiling
                });
            } else if state.save_hold != Some(Hold::SaveOversize)
                && matches!(error.downcast_ref::<Hold>(), Some(Hold::SaveFull))
            {
                state.save_hold = Some(Hold::SaveFull);
            }
            if let Some(runtime) = &state.current {
                if let Some(session) = runtime
                    .session
                    .lock()
                    .map_err(|_| Hold::DbUnavailable)?
                    .as_mut()
                {
                    session.reload = true;
                }
            }
            Ok(())
        })?;
    }
    if result.is_err() {
        if let Some(hold) = with_state(path, |state| Ok(state.save_hold))? {
            telemetry::event("hold", &hold);
            result = Err(hold.into());
        }
    }
    result
}

/// Progress recovery under the source owner, then the write. A failed write
/// reports the store's typed hold.
fn recovered_write<T>(
    path: &Path,
    progress_owner: Option<&crate::snapshot_sync::SnapshotProgressLock>,
    identity: &Identity,
    session: &mut Session,
    write: impl FnOnce(&mut Session) -> Result<T>,
) -> Result<T> {
    let result =
        crate::snapshot_sync::with_state_v2_progress_owner(path, progress_owner, |owner, _| {
            super::ack::ProgressRecovery::recover_route_locked(
                identity,
                session.stamp.0,
                path,
                owner,
            )?;
            write(session)
        });
    if result.is_err() {
        if let Some(hold) = session.db.save_failure() {
            return Err(hold.into());
        }
    }
    result
}

pub(in super::super) type GrowthRows =
    BTreeMap<String, super::super::sampled_audit::GrowthRetention>;
/// Claim-only growth write without a graph hydrate. The caller holds
/// CheckpointLock and has authenticated `expected` as its lineage's G. One
/// BEGIN IMMEDIATE transaction reads the committed growth rows, the key's raw
/// hold and which of those keys still have a file row; `decide` updates the
/// rows and says whether to write. The rows then commit as G+1 through the
/// save's own row writer, so row caps, erasure marks and the gauge apply.
/// A graph without a v2 runtime or binding is refused: there is no route.
pub(in super::super) fn claim_growth_locked(
    path: &Path,
    index: &ScanIndex,
    expected: u64,
    key: &str,
    decide: impl FnOnce(&mut GrowthRows, bool, &BTreeSet<String>) -> bool,
) -> Result<(bool, GrowthRows)> {
    let runtime = index.v2().persistence_v2.clone();
    ensure!(runtime.is_some(), Hold::ReloadRequired);
    let _save_window = telemetry::Window::begin("save");
    with_save_session(path, runtime, expected, true, |state, session, id| {
        recovered_write(path, None, &id, session, |session| {
            #[cfg(test)]
            if tests::COMMIT_BEFORE_GROWTH_CLAIM.with(std::cell::Cell::take) {
                let tx = session.db.begin(TxnMode::Write)?;
                ensure!(
                    tx.commit(expected, expected + 1)
                        == DurableCommitOutcome::Committed(expected + 1),
                    "synthetic concurrent commit"
                );
            }
            let claimed = growth_claim_txn(
                &mut session.db,
                &id,
                expected,
                key,
                state.save_digests.as_mut(),
                decide,
            )?;
            if claimed.0 {
                session.stamp = session.db.stamp()?;
            }
            Ok(claimed)
        })
    })?
    .ok_or_else(|| Hold::ReloadRequired.into())
}
fn growth_claim_txn(
    db: &mut sqlite::Sqlite,
    identity: &Identity,
    expected: u64,
    key: &str,
    baseline: Option<&mut kinds::Baseline>,
    decide: impl FnOnce(&mut GrowthRows, bool, &BTreeSet<String>) -> bool,
) -> Result<(bool, GrowthRows)> {
    const KIND: &str = "file.growth_retention";
    if let Some(baseline) = &baseline {
        ensure!(baseline.generation == expected, Hold::ReloadRequired);
    }
    let next = expected.checked_add(1).ok_or(Hold::DbUnavailable)?;
    let mut span = kinds::SaveSpan::begin(db);
    db.validate_save(identity, expected)?;
    let mut tx = db.begin(TxnMode::Write)?;
    let mut old = mapper::Digests::new();
    let mut rows: GrowthRows = mapper::read_map(&mut tx, KIND, None, Some(&mut old))?;
    let hold = RowKey::record("raw_hold.growth_retention", key.as_bytes(), 0)?;
    let held = tx.get(&hold)?.is_some();
    let mut files = BTreeSet::new();
    for name in rows.keys().map(String::as_str).chain([key]) {
        if tx.get(&mapper::key("file.progress", name, 1)?)?.is_some() {
            files.insert(name.to_owned());
        }
    }
    if !decide(&mut rows, held, &files) {
        return Ok((false, rows));
    }
    let mut writer = mapper::Rows {
        tx: Some(&mut tx as &mut dyn Transaction),
        old,
        ..Default::default()
    };
    writer.map(KIND, &rows)?;
    let digests = writer.finish()?;
    // COMMIT re-checks the generation control against G inside this write.
    let outcome = tx.commit(expected, next);
    span.outcome(&outcome);
    let refused = outcome == DurableCommitOutcome::NotPublished;
    span.emit(db, if refused { expected } else { next });
    match outcome {
        DurableCommitOutcome::Committed(generation) if generation == next => {
            if let Some(baseline) = baseline {
                // A reclaimed member can return with identical bytes; its old
                // digest would skip recreating it. Replace manifest and members.
                baseline.rows.retain(
                    |key, _| !matches!(key, RowKey::Record { kind, .. } if kind.name() == KIND),
                );
                baseline.rows.extend(digests);
                baseline.generation = next;
            }
            Ok((true, rows))
        }
        DurableCommitOutcome::NotPublished => {
            bail!(db.save_failure().unwrap_or(Hold::ReloadRequired))
        }
        _ => bail!(Hold::ReloadRequired),
    }
}
pub(in super::super) fn guard_containment_locked(path: &Path) -> Result<()> {
    if binding(path).is_none() || !route_needed(path, published(path)?)? {
        return Ok(());
    }
    // A containment guard never promotes a DB. This also covers a parent/root
    // appearing during the absent-parent path where no checkpoint lock exists.
    held(with_state(path, |state| {
        ensure!(
            !state.latched && !fence::evidence(path)?,
            Hold::DbUnavailable
        );
        Ok(())
    }))
}

/// Caller retains the process-lifetime LockedStateDir. This guard is repeated
/// at each external boundary; COMMIT fencing alone is too late for uploads.
pub(in super::super) fn guard_external(
    path: &Path,
    runtime: Option<&Arc<Runtime>>,
    graph_generation: u64,
) -> Result<()> {
    guard_current(path, runtime, graph_generation, true)
}

/// Local receipt binding before collection: a save-pressure hold must not stop
/// the held pass that retries the save. Lock, reload, fence and generation
/// checks still apply; uploads keep `guard_external` at each external boundary.
pub(in super::super) fn guard_local(
    path: &Path,
    runtime: Option<&Arc<Runtime>>,
    graph_generation: u64,
) -> Result<()> {
    guard_current(path, runtime, graph_generation, false)
}

/// Only the local checkpoint-retry path may ignore a save-pressure hold.
/// Generation, owner, reload and capability fencing still apply.
pub(in super::super) fn recovery_save_guard(
    path: &Path,
    index: &ScanIndex,
) -> Result<Option<impl Fn() -> Result<()>>> {
    let Some(runtime) = &index.v2().persistence_v2 else {
        return Ok(None);
    };
    if !with_state(path, |state| Ok(state.save_hold.is_some()))? {
        return Ok(None);
    }
    let path = path.to_owned();
    let runtime = runtime.clone();
    let generation = super::super::sampled_audit::own_growth_claim_generation(index, &path)
        .unwrap_or(index.generation);
    Ok(Some(move || {
        guard_current(&path, Some(&runtime), generation, false)
    }))
}

fn guard_current(
    path: &Path,
    runtime: Option<&Arc<Runtime>>,
    graph_generation: u64,
    external: bool,
) -> Result<()> {
    let Some(runtime) = runtime else {
        return Ok(());
    };
    let _lock = super::super::CheckpointLock::acquire(path)?;
    held(with_state(path, |state| {
        if external {
            if let Some(hold) = state.save_hold {
                return Err(hold.into());
            }
        }
        let mut guard = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
        let session = guard.as_mut().ok_or(Hold::ReloadRequired)?;
        ensure!(
            !session.reload && session.path == path,
            Hold::ReloadRequired
        );
        let pair = fence::reconcile(path, &session.identity.binding, state.latched)?;
        ensure!(
            pair.is_some_and(|(id, _)| id == session.identity),
            Hold::FenceLost
        );
        let stamp = session.db.stamp()?;
        ensure!(
            stamp == session.stamp && stamp.0 == graph_generation,
            Hold::ReloadRequired
        );
        Ok(())
    }))
}

fn runtime_path(index: &ScanIndex) -> Result<Option<PathBuf>> {
    let Some(runtime) = &index.v2().persistence_v2 else {
        return Ok(None);
    };
    let guard = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
    Ok(Some(
        guard.as_ref().ok_or(Hold::ReloadRequired)?.path.clone(),
    ))
}

/// Live custody alone exceeds the companion bound. Pace collection at the
/// growth-full interval: one parse/admission retry per interval, no POST in
/// between, and owed debt stays in the unchanged index/progress.
pub(in super::super) fn hold_ack_custody(path: &Path) {
    let retry_at =
        Instant::now() + Duration::from_secs(super::super::sampled_audit::GROWTH_FULL_INTERVAL);
    if with_state(path, |state| {
        state.custody_retry_at = Some(retry_at);
        Ok(())
    })
    .is_ok()
    {
        telemetry::event("hold", &Hold::AckCustody);
        telemetry::count("ack_custody_hold_alarm", 1);
    }
}

/// Existing routes only: an admission probe never adds a registry slot.
pub(in super::super) fn ack_custody_held(path: &Path) -> bool {
    let Some(state) = states()
        .lock()
        .ok()
        .and_then(|states| states.get(path).cloned())
    else {
        return false;
    };
    state.lock().is_ok_and(|state| state.custody_held())
}

pub(in super::super) fn save_oversize_active(index: &ScanIndex) -> Result<bool> {
    let Some(path) = runtime_path(index)? else {
        return Ok(false);
    };
    with_state(&path, |state| {
        Ok(state.save_hold == Some(Hold::SaveOversize))
    })
}

/// Native completion can make a recovery delta safe without advancing an
/// unACKed file entry. The subsequent successful normal save clears the hold.
pub(in super::super) fn save_read_completed(index: &ScanIndex, key: &str) -> Result<()> {
    let Some(path) = runtime_path(index)? else {
        return Ok(());
    };
    with_state(&path, |state| {
        if state.save_hold == Some(Hold::SaveOversize)
            && state
                .last_read
                .as_ref()
                .is_some_and(|(held, _)| held == key)
        {
            state.save_retry_completed = true;
        }
        Ok(())
    })
}

/// Gate before transcript samples/reads. Keep the source fence: upload recovery
/// and accepted progress are source-owned, so a per-file bypass is unsafe here.
/// Only the page-one file may retry; growth_read_admitted then requires the
/// existing durable growth Full claim before admitting its payload.
pub(in super::super) fn save_read_admitted(index: &ScanIndex, key: &str, now: u64) -> Result<bool> {
    let Some(path) = runtime_path(index)? else {
        return Ok(true);
    };
    with_state(&path, |state| {
        if state.save_hold == Some(Hold::SaveOversize)
            && !state.last_read.as_ref().is_some_and(|(held, last)| {
                held == key
                    && now >= last.saturating_add(super::super::sampled_audit::GROWTH_FULL_INTERVAL)
            })
        {
            // Unknown key means the delta was not a single file acquisition.
            return Ok(false);
        }
        if state.page_limit == 1 {
            state.last_read = Some((key.to_owned(), now));
            state.save_retry_completed = false;
        }
        Ok(true)
    })
}

pub(in super::super) fn collection_page_limit(index: &ScanIndex, requested: usize) -> usize {
    let Some(_) = &index.v2().persistence_v2 else {
        return requested;
    };
    let path = runtime_path(index).ok().flatten();
    path.and_then(|p| {
        with_state(&p, |s| {
            s.requested_page = requested.max(1);
            s.page_limit = s.page_limit.min(s.requested_page);
            Ok(s.page_limit.min(requested))
        })
        .ok()
    })
    .unwrap_or(requested.min(250))
}

pub(super) fn purge_policy() -> (Duration, Duration) {
    let seconds = std::env::var("OTTTO_CLAUDE_STATE_V2_ERASURE_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(86400)
        .min(72 * 3600);
    (Duration::from_secs(seconds), Duration::from_secs(2))
}

/// idle releases the page baseline when a cycle completes; an error exit skips
/// idle, so dropping this at the cycle's end releases it as well.
pub(in super::super) struct BaselineRelease(Option<PathBuf>);
impl BaselineRelease {
    pub(in super::super) fn new(path: &Path, index: &ScanIndex) -> Self {
        // A v1 graph has no runtime: hold nothing, so drop is a no-op.
        Self(index.v2().persistence_v2.as_ref().map(|_| path.to_owned()))
    }
}
impl Drop for BaselineRelease {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = with_state(path, |state| {
                state.save_digests = None;
                Ok(())
            });
        }
    }
}
pub(in super::super) fn idle(path: &Path, index: &ScanIndex, quiet: bool) -> Result<()> {
    let Some(runtime) = &index.v2().persistence_v2 else {
        return Ok(());
    };
    // The cycle can finish without saving. Release its baseline even if
    // advisory maintenance cannot acquire the checkpoint lock or fails.
    with_state(path, |state| {
        state.save_digests = None;
        Ok(())
    })?;
    let _lock = super::super::CheckpointLock::acquire(path)?;
    held(with_state(path, |state| {
        let mut session = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
        let session = session.as_mut().ok_or(Hold::DbUnavailable)?;
        ensure!(!session.reload && session.path == path, Hold::DbUnavailable);
        let pair = fence::reconcile(path, &session.identity.binding, state.latched)?;
        ensure!(
            pair.is_some_and(|(identity, _)| identity == session.identity),
            Hold::ForeignBinding
        );
        telemetry::baseline(path);
        // This hook is between sync cycles even when that cycle saved rows.
        erasure_inventory(path)?;
        session.db.between_cycles(quiet).map_err(Hold::storage)?;
        session.db.clean_checkpoint().map_err(Hold::storage)?;
        session.stamp = session.db.stamp()?;
        telemetry::event(
            "bytes_written_per_pass",
            &state
                .pass_written_start
                .zip(telemetry::process_written_bytes())
                .and_then(|(a, b)| b.checked_sub(a)),
        );
        Ok(())
    }))
}
fn register(state: &mut RouteState, index: &ScanIndex) -> Result<()> {
    state.runtimes.retain(|r| r.strong_count() != 0);
    ensure!(state.runtimes.len() < 16, Hold::DbUnavailable);
    if let Some(runtime) = &index.v2().persistence_v2 {
        state.runtimes.push(Arc::downgrade(runtime));
        state.current = Some(runtime.clone());
    }
    Ok(())
}

/// Inventory only: the baseline's explicit single-file erasure exception and
/// the H/N/L-only restart cache are not covered by a DB VACUUM claim.
fn erasure_inventory(path: &Path) -> Result<()> {
    let artifacts = fence::ARTIFACTS
        .iter()
        .filter_map(|(suffix, _, class)| class.map(|class| (class, fence::sibling(path, suffix))))
        .chain(std::iter::once((
            "restart_record_inventory",
            crate::durable_tail_store::store_dir_for_index(path),
        )));
    for (class, artifact) in artifacts {
        let mut count = 0_u64;
        let mut bytes = 0_u64;
        let mut bounded = false;
        match fs::symlink_metadata(&artifact) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
                for entry in fs::read_dir(&artifact)?.take(1025) {
                    let m = entry?.metadata()?;
                    count += 1;
                    bytes = bytes.saturating_add(m.len());
                    if count > 1024 {
                        bounded = true;
                        break;
                    }
                }
            }
            Ok(m) => {
                count = 1;
                bytes = m.len();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if class == "ack_receipt_inventory" {
            let (failed_count, failed_bytes) = super::ack::failed_import_inventory(path)?;
            count = count.saturating_add(failed_count);
            bytes = bytes.saturating_add(failed_bytes);
        }
        telemetry::event(
            class,
            &serde_json::json!({"count":count,"bytes":bytes,"bounded":bounded}),
        );
    }
    Ok(())
}

fn invalidate_locked(path: &Path) -> Result<()> {
    with_state(path, |state| {
        state.latched = true;
        state.inventory_ready = false;
        state.save_digests = None;
        state.current = None;
        for runtime in state.runtimes.drain(..).filter_map(|r| r.upgrade()) {
            runtime
                .session
                .lock()
                .map_err(|_| Hold::DbUnavailable)?
                .take();
        }
        Ok(())
    })
}
/// Uninstall retains its existing OS/ownership/cleanup ordering. Close native
/// handles first; its established cleanup owner performs all file deletion.
#[cfg(target_os = "macos")]
pub(in super::super) fn invalidate_tree(support: &Path) -> Result<()> {
    close_tree(support, false)
}

/// Explicit erasure only. Close the shared session before unlinking all
/// artifacts, and invalidate clones before releasing CheckpointLock.
pub(in super::super) fn erase_locked(path: &Path, index: Option<&ScanIndex>) -> Result<()> {
    invalidate_locked(path)?;
    if let Some(runtime) = index.and_then(|i| i.v2().persistence_v2.as_ref()) {
        runtime
            .session
            .lock()
            .map_err(|_| Hold::DbUnavailable)?
            .take();
    }
    for (suffix, _, _) in fence::ARTIFACTS {
        fence::remove_artifact(&fence::sibling(path, suffix))?;
    }
    super::ack::erase_failed_imports(path)?;
    super::super::sync_checkpoint_parent(path)?;
    let records = crate::durable_tail_store::store_dir_for_index(path);
    match fs::symlink_metadata(&records) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => fs::remove_dir_all(&records)?,
        Ok(_) => fs::remove_file(&records)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    super::super::sync_checkpoint_parent(path)?;
    telemetry::event("source_erasure_confirmed", &1);
    // Retain the invalidated route's custody latch: erased artifacts must not
    // let this process resume v1 or re-create v2 without an explicit new lineage.
    Ok(())
}

/// Close/erase only live runtimes already owned by this process. The caller's
/// existing whole-tree removal owns legacy files and unregistered artifacts;
/// discovering those files here would register routes for files no source reads.
pub(in super::super) fn erase_tree(support: &Path) -> Result<()> {
    close_tree(support, true)
}

fn close_tree(support: &Path, erase: bool) -> Result<()> {
    let root = support.join("snapshots");
    let routes: Vec<_> = states()
        .lock()
        .map_err(|_| Hold::DbUnavailable)?
        .iter()
        .filter(|(path, _)| path.starts_with(&root))
        .map(|(path, state)| (path.clone(), state.clone()))
        .collect();
    for (path, state) in routes {
        let live = {
            let state = state.lock().map_err(|_| Hold::DbUnavailable)?;
            let mut live = false;
            for runtime in state.runtimes.iter().filter_map(|r| r.upgrade()) {
                if runtime
                    .session
                    .lock()
                    .map_err(|_| Hold::DbUnavailable)?
                    .is_some()
                {
                    live = true;
                    break;
                }
            }
            live
        };
        if !live {
            continue;
        }
        if path.parent().is_some_and(Path::is_dir) {
            let _lock = super::super::CheckpointLock::acquire(&path)?;
            if erase {
                erase_locked(&path, None)?;
            } else {
                invalidate_locked(&path)?;
            }
        } else {
            invalidate_locked(&path)?;
        }
    }
    Ok(())
}

/// Store-only rows of one kind, read on the graph's own session in one short
/// read transaction. `Some`: those families' rows by key (a missing row is no
/// callback). `None`: the whole kind, complete by its manifest count. Each
/// value comes with its row digest as stored. A graph not at the generation
/// its save would commit over (its own, or its confirmed growth claim's),
/// or a store changed elsewhere, holds.
pub(in super::super) fn read_cold<T: serde::de::DeserializeOwned + Serialize>(
    index: &ScanIndex,
    kind: &str,
    roots: Option<&std::collections::BTreeSet<String>>,
    f: &mut dyn FnMut(String, T, [u8; 32]) -> Result<()>,
) -> Result<()> {
    // The save path's rule: a claim-only growth save in this pass moved the
    // store past the working graph. Authenticate before the session lock.
    let path = runtime_path(index)?.ok_or(Hold::DbUnavailable)?;
    let generation = super::super::sampled_audit::own_growth_claim_generation(index, &path)
        .unwrap_or(index.generation);
    let runtime = index
        .v2()
        .persistence_v2
        .as_ref()
        .ok_or(Hold::DbUnavailable)?;
    let mut guard = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
    let session = guard.as_mut().ok_or(Hold::DbUnavailable)?;
    ensure!(
        !session.reload && !session.db.reload_required(),
        Hold::DbUnavailable
    );
    let stamp = session.db.stamp()?;
    ensure!(
        stamp == session.stamp && generation == stamp.0,
        Hold::DbUnavailable
    );
    let mut tx = session.db.begin(TxnMode::Read)?;
    let expected = match roots {
        Some(_) => None,
        None => {
            let h = tx
                .get(&mapper::key(kind, "", 0)?)?
                .context("state_v2_missing_manifest")?;
            Some(mapper::read::<usize>(&mut tx, &h, None)?)
        }
    };
    let mut count = 0_usize;
    mapper::visit(&mut tx, kind, roots, |tx, h| {
        let RowKey::Record {
            key_bytes,
            position,
            ..
        } = &h.key
        else {
            bail!("state_v2_record_key")
        };
        if *position == 0 {
            ensure!(key_bytes.is_empty(), "state_v2_manifest_key");
            return Ok(());
        }
        ensure!(*position == 1, "state_v2_member_position");
        count += 1;
        let mut digests = mapper::Digests::new();
        let value = mapper::read(tx, &h, Some(&mut digests))?;
        let digest = digests.remove(&h.key).context("state_v2_row_digest")?;
        f(mapper::family(key_bytes)?, value, digest)
    })?;
    ensure!(
        expected.map_or(true, |expected| expected == count),
        "state_v2_missing_member"
    );
    Ok(())
}

/// Cold usage pending: load the families a page names before it
/// accumulates (`Some`), or every family before a decision that joins them
/// (`None`). A missing, changed or unreadable row, or a store this graph does
/// not hold, is Unknown and the caller refuses its whole decision. Counted.
/// Rows install one at a time, only after every wanted row was read: a later
/// digest mismatch can leave earlier verified rows installed while the caller
/// still refuses the whole decision.
pub(in super::super) fn load_usage(
    index: &mut ScanIndex,
    roots: Option<&std::collections::BTreeSet<String>>,
) -> Result<()> {
    let usage = &index.claude_usage_family_pending;
    if usage.cold().is_none() {
        return Ok(());
    }
    let wanted = match roots {
        Some(roots) => {
            let wanted = usage.unloaded(roots.iter().map(String::as_str));
            if wanted.is_empty() {
                return Ok(());
            }
            Some(wanted)
        }
        None if usage.all().is_ok() => return Ok(()),
        None => None,
    };
    let result = (|| -> Result<()> {
        let mut read = Vec::new();
        read_cold(
            index,
            "usage.pending",
            wanted.as_ref(),
            &mut |root, value, digest| {
                read.push((root, value, digest));
                Ok(())
            },
        )?;
        // Every wanted row must have been read before any is installed.
        if let Some(wanted) = &wanted {
            let read: std::collections::BTreeSet<&String> =
                read.iter().map(|(root, _, _)| root).collect();
            ensure!(
                wanted.iter().all(|root| read.contains(root)),
                super::super::usage_pending::Unknown
            );
        }
        let cold = index
            .claude_usage_family_pending
            .cold_mut()
            .ok_or(Hold::DbUnavailable)?;
        for (root, value, digest) in read {
            cold.install(root, value, digest)?;
        }
        if wanted.is_none() {
            cold.complete()?;
        }
        Ok(())
    })();
    if result.is_err() {
        telemetry::count("usage_pending_unknown", 1);
    }
    result
}

/// End a decision that loaded every cold usage family: values unchanged
/// since their row was read return to heads, except the `keep` families.
pub(in super::super) fn settle_usage(
    index: &mut ScanIndex,
    keep: &std::collections::BTreeSet<String>,
) {
    if let Some(cold) = index.claude_usage_family_pending.cold_mut() {
        cold.settle(keep, |family| mapper::digest(family).ok());
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
#[cfg(test)]
pub(in super::super) use tests::{
    delete_usage_row_in_session, erase_published, materialized, usage_unknown_count,
};

// OPS maintenance boundary; routing/import/ACK remain owned by their adapters.
#[path = "runtime_ops.rs"]
mod ops;
pub(in super::super) use ops::before_collection;

/// Read-only custody seam for growth receipts. Callers doing CAS retain the
/// checkpoint lock; never acquire it recursively from the save hook.
pub(in super::super) fn confirmed_growth_stamp(
    index: &ScanIndex,
    path: &Path,
) -> Result<(u64, u64)> {
    held(with_state(path, |state| {
        let runtime = index
            .v2()
            .persistence_v2
            .as_ref()
            .ok_or(Hold::ReloadRequired)?;
        ensure!(
            state
                .current
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, runtime)),
            Hold::ForeignBinding
        );
        let guard = runtime.session.lock().map_err(|_| Hold::ReloadRequired)?;
        let session = guard.as_ref().ok_or(Hold::ReloadRequired)?;
        ensure!(
            !session.reload && session.path == path,
            Hold::ReloadRequired
        );
        let pair = fence::reconcile(path, &session.identity.binding, state.latched)?;
        ensure!(
            pair.is_some_and(|(identity, _)| identity == session.identity),
            Hold::FenceLost
        );
        let stamp = session.db.stamp()?;
        ensure!(stamp == session.stamp, Hold::ReloadRequired);
        Ok(stamp)
    }))
}

#[cfg(test)]
#[path = "runtime_growth_tests.rs"]
mod growth_tests;

#[path = "runtime_live_keys.rs"]
mod live_keys;
pub(crate) use live_keys::{live_key_digests, IncompleteReason, LiveKeys};
