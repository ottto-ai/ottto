//! Locked runtime routing. Conversion stays paused until publication integration
//! is complete. OFF remains v1 before publication; custody evidence always wins.
use super::*;
use anyhow::{bail, ensure};
use import::{ClaudeMapper, Mapper, Pace, Pause};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum Hold {
    Future,
    DbUnavailable,
    ForeignBinding,
    FenceLost,
    NewerSchema,
    MigrationFailed,
    ReloadRequired,
    IntegrityRetry,
    SaveAdmission,
    ReferenceDrift,
}
impl std::fmt::Display for Hold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Future => "scan_index_representation_refused",
            Self::DbUnavailable => "state_v2_db_unavailable",
            Self::ForeignBinding => "state_v2_foreign_binding",
            Self::NewerSchema => "state_v2_newer_schema_refused",
            Self::MigrationFailed => "state_v2_migration_failed",
            Self::SaveAdmission => "state_v2_save_admission",
            Self::IntegrityRetry => "state_v2_integrity_retry",
            Self::ReferenceDrift => "state_v2_reference_drift",
            Self::ReloadRequired => "current_index_requires_reload",
            Self::FenceLost => "state_v2_fence_lost",
        })
    }
}
impl std::error::Error for Hold {}
impl Hold {
    pub(super) fn storage(error: anyhow::Error) -> anyhow::Error {
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
        let hold = if error.chain().any(|e| {
            matches!(
                e.to_string().as_str(),
                "state_v2_save_admission" | "state_v2_path_diff_admission"
            )
        }) {
            Self::SaveAdmission
        } else if error
            .chain()
            .any(|e| e.to_string() == "state_v2_foreign_binding")
        {
            Self::ForeignBinding
        } else if error
            .chain()
            .any(|e| e.to_string() == "scan_index_representation_refused")
        {
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
}
struct RouteState {
    pace: Pace,
    latched: bool,
    inventory_ready: bool,
    original: Option<import::Original>,
    sample_v1: bool,
    runtimes: Vec<std::sync::Weak<Runtime>>,
    current: Option<Arc<Runtime>>,
    cached: Option<ScanIndex>,
    page_limit: usize,
    pass_written_start: Option<u64>,
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
        ensure!(
            states.contains_key(path) || states.len() < 64,
            Hold::DbUnavailable
        );
        states
            .entry(path.to_owned())
            .or_insert_with(|| {
                Arc::new(Mutex::new(RouteState {
                    pace: Pace::default(),
                    latched: false,
                    inventory_ready: false,
                    original: None,
                    sample_v1: false,
                    runtimes: Vec::new(),
                    current: None,
                    cached: None,
                    page_limit: 250,
                    pass_written_start: None,
                }))
            })
            .clone()
    };
    let mut state = state.lock().map_err(|_| Hold::DbUnavailable)?;
    f(&mut state)
}

pub(super) fn enabled(support: Option<&Path>) -> bool {
    let Some(support) = support else {
        return false;
    };
    std::env::var("OTTTO_CLAUDE_STATE_V2")
        .ok()
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        || support.join("snapshots/claude_state_v2").is_file()
}
fn route_needed(path: &Path, switched: bool) -> Result<bool> {
    Ok(switched
        || states()
            .lock()
            .map_err(|_| Hold::DbUnavailable)?
            .contains_key(path)
        || fence::evidence(path)?)
}
pub(super) fn observed(path: &Path) -> bool {
    let state = states()
        .lock()
        .ok()
        .and_then(|states| states.get(path).cloned());
    state.is_some_and(|state| state.lock().is_ok_and(|state| state.sample_v1))
}
fn binding(path: &Path) -> Option<super::super::scan_index_persistence::Binding> {
    super::super::scan_index_integration::scan_index_storage_binding(path)
        .filter(|b| b.source == super::super::scan_index_persistence::Source::Claude)
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
) -> Result<Option<ScanIndex>> {
    load_with(path, enabled(support), &ClaudeMapper)
}
fn load_with<M: Mapper>(path: &Path, switched: bool, mapper: &M) -> Result<Option<ScanIndex>> {
    let Some(binding) = binding(path) else {
        return Ok(None);
    };
    if !route_needed(path, switched)? {
        return Ok(None);
    }
    let result = held(with_state(path, |state| {
        state.inventory_ready = false;
        state.original = None;
        state.pass_written_start = telemetry::process_written_bytes();
        state.sample_v1 = switched;
        let pair = fence::reconcile(path, &binding, state.latched)?;
        if let Some((identity, db_path)) = pair {
            state.latched = true;
            if !switched {
                telemetry::event("switch_off_ignored", &1);
            }
            telemetry::baseline(path);
            if let Some(runtime) = state.current.clone() {
                let mut guard = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
                if let Some(session) = guard.as_mut() {
                    let stamp = session.db.stamp()?;
                    if !session.reload && session.identity == identity && session.stamp == stamp {
                        super::ack::ProgressRecovery::recover_route(&identity, stamp.0, path)?;
                        if let Some(index) = state.cached.as_ref() {
                            if index.generation == stamp.0 {
                                telemetry::event("route", &"v2_cached");
                                return Ok(Some(index.clone()));
                            }
                        }
                        // A concurrent borrower consumed the graph, so hydrate
                        // on the same connection; never acquire another owner.
                        let _gauge = telemetry::Stage::new(telemetry::Kind::Hydrate);
                        telemetry::event("hydrate_count", &1);
                        let (mut index, mut cx) = mapper.hydrate_context(&mut session.db)?;
                        ensure!(index.generation == stamp.0, Hold::DbUnavailable);
                        normalize_hydrated(&mut index)?;
                        if session
                            .db
                            .begin(TxnMode::Read)?
                            .get(&RowKey::record("unit.deferred", Vec::new(), 0)?)?
                            .is_some()
                        {
                            super::recovery_backup::roll(path, &mut session.db, &identity)?;
                        }
                        mapper.restore_selected(&mut session.db, &mut index, &mut cx)?;
                        super::recovery_backup::roll(path, &mut session.db, &identity)?;
                        session.stamp = session.db.stamp()?;
                        ensure!(index.generation == session.stamp.0, Hold::DbUnavailable);
                        normalize_hydrated(&mut index)?;
                        session.cx = cx;
                        index.persistence_v2 = Some(runtime.clone());
                        state.cached = Some(index.clone());
                        return Ok(Some(index));
                    }
                }
                // Invalidate every old clone before replacing the connection.
                guard.take();
                state.cached = None;
                state.current = None;
            }
            let _gauge = telemetry::Stage::new(telemetry::Kind::Hydrate);
            telemetry::event("hydrate_count", &1);
            let (deadline, work) = purge_policy();
            let mut db = sqlite::Sqlite::open_with_policy(&db_path, &identity, deadline, work)
                .map_err(Hold::storage)?;
            db.path_extractor(M::private_paths);
            db.reference_extractor(M::references);
            let stamp = db.stamp()?;
            super::ack::ProgressRecovery::recover_route(&identity, stamp.0, path)?;
            let (mut index, mut cx) = mapper.hydrate_context(&mut db)?;
            normalize_hydrated(&mut index)?;
            if db
                .begin(TxnMode::Read)?
                .get(&RowKey::record("unit.deferred", Vec::new(), 0)?)?
                .is_some()
            {
                super::recovery_backup::roll(path, &mut db, &identity)?;
            }
            mapper.restore_selected(&mut db, &mut index, &mut cx)?;
            super::recovery_backup::roll(path, &mut db, &identity)?;
            let stamp = db.stamp()?;
            ensure!(index.generation == stamp.0, Hold::DbUnavailable);
            normalize_hydrated(&mut index)?;
            db.prime_headers()?;
            index.persistence_v2 = Some(Arc::new(Runtime {
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
            state.cached = Some(index.clone());
            telemetry::event("route", &"v2");
            return Ok(Some(index));
        }
        if !switched {
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
            match mapper.inventory_context(path) {
                Ok(original) => {
                    state.inventory_ready = true;
                    state.original = original;
                }
                Err(class) => {
                    pause(state, now, class);
                }
            }
        }
        telemetry::event("route", &"v1");
        Ok(None)
    }));
    if result.is_err() {
        with_state(path, |state| {
            state.cached = None;
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

fn pause(state: &mut RouteState, now: Instant, class: Pause) {
    state.inventory_ready = false;
    state.original = None;
    state.pace.failed(now, class);
    telemetry::event("import_paused", &class);
    telemetry::event("import_paused_alarm", &1);
    if state.pace.disabled() {
        telemetry::event("import_disabled", &1);
    }
}

/// Import is attempted only on the normalized available graph and only if the
/// pre-decode inventory acquired a due slot. No writes on any paused path.
pub(in super::super) fn after_v1_locked(path: &Path, index: &mut ScanIndex) -> Result<()> {
    import_with(path, index, &ClaudeMapper)
}
fn import_with<M: Mapper>(path: &Path, index: &mut ScanIndex, mapper: &M) -> Result<()> {
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
        let now = Instant::now();
        if !index.persistence_available() {
            pause(state, now, Pause::Partial);
            return Ok(());
        }
        let _gauge = telemetry::Stage::import(path);
        if let Err(class) = mapper.preflight(index) {
            pause(state, now, class);
            return Ok(());
        }
        let result = (|| -> Result<KindCx> {
            if let Some(original) = &mut state.original {
                original.unchanged()?;
                // Progress locking belongs to the actual conversion attempt,
                // never the read-only inventory or a paused conversion.
                original.capture_progress(path)?;
            }
            telemetry::event(
                "orphan_removed",
                &fence::cleanup_unpublished(path, state.latched)?,
            );
            let mut random = [0_u8; 16];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
            let generation = mapper.import_generation(index)?;
            let identity = Identity {
                format: FORMAT,
                db_id: random.iter().map(|b| format!("{b:02x}")).collect(),
                binding,
                fence_generation: generation,
            };
            let identity = match &state.original {
                Some(original) => original.retry_identity(identity)?,
                None => identity,
            };
            preserve_baseline(path, state.original.as_ref())?;
            let import = fence::sibling(path, ".v2.sqlite.import");
            let mut db = sqlite::Sqlite::create_import(&import)?;
            db.path_extractor(M::private_paths);
            db.reference_extractor(M::references);
            db.control("identity", &identity)?;
            db.control("generation", &index.generation)?;
            let cx = mapper.import_graph(&mut db, index, state.original.as_ref())?;
            if let Some(original) = &state.original {
                original.unchanged()?;
                original.publish_import(path, &identity, db, &mut state.latched)?;
            } else {
                db.finish_import()?;
                fence::boundary(fence::Boundary::ImportFinished)?;
                fence::publish(path, &identity, &mut state.latched)?;
            }
            Ok(cx)
        })();
        let cx = match result {
            Ok(cx) => {
                telemetry::event("import_done", &1);
                cx
            }
            Err(error) if state.latched => return Err(Hold::storage(error)),
            Err(error) => {
                let class = error.downcast_ref::<Pause>().copied().unwrap_or(Pause::Io);
                pause(state, now, class);
                return Ok(());
            }
        };
        // Publication succeeded: adoption failure is a hold, never a v1 result.
        let (identity, db_path) =
            fence::reconcile(path, &binding_for(path)?, true)?.ok_or(Hold::DbUnavailable)?;
        let (deadline, work) = purge_policy();
        let mut db = sqlite::Sqlite::open_with_policy(&db_path, &identity, deadline, work)
            .map_err(Hold::storage)?;
        db.path_extractor(M::private_paths);
        db.reference_extractor(M::references);
        db.prime_headers()?;
        let stamp = db.stamp()?;
        ensure!(
            stamp.0 == mapper.import_generation(index)?,
            Hold::DbUnavailable
        );
        index.generation = stamp.0;
        index.persistence_v2 = Some(Arc::new(Runtime {
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
        register(state, index)?;
        state.cached = Some(index.clone());
        Ok(())
    })
}
fn binding_for(path: &Path) -> Result<super::super::scan_index_persistence::Binding> {
    binding(path).ok_or_else(|| Hold::ForeignBinding.into())
}

fn preserve_baseline(path: &Path, original: Option<&import::Original>) -> Result<()> {
    if let Some(original) = original {
        original.preserve(path)?;
        telemetry::baseline(path);
        return Ok(());
    }
    if !fence::exists(path)? {
        return Ok(());
    }
    let mut bytes = fence::preserve_file(path, &fence::sibling(path, ".v1-readonly"))?;
    // Preserve the entire immutable shard directory, including every referenced
    // payload. Never parse row content or follow links. Reject nested objects.
    let shards = fence::sibling(path, ".shards");
    if fence::exists(&shards)? {
        let metadata = fs::symlink_metadata(&shards)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "state_v2_unsafe_baseline"
        );
        let target = fence::sibling(path, ".v1-readonly.shards");
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&target)?;
        for entry in fs::read_dir(shards)? {
            let entry = entry?;
            bytes = bytes
                .checked_add(fence::preserve_file(
                    &entry.path(),
                    &target.join(entry.file_name()),
                )?)
                .ok_or(Hold::DbUnavailable)?;
        }
        super::super::sync_checkpoint_parent(&target.join("unused"))?;
        super::super::sync_checkpoint_parent(path)?;
    }
    telemetry::event("baseline_bytes", &bytes);
    telemetry::baseline(path);
    Ok(())
}

/// All save routes check independent evidence before any v1 CAS or publication.
pub(in super::super) fn save_locked(
    path: &Path,
    index: &mut ScanIndex,
    claim_only: bool,
    progress_owner: Option<&crate::snapshot_sync::SnapshotProgressLock>,
) -> Result<bool> {
    save_with_mode(path, index, &ClaudeMapper, claim_only, progress_owner)
}
#[cfg(test)]
fn save_with<M: Mapper>(path: &Path, index: &mut ScanIndex, mapper: &M) -> Result<bool> {
    save_with_mode(path, index, mapper, false, None)
}
fn save_with_mode<M: Mapper>(
    path: &Path,
    index: &mut ScanIndex,
    mapper: &M,
    claim_only: bool,
    progress_owner: Option<&crate::snapshot_sync::SnapshotProgressLock>,
) -> Result<bool> {
    let Some(binding) = binding(path) else {
        ensure!(index.persistence_v2.is_none(), Hold::ForeignBinding);
        return Ok(false);
    };
    if index.persistence_v2.is_none() && !route_needed(path, false)? {
        return Ok(false);
    }
    // This accessor authenticates the owner/session; call before route/session locks.
    let claim_generation = super::super::sampled_audit::own_growth_claim_generation(index, path);
    let result = held(with_state(path, |state| {
        let pair = fence::reconcile(path, &binding, state.latched)?;
        let Some(runtime) = index.persistence_v2.clone() else {
            ensure!(pair.is_none(), Hold::DbUnavailable);
            return Ok(false);
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
        let previous = state.cached.take().ok_or(Hold::ReloadRequired)?;
        ensure!(
            previous.generation == session.stamp.0
                && claim_generation.unwrap_or(index.generation) == previous.generation,
            Hold::ReloadRequired
        );
        if claim_generation.is_some() {
            index.generation = previous.generation;
        }
        crate::snapshot_sync::with_state_v2_progress_owner(path, progress_owner, |owner, _| {
            super::ack::ProgressRecovery::recover_route_locked(
                &identity,
                session.stamp.0,
                path,
                owner,
            )?;
            super::recovery_backup::roll_locked(path, &mut session.db, &identity, owner)?;
            let selected = if claim_only {
                M::selected_claim_save
            } else {
                M::selected_save
            };
            let save_result = selected(
                mapper,
                &mut session.db,
                &identity,
                &previous,
                index,
                &mut session.cx,
            );
            // A subset save can commit and then return SaveAdmission. Protect that
            // exact generation before propagating its collection hold.
            if session.db.stamp()?.0 != previous.generation {
                super::recovery_backup::roll_locked(path, &mut session.db, &identity, owner)?;
            }
            if save_result? {
                session.stamp = session.db.stamp()?;
                state.cached = Some(index.clone());
                return Ok(true);
            }
            mapper.preflight(index).map_err(|_| Hold::DbUnavailable)?;
            state.cached = None;
            let mut tx = session.db.begin(TxnMode::Write)?;
            // Identity is independently authenticated; generation is atomically
            // compared again by commit. Hold comparisons remain mapper-owned.
            mapper.merge_cas(&mut tx, index)?;
            if !claim_only {
                index.retire_committed_claude_account_pending_windows();
            }
            lenient_check(index)?;
            let previous = index.generation;
            let next = previous.checked_add(1).ok_or(Hold::DbUnavailable)?;
            mapper.delta(&mut tx, index, None)?;
            apply_outcome(index, &mut session.reload, tx.commit(previous, next))?;
            session.stamp = session.db.stamp()?;
            // Cache exactly the committed graph, including subset-save outcomes;
            // never retain an end-of-cycle graph with unsaved semantic mutations.
            state.cached = Some(index.clone());
            Ok(true)
        })
    }));
    if let Err(error) = &result {
        with_state(path, |state| {
            state.cached = None;
            // A smaller next collection page retries one atomic save, never
            // fragments a graph transaction or drops its custody rows.
            if error.chain().any(|e| {
                matches!(
                    e.to_string().as_str(),
                    "state_v2_save_admission" | "state_v2_path_diff_admission"
                )
            }) {
                state.page_limit = (state.page_limit / 2).max(1);
                telemetry::event("save_page_reduced", &state.page_limit);
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
    if result.as_ref().is_ok_and(|saved| *saved) && !claim_only {
        super::super::sampled_audit::renew_growth_claims(index, path);
        with_state(path, |state| {
            state.cached = Some(index.clone());
            Ok(())
        })?;
    }
    result
}
fn lenient_check(index: &ScanIndex) -> Result<()> {
    super::super::lenient_decode::check_held_output(index)
}
fn apply_outcome(
    index: &mut ScanIndex,
    reload: &mut bool,
    outcome: DurableCommitOutcome,
) -> Result<()> {
    match outcome {
        DurableCommitOutcome::Committed(g) => {
            index.generation = g;
            Ok(())
        }
        DurableCommitOutcome::NotPublished => bail!("state_v2_not_published"),
        DurableCommitOutcome::Published(g) => {
            index.generation = g;
            *reload = true;
            bail!("current_index_requires_reload");
        }
        DurableCommitOutcome::Ambiguous => {
            *reload = true;
            bail!("current_index_requires_reload");
        }
    }
}

pub(in super::super) fn guard_containment_locked(path: &Path) -> Result<()> {
    if binding(path).is_none() || !route_needed(path, false)? {
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
    let Some(runtime) = runtime else {
        return Ok(());
    };
    let _lock = super::super::CheckpointLock::acquire(path)?;
    held(with_state(path, |state| {
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

pub(in super::super) fn collection_page_limit(index: &ScanIndex, requested: usize) -> usize {
    let Some(runtime) = &index.persistence_v2 else {
        return requested;
    };
    let path = runtime
        .session
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.path.clone()));
    path.and_then(|p| with_state(&p, |s| Ok(s.page_limit.min(requested))).ok())
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

pub(in super::super) fn idle(path: &Path, index: &ScanIndex, quiet: bool) -> Result<()> {
    let Some(runtime) = &index.persistence_v2 else {
        return Ok(());
    };
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
    if let Some(runtime) = &index.persistence_v2 {
        state.runtimes.push(Arc::downgrade(runtime));
        state.current = Some(runtime.clone());
    }
    Ok(())
}

/// Inventory only: the baseline's explicit single-file erasure exception and
/// the H/N/L-only restart cache are not covered by a DB VACUUM claim.
fn erasure_inventory(path: &Path) -> Result<()> {
    for (class, artifact) in [
        (
            "migration_backup_inventory",
            fence::sibling(path, ".v2.sqlite.migration-backup"),
        ),
        (
            "import_remnant_inventory",
            fence::sibling(path, ".v2.sqlite.import"),
        ),
        ("baseline_inventory", fence::sibling(path, ".v1-readonly")),
        (
            "ack_receipt_inventory",
            fence::sibling(path, ".v2-ack-receipt"),
        ),
        (
            "restart_record_inventory",
            crate::durable_tail_store::store_dir_for_index(path),
        ),
    ] {
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
        state.sample_v1 = false;
        state.cached = None;
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
pub(in super::super) fn invalidate_tree(support: &Path) -> Result<()> {
    let root = support.join("snapshots");
    let paths: Vec<_> = states()
        .lock()
        .map_err(|_| Hold::DbUnavailable)?
        .keys()
        .filter(|p| p.starts_with(&root))
        .cloned()
        .collect();
    for path in paths {
        if path.parent().is_some_and(Path::is_dir) {
            let _lock = super::super::CheckpointLock::acquire(&path)?;
            invalidate_locked(&path)?;
        } else {
            invalidate_locked(&path)?;
        }
    }
    Ok(())
}

/// Explicit erasure only. Close the shared session before unlinking all
/// artifacts, and invalidate clones before releasing CheckpointLock.
pub(in super::super) fn erase_locked(path: &Path, index: Option<&ScanIndex>) -> Result<()> {
    invalidate_locked(path)?;
    if let Some(runtime) = index.and_then(|i| i.persistence_v2.as_ref()) {
        runtime
            .session
            .lock()
            .map_err(|_| Hold::DbUnavailable)?
            .take();
    }
    for suffix in [
        "",
        ".shards",
        ".v2.sqlite",
        ".v2.sqlite-wal",
        ".v2.sqlite-shm",
        ".v2.sqlite.migration-backup",
        ".v2.sqlite.import",
        ".v2.sqlite.import-wal",
        ".v2.sqlite.import-shm",
        ".v1-readonly",
        ".v1-readonly.shards",
        ".v2-fence.tmp",
        ".v2-ack-receipt",
    ] {
        let artifact = fence::sibling(path, suffix);
        match fs::symlink_metadata(&artifact) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => fs::remove_dir_all(&artifact)?,
            Ok(_) => fs::remove_file(&artifact)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    super::recovery_backup::erase(path)?;
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
    // Keep the latch until process exit. Stale clones cannot fall back to v1.
    with_state(path, |state| {
        state.latched = true;
        Ok(())
    })
}

/// Called by explicit source erasure and identity-forget/uninstall before the
/// enclosing snapshot tree is removed. Never used by source disable/repair.
pub(in super::super) fn erase_tree(support: &Path) -> Result<()> {
    let root = support.join("snapshots");
    let mut paths: std::collections::BTreeSet<PathBuf> = states()
        .lock()
        .map_err(|_| Hold::DbUnavailable)?
        .keys()
        .filter(|p| p.starts_with(&root))
        .cloned()
        .collect();
    fn discover(
        dir: &Path,
        depth: u8,
        paths: &mut std::collections::BTreeSet<PathBuf>,
    ) -> Result<()> {
        if depth == 0 {
            return Ok(());
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                discover(&entry.path(), depth - 1, paths)?;
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("claude_code-") {
                continue;
            }
            let name = name
                .split(".json")
                .next()
                .filter(|_| name.contains(".json"));
            if let Some(name) = name {
                let path = dir.join(format!("{name}.json"));
                if binding(&path).is_some() {
                    paths.insert(path);
                }
            }
        }
        Ok(())
    }
    discover(&root, 4, &mut paths)?;
    for path in paths {
        if path.parent().is_some_and(Path::is_dir) {
            let _lock = super::super::CheckpointLock::acquire(&path)?;
            erase_locked(&path, None)?;
        } else {
            invalidate_locked(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;

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
        let runtime = index.persistence_v2.as_ref().ok_or(Hold::ReloadRequired)?;
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
