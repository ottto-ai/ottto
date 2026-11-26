//! Test-only observation of the real scanner; no alternate parser/finalizer.
use crate::snapshots::*;
use crate::transcript_acquisition::Scope;

#[path = "e2_pipeline_twin_diagnostics.rs"]
pub(crate) mod twin_diagnostics;

pub(crate) use crate::snapshots::upload::freshness_debt::tests::{
    assert_file_debt_retired, assert_file_receipt_retires_debt,
};

/// The sampled scope and identity-capture mode this fixture's scans bind.
fn scan_binding(source: SnapshotSource) -> (Scope, bool) {
    match source {
        SnapshotSource::ClaudeCode => (Scope("e2-pipeline".into()), CLAUDE_IDENTITY_CAPTURE),
        // Outside a sync cycle every scan captures (also in tests).
        _ => (Scope("money-equivalence".into()), true),
    }
}
const CLAUDE_IDENTITY_CAPTURE: bool = false;

/// The state database a fixture's Claude scans continue from.
pub(crate) struct FixtureRoute {
    path: PathBuf,
    /// The caller saves through `Disk`; a page never commits on its own.
    caller_commits: bool,
    /// The routes this owner made for its other indexes: one source has one
    /// route per index, so another index's scan never orphans this one's heads.
    others: Vec<PathBuf>,
}

/// Routes fixtures made. Any other route belongs to the caller's session.
fn fixture_routes() -> &'static Mutex<BTreeSet<PathBuf>> {
    static ROUTES: std::sync::OnceLock<Mutex<BTreeSet<PathBuf>>> = std::sync::OnceLock::new();
    ROUTES.get_or_init(Default::default)
}

fn fixture_bindings() -> &'static Mutex<BTreeMap<PathBuf, scan_index_persistence::Binding>> {
    static BINDINGS: std::sync::OnceLock<
        Mutex<BTreeMap<PathBuf, scan_index_persistence::Binding>>,
    > = std::sync::OnceLock::new();
    BINDINGS.get_or_init(Default::default)
}

/// Synthetic checkpoint names keep their fixture-owned temporary location.
/// The production binding recognizer never accepts these aliases.
pub(super) fn fixture_binding(path: &Path) -> Option<scan_index_persistence::Binding> {
    fixture_bindings().lock().unwrap().get(path).cloned()
}

/// Explicit fixture save: boundary tests of the legacy writer keep `save`.
impl ScanIndex {
    pub(crate) fn save_fixture(&mut self, path: &Path) -> Result<()> {
        prepare_fixture_save(self, path)?;
        self.save(path)
    }

    pub(crate) fn save_fixture_for_source(
        &mut self,
        path: &Path,
        source: SnapshotSource,
    ) -> Result<()> {
        bind_source_for_test(path, source);
        self.save_fixture(path)
    }
}

pub(crate) fn persistence_source(source: SnapshotSource) -> scan_index_persistence::Source {
    match source {
        SnapshotSource::ClaudeCode => scan_index_persistence::Source::Claude,
        SnapshotSource::Codex => scan_index_persistence::Source::Codex,
        SnapshotSource::Pi => scan_index_persistence::Source::Pi,
    }
}

fn insert_fixture_binding(path: &Path, source: scan_index_persistence::Source) {
    fixture_bindings().lock().unwrap().insert(
        path.to_owned(),
        scan_index_persistence::Binding {
            source,
            namespace_hash: "a".repeat(64),
        },
    );
}

/// Bind an unbound `path` to `source`; a bound path must already name it.
pub(crate) fn bind_source_for_test(path: &Path, source: SnapshotSource) {
    if scan_index_integration::scan_index_storage_binding(path).is_none() {
        insert_fixture_binding(path, persistence_source(source));
    }
    assert_route_source(path, source);
}

/// The source and destination namespace `path`'s storage binding names,
/// including a registered synthetic alias.
pub(crate) fn binding_for_test(path: &Path) -> (SnapshotSource, String) {
    let binding = scan_index_integration::scan_index_storage_binding(path).expect("a bound route");
    (binding.source.snapshot(), binding.namespace_hash)
}

/// A reused fixture route must hold `source`'s graph.
fn assert_route_source(route: &Path, source: SnapshotSource) {
    assert_eq!(
        scan_index_integration::scan_index_storage_binding(route)
            .map(|binding| binding.source.snapshot()),
        Some(source),
        "fixture route {} holds another source",
        route.display()
    );
}

fn prepare_fixture_save(index: &mut ScanIndex, path: &Path) -> Result<()> {
    let synthetic = fixture_binding(path).is_some()
        || scan_index_integration::scan_index_storage_binding(path).is_none();
    bind_input_for_test(index, path);
    if index.v2().persistence_v2.is_none()
        || (synthetic && route_of(index).as_deref() != Some(path))
    {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let binding = scan_index_integration::scan_index_storage_binding(path).unwrap();
        let baseline = ScanIndex::load_for_snapshot_source_with_origin(
            path,
            binding.source.snapshot(),
            &path.parent().unwrap().join("fixture-support"),
        )?
        .0;
        anyhow::ensure!(
            baseline.v2().persistence_v2.is_some(),
            "fixture_requires_native_custody"
        );
        index.retain_persistence_baseline_from(&baseline);
        index.generation = baseline.generation;
        E2ScanFixture::register_route_for_test(path);
    }
    Ok(())
}

/// Name the fixture's synthetic destination before a legacy admission assertion.
pub(crate) fn bind_input_for_test(index: &ScanIndex, path: &Path) {
    if scan_index_integration::scan_index_storage_binding(path).is_none() {
        insert_fixture_binding(path, fixture_source(index, path));
    }
}

/// `index`'s source: its route's binding, else its active quarantine
/// witness, else the synthetic file name.
fn fixture_source(index: &ScanIndex, path: &Path) -> scan_index_persistence::Source {
    route_of(index)
        .and_then(|route| scan_index_integration::scan_index_storage_binding(&route))
        .map(|binding| binding.source)
        .or_else(|| {
            index
                .active_quarantine_witness
                .as_ref()
                .and_then(|witness| {
                    [
                        scan_index_persistence::Source::Claude,
                        scan_index_persistence::Source::Codex,
                        scan_index_persistence::Source::Pi,
                    ]
                    .into_iter()
                    .find(|source| witness == &snapshot_quarantine_witness(source.snapshot()))
                })
        })
        .unwrap_or_else(|| {
            let name = path.file_name().unwrap().to_string_lossy();
            if name.contains("codex") {
                scan_index_persistence::Source::Codex
            } else if name.contains("pi-") {
                scan_index_persistence::Source::Pi
            } else {
                scan_index_persistence::Source::Claude
            }
        })
}

/// Install a new synthetic legacy input; never overwrite live native custody.
pub(crate) fn legacy_input_for_test(path: &Path, bytes: &[u8]) {
    bind_input_for_test(&ScanIndex::default(), path);
    state_v2::erase_published(path);
    ottto_core::write_owner_only_file_atomic(path, bytes).unwrap();
}

/// Model the next ordinary pass after quarantine/Repair published its G=0 store.
pub(crate) fn load_source_for_test(
    path: &Path,
    source: SnapshotSource,
    support: &Path,
) -> Result<(ScanIndex, ScanIndexLoadOrigin)> {
    bind_source_for_test(path, source);
    match ScanIndex::load_for_snapshot_source_with_origin(path, source, support) {
        Ok((index, origin)) if origin == ScanIndexLoadOrigin::Quarantined => {
            // Legacy quarantine authorizes a fresh rebuilt graph. The fixture
            // publishes it natively before the next collection pass.
            assert_eq!(index.generation, 0);
            let mut native = seed_index_at_generation(&index, path, Some(0));
            carry_runtime(&index, &mut native);
            Ok((native, origin))
        }
        Err(error)
            if error.downcast_ref::<state_v2::Hold>() == Some(&state_v2::Hold::ReloadRequired)
                && state_v2::published(path).unwrap_or(false) =>
        {
            ScanIndex::load_for_snapshot_source_with_origin(path, source, support)
        }
        result => result,
    }
}

/// Replace synthetic persisted state through the native mapper. Decoder tests
/// supply legacy bytes, but never overwrite a published fence with those bytes.
pub(crate) fn seed_json_for_test(path: &Path, bytes: &[u8]) -> ScanIndex {
    let mut index = lenient_decode::read(std::io::Cursor::new(bytes), "load", "unattributed")
        .expect("admitted decoder fixture");
    // The mapper's fixture publication commits seed G+1. Keep an existing
    // fixture generation so receipt/handoff tests still isolate their damage.
    index.generation = index.generation.saturating_sub(1);
    bind_input_for_test(&index, path);
    seed_index_for_test(&index, path)
}

pub(crate) fn mutate_index_for_test(path: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let mut value = serde_json::to_value(ScanIndex::load(path).unwrap()).unwrap();
    mutate(&mut value);
    seed_json_for_test(path, &serde_json::to_vec(&value).unwrap());
}

/// Decoder-only inspection does not adopt the mapper's input as live custody.
pub(crate) fn read_legacy_for_test(path: &Path) -> ScanIndex {
    read_scan_index_representation(path, "load", "unattributed", None).unwrap()
}

/// Inventory refusals preserve their original input and expose support action.
pub(crate) fn assert_import_support_for_test(path: &Path) {
    bind_input_for_test(&ScanIndex::default(), path);
    let before = fs::read(path).unwrap();
    let error = ScanIndex::load(path).unwrap_err();
    assert_eq!(
        error.downcast_ref::<state_v2::Hold>(),
        Some(&state_v2::Hold::DbUnavailable)
    );
    assert_support_error_for_test(&error);
    assert_eq!(fs::read(path).unwrap(), before);
}

pub(crate) fn assert_support_error_for_test(error: &anyhow::Error) {
    assert_eq!(
        scan_index_health::state_v2_reason(error).unwrap().action(),
        "contact_support"
    );
}

/// Explicit native seed for decoder fixtures whose original bytes deliberately
/// fail the production inventory gate. This never runs on a daemon load/save.
pub(crate) fn seed_index_for_test(index: &ScanIndex, path: &Path) -> ScanIndex {
    seed_index_at_generation(index, path, None)
}

fn seed_index_at_generation(index: &ScanIndex, path: &Path, generation: Option<u64>) -> ScanIndex {
    bind_input_for_test(index, path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let retained = state_v2::money_test_support::FixtureProgress::capture(path);
    let binding = scan_index_integration::scan_index_storage_binding(path).unwrap();
    let progress = crate::snapshot_sync::with_state_v2_progress_lock(path, |progress_path| {
        match fs::read(progress_path) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(serde_json::to_vec(&serde_json::json!({
                    "schema_version": 3,
                    "destination_namespace_hash": binding.namespace_hash,
                }))?)
            }
            Err(error) => Err(error.into()),
        }
    })
    .unwrap();
    state_v2::erase_published(path);
    let loaded = state_v2::money_test_support::publish_fixture_at_generation(
        index,
        path,
        &progress,
        &retained,
        generation.unwrap_or(index.generation + 1),
    );
    assert!(
        state_v2::money_test_support::FixtureProgress::capture(path) == retained,
        "index-only fixture mutation preserves every progress row"
    );
    E2ScanFixture::register_route_for_test(path);
    loaded
}

#[test]
fn synthetic_default_indexes_save_and_reload_through_native_custody() {
    let scratch = crate::test_scratch::ScratchDir::canonical("fixture-native-save");
    for (slot, source) in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .enumerate()
    {
        let path = scratch.join(format!("fixture-{slot}.json"));
        let mut index = ScanIndex {
            historical_replay_generation: Some(source.api_slug().into()),
            ..Default::default()
        };
        index.activate_quarantine_witness(source);
        index.save_fixture(&path).unwrap();
        assert_eq!(fixture_binding(&path).unwrap().source.snapshot(), source);
        assert_eq!(route_of(&index).as_deref(), Some(path.as_path()));
        assert_eq!(index.generation, 1);
        let replay = index.historical_replay_generation.clone();
        drop(index);
        state_v2::cold_close_for_test(&path).unwrap();
        let restored = ScanIndex::load(&path).unwrap();
        assert_eq!(restored.generation, 1);
        assert_eq!(restored.historical_replay_generation, replay);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(path).unwrap()).unwrap()
                ["storage_format"],
            2
        );
    }
}

/// Claude continues only from the state database, so an owner's retained
/// state is its route: the prior this owner produced is committed there first,
/// as the daemon saves between passes, and any other owner's prior moves to a
/// new, empty route, which reads what changed Full. A caller's own session is
/// left alone.
pub(crate) fn routed_for_test(
    source: SnapshotSource,
    cache: &sampled_scan::SharedCache,
    index: ScanIndex,
    dir: &Path,
) -> ScanIndex {
    let on = route_of(&index);
    // A save and reload drops the runtime-only fields; the RAM-era fixture
    // passed every prior in memory, so each page keeps them.
    let runtime = runtime_only(&index);
    let carry = |mut loaded: ScanIndex| {
        carry_runtime(&runtime, &mut loaded);
        loaded
    };
    let mut own = cache.test_route.lock().unwrap();
    if let Some(route) = own.as_mut() {
        if route.caller_commits {
            return match on {
                Some(_) => index,
                None => {
                    assert_route_source(&route.path, source);
                    carry(ScanIndex::load(&route.path).unwrap())
                }
            };
        }
        if let Some(mine) = on
            .as_ref()
            .filter(|on| **on == route.path || route.others.contains(on))
        {
            assert_route_source(mine, source);
            if *mine != route.path {
                route.others.retain(|other| other != mine);
                let left = std::mem::replace(&mut route.path, mine.clone());
                route.others.push(left);
            }
            let mut page = index.clone();
            if save_on_route(&mut page, mine).is_ok() {
                return carry(ScanIndex::load(mine).unwrap());
            }
        }
    }
    if on
        .as_ref()
        .is_some_and(|path| !fixture_routes().lock().unwrap().contains(path))
    {
        return index;
    }
    let (path, cold) = publish_route(source, &index, dir);
    let others = own.take().map_or_else(Vec::new, |route| {
        let mut others = route.others;
        others.push(route.path);
        others
    });
    *own = Some(FixtureRoute {
        path,
        caller_commits: false,
        others,
    });
    carry(cold)
}

/// `settled` (a settlement saved beside its own files) back on `from`'s route.
pub(crate) fn onto_route_for_test(settled: &mut ScanIndex, from: &ScanIndex) {
    settled.retain_persistence_baseline_from(from);
}

/// A restarted owner `cache` continues from `route`'s committed heads.
pub(crate) fn continue_route_for_test(cache: &sampled_scan::SharedCache, route: &Path) {
    *cache.test_route.lock().unwrap() = Some(FixtureRoute {
        path: route.to_owned(),
        caller_commits: false,
        others: Vec::new(),
    });
}

/// `index`'s files with no continuation, on their own route: each head is
/// retired, so the next read of each is a Full as a first read is.
pub(crate) fn forget_continuations_for_test(_cache: &sampled_scan::SharedCache, index: &ScanIndex) {
    if let Some(route) = route_of(index) {
        state_v2::retire_tail(&route, index.files.keys().cloned()).unwrap();
    }
}

/// Saves `index` on its route. A prior offered again after the route moved on
/// (a fixture re-feeding one committed index, as a held page does) first takes
/// the route's current baseline, as the daemon's reload would.
fn save_on_route(index: &mut ScanIndex, route: &Path) -> Result<()> {
    let mut first = index.clone();
    if first.save(route).is_ok() {
        *index = first;
        return Ok(());
    }
    let current = ScanIndex::load(route)?;
    index.retain_persistence_baseline_from(&current);
    index.generation = current.generation;
    index.decode_holds = current.decode_holds.clone();
    index.save_fixture(route)
}

/// An in-memory prior keeps every runtime-only (`serde(skip)`) field across
/// the fixture's save and reload, as the RAM-era fixture's index did; a sync
/// cycle also re-applies the paused list and copy capabilities to each index.
fn carry_runtime(from: &ScanIndex, into: &mut ScanIndex) {
    into.claude_reemission_exclusions = from.claude_reemission_exclusions.clone();
    into.copy_unproven_enabled = from.copy_unproven_enabled;
    into.copy_prefix_base_upload_context = from.copy_prefix_base_upload_context.clone();
    into.active_quarantine_witness = from.active_quarantine_witness.clone();
    into.active_upload_context_fingerprint = from.active_upload_context_fingerprint.clone();
    into.context_read_counts = from.context_read_counts.clone();
    into.active_effective_upload_body_witness_revision =
        from.active_effective_upload_body_witness_revision;
    into.active_effective_upload_body_witness_revision_monotone =
        from.active_effective_upload_body_witness_revision_monotone;
    into.effective_upload_body_witness_revision_excluded_source_files = from
        .effective_upload_body_witness_revision_excluded_source_files
        .clone();
    into.reason_reoffer_retries = from.reason_reoffer_retries.clone();
    into.terminal_contract_retries = from.terminal_contract_retries.clone();
    into.head_conflict_sessions = from.head_conflict_sessions.clone();
    into.reason_reoffer_cooldowns = from.reason_reoffer_cooldowns.clone();
    into.claude_no_list_policy = from.claude_no_list_policy;
    into.first_read_tier_cutoff = from.first_read_tier_cutoff;
    into.backfill_cutoff_nanos = from.backfill_cutoff_nanos;
    into.claude_history_emission = from.claude_history_emission.clone();
    into.withheld_memo = from.withheld_memo.clone();
}

/// An empty graph holding only `index`'s runtime-only fields.
fn runtime_only(index: &ScanIndex) -> ScanIndex {
    let mut runtime = ScanIndex::default();
    carry_runtime(index, &mut runtime);
    runtime
}

/// Close every native session and staged observation before a simulated restart.
/// Callers drop all pages that borrowed the prior before handing it over.
pub(crate) fn cold_restart(prior: ScanIndex) -> ScanIndex {
    let route = route_of(&prior).expect("a persisted restart prior");
    let runtime = runtime_only(&prior);
    drop(prior);
    state_v2::cold_close_for_test(&route).unwrap();
    let mut restored = ScanIndex::load(&route).unwrap();
    carry_runtime(&runtime, &mut restored);
    restored
}

/// `prior` published on a new fixture route under `dir`: (route, cold graph).
fn publish_route(source: SnapshotSource, prior: &ScanIndex, dir: &Path) -> (PathBuf, ScanIndex) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (session, cold) = StateV2ColdSession::publish(
        persistence_source(source),
        prior,
        &dir.canonicalize().unwrap().join(format!("route-{n}")),
    );
    let path = session.path().to_owned();
    // Other arms still read this route; the scratch dir owns it.
    std::mem::forget(session);
    E2ScanFixture::register_route_for_test(&path);
    (path, cold)
}

/// A restart of `index` as its own install: its graph published on
/// a new route, so another install's commits from the same prior never stale
/// it. An unrouted index is returned as is.
pub(crate) fn own_install_for_test(index: &ScanIndex, dir: &Path) -> ScanIndex {
    let Some(route) = route_of(index) else {
        return index.clone();
    };
    let source = scan_index_integration::scan_index_storage_binding(&route)
        .expect("a bound route")
        .source
        .snapshot();
    // A restart from disk: runtime-only fields are gone, as through a file.
    publish_route(source, index, dir).1
}

/// This thread's process total of the Tail counter `name{label}`, summed over
/// sources.
pub(crate) fn tail_counter_for_test(name: &'static str, label: &'static str) -> u64 {
    tail_source::counters::total(name, label)
}

/// The certified checkpoint a key continues from, read back for assertions.
pub(crate) struct Continuation {
    last_full_verified: u64,
    sealed_offset: u64,
}
impl Continuation {
    pub(crate) fn sealed_offset(&self) -> u64 {
        self.sealed_offset
    }
    pub(crate) fn last_full_verified(&self) -> u64 {
        self.last_full_verified
    }
}

/// `key`'s continuation: its head on `index`'s route (this pass's staged
/// head, else the committed one), as the RAM-era fixture read its retained
/// checkpoint.
pub(crate) fn continuation_for_test(
    source: SnapshotSource,
    _cache: &sampled_scan::SharedCache,
    index: &ScanIndex,
    key: &str,
) -> Option<Continuation> {
    let certificate = match source {
        SnapshotSource::ClaudeCode => head_certificate::<tail_source::claude::Claude>(index, key)?,
        SnapshotSource::Codex => head_certificate::<tail_source::codex::Codex>(index, key)?,
        SnapshotSource::Pi => head_certificate::<tail_source::pi::Pi>(index, key)?,
    };
    Some(Continuation {
        last_full_verified: certificate.verified_unix_seconds,
        sealed_offset: certificate.sealed_offset,
    })
}

/// `key`'s head certificate on `index`'s route, through `S`'s codec.
fn head_certificate<S: tail_source::TailSource>(
    index: &ScanIndex,
    key: &str,
) -> Option<crate::transcript_acquisition::DurableCertificate> {
    let route = route_of(index)?;
    let (revision, body) = match state_v2::staged_head_for_test(&route, key) {
        Some(staged) => staged,
        None => {
            let head = state_v2::load_head(index, key, S::REDUCTION_REVISION).ok()??;
            (head.revision, head.body)
        }
    };
    let mut acc = SnapshotAccumulator::new(S::SOURCE);
    Some(S::decode_head(revision, &body, &mut acc).ok()?.certificate)
}

/// How `key`'s committed Claude certificate answers the file now at its
/// path: `Ok` when it restores, else the refusal.
#[cfg(unix)]
pub(crate) fn claude_certificate_restore_for_test(
    index: &ScanIndex,
    key: &str,
) -> Result<(), crate::transcript_acquisition::CertificateRefusal> {
    let certificate = head_certificate::<tail_source::claude::Claude>(index, key).unwrap();
    let mut file = std::fs::File::open(key).unwrap();
    certificate
        .restore_grown_counted(
            &mut file,
            crate::transcript_acquisition::Scope("e2-pipeline".into()),
            None,
            None,
        )
        .map(|_| ())
}

/// Model a reboot's device renumber in a committed certificate, leaving
/// inode, birth, samples and reduction unchanged. The next ordinary load
/// keeps that certificate: the device is never compared across boots.
#[cfg(unix)]
pub(crate) fn renumber_device_for_test(index: &mut ScanIndex, key: &str) {
    let route = route_of(index).unwrap();
    let revision = tail_source::reduction_revision(SnapshotSource::ClaudeCode);
    let head = state_v2::load_head(index, key, revision).unwrap().unwrap();
    let device = tail_source::certified_certificate(&head.body)
        .unwrap()
        .device
        ^ 1;
    let body = tail_source::renumber_device_for_test(&head.body, key);
    state_v2::stage_tail(
        &route,
        key,
        state_v2::StagedFile {
            revision,
            head: body,
            ..Default::default()
        },
    )
    .unwrap();
    save_on_route(index, &route).unwrap();
    assert_eq!(
        head_certificate::<tail_source::claude::Claude>(index, key)
            .unwrap()
            .device,
        device
    );
}

/// The entity-set digest the finalizer writes on each physical file.
#[cfg(unix)]
pub(crate) fn file_entity_set_hex_for_test(fingerprints: &BTreeSet<String>) -> String {
    snapshot_file_entity_set_hex(fingerprints)
}

/// Count EOFs applied by the scan steps on the calling worker.
pub(crate) fn observe_codex_group_eofs<T>(run: impl FnOnce() -> T) -> (T, usize) {
    use sampled_scan::codex_cursor::tests::GROUP_EOF_APPLIED;
    let before = GROUP_EOF_APPLIED.get();
    let result = run();
    (result, GROUP_EOF_APPLIED.get() - before)
}

/// The graph compared byte for byte, routed or not.
pub(crate) fn resident_for_test(index: &ScanIndex) -> ScanIndex {
    index.clone()
}

/// A scan fixture's page continues from its owner's route; with no cache it
/// reads a fixture route unrouted.
pub(crate) fn route_for_test(
    source: SnapshotSource,
    cache: Option<&sampled_scan::SharedCache>,
    index: ScanIndex,
) -> ScanIndex {
    let Some(cache) = cache else {
        // A scan with no cache to own a route is the cold oracle: it reads a
        // fixture route's graph unrouted, as before Claude kept its Tail there,
        // so another arm's commits on that route never stale it.
        let fixture_route =
            route_of(&index).is_some_and(|path| fixture_routes().lock().unwrap().contains(&path));
        if !fixture_route {
            return index;
        }
        let mut copy = index.clone();
        copy.v2_mut().persistence_v2 = None;
        carry_runtime(&index, &mut copy);
        return copy;
    };
    let dir = std::env::temp_dir().join(format!("ottto-fixture-routes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    routed_for_test(source, cache, index, &dir)
}

/// The saved, already-indexed walk used by a quiet restart. Like the
/// discovery-growth fixture, it keeps the roster across the restart; only
/// unchanged members already represented by the committed index are drained.
pub(crate) fn retain_indexed_walk_for_test(
    index: &mut ScanIndex,
    source: SnapshotSource,
    roots: &[PathBuf],
    collected_at: &str,
    backfill_window_days: u64,
) {
    retain_indexed_walk_with_pending_for_test(
        index,
        source,
        roots,
        collected_at,
        backfill_window_days,
        &[],
    );
}

pub(crate) fn retain_indexed_walk_with_pending_for_test(
    index: &mut ScanIndex,
    source: SnapshotSource,
    roots: &[PathBuf],
    collected_at: &str,
    backfill_window_days: u64,
    pending: &[PathBuf],
) {
    ensure_bounded_traversal(source, roots, index, collected_at, backfill_window_days);
    advance_bounded_directory_traversal(source, index, backfill_window_days, None);
    let walk = index.traversal.as_ref().expect("indexed walk");
    assert!(walk.pending_directories.is_empty(), "the walk is complete");
    for candidate in &walk.pending_candidates {
        let metadata = std::fs::symlink_metadata(&candidate.path).unwrap();
        let entry = &index.files[&local_index_key(&candidate.path)];
        assert!(entry.same_listing_stamp_as(&metadata));
        assert!(!entry.source_file_fingerprint.is_empty());
    }
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_candidates
        .retain(|candidate| pending.contains(&candidate.path));
}

pub(crate) fn pending_keys_for_test(index: &ScanIndex) -> BTreeSet<String> {
    index
        .traversal
        .iter()
        .flat_map(|walk| &walk.pending_candidates)
        .map(|candidate| local_index_key(&candidate.path))
        .collect()
}

/// The time a fixture's next visit is taken to come after its last. The
/// fixtures' `collected_at` never moves, so a kept generation's metadata
/// re-listing (`LISTING_INTERVAL_SECONDS`) and its owed-file pace
/// (`LISTING_OWED_PACE_SECONDS`) would never come due; production's clock
/// moves on. Age the walk's listing clocks by the longer of the two, as a
/// visit that much later sees them. Only the listing clocks move.
pub(crate) fn age_listing_for_test(index: &mut ScanIndex) {
    let Some(walk) = index.traversal.as_mut() else {
        return;
    };
    let age = |at: &mut u64| {
        *at = at.saturating_sub(LISTING_INTERVAL_SECONDS.max(LISTING_OWED_PACE_SECONDS));
    };
    if let Some(started) = walk.listing_started_unix_seconds.as_mut() {
        age(started);
    }
    walk.listing_owed_requeued_unix_seconds
        .values_mut()
        .for_each(age);
}

/// The state database `index` is bound to, if any.
pub(crate) fn route_of(index: &ScanIndex) -> Option<PathBuf> {
    state_v2::runtime_path(index).ok().flatten()
}

/// Attach a synthetic working graph to its own empty native baseline. Its
/// first real save must still reconcile provisional ownership against empty
/// committed state, exactly as the daemon's first pass does.
pub(crate) fn bind_fixture_route(
    source: SnapshotSource,
    index: &mut ScanIndex,
    dir: &Path,
    namespace: &str,
) -> PathBuf {
    if let Some(route) = route_of(index) {
        return route;
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = dir
        .canonicalize()
        .unwrap()
        .join(format!("fixture-route-{n}"))
        .join("snapshots/destinations")
        .join(namespace)
        .join(format!("{}-synthetic-scan-index.json", source.api_slug()));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    prepare_fixture_save(index, &path).unwrap();
    path
}

/// Commit on the owner's native route, then publish a detached copy as
/// generation 1 of a new store at `path`, which must not be the owner's own.
/// The copy has no continuation; another owner must read changed input Full.
pub(crate) fn save_for_test(index: &mut ScanIndex, path: &Path) {
    let source = fixture_source(index, path).snapshot();
    let route = save_owner_for_test(source, index, path);
    assert!(
        !same_location(&route, path),
        "a detached copy never replaces its owner's custody"
    );
    let mut copy = detached_copy(index);
    copy.generation = 0;
    bind_source_for_test(path, source);
    seed_index_for_test(&copy, path);
}

/// Commit on this owner's native route; an unrouted seed is first attached to
/// an empty `source` store beside `path`.
pub(crate) fn save_owner_for_test(
    source: SnapshotSource,
    index: &mut ScanIndex,
    path: &Path,
) -> PathBuf {
    let route = bind_fixture_route(source, index, path.parent().unwrap(), &"a".repeat(64));
    save_on_route(index, &route).unwrap();
    route
}

/// The legacy JSON view of `index` at `path`, for readers whose subject is old
/// bytes (the metadata CLI, a historical binary). It carries no continuation.
pub(crate) fn legacy_view_for_test(index: &ScanIndex, path: &Path) {
    bind_input_for_test(index, path);
    let mut copy = detached_copy(index);
    copy.generation = 1;
    let mut bytes = Vec::new();
    lenient_decode::write_index(&mut bytes, &copy).unwrap();
    legacy_input_for_test(path, &bytes);
}

/// `index`'s persisted fields with no route and no runtime-only state.
fn detached_copy(index: &ScanIndex) -> ScanIndex {
    let mut copy = index.clone();
    carry_runtime(&ScanIndex::default(), &mut copy);
    copy.v2_mut().persistence_v2 = None;
    copy
}

fn same_location(a: &Path, b: &Path) -> bool {
    let canonical = |path: &Path| {
        path.parent()
            .and_then(|parent| parent.canonicalize().ok())
            .map(|parent| parent.join(path.file_name().unwrap()))
            .unwrap_or_else(|| path.to_owned())
    };
    canonical(a) == canonical(b)
}

/// Save and reload on this owner's native route; an unrouted seed is first
/// attached to an empty store under the supplied fixture directory.
pub(crate) fn save_reload_for_test(index: &mut ScanIndex, path: &Path) -> ScanIndex {
    let was_routed = route_of(index).is_some();
    let route = save_owner_for_test(SnapshotSource::ClaudeCode, index, path);
    let mut loaded = ScanIndex::load(&route).unwrap();
    if was_routed {
        carry_runtime(index, &mut loaded);
    }
    loaded
}

pub(crate) struct Acquisition {
    pub(crate) path: PathBuf,
    pub(crate) reason: Option<CandidateParseReason>,
    pub(crate) mode: crate::transcript_acquisition::ReadMode,
    pub(crate) start: u64,
}

#[derive(Default)]
pub(crate) struct E2ScanFixture {
    pub(crate) cache: Arc<sampled_scan::SharedCache>,
    observed: Mutex<Vec<PathBuf>>,
    pub(crate) acquisitions: Mutex<Vec<Acquisition>>,
    full_reasons: Mutex<[usize; crate::transcript_acquisition::FULL_REASON_COUNT]>,
    touches_proven: Mutex<usize>,
    pub(crate) versions: Option<Arc<codex_version::CodexVersionFeed>>,
    capture_claude_identity: bool,
    collection_clock: bool,
    collection_window_days: Option<u64>,
    subagent_births: bool,
    attribution: Mutex<Option<crate::session_attribution::SessionAttributionContext>>,
}
impl E2ScanFixture {
    /// Resource scenarios opt in to the shared virtual collection window.
    /// Existing fixtures keep their fixed timestamps and historical bytes.
    pub(crate) fn clocked_collection() -> Self {
        Self {
            collection_clock: true,
            ..Self::default()
        }
    }

    pub(crate) fn set_collection_window_days(&mut self, days: u64) {
        self.collection_window_days = Some(days);
    }

    fn collection_time(&self, fallback: &str) -> String {
        if !self.collection_clock {
            return fallback.to_owned();
        }
        time::OffsetDateTime::from_unix_timestamp(
            crate::scan_clock::utc_seconds().try_into().unwrap(),
        )
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
    }

    pub(crate) fn mark_sidecar_sweep_incomplete(index: &mut ScanIndex) {
        index.claude_desktop_store_retry_not_before_unix_seconds = Some(0);
    }

    /// Model historical child births only for tests that name them. Existing
    /// fixtures keep their subagent birth exemption and captured receipts.
    pub(crate) fn with_subagent_births() -> Self {
        Self {
            subagent_births: true,
            ..Self::default()
        }
    }

    /// Opt in when the fixture asserts marker/identity behavior. Money-only
    /// fixtures retain their historical capture-off scope and bytes.
    pub(crate) fn capturing_identity() -> Self {
        Self::with_identity_capture(true)
    }

    pub(crate) fn with_identity_capture(capture_claude_identity: bool) -> Self {
        Self {
            capture_claude_identity,
            ..Self::default()
        }
    }

    /// The key this scanner's next pass finishes under, as the service's scan.
    pub(crate) fn set_attribution(
        &self,
        attribution: Option<crate::session_attribution::SessionAttributionContext>,
    ) {
        *self.attribution.lock().unwrap() = attribution;
    }

    pub(crate) fn full_reasons(&self) -> [usize; crate::transcript_acquisition::FULL_REASON_COUNT] {
        *self.full_reasons.lock().unwrap()
    }

    /// The last pass's `same_size_touch_proven` counter: reads a write
    /// generation count proved a same-size touch.
    pub(crate) fn touches_proven(&self) -> usize {
        *self.touches_proven.lock().unwrap()
    }

    pub(crate) fn paths(&self) -> Vec<PathBuf> {
        self.observed.lock().unwrap().clone()
    }

    pub(crate) fn register_route_for_test(path: &Path) {
        // Each new fixture route first releases the sessions of fixtures
        // whose directories are gone.
        state_v2::close_removed_routes_for_test();
        fixture_routes().lock().unwrap().insert(path.to_owned());
    }

    /// This owner continues from `path`'s committed heads.
    pub(crate) fn on_committed_route(&self, path: &Path) {
        *self.cache.test_route.lock().unwrap() = Some(FixtureRoute {
            path: path.to_owned(),
            caller_commits: true,
            others: Vec::new(),
        });
    }

    pub(crate) fn routed(&self, index: ScanIndex, dir: &Path) -> ScanIndex {
        routed_for_test(SnapshotSource::ClaudeCode, &self.cache, index, dir)
    }

    /// Begins this owner's pass, as the daemon does before a scan.
    /// `state_dir` holds the index and the single-writer lock.
    pub(crate) fn begin_pass(&self, source: SnapshotSource, state_dir: &Path, index_path: &Path) {
        begin_source_pass(&self.cache, state_dir, source, index_path);
    }

    /// `index`'s files lose their continuation.
    pub(crate) fn evict(&self, index: &ScanIndex) {
        forget_continuations_for_test(&self.cache, index);
    }

    #[expect(clippy::too_many_arguments, reason = "test helper, 8 case inputs")]
    pub(crate) fn scan(
        &self,
        roots: &[PathBuf],
        support: &Path,
        index: ScanIndex,
        limit: usize,
        sampled: bool,
        births: &BTreeMap<PathBuf, i128>,
        hints: &[PathBuf],
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        self.observed.lock().unwrap().clear();
        self.acquisitions.lock().unwrap().clear();
        let (scope, _) = scan_binding(SnapshotSource::ClaudeCode);
        let mut scan = OwnedSourceScan::new_with_recovery_priority(
            SnapshotSource::ClaudeCode,
            roots,
            index,
            &self.collection_time("2026-08-02T08:00:00Z"),
            self.collection_window_days.unwrap_or(183),
            limit,
            Some(support),
            hints,
            false,
            &mut ListingRequest::default(),
            self.capture_claude_identity,
            &[],
            sampled.then_some((self.cache.as_ref(), &scope)),
            false,
        );
        if sampled {
            scan = scan.with_sampled_acquisition(self.cache.clone(), scope);
        }
        // The same synthetic root births reach the page's staged twin probes,
        // which read metadata before the file is opened for parse.
        let staged = births
            .iter()
            .filter(|(path, _)| {
                claude_index_path_member_ref(path)
                    .is_some_and(|member| member.subagent_stem.is_none() || self.subagent_births)
            })
            .filter_map(|(path, birth)| Some((local_index_key(path), u64::try_from(*birth).ok()?)))
            .collect();
        claude_history_upgrade::with_staged_births_for_test(staged, || self.drive(scan, births))
    }

    /// Same retained reader seam for sources without Claude evidence.
    pub(crate) fn scan_other(
        &self,
        source: SnapshotSource,
        roots: &[PathBuf],
        support: &Path,
        index: ScanIndex,
        sampled: bool,
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        self.scan_other_page(source, roots, support, index, sampled, 100, &[])
    }

    /// The same native acquisition with a bounded page and watcher hints.
    #[expect(clippy::too_many_arguments, reason = "test helper, 8 scan inputs")]
    pub(crate) fn scan_other_page(
        &self,
        source: SnapshotSource,
        roots: &[PathBuf],
        support: &Path,
        mut index: ScanIndex,
        sampled: bool,
        limit: usize,
        hints: &[PathBuf],
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        index.activate_effective_upload_body_witness_revision(
            crate::snapshot_sync::effective_upload_body_witness_revision(source),
        );
        let (scope, _) = scan_binding(source);
        let mut scan = OwnedSourceScan::new_with_recovery_priority(
            source,
            roots,
            index,
            &self.collection_time("2026-10-27T08:00:00Z"),
            self.collection_window_days.unwrap_or(183),
            limit,
            Some(support),
            hints,
            false,
            &mut ListingRequest::default(),
            false,
            &[],
            sampled.then_some((self.cache.as_ref(), &scope)),
            false,
        );
        if sampled {
            scan = scan.with_sampled_acquisition(self.cache.clone(), scope);
        }
        if let Some(versions) = self.versions.as_ref() {
            scan = scan.with_codex_versions(versions.clone());
        }
        self.drive(scan, &BTreeMap::new())
    }

    fn drive(
        &self,
        mut scan: OwnedSourceScan,
        births: &BTreeMap<PathBuf, i128>,
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        let mut seen = BTreeSet::new();
        let mut recorded_active = false;
        for _ in 0..100_000 {
            // Existing fixture setter changes only physical birth. JSONL still
            // comes from the opened reader, including retained prefix/suffix.
            if let Some(active) = scan.active_file.as_deref_mut() {
                if seen.insert(active.candidate.path.clone()) {
                    self.observed
                        .lock()
                        .unwrap()
                        .push(active.candidate.path.clone());
                }
                // An active file spans multiple steps. Record once per active
                // lifetime, including repeated paths and unsampled native reads.
                if !recorded_active {
                    let plan = active.parser.reader.acquisition.as_ref();
                    let mode = plan.map_or_else(
                        || {
                            active.sampling.as_ref().map_or(
                                crate::transcript_acquisition::ReadMode::Full(
                                    crate::transcript_acquisition::FullReason::StateMissing,
                                ),
                                |sampling| sampling.mode,
                            )
                        },
                        |plan| plan.mode(),
                    );
                    let start = plan.map_or(0, |plan| plan.start_offset());
                    twin_diagnostics::event(&active.candidate.path, || {
                        format!(
                            "acquire mode={mode:?} start={start} reason={:?} sampled={}",
                            active.parse_reason,
                            active.sampling.is_some(),
                        )
                    });
                    self.acquisitions.lock().unwrap().push(Acquisition {
                        path: active.candidate.path.clone(),
                        reason: active.parse_reason,
                        mode,
                        start,
                    });
                    recorded_active = true;
                }
                if let Some(birth) = births.get(&active.candidate.path) {
                    if self.subagent_births
                        || !active
                            .parser
                            .accumulator
                            .claude_file_birth
                            .is_subagent_for_test()
                    {
                        active
                            .parser
                            .accumulator
                            .claude_file_birth
                            .set_birth_for_test(*birth);
                    }
                }
            }
            if scan.active_file.is_none() {
                recorded_active = false;
            }
            let modes = scan.sampling.as_ref().map_or((0, 0, 0), |s| {
                (s.full_files, s.tail_files, s.unchanged_files)
            });
            let reasons = scan
                .sampling
                .as_ref()
                .map_or([0; crate::transcript_acquisition::FULL_REASON_COUNT], |s| {
                    s.full_reasons
                });
            let touches = scan
                .sampling
                .as_ref()
                .map_or(0, |s| s.same_size_touch_proven);
            let attribution = self.attribution.lock().unwrap();
            let step = scan.step(attribution.as_ref());
            drop(attribution);
            match step {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => {
                    *self.full_reasons.lock().unwrap() = reasons;
                    *self.touches_proven.lock().unwrap() = touches;
                    twin_diagnostics::folds(&scan.snapshots);
                    return (index, scan, modes);
                }
            }
        }
        panic!("bounded synthetic E2 scan failed to finish");
    }
}

pub(crate) fn birth_store_bytes(index: &ScanIndex) -> Vec<u8> {
    serde_json::to_vec(&index.claude_money_birth_store).unwrap()
}

pub(crate) fn with_resident_budget<T>(budget: f64, run: impl FnOnce() -> T) -> T {
    crate::snapshots::claude_history_upgrade::with_resident_budget(budget, run)
}

pub(crate) fn with_history_byte_limit<T>(limit: u64, f: impl FnOnce() -> T) -> T {
    with_body_witness_adoption_byte_budget(limit, f)
}

pub(crate) fn explicitly_held(
    disposition: &ClaudeUsageAuthorityDisposition,
    session: &str,
) -> bool {
    disposition.quarantined_source_session_ids.contains(session)
}

/// `index` published as a live state_v2 store under `dir`, owing `path`'s
/// growth from its indexed size with its growth Full claimed now (paced) or
/// one interval ago (due), as a daemon that already spent that Full holds it.
pub(crate) fn owe_claimed_growth(
    index: &ScanIndex,
    dir: &Path,
    path: &Path,
    paced: bool,
) -> ScanIndex {
    let key = local_index_key(path);
    let now = sampled_scan::now_seconds();
    let claim = if paced {
        now
    } else {
        now - sampled_audit::GROWTH_FULL_INTERVAL
    };
    let mut seed = index.clone();
    let owed =
        json!({"predecessor_size": seed.files[&key].size_bytes, "last_growth_full_unix": claim});
    seed.v2_mut()
        .growth_retention
        .insert(key, serde_json::from_value(owed).unwrap());
    // State v2 refuses a store below a symlinked ancestor (a `$TMPDIR` one).
    let parent = dir.join("snapshots/destinations").join("a".repeat(64));
    fs::create_dir_all(&parent).unwrap();
    let store = parent
        .canonicalize()
        .unwrap()
        .join(format!("claude_code-growth-{paced}-scan-index.json"));
    let published = publish_state_v2_for_test(&seed, &store, br#"{"generation":0}"#);
    assert_eq!(
        sampled_audit::growth_full_paced(&published, &local_index_key(path), now),
        paced
    );
    published
}

pub(crate) fn indexed_size(index: &ScanIndex, path: &Path) -> Option<u64> {
    index
        .files
        .get(&local_index_key(path))
        .map(|entry| entry.size_bytes)
}

/// Model already delivered history after the synthetic uploader has ACKed
/// every current entity: each file holds its receipt under `context` (an
/// empty file its local empty proof). Creates no ACK.
pub(crate) fn receipt_acked_files_for_test(index: &mut ScanIndex, context: &str) {
    let delivered = index.current_snapshot_fingerprints();
    assert!(!delivered.is_empty());
    assert!(delivered
        .iter()
        .all(|fp| index.accepted_snapshot_fingerprint_recorded(fp)));
    for entry in index.files.values_mut() {
        entry.upload_context_receipt = Some(crate::snapshots::upload_context_receipt::Receipt {
            context_fingerprint: context.into(),
            replay_generation: crate::snapshots::upload_context_receipt::RECEIPT_REPLAY_EPOCH,
            source_witness: entry.source_file_fingerprint.clone(),
            body_witness: entry.last_upload_body_witness.clone().unwrap_or_default(),
        });
    }
}

/// An earlier upload delivered this origin's body. The receipt is under another
/// context and other bytes, so it decides the copy and proves no current read:
/// the file still owes its own upload exactly as if it had no receipt.
pub(crate) fn origin_accepted_for_test(index: &mut ScanIndex, key: &str) {
    index.files.get_mut(key).unwrap().upload_context_receipt =
        Some(crate::snapshots::upload_context_receipt::Receipt {
            context_fingerprint: "another-upload-context".into(),
            replay_generation: crate::snapshots::upload_context_receipt::RECEIPT_REPLAY_EPOCH,
            source_witness: "a".repeat(64),
            body_witness: "b".repeat(64),
        });
}

/// Declare the counted hashes of a synthetic accepted body, independently of
/// its census and receipt. Real pipeline fixtures use exact ACK settlement.
pub(crate) fn accepted_origin_hashes_for_test(
    index: &mut ScanIndex,
    key: &str,
    session: &str,
    hashes: &[u64],
) {
    use super::claude_money_birth_store::location_key;
    use super::upload_context_receipt::SlotRows;
    let mut digest = Sha256::new();
    digest.update(SnapshotSource::ClaudeCode.api_slug().as_bytes());
    digest.update([0]);
    digest.update(session.as_bytes());
    let slot = crate::hex::encode(&digest.finalize()[..16]);
    let row = index
        .upload_context_proof
        .request_contributions
        .entry(slot)
        .or_insert_with(|| SlotRows {
            fingerprint: "c".repeat(64),
            body_witness: "d".repeat(64),
            rows: Box::new([]),
        });
    let loc = location_key(key);
    let mut rows = row.rows.to_vec();
    rows.retain(|(location, _)| *location != loc);
    let mut hashes = hashes.to_vec();
    hashes.sort_unstable();
    hashes.dedup();
    rows.push((loc, Arc::from(hashes)));
    rows.sort_by_key(|(location, _)| *location);
    row.rows = rows.into_boxed_slice();
}

/// Each sent item's exact ACK (entity -> upload body witness), as the
/// synthetic responders answer a fully accepted page.
pub(crate) fn exact_acks_for_test(items: &[SnapshotItem]) -> BTreeMap<String, String> {
    items
        .iter()
        .map(|item| {
            (
                item.snapshot_fingerprint.clone(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect()
}

/// The production finish of per-file upload-context proof for one page:
/// the page's final `items` become receipt candidates under the index's
/// active context, and only exact `acks` earn receipts (`snapshot_sync`
/// finish and partial checkpoint run the same calls), and the exact ACKs
/// stamp their entities' durable context proof under the active context in
/// one fixture destination. Call it after the page's settlement, where the
/// service does.
pub(crate) fn accept_upload_context_acks_for_test(
    index: &mut ScanIndex,
    items: &[SnapshotItem],
    acks: &BTreeMap<String, String>,
) {
    let candidates = index.file_upload_context_ack_candidates(items, &BTreeMap::new());
    index.accept_file_upload_context_acks(&candidates, acks, &BTreeMap::new());
    let contexts = index
        .active_upload_context_fingerprint
        .as_ref()
        .map(|context| {
            acks.keys()
                .map(|entity| (entity.clone(), context.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    index.stamp_entity_upload_context_acks("e2-fixture-destination", acks, &contexts);
    crate::snapshot_sync::accept_request_contributions_for_test(index, items, acks);
}

/// `path` holds a receipt for its current body under the active context
/// (its revision may still be cleared for a forced reparse).
pub(crate) fn upload_context_receipt_earned_for_test(index: &ScanIndex, path: &Path) -> bool {
    index
        .files
        .get(&local_index_key(path))
        .is_some_and(|entry| {
            entry
                .upload_context_receipt
                .as_ref()
                .is_some_and(|receipt| {
                    index.active_upload_context_fingerprint.as_ref()
                        == Some(&receipt.context_fingerprint)
                        && receipt.replay_generation
                            == crate::snapshots::upload_context_receipt::RECEIPT_REPLAY_EPOCH
                        && entry.last_upload_body_witness.as_ref() == Some(&receipt.body_witness)
                })
        })
}

/// `path`'s stored proof is bound to the active context and current replay epoch.
pub(crate) fn upload_context_proof_is_current_for_test(index: &ScanIndex, path: &Path) -> bool {
    index
        .files
        .get(&local_index_key(path))
        .and_then(|entry| entry.upload_context_receipt.as_ref())
        .is_some_and(|proof| {
            index.active_upload_context_fingerprint.as_ref() == Some(&proof.context_fingerprint)
                && proof.replay_generation
                    == crate::snapshots::upload_context_receipt::RECEIPT_REPLAY_EPOCH
        })
}

/// `path` still owes its own upload-context proof under the active context.
pub(crate) fn upload_context_owed_for_test(index: &ScanIndex, path: &Path) -> bool {
    index.file_upload_context_requires_adoption(&local_index_key(path))
}

/// Files that still owe their own upload-context proof, by the per-file gate
/// alone (no owed-count exemption).
pub(crate) fn upload_context_unproven_files_for_test(index: &ScanIndex) -> usize {
    index
        .files
        .keys()
        .filter(|key| index.file_upload_context_requires_adoption(key))
        .count()
}

/// Install the real exclusion input used by ordinary-money fixture families.
/// An empty slice adopts request-owned money on the next normal source pass.
pub(crate) fn write_exclusions(support: &Path, sessions: &[&str]) {
    use sha2::Digest;
    let path = claude_reemission_exclusions::ReemissionExclusions::path(support);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let lines = sessions
        .iter()
        .map(|session| format!("{:x}\n", sha2::Sha256::digest(session.as_bytes())))
        .collect::<String>();
    fs::write(path, lines).unwrap();
}

/// Ordinary (pre-`e2`) money for every family, scoped to this fixture index:
/// the list names every family.
pub(crate) fn ordinary_index(mut index: ScanIndex) -> ScanIndex {
    index.claude_reemission_exclusions =
        claude_reemission_exclusions::ReemissionExclusions::listing_every_family_for_test();
    index
}

/// Ordinary-money parser fixture through the existing native parser, every
/// family listed. No alternate resolver or money builder.
pub(crate) fn parse_ordinary(
    path: &Path,
    at: &str,
    fingerprint: String,
) -> Result<Vec<SnapshotItem>> {
    parse_ordinary_with_metadata(path, at, fingerprint, &ClaudeTitleMetadata::default())
}

pub(in crate::snapshots) fn parse_ordinary_with_metadata(
    path: &Path,
    at: &str,
    fingerprint: String,
    metadata: &ClaudeTitleMetadata,
) -> Result<Vec<SnapshotItem>> {
    let mut file = File::open(path)?;
    let opened = opened_object_identity(SnapshotSource::ClaudeCode, &mut file)?;
    let mut parser = OwnedJsonlParser::new(
        file,
        path,
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        None,
    )?;
    while !parser.step()? {}
    let index = ordinary_index(ScanIndex::default());
    parser
        .finish_with_repository_identity(
            &opened,
            path,
            at,
            fingerprint,
            None,
            Some(metadata),
            None,
            None,
            Some(claude_request_money::e2::ReadContext {
                index: &index,
                path,
                twins: &std::cell::OnceCell::new(),
            }),
        )
        .map(|parsed| parsed.snapshots)
}

/// Telemetry retention dependency row: an account hold on `key`.
pub(crate) fn hold_claude_account_for_test(index: &mut ScanIndex, key: &str) {
    index
        .claude_account_deferred_holds
        .insert(key.to_owned(), "held-source".to_owned());
}

/// Telemetry retention dependency row: a Tail head for `key` (no pages) on
/// `index`'s live route, committed by an ordinary save. True when the
/// committed heads then hold it.
pub(crate) fn commit_tail_head_for_test(index: &mut ScanIndex, key: &str) -> bool {
    let route = route_of(index).expect("a routed index");
    state_v2::stage_tail(
        &route,
        key,
        state_v2::StagedFile {
            revision: 1,
            head: b"head".to_vec(),
            ..Default::default()
        },
    )
    .unwrap();
    index.save_fixture(&route).unwrap();
    state_v2::tail_head_keys(index).unwrap().contains(key)
}

/// Telemetry retention dependency row: `owner` is a legacy owner root of
/// `root`'s family witness, under a terminal (unproven) authority record.
pub(crate) fn legacy_owner_of_terminal_family_for_test(
    index: &mut ScanIndex,
    root: &str,
    owner: &str,
) {
    index.insert_unproven_terminal_claude_authority_for_test(root, &"1".repeat(64));
    index
        .claude_usage_family_witnesses
        .get_mut(root)
        .expect("the terminal record retains its witness")
        .legacy_owner_roots
        .insert(owner.to_owned());
}

pub(crate) fn file_upload_body_set(items: &[SnapshotItem]) -> String {
    snapshot_file_upload_body_set_hex(
        items
            .iter()
            .map(snapshot_upload_body_witness)
            .collect::<BTreeSet<_>>(),
    )
}

/// Retain a file decode hold alongside its known entry for selection controls.
pub(crate) fn hold_file_decode_for_test(index: &mut ScanIndex, key: &str) {
    index
        .decode_holds
        .v2_insert("files", key.to_owned(), b"null".to_vec(), None, 4)
        .unwrap();
}

/// Retain the decoder's exact-entity hold for retry eligibility controls.
pub(crate) fn hold_entity_decode_for_test(index: &mut ScanIndex, fingerprint: &str) {
    index
        .decode_holds
        .v2_insert(
            "quarantined_snapshot_fingerprints",
            fingerprint.to_owned(),
            b"null".to_vec(),
            None,
            4,
        )
        .unwrap();
}

/// Mutate only real committed fixture state; no manufactured certificate.
pub(crate) fn damage_tail_for_test(index: &ScanIndex, key: &str, damage: &str) {
    let route = route_of(index).unwrap();
    if damage == "missing" {
        state_v2::retire_tail(&route, [key.to_owned()]).unwrap();
        return;
    }
    let revision = tail_source::reduction_revision(SnapshotSource::ClaudeCode);
    let head = state_v2::load_head(index, key, revision).unwrap().unwrap();
    let mut staged = state_v2::StagedFile {
        revision: head.revision,
        head: head.body.clone(),
        ..Default::default()
    };
    // Ordinary stages keep the committed collection metadata and pages.
    match damage {
        "future" => staged.revision += 1,
        "corrupt" => staged.head = vec![0],
        _ => panic!("unknown fixture damage"),
    }
    state_v2::stage_tail(&route, key, staged).unwrap();
}

/// The acquisition gate, exposed without widening its production visibility.
pub(crate) fn forced_needs_native_for_test(index: &ScanIndex, path: &Path) -> bool {
    claude_request_census::forced_member_needs_native(index, &local_index_key(path))
}

/// Resolve actual discovery revisions without staging a file reduction: this
/// exercises the debt-only Tail save with the caller's exact-ACKed carrier.
pub(crate) fn resolve_carrier_discovery_debt_for_test(
    index: &mut ScanIndex,
    path: &Path,
) -> (usize, usize) {
    fn revisions(index: &ScanIndex, key: &str) -> (usize, Vec<u8>) {
        let head = state_v2::load_head(index, key, u32::MAX).unwrap().unwrap();
        let mut count = 0;
        state_v2::load_revisions(index, key, &head, |_, _| {
            count += 1;
            Ok(())
        })
        .unwrap();
        (count, head.body)
    }
    let key = local_index_key(path);
    let (before, body) = revisions(index, &key);
    index.activate_upload_context("e2-synthetic-destination".into());
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[path.parent().unwrap().to_path_buf()],
        index,
        "2026-08-02T08:00:00Z",
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.clone().unwrap();
    let mut fold = money_freshness::WalkFold::EMPTY;
    let mut page = upload::freshness_debt::Page::begin(
        SnapshotSource::ClaudeCode,
        index,
        &traversal,
        false,
        &mut fold,
    );
    let metadata = fs::metadata(path).unwrap();
    page.listed(
        index,
        upload::freshness_debt::Listing {
            path,
            metadata: &metadata,
            in_window: true,
        },
    );
    let _ = page.end(index, false, |_| {});
    let route = route_of(index).unwrap();
    index.save_fixture(&route).unwrap();
    let (after, kept) = revisions(index, &key);
    assert_eq!(body, kept, "debt-only save retains the committed reduction");
    (before, after)
}

pub(crate) fn non_tail_carrier_observation_for_test(index: &ScanIndex, path: &Path) {
    state_v2::observe_tail(
        &route_of(index).unwrap(),
        &local_index_key(path),
        state_v2::Observation {
            representation: state_v2::Representation::NonTail,
            ..Default::default()
        },
    )
    .unwrap();
}

/// A comparison caches logical input, never an open connection across restores.
pub(crate) fn detach_route_for_test(index: &mut ScanIndex) {
    index.v2_mut().persistence_v2 = None;
}

pub(crate) fn expire_claimed_growth_for_test(index: &mut ScanIndex, path: &Path) {
    let key = local_index_key(path);
    let now = sampled_scan::now_seconds();
    assert!(sampled_audit::growth_full_paced(index, &key, now));
    assert!(index
        .traversal
        .as_ref()
        .is_some_and(|walk| walk.counts.growth_deferred > 0));
    expire_growth_claim(index, path);
}

/// Age only a saved claim proved by an uncommitted deferred page. Its
/// predecessor metadata and queue changes remain uncommitted.
pub(crate) fn expire_observed_growth_for_test(
    index: &mut ScanIndex,
    path: &Path,
    deferred: &ScanIndex,
) {
    assert_eq!(route_of(index), route_of(deferred));
    let key = local_index_key(path);
    assert!(sampled_audit::growth_full_paced(
        deferred,
        &key,
        sampled_scan::now_seconds()
    ));
    assert!(deferred
        .traversal
        .as_ref()
        .is_some_and(|walk| walk.counts.growth_deferred > 0));
    let saved = serde_json::to_value(&index.v2().growth_retention[&key]).unwrap();
    let observed = serde_json::to_value(&deferred.v2().growth_retention[&key]).unwrap();
    assert_eq!(
        saved["last_growth_full_unix"],
        observed["last_growth_full_unix"]
    );
    expire_growth_claim(index, path);
}

fn expire_growth_claim(index: &mut ScanIndex, path: &Path) {
    let key = local_index_key(path);
    let now = sampled_scan::now_seconds();
    let state = index.v2_mut().growth_retention.get_mut(&key).unwrap();
    let mut value = serde_json::to_value(&*state).unwrap();
    value["last_growth_full_unix"] = json!(now - sampled_audit::GROWTH_FULL_INTERVAL);
    *state = serde_json::from_value(value).unwrap();
    assert!(!sampled_audit::growth_full_paced(index, &key, now));
    let route = route_of(index).unwrap();
    // Ordinary saves preserve the maximum durable claim. A fixture clock jump
    // installs its aged row explicitly, as owe_claimed_growth does.
    let runtime = runtime_only(index);
    let mut aged = seed_index_for_test(index, &route);
    carry_runtime(&runtime, &mut aged);
    assert!(!sampled_audit::growth_full_paced(&aged, &key, now));
    *index = aged;
}

pub(crate) fn discard_store_for_test(path: &Path) {
    state_v2::erase_published(path);
}

pub(crate) fn edit_record_for_test(
    index: &ScanIndex,
    kind: &str,
    name: &str,
    edit: impl FnOnce(&mut serde_json::Value),
) {
    state_v2::money_test_support::edit_record_for_test(index, kind, name, edit);
}

pub(crate) fn exhaust_progress_generation_for_test(index: &ScanIndex) {
    state_v2::money_test_support::exhaust_progress_generation_for_test(index);
}

/// Native acquisition for pipeline oracles that require Full-certified source
/// evidence. An incompatible restored acquisition scope requests the production
/// Full(ScopeChanged) path. Index and delivery custody stay on the same native
/// route; a caller's warm memo stays owned across pages.
pub(crate) fn scan_native_full_pipeline_for_test(
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    window_days: u64,
    limit: usize,
    support: &Path,
    cache: Option<Arc<sampled_scan::SharedCache>>,
) -> Result<SourceScanResult> {
    struct RestoreScope(bool);
    impl Drop for RestoreScope {
        fn drop(&mut self) {
            crate::transcript_acquisition::RESTORED_SCOPE_MISMATCH.with(|flag| flag.set(self.0));
        }
    }
    let _full = RestoreScope(
        crate::transcript_acquisition::RESTORED_SCOPE_MISMATCH.with(|flag| flag.replace(true)),
    );
    state_v2::release_collection_page_limit_for_test(index);
    state_v2::before_collection(index)?;
    let cache = cache.unwrap_or_default();
    let scope = Scope("native-full-pipeline-fixture".into());
    let mut state = OwnedSourceScan::new_with_recovery_priority(
        SnapshotSource::ClaudeCode,
        roots,
        std::mem::take(index),
        collected_at,
        window_days,
        limit,
        Some(support),
        &[],
        false,
        &mut ListingRequest::default(),
        true,
        &[],
        Some((cache.as_ref(), &scope)),
        false,
    )
    .with_sampled_acquisition(cache, scope);
    loop {
        if let Err(error) = state_v2::before_collection(&state.index) {
            *index = state.index;
            return Err(error);
        }
        let retained_reads = state
            .sampling
            .as_ref()
            .map_or(0, |context| context.tail_files + context.unchanged_files);
        match state.step(None) {
            OwnedSourceScanStep::Pending(next) => state = next,
            OwnedSourceScanStep::Complete {
                index: complete,
                scan,
                ..
            } => {
                assert_eq!(retained_reads, 0, "this fixture requires Full source proof");
                *index = complete;
                return Ok(scan);
            }
        }
    }
}

pub(crate) fn growth_diagnostics_for_test(index: &ScanIndex, path: &Path) -> (bool, u64) {
    (
        sampled_audit::growth_full_paced(
            index,
            &local_index_key(path),
            sampled_scan::now_seconds(),
        ),
        index
            .traversal
            .as_ref()
            .map_or(0, |walk| walk.counts.growth_deferred),
    )
}

pub(crate) fn delete_holder_for_test(index: &mut ScanIndex, key: &str) {
    index.drop_file_entry(key);
}
pub(crate) fn invalidate_holder_for_test(index: &mut ScanIndex, key: &str) {
    index.claude_request_census.invalidate_keeping_birth(key);
}
pub(crate) fn accepted_file_for_test(index: &ScanIndex, key: &str) -> bool {
    index.file_has_accepted_body_unheld(key)
}
pub(crate) fn unhold_claude_account_for_test(index: &mut ScanIndex, key: &str) {
    index.claude_account_deferred_holds.remove(key);
}
