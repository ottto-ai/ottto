//! Test-only observation of the real scanner; no alternate parser/finalizer.
use super::*;
use crate::transcript_acquisition::Scope;

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

/// Claude continues only from the state database, so an owner's retained
/// state is its route: the prior this owner produced is committed there first,
/// as the daemon saves between passes, and any other owner's prior moves to a
/// new, empty route, which reads what changed Full. A caller's own session is
/// left alone.
pub(crate) fn routed_for_test(
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
                None => carry(ScanIndex::load(&route.path).unwrap()),
            };
        }
        if let Some(mine) = on
            .as_ref()
            .filter(|on| **on == route.path || route.others.contains(on))
        {
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
    let prior = if on.is_some() {
        state_v2::money_test_support::resident(&index)
    } else {
        index
    };
    let (path, cold) = publish_route(&prior, dir);
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

/// `index`'s files with no continuation, on their own route: RAM is released
/// and each head retired, so the next read of each is a Full as a first read
/// is. A released cache alone keeps the heads, as in production.
pub(crate) fn forget_continuations_for_test(cache: &sampled_scan::SharedCache, index: &ScanIndex) {
    cache.clear();
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
    index.save(route)
}

/// An in-memory prior keeps every runtime-only (`serde(skip)`) field across
/// the fixture's save and reload, as the RAM-era fixture's index did; a sync
/// cycle also re-applies the paused list and copy capabilities to each index.
fn carry_runtime(from: &ScanIndex, into: &mut ScanIndex) {
    into.claude_reemission_exclusions = from.claude_reemission_exclusions.clone();
    into.copy_unproven_enabled = from.copy_unproven_enabled;
    into.copy_prefix_base_upload_context = from.copy_prefix_base_upload_context.clone();
    into.codex_counting_moved_evidence = from.codex_counting_moved_evidence.clone();
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
    into.claude_history_unverified_in_process = from.claude_history_unverified_in_process;
    into.claude_rebuild_read_load_eligible = from.claude_rebuild_read_load_eligible;
    into.reason_reoffer_cooldowns = from.reason_reoffer_cooldowns.clone();
    into.codex_counting_evictions = from.codex_counting_evictions;
    into.claude_no_list_policy = from.claude_no_list_policy;
    into.claude_history_emission = from.claude_history_emission.clone();
    into.copy_prefix_recovery_scope = from.copy_prefix_recovery_scope.clone();
    into.withheld_memo = from.withheld_memo.clone();
}

/// An empty graph holding only `index`'s runtime-only fields.
fn runtime_only(index: &ScanIndex) -> ScanIndex {
    let mut runtime = ScanIndex::default();
    carry_runtime(index, &mut runtime);
    runtime
}

/// `prior` published on a new fixture route under `dir`: (route, cold graph).
fn publish_route(prior: &ScanIndex, dir: &Path) -> (PathBuf, ScanIndex) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (session, cold) = StateV2ColdSession::publish(
        scan_index_persistence::Source::Claude,
        prior,
        &dir.canonicalize().unwrap().join(format!("route-{n}")),
    );
    let path = session.path().to_owned();
    // Other arms still read this route; the scratch dir owns it.
    std::mem::forget(session);
    E2ScanFixture::register_route_for_test(&path);
    (path, cold)
}

/// A restart of `index` as its own install: its resident graph published on
/// a new route, so another install's commits from the same prior never stale
/// it. An unrouted index is returned as is.
pub(crate) fn own_install_for_test(index: &ScanIndex, dir: &Path) -> ScanIndex {
    if route_of(index).is_none() {
        return index.clone();
    }
    // A restart from disk: runtime-only fields are gone, as through a file.
    publish_route(&state_v2::money_test_support::resident(index), dir).1
}

/// This thread's process total of the Tail counter `name{label}`, summed over
/// sources.
pub(crate) fn tail_counter_for_test(name: &'static str, label: &'static str) -> u64 {
    tail_source::counters::total(name, label)
}

/// The certified checkpoint a key continues from, read back for assertions.
pub(crate) struct Continuation {
    audit_debt: Option<crate::transcript_acquisition::AuditDebt>,
    last_full_verified: u64,
}
impl Continuation {
    pub(crate) fn audit_debt(&self) -> Option<crate::transcript_acquisition::AuditDebt> {
        self.audit_debt
    }
    pub(crate) fn last_full_verified(&self) -> u64 {
        self.last_full_verified
    }
}

/// `key`'s continuation: for a source with a Tail codec its head on
/// `index`'s route (this pass's staged head, else the committed one), as the
/// RAM-era fixture read its retained checkpoint; any other source's retained
/// copy.
pub(crate) fn continuation_for_test(
    source: SnapshotSource,
    cache: &sampled_scan::SharedCache,
    index: &ScanIndex,
    key: &str,
) -> Option<Continuation> {
    let certificate = match source {
        SnapshotSource::ClaudeCode => head_certificate::<tail_source::claude::Claude>(index, key)?,
        SnapshotSource::Codex => head_certificate::<tail_source::codex::Codex>(index, key)?,
        SnapshotSource::Pi => {
            return cache
                .retained_checkpoint(key)
                .map(|checkpoint| Continuation {
                    audit_debt: checkpoint.audit_debt(),
                    last_full_verified: checkpoint.last_full_verified(),
                })
        }
    };
    Some(Continuation {
        audit_debt: certificate
            .audit_debt_unix_seconds
            .map(|due_unix_seconds| crate::transcript_acquisition::AuditDebt { due_unix_seconds }),
        last_full_verified: certificate.verified_unix_seconds,
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

/// A routed graph read back resident, for byte comparisons; an unrouted one
/// as is.
pub(crate) fn resident_for_test(index: &ScanIndex) -> ScanIndex {
    if route_of(index).is_some() {
        state_v2::money_test_support::resident(index)
    } else {
        index.clone()
    }
}

/// A scan fixture's page of a source with a Tail codec continues from its
/// owner's route; with no cache it reads a fixture route unrouted. Other
/// sources are left alone.
pub(crate) fn route_for_test(
    source: SnapshotSource,
    cache: Option<&sampled_scan::SharedCache>,
    index: ScanIndex,
) -> ScanIndex {
    if !tail_source::has_codec(source) {
        return index;
    }
    let Some(cache) = cache else {
        // A scan with no cache to own a route is the cold oracle: it reads a
        // fixture route's graph unrouted, as before Claude kept its Tail there,
        // so another arm's commits on that route never stale it.
        let fixture_route =
            route_of(&index).is_some_and(|path| fixture_routes().lock().unwrap().contains(&path));
        if !fixture_route {
            return index;
        }
        let mut copy = state_v2::money_test_support::resident(&index);
        copy.v2_mut().persistence_v2 = None;
        carry_runtime(&index, &mut copy);
        return copy;
    };
    let dir = std::env::temp_dir().join(format!("ottto-fixture-routes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    routed_for_test(cache, index, &dir)
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

/// A fixture's save beside its own files. A routed index commits on its route
/// and leaves an unrouted copy at `path`: a later load from there holds no
/// Claude continuation, so its next change reads Full.
pub(crate) fn save_for_test(index: &mut ScanIndex, path: &Path) {
    let Some(route) = route_of(index) else {
        return index.save(path).unwrap();
    };
    save_on_route(index, &route).unwrap();
    let mut copy = state_v2::money_test_support::resident(index);
    copy.v2_mut().persistence_v2 = None;
    // A fresh copy each save: its generation is the route's, not this file's.
    let _ = fs::remove_file(path);
    copy.generation = 0;
    copy.save(path).unwrap();
}

/// The same owner's save and reload between passes, as the daemon's: a
/// routed index commits on its route and continues from it (the RAM-era
/// fixture kept its cache across this reload); an unrouted one round-trips
/// through `path`.
pub(crate) fn save_reload_for_test(index: &mut ScanIndex, path: &Path) -> ScanIndex {
    let Some(route) = route_of(index) else {
        index.save(path).unwrap();
        return ScanIndex::load(path).unwrap();
    };
    save_on_route(index, &route).unwrap();
    let mut loaded = ScanIndex::load(&route).unwrap();
    carry_runtime(index, &mut loaded);
    loaded
}

#[derive(Default)]
pub(crate) struct E2ScanFixture {
    pub(crate) cache: Arc<sampled_scan::SharedCache>,
    observed: Mutex<Vec<PathBuf>>,
    pub(crate) versions: Option<Arc<codex_version::CodexVersionFeed>>,
    capture_claude_identity: bool,
    attribution: Mutex<Option<crate::session_attribution::SessionAttributionContext>>,
}
impl E2ScanFixture {
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

    pub(crate) fn paths(&self) -> Vec<PathBuf> {
        self.observed.lock().unwrap().clone()
    }

    pub(crate) fn register_route_for_test(path: &Path) {
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
        routed_for_test(&self.cache, index, dir)
    }

    /// Begins this owner's pass, as the daemon does before a scan.
    /// `state_dir` holds the index and the single-writer lock.
    pub(crate) fn begin_pass(&self, source: SnapshotSource, state_dir: &Path, index_path: &Path) {
        let (scope, capture) = scan_binding(source);
        let capture = if source == SnapshotSource::ClaudeCode {
            self.capture_claude_identity
        } else {
            capture
        };
        begin_source_pass(&self.cache, state_dir, source, index_path, &scope, capture);
    }

    /// `index`'s files lose their continuation.
    pub(crate) fn evict(&self, index: &ScanIndex) {
        forget_continuations_for_test(&self.cache, index);
    }

    pub(crate) fn evict_for_pressure(&self, index: &ScanIndex) {
        let mut retained = self.cache.retained().unwrap();
        let empty = sampled_scan::RetainedCache::default();
        let limit = crate::heap_layout_bound::bound(&empty, usize::MAX).unwrap_or(0);
        assert!(retained.release_until(limit) || !crate::heap_layout_bound::layout_supported());
        drop(retained);
        forget_continuations_for_test(&self.cache, index);
    }

    #[allow(clippy::too_many_arguments)]
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
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            roots,
            index,
            "2026-08-02T08:00:00Z",
            183,
            limit,
            Some(support),
            hints,
            false,
            self.capture_claude_identity,
        );
        if sampled {
            let (scope, _) = scan_binding(SnapshotSource::ClaudeCode);
            scan = scan.with_sampled_acquisition(self.cache.clone(), scope);
        }
        // The same synthetic root births reach the page's staged twin probes,
        // which read metadata before the file is opened for parse.
        let staged = births
            .iter()
            .filter(|(path, _)| {
                claude_index_path_member_ref(path)
                    .is_some_and(|member| member.subagent_stem.is_none())
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
        mut index: ScanIndex,
        sampled: bool,
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        index.activate_effective_upload_body_witness_revision(
            crate::snapshot_sync::effective_upload_body_witness_revision(source),
        );
        let mut scan = OwnedSourceScan::new(
            source,
            roots,
            index,
            "2026-10-27T08:00:00Z",
            183,
            100,
            Some(support),
            &[],
            false,
        );
        if sampled {
            let (scope, _) = scan_binding(source);
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
                if let Some(birth) = births.get(&active.candidate.path) {
                    if !active
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
            let modes = scan.sampling.as_ref().map_or((0, 0, 0), |s| {
                (s.full_files, s.tail_files, s.unchanged_files)
            });
            let attribution = self.attribution.lock().unwrap();
            let step = scan.step(attribution.as_ref());
            drop(attribution);
            match step {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
            }
        }
        panic!("bounded synthetic E2 scan failed to finish");
    }
}

pub(crate) fn birth_store_bytes(index: &ScanIndex) -> Vec<u8> {
    serde_json::to_vec(&index.claude_money_birth_store).unwrap()
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
        entry.upload_context_receipt = Some(super::upload_context_receipt::Receipt {
            context_fingerprint: context.into(),
            replay_generation: super::upload_context_receipt::RECEIPT_REPLAY_EPOCH,
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
        Some(super::upload_context_receipt::Receipt {
            context_fingerprint: "another-upload-context".into(),
            replay_generation: super::upload_context_receipt::RECEIPT_REPLAY_EPOCH,
            source_witness: "a".repeat(64),
            body_witness: "b".repeat(64),
        });
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
    let candidates = index.file_upload_context_ack_candidates(items);
    index.accept_file_upload_context_acks(&candidates, acks);
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
                            == super::upload_context_receipt::RECEIPT_REPLAY_EPOCH
                        && entry.last_upload_body_witness.as_ref() == Some(&receipt.body_witness)
                })
        })
}

/// `path` still owes its own upload-context proof under the active context.
pub(crate) fn upload_context_owed_for_test(index: &ScanIndex, path: &Path) -> bool {
    index.file_upload_context_requires_adoption(&local_index_key(path))
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

/// A real fail-closed exclusion-list result, scoped to this fixture index.
pub(crate) fn ordinary_index(mut index: ScanIndex) -> ScanIndex {
    index.claude_reemission_exclusions = claude_reemission_exclusions::ReemissionExclusions::parse(
        b"malformed synthetic exclusion input",
    );
    index
}

/// Ordinary-money parser fixture through the existing native parser and real
/// paused-adoption input. No alternate resolver or money builder.
pub(crate) fn parse_ordinary(
    path: &Path,
    at: &str,
    fingerprint: String,
) -> Result<Vec<SnapshotItem>> {
    parse_ordinary_with_metadata(path, at, fingerprint, &ClaudeTitleMetadata::default())
}

pub(super) fn parse_ordinary_with_metadata(
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
        None,
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

/// Persist a real malformed-list input to exercise fail-closed ordinary money.
pub(crate) fn pause_adoption(support: &Path) {
    let path = claude_reemission_exclusions::ReemissionExclusions::path(support);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, b"malformed synthetic exclusion input").unwrap();
}
