// Extends the native archive/transition fixture and stored-body ACK driver.
// A Codex account home removed from the roster, with its tree deleted, must
// not keep scan generations red. Kept home A is the `Corpus` (two accounts,
// a mid-session switch, a side call, an evidence gap and tagged rows);
// removed home B holds two more sessions. An absent optional root enables
// legacy witness inference, as an absent `archived_sessions` does, and a
// known root that goes missing for one generation forces an unrelated red
// walk.
use crate::snapshots::sources::codex::counting::version::proven_owner;

const REMOVED_FRESH: &str = "019e5a00-0000-7000-8000-00000000000e";
const REMOVED_OLD: &str = "019e5a00-0000-7000-8000-00000000000f";
const LATER: &str = "2026-10-07T13:00:00Z";
const LATEST: &str = "2026-10-07T14:00:00Z";

struct Homes {
    c: Corpus,
    _removed_home: crate::test_scratch::ScratchDir,
    removed: PathBuf,
    parked: PathBuf,
    flaky: PathBuf,
    absent: PathBuf,
    slots: [(String, String, usize); 2],
}

/// One ordinary page after its accepted checkpoint (the durable store).
struct Step {
    index: ScanIndex,
    scan: SourceScanResult,
    posts: Vec<Vec<u8>>,
    /// Transcript deliveries, `(mode, start)`.
    reads: Vec<(DeliveryMode, u64)>,
    /// This page's Codex RootResolutionUnresolved count.
    unresolved: u64,
}

impl Homes {
    fn new() -> Self {
        let c = Corpus::new();
        c.write(MAIN, Some("a"));
        // Usage on both sides of the mid-session account switch.
        append(
            &c.path(MAIN),
            &(turn(3) + &header(MAIN, Some("switched")) + &turn(4)),
        );
        c.write(OTHER, Some("b"));
        c.write(SIDE, Some("b"));
        c.write(GAP, None);
        let home = c.sessions.parent().unwrap().to_path_buf();
        let flaky = home.join("flaky-root");
        fs::create_dir(&flaky).unwrap();
        let removed_home = crate::test_scratch::ScratchDir::canonical("codex-removed-home");
        let removed_parent = fs::canonicalize(removed_home.as_ref()).unwrap();
        let removed = removed_parent.join("sessions");
        fs::create_dir_all(&removed).unwrap();
        for (id, account) in [(REMOVED_FRESH, "a"), (REMOVED_OLD, "b")] {
            fs::write(
                removed.join(format!("rollout-{id}.jsonl")),
                rollout(id, Some(account)),
            )
            .unwrap();
        }
        Self {
            c,
            _removed_home: removed_home,
            removed,
            parked: removed_parent.join("parked-sessions"),
            flaky,
            absent: home.join("absent-home").join("archived_sessions"),
            slots: named_creator_slots(),
        }
    }
    fn roots(&self, with_removed: bool) -> Vec<PathBuf> {
        let mut roots = vec![
            self.c.sessions.clone(),
            self.c.archived.clone(),
            self.flaky.clone(),
            self.absent.clone(),
        ];
        if with_removed {
            roots.push(self.removed.clone());
        }
        roots
    }
    fn path(&self, id: &str) -> PathBuf {
        self.removed.join(format!("rollout-{id}.jsonl"))
    }
    fn removed_keys(&self) -> BTreeSet<String> {
        [REMOVED_FRESH, REMOVED_OLD]
            .iter()
            .map(|id| local_index_key(&self.path(id)))
            .collect()
    }
    /// Whether every removed entry is still indexed.
    fn removed_indexed(&self, index: &ScanIndex) -> bool {
        self.removed_keys()
            .iter()
            .all(|key| index.files.contains_key(key))
    }
    fn scan(
        &self,
        with_removed: bool,
        index: ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
        limit: usize,
        at: &str,
    ) -> (ScanIndex, SourceScanResult, Delivered, u64, Vec<Value>) {
        page_observed_at(
            &self.roots(with_removed),
            index,
            cache,
            limit,
            &self.slots,
            at,
            |_| {},
        )
    }
    fn step(
        &self,
        with_removed: bool,
        index: ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
        limit: usize,
        at: &str,
    ) -> Step {
        self.step_on(&self.roots(with_removed), index, cache, limit, at, false)
    }
    /// `step` over explicit roots. With `hold`, the header inventory of the
    /// first step that prepares one is forced incomplete, as an unlisted
    /// rollout leaves it, so the page is held.
    fn step_on(
        &self,
        roots: &[PathBuf],
        mut index: ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
        limit: usize,
        at: &str,
        hold: bool,
    ) -> Step {
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let before = index.clone();
        let mut injected = !hold;
        let ((working, scan, delivered, _, logs), events) =
            crate::snapshots::disappearance_diagnostics::observe(|| {
                page_observed_at(roots, index, cache, limit, &self.slots, at, |scan| {
                    if let Some(inventory) =
                        scan.codex_join_inventory.as_mut().filter(|_| !injected)
                    {
                        inventory.complete = false;
                        injected = true;
                    }
                })
            });
        assert!(injected, "an inventory to hold");
        assert_eq!(full_decodes(&logs), 0);
        let (index, posts) = working.checkpoint_with_captured_posts(&scan, &before, "complete");
        let reads = delivered
            .0
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|(mode, _)| *mode != DeliveryMode::Unchanged)
            .collect::<Vec<_>>();
        Step {
            index,
            scan,
            posts,
            reads,
            unresolved: events[SnapshotSource::Codex.slot()][1],
        }
    }
    /// A cold Full of the configured roots, from a fresh index.
    fn cold(&self, with_removed: bool, at: &str) -> SourceScanResult {
        self.scan(with_removed, ScanIndex::default(), Arc::default(), 100, at)
            .1
    }
    fn tail_of(&self, path: &Path) -> (DeliveryMode, u64) {
        let start = fs::metadata(path).unwrap().len();
        append(path, &turn(5));
        (DeliveryMode::Tail, start)
    }
}

/// No Codex counting tombstone is kept.
fn no_tombstones(index: &ScanIndex) -> bool {
    serde_json::to_value(index)
        .unwrap()
        .get("codex_counting_tombstones")
        .is_none()
}

/// No legacy unresolved-root witness is persisted.
fn no_witnesses(index: &ScanIndex) -> bool {
    index.legacy_unresolved_root_file_witnesses.is_empty()
}

/// The generation's walk is kept and red.
fn red(index: &ScanIndex) -> bool {
    index
        .traversal
        .as_ref()
        .is_some_and(|walk| walk.has_errors())
}

fn assert_positive_control(row: &str, accepted: &RouteResult, scan: &SourceScanResult) {
    assert_ne!(
        accepted.snapshots[MAIN]["session_account_evidence"],
        accepted.snapshots[OTHER]["session_account_evidence"],
        "{row}: two accounts; MAIN switched mid-session"
    );
    assert!(
        accepted.snapshots[OTHER]["session_account_evidence"].is_object(),
        "{row}"
    );
    assert!(
        accepted.snapshots[GAP]["session_account_evidence"].is_null(),
        "{row}: evidence gap"
    );
    assert!(accepted.snapshots.contains_key(SIDE), "{row}: side call");
    assert!(
        scan.snapshots
            .iter()
            .flat_map(|item| &item.model_usage)
            .any(|usage| usage.account_identifier_hash.is_some()),
        "{row}: tagged positive control"
    );
}

/// Generation 1: homes A and B read, uploaded, accepted and healthy. Returns
/// the page, its accepted route and its post-ACK ledger route.
fn accepted_generation(
    row: &str,
    h: &Homes,
    prior: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
) -> (Step, RouteResult, RouteResult) {
    let first = h.step(true, prior, cache.clone(), 100, NOW);
    assert!(
        first.scan.census_complete && first.index.traversal.is_none(),
        "{row}"
    );
    assert_eq!(first.unresolved, 0, "{row}");
    let acked = crate::snapshot_sync::codex_transition_acked_route(
        &first.index,
        &first.scan,
        Mode::ColdFull,
    );
    let accepted = route(&first.index, &first.scan, first.posts.clone());
    assert_positive_control(row, &accepted, &first.scan);
    assert_eq!(accepted.accepted.len(), 6, "{row}: every entity accepted");
    for key in h.removed_keys() {
        let entry = &first.index.files[&key];
        assert!(
            !entry.codex_history_is_protected(),
            "{row}: an ordinary entry"
        );
        assert!(entry.last_snapshot_fingerprint.is_some(), "{row}");
    }
    (first, accepted, acked)
}

/// The accepted bodies of `entities`, still carried: each accepted
/// fingerprint is still in the local ledger.
fn carried(
    row: &str,
    index: &ScanIndex,
    accepted: &RouteResult,
    entities: &[&str],
) -> BTreeMap<String, Accepted> {
    entities
        .iter()
        .map(|entity| {
            let fingerprint = accepted.snapshots[*entity]["snapshot_fingerprint"]
                .as_str()
                .unwrap();
            assert!(
                index.accepted_snapshot_fingerprints.contains(fingerprint),
                "{row}: {entity} carried"
            );
            ((*entity).to_owned(), accepted.accepted[*entity].clone())
        })
        .collect()
}

/// `assert_carried_equivalent` for Codex. A carried entity's money is its
/// accepted body, compared field by field there, so the cold side keeps token
/// evidence for the emitted entities only.
fn assert_carried(mut cold: RouteResult, actual: &RouteResult) {
    if let Some(counts) = cold.codex_evidence.get_mut("token_count") {
        let kept = counts
            .as_object()
            .unwrap()
            .iter()
            .filter(|(entity, _)| actual.snapshots.contains_key(entity.as_str()))
            .map(|(entity, value)| (entity.clone(), value.clone()))
            .collect::<serde_json::Map<_, _>>();
        *counts = Value::Object(kept);
    }
    money_oracle::assert_carried_equivalent(&cold, actual);
}

/// A separate restart over the kept roots reads and sends nothing. Returns
/// the store it leaves.
fn assert_quiet_restart(
    row: &str,
    h: &Homes,
    prior: ScanIndex,
    accepted: &BTreeMap<String, Accepted>,
) -> ScanIndex {
    let ((index, scan, delivery, logs), io) = oracle::observe_codex_quiet_with_bytes(|| {
        let (index, scan, delivery, consumed, logs) =
            h.scan(false, prior, Arc::default(), 100, NOW);
        ((index, scan, delivery, logs), consumed)
    });
    assert_eq!(full_decodes(&logs), 0, "{row}");
    assert!(delivery.0.lock().unwrap().is_empty(), "{row}");
    let previous = index.clone();
    let (index, posts) = index.checkpoint_with_captured_posts(&scan, &previous, "complete");
    assert!(posts.is_empty(), "{row}: quiet restart emitted a POST");
    let mut quiet = route(&index, &scan, posts);
    quiet.accepted = accepted.clone();
    quiet.mode = Mode::Restart;
    quiet.io = io;
    money_oracle::assert_quiet_restart_zero_bytes(&quiet);
    index
}

#[derive(Clone, Copy, Debug)]
enum Arm {
    /// The matching retry runs on one warm page.
    Drain,
    /// The process stops between the retry's start page and its
    /// reconciliation page, and resumes in this mode.
    Recover(Mode),
    /// An earlier build left the red store: persisted witnesses for every
    /// removed entry, saved through the committable checkpoint. The retry
    /// then pages, restarting from the durable store between pages.
    Upgrade,
}

struct Drained {
    h: Homes,
    session: StateV2ColdSession,
    gen1: RouteResult,
    gen1_acked: RouteResult,
    bytes: [(&'static str, Vec<u8>); 2],
    index: ScanIndex,
    accepted: BTreeMap<String, Accepted>,
    cache: Arc<sampled_scan::SharedCache>,
}

/// Generations 1-3 of the removed-root row: accepted, then the account's home
/// leaves the roster and is deleted while an unrelated known root is missing
/// (a changed context, red for that root alone), then the matching retry.
fn drain(row: &str, arm: Arm) -> Drained {
    let h = Homes::new();
    let (session, prior) = h.c.publish();
    let mut cache = Arc::new(sampled_scan::SharedCache::default());
    let (first, gen1, gen1_acked) = accepted_generation(row, &h, prior, &cache);
    let removed_keys = h.removed_keys();
    let kept_owners = [MAIN, OTHER, SIDE, GAP]
        .map(|id| local_index_key(&h.c.path(id)))
        .into_iter()
        .map(|key| {
            let owner = proven_owner(&first.index.files[&key]).map(str::to_owned);
            (key, owner)
        })
        .collect::<BTreeMap<_, _>>();
    let removed_fingerprints = removed_keys
        .iter()
        .flat_map(|key| first.index.file_snapshot_fingerprints[key].iter().cloned())
        .collect::<BTreeSet<_>>();
    let bytes = [REMOVED_FRESH, REMOVED_OLD].map(|id| (id, fs::read(h.path(id)).unwrap()));

    fs::remove_dir_all(&h.removed).unwrap();
    fs::remove_dir(&h.flaky).unwrap();
    let second = h.step(false, first.index, cache.clone(), 100, NOW);
    assert_eq!(
        second.unresolved, 1,
        "{row}: the unrelated missing root only"
    );
    assert!(second.posts.is_empty() && second.reads.is_empty(), "{row}");
    let walk = second.index.traversal.as_ref().expect("red walk kept");
    assert!(
        walk.pending_directories.is_empty() && walk.has_errors(),
        "{row}"
    );
    assert!(no_witnesses(&second.index), "{row}");
    assert!(h.removed_indexed(&second.index), "{row}");

    let mut index = second.index;
    fs::create_dir(&h.flaky).unwrap();
    if let Arm::Upgrade = arm {
        index
            .legacy_unresolved_root_file_witnesses
            .extend(removed_keys.iter().cloned());
        let mut committed = index.committable_subset(&index, &BTreeSet::new(), &BTreeMap::new());
        committed.save(session.path()).unwrap();
        index = ScanIndex::load(session.path()).unwrap();
        assert_eq!(
            index.legacy_unresolved_root_file_witnesses, removed_keys,
            "{row}"
        );
        assert!(
            index.traversal_namespace_loss(index.traversal.as_ref().unwrap()),
            "{row}"
        );
        cache = Arc::default();
    }
    retry_due(&mut index);
    // A removed key also carries a kept entity's fingerprint.
    let side_key = local_index_key(&h.c.path(SIDE));
    let shared = index.file_snapshot_fingerprints[&side_key]
        .iter()
        .next()
        .unwrap()
        .clone();
    index
        .file_snapshot_fingerprints
        .get_mut(&local_index_key(&h.path(REMOVED_FRESH)))
        .unwrap()
        .insert(shared.clone());
    // Recovery and the upgrade checkpoint the durable store between the
    // start page and the bounded reconciliation pages.
    let paged = match arm {
        Arm::Recover(mode) => Some(mode),
        Arm::Upgrade => Some(Mode::Restart),
        Arm::Drain => None,
    };
    let grown = if paged.is_some() {
        vec![GAP, MAIN]
    } else {
        vec![GAP]
    };
    let mut tails = grown
        .iter()
        .map(|id| h.tail_of(&h.c.path(id)))
        .collect::<Vec<_>>();
    let limit = if paged.is_some() { 1 } else { 100 };
    let mut steps = vec![h.step(false, index, cache.clone(), limit, NOW)];
    if let Some(mode) = paged {
        let start = &steps[0];
        let walk = start
            .index
            .traversal
            .as_ref()
            .expect("stopped between the start and the reconciliation page");
        assert!(!walk.reconciliation_started, "{row}");
        assert!(no_witnesses(&start.index), "{row}");
        assert!(h.removed_indexed(&start.index), "{row}");
        let (mut index, resumed) = match mode {
            Mode::Restart => (ScanIndex::load(session.path()).unwrap(), Arc::default()),
            Mode::DiskRestore => (ScanIndex::load(session.path()).unwrap(), cache.clone()),
            _ => (start.index.clone(), Arc::default()),
        };
        cache = resumed;
        for _ in 0..8 {
            let next = h.step(false, index, cache.clone(), limit, NOW);
            let done = next.index.traversal.is_none();
            index = next.index.clone();
            steps.push(next);
            if done {
                break;
            }
        }
    }

    assert_eq!(
        steps.iter().map(|step| step.unresolved).sum::<u64>(),
        0,
        "{row}"
    );
    let last = steps.last().unwrap();
    let index = &last.index;
    assert!(
        last.scan.census_complete && index.traversal.is_none(),
        "{row}: healthy"
    );
    assert!(no_witnesses(index), "{row}");
    for key in &removed_keys {
        assert!(!index.files.contains_key(key), "{row}: retired");
        assert!(index.file_snapshot_fingerprints.get(key).is_none(), "{row}");
    }
    assert!(no_tombstones(index), "{row}: counting history is retired");
    for (key, owner) in &kept_owners {
        assert_eq!(
            &proven_owner(&index.files[key]).map(str::to_owned),
            owner,
            "{row}: moved-evidence folding and the sidecar census leave kept owners"
        );
    }
    // Local pruning only: the removed entries' own fingerprints leave the
    // ledger, a fingerprint a kept entry shares stays, and every remaining
    // incidence keeps its acceptance. Nothing reaches the destination.
    let removed_only = removed_fingerprints
        .iter()
        .filter(|fingerprint| **fingerprint != shared)
        .collect::<Vec<_>>();
    assert!(!removed_only.is_empty(), "{row}");
    assert!(
        removed_only.iter().all(|fingerprint| !index
            .accepted_snapshot_fingerprints
            .contains(fingerprint.as_str())),
        "{row}"
    );
    assert!(
        index.accepted_snapshot_fingerprints.contains(&shared),
        "{row}"
    );
    for fingerprint in index
        .file_snapshot_fingerprints
        .values()
        .flatten()
        .chain(index.accepted_rebuild_incidence.values().flatten())
    {
        assert!(
            index.accepted_snapshot_fingerprints.contains(fingerprint),
            "{row}"
        );
    }
    let emitted_ids = steps
        .iter()
        .flat_map(|step| &step.scan.snapshots)
        .map(|item| item.source_session_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        emitted_ids,
        grown
            .iter()
            .map(|id| id.to_string())
            .collect::<BTreeSet<_>>(),
        "{row}: removed entities send nothing; unchanged kept entities no new body"
    );
    let mut reads = steps
        .iter()
        .flat_map(|step| step.reads.iter().copied())
        .collect::<Vec<_>>();
    reads.sort_by_key(|(_, start)| *start);
    tails.sort_by_key(|(_, start)| *start);
    assert_eq!(reads, tails, "{row}: one Tail per grown file; no re-read");

    let cold = h.cold(false, NOW);
    let mut accepted = gen1.accepted.clone();
    for step in &steps {
        if step.scan.snapshots.is_empty() {
            continue;
        }
        let mut cold_page = cold.clone();
        cold_page.snapshots.retain(|item| {
            step.scan
                .snapshots
                .iter()
                .any(|actual| actual.source_session_id == item.source_session_id)
        });
        let mut actual = route(&step.index, &step.scan, step.posts.clone());
        if let Some(mode) = paged {
            actual.mode = mode;
        }
        money_oracle::assert_equivalent(&emitted(&step.index, &cold_page), &actual);
        accepted.extend(actual.accepted.clone());
    }
    if let [step] = steps.as_slice() {
        let mut actual = route(&step.index, &step.scan, step.posts.clone());
        actual
            .accepted
            .extend(carried(row, &step.index, &gen1, &[MAIN, OTHER, SIDE]));
        assert_carried(emitted(&step.index, &cold), &actual);
    }
    let index = steps.pop().unwrap().index;
    Drained {
        h,
        session,
        gen1,
        gen1_acked,
        bytes,
        index,
        accepted,
        cache,
    }
}

/// [money] A removed and deleted account home stops keeping generations red,
/// whatever happens between the matching retry's pages. Every row's witnesses
/// drain at the first matching retry, which counts no
/// RootResolutionUnresolved, ends healthy and retires the removed entries
/// through the ordinary guarded reconciliation: tombstones under their proven
/// owners, local ledger pruning only, no body and no read. Each page's money
/// equals a cold Full, and a separate quiet restart then reads and sends
/// nothing.
/// - "O1 drain": one warm page. The kept home's money stays equal to a cold
///   Full, and a genuinely truncated kept file never re-emits smaller money.
/// - "O4 restart" / "O4 disk restore" / "O4 evicted cache": a restart, a
///   durable restore or an evicted cache between the start page and its
///   reconciliation page resumes without re-inference and retires exactly as
///   one warm page does.
/// - "O5 upgrade": the red store an earlier build left (persisted witnesses
///   for every removed entry after a finished red matching retry), saved and
///   loaded through the committable checkpoint, drains on the new build's
///   first matching retry and retires across bounded reconciliation pages,
///   each one restarted from the durable store, with no re-read.
#[test]
fn removed_account_root_drains_and_retires_on_every_resume_path() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (row, arm) in [
        ("O1 drain", Arm::Drain),
        ("O4 restart", Arm::Recover(Mode::Restart)),
        ("O4 disk restore", Arm::Recover(Mode::DiskRestore)),
        ("O4 evicted cache", Arm::Recover(Mode::EvictRetry)),
        ("O5 upgrade", Arm::Upgrade),
    ] {
        let d = drain(row, arm);
        let index = assert_quiet_restart(
            row,
            &d.h,
            ScanIndex::load(d.session.path()).unwrap(),
            &d.accepted,
        );
        if !matches!(arm, Arm::Drain) {
            continue;
        }
        let other = d.h.c.path(OTHER);
        let key = local_index_key(&other);
        let before = index.clone();
        // Genuinely behind: a smaller rewrite whose usage no longer parses. A
        // well-formed shorter file is a legitimate correction, not a
        // regression.
        let unreadable = json!({"type":"event_msg", "timestamp":"2026-10-07T10:00:00Z",
            "payload":{"type":"token_count", "info":{"total_token_usage":{"input_tokens":"invalid"}}}});
        fs::write(
            &other,
            header(OTHER, Some("b")) + &unreadable.to_string() + "\n",
        )
        .unwrap();
        assert!(
            fs::metadata(&other).unwrap().len() < before.files[&key].size_bytes,
            "{row}: behind its accepted witness"
        );
        let behind = d.h.step(false, index, d.cache.clone(), 100, LATER);
        assert!(behind.scan.snapshots.is_empty(), "{row}: no smaller body");
        assert_eq!(
            behind.index.files[&key].last_upload_body_witness,
            before.files[&key].last_upload_body_witness,
            "{row}"
        );
        let mut cold = d.h.cold(false, LATER);
        cold.snapshots
            .retain(|item| item.source_session_id == OTHER);
        let mut held = emitted(&behind.index, &behind.scan);
        held.accepted = d.accepted.clone();
        money_oracle::assert_no_smaller_reemit(
            OTHER,
            &d.gen1,
            &held,
            &emitted(&behind.index, &cold),
            true,
        );
    }
}

/// The restored file is a new object read in a later pass: its file
/// fingerprint, the revision hashes derived from it and the pass time differ
/// from the original upload's. Every other stored-body field (money,
/// identity, placement) must not; a cold Full of the restored file pins these.
fn without_file_revision(mut route: RouteResult) -> RouteResult {
    let buckets = route
        .accepted_identity_buckets
        .as_mut()
        .and_then(Value::as_object_mut)
        .expect("post-ACK buckets");
    for bucket in buckets.values_mut() {
        let body = bucket["stored_body"].as_object_mut().unwrap();
        body.remove("source_file_fingerprint");
        body.remove("collected_at");
        let envelope = body["semantic_envelope"].as_object_mut().unwrap();
        envelope.remove("revision_v2_hash");
    }
    route
}

/// [money] O6b: the same path restored after retirement, while its
/// state is freshly retired and after a later complete generation. Only the
/// in-window file is read, once; its body keeps its destination key and
/// replaces one head with the original accepted totals and placement, and
/// equals a cold V2 Full. Every restored file starts with V2.
#[test]
fn removed_account_readded_after_retirement_counts_once() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (row, collected) in [
        ("O6b tombstones kept", false),
        ("O6b tombstones collected", true),
    ] {
        let d = drain(row, Arm::Drain);
        let mut index = d.index;
        let mut at = NOW;
        if collected {
            let later = d.h.step(false, index, d.cache.clone(), 100, LATER);
            assert!(later.posts.is_empty() && later.reads.is_empty(), "{row}");
            assert!(later.index.traversal.is_none(), "{row}");
            assert!(
                no_tombstones(&later.index),
                "{row}: a later complete generation collects absent owners"
            );
            index = later.index;
            at = LATEST;
        } else {
            assert!(no_tombstones(&index));
        }
        // Aged files are never first reads. A head that absence kept (its
        // debt never clears by absence) is the noted exception: read once.
        let mut read = vec![REMOVED_FRESH];
        if !matches!(
            state_v2::load_head(&index, &local_index_key(&d.h.path(REMOVED_OLD)), u32::MAX),
            Ok(None)
        ) {
            read.push(REMOVED_OLD);
        }
        fs::create_dir_all(&d.h.removed).unwrap();
        for (id, bytes) in &d.bytes {
            fs::write(d.h.path(id), bytes).unwrap();
        }
        aged_mtime(&d.h.path(REMOVED_OLD));
        let readded = d.h.step(true, index, d.cache.clone(), 100, at);
        assert_eq!(
            readded.reads,
            vec![(DeliveryMode::Full, 0); read.len()],
            "{row}: only {read:?} read, once each"
        );
        let emitted = readded
            .scan
            .snapshots
            .iter()
            .map(|item| item.source_session_id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(
            emitted.contains(REMOVED_FRESH) && emitted.iter().all(|id| read.contains(id)),
            "{row}: emitted {emitted:?}, read {read:?}"
        );
        assert!(readded.index.traversal.is_none(), "{row}: healthy");
        assert!(
            readded.index.files[&local_index_key(&d.h.path(REMOVED_FRESH))].codex_counting_v2,
            "{row}: a restored file uses V2"
        );
        let replay = crate::snapshot_sync::codex_transition_acked_route(
            &readded.index,
            &readded.scan,
            Mode::Ram,
        );
        let mut original = d.gen1_acked.clone();
        original
            .snapshots
            .retain(|id, _| emitted.contains(id.as_str()));
        assert!(original.accepted_identity_buckets.is_some(), "{row}");
        assert!(replay.accepted_identity_buckets.is_some(), "{row}");
        money_oracle::assert_placement_equivalent(
            &without_file_revision(original),
            &without_file_revision(replay.clone()),
        );
        let mut destination = d.gen1.snapshots.clone();
        destination.extend(replay.snapshots.clone());
        assert_eq!(
            destination.len(),
            d.gen1.snapshots.len(),
            "{row}: stable keys: one latest head per entity"
        );
        for (id, field) in emitted
            .iter()
            .flat_map(|id| money_oracle::FIELDS.iter().map(move |f| (*id, *f)))
        {
            assert_eq!(
                destination[id][field], d.gen1.snapshots[id][field],
                "{row}: {id} {field}: the original accepted total, never a sum"
            );
        }
        let mut cold = d.h.cold(true, at);
        cold.snapshots
            .retain(|item| item.source_session_id == REMOVED_FRESH);
        // A cold Full never reads the aged file; it compares the in-window one.
        let mut fresh = readded.scan.clone();
        fresh
            .snapshots
            .retain(|item| item.source_session_id == REMOVED_FRESH);
        money_oracle::assert_equivalent(
            &crate::snapshot_sync::codex_transition_acked_route(
                &readded.index,
                &cold,
                Mode::ColdFull,
            ),
            &crate::snapshot_sync::codex_transition_acked_route(&readded.index, &fresh, Mode::Ram),
        );
    }
}

/// [money] Without proof of removal the generation stays red and nothing
/// retires; once the roster is restored, the removed home's unchanged files
/// Skip with no first read and no re-read, and money equals a cold Full.
/// - "O2 configured missing": a configured root that is missing (unmounted)
///   keeps today's red: one RootResolutionUnresolved, its keys never
///   witnesses, its entities held with their accepted bodies.
/// - "O3 present unconfigured": the roster drops a home whose folder is still
///   present: no proof, so its entries stay witnesses and the retry stays red.
/// - "O6a re-added before retirement": the home re-added (and its folder
///   back) before any healthy generation reconciled: its unchanged files
///   Skip, with no read and no body.
#[test]
fn unproven_root_removal_stays_red_and_restored_files_skip() {
    const O2: &str = "O2 configured missing";
    const O3: &str = "O3 present unconfigured";
    const O6A: &str = "O6a re-added before retirement";
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for row in [O2, O3, O6A] {
        let h = Homes::new();
        let (_session, prior) = h.c.publish();
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (first, gen1, _) = accepted_generation(row, &h, prior, &cache);
        let witnesses = |index: &ScanIndex| {
            h.removed_keys()
                .iter()
                .map(|key| index.files[key].last_upload_body_witness.clone())
                .collect::<Vec<_>>()
        };
        let accepted_witnesses = witnesses(&first.index);
        // The red generations, ending with the roster restored. Returns the
        // red store, the kept file the restored generation grows and, for O2,
        // the route that accepted GAP's grown body.
        let (index, grows, grown) = match row {
            O2 => {
                fs::rename(&h.removed, &h.parked).unwrap();
                let tail = h.tail_of(&h.c.path(GAP));
                let second = h.step(true, first.index, cache.clone(), 100, NOW);
                assert_eq!(second.unresolved, 1, "{row}: the configured missing root");
                assert!(no_witnesses(&second.index), "{row}");
                assert!(red(&second.index), "{row}");
                assert!(h.removed_indexed(&second.index), "{row}");
                assert!(no_tombstones(&second.index), "{row}");
                assert_eq!(second.reads, vec![tail], "{row}");
                let mut cold = h.cold(true, NOW);
                cold.snapshots.retain(|item| item.source_session_id == GAP);
                let cold = emitted(&second.index, &cold);
                let grown = route(&second.index, &second.scan, second.posts.clone());
                let mut held = grown.clone();
                held.accepted.extend(carried(
                    row,
                    &second.index,
                    &gen1,
                    &[REMOVED_FRESH, REMOVED_OLD],
                ));
                for id in [REMOVED_FRESH, REMOVED_OLD] {
                    money_oracle::assert_held(id, &gen1, &held, &cold);
                }
                fs::rename(&h.parked, &h.removed).unwrap();
                let mut index = second.index;
                retry_due(&mut index);
                (index, MAIN, Some(grown))
            }
            O3 => {
                fs::remove_dir(&h.flaky).unwrap();
                let second = h.step(false, first.index, cache.clone(), 100, NOW);
                assert_eq!(second.unresolved, 1, "{row}");
                let mut index = second.index;
                fs::create_dir(&h.flaky).unwrap();
                retry_due(&mut index);
                let third = h.step(false, index, cache.clone(), 100, NOW);
                assert_eq!(
                    third.unresolved, 1,
                    "{row}: a present home is no proof of removal"
                );
                assert_eq!(
                    third.index.legacy_unresolved_root_file_witnesses,
                    h.removed_keys(),
                    "{row}"
                );
                assert!(red(&third.index), "{row}");
                assert!(h.removed_indexed(&third.index), "{row}");
                assert!(no_tombstones(&third.index), "{row}");
                assert!(third.posts.is_empty() && third.reads.is_empty(), "{row}");
                (third.index, GAP, None)
            }
            O6A => {
                fs::rename(&h.removed, &h.parked).unwrap();
                fs::remove_dir(&h.flaky).unwrap();
                let second = h.step(false, first.index, cache.clone(), 100, NOW);
                assert_eq!(second.unresolved, 1, "{row}");
                assert!(red(&second.index), "{row}");
                fs::rename(&h.parked, &h.removed).unwrap();
                fs::create_dir(&h.flaky).unwrap();
                (second.index, GAP, None)
            }
            other => unreachable!("{other}"),
        };
        let tail = h.tail_of(&h.c.path(grows));
        let back = h.step(true, index, cache.clone(), 100, NOW);
        assert_eq!(back.unresolved, 0, "{row}");
        assert_eq!(
            back.reads,
            vec![tail],
            "{row}: the restored roster's files Skip: no first read, no re-read"
        );
        assert!(
            back.scan.census_complete && back.index.traversal.is_none(),
            "{row}"
        );
        if row == O3 {
            assert!(no_witnesses(&back.index), "{row}");
        }
        if row == O6A {
            assert_eq!(witnesses(&back.index), accepted_witnesses, "{row}");
        }
        assert!(no_tombstones(&back.index), "{row}");
        let mut actual = route(&back.index, &back.scan, back.posts.clone());
        if row == O6A {
            assert_eq!(
                actual
                    .snapshots
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec![GAP],
                "{row}"
            );
        }
        let mut from_gen1 = vec![MAIN, OTHER, SIDE, REMOVED_FRESH, REMOVED_OLD];
        if let Some(grown) = &grown {
            actual
                .accepted
                .extend(carried(row, &back.index, grown, &[GAP]));
            from_gen1.retain(|id| *id != grows);
        }
        actual
            .accepted
            .extend(carried(row, &back.index, &gen1, &from_gen1));
        assert_carried(emitted(&back.index, &h.cold(true, NOW)), &actual);
    }
}

/// [money] C1: the removed root's witnesses drain at the matching start while
/// an incomplete header inventory holds that page. While the hold is owed the
/// generation stays red, reconciliation never starts, nothing settles and the
/// removed entries stay indexed; the held session keeps its accepted body.
/// The release catches it up cold-equal, leaves the generation healthy and
/// retires the removed entries through tombstones. A symlinked removed root
/// (canonical keys stay witnesses) and a configured missing root
/// keep the generation red after the release.
#[test]
fn removed_root_drain_waits_for_the_inventory_hold() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let held_by_inventory = |index: &ScanIndex| inventory_hold_of(index).is_some();
    for arm in ["removed", "symlinked", "configured-missing"] {
        let h = Homes::new();
        let link = h.c.sessions.parent().unwrap().join("linked-sessions");
        let configured = if arm == "symlinked" {
            std::os::unix::fs::symlink(&h.removed, &link).unwrap();
            link.clone()
        } else {
            h.removed.clone()
        };
        let without = h.roots(false);
        let mut with = without.clone();
        with.push(configured);
        let (_session, prior) = h.c.publish();
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let first = h.step_on(&with, prior, cache.clone(), 100, NOW, false);
        assert!(
            first.scan.census_complete && first.index.traversal.is_none(),
            "{arm}"
        );
        let gen1 = route(&first.index, &first.scan, first.posts.clone());
        assert_positive_control(arm, &gen1, &first.scan);
        let removed_keys = h.removed_keys();
        assert!(
            h.removed_indexed(&first.index),
            "{arm}: keys under the canonical root"
        );
        let roots = if arm == "configured-missing" {
            fs::rename(&h.removed, &h.parked).unwrap();
            &with
        } else {
            fs::remove_dir_all(&h.removed).unwrap();
            if arm == "symlinked" {
                fs::remove_file(&link).unwrap();
            }
            &without
        };
        fs::remove_dir(&h.flaky).unwrap();
        let second = h.step_on(roots, first.index, cache.clone(), 100, NOW, false);
        assert!(
            second
                .index
                .traversal
                .as_ref()
                .is_some_and(|walk| walk.has_retryable_problems()),
            "{arm}"
        );

        let mut index = second.index;
        fs::create_dir(&h.flaky).unwrap();
        retry_due(&mut index);
        let gap = local_index_key(&h.c.path(GAP));
        let accepted_witness = index.files[&gap].last_upload_body_witness.clone();
        let tail = h.tail_of(&h.c.path(GAP));
        let mut cold = page_observed_at(
            &without,
            ScanIndex::default(),
            Arc::default(),
            100,
            &h.slots,
            NOW,
            |_| {},
        )
        .1;
        cold.snapshots.retain(|item| item.source_session_id == GAP);
        let held = h.step_on(roots, index, cache.clone(), 100, NOW, true);
        assert_eq!(held.unresolved, u64::from(arm != "removed"), "{arm}");
        if arm == "removed" {
            assert!(no_witnesses(&held.index), "{arm}");
        }
        let walk = held.index.traversal.as_ref().expect("the held generation");
        assert!(held_by_inventory(&held.index), "{arm}: the page is held");
        assert!(
            walk.has_retryable_problems(),
            "{arm}: red while the hold is owed"
        );
        assert!(!walk.reconciliation_started, "{arm}: no reconciliation");
        assert!(
            held.scan.snapshots.is_empty() && held.posts.is_empty() && held.reads.is_empty(),
            "{arm}"
        );
        assert!(h.removed_indexed(&held.index), "{arm}");
        assert!(no_tombstones(&held.index), "{arm}");
        assert_eq!(
            held.index.files[&gap].last_upload_body_witness, accepted_witness,
            "{arm}"
        );
        let mut held_route = emitted(&held.index, &held.scan);
        held_route.accepted = gen1.accepted.clone();
        money_oracle::assert_held(GAP, &gen1, &held_route, &emitted(&held.index, &cold));

        let mut index = held.index;
        let mut released = Vec::new();
        for _ in 0..8 {
            let next = h.step_on(roots, index, cache.clone(), 100, NOW, false);
            let done = next.index.traversal.as_ref().map_or(true, |walk| {
                !held_by_inventory(&next.index) && walk.has_retryable_problems()
            });
            index = next.index.clone();
            released.push(next);
            if done {
                break;
            }
        }
        assert!(!held_by_inventory(&index), "{arm}: released");
        assert_eq!(
            released
                .iter()
                .flat_map(|step| &step.scan.snapshots)
                .map(|item| item.source_session_id.as_str())
                .collect::<Vec<_>>(),
            vec![GAP],
            "{arm}: the held session catches up once"
        );
        assert_eq!(
            released
                .iter()
                .flat_map(|step| step.reads.iter().copied())
                .collect::<Vec<_>>(),
            vec![tail],
            "{arm}"
        );
        for step in released
            .iter()
            .filter(|step| !step.scan.snapshots.is_empty())
        {
            money_oracle::assert_equivalent(
                &emitted(&step.index, &cold),
                &route(&step.index, &step.scan, step.posts.clone()),
            );
        }
        if arm == "removed" {
            assert_eq!(
                released.iter().map(|step| step.unresolved).sum::<u64>(),
                0,
                "{arm}"
            );
            assert!(index.traversal.is_none(), "{arm}: green after the release");
            assert!(
                removed_keys
                    .iter()
                    .all(|key| !index.files.contains_key(key)),
                "{arm}"
            );
            assert!(no_tombstones(&index));
        } else {
            let walk = index.traversal.as_ref().expect("still red");
            assert!(
                walk.has_retryable_problems(),
                "{arm}: red after the release"
            );
            assert!(h.removed_indexed(&index), "{arm}");
            assert!(no_tombstones(&index), "{arm}");
        }
    }
}

/// The census and deletion rows above, every page flagged as a first-import
/// page: drain, restart, disk restore, evicted cache and upgrade; the
/// unproven removal that stays red; and the drain behind an inventory hold
/// keep their census, retirement and ACK results at the larger page total.
#[test]
fn removed_root_rows_hold_at_the_first_import_page_total() {
    with_first_import_pages(|| {
        removed_account_root_drains_and_retires_on_every_resume_path();
        unproven_root_removal_stays_red_and_restored_files_skip();
        removed_root_drain_waits_for_the_inventory_hold();
    });
}
