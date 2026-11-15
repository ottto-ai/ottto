// Extends the native archive/transition fixture and stored-body ACK driver.
// A Codex account home removed from the roster, with its tree deleted, must
// not keep scan generations red. Kept home A is the `Corpus` (two accounts,
// a mid-session switch, a side call, an evidence gap and tagged rows);
// removed home B holds two more sessions. An absent optional root enables
// legacy witness inference, as an absent `archived_sessions` does, and a
// known root that goes missing for one generation forces an unrelated red
// walk.
use crate::snapshots::codex_counting_version::{proven_owner, AckEvidence};

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
        append(&c.path(MAIN), &(turn(3) + &header(MAIN, Some("switched"))));
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
        let hash = |kind: &str, account: &str| {
            let value = if kind == "account" {
                "user"
            } else {
                "workspace"
            };
            ottto_core::billing_identity_hash(
                "openai",
                kind,
                &format!("synthetic-{value}-{account}"),
            )
            .unwrap()
        };
        let slots = ["a", "b"].map(|account| {
            (
                hash("account", account),
                hash("workspace", account),
                crate::codex_scan_diagnostics::CREATOR_NAMED,
            )
        });
        Self {
            c,
            _removed_home: removed_home,
            removed,
            parked: removed_parent.join("parked-sessions"),
            flaky,
            absent: home.join("absent-home").join("archived_sessions"),
            slots,
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
        mut index: ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
        limit: usize,
        at: &str,
    ) -> Step {
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let before = index.clone();
        let ((working, scan, delivered, _, logs), events) =
            crate::snapshots::disappearance_diagnostics::observe(|| {
                self.scan(with_removed, index, cache, limit, at)
            });
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
        append(path, &turn(4));
        (DeliveryMode::Tail, start)
    }
}

fn assert_positive_control(accepted: &RouteResult, scan: &SourceScanResult) {
    assert_ne!(
        accepted.snapshots[MAIN]["session_account_evidence"],
        accepted.snapshots[OTHER]["session_account_evidence"],
        "two accounts; MAIN switched mid-session"
    );
    assert!(accepted.snapshots[OTHER]["session_account_evidence"].is_object());
    assert!(
        accepted.snapshots[GAP]["session_account_evidence"].is_null(),
        "evidence gap"
    );
    assert!(accepted.snapshots.contains_key(SIDE), "side call");
    assert!(
        scan.snapshots
            .iter()
            .flat_map(|item| &item.model_usage)
            .any(|row| row.account_identifier_hash.is_some()),
        "tagged positive control"
    );
}

/// Generation 1: homes A and B read, uploaded, accepted and healthy. Returns
/// the page, its accepted route and its post-ACK ledger route.
fn accepted_generation(
    h: &Homes,
    prior: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
) -> (Step, RouteResult, RouteResult) {
    let first = h.step(true, prior, cache.clone(), 100, NOW);
    assert!(first.scan.census_complete && first.index.traversal.is_none());
    assert_eq!(first.unresolved, 0);
    let acked = crate::snapshot_sync::codex_transition_acked_route(
        &first.index,
        &first.scan,
        Mode::ColdFull,
    );
    let accepted = route(&first.index, &first.scan, first.posts.clone());
    assert_positive_control(&accepted, &first.scan);
    assert_eq!(accepted.accepted.len(), 6, "every entity accepted");
    for key in h.removed_keys() {
        let entry = &first.index.files[&key];
        assert!(!entry.codex_history_is_protected(), "an ordinary entry");
        assert_ne!(AckEvidence::of_view(Some(entry)), AckEvidence::None);
    }
    (first, accepted, acked)
}

/// The accepted bodies of `entities`, still carried: each accepted
/// fingerprint is still in the local ledger.
fn carried(
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
                "{entity} carried"
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
    h: &Homes,
    prior: ScanIndex,
    accepted: &BTreeMap<String, Accepted>,
) -> ScanIndex {
    let ((index, scan, delivery, logs), io) = oracle::observe_codex_quiet_with_bytes(|| {
        let (index, scan, delivery, consumed, logs) =
            h.scan(false, prior, Arc::default(), 100, NOW);
        ((index, scan, delivery, logs), consumed)
    });
    assert_eq!(full_decodes(&logs), 0);
    assert!(delivery.0.lock().unwrap().is_empty());
    let previous = index.clone();
    let (index, posts) = index.checkpoint_with_captured_posts(&scan, &previous, "complete");
    assert!(posts.is_empty(), "quiet restart emitted a POST");
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
    /// removed entry, saved through the committable checkpoint.
    Upgrade,
}

struct Drained {
    h: Homes,
    session: StateV2ColdSession,
    gen1: RouteResult,
    gen1_acked: RouteResult,
    owners: BTreeMap<&'static str, String>,
    bytes: [(&'static str, Vec<u8>); 2],
    index: ScanIndex,
    accepted: BTreeMap<String, Accepted>,
    cache: Arc<sampled_scan::SharedCache>,
}

/// Generations 1-3 of the removed-root row: accepted, then the account's home
/// leaves the roster and is deleted while an unrelated known root is missing
/// (a changed context, red for that root alone), then the matching retry.
fn drain(arm: Arm) -> Drained {
    let h = Homes::new();
    let (session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &h.c.scratch.join("state"),
    );
    let mut cache = Arc::new(sampled_scan::SharedCache::default());
    let (first, gen1, gen1_acked) = accepted_generation(&h, prior, &cache);
    let removed_keys = h.removed_keys();
    let owners = [REMOVED_FRESH, REMOVED_OLD]
        .into_iter()
        .map(|id| {
            let entry = &first.index.files[&local_index_key(&h.path(id))];
            let owner = proven_owner(entry).map_or_else(
                || crate::snapshots::codex_protected_owner(id),
                str::to_owned,
            );
            (id, owner)
        })
        .collect::<BTreeMap<_, _>>();
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
    assert_eq!(second.unresolved, 1, "the unrelated missing root only");
    assert!(second.posts.is_empty() && second.reads.is_empty());
    let walk = second.index.traversal.as_ref().expect("red walk kept");
    assert!(walk.pending_directories.is_empty() && walk.counts.has_errors());
    assert!(second
        .index
        .legacy_unresolved_root_file_witnesses
        .is_empty());
    assert!(removed_keys
        .iter()
        .all(|key| second.index.files.contains_key(key)));

    let mut index = second.index;
    fs::create_dir(&h.flaky).unwrap();
    if let Arm::Upgrade = arm {
        index
            .legacy_unresolved_root_file_witnesses
            .extend(removed_keys.iter().cloned());
        let mut committed = index.committable_subset(&index, &BTreeSet::new(), &BTreeMap::new());
        committed.save(session.path()).unwrap();
        index = ScanIndex::load(session.path()).unwrap();
        assert_eq!(index.legacy_unresolved_root_file_witnesses, removed_keys);
        assert!(index.traversal_namespace_loss(index.traversal.as_ref().unwrap()));
        cache = Arc::default();
    }
    index
        .traversal
        .as_mut()
        .unwrap()
        .unhealthy_retry_not_before_unix_seconds = Some(0);
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
    let grown = match arm {
        Arm::Recover(_) => vec![GAP, MAIN],
        _ => vec![GAP],
    };
    let mut tails = grown
        .iter()
        .map(|id| h.tail_of(&h.c.path(id)))
        .collect::<Vec<_>>();
    let limit = if matches!(arm, Arm::Recover(_)) {
        1
    } else {
        100
    };
    let mut steps = vec![h.step(false, index, cache.clone(), limit, NOW)];
    if let Arm::Recover(mode) = arm {
        let start = &steps[0];
        let walk = start
            .index
            .traversal
            .as_ref()
            .expect("stopped between the start and the reconciliation page");
        assert!(!walk.reconciliation_started);
        assert!(start.index.legacy_unresolved_root_file_witnesses.is_empty());
        assert!(removed_keys
            .iter()
            .all(|key| start.index.files.contains_key(key)));
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

    assert_eq!(steps.iter().map(|step| step.unresolved).sum::<u64>(), 0);
    let last = steps.last().unwrap();
    let index = &last.index;
    assert!(
        last.scan.census_complete && index.traversal.is_none(),
        "healthy"
    );
    assert!(index.legacy_unresolved_root_file_witnesses.is_empty());
    for key in &removed_keys {
        assert!(!index.files.contains_key(key), "retired");
        assert!(index.file_snapshot_fingerprints.get(key).is_none());
    }
    assert_eq!(
        index
            .codex_counting_tombstones
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        owners.values().cloned().collect::<BTreeSet<_>>(),
        "tombstones under the removed entries' proven owners only"
    );
    assert!(
        index
            .codex_counting_tombstones
            .values()
            .all(|tombstone| tombstone.retired_in == NOW),
        "same-generation tombstones kept"
    );
    for (key, owner) in &kept_owners {
        assert_eq!(
            &proven_owner(&index.files[key]).map(str::to_owned),
            owner,
            "moved-evidence folding and the sidecar census leave kept owners"
        );
    }
    // Local pruning only: the removed entries' own fingerprints leave the
    // ledger, a fingerprint a kept entry shares stays, and every remaining
    // incidence keeps its acceptance. Nothing reaches the destination.
    let removed_only = removed_fingerprints
        .iter()
        .filter(|fingerprint| **fingerprint != shared)
        .collect::<Vec<_>>();
    assert!(!removed_only.is_empty());
    assert!(removed_only.iter().all(|fingerprint| !index
        .accepted_snapshot_fingerprints
        .contains(fingerprint.as_str())));
    assert!(index.accepted_snapshot_fingerprints.contains(&shared));
    for fingerprint in index
        .file_snapshot_fingerprints
        .values()
        .flatten()
        .chain(index.accepted_rebuild_incidence.values().flatten())
    {
        assert!(index.accepted_snapshot_fingerprints.contains(fingerprint));
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
        "removed entities send nothing; unchanged kept entities no new body"
    );
    let mut reads = steps
        .iter()
        .flat_map(|step| step.reads.iter().copied())
        .collect::<Vec<_>>();
    reads.sort_by_key(|(_, start)| *start);
    tails.sort_by_key(|(_, start)| *start);
    assert_eq!(reads, tails, "one Tail per grown file; no re-read");

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
        if let Arm::Recover(mode) = arm {
            actual.mode = mode;
        }
        money_oracle::assert_equivalent(&emitted(&step.index, &cold_page), &actual);
        accepted.extend(actual.accepted.clone());
    }
    if let [step] = steps.as_slice() {
        let mut actual = route(&step.index, &step.scan, step.posts.clone());
        actual
            .accepted
            .extend(carried(&step.index, &gen1, &[MAIN, OTHER, SIDE]));
        assert_carried(emitted(&step.index, &cold), &actual);
    }
    let index = steps.pop().unwrap().index;
    Drained {
        h,
        session,
        gen1,
        gen1_acked,
        owners,
        bytes,
        index,
        accepted,
        cache,
    }
}

/// [money] O1: a removed and deleted account home stops keeping generations
/// red. Its persisted witnesses drain at the first matching retry, which
/// counts no RootResolutionUnresolved, ends healthy and retires the removed
/// entries through the ordinary guarded reconciliation: tombstones under
/// their proven owners, local ledger pruning only, no body and no read. The
/// kept home's money stays equal to a cold Full, and a genuinely truncated
/// kept file never re-emits smaller money.
#[test]
fn removed_account_root_drains_and_retires() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let d = drain(Arm::Drain);
    let index = assert_quiet_restart(
        &d.h,
        ScanIndex::load(d.session.path()).unwrap(),
        &d.accepted,
    );

    let other = d.h.c.path(OTHER);
    let key = local_index_key(&other);
    let before = index.clone();
    // Genuinely behind: a smaller rewrite whose usage no longer parses. A
    // well-formed shorter file is a legitimate correction, not a regression.
    let unreadable = json!({"type":"event_msg", "timestamp":"2026-10-07T10:00:00Z",
        "payload":{"type":"token_count", "info":{"total_token_usage":{"input_tokens":"invalid"}}}});
    fs::write(
        &other,
        header(OTHER, Some("b")) + &unreadable.to_string() + "\n",
    )
    .unwrap();
    assert!(
        fs::metadata(&other).unwrap().len() < before.files[&key].size_bytes,
        "behind its accepted witness"
    );
    let behind = d.h.step(false, index, d.cache.clone(), 100, LATER);
    assert!(behind.scan.snapshots.is_empty(), "no smaller body");
    assert_eq!(
        behind.index.files[&key].last_upload_body_witness,
        before.files[&key].last_upload_body_witness
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

/// [money] O4: a restart, a durable restore or an evicted cache between the
/// matching retry's start page and its reconciliation page resumes without
/// re-inference and retires exactly as one warm page does; each page's money
/// equals a cold Full. A separate quiet restart then reads and sends nothing.
#[test]
fn removed_account_root_recovers_between_pages() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for mode in [Mode::Restart, Mode::DiskRestore, Mode::EvictRetry] {
        let d = drain(Arm::Recover(mode));
        assert_quiet_restart(
            &d.h,
            ScanIndex::load(d.session.path()).unwrap(),
            &d.accepted,
        );
    }
}

/// [money] O5: the red store an earlier build left (persisted witnesses for
/// every removed entry after a finished red matching retry), saved and loaded
/// through the committable checkpoint, drains and retires on the new build's
/// first matching retry, with no re-read.
#[test]
fn upgraded_removed_root_witnesses_drain_and_retire() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let d = drain(Arm::Upgrade);
    assert_quiet_restart(
        &d.h,
        ScanIndex::load(d.session.path()).unwrap(),
        &d.accepted,
    );
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
        envelope.remove("revision_hash");
        envelope.remove("revision_v2_hash");
    }
    route
}

/// [money] O6b: the same path restored after retirement, while its
/// tombstones survive and after a later generation collected them. Only the
/// in-window file is read, once; its body keeps its destination key and
/// replaces one head with the original accepted totals and placement, and
/// equals a cold Full with equivalent historical evidence. The restored owner
/// is a post-cutover Legacy-acknowledged owner.
#[test]
fn removed_account_readded_after_retirement_counts_once() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for collected in [false, true] {
        let d = drain(Arm::Drain);
        let mut index = d.index;
        let mut at = NOW;
        if collected {
            let later = d.h.step(false, index, d.cache.clone(), 100, LATER);
            assert!(later.posts.is_empty() && later.reads.is_empty());
            assert!(later.index.traversal.is_none());
            assert!(
                later
                    .index
                    .codex_counting_tombstones
                    .values()
                    .next()
                    .is_none(),
                "a later complete generation collects absent owners"
            );
            index = later.index;
            at = LATEST;
        } else {
            assert_eq!(
                index
                    .codex_counting_tombstones
                    .get(&d.owners[REMOVED_FRESH])
                    .map(|tombstone| tombstone.evidence),
                Some(AckEvidence::LegacyAcked)
            );
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
        // Equivalent historical evidence: Legacy while the tombstone
        // survives, none (a fresh V2 owner) once it was collected.
        let historical = (!collected).then(|| d.h.cold(true, at));
        let _cutover = crate::snapshots::TestCutover::set(0);
        let readded = d.h.step(true, index, d.cache.clone(), 100, at);
        assert_eq!(
            readded.reads,
            vec![(DeliveryMode::Full, 0); read.len()],
            "only {read:?} read, once each (collected: {collected})"
        );
        let emitted = readded
            .scan
            .snapshots
            .iter()
            .map(|item| item.source_session_id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(
            emitted.contains(REMOVED_FRESH) && emitted.iter().all(|id| read.contains(id)),
            "emitted {emitted:?}, read {read:?}"
        );
        assert!(readded.index.traversal.is_none(), "healthy");
        if !collected {
            assert!(
                !readded.index.files[&local_index_key(&d.h.path(REMOVED_FRESH))].codex_counting_v2,
                "the surviving tombstone keeps Legacy counting"
            );
        }
        let replay = crate::snapshot_sync::codex_transition_acked_route(
            &readded.index,
            &readded.scan,
            Mode::Ram,
        );
        let mut original = d.gen1_acked.clone();
        original
            .snapshots
            .retain(|id, _| emitted.contains(id.as_str()));
        assert!(original.accepted_identity_buckets.is_some());
        assert!(replay.accepted_identity_buckets.is_some());
        money_oracle::assert_placement_equivalent(
            &without_file_revision(original),
            &without_file_revision(replay.clone()),
        );
        let mut destination = d.gen1.snapshots.clone();
        destination.extend(replay.snapshots.clone());
        assert_eq!(
            destination.len(),
            d.gen1.snapshots.len(),
            "stable keys: one latest head per entity"
        );
        for (id, field) in emitted
            .iter()
            .flat_map(|id| money_oracle::FIELDS.iter().map(move |f| (*id, *f)))
        {
            assert_eq!(
                destination[id][field], d.gen1.snapshots[id][field],
                "{id} {field}: the original accepted total, never a sum"
            );
        }
        let mut cold = historical.unwrap_or_else(|| d.h.cold(true, at));
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

/// [money] O6a: the home re-added (and its folder back) before any healthy
/// generation reconciled: its unchanged files Skip, with no read and no
/// body, and nothing retires.
#[test]
fn removed_account_readded_before_retirement_skips() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let h = Homes::new();
    let (_session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &h.c.scratch.join("state"),
    );
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (first, gen1, _) = accepted_generation(&h, prior, &cache);
    let witnesses = |index: &ScanIndex| {
        h.removed_keys()
            .iter()
            .map(|key| index.files[key].last_upload_body_witness.clone())
            .collect::<Vec<_>>()
    };
    let accepted_witnesses = witnesses(&first.index);
    fs::rename(&h.removed, &h.parked).unwrap();
    fs::remove_dir(&h.flaky).unwrap();
    let second = h.step(false, first.index, cache.clone(), 100, NOW);
    assert_eq!(second.unresolved, 1);
    assert!(second
        .index
        .traversal
        .as_ref()
        .is_some_and(|walk| walk.counts.has_errors()));
    fs::rename(&h.parked, &h.removed).unwrap();
    fs::create_dir(&h.flaky).unwrap();
    let tail = h.tail_of(&h.c.path(GAP));
    let third = h.step(true, second.index, cache.clone(), 100, NOW);
    assert_eq!(third.unresolved, 0);
    assert_eq!(third.reads, vec![tail], "the removed home's files Skip");
    assert!(third.scan.census_complete && third.index.traversal.is_none());
    assert_eq!(witnesses(&third.index), accepted_witnesses);
    assert!(third
        .index
        .codex_counting_tombstones
        .values()
        .next()
        .is_none());
    let mut actual = route(&third.index, &third.scan, third.posts.clone());
    assert_eq!(
        actual
            .snapshots
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![GAP]
    );
    actual.accepted.extend(carried(
        &third.index,
        &gen1,
        &[MAIN, OTHER, SIDE, REMOVED_FRESH, REMOVED_OLD],
    ));
    assert_carried(emitted(&third.index, &h.cold(true, NOW)), &actual);
}

/// [money] O2: a configured root that is missing (unmounted) keeps today's
/// red: one RootResolutionUnresolved, its keys never witnesses, its entities
/// held with their accepted bodies, nothing retired. Back in place, its files
/// Skip with no first read and no re-read.
#[test]
fn configured_missing_root_stays_red_and_held() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let h = Homes::new();
    let (_session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &h.c.scratch.join("state"),
    );
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (first, gen1, _) = accepted_generation(&h, prior, &cache);
    fs::rename(&h.removed, &h.parked).unwrap();
    let tail = h.tail_of(&h.c.path(GAP));
    let second = h.step(true, first.index, cache.clone(), 100, NOW);
    assert_eq!(second.unresolved, 1, "the configured missing root");
    assert!(second
        .index
        .legacy_unresolved_root_file_witnesses
        .is_empty());
    assert!(second
        .index
        .traversal
        .as_ref()
        .is_some_and(|walk| walk.counts.has_errors()));
    assert!(h
        .removed_keys()
        .iter()
        .all(|key| second.index.files.contains_key(key)));
    assert!(second
        .index
        .codex_counting_tombstones
        .values()
        .next()
        .is_none());
    assert_eq!(second.reads, vec![tail]);
    let mut cold = h.cold(true, NOW);
    cold.snapshots.retain(|item| item.source_session_id == GAP);
    let cold = emitted(&second.index, &cold);
    let grown = route(&second.index, &second.scan, second.posts.clone());
    let mut held = grown.clone();
    held.accepted
        .extend(carried(&second.index, &gen1, &[REMOVED_FRESH, REMOVED_OLD]));
    for id in [REMOVED_FRESH, REMOVED_OLD] {
        money_oracle::assert_held(id, &gen1, &held, &cold);
    }

    fs::rename(&h.parked, &h.removed).unwrap();
    let mut index = second.index;
    index
        .traversal
        .as_mut()
        .unwrap()
        .unhealthy_retry_not_before_unix_seconds = Some(0);
    let tail = h.tail_of(&h.c.path(MAIN));
    let third = h.step(true, index, cache.clone(), 100, NOW);
    assert_eq!(third.unresolved, 0);
    assert_eq!(third.reads, vec![tail], "Skip: no first read, no re-read");
    assert!(third.scan.census_complete && third.index.traversal.is_none());
    assert!(third
        .index
        .codex_counting_tombstones
        .values()
        .next()
        .is_none());
    let mut actual = route(&third.index, &third.scan, third.posts.clone());
    actual
        .accepted
        .extend(carried(&third.index, &grown, &[GAP]));
    actual.accepted.extend(carried(
        &third.index,
        &gen1,
        &[OTHER, SIDE, REMOVED_FRESH, REMOVED_OLD],
    ));
    assert_carried(emitted(&third.index, &h.cold(true, NOW)), &actual);
}

/// [money] O3: the roster drops a home whose folder is still present: no
/// proof, so its entries stay witnesses, the retry stays red and nothing
/// retires. When the roster recovers, the files Skip with no re-read.
#[test]
fn present_unconfigured_root_keeps_witnesses() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let h = Homes::new();
    let (_session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &h.c.scratch.join("state"),
    );
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (first, gen1, _) = accepted_generation(&h, prior, &cache);
    fs::remove_dir(&h.flaky).unwrap();
    let second = h.step(false, first.index, cache.clone(), 100, NOW);
    assert_eq!(second.unresolved, 1);
    let mut index = second.index;
    fs::create_dir(&h.flaky).unwrap();
    index
        .traversal
        .as_mut()
        .unwrap()
        .unhealthy_retry_not_before_unix_seconds = Some(0);
    let third = h.step(false, index, cache.clone(), 100, NOW);
    assert_eq!(third.unresolved, 1, "a present home is no proof of removal");
    assert_eq!(
        third.index.legacy_unresolved_root_file_witnesses,
        h.removed_keys()
    );
    assert!(third
        .index
        .traversal
        .as_ref()
        .is_some_and(|walk| walk.counts.has_errors()));
    assert!(h
        .removed_keys()
        .iter()
        .all(|key| third.index.files.contains_key(key)));
    assert!(third
        .index
        .codex_counting_tombstones
        .values()
        .next()
        .is_none());
    assert!(third.posts.is_empty() && third.reads.is_empty());

    let tail = h.tail_of(&h.c.path(GAP));
    let fourth = h.step(true, third.index, cache.clone(), 100, NOW);
    assert_eq!(fourth.unresolved, 0);
    assert_eq!(fourth.reads, vec![tail], "the restored roster's files Skip");
    assert!(fourth.scan.census_complete && fourth.index.traversal.is_none());
    assert!(fourth
        .index
        .legacy_unresolved_root_file_witnesses
        .is_empty());
    assert!(fourth
        .index
        .codex_counting_tombstones
        .values()
        .next()
        .is_none());
    let mut actual = route(&fourth.index, &fourth.scan, fourth.posts.clone());
    actual.accepted.extend(carried(
        &fourth.index,
        &gen1,
        &[MAIN, OTHER, SIDE, REMOVED_FRESH, REMOVED_OLD],
    ));
    assert_carried(emitted(&fourth.index, &h.cold(true, NOW)), &actual);
}
