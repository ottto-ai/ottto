//! Identity re-offer latch through the production scanner, finalizer and
//! ACK custody, over synthetic Desktop stores; never live provider state.
use super::*;
use desktop_identity::IdentityLatch::{Pending, Settled};

const ACCOUNT: &str = "123e4567-e89b-12d3-a456-426614174000";
const ORG: &str = "123e4567-e89b-12d3-a456-426614174001";
// Before the transcript's first activity, so the creation proof holds.
const CREATED: &str = "2026-08-01T00:00:00Z";
// After collection: the creation-proof downgrade always applies.
const CREATED_LATE: &str = "2026-08-02T08:00:00Z";

/// `recovered` = [posted, unchanged, refused, bytes]; `adoption` = [sent, ...];
/// `refused` = the flat `desktop_identity_reoffer_refused` total.
#[derive(Debug, Default, PartialEq, Eq)]
struct Reoffers {
    recovered: [u64; 4],
    adoption: [u64; 4],
    refused: u64,
}

struct IdentityFixture {
    home: crate::test_scratch::ScratchDir,
    native: Fixture,
}
impl IdentityFixture {
    fn new(created_at: &str) -> Self {
        let home = crate::test_scratch::ScratchDir::new("desktop-identity-latch");
        let mut native = Fixture::new(1);
        let old = native.dir.clone();
        native.dir = home.join(".claude/projects");
        fs::create_dir_all(&native.dir).unwrap();
        let path = native.dir.join(format!("{}.jsonl", native.session));
        fs::rename(&native.path, &path).unwrap();
        native.path = path;
        fs::remove_dir_all(old).unwrap();
        let fixture = Self { home, native };
        fixture.write_store(created_at, "first");
        fixture
    }
    /// The child's own account/organization come from its store location.
    fn write_store(&self, created_at: &str, title: &str) {
        let store = self
            .home
            .join("Library/Application Support/Claude/claude-code-sessions")
            .join(ACCOUNT)
            .join(ORG);
        fs::create_dir_all(&store).unwrap();
        fs::write(
            store.join("child.json"),
            json!({
                "cliSessionId": self.native.session, "sessionId": "local_child",
                "createdAt": created_at, "title": title, "titleSource": "user"
            })
            .to_string(),
        )
        .unwrap();
    }
    fn key(&self) -> String {
        local_index_key(&self.native.path)
    }
    fn latch(&self, index: &ScanIndex) -> Option<desktop_identity::IdentityLatch> {
        index
            .claude_desktop_identity_latches
            .get(&self.key())
            .copied()
    }
    /// Durable Desktop entries with an incomplete identity census until `until`.
    fn loaded_incomplete(&self, until: &str) -> ScanIndex {
        let mut index = ScanIndex::default();
        ClaudeTitleMetadata::load_from_roots_with_index(
            std::slice::from_ref(&self.native.dir),
            &mut index,
            COLLECTED,
            true,
        );
        incomplete_until(&mut index, until);
        index
    }
    fn run(&self, index: ScanIndex, at: &str) -> (Run, Reoffers) {
        self.run_with(index, Arc::new(SharedCache::default()), at)
    }
    fn run_with(&self, index: ScanIndex, cache: Arc<SharedCache>, at: &str) -> (Run, Reoffers) {
        let (run, rows) = crate::local_resource_diagnostics::capture(|| {
            let mut run = raw_scan_at(&self.native, index, Some(cache), true, at, |_| {});
            finalize_scan_after_policy_with_body_witness(
                SOURCE,
                &mut run.result,
                &mut run.index,
                snapshot_upload_body_witness,
            );
            run
        });
        let diagnostics = serde_json::to_string(&rows).unwrap();
        assert!(
            !diagnostics.contains(&self.key()),
            "latch keys never reach diagnostics"
        );
        let sum = |counter: &str, field: &str| {
            rows.iter()
                .filter_map(|row| row["counts"]["desktop_metadata"][counter][field].as_u64())
                .sum::<u64>()
        };
        let recovered = "desktop_identity_recovered_reoffer";
        let adoption = "desktop_identity_adoption_reoffer";
        let counts = Reoffers {
            recovered: ["posted", "unchanged", "refused", "bytes"].map(|f| sum(recovered, f)),
            adoption: ["sent", "unchanged", "refused", "bytes"].map(|f| sum(adoption, f)),
            refused: rows
                .iter()
                .filter_map(|row| {
                    row["counts"]["desktop_metadata"]["desktop_identity_reoffer_refused"].as_u64()
                })
                .sum(),
        };
        (run, counts)
    }
    fn child<'a>(&self, run: &'a Run) -> &'a SnapshotItem {
        assert_eq!(run.result.snapshots.len(), 1, "only this child is offered");
        let item = &run.result.snapshots[0];
        assert_eq!(item.source_session_id, self.native.session);
        assert!(
            !serde_json::to_string(&batch(&run.result.snapshots))
                .unwrap()
                .contains(&self.key()),
            "latch keys never reach the upload"
        );
        item
    }
    fn restart(&self, mut index: ScanIndex) -> ScanIndex {
        let path = self.home.join("index.json");
        index.save(&path).unwrap();
        ScanIndex::load(&path).unwrap()
    }
    fn quiet(&self, mut index: ScanIndex, times: &[&str]) -> ScanIndex {
        for at in times {
            let (run, counts) = self.run(index, at);
            assert!(run.result.snapshots.is_empty(), "{at}");
            assert_eq!(run.native_bytes, 0, "{at}");
            assert_eq!(counts, Reoffers::default(), "{at}");
            index = ack(run);
        }
        index
    }
    fn len(&self) -> u64 {
        fs::metadata(&self.native.path).unwrap().len()
    }
}

fn incomplete_until(index: &mut ScanIndex, until: &str) {
    index.claude_desktop_identity_census_complete = false;
    index.claude_desktop_lineage_census_complete = false;
    index.claude_desktop_census_witness = None;
    index.claude_desktop_store_retry_not_before_unix_seconds = rfc3339_unix_seconds(until);
}

/// The completed-cycle save: every offered body ACKed (finalized once).
fn ack(run: Run) -> ScanIndex {
    validate_exact_ack(&batch(&run.result.snapshots));
    let accepted = run
        .result
        .snapshots
        .iter()
        .map(|s| s.snapshot_fingerprint.clone())
        .collect();
    let mut index = run.index;
    index.record_accepted_snapshot_fingerprints(&accepted);
    index
}

/// Everything but the disposition: the re-offer is the FULL current body.
fn body_without_disposition(item: &SnapshotItem) -> Value {
    let mut evidence = item.session_account_evidence.clone().unwrap();
    evidence.identity_disposition = None;
    json!({
        "source_session_id": item.source_session_id,
        "session_account_evidence": evidence,
        "input_tokens": item.input_tokens,
        "output_tokens": item.output_tokens,
        "request_count": item.request_count,
        "model_usage": item.model_usage,
        "usage_buckets": item.usage_buckets,
        "request_evidence": item.request_evidence,
        "cost": item.cost,
    })
}

fn disposition(item: &SnapshotItem) -> Option<&'static str> {
    item.session_account_evidence
        .as_ref()
        .and_then(|evidence| evidence.identity_disposition)
}

#[test]
fn desktop_identity_missing_to_complete_reoffers_once_and_settles_only_on_ack() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED);
    let index = f.loaded_incomplete("2026-08-02T07:11:00Z");
    let (first, counts) = f.run(index, COLLECTED);
    assert_eq!(counts, Reoffers::default());
    let missing = f.child(&first).clone();
    let evidence = missing.session_account_evidence.clone().unwrap();
    assert_eq!(evidence.identity_disposition, Some("missing"));
    assert!(evidence.account_identifier_hash.is_some());
    assert!(evidence.provider_workspace_hash.is_some());
    let committed = f.restart(ack(first));
    assert_eq!(f.latch(&committed), Some(Pending), "own missing at an ACK");

    // A census flap reads and offers nothing and leaves the latch alone.
    let (flap, counts) = f.run(committed.clone(), "2026-08-02T07:10:30Z");
    assert!(flap.result.snapshots.is_empty());
    assert_eq!((flap.native_bytes, counts), (0, Reoffers::default()));
    assert_eq!(f.latch(&flap.index), Some(Pending));

    // Recovery: exactly one full-body re-offer naming the child's own pair.
    let (recovered, counts) = f.run(committed.clone(), "2026-08-02T07:12:00Z");
    let complete = f.child(&recovered);
    assert_eq!(disposition(complete), Some("complete"));
    assert_eq!(
        body_without_disposition(complete),
        body_without_disposition(&missing),
        "same account pair, totals and rows; only the disposition recovers"
    );
    let bytes = f.len();
    assert_eq!(recovered.native_bytes, bytes, "uncached: counted read");
    assert_eq!(counts.recovered, [1, 0, 0, bytes]);
    assert_eq!(counts.adoption, [0; 4]);

    // A failed upload / partial save keeps it pending, so it retries.
    let failed = recovered
        .index
        .committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(f.latch(&failed), Some(Pending));
    let failed = f.restart(failed);
    let (retried, counts) = f.run(failed, "2026-08-02T07:13:00Z");
    assert_eq!(disposition(f.child(&retried)), Some("complete"));
    assert_eq!(counts.recovered, [1, 0, 0, bytes]);
    let settled = ack(retried);
    assert_eq!(f.latch(&settled), Some(Settled));

    // Restart, cache eviction (fresh caches) and flaps never re-offer.
    let mut index = f.quiet(
        f.restart(settled),
        &[
            "2026-08-02T07:14:00Z",
            "2026-08-02T07:15:00Z",
            "2026-08-02T07:16:00Z",
        ],
    );
    incomplete_until(&mut index, "2026-08-02T07:30:00Z");
    let index = f.quiet(index, &["2026-08-02T07:20:00Z"]);
    let index = f.quiet(f.restart(index), &["2026-08-02T07:31:00Z"]);
    assert_eq!(f.latch(&index), Some(Settled));
}

#[test]
fn desktop_identity_complete_flaps_and_restarts_never_reoffer() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED);
    let (first, counts) = f.run(ScanIndex::default(), COLLECTED);
    assert_eq!(disposition(f.child(&first)), Some("complete"));
    assert_eq!(counts, Reoffers::default());
    let mut index = ack(first);
    assert_eq!(f.latch(&index), Some(Settled));
    for (incomplete, until, complete) in [
        (
            "2026-08-02T07:12:00Z",
            "2026-08-02T07:13:00Z",
            "2026-08-02T07:14:00Z",
        ),
        (
            "2026-08-02T07:15:00Z",
            "2026-08-02T07:16:00Z",
            "2026-08-02T07:17:00Z",
        ),
        (
            "2026-08-02T07:18:00Z",
            "2026-08-02T07:19:00Z",
            "2026-08-02T07:20:00Z",
        ),
    ] {
        incomplete_until(&mut index, until);
        index = f.quiet(f.restart(index), &[incomplete]);
        index = f.quiet(f.restart(index), &[complete]);
        assert_eq!(f.latch(&index), Some(Settled));
    }
}

#[test]
fn desktop_identity_downgraded_emission_never_latches_and_recovers_when_evidence_completes() {
    // E1: the creation-proof downgrade wins over a complete own disposition.
    // Nothing persists, and the read itself memoizes this evidence, so the
    // same evidence costs no second read and no refused re-offer.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED_LATE);
    let cache = Arc::new(SharedCache::default());
    let (first, counts) = f.run_with(ScanIndex::default(), cache.clone(), COLLECTED);
    assert_eq!(disposition(f.child(&first)), Some("missing"));
    assert_eq!(counts, Reoffers::default());
    let index = ack(first);
    assert_eq!(
        f.latch(&index),
        None,
        "the latch means settled complete only"
    );
    let index = f.quiet(f.restart(index), &["2026-08-02T07:12:00Z"]);
    let (retained, counts) = f.run_with(index, cache.clone(), "2026-08-02T07:12:30Z");
    assert!(retained.result.snapshots.is_empty());
    assert_eq!((retained.native_bytes, counts), (0, Reoffers::default()));
    // A new process forgets the memo: adoption stays cache-only, so one
    // refused re-offer from RAM where a reduction is retained, 0 bytes.
    desktop_identity::reset_refused_memo_for_test();
    let supported = u64::from(crate::heap_layout_bound::layout_supported());
    let (refused, counts) = f.run_with(ack(retained), cache.clone(), "2026-08-02T07:13:00Z");
    assert!(refused.result.snapshots.is_empty());
    assert_eq!(refused.native_bytes, 0);
    assert_eq!(counts.adoption, [0, 0, supported, 0]);
    assert_eq!(counts.refused, supported);
    let index = ack(refused);
    assert_eq!(f.latch(&index), None, "a refusal never settles");
    let (quiet, counts) = f.run_with(index, cache, "2026-08-02T07:14:00Z");
    assert!(quiet.result.snapshots.is_empty());
    assert_eq!((quiet.native_bytes, counts), (0, Reoffers::default()));
    // The cause clears: the child's own complete identity is not lost.
    f.write_store(CREATED, "creation proof recovered");
    let (recovered, _) = f.run(ack(quiet), "2026-08-02T07:15:00Z");
    assert_eq!(disposition(f.child(&recovered)), Some("complete"));
    let index = ack(recovered);
    assert_eq!(f.latch(&index), Some(Settled));
    f.quiet(f.restart(index), &["2026-08-02T07:16:00Z"]);
}

#[test]
fn desktop_identity_refused_reoffer_once_per_process_then_complete_evidence_recovers() {
    // Census-caused missing that the creation proof also downgrades. Runs on
    // every platform: a pending child is read, not served from the RAM cache.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED_LATE);
    let (first, _) = f.run(f.loaded_incomplete("2026-08-02T07:11:00Z"), COLLECTED);
    assert_eq!(disposition(f.child(&first)), Some("missing"));
    let index = ack(first);
    assert_eq!(f.latch(&index), Some(Pending));
    let refused_once = |index: ScanIndex, at: &str| {
        let (refused, counts) = f.run(f.restart(index), at);
        assert!(
            refused.result.snapshots.is_empty(),
            "the unchanged missing body is never posted again"
        );
        assert_eq!(
            counts,
            Reoffers {
                recovered: [0, 0, 1, f.len()],
                refused: 1,
                ..Reoffers::default()
            },
            "{at}"
        );
        let index = ack(refused);
        assert_eq!(f.latch(&index), Some(Pending), "a refusal never settles");
        index
    };
    // Exactly one refused re-offer, then quiet for N passes and a save/load.
    let index = refused_once(index, "2026-08-02T07:12:00Z");
    let index = f.quiet(
        f.restart(index),
        &[
            "2026-08-02T07:13:00Z",
            "2026-08-02T07:14:00Z",
            "2026-08-02T07:15:00Z",
        ],
    );
    // The real cap evicts this child: at most one extra counted refusal.
    desktop_identity::fill_refused_memo_for_test();
    let index = refused_once(index, "2026-08-02T07:16:00Z");
    let index = f.quiet(index, &["2026-08-02T07:17:00Z", "2026-08-02T07:18:00Z"]);
    // A new process: at most one per process, and no unbounded loop.
    desktop_identity::reset_refused_memo_for_test();
    let index = refused_once(index, "2026-08-02T07:19:00Z");
    let index = f.quiet(index, &["2026-08-02T07:20:00Z"]);
    // The evidence becomes complete: exactly one body, latched complete.
    f.write_store(CREATED, "creation proof recovered");
    let (recovered, _) = f.run(index, "2026-08-02T07:21:00Z");
    assert_eq!(disposition(f.child(&recovered)), Some("complete"));
    assert_eq!(recovered.native_bytes, f.len());
    let index = ack(recovered);
    assert_eq!(f.latch(&index), Some(Settled));
    f.quiet(
        f.restart(index),
        &["2026-08-02T07:22:00Z", "2026-08-02T07:23:00Z"],
    );
}

#[test]
fn desktop_identity_recovery_reads_its_settled_e2_path_twin_and_publishes() {
    // Without the page-start prepass only the pending path is read: E2 holds
    // a session whose known twin is absent from the page, so it never settles.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let f = IdentityFixture::new(CREATED);
    let copy = f.native.dir.join("other-project");
    fs::create_dir_all(&copy).unwrap();
    let copy = copy.join(format!("{}.jsonl", f.native.session));
    fs::write(&copy, fs::read(&f.native.path).unwrap()).unwrap();
    let (first, _) = f.run(f.loaded_incomplete("2026-08-02T07:11:00Z"), COLLECTED);
    assert!(first.result.snapshots.iter().all(|item| {
        item.source_session_id == f.native.session && disposition(item) == Some("missing")
    }));
    let mut index = ack(first);
    // E2 may publish one body for both paths: recover the path that owns it.
    let (pending, twin) = {
        let keys = [f.key(), local_index_key(&copy)];
        let owner = keys
            .iter()
            .position(|key| index.claude_desktop_identity_latches.get(key) == Some(&Pending))
            .expect("the path carrying the missing body is pending");
        (keys[owner].clone(), keys[1 - owner].clone())
    };
    index
        .claude_desktop_identity_latches
        .insert(twin.clone(), Settled);
    let (recovered, counts) = f.run(index, "2026-08-02T07:12:00Z");
    assert_eq!(
        recovered.native_bytes,
        2 * f.len(),
        "the settled twin is read with the recovering path"
    );
    assert!(!recovered.result.snapshots.is_empty(), "E2 withheld it");
    assert!(recovered.result.snapshots.iter().all(|item| {
        item.source_session_id == f.native.session && disposition(item) == Some("complete")
    }));
    assert_eq!(counts.recovered, [1, 0, 0, f.len()]);
    let index = ack(recovered);
    assert_eq!(index.claude_desktop_identity_latches[&pending], Settled);
    assert_eq!(index.claude_desktop_identity_latches[&twin], Settled);
    f.quiet(
        f.restart(index),
        &["2026-08-02T07:13:00Z", "2026-08-02T07:14:00Z"],
    );
}

#[test]
fn desktop_identity_adoption_waits_when_uncached_and_unchanged_body_sends_nothing() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED);
    let cache = Arc::new(SharedCache::default());
    let (first, _) = f.run_with(ScanIndex::default(), cache.clone(), COLLECTED);
    assert_eq!(disposition(f.child(&first)), Some("complete"));
    let mut index = ack(first);
    // An older reader dropped the map: no entry is not settled.
    index.claude_desktop_identity_latches.clear();
    let index = f.restart(index);
    // Not due and not cached (fresh cache, as after a restart): no read.
    let (cold, counts) = f.run(index, "2026-08-02T07:12:00Z");
    assert!(cold.result.snapshots.is_empty());
    assert_eq!((cold.native_bytes, counts), (0, Reoffers::default()));
    assert_eq!(f.latch(&cold.index), None);
    // A retained copy that acquisition would NOT reuse unchanged (here a
    // different scope) selects nothing: a matching extent is not enough.
    let mut rescoped = ack(cold);
    let context = rescoped.active_upload_context_fingerprint.clone();
    rescoped.active_upload_context_fingerprint = Some("other-context".into());
    rescoped.upload_context_fingerprint = Some("other-context".into());
    let (refused, counts) = f.run_with(rescoped, cache.clone(), "2026-08-02T07:12:30Z");
    assert!(refused.result.snapshots.is_empty());
    assert_eq!((refused.native_bytes, counts), (0, Reoffers::default()));
    assert_eq!(f.latch(&refused.index), None);
    let mut index = ack(refused);
    index.active_upload_context_fingerprint = context.clone();
    index.upload_context_fingerprint = context;
    // Cached: one adoption pass from the retained reduction; the body is
    // unchanged, so nothing new is sent and the child settles.
    let supported = u64::from(crate::heap_layout_bound::layout_supported());
    let (warm, counts) = f.run_with(index, cache.clone(), "2026-08-02T07:13:00Z");
    assert!(warm.result.snapshots.is_empty(), "fingerprint dedupe");
    assert_eq!(warm.native_bytes, 0);
    assert_eq!(counts.adoption, [0, supported, 0, 0]);
    assert_eq!(counts.recovered, [0; 4]);
    let index = ack(warm);
    assert_eq!(f.latch(&index).is_some(), supported == 1);
    let (quiet, counts) = f.run_with(index, cache, "2026-08-02T07:14:00Z");
    assert!(quiet.result.snapshots.is_empty());
    assert_eq!((quiet.native_bytes, counts), (0, Reoffers::default()));
}

#[test]
fn desktop_identity_adoption_sends_once_from_cache_with_the_childs_own_account() {
    // Legacy: the stored body lacked the account (missing during an
    // incomplete census) and the old reader lost the latch.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED);
    let (stored, _) = f.run(f.loaded_incomplete("2026-08-02T07:11:00Z"), COLLECTED);
    let missing = f.child(&stored).clone();
    assert_eq!(disposition(&missing), Some("missing"));
    let stored = ack(stored);
    // The same unchanged extent, retained in RAM by a pass under complete
    // coverage (a cold file is never sampled under partial coverage).
    let cache = Arc::new(SharedCache::default());
    let (retained, _) = f.run_with(ScanIndex::default(), cache.clone(), COLLECTED);
    assert_eq!(disposition(f.child(&retained)), Some("complete"));
    let mut index = ack(retained);
    // Its stored and accepted body is the legacy missing one, with no latch.
    let key = f.key();
    let entry = index.files.get_mut(&key).unwrap();
    entry.last_snapshot_fingerprint = stored.files[&key].last_snapshot_fingerprint.clone();
    entry.last_upload_body_witness = stored.files[&key].last_upload_body_witness.clone();
    index.file_snapshot_fingerprints = stored.file_snapshot_fingerprints.clone();
    index.accepted_snapshot_fingerprints = stored.accepted_snapshot_fingerprints.clone();
    index.claude_desktop_identity_latches.clear();
    // An uncached pass (as after a restart): adoption waits, reads nothing.
    let (cold, counts) = f.run(f.restart(index), "2026-08-02T07:12:00Z");
    assert!(cold.result.snapshots.is_empty());
    assert_eq!((cold.native_bytes, counts), (0, Reoffers::default()));
    let supported = u64::from(crate::heap_layout_bound::layout_supported());
    let (warm, counts) = f.run_with(ack(cold), cache.clone(), "2026-08-02T07:13:00Z");
    assert_eq!(warm.native_bytes, 0, "adoption never reads the transcript");
    assert_eq!(counts.adoption, [supported, 0, 0, 0]);
    assert_eq!(warm.result.snapshots.len() as u64, supported);
    if let Some(sent) = warm.result.snapshots.first() {
        assert_eq!(disposition(sent), Some("complete"));
        assert_eq!(
            body_without_disposition(sent),
            body_without_disposition(&missing),
            "the account is the child's own, from its own complete disposition"
        );
    }
    let index = ack(warm);
    let (quiet, counts) = f.run_with(index, cache, "2026-08-02T07:14:00Z");
    assert!(quiet.result.snapshots.is_empty());
    assert_eq!((quiet.native_bytes, counts), (0, Reoffers::default()));
}
