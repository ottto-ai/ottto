//! Identity re-offer latch through the production scanner, finalizer and
//! ACK custody, over synthetic Desktop stores; never live provider state.
use super::*;
use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRef, SnapshotEntityRejection};
use desktop_identity::IdentityLatch::{Pending, Settled};

const ACCOUNT: &str = "123e4567-e89b-12d3-a456-426614174000";
const ORG: &str = "123e4567-e89b-12d3-a456-426614174001";
// Before the transcript's first activity, so the creation proof holds.
const CREATED: &str = "2026-08-01T00:00:00Z";
// After collection: the creation-proof downgrade always applies.
const CREATED_LATE: &str = "2026-08-02T08:00:00Z";
const CREATED_LATER: &str = "2026-08-02T08:30:00Z";

/// `recovered` = [posted, unchanged, refused, bytes]; `adoption` = [sent, ...];
/// `refused` = the flat `desktop_identity_reoffer_refused` total; `evicted` =
/// `desktop_identity_reoffer_memo_evicted`.
#[derive(Debug, Default, PartialEq, Eq)]
struct Reoffers {
    recovered: [u64; 4],
    adoption: [u64; 4],
    refused: u64,
    evicted: u64,
}
impl Reoffers {
    fn of(rows: &[Value]) -> Self {
        let sum = |counter: &str, field: &str| {
            rows.iter()
                .filter_map(|row| row["counts"]["desktop_metadata"][counter][field].as_u64())
                .sum::<u64>()
        };
        let flat = |counter: &str| {
            rows.iter()
                .filter_map(|row| row["counts"]["desktop_metadata"][counter].as_u64())
                .sum::<u64>()
        };
        let recovered = "desktop_identity_recovered_reoffer";
        let adoption = "desktop_identity_adoption_reoffer";
        Self {
            recovered: ["posted", "unchanged", "refused", "bytes"].map(|f| sum(recovered, f)),
            adoption: ["sent", "unchanged", "refused", "bytes"].map(|f| sum(adoption, f)),
            refused: flat("desktop_identity_reoffer_refused"),
            evicted: flat("desktop_identity_reoffer_memo_evicted"),
        }
    }
}

/// What the backend said about the bodies a pass put on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Accepted,
    Unchanged,
    /// Unchanged, with `unchanged_basis`: the server stored nothing.
    Unstored,
    Rejected,
    Conflict,
    /// The legacy ACK: a count and no entity lists.
    CountOnly,
    /// The upload failed: no response to classify.
    Silent,
}
impl Backend {
    /// `accepted` is what the backend reports: accepted PLUS unchanged.
    fn response(self, items: &[SnapshotItem]) -> Option<SnapshotBatchResponse> {
        let refs = || {
            items
                .iter()
                .map(|item| SnapshotEntityRef {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: None,
                    head_challenge: None,
                    unchanged_basis: None,
                })
                .collect::<Vec<_>>()
        };
        let list = |wanted: Self| if self == wanted { refs() } else { Vec::new() };
        let unchanged = matches!(self, Self::Unchanged | Self::Unstored);
        let counted = unchanged || matches!(self, Self::Accepted | Self::CountOnly);
        (self != Self::Silent).then(|| SnapshotBatchResponse {
            accepted: if counted { items.len() as u64 } else { 0 },
            sessions_reconciled: 0,
            session_ids: Vec::new(),
            disabled: false,
            disabled_reason: None,
            entity_ack_contract: (self != Self::CountOnly)
                .then(|| SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
            accepted_entities: list(Self::Accepted),
            unchanged_entities: if unchanged {
                let mut refs = refs();
                for entity in &mut refs {
                    entity.unchanged_basis =
                        (self == Self::Unstored).then(|| "head_covers_usage".to_string());
                }
                refs
            } else {
                Vec::new()
            },
            conflict_entities: list(Self::Conflict),
            rejected_entities: list(Self::Rejected)
                .into_iter()
                .map(|entity| SnapshotEntityRejection {
                    source_session_id: entity.source_session_id,
                    snapshot_fingerprint: entity.snapshot_fingerprint,
                    reason: "usage_accounting_authority_downgrade".into(),
                    detail: "not logged".into(),
                    permanent: true,
                    occurrence_count: 1,
                })
                .collect(),
        })
    }
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
        self.run_answered(index, cache, at, Backend::Accepted)
    }
    fn run_answered(
        &self,
        index: ScanIndex,
        cache: Arc<SharedCache>,
        at: &str,
        backend: Backend,
    ) -> (Run, Reoffers) {
        let (run, rows) = crate::local_resource_diagnostics::capture(|| {
            let mut run = raw_scan_at(&self.native, index, Some(cache), true, at, |_| {});
            finalize_scan_after_policy_with_body_witness(
                SOURCE,
                &mut run.result,
                &mut run.index,
                snapshot_upload_body_witness,
            );
            if let Some(response) = backend.response(&run.result.snapshots) {
                classify_desktop_identity_reoffers(&run.result.snapshots, &response);
            }
            run
        });
        let diagnostics = serde_json::to_string(&rows).unwrap();
        assert!(
            !diagnostics.contains(&self.key()),
            "latch keys never reach diagnostics"
        );
        (run, Reoffers::of(&rows))
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
    accept(run)
}

fn accept(run: Run) -> ScanIndex {
    let accepted = run
        .result
        .snapshots
        .iter()
        .map(|s| s.snapshot_fingerprint.clone())
        .collect();
    let mut index = run.index;
    // One ledger per body: a raw path-twin pair shares its fingerprint.
    for item in &run.result.snapshots {
        settle(&mut index, &run.result, &ledger(item));
    }
    index.record_accepted_snapshot_fingerprints(&accepted);
    index
}

/// What the upload ledger holds after this exact body's ACK.
fn ledger(item: &SnapshotItem) -> BTreeMap<String, String> {
    BTreeMap::from([(
        item.snapshot_fingerprint.clone(),
        snapshot_upload_body_witness(item),
    )])
}

fn settle(index: &mut ScanIndex, result: &SourceScanResult, ledger: &BTreeMap<String, String>) {
    index.settle_desktop_identity_reoffers(result, ledger, &BTreeMap::new(), &BTreeMap::new());
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
    let (recovered, counts) = f.run_answered(
        committed.clone(),
        Arc::new(SharedCache::default()),
        "2026-08-02T07:12:00Z",
        Backend::Silent,
    );
    let complete = f.child(&recovered);
    assert_eq!(disposition(complete), Some("complete"));
    assert_eq!(
        body_without_disposition(complete),
        body_without_disposition(&missing),
        "same account pair, totals and rows; only the disposition recovers"
    );
    let bytes = f.len();
    assert_eq!(recovered.native_bytes, bytes, "uncached: counted read");
    assert_eq!(counts, Reoffers::default(), "no response, nothing counted");

    // A failed upload / partial save keeps it pending, so it retries.
    let failed = recovered
        .index
        .committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(f.latch(&failed), Some(Pending));
    let failed = f.restart(failed);
    let (retried, counts) = f.run(failed, "2026-08-02T07:13:00Z");
    assert_eq!(disposition(f.child(&retried)), Some("complete"));
    assert_eq!(counts.recovered, [1, 0, 0, bytes], "counted once, retried");
    assert_eq!(counts.adoption, [0; 4]);
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
fn desktop_identity_counters_read_the_response_lists_never_the_accepted_count() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let at = "2026-08-02T07:12:00Z";
    for (backend, outcome, refused) in [
        (Backend::Accepted, [1, 0, 0], 0),
        (Backend::Unchanged, [0, 1, 0], 0),
        (Backend::Rejected, [0, 0, 1], 1),
        (Backend::Conflict, [0, 0, 0], 0),
        (Backend::CountOnly, [0, 0, 0], 0),
    ] {
        desktop_identity::reset_refused_memo_for_test();
        let f = IdentityFixture::new(CREATED);
        let (first, _) = f.run(f.loaded_incomplete("2026-08-02T07:11:00Z"), COLLECTED);
        let committed = f.restart(ack(first));

        // Recovered: `accepted` is 1 for an unchanged body, which is never posted.
        let cache = Arc::new(SharedCache::default());
        let (recovered, counts) = f.run_answered(committed, cache, at, backend);
        assert_eq!(disposition(f.child(&recovered)), Some("complete"));
        let [posted, unchanged, rejected] = outcome;
        let bytes = if outcome == [0; 3] { 0 } else { f.len() };
        assert_eq!(
            counts,
            Reoffers {
                recovered: [posted, unchanged, rejected, bytes],
                refused,
                ..Reoffers::default()
            },
            "{backend:?}"
        );
    }
}

#[test]
fn desktop_identity_adoption_counters_read_the_response_lists() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED);
    let (stored, _) = f.run(f.loaded_incomplete("2026-08-02T07:11:00Z"), COLLECTED);
    let stored = ack(stored);
    let cache = Arc::new(SharedCache::default());
    let (retained, _) = f.run_with(ScanIndex::default(), cache.clone(), COLLECTED);
    let mut index = ack(retained);
    let key = f.key();
    let entry = index.files.get_mut(&key).unwrap();
    entry.last_snapshot_fingerprint = stored.files[&key].last_snapshot_fingerprint.clone();
    entry.last_upload_body_witness = stored.files[&key].last_upload_body_witness.clone();
    index.file_snapshot_fingerprints = stored.file_snapshot_fingerprints.clone();
    index.accepted_snapshot_fingerprints = stored.accepted_snapshot_fingerprints.clone();
    index.claude_desktop_identity_latches.clear();
    let (cold, _) = f.run(f.restart(index), "2026-08-02T07:12:00Z");
    let supported = u64::from(crate::heap_layout_bound::layout_supported());
    let at = "2026-08-02T07:13:00Z";
    let (warm, counts) = f.run_answered(ack(cold), cache, at, Backend::Unchanged);
    assert_eq!(warm.result.snapshots.len() as u64, supported);
    assert_eq!(counts.adoption, [0, supported, 0, 0], "unchanged, not sent");
    assert_eq!(counts.recovered, [0; 4]);
}

#[test]
fn desktop_identity_settles_on_this_bodys_ack_never_on_an_older_bodys_fingerprint() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED);
    let (first, _) = f.run(f.loaded_incomplete("2026-08-02T07:11:00Z"), COLLECTED);
    let missing = f.child(&first).clone();
    let committed = f.restart(ack(first));
    assert_eq!(f.latch(&committed), Some(Pending));
    let cache = || Arc::new(SharedCache::default());

    // The re-offer fails while the upload ledger still ACKs the missing body,
    // and an unchanged answer that stored nothing named that older body too.
    let old = ledger(&missing);
    let bodies = std::slice::from_ref(&missing);
    classify_desktop_identity_reoffers(bodies, &Backend::Unstored.response(bodies).unwrap());
    let at = "2026-08-02T07:12:00Z";
    let (failed, counts) = f.run_answered(committed.clone(), cache(), at, Backend::Silent);
    assert_eq!(counts, Reoffers::default());
    let complete = f.child(&failed).clone();
    assert_eq!(complete.snapshot_fingerprint, missing.snapshot_fingerprint);
    assert_ne!(ledger(&complete), old, "same fingerprint, new body");
    let mut working = failed.index;
    settle(&mut working, &failed.result, &old);
    assert_eq!(f.latch(&working), Some(Pending), "the whole-index save");
    let accepted = old.keys().cloned().collect();
    let partial = working.committable_subset(&committed, &accepted, &BTreeMap::new());
    assert_eq!(
        f.latch(&partial),
        Some(Pending),
        "the fingerprint-safe subset"
    );

    // That subset advanced the entry to the unACKed body: the retry still sends.
    let at = "2026-08-02T07:13:00Z";
    let (retried, counts) = f.run_answered(f.restart(partial), cache(), at, Backend::Accepted);
    assert_eq!(disposition(f.child(&retried)), Some("complete"));
    assert_eq!(counts.recovered[..3], [1, 0, 0]);
    let index = ack(retried);
    assert_eq!(f.latch(&index), Some(Settled));
    f.quiet(f.restart(index), &["2026-08-02T07:14:00Z"]);

    // An unchanged answer settles, even one that stored nothing.
    let at = "2026-08-02T07:12:00Z";
    let (unstored, _) = f.run_answered(committed.clone(), cache(), at, Backend::Unstored);
    let mut working = unstored.index;
    let verdict = classify_desktop_identity_reoffers(
        &unstored.result.snapshots,
        &Backend::Unstored
            .response(&unstored.result.snapshots)
            .unwrap(),
    );
    working.settle_desktop_identity_reoffers(
        &unstored.result,
        &BTreeMap::new(),
        &verdict,
        &BTreeMap::new(),
    );
    assert_eq!(f.latch(&working), Some(Settled));

    // A refusal is no ACK: pending, and this evidence is not offered again.
    desktop_identity::reset_refused_memo_for_test();
    let (rejected, counts) = f.run_answered(committed, cache(), at, Backend::Rejected);
    assert_eq!(counts.recovered[2], 1);
    let body = f.child(&rejected).clone();
    let held = BTreeMap::from([(
        body.snapshot_fingerprint.clone(),
        SnapshotQuarantineRecord {
            contract_retry_claims: None,
            reconstruction_contract: crate::snapshots::terminal_contract_retry::current_contract(),
            witness: crate::snapshots::snapshot_quarantine_witness(SOURCE),
            retry_after_unix_seconds: 0,
            upload_body_witness: Some(snapshot_upload_body_witness(&body)),
            failed_reconstruction_count: crate::snapshots::MAX_SNAPSHOT_RECONSTRUCTION_FAILURES,
            disposition: crate::snapshots::SnapshotQuarantineDisposition::UnprovenTerminal,
        },
    )]);
    let mut working = rejected.index;
    working.settle_desktop_identity_reoffers(
        &rejected.result,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &held,
    );
    assert_eq!(f.latch(&working), Some(Pending));
    let (quiet, counts) = f.run(working, "2026-08-02T07:15:00Z");
    assert!(quiet.result.snapshots.is_empty());
    assert_eq!((quiet.native_bytes, counts), (0, Reoffers::default()));
}

#[test]
fn desktop_identity_memo_eviction_counter_equals_evictions_past_the_cap() {
    let evicted = |extra| {
        let ((), rows) = crate::local_resource_diagnostics::capture(|| {
            desktop_identity::fill_refused_memo_for_test(extra);
        });
        Reoffers::of(&rows)
    };
    assert_eq!(evicted(0), Reoffers::default(), "at the cap nothing evicts");
    let counts = evicted(7);
    assert_eq!(counts.evicted, 7);
    assert_eq!(counts.refused, 0, "an eviction is not a refusal");
}

#[test]
fn desktop_identity_same_digest_offers_nothing_and_a_changed_digest_offers_once() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED_LATE);
    let (first, _) = f.run(f.loaded_incomplete("2026-08-02T07:11:00Z"), COLLECTED);
    let index = ack(first);
    assert_eq!(f.latch(&index), Some(Pending));
    let offer_once = |index: ScanIndex, at: &str| {
        let (offer, counts) = f.run(f.restart(index), at);
        assert!(offer.result.snapshots.is_empty(), "{at}");
        assert_eq!(offer.native_bytes, f.len(), "{at}");
        let refused = Reoffers {
            recovered: [0, 0, 1, f.len()],
            refused: 1,
            ..Reoffers::default()
        };
        assert_eq!(counts, refused, "{at}");
        ack(offer)
    };

    // The same digest: one counted offer, then nothing in this process.
    let index = offer_once(index, "2026-08-02T07:12:00Z");
    let index = f.quiet(index, &["2026-08-02T07:13:00Z", "2026-08-02T07:14:00Z"]);

    // The selector compares the digest itself. Every digest input also moves
    // the source fingerprint today, so only a seeded memo reaches this branch.
    desktop_identity::remember_other_evidence_for_test(&f.key());
    let index = offer_once(index, "2026-08-02T07:15:00Z");
    let index = f.quiet(index, &["2026-08-02T07:16:00Z"]);

    // Real new evidence, still downgraded: one read, then quiet again.
    f.write_store(CREATED_LATER, "new evidence");
    let (offer, counts) = f.run(index, "2026-08-02T07:17:00Z");
    assert_eq!((offer.native_bytes, counts), (f.len(), Reoffers::default()));
    let index = ack(offer);
    assert_eq!(f.latch(&index), Some(Pending));
    f.quiet(
        f.restart(index),
        &["2026-08-02T07:18:00Z", "2026-08-02T07:19:00Z"],
    );
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
    assert_eq!(
        f.latch(&recovered.index),
        Some(Pending),
        "natural completion still owes an exact ACK"
    );
    let mut working = recovered.index;
    settle(&mut working, &recovered.result, &BTreeMap::new());
    assert_eq!(
        f.latch(&working),
        Some(Pending),
        "no synthetic ack helper before the verdict"
    );
    let body = &recovered.result.snapshots[0];
    settle(&mut working, &recovered.result, &ledger(body));
    assert_eq!(f.latch(&working), Some(Settled));
    f.quiet(f.restart(working), &["2026-08-02T07:16:00Z"]);
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
    let refused_once = |index: ScanIndex, at: &str, evicted: u64| {
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
                evicted,
                ..Reoffers::default()
            },
            "{at}"
        );
        let index = ack(refused);
        assert_eq!(f.latch(&index), Some(Pending), "a refusal never settles");
        index
    };
    // Exactly one refused re-offer, then quiet for N passes and a save/load.
    let index = refused_once(index, "2026-08-02T07:12:00Z", 0);
    let index = f.quiet(
        f.restart(index),
        &[
            "2026-08-02T07:13:00Z",
            "2026-08-02T07:14:00Z",
            "2026-08-02T07:15:00Z",
        ],
    );
    // The real cap evicts this child: at most one extra counted refusal.
    desktop_identity::fill_refused_memo_for_test(0);
    let index = refused_once(index, "2026-08-02T07:16:00Z", 1);
    let index = f.quiet(index, &["2026-08-02T07:17:00Z", "2026-08-02T07:18:00Z"]);
    // A new process: at most one per process, and no unbounded loop.
    desktop_identity::reset_refused_memo_for_test();
    let index = refused_once(index, "2026-08-02T07:19:00Z", 0);
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
fn desktop_identity_recovery_pulls_its_settled_e2_path_twin_onto_the_page() {
    // Without the page-start prepass only the pending path is read, and E2
    // holds a session whose known twin is absent from the page, so the
    // re-offer never settles. This pins the page; publishing a page that
    // holds both paths belongs to the E2 suites, so the two raw bodies are
    // accepted here without the one-body ACK check.
    use crate::snapshots::claude_request_money::e2;
    let _gate = e2::GateForTest::set(true);
    e2::with_fixture_birth(1_785_542_400_000_000_000, || {
        let f = IdentityFixture::new(CREATED);
        let copy = f.native.dir.join("other-project");
        fs::create_dir_all(&copy).unwrap();
        let copy = copy.join(format!("{}.jsonl", f.native.session));
        fs::write(&copy, fs::read(&f.native.path).unwrap()).unwrap();
        let (first, _) = f.run(ScanIndex::default(), COLLECTED);
        assert_eq!(first.native_bytes, 2 * f.len());
        let mut index = accept(first);
        let (pending, twin) = (f.key(), local_index_key(&copy));
        assert_eq!(index.claude_desktop_identity_latches[&pending], Settled);
        assert_eq!(index.claude_desktop_identity_latches[&twin], Settled);
        index
            .claude_desktop_identity_latches
            .insert(pending.clone(), Pending);
        let (recovered, counts) = f.run(index, "2026-08-02T07:12:00Z");
        assert_eq!(
            recovered.native_bytes,
            2 * f.len(),
            "the settled twin is read with the recovering path"
        );
        let [posted, unchanged, refused, bytes] = counts.recovered;
        assert_eq!((posted + unchanged, refused, bytes), (1, 0, f.len()));
        let index = accept(recovered);
        assert_eq!(index.claude_desktop_identity_latches[&pending], Settled);
        assert_eq!(index.claude_desktop_identity_latches[&twin], Settled);
        f.quiet(
            f.restart(index),
            &["2026-08-02T07:13:00Z", "2026-08-02T07:14:00Z"],
        );
    });
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
    // unchanged, so nothing new is sent; without an exact ACK it stays pending.
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

#[test]
fn desktop_identity_natural_complete_refusal_cannot_settle_whole_or_partial_save() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    for backend in [Backend::Rejected, Backend::Conflict] {
        for downgraded in [false, true] {
            desktop_identity::reset_refused_memo_for_test();
            let f = IdentityFixture::new(if downgraded { CREATED_LATE } else { CREATED });
            let (committed, old_acks) = if downgraded {
                let (missing, _) = f.run(ScanIndex::default(), COLLECTED);
                assert_eq!(disposition(f.child(&missing)), Some("missing"));
                let old = ledger(f.child(&missing));
                let committed = ack(missing);
                assert_eq!(f.latch(&committed), None);
                f.write_store(CREATED, "natural proof recovery");
                (committed, old)
            } else {
                (ScanIndex::default(), BTreeMap::new())
            };
            let (run, _) = f.run_answered(
                committed.clone(),
                Arc::new(SharedCache::default()),
                "2026-08-02T07:12:00Z",
                backend,
            );
            let body = f.child(&run);
            assert_eq!(disposition(body), Some("complete"));
            assert!(run
                .result
                .pending_finalization
                .iter()
                .all(|p| p.desktop_identity_reoffer.is_none()));
            if downgraded {
                assert!(old_acks.contains_key(&body.snapshot_fingerprint));
                assert_ne!(ledger(body), old_acks);
            }
            let quarantine = BTreeMap::from([(
                body.snapshot_fingerprint.clone(),
                SnapshotQuarantineRecord {
                    upload_body_witness: Some(snapshot_upload_body_witness(body)),
                    ..snapshot_quarantine_record(SOURCE)
                },
            )]);
            let mut working = run.index;
            working.settle_desktop_identity_reoffers(
                &run.result,
                &old_acks,
                &BTreeMap::new(),
                &quarantine,
            );
            // Independent save alternatives need independent CAS destinations.
            let whole_path = f.home.join("whole-index.json");
            working.clone().save(&whole_path).unwrap();
            let whole = ScanIndex::load(&whole_path).unwrap();
            assert_eq!(f.latch(&whole), Some(Pending), "whole-index save");
            let accepted = old_acks.keys().cloned().collect();
            let partial = working.committable_subset(&committed, &accepted, &quarantine);
            assert_eq!(
                f.latch(&f.restart(partial)),
                Some(Pending),
                "fingerprint/quarantine-safe partial save"
            );
        }
    }
}

#[test]
fn desktop_identity_legacy_unknown_carry_bounds_reads_and_preserves_growth() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED);
    let (missing, _) = f.run(f.loaded_incomplete("2026-08-02T07:11:00Z"), COLLECTED);
    let fingerprint = f.child(&missing).snapshot_fingerprint.clone();
    let mut index = ack(missing);
    index
        .accepted_rebuild_incidence
        .insert(String::new(), BTreeSet::from([fingerprint.clone()]));
    index.accepted_incidence_pending_census = true;
    let len = f.len();
    let (carried, counts) = f.run(index, "2026-08-02T07:12:00Z");
    assert!(
        carried.result.snapshots.is_empty(),
        "legacy carry still protects the old ACK"
    );
    assert_eq!(carried.native_bytes, len);
    assert_eq!(counts.recovered, [0, 1, 0, len]);
    assert_eq!(f.latch(&carried.index), Some(Pending));
    assert!(carried.index.accepted_rebuild_incidence[""].contains(&fingerprint));
    let index = f.quiet(
        carried.index,
        &[
            "2026-08-02T07:13:00Z",
            "2026-08-02T07:14:00Z",
            "2026-08-02T07:15:00Z",
        ],
    );
    f.native.append_transcript(1);
    let (grown, counts) = f.run(index, "2026-08-02T07:16:00Z");
    assert!(
        grown.native_bytes > 0,
        "growth takes the ordinary read before identity deferral"
    );
    assert_eq!(grown.index.files[&f.key()].size_bytes, f.len());
    assert!(f.child(&grown).input_tokens > 0);
    assert_ne!(
        f.child(&grown).snapshot_fingerprint,
        fingerprint,
        "appended usage is offered"
    );
    assert_eq!(counts, Reoffers::default());
}

#[test]
fn desktop_identity_unstored_ack_is_local_to_destination_and_invocation() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = IdentityFixture::new(CREATED);
    let (missing, _) = f.run(f.loaded_incomplete("2026-08-02T07:11:00Z"), COLLECTED);
    let committed = ack(missing);
    let (run, _) = f.run_answered(
        committed,
        Arc::new(SharedCache::default()),
        "2026-08-02T07:12:00Z",
        Backend::Silent,
    );
    let response = Backend::Unstored.response(&run.result.snapshots).unwrap();
    let a_verdict = classify_desktop_identity_reoffers(&run.result.snapshots, &response);
    assert_eq!(
        a_verdict,
        ledger(f.child(&run)),
        "exact body answered under A"
    );
    let mut a = run.index.clone();
    a.activate_upload_context("destination-a".into());
    a.settle_desktop_identity_reoffers(&run.result, &BTreeMap::new(), &a_verdict, &BTreeMap::new());
    assert_eq!(f.latch(&a), Some(Settled));
    for (destination, rejected) in [
        ("destination-b", false),
        ("destination-b", true),
        ("destination-a", false),
    ] {
        let mut other = run.index.clone();
        other.activate_upload_context(destination.into());
        let quarantine = if rejected {
            let body = f.child(&run);
            BTreeMap::from([(
                body.snapshot_fingerprint.clone(),
                SnapshotQuarantineRecord {
                    upload_body_witness: Some(snapshot_upload_body_witness(body)),
                    ..snapshot_quarantine_record(SOURCE)
                },
            )])
        } else {
            BTreeMap::new()
        };
        other.settle_desktop_identity_reoffers(
            &run.result,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &quarantine,
        );
        assert_eq!(
            f.latch(&other),
            Some(Pending),
            "{destination}: a prior invocation's ACK is no evidence"
        );
    }
}
