//! Scan-level Claude Tail oracle rows using the existing synthetic pipeline.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as fixture, money_oracle, Accepted, Mode, RouteResult,
};
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::StateV2ColdSession;

const SOURCE: SnapshotSource = SnapshotSource::ClaudeCode;

/// Canonical upload and exact ACK, including the observed placement ledger.
fn result(page: &Page, mode: Mode) -> RouteResult {
    let mut progress = e2_progress();
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let (status, batches, _) = upload(&page.scan.snapshots, &mut progress, ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let mut result = RouteResult::emitted(mode, SOURCE, batches, &page.scan.snapshots);
    result.modes = page.modes;
    result.accepted_identity_buckets = Some(
        serde_json::to_value(
            page.scan
                .snapshots
                .iter()
                .map(|item| {
                    (
                        &item.source_session_id,
                        progress
                            .accepted_identity_buckets
                            .get(&item.source_session_id),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap(),
    );
    result
}

fn page(c: &Corpus, index: ScanIndex, limit: usize, sampled: bool) -> Page {
    let mut page = c.raw(
        &E2ScanFixture::capturing_identity(),
        index,
        limit,
        sampled,
        &[],
    );
    page.enrich(c);
    page
}

/// Commit the native page's exact ACKs and context receipts to the same
/// live database; the next caller gets the production cold load.
fn commit(session: &StateV2ColdSession, mut page: Page) -> ScanIndex {
    page.finish();
    let mut progress = e2_progress();
    assert_eq!(
        upload(&page.scan.snapshots, &mut progress, ack).0.unwrap(),
        ResumableUploadResult::Completed
    );
    page.index
        .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    accept_upload_context_acks_for_test(
        &mut page.index,
        &page.scan.snapshots,
        &progress.fresh_context_body_acks,
    );
    session.save_reload(&mut page.index).0
}

fn accepted(result: &mut RouteResult, items: &[SnapshotItem]) {
    result.accepted = result
        .snapshots
        .iter()
        .map(|(id, body)| {
            (
                id.clone(),
                Accepted {
                    body: body.clone(),
                    witness: snapshot_upload_body_witness(
                        items
                            .iter()
                            .find(|item| &item.source_session_id == id)
                            .unwrap(),
                    ),
                },
            )
        })
        .collect();
}

/// Independent accounts, a switch, side-call and evidence gap. Every fixture
/// line and telemetry row is consumed by the native pipeline.
fn placement_corpus(name: &str) -> (Corpus, PathBuf) {
    let mut c = Corpus::new(name);
    let path = c.root(
        ROOT,
        &(line(ROOT, "a", AT, 10)
            + &line(ROOT, "b", "2026-08-02T07:01:00Z", 20)
            + &line(ROOT, "gap", "2026-08-02T07:02:00Z", 12)),
    );
    c.agent(0, &line(ROOT, "agent", "2026-08-02T07:03:00Z", 5));
    c.evidence(
        &[
            api_login(ROOT, "a", 10, '1', Some('7')),
            api_login(ROOT, "b", 20, '2', Some('8')),
            api_login(ROOT, "agent", 5, '2', Some('8')),
            api_login(ROOT, "side", 4, '2', Some('8')),
        ],
        &[
            trace("a", ""),
            trace("b", ""),
            trace("agent", "agent-000"),
            trace("side", ""),
        ],
    );
    (c, path)
}

fn accounts(result: &RouteResult) -> BTreeSet<String> {
    fn walk(value: &serde_json::Value, out: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(fields) => {
                if let Some(account) = fields
                    .get("account_identifier_hash")
                    .and_then(|v| v.as_str())
                {
                    out.insert(account.into());
                }
                for v in fields.values() {
                    walk(v, out);
                }
            }
            serde_json::Value::Array(values) => {
                for v in values {
                    walk(v, out);
                }
            }
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    for body in result.snapshots.values() {
        walk(body, &mut out);
    }
    out
}

/// [money] A restarted Tail and pressure-evicted owner preserve two-account
/// placement, tagged rows and side calls; swapped placement fails the oracle.
#[test]
fn append_after_restart_and_eviction_preserves_placement() {
    with_e2(|| {
        let (c, path) = placement_corpus("s2-placement-restart");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let prior = commit(&session, page(&c, index, 100, true));
        append(&path, &line(ROOT, "later", "2026-08-02T07:04:00Z", 6));
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        assert!(
            accounts(&cold).len() >= 2,
            "positive control: two placed accounts"
        );
        assert!(cold.snapshots.len() >= 2, "root and agent");
        let mut stored = page(&c, prior.clone(), 100, true);
        assert_eq!(stored.modes.0, 0, "valid committed heads cannot Full");
        assert!(stored.modes.1 > 0);
        let warm = result(&stored, Mode::Restart);
        money_oracle::assert_equivalent(&cold, &warm);
        let scanner = E2ScanFixture::capturing_identity();
        scanner.evict_for_pressure();
        let mut evicted = c.raw(&scanner, prior, 100, true, &[]);
        evicted.enrich(&c);
        money_oracle::assert_equivalent(&cold, &result(&evicted, Mode::EvictRetry));
        let mut wrong = warm.clone();
        wrong.snapshots.get_mut(ROOT).unwrap()["request_evidence"][0]["provider_workspace_hash"] =
            json!("f".repeat(64));
        assert!(
            std::panic::catch_unwind(|| money_oracle::assert_equivalent(&cold, &wrong)).is_err()
        );
        stored.finish();
    });
}

/// [money] Pages use fresh owners and cold graph loads at every boundary.
/// Accumulated emitted bodies equal the single cold Full upload.
#[test]
fn restart_between_pages_matches_single_full() {
    with_e2(|| {
        let mut c = Corpus::new("s2-restart-pages");
        c.root(ROOT, &line(ROOT, "a", AT, 10));
        c.root(COPY, &line(COPY, "b", AT, 20));
        let (session, mut index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        let mut items = BTreeMap::new();
        for _ in 0..6 {
            let current = page(&c, index, 1, true);
            for item in &current.scan.snapshots {
                items.insert(item.source_session_id.clone(), item.clone());
            }
            let complete = current.scan.census_complete;
            index = commit(&session, current);
            if complete {
                break;
            }
        }
        assert_eq!(items.len(), 2);
        // Re-batch through the same uploader so page envelope ordering cannot
        // hide a missing entity or duplicated cumulative money.
        let items: Vec<_> = items.into_values().collect();
        let (status, batches, _) = upload(&items, &mut e2_progress(), ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        let mut warm = RouteResult::emitted(Mode::Restart, SOURCE, batches, &items);
        // Body placement is asserted; this row does not observe one aggregate
        // destination ledger across independent page ACKs.
        let mut cold = cold;
        cold.accepted_identity_buckets = None;
        warm.accepted_identity_buckets = None;
        money_oracle::assert_equivalent(&cold, &warm);
        let ((quiet, _), consumed) = fixture::observe_consumed(|| {
            let quiet = page(&c, index, 100, true);
            let modes = quiet.modes;
            (quiet, modes)
        });
        assert!(quiet.scan.snapshots.is_empty());
        assert_eq!(quiet.modes.0, 0);
        assert_eq!(
            consumed, 0,
            "quiet restart: no native or rederive consumption"
        );
    });
}

/// [money] A partial entity ACK cannot settle the sibling. Retry bodies stay
/// exact and the resulting accepted placement agrees with the cold Full.
#[test]
fn partial_ack_keeps_the_unaccepted_sibling_owed() {
    with_e2(|| {
        let (c, _) = placement_corpus("s2-partial-ack");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let mut current = page(&c, index, 100, true);
        current.finish();
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        let mut progress = e2_progress();
        let (status, batches, _) = upload(&current.scan.snapshots, &mut progress, |items| {
            let mut response = ack(items)?;
            let mut refused = response.accepted_entities.pop().unwrap();
            response.accepted -= 1;
            refused.head_etag = None;
            response.conflict_entities.push(refused);
            Ok(response)
        });
        assert_eq!(
            status.unwrap(),
            ResumableUploadResult::Deferred { count: 1 }
        );
        assert_eq!(progress.accepted_fingerprints.len(), 1);
        assert_eq!(progress.quarantined_fingerprints.len(), 1);
        let mut observed =
            RouteResult::emitted(Mode::Restart, SOURCE, batches, &current.scan.snapshots);
        let mut cold = cold;
        cold.accepted_identity_buckets = None;
        observed.accepted_identity_buckets = None;
        money_oracle::assert_equivalent(&cold, &observed);
        // Persist the progress through its real codec before retrying.
        let progress_path = c.base.join("partial-progress.json");
        progress.save(&progress_path).unwrap();
        let restored = SnapshotUploadProgress::load(
            &progress_path,
            &format!("{:064x}", 99),
            snapshot_quarantine_witness(SOURCE),
        )
        .unwrap();
        assert_eq!(
            restored.accepted_fingerprints,
            progress.accepted_fingerprints
        );
        assert_eq!(
            restored.quarantined_fingerprints,
            progress.quarantined_fingerprints
        );
        let _index = session.save_reload(&mut current.index).0;
    });
}

/// [money] A saved accepted extent ahead of all available bytes has no
/// independent shrink proof. The scan must retain accepted money and emit none.
#[test]
fn scan_below_floor_holds_without_a_smaller_reemit() {
    with_e2(|| {
        let mut c = Corpus::new("s2-scan-floor");
        let path = c.root(ROOT, &line(ROOT, "a", AT, 10));
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let initial = page(&c, index, 100, true);
        let mut prior_body = result(&initial, Mode::ColdFull);
        accepted(&mut prior_body, &initial.scan.snapshots);
        let mut prior = commit(&session, initial);
        let key = path.to_str().unwrap();
        prior.files.get_mut(key).unwrap().size_bytes += 128;
        let current = page(&c, prior, 100, true);
        let mut held = result(&current, Mode::Restart);
        held.accepted = prior_body.accepted.clone();
        money_oracle::assert_no_smaller_reemit(ROOT, &prior_body, &held, &prior_body, true);
        assert_eq!(
            current.index.files[key].last_upload_body_witness,
            current.committed.files[key].last_upload_body_witness
        );
    });
}

/// [money] A lossy append gets no new stored authority. Repeated reads from
/// the last good head retain the cold Full's money and loss disclosures.
#[test]
fn lossy_prefix_retains_the_previous_head_and_matches_full() {
    with_e2(|| {
        let mut c = Corpus::new("s2-lossy-prefix");
        let path = c.root(ROOT, &line(ROOT, "a", AT, 10));
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let prior = commit(&session, page(&c, index, 100, true));
        append(
            &path,
            &(String::from("{broken\n") + &line(ROOT, "b", "2026-08-02T07:01:00Z", 20)),
        );
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        let current = page(&c, prior, 100, true);
        assert_eq!(current.modes.0, 0);
        assert!(current.modes.1 > 0);
        money_oracle::assert_equivalent(&cold, &result(&current, Mode::Restart));
        let mut prior = commit(&session, current);
        // Evidence debt keeps the lossy file eligible on the next walk.
        prior
            .files
            .get_mut(path.to_str().unwrap())
            .unwrap()
            .source_file_fingerprint
            .clear();
        let replay = page(&c, prior, 100, true);
        assert_eq!(
            replay.modes.0, 0,
            "lossy completion must leave the old head"
        );
        assert!(
            replay.modes.1 > 0,
            "the old seal must replay the lossy suffix"
        );
        money_oracle::assert_equivalent(&cold, &result(&replay, Mode::Restart));
    });
}

/// [money] Fixed-evidence path twins converge through real scan + exact ACK
/// + database reload. A settled family is never selected on later walks.
fn assert_family_converges(c: &Corpus, session: &StateV2ColdSession, mut index: ScanIndex) {
    let mut counts = Vec::new();
    for _ in 0..6 {
        let current = page(c, index, 100, true);
        counts.push((
            current.scan.scanned_file_count,
            current.scan.snapshots.len(),
        ));
        index = commit(session, current);
    }
    assert!(counts[0].0 > 0);
    assert_eq!(
        &counts[4..],
        &[(0, 0), (0, 0)],
        "family reselected after resolve/terminal: {counts:?}"
    );
}

#[test]
fn forced_family_converges_after_resolve() {
    with_e2(|| {
        let mut c = Corpus::new("s2-family-convergence");
        c.write_at(
            &format!("a/{ROOT}.jsonl"),
            &line(ROOT, "a", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(line(ROOT, "a", AT, 10) + &line(ROOT, "b", "2026-08-02T07:03:10Z", 20)),
            "2026-08-02T07:03:00Z",
        );
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        assert_family_converges(&c, &session, index);
    });
}

/// [money] Changed current account evidence changes placement just as cold
/// Full does. Stored facts must not retain yesterday's account assignment.
#[test]
fn changed_account_evidence_matches_cold_placement() {
    with_e2(|| {
        let (c, path) = placement_corpus("s2-changed-account");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let first = page(&c, index, 100, true);
        let before = result(&first, Mode::ColdFull);
        let mut prior = commit(&session, first);
        c.evidence(
            &[
                api_login(ROOT, "a", 10, '3', Some('9')),
                api_login(ROOT, "b", 20, '2', Some('8')),
                api_login(ROOT, "agent", 5, '2', Some('8')),
                api_login(ROOT, "side", 4, '2', Some('8')),
            ],
            &[
                trace("a", ""),
                trace("b", ""),
                trace("agent", "agent-000"),
                trace("side", ""),
            ],
        );
        // The existing evidence-only clear selects a quiet record, without
        // changing its accepted body or the Tail's physical identity.
        prior
            .files
            .get_mut(path.to_str().unwrap())
            .unwrap()
            .source_file_fingerprint
            .clear();
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        assert_ne!(
            accounts(&before),
            accounts(&cold),
            "evidence change must affect placement"
        );
        let current = page(&c, prior, 100, true);
        assert_eq!(current.modes.0, 0);
        money_oracle::assert_equivalent(&cold, &result(&current, Mode::Restart));
    });
}
